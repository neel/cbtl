// SPDX-FileCopyrightText: 2022 Sunanda Bose <email>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/session.h"
#include "crn/packets.h"
#include <pqxx/pqxx>
#include <pqxx/transaction>

crn::session::session(crn::storage& db, const crn::keys::identity::pair& master, const crn::keys::view_key& view, socket_type socket): _socket(std::move(socket)), _time(boost::posix_time::second_clock::local_time()), _db(db), _master(master), _view(view) { }

crn::session::pointer crn::session::create(crn::storage& db, const crn::keys::identity::pair& master, const crn::keys::view_key& view, socket_type socket) { return pointer(new session(db, master, view, std::move(socket))); }

void crn::session::run(){
    do_read();
}
void crn::session::do_read(){
    std::cout << "reading from socket" << std::endl;
    boost::asio::async_read(
        _socket,
        boost::asio::buffer(_header, sizeof(crn::packets::header) ),
        boost::bind(
            &session::handle_read_header,
            shared_from_this(),
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred
        )
    );
}
void crn::session::handle_read_header(const boost::system::error_code& error, std::size_t bytes_transferred){
    if(error) {
        std::cout << error.message() << std::endl;
        return;
    }
    std::cout << "reading header" << std::endl;
    assert(bytes_transferred == sizeof(crn::packets::header));

    std::copy_n(_header.cbegin(), bytes_transferred, reinterpret_cast<std::uint8_t*>(&_head));
    _head.size = ntohl(_head.size);
    std::cout << "expecting data " << _head.size << std::endl;
    boost::asio::async_read(
        _socket,
        boost::asio::buffer(_data, _head.size),
        boost::bind(
            &session::handle_read_data,
            shared_from_this(),
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred
        )
    );
}
void crn::session::handle_read_data(const boost::system::error_code& error, std::size_t bytes_transferred) {
    if (error) {
        std::cout << error.message() << std::endl;
        return;
    }
    std::string req_str;
    req_str.reserve(bytes_transferred);
    std::copy_n(_data.cbegin(), bytes_transferred, std::back_inserter(req_str));
    nlohmann::json req_json = nlohmann::json::parse(req_str);
    crn::packets::type type = static_cast<crn::packets::type>(_head.type);
    std::cout << "<< " << std::endl << req_json.dump(4) << std::endl;

    if(type == crn::packets::type::request){
        crn::packets::request req = req_json;
        handle_request(req);
    }else if(type == crn::packets::type::response && _challenge_data.challenged){
        crn::packets::actions action = static_cast<crn::packets::actions>(req_json["action"]["type"].get<std::uint32_t>());
        if(action == crn::packets::actions::identify){
            using response_type = crn::packets::response<crn::packets::action_data<crn::packets::actions::identify>>;
            response_type response = req_json;
            handle_challenge_response(response);
        }else if(action == crn::packets::actions::fetch){
            using response_type = crn::packets::response<crn::packets::action_data<crn::packets::actions::fetch>>;
            response_type response = req_json;
            handle_challenge_response(response);
        }else if(action == crn::packets::actions::insert){
            using response_type = crn::packets::response<crn::packets::action_data<crn::packets::actions::insert>>;
            response_type response = req_json;
            CryptoPP::Integer gaccess = handle_challenge_response(response);
            handle_action(response.action(), gaccess);
        }else if(action == crn::packets::actions::remove){
            using response_type = crn::packets::response<crn::packets::action_data<crn::packets::actions::remove>>;
            response_type response = req_json;
            handle_challenge_response(response);
        }
    }

    do_read();
}
void crn::session::write_handler(){

}

void crn::session::handle_request(const crn::packets::request& req){
    auto G = _master.pub().G();
    // fetch req.last
    crn::storage db;
    crn::blocks::access access = db.fetch(req.last);
    // verify
    crn::keys::identity::public_key pub(req.y, _master.pub());
    bool verified = access.active().verify(req.token, pub, _master.pri());
    if(verified){
        // construct challenge
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::Integer rho = G.random(rng, true), lambda = G.random(rng, true);
        auto cipher = G.Gp().Multiply(lambda, G.Gp().Exponentiate(pub.y(), _master.pri().x()));
        crn::packets::challenge challenge = access.active().challenge(rng, _master.pub().G(), req.token, rho, cipher);
        _challenge_data.token      = req.token;
        _challenge_data.y          = req.y;
        _challenge_data.last       = access.address().id();
        _challenge_data.challenged = true;
        _challenge_data.forward    = access.active().forward();
        _challenge_data.rho        = rho;
        _challenge_data.lambda     = lambda;
        // send challenge
        crn::packets::envelop<crn::packets::challenge> envelop(crn::packets::type::challenge, challenge);
        envelop.write(_socket);

        nlohmann::json challenge_json = challenge;
        std::cout << ">> " << std::endl << challenge_json.dump(4) << std::endl;
    }else{
        std::cout << "failed to verify" << std::endl;
    }
}


CryptoPP::Integer crn::session::handle_challenge_response(const crn::packets::basic_response& response){
    auto Gp = _master.pub().G().Gp(), Gp1 = _master.pub().G().Gp1();
    auto rho_inv = Gp1.MultiplicativeInverse(_challenge_data.rho);
    auto c2_d = Gp.Exponentiate(_challenge_data.forward, rho_inv);
    if(c2_d != response.c2()){
        std::cout << "Error matching c2" << std::endl;
        // TODO abort
    }else{
        auto alpha = Gp.Exponentiate(Gp.Divide(response.c1(), _challenge_data.forward), rho_inv);
        auto beta  = Gp.Multiply(response.c3(), Gp.Divide(response.c2(), c2_d));

        if(alpha != beta || beta != response.c3() || alpha != response.c3()){
            std::cout << "Verification failed" << std::endl;
            // TODO abort
        }else{
            std::cout << "Verification Successful" << std::endl;

            auto access = crn::keys::access_key::reconstruct(response.access(), _challenge_data.lambda, _master.pri());

            // auto sup_suffix = Gp.Multiply(Gp.Exponentiate(_master.pub().y(), _view.secret()),  Gp.Exponentiate(access, _master.pri().x()));

            std::cout << "computed access key: " << std::endl << access << std::endl;

            crn::keys::identity::public_key passive_pub("patient-0.pub");
            // passive.init();
            crn::blocks::access last_passive = crn::blocks::last::passive(_db, passive_pub, access);
            crn::keys::identity::public_key pub(_challenge_data.y, _master.pub());
            crn::blocks::params params( crn::blocks::params::active(_challenge_data.last, pub, response.c3()), last_passive, passive_pub, _master.pri(), access);
            CryptoPP::AutoSeededRandomPool rng;
            crn::blocks::access block = crn::blocks::access::construct(rng, params, _master.pri(), _challenge_data.token, access, last_passive.passive().forward(), _view);
            std::cout << "written new block: " << block.address().hash() << std::endl;
            if(_db.exists(block.address().hash())){
                // TODO abort
                std::cout << "block already exist" << std::endl;
            }else{
                _db.add(block);
                return access;
            }
        }
    }
    return 0;
}

std::string crn::session::handle_action(const crn::packets::action_data<crn::packets::actions::insert>& action, const CryptoPP::Integer& gaccess){
    pqxx::connection conn{"postgresql://crn_user@localhost/crn"};
    pqxx::work transaction{conn};

    conn.prepare("fetch_pv","SELECT encode(random, 'hex') FROM persons where y = (decode($1, 'hex');");
    conn.prepare("fetch_record","SELECT encode(random, 'hex') FROM records where anchor = $1;");
    conn.prepare("insert_record","INSERT INTO records(anchor, hint, random, \"case\") VALUES ($1, decode($2, 'hex'), decode($3, 'hex'), $4);");

    std::string y_hex = crn::utils::hex::encode(action.y(), CryptoPP::Integer::UNSIGNED);
    pqxx::result res_ident = transaction.exec_prepared("fetch_pv", y_hex);
    if(res_ident.size() != 1){
        std::cout << "patient not found " << y_hex << std::endl;
        return "";
    }
    CryptoPP::Integer pv = crn::utils::hex::decode(res_ident[0][0].c_str(), CryptoPP::Integer::UNSIGNED);
    CryptoPP::Integer random = pv;
    auto Gp = _master.pub().Gp();
    std::string last;
    while(true){
        CryptoPP::Integer pass = crn::utils::sha256::digest(Gp.Exponentiate(gaccess, random), CryptoPP::Integer::UNSIGNED);
        std::string anchor = crn::utils::aes::encrypt(y_hex, pass, CryptoPP::Integer::UNSIGNED);
        pqxx::result res_record = transaction.exec_prepared("fetch_record", anchor);
        if(res_record.size() == 1){
            random = crn::utils::hex::decode(res_record[0][0].c_str(), CryptoPP::Integer::UNSIGNED);
        }else{
            std::cout << "found last " << anchor << std::endl;
            last = anchor;
        }
    }

    CryptoPP::AutoSeededRandomPool rng;

    using action_type = crn::packets::action_data<crn::packets::actions::insert>;
    for(action_type::collection::const_iterator i = action.begin(); i != action.end(); ++i){
        const action_type::data& d = *i;
        CryptoPP::Integer pass   = crn::utils::sha256::digest(Gp.Exponentiate(gaccess, random), CryptoPP::Integer::UNSIGNED);
        CryptoPP::Integer r      = _master.pub().random(rng, false);
        CryptoPP::Integer suffix = crn::utils::sha512::digest(Gp.Exponentiate(gaccess, r), CryptoPP::Integer::UNSIGNED);
        std::string hint         = crn::utils::hex::encode(Gp.Multiply(random, suffix), CryptoPP::Integer::UNSIGNED);
        last                     = crn::utils::aes::encrypt(y_hex, pass, CryptoPP::Integer::UNSIGNED);
        transaction.exec_prepared("insert_record", last, hint, crn::utils::hex::encode(r, CryptoPP::Integer::UNSIGNED), d);
        random = r;
    }
    transaction.commit();
    return last;
}

