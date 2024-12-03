// SPDX-FileCopyrightText: 2022 Sunanda Bose <email>
// SPDX-License-Identifier: BSD-3-Clause

#include "cbtl/session.h"
#include "cbtl/packets.h"
#include <pqxx/pqxx>
#include <pqxx/transaction>
#include <format>
#include <ctime>

cbtl::session::session(cbtl::storage& db, const cbtl::keys::identity::pair& master, const cbtl::keys::view_key& view, socket_type socket): _socket(std::move(socket)), _time(boost::posix_time::second_clock::local_time()), _db(db), _master(master), _view(view) { }

cbtl::session::pointer cbtl::session::create(cbtl::storage& db, const cbtl::keys::identity::pair& master, const cbtl::keys::view_key& view, socket_type socket) { return pointer(new session(db, master, view, std::move(socket))); }

void cbtl::session::run(){
    do_read();
}
void cbtl::session::do_read(){
    // std::cout << "reading from socket" << std::endl;
    boost::asio::async_read(
        _socket,
        boost::asio::buffer(_header, sizeof(cbtl::packets::header) ),
        boost::bind(
            &session::handle_read_header,
            shared_from_this(),
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred
        )
    );
}
void cbtl::session::handle_read_header(const boost::system::error_code& error, std::size_t bytes_transferred){
    if(error) {
        std::cout << error.message() << std::endl;
        return;
    }
    // std::cout << "reading header" << std::endl;
    assert(bytes_transferred == sizeof(cbtl::packets::header));

    std::copy_n(_header.cbegin(), bytes_transferred, reinterpret_cast<std::uint8_t*>(&_head));
    _head.size = ntohl(_head.size);
    // std::cout << "expecting data " << _head.size << std::endl;
    _body.clear();
    _body.reserve(_head.size);
    read_more(boost::system::error_code{}, 0);
}

void cbtl::session::read_more(const boost::system::error_code& error, std::size_t bytes_transferred) {
    if (error) {
        std::cout << error.message() << std::endl;
        return;
    }

    // std::cout << "bytes_transferred: " << bytes_transferred << std::endl;

    std::copy_n(_data.cbegin(), bytes_transferred, std::back_inserter(_body));
    auto pending = (_head.size - _body.size());
    if(_body.size() < _head.size){
        boost::asio::async_read(
            _socket,
            boost::asio::buffer(_data, pending),
            boost::bind(
                &session::read_more,
                shared_from_this(),
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred
            )
        );
    }else{
        std::cout << std::format("read {} bytes", _body.size()) << std::endl;
        read_finished();
    }
}

void cbtl::session::read_finished() {
    nlohmann::json req_json;
    try{
        req_json = nlohmann::json::parse(_body);
    }catch(const nlohmann::json::parse_error& error){
        std::cout << "Failed to parse request: " << error.what() << std::endl;
        std::cout << "length: " << _body.size() << std::endl;
        std::cout << "str: " << _body << std::endl;
    }
    cbtl::packets::type type = static_cast<cbtl::packets::type>(_head.type);
    // std::cout << "<< " << std::endl << req_json.dump(4) << std::endl;

    std::clock_t start = std::clock();
    if(type == cbtl::packets::type::request){
        cbtl::packets::request req = req_json;
        handle_request(req);
    }else if(type == cbtl::packets::type::response && _challenge_data.challenged){
        cbtl::packets::actions action = static_cast<cbtl::packets::actions>(req_json["action"]["type"].get<std::uint32_t>());
        if(action == cbtl::packets::actions::identify){
            using response_type = cbtl::packets::response<cbtl::packets::action_data<cbtl::packets::actions::identify>>;
            response_type response = req_json;
            cbtl::packets::result result = stage2(response);

            std::clock_t end = std::clock();
            long double duration = 1000.0 * (end - start) / CLOCKS_PER_SEC;
            std::cout << std::format("Identified 1 record in {}ms", duration) << std::endl;
        }else if(action == cbtl::packets::actions::fetch){
            using response_type = cbtl::packets::response<cbtl::packets::action_data<cbtl::packets::actions::fetch>>;
            response_type response = req_json;
            cbtl::packets::result result = stage2(response);

            std::clock_t end = std::clock();
            long double duration = 1000.0 * (end - start) / CLOCKS_PER_SEC;
            std::cout << std::format("Fetched {} records in {}ms", result.aux["cases"].size(), duration) << std::endl;
        }else if(action == cbtl::packets::actions::insert){
            using response_type = cbtl::packets::response<cbtl::packets::action_data<cbtl::packets::actions::insert>>;
            response_type response = req_json;
            cbtl::packets::result result = stage2(response);

            std::clock_t end = std::clock();
            long double duration = 1000.0 * (end - start) / CLOCKS_PER_SEC;
            std::cout << std::format("Inserted {} records in {}ms", response.action().count(), duration) << std::endl;
        }else if(action == cbtl::packets::actions::remove){
            using response_type = cbtl::packets::response<cbtl::packets::action_data<cbtl::packets::actions::remove>>;
            response_type response = req_json;
            cbtl::packets::result result = stage2(response);
        }
    }
    do_read();
}
void cbtl::session::write_handler(){

}

void cbtl::session::handle_request(const cbtl::packets::request& req){
    auto G = _master.pub().G();
    // fetch req.last
    cbtl::storage db;
    cbtl::blocks::access access = db.fetch(req.last);
    // verify
    cbtl::keys::identity::public_key pub(req.y, _master.pub());
    bool verified = access.active().verify(req.token, pub, _master.pri());
    if(verified){
        // construct challenge
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::Integer rho = G.random(rng, true), lambda = G.random(rng, true);
        auto cipher = G.Gp().Multiply(lambda, G.Gp().Exponentiate(pub.y(), _master.pri().x()));
        cbtl::packets::challenge challenge = access.active().challenge(rng, _master.pub().G(), req.token, rho, cipher);
        _challenge_data.token      = req.token;
        _challenge_data.y          = req.y;
        _challenge_data.last       = access.address().id();
        _challenge_data.challenged = true;
        _challenge_data.forward    = access.active().forward();
        _challenge_data.lambda     = lambda;
        _challenge_data.requested  = boost::posix_time::microsec_clock::local_time();
        // send challenge
        cbtl::packets::envelop<cbtl::packets::challenge> envelop(cbtl::packets::type::challenge, challenge);
        envelop.write(_socket);

        nlohmann::json challenge_json = challenge;
        // std::cout << ">> " << std::endl << challenge_json.dump(4) << std::endl;
    }else{
        std::cout << "failed to verify" << std::endl;
    }
}

CryptoPP::Integer cbtl::session::verify(const cbtl::packets::basic_response& response){
    auto Gp = _master.pub().G().Gp(), Gp1 = _master.pub().G().Gp1();

    // std::cout << "Verification Successful" << std::endl;
    CryptoPP::Integer active_next = Gp.Multiply(_challenge_data.last, cbtl::utils::sha512::digest(_challenge_data.token, CryptoPP::Integer::UNSIGNED));
    if(_db.exists(cbtl::utils::hex::encode(active_next, CryptoPP::Integer::UNSIGNED), true)){
        std::cout << "Next active address already exists" << std::endl;
        return 0;
    }

    return cbtl::keys::access_key::reconstruct(response.access(), _challenge_data.lambda, _master.pri());
}

cbtl::blocks::access cbtl::session::make(const cbtl::keys::identity::public_key& passive_pub, const CryptoPP::Integer& gaccess, const nlohmann::json& contents){
    cbtl::blocks::access last_passive = cbtl::blocks::last::passive(_db, passive_pub, gaccess, _master.pri());
    // std::cout << "last_pasive: " << last_passive.address().id() << std::endl;
    cbtl::keys::identity::public_key pub(_challenge_data.y, _master.pub());
    cbtl::blocks::params params( cbtl::blocks::params::active(_challenge_data.last, pub, _challenge_data.forward), last_passive, passive_pub, _master.pri(), gaccess, _challenge_data.requested);
    CryptoPP::AutoSeededRandomPool rng;
    return cbtl::blocks::access::construct(rng, params, _master.pri(), _challenge_data.token, gaccess, last_passive.passive().forward(), _view, contents.dump(4));
}

cbtl::packets::result cbtl::session::process(const cbtl::packets::action_data<cbtl::packets::actions::identify>& action, const CryptoPP::Integer& gaccess){
    std::string anchor = action.anchor();
    pqxx::connection conn{"postgresql://cbtl_user@localhost/cbtl"};
    pqxx::work transaction{conn};
    conn.prepare("fetch_anchor","SELECT encode(hint, 'hex'), encode(random, 'hex') FROM records where anchor = $1;");
    pqxx::result res_anchor = transaction.exec_prepared("fetch_anchor", anchor);
    if(res_anchor.size() != 1){
        return cbtl::packets::result::failure(404, "anchor does not exist");
    }
    CryptoPP::Integer random = cbtl::utils::hex::decode(res_anchor[0][1].c_str(), CryptoPP::Integer::UNSIGNED);
    CryptoPP::Integer hint   = cbtl::utils::hex::decode(res_anchor[0][0].c_str(), CryptoPP::Integer::UNSIGNED);

    std::string public_key_str;
    CryptoPP::Integer y = 0;

    try{
        auto Gp = _master.pub().Gp();
        CryptoPP::Integer suffix      = cbtl::utils::sha512::digest(Gp.Exponentiate(gaccess, random), CryptoPP::Integer::UNSIGNED);
        CryptoPP::Integer random_prev = Gp.Divide(hint, suffix);
        CryptoPP::Integer pass        = cbtl::utils::sha256::digest(Gp.Exponentiate(gaccess, random_prev), CryptoPP::Integer::UNSIGNED);
        public_key_str                = cbtl::utils::aes::decrypt(anchor, pass, CryptoPP::Integer::UNSIGNED);
        y                             = cbtl::utils::hex::decode(public_key_str, CryptoPP::Integer::UNSIGNED);
    }catch(const std::exception& ex){
        return cbtl::packets::result::failure(500, ex.what());
    }

    cbtl::keys::identity::public_key passive_pub(y, _master.pub().G());
    nlohmann::json contents = {
        {"active",  cbtl::utils::hex::encode(_challenge_data.y, CryptoPP::Integer::UNSIGNED)},
        {"passive", cbtl::utils::hex::encode(y, CryptoPP::Integer::UNSIGNED)},
        {"anchors", {
            anchor
        }}
    };
    cbtl::blocks::access block = make(passive_pub, gaccess, contents);
    if(_db.exists(block.address().hash())){
        return cbtl::packets::result::failure(403, "block already exists");
    }else{
        _db.add(block);
    }

    return cbtl::packets::result::success(_challenge_data.y, y, block.address().hash(), {
        {"anchor",  anchor}
    });

}

cbtl::packets::result cbtl::session::process(const cbtl::packets::action_data<cbtl::packets::actions::insert>& action, const CryptoPP::Integer& gaccess){
    pqxx::connection conn{"postgresql://cbtl_user@localhost/cbtl"};
    pqxx::work transaction{conn};

    conn.prepare("fetch_pv","SELECT encode(random, 'hex') FROM persons where y = decode($1, 'hex');");
    conn.prepare("fetch_record","SELECT encode(random, 'hex') FROM records where anchor = $1;");
    conn.prepare("insert_record","INSERT INTO records(anchor, hint, random, \"case\") VALUES ($1, decode($2, 'hex'), decode($3, 'hex'), $4);");

    std::string y_hex = cbtl::utils::hex::encode(action.y(), CryptoPP::Integer::UNSIGNED);
    pqxx::result res_ident = transaction.exec_prepared("fetch_pv", y_hex);
    if(res_ident.size() != 1){
        return cbtl::packets::result::failure(404, "patient does not exist");
    }
    CryptoPP::Integer pv = cbtl::utils::hex::decode(res_ident[0][0].c_str(), CryptoPP::Integer::UNSIGNED);
    CryptoPP::Integer random = pv;
    auto Gp = _master.pub().Gp();
    std::string last;
    while(true){
        CryptoPP::Integer pass = cbtl::utils::sha256::digest(Gp.Exponentiate(gaccess, random), CryptoPP::Integer::UNSIGNED);
        std::string anchor = cbtl::utils::aes::encrypt(y_hex, pass, CryptoPP::Integer::UNSIGNED);
        pqxx::result res_record = transaction.exec_prepared("fetch_record", anchor);
        if(res_record.size() == 1){
            random = cbtl::utils::hex::decode(res_record[0][0].c_str(), CryptoPP::Integer::UNSIGNED);
        }else{
            last = anchor;
            break;
        }
    }

    CryptoPP::AutoSeededRandomPool rng;
    std::vector<std::string> anchors;
    using action_type = cbtl::packets::action_data<cbtl::packets::actions::insert>;
    for(action_type::collection::const_iterator i = action.begin(); i != action.end(); ++i){
        const action_type::data& d = *i;
        CryptoPP::Integer pass   = cbtl::utils::sha256::digest(Gp.Exponentiate(gaccess, random), CryptoPP::Integer::UNSIGNED);
        CryptoPP::Integer r      = _master.pub().random(rng, false);
        CryptoPP::Integer suffix = cbtl::utils::sha512::digest(Gp.Exponentiate(gaccess, r), CryptoPP::Integer::UNSIGNED);
        std::string hint         = cbtl::utils::hex::encode(Gp.Multiply(random, suffix), CryptoPP::Integer::UNSIGNED);
        last                     = cbtl::utils::aes::encrypt(y_hex, pass, CryptoPP::Integer::UNSIGNED);
        anchors.push_back(last);
        transaction.exec_prepared("insert_record", last, hint, cbtl::utils::hex::encode(r, CryptoPP::Integer::UNSIGNED), d);
        // std::cout << "inserting " << d << std::endl;
        random = r;
    }
    transaction.commit();

    nlohmann::json contents = {
        {"active",  cbtl::utils::hex::encode(_challenge_data.y, CryptoPP::Integer::UNSIGNED)},
        {"passive", cbtl::utils::hex::encode(action.y(), CryptoPP::Integer::UNSIGNED)},
        {"anchors", anchors}
    };

    cbtl::keys::identity::public_key passive_pub(action.y(), _master.pub().G());
    cbtl::blocks::access block = make(passive_pub, gaccess, contents);
    if(_db.exists(block.address().hash())){
        return cbtl::packets::result::failure(403, "block already exists");
    }else{
        _db.add(block);
    }

    return cbtl::packets::result::success(_challenge_data.y, action.y(), block.address().hash(), {
        {"last",  last}
    });
}

cbtl::packets::result cbtl::session::process(const cbtl::packets::action_data<cbtl::packets::actions::fetch>& action, const CryptoPP::Integer& gaccess){
    pqxx::connection conn{"postgresql://cbtl_user@localhost/cbtl"};
    pqxx::work transaction{conn};

    conn.prepare("fetch_pv","SELECT encode(random, 'hex') FROM persons where y = decode($1, 'hex');");
    conn.prepare("fetch_record","SELECT encode(random, 'hex'), \"case\" FROM records where anchor = $1;");

    std::string y_hex = cbtl::utils::hex::encode(action.y(), CryptoPP::Integer::UNSIGNED);
    pqxx::result res_ident = transaction.exec_prepared("fetch_pv", y_hex);
    if(res_ident.size() != 1){
        return cbtl::packets::result::failure(404, "patient does not exist");
    }
    CryptoPP::Integer pv = cbtl::utils::hex::decode(res_ident[0][0].c_str(), CryptoPP::Integer::UNSIGNED);
    CryptoPP::Integer random = pv;
    auto Gp = _master.pub().Gp();
    std::string last;
    std::vector<std::string> cases;
    while(true){
        CryptoPP::Integer pass = cbtl::utils::sha256::digest(Gp.Exponentiate(gaccess, random), CryptoPP::Integer::UNSIGNED);
        std::string anchor = cbtl::utils::aes::encrypt(y_hex, pass, CryptoPP::Integer::UNSIGNED);
        pqxx::result res_record = transaction.exec_prepared("fetch_record", anchor);
        if(res_record.size() == 1){
            random = cbtl::utils::hex::decode(res_record[0][0].c_str(), CryptoPP::Integer::UNSIGNED);
            // std::cout << "random: " << random << std::endl;
            std::string case_str = res_record[0][1].c_str();
            cases.push_back(case_str);
            // std::cout << "case: " << case_str  << std::endl;
        }else{
            // std::cout << "found last " << anchor << std::endl;
            last = anchor;
            break;
        }
    }
    transaction.commit();

    nlohmann::json contents = {
        {"active",  cbtl::utils::hex::encode(_challenge_data.y, CryptoPP::Integer::UNSIGNED)},
        {"passive", cbtl::utils::hex::encode(action.y(), CryptoPP::Integer::UNSIGNED)}
    };

    cbtl::keys::identity::public_key passive_pub(action.y(), _master.pub().G());
    cbtl::blocks::access block = make(passive_pub, gaccess, contents);
    if(_db.exists(block.address().hash())){
        return cbtl::packets::result::failure(403, "block already exists");
    }else{
        _db.add(block);
    }

    return cbtl::packets::result::success(_challenge_data.y, action.y(), block.address().hash(), {
        {"cases", cases},
        {"last",  last}
    });
}

cbtl::packets::result cbtl::session::process(const cbtl::packets::action_data<cbtl::packets::actions::remove>& action, const CryptoPP::Integer& gaccess){
    return cbtl::packets::result::failure(500, "Not Implemented");
}

