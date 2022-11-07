// SPDX-FileCopyrightText: 2022 Neel Basu <email>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/session.h"

crn::session::session(crn::storage& db, const crn::keys::identity::pair& master, socket_type socket): _socket(std::move(socket)), _time(boost::posix_time::second_clock::local_time()), _db(db), _master(master) { }

crn::session::pointer crn::session::create(crn::storage& db, const crn::keys::identity::pair& master, socket_type socket) { return pointer(new session(db, master, std::move(socket))); }

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
        crn::packets::response response = req_json;
        handle_challenge_response(response);
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


void crn::session::handle_challenge_response(const crn::packets::response& response){
    auto Gp = _master.pub().G().Gp(), Gp1 = _master.pub().G().Gp1();
    auto rho_inv = Gp1.MultiplicativeInverse(_challenge_data.rho);
    auto c2_d = Gp.Exponentiate(_challenge_data.forward, rho_inv);
    if(c2_d != response.c2){
        std::cout << "Error matching c2" << std::endl;
        // TODO abort
    }else{
        auto alpha = Gp.Exponentiate(Gp.Divide(response.c1, _challenge_data.forward), rho_inv);
        auto beta  = Gp.Multiply(response.c3, Gp.Divide(response.c2, c2_d));

        if(alpha != beta || beta != response.c3 || alpha != response.c3){
            std::cout << "Verification failed" << std::endl;
            // TODO abort
        }else{
            std::cout << "Verification Successful" << std::endl;

            auto access = crn::keys::access_key::reconstruct(response.access, _challenge_data.lambda, _master.pri());

            std::cout << "computed access key: " << std::endl << access << std::endl;

            crn::keys::identity::public_key passive_pub("patient-0.pub");
            // passive.init();
            crn::blocks::access last_passive = crn::blocks::last::passive(_db, passive_pub, _master.pri());
            crn::keys::identity::public_key pub(_challenge_data.y, _master.pub());
            crn::blocks::params params( crn::blocks::params::active(_challenge_data.last, pub, response.c3), last_passive, passive_pub, _master.pri());
            CryptoPP::AutoSeededRandomPool rng;
            crn::blocks::access block = crn::blocks::access::construct(rng, params, _master.pri(), _challenge_data.token);
            std::cout << "written new block: " << block.address().hash() << std::endl;
            if(_db.exists(block.address().hash())){
                // TODO abort
                std::cout << "block already exist" << std::endl;
            }else{
                _db.add(block);
            }
        }
    }
}
