// SPDX-FileCopyrightText: 2022 Neel Basu <email>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/session.h"

crn::session::session(crn::storage& db, crn::identity::user& master, socket_type socket): _socket(std::move(socket)), _time(boost::posix_time::second_clock::local_time()), _db(db), _master(master) { }

crn::session::pointer crn::session::create(crn::storage& db, crn::identity::user& master, socket_type socket) { return pointer(new session(db, master, std::move(socket))); }

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
        // fetch req.last
        crn::storage db;
        crn::blocks::access access = db.fetch(req.last);
        // verify
        bool verified = access.active().verify(_master.pub().G(), req.token, req.y, _master.pri().x());
        if(verified){
            // construct challenge
            CryptoPP::AutoSeededRandomPool rng;
            CryptoPP::Integer rho = _master.pub().G().random(rng, true);
            crn::packets::challenge challenge = access.active().challenge(rng, _master.pub().G(), req.token, rho);
            _challenge_data.token      = req.token;
            _challenge_data.y          = req.y;
            _challenge_data.last       = access.address().id();
            _challenge_data.challenged = true;
            _challenge_data.forward    = access.active().forward();
            _challenge_data.rho        = rho;
            // send challenge
            crn::packets::envelop<crn::packets::challenge> envelop(crn::packets::type::challenge, challenge);
            std::vector<std::uint8_t> dbuffer;
            envelop.copy(std::back_inserter(dbuffer));
            boost::asio::write(_socket, boost::asio::buffer(dbuffer.data(), dbuffer.size()));

            nlohmann::json challenge_json = challenge;
            std::cout << ">> " << std::endl << challenge_json.dump(4) << std::endl;
        }else{
            std::cout << "failed to verify" << std::endl;
        }
    }else if(type == crn::packets::type::response && _challenge_data.challenged){
        crn::packets::response response = req_json;
        // TODO verify challenge response
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
                // TODO get the last passive block
                crn::identity::keys::public_key passive("patient-0.pub");
                passive.init();
                crn::blocks::access last_passive = crn::blocks::last::passive(_db, passive, _master.pri());

                crn::blocks::access::params params;
                params.active.id     = _challenge_data.last;
                params.active.token  = response.c3;
                params.active.y      = _challenge_data.y;
                params.passive.id    = last_passive.address().id();
                params.passive.y     = passive.y();
                params.passive.token = last_passive.passive().token(passive.G(), passive.y(), _master.pri().x());
                params.w             = _master.pri().x();

                CryptoPP::AutoSeededRandomPool rng;
                crn::blocks::access block = crn::blocks::access::construct(rng, _master.pub().G(), params, _challenge_data.token);
                std::cout << "written new block: " << block.address().hash() << std::endl;

                _db.add(block);
            }
        }
    }


    do_read();
}
void crn::session::write_handler(){

}
