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


    if(type == crn::packets::type::request){
        crn::packets::request req = req_json;
        std::cout << "<< " << std::endl << req_json.dump(4) << std::endl;
        // fetch req.last
        crn::storage db;
        crn::blocks::access access = db.fetch(req.last);
        // verify
        bool verified = access.active().verify(_master.pub().G(), req.token, _master.pri().x());
        if(verified){
            // construct challenge
            CryptoPP::AutoSeededRandomPool rng;
            crn::packets::challenge challenge = access.active().challenge(rng, _master.pub().G(), req.token, _master.pub().G().random(rng, true));
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
        // TODO mark the session as challengED
        // TODO wait for response
    }


    do_read();
}
void crn::session::write_handler(){

}
