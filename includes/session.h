// SPDX-FileCopyrightText: 2022 Neel Basu <email>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef SESSION_H
#define SESSION_H

#include <iostream>
#include <boost/enable_shared_from_this.hpp>
#include <boost/noncopyable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/bind/bind.hpp>
#include <boost/array.hpp>
#include <boost/format.hpp>
#include <boost/asio/write.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/read.hpp>
#include <boost/date_time/posix_time/ptime.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/asio/placeholders.hpp>
#include <arpa/inet.h>
#include "packets.h"
#include "db.h"
#include "keys.h"
#include "blocks_io.h"

namespace crn{



class session: public boost::enable_shared_from_this<session>, private boost::noncopyable{
#if (BOOST_VERSION / 1000 >=1 && BOOST_VERSION / 100 % 1000 >= 70)
    typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp, boost::asio::io_context::executor_type> socket_type;
#else
    typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp> socket_type;
#endif

  private:
    using buffer_type = boost::array<std::uint8_t, sizeof(crn::packets::header)>;
    socket_type                     _socket;
    boost::posix_time::ptime        _time;
    buffer_type                     _header;
    boost::array<char, 4096>        _data;
    crn::packets::header            _head;
    crn::db&                        _db;
    crn::identity::user&            _master;
  public:
    typedef boost::shared_ptr<session> pointer;
    static pointer create(crn::db& db, crn::identity::user& master, socket_type socket) { return pointer(new session(db, master, std::move(socket))); }
    ~session() {}
  private:
    explicit session(crn::db& db, crn::identity::user& master, socket_type socket): _socket(std::move(socket)), _time(boost::posix_time::second_clock::local_time()), _db(db), _master(master) { }
    public:
      void run(){
          do_read();
      }
      void do_read(){
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
      void handle_read_header(const boost::system::error_code& error, std::size_t bytes_transferred){
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
      void handle_read_data(const boost::system::error_code& error, std::size_t bytes_transferred) {
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
          // TODO fetch req.last
          crn::db db;
          crn::blocks::access access = db.fetch(req.last);
          // TODO verify
          bool verified = access.active().verify(_master.pub().G(), req.token, _master.pri().x());
          if(verified){
            // TODO construct challenge
            CryptoPP::AutoSeededRandomPool rng;
            crn::packets::challenge challenge = access.active().challenge(rng, _master.pub().G(), req.token, _master.pub().G().random(rng, true));
            // TODO send challenge
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
      void write_handler(){

      }
      socket_type& socket(){ return _socket; }
};

}

#endif // SESSION_H
