// SPDX-FileCopyrightText: 2022 Sunanda Bose <email>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_SESSION_H
#define CRN_SESSION_H

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
#include "crn/packets.h"
#include "crn/storage.h"
#include "crn/keys.h"
#include "crn/blocks/io.h"

namespace crn{



class session: public boost::enable_shared_from_this<session>, private boost::noncopyable{
  struct challenge_data{
    CryptoPP::Integer last;     // \tau_{u}^{(0)}
    CryptoPP::Integer y;        // g^{\pi_{u}}
    CryptoPP::Integer token;    // g^{\pi_{u} r_{u}^{(0)}}
    bool challenged;
    CryptoPP::Integer forward;
    CryptoPP::Integer rho;
    CryptoPP::Integer lambda;

    inline challenge_data(): challenged(false) {}
  };

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
    crn::storage&                   _db;
    crn::keys::identity::pair       _master;
    crn::keys::view_key             _view;
    challenge_data                  _challenge_data;
  public:
    typedef boost::shared_ptr<session> pointer;
    static pointer create(crn::storage& db, const crn::keys::identity::pair& master, const crn::keys::view_key& view, socket_type socket);
    inline ~session() {}
  private:
    explicit session(crn::storage& db, const crn::keys::identity::pair& master, const crn::keys::view_key& view, socket_type socket);
  public:
      void run();
      void do_read();
      void handle_read_header(const boost::system::error_code& error, std::size_t bytes_transferred);
      void handle_read_data(const boost::system::error_code& error, std::size_t bytes_transferred);
      // void handle_storage_data(const boost::system::error_code& error, std::size_t bytes_transferred);
      void write_handler();
      inline socket_type& socket(){ return _socket; }
  private:
      void handle_request(const crn::packets::request& req);
      // CryptoPP::Integer handle_challenge_response(const crn::packets::basic_response& response);
      template <typename ActionDataT>
      void stage2(const crn::packets::response<ActionDataT>& response){
        CryptoPP::Integer gaccess = verify(response);
        if(!gaccess.IsZero()){
          crn::packets::result result = process(response.action(), gaccess, response.c3());
          crn::packets::envelop<crn::packets::result> envelop(crn::packets::type::result, result);
          std::size_t bytes = envelop.write(_socket);
          std::cout << bytes << " sent" << std::endl;
        }
      }
  private:
      crn::packets::result process(const crn::packets::action_data<crn::packets::actions::insert>& action, const CryptoPP::Integer& gaccess, const CryptoPP::Integer& active_back);
      crn::packets::result process(const crn::packets::action_data<crn::packets::actions::identify>& action, const CryptoPP::Integer& gaccess, const CryptoPP::Integer& active_back);
      crn::packets::result process(const crn::packets::action_data<crn::packets::actions::fetch>& action, const CryptoPP::Integer& gaccess, const CryptoPP::Integer& active_back);
      crn::packets::result process(const crn::packets::action_data<crn::packets::actions::remove>& action, const CryptoPP::Integer& gaccess, const CryptoPP::Integer& active_back);
      CryptoPP::Integer verify(const crn::packets::basic_response& response);
      crn::blocks::access make(const crn::keys::identity::public_key& passive_pub, const CryptoPP::Integer& gaccess, const CryptoPP::Integer& active_back, const nlohmann::json& contents);
};

}

#endif // CRN_SESSION_H
