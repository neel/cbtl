// SPDX-FileCopyrightText: 2022 Sunanda Bose <email>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_SESSION_H
#define cbtl_SESSION_H

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
#include "cbtl/packets.h"
#include "cbtl/redis-storage.h"
#include "cbtl/keys.h"
#include "cbtl/blocks/io.h"

namespace cbtl{



class session: public boost::enable_shared_from_this<session>, private boost::noncopyable{
  struct challenge_data{
    CryptoPP::Integer last;     // \tau_{u}^{(0)}
    CryptoPP::Integer y;        // g^{\pi_{u}}
    CryptoPP::Integer token;    // g^{\pi_{u} r_{u}^{(0)}}
    bool challenged;
    CryptoPP::Integer forward;
    CryptoPP::Integer lambda;
    boost::posix_time::ptime requested;

    inline challenge_data(): challenged(false) {}
  };

#if (BOOST_VERSION / 1000 >=1 && BOOST_VERSION / 100 % 1000 >= 70)
    typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp, boost::asio::io_context::executor_type> socket_type;
#else
    typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp> socket_type;
#endif

  private:
    using buffer_type = boost::array<std::uint8_t, sizeof(cbtl::packets::header)>;
    socket_type                     _socket;
    boost::posix_time::ptime        _time;
    buffer_type                     _header;
    boost::array<char, 4096>        _data;
    cbtl::packets::header            _head;
    std::string                     _body;
    cbtl::storage&                   _db;
    cbtl::keys::identity::pair       _master;
    cbtl::keys::view_key             _view;
    challenge_data                  _challenge_data;
  public:
    typedef boost::shared_ptr<session> pointer;
    static pointer create(cbtl::storage& db, const cbtl::keys::identity::pair& master, const cbtl::keys::view_key& view, socket_type socket);
    inline ~session() {}
  private:
    explicit session(cbtl::storage& db, const cbtl::keys::identity::pair& master, const cbtl::keys::view_key& view, socket_type socket);
  public:
      void run();
      void do_read();
      void handle_read_header(const boost::system::error_code& error, std::size_t bytes_transferred);
      void read_more(const boost::system::error_code& error, std::size_t bytes_transferred);
      void read_finished();
      // void handle_storage_data(const boost::system::error_code& error, std::size_t bytes_transferred);
      void write_handler();
      inline socket_type& socket(){ return _socket; }
  private:
      void handle_request(const cbtl::packets::request& req);
      // CryptoPP::Integer handle_challenge_response(const cbtl::packets::basic_response& response);
      template <typename ActionDataT>
      cbtl::packets::result stage2(const cbtl::packets::response<ActionDataT>& response){
        CryptoPP::Integer gaccess = verify(response);
        if(!gaccess.IsZero()){
          cbtl::packets::result result = process(response.action(), gaccess);
          cbtl::packets::envelop<cbtl::packets::result> envelop(cbtl::packets::type::result, result);
          std::size_t bytes = envelop.write(_socket);
          // std::cout << bytes << " sent" << std::endl;
          return result;
        }
        return cbtl::packets::result::failure(0, "gaccess verification failed");
      }
  private:
      cbtl::packets::result process(const cbtl::packets::action_data<cbtl::packets::actions::insert>& action, const CryptoPP::Integer& gaccess);
      cbtl::packets::result process(const cbtl::packets::action_data<cbtl::packets::actions::identify>& action, const CryptoPP::Integer& gaccess);
      cbtl::packets::result process(const cbtl::packets::action_data<cbtl::packets::actions::fetch>& action, const CryptoPP::Integer& gaccess);
      cbtl::packets::result process(const cbtl::packets::action_data<cbtl::packets::actions::remove>& action, const CryptoPP::Integer& gaccess);
      CryptoPP::Integer verify(const cbtl::packets::basic_response& response);
      cbtl::blocks::access make(const cbtl::keys::identity::public_key& passive_pub, const CryptoPP::Integer& gaccess, const nlohmann::json& contents);
};

}

#endif // cbtl_SESSION_H
