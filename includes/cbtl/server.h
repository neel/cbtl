// SPDX-FileCopyrightText: 2022 Sunanda Bose <email>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_SERVER_H
#define cbtl_SERVER_H

#include <iostream>
#include <boost/enable_shared_from_this.hpp>
#include <boost/noncopyable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/bind/bind.hpp>
#include <boost/format.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/io_service.hpp>
#include "cbtl/session.h"
#include "cbtl/keys.h"
#include "cbtl/redis-storage.h"

namespace cbtl{

class server: public boost::enable_shared_from_this<server>, private boost::noncopyable{
#if (BOOST_VERSION / 1000 >=1 && BOOST_VERSION / 100 % 1000 >= 70)
    typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp, boost::asio::io_context::executor_type> socket_type;
#else
    typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp> socket_type;
#endif
  private:
    boost::asio::io_service&        _io;
    boost::asio::ip::tcp::acceptor  _acceptor;
    socket_type                     _socket;
    boost::asio::signal_set         _signals;
    cbtl::storage&                   _db;
    cbtl::keys::identity::pair       _master;
    cbtl::keys::view_key             _view;
  public:
    server(cbtl::storage& db, const cbtl::keys::identity::pair& master, const cbtl::keys::view_key& view, boost::asio::io_service& io, std::uint32_t port);
    server(cbtl::storage& db, const cbtl::keys::identity::pair& master, const cbtl::keys::view_key& view, boost::asio::io_service& io, const boost::asio::ip::tcp::endpoint& endpoint);
    ~server() noexcept;
    void stop();
    void run();
    void accept();
    void on_accept(boost::system::error_code ec);
};


}

#endif // cbtl_SERVER_H
