// SPDX-FileCopyrightText: 2022 Neel Basu <email>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_SERVER_H
#define CRN_SERVER_H

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
#include "crn/session.h"
#include "crn/keys.h"
#include "crn/storage.h"

namespace crn{

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
    crn::storage&                        _db;
    crn::identity::user&            _master;
  public:
    server(crn::storage& db, crn::identity::user& master, boost::asio::io_service& io, std::uint32_t port);
    server(crn::storage& db, crn::identity::user& master, boost::asio::io_service& io, const boost::asio::ip::tcp::endpoint& endpoint);
    ~server() noexcept;
    void stop();
    void run();
    void accept();
    void on_accept(boost::system::error_code ec);
};


}

#endif // CRN_SERVER_H
