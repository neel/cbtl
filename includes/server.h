// SPDX-FileCopyrightText: 2022 Neel Basu <email>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef SERVER_H
#define SERVER_H

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
#include "session.h"
#include "keys.h"
#include "storage.h"

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
    inline server(crn::storage& db, crn::identity::user& master, boost::asio::io_service& io, std::uint32_t port): server(db, master, io, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::any(), port)) {}
    inline server(crn::storage& db, crn::identity::user& master, boost::asio::io_service& io, const boost::asio::ip::tcp::endpoint& endpoint):_io(io), _acceptor(_io), _socket(io), _signals(io, SIGINT, SIGTERM), _db(db), _master(master) {
        boost::system::error_code ec;
        _acceptor.open(endpoint.protocol(), ec);
        if(ec) throw std::runtime_error((boost::format("Failed to open acceptor %1%") % ec.message()).str());
        _acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
        if(ec) throw std::runtime_error((boost::format("Failed to set reusable option %1%") % ec.message()).str());
        _acceptor.bind(endpoint, ec);
        if(ec) throw std::runtime_error((boost::format("Failed to bind acceptor %1%") % ec.message()).str());
        _acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        if(ec) throw std::runtime_error((boost::format("Failed to listen %1%") % ec.message()).str());

        _signals.async_wait(boost::bind(&server::stop, this));
    }
    inline ~server(){ stop(); }
    inline void stop(){
        _acceptor.close();
        _io.stop();
    }
    inline void run(){
        if(! _acceptor.is_open())
            return;
        accept();
    }
    inline void accept(){
        std::cout << "accepting" << std::endl;
        _acceptor.async_accept(_socket, std::bind(&server::on_accept, this, std::placeholders::_1));
    }
    inline void on_accept(boost::system::error_code ec){
        if(ec){
            // TODO failed to accept
          std::cout << "on_accept: " << ec.message() << std::endl;
        }else{
            auto conn = session::create(_db, _master, std::move(_socket));
            conn->run();
        }
        accept();
    }
};


}

#endif // SERVER_H
