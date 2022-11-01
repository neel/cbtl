// SPDX-FileCopyrightText: 2022 Neel Basu <email>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef SERVER_H
#define SERVER_H

#include <iostream>
#include <boost/enable_shared_from_this.hpp>
#include <boost/noncopyable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/lexical_cast.hpp>
#include "session.h"

//https://stackoverflow.com/questions/11021735/boost-asio-stateful-server-design

namespace crn{

class Server: public boost::enable_shared_from_this<Server>, private boost::noncopyable{
  private:
    boost::asio::io_context        _ios;
    boost::asio::ip::tcp::acceptor _acceptor;
  public:
    explicit Server(boost::asio::ip::tcp::endpoint& endpoint):_acceptor(_ios, endpoint){

    }
    void start(){
      accept();
      _ios.run();
    }
    void accept(){
      std::cout << "accepting " << std::endl;;
      Session::pointer session = Session::create(_ios);
      _acceptor.async_accept(session->socket(), boost::bind(&Server::handler, this, session, boost::asio::placeholders::error));
    }
    void handler(Session::pointer session, const boost::system::error_code &ec){
      if(!ec){
        session->handler(ec);
      }else{
        //possible destroy session ? but how to destroy a shared pointer ?
      }
      accept();
    }
};


}

#endif // SERVER_H
