// SPDX-FileCopyrightText: 2022 Neel Basu <email>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef SESSION_H
#define SESSION_H

#include <iostream>
#include <boost/enable_shared_from_this.hpp>
#include <boost/noncopyable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include <boost/asio/write.hpp>
#include <boost/lexical_cast.hpp>

namespace crn{

class Session: public boost::enable_shared_from_this<Session>, private boost::noncopyable{
  private:
    size_t _id;
    boost::asio::ip::tcp::socket   _socket;
  public:
    typedef boost::shared_ptr<Session> pointer;
    static pointer create(boost::asio::io_context& ios){
      return pointer(new Session(ios));
    }
  private:
  explicit Session(boost::asio::io_context& ios): _socket(ios){
    static size_t counter = 0;
    _id = counter++;
    std::cout << ">> Session " << id() << " constructing" << std::endl;
  }
  public:
    void handler(const boost::system::error_code &ec){
      const std::string message = (boost::format("HTTP/1.1 200 OK\r\nContent-Length: %2%\r\n\r\nHello, %1%!") % id() % (7+boost::lexical_cast<std::string>(id()).length())).str();
      if(!ec){
        boost::asio::async_write(_socket, boost::asio::buffer(message), boost::bind(&Session::write_handler, this));
      }else{
        std::cout << ec.message() << std::endl;
      }
    }
    void write_handler(){

    }
    size_t id() const{
      return _id;
    }
    boost::asio::ip::tcp::socket& socket(){
      return _socket;
    }
    virtual ~Session(){
      std::cout << ">> Session " << id() << " destructing" << std::endl;
    }
    };

}

#endif // SESSION_H
