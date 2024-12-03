// SPDX-FileCopyrightText: 2022 Sunanda Bose <email>
// SPDX-License-Identifier: BSD-3-Clause

#include "cbtl/server.h"

cbtl::server::server(cbtl::storage& db, const cbtl::keys::identity::pair& master, const cbtl::keys::view_key& view, boost::asio::io_service& io, std::uint32_t port): server(db, master, view, io, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::any(), port)) {}


cbtl::server::server(cbtl::storage& db, const cbtl::keys::identity::pair& master, const cbtl::keys::view_key& view, boost::asio::io_service& io, const boost::asio::ip::tcp::endpoint& endpoint):_io(io), _acceptor(_io), _socket(io), _signals(io, SIGINT, SIGTERM), _db(db), _master(master), _view(view) {
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

cbtl::server::~server() noexcept{
    stop();
}


void cbtl::server::stop(){
    _acceptor.close();
    _io.stop();
}

void cbtl::server::run(){
    if(! _acceptor.is_open())
        return;
    accept();
}


void cbtl::server::accept(){
    std::cout << "accepting" << std::endl;
    _acceptor.async_accept(_socket, std::bind(&server::on_accept, this, std::placeholders::_1));
}


void cbtl::server::on_accept(boost::system::error_code ec){
    if(ec){
        // TODO failed to accept
        std::cout << "on_accept: " << ec.message() << std::endl;
    }else{
        auto conn = session::create(_db, _master, _view, std::move(_socket));
        conn->run();
    }
    accept();
}
