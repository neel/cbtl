#include <iostream>
#include <array>
#include <string>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include "packets.h"

int main(int argc, char** argv) {
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve("127.0.0.1", "9887");
    boost::asio::ip::tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints);

    crn::packets::request request;
    request.last = "xyz";
    request.token = 4545;

    crn::packets::envelop<crn::packets::request> envelop(crn::packets::type::request, request);
    std::vector<std::uint8_t> dbuffer;
    envelop.copy(std::back_inserter(dbuffer));

    std::copy(dbuffer.cbegin(), dbuffer.cend(), std::ostream_iterator<char>(std::cout));

    boost::asio::write(socket, boost::asio::buffer(dbuffer.data(), dbuffer.size()));


    return 0;
}
