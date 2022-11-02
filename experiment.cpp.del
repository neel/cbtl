#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include "db.h"
#include "server.h"

int main(int argc, char** argv){
    crn::db db;
    std::cout << std::boolalpha << db.exists("hello") << std::endl;

    boost::asio::io_service io;

    crn::server server(io, boost::lexical_cast<std::uint32_t>(argv[1]));
    server.run();

    io.run();

    return 0;
}
