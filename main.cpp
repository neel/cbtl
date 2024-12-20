#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include "cbtl/redis-storage.h"
#include "cbtl/server.h"
#include "cbtl/keys.h"

int main(int argc, char** argv){
    boost::program_options::options_description desc("CLI Frontend for Data Managers");
    desc.add_options()
        ("help,h", "prints this help message")
        ("public,p", boost::program_options::value<std::string>(), "path to the public key")
        ("secret,s", boost::program_options::value<std::string>(), "path to the secret key")
        ("view,v",   boost::program_options::value<std::string>(), "path to the master view secret")
        ;

    boost::program_options::variables_map map;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), map);
    boost::program_options::notify(map);

    if(map.count("help") || !map.count("public") || !map.count("secret")){
        std::cout << desc << std::endl;
        return 1;
    }

    std::string public_key = map["public"].as<std::string>(),
                secret_key = map["secret"].as<std::string>(),
                view_key   = map["view"].as<std::string>();

    cbtl::storage db;

    cbtl::keys::identity::pair master(secret_key, public_key);
    cbtl::keys::view_key view(view_key);
    // master.init();

    boost::asio::io_service io;

    cbtl::server server(db, master, view, io, 9887);
    server.run();

    io.run();

    return 0;
}

