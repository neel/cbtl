#include <iostream>
#include <array>
#include <string>
#include "utils.h"
#include <boost/program_options.hpp>
#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include "storage.h"
#include "packets.h"
#include "keys.h"

int main(int argc, char** argv) {
    boost::program_options::options_description desc("CLI Frontend for Data Managers");
    desc.add_options()
        ("help,h", "prints this help message")
        ("public,p", boost::program_options::value<std::string>(), "path to the public key")
        ("secret,s", boost::program_options::value<std::string>(), "path to the secret key")
        ("access,a", boost::program_options::value<std::string>(), "path to the access key")
        ;

    boost::program_options::variables_map map;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), map);
    boost::program_options::notify(map);

    if(map.count("help") || !map.count("public") || !map.count("secret") || !map.count("access")){
        std::cout << desc << std::endl;
        return 1;
    }

    std::string public_key = map["public"].as<std::string>(),
                secret_key = map["secret"].as<std::string>(),
                access_key = map["access"].as<std::string>();

    crn::storage db;

    crn::identity::user user(db, secret_key, public_key);
    user.init();

    crn::group G = user.pub();

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve("127.0.0.1", "9887");
    boost::asio::ip::tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints);

    crn::packets::request request = user.request();
    crn::packets::envelop<crn::packets::request> envelop(crn::packets::type::request, request);
    std::vector<std::uint8_t> dbuffer;
    envelop.copy(std::back_inserter(dbuffer));
    boost::asio::write(socket, boost::asio::buffer(dbuffer.data(), dbuffer.size()));

    nlohmann::json request_json = request;
    std::cout << ">> " << std::endl << request_json.dump(4) << std::endl;

    return 0;
}
