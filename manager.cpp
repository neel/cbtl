#include <iostream>
#include <array>
#include <string>
#include "utils.h"
#include <boost/program_options.hpp>
#include <db_cxx.h>
#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include "db.h"
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

    crn::db db;

    crn::identity::user user(db, secret_key, public_key);
    user.init();

    std::cout << "y: " << user.pub().y() << std::endl;
    std::cout << "x: " << user.pri().x() << std::endl;

    crn::group G = user.pub();
    std::string last_id;

    // CryptoPP::Integer token = 0;
    // try{
    //     std::string block_id = user.pub().genesis_id();;
    //     while(true){
    //         if(db.exists(block_id)){
    //             last_id  = block_id;
    //             crn::blocks::access block = db.fetch(block_id);
    //             block_id = block.active().next(G, block.address().id(), user.pri().x());
    //             token = G.Gp().Exponentiate(block.active().forward(), user.pri().x());
    //         }else{
    //             std::cout << "last block: " << last_id<< std::endl;
    //             break;
    //         }
    //     }
    // }catch(DbException& e){
    //     std::cout << e.what() << std::endl;
    // }catch(std::exception& e){
    //     std::cout << e.what() << std::endl;
    // }

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve("127.0.0.1", "9887");
    boost::asio::ip::tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints);

    crn::packets::envelop<crn::packets::request> envelop(crn::packets::type::request, user.request());
    std::vector<std::uint8_t> dbuffer;
    envelop.copy(std::back_inserter(dbuffer));
    // std::copy(dbuffer.cbegin(), dbuffer.cend(), std::ostream_iterator<char>(std::cout));
    boost::asio::write(socket, boost::asio::buffer(dbuffer.data(), dbuffer.size()));

    return 0;
}
