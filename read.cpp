#include <iostream>
#include <array>
#include <string>
#include "crn/utils.h"
#include <boost/program_options.hpp>
#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include "crn/storage.h"
#include "crn/packets.h"
#include "crn/keys.h"
#include "crn/blocks.h"

int main(int argc, char** argv) {
    boost::program_options::options_description desc("CLI Frontend for Data Managers");
    desc.add_options()
        ("help,h",    "prints this help message")
        ("public,p",  boost::program_options::value<std::string>(), "path to the public key")
        ("secret,s",  boost::program_options::value<std::string>(), "path to the secret key")
        ("at,i",      boost::program_options::value<std::uint64_t>(), "traverse till i^th block")
        ("active,u",  boost::program_options::bool_switch()->default_value(false), "traverse active")
        ("passive,v", boost::program_options::bool_switch()->default_value(false), "traverse passive")
        ;

    boost::program_options::variables_map map;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), map);
    boost::program_options::notify(map);

    if(map.count("help") || !map.count("public") || !map.count("secret") || !map.count("at")){
        std::cout << desc << std::endl;
        return 1;
    }
    if(map["active"].as<bool>() == map["passive"].as<bool>()){
        std::cout << "Error: either use active or use passive. But not both or neither" << std::endl;
        std::cout << desc << std::endl;
        return 1;
    }

    std::string public_key = map["public"].as<std::string>(),
                secret_key = map["secret"].as<std::string>();

    std::uint64_t at = map["at"].as<std::uint64_t>();

    crn::storage db;

    crn::keys::identity::pair user(secret_key, public_key);

    crn::group G = user.pub();
    auto Gp = G.Gp(), Gp1 = G.Gp1();

    std::size_t i = 0;
    crn::blocks::access last = crn::blocks::genesis(db, user.pub());
    while(i++ < at){
        std::string address = last.active().next(user.pub().G(), last.address().id(), user.pri().x());
        if(db.exists(address, true)){
            CryptoPP::Integer x = Gp.Exponentiate(last.active().forward(), user.pri().x());
            std::string block_id = db.id(address);
            last = db.fetch(block_id);
            CryptoPP::Integer y = last.address().passive();

            auto body = last.body();
            crn::free_coordinates random = body.random();
            auto line = crn::linear_diophantine::interpolate(crn::free_coordinates{x, y}, random);
            CryptoPP::Integer password = line.eval(body.gamma());

            std::cout << i << std::endl;
            std::cout << "block id: " << std::endl << block_id << std::endl;
            std::cout << "password: " << std::endl << password << std::endl;
            std::cout << "-----------------------------" << std::endl;
        }else{
            break;
        }
    }
    return 0;
}
