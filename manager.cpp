#include <iostream>
#include <array>
#include <string>
#include "key_pair.h"
#include "utils.h"
#include <boost/program_options.hpp>
#include <db_cxx.h>
#include <nlohmann/json.hpp>
#include "db.h"

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

    crn::key_pair keys(public_key, secret_key);

    crn::group G = keys;

    crn::db db;
    try{
        std::string genesis_id = crn::blocks::access::genesis_id(keys.public_key().y());
        std::string block_id = genesis_id, last_id;
        while(true){
            if(db.exists(block_id)){
                last_id  = block_id;
                crn::blocks::access block = db.fetch(block_id);
                block_id = block.active().next(G, block.address().id(), keys.private_key().x());
            }else{
                std::cout << "last block: " << last_id<< std::endl;
                break;
            }
        }
    }catch(DbException& e){
        std::cout << e.what() << std::endl;
    }catch(std::exception& e){
        std::cout << e.what() << std::endl;
    }

    return 0;
}
