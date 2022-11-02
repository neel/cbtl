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

    // { Create Key Value Data base
    // Db db(NULL, 0);
    // try{
    //     db.open(NULL /* Transaction pointer */,  "blockchain.db", NULL /*Optional logical database name*/ , DB_BTREE, DB_RDONLY, 0); // File mode (using defaults)
    //
    //     std::string next_key = crn::utils::SHA512(keys.public_key().y());
    //     std::string last_key = next_key;
    //
    //     while(true){
    //         Dbt key((void*) next_key.c_str(), next_key.size()), value;
    //         int ret = db.get(NULL, &key, &value, 0);
    //         if(ret == DB_NOTFOUND){
    //             // last block
    //             std::cout << "last: " << last_key << std::endl;
    //             break;
    //         }else{
    //             std::string json_str((const char*) value.get_data(), value.get_size());
    //             nlohmann::json json = nlohmann::json::parse(json_str);
    //             CryptoPP::Integer block_id = crn::utils::dHex(json["id"].get<std::string>());
    //             CryptoPP::Integer trapdoor = crn::utils::sha512(keys.private_key().raise_x(crn::utils::dHex(json["active"][0].get<std::string>())));
    //             CryptoPP::Integer next = keys.Gp().Multiply(block_id, trapdoor);
    //             last_key = next_key;
    //             next_key = crn::utils::eHex(next);
    //             std::cout << "next: " << next_key << std::endl;
    //         }
    //     }
    //     db.sync(0);
    //     db.close(0);
    // }catch(DbException& e){
    //     std::cout << e.what() << std::endl;
    // }catch(std::exception& e){
    //     std::cout << e.what() << std::endl;
    // }
    //}

    crn::group G = keys;

    crn::db db;
    try{
        std::string genesis_id = crn::blocks::access::genesis_id(keys.public_key().y());
        while(true){
            if(db.exists(genesis_id)){
                crn::blocks::access block = db.fetch(genesis_id);
                block.active().next(G, block.address().id(), keys.private_key().x());
            }
        }
    }catch(DbException& e){
        std::cout << e.what() << std::endl;
    }catch(std::exception& e){
        std::cout << e.what() << std::endl;
    }

    return 0;
}
