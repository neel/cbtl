#include <iostream>
#include <string>
#include <array>
#include <cassert>
#include <exception>
#include <fstream>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/elgamal.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/dsa.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <nlohmann/json.hpp>
#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>
#include <db_cxx.h>

#include "key_pair.h"
#include "utils.h"
#include "genesis_block.h"

constexpr static const std::uint32_t key_size = 1024;


int main(int argc, char** argv) {
    unsigned int managers = 0, supers = 0, patients = 0;
    boost::program_options::options_description desc("crn-gen generates keys for the Trusted Server and Data Managers, Supervisors and patients");
    desc.add_options()
        ("help,h", "prints this help message")
        ("name-master",  boost::program_options::value<std::string>()->default_value("master"),    "filename for the Master Key (Trusted Server)")
        ("name-manager", boost::program_options::value<std::string>()->default_value("manager"),   "filename for the Data Manager's key (file names will be suffixed by integer counter)")
        ("name-super",   boost::program_options::value<std::string>()->default_value("super"),     "filename for the Data Manager's key (file names will be suffixed by integer counter)")
        ("name-patient", boost::program_options::value<std::string>()->default_value("super"),     "filename for the Data Manager's key (file names will be suffixed by integer counter)")
        ("managers,M",   boost::program_options::value<unsigned int>(&managers)->default_value(2), "number of Data Managers")
        ("supers,S",     boost::program_options::value<unsigned int>(&supers)->default_value(2),   "number of Supervisors")
        ("patients,P",   boost::program_options::value<unsigned int>(&patients)->default_value(2), "number of Patients")
        ;

    boost::program_options::variables_map map;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), map);
    boost::program_options::notify(map);

    if(map.count("help")){
        std::cout << desc << std::endl;
        return 1;
    }

    std::string master = "master", manager = "manager", super = "super", patient = "patient";
    if(map.count("master")) { master  = map["master"] .as<std::string>(); }
    if(map.count("manager")){ manager = map["manager"].as<std::string>(); }
    if(map.count("super"))  { super   = map["super"]  .as<std::string>(); }
    if(map.count("patient")){ patient = map["patient"].as<std::string>(); }


    CryptoPP::AutoSeededRandomPool rng;

    crn::key_pair trusted_server(rng, key_size);
    trusted_server.save(master);


    CryptoPP::Integer theta = trusted_server.public_key().random(rng, false), phi = trusted_server.public_key().random(rng, false);

    std::ofstream view(master+".view");
    view << crn::utils::eHex(phi);
    view.close();

    std::vector<crn::genesis_block> genesis_blocks;

    for(std::uint32_t i = 0; i < managers; ++i){
        std::string name = manager+"-"+boost::lexical_cast<std::string>(i);
        crn::key_pair key(rng, trusted_server.public_key());
        key.save(name);
        std::ofstream access(name+".access");
        access << crn::utils::eHex( key.public_key().raise({trusted_server.x(), theta}));
        access.close();
        crn::genesis_block genesis(rng, key.public_key(), trusted_server.private_key());
        genesis_blocks.push_back(genesis);
    }

    for(std::uint32_t i = 0; i < supers; ++i){
        std::string name = super+"-"+boost::lexical_cast<std::string>(i);
        crn::key_pair key(rng, trusted_server.public_key());
        key.save(name);
        std::ofstream access(name+".access");
        access << crn::utils::eHex( key.public_key().raise({trusted_server.x(), theta}));
        access.close();
        std::ofstream view(name+".view");
        view << crn::utils::eHex( key.public_key().raise({trusted_server.x(), phi}));
        view.close();
        crn::genesis_block genesis(rng, key.public_key(), trusted_server.private_key());
        genesis_blocks.push_back(genesis);
    }

    for(std::uint32_t i = 0; i < patients; ++i){
        std::string name = patient+"-"+boost::lexical_cast<std::string>(i);
        crn::key_pair key(rng, trusted_server.public_key());
        key.save(name);
        crn::genesis_block genesis(rng, key.public_key(), trusted_server.private_key());
        genesis_blocks.push_back(genesis);
    }

    // TODO Distribute those keys

    // { Create Key Value Data base
    Db db(NULL, 0);
    try{
        db.open(NULL /* Transaction pointer */,  "blockchain.db", NULL /*Optional logical database name*/ , DB_BTREE, DB_CREATE, 0); // File mode (using defaults)
        for(std::vector<crn::genesis_block>::const_iterator i = genesis_blocks.cbegin(); i != genesis_blocks.cend(); ++i){
            const crn::genesis_block& block = *i;
            nlohmann::json json = block;
            std::string json_str = json.dump();
            std::string block_id = block.hash();
            Dbt key((void*) block_id.c_str(), block_id.size());
            Dbt value((void*) json_str.c_str(), json_str.size());
            int ret = db.put(NULL, &key, &value, DB_NOOVERWRITE);
            if (ret == DB_KEYEXIST) {
                // TODO failure
                std::cout << "failed " << __LINE__ << std::endl;
            }else{
                std::cout << "written " << block_id << std::endl;
            }
        }
        db.sync(0);
        db.close(0);
    }catch(DbException& e){
        std::cout << e.what() << std::endl;
    }catch(std::exception& e){
        std::cout << e.what() << std::endl;
    }
    //}

    return 0;
}

