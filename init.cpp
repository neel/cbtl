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

#include "crn/keys.h"
#include "crn/utils.h"
#include "crn/storage.h"
#include "crn/blocks.h"
#include "crn/blocks/io.h"

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

    crn::keys::identity::pair trusted_server(rng, key_size);
    trusted_server.save(master);

    CryptoPP::Integer theta = trusted_server.pub().random(rng, false), phi = trusted_server.pub().random(rng, false);

    // std::ofstream view(master+".view");
    // view << crn::utils::eHex(phi);
    // view.close();

    crn::keys::view_key view(phi);
    view.save("master");

    crn::group G = trusted_server.pub();
    auto Gp = G.Gp();
    auto Gp1 = G.Gp1();

    crn::storage db;
    for(std::uint32_t i = 0; i < managers; ++i){
        std::string name = manager+"-"+boost::lexical_cast<std::string>(i);
        crn::keys::identity::pair key(rng, trusted_server.pri());
        // key.init();
        key.save(name);
        auto access = crn::keys::access_key::construct(theta, key.pub(), trusted_server.pri());
        access.save(name);
        crn::blocks::params params = crn::blocks::params::genesis(trusted_server.pri(), key.pub());
        crn::blocks::access genesis = crn::blocks::access::genesis(rng, params, trusted_server.pri());
        db.add(genesis);
    }

    for(std::uint32_t i = 0; i < supers; ++i){
        std::string name = super+"-"+boost::lexical_cast<std::string>(i);
        crn::keys::identity::pair key(rng, trusted_server.pri());
        // key.init();
        key.save(name);
        auto access = crn::keys::access_key::construct(theta, key.pub(), trusted_server.pri());
        access.save(name);
        std::ofstream view(name+".view");
        view << crn::utils::eHex( Gp.Exponentiate(Gp.Exponentiate( key.pub().y(), trusted_server.pri().x()), phi) );
        view.close();
        crn::blocks::params params = crn::blocks::params::genesis(trusted_server.pri(), key.pub());
        crn::blocks::access genesis = crn::blocks::access::genesis(rng, params, trusted_server.pri());
        db.add(genesis);
    }

    for(std::uint32_t i = 0; i < patients; ++i){
        std::string name = patient+"-"+boost::lexical_cast<std::string>(i);
        crn::keys::identity::pair key(rng, trusted_server.pri());
        // key.init();
        key.save(name);
        crn::blocks::params params = crn::blocks::params::genesis(trusted_server.pri(), key.pub());
        crn::blocks::access genesis = crn::blocks::access::genesis(rng, params, trusted_server.pri());
        db.add(genesis);
    }

    // TODO Distribute those keys

    return 0;
}

