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
#include <pqxx/pqxx>
#include <pqxx/transaction>
#include <boost/lexical_cast.hpp>

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

    crn::math::group G = trusted_server.pub();
    auto g   = G.g();
    auto Gp  = G.Gp();
    auto Gp1 = G.Gp1();

    CryptoPP::Integer phi = trusted_server.pub().random(rng, false);
    CryptoPP::Integer theta = 0, h = 0, h_inverse = 0, gaccess;
    while(h_inverse == 0 || Gp.Exponentiate(Gp.Exponentiate(g, h_inverse), h) != g){
        theta = trusted_server.pub().random(rng, false);
        gaccess = Gp.Exponentiate(g, theta);
        h = crn::utils::sha512::digest(gaccess, CryptoPP::Integer::UNSIGNED);
        h_inverse = Gp1.MultiplicativeInverse(h);
    }

    crn::keys::view_key view(phi);
    view.save("master");

    crn::storage db;
    for(std::uint32_t i = 0; i < managers; ++i){
        std::string name = manager+"-"+boost::lexical_cast<std::string>(i);
        crn::keys::identity::pair key(rng, trusted_server.pri());
        key.save(name);
        auto access = crn::keys::access_key::construct(theta, key.pub(), trusted_server.pri());
        access.save(name);
        auto now = boost::posix_time::microsec_clock::local_time();
        crn::blocks::params params = crn::blocks::params::genesis(trusted_server.pri(), key.pub(), now);
        crn::blocks::access genesis = crn::blocks::access::genesis(rng, params, trusted_server.pri(), h);
        db.add(genesis);
    }

    for(std::uint32_t i = 0; i < supers; ++i){
        std::string name = super+"-"+boost::lexical_cast<std::string>(i);
        crn::keys::identity::pair key(rng, trusted_server.pri());
        key.save(name);
        auto access = crn::keys::access_key::construct(theta, key.pub(), trusted_server.pri());
        access.save(name);
        auto view   = crn::keys::view_key::construct(phi, key.pub(), trusted_server.pri());
        view.save(name);
        auto now = boost::posix_time::microsec_clock::local_time();
        crn::blocks::params params = crn::blocks::params::genesis(trusted_server.pri(), key.pub(), now);
        crn::blocks::access genesis = crn::blocks::access::genesis(rng, params, trusted_server.pri(), h);
        db.add(genesis);
    }

    pqxx::connection conn{"postgresql://crn_user@localhost/crn"};
    pqxx::work transaction{conn};
    conn.prepare("truncate_persons", "DELETE FROM public.persons;");
    conn.prepare("truncate_records", "DELETE FROM public.records;");
    conn.prepare(
        "insert_person",
        R"(
            INSERT INTO persons(y, random, name, age)
                VALUES (decode($1, 'hex'), decode($2, 'hex'), $3, $4);
        )"
    );
    conn.prepare(
        "insert_record",
        R"(
            INSERT INTO records(anchor, hint, random, "case")
                VALUES ($1, decode($2, 'hex'), decode($3, 'hex'), $4);
        )"
    );
    transaction.exec_prepared("truncate_persons");
    transaction.exec_prepared("truncate_records");
    for(std::uint32_t i = 0; i < patients; ++i){
        std::string name = patient+"-"+boost::lexical_cast<std::string>(i);
        crn::keys::identity::pair key(rng, trusted_server.pri());
        key.save(name);
        auto now = boost::posix_time::microsec_clock::local_time();
        crn::blocks::params params = crn::blocks::params::genesis(trusted_server.pri(), key.pub(), now);
        crn::blocks::access genesis = crn::blocks::access::genesis(rng, params, trusted_server.pri(), h);
        db.add(genesis);

        CryptoPP::Integer pv = trusted_server.pub().random(rng, false), tv0 = trusted_server.pub().random(rng, false);
        std::string y_hex = crn::utils::hex::encode(key.pub().y(), CryptoPP::Integer::UNSIGNED);
        transaction.exec_prepared("insert_person",
            y_hex,
            crn::utils::hex::encode(pv, CryptoPP::Integer::UNSIGNED),
            name,
            CryptoPP::Integer(rng, 10, 100).ConvertToLong()
        );
        CryptoPP::Integer pass   = crn::utils::sha256::digest(Gp.Exponentiate(gaccess, pv), CryptoPP::Integer::UNSIGNED);
        CryptoPP::Integer suffix = crn::utils::sha512::digest(Gp.Exponentiate(gaccess, tv0), CryptoPP::Integer::UNSIGNED);
        transaction.exec_prepared("insert_record",
            crn::utils::aes::encrypt(y_hex, pass, CryptoPP::Integer::UNSIGNED),
            crn::utils::hex::encode(Gp.Multiply(pv, suffix), CryptoPP::Integer::UNSIGNED),
            crn::utils::hex::encode(tv0, CryptoPP::Integer::UNSIGNED),
            "genesis"
        );
    }

    transaction.commit();

    // TODO Distribute those keys

    std::cout << "---------------------------------------------------" << std::endl;
    std::cout << "g^{\\theta}: " << Gp.Exponentiate(g, theta) << std::endl;

    return 0;
}

