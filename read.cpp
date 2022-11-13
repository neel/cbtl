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
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>

int main(int argc, char** argv) {
    boost::program_options::options_description desc("CLI Frontend for Data Managers");
    desc.add_options()
        ("help,h",    "prints this help message")
        ("public,p",  boost::program_options::value<std::string>(), "path to the public key")
        ("secret,s",  boost::program_options::value<std::string>(), "path to the secret key")
        ("master,m",  boost::program_options::value<std::string>(), "path to the master public key")
        ("at,i",      boost::program_options::value<std::uint64_t>(), "traverse till i^th block")
        ("active,u",  boost::program_options::bool_switch()->default_value(false), "traverse active")
        ("passive,v", boost::program_options::bool_switch()->default_value(false), "traverse passive")
        ;

    boost::program_options::variables_map map;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), map);
    boost::program_options::notify(map);

    if(map.count("help") || !map.count("public") || !map.count("secret") || !map.count("master") || !map.count("at")){
        std::cout << desc << std::endl;
        return 1;
    }
    if(map["active"].as<bool>() == map["passive"].as<bool>()){
        std::cout << "Error: either use active or use passive. But not both or neither" << std::endl;
        std::cout << desc << std::endl;
        return 1;
    }

    std::string public_key = map["public"].as<std::string>(),
                secret_key = map["secret"].as<std::string>(),
                master_key = map["master"].as<std::string>();

    std::uint64_t at = map["at"].as<std::uint64_t>();

    crn::storage db;

    crn::keys::identity::pair user(secret_key, public_key);
    crn::keys::identity::public_key master(master_key);

    crn::group G = user.pub();
    auto Gp = G.Gp(), Gp1 = G.Gp1();

    bool is_active = map["active"].as<bool>();

    std::size_t i = 0;
    crn::blocks::access last = crn::blocks::genesis(db, user.pub());
    while(i++ < at){
        std::string address = is_active
                                ? last.active().next(user.pub().G(), last.address().id(), user.pri().x())
                                : last.passive().next(user.pub().G(), last.address().id(), master.y(), user.pri().x());
        if(db.exists(address, true)){
            CryptoPP::Integer x = crn::utils::sha256(Gp.Exponentiate(last.active().forward(), user.pri().x()));
            std::string block_id = db.id(address);
            last = db.fetch(block_id);
            CryptoPP::Integer y = is_active ? last.address().passive() : last.address().active();
            if(!is_active){
                x = crn::utils::sha256(Gp.Exponentiate(last.active().forward(), user.pri().x()));
            }

            // std::cout << "coordinates:" << std::endl << x << y << std::endl;

            auto body = last.body();
            crn::free_coordinates random = body.random();
            auto line = crn::linear_diophantine::interpolate(crn::free_coordinates{x, y}, random);
            // std::cout << "line: " << line << std::endl;
            // std::cout << "random: " << random.x() << random.y() << std::endl;
            CryptoPP::Integer delta = line.eval(body.gamma());
            std::string ciphertext = body.ciphertext();

            std::vector<CryptoPP::byte> bytes;
            bytes.resize(delta.MinEncodedSize(CryptoPP::Integer::SIGNED));
            delta.Encode(&bytes[0], bytes.size(), CryptoPP::Integer::SIGNED);
            CryptoPP::SHA256 hash;
            CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
            hash.CalculateDigest(digest, bytes.data(), bytes.size());

            CryptoPP::HexEncoder encoder;
            std::string hash_str;
            encoder.Attach(new CryptoPP::StringSink(hash_str));
            encoder.Put(digest, sizeof(digest));
            encoder.MessageEnd();

            std::cout << "H(secret): " << hash_str << std::endl;

            CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec;
            dec.SetKey(&digest[0], CryptoPP::SHA256::DIGESTSIZE);
            std::string plaintext;
            try{
                CryptoPP::StringSource s(ciphertext, true, new CryptoPP::Base64Decoder(new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::StringSink(plaintext)))); // StringSource
            }catch(const CryptoPP::InvalidCiphertext&){
                std::cout << "invalid ciphertext" << std::endl;
                plaintext = "failed";
            }
            std::cout << i << std::endl;
            std::cout << "block id: " << std::endl << block_id << std::endl;
            std::cout << "password: " << std::endl << delta << std::endl;
            std::cout << "message:  " << std::endl << plaintext << std::endl;
            std::cout << "-----------------------------" << std::endl;
        }else{
            std::cout << "future: " << address << std::endl;
            break;
        }
    }
    return 0;
}
