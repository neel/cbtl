#include <iostream>
#include <array>
#include <string>
#include <format>
#include "crn/utils.h"
#include <boost/program_options.hpp>
#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include "crn/redis-storage.h"
#include "crn/packets.h"
#include "crn/keys.h"
#include "crn/blocks.h"
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>

int main(int argc, char** argv) {
    boost::program_options::options_description desc("CLI Block Reader for Data Managers and Supervisors");
    desc.add_options()
        ("help,h",    "prints this help message")
        ("public,p",  boost::program_options::value<std::string>(), "path to the public key")
        ("secret,s",  boost::program_options::value<std::string>(), "path to the secret key")
        ("master,m",  boost::program_options::value<std::string>(), "path to the master public key")
        ("access,a",  boost::program_options::value<std::string>(), "path to the supervisors access key")
        ("view,w",    boost::program_options::value<std::string>(), "path to the supervisors view key")
        ("limit,l",   boost::program_options::value<std::uint64_t>(), "traverse till l^th block")
        ("id,t",      boost::program_options::value<std::string>(),   "read the specified block")
        ("active,u",  boost::program_options::bool_switch()->default_value(false), "traverse active")
        ("passive,v", boost::program_options::bool_switch()->default_value(false), "traverse passive")
        ("super,x",   boost::program_options::bool_switch()->default_value(false), "view as supervisor")
        ;

    boost::program_options::variables_map map;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), map);
    boost::program_options::notify(map);

    if(map.count("help")){
        std::cout << desc << std::endl;
        return 1;
    }
    if(map["active"].as<bool>() || map["passive"].as<bool>()){
        if(!map.count("public") || !map.count("secret") || !map.count("master") || !map.count("limit")){
            if(map["active"].as<bool>()) std::cout << "active";
            if(map["passive"].as<bool>()) std::cout << "passive";
            std::cout << " traversal requires -p public_key -s secret_key -m master_key -a limit" << std::endl;
            std::cout << desc << std::endl;
            return 1;
        }
        if(map["active"].as<bool>() == map["passive"].as<bool>()){
            std::cout << "Error: either use active or use passive. But not both." << std::endl;
            std::cout << desc << std::endl;
            return 1;
        }

        std::string public_key = map["public"].as<std::string>(),
                    secret_key = map["secret"].as<std::string>(),
                    master_key = map["master"].as<std::string>();

        std::uint64_t limit = map["limit"].as<std::uint64_t>();

        crn::storage db;

        crn::keys::identity::pair user(secret_key, public_key);
        crn::keys::identity::public_key master(master_key);

        crn::math::group G = user.pub();
        auto Gp = G.Gp(), Gp1 = G.Gp1();

        bool is_active = map["active"].as<bool>();

        std::size_t i = 0;
        crn::blocks::access last = crn::blocks::genesis(db, user.pub());
        bool forward = true;
        if(map.count("id")){
            std::string id = map["id"].as<std::string>();
            last = db.fetch(id);
            forward = false;
        }
        std::cout << "last.id: " << last.address().id() << std::endl;

        std::clock_t start = std::clock();

        while(i++ < limit){
            std::string address;
            if(forward){
                address = is_active
                                ? last.active().next(user.pub().G(),  last.address().id(), user.pri())
                                : last.passive().next(user.pub().G(), last.address().id(), user.pri());
            }else{
                // std::cout << "traversing backward" << std::endl;
                // std::cout << "last.active().forward(): " << last.active().forward() << std::endl;
                // std::cout << "last.passive().forward(): " << last.passive().forward() << std::endl;
                address = is_active
                                ? last.active().prev (user.pub().G(), last.address().active(),  last.passive().forward(), user.pri())
                                : last.passive().prev(user.pub().G(), last.address().passive(), last.active().forward(),  user.pri());
            }
            if(db.exists(address, forward)){
                std::string block_id = forward ? db.id(address) : address;
                crn::blocks::access current = db.fetch(block_id);
                CryptoPP::Integer x;
                if(is_active){
                    if(forward){
                        x = crn::utils::sha256::digest(Gp.Exponentiate(last.active().forward(),   user.pri().x()), CryptoPP::Integer::UNSIGNED);
                    }else{
                        x = crn::utils::sha256::digest(Gp.Exponentiate(current.active().forward(), user.pri().x()), CryptoPP::Integer::UNSIGNED);
                    }
                }else{
                    x = crn::utils::sha256::digest(Gp.Exponentiate(current.active().forward(), user.pri().x()), CryptoPP::Integer::UNSIGNED);
                }
                CryptoPP::Integer y = is_active ? current.address().passive() : current.address().active();
                if(forward) last = current;

                auto body = last.body();
                crn::math::free_coordinates random = body.random();
                auto line = crn::math::diophantine::interpolate(crn::math::free_coordinates{x, y}, random);
                CryptoPP::Integer delta = line.eval(body.gamma());
                std::string ciphertext = body.ciphertext();
                std::string plaintext;
                try{
                    plaintext = crn::utils::aes::decrypt(ciphertext, delta, CryptoPP::Integer::SIGNED);
                }catch(const CryptoPP::InvalidCiphertext&){
                    std::cout << "invalid ciphertext" << std::endl;
                    plaintext = "failed";
                }
                if(!forward) last = current;
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
        std::clock_t end = std::clock();
        long double duration = 1000.0 * (end - start) / CLOCKS_PER_SEC;
        std::cout << std::format("Retrieved {} entries in {}ms", i, duration) << std::endl;
        return 0;
    }else if(map["super"].as<bool>()){
        std::string access_key = map["access"].as<std::string>(),
                    view_key   = map["view"].as<std::string>(),
                    secret_key = map["secret"].as<std::string>();
        std::string id         = map["id"].as<std::string>();

        crn::keys::identity::private_key secret(secret_key);
        crn::keys::access_key access(access_key);
        crn::keys::view_key view(view_key);

        auto G = secret.G();
        auto Gp = G.Gp(), Gp1 = G.Gp1();

        crn::storage db;
        std::string plaintext;
        try{
            crn::blocks::access block = db.fetch(id);
            std::string ciphertext    = block.body().ciphertext();
            CryptoPP::Integer super   = block.body().super();
            CryptoPP::Integer gamma   = block.body().gamma();
            CryptoPP::Integer x_inv   = Gp1.MultiplicativeInverse(secret.x());
            CryptoPP::Integer suffix  = Gp.Exponentiate(Gp.Multiply(Gp.Exponentiate(access.secret(), x_inv), Gp.Exponentiate(view.secret(), x_inv)), gamma);
            CryptoPP::Integer pswdh   = Gp.Divide(super, suffix);

            // std::cout << "super: " << super << std::endl;
            // std::cout << "suffix: " << suffix << std::endl;
            std::cout << "password: " << pswdh << std::endl;

            CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
            pswdh.Encode(&digest[0], CryptoPP::SHA256::DIGESTSIZE);
            plaintext = crn::utils::aes::decrypt(ciphertext, digest);
        }catch(const CryptoPP::InvalidCiphertext&){
            std::cout << "invalid ciphertext" << std::endl;
        }
        std::cout << "message:  " << std::endl << plaintext << std::endl;
    }


    return 0;
}
