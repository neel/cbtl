#include <iostream>
#include <array>
#include <string>
#include <zmq.hpp>

#include "key_pair.h"
#include "utils.h"

#include <boost/program_options.hpp>

#include <cryptopp/integer.h>

#include <nlohmann/json.hpp>

#include <db_cxx.h>

int main(int argc, char** argv) {
    boost::program_options::options_description desc("CLI Frontend for the Trusted Server");
    desc.add_options()
        ("help,h", "prints this help message")
        ("public,p", boost::program_options::value<std::string>(), "path to the public key")
        ("secret,s", boost::program_options::value<std::string>(), "path to the secret key")
        ;

    boost::program_options::variables_map map;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), map);
    boost::program_options::notify(map);

    if(map.count("help") || !map.count("public") || !map.count("secret")){
        std::cout << desc << std::endl;
        return 1;
    }

    std::string public_key = map["public"].as<std::string>(),
                secret_key = map["secret"].as<std::string>();

    crn::key_pair keys(public_key, secret_key);

    zmq::context_t context (2);
    zmq::socket_t socket (context, zmq::socket_type::rep);
    socket.bind ("tcp://*:5555");
    while (true) {
        zmq::message_t request;

        //  Wait for next request from client
        auto res = socket.recv(request, zmq::recv_flags::none);
        if(res){
            nlohmann::json request_json = nlohmann::json::parse(request.str());
            std::cout << "Received " << request << std::endl;
            std::string last_str    = request_json["previous"].get<std::string>();
            CryptoPP::Integer last  = crn::utils::dHex(last_str);
            CryptoPP::Integer token = crn::utils::dHex(request_json["token"].get<std::string>());
            Db db(NULL, 0);
            try{
                db.open(NULL /* Transaction pointer */,  "blockchain.db", NULL /*Optional logical database name*/ , DB_BTREE, DB_CREATE, 0); // File mode (using defaults)
                Dbt key((void*) last_str.c_str(), last_str.size()), value;
                int ret = db.get(NULL, &key, &value, 0);
                if(ret == DB_NOTFOUND){
                    std::cout << "not found: " << last_str << std::endl;
                }else{
                    // verify
                    std::string json_str((const char*) value.get_data(), value.get_size());
                    nlohmann::json json = nlohmann::json::parse(json_str);
                    CryptoPP::Integer last_checksum = crn::utils::dHex(json["checksum"].get<std::string>());
                    if( crn::utils::sha512(keys.private_key().raise_x(token)) != last_checksum ){
                        std::cout << "bad request: " << last_checksum << std::endl;
                    }else{

                    }
                }
                db.sync(0);
                db.close(0);
            }catch(DbException& e){
                std::cout << e.what() << std::endl;
            }catch(std::exception& e){
                std::cout << e.what() << std::endl;
            }
        }

        //  Send reply back to client
        zmq::message_t reply (5);
        memcpy(reply.data (), "World", 5);
        socket.send (reply, zmq::send_flags::none);
    }
    return 0;
}
