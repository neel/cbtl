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

boost::system::error_code receive(boost::asio::ip::tcp::socket& socket, nlohmann::json& json){
    using buffer_type = boost::array<std::uint8_t, sizeof(crn::packets::header)>;
    buffer_type buff;
    boost::system::error_code error;
    std::size_t len = socket.read_some(boost::asio::buffer(buff), error);
    if(!error){
        assert(len == buff.size());
        crn::packets::header header;
        std::copy_n(buff.cbegin(), len, reinterpret_cast<std::uint8_t*>(&header));
        header.size = ntohl(header.size);
        std::cout << "expecting data " << header.size << std::endl;

        constexpr std::uint32_t buffer_size = 2048;
        boost::array<char, buffer_size> data;
        std::string data_str;
        std::uint32_t pending = header.size;
        while(pending > 0){
            std::fill(data.begin(), data.end(), 0);
            std::size_t bytes_read = boost::asio::read(socket, boost::asio::buffer(data), boost::asio::transfer_exactly(std::min(buffer_size, pending)), error);
            pending = pending - bytes_read;
            std::copy_n(data.cbegin(), bytes_read, std::back_inserter(data_str));
        }
        try{
            json = nlohmann::json::parse(data_str);
        }catch(const nlohmann::json::parse_error& error){
            std::cout << "JSON parsing error: " << error.what() << std::endl;
            std::cout << "bytes read: " << header.size << std::endl;
            std::cout << "data: " << data_str << std::endl;
        }
    }
    return error;
}

int main(int argc, char** argv) {
    boost::program_options::options_description desc("CLI Frontend for Data Managers");
    desc.add_options()
        ("help,h",    "prints this help message")
        ("public,p",  boost::program_options::value<std::string>(),   "path to the public key")
        ("secret,s",  boost::program_options::value<std::string>(),   "path to the secret key")
        ("access,a",  boost::program_options::value<std::string>(),   "path to the access key")
        ("master,m",  boost::program_options::value<std::string>(),   "path to the trusted server's public key")
        ("anchor,A",  boost::program_options::value<std::string>(),   "record anchor to identify")
        ("patient,P", boost::program_options::value<std::string>(),    "public key of the patient who's record to access")
        ("insert,I",  "records to insert for patient identified by -P")
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
                access_key = map["access"].as<std::string>(),
                master_key = map["master"].as<std::string>();

    crn::storage db;

    crn::keys::identity::pair user(secret_key, public_key);
    crn::keys::identity::public_key master_pub(master_key);
    crn::keys::access_key access(access_key);

    crn::math::group G = user.pub();
    auto Gp = G.Gp(), Gp1 = G.Gp1();

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve("127.0.0.1", "9887");
    boost::asio::ip::tcp::socket socket(io_context);
    try{
        boost::asio::connect(socket, endpoints);
    }catch(const boost::system::system_error& error){
        std::cout << "Failed to connect to the Trusted Server " << std::endl << error.what() << std::endl;
        return 1;
    }

    crn::packets::request request = crn::packets::request::construct(db, user);
    nlohmann::json request_json = request;
    std::cout << ">> " << std::endl << request_json.dump(4) << std::endl;
    {
        crn::packets::envelop<crn::packets::request> envelop(crn::packets::type::request, request);
        envelop.write(socket);
    }
    using buffer_type = boost::array<std::uint8_t, sizeof(crn::packets::header)>;

    nlohmann::json challenge_json;
    boost::system::error_code error = receive(socket, challenge_json);
    if(!error){
        std::cout << "<< " << std::endl << challenge_json.dump(4) << std::endl;
        crn::packets::challenge challenge = challenge_json;
        CryptoPP::Integer lambda = Gp.Divide(challenge.random, Gp.Exponentiate(master_pub.y(), user.pri().x()));

        if(map.count("anchor")){
            std::string anchor = map["anchor"].as<std::string>();
            auto action = crn::packets::action<crn::packets::actions::identify>(anchor);
            auto response = crn::packets::respond(action, user.pri(), access, lambda);

            // send the challenge
            nlohmann::json response_json = challenge;
            std::cout << ">> " << std::endl << response_json.dump(4) << std::endl;
            {
                crn::packets::envelop<crn::packets::response<crn::packets::action_data<crn::packets::actions::identify>>> envelop(crn::packets::type::response, response);
                envelop.write(socket);
            }
        }else if(map.count("insert")){
            std::string patient_pub_str = map["patient"].as<std::string>();
            crn::keys::identity::public_key patient_pub(patient_pub_str);
            auto action = crn::packets::action<crn::packets::actions::insert>(patient_pub);
            while(true){
                std::string line;
                std::getline(std::cin, line);
                if(line.empty()){
                    break;
                }else{
                    action.add(line);
                }
            }
            std::cout << action.count() << " cases in action" << std::endl;
            auto response = crn::packets::respond(action, user.pri(), access, lambda);

            // send the challenge
            nlohmann::json response_json = challenge;
            std::cout << ">> " << std::endl << response_json.dump(4) << std::endl;
            {
                crn::packets::envelop<crn::packets::response<crn::packets::action_data<crn::packets::actions::insert>>> envelop(crn::packets::type::response, response);
                envelop.write(socket);
            }
        }else if(map.count("patient")){
            std::string patient_pub_str = map["patient"].as<std::string>();
            crn::keys::identity::public_key patient_pub(patient_pub_str);
            auto action = crn::packets::action<crn::packets::actions::fetch>(patient_pub);
            auto response = crn::packets::respond(action, user.pri(), access, lambda);

            // send the challenge
            nlohmann::json response_json = challenge;
            std::cout << ">> " << std::endl << response_json.dump(4) << std::endl;
            {
                crn::packets::envelop<crn::packets::response<crn::packets::action_data<crn::packets::actions::fetch>>> envelop(crn::packets::type::response, response);
                envelop.write(socket);
            }
        }

        nlohmann::json result_json;
        error = receive(socket, result_json);
        if(!error){
            std::cout << "<< " << std::endl << result_json.dump(4) << std::endl;
        }
    }

    return 0;
}
