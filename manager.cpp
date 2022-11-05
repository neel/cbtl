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

int main(int argc, char** argv) {
    boost::program_options::options_description desc("CLI Frontend for Data Managers");
    desc.add_options()
        ("help,h", "prints this help message")
        ("public,p", boost::program_options::value<std::string>(), "path to the public key")
        ("secret,s", boost::program_options::value<std::string>(), "path to the secret key")
        ("access,a", boost::program_options::value<std::string>(), "path to the access key")
        ("master,m", boost::program_options::value<std::string>(), "path to the trusted server's public key")
        ("record,k", boost::program_options::value<std::uint64_t>(), "record number to access")
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

    std::uint64_t record = map["record"].as<std::uint64_t>();

    crn::storage db;

    crn::keys::identity::pair user(secret_key, public_key);
    crn::keys::identity::public_key master_pub(master_key);
    crn::keys::access_key access(access_key);

    crn::group G = user.pub();
    auto Gp = G.Gp(), Gp1 = G.Gp1();



    boost::asio::io_context io_context;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve("127.0.0.1", "9887");
    boost::asio::ip::tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints);

    crn::packets::request request = crn::packets::request::construct(db, user);
    nlohmann::json request_json = request;
    std::cout << ">> " << std::endl << request_json.dump(4) << std::endl;
    {
        crn::packets::envelop<crn::packets::request> envelop(crn::packets::type::request, request);
        envelop.write(socket);
    }
    using buffer_type = boost::array<std::uint8_t, sizeof(crn::packets::header)>;

    boost::system::error_code error;
    buffer_type buff;
    std::size_t len = socket.read_some(boost::asio::buffer(buff), error);
    if(!error){
        assert(len == buff.size());
        crn::packets::header header;
        std::copy_n(buff.cbegin(), len, reinterpret_cast<std::uint8_t*>(&header));
        header.size = ntohl(header.size);
        std::cout << "expecting data " << header.size << std::endl;

        boost::array<char, 4096> data;
        len = boost::asio::read(socket, boost::asio::buffer(data), boost::asio::transfer_exactly(header.size), error);
        std::string challenge_str;
        challenge_str.reserve(header.size);
        std::copy_n(data.cbegin(), header.size, std::back_inserter(challenge_str));
        nlohmann::json challenge_json = nlohmann::json::parse(challenge_str);
        std::cout << "<< " << std::endl << challenge_json.dump(4) << std::endl;
        crn::packets::challenge challenge = challenge_json;
        CryptoPP::Integer lambda = Gp.Divide(challenge.random, Gp.Exponentiate(master_pub.y(), user.pri().x()));

        crn::packets::response response;

        // construct response for the challenge
        CryptoPP::Integer x_inv = Gp1.MultiplicativeInverse(user.pri().x());
        response.c1 = Gp.Exponentiate(challenge.c1, x_inv);
        response.c2 = Gp.Exponentiate(challenge.c2, x_inv);
        response.c3 = Gp.Exponentiate(challenge.c3, x_inv);
        response.access = access.prepare(user.pri(), record, lambda);

        // send the challenge
        nlohmann::json response_json = challenge;
        std::cout << ">> " << std::endl << response_json.dump(4) << std::endl;
        {
            crn::packets::envelop<crn::packets::response> envelop(crn::packets::type::response, response);
            envelop.write(socket);
        }
    }

    return 0;
}
