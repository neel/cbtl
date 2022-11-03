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

    crn::storage db;

    crn::identity::user user(db, secret_key, public_key);
    user.init();

    crn::group G = user.pub();
    auto Gp = G.Gp(), Gp1 = G.Gp1();

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve("127.0.0.1", "9887");
    boost::asio::ip::tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints);

    crn::packets::request request = user.request();
    nlohmann::json request_json = request;
    std::cout << ">> " << std::endl << request_json.dump(4) << std::endl;
    {
        crn::packets::envelop<crn::packets::request> envelop(crn::packets::type::request, request);
        std::vector<std::uint8_t> dbuffer;
        envelop.copy(std::back_inserter(dbuffer));
        boost::asio::write(socket, boost::asio::buffer(dbuffer.data(), dbuffer.size()));
        dbuffer.clear();
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

        // construct response for the challenge
        CryptoPP::Integer x_inv = Gp1.MultiplicativeInverse(user.pri().x());
        challenge.c1 = Gp.Exponentiate(challenge.c1, x_inv);
        challenge.c2 = Gp.Exponentiate(challenge.c2, x_inv);
        challenge.c3 = Gp.Exponentiate(challenge.c3, x_inv);

        // send the challenge
        nlohmann::json response_json = challenge;
        std::cout << ">> " << std::endl << response_json.dump(4) << std::endl;
        {
            crn::packets::envelop<crn::packets::response> envelop(crn::packets::type::response, challenge);
            std::vector<std::uint8_t> dbuffer;
            envelop.copy(std::back_inserter(dbuffer));
            boost::asio::write(socket, boost::asio::buffer(dbuffer.data(), dbuffer.size()));
        }
    }

    return 0;
}
