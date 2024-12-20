// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_PACKETS_H
#define cbtl_PACKETS_H

#include <iostream>
#include <cstdint>
#include <cryptopp/integer.h>
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include "cbtl/keys/public.h"
#include "cbtl/keys/private.h"
#include "cbtl/keys/access.h"
#include "cbtl/utils.h"

namespace cbtl{

namespace blocks{
    struct access;
}

namespace keys{
namespace identity{
    struct public_key;
    struct private_key;
    struct pair;
}
}

struct storage;

namespace packets{

enum class type{
    unknown,
    request,
    challenge,
    response,
    result
};

enum class actions{
    none,
    identify,
    fetch,
    insert,
    remove
};

template <actions A>
class action_data;

// void to_json(nlohmann::json& j, const action_data<actions::identify>& q);
// void from_json(const nlohmann::json& j, action_data<actions::identify>& q);

template <>
class action_data<actions::identify> {
    std::string _anchor;

    friend void from_json(const nlohmann::json& j, action_data<actions::identify>& q);
    public:
        action_data(const std::string& anchor): _anchor(anchor) {}
        const std::string& anchor() const { return _anchor; }
};

// void to_json(nlohmann::json& j, const action_data<actions::fetch>& q);
// void from_json(const nlohmann::json& j, action_data<actions::fetch>& q);

template <>
class action_data<actions::fetch> {
    CryptoPP::Integer _y;

    friend void from_json(const nlohmann::json& j, action_data<actions::fetch>& q);
    public:
        action_data(const CryptoPP::Integer& y): _y(y) {}
        action_data(const cbtl::keys::identity::public_key& pub): _y(pub.y()) {}
        const CryptoPP::Integer& y() const { return _y; }
};

// void to_json(nlohmann::json& j, const action_data<actions::insert>& q);
// void from_json(const nlohmann::json& j, action_data<actions::insert>& q);

template <>
class action_data<actions::insert> {
    CryptoPP::Integer _y;
    public:
        using data = std::string;
        using collection = std::vector<data>;
    private:
        collection _cases;

    friend void from_json(const nlohmann::json& j, action_data<actions::insert>& q);
    public:
        action_data(const CryptoPP::Integer& y): _y(y) {}
        action_data(const cbtl::keys::identity::public_key& pub): _y(pub.y()) {}
        const CryptoPP::Integer& y() const { return _y; }
        collection::const_iterator begin() const { return _cases.begin(); }
        collection::const_iterator end() const { return _cases.end(); }
        void add(const data& d) { _cases.push_back(d); }
        std::size_t count() const { return _cases.size(); }
};


// void to_json(nlohmann::json& j, const action_data<actions::remove>& q);
// void from_json(const nlohmann::json& j, action_data<actions::remove>& q);

template <>
class action_data<actions::remove> {
    std::string _anchor;

    friend void from_json(const nlohmann::json& j, action_data<actions::remove>& q);
    public:
        action_data(const std::string& anchor): _anchor(anchor) {}
        const std::string& anchor() const { return _anchor; }
};

template <actions A, typename... Args>
action_data<A> action(const Args&... args){
    return action_data<A>(args...);
}

struct header{
    std::uint8_t  type;
    std::uint32_t size;

    inline header(): header(type::unknown) {}
    explicit inline header(enum type t): type((std::uint8_t) t), size(0) {}
};

struct request{
    std::string       last;     // \tau_{u}^{(0)}
    CryptoPP::Integer y;        // g^{\pi_{u}}
    CryptoPP::Integer token;    // g^{\pi_{u} r_{u}^{(0)}}

    static request construct(const cbtl::blocks::access& block, const cbtl::keys::identity::pair& keys);
    static request construct(cbtl::storage& db, const cbtl::keys::identity::pair& keys);
};

void to_json(nlohmann::json& j, const request& q);
void from_json(const nlohmann::json& j, request& q);

struct challenge{
    CryptoPP::Integer random;
};

void to_json(nlohmann::json& j, const challenge& c);
void from_json(const nlohmann::json& j, challenge& c);

struct basic_response{
    CryptoPP::Integer _access;

    const CryptoPP::Integer& access() const { return _access; }

    basic_response(const cbtl::keys::identity::private_key& pri, const cbtl::keys::access_key& access, const CryptoPP::Integer& lambda) {
        auto Gp = pri.G().Gp(), Gp1 = pri.G().Gp1();
        CryptoPP::Integer x     = pri.x();
        CryptoPP::Integer x_inv = Gp1.MultiplicativeInverse(pri.x());
        _access = access.prepare(pri, lambda);
    }
    basic_response(const CryptoPP::Integer& access): _access(access) { }
};

template <typename ActionT>
struct response: public basic_response{
    response(const ActionT& action, const cbtl::keys::identity::private_key& pri, const cbtl::keys::access_key& access, const CryptoPP::Integer& lambda): basic_response(pri, access, lambda), _action(action) { }
    const ActionT& action() const { return _action; }

    friend struct nlohmann::adl_serializer<cbtl::packets::response<ActionT>>;
    private:
        response(const ActionT& action, const CryptoPP::Integer& access): basic_response(access), _action(action) { }
    private:
        ActionT _action;
};

template <typename ActionT>
response<ActionT> respond(const ActionT& action, const cbtl::keys::identity::private_key& pri, const cbtl::keys::access_key& access, const CryptoPP::Integer& lambda){
    return response<ActionT>(action, pri, access, lambda);
}

// void to_json(nlohmann::json& j, const response& res);
// void from_json(const nlohmann::json& j, response& res);

template <typename DataT>
struct envelop{
    header _head;
    DataT  _data;
    std::string _serialized;

    explicit envelop(enum type t, const DataT& d): _head(t), _data(d) {
        _serialized = serialize();
        _head.size = htonl(_serialized.size());
    }
    std::string serialize() const {
        nlohmann::json data = _data;
        return data.dump();
    }
    const DataT& data() const { return _data; }
    template <typename IteratorT>
    void copy(IteratorT begin){
        std::uint8_t* h = reinterpret_cast<std::uint8_t*>(&_head);
        IteratorT it = std::copy_n(h, sizeof(_head), begin);
        std::copy(_serialized.cbegin(), _serialized.cend(), it);
    }
    template <typename SocketT>
    std::size_t write(SocketT& socket){
        std::vector<std::uint8_t> buffer;
        copy(std::back_inserter(buffer));
        std::size_t written = boost::asio::write(socket, boost::asio::buffer(buffer.data(), buffer.size()));
        buffer.clear();
        return written;
    }
};

struct result{
   std::uint32_t error;
   std::string reason;
   CryptoPP::Integer passive;
   CryptoPP::Integer active;
   std::string       block;
   nlohmann::json    aux;

   static result failure(std::uint32_t code, const std::string& reason);
   static result success(const CryptoPP::Integer& active, const CryptoPP::Integer& passive, const std::string& block, const nlohmann::json& aux);
   // static result success(const CryptoPP::Integer& passive, const std::string& block, const nlohmann::json& aux);
};

void to_json(nlohmann::json& j, const result& res);
void from_json(const nlohmann::json& j, result& res);

}
}

namespace nlohmann {
    template <>
    struct adl_serializer<cbtl::packets::action_data<cbtl::packets::actions::identify>>{
        static cbtl::packets::action_data<cbtl::packets::actions::identify> from_json(const json& j) {
            std::string anchor = j["anchor"].get<std::string>();
            return cbtl::packets::action_data<cbtl::packets::actions::identify>(anchor);
        }
        static void to_json(json& j, const cbtl::packets::action_data<cbtl::packets::actions::identify>& res) {
            j = nlohmann::json {
                {"type", static_cast<std::uint32_t>(cbtl::packets::actions::identify)},
                {"anchor", res.anchor()}
            };
        }
    };

    template <>
    struct adl_serializer<cbtl::packets::action_data<cbtl::packets::actions::fetch>>{
        static cbtl::packets::action_data<cbtl::packets::actions::fetch> from_json(const json& j) {
            CryptoPP::Integer y = cbtl::utils::hex::decode(j["y"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            return cbtl::packets::action_data<cbtl::packets::actions::fetch>(y);
        }
        static void to_json(json& j, const cbtl::packets::action_data<cbtl::packets::actions::fetch>& res) {
            j = nlohmann::json {
                {"type", static_cast<std::uint32_t>(cbtl::packets::actions::fetch)},
                {"y", cbtl::utils::hex::encode(res.y(), CryptoPP::Integer::UNSIGNED)}
            };
        }
    };

    template <>
    struct adl_serializer<cbtl::packets::action_data<cbtl::packets::actions::insert>>{
        static cbtl::packets::action_data<cbtl::packets::actions::insert> from_json(const json& j) {
            CryptoPP::Integer y = cbtl::utils::hex::decode(j["y"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            cbtl::packets::action_data<cbtl::packets::actions::insert> action(y);
            for(cbtl::packets::action_data<cbtl::packets::actions::insert>::data d: j["cases"]){
                action.add(d);
            }
            return action;
        }
        static void to_json(json& j, const cbtl::packets::action_data<cbtl::packets::actions::insert>& res) {
            nlohmann::json cases = nlohmann::json::array();
            for(auto i = res.begin(); i != res.end(); ++i){
                const cbtl::packets::action_data<cbtl::packets::actions::insert>::data& d = *i;
                cases.push_back(d);
            }
            j = nlohmann::json {
                {"type", static_cast<std::uint32_t>(cbtl::packets::actions::insert)},
                {"y", cbtl::utils::hex::encode(res.y(), CryptoPP::Integer::UNSIGNED)},
                {"cases", cases}
            };
        }
    };

    template <>
    struct adl_serializer<cbtl::packets::action_data<cbtl::packets::actions::remove>>{
        static cbtl::packets::action_data<cbtl::packets::actions::remove> from_json(const json& j) {
            std::string anchor = j["anchor"].get<std::string>();
            return cbtl::packets::action_data<cbtl::packets::actions::remove>(anchor);
        }
        static void to_json(json& j, const cbtl::packets::action_data<cbtl::packets::actions::remove>& res) {
            j = nlohmann::json {
                {"type", static_cast<std::uint32_t>(cbtl::packets::actions::remove)},
                {"anchor", res.anchor()}
            };
        }
    };

    template <typename ActionT>
    struct adl_serializer<cbtl::packets::response<ActionT>> {
        static cbtl::packets::response<ActionT> from_json(const json& j) {
            ActionT action = j["action"];
            CryptoPP::Integer access = cbtl::utils::hex::decode(j["access"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            return cbtl::packets::response<ActionT>(action, access);
        }

        static void to_json(json& j, const cbtl::packets::response<ActionT>& res) {
            j = nlohmann::json {
                {"action",  res.action()},
                {"access", cbtl::utils::hex::encode(res.access(), CryptoPP::Integer::UNSIGNED)}
            };
        }
    };

}


#endif // cbtl_PACKETS_H
