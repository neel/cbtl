// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef PACKETS_H
#define PACKETS_H

#include <iostream>
#include <cstdint>
#include <cryptopp/integer.h>
#include <nlohmann/json.hpp>
#include <arpa/inet.h>

namespace crn{
namespace packets{

enum class type{
    unknown,
    request,
    challenge,
    response
};

struct header{
    std::uint8_t  type;
    std::uint32_t size;

    inline header(): header(type::unknown) {}
    explicit inline header(enum type t): type((std::uint8_t) t), size(0) {}
};

struct request{
    std::string last;
    CryptoPP::Integer token;
};

void to_json(nlohmann::json& j, const request& q);
void from_json(const nlohmann::json& j, request& q);

struct challenge{
    CryptoPP::Integer c1;
    CryptoPP::Integer c2;
    CryptoPP::Integer c3;
};

void to_json(nlohmann::json& j, const challenge& c);
void from_json(const nlohmann::json& j, challenge& c);

typedef challenge response;

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
    template <typename IteratorT>
    void copy(IteratorT begin){
        std::uint8_t* h = reinterpret_cast<std::uint8_t*>(&_head);
        IteratorT it = std::copy_n(h, sizeof(_head), begin);
        std::copy(_serialized.cbegin(), _serialized.cend(), it);
    }
};

}
}


#endif // PACKETS_H
