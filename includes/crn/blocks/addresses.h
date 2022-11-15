// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_BLOCKS_ADDRESSES_H
#define CRN_BLOCKS_ADDRESSES_H

#include <cryptopp/integer.h>
#include <nlohmann/json.hpp>
#include <string>

namespace crn{
namespace blocks{

struct access;

class addresses{
    friend struct crn::blocks::access;

    CryptoPP::Integer _active;
    CryptoPP::Integer _passive;
    CryptoPP::Integer _id;

    friend class nlohmann::adl_serializer<crn::blocks::addresses>;
    addresses(const CryptoPP::Integer& active, const CryptoPP::Integer& passive);
    public:
        addresses(const addresses& other) = default;
    public:
        inline const CryptoPP::Integer& active() const { return _active; }
        inline const CryptoPP::Integer& passive() const { return _passive; }
        inline const CryptoPP::Integer id() const { return _id; }
        std::string hash() const;
};

}
}

#endif // CRN_BLOCKS_ADDRESSES_H
