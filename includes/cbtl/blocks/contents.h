// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_BLOCKS_CONTENTS_H
#define cbtl_BLOCKS_CONTENTS_H

#include "cbtl/math/diophantine.h"
#include <cryptopp/integer.h>
#include <string>
#include "cbtl/keys.h"
#include "cbtl/blocks/addresses.h"

namespace cbtl{
namespace blocks{

struct contents{
    contents(const cbtl::keys::identity::public_key& pub, const CryptoPP::Integer& ru, const CryptoPP::Integer& active_req, const cbtl::blocks::addresses& addr, const std::string& msg, const CryptoPP::Integer& super);
    inline const cbtl::math::free_coordinates& random() const { return _random; }
    inline const CryptoPP::Integer& gamma() const { return _gamma; }
    inline const std::string& ciphertext() const { return _message; }
    inline const CryptoPP::Integer& super() const { return _super; }
    private:
        friend class nlohmann::adl_serializer<cbtl::blocks::contents>;
        contents(const cbtl::math::free_coordinates& random, const CryptoPP::Integer& gamma, const CryptoPP::Integer& super, const std::string& msg);
        void compute(const cbtl::math::free_coordinates& p1, const cbtl::math::free_coordinates& p2, const std::string& msg, const cbtl::math::group& G, const CryptoPP::Integer& super);
    private:
        cbtl::math::free_coordinates  _random;
        CryptoPP::Integer      _gamma;
        CryptoPP::Integer      _super;
        std::string            _message;
};

}
}

#endif // cbtl_BLOCKS_CONTENTS_H
