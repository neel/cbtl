// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_BLOCKS_CONTENTS_H
#define CRN_BLOCKS_CONTENTS_H

#include "crn/math/line.h"
#include <cryptopp/integer.h>
#include <string>
#include "crn/keys.h"
#include "crn/blocks/addresses.h"

namespace crn{
namespace blocks{

struct contents{
    contents(const crn::keys::identity::public_key& pub, const CryptoPP::Integer& random, const CryptoPP::Integer& active_req, const crn::blocks::addresses& addr, const std::string& msg, const CryptoPP::Integer& super);
    inline const crn::math::free_coordinates& random() const { return _random; }
    inline const CryptoPP::Integer& gamma() const { return _gamma; }
    inline const std::string& ciphertext() const { return _message; }
    inline const CryptoPP::Integer& super() const { return _super; }
    private:
        friend class nlohmann::adl_serializer<crn::blocks::contents>;
        contents(const crn::math::free_coordinates& random, const CryptoPP::Integer& gamma, const CryptoPP::Integer& super, const std::string& msg);
        void compute(const crn::math::free_coordinates& p1, const crn::math::free_coordinates& p2, const std::string& msg, const crn::math::group& G, const CryptoPP::Integer& super);
    private:
        crn::math::free_coordinates  _random;
        CryptoPP::Integer      _gamma;
        CryptoPP::Integer      _super;
        std::string            _message;
};

}
}

#endif // CRN_BLOCKS_CONTENTS_H
