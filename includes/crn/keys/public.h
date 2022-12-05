// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_KEYS_PUBLIC_H
#define CRN_KEYS_PUBLIC_H

#include "crn/keys/dsa.h"
#include "crn/math/group.h"
#include <cryptopp/dsa.h>
#include <cryptopp/files.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>

namespace crn{
namespace keys{
namespace identity{

struct private_key;

struct public_key: dsa<CryptoPP::DSA::PublicKey, public_key>{
    using base_type = dsa<CryptoPP::DSA::PublicKey, public_key>;

    inline explicit public_key(const std::string& path): base_type(path) { init(); }
    public_key(const private_key& pk);
    public_key(const public_key& other) = default;
    public_key(const CryptoPP::Integer& y, const crn::math::group& other);

    static public_key from(const nlohmann::json& json);
    nlohmann::json json() const;

    bool initialize();
    const CryptoPP::Integer& y() const {return _y;}

    std::string genesis_id() const;
    protected:
        explicit public_key(const nlohmann::json& json, bool);
    private:
        CryptoPP::Integer _y;
};

}
}
}

#endif // CRN_KEYS_PUBLIC_H
