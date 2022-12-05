// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_KEYS_PRIVATE_H
#define CRN_KEYS_PRIVATE_H

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

struct private_key: dsa<CryptoPP::DSA::PrivateKey, private_key>{
    using base_type = dsa<CryptoPP::DSA::PrivateKey, private_key>;

    inline explicit private_key(const std::string& path): base_type(path) { init(); }
    private_key(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size);
    private_key(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params);
    private_key(CryptoPP::AutoSeededRandomPool& rng, const private_key& other);
    private_key(const private_key& other) = default;

    static private_key from(const nlohmann::json& json);
    nlohmann::json json() const;

    bool initialize();
    inline const CryptoPP::Integer& x() const {return _x;}
    protected:
        explicit private_key(const nlohmann::json& json, bool);
    private:
        CryptoPP::Integer _x;
};

}
}
}

#endif // CRN_KEYS_PRIVATE_H
