// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_KEYS_PAIR_H
#define CRN_KEYS_PAIR_H

#include "crn/keys/dsa.h"
#include "crn/keys/public.h"
#include "crn/keys/private.h"
#include "crn/math/group.h"
#include <cryptopp/dsa.h>
#include <cryptopp/files.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>

namespace crn{
namespace keys{
namespace identity{

struct pair{
    pair(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size);
    pair(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params);
    pair(CryptoPP::AutoSeededRandomPool& rng, const private_key& other);
    pair(const std::string& private_path, const std::string& public_path);

    inline const public_key& pub() const { return _public; }
    inline const private_key& pri() const { return _private; }
    inline public_key& pub() { return _public; }
    inline private_key& pri() { return _private; }

    bool init();

    void save(const std::string& name) const;
    private:
        private_key _private;
        public_key  _public;
};

}
}
}

#endif // CRN_KEYS_PAIR_H
