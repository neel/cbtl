// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef GENESIS_BLOCK_H
#define GENESIS_BLOCK_H

#include <nlohmann/json.hpp>
#include "participant_private.h"
#include "participant_public.h"

namespace crn{

struct genesis_block{
    inline genesis_block(CryptoPP::AutoSeededRandomPool& rng, const participant_public& p, const participant_private& m): _public(p), _master(m), _r(p.random(rng, false)), _rho(p.random(rng, true)) { }
    genesis_block(const genesis_block&) = default;

    std::string hash() const;
    CryptoPP::Integer active() const;
    std::pair<CryptoPP::Integer, CryptoPP::Integer> passive() const;
    std::string checksum() const;

    private:
        participant_public  _public;
        participant_private _master;
        CryptoPP::Integer   _r, _rho;
};

void to_json(nlohmann::json& j, const genesis_block& genesis);

}

#endif // GENESIS_BLOCK_H
