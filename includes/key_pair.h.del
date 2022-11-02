// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef KEY_PAIR_H
#define KEY_PAIR_H

#include "participant_public.h"
#include "participant_private.h"

namespace crn{

struct key_pair: participant_public, participant_private{
    key_pair(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size);
    key_pair(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params);
    inline key_pair(CryptoPP::AutoSeededRandomPool& rng, const participant_public& pk): key_pair(rng, pk.params()){}
    key_pair(const std::string& public_path, const std::string& private_path);

    inline const participant_public& public_key() const { return *this; }
    inline const participant_private& private_key() const { return *this; }
    void save(const std::string& name);
};


}

#endif // KEY_PAIR_H
