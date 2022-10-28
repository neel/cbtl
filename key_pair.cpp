// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "key_pair.h"
#include <cassert>

crn::key_pair::key_pair(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size){
    bool success = false;
    while(!success){
        _secret.GenerateRandomWithKeySize(rng, key_size);
        success = participant_private::init();
    }
    _public.AssignFrom(_secret);
    participant_public::init();
}

crn::key_pair::key_pair(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params){
    bool success = false;
    while(!success){
        _secret.GenerateRandom(rng, params);
        success = participant_private::init();
    }
    _public.AssignFrom(_secret);
    participant_public::init();
}

crn::key_pair::key_pair(const std::string& public_path, const std::string& private_path){
    participant_public::load(public_path);
    participant_private::load(private_path);
    assert( Gp().Exponentiate(g(), x()) == y() );
}


void crn::key_pair::save(const std::string& name){
    participant_public::save(name+".pub");
    participant_private::save(name);
}
