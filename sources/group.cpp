// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/group.h"
#include <cryptopp/argnames.h>

CryptoPP::AlgorithmParameters crn::group::params() const {
    return CryptoPP::MakeParameters
        (CryptoPP::Name::Modulus(), _p)
        (CryptoPP::Name::SubgroupOrder(), _q)
        (CryptoPP::Name::SubgroupGenerator(), _g);
}

CryptoPP::Integer crn::group::random(CryptoPP::AutoSeededRandomPool& rng, bool invertible) const {
    CryptoPP::Integer r(rng, 2, _p-1);
    while(true){
        CryptoPP::Integer r_inverse = Gp1().MultiplicativeInverse(r);
        if(invertible && r_inverse != 0 && Gp().Exponentiate(Gp().Exponentiate(_g, r_inverse), r) == _g){
            break; // r is OK
        }else if (!invertible && r_inverse == 0) {
            break; // r is OK
        }else{
            r = CryptoPP::Integer(rng, 2, _p-2);
        }
    }

    return r;
}
