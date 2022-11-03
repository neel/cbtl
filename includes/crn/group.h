// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_GROUP_H
#define CRN_GROUP_H

#include <cryptopp/integer.h>
#include <cryptopp/modarith.h>
#include <cryptopp/osrng.h>

namespace crn{

/**
 * @brief the algebric group
 */
struct group{
    inline const CryptoPP::Integer& g() const {return _g;}
    inline const CryptoPP::Integer& p() const {return _p;}
    inline const CryptoPP::Integer& q() const {return _q;}
    protected:
        CryptoPP::Integer _g;
        CryptoPP::Integer _p;
        CryptoPP::Integer _q;
    public:
        group() = default;
        group(const group&) = default;
        CryptoPP::AlgorithmParameters params() const;
        inline CryptoPP::ModularArithmetic Gp() const { return CryptoPP::ModularArithmetic(_p);}
        inline CryptoPP::ModularArithmetic Gp1() const { return CryptoPP::ModularArithmetic(_p -1);}
        CryptoPP::Integer random(CryptoPP::AutoSeededRandomPool& rng, bool invertible = true) const;

};

inline CryptoPP::ModularArithmetic G(const CryptoPP::Integer& p){ return CryptoPP::ModularArithmetic(p); }

}

#endif // CRN_GROUP_H
