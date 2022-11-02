// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef PARTICIPANT_PUBLIC_H
#define PARTICIPANT_PUBLIC_H

#include "group.h"
#include <cryptopp/dsa.h>

namespace crn{

/**
 * @brief The public information of a participant
 */
struct participant_public: virtual group{
    protected:
        inline participant_public(){}
        inline participant_public(const CryptoPP::DSA::PublicKey& pk): _public(pk){ init(); }
        void init();
    protected:
        CryptoPP::DSA::PublicKey _public;
    private:
        CryptoPP::Integer _y;
    public:
        participant_public(const participant_public&) = default;
        inline const CryptoPP::Integer& y() const {return _y;}
        unsigned long load(const std::string& path);
        unsigned long save(const std::string& path) const;
        /**
         * Calculates $y^{r}$
         */
        inline CryptoPP::Integer raise(CryptoPP::Integer r) const { return Gp().Exponentiate(_y, r); }
        CryptoPP::Integer raise(std::initializer_list<CryptoPP::Integer> vs) const;
};

}

#endif // PARTICIPANT_PUBLIC_H
