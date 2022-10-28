// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef PARTICIPANT_PRIVATE_H
#define PARTICIPANT_PRIVATE_H

#include "group.h"
#include <cryptopp/dsa.h>
#include <cryptopp/files.h>

namespace crn{

/**
 * @brief the private information of a participant
 */
struct participant_private: virtual group{
    protected:
        inline participant_private(){}
        inline participant_private(const CryptoPP::DSA::PrivateKey& sk): _secret(sk){ init(); }
        bool init();
    protected:
        CryptoPP::DSA::PrivateKey _secret;
    private:
        CryptoPP::Integer _x;
    public:
        participant_private(const participant_private&) = default;
        inline const CryptoPP::Integer& x() const {return _x;}
        unsigned long load(const std::string& path);
        unsigned long save(const std::string& path);
        /**
         * Calculates $r^{x}$
         */
        inline CryptoPP::Integer raise_x(CryptoPP::Integer r) const { return G(_p).Exponentiate(r, _x); }
        CryptoPP::Integer raise_x(CryptoPP::Integer r, std::initializer_list<CryptoPP::Integer> vs) const;
};

}

#endif // PARTICIPANT_PRIVATE_H
