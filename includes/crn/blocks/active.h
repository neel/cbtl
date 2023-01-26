// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_BLOCKS_ACTIVE_H
#define CRN_BLOCKS_ACTIVE_H

#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>
#include "crn/math/group.h"
#include "crn/utils.h"
#include "crn/keys.h"
#include "crn/blocks/params.h"

namespace crn{

namespace packets{
    struct challenge;
}

namespace blocks{
namespace parts{

struct active{
    active() = delete;
    active(const active& other) = default;
    inline CryptoPP::Integer backward() const { return _backward; }
    inline CryptoPP::Integer forward() const { return _forward; }
    inline CryptoPP::Integer checksum() const { return _checksum; }

    /**
     * @brief Calculate the next block's $c_{u}$ using the current block's id and active user's secret.
     */
    std::string next(const crn::math::group& G, const CryptoPP::Integer& id, const crn::keys::identity::private_key& pri) const;
    /**
     * @brief Calculate the previous block's $\tau$ using the current block's id and active user's secret.
     */
    std::string prev(const crn::math::group& G, const CryptoPP::Integer& address, const CryptoPP::Integer& passive_forward, const crn::keys::identity::private_key& pri) const;

    static active construct(const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& master, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv, const CryptoPP::Integer& gru_last);
    static active construct(const crn::math::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& w, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv, const CryptoPP::Integer& gru_last);
    static active construct(const crn::blocks::params::active& p, const crn::keys::identity::private_key& master, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv);

    bool verify(const CryptoPP::Integer& token, const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& master) const;
    bool verify(const crn::math::group& G, const CryptoPP::Integer& token, const CryptoPP::Integer& y, const CryptoPP::Integer& w) const;
    crn::packets::challenge challenge(CryptoPP::AutoSeededRandomPool& rng, const crn::math::group& G, const CryptoPP::Integer& token, const CryptoPP::Integer& rho, const CryptoPP::Integer& lambda) const;

    protected:
        friend class nlohmann::adl_serializer<crn::blocks::parts::active>;
        /**
         * @brief constructs the active part of a generic access block
         * Trapdoor t = $g^{\pi_{u}^{-1} r_{u}^{(0)}}$ is provided by the caller which is expected to be verified before calling the constructor.
         * Expects a non-invertible random number r
         */
        active(const CryptoPP::Integer& forward, const CryptoPP::Integer& backward, const CryptoPP::Integer& checksum);
    private:
        CryptoPP::Integer _forward;
        CryptoPP::Integer _backward;
        CryptoPP::Integer _checksum;
};

}
}
}

#endif // CRN_BLOCKS_ACTIVE_H
