// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_BLOCKS_PASSIVE_H
#define CRN_BLOCKS_PASSIVE_H

#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>
#include "crn/math/group.h"
#include "crn/utils.h"
#include "crn/keys.h"
#include "crn/blocks/params.h"

namespace crn{

namespace keys{
namespace identity{

    struct private_key;

}
}

namespace blocks{
namespace parts{

struct passive{
    passive() = delete;
    passive(const passive& other) = default;
    inline CryptoPP::Integer backward() const { return _backward; }
    inline CryptoPP::Integer forward() const { return _forward; }
    inline CryptoPP::Integer cipher() const { return _cipher; }

    /**
     * @brief Calculate the next block's $c_{u}$ using the current block's id and passive user's secret.
     */
    std::string next(const crn::math::group& G, const CryptoPP::Integer& id, const crn::keys::identity::private_key& pri) const;
    /**
     * @brief Calculate the next block's $c_{u}$ using the $H(g^{\theta})$ provided by the Trusted Server.
     */
    std::string next(const crn::math::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& h, const crn::keys::identity::private_key& master) const;
    /**
     * @brief Calculate the previous block's $\tau$ using the current block's id and passive user's secret.
     */
    std::string prev(const crn::math::group& G, const CryptoPP::Integer& address, const CryptoPP::Integer& gru, const crn::keys::identity::private_key& pri) const;
    /**
     * @brief constructs the passive part of a generic access block
     * Trapdoor t = $g^{\pi_{v} r_{v}^{(0)}}$ is provided by the caller which is expected to be verified before calling the constructor.
     * y is the public key of the passive user
     */
    static passive construct(const crn::math::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& h, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv, const CryptoPP::Integer& passive_forward_last, const CryptoPP::Integer& w);
    static passive construct(const crn::keys::identity::public_key& pub, const CryptoPP::Integer& h, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv, const CryptoPP::Integer& passive_forward_last, const crn::keys::identity::private_key& pri);
    static passive construct(const crn::blocks::params::passive& p, const CryptoPP::Integer& h, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv, const CryptoPP::Integer& passive_forward_last, const crn::keys::identity::private_key& pri);

    protected:
        friend class nlohmann::adl_serializer<crn::blocks::parts::passive>;
        passive(const CryptoPP::Integer& forward, const CryptoPP::Integer& backward, const CryptoPP::Integer& cipher);
    private:
        CryptoPP::Integer _forward;
        CryptoPP::Integer _backward;
        CryptoPP::Integer _cipher;
};

}
}
}

#endif // CRN_BLOCKS_PASSIVE_H
