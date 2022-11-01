// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef BLOCK_H
#define BLOCK_H

#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>

#include "group.h"
#include "utils.h"

namespace crn{
namespace blocks{

namespace parts{

struct active;
struct passive;

struct active{
    struct params{
        CryptoPP::Integer y;        ///< $ g^{\pi_{u}} $
        CryptoPP::Integer w;        ///< $ w $
        CryptoPP::Integer token;    ///< $ g^{\pi_{u}^{-1}r_{u}^{(0)}} $
    };

    active() = delete;
    active(const active& other) = default;
    inline CryptoPP::Integer backward() const { return _backward; }
    inline CryptoPP::Integer forward() const { return _forward; }
    inline CryptoPP::Integer checksum() const { return _checksum; }

    /**
     * @brief Calculate the next block's $c_{u}$ using the current block's id and active user's secret.
     */
    std::string next(const crn::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& secret) const;
    /**
     * @brief Calculate the previous block's $\tau$ using the current block's id and active user's secret.
     */
    std::string prev(const crn::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& secret) const;

    static active construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& w, const CryptoPP::Integer& t);
    static active construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const params& p);

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

struct passive{
    struct params{
        CryptoPP::Integer y;        ///< $ g^{\pi_{v}} $
        CryptoPP::Integer w;        ///< $ w $
        CryptoPP::Integer token;    ///< $ g^{\pi_{v}r_{v}^{(0)}} $
    };

    passive() = delete;
    passive(const passive& other) = default;
    inline CryptoPP::Integer backward() const { return _backward; }
    inline CryptoPP::Integer forward() const { return _forward; }
    inline CryptoPP::Integer cipher() const { return _cipher; }

    /**
     * @brief Calculate the next block's $c_{u}$ using the current block's id and passive user's secret.
     */
    std::string next(const crn::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& y, const CryptoPP::Integer& secret) const;
    /**
     * @brief Calculate the previous block's $\tau$ using the current block's id and passive user's secret.
     */
    std::string prev(const crn::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& y, const CryptoPP::Integer& secret) const;
    /**
     * @brief constructs the passive part of a generic access block
     * Trapdoor t = $g^{\pi_{v} r_{v}^{(0)}}$ is provided by the caller which is expected to be verified before calling the constructor.
     * y is the public key of the passive user
     */
    static passive construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& w, const CryptoPP::Integer& t);
    static passive construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const params& p);

    protected:
        friend class nlohmann::adl_serializer<crn::blocks::parts::passive>;
        passive(const CryptoPP::Integer& forward, const CryptoPP::Integer& backward, const CryptoPP::Integer& cipher);
    private:
        CryptoPP::Integer _forward;
        CryptoPP::Integer _backward;
        CryptoPP::Integer _cipher;
};

}

struct access{
    struct params{
        struct participants_token{
            CryptoPP::Integer id;
            CryptoPP::Integer y;
            CryptoPP::Integer token;
        };
        CryptoPP::Integer  w;
        participants_token active, passive;
    };
    class addresses{
        friend struct access;

        CryptoPP::Integer _active;
        CryptoPP::Integer _passive;
        std::string       _id;

        friend class nlohmann::adl_serializer<crn::blocks::access::addresses>;
        addresses(const CryptoPP::Integer& active, const CryptoPP::Integer& passive);
        public:
            addresses(const addresses& other) = default;
        public:
            inline const CryptoPP::Integer& active() const { return _active; }
            inline const CryptoPP::Integer& passive() const { return _passive; }
            inline const std::string id() const { return _id; }
    };

    inline const parts::active& active() const { return _active; }
    inline const parts::passive& passive() const { return _passive; }
    inline const addresses& address() const { return _address; }

    static access construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const params& p, const CryptoPP::Integer& active_request);
    protected:
        friend class nlohmann::adl_serializer<crn::blocks::access>;
        access(const parts::active& active, const parts::passive& passive, const addresses& addr);
    private:
        parts::active     _active;
        parts::passive    _passive;
        addresses         _address;
};

}
}

#endif // BLOCK_H