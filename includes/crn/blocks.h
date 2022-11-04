// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_BLOCKS_H
#define CRN_BLOCKS_H

#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>
#include "crn/group.h"
#include "crn/utils.h"
#include "crn/keys.h"

namespace crn{

struct storage;

namespace packets{
    struct challenge;
}

namespace blocks{

struct access;

struct params{
    struct active{
        active(const CryptoPP::Integer& id, const crn::identity::keys::public_key& pub, const CryptoPP::Integer& token);
        bool genesis() const;
        CryptoPP::Integer address(const CryptoPP::Integer& request) const;

        static active genesis(const crn::identity::keys::public_key& pub);

        inline const CryptoPP::Integer& id() const { return _id; }
        inline const crn::identity::keys::public_key& pub() const { return _pub; }
        inline const CryptoPP::Integer& token() const { return _token; }
        protected:
            active(const crn::identity::keys::public_key& pub);
        private:
            CryptoPP::Integer _id;
            crn::identity::keys::public_key _pub;
            CryptoPP::Integer _token;    ///< $ g^{\pi_{u}^{-1}r_{u}^{(0)}} $
    };
    struct passive{
        passive(const CryptoPP::Integer& id, const crn::identity::keys::public_key& pub, const CryptoPP::Integer& token);
        bool genesis() const;
        CryptoPP::Integer address() const;

        static passive genesis(const crn::identity::keys::public_key& pub);
        static passive construct(const crn::blocks::access& last, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& pri);

        inline const CryptoPP::Integer& id() const { return _id; }
        inline const crn::identity::keys::public_key& pub() const { return _pub; }
        inline const CryptoPP::Integer& token() const { return _token; }
        protected:
            passive(const crn::identity::keys::public_key& pub);
        private:
            CryptoPP::Integer _id;
            crn::identity::keys::public_key _pub;
            CryptoPP::Integer _token;    ///< $ g^{\pi_{v}r_{v}^{(0)}} $
    };

    active  _active;
    passive _passive;
    crn::identity::keys::private_key  _master;

    params(const params::active& active, const params::passive& passive, const crn::identity::keys::private_key& master);
    params(const params::active& active, const crn::blocks::access& passive_last, const crn::identity::keys::public_key& passive_pub, const crn::identity::keys::private_key& master);

    // inline const active& active() const { return _active; }
    // inline const passive& passive() const { return _passive; }

    static params genesis(const crn::identity::keys::private_key& master, const crn::identity::keys::public_key& passive_pub);
};

namespace parts{

struct active;
struct passive;

struct active{
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

    static active construct(CryptoPP::AutoSeededRandomPool& rng, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& master, const CryptoPP::Integer& token);
    static active construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& w, const CryptoPP::Integer& t);
    static active construct(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params::active& p, const crn::identity::keys::private_key& master);

    bool verify(const CryptoPP::Integer& token, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& master) const;
    bool verify(const crn::group& G, const CryptoPP::Integer& token, const CryptoPP::Integer& y, const CryptoPP::Integer& w) const;
    crn::packets::challenge challenge(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const CryptoPP::Integer& token, const CryptoPP::Integer& rho) const;

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
    passive() = delete;
    passive(const passive& other) = default;
    inline CryptoPP::Integer backward() const { return _backward; }
    inline CryptoPP::Integer forward() const { return _forward; }
    inline CryptoPP::Integer cipher() const { return _cipher; }

    CryptoPP::Integer token(const crn::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& secret) const;
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
    static passive construct(CryptoPP::AutoSeededRandomPool& rng, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& master, const CryptoPP::Integer& t);
    static passive construct(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params::passive& p, const crn::identity::keys::private_key& master);

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
    class addresses{
        friend struct access;

        CryptoPP::Integer _active;
        CryptoPP::Integer _passive;
        CryptoPP::Integer _id;

        friend class nlohmann::adl_serializer<crn::blocks::access::addresses>;
        addresses(const CryptoPP::Integer& active, const CryptoPP::Integer& passive);
        public:
            addresses(const addresses& other) = default;
        public:
            inline const CryptoPP::Integer& active() const { return _active; }
            inline const CryptoPP::Integer& passive() const { return _passive; }
            inline const CryptoPP::Integer id() const { return _id; }
            std::string hash() const;
    };

    inline const parts::active& active() const { return _active; }
    inline const parts::passive& passive() const { return _passive; }
    inline const addresses& address() const { return _address; }
    inline bool is_genesis() const { return _address.active() == _address.passive(); }
    inline static std::string genesis_id(const CryptoPP::Integer& y) { return crn::utils::eHex(crn::utils::sha512(y)); }

    static access genesis(CryptoPP::AutoSeededRandomPool& rng, const params& p, const crn::identity::keys::private_key& master);
    static access construct(CryptoPP::AutoSeededRandomPool& rng, const params& p, const crn::identity::keys::private_key& master, const CryptoPP::Integer& active_request);
    protected:
        friend class nlohmann::adl_serializer<crn::blocks::access>;
        access(const parts::active& active, const parts::passive& passive, const addresses& addr);
    private:
        parts::active     _active;
        parts::passive    _passive;
        addresses         _address;
};

access genesis(crn::storage& db, const crn::identity::keys::public_key& pub);
struct last{
    static access active (crn::storage& db, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& pri);
    static access passive(crn::storage& db, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& secret);
};

}
}

#endif // CRN_BLOCKS_H
