// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_BLOCKS_ACCESS_H
#define CRN_BLOCKS_ACCESS_H

#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>
#include "crn/group.h"
#include "crn/utils.h"
#include "crn/keys.h"
#include "crn/blocks/active.h"
#include "crn/blocks/passive.h"

namespace crn{

struct storage;

namespace blocks{

struct params;

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

    static access genesis(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params& p, const crn::identity::keys::private_key& master);
    static access construct(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params& p, const crn::identity::keys::private_key& master, const CryptoPP::Integer& active_request);
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

#endif // CRN_BLOCKS_ACCESS_H
