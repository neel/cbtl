// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_BLOCKS_PARAMS_H
#define CRN_BLOCKS_PARAMS_H

#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>
#include "crn/group.h"
#include "crn/utils.h"
#include "crn/keys.h"

namespace crn{
namespace blocks{

struct access;

struct params{
    struct active{
        active(const CryptoPP::Integer& id, const crn::keys::identity::public_key& pub, const CryptoPP::Integer& token);
        bool genesis() const;
        CryptoPP::Integer address(const CryptoPP::Integer& request) const;

        static active genesis(const crn::keys::identity::public_key& pub);

        inline const CryptoPP::Integer& last() const { return _last; }
        inline const crn::keys::identity::public_key& pub() const { return _pub; }
        inline const CryptoPP::Integer& token() const { return _token; }
        protected:
            active(const crn::keys::identity::public_key& pub);
        private:
            CryptoPP::Integer _last;
            crn::keys::identity::public_key _pub;
            CryptoPP::Integer _token;    ///< $ g^{\pi_{u}^{-1}r_{u}^{(0)}} $
    };
    struct passive{
        passive(const CryptoPP::Integer& id, const crn::keys::identity::public_key& pub, const CryptoPP::Integer& token);
        bool genesis() const;
        CryptoPP::Integer address() const;

        static passive genesis(const crn::keys::identity::public_key& pub);
        static passive construct(const crn::blocks::access& last, const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& pri);

        inline const CryptoPP::Integer& last() const { return _last; }
        inline const crn::keys::identity::public_key& pub() const { return _pub; }
        inline const CryptoPP::Integer& token() const { return _token; }
        protected:
            passive(const crn::keys::identity::public_key& pub);
        private:
            CryptoPP::Integer _last;
            crn::keys::identity::public_key _pub;
            CryptoPP::Integer _token;    ///< $ g^{\pi_{v}r_{v}^{(0)}} $
    };

    params(const params::active& active, const params::passive& passive, const crn::keys::identity::private_key& master);
    params(const params::active& active, const crn::blocks::access& passive_last, const crn::keys::identity::public_key& passive_pub, const crn::keys::identity::private_key& master);

    inline const params::active& a() const { return _active; }
    inline const params::passive& p() const { return _passive; }
    inline const crn::keys::identity::private_key& mastre() const { return _master; }

    static params genesis(const crn::keys::identity::private_key& master, const crn::keys::identity::public_key& passive_pub);

    private:
        active  _active;
        passive _passive;
        crn::keys::identity::private_key  _master;
};

}
}

#endif // CRN_BLOCKS_PARAMS_H
