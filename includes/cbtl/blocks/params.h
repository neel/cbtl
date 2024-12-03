// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_BLOCKS_PARAMS_H
#define cbtl_BLOCKS_PARAMS_H

#include <boost/date_time/posix_time/posix_time.hpp>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>
#include "cbtl/math/group.h"
#include "cbtl/utils.h"
#include "cbtl/keys.h"

namespace cbtl{
namespace blocks{

struct access;

struct params{
    struct active{
        active(const CryptoPP::Integer& id, const cbtl::keys::identity::public_key& pub, const CryptoPP::Integer& last_forward);
        bool genesis() const;
        CryptoPP::Integer address(const CryptoPP::Integer& request) const;

        static active genesis(const cbtl::keys::identity::public_key& pub);

        inline const CryptoPP::Integer& last() const { return _last; }
        inline const CryptoPP::Integer& last_forward() const { return _last_forward; }
        inline const cbtl::keys::identity::public_key& pub() const { return _pub; }
        protected:
            active(const cbtl::keys::identity::public_key& pub);
        private:
            CryptoPP::Integer _last;
            cbtl::keys::identity::public_key _pub;
            CryptoPP::Integer _last_forward;
    };
    struct passive{
        passive(const CryptoPP::Integer& id, const cbtl::keys::identity::public_key& pub, const CryptoPP::Integer& token);
        bool genesis() const;
        CryptoPP::Integer address() const;

        static passive genesis(const cbtl::keys::identity::public_key& pub);
        static passive construct(const cbtl::blocks::access& last, const cbtl::keys::identity::public_key& pub, const CryptoPP::Integer& gaccess, const cbtl::keys::identity::private_key& master);

        inline const CryptoPP::Integer& last() const { return _last; }
        inline const cbtl::keys::identity::public_key& pub() const { return _pub; }
        inline const CryptoPP::Integer& token() const { return _token; }
        protected:
            passive(const cbtl::keys::identity::public_key& pub);
        private:
            CryptoPP::Integer _last;
            cbtl::keys::identity::public_key _pub;
            CryptoPP::Integer _token;    ///< $ g^{\pi_{v}r_{v}^{(0)}} $
    };

    params(const params::active& active, const params::passive& passive, const cbtl::keys::identity::private_key& master, const boost::posix_time::ptime& requested);
    params(const active& active, const cbtl::blocks::access& passive_last, const keys::identity::public_key& passive_pub, const keys::identity::private_key& master, const CryptoPP::Integer& gaccess, const boost::posix_time::ptime& requested);

    inline const params::active& a() const { return _active; }
    inline const params::passive& p() const { return _passive; }
    inline const cbtl::keys::identity::private_key& master() const { return _master; }
    
    inline const boost::posix_time::ptime& requested() const { return _requested; }

    static params genesis(const cbtl::keys::identity::private_key& master, const cbtl::keys::identity::public_key& passive_pub, const boost::posix_time::ptime& requested);

    private:
        active  _active;
        passive _passive;
        cbtl::keys::identity::private_key  _master;
        boost::posix_time::ptime          _requested;
};

}
}

#endif // cbtl_BLOCKS_PARAMS_H
