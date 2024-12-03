// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_BLOCKS_ACCESS_H
#define cbtl_BLOCKS_ACCESS_H

#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "cbtl/math/group.h"
#include "cbtl/utils.h"
#include "cbtl/keys.h"
#include "cbtl/blocks/active.h"
#include "cbtl/blocks/passive.h"
#include "cbtl/blocks/contents.h"
#include "cbtl/math/diophantine.h"

namespace cbtl{

struct storage;

namespace blocks{

struct params;

struct access{
    inline const parts::active& active() const { return _active; }
    inline const parts::passive& passive() const { return _passive; }
    inline const addresses& address() const { return _address; }
    inline bool genesis() const { return _address.active() == _address.passive(); }
    inline static std::string genesis_id(const CryptoPP::Integer& y) { return cbtl::utils::hex::encode(cbtl::utils::sha512::digest(y, CryptoPP::Integer::UNSIGNED), CryptoPP::Integer::UNSIGNED); }
    inline const boost::posix_time::ptime& requested() const { return _requested;}
    inline const boost::posix_time::ptime& created() const { return _created;}
    inline const contents& body() const { return _contents; }

    static access genesis(CryptoPP::AutoSeededRandomPool& rng, const cbtl::blocks::params& p, const cbtl::keys::identity::private_key& master, const CryptoPP::Integer& h);
    static access construct(CryptoPP::AutoSeededRandomPool& rng, const cbtl::blocks::params& p, const cbtl::keys::identity::private_key& master, const CryptoPP::Integer& active_request, const CryptoPP::Integer& gaccess, const CryptoPP::Integer& passive_forward_last, const cbtl::keys::view_key& view, const std::string message);

    protected:
        friend class nlohmann::adl_serializer<cbtl::blocks::access>;
        access(const parts::active& active, const parts::passive& passive, const addresses& addr, const contents& body, const boost::posix_time::ptime& requested);
    private:
        parts::active     _active;
        parts::passive    _passive;
        addresses         _address;
        blocks::contents  _contents;
        boost::posix_time::ptime _requested;
        boost::posix_time::ptime _created;
};

access genesis(cbtl::storage& db, const cbtl::keys::identity::public_key& pub);
struct last{
    static access active (cbtl::storage& db, const cbtl::keys::identity::public_key& pub, const cbtl::keys::identity::private_key& pri);
    static access passive(cbtl::storage& db, const cbtl::keys::identity::public_key& pub, const cbtl::keys::identity::private_key& secret);
    static access passive(cbtl::storage& db, const cbtl::keys::identity::public_key& pub, const CryptoPP::Integer& gaccess, const cbtl::keys::identity::private_key& master);
};

}
}

#endif // cbtl_BLOCKS_ACCESS_H
