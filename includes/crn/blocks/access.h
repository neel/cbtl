// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_BLOCKS_ACCESS_H
#define CRN_BLOCKS_ACCESS_H

#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "crn/group.h"
#include "crn/utils.h"
#include "crn/keys.h"
#include "crn/blocks/active.h"
#include "crn/blocks/passive.h"
#include "crn/line.h"

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

    struct contents{
        contents(const crn::keys::identity::public_key& pub, const CryptoPP::Integer& random, const CryptoPP::Integer& active_req, const addresses& addr, const std::string& msg);
        inline const crn::free_coordinates& random() const { return _random; }
        inline const CryptoPP::Integer& gamma() const { return _gamma; }
        inline const std::string& ciphertext() const { return _message; }
        private:
            friend class nlohmann::adl_serializer<crn::blocks::access::contents>;
            contents(const crn::free_coordinates& random, const CryptoPP::Integer& gamma, const std::string& msg);
            void compute(const crn::free_coordinates& p1, const crn::free_coordinates& p2, const std::string& msg, const crn::group& G);
        private:
            crn::free_coordinates  _random;
            CryptoPP::Integer      _gamma;
            CryptoPP::Integer      _super;
            std::string            _message;
    };

    inline const parts::active& active() const { return _active; }
    inline const parts::passive& passive() const { return _passive; }
    inline const addresses& address() const { return _address; }
    inline bool genesis() const { return _address.active() == _address.passive(); }
    inline static std::string genesis_id(const CryptoPP::Integer& y) { return crn::utils::eHex(crn::utils::sha512(y)); }
    inline const boost::posix_time::ptime& requested() const { return _requested;}
    inline const boost::posix_time::ptime& created() const { return _created;}
    inline const contents& body() const { return _contents; }

    static access genesis(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params& p, const crn::keys::identity::private_key& master);
    static access construct(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params& p, const crn::keys::identity::private_key& master, const CryptoPP::Integer& active_request);

    void line(const CryptoPP::Integer& xu, const CryptoPP::Integer& xv) const;
    protected:
        friend class nlohmann::adl_serializer<crn::blocks::access>;
        access(const parts::active& active, const parts::passive& passive, const addresses& addr, const contents& body);
    private:
        parts::active     _active;
        parts::passive    _passive;
        addresses         _address;
        contents          _contents;
        boost::posix_time::ptime _requested;
        boost::posix_time::ptime _created;
};

access genesis(crn::storage& db, const crn::keys::identity::public_key& pub);
struct last{
    static access active (crn::storage& db, const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& pri);
    static access passive(crn::storage& db, const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& secret);
};

}
}

#endif // CRN_BLOCKS_ACCESS_H
