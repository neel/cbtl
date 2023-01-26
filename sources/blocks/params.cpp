// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/blocks/params.h"
#include "crn/blocks/access.h"
#include "crn/utils.h"

crn::blocks::params::active::active(const CryptoPP::Integer& id, const crn::keys::identity::public_key& pub, const CryptoPP::Integer& last_forward): _last(id), _pub(pub), _last_forward(last_forward) {
    if(id.IsZero()){
        throw std::invalid_argument("last block id cannot be 0 unless it is a genesis block (in that case use genesis function to construct instead of using this constructor)");
    }
}
crn::blocks::params::active::active(const crn::keys::identity::public_key& pub): _last(CryptoPP::Integer::Zero()), _pub(pub) {}
crn::blocks::params::active crn::blocks::params::active::genesis(const crn::keys::identity::public_key& pub){ return crn::blocks::params::active(pub); }
bool crn::blocks::params::active::genesis() const{ return false; }
CryptoPP::Integer crn::blocks::params::active::address(const CryptoPP::Integer& request) const{
    return _pub.Gp().Multiply(_last, crn::utils::sha512::digest(request, CryptoPP::Integer::UNSIGNED));
}



crn::blocks::params::passive::passive(const CryptoPP::Integer& id, const crn::keys::identity::public_key& pub, const CryptoPP::Integer& token): _last(id), _pub(pub), _token(token) {
    if(id.IsZero()){
        throw std::invalid_argument("last block id cannot be 0 unless it is a genesis block (in that case use genesis function to construct instead of using this constructor)");
    }
    if(token.IsZero()){
        throw std::invalid_argument("token id cannot be 0 unless it is a genesis block (in that case use genesis function to construct instead of using this constructor)");
    }
}
crn::blocks::params::passive::passive(const crn::keys::identity::public_key& pub): _last(CryptoPP::Integer::Zero()), _pub(pub), _token(CryptoPP::Integer::Zero()) {}
crn::blocks::params::passive crn::blocks::params::passive::genesis(const crn::keys::identity::public_key& pub){ return crn::blocks::params::passive(pub); }
bool crn::blocks::params::passive::genesis() const{ return _token.IsZero(); }
CryptoPP::Integer crn::blocks::params::passive::address() const{
    return _pub.Gp().Multiply(_last, crn::utils::sha512::digest(_token, CryptoPP::Integer::UNSIGNED));
}
crn::blocks::params::passive crn::blocks::params::passive::construct(const crn::blocks::access& last, const crn::keys::identity::public_key& pub, const CryptoPP::Integer& gaccess){
    CryptoPP::Integer h = crn::utils::sha512::digest(gaccess, CryptoPP::Integer::UNSIGNED);
    auto Gp = pub.G().Gp(), Gp1 = pub.G().Gp1();
    auto h_inverse = Gp1.MultiplicativeInverse(h);
    auto token     = Gp.Exponentiate(last.passive().cipher(), h_inverse);
    return crn::blocks::params::passive(last.address().id(), pub, token);
}



crn::blocks::params::params(const params::active& active, const params::passive& passive, const crn::keys::identity::private_key& master, const boost::posix_time::ptime& requested): _active(active), _passive(passive), _master(master), _requested(requested) { }
crn::blocks::params::params(const params::active& active, const crn::blocks::access& passive_last, const crn::keys::identity::public_key& passive_pub, const crn::keys::identity::private_key& master, const CryptoPP::Integer& gaccess, const boost::posix_time::ptime& requested): params(active, params::passive::construct(passive_last, passive_pub, gaccess), master, requested) { }

crn::blocks::params crn::blocks::params::genesis(const crn::keys::identity::private_key& master, const crn::keys::identity::public_key& pub, const boost::posix_time::ptime& requested) {
    return crn::blocks::params(crn::blocks::params::active::genesis(pub), crn::blocks::params::passive::genesis(pub), master, requested);
}

