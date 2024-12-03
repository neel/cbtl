// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "cbtl/blocks/params.h"
#include "cbtl/blocks/access.h"
#include "cbtl/utils.h"

cbtl::blocks::params::active::active(const CryptoPP::Integer& id, const cbtl::keys::identity::public_key& pub, const CryptoPP::Integer& last_forward): _last(id), _pub(pub), _last_forward(last_forward) {
    if(id.IsZero()){
        throw std::invalid_argument("last block id cannot be 0 unless it is a genesis block (in that case use genesis function to construct instead of using this constructor)");
    }
}
cbtl::blocks::params::active::active(const cbtl::keys::identity::public_key& pub): _last(CryptoPP::Integer::Zero()), _pub(pub) {}
cbtl::blocks::params::active cbtl::blocks::params::active::genesis(const cbtl::keys::identity::public_key& pub){ return cbtl::blocks::params::active(pub); }
bool cbtl::blocks::params::active::genesis() const{ return _last_forward.IsZero(); }
CryptoPP::Integer cbtl::blocks::params::active::address(const CryptoPP::Integer& request) const{
    return _pub.Gp().Multiply(_last, cbtl::utils::sha512::digest(request, CryptoPP::Integer::UNSIGNED));
}



cbtl::blocks::params::passive::passive(const CryptoPP::Integer& id, const cbtl::keys::identity::public_key& pub, const CryptoPP::Integer& token): _last(id), _pub(pub), _token(token) {
    if(id.IsZero()){
        throw std::invalid_argument("last block id cannot be 0 unless it is a genesis block (in that case use genesis function to construct instead of using this constructor)");
    }
    if(token.IsZero()){
        throw std::invalid_argument("token id cannot be 0 unless it is a genesis block (in that case use genesis function to construct instead of using this constructor)");
    }
}
cbtl::blocks::params::passive::passive(const cbtl::keys::identity::public_key& pub): _last(CryptoPP::Integer::Zero()), _pub(pub), _token(CryptoPP::Integer::Zero()) {}
cbtl::blocks::params::passive cbtl::blocks::params::passive::genesis(const cbtl::keys::identity::public_key& pub){ return cbtl::blocks::params::passive(pub); }
bool cbtl::blocks::params::passive::genesis() const{ return _token.IsZero(); }
CryptoPP::Integer cbtl::blocks::params::passive::address() const{
    return _pub.Gp().Multiply(_last, cbtl::utils::sha512::digest(_token, CryptoPP::Integer::UNSIGNED));
}
cbtl::blocks::params::passive cbtl::blocks::params::passive::construct(const cbtl::blocks::access& last, const cbtl::keys::identity::public_key& pub, const CryptoPP::Integer& gaccess, const cbtl::keys::identity::private_key& master){
    CryptoPP::Integer h = cbtl::utils::sha512::digest(gaccess, CryptoPP::Integer::UNSIGNED);
    auto Gp = pub.G().Gp(), Gp1 = pub.G().Gp1();
    auto hash      = cbtl::utils::sha512::digest(Gp.Exponentiate(last.passive().forward(), master.x()), CryptoPP::Integer::UNSIGNED);
    auto cipher    = Gp.Divide(last.passive().cipher(), hash);
    auto h_inverse = Gp1.MultiplicativeInverse(h);
    auto token     = Gp.Exponentiate(cipher, h_inverse);
    return cbtl::blocks::params::passive(last.address().id(), pub, token);
}



cbtl::blocks::params::params(const params::active& active, const params::passive& passive, const cbtl::keys::identity::private_key& master, const boost::posix_time::ptime& requested): _active(active), _passive(passive), _master(master), _requested(requested) { }
cbtl::blocks::params::params(const params::active& active, const cbtl::blocks::access& passive_last, const cbtl::keys::identity::public_key& passive_pub, const cbtl::keys::identity::private_key& master, const CryptoPP::Integer& gaccess, const boost::posix_time::ptime& requested): params(active, params::passive::construct(passive_last, passive_pub, gaccess, master), master, requested) { }

cbtl::blocks::params cbtl::blocks::params::genesis(const cbtl::keys::identity::private_key& master, const cbtl::keys::identity::public_key& pub, const boost::posix_time::ptime& requested) {
    return cbtl::blocks::params(cbtl::blocks::params::active::genesis(pub), cbtl::blocks::params::passive::genesis(pub), master, requested);
}

