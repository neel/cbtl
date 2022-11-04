// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/blocks.h"
#include "crn/utils.h"
#include "crn/packets.h"
#include "crn/keys.h"
#include "crn/storage.h"

crn::blocks::parts::active::active(const CryptoPP::Integer& forward, const CryptoPP::Integer& backward, const CryptoPP::Integer& checksum): _forward(forward), _backward(backward), _checksum(checksum) {}



crn::blocks::parts::active crn::blocks::parts::active::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& w, const CryptoPP::Integer& t){
    auto g  = G.g();
    auto Gp = G.Gp();

    auto random   = G.random(rng, false);
    auto forward  = Gp.Exponentiate(g, random);
    auto token    = Gp.Exponentiate(y, random);
    auto token_w  = Gp.Exponentiate(token, w);
    auto checksum = Gp.Multiply(token_w, y);
    auto hash     = crn::utils::sha512(checksum);
    crn::blocks::parts::active part(forward, t, hash);
    return part;
}
crn::blocks::parts::active crn::blocks::parts::active::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& master, const CryptoPP::Integer& token) {
    return construct(rng, pub.G(), pub.y(), master.x(), token);
}
crn::blocks::parts::active crn::blocks::parts::active::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params::active& p, const crn::identity::keys::private_key& master){
    return crn::blocks::parts::active::construct(rng, p.pub(), master, p.token());
}


std::string crn::blocks::parts::active::next(const crn::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& secret) const{
    auto link = G.Gp().Exponentiate(_forward, secret);
    auto hash = crn::utils::sha512(link);
    auto addr = G.Gp().Multiply(id, hash);
    return crn::utils::eHex(addr);
}

std::string crn::blocks::parts::active::prev(const crn::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& secret) const{
    auto link = G.Gp().Exponentiate(_forward, secret);
         link = G.Gp().Exponentiate(link, secret);
    auto hash = crn::utils::sha512(link);
    auto addr = G.Gp().Divide(id, hash);
    return crn::utils::eHex(addr);
}

bool crn::blocks::parts::active::verify(const CryptoPP::Integer& token, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& master) const{
    return verify(pub.G(), token, pub.y(), master.x());
}


bool crn::blocks::parts::active::verify(const crn::group& G, const CryptoPP::Integer& token, const CryptoPP::Integer& y, const CryptoPP::Integer& w) const{
    auto Gp = G.Gp();
    auto token_w  = Gp.Exponentiate(token, w);
    auto checksum = Gp.Multiply(token_w, y);
    auto hash     = crn::utils::sha512(checksum);
    return _checksum == hash;
}

crn::packets::challenge crn::blocks::parts::active::challenge(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const CryptoPP::Integer& token, const CryptoPP::Integer& rho) const{
    auto Gp = G.Gp(), Gp1 = G.Gp1();
    auto rho_inv = Gp1.MultiplicativeInverse(rho);
    crn::packets::challenge c;
    c.c1 = Gp.Multiply( token, Gp.Exponentiate(_forward, rho) );
    c.c2 = Gp.Exponentiate(token, rho_inv);
    c.c3 = _forward;
    return c;
}



crn::blocks::parts::passive crn::blocks::parts::passive::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& w, const CryptoPP::Integer& t){
    auto rho = G.random(rng, true), r = G.random(rng, false);
    auto forward  = G.Gp().Exponentiate(y, rho);
                      forward  = G.Gp().Exponentiate(forward, r);
    auto backward = (t == 0) ? CryptoPP::Integer::Zero() : G.Gp().Exponentiate(t, rho);
    auto rho_inv  = G.Gp1().MultiplicativeInverse(rho);
    auto cipher   = G.Gp().Multiply(rho_inv, G.Gp().Exponentiate(y, w));
    return crn::blocks::parts::passive(forward, backward, cipher);
}
crn::blocks::parts::passive crn::blocks::parts::passive::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& master, const CryptoPP::Integer& t) {
    return construct(rng, pub.G(), pub.y(), master.x(), t);
}
crn::blocks::parts::passive crn::blocks::parts::passive::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params::passive& p, const crn::identity::keys::private_key& master){
    return crn::blocks::parts::passive::construct(rng, p.pub(), master, p.token());
}


crn::blocks::parts::passive::passive(const CryptoPP::Integer& forward, const CryptoPP::Integer& backward, const CryptoPP::Integer& cipher): _forward(forward), _backward(backward), _cipher(cipher){}

CryptoPP::Integer crn::blocks::parts::passive::token(const crn::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& secret) const{
    auto rho_inv = G.Gp().Divide(_cipher, G.Gp().Exponentiate(y, secret) );
    return G.Gp().Exponentiate(_forward, rho_inv);
}


std::string crn::blocks::parts::passive::next(const crn::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& y, const CryptoPP::Integer& secret) const{
    auto hash = crn::utils::sha512(token(G, y, secret));
    auto addr = G.Gp().Multiply(id, hash);
    return crn::utils::eHex(addr);
}

std::string crn::blocks::parts::passive::prev(const crn::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& y, const CryptoPP::Integer& secret) const{
    auto rho_inv = G.Gp().Divide(_cipher, G.Gp().Exponentiate(y, secret) );
    auto link    = G.Gp().Exponentiate(_backward, rho_inv);
    auto hash    = crn::utils::sha512(link);
    auto addr    = G.Gp().Divide(id, hash);
    return crn::utils::eHex(addr);
}


crn::blocks::access::addresses::addresses(const CryptoPP::Integer& active, const CryptoPP::Integer& passive): _active(active), _passive(passive){
    if(_active == _passive){
        _id = crn::utils::sha512(_active);
    }else{
        _id = crn::utils::sha512(crn::utils::eHex(_active) + " " + crn::utils::eHex(_passive));
    }
}

std::string crn::blocks::access::addresses::hash() const{
    return crn::utils::eHex(_id);
}




crn::blocks::params::active::active(const CryptoPP::Integer& id, const crn::identity::keys::public_key& pub, const CryptoPP::Integer& token): _id(id), _pub(pub), _token(token) {
    if(id.IsZero()){
        throw std::invalid_argument("last block id cannot be 0 unless it is a genesis block (in that case use genesis function to construct instead of using this constructor)");
    }
    if(token.IsZero()){
        throw std::invalid_argument("token id cannot be 0 unless it is a genesis block (in that case use genesis function to construct instead of using this constructor)");
    }
}
crn::blocks::params::active::active(const crn::identity::keys::public_key& pub): _id(CryptoPP::Integer::Zero()), _pub(pub), _token(CryptoPP::Integer::Zero()) {}
crn::blocks::params::active crn::blocks::params::active::genesis(const crn::identity::keys::public_key& pub){ return crn::blocks::params::active(pub); }
bool crn::blocks::params::active::genesis() const{ return _token.IsZero(); }
CryptoPP::Integer crn::blocks::params::active::address(const CryptoPP::Integer& request) const{
    return _pub.Gp().Multiply(_id, crn::utils::sha512(request));
}



crn::blocks::params::passive::passive(const CryptoPP::Integer& id, const crn::identity::keys::public_key& pub, const CryptoPP::Integer& token): _id(id), _pub(pub), _token(token) {
    if(id.IsZero()){
        throw std::invalid_argument("last block id cannot be 0 unless it is a genesis block (in that case use genesis function to construct instead of using this constructor)");
    }
    if(token.IsZero()){
        throw std::invalid_argument("token id cannot be 0 unless it is a genesis block (in that case use genesis function to construct instead of using this constructor)");
    }
}
crn::blocks::params::passive::passive(const crn::identity::keys::public_key& pub): _id(CryptoPP::Integer::Zero()), _pub(pub), _token(CryptoPP::Integer::Zero()) {}
crn::blocks::params::passive crn::blocks::params::passive::genesis(const crn::identity::keys::public_key& pub){ return crn::blocks::params::passive(pub); }
bool crn::blocks::params::passive::genesis() const{ return _token.IsZero(); }
CryptoPP::Integer crn::blocks::params::passive::address() const{
    return _pub.Gp().Multiply(_id, crn::utils::sha512(_token));
}
crn::blocks::params::passive crn::blocks::params::passive::construct(const crn::blocks::access& last, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& pri){
    auto secret  = pub.Gp().Exponentiate(pub.y(), pri.x());
    auto rho_inv = pub.Gp().Divide(last.passive().cipher(), secret);
    auto token   = pub.Gp().Exponentiate(last.passive().forward(), rho_inv);
    return crn::blocks::params::passive(last.address().id(), pub, token);
}



crn::blocks::params::params(const params::active& active, const params::passive& passive, const crn::identity::keys::private_key& master): _active(active), _passive(passive), _master(master) { }
crn::blocks::params::params(const params::active& active, const crn::blocks::access& passive_last, const crn::identity::keys::public_key& passive_pub, const crn::identity::keys::private_key& master): params(active, params::passive::construct(passive_last, passive_pub, master), master) { }

crn::blocks::params crn::blocks::params::genesis(const crn::identity::keys::private_key& master, const crn::identity::keys::public_key& pub){
    return crn::blocks::params(crn::blocks::params::active::genesis(pub), crn::blocks::params::passive::genesis(pub), master);
}


crn::blocks::access::access(const parts::active& active, const parts::passive& passive, const addresses& addr): _active(active), _passive(passive), _address(addr){}

crn::blocks::access crn::blocks::access::genesis(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params& p, const crn::identity::keys::private_key& master){
    if(p._active.genesis() == p._passive.genesis() && p._active.genesis()){
        auto active  = parts::active::construct(rng, p._active, master);
        auto passive = parts::passive::construct(rng, p._passive, master);

        addresses addr(p._active.pub().y(), p._passive.pub().y());
        return access(active, passive, addr);
    }else{
        throw std::invalid_argument("p is not genesis parameters");
    }
}

crn::blocks::access crn::blocks::access::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params& p, const crn::identity::keys::private_key& master, const CryptoPP::Integer& active_request) {
    auto active  = parts::active::construct(rng, p._active, master);
    auto passive = parts::passive::construct(rng, p._passive, master);

    if(active_request.IsZero()){
        throw std::invalid_argument("active_request must not be zero unless it is a genesis block (use genesis function in that case)");
    }
    if(p._active.genesis() == p._passive.genesis() && p._active.genesis()){
        throw std::invalid_argument("genesis parms not accepted (use genesis function)");
    }

    CryptoPP::Integer addr_active  = p._active.address(active_request);
    CryptoPP::Integer addr_passive = p._passive.address();
    addresses addr(addr_active, addr_passive);
    return access(active, passive, addr);
}

crn::blocks::access crn::blocks::genesis(crn::storage& db, const crn::identity::keys::public_key& pub){
    return db.fetch(pub.genesis_id());
}

crn::blocks::access crn::blocks::last::active(crn::storage& db, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& pri){
    crn::blocks::access last = crn::blocks::genesis(db, pub);
    while(true){
        std::string address = last.active().next(pub.G(), last.address().id(), pri.x());
        if(db.exists(address, true)){
            std::string block_id = db.id(address);
            last = db.fetch(block_id);
        }else{
            break;
        }
    }

    return last;
}

crn::blocks::access crn::blocks::last::passive(crn::storage& db, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& secret){
    crn::blocks::access last = crn::blocks::genesis(db, pub);
    while(true){
        std::string address = last.passive().next(pub.G(), last.address().id(), pub.y(), secret.x());
        if(db.exists(address, true)){
            std::string block_id = db.id(address);
            last = db.fetch(block_id);
        }else{
            break;
        }
    }
    return last;
}
