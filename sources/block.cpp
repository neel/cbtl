// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "block.h"
#include "utils.h"

crn::blocks::parts::active::active(const CryptoPP::Integer& forward, const CryptoPP::Integer& backward, const CryptoPP::Integer& checksum): _forward(forward), _backward(backward), _checksum(checksum) {}

crn::blocks::parts::active crn::blocks::parts::active::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& w, const CryptoPP::Integer& t){
    auto random   = G.random(rng, false);
    auto forward  = G.Gp().Exponentiate(G.g(), random);
    auto checksum = G.Gp().Exponentiate(y, w);
         checksum = G.Gp().Exponentiate(checksum, random);
    auto hash     = crn::utils::sha512(checksum);
    crn::blocks::parts::active part(forward, t, checksum);
    return part;
}

crn::blocks::parts::active crn::blocks::parts::active::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const crn::blocks::parts::active::params& p){
    return crn::blocks::parts::active::construct(rng, G, p.y, p.w, p.token);
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


crn::blocks::parts::passive crn::blocks::parts::passive::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& w, const CryptoPP::Integer& t){
    auto rho = G.random(rng, true), r = G.random(rng, false);
    auto forward  = G.Gp().Exponentiate(y, rho);
                      forward  = G.Gp().Exponentiate(forward, r);
    auto backward = (t == 0) ? CryptoPP::Integer::Zero() : G.Gp().Exponentiate(t, rho);
    auto rho_inv  = G.Gp1().MultiplicativeInverse(rho);
    auto cipher   = G.Gp().Multiply(rho_inv, w);
    return crn::blocks::parts::passive(forward, backward, cipher);
}

crn::blocks::parts::passive crn::blocks::parts::passive::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const crn::blocks::parts::passive::params& p){
    return crn::blocks::parts::passive::construct(rng, G, p.y, p.w, p.token);
}


crn::blocks::parts::passive::passive(const CryptoPP::Integer& forward, const CryptoPP::Integer& backward, const CryptoPP::Integer& cipher): _forward(forward), _backward(backward), _cipher(cipher){}

std::string crn::blocks::parts::passive::next(const crn::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& y, const CryptoPP::Integer& secret) const{
    auto rho_inv = G.Gp().Divide(_cipher, G.Gp().Exponentiate(y, secret) );
    auto link    = G.Gp().Exponentiate(_forward, rho_inv);
    auto hash    = crn::utils::sha512(link);
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


crn::blocks::access::params crn::blocks::access::params::genesis(CryptoPP::Integer w, CryptoPP::Integer y){
    crn::blocks::access::params params;
    params.w             = w;
    params.active.id     = 0;
    params.active.token  = 0;
    params.active.y      = y;
    params.passive.id    = 0;
    params.passive.token = 0;
    params.passive.y     = y;
    return params;
}


crn::blocks::access::access(const parts::active& active, const parts::passive& passive, const addresses& addr): _active(active), _passive(passive), _address(addr){}

crn::blocks::access crn::blocks::access::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const crn::blocks::access::params& p, const CryptoPP::Integer& active_request) {
    blocks::parts::active::params active_params   {p.active.y,  p.w, p.active.token};
    blocks::parts::passive::params passive_params {p.passive.y, p.w, p.passive.token};

    auto active  = parts::active::construct(rng, G, active_params);
    auto passive = parts::passive::construct(rng, G, passive_params);

    if(p.active.id == 0 && p.passive.id == 0){
        addresses addr(p.active.y, p.passive.y);
        return access(active, passive, addr);
    }else{
        CryptoPP::Integer hash         = crn::utils::sha512(active_request);
        CryptoPP::Integer addr_active  = G.Gp().Multiply(p.active.id, hash);
        CryptoPP::Integer addr_passive = G.Gp().Multiply(p.passive.id, crn::utils::sha512(p.passive.token));
        addresses addr(addr_active, addr_passive);
        return access(active, passive, addr);
    }
}



