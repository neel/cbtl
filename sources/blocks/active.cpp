// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/blocks/active.h"
#include "crn/utils.h"
#include "crn/keys.h"
#include "crn/packets.h"

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

