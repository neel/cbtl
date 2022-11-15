// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/blocks/passive.h"
#include "crn/utils.h"
#include "crn/keys.h"

crn::blocks::parts::passive crn::blocks::parts::passive::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& w, const CryptoPP::Integer& t){
    auto rho = G.random(rng, true), r = G.random(rng, false);
    auto forward  = G.Gp().Exponentiate(y, rho);
         forward  = G.Gp().Exponentiate(forward, r);
    auto backward = (t == 0) ? CryptoPP::Integer::Zero() : G.Gp().Exponentiate(t, rho);
    auto rho_inv  = G.Gp1().MultiplicativeInverse(rho);
    auto cipher   = G.Gp().Multiply(rho_inv, G.Gp().Exponentiate(y, w));
    return crn::blocks::parts::passive(forward, backward, cipher);
}
crn::blocks::parts::passive crn::blocks::parts::passive::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& master, const CryptoPP::Integer& t) {
    return construct(rng, pub.G(), pub.y(), master.x(), t);
}
crn::blocks::parts::passive crn::blocks::parts::passive::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params::passive& p, const crn::keys::identity::private_key& master){
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
    return crn::utils::eHex(addr, CryptoPP::Integer::UNSIGNED);
}

std::string crn::blocks::parts::passive::prev(const crn::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& y, const CryptoPP::Integer& secret) const{
    auto rho_inv = G.Gp().Divide(_cipher, G.Gp().Exponentiate(y, secret) );
    auto link    = G.Gp().Exponentiate(_backward, rho_inv);
    auto hash    = crn::utils::sha512(link);
    auto addr    = G.Gp().Divide(id, hash);
    return crn::utils::eHex(addr, CryptoPP::Integer::UNSIGNED);
}

