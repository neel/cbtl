// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/blocks/passive.h"
#include "crn/utils.h"
#include "crn/keys.h"

crn::blocks::parts::passive crn::blocks::parts::passive::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::math::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& h, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv){
    auto r = G.random(rng, false);
    auto Gp = G.Gp();
    auto forward  = Gp.Exponentiate(G.g(), r);
    auto backward = (ru == 0 || rv == 0) ? CryptoPP::Integer::Zero() : Gp.Multiply( crn::utils::sha512::digest( Gp.Exponentiate(y, ru) ), rv );
    auto cipher   = Gp.Exponentiate(Gp.Exponentiate(y, r), h);
    return crn::blocks::parts::passive(forward, backward, cipher);
}
crn::blocks::parts::passive crn::blocks::parts::passive::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::keys::identity::public_key& pub, const CryptoPP::Integer& h, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv) {
    return construct(rng, pub.G(), pub.y(), h, ru, rv);
}
crn::blocks::parts::passive crn::blocks::parts::passive::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params::passive& p, const CryptoPP::Integer& h, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv){
    return crn::blocks::parts::passive::construct(rng, p.pub(), h, ru, rv);
}


crn::blocks::parts::passive::passive(const CryptoPP::Integer& forward, const CryptoPP::Integer& backward, const CryptoPP::Integer& cipher): _forward(forward), _backward(backward), _cipher(cipher){}

// CryptoPP::Integer crn::blocks::parts::passive::token(const crn::math::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& secret) const{
//     auto rho_inv = G.Gp().Divide(_cipher, G.Gp().Exponentiate(y, secret) );
//     return G.Gp().Exponentiate(_forward, rho_inv);
// }


std::string crn::blocks::parts::passive::next(const crn::math::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& secret) const{
    auto Gp = G.Gp();
    auto token = Gp.Exponentiate(_forward, secret);
    auto hash = crn::utils::sha512::digest(token);
    auto addr = G.Gp().Multiply(id, hash);
    return crn::utils::hex::encode(addr, CryptoPP::Integer::UNSIGNED);
}

std::string crn::blocks::parts::passive::next_by_hash(const crn::math::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& h) const{
    auto Gp = G.Gp(), Gp1 = G.Gp1();
    auto h_inverse = Gp1.MultiplicativeInverse(h);
    auto token     = Gp.Exponentiate(_cipher, h_inverse);
    auto hash      = crn::utils::sha512::digest(token);
    auto addr      = Gp.Multiply(id, hash);
    return crn::utils::hex::encode(addr, CryptoPP::Integer::UNSIGNED);
}


std::string crn::blocks::parts::passive::prev(const crn::math::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& y, const CryptoPP::Integer& secret) const{
    auto rho_inv = G.Gp().Divide(_cipher, G.Gp().Exponentiate(y, secret) );
    auto link    = G.Gp().Exponentiate(_backward, rho_inv);
    auto hash    = crn::utils::sha512::digest(link);
    auto addr    = G.Gp().Divide(id, hash);
    return crn::utils::hex::encode(addr, CryptoPP::Integer::UNSIGNED);
}

