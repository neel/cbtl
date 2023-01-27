// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/blocks/active.h"
#include "crn/utils.h"
#include "crn/keys.h"
#include "crn/packets.h"

crn::blocks::parts::active::active(const CryptoPP::Integer& forward, const CryptoPP::Integer& backward, const CryptoPP::Integer& checksum): _forward(forward), _backward(backward), _checksum(checksum) {}

crn::blocks::parts::active crn::blocks::parts::active::construct(const crn::math::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& w, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv, const CryptoPP::Integer& gru_last){
    auto g  = G.g();
    auto Gp = G.Gp();

    auto forward  = Gp.Exponentiate(g, ru);
    auto token    = Gp.Exponentiate(y, ru);
    auto token_w  = Gp.Exponentiate(token, w);
    auto checksum = Gp.Multiply(token_w, y);
    auto hash     = crn::utils::sha512::digest(checksum, CryptoPP::Integer::UNSIGNED);
    auto bhash    = crn::utils::sha512::digest(Gp.Exponentiate(y, rv), CryptoPP::Integer::UNSIGNED);
    auto backward = gru_last.IsZero() ? CryptoPP::Integer::Zero() : Gp.Multiply(bhash, gru_last);
    crn::blocks::parts::active part(forward, backward, hash);
    return part;
}
crn::blocks::parts::active crn::blocks::parts::active::construct(const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& master, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv, const CryptoPP::Integer& gru_last) {
    return construct(pub.G(), pub.y(), master.x(), ru, rv, gru_last);
}
crn::blocks::parts::active crn::blocks::parts::active::construct(const crn::blocks::params::active& p, const crn::keys::identity::private_key& master, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv){
    return crn::blocks::parts::active::construct(p.pub(), master, ru, rv, p.last_forward());
}

std::string crn::blocks::parts::active::next(const crn::math::group& G, const CryptoPP::Integer& id, const crn::keys::identity::private_key& pri) const{
    auto link = G.Gp().Exponentiate(_forward, pri.x());
    auto hash = crn::utils::sha512::digest(link, CryptoPP::Integer::UNSIGNED);
    auto addr = G.Gp().Multiply(id, hash);
    return crn::utils::hex::encode(addr, CryptoPP::Integer::UNSIGNED);
}

std::string crn::blocks::parts::active::prev(const crn::math::group& G, const CryptoPP::Integer& address, const CryptoPP::Integer& passive_forward, const crn::keys::identity::private_key& pri) const{
    auto link = G.Gp().Exponentiate(passive_forward, pri.x());
    auto hash = crn::utils::sha512::digest(link, CryptoPP::Integer::UNSIGNED);
    // std::cout << "------" << std::endl;
    // std::cout << "passive_forward: " << passive_forward << std::endl;
    // std::cout << "prefix: " << link << std::endl;
    // std::cout << "------" << std::endl;
    auto active_forward_prev = G.Gp().Divide(_backward, hash);
    // std::cout << "active_forward_prev: " << active_forward_prev << std::endl;
    auto token = G.Gp().Exponentiate(active_forward_prev, pri.x());
    auto token_hash = crn::utils::sha512::digest(token, CryptoPP::Integer::UNSIGNED);
    auto addr = G.Gp().Divide(address, token_hash);
    return crn::utils::hex::encode(addr, CryptoPP::Integer::UNSIGNED);
}

bool crn::blocks::parts::active::verify(const CryptoPP::Integer& token, const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& master) const{
    return verify(pub.G(), token, pub.y(), master.x());
}


bool crn::blocks::parts::active::verify(const crn::math::group& G, const CryptoPP::Integer& token, const CryptoPP::Integer& y, const CryptoPP::Integer& w) const{
    auto Gp = G.Gp();
    auto token_w  = Gp.Exponentiate(token, w);
    auto checksum = Gp.Multiply(token_w, y);
    auto hash     = crn::utils::sha512::digest(checksum, CryptoPP::Integer::UNSIGNED);
    return _checksum == hash;
}

crn::packets::challenge crn::blocks::parts::active::challenge(CryptoPP::AutoSeededRandomPool& rng, const crn::math::group& G, const CryptoPP::Integer& token, const CryptoPP::Integer& rho, const CryptoPP::Integer& lambda) const{
    auto Gp = G.Gp(), Gp1 = G.Gp1();
    auto rho_inv = Gp1.MultiplicativeInverse(rho);
    crn::packets::challenge c;
    c.random = lambda;
    return c;
}

