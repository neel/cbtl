// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/blocks/passive.h"
#include "crn/utils.h"
#include "crn/keys.h"

crn::blocks::parts::passive crn::blocks::parts::passive::construct(const crn::math::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& h, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv, const CryptoPP::Integer& passive_forward_last, const CryptoPP::Integer& w){
    auto Gp = G.Gp();
    auto forward  = Gp.Exponentiate(G.g(), rv);
    auto backward = passive_forward_last.IsZero() ? CryptoPP::Integer::Zero() : Gp.Multiply( crn::utils::sha512::digest( Gp.Exponentiate(y, ru), CryptoPP::Integer::UNSIGNED ), passive_forward_last);
    auto hash     = crn::utils::sha512::digest(Gp.Exponentiate(forward, w), CryptoPP::Integer::UNSIGNED);
    auto cipher   = Gp.Multiply(hash, Gp.Exponentiate(Gp.Exponentiate(y, rv), h));
    std::cout << "hash: " << hash << std::endl;
    std::cout << "cipher_part: " << Gp.Exponentiate(Gp.Exponentiate(y, rv), h) << std::endl;
    std::cout << "cipher: " << cipher << std::endl;
    return crn::blocks::parts::passive(forward, backward, cipher);
}
crn::blocks::parts::passive crn::blocks::parts::passive::construct(const crn::keys::identity::public_key& pub, const CryptoPP::Integer& h, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv, const CryptoPP::Integer& passive_forward_last, const crn::keys::identity::private_key& pri) {
    return construct(pub.G(), pub.y(), h, ru, rv, passive_forward_last, pri.x());
}
crn::blocks::parts::passive crn::blocks::parts::passive::construct(const crn::blocks::params::passive& p, const CryptoPP::Integer& h, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv, const CryptoPP::Integer& passive_forward_last, const crn::keys::identity::private_key& pri){
    return crn::blocks::parts::passive::construct(p.pub(), h, ru, rv, passive_forward_last, pri);
}


crn::blocks::parts::passive::passive(const CryptoPP::Integer& forward, const CryptoPP::Integer& backward, const CryptoPP::Integer& cipher): _forward(forward), _backward(backward), _cipher(cipher){}

std::string crn::blocks::parts::passive::next(const crn::math::group& G, const CryptoPP::Integer& id, const crn::keys::identity::private_key& pri) const{
    auto Gp = G.Gp();
    auto token = Gp.Exponentiate(_forward, pri.x());
    auto hash = crn::utils::sha512::digest(token, CryptoPP::Integer::UNSIGNED);
    auto addr = G.Gp().Multiply(id, hash);
    return crn::utils::hex::encode(addr, CryptoPP::Integer::UNSIGNED);
}

std::string crn::blocks::parts::passive::next(const crn::math::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& h, const crn::keys::identity::private_key& master) const{
    auto Gp = G.Gp(), Gp1 = G.Gp1();
    auto whash     = crn::utils::sha512::digest(Gp.Exponentiate(_forward, master.x()), CryptoPP::Integer::UNSIGNED);
    std::cout << "whash: " << whash << std::endl;
    auto cipher    = Gp.Divide(_cipher, whash);
    std::cout << "cipher: " << cipher << std::endl;
    auto h_inverse = Gp1.MultiplicativeInverse(h);
    auto token     = Gp.Exponentiate(cipher, h_inverse);
    auto hash      = crn::utils::sha512::digest(token, CryptoPP::Integer::UNSIGNED);
    auto addr      = Gp.Multiply(id, hash);
    return crn::utils::hex::encode(addr, CryptoPP::Integer::UNSIGNED);
}


std::string crn::blocks::parts::passive::prev(const crn::math::group& G, const CryptoPP::Integer& address, const CryptoPP::Integer& gru, const crn::keys::identity::private_key& pri) const{
    auto Gp = G.Gp();
    auto hash    = crn::utils::sha512::digest( Gp.Exponentiate(gru, pri.x()), CryptoPP::Integer::UNSIGNED );
    auto suffix  = crn::utils::sha512::digest( Gp.Exponentiate( Gp.Divide(_backward, hash), pri.x() ), CryptoPP::Integer::UNSIGNED );
    auto addr    = Gp.Divide(address, suffix);
    return crn::utils::hex::encode(addr, CryptoPP::Integer::UNSIGNED);
}

