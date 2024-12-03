// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "cbtl/blocks/passive.h"
#include "cbtl/utils.h"
#include "cbtl/keys.h"

cbtl::blocks::parts::passive cbtl::blocks::parts::passive::construct(const cbtl::math::group& G, const CryptoPP::Integer& y, const CryptoPP::Integer& h, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv, const CryptoPP::Integer& passive_forward_last, const CryptoPP::Integer& w){
    auto Gp = G.Gp();
    auto forward  = Gp.Exponentiate(G.g(), rv);
    auto backward = passive_forward_last.IsZero() ? CryptoPP::Integer::Zero() : Gp.Multiply( cbtl::utils::sha512::digest( Gp.Exponentiate(y, ru), CryptoPP::Integer::UNSIGNED ), passive_forward_last);
    auto hash     = cbtl::utils::sha512::digest(Gp.Exponentiate(forward, w), CryptoPP::Integer::UNSIGNED);
    auto cipher   = Gp.Multiply(hash, Gp.Exponentiate(Gp.Exponentiate(y, rv), h));
    // std::cout << "hash: " << hash << std::endl;
    // std::cout << "cipher_part: " << Gp.Exponentiate(Gp.Exponentiate(y, rv), h) << std::endl;
    // std::cout << "cipher: " << cipher << std::endl;
    return cbtl::blocks::parts::passive(forward, backward, cipher);
}
cbtl::blocks::parts::passive cbtl::blocks::parts::passive::construct(const cbtl::keys::identity::public_key& pub, const CryptoPP::Integer& h, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv, const CryptoPP::Integer& passive_forward_last, const cbtl::keys::identity::private_key& pri) {
    return construct(pub.G(), pub.y(), h, ru, rv, passive_forward_last, pri.x());
}
cbtl::blocks::parts::passive cbtl::blocks::parts::passive::construct(const cbtl::blocks::params::passive& p, const CryptoPP::Integer& h, const CryptoPP::Integer& ru, const CryptoPP::Integer& rv, const CryptoPP::Integer& passive_forward_last, const cbtl::keys::identity::private_key& pri){
    return cbtl::blocks::parts::passive::construct(p.pub(), h, ru, rv, passive_forward_last, pri);
}


cbtl::blocks::parts::passive::passive(const CryptoPP::Integer& forward, const CryptoPP::Integer& backward, const CryptoPP::Integer& cipher): _forward(forward), _backward(backward), _cipher(cipher){}

std::string cbtl::blocks::parts::passive::next(const cbtl::math::group& G, const CryptoPP::Integer& id, const cbtl::keys::identity::private_key& pri) const{
    auto Gp = G.Gp();
    auto token = Gp.Exponentiate(_forward, pri.x());
    auto hash = cbtl::utils::sha512::digest(token, CryptoPP::Integer::UNSIGNED);
    auto addr = G.Gp().Multiply(id, hash);
    return cbtl::utils::hex::encode(addr, CryptoPP::Integer::UNSIGNED);
}

std::string cbtl::blocks::parts::passive::next(const cbtl::math::group& G, const CryptoPP::Integer& id, const CryptoPP::Integer& h, const cbtl::keys::identity::private_key& master) const{
    auto Gp = G.Gp(), Gp1 = G.Gp1();
    auto whash     = cbtl::utils::sha512::digest(Gp.Exponentiate(_forward, master.x()), CryptoPP::Integer::UNSIGNED);
    // std::cout << "whash: " << whash << std::endl;
    auto cipher    = Gp.Divide(_cipher, whash);
    // std::cout << "cipher: " << cipher << std::endl;
    auto h_inverse = Gp1.MultiplicativeInverse(h);
    auto token     = Gp.Exponentiate(cipher, h_inverse);
    auto hash      = cbtl::utils::sha512::digest(token, CryptoPP::Integer::UNSIGNED);
    auto addr      = Gp.Multiply(id, hash);
    return cbtl::utils::hex::encode(addr, CryptoPP::Integer::UNSIGNED);
}


std::string cbtl::blocks::parts::passive::prev(const cbtl::math::group& G, const CryptoPP::Integer& address, const CryptoPP::Integer& gru, const cbtl::keys::identity::private_key& pri) const{
    auto Gp = G.Gp();
    auto hash    = cbtl::utils::sha512::digest( Gp.Exponentiate(gru, pri.x()), CryptoPP::Integer::UNSIGNED );
    auto suffix  = cbtl::utils::sha512::digest( Gp.Exponentiate( Gp.Divide(_backward, hash), pri.x() ), CryptoPP::Integer::UNSIGNED );
    auto addr    = Gp.Divide(address, suffix);
    return cbtl::utils::hex::encode(addr, CryptoPP::Integer::UNSIGNED);
}

