// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/keys/access.h"
#include "crn/utils.h"
#include "crn/keys/private.h"
#include "crn/math/group.h"

crn::keys::access_key crn::keys::access_key::construct(const CryptoPP::Integer& theta, const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& master){
    auto Gp = pub.Gp();
    auto secret = Gp.Exponentiate(Gp.Exponentiate(pub.y(), theta), master.x());

    return crn::keys::access_key(secret);
}


crn::keys::access_key::access_key(const std::string& path){
    std::ifstream file(path);
    std::string hexed;
    file >> hexed;
    _secret = crn::utils::hex::decode(hexed, CryptoPP::Integer::UNSIGNED);
}


CryptoPP::Integer crn::keys::access_key::prepare(const crn::keys::identity::private_key& pri, const CryptoPP::Integer& lambda) const{
    auto Gp = pri.Gp(), Gp1 = pri.Gp1();
    auto x_inv = Gp1.MultiplicativeInverse(pri.x());
    auto res   = Gp.Exponentiate(_secret, x_inv);
         res   = Gp.Exponentiate(res, lambda);
    return res;
}

CryptoPP::Integer crn::keys::access_key::reconstruct(const CryptoPP::Integer& prepared, const CryptoPP::Integer& lambda, const crn::keys::identity::private_key& master){
    auto Gp = master.Gp(), Gp1 = master.Gp1();
    auto lambda_inv = Gp1.MultiplicativeInverse(lambda);
    auto w_inv      = Gp1.MultiplicativeInverse(master.x());
    auto secret     = Gp.Exponentiate(prepared, lambda_inv);
         secret     = Gp.Exponentiate(secret, w_inv);
    return secret;
}

void crn::keys::access_key::save(const std::string& name) const{
    std::ofstream access(name+".access");
    access << crn::utils::hex::encode(_secret, CryptoPP::Integer::UNSIGNED);
    access.close();
}

void crn::keys::access_key::load(const std::string& name){
    std::ifstream access(name+".access");
    std::string hexed;
    access >> hexed;
    access.close();
    _secret = crn::utils::hex::decode(hexed, CryptoPP::Integer::UNSIGNED);
}
