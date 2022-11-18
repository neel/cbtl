// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/math/group.h"
#include <cryptopp/argnames.h>
#include "crn/utils.h"

CryptoPP::AlgorithmParameters crn::math::group::params() const {
    return CryptoPP::MakeParameters
        (CryptoPP::Name::Modulus(), _p)
        (CryptoPP::Name::SubgroupOrder(), _q)
        (CryptoPP::Name::SubgroupGenerator(), _g);
}

CryptoPP::Integer crn::math::group::random(CryptoPP::AutoSeededRandomPool& rng, bool invertible) const {
    CryptoPP::Integer r(rng, 2, _p-1);
    while(true){
        CryptoPP::Integer r_inverse = Gp1().MultiplicativeInverse(r);
        if(invertible && r_inverse != 0 && Gp().Exponentiate(Gp().Exponentiate(_g, r_inverse), r) == _g){
            break; // r is OK
        }else if (!invertible && r_inverse == 0) {
            break; // r is OK
        }else{
            r = CryptoPP::Integer(rng, 2, _p-2);
        }
    }

    return r;
}

bool crn::math::operator==(const crn::math::group& l, const crn::math::group& r){
    return l.g() == r.g() && l.p() == r.p() && l.q() == r.q();
}
bool crn::math::operator!=(const crn::math::group& l, const crn::math::group& r){
    return !operator==(l, r);
}


void crn::math::to_json(nlohmann::json& j, const crn::math::group& grp){
    j = nlohmann::json {
        {"p", crn::utils::hex::encode(grp.p(), CryptoPP::Integer::UNSIGNED)},
        {"q", crn::utils::hex::encode(grp.q(), CryptoPP::Integer::UNSIGNED)},
        {"g", crn::utils::hex::encode(grp.g(), CryptoPP::Integer::UNSIGNED)}
    };
}
void crn::math::from_json(const nlohmann::json& j, crn::math::group& grp){
    grp._p = crn::utils::hex::decode(j["p"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
    grp._q = crn::utils::hex::decode(j["q"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
    grp._g = crn::utils::hex::decode(j["g"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
}
