// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "cbtl/math/group.h"
#include <cryptopp/argnames.h>
#include "cbtl/utils.h"

CryptoPP::AlgorithmParameters cbtl::math::group::params() const {
    return CryptoPP::MakeParameters
        (CryptoPP::Name::Modulus(), _p)
        (CryptoPP::Name::SubgroupOrder(), _q)
        (CryptoPP::Name::SubgroupGenerator(), _g);
}

CryptoPP::Integer cbtl::math::group::random(CryptoPP::AutoSeededRandomPool& rng, bool invertible) const {
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

bool cbtl::math::operator==(const cbtl::math::group& l, const cbtl::math::group& r){
    return l.g() == r.g() && l.p() == r.p() && l.q() == r.q();
}
bool cbtl::math::operator!=(const cbtl::math::group& l, const cbtl::math::group& r){
    return !operator==(l, r);
}


void cbtl::math::to_json(nlohmann::json& j, const cbtl::math::group& grp){
    j = nlohmann::json {
        {"p", cbtl::utils::hex::encode(grp.p(), CryptoPP::Integer::UNSIGNED)},
        {"q", cbtl::utils::hex::encode(grp.q(), CryptoPP::Integer::UNSIGNED)},
        {"g", cbtl::utils::hex::encode(grp.g(), CryptoPP::Integer::UNSIGNED)}
    };
}
void cbtl::math::from_json(const nlohmann::json& j, cbtl::math::group& grp){
    grp._p = cbtl::utils::hex::decode(j["p"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
    grp._q = cbtl::utils::hex::decode(j["q"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
    grp._g = cbtl::utils::hex::decode(j["g"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
}
