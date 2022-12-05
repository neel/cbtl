// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/keys/private.h"
#include "crn/utils.h"


crn::keys::identity::private_key::private_key(CryptoPP::AutoSeededRandomPool& rng, const crn::keys::identity::private_key& other): private_key(rng, other.params()) { }
crn::keys::identity::private_key::private_key(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size){
    bool success = false;
    while(!success){
        _key.GenerateRandomWithKeySize(rng, key_size);
        success = init();
    }
}
crn::keys::identity::private_key::private_key(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params){
    bool success = false;
    while(!success){
        _key.GenerateRandom(rng, params);
        success = init();
    }
}
crn::keys::identity::private_key::private_key(const nlohmann::json& json, bool){
    auto p = CryptoPP::MakeParameters
        (CryptoPP::Name::Modulus(),             crn::utils::hex::decode(json["p"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::SubgroupOrder(),       crn::utils::hex::decode(json["q"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::SubgroupGenerator(),   crn::utils::hex::decode(json["g"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::PrivateExponent(),     crn::utils::hex::decode(json["x"].get<std::string>(), CryptoPP::Integer::UNSIGNED));
    _key.AssignFrom(p);
    init();
}

crn::keys::identity::private_key crn::keys::identity::private_key::from(const nlohmann::json& json){
    return crn::keys::identity::private_key(json);
}

nlohmann::json crn::keys::identity::private_key::json() const{
    return nlohmann::json {
        {"p", crn::utils::hex::encode(_p, CryptoPP::Integer::UNSIGNED)},
        {"q", crn::utils::hex::encode(_q, CryptoPP::Integer::UNSIGNED)},
        {"g", crn::utils::hex::encode(_g, CryptoPP::Integer::UNSIGNED)},
        {"x", crn::utils::hex::encode(_x, CryptoPP::Integer::UNSIGNED)}
    };
}

bool crn::keys::identity::private_key::initialize() {
    _key.GetValue("PrivateExponent", _x);
    CryptoPP::Integer x_inverse = Gp1().MultiplicativeInverse(_x);
    return x_inverse != 0 && Gp().Exponentiate(Gp().Exponentiate(_g, x_inverse), _x) == _g;
}
