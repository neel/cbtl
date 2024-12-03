// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "cbtl/keys/private.h"
#include "cbtl/utils.h"


cbtl::keys::identity::private_key::private_key(CryptoPP::AutoSeededRandomPool& rng, const cbtl::keys::identity::private_key& other): private_key(rng, other.params()) { }
cbtl::keys::identity::private_key::private_key(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size){
    bool success = false;
    while(!success){
        _key.GenerateRandomWithKeySize(rng, key_size);
        success = init();
    }
}
cbtl::keys::identity::private_key::private_key(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params){
    bool success = false;
    while(!success){
        _key.GenerateRandom(rng, params);
        success = init();
    }
}
cbtl::keys::identity::private_key::private_key(const nlohmann::json& json, bool){
    auto p = CryptoPP::MakeParameters
        (CryptoPP::Name::Modulus(),             cbtl::utils::hex::decode(json["p"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::SubgroupOrder(),       cbtl::utils::hex::decode(json["q"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::SubgroupGenerator(),   cbtl::utils::hex::decode(json["g"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::PrivateExponent(),     cbtl::utils::hex::decode(json["x"].get<std::string>(), CryptoPP::Integer::UNSIGNED));
    _key.AssignFrom(p);
    init();
}

cbtl::keys::identity::private_key cbtl::keys::identity::private_key::from(const nlohmann::json& json){
    return cbtl::keys::identity::private_key(json);
}

nlohmann::json cbtl::keys::identity::private_key::json() const{
    return nlohmann::json {
        {"p", cbtl::utils::hex::encode(_p, CryptoPP::Integer::UNSIGNED)},
        {"q", cbtl::utils::hex::encode(_q, CryptoPP::Integer::UNSIGNED)},
        {"g", cbtl::utils::hex::encode(_g, CryptoPP::Integer::UNSIGNED)},
        {"x", cbtl::utils::hex::encode(_x, CryptoPP::Integer::UNSIGNED)}
    };
}

bool cbtl::keys::identity::private_key::initialize() {
    _key.GetValue("PrivateExponent", _x);
    CryptoPP::Integer x_inverse = Gp1().MultiplicativeInverse(_x);
    return x_inverse != 0 && Gp().Exponentiate(Gp().Exponentiate(_g, x_inverse), _x) == _g;
}
