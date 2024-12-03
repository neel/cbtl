// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "cbtl/keys/public.h"
#include "cbtl/keys/private.h"
#include "cbtl/utils.h"

cbtl::keys::identity::public_key::public_key(const cbtl::keys::identity::private_key& pk){
    _key.AssignFrom(pk.key());
    init();
}
bool cbtl::keys::identity::public_key::initialize() {
    _key.GetValue("PublicElement", _y);
    return true;
}

std::string cbtl::keys::identity::public_key::genesis_id() const{
    return cbtl::utils::hex::encode(cbtl::utils::sha512::digest(_y, CryptoPP::Integer::UNSIGNED), CryptoPP::Integer::UNSIGNED);
}
cbtl::keys::identity::public_key::public_key(const nlohmann::json& json, bool){
    auto p = CryptoPP::MakeParameters
        (CryptoPP::Name::Modulus(),             cbtl::utils::hex::decode(json["p"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::SubgroupOrder(),       cbtl::utils::hex::decode(json["q"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::SubgroupGenerator(),   cbtl::utils::hex::decode(json["g"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::PublicElement(),       cbtl::utils::hex::decode(json["y"].get<std::string>(), CryptoPP::Integer::UNSIGNED));
    _key.AssignFrom(p);
    init();
}
cbtl::keys::identity::public_key cbtl::keys::identity::public_key::from(const nlohmann::json& json){
    return cbtl::keys::identity::public_key(json);
}

nlohmann::json cbtl::keys::identity::public_key::json() const{
    return nlohmann::json {
        {"p", cbtl::utils::hex::encode(_p, CryptoPP::Integer::UNSIGNED)},
        {"q", cbtl::utils::hex::encode(_q, CryptoPP::Integer::UNSIGNED)},
        {"g", cbtl::utils::hex::encode(_g, CryptoPP::Integer::UNSIGNED)},
        {"y", cbtl::utils::hex::encode(_y, CryptoPP::Integer::UNSIGNED)}
    };
}

cbtl::keys::identity::public_key::public_key(const CryptoPP::Integer& y, const cbtl::math::group& other){
    CryptoPP::AlgorithmParameters p = other.params() (CryptoPP::Name::PublicElement(), y);
    _key.AssignFrom(p);
    init();
}
