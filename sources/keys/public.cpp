// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/keys/public.h"
#include "crn/keys/private.h"
#include "crn/utils.h"

crn::keys::identity::public_key::public_key(const crn::keys::identity::private_key& pk){
    _key.AssignFrom(pk.key());
    init();
}
bool crn::keys::identity::public_key::initialize() {
    _key.GetValue("PublicElement", _y);
    return true;
}

std::string crn::keys::identity::public_key::genesis_id() const{
    return crn::utils::hex::encode(crn::utils::sha512::digest(_y, CryptoPP::Integer::UNSIGNED), CryptoPP::Integer::UNSIGNED);
}
crn::keys::identity::public_key::public_key(const nlohmann::json& json, bool){
    auto p = CryptoPP::MakeParameters
        (CryptoPP::Name::Modulus(),             crn::utils::hex::decode(json["p"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::SubgroupOrder(),       crn::utils::hex::decode(json["q"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::SubgroupGenerator(),   crn::utils::hex::decode(json["g"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::PublicElement(),       crn::utils::hex::decode(json["y"].get<std::string>(), CryptoPP::Integer::UNSIGNED));
    _key.AssignFrom(p);
    init();
}
crn::keys::identity::public_key crn::keys::identity::public_key::from(const nlohmann::json& json){
    return crn::keys::identity::public_key(json);
}

nlohmann::json crn::keys::identity::public_key::json() const{
    return nlohmann::json {
        {"p", crn::utils::hex::encode(_p, CryptoPP::Integer::UNSIGNED)},
        {"q", crn::utils::hex::encode(_q, CryptoPP::Integer::UNSIGNED)},
        {"g", crn::utils::hex::encode(_g, CryptoPP::Integer::UNSIGNED)},
        {"y", crn::utils::hex::encode(_y, CryptoPP::Integer::UNSIGNED)}
    };
}

crn::keys::identity::public_key::public_key(const CryptoPP::Integer& y, const crn::math::group& other){
    CryptoPP::AlgorithmParameters p = other.params() (CryptoPP::Name::PublicElement(), y);
    _key.AssignFrom(p);
    init();
}
