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
    return crn::utils::eHex(crn::utils::sha512(_y), CryptoPP::Integer::UNSIGNED);
}
crn::keys::identity::public_key::public_key(const nlohmann::json& json, bool){
    auto p = CryptoPP::MakeParameters
        (CryptoPP::Name::Modulus(),             crn::utils::dHex(json["p"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::SubgroupOrder(),       crn::utils::dHex(json["q"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::SubgroupGenerator(),   crn::utils::dHex(json["g"].get<std::string>(), CryptoPP::Integer::UNSIGNED))
        (CryptoPP::Name::PublicElement(),       crn::utils::dHex(json["y"].get<std::string>(), CryptoPP::Integer::UNSIGNED));
    _key.AssignFrom(p);
    init();
}
crn::keys::identity::public_key crn::keys::identity::public_key::from(const nlohmann::json& json){
    return crn::keys::identity::public_key(json);
}

nlohmann::json crn::keys::identity::public_key::json() const{
    return nlohmann::json {
        {"p", crn::utils::eHex(_p, CryptoPP::Integer::UNSIGNED)},
        {"q", crn::utils::eHex(_q, CryptoPP::Integer::UNSIGNED)},
        {"g", crn::utils::eHex(_g, CryptoPP::Integer::UNSIGNED)},
        {"y", crn::utils::eHex(_y, CryptoPP::Integer::UNSIGNED)}
    };
}

crn::keys::identity::public_key::public_key(const CryptoPP::Integer& y, const crn::math::group& other){
    CryptoPP::AlgorithmParameters p = other.params() (CryptoPP::Name::PublicElement(), y);
    _key.AssignFrom(p);
    init();
}
