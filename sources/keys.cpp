// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/keys.h"
#include "crn/storage.h"
#include "crn/blocks/io.h"
#include "crn/packets.h"
#include "crn/group.h"
#include <cryptopp/argnames.h>

crn::identity::keys::private_key::private_key(CryptoPP::AutoSeededRandomPool& rng, const crn::identity::keys::private_key& other): private_key(rng, other.params()) { }
crn::identity::keys::private_key::private_key(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size){
    bool success = false;
    while(!success){
        _key.GenerateRandomWithKeySize(rng, key_size);
        success = init();
    }
}
crn::identity::keys::private_key::private_key(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params){
    bool success = false;
    while(!success){
        _key.GenerateRandom(rng, params);
        success = init();
    }
}
crn::identity::keys::private_key::private_key(const nlohmann::json& json, bool){
    auto p = CryptoPP::MakeParameters
        (CryptoPP::Name::Modulus(),             crn::utils::dHex(json["p"].get<std::string>()))
        (CryptoPP::Name::SubgroupOrder(),       crn::utils::dHex(json["q"].get<std::string>()))
        (CryptoPP::Name::SubgroupGenerator(),   crn::utils::dHex(json["g"].get<std::string>()))
        (CryptoPP::Name::PrivateExponent(),     crn::utils::dHex(json["x"].get<std::string>()));
    _key.AssignFrom(p);
    init();
}

crn::identity::keys::private_key crn::identity::keys::private_key::from(const nlohmann::json& json){
    return crn::identity::keys::private_key(json);
}

nlohmann::json crn::identity::keys::private_key::json() const{
    return nlohmann::json {
        {"p", crn::utils::eHex(_p)},
        {"q", crn::utils::eHex(_q)},
        {"g", crn::utils::eHex(_g)},
        {"x", crn::utils::eHex(_x)}
    };
}



bool crn::identity::keys::private_key::initialize() {
    _key.GetValue("PrivateExponent", _x);
    CryptoPP::Integer x_inverse = Gp1().MultiplicativeInverse(_x);
    return x_inverse != 0 && Gp().Exponentiate(Gp().Exponentiate(_g, x_inverse), _x) == _g;
}

crn::identity::keys::public_key::public_key(const crn::identity::keys::private_key& pk){
    _key.AssignFrom(pk.key());
    init();
}
bool crn::identity::keys::public_key::initialize() {
    _key.GetValue("PublicElement", _y);
    return true;
}

std::string crn::identity::keys::public_key::genesis_id() const{
    return crn::utils::eHex(crn::utils::sha512(_y));
}
crn::identity::keys::public_key::public_key(const nlohmann::json& json, bool){
    auto p = CryptoPP::MakeParameters
        (CryptoPP::Name::Modulus(),             crn::utils::dHex(json["p"].get<std::string>()))
        (CryptoPP::Name::SubgroupOrder(),       crn::utils::dHex(json["q"].get<std::string>()))
        (CryptoPP::Name::SubgroupGenerator(),   crn::utils::dHex(json["g"].get<std::string>()))
        (CryptoPP::Name::PublicElement(),       crn::utils::dHex(json["y"].get<std::string>()));
    _key.AssignFrom(p);
    init();
}
crn::identity::keys::public_key crn::identity::keys::public_key::from(const nlohmann::json& json){
    return crn::identity::keys::public_key(json);
}

nlohmann::json crn::identity::keys::public_key::json() const{
    return nlohmann::json {
        {"p", crn::utils::eHex(_p)},
        {"q", crn::utils::eHex(_q)},
        {"g", crn::utils::eHex(_g)},
        {"y", crn::utils::eHex(_y)}
    };
}

crn::identity::keys::public_key::public_key(const CryptoPP::Integer& y, const crn::group& other){
    CryptoPP::AlgorithmParameters p = other.params() (CryptoPP::Name::PublicElement(), y);
    _key.AssignFrom(p);
    init();
}



crn::identity::keys::pair::pair(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size): _private(rng, key_size), _public(_private)  { }
crn::identity::keys::pair::pair(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params): _private(rng, params), _public(_private) { }
crn::identity::keys::pair::pair(CryptoPP::AutoSeededRandomPool& rng, const crn::identity::keys::private_key& other): _private(rng, other), _public(_private) { }
crn::identity::keys::pair::pair(const std::string& private_path, const std::string& public_path): _private(private_path), _public(public_path) { }
bool crn::identity::keys::pair::init(){
    return _public.init() && _private.init();
}

void crn::identity::keys::pair::save(const std::string& name) const{
    _public.save(name+".pub");
    _private.save(name);
}


/// ----- identity

crn::packets::request crn::identity::user::request() const{
    crn::blocks::access last = crn::blocks::last::active(_db, pub(), pri());
    crn::packets::request req;
    req.y     = pub().y();
    req.last  = last.address().hash();
    req.token = pub().Gp().Exponentiate( last.active().forward(), pri().x() );
    return req;
}

