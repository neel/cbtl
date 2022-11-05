// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/keys.h"
#include "crn/storage.h"
#include "crn/blocks/io.h"
#include "crn/packets.h"
#include "crn/group.h"
#include <cryptopp/argnames.h>

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
        (CryptoPP::Name::Modulus(),             crn::utils::dHex(json["p"].get<std::string>()))
        (CryptoPP::Name::SubgroupOrder(),       crn::utils::dHex(json["q"].get<std::string>()))
        (CryptoPP::Name::SubgroupGenerator(),   crn::utils::dHex(json["g"].get<std::string>()))
        (CryptoPP::Name::PrivateExponent(),     crn::utils::dHex(json["x"].get<std::string>()));
    _key.AssignFrom(p);
    init();
}

crn::keys::identity::private_key crn::keys::identity::private_key::from(const nlohmann::json& json){
    return crn::keys::identity::private_key(json);
}

nlohmann::json crn::keys::identity::private_key::json() const{
    return nlohmann::json {
        {"p", crn::utils::eHex(_p)},
        {"q", crn::utils::eHex(_q)},
        {"g", crn::utils::eHex(_g)},
        {"x", crn::utils::eHex(_x)}
    };
}



bool crn::keys::identity::private_key::initialize() {
    _key.GetValue("PrivateExponent", _x);
    CryptoPP::Integer x_inverse = Gp1().MultiplicativeInverse(_x);
    return x_inverse != 0 && Gp().Exponentiate(Gp().Exponentiate(_g, x_inverse), _x) == _g;
}

crn::keys::identity::public_key::public_key(const crn::keys::identity::private_key& pk){
    _key.AssignFrom(pk.key());
    init();
}
bool crn::keys::identity::public_key::initialize() {
    _key.GetValue("PublicElement", _y);
    return true;
}

std::string crn::keys::identity::public_key::genesis_id() const{
    return crn::utils::eHex(crn::utils::sha512(_y));
}
crn::keys::identity::public_key::public_key(const nlohmann::json& json, bool){
    auto p = CryptoPP::MakeParameters
        (CryptoPP::Name::Modulus(),             crn::utils::dHex(json["p"].get<std::string>()))
        (CryptoPP::Name::SubgroupOrder(),       crn::utils::dHex(json["q"].get<std::string>()))
        (CryptoPP::Name::SubgroupGenerator(),   crn::utils::dHex(json["g"].get<std::string>()))
        (CryptoPP::Name::PublicElement(),       crn::utils::dHex(json["y"].get<std::string>()));
    _key.AssignFrom(p);
    init();
}
crn::keys::identity::public_key crn::keys::identity::public_key::from(const nlohmann::json& json){
    return crn::keys::identity::public_key(json);
}

nlohmann::json crn::keys::identity::public_key::json() const{
    return nlohmann::json {
        {"p", crn::utils::eHex(_p)},
        {"q", crn::utils::eHex(_q)},
        {"g", crn::utils::eHex(_g)},
        {"y", crn::utils::eHex(_y)}
    };
}

crn::keys::identity::public_key::public_key(const CryptoPP::Integer& y, const crn::group& other){
    CryptoPP::AlgorithmParameters p = other.params() (CryptoPP::Name::PublicElement(), y);
    _key.AssignFrom(p);
    init();
}



crn::keys::identity::pair::pair(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size): _private(rng, key_size), _public(_private)  { }
crn::keys::identity::pair::pair(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params): _private(rng, params), _public(_private) { }
crn::keys::identity::pair::pair(CryptoPP::AutoSeededRandomPool& rng, const crn::keys::identity::private_key& other): _private(rng, other), _public(_private) { }
crn::keys::identity::pair::pair(const std::string& private_path, const std::string& public_path): _private(private_path), _public(public_path) { }
bool crn::keys::identity::pair::init(){
    return _public.init() && _private.init();
}

void crn::keys::identity::pair::save(const std::string& name) const{
    _public.save(name+".pub");
    _private.save(name);
}



crn::keys::access_key crn::keys::access_key::construct(const CryptoPP::Integer& theta, const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& master){
    auto Gp = pub.Gp();
    auto secret = Gp.Exponentiate(Gp.Exponentiate(pub.y(), theta), master.x());

    return crn::keys::access_key(secret);
}


crn::keys::access_key::access_key(const std::string& path){
    std::ifstream file(path);
    std::string hexed;
    file >> hexed;
    _secret = crn::utils::dHex(hexed);
}


CryptoPP::Integer crn::keys::access_key::prepare(const crn::keys::identity::private_key& pri, const CryptoPP::Integer& k, const CryptoPP::Integer& lambda) const{
    auto Gp = pri.Gp(), Gp1 = pri.Gp1();
    auto x_inv = Gp1.MultiplicativeInverse(pri.x());
    auto res   = Gp.Exponentiate(_secret, x_inv);
         res   = Gp.Exponentiate(res, k);
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
    access << crn::utils::eHex(_secret);
    access.close();
}

void crn::keys::access_key::load(const std::string& name){
    std::ifstream access(name+".access");
    std::string hexed;
    access >> hexed;
    access.close();
    _secret = crn::utils::dHex(hexed);
}


