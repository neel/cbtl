// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "keys.h"
#include "blocks_io.h"

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

std::string crn::identity::user::last_id() const{
    std::string last;
    std::string block_id = pub().genesis_id();
    while(true){
        if(_db.exists(block_id)){
            last  = block_id;
            crn::blocks::access block = _db.fetch(block_id);
            block_id = block.active().next(pub().G(), block.address().id(), pri().x());
        }else{
            break;
        }
    }
    return last;
}

CryptoPP::Integer crn::identity::user::request(std::string& id) const{
    auto Gp = pub().G().Gp();
    id = last_id();
    crn::blocks::access block = _db.fetch(id);
    std::cout << "last_id: " << id << std::endl;
    std::cout << "block.forward: " << block.active().forward() << std::endl;
    return Gp.Exponentiate( block.active().forward(), pri().x() );
}

crn::packets::request crn::identity::user::request() const{
    crn::packets::request req;
    req.token = request(req.last);
    std::cout << "req.token: " << req.token<< std::endl;
    return req;
}

