// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/blocks/access.h"
#include "crn/utils.h"
#include "crn/keys.h"
#include "crn/storage.h"

crn::blocks::access::addresses::addresses(const CryptoPP::Integer& active, const CryptoPP::Integer& passive): _active(active), _passive(passive){
    if(_active == _passive){
        _id = crn::utils::sha512(_active);
    }else{
        _id = crn::utils::sha512(crn::utils::eHex(_active) + " " + crn::utils::eHex(_passive));
    }
}

std::string crn::blocks::access::addresses::hash() const{
    return crn::utils::eHex(_id);
}

crn::blocks::access::access(const parts::active& active, const parts::passive& passive, const addresses& addr): _active(active), _passive(passive), _address(addr){}

crn::blocks::access crn::blocks::access::genesis(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params& p, const crn::identity::keys::private_key& master){
    if(p._active.genesis() == p._passive.genesis() && p._active.genesis()){
        auto active  = parts::active::construct(rng, p._active, master);
        auto passive = parts::passive::construct(rng, p._passive, master);

        addresses addr(p._active.pub().y(), p._passive.pub().y());
        return access(active, passive, addr);
    }else{
        throw std::invalid_argument("p is not genesis parameters");
    }
}

crn::blocks::access crn::blocks::access::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params& p, const crn::identity::keys::private_key& master, const CryptoPP::Integer& active_request) {
    auto active  = parts::active::construct(rng, p._active, master);
    auto passive = parts::passive::construct(rng, p._passive, master);

    if(active_request.IsZero()){
        throw std::invalid_argument("active_request must not be zero unless it is a genesis block (use genesis function in that case)");
    }
    if(p._active.genesis() == p._passive.genesis() && p._active.genesis()){
        throw std::invalid_argument("genesis parms not accepted (use genesis function)");
    }

    CryptoPP::Integer addr_active  = p._active.address(active_request);
    CryptoPP::Integer addr_passive = p._passive.address();
    addresses addr(addr_active, addr_passive);
    return access(active, passive, addr);
}

crn::blocks::access crn::blocks::genesis(crn::storage& db, const crn::identity::keys::public_key& pub){
    return db.fetch(pub.genesis_id());
}

crn::blocks::access crn::blocks::last::active(crn::storage& db, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& pri){
    crn::blocks::access last = crn::blocks::genesis(db, pub);
    while(true){
        std::string address = last.active().next(pub.G(), last.address().id(), pri.x());
        if(db.exists(address, true)){
            std::string block_id = db.id(address);
            last = db.fetch(block_id);
        }else{
            break;
        }
    }

    return last;
}

crn::blocks::access crn::blocks::last::passive(crn::storage& db, const crn::identity::keys::public_key& pub, const crn::identity::keys::private_key& secret){
    crn::blocks::access last = crn::blocks::genesis(db, pub);
    while(true){
        std::string address = last.passive().next(pub.G(), last.address().id(), pub.y(), secret.x());
        if(db.exists(address, true)){
            std::string block_id = db.id(address);
            last = db.fetch(block_id);
        }else{
            break;
        }
    }
    return last;
}

