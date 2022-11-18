// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/blocks/access.h"
#include "crn/blocks/contents.h"
#include "crn/utils.h"
#include "crn/keys.h"
#include "crn/storage.h"
#include <cryptopp/nbtheory.h>
#include <cryptopp/polynomi.h>
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>

crn::blocks::access::access(const parts::active& active, const parts::passive& passive, const addresses& addr, const contents& body): _active(active), _passive(passive), _address(addr), _contents(body){}

crn::blocks::access crn::blocks::access::genesis(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params& p, const crn::keys::identity::private_key& master){
    if(p.a().genesis() == p.p().genesis() && p.a().genesis()){
        CryptoPP::Integer random;
        auto active  = parts::active::construct(rng, p.a(), master, random);
        auto passive = parts::passive::construct(rng, p.p(), master);

        crn::blocks::addresses addr(p.a().pub().y(), p.p().pub().y());
        crn::blocks::contents contents(p.p().pub(), random, 0, addr, "genesis", 0);
        return access(active, passive, addr, contents);
    }else{
        throw std::invalid_argument("p is not genesis parameters");
    }
}

crn::blocks::access crn::blocks::access::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params& p, const crn::keys::identity::private_key& master, const CryptoPP::Integer& active_request, const CryptoPP::Integer& gaccess, const crn::keys::view_key& view) {
    auto G = master.G();
    auto Gp = G.Gp();

    CryptoPP::Integer random;   // r_{u}
    auto active  = parts::active::construct(rng, p.a(), master, random);
    // TODO if SHA256(active_request) is Odd then SHA256(g^{\pi_{v} r_{u}}) has to be Even or vice versa
    auto passive = parts::passive::construct(rng, p.p(), master);

    if(active_request.IsZero()){
        throw std::invalid_argument("active_request must not be zero unless it is a genesis block (use genesis function in that case)");
    }
    if(p.a().genesis() == p.p().genesis() && p.a().genesis()){
        throw std::invalid_argument("genesis parms not accepted (use genesis function)");
    }

    auto suffix = Gp.Exponentiate(Gp.Multiply(Gp.Exponentiate(G.g(), view.secret()),  gaccess), master.x());

    std::cout << "suffix: " << suffix << std::endl;

    CryptoPP::Integer addr_active  = p.a().address(active_request);
    CryptoPP::Integer addr_passive = p.p().address();

    addresses addr(addr_active, addr_passive);
    crn::blocks::contents contents(p.p().pub(), random, active_request, addr, "Hello World", suffix);

    return access(active, passive, addr, contents);
}

crn::blocks::access crn::blocks::genesis(crn::storage& db, const crn::keys::identity::public_key& pub){
    return db.fetch(pub.genesis_id());
}

crn::blocks::access crn::blocks::last::active(crn::storage& db, const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& pri){
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

crn::blocks::access crn::blocks::last::passive(crn::storage& db, const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& secret){
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

void crn::blocks::access::line(const CryptoPP::Integer& xu, const CryptoPP::Integer& xv) const{
    CryptoPP::Integer delta_x, delta_y;
}

