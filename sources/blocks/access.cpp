// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "cbtl/blocks/access.h"
#include "cbtl/blocks/contents.h"
#include "cbtl/utils.h"
#include "cbtl/keys.h"
#include "cbtl/redis-storage.h"
#include <cryptopp/nbtheory.h>
#include <cryptopp/polynomi.h>
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>

cbtl::blocks::access::access(const parts::active& active, const parts::passive& passive, const addresses& addr, const contents& body, const boost::posix_time::ptime& requested): _active(active), _passive(passive), _address(addr), _contents(body), _requested(requested) {}

cbtl::blocks::access cbtl::blocks::access::genesis(CryptoPP::AutoSeededRandomPool& rng, const cbtl::blocks::params& p, const cbtl::keys::identity::private_key& master, const CryptoPP::Integer& h){
    if(p.a().genesis() == p.p().genesis() && p.a().genesis()){
        auto G = master.G();
        auto Gp = G.Gp();

        CryptoPP::Integer rv = G.random(rng, false);   // r_{v}
        CryptoPP::Integer ru = G.random(rng, false);   // r_{u}
        CryptoPP::Integer dux = cbtl::utils::sha256::digest(0, CryptoPP::Integer::UNSIGNED);
        while(true){
            ru = G.random(rng, false);   // r_{u}
            CryptoPP::Integer dvx = cbtl::utils::sha256::digest(Gp.Exponentiate(p.p().pub().y(), ru), CryptoPP::Integer::UNSIGNED);
            if((dux.IsEven() && dvx.IsOdd()) || (dux.IsOdd() && dvx.IsEven())){
                assert((dux - dvx).IsOdd());
                break;
            }
        }

        auto active  = parts::active::construct(p.a(), master, ru, rv);
        auto passive = parts::passive::construct(p.p(), h, ru, rv, 0, master);

        cbtl::blocks::addresses addr(p.a().pub().y(), p.p().pub().y());
        cbtl::blocks::contents contents(p.p().pub(), ru, 0, addr, "genesis", 0);
        return access(active, passive, addr, contents, p.requested());
    }else{
        throw std::invalid_argument("p is not genesis parameters");
    }
}

cbtl::blocks::access cbtl::blocks::access::construct(CryptoPP::AutoSeededRandomPool& rng, const cbtl::blocks::params& p, const cbtl::keys::identity::private_key& master, const CryptoPP::Integer& active_request, const CryptoPP::Integer& gaccess, const CryptoPP::Integer& passive_forward_last, const cbtl::keys::view_key& view, const std::string message) {
    auto G = master.G();
    auto Gp = G.Gp();

    if(active_request.IsZero()){
        throw std::invalid_argument("active_request must not be zero unless it is a genesis block (use genesis function in that case)");
    }
    if(p.a().genesis() == p.p().genesis() && p.a().genesis()){
        throw std::invalid_argument("genesis parms not accepted (use genesis function)");
    }

    CryptoPP::Integer rv = G.random(rng, false);   // r_{v}
    CryptoPP::Integer ru = G.random(rng, false);   // r_{u}
    CryptoPP::Integer dux = cbtl::utils::sha256::digest(active_request, CryptoPP::Integer::UNSIGNED);
    while(true){
        ru = G.random(rng, false);   // r_{u}
        CryptoPP::Integer dvx = cbtl::utils::sha256::digest(Gp.Exponentiate(p.p().pub().y(), ru), CryptoPP::Integer::UNSIGNED);
        if((dux.IsEven() && dvx.IsOdd()) || (dux.IsOdd() && dvx.IsEven())){
            assert((dux - dvx).IsOdd());
            break;
        }
    }

    auto active  = parts::active::construct(p.a(), master, ru, rv);
    auto passive = parts::passive::construct(p.p(), cbtl::utils::sha512::digest(gaccess, CryptoPP::Integer::UNSIGNED), ru, rv, passive_forward_last, master);

    auto suffix = Gp.Exponentiate(Gp.Multiply(Gp.Exponentiate(G.g(), view.secret()),  gaccess), master.x());

    // std::cout << "suffix: " << suffix << std::endl;

    CryptoPP::Integer addr_active  = p.a().address(active_request);
    CryptoPP::Integer addr_passive = p.p().address();

    addresses addr(addr_active, addr_passive);
    cbtl::blocks::contents contents(p.p().pub(), ru, active_request, addr, message, suffix);

    // std::cout << "active_request: " << active_request << std::endl;
    // std::cout << "id: " << addr.hash() << std::endl;

    return access(active, passive, addr, contents, p.requested());
}

cbtl::blocks::access cbtl::blocks::genesis(cbtl::storage& db, const cbtl::keys::identity::public_key& pub){
    return db.fetch(pub.genesis_id());
}

cbtl::blocks::access cbtl::blocks::last::active(cbtl::storage& db, const cbtl::keys::identity::public_key& pub, const cbtl::keys::identity::private_key& pri){
    cbtl::blocks::access last = cbtl::blocks::genesis(db, pub);
    while(true){
        std::string address = last.active().next(pub.G(), last.address().id(), pri);
        if(db.exists(address, true)){
            std::string block_id = db.id(address);
            last = db.fetch(block_id);
        }else{
            break;
        }
    }

    return last;
}

cbtl::blocks::access cbtl::blocks::last::passive(cbtl::storage& db, const cbtl::keys::identity::public_key& pub, const cbtl::keys::identity::private_key& secret){
    cbtl::blocks::access last = cbtl::blocks::genesis(db, pub);
    while(true){
        std::string address = last.passive().next(pub.G(), last.address().id(), secret);
        if(db.exists(address, true)){
            std::string block_id = db.id(address);
            last = db.fetch(block_id);
        }else{
            break;
        }
    }
    return last;
}

cbtl::blocks::access cbtl::blocks::last::passive(cbtl::storage& db, const cbtl::keys::identity::public_key& pub, const CryptoPP::Integer& gaccess, const cbtl::keys::identity::private_key& master){
    CryptoPP::Integer h = cbtl::utils::sha512::digest(gaccess, CryptoPP::Integer::UNSIGNED);
    cbtl::blocks::access last = cbtl::blocks::genesis(db, pub);
    while(true){
        std::string address = last.passive().next(pub.G(), last.address().id(), h, master);
        if(db.exists(address, true)){
            // std::cout << "cbtl::blocks::access cbtl::blocks::last::passive: " << "next" << std::endl;
            std::string block_id = db.id(address);
            last = db.fetch(block_id);
        }else{
            // std::cout << "cbtl::blocks::access cbtl::blocks::last::passive: " << "end" << std::endl;
            break;
        }
    }
    return last;
}



