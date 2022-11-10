// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/blocks/access.h"
#include "crn/utils.h"
#include "crn/keys.h"
#include "crn/storage.h"
#include <cryptopp/nbtheory.h>
#include <cryptopp/polynomi.h>
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/modes.h>

crn::blocks::access::addresses::addresses(const CryptoPP::Integer& active, const CryptoPP::Integer& passive): _active(active), _passive(passive){
    if(_active == _passive){
        _id = crn::utils::sha512(_active);
    }else{
        std::string input = crn::utils::eHex(_active) + " " + crn::utils::eHex(_passive);
        _id = crn::utils::sha512(input);
    }
}

std::string crn::blocks::access::addresses::hash() const{
    return crn::utils::eHex(_id);
}

crn::blocks::access::contents::contents(const crn::free_coordinates& random, const CryptoPP::Integer& gamma, const std::string& msg): _random(random), _gamma(gamma), _message(msg) { }
crn::blocks::access::contents::contents(const crn::keys::identity::public_key& pub, const CryptoPP::Integer& random, const CryptoPP::Integer& active_req, const crn::blocks::access::addresses& addr, const std::string& msg) {
    auto G = pub.G();
    auto Gp = G.Gp();
    CryptoPP::Integer xv = Gp.Exponentiate(pub.y(), random), yv = addr.active();
    CryptoPP::Integer xu = active_req, yu = addr.passive();
    compute(crn::free_coordinates{xu, yu}, crn::free_coordinates{xv, yv}, msg, G);
}


void crn::blocks::access::contents::compute(const crn::free_coordinates& p1, const crn::free_coordinates& p2, const std::string& msg, const crn::group& G){
    crn::linear_diophantine line = crn::linear_diophantine::interpolate(p1, p2);
    CryptoPP::AutoSeededRandomPool rng;
    _random = line.random(rng, G.p()-1);
    crn::free_coordinates r = line.random(rng, G.p()-1);
    _gamma = r.x();
    CryptoPP::Integer delta = r.y();
    std::cout << "password: " << delta << std::endl;

    // { TODO encrypt msg with delta;
    auto signedness = delta.IsNegative() ? CryptoPP::Integer::SIGNED : CryptoPP::Integer::UNSIGNED;
    std::vector<CryptoPP::byte> bytes;
    bytes.resize(delta.MinEncodedSize(signedness));
    delta.Encode(&bytes[0], bytes.size());
    CryptoPP::SHA256 hash;
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest, bytes.data(), bytes.size());
    std::string ciphertext;
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKey(&digest[0], CryptoPP::SHA256::DIGESTSIZE);
    CryptoPP::StringSource(msg, true, new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(ciphertext), false))); // StringSource

    // }
    _message = ciphertext;

}


crn::blocks::access::access(const parts::active& active, const parts::passive& passive, const addresses& addr, const contents& body): _active(active), _passive(passive), _address(addr), _contents(body){}

crn::blocks::access crn::blocks::access::genesis(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params& p, const crn::keys::identity::private_key& master){
    if(p.a().genesis() == p.p().genesis() && p.a().genesis()){
        CryptoPP::Integer random;
        auto active  = parts::active::construct(rng, p.a(), master, random);
        auto passive = parts::passive::construct(rng, p.p(), master);

        addresses addr(p.a().pub().y(), p.p().pub().y());
        access::contents contents(p.p().pub(), random, 0, addr, "genesis");
        return access(active, passive, addr, contents);
    }else{
        throw std::invalid_argument("p is not genesis parameters");
    }
}

crn::blocks::access crn::blocks::access::construct(CryptoPP::AutoSeededRandomPool& rng, const crn::blocks::params& p, const crn::keys::identity::private_key& master, const CryptoPP::Integer& active_request) {
    auto Gp = master.Gp();

    CryptoPP::Integer random;
    auto active  = parts::active::construct(rng, p.a(), master, random);
    auto passive = parts::passive::construct(rng, p.p(), master);

    if(active_request.IsZero()){
        throw std::invalid_argument("active_request must not be zero unless it is a genesis block (use genesis function in that case)");
    }
    if(p.a().genesis() == p.p().genesis() && p.a().genesis()){
        throw std::invalid_argument("genesis parms not accepted (use genesis function)");
    }

    CryptoPP::Integer addr_active  = p.a().address(active_request);
    CryptoPP::Integer addr_passive = p.p().address();

    addresses addr(addr_active, addr_passive);
    access::contents contents(p.p().pub(), random, active_request, addr, "Hello World");

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

