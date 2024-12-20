// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "cbtl/blocks/contents.h"
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <iostream>

cbtl::blocks::contents::contents(const cbtl::math::free_coordinates& random, const CryptoPP::Integer& gamma, const CryptoPP::Integer& super, const std::string& msg): _random(random), _gamma(gamma), _super(super), _message(msg) { }
cbtl::blocks::contents::contents(const cbtl::keys::identity::public_key& pub, const CryptoPP::Integer& ru, const CryptoPP::Integer& active_req, const cbtl::blocks::addresses& addr, const std::string& msg, const CryptoPP::Integer& super) {
    auto G = pub.G();
    auto Gp = G.Gp();
    CryptoPP::Integer xv = cbtl::utils::sha256::digest(Gp.Exponentiate(pub.y(), ru), CryptoPP::Integer::UNSIGNED), yv = addr.active();
    CryptoPP::Integer xu = cbtl::utils::sha256::digest(active_req, CryptoPP::Integer::UNSIGNED), yu = addr.passive();
    compute(cbtl::math::free_coordinates{xu, yu}, cbtl::math::free_coordinates{xv, yv}, msg, G, super);
}


void cbtl::blocks::contents::compute(const cbtl::math::free_coordinates& p1, const cbtl::math::free_coordinates& p2, const std::string& msg, const cbtl::math::group& G, const CryptoPP::Integer& super){
    cbtl::math::diophantine line = cbtl::math::diophantine::interpolate(p1, p2);
    CryptoPP::AutoSeededRandomPool rng;
    _random = line.random(rng, G.p());
    while(_random == p1 || _random == p2){
        _random = line.random(rng, G.p());
    }
    cbtl::math::free_coordinates r = line.random_nix(rng, G);
    while(r == _random || r == p1 || r == p2){
        r = line.random_nix(rng, G);
    }
    _gamma = r.x();
    assert(_gamma.IsPositive());
    assert(_gamma <= G.p()-1);
    CryptoPP::Integer delta = r.y();
    // std::cout << "password: " << delta << std::endl;

    assert(cbtl::math::diophantine::interpolate(p1, _random) == line);
    assert(cbtl::math::diophantine::interpolate(p2, _random) == line);
    assert(cbtl::math::diophantine::interpolate(p1, r) == line);
    assert(cbtl::math::diophantine::interpolate(p2, r) == line);
    assert(cbtl::math::diophantine::interpolate(r, _random) == line);
    assert(cbtl::math::diophantine::interpolate(p1, _random).eval(_gamma) == delta);
    assert(cbtl::math::diophantine::interpolate(p2, _random).eval(_gamma) == delta);

    // { TODO encrypt msg with delta;
    // std::vector<CryptoPP::byte> bytes;
    // bytes.resize(delta.MinEncodedSize(CryptoPP::Integer::SIGNED));
    // delta.Encode(&bytes[0], bytes.size(), CryptoPP::Integer::SIGNED);
    // CryptoPP::SHA256 hash;
    // CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    // hash.CalculateDigest(digest, bytes.data(), bytes.size());

    auto Gp = G.Gp();
    // CryptoPP::Integer hash_int;
    // hash_int.Decode(&digest[0], CryptoPP::SHA256::DIGESTSIZE);
    // _super = Gp.Multiply(hash_int, Gp.Exponentiate(super, _gamma));
    _super = Gp.Multiply(cbtl::utils::sha256::digest(delta, CryptoPP::Integer::SIGNED), Gp.Exponentiate(super, _gamma));

    // std::string ciphertext;
    // CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
    // enc.SetKey(&digest[0], CryptoPP::SHA256::DIGESTSIZE);
    // CryptoPP::StringSource(msg, true, new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(ciphertext), false))); // StringSource

    // }
    // _message = ciphertext;
    _message = cbtl::utils::aes::encrypt(msg, delta, CryptoPP::Integer::SIGNED);
}
