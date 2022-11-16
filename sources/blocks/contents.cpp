// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/blocks/contents.h"
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <iostream>

crn::blocks::contents::contents(const crn::math::free_coordinates& random, const CryptoPP::Integer& gamma, const CryptoPP::Integer& super, const std::string& msg): _random(random), _gamma(gamma), _message(msg), _super(super) { }
crn::blocks::contents::contents(const crn::keys::identity::public_key& pub, const CryptoPP::Integer& random, const CryptoPP::Integer& active_req, const crn::blocks::addresses& addr, const std::string& msg, const CryptoPP::Integer& super) {
    auto G = pub.G();
    auto Gp = G.Gp();
    CryptoPP::Integer xv = crn::utils::sha256(Gp.Exponentiate(pub.y(), random)), yv = addr.active();

    // std::cout << "coordinates:" << std::endl << xv << yv << std::endl;

    CryptoPP::Integer xu = crn::utils::sha256(active_req), yu = addr.passive();
    compute(crn::math::free_coordinates{xu, yu}, crn::math::free_coordinates{xv, yv}, msg, G, super);
}


void crn::blocks::contents::compute(const crn::math::free_coordinates& p1, const crn::math::free_coordinates& p2, const std::string& msg, const crn::math::group& G, const CryptoPP::Integer& super){
    crn::math::linear_diophantine line = crn::math::linear_diophantine::interpolate(p1, p2);
    CryptoPP::AutoSeededRandomPool rng;
    _random = line.random(rng, G, false);
    while(_random == p1 || _random == p2){
        _random = line.random(rng, G);
    }
    crn::math::free_coordinates r = line.random(rng, G);
    while(r == _random || r == p1 || r == p2){
        r = line.random(rng, G);
    }
    _gamma = r.x();
    assert(_gamma.IsPositive());
    assert(_gamma <= G.p()-1);
    CryptoPP::Integer delta = r.y();
    std::cout << "password: " << delta << std::endl;

    assert(crn::math::linear_diophantine::interpolate(p1, _random) == line);
    assert(crn::math::linear_diophantine::interpolate(p2, _random) == line);
    assert(crn::math::linear_diophantine::interpolate(p1, r) == line);
    assert(crn::math::linear_diophantine::interpolate(p2, r) == line);
    assert(crn::math::linear_diophantine::interpolate(r, _random) == line);
    assert(crn::math::linear_diophantine::interpolate(p1, _random).eval(_gamma) == delta);
    assert(crn::math::linear_diophantine::interpolate(p2, _random).eval(_gamma) == delta);

    // { TODO encrypt msg with delta;
    std::vector<CryptoPP::byte> bytes;
    bytes.resize(delta.MinEncodedSize(CryptoPP::Integer::SIGNED));
    delta.Encode(&bytes[0], bytes.size(), CryptoPP::Integer::SIGNED);
    CryptoPP::SHA256 hash;
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest, bytes.data(), bytes.size());

    CryptoPP::HexEncoder encoder;
    std::string hash_str;
    encoder.Attach(new CryptoPP::StringSink(hash_str));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    std::cout << "H(secret): " << hash_str << std::endl;

    auto Gp = G.Gp();
    CryptoPP::Integer hash_int;
    hash_int.Decode(&digest[0], CryptoPP::SHA256::DIGESTSIZE);
    _super = Gp.Multiply(hash_int, Gp.Exponentiate(super, _gamma));

    std::string ciphertext;
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKey(&digest[0], CryptoPP::SHA256::DIGESTSIZE);
    CryptoPP::StringSource(msg, true, new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(ciphertext), false))); // StringSource

    // }
    _message = ciphertext;

}
