// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "utils.h"
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>


std::string crn::utils::eHex(const CryptoPP::Integer& value){
    std::vector<CryptoPP::byte> bytes;
    bytes.resize(value.MinEncodedSize());
    value.Encode(&bytes[0], bytes.size());
    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(bytes.data(), bytes.size());
    encoder.MessageEnd();
    return output;
}

std::string crn::utils::SHA512(const CryptoPP::Integer& value){
    std::vector<CryptoPP::byte> bytes;
    bytes.resize(value.MinEncodedSize());
    value.Encode(&bytes[0], bytes.size());
    CryptoPP::SHA512 hash;
    CryptoPP::byte digest[CryptoPP::SHA512::DIGESTSIZE];
    hash.CalculateDigest(digest, bytes.data(), bytes.size());
    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();
    return output;
}
