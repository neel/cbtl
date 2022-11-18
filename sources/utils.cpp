// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/utils.h"
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>


std::string crn::utils::hex::encode(const CryptoPP::Integer& value, CryptoPP::Integer::Signedness signedness){
    std::vector<CryptoPP::byte> bytes;
    bytes.resize(value.MinEncodedSize(signedness));
    value.Encode(&bytes[0], bytes.size(), signedness);
    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(bytes.data(), bytes.size());
    encoder.MessageEnd();
    return output;
}

CryptoPP::Integer crn::utils::hex::decode(const std::string& str, CryptoPP::Integer::Signedness signedness){
    CryptoPP::HexDecoder decoder;
    decoder.Put( (CryptoPP::byte*) str.data(), str.size() );
    decoder.MessageEnd();
    std::vector<CryptoPP::byte> bytes;
    bytes.resize(decoder.MaxRetrievable());
    decoder.Get(&bytes[0], bytes.size());
    CryptoPP::Integer value;
    value.Decode(&bytes[0], bytes.size(), signedness);
    return value;
}


std::string crn::utils::sha512::str(const CryptoPP::Integer& value){
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

std::string crn::utils::sha256::str(const CryptoPP::Integer& value){
    std::vector<CryptoPP::byte> bytes;
    bytes.resize(value.MinEncodedSize());
    value.Encode(&bytes[0], bytes.size());
    CryptoPP::SHA256 hash;
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest, bytes.data(), bytes.size());
    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();
    return output;
}

std::string crn::utils::sha512::str(const std::string& value){
    std::vector<CryptoPP::byte> bytes;
    std::copy(value.begin(), value.end(), std::back_inserter(bytes));
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

CryptoPP::Integer crn::utils::sha512::digest(const CryptoPP::Integer& value){
    std::vector<CryptoPP::byte> bytes;
    bytes.resize(value.MinEncodedSize());
    value.Encode(&bytes[0], value.MinEncodedSize());
    CryptoPP::SHA512 hash;
    CryptoPP::byte digest[CryptoPP::SHA512::DIGESTSIZE];
    hash.CalculateDigest(digest, bytes.data(), bytes.size());
    CryptoPP::Integer ret;
    ret.Decode(&digest[0], CryptoPP::SHA512::DIGESTSIZE);
    return ret;
}

CryptoPP::Integer crn::utils::sha256::digest(const CryptoPP::Integer& value){
    std::vector<CryptoPP::byte> bytes;
    bytes.resize(value.MinEncodedSize());
    value.Encode(&bytes[0], value.MinEncodedSize());
    CryptoPP::SHA256 hash;
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest, bytes.data(), bytes.size());
    CryptoPP::Integer ret;
    ret.Decode(&digest[0], CryptoPP::SHA256::DIGESTSIZE);
    return ret;
}

CryptoPP::Integer crn::utils::sha512::digest(const std::string& value){
    std::vector<CryptoPP::byte> bytes;
    std::copy(value.begin(), value.end(), std::back_inserter(bytes));
    CryptoPP::SHA512 hash;
    CryptoPP::byte digest[CryptoPP::SHA512::DIGESTSIZE];
    hash.CalculateDigest(digest, bytes.data(), bytes.size());
    CryptoPP::Integer ret;
    ret.Decode(&digest[0], CryptoPP::SHA512::DIGESTSIZE);
    return ret;
}

