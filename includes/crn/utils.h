// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_UTILS_H
#define CRN_UTILS_H

#include <string>
#include <cryptopp/integer.h>
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>

namespace crn{
namespace utils{

namespace hex{
    std::string encode(const CryptoPP::Integer& value, CryptoPP::Integer::Signedness signedness);
    CryptoPP::Integer decode(const std::string& str, CryptoPP::Integer::Signedness signedness);
}

namespace sha512{
    CryptoPP::Integer digest(const CryptoPP::Integer& value);
    CryptoPP::Integer digest(const std::string& value);
    std::string str(const CryptoPP::Integer& value);
    std::string str(const std::string& value);
}

namespace sha256{
    CryptoPP::Integer digest(const CryptoPP::Integer& value);
    std::string str(const CryptoPP::Integer& value);
}


namespace aes{
    std::string encrypt(const std::string& plaintext, CryptoPP::byte (&digest)[CryptoPP::SHA256::DIGESTSIZE]);
    std::string encrypt(const std::string& plaintext, const CryptoPP::Integer& password, CryptoPP::Integer::Signedness signedness);
    std::string decrypt(const std::string& ciphertext, CryptoPP::byte (&digest)[CryptoPP::SHA256::DIGESTSIZE]);
    std::string decrypt(const std::string& ciphertext, const CryptoPP::Integer& password, CryptoPP::Integer::Signedness signedness);
}

}
}

#endif // CRN_UTILS_H
