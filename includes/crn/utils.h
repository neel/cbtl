// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_UTILS_H
#define CRN_UTILS_H

#include <string>
#include <cryptopp/integer.h>

namespace crn{
namespace utils{

std::string eHex(const CryptoPP::Integer& value);
CryptoPP::Integer dHex(const std::string& str);
std::string SHA512(const CryptoPP::Integer& value);
std::string SHA256(const CryptoPP::Integer& value);
std::string SHA512(const std::string& value);
CryptoPP::Integer sha512(const CryptoPP::Integer& value);
CryptoPP::Integer sha512(const std::string& value);

}
}

#endif // CRN_UTILS_H
