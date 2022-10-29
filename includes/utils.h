// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <cryptopp/integer.h>

namespace crn{
namespace utils{

std::string eHex(const CryptoPP::Integer& value);
CryptoPP::Integer dHex(const std::string& str);
std::string SHA512(const CryptoPP::Integer& value);
CryptoPP::Integer sha512(const CryptoPP::Integer& value);

}
}

#endif // UTILS_H
