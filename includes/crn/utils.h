// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_UTILS_H
#define CRN_UTILS_H

#include <string>
#include <cryptopp/integer.h>

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

}
}

#endif // CRN_UTILS_H
