// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_KEYS_ACCESS_H
#define cbtl_KEYS_ACCESS_H

#include <string>
#include "cbtl/keys/public.h"
#include <cryptopp/integer.h>

namespace cbtl{
namespace keys{

struct access_key{
    void save(const std::string& path) const;
    void load(const std::string& path);

    access_key() = delete;

    static access_key construct(const CryptoPP::Integer& theta, const cbtl::keys::identity::public_key& pub, const cbtl::keys::identity::private_key& master);
    access_key(const std::string& path);

    CryptoPP::Integer prepare(const cbtl::keys::identity::private_key& pri, const CryptoPP::Integer& lambda) const;

    static CryptoPP::Integer reconstruct(const CryptoPP::Integer& prepared, const CryptoPP::Integer& lambda, const cbtl::keys::identity::private_key& master);

    inline const CryptoPP::Integer& secret() const { return _secret; }
    private:
        inline explicit access_key(const CryptoPP::Integer& secret): _secret(secret) {}
    private:
        CryptoPP::Integer _secret;
};

}
}

#endif // cbtl_KEYS_ACCESS_H
