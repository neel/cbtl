// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_KEYS_VIEW_H
#define cbtl_KEYS_VIEW_H

#include <string>
#include "cbtl/keys/public.h"
#include <cryptopp/integer.h>

namespace cbtl{
namespace keys{

struct view_key{
    void save(const std::string& name) const;
    void load(const std::string& name);

    view_key() = delete;

    inline explicit view_key(const CryptoPP::Integer& phi): _secret(phi) {}
    static view_key construct(const CryptoPP::Integer& phi, const cbtl::keys::identity::public_key& pub, const cbtl::keys::identity::private_key& master);
    explicit view_key(const std::string& name);

    inline const CryptoPP::Integer& secret() const { return _secret; }
    private:
        CryptoPP::Integer _secret;
};

}
}

#endif // cbtl_KEYS_VIEW_H
