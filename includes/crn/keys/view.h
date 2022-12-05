// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_KEYS_VIEW_H
#define CRN_KEYS_VIEW_H

#include <string>
#include "crn/keys/public.h"
#include <cryptopp/integer.h>

namespace crn{
namespace keys{

struct view_key{
    void save(const std::string& name) const;
    void load(const std::string& name);

    view_key() = delete;

    inline explicit view_key(const CryptoPP::Integer& phi): _secret(phi) {}
    static view_key construct(const CryptoPP::Integer& phi, const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& master);
    explicit view_key(const std::string& name);

    inline const CryptoPP::Integer& secret() const { return _secret; }
    private:
        CryptoPP::Integer _secret;
};

}
}

#endif // CRN_KEYS_VIEW_H
