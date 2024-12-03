// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "cbtl/keys/view.h"
#include "cbtl/utils.h"
#include "cbtl/keys/private.h"


cbtl::keys::view_key cbtl::keys::view_key::construct(const CryptoPP::Integer& phi, const cbtl::keys::identity::public_key& pub, const cbtl::keys::identity::private_key& master){
    auto Gp = pub.Gp();
    auto secret = Gp.Exponentiate(Gp.Exponentiate(pub.y(), phi), master.x());

    return cbtl::keys::view_key(secret);
}

cbtl::keys::view_key::view_key(const std::string& name){
    load(name);
}


void cbtl::keys::view_key::save(const std::string& name) const{
    std::ofstream access(name+".view");
    access << cbtl::utils::hex::encode(_secret, CryptoPP::Integer::UNSIGNED);
    access.close();
}

void cbtl::keys::view_key::load(const std::string& name){
    std::ifstream view(name);
    if(!view.is_open()){
        throw std::runtime_error("Failed to open "+name);
    }
    std::string hexed;
    view >> hexed;
    view.close();
    _secret = cbtl::utils::hex::decode(hexed, CryptoPP::Integer::UNSIGNED);
}
