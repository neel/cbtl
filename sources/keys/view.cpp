// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/keys/view.h"
#include "crn/utils.h"
#include "crn/keys/private.h"


crn::keys::view_key crn::keys::view_key::construct(const CryptoPP::Integer& phi, const crn::keys::identity::public_key& pub, const crn::keys::identity::private_key& master){
    auto Gp = pub.Gp();
    auto secret = Gp.Exponentiate(Gp.Exponentiate(pub.y(), phi), master.x());

    return crn::keys::view_key(secret);
}

crn::keys::view_key::view_key(const std::string& name){
    load(name);
}


void crn::keys::view_key::save(const std::string& name) const{
    std::ofstream access(name+".view");
    access << crn::utils::eHex(_secret, CryptoPP::Integer::UNSIGNED);
    access.close();
}

void crn::keys::view_key::load(const std::string& name){
    std::ifstream view(name);
    if(!view.is_open()){
        throw std::runtime_error("Failed to open "+name);
    }
    std::string hexed;
    view >> hexed;
    view.close();
    _secret = crn::utils::dHex(hexed, CryptoPP::Integer::UNSIGNED);
}
