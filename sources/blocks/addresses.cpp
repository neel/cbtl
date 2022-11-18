// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/blocks/addresses.h"
#include "crn/utils.h"

crn::blocks::addresses::addresses(const CryptoPP::Integer& active, const CryptoPP::Integer& passive): _active(active), _passive(passive){
    if(_active == _passive){
        _id = crn::utils::sha512::digest(_active);
    }else{
        std::string input = crn::utils::hex::encode(_active, CryptoPP::Integer::UNSIGNED) + " " + crn::utils::hex::encode(_passive, CryptoPP::Integer::UNSIGNED);
        _id = crn::utils::sha512::digest(input);
    }
}

std::string crn::blocks::addresses::hash() const{
    return crn::utils::hex::encode(_id, CryptoPP::Integer::UNSIGNED);
}

