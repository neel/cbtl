// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "cbtl/blocks/addresses.h"
#include "cbtl/utils.h"

cbtl::blocks::addresses::addresses(const CryptoPP::Integer& active, const CryptoPP::Integer& passive): _active(active), _passive(passive){
    if(_active == _passive){
        _id = cbtl::utils::sha512::digest(_active, CryptoPP::Integer::UNSIGNED);
    }else{
        std::string input = cbtl::utils::hex::encode(_active, CryptoPP::Integer::UNSIGNED) + " " + cbtl::utils::hex::encode(_passive, CryptoPP::Integer::UNSIGNED);
        _id = cbtl::utils::sha512::digest(input);
    }
}

std::string cbtl::blocks::addresses::hash() const{
    return cbtl::utils::hex::encode(_id, CryptoPP::Integer::UNSIGNED);
}

