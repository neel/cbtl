// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "genesis_block.h"
#include "utils.h"

void crn::to_json(nlohmann::json& j, const crn::genesis_block& genesis) {
    j = nlohmann::json{
        {"id",         genesis.hash() },
        {"active",   { crn::utils::eHex(genesis.active()) }  },
        {"passive",  { crn::utils::eHex( genesis.passive().first ), crn::utils::eHex( genesis.passive().second ) } },
        {"checksum",   genesis.checksum() }
    };
}

std::string crn::genesis_block::hash() const{
    return crn::utils::SHA512(_public.y());
}

CryptoPP::Integer crn::genesis_block::active() const{
    return _public.Gp().Exponentiate(_public.g(), _r);
}

std::pair<CryptoPP::Integer, CryptoPP::Integer> crn::genesis_block::passive() const{
    auto Gp = _public.Gp();
    auto Gp1 = _public.Gp1();
    return std::make_pair(
        Gp.Exponentiate(_public.raise(_rho), _r),
        Gp.Multiply( Gp1.MultiplicativeInverse(_rho), _master.raise_x(_public.y()) )
    );
}

std::string crn::genesis_block::checksum() const{
    auto Gp = _public.Gp();
    CryptoPP::Integer h = Gp.Exponentiate(_master.raise_x(_public.y()), _r);
    return crn::utils::SHA512(h);
}
