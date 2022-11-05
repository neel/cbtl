// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/packets.h"
#include "crn/utils.h"
#include "crn/keys.h"
#include "crn/blocks/access.h"
#include "crn/storage.h"

crn::packets::request crn::packets::request::construct(const crn::blocks::access& block, const crn::keys::identity::pair& keys){
    crn::packets::request req;
    req.y     = keys.pub().y();
    req.last  = block.address().hash();
    req.token = keys.pub().Gp().Exponentiate( block.active().forward(), keys.pri().x() );
    return req;
}

crn::packets::request crn::packets::request::construct(crn::storage& db, const crn::keys::identity::pair& keys){
    return construct(crn::blocks::last::active(db, keys.pub(), keys.pri()), keys);
}



void crn::packets::to_json(nlohmann::json& j, const request& q){
    j = nlohmann::json {
        {"y",     crn::utils::eHex(q.y)},
        {"last",  q.last},
        {"token", crn::utils::eHex(q.token)}
    };
}

void crn::packets::from_json(const nlohmann::json& j, request& q){
    q.y     = crn::utils::dHex(j["y"].get<std::string>());
    q.last  = j["last"].get<std::string>();
    q.token = crn::utils::dHex(j["token"].get<std::string>());
}

void crn::packets::to_json(nlohmann::json& j, const challenge& c){
    j = nlohmann::json {
        {"c1", crn::utils::eHex(c.c1)},
        {"c2", crn::utils::eHex(c.c2)},
        {"c3", crn::utils::eHex(c.c3)},
        {"random", crn::utils::eHex(c.random)}
    };
}

void crn::packets::from_json(const nlohmann::json& j, challenge& c){
    c.c1 = crn::utils::dHex(j["c1"].get<std::string>());
    c.c2 = crn::utils::dHex(j["c2"].get<std::string>());
    c.c3 = crn::utils::dHex(j["c3"].get<std::string>());
    c.random = crn::utils::dHex(j["random"].get<std::string>());
}

void crn::packets::to_json(nlohmann::json& j, const response& res){
    j = nlohmann::json {
        {"c1", crn::utils::eHex(res.c1)},
        {"c2", crn::utils::eHex(res.c2)},
        {"c3", crn::utils::eHex(res.c3)},
        {"access", crn::utils::eHex(res.access)}
    };
}

void crn::packets::from_json(const nlohmann::json& j, response& res){
    res.c1 = crn::utils::dHex(j["c1"].get<std::string>());
    res.c2 = crn::utils::dHex(j["c2"].get<std::string>());
    res.c3 = crn::utils::dHex(j["c3"].get<std::string>());
    res.access = crn::utils::dHex(j["access"].get<std::string>());
}

