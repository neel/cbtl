// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "packets.h"
#include "utils.h"

void crn::packets::to_json(nlohmann::json& j, const request& q){
    j = nlohmann::json {
        {"last", q.last},
        {"token", crn::utils::eHex(q.token)}
    };
}

void crn::packets::from_json(const nlohmann::json& j, request& q){
    q.last  = j["last"].get<std::string>();
    q.token = crn::utils::dHex(j["token"].get<std::string>());
}

void crn::packets::to_json(nlohmann::json& j, const challenge& c){
    j = nlohmann::json {
        {"c1", crn::utils::eHex(c.c1)},
        {"c1", crn::utils::eHex(c.c2)},
        {"c3", crn::utils::eHex(c.c3)},
    };
}

void crn::packets::from_json(const nlohmann::json& j, challenge& c){
    c.c1 = crn::utils::dHex(j["c1"].get<std::string>());
    c.c2 = crn::utils::dHex(j["c2"].get<std::string>());
    c.c3 = crn::utils::dHex(j["c3"].get<std::string>());
}
