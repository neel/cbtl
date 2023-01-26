// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/packets.h"
#include "crn/utils.h"
#include "crn/keys.h"
#include "crn/blocks/access.h"
#include "crn/storage.h"

crn::packets::request crn::packets::request::construct(const crn::blocks::access& block, const crn::keys::identity::pair& keys){
    crn::packets::request req;
    req.y      = keys.pub().y();
    req.last   = block.address().hash();
    req.token  = keys.pub().Gp().Exponentiate( block.active().forward(), keys.pri().x() );
    return req;
}

crn::packets::request crn::packets::request::construct(crn::storage& db, const crn::keys::identity::pair& keys){
    return construct(crn::blocks::last::active(db, keys.pub(), keys.pri()), keys);
}


// void crn::packets::to_json(nlohmann::json& j, const action_data<actions::identify>& q){
//     j = nlohmann::json {
//         {"type", static_cast<std::uint32_t>(actions::identify)},
//         {"anchor", q.anchor()}
//     };
// }
// void crn::packets::from_json(const nlohmann::json& j, action_data<actions::identify>& q){
//     q._anchor = j["anchor"].get<std::string>();
// }

// void crn::packets::to_json(nlohmann::json& j, const action_data<actions::fetch>& q){
//     j = nlohmann::json {
//         {"type", static_cast<std::uint32_t>(actions::fetch)},
//         {"y", crn::utils::hex::encode(q.y(), CryptoPP::Integer::UNSIGNED)}
//     };
// }
// void crn::packets::from_json(const nlohmann::json& j, action_data<actions::fetch>& q){
//     q._y = crn::utils::hex::decode(j["y"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
// }

// void crn::packets::to_json(nlohmann::json& j, const action_data<actions::insert>& q){
//     nlohmann::json cases = nlohmann::json::array();
//     for(auto i = q.begin(); i != q.end(); ++i){
//         const action_data<actions::insert>::data& d = *i;
//         cases.push_back(d);
//     }
//     j = nlohmann::json {
//         {"type", static_cast<std::uint32_t>(actions::insert)},
//         {"y", crn::utils::hex::encode(q.y(), CryptoPP::Integer::UNSIGNED)},
//         {"cases", cases}
//     };
// }
//
// void crn::packets::from_json(const nlohmann::json& j, action_data<actions::insert>& q){
//     q._y = crn::utils::hex::decode(j["y"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
//     for(action_data<actions::insert>::data d: j["cases"]){
//         q.add(d);
//     }
// }
//
// void crn::packets::to_json(nlohmann::json& j, const action_data<actions::remove>& q){
//     j = nlohmann::json {
//         {"type", static_cast<std::uint32_t>(actions::remove)},
//         {"anchor", q.anchor()}
//     };
// }
// void crn::packets::from_json(const nlohmann::json& j, action_data<actions::remove>& q){
//     q._anchor = j["anchor"].get<std::string>();
// }


void crn::packets::to_json(nlohmann::json& j, const request& q){
    j = nlohmann::json {
        {"y",     crn::utils::hex::encode(q.y, CryptoPP::Integer::UNSIGNED)},
        {"last",  q.last},
        {"token", crn::utils::hex::encode(q.token, CryptoPP::Integer::UNSIGNED)}
    };
}

void crn::packets::from_json(const nlohmann::json& j, request& q){
    q.y     = crn::utils::hex::decode(j["y"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
    q.last  = j["last"].get<std::string>();
    q.token = crn::utils::hex::decode(j["token"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
}

void crn::packets::to_json(nlohmann::json& j, const challenge& c){
    j = nlohmann::json {
        {"random", crn::utils::hex::encode(c.random, CryptoPP::Integer::UNSIGNED)}
    };
}

void crn::packets::from_json(const nlohmann::json& j, challenge& c){
    c.random = crn::utils::hex::decode(j["random"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
}

// void crn::packets::to_json(nlohmann::json& j, const response& res){
//     j = nlohmann::json {
//         {"c1", crn::utils::hex::encode(res.c1, CryptoPP::Integer::UNSIGNED)},
//         {"c2", crn::utils::hex::encode(res.c2, CryptoPP::Integer::UNSIGNED)},
//         {"c3", crn::utils::hex::encode(res.c3, CryptoPP::Integer::UNSIGNED)},
//         {"access", crn::utils::hex::encode(res.access, CryptoPP::Integer::UNSIGNED)}
//     };
// }
//
// void crn::packets::from_json(const nlohmann::json& j, response& res){
//     res.c1 = crn::utils::hex::decode(j["c1"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
//     res.c2 = crn::utils::hex::decode(j["c2"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
//     res.c3 = crn::utils::hex::decode(j["c3"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
//     res.access = crn::utils::hex::decode(j["access"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
// }


crn::packets::result crn::packets::result::failure(std::uint32_t code, const std::string& reason){
    crn::packets::result res;
    res.error = code;
    res.reason  = reason;
    return res;
}

crn::packets::result crn::packets::result::success(const CryptoPP::Integer& active, const CryptoPP::Integer& passive, const std::string& block, const nlohmann::json& aux){
    crn::packets::result res;
    res.error   = 0;
    res.reason  = "OK";
    res.active  = active;
    res.passive = passive;
    res.block   = block;
    res.aux     = aux;
    return res;
}

// crn::packets::result crn::packets::result::success(const CryptoPP::Integer& passive, const std::string& block, const nlohmann::json& aux){
//     return success(0, passive, block, aux);
// }




void crn::packets::to_json(nlohmann::json& j, const crn::packets::result& res){
    j = {
        {"error",   res.error},
        {"reason",  res.reason},
        {"passive", crn::utils::hex::encode(res.passive, CryptoPP::Integer::UNSIGNED)},
        {"active",  crn::utils::hex::encode(res.active,  CryptoPP::Integer::UNSIGNED)},
        {"block",   res.block},
        {"aux",     res.aux}
    };
}

void crn::packets::from_json(const nlohmann::json& j, crn::packets::result& res){
    res.error   = j["error"].get<std::uint32_t>();
    res.reason  = j["reason"].get<std::string>();
    res.active  = crn::utils::hex::decode(j["active"].get<std::string>(),  CryptoPP::Integer::UNSIGNED);
    res.passive = crn::utils::hex::decode(j["passive"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
    res.block   = j["block"].get<std::string>();
    res.aux     = j["aux"];
}

