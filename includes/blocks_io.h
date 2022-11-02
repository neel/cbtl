// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef BLOCKS_IO_H
#define BLOCKS_IO_H

#include <nlohmann/json.hpp>
#include "blocks.h"
#include "utils.h"

namespace nlohmann {
    template <>
    struct adl_serializer<crn::blocks::parts::active> {
        static crn::blocks::parts::active from_json(const json& j) {
            auto forward  = crn::utils::dHex(j["forward"].get<std::string>());
            auto backward = crn::utils::dHex(j["backward"].get<std::string>());
            auto checksum = crn::utils::dHex(j["checksum"].get<std::string>());
            return crn::blocks::parts::active(forward, backward, checksum);
        }

        static void to_json(json& j, const crn::blocks::parts::active& a) {
            j = nlohmann::json {
                {"forward",  crn::utils::eHex(a.forward())},
                {"backward", crn::utils::eHex(a.backward())},
                {"checksum", crn::utils::eHex(a.checksum())}
            };
        }
    };
    template <>
    struct adl_serializer<crn::blocks::parts::passive> {
        static crn::blocks::parts::passive from_json(const json& j) {
            auto forward  = crn::utils::dHex(j["forward"].get<std::string>());
            auto backward = crn::utils::dHex(j["backward"].get<std::string>());
            auto cipher   = crn::utils::dHex(j["cipher"].get<std::string>());
            return crn::blocks::parts::passive(forward, backward, cipher);
        }

        static void to_json(json& j, const crn::blocks::parts::passive& a) {
            j = nlohmann::json {
                {"forward",  crn::utils::eHex(a.forward())},
                {"backward", crn::utils::eHex(a.backward())},
                {"cipher",   crn::utils::eHex(a.cipher())}
            };
        }
    };
    template <>
    struct adl_serializer<crn::blocks::access::addresses> {
        static crn::blocks::access::addresses from_json(const json& j) {
            auto id      = crn::utils::dHex(j["id"].get<std::string>());
            auto active  = crn::utils::dHex(j["active"].get<std::string>());
            auto passive = crn::utils::dHex(j["passive"].get<std::string>());
            return crn::blocks::access::addresses(active, passive);
        }

        static void to_json(json& j, const crn::blocks::access::addresses& a) {
            j = nlohmann::json {
                {"id",      crn::utils::eHex(a.id())},
                {"active",  crn::utils::eHex(a.active())},
                {"passive", crn::utils::eHex(a.passive())}
            };
        }
    };
    template <>
    struct adl_serializer<crn::blocks::access> {
        static crn::blocks::access from_json(const json& j) {
            crn::blocks::parts::active     active    = j["active"].get<crn::blocks::parts::active>();
            crn::blocks::parts::passive    passive   = j["passive"].get<crn::blocks::parts::passive>();
            crn::blocks::access::addresses addresses = j["address"].get<crn::blocks::access::addresses>();
            return crn::blocks::access(active, passive, addresses);
        }

        static void to_json(json& j, const crn::blocks::access& block) {
            j = nlohmann::json {
                {"active",  block._active},
                {"passive", block._passive},
                {"address", block._address}
            };
        }
    };
}

#endif // BLOCKS_IO_H
