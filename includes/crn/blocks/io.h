// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_BLOCKS_IO_H
#define CRN_BLOCKS_IO_H

#include <nlohmann/json.hpp>
#include "crn/blocks.h"
#include "crn/utils.h"
#include "crn/blocks/contents.h"

namespace nlohmann {
    template <>
    struct adl_serializer<crn::blocks::parts::active> {
        static crn::blocks::parts::active from_json(const json& j) {
            auto forward  = crn::utils::dHex(j["forward"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto backward = crn::utils::dHex(j["backward"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto checksum = crn::utils::dHex(j["checksum"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            return crn::blocks::parts::active(forward, backward, checksum);
        }

        static void to_json(json& j, const crn::blocks::parts::active& a) {
            j = nlohmann::json {
                {"forward",  crn::utils::eHex(a.forward(), CryptoPP::Integer::UNSIGNED)},
                {"backward", crn::utils::eHex(a.backward(), CryptoPP::Integer::UNSIGNED)},
                {"checksum", crn::utils::eHex(a.checksum(), CryptoPP::Integer::UNSIGNED)}
            };
        }
    };
    template <>
    struct adl_serializer<crn::blocks::parts::passive> {
        static crn::blocks::parts::passive from_json(const json& j) {
            auto forward  = crn::utils::dHex(j["forward"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto backward = crn::utils::dHex(j["backward"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto cipher   = crn::utils::dHex(j["cipher"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            return crn::blocks::parts::passive(forward, backward, cipher);
        }

        static void to_json(json& j, const crn::blocks::parts::passive& a) {
            j = nlohmann::json {
                {"forward",  crn::utils::eHex(a.forward(), CryptoPP::Integer::UNSIGNED)},
                {"backward", crn::utils::eHex(a.backward(), CryptoPP::Integer::UNSIGNED)},
                {"cipher",   crn::utils::eHex(a.cipher(), CryptoPP::Integer::UNSIGNED)}
            };
        }
    };
    template <>
    struct adl_serializer<crn::blocks::addresses> {
        static crn::blocks::addresses from_json(const json& j) {
            auto id      = crn::utils::dHex(j["id"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto active  = crn::utils::dHex(j["active"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto passive = crn::utils::dHex(j["passive"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            return crn::blocks::addresses(active, passive);
        }

        static void to_json(json& j, const crn::blocks::addresses& a) {
            j = nlohmann::json {
                {"id",      crn::utils::eHex(a.id(), CryptoPP::Integer::UNSIGNED)},
                {"active",  crn::utils::eHex(a.active(), CryptoPP::Integer::UNSIGNED)},
                {"passive", crn::utils::eHex(a.passive(), CryptoPP::Integer::UNSIGNED)}
            };
        }
    };

    template <>
    struct adl_serializer<crn::blocks::contents> {
        static crn::blocks::contents from_json(const json& j) {
            crn::math::free_coordinates random = j["random"].get<crn::math::free_coordinates>();
            CryptoPP::Integer gamma      = crn::utils::dHex(j["gamma"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            CryptoPP::Integer super      = crn::utils::dHex(j["super"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            std::string message          = j["message"].get<std::string>();

            return crn::blocks::contents(random, gamma, super, message);
        }

        static void to_json(json& j, const crn::blocks::contents& contents) {
            j = nlohmann::json {
                {"random",   contents.random()},
                {"gamma",    crn::utils::eHex(contents.gamma(), CryptoPP::Integer::UNSIGNED)},
                {"super",    crn::utils::eHex(contents.super(), CryptoPP::Integer::UNSIGNED)},
                {"message",  contents._message}
            };
        }
    };

    template <>
    struct adl_serializer<crn::blocks::access> {
        static crn::blocks::access from_json(const json& j) {
            crn::blocks::parts::active     active    = j["active"].get<crn::blocks::parts::active>();
            crn::blocks::parts::passive    passive   = j["passive"].get<crn::blocks::parts::passive>();
            crn::blocks::addresses         addresses = j["address"].get<crn::blocks::addresses>();
            crn::blocks::contents          contents  = j["contents"].get<crn::blocks::contents>();
            return crn::blocks::access(active, passive, addresses, contents);
        }

        static void to_json(json& j, const crn::blocks::access& block) {
            j = nlohmann::json {
                {"active",   block._active},
                {"passive",  block._passive},
                {"address",  block._address},
                {"contents", block._contents}
            };
        }
    };
}

#endif // CRN_BLOCKS_IO_H
