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
            auto forward  = crn::utils::hex::decode(j["forward"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto backward = crn::utils::hex::decode(j["backward"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto checksum = crn::utils::hex::decode(j["checksum"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            return crn::blocks::parts::active(forward, backward, checksum);
        }

        static void to_json(json& j, const crn::blocks::parts::active& a) {
            j = nlohmann::json {
                {"forward",  crn::utils::hex::encode(a.forward(), CryptoPP::Integer::UNSIGNED)},
                {"backward", crn::utils::hex::encode(a.backward(), CryptoPP::Integer::UNSIGNED)},
                {"checksum", crn::utils::hex::encode(a.checksum(), CryptoPP::Integer::UNSIGNED)}
            };
        }
    };
    template <>
    struct adl_serializer<crn::blocks::parts::passive> {
        static crn::blocks::parts::passive from_json(const json& j) {
            auto forward  = crn::utils::hex::decode(j["forward"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto backward = crn::utils::hex::decode(j["backward"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto cipher   = crn::utils::hex::decode(j["cipher"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            return crn::blocks::parts::passive(forward, backward, cipher);
        }

        static void to_json(json& j, const crn::blocks::parts::passive& a) {
            j = nlohmann::json {
                {"forward",  crn::utils::hex::encode(a.forward(), CryptoPP::Integer::UNSIGNED)},
                {"backward", crn::utils::hex::encode(a.backward(), CryptoPP::Integer::UNSIGNED)},
                {"cipher",   crn::utils::hex::encode(a.cipher(), CryptoPP::Integer::UNSIGNED)}
            };
        }
    };
    template <>
    struct adl_serializer<crn::blocks::addresses> {
        static crn::blocks::addresses from_json(const json& j) {
            auto id      = crn::utils::hex::decode(j["id"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto active  = crn::utils::hex::decode(j["active"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto passive = crn::utils::hex::decode(j["passive"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            return crn::blocks::addresses(active, passive);
        }

        static void to_json(json& j, const crn::blocks::addresses& a) {
            j = nlohmann::json {
                {"id",      crn::utils::hex::encode(a.id(), CryptoPP::Integer::UNSIGNED)},
                {"active",  crn::utils::hex::encode(a.active(), CryptoPP::Integer::UNSIGNED)},
                {"passive", crn::utils::hex::encode(a.passive(), CryptoPP::Integer::UNSIGNED)}
            };
        }
    };

    template <>
    struct adl_serializer<crn::blocks::contents> {
        static crn::blocks::contents from_json(const json& j) {
            crn::math::free_coordinates random = j["random"].get<crn::math::free_coordinates>();
            CryptoPP::Integer gamma      = crn::utils::hex::decode(j["gamma"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            CryptoPP::Integer super      = crn::utils::hex::decode(j["super"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            std::string message          = j["message"].get<std::string>();

            return crn::blocks::contents(random, gamma, super, message);
        }

        static void to_json(json& j, const crn::blocks::contents& contents) {
            j = nlohmann::json {
                {"random",   contents.random()},
                {"gamma",    crn::utils::hex::encode(contents.gamma(), CryptoPP::Integer::UNSIGNED)},
                {"super",    crn::utils::hex::encode(contents.super(), CryptoPP::Integer::UNSIGNED)},
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
            boost::posix_time::ptime       requested = boost::posix_time::time_from_string(j["requested"].get<std::string>());
            return crn::blocks::access(active, passive, addresses, contents, requested);
        }

        static void to_json(json& j, const crn::blocks::access& block) {
            j = nlohmann::json {
                {"active",   block._active},
                {"passive",  block._passive},
                {"address",  block._address},
                {"contents", block._contents},
                {"requested", boost::posix_time::to_simple_string(block._requested)}
            };
        }
    };
}

#endif // CRN_BLOCKS_IO_H
