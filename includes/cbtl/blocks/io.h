// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_BLOCKS_IO_H
#define cbtl_BLOCKS_IO_H

#include <nlohmann/json.hpp>
#include "cbtl/blocks.h"
#include "cbtl/utils.h"
#include "cbtl/blocks/contents.h"

namespace nlohmann {
    template <>
    struct adl_serializer<cbtl::blocks::parts::active> {
        static cbtl::blocks::parts::active from_json(const json& j) {
            auto forward  = cbtl::utils::hex::decode(j["forward"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto backward = cbtl::utils::hex::decode(j["backward"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto checksum = cbtl::utils::hex::decode(j["checksum"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            return cbtl::blocks::parts::active(forward, backward, checksum);
        }

        static void to_json(json& j, const cbtl::blocks::parts::active& a) {
            j = nlohmann::json {
                {"forward",  cbtl::utils::hex::encode(a.forward(), CryptoPP::Integer::UNSIGNED)},
                {"backward", cbtl::utils::hex::encode(a.backward(), CryptoPP::Integer::UNSIGNED)},
                {"checksum", cbtl::utils::hex::encode(a.checksum(), CryptoPP::Integer::UNSIGNED)}
            };
        }
    };
    template <>
    struct adl_serializer<cbtl::blocks::parts::passive> {
        static cbtl::blocks::parts::passive from_json(const json& j) {
            auto forward  = cbtl::utils::hex::decode(j["forward"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto backward = cbtl::utils::hex::decode(j["backward"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto cipher   = cbtl::utils::hex::decode(j["cipher"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            return cbtl::blocks::parts::passive(forward, backward, cipher);
        }

        static void to_json(json& j, const cbtl::blocks::parts::passive& a) {
            j = nlohmann::json {
                {"forward",  cbtl::utils::hex::encode(a.forward(), CryptoPP::Integer::UNSIGNED)},
                {"backward", cbtl::utils::hex::encode(a.backward(), CryptoPP::Integer::UNSIGNED)},
                {"cipher",   cbtl::utils::hex::encode(a.cipher(), CryptoPP::Integer::UNSIGNED)}
            };
        }
    };
    template <>
    struct adl_serializer<cbtl::blocks::addresses> {
        static cbtl::blocks::addresses from_json(const json& j) {
            auto id      = cbtl::utils::hex::decode(j["id"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto active  = cbtl::utils::hex::decode(j["active"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            auto passive = cbtl::utils::hex::decode(j["passive"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            return cbtl::blocks::addresses(active, passive);
        }

        static void to_json(json& j, const cbtl::blocks::addresses& a) {
            j = nlohmann::json {
                {"id",      cbtl::utils::hex::encode(a.id(), CryptoPP::Integer::UNSIGNED)},
                {"active",  cbtl::utils::hex::encode(a.active(), CryptoPP::Integer::UNSIGNED)},
                {"passive", cbtl::utils::hex::encode(a.passive(), CryptoPP::Integer::UNSIGNED)}
            };
        }
    };

    template <>
    struct adl_serializer<cbtl::blocks::contents> {
        static cbtl::blocks::contents from_json(const json& j) {
            cbtl::math::free_coordinates random = j["random"].get<cbtl::math::free_coordinates>();
            CryptoPP::Integer gamma      = cbtl::utils::hex::decode(j["gamma"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            CryptoPP::Integer super      = cbtl::utils::hex::decode(j["super"].get<std::string>(), CryptoPP::Integer::UNSIGNED);
            std::string message          = j["message"].get<std::string>();

            return cbtl::blocks::contents(random, gamma, super, message);
        }

        static void to_json(json& j, const cbtl::blocks::contents& contents) {
            j = nlohmann::json {
                {"random",   contents.random()},
                {"gamma",    cbtl::utils::hex::encode(contents.gamma(), CryptoPP::Integer::UNSIGNED)},
                {"super",    cbtl::utils::hex::encode(contents.super(), CryptoPP::Integer::UNSIGNED)},
                {"message",  contents._message}
            };
        }
    };

    template <>
    struct adl_serializer<cbtl::blocks::access> {
        static cbtl::blocks::access from_json(const json& j) {
            cbtl::blocks::parts::active     active    = j["active"].get<cbtl::blocks::parts::active>();
            cbtl::blocks::parts::passive    passive   = j["passive"].get<cbtl::blocks::parts::passive>();
            cbtl::blocks::addresses         addresses = j["address"].get<cbtl::blocks::addresses>();
            cbtl::blocks::contents          contents  = j["contents"].get<cbtl::blocks::contents>();
            boost::posix_time::ptime       requested = boost::posix_time::time_from_string(j["requested"].get<std::string>());
            return cbtl::blocks::access(active, passive, addresses, contents, requested);
        }

        static void to_json(json& j, const cbtl::blocks::access& block) {
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

#endif // cbtl_BLOCKS_IO_H
