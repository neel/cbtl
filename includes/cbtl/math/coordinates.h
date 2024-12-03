// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_MATH_COORDINATES_H
#define cbtl_MATH_COORDINATES_H

#include "cbtl/math/vector.h"
#include "cbtl/math/group.h"
#include "cbtl/utils.h"
#include <cryptopp/integer.h>

namespace cbtl{
namespace math{

struct coordinates: cbtl::math::vector<2> {
    inline coordinates(const cbtl::math::group& G): cbtl::math::vector<2>(G){}
    inline coordinates(const cbtl::math::vector<2>& vec): cbtl::math::vector<2>(vec) {}
    inline coordinates(const cbtl::math::group& G, const CryptoPP::Integer& x, const CryptoPP::Integer& y): cbtl::math::vector<2>(G, x, y) {}
    inline const CryptoPP::Integer& x() const { return cbtl::math::vector<2>::at(0); }
    inline const CryptoPP::Integer& y() const { return cbtl::math::vector<2>::at(1); }
};

struct free_coordinates {
    inline free_coordinates() = default;
    inline free_coordinates(const free_coordinates&) = default;
    inline free_coordinates(const CryptoPP::Integer& x, const CryptoPP::Integer& y): _x(x), _y(y) {}
    inline const CryptoPP::Integer& x() const { return _x; }
    inline const CryptoPP::Integer& y() const { return _y; }

    private:
        CryptoPP::Integer _x, _y;
};

bool operator==(const free_coordinates& l, const free_coordinates& r);
bool operator!=(const free_coordinates& l, const free_coordinates& r);
free_coordinates operator*(const free_coordinates& c, const CryptoPP::Integer& s);
free_coordinates operator+(const free_coordinates& l, const free_coordinates& r);

inline std::ostream& operator<<(std::ostream& os, const free_coordinates& c){
    os << "x: " << c.x() << ", y: " << c.y();
    return os;
}

}
}

namespace nlohmann {
    template <>
    struct adl_serializer<cbtl::math::free_coordinates> {
        static cbtl::math::free_coordinates from_json(const json& j) {
            CryptoPP::Integer x = cbtl::utils::hex::decode(j["x"].get<std::string>(), CryptoPP::Integer::SIGNED);
            CryptoPP::Integer y = cbtl::utils::hex::decode(j["y"].get<std::string>(), CryptoPP::Integer::SIGNED);
            return cbtl::math::free_coordinates{x, y};
        }

        static void to_json(json& j, const cbtl::math::free_coordinates& c) {
            j = nlohmann::json {
                {"x", cbtl::utils::hex::encode(c.x(), CryptoPP::Integer::SIGNED)},
                {"y", cbtl::utils::hex::encode(c.y(), CryptoPP::Integer::SIGNED)}
            };
        }
    };
}

#endif // cbtl_MATH_COORDINATES_H
