// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_MATH_COORDINATES_H
#define CRN_MATH_COORDINATES_H

#include "crn/math/vector.h"
#include "crn/math/group.h"
#include "crn/utils.h"
#include <cryptopp/integer.h>

namespace crn{
namespace math{

struct coordinates: crn::math::vector<2> {
    inline coordinates(const crn::math::group& G): crn::math::vector<2>(G){}
    inline coordinates(const crn::math::vector<2>& vec): crn::math::vector<2>(vec) {}
    inline coordinates(const crn::math::group& G, const CryptoPP::Integer& x, const CryptoPP::Integer& y): crn::math::vector<2>(G, x, y) {}
    inline const CryptoPP::Integer& x() const { return crn::math::vector<2>::at(0); }
    inline const CryptoPP::Integer& y() const { return crn::math::vector<2>::at(1); }
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
    struct adl_serializer<crn::math::free_coordinates> {
        static crn::math::free_coordinates from_json(const json& j) {
            CryptoPP::Integer x = crn::utils::dHex(j["x"].get<std::string>(), CryptoPP::Integer::SIGNED);
            CryptoPP::Integer y = crn::utils::dHex(j["y"].get<std::string>(), CryptoPP::Integer::SIGNED);
            return crn::math::free_coordinates{x, y};
        }

        static void to_json(json& j, const crn::math::free_coordinates& c) {
            j = nlohmann::json {
                {"x", crn::utils::eHex(c.x(), CryptoPP::Integer::SIGNED)},
                {"y", crn::utils::eHex(c.y(), CryptoPP::Integer::SIGNED)}
            };
        }
    };
}

#endif // CRN_MATH_COORDINATES_H
