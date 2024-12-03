// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_MATH_DIOPHANTINE_H
#define cbtl_MATH_DIOPHANTINE_H

#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include "cbtl/math/group.h"
#include "cbtl/math/coordinates.h"
#include "cbtl/utils.h"

namespace cbtl{
namespace math{

/**
 * @todo write docs
 */
class diophantine{
    CryptoPP::Integer _a, _b, _c;
    cbtl::math::free_coordinates _delta, _shift;

    friend std::ostream& operator<<(std::ostream&, const diophantine&);
    friend bool operator==(const diophantine&, const diophantine&);

    diophantine(const CryptoPP::Integer& a, const CryptoPP::Integer& b, const CryptoPP::Integer& c, const cbtl::math::free_coordinates& delta, const cbtl::math::free_coordinates& shift);
    public:
        static diophantine interpolate(const cbtl::math::free_coordinates& l, const cbtl::math::free_coordinates& r);
        /**
         * Gives a random coordinate on the line that has a non-invertible x value in Z/Zp-1
         */
        cbtl::math::free_coordinates random_nix(CryptoPP::AutoSeededRandomPool& rng, const cbtl::math::group& G) const;
        /**
         * Gives a random coordinate on that line such that x value of that coordinate is less than n
         */
        cbtl::math::free_coordinates random(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::Integer& n) const;
        CryptoPP::Integer eval(const CryptoPP::Integer& x) const;
};

inline bool operator==(const diophantine& l, const diophantine& r){
    return (l._a == r._a && l._b == r._b && l._c == r._c) || (l._a == -r._a && l._b == -r._b && l._c == -r._c);
}

inline std::ostream& operator<<(std::ostream& os, const diophantine& line){
    os << line._a << "x" << " + " << line._b << "y" << " = " << line._c;
    return os;
}

}
}

#endif // cbtl_MATH_DIOPHANTINE_H
