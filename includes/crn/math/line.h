// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_MATH_LINE_H
#define CRN_MATH_LINE_H

#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include "crn/math/group.h"
#include "crn/math/coordinates.h"
#include "crn/utils.h"

namespace crn{
namespace math{

/**
 * @todo write docs
 */
class linear_diophantine{
    CryptoPP::Integer _a, _b, _c;
    crn::math::free_coordinates _delta, _shift;

    friend std::ostream& operator<<(std::ostream&, const linear_diophantine&);
    friend bool operator==(const linear_diophantine&, const linear_diophantine&);

    linear_diophantine(const CryptoPP::Integer& a, const CryptoPP::Integer& b, const CryptoPP::Integer& c, const crn::math::free_coordinates& delta, const crn::math::free_coordinates& shift);
    public:
        static linear_diophantine interpolate(const crn::math::free_coordinates& l, const crn::math::free_coordinates& r);
        crn::math::free_coordinates random(CryptoPP::AutoSeededRandomPool& rng, const crn::math::group& G, bool force_noninvertible = true) const;
        CryptoPP::Integer eval(const CryptoPP::Integer& x) const;
};

inline bool operator==(const linear_diophantine& l, const linear_diophantine& r){
    return (l._a == r._a && l._b == r._b && l._c == r._c) || (l._a == -r._a && l._b == -r._b && l._c == -r._c);
}

inline std::ostream& operator<<(std::ostream& os, const linear_diophantine& line){
    os << line._a << "x" << " + " << line._b << "y" << " = " << line._c;
    return os;
}

}
}

#endif // CRN_LINE_H
