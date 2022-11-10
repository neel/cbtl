// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/line.h"
#include <iostream>

crn::linear_diophantine::linear_diophantine(const CryptoPP::Integer& a, const CryptoPP::Integer& b, const CryptoPP::Integer& c, const crn::free_coordinates& delta, const crn::free_coordinates& shift): _a(a), _b(b), _c(c), _delta(delta), _shift(shift) { }

crn::linear_diophantine crn::linear_diophantine::interpolate(const crn::free_coordinates& l, const crn::free_coordinates& r){
    CryptoPP::Integer dx  = r.x() - l.x(), dy = r.y() - l.y();
    CryptoPP::Integer c   = (r.y() * l.x()) - (r.x() * l.y());
    CryptoPP::Integer gcd = CryptoPP::Integer::Gcd(dx, dy);
    CryptoPP::Integer res = c / gcd;

    // std::cout << "res: " << res << std::endl;

    if(!res.IsZero()){
        auto a = dy / gcd, b = dx / gcd;
        c = res;

        if(a.IsNegative()){
            a = -1 * a;
            b = -1 * b;
            c = -1 * c;
        }

        free_coordinates shift{l.x(), l.y()};
        free_coordinates delta{-b, -a};

        // std::cout << "shift: " << shift << std::endl;
        // std::cout << "delta: " << delta << std::endl;

        auto line = crn::linear_diophantine(a, -b, c, delta, shift);
        assert(line.eval(l.x()) == l.y());
        assert(line.eval(r.x()) == r.y());
        return line;
    }else{
        throw std::runtime_error("NO NO NO Math broke");
    }
    // free_coordinates shift{l.x(), l.y()};
    // free_coordinates delta{dx, dy};
    // auto line = crn::linear_diophantine(mdy, dx, c, delta, shift);
    //
    // // std::cout << "l.x(): " << l.x() << std::endl;
    // // std::cout << "l.y(): " << l.y() << std::endl;
    // // std::cout << "r.x(): " << r.x() << std::endl;
    // // std::cout << "r.y(): " << r.y() << std::endl;
    // // std::cout << "eval: " << line.eval(l.x()) << std::endl;
    //
    // return line;
}

crn::free_coordinates crn::linear_diophantine::random(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::Integer& p) const{
    CryptoPP::Integer r(rng, 2, p-1);
    // std::cout << "r: " << r << std::endl;
    auto coordinate = _shift + (_delta * r);
    assert(eval(coordinate.x()) == coordinate.y());
    return coordinate;
}

CryptoPP::Integer crn::linear_diophantine::eval(const CryptoPP::Integer& x) const{
    return (_c - (_a * x)) / _b;
}


crn::free_coordinates crn::operator+(const crn::free_coordinates& l, const crn::free_coordinates& r){
    return crn::free_coordinates{l.x() + r.x(), l.y() + r.y()};
}

crn::free_coordinates crn::operator*(const crn::free_coordinates& c, const CryptoPP::Integer& s){
    return crn::free_coordinates{c.x() * s, c.y() * s};
}
