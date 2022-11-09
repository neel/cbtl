// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/line.h"
#include <iostream>

crn::linear_diophantine::linear_diophantine(const CryptoPP::Integer& a, const CryptoPP::Integer& b, const CryptoPP::Integer& c, const crn::free_coordinates& delta, const crn::free_coordinates& shift): _a(a), _b(b), _c(c), _delta(delta), _shift(shift) { }

crn::linear_diophantine crn::linear_diophantine::interpolate(const crn::free_coordinates& l, const crn::free_coordinates& r){
    CryptoPP::Integer dx  = r.x() - l.x(), dy = r.y() - l.y(), mdy = l.y() - r.y();
    CryptoPP::Integer c   = (r.x() * l.y()) - (r.y() * l.x());
    CryptoPP::Integer gcd = CryptoPP::Integer::Gcd(dx, mdy);
    CryptoPP::Integer res = c / gcd;
    if(!res.IsZero()){
        auto a = mdy / gcd, b = dx / gcd;
        c = res;

        free_coordinates shift{l.x(), l.y()};
        free_coordinates delta{a, b};

        std::cout << "a: " << a << std::endl;
        std::cout << "b: " << b << std::endl;
        std::cout << "c: " << c << std::endl;

        return crn::linear_diophantine(a, b, c, delta, shift);
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
    return _shift + (_delta * r);
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
