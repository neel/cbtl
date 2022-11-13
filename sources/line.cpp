// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/line.h"
#include <iostream>
#include <cryptopp/nbtheory.h>

crn::linear_diophantine::linear_diophantine(const CryptoPP::Integer& a, const CryptoPP::Integer& b, const CryptoPP::Integer& c, const crn::free_coordinates& delta, const crn::free_coordinates& shift): _a(a), _b(b), _c(c), _delta(delta), _shift(shift) { }

crn::linear_diophantine crn::linear_diophantine::interpolate(const crn::free_coordinates& l, const crn::free_coordinates& r){
    CryptoPP::Integer dx  = r.x() - l.x(), dy = r.y() - l.y();
    CryptoPP::Integer c   = (r.y() * l.x()) - (r.x() * l.y());
    CryptoPP::Integer gcd = CryptoPP::Integer::Gcd(dx, dy);
//    if(gcd.IsZero()){
//        std::cout << "dx: " << dx << std::endl << "dy: " << dy << std::endl;
//    }
    assert(!gcd.IsZero());
    CryptoPP::Integer res = c / gcd;
    assert(!res.IsZero());
//    std::cout << "gcd: " << gcd << std::endl << "res: " << res << std::endl;

//    if(!res.IsZero()){
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
//    }else{
//        throw std::runtime_error("NO NO NO Math broke");
//    }
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
    // Generates a random coordinate that satisfies the line
    // The x coordinate must be less that p-1
    // The multiplicative inverse of the x coordinate must not exist in Z_{p-1}

    auto min = (2 - _shift.x()) / _delta.x();
    auto max = (p - _shift.x()) / _delta.x();

//    std::cout << "s: " << _shift << std::endl << "d: " << _delta << std::endl;
//    std::cout << "min: " << min << std::endl << "max: " << max << std::endl;
//    std::cout << "gap: " << (max - min) << std::endl;
//    std::cout << "shift.EVEN: " << _shift.x().IsEven() << " delta.EVEN: " << _delta.x().IsEven() << std::endl;

    std::size_t retries = 0;

    CryptoPP::ModularArithmetic Gp1(p-1);
    while(true){
        CryptoPP::Integer r(rng, std::min(min, max), std::max(min, max));
        // coordinate.x() must not be coprime with p-1
        // p-1 is even because p is prime and any prime > 2 is odd and odd-1 is even
        // Hence if shift.x() + delta.x() * r is even then it is definitely not a coprime with p-1
        // shift: even, delta: even -> okay
        // shift: even, delta: odd  -> r has to be even
        // shift: odd,  delta: odd  -> r has to be odd
        // shift: odd,  delta: even -> it has to be devisible by the other factors of p-1
        if(_shift.x().IsEven() && _delta.x().IsOdd() && !r.IsEven()) r = r + 1;
        if(_shift.x().IsOdd() && _delta.x().IsOdd() && !r.IsOdd())   r = r + 1;
        auto coordinate = _shift + (_delta * r);
        if(coordinate.x() >= 2 && coordinate.x() <= (p-1)){
            auto x_inv = Gp1.MultiplicativeInverse(coordinate.x());
            if(x_inv.IsZero()){
                assert(eval(coordinate.x()) == coordinate.y());
                std::cout << "found after retries " << retries << std::endl;
                return coordinate;
            }
        }
        ++retries;
    }


    // CryptoPP::Integer r(rng, 2, p-1);
    // // std::cout << "r: " << r << std::endl;
    // auto coordinate = _shift + (_delta * r);
    // assert(eval(coordinate.x()) == coordinate.y());
    // return coordinate;
}

CryptoPP::Integer crn::linear_diophantine::eval(const CryptoPP::Integer& x) const{
    return (_c - (_a * x)) / _b;
}

bool crn::operator==(const crn::free_coordinates& l, const crn::free_coordinates& r){
    return l.x() == r.x() && l.y() == r.y();
}
crn::free_coordinates crn::operator+(const crn::free_coordinates& l, const crn::free_coordinates& r){
    return crn::free_coordinates{l.x() + r.x(), l.y() + r.y()};
}

crn::free_coordinates crn::operator*(const crn::free_coordinates& c, const CryptoPP::Integer& s){
    return crn::free_coordinates{c.x() * s, c.y() * s};
}
