// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/math/diophantine.h"
#include <iostream>
#include <cryptopp/nbtheory.h>

crn::math::diophantine::diophantine(const CryptoPP::Integer& a, const CryptoPP::Integer& b, const CryptoPP::Integer& c, const crn::math::free_coordinates& delta, const crn::math::free_coordinates& shift): _a(a), _b(b), _c(c), _delta(delta), _shift(shift) { }

crn::math::diophantine crn::math::diophantine::interpolate(const crn::math::free_coordinates& u, const crn::math::free_coordinates& v){
    assert(u != v);
    CryptoPP::Integer dx  = u.x() - v.x(), dy = v.y() - u.y();
    CryptoPP::Integer c   = (v.y() * u.x()) - (v.x() * u.y());
    CryptoPP::Integer gcd = CryptoPP::Integer::Gcd(dx, dy);
    assert(!gcd.IsZero());
    CryptoPP::Integer res = c / gcd;
    assert(!res.IsZero());
    auto a = dy / gcd, b = dx / gcd;
    c = res;
    free_coordinates shift{u.x(), u.y()};
    free_coordinates delta{b, -a};
    auto line = crn::math::diophantine(a, b, c, delta, shift);
    assert(line.eval(u.x()) == u.y());
    assert(line.eval(v.x()) == v.y());
    return line;
}

crn::math::free_coordinates crn::math::diophantine::random_nix(CryptoPP::AutoSeededRandomPool& rng, const crn::math::group& G) const{
    // Generates a random coordinate that satisfies the line
    // The x coordinate must be less that p-1
    // The multiplicative inverse of the x coordinate must not exist in Z_{p-1}

    auto min = (2 - _shift.x()) / _delta.x();
    auto max = (G.p() - _shift.x()) / _delta.x();
    std::size_t retries = 0;
    CryptoPP::ModularArithmetic Gp1 = G.Gp1();
    while(true){
        CryptoPP::Integer r(rng, std::min(min, max), std::max(min, max));
        // coordinate.x() must not be coprime with p-1
        // p-1 is even because p is prime and any prime > 2 is odd and odd-1 is even
        // Hence if shift.x() + delta.x() * r is even then it is definitely not a coprime with p-1
        // shift: even, delta: even -> okay
        // shift: even, delta: odd  -> r has to be even
        // shift: odd,  delta: odd  -> r has to be odd
        // shift: odd,  delta: even -> it has to be devisible by the other factors of p-1
        //              but delta = -b = -dx/gcd = (l.x() - r.x()) / gcd = l.x()/gcd - r.x()/gcd
        //              if delta is even then either both l.x()/gcd and r.x()/gcd are even or both ar odd
        //              if both are even then this last case (4) won't happen.
        //              Hence both l.x()/gcd and r.x()/gcd are odd
        //              In this case it is not possible to generate an even value for (shift.x() + delta.x() * r)
        //              But we can make it divisible by the smallest prime factor f > 2 of (p-1)
        //              Which requires factorization of (p-1) which can be expensive
        if(_shift.x().IsEven() && _delta.x().IsOdd() && !r.IsEven()) r = r + 1;
        if(_shift.x().IsOdd()  && _delta.x().IsOdd() && !r.IsOdd() ) r = r + 1;
        if(_delta.x().IsEven()){
            throw std::runtime_error("Unexpected: found delta to be Even");
        }
        auto coordinate = _shift + (_delta * r);
        if(coordinate.x() >= 2 && coordinate.x() <= (G.p()-1)){
            auto x_inv = Gp1.MultiplicativeInverse(coordinate.x());
            if(x_inv.IsZero()){
                assert(eval(coordinate.x()) == coordinate.y());
                // std::cout << "found after retries " << retries << std::endl;
                return coordinate;
            }
        }
        ++retries;
    }
}

crn::math::free_coordinates crn::math::diophantine::random(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::Integer& n) const{
    auto min = (2 - _shift.x()) / _delta.x();
    auto max = (n - _shift.x()) / _delta.x();
    while(true){
        CryptoPP::Integer r(rng, std::min(min, max), std::max(min, max));
        auto coordinate = _shift + (_delta * r);
        if(coordinate.x() >= 2 && coordinate.x() <= (n-1)){
            assert(eval(coordinate.x()) == coordinate.y());
            return coordinate;
        }
    }
}


CryptoPP::Integer crn::math::diophantine::eval(const CryptoPP::Integer& x) const{
    return (_c - (_a * x)) / _b;
}

bool crn::math::operator==(const crn::math::free_coordinates& l, const crn::math::free_coordinates& r){
    return l.x() == r.x() && l.y() == r.y();
}
bool crn::math::operator!=(const crn::math::free_coordinates& l, const crn::math::free_coordinates& r){
    return !operator==(l, r);
}

crn::math::free_coordinates crn::math::operator+(const crn::math::free_coordinates& l, const crn::math::free_coordinates& r){
    return crn::math::free_coordinates{l.x() + r.x(), l.y() + r.y()};
}

crn::math::free_coordinates crn::math::operator*(const crn::math::free_coordinates& c, const CryptoPP::Integer& s){
    return crn::math::free_coordinates{c.x() * s, c.y() * s};
}
