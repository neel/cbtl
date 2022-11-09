// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/line.h"
#include <iostream>

crn::linear_diophantine::linear_diophantine(const crn::group& G, const CryptoPP::Integer& a, const CryptoPP::Integer& b, const CryptoPP::Integer& c, const vector<2>& delta, const vector<2>& shift): _G(G), _a(a), _b(b), _c(c), _delta(delta), _shift(shift) { }

crn::linear_diophantine crn::linear_diophantine::interpolate(const crn::coordinates& l, const crn::coordinates& r){
    assert(l.G() == r.G());
    auto Gp = l.G().Gp();
    CryptoPP::Integer dx  = Gp.Subtract(r.x(), l.x()), dy = Gp.Subtract(r.y(), l.y()), mdy = Gp.Subtract(l.y(), r.y());
    CryptoPP::Integer c   = Gp.Subtract(Gp.Multiply(dx, l.y()), Gp.Multiply(dy, l.x()));
    // CryptoPP::Integer gcd = CryptoPP::Integer::Gcd(dx, mdy);
    // CryptoPP::Integer res = Gp.Divide(c, gcd);
    // if(res.IsZero()){
    //     // auto a = Gp.Divide(mdy, gcd), b = Gp.Divide(dx, gcd);
    //     // c = res;
    //     //
    //     // crn::vector<2> shift{l.G(), l.x(), l.y()};
    //     // crn::vector<2> delta{l.G(), a, b};
    //     //
    //     // return crn::line(l.G(), a, b, c, delta, shift);
    //     throw std::runtime_error("NO NO NO Math broke");
    // }
    crn::vector<2> shift{l.G(), l.x(), l.y()};
    crn::vector<2> delta{l.G(), dx, dy};
    auto line = crn::linear_diophantine(l.G(), mdy, dx, c, delta, shift);

    std::cout << "l.y(): " << l.y() << std::endl;
    std::cout << "eval: " << line.eval(l.x()) << std::endl;

    return line;
}

crn::coordinates crn::linear_diophantine::random(CryptoPP::AutoSeededRandomPool& rng, bool invertible) const{
    auto r = _G.random(rng, invertible);
    return _shift + (_delta * r);
}

CryptoPP::Integer crn::linear_diophantine::eval(const CryptoPP::Integer& x) const{
    auto Gp = _G.Gp();
    return Gp.Divide(Gp.Subtract(_c, Gp.Multiply(x, _a)), _b);
}
