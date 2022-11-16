// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_MATH_VECTOR_H
#define CRN_MATH_VECTOR_H

#include "crn/math/group.h"
#include <cryptopp/integer.h>

namespace crn{
namespace math{

template <std::size_t N>
class vector{
    typedef std::array<CryptoPP::Integer, N> storage_type;
    crn::math::group   _G;
    storage_type _values;
    public:
        vector(const crn::math::group& G): _G(G) {}
        vector(const vector<N>& other) = default;
        template <typename... Args>
        vector(const crn::math::group& G, const Args&... args): _G(G), _values({args...}) {}
        const CryptoPP::Integer& at(std::size_t index) const { return _values.at(index); }
        const CryptoPP::Integer& operator[](std::size_t index) const { return at(index); }
        CryptoPP::Integer& at(std::size_t index) { return _values.at(index); }
        CryptoPP::Integer& operator[](std::size_t index) { return at(index); }
        template <typename FunctionT>
        void apply(FunctionT&& f){
            for(std::size_t i = 0; i < N; ++i){
                _values[i] = f(i);
            }
        }
        const crn::math::group& G() const { return _G; }
};

template <std::size_t N>
vector<N> operator+(const vector<N>& l, const vector<N>& r){
    assert(l.G() == r.G());
    auto Gp = l.G().Gp();
    vector<N> res = l;
    res.apply([&l, &r, &Gp](std::size_t i){
        return Gp.Add(l[i], r[i]);
    });
    return res;
}
template <std::size_t N>
vector<N> operator-(const vector<N>& l, const vector<N>& r){
    assert(l.G() == r.G());
    auto Gp = l.G().Gp();
    vector<N> res = l;
    res.apply([&l, &r, &Gp](std::size_t i){
        return Gp.Subtract(l[i], r[i]);
    });
    return res;
}
template <std::size_t N>
vector<N> operator*(const vector<N>& c, const CryptoPP::Integer& s){
    auto Gp = c.G().Gp();
    vector<N> res = c;
    res.apply([&c, &Gp, &s](std::size_t i){
        return Gp.Multiply(c[i], s);
    });
    return res;
}
template <std::size_t N>
vector<N> operator/(const vector<N>& c, const CryptoPP::Integer& s){
    auto Gp = c.G().Gp();
    vector<N> res = c;
    res.apply([&c, &Gp, &s](std::size_t i){
        return Gp.Divide(c[i], s);
    });
    return res;
}
template <std::size_t N>
vector<N> operator*(const CryptoPP::Integer& s, const vector<N>& c){
    return operator*(c, s);
}
template <std::size_t N>
vector<N> operator/(const CryptoPP::Integer& s, const vector<N>& c){
    return operator/(c, s);
}

}
}

#endif // CRN_MATH_VECTOR_H
