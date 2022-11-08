// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_LINE_H
#define CRN_LINE_H

#include <cryptopp/integer.h>
#include "crn/group.h"
#include "crn/utils.h"

namespace crn{

template <std::size_t N>
class vector{
    typedef std::array<CryptoPP::Integer, N> storage_type;
    crn::group   _G;
    storage_type _values;
    public:
        vector(const crn::group& G): _G(G) {}
        vector(const vector<N>& other) = default;
        template <typename... Args>
        vector(const crn::group& G, const Args&... args): _G(G), _values({args...}) {}
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
        const crn::group& G() const { return _G; }
};

struct coordinates: vector<2> {
    inline coordinates(const crn::group& G): vector<2>(G){}
    inline coordinates(const vector<2>& vec): vector<2>(vec) {}
    inline coordinates(const crn::group& G, const CryptoPP::Integer& x, const CryptoPP::Integer& y): vector<2>(G, x, y) {}
    inline const CryptoPP::Integer& x() const { return vector<2>::at(0); }
    inline const CryptoPP::Integer& y() const { return vector<2>::at(1); }
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

/**
 * @todo write docs
 */
class linear_diophantine{
    CryptoPP::Integer _a, _b, _c;
    vector<2> _delta, _shift;
    crn::group   _G;

    linear_diophantine(const crn::group& G, const CryptoPP::Integer& a, const CryptoPP::Integer& b, const CryptoPP::Integer& c, const vector<2>& delta, const vector<2>& shift);
    public:
        static linear_diophantine interpolate(const coordinates& l, const coordinates& r);
        coordinates random(CryptoPP::AutoSeededRandomPool& rng, bool invertible) const;
        CryptoPP::Integer eval(const CryptoPP::Integer& x) const;
};

}

namespace nlohmann {
    template <>
    struct adl_serializer<crn::coordinates> {
        static crn::coordinates from_json(const json& j) {
            CryptoPP::Integer x = crn::utils::dHex(j["x"].get<std::string>());
            CryptoPP::Integer y = crn::utils::dHex(j["y"].get<std::string>());
            crn::group G = j["G"].get<crn::group>();
            return crn::coordinates{G, x, y};
        }

        static void to_json(json& j, const crn::coordinates& c) {
            j = nlohmann::json {
                {"x", crn::utils::eHex(c.x())},
                {"y", crn::utils::eHex(c.y())},
                {"G", c.G()}
            };
        }
    };
}

#endif // CRN_LINE_H
