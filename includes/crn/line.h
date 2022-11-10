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

struct free_coordinates {
    inline free_coordinates() = default;
    inline free_coordinates(const free_coordinates&) = default;
    inline free_coordinates(const CryptoPP::Integer& x, const CryptoPP::Integer& y): _x(x), _y(y) {}
    inline const CryptoPP::Integer& x() const { return _x; }
    inline const CryptoPP::Integer& y() const { return _y; }

    private:
        CryptoPP::Integer _x, _y;
};

free_coordinates operator*(const free_coordinates& c, const CryptoPP::Integer& s);
free_coordinates operator+(const free_coordinates& l, const free_coordinates& r);

inline std::ostream& operator<<(std::ostream& os, const free_coordinates& c){
    os << "x: " << c.x() << ", y: " << c.y();
    return os;
}

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
    crn::free_coordinates _delta, _shift;

    friend std::ostream& operator<<(std::ostream&, const linear_diophantine&);
    friend bool operator==(const linear_diophantine&, const linear_diophantine&);

    linear_diophantine(const CryptoPP::Integer& a, const CryptoPP::Integer& b, const CryptoPP::Integer& c, const free_coordinates& delta, const free_coordinates& shift);
    public:
        static linear_diophantine interpolate(const free_coordinates& l, const free_coordinates& r);
        free_coordinates random(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::Integer& p) const;
        CryptoPP::Integer eval(const CryptoPP::Integer& x) const;
};

inline bool operator==(const linear_diophantine& l, const linear_diophantine& r){
    return l._a == r._a && l._b == r._b && l._c == r._c;
}

inline std::ostream& operator<<(std::ostream& os, const linear_diophantine& line){
    os << line._a << "x" << " + " << line._b << "y" << " = " << line._c;
    return os;
}

}

namespace nlohmann {
    template <>
    struct adl_serializer<crn::free_coordinates> {
        static crn::free_coordinates from_json(const json& j) {
            CryptoPP::Integer x = crn::utils::dHex(j["x"].get<std::string>(), true);
            CryptoPP::Integer y = crn::utils::dHex(j["y"].get<std::string>(), true);
            return crn::free_coordinates{x, y};
        }

        static void to_json(json& j, const crn::free_coordinates& c) {
            j = nlohmann::json {
                {"x", crn::utils::eHex(c.x())},
                {"y", crn::utils::eHex(c.y())}
            };
        }
    };
}

#endif // CRN_LINE_H
