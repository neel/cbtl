#include <iostream>
#include <string>
#include <array>
#include <cassert>
#include <exception>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/elgamal.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/dsa.h>

constexpr static const std::uint32_t key_size = 1024;

/**
 * @brief the algebric group
 */
struct group{
    inline const CryptoPP::Integer& g() const {return _g;}
    inline const CryptoPP::Integer& p() const {return _p;}
    inline const CryptoPP::Integer& q() const {return _q;}
    protected:
        CryptoPP::Integer _g;
        CryptoPP::Integer _p;
        CryptoPP::Integer _q;
};

/**
 * @brief The public information of a participant
 */
struct participant_public: virtual group{
    inline participant_public(){}
    inline participant_public(const CryptoPP::DSA::PublicKey& pk): _public(pk){ init(); }
    inline void init() {
        _public.GetValue("SubgroupGenerator", _g);
        _public.GetValue("SubgroupOrder", _q);
        _public.GetValue("Modulus", _p);
        _public.GetValue("PublicElement", _y);
    }
    inline const CryptoPP::Integer& y() const {return _y;}
    protected:
        CryptoPP::DSA::PublicKey _public;
    private:
        CryptoPP::Integer _y;
};

/**
 * @brief the private information of a participant
 */
struct participant_private: virtual group{
    inline participant_private(){}
    inline participant_private(const CryptoPP::DSA::PrivateKey& sk): _secret(sk){ init(); }
    inline void init() {
        _secret.GetValue("SubgroupGenerator", _g);
        _secret.GetValue("SubgroupOrder", _q);
        _secret.GetValue("Modulus", _p);
        _secret.GetValue("PrivateExponent", _x);
    }
    inline const CryptoPP::Integer& x() const {return _x;}
    protected:
        CryptoPP::DSA::PrivateKey _secret;
    private:
        CryptoPP::Integer _x;
};

struct key_pair: participant_public, participant_private{
    inline key_pair(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size){
        _secret.GenerateRandomWithKeySize(rng, key_size);
        _public.AssignFrom(_secret);
        participant_public::init();
        participant_private::init();
    }
    inline key_pair(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params){
        _secret.GenerateRandom(rng, params);
        _public.AssignFrom(_secret);
        participant_public::init();
        participant_private::init();
    }
};

struct transaction{
    struct traversal_locks;
    class traversal_doors;

    const traversal_doors& doors() const { return _doors; }
    const traversal_locks& locks() const { return _locks; }
    const CryptoPP::Integer& hash() const { return _hash; }

    CryptoPP::Integer next_active(const participant_private& active, const participant_public& authority) const{
        assert(authority.g() == active.g());
        assert(authority.p() == active.p());

        CryptoPP::Integer p = active.p(), g = active.g();
        CryptoPP::ModularArithmetic G(p);

        CryptoPP::Integer temp, inverse, random;

        G.SimultaneousExponentiate(&temp, _locks.random(), std::array<CryptoPP::Integer, 1>{active.x()}.data(), 1);
        inverse = G.MultiplicativeInverse(temp);
        random  = G.Multiply(_locks.active(), inverse);
        temp = 0;

        G.SimultaneousExponentiate(&temp, authority.y(), std::array<CryptoPP::Integer, 2>{active.x(), random}.data(), 2);
        return G.Multiply(temp, hash());
    }

    CryptoPP::Integer random(const participant_private& active) const{
        CryptoPP::Integer temp, inverse, random;
        CryptoPP::Integer p = active.p(), g = active.g();
        CryptoPP::ModularArithmetic G(p);

        G.SimultaneousExponentiate(&temp, _locks.random(), std::array<CryptoPP::Integer, 1>{active.x()}.data(), 1);
        inverse = G.MultiplicativeInverse(temp);
        return G.Multiply(_locks.active(), inverse);
    }

    /**
     * @brief Authority w generates a transaction for the event performed by the active user affecting the passive user.
     *
     */
    inline static transaction create(CryptoPP::AutoSeededRandomPool& rng, const participant_public& active, const participant_public& passive, const participant_private& authority, CryptoPP::Integer tau0, CryptoPP::Integer r0){
        assert(active.g() == passive.g());
        assert(active.p() == passive.p());
        assert(authority.g() == passive.g());
        assert(authority.p() == passive.p());

        transaction t;

        CryptoPP::Integer p = active.p(), g = active.g();


        CryptoPP::Integer rho(rng, 1, p), r(rng, 1, p);

        CryptoPP::ModularArithmetic G(p);

        //{ locks
        G.SimultaneousExponentiate(&t._locks._random,   g, std::array<CryptoPP::Integer, 1>{rho}.data(), 1);
        G.SimultaneousExponentiate(&t._locks._checksum, g, std::array<CryptoPP::Integer, 1>{r  }.data(), 1);

        {
            CryptoPP::Integer temp;
            G.SimultaneousExponentiate(&temp, active.y(),  std::array<CryptoPP::Integer, 1>{rho}.data(), 1);
            t._locks._ciphers._active = G.Multiply(temp, r);
            temp = 0;
            G.SimultaneousExponentiate(&temp, passive.y(), std::array<CryptoPP::Integer, 1>{rho}.data(), 1);
            t._locks._ciphers._passive = G.Multiply(temp, r);
            temp = 0;
        }
        // }

        // { doors
        CryptoPP::Integer temp;
        G.SimultaneousExponentiate(&temp, active.y(), std::array<CryptoPP::Integer, 2>{authority.x(), r0}.data(), 1);
        t._doors._active = G.Multiply(tau0, temp);
        temp = 0;
        G.SimultaneousExponentiate(&temp, passive.y(), std::array<CryptoPP::Integer, 2>{authority.x(), r0}.data(), 1);
        t._doors._passive = temp;
        // }
        t._hash = G.Add(t._doors._active, t._doors._passive); // TODO Why add ? could also be XOR

        return t;
    }

    struct traversal_locks{
        struct cipher_pair{
            CryptoPP::Integer _active;
            CryptoPP::Integer _passive;
        };

        inline const CryptoPP::Integer& random() const { return _random; }
        inline const CryptoPP::Integer& active() const { return _ciphers._active; }
        inline const CryptoPP::Integer& passive() const { return _ciphers._passive; }
        inline const CryptoPP::Integer& checksum() const { return _checksum; }
        private:
            CryptoPP::Integer _random;
            cipher_pair       _ciphers;
            CryptoPP::Integer _checksum;

        friend transaction transaction::create(CryptoPP::AutoSeededRandomPool&, const participant_public&, const participant_public&, const participant_private&, CryptoPP::Integer, CryptoPP::Integer);
    };
    class traversal_doors{
        CryptoPP::Integer _active;
        CryptoPP::Integer _passive;

        friend transaction transaction::create(CryptoPP::AutoSeededRandomPool&, const participant_public&, const participant_public&, const participant_private&, CryptoPP::Integer, CryptoPP::Integer);

        public:
            inline const CryptoPP::Integer& active() const { return _active; }
            inline const CryptoPP::Integer& passive() const { return _passive; }
    };

    private:
        traversal_locks _locks;
        traversal_doors _doors;
        CryptoPP::Integer _hash;

        inline transaction() {}
};

CryptoPP::ModularArithmetic G(const CryptoPP::Integer& p){ return CryptoPP::ModularArithmetic(p); }

void hello_world(CryptoPP::AutoSeededRandomPool& rng){
    CryptoPP::Integer g, p, q, x, x_inverse = 0, gx, y, y_inverse;

    CryptoPP::DSA::PrivateKey sk;
    while(0 == x_inverse){
        sk.GenerateRandomWithKeySize(rng, key_size);
        sk.GetValue("PrivateExponent", x);
        sk.GetValue("SubgroupGenerator", g);
        sk.GetValue("SubgroupOrder", q);
        sk.GetValue("Modulus", p);
        x_inverse = G(p-1).MultiplicativeInverse(x);
    }
    CryptoPP::DSA::PublicKey pk;
    pk.AssignFrom(sk);
    if (!sk.Validate(rng, 3) || !pk.Validate(rng, 3)) {
        throw std::runtime_error("DSA key generation failed");
    }
    pk.GetValue("PublicElement", gx);

    std::cout << "g : " << g  << std::endl;
    std::cout << "q : " << q  << std::endl;
    std::cout << "p : " << p  << std::endl;
    std::cout << "x : " << x  << std::endl;
    std::cout << "gx: " << gx << std::endl;
    G(p).SimultaneousExponentiate(&y, g, std::array<CryptoPP::Integer, 1>{x}.data(), 1);
    assert(gx == y);
    assert(G(p-1).Multiply(x, x_inverse) == 1);
    assert(G(p).Multiply(x, x_inverse) != 1);
    assert(G(p).Exponentiate(G(p).Exponentiate(g, x_inverse), x) == g);

    y_inverse = G(p).MultiplicativeInverse(y);

    // std::string names_sk = sk.GetValueNames(), names_pk = pk.GetValueNames();
    // std::cout << "Secret Key Parameters:" << std::endl;
    // std::size_t i = names_sk.find(";", 0), prev = 0;
    // while(i != std::string::npos) {
    //     std::cout << names_sk.substr(prev+1, i-prev-1) << std::endl;
    //     prev = i;
    //     i = names_sk.find(";", prev+1);
    // }
    // std::cout << std::endl;
    // std::cout << "Public Key Parameters:" << std::endl;
    // i = names_pk.find(";", 0), prev = 0;
    // while(i != std::string::npos) {
    //     std::cout << names_pk.substr(prev+1, i-prev-1) << std::endl;
    //     prev = i;
    //     i = names_pk.find(";", prev+1);
    // }
    // std::cout << std::endl;
    // std::cout << "-----------------------" << std::endl;
    // std::cout << std::endl;

    CryptoPP::Integer a, b, c, d, r(rng, 1, p-1);
    a = G(p).Exponentiate(g, r);                              // g^r                   // Stored in last block
    b = G(p).Exponentiate(G(p).Exponentiate(g, x_inverse), r);   // g^{rx^{-1}}           // Active user sends (A_{w} needs to verify correctness of this)
    c = G(p).Exponentiate(G(p).Exponentiate(g, x), r);           // g^{rx}                // Active user sends (A_{w} has already verified correctness of this)
    d = G(p).Exponentiate(b, x);                              // g^r

    assert(a==d);

    // std::cout << G.Exponentiate(g, x+1) << std::endl;
    // std::cout << G.Multiply(g, G.Exponentiate(g, x_inverse)) << std::endl;
    // std::cout << G.Exponentiate(g, G.Add(x, x_inverse)) << std::endl;

    assert(G(p-1).Divide(G(p-1).Add(G(p-1).Square(x), 1), x) == G(p-1).Add(x, x_inverse));

    std::cout << "1 " << G(p-1).Divide(G(p-1).Multiply(g, G(p-1).Exponentiate(g, x)), G(p-1).Exponentiate(g, x)) << std::endl;
    std::cout << "2 " << G(p-1).Multiply(g, G(p-1).Exponentiate(g, x_inverse)) << std::endl;                // g.g^{x^{-1}}
    std::cout << "3 " << G(p-1).Exponentiate(g, G(p-1).Add(1, x_inverse)) << std::endl;                     // g^{1+x^{-1}}
    std::cout << "4 " << G(p-1).Exponentiate(g, G(p-1).Divide(G(p-1).Add(x, 1), x)) << std::endl;           // g^{(x+1)/x}
    std::cout << "5 " << G(p-1).Divide(G(p).Exponentiate(g, G(p).Add(x, 1)), G(p).Exponentiate(g, x)) << std::endl;

    // assert(G(p-1).Divide(x+1, x) == G(p-1).Add(x, x_inverse));
    // assert(G(p).Divide(x+1, x)   == G(p).Add(x, x_inverse));
    // std::cout << G(p).Divide(x+1, x) << std::endl << G(p).Add(x, x_inverse) << std::endl << (G(p).Divide(x+1, x) == G(p).Add(x, x_inverse)) << std::endl;
    // std::cout << G.Exponentiate(g, G.Divide(x+1, x)) << std::endl << G.Exponentiate(g, G.Add(x, x_inverse)) << std::endl;

    // assert(G(p-1).Divide(x+1, x) != G(p-1).Add(x, x_inverse));
    // assert(G(p).Divide(x+1, x)   != G(p-1).Add(x, x_inverse));

    // std::cout << H.Divide(H.Add(H.Square(x), 1), x) << std::endl << H.Add(x, x_inverse) << std::endl;
/*
    {
        CryptoPP::Integer lhs = H.Divide(
                                    H.Multiply(
                                        H.Exponentiate(
                                            H.Exponentiate(g, x),
                                            r
                                        ),
                                        H.Exponentiate(
                                            g,
                                            r
                                        )
                                    ),
                                    H.Exponentiate(g, x)
                                );
        CryptoPP::Integer rhs = H.Multiply(
                                    H.Exponentiate(g, r),
                                    H.Exponentiate(
                                        H.Exponentiate(g, x_inverse),
                                        r
                                    )
                                );
        std::cout << "lhs: " << lhs << std::endl;
        std::cout << "rhs: " << rhs << std::endl;
        assert(lhs == rhs);
    }*/

}

int main(int argc, char** argv) {
    CryptoPP::AutoSeededRandomPool rng;

    hello_world(rng);
    std::cout << "-----------" << std::endl;

    // key_pair authority = key_pair(rng, key_size);
    // CryptoPP::Integer p = authority.p(), q = authority.q(), g = authority.g();
    //
    // CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters
    //     (CryptoPP::Name::Modulus(), p)
    //     (CryptoPP::Name::SubgroupOrder(), q)
    //     (CryptoPP::Name::SubgroupGenerator(), g);
    //
    // key_pair a(rng, params), b(rng, params), c(rng, params), d(rng, params);
    //
    // transaction init_a = transaction::create(rng, a, authority, authority, CryptoPP::Integer(rng, 1, p), CryptoPP::Integer(rng, 1, p));
    // transaction init_b = transaction::create(rng, b, authority, authority, CryptoPP::Integer(rng, 1, p), CryptoPP::Integer(rng, 1, p));
    // transaction init_c = transaction::create(rng, c, authority, authority, CryptoPP::Integer(rng, 1, p), CryptoPP::Integer(rng, 1, p));
    // transaction init_d = transaction::create(rng, d, authority, authority, CryptoPP::Integer(rng, 1, p), CryptoPP::Integer(rng, 1, p));
    //
    // std::cout << "init_a: " << init_a.doors().active() << std::endl;
    //
    // transaction a_reads_b = transaction::create(rng, a, b, authority, init_a.hash(), init_a.random(a));
    //
    // std::cout << "a_reads_b: " << a_reads_b.doors().active() << std::endl;
    // CryptoPP::Integer a_next = init_a.next_active(a, authority);
    // std::cout << "a_next: " << a_next << std::endl;

    return 0;
}

