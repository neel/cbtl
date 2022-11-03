// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef KEYS_H
#define KEYS_H

#include "crn/group.h"
#include <cryptopp/dsa.h>
#include <cryptopp/files.h>
#include "crn/storage.h"
#include "crn/packets.h"

namespace crn{
namespace identity{
namespace keys{

template <typename KeyT, typename DerivedT>
struct dsa: group{
    bool init(){
        _key.GetValue("SubgroupGenerator", _g);
        _key.GetValue("SubgroupOrder", _q);
        _key.GetValue("Modulus", _p);
        return static_cast<DerivedT*>(this)->initialize();
    }
    unsigned long load(const std::string& path){
        CryptoPP::ByteQueue queue;
        CryptoPP::FileSource source(path.c_str(), true);
        unsigned long len = source.TransferTo(queue);
        queue.MessageEnd();
        _key.Load(queue);
        return len;
    }
    unsigned long save(const std::string& path) const{
        CryptoPP::ByteQueue queue;
        _key.Save(queue);
        CryptoPP::FileSink sink(path.c_str());
        unsigned long len = queue.CopyTo(sink);
        sink.MessageEnd();
        return len;
    }
    const KeyT& key() const { return _key; }
    const group& G() const { return *this; }
    protected:
        dsa() = default;
        explicit dsa(const KeyT& k): _key(k){ init(); }
        explicit dsa(const std::string& path){ load(path); }
    protected:
        KeyT _key;
};

struct private_key: dsa<CryptoPP::DSA::PrivateKey, private_key>{
    using base_type = dsa<CryptoPP::DSA::PrivateKey, private_key>;

    inline explicit private_key(const std::string& path): base_type(path) {}
    private_key(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size);
    private_key(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params);
    private_key(CryptoPP::AutoSeededRandomPool& rng, const private_key& other);
    private_key(const private_key& other) = default;

    bool initialize();
    inline const CryptoPP::Integer& x() const {return _x;}
    private:
        CryptoPP::Integer _x;
};

struct public_key: dsa<CryptoPP::DSA::PublicKey, public_key>{
    using base_type = dsa<CryptoPP::DSA::PublicKey, public_key>;

    inline explicit public_key(const std::string& path): base_type(path) {}
    public_key(const private_key& pk);
    public_key(const public_key& other) = default;

    bool initialize();
    const CryptoPP::Integer& y() const {return _y;}

    std::string genesis_id() const;
    private:
        CryptoPP::Integer _y;
};

struct pair{
    pair(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size);
    pair(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params);
    pair(CryptoPP::AutoSeededRandomPool& rng, const private_key& other);
    pair(const std::string& private_path, const std::string& public_path);

    inline const public_key& pub() const { return _public; }
    inline const private_key& pri() const { return _private; }
    inline public_key& pub() { return _public; }
    inline private_key& pri() { return _private; }

    bool init();

    void save(const std::string& name) const;
    private:
        private_key _private;
        public_key  _public;
};

}

struct user: keys::pair{
    template <typename... Args>
    user(crn::storage& db, Args... args): keys::pair(args...), _db(db) {}

    std::string last_id() const;
    CryptoPP::Integer request(std::string& id) const;
    crn::packets::request request() const;
    private:
        crn::storage& _db;

};

}
}

#endif // KEYS_H
