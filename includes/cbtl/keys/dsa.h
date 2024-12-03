// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_KEYS_DSA_H
#define cbtl_KEYS_DSA_H

#include "cbtl/math/group.h"
#include <cryptopp/dsa.h>
#include <cryptopp/files.h>

namespace cbtl{
namespace keys{
namespace identity{


template <typename KeyT, typename DerivedT>
struct dsa: cbtl::math::group{
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

}
}
}


#endif // cbtl_KEYS_DSA_H
