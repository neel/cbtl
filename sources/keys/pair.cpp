// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "cbtl/keys/pair.h"


cbtl::keys::identity::pair::pair(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size): _private(rng, key_size), _public(_private)  { }
cbtl::keys::identity::pair::pair(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params): _private(rng, params), _public(_private) { }
cbtl::keys::identity::pair::pair(CryptoPP::AutoSeededRandomPool& rng, const cbtl::keys::identity::private_key& other): _private(rng, other), _public(_private) { }
cbtl::keys::identity::pair::pair(const std::string& private_path, const std::string& public_path): _private(private_path), _public(public_path) { }
bool cbtl::keys::identity::pair::init(){
    return _public.init() && _private.init();
}

void cbtl::keys::identity::pair::save(const std::string& name) const{
    _public.save(name+".pub");
    _private.save(name);
}
