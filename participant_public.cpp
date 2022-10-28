// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "participant_public.h"
#include <cryptopp/files.h>

void crn::participant_public::init() {
    _public.GetValue("SubgroupGenerator", _g);
    _public.GetValue("SubgroupOrder", _q);
    _public.GetValue("Modulus", _p);
    _public.GetValue("PublicElement", _y);
}

unsigned long crn::participant_public::save(const std::string& path) const {
    CryptoPP::ByteQueue queue;
    _public.Save(queue);
    CryptoPP::FileSink sink(path.c_str());
    unsigned long len = queue.CopyTo(sink);
    sink.MessageEnd();
    return len;
}

unsigned long crn::participant_public::load(const std::string& path){
    CryptoPP::ByteQueue queue;
    CryptoPP::FileSource source(path.c_str(), true);
    unsigned long len = source.TransferTo(queue);
    queue.MessageEnd();
    _public.Load(queue);
    init();
    std::cout << len << " " << _y << std::endl;
    return len;
}

CryptoPP::Integer crn::participant_public::raise(std::initializer_list<CryptoPP::Integer> vs) const{
    CryptoPP::Integer result = _y;
    for(const CryptoPP::Integer& v: vs){
        result = Gp().Exponentiate(result, v);
    }
    return result;
}
