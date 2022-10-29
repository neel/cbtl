// SPDX-FileCopyrightText: 2022 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#include "participant_private.h"

bool crn::participant_private::init() {
    _secret.GetValue("SubgroupGenerator", _g);
    _secret.GetValue("SubgroupOrder", _q);
    _secret.GetValue("Modulus", _p);
    _secret.GetValue("PrivateExponent", _x);
    CryptoPP::Integer x_inverse = Gp1().MultiplicativeInverse(_x);
    return x_inverse != 0 && Gp().Exponentiate(Gp().Exponentiate(_g, x_inverse), _x) == _g;
}

unsigned long crn::participant_private::save(const std::string& path){
    CryptoPP::ByteQueue queue;
    _secret.Save(queue);
    CryptoPP::FileSink sink(path.c_str());
    unsigned long len = queue.CopyTo(sink);
    sink.MessageEnd();
    return len;
}

unsigned long crn::participant_private::load(const std::string& path){
    CryptoPP::ByteQueue queue;
    CryptoPP::FileSource source(path.c_str(), true);
    unsigned long len = source.TransferTo(queue);
    queue.MessageEnd();
    _secret.Load(queue);
    init();
    return len;
}

CryptoPP::Integer crn::participant_private::raise_x(CryptoPP::Integer r, std::initializer_list<CryptoPP::Integer> vs) const{
    CryptoPP::Integer result = raise_x(r);
    for(const CryptoPP::Integer& v: vs){
        result = Gp().Exponentiate(result, v);
    }
    return result;
}
