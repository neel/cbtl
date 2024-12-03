// SPDX-FileCopyrightText: 2023 Sunanda Bose <sunanda@simula.no>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_STORAGE_H
#define cbtl_STORAGE_H

#include <string>
#include "cbtl/blocks_fwd.h"
#include "cbtl/blocks.h"
#include <cryptopp/integer.h>

namespace cbtl{

/**
 * @todo write docs
 */
template <typename EngineT>
class storage{
    using engine_type = EngineT;

    storage(engine_type&& engine): _engine(engine) {}
    ~storage() {}

    bool add(const cbtl::blocks::access& block){
        return _engine.add(block);
    }
    bool exists(const std::string& id, bool index = false){
        return _engine.exists(id, index);
    }
    std::string id(const std::string& addr){
        return _engine.id(addr);
    }
    cbtl::blocks::access fetch(const std::string& block_id){
        return _engine.fetch(block_id);
    }

    private:
        engine_type _engine;
};


}

#endif // cbtl_STORAGE_H
