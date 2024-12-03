// SPDX-FileCopyrightText: 2022 Sunanda Bose <email>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef cbtl_STORAGE_REDIS_H
#define cbtl_STORAGE_REDIS_H

#include <string>
#include <hiredis/hiredis.h>
#include "cbtl/blocks_fwd.h"
#include <cryptopp/integer.h>

namespace cbtl{

struct storage{
    storage();
    ~storage();

    bool add(const cbtl::blocks::access& block);
    bool exists(const std::string& id, bool index = false);

    std::string id(const std::string& addr);

    cbtl::blocks::access fetch(const std::string& block_id);

    protected:
        void open();
        void close();

    private:
        redisContext* _context;
        bool _opened;
};

}

#endif // cbtl_STORAGE_REDIS_H

