// SPDX-FileCopyrightText: 2022 Sunanda Bose <email>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CRN_STORAGE_BDB_H
#define CRN_STORAGE_BDB_H

#include <string>
#include <db_cxx.h>
#include "crn/blocks_fwd.h"
#include <cryptopp/integer.h>

namespace crn{

struct storage{
    storage();
    ~storage();

    bool add(const crn::blocks::access& block);
    bool exists(const std::string& id, bool index = false);

    std::string id(const std::string& addr);

    crn::blocks::access fetch(const std::string& block_id);

    protected:
        void open();
        void close();

    private:
        Db* _blocks;
        Db* _index;
        DbTxn* _transaction;
        DbEnv _env;
        bool _opened;
};

}

#endif // CRN_STORAGE_BDB_H
