// SPDX-FileCopyrightText: 2022 Neel Basu <email>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef DB_H
#define DB_H

#include <string>
#include <db_cxx.h>
#include "blocks.h"

namespace crn{

struct db{
    db();
    ~db();

    bool add(const crn::blocks::access& block);
    bool exists(const std::string& id);
    bool search(const CryptoPP::Integer& address);

    crn::blocks::access fetch(const std::string& block_id);

    protected:
        void open();
        void close();
        void commit();
        void abort();

    private:
        Db* _blocks;
        Db* _index;
        DbTxn* _transaction;
        DbEnv _env;
        bool _opened;
};

}

#endif // DB_H
