// SPDX-FileCopyrightText: 2022 Neel Basu <email>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef DB_H
#define DB_H

#include <string>
#include <db_cxx.h>
#include "block.h"

namespace crn{

struct db{
    db();
    ~db();

    bool add(const crn::blocks::access& block);
    bool exists(const std::string& id);
    bool search(const CryptoPP::Integer& address);

    protected:
        void open();
        void commit();
        void abort();
        void close();

    private:
        Db* _blocks;
        Db* _index;
        DbTxn* _transaction;
        DbEnv _env;
        bool _opened;
};

}

#endif // DB_H