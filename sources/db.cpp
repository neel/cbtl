// SPDX-FileCopyrightText: 2022 Neel Basu <email>
// SPDX-License-Identifier: BSD-3-Clause

#include "db.h"
#include "blocks_io.h"

crn::db::db(): _env(0), _opened(false) {
    // _env.open("storage", DB_CREATE | DB_INIT_LOCK | DB_INIT_MPOOL | DB_INIT_TXN, 0);
}

crn::db::~db(){
    close();
}


void crn::db::open(){
    _blocks = new Db(NULL, 0);
    _index  = new Db(NULL, 0);
    // _env.txn_begin(NULL, &_transaction, 0);
    _blocks->open(NULL, "storage.db", "blocks" , DB_BTREE, DB_CREATE, 0);
    _index->open (NULL, "storage.db", "indexes", DB_BTREE, DB_CREATE, 0);
    // _opened = true;
}

void crn::db::close(){
    if(_opened){
        _blocks->sync(0);
        _blocks->close(0);
        _index->sync(0);
        _index->close(0);
        _opened = false;
    }
    if(_blocks != 0x0){
        delete _blocks;
        _blocks = 0x0;
    }
    if(_index != 0x0){
        delete _index;
        _index = 0x0;
    }
}

void crn::db::commit(){
    _transaction->commit(DB_TXN_SYNC);
    close();
    _transaction = 0x0;
}

void crn::db::abort(){
    _transaction->abort();
    close();
    _transaction = 0x0;
}


bool crn::db::add(const crn::blocks::access& block){
    std::string block_id = block.address().id();
    // if(exists(block_id)){
    //     return false;
    // }
    open();
    nlohmann::json json = block;
    std::string block_str = json.dump();

    int r_block = 0, r_addr_active = 0, r_addr_passive = 0;

    Dbt id((void*) block_id.c_str(), block_id.size());
    {
        Dbt value((void*) block_str.c_str(), block_str.size());
        r_block = _blocks->put(NULL, &id, &value, DB_NOOVERWRITE);
        std::cout << "r_block: " << r_block << std::endl;
    }
    if(!block.is_genesis()){
        {
            std::string active_address = crn::utils::eHex(block.address().active());
            Dbt key((void*) active_address.c_str(), active_address.size());
            r_addr_active = _index->put(NULL, &key, &id, DB_NOOVERWRITE);
            std::cout << "r_addr_active: " << r_addr_active << std::endl;
        }{
            std::string passive_address = crn::utils::eHex(block.address().passive());
            Dbt key((void*) passive_address.c_str(), passive_address.size());
            r_addr_passive = _index->put(NULL, &key, &id, DB_NOOVERWRITE);
            std::cout << "r_addr_passive: " << r_addr_passive << std::endl;
        }
    }
    close();
    return r_block == 0 && r_addr_active == 0 && r_addr_passive == 0;
}

bool crn::db::exists(const std::string& id){
    open();
    Dbt key((void*) id.c_str(), id.size());
    int ret = _blocks->exists(NULL, &key, 0);
    close();
    return ret != DB_NOTFOUND;
}

crn::blocks::access crn::db::fetch(const std::string& block_id){
    open();
    crn::blocks::access* block;
    Dbt id((void*) block_id.c_str(), block_id.size()), value;
    int ret = _blocks->get(NULL, &id, &value, 0);
    if(ret == DB_NOTFOUND){
        // TODO throw
    }else{
        std::string json_str((const char*) value.get_data(), value.get_size());
        nlohmann::json json = nlohmann::json::parse(json_str);
        *block = json;
    }
    close();
    return *block;
}


bool crn::db::search(const CryptoPP::Integer& address){
    open();
    std::string addr = crn::utils::eHex(address);
    Dbt key((void*) addr.c_str(), addr.size());
    int ret = _blocks->exists(NULL, &key, 0);
    close();

    return ret != DB_NOTFOUND;
}
