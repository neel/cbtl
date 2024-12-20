// SPDX-FileCopyrightText: 2022 Sunanda Bose <email>
// SPDX-License-Identifier: BSD-3-Clause

#include "cbtl/bdb-storage.h"
#include "cbtl/blocks.h"
#include "cbtl/blocks/io.h"
#include <exception>
#include <filesystem>

cbtl::storage::storage(): _env(std::uint32_t(0)), _opened(false) {
    std::filesystem::path env_dir("storage");
    if(!std::filesystem::exists(env_dir) || !std::filesystem::is_directory(env_dir)){
        std::filesystem::create_directory(env_dir);
    }
    _env.open("storage", DB_CREATE | DB_INIT_LOCK | DB_INIT_MPOOL | DB_INIT_TXN, 0);
}

cbtl::storage::~storage(){
    close();
}


void cbtl::storage::open(){
    _blocks = new Db(&_env, 0);
    _index  = new Db(&_env, 0);
    // _env.txn_begin(NULL, &_transaction, 0);
    _blocks->open(NULL, "storage.db", "blocks" , DB_BTREE, DB_CREATE | DB_AUTO_COMMIT, 0);
    _index->open (NULL, "storage.db", "indexes", DB_BTREE, DB_CREATE | DB_AUTO_COMMIT, 0);
    // _opened = true;
}

void cbtl::storage::close(){
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


bool cbtl::storage::add(const cbtl::blocks::access& block){
    std::string block_id = block.address().hash();
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
    }
    if(!block.genesis()){
        {
            std::string active_address = cbtl::utils::hex::encode(block.address().active(), CryptoPP::Integer::UNSIGNED);
            Dbt key((void*) active_address.c_str(), active_address.size());
            r_addr_active = _index->put(NULL, &key, &id, DB_NOOVERWRITE);
            // std::cout << "r_addr_active: " << r_addr_active << std::endl;
        }{
            std::string passive_address = cbtl::utils::hex::encode(block.address().passive(), CryptoPP::Integer::UNSIGNED);
            Dbt key((void*) passive_address.c_str(), passive_address.size());
            r_addr_passive = _index->put(NULL, &key, &id, DB_NOOVERWRITE);
            // std::cout << "r_addr_passive: " << r_addr_passive << std::endl;
        }
    }
    close();
    return r_block == 0 && r_addr_active == 0 && r_addr_passive == 0;
}

bool cbtl::storage::exists(const std::string& id, bool index){
    open();
    Db* db = index ? _index : _blocks;
    Dbt key((void*) id.c_str(), id.size());
    int ret = db->exists(NULL, &key, 0);
    close();
    return ret != DB_NOTFOUND;
}

std::string cbtl::storage::id(const std::string& addr){
    open();
    Dbt id((void*) addr.c_str(), addr.size()), value;
    int ret = _index->get(NULL, &id, &value, 0);
    if(ret == DB_NOTFOUND){
        throw std::out_of_range("address "+ addr + " not found");
    }else{
        std::string id((const char*) value.get_data(), value.get_size());
        close();
        return id;
    }
}


cbtl::blocks::access cbtl::storage::fetch(const std::string& block_id){
    open();
    Dbt id((void*) block_id.c_str(), block_id.size()), value;
    int ret = _blocks->get(NULL, &id, &value, 0);
    if(ret == DB_NOTFOUND){
        throw std::out_of_range("block "+ block_id + " not found");
    }else{
        std::string json_str((const char*) value.get_data(), value.get_size());
        nlohmann::json json = nlohmann::json::parse(json_str);
        cbtl::blocks::access block = json;
        close();
        return block;
    }
}
