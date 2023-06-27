// SPDX-FileCopyrightText: 2022 Sunanda Bose <email>
// SPDX-License-Identifier: BSD-3-Clause

#include "crn/redis-storage.h"
#include "crn/blocks.h"
#include "crn/blocks/io.h"
#include <exception>
#include <boost/filesystem.hpp>

crn::storage::storage(): _opened(false) {
    open();
}

crn::storage::~storage(){
    close();
}


void crn::storage::open(){
    _context = redisConnect("127.0.0.1", 6379);
}

void crn::storage::close(){
    if(_opened){
        redisFree(_context);
        _opened = false;
    }

}

bool crn::storage::add(const crn::blocks::access& block){
    std::string block_id = block.address().hash();
    nlohmann::json json = block;
    std::string block_str = json.dump();

    bool ok = true;
    redisReply* reply;

    {
        reply = (redisReply*) redisCommand(_context, "SET id:%s %s", block_id.c_str(), block_str.c_str());
        ok = (reply != 0x0);
        if(ok) freeReplyObject(reply);
    }
    if(ok){
        std::string active_address = crn::utils::hex::encode(block.address().active(), CryptoPP::Integer::UNSIGNED);
        reply = (redisReply*) redisCommand(_context, "SET addr:%s %s", active_address.c_str(), block_id.c_str());
        ok = (reply != 0x0);
        if(ok) freeReplyObject(reply);
    }
    if(ok){
        std::string passive_address = crn::utils::hex::encode(block.address().active(), CryptoPP::Integer::UNSIGNED);
        reply = (redisReply*) redisCommand(_context, "SET addr:%s %s", passive_address.c_str(), block_id.c_str());
        ok = (reply != 0x0);
        if(ok) freeReplyObject(reply);
    }
    return ok;
}

bool crn::storage::exists(const std::string& id, bool index){
    std::string prefix = index ? std::string("addr") : std::string("id");
    redisReply* reply = (redisReply*) redisCommand(_context, "EXISTS %s:%s", prefix.c_str(), id.c_str());
    if(reply){
        std::cout << "(reply->type == REDIS_REPLY_INTEGER): " << (reply->type == REDIS_REPLY_INTEGER) << std::endl;
        if(reply->type == REDIS_REPLY_INTEGER){
            bool ret = (reply->integer == 1);
            if(reply != 0x0){
                freeReplyObject(reply);
                reply = 0x0;
            }
            return ret;
        }
    }
    if(reply != 0x0){
        freeReplyObject(reply);
        reply = 0x0;
    }
    return false;
}

std::string crn::storage::id(const std::string& addr){
    redisReply* reply = (redisReply*) redisCommand(_context, "GET addr:%s", addr.c_str());
    if(reply){
        std::cout << "(reply->type == REDIS_REPLY_STRING): " << (reply->type == REDIS_REPLY_STRING) << std::endl;
        if(reply->type == REDIS_REPLY_STRING){
            std::string value(reply->str, reply->len);
            if(reply != 0x0){
                freeReplyObject(reply);
                reply = 0x0;
            }
            return value;
        }else{
            throw std::out_of_range("address "+ addr + " not found");
        }
    }
    if(reply != 0x0){
        freeReplyObject(reply);
        reply = 0x0;
    }
    return std::string();
}


crn::blocks::access crn::storage::fetch(const std::string& block_id){
    redisReply* reply = (redisReply*) redisCommand(_context, "GET id:%s", block_id.c_str());
    if(reply){
        if(reply->type == REDIS_REPLY_STRING){
            std::string json_str(reply->str, reply->len);
            nlohmann::json json = nlohmann::json::parse(json_str);
            crn::blocks::access block = json;
            if(reply != 0x0){
                freeReplyObject(reply);
                reply = 0x0;
            }
            return block;
        }else{
            throw std::out_of_range("block "+ block_id + " not found");
        }
    }else{
        throw std::runtime_error("reply is null");
    }
}

