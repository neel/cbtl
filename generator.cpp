#include <iostream>
#include <string>
#include <array>
#include <cassert>
#include <exception>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/elgamal.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/dsa.h>
#include <cryptopp/files.h>
#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>
#include <db_cxx.h>

constexpr static const std::uint32_t key_size = 1024;

/**
 * @brief the algebric group
 */
struct group{
    inline const CryptoPP::Integer& g() const {return _g;}
    inline const CryptoPP::Integer& p() const {return _p;}
    inline const CryptoPP::Integer& q() const {return _q;}
    protected:
        CryptoPP::Integer _g;
        CryptoPP::Integer _p;
        CryptoPP::Integer _q;
    public:
        group() = default;
        group(const group&) = default;
        inline CryptoPP::AlgorithmParameters params() const {
            return CryptoPP::MakeParameters
                (CryptoPP::Name::Modulus(), _p)
                (CryptoPP::Name::SubgroupOrder(), _q)
                (CryptoPP::Name::SubgroupGenerator(), _g);
        }
};

CryptoPP::ModularArithmetic G(const CryptoPP::Integer& p){ return CryptoPP::ModularArithmetic(p); }

/**
 * @brief The public information of a participant
 */
struct participant_public: virtual group{
    protected:
        inline participant_public(){}
        inline participant_public(const CryptoPP::DSA::PublicKey& pk): _public(pk){ init(); }
        inline void init() {
            _public.GetValue("SubgroupGenerator", _g);
            _public.GetValue("SubgroupOrder", _q);
            _public.GetValue("Modulus", _p);
            _public.GetValue("PublicElement", _y);
        }
    protected:
        CryptoPP::DSA::PublicKey _public;
    private:
        CryptoPP::Integer _y;
    public:
        participant_public(const participant_public&) = default;
        inline const CryptoPP::Integer& y() const {return _y;}
        inline unsigned long save(const std::string& path){
            CryptoPP::ByteQueue queue;
            _public.BEREncode(queue);
            CryptoPP::FileSink sink(path.c_str());
            return queue.CopyTo(sink);
        }
        /**
         * Calculates $y^{r}$
         */
        inline CryptoPP::Integer raise(CryptoPP::Integer r){
            return G(_p).Exponentiate(_y, r);
        }
};

/**
 * @brief the private information of a participant
 */
struct participant_private: virtual group{
    protected:
        inline participant_private(){}
        inline participant_private(const CryptoPP::DSA::PrivateKey& sk): _secret(sk){ init(); }
        inline bool init() {
            _secret.GetValue("SubgroupGenerator", _g);
            _secret.GetValue("SubgroupOrder", _q);
            _secret.GetValue("Modulus", _p);
            _secret.GetValue("PrivateExponent", _x);
            CryptoPP::Integer x_inverse = G(_p-1).MultiplicativeInverse(_x);
            return x_inverse != 0 && G(_p).Exponentiate(G(_p).Exponentiate(_g, x_inverse), _x) == _g;
        }
    protected:
        CryptoPP::DSA::PrivateKey _secret;
    private:
        CryptoPP::Integer _x;
    public:
        participant_private(const participant_private&) = default;
        inline const CryptoPP::Integer& x() const {return _x;}
        inline unsigned long save(const std::string& path){
            CryptoPP::ByteQueue queue;
            _secret.BEREncode(queue);
            CryptoPP::FileSink sink(path.c_str());
            return queue.CopyTo(sink);
        }
        /**
         * Calculates $r^{x}$
         */
        inline CryptoPP::Integer raise_x(CryptoPP::Integer r){
            return G(_p).Exponentiate(r, _x);
        }
};

struct key_pair: participant_public, participant_private{
    inline key_pair(CryptoPP::AutoSeededRandomPool& rng, std::uint32_t key_size){
        bool success = false;
        while(!success){
            _secret.GenerateRandomWithKeySize(rng, key_size);
            success = participant_private::init();
        }
        _public.AssignFrom(_secret);
        participant_public::init();
    }
    inline key_pair(CryptoPP::AutoSeededRandomPool& rng, const CryptoPP::AlgorithmParameters& params){
        bool success = false;
        while(!success){
            _secret.GenerateRandom(rng, params);
            success = participant_private::init();
        }
        _public.AssignFrom(_secret);
        participant_public::init();
    }
    inline key_pair(CryptoPP::AutoSeededRandomPool& rng, const participant_public& pk): key_pair(rng, pk.params()){}

    inline const participant_public& public_key() const { return *this; }
    inline const participant_private& private_key() const { return *this; }
    inline void save(const std::string& name){
        participant_public::save(name+".pub");
        participant_private::save(name);
    }
};


int main(int argc, char** argv) {
    unsigned int managers = 0, supers = 0, patients = 0;
    boost::program_options::options_description desc("crn-gen generates keys for the Trusted Server and Data Managers, Supervisors and patients");
    desc.add_options()
        ("help", "prints this help message")
        ("name-master",  boost::program_options::value<std::string>()->default_value("master"),    "filename for the Master Key (Trusted Server)")
        ("name-manager", boost::program_options::value<std::string>()->default_value("manager"),   "filename for the Data Manager's key (file names will be suffixed by integer counter)")
        ("name-super",   boost::program_options::value<std::string>()->default_value("super"),     "filename for the Data Manager's key (file names will be suffixed by integer counter)")
        ("name-patient", boost::program_options::value<std::string>()->default_value("super"),     "filename for the Data Manager's key (file names will be suffixed by integer counter)")
        ("managers",     boost::program_options::value<unsigned int>(&managers)->default_value(2), "number of Data Managers")
        ("supers",       boost::program_options::value<unsigned int>(&supers)->default_value(2),   "number of Supervisors")
        ("patients",     boost::program_options::value<unsigned int>(&patients)->default_value(2), "number of Patients")
        ;
    boost::program_options::variables_map map;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), map);
    boost::program_options::notify(map);

    if(map.count("help")){
        std::cout << desc << std::endl;
        return 1;
    }

    std::string master = "master", manager = "manager", super = "super", patient = "patient";
    if(map.count("master")) { master  = map["master"] .as<std::string>(); }
    if(map.count("manager")){ manager = map["manager"].as<std::string>(); }
    if(map.count("super"))  { super   = map["super"]  .as<std::string>(); }
    if(map.count("patient")){ patient = map["patient"].as<std::string>(); }


    CryptoPP::AutoSeededRandomPool rng;

    key_pair tk(rng, key_size);
    tk.save(master);

    for(std::uint32_t i = 0; i < managers; ++i){
        std::string name = manager+"-"+boost::lexical_cast<std::string>(i);
        key_pair key(rng, tk.public_key());
        key.save(name);
    }

    for(std::uint32_t i = 0; i < supers; ++i){
        std::string name = super+"-"+boost::lexical_cast<std::string>(i);
        key_pair key(rng, tk.public_key());
        key.save(name);
    }

    for(std::uint32_t i = 0; i < patients; ++i){
        std::string name = patient+"-"+boost::lexical_cast<std::string>(i);
        key_pair key(rng, tk.public_key());
        key.save(name);
    }

    // TODO Distribute those keys

    // { Create Key Value Data base
    Db db(NULL, 0);
    try{
        db.open(NULL /* Transaction pointer */,  "blockchain.db", NULL /*Optional logical database name*/ , DB_BTREE, DB_CREATE, 0); // File mode (using defaults)

        db.close(0);
    }catch(DbException& e){

    }catch(std::exception& e){

    }
    //}

    return 0;
}

