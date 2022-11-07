#include <string>
#include <iostream>
#include "crn/utils.h"

int main(int argc, char** argv){
    CryptoPP::Integer input;

    input = 4512121416314646;
    std::cout << "SHA512: " << crn::utils::SHA512(input) << std::endl;

    input = 4512121416314646;
    std::cout << " eHex: " << crn::utils::eHex(input) << std::endl;

    input = 4512121416314646;
    std::cout << "sha512: " << crn::utils::sha512(input) << std::endl;
    std::cout << "eHex(sha512): " << crn::utils::eHex(crn::utils::sha512(input)) << std::endl;
}
