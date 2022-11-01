#include <db.h>

int main(int argc, char** argv){
    crn::db db;

    std::cout << std::boolalpha << db.exists("hello") << std::endl;

    return 0;
}
