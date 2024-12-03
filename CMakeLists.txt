cmake_minimum_required(VERSION 3.0)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

project(cbtl)

find_package(CryptoPP REQUIRED)
find_package(BerkeleyDB REQUIRED)
find_package(hiredis REQUIRED)
find_package(PQXX REQUIRED)
find_package(nlohmann_json REQUIRED)
FIND_PACKAGE(Boost COMPONENTS filesystem regex system serialization program_options REQUIRED)

SET(INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}/includes
)

SET(SOURCES
    sources/utils.cpp
    sources/blocks/active.cpp
    sources/blocks/passive.cpp
    sources/blocks/params.cpp
    sources/blocks/access.cpp
    sources/blocks/contents.cpp
    sources/blocks/addresses.cpp
    sources/math/group.cpp
    sources/math/diophantine.cpp
    sources/math/vector.cpp
    sources/math/coordinates.cpp
    sources/keys/dsa.cpp
    sources/keys/private.cpp
    sources/keys/public.cpp
    sources/keys/pair.cpp
    sources/keys/access.cpp
    sources/keys/view.cpp
    # sources/bdb-storage.cpp
    sources/redis-storage.cpp
    sources/server.cpp
    sources/session.cpp
    sources/packets.cpp
)

FILE(GLOB_RECURSE LibFiles "includes/*.h")
add_custom_target(headers SOURCES ${LibFiles})

add_library(cbtl SHARED ${SOURCES})

add_executable(cbtl-init    init.cpp)
add_executable(cbtl-request request.cpp)
add_executable(cbtl-server  main.cpp)
add_executable(cbtl-read    read.cpp)
# add_executable(rough       rough.cpp)

target_link_libraries(cbtl ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json ${PQXX_LIBRARIES} ${HIREDIS_LIBRARIES})

target_link_libraries(cbtl-server     cbtl ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)
target_link_libraries(cbtl-init       cbtl ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json ${PQXX_LIBRARIES})
target_link_libraries(cbtl-request    cbtl ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)
target_link_libraries(cbtl-read       cbtl ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)
# target_link_libraries(rough          cbtl ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)

target_compile_features(cbtl         PRIVATE cxx_std_20)
target_compile_features(cbtl-init    PRIVATE cxx_std_20)
target_compile_features(cbtl-server  PRIVATE cxx_std_20)
target_compile_features(cbtl-request PRIVATE cxx_std_20)
target_compile_features(cbtl-read    PRIVATE cxx_std_20)

target_include_directories(cbtl PUBLIC ${INCLUDE_DIRS})

install(TARGETS cbtl         RUNTIME DESTINATION lib)
install(TARGETS cbtl-server  RUNTIME DESTINATION bin)
install(TARGETS cbtl-init    RUNTIME DESTINATION bin)
install(TARGETS cbtl-request RUNTIME DESTINATION bin)
install(TARGETS cbtl-read    RUNTIME DESTINATION bin)
