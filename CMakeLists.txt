cmake_minimum_required(VERSION 3.0)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

project(crn)

find_package(CryptoPP REQUIRED)
find_package(BerkeleyDB REQUIRED)
find_package(nlohmann_json REQUIRED)
FIND_PACKAGE(Boost COMPONENTS filesystem regex system serialization program_options REQUIRED)

SET(INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}/includes
)

SET(SOURCES
    sources/group.cpp
    sources/line.cpp
    sources/utils.cpp
    sources/blocks/active.cpp
    sources/blocks/passive.cpp
    sources/blocks/params.cpp
    sources/blocks/access.cpp
    sources/blocks/contents.cpp
    sources/blocks/addresses.cpp
    sources/storage.cpp
    sources/server.cpp
    sources/session.cpp
    sources/packets.cpp
    sources/keys.cpp
)

add_library(crn SHARED ${SOURCES})

add_executable(crn-init    init.cpp)
add_executable(crn-manager manager.cpp)
add_executable(crn-server  main.cpp)
add_executable(crn-read    read.cpp)
add_executable(rough  rough.cpp)

target_link_libraries(crn ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)

target_link_libraries(crn-server     crn ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)
target_link_libraries(crn-init       crn ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)
target_link_libraries(crn-manager    crn ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)
target_link_libraries(crn-read       crn ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)
target_link_libraries(rough    crn ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)

target_include_directories(crn PUBLIC ${INCLUDE_DIRS})

install(TARGETS crn         RUNTIME DESTINATION lib)
install(TARGETS crn-server  RUNTIME DESTINATION bin)
install(TARGETS crn-init    RUNTIME DESTINATION bin)
install(TARGETS crn-manager RUNTIME DESTINATION bin)
install(TARGETS crn-read    RUNTIME DESTINATION bin)
