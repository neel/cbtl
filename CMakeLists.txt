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
    sources/utils.cpp
    sources/block.cpp
    sources/db.cpp
    sources/server.cpp
    sources/session.cpp
    sources/packets.cpp
    sources/keys.cpp
)

add_executable(crn-init    ${SOURCES} init.cpp)
add_executable(crn-manager ${SOURCES} manager.cpp)
add_executable(crn-server  ${SOURCES} main.cpp)

target_link_libraries(crn-server     ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)
target_link_libraries(crn-init       ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)
target_link_libraries(crn-manager    ${CryptoPP_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)

target_include_directories(crn-server     PUBLIC ${INCLUDE_DIRS})
target_include_directories(crn-init       PUBLIC ${INCLUDE_DIRS})
target_include_directories(crn-manager    PUBLIC ${INCLUDE_DIRS})

install(TARGETS crn-server  RUNTIME DESTINATION bin)
install(TARGETS crn-init    RUNTIME DESTINATION bin)
install(TARGETS crn-manager RUNTIME DESTINATION bin)
