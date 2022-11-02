cmake_minimum_required(VERSION 3.0)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

project(crn)

find_package(CryptoPP REQUIRED)
find_package(ZeroMQ REQUIRED)
find_package(BerkeleyDB REQUIRED)
find_package(nlohmann_json REQUIRED)
FIND_PACKAGE(Boost COMPONENTS filesystem regex system serialization program_options REQUIRED)

SET(INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}/includes
)

SET(SOURCES
    sources/group.cpp
    sources/participant_private.cpp
    sources/participant_public.cpp
    sources/key_pair.cpp
    sources/utils.cpp
    sources/genesis_block.cpp
    sources/block.cpp
    sources/db.cpp
    sources/server.cpp
    sources/session.cpp
    sources/packets.cpp
    sources/keys.cpp
)

add_executable(crn-client  ${SOURCES} client.cpp)
add_executable(crn-gen     ${SOURCES} generator.cpp)
add_executable(crn-init    ${SOURCES} init.cpp)
add_executable(crn-manager ${SOURCES} manager.cpp)
add_executable(crn-server  ${SOURCES} server.cpp)

target_link_libraries(crn-server     ${CryptoPP_LIBRARIES} ${ZeroMQ_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)
target_link_libraries(crn-client     ${CryptoPP_LIBRARIES} ${ZeroMQ_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)
target_link_libraries(crn-gen        ${CryptoPP_LIBRARIES} ${ZeroMQ_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)
target_link_libraries(crn-init       ${CryptoPP_LIBRARIES} ${ZeroMQ_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)
target_link_libraries(crn-manager    ${CryptoPP_LIBRARIES} ${ZeroMQ_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES} nlohmann_json::nlohmann_json)

target_include_directories(crn-server     PUBLIC ${INCLUDE_DIRS})
target_include_directories(crn-client     PUBLIC ${INCLUDE_DIRS})
target_include_directories(crn-gen        PUBLIC ${INCLUDE_DIRS})
target_include_directories(crn-init       PUBLIC ${INCLUDE_DIRS})
target_include_directories(crn-manager    PUBLIC ${INCLUDE_DIRS})

install(TARGETS crn-server  RUNTIME DESTINATION bin)
install(TARGETS crn-client  RUNTIME DESTINATION bin)
install(TARGETS crn-manager RUNTIME DESTINATION bin)
