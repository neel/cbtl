cmake_minimum_required(VERSION 3.0)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

project(crn)

find_package(CryptoPP REQUIRED)
find_package(ZeroMQ REQUIRED)
find_package(BerkeleyDB REQUIRED)
FIND_PACKAGE(Boost COMPONENTS filesystem regex system serialization program_options REQUIRED)

SET(INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}/includes
)

add_executable(crn-server main.cpp)
add_executable(crn-client client.cpp)
add_executable(crn-gen generator.cpp)

target_link_libraries(crn-server ${CryptoPP_LIBRARIES} ${ZeroMQ_LIBRARIES})
target_link_libraries(crn-client ${CryptoPP_LIBRARIES} ${ZeroMQ_LIBRARIES})
target_link_libraries(crn-gen ${CryptoPP_LIBRARIES} ${ZeroMQ_LIBRARIES} ${Boost_LIBRARIES} ${BerkeleyDB_LIBRARIES})

target_include_directories(crn-server PUBLIC ${INCLUDE_DIRS})
target_include_directories(crn-client PUBLIC ${INCLUDE_DIRS})
target_include_directories(crn-gen PUBLIC ${INCLUDE_DIRS})

install(TARGETS crn-server RUNTIME DESTINATION bin)
install(TARGETS crn-client RUNTIME DESTINATION bin)
