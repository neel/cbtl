cmake_minimum_required(VERSION 3.0)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

project(crn)

find_package(CryptoPP REQUIRED)
FIND_PACKAGE(Boost COMPONENTS filesystem regex system serialization REQUIRED)

add_subdirectory(3rdparty)

SET(INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}/includes
  3rdparty/azmq
)

add_executable(crn main.cpp)

target_link_libraries(crn ${CryptoPP_LIBRARIES} ${AzioMQ_LIBRARIES} ${ZeroMQ_LIBRARIES})
target_include_directories(crn PUBLIC ${INCLUDE_DIRS})

install(TARGETS crn RUNTIME DESTINATION bin)
