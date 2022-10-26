cmake_minimum_required(VERSION 3.0)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

project(crn)

find_package(CryptoPP REQUIRED)

add_executable(crn main.cpp)

target_link_libraries(crn ${CryptoPP_LIBRARIES})

install(TARGETS crn RUNTIME DESTINATION bin)
