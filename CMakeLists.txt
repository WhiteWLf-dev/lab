cmake_minimum_required(VERSION 3.10)

project(DESExample C)

set(CMAKE_C_STANDARD 11)

find_package(OpenSSL REQUIRED)

add_executable(des main.c)

target_link_libraries(des OpenSSL::SSL OpenSSL::Crypto)
