cmake_minimum_required(VERSION 3.10)
project(pkcertchain C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

set(PKCERTCHAIN_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

file(GLOB_RECURSE PKCERTCHAIN_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
)

add_executable(pkcertchain ${PKCERTCHAIN_SOURCES})

target_include_directories(pkcertchain PRIVATE ${PKCERTCHAIN_INCLUDE_DIR})

target_compile_definitions(pkcertchain PRIVATE _DEFAULT_SOURCE)
target_compile_options(pkcertchain PRIVATE -O3 -Wall -Wextra)

target_link_libraries(pkcertchain PRIVATE OpenSSL::Crypto)
