cmake_minimum_required(VERSION 3.10)
project(pkcertchain C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native -Wall -Wextra")

find_package(OpenSSL REQUIRED)

# Recursive but only project folders
file(GLOB_RECURSE SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/datatype/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/Proofs/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.c"
)

# Exclude anything in build/ or hidden directories
list(FILTER SOURCES EXCLUDE REGEX ".*/build/.*")
list(FILTER SOURCES EXCLUDE REGEX ".*/\\.git/.*")

file(GLOB_RECURSE HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/datatype/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/Proofs/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.h"
)

add_executable(pkcertchain
    ${SOURCES}
    ${HEADERS}   # optional for IDE
)

target_include_directories(pkcertchain
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(pkcertchain
    PRIVATE
    OpenSSL::Crypto
)
