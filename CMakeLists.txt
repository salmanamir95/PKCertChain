cmake_minimum_required(VERSION 3.10)
project(pkcertchain C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native -Wall -Wextra")
add_compile_definitions(_DEFAULT_SOURCE)

find_package(OpenSSL REQUIRED)

# Recursive but only project folders
file(GLOB_RECURSE SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/**/*.c"
)

# Exclude anything in build/ or hidden directories
list(FILTER SOURCES EXCLUDE REGEX ".*/build/.*")
list(FILTER SOURCES EXCLUDE REGEX ".*/\\.git/.*")

file(GLOB_RECURSE HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/**/*.h"
)

add_executable(pkcertchain
    ${SOURCES}
    ${HEADERS}   # optional for IDE
)

target_include_directories(pkcertchain
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(pkcertchain
    PRIVATE
    OpenSSL::Crypto
)
