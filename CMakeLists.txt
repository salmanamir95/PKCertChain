cmake_minimum_required(VERSION 3.20)

project(PKCertChain LANGUAGES C CXX)

# -------------------------------------------------
# Create library (STATIC so you can extend later)
# -------------------------------------------------
add_library(PKCertChain STATIC)

# -------------------------------------------------
# Sources (ignore tests explicitly)
# -------------------------------------------------
file(GLOB_RECURSE PKC_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c
)

target_sources(PKCertChain PRIVATE ${PKC_SOURCES})

# -------------------------------------------------
# Include directories
# -------------------------------------------------
target_include_directories(PKCertChain PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# -------------------------------------------------
# Dependency: shared (crypto + core utilities)
# -------------------------------------------------
target_link_libraries(PKCertChain PUBLIC shared)

# -------------------------------------------------
# Language standard
# -------------------------------------------------
target_compile_features(PKCertChain PUBLIC cxx_std_23)

# -------------------------------------------------
# Compiler warnings (safe defaults)
# -------------------------------------------------
target_compile_options(PKCertChain PRIVATE
    -Wall
    -Wextra
    -Wshadow
    -Wconversion
)

# -------------------------------------------------
# Output directory
# peer/build/backend/PKCertChain
# -------------------------------------------------
set_target_properties(PKCertChain PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/backend/PKCertChain
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/backend/PKCertChain
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/backend/PKCertChain
)