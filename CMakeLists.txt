cmake_minimum_required(VERSION 3.20)

project(PKCertChain LANGUAGES C CXX)

# -------------------------------------------------
# Header-only library (NO compilation)
# -------------------------------------------------
add_library(PKCertChain INTERFACE)

# -------------------------------------------------
# Include directories
# -------------------------------------------------
target_include_directories(PKCertChain INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# -------------------------------------------------
# Dependency: shared (crypto + core utilities)
# -------------------------------------------------
target_link_libraries(PKCertChain INTERFACE shared)

# -------------------------------------------------
# Language standard
# -------------------------------------------------
target_compile_features(PKCertChain INTERFACE cxx_std_23)