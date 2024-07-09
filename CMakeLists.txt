cmake_minimum_required(VERSION 3.27)
project(sri)

# CPP 17
set(CMAKE_CXX_STANDARD 17)

# My code to build
add_executable(
        sri main.cpp
        SRI.cpp
        lib/htmlcxx-0.86/html/ParserDom.cc
        lib/htmlcxx-0.86/html/Node.cc
        lib/htmlcxx-0.86/html/ParserSax.cc
        HTMLFile.h
        HTMLFile.cpp
)

# Link the static version of the Crypto++ library
# set(CMAKE_EXE_LINKER_FLAGS "-static")

# Dependency with Cryptopp 8 installed with
# sudo apt-get install libcrypto++8 libcrypto++-dev
target_link_libraries(sri cryptopp)

# Find the CURL library
find_package(CURL REQUIRED)
# Link the CURL library
target_link_libraries(${PROJECT_NAME} CURL::libcurl)