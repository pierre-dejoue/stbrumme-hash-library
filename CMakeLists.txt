cmake_minimum_required(VERSION 3.28)

project(hash-library DESCRIPTION "Stephan Brumme's portable C++ hashing library")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

#
# Library
#
set(LIB_SOURCES
    ./crc32.cpp
    ./keccak.cpp
    ./md5.cpp
    ./sha1.cpp
    ./sha3.cpp
    ./sha256.cpp
)

set(LIB_HEADERS
    ./hash.h
    ./hmac.h
    ./crc32.h
    ./keccak.h
    ./md5.h
    ./sha1.h
    ./sha3.h
    ./sha256.h
)

add_library(hash-lib STATIC ${LIB_SOURCES} ${LIB_HEADERS})

target_include_directories(hash-lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

#
# Applications
#
add_executable(digest ./digest.cpp)
target_link_libraries(digest PRIVATE hash-lib)
add_executable(tests ./tests/tests.cpp)
target_link_libraries(tests PRIVATE hash-lib)
add_executable(github-issue2 ./tests/github-issue2.cpp)
target_link_libraries(github-issue2 PRIVATE hash-lib)
add_executable(github-issue6 ./tests/github-issue6.cpp)
target_link_libraries(github-issue6 PRIVATE hash-lib)
