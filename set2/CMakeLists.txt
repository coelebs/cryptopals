cmake_minimum_required(VERSION 3.9)
project(cryptopals1.2)

INCLUDE_DIRECTORIES(../libs/docopt.cpp)
LINK_DIRECTORIES(../libs/docopt.cpp)

add_definitions(-Wall)
add_executable(cryptopals main.cpp base64.cpp)
TARGET_LINK_LIBRARIES(cryptopals docopt crypto)
