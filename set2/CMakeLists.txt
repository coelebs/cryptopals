INCLUDE_DIRECTORIES(../libs/docopt.cpp ../libs/base64)
LINK_DIRECTORIES(../libs/docopt.cpp ../libs/base64)

add_executable(cryptopals main.cpp)
add_library(set2 set2.cpp encryption_box.cpp)

TARGET_LINK_LIBRARIES(cryptopals docopt crypto base64 set2)
TARGET_LINK_LIBRARIES(set2 crypto base64)

target_include_directories(set2 PUBLIC $(CMAKE_CURRENT_SOURCE_DIR))
