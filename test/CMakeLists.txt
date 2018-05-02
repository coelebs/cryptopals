add_executable(test_set1 test_set1.cpp)
add_executable(test_set2 test_set2.cpp)

TARGET_LINK_LIBRARIES(test_set1 set2 gtest)
TARGET_LINK_LIBRARIES(test_set2 set2 gtest base64)

add_test(NAME set1 COMMAND test_set1)
add_test(NAME set2 COMMAND test_set2)
