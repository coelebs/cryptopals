cmake_minimum_required(VERSION 3.9)

project(crypotpals)

enable_testing()

add_compile_options(-g)

add_subdirectory(set2)
add_subdirectory(libs)
add_subdirectory(test)
