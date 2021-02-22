cmake_minimum_required(VERSION 3.15)
project(mqueue_server C)

set(CMAKE_C_STANDARD 99)

add_executable(mqueue_server main.c)
target_link_libraries(mqueue_server rt)