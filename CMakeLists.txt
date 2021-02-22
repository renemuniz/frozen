cmake_minimum_required(VERSION 3.15)
project(poc_client C)

set(CMAKE_C_STANDARD 11)

include_directories(monitor/include)
include_directories(agent/include)
include_directories(ecs/include)
include_directories(lib/wget2-1.99.2/include/wget)
include_directories(lib/mbed-tls/include)

link_directories(lib/wget2-1.99.2/libwget/.libs)

set(GCC_COVERAGE_COMPILE_FLAGS "-pthread")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")

set(GCC_COVERAGE_LINK_FLAGS "-lwget")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

file(GLOB SOURCES "monitor/*.c")
file(GLOB SOURCES "agent/*.c")
file(GLOB SOURCES "ecs/*.c")
file(GLOB SOURCES "lib/mbed-tls/*.c")

add_executable(launcher
        monitor/monitor.c)
add_executable(dca
        agent/dca.c)
add_executable(ecs
        ecs/ecs.c
        lib/mbed-tls/aes.c
        lib/mbed-tls/aesni.c)

target_link_libraries(dca rt wget)
target_link_libraries(ecs rt wget)