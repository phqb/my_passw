cmake_minimum_required(VERSION 3.10)

project(my_passw VERSION 0.1)

add_executable(my_passw main.c)

target_include_directories(my_passw PUBLIC
                          "${PROJECT_SOURCE_DIR}/include")

add_library(libcrypto STATIC IMPORTED)
set_property(TARGET libcrypto 
             PROPERTY IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/lib/libcrypto.a")

target_link_libraries(my_passw PUBLIC libcrypto)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(my_passw PRIVATE Threads::Threads)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic")