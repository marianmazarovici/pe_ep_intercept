cmake_minimum_required(VERSION 3.6)
project(pe_ep_intercept)

set(KEYSTONE_BUILD_STATIC_RUNTIME on)
include_directories(include include/keystone/include)
add_subdirectory(include/keystone)

set(Boost_USE_STATIC_LIBS        ON)
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME    OFF)
find_package(Boost 1.65.0 COMPONENTS serialization REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

add_subdirectory(src)