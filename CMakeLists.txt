cmake_minimum_required(VERSION 3.20.2)

# project variables
set(META_PROJECT_NAME        "xmss")
set(META_VERSION_MAJOR       "1")
set(META_VERSION_MINOR       "0")
set(META_VERSION_PATCH       "0")
set(META_VERSION             "${META_VERSION_MAJOR}.${META_VERSION_MINOR}.${META_VERSION_PATCH}")
set(META_NAME_VERSION        "${META_PROJECT_NAME} v${META_VERSION}")

set(PROTOCOLPP_VERSION ${META_VERSION})

message("=> Project : ${META_NAME_VERSION}")

# define project
project(${META_PROJECT_NAME}
        VERSION ${META_VERSION}
        LANGUAGES C)

# set CXX flags
if(CMAKE_BUILD_TYPE STREQUAL "debug32")
    set(CMAKE_CFLAGS "-std=c17 -m32 -D SHIFT=10 -D LEN=3 -g -O0 -Wextra -Wpedantic")
    message("C_FLAGS_DEBUG_32: ${CMAKE_CFLAGS}")
elseif(CMAKE_BUILD_TYPE STREQUAL "release32")
    set(CMAKE_CFLAGS "-std=c17 -m32 -D SHIFT=10 -D LEN=3 -g -O3 -Wextra -Wpedantic")
    message("C_FLAGS_RELEASE_32: ${CMAKE_CFLAGS}")
elseif(CMAKE_BUILD_TYPE STREQUAL "coverage32")
    set(CMAKE_CXX_FLAGS "-std=c17 -m32 -D SHIFT=10 -D LEN=3 -g -O0 -Wextra -Wpedantic -coverage")
    message("C_FLAGS_COVERAGE: ${CMAKE_CFLAGS}")
elseif(CMAKE_BUILD_TYPE STREQUAL "debug")
    set(CMAKE_CFLAGS "-std=c17 -D SHIFT=10 -D LEN=3 -g -O0 -Wextra -Wpedantic")
    message("C_FLAGS_DEBUG: ${CMAKE_CXX_FLAGS}")
elseif(CMAKE_BUILD_TYPE STREQUAL "coverage")
    set(CMAKE_CXX_FLAGS "-std=c17 -D SHIFT=10 -D LEN=3 -g -O0 -Wextra -Wpedantic -coverage")
    message("C_FLAGS_COVERAGE: ${CMAKE_CFLAGS}")
else()
    set(CMAKE_CFLAGS "-std=c17 -D SHIFT=10 -D LEN=3 -O3")
    message("C_FLAGS_RELEASE: ${CMAKE_CFLAGS}")
endif()

# list the source files
set(SOURCE_FILES
    ./params.c
    ./randombytes.c
    ./xmss_core_fast.c
    ./hash.c
    ./hash_address.c
    ./wots.c
    ./utils.c
    ./xmss_commons.c
    ./fips202.c
    ./xmss.c
    ./sha2.c)

set(INCLUDE_DIRS
    .)

message("BUILD: ${CMAKE_BUILD_TYPE}")

# add include directories
include_directories(${INCLUDE_DIRS})

ADD_LIBRARY(xmss STATIC ${SOURCE_FILES})

# build test_xmss
add_executable(xmss_test
               ./xmss_tests.c)

TARGET_LINK_LIBRARIES(xmss_test xmss)

