## Compile interopabiity test executable for 'src/crypto'
##

cmake_minimum_required(VERSION 3.5)

## ON/OFF Options
option(CMAKE_BUILD_32BIT          "Enable 32-bit build."          OFF)

project(crypto_interop_test)

## The library name of the tested code
set(MSS_LIB_NAME crypto)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../../lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../../bin")
set(MSS_UNITTEST_DIR "${CMAKE_SOURCE_DIR}/../../unit_tests")
set(MSS_SRC_DIR "${CMAKE_SOURCE_DIR}/../../src")
set(MSS_LIB_DIR "${MSS_SRC_DIR}/${MSS_LIB_NAME}")
set(MSS_TEST_DIR "${MSS_SRC_DIR}/${MSS_LIB_NAME}/interop_test")
set(DEFS_FILE "${CMAKE_SOURCE_DIR}/defs.txt")
set(FLAGS_FILE "${CMAKE_SOURCE_DIR}/flags.txt")
set(SOURCES_FILE "${CMAKE_SOURCE_DIR}/test_sources.txt")
set(CRYPTO_SRC_FILE "${CMAKE_SOURCE_DIR}/crypto_sources.txt")
set(BSSL_PATH "${CMAKE_SOURCE_DIR}/boringssl")
set(WOLFSSL_PATH "${CMAKE_SOURCE_DIR}/wolfssl")

## Find tool
find_package(Ruby)

## Include general definitions
include(${DEFS_FILE})

## Add flags from 'defs.txt'
add_definitions("${EXTRA_DEFINITIONS}")

if(CMAKE_BUILD_32BIT)
add_definitions(" -O1")
endif()

## Read all the crypto source file names
file(STRINGS ${CRYPTO_SRC_FILE} MSS_CRYPTO_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_CRYPTO_SOURCES "${MSS_CRYPTO_SOURCES}")

## Read all test source file names
file(STRINGS ${SOURCES_FILE} MSS_TEST_SOURCES)
string(REGEX REPLACE "MSS_TEST_DIR/" "${MSS_TEST_DIR}/" MSS_TEST_SOURCES "${MSS_TEST_SOURCES}")

## Read and set flags
file(STRINGS ${FLAGS_FILE} project_flags)
foreach(flag ${project_flags})
  string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

if(NOT WIN32)
  add_definitions("${MOCANA_FLAGS} -D__ENABLE_DIGICERT_DEV_URANDOM__")
else()
  add_definitions("${MOCANA_FLAGS}")
endif()

set(BSSL_LIB_PATH ${BSSL_PATH}/build/libcrypto.a)
set(BSSL_ALL_LIBS ${BSSL_LIB_PATH})
set(BSSL_INCLUDE_PATH ${BSSL_PATH}/include)

set(WOLFSSL_LIB_PATH ${WOLFSSL_PATH}/src/.libs/libwolfssl.a)
set(WOLFSSL_ALL_LIBS ${WOLFSSL_LIB_PATH})
set(WOLFSSL_INCLUDE_PATH ${WOLFSSL_PATH})

## Add include
include_directories("." ${MSS_SRC_DIR}
${MSS_LIB_DIR}
${MSS_TEST_DIR}
${BSSL_INCLUDE_PATH}
${WOLFSSL_INCLUDE_PATH})

## Define test program
add_executable(${MSS_LIB_NAME}_interop_test ${MSS_TEST_SOURCES})

## Define supporting libs
file(GLOB PLATFORM_SRC ${MSS_SRC_DIR}/platform/*.c)
file(GLOB COMMON_SRC ${MSS_SRC_DIR}/common/*.c ${MSS_SRC_DIR}/common/vlong/*.c)
file(GLOB UNITTEST_SRC ${MSS_UNITTEST_DIR}/*.c)

add_library(platform_${MSS_LIB_NAME} STATIC ${PLATFORM_SRC})
add_library(common_${MSS_LIB_NAME} STATIC ${COMMON_SRC})
add_library(crypto_${MSS_LIB_NAME} STATIC ${MSS_CRYPTO_SOURCES})
add_library(unittest_${MSS_LIB_NAME} STATIC ${UNITTEST_SRC})

# Add 'pthread' lib when on Linux
if(UNIX)
set(EXTRA_LIBS
 pthread
)
else()
set(EXTRA_LIBS "")
endif()

## Optimization flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native")

## What to link
target_link_libraries(${MSS_LIB_NAME}_interop_test
platform_${MSS_LIB_NAME}
common_${MSS_LIB_NAME}
crypto_${MSS_LIB_NAME}
common_${MSS_LIB_NAME}
platform_${MSS_LIB_NAME}
unittest_${MSS_LIB_NAME}
${BSSL_ALL_LIBS}
${WOLFSSL_ALL_LIBS}
${EXTRA_LIBS})

## Use CTest
set(CT_VALGRIND_XML_OPTIONS "--xml=yes --xml-file=${CMAKE_SOURCE_DIR}/memcheck.xml")
set(CT_VALGRIND_MEMCHECK_OPTIONS "--tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=50")

## Set DART variableas
set(VALGRIND_COMMAND_OPTIONS "${CT_VALGRIND_XML_OPTIONS} ${CT_VALGRIND_MEMCHECK_OPTIONS}")

include(CTest)

## Set test cases
set(CT_TEST_CASES "")

enable_testing()
add_test(NAME ${MSS_LIB_NAME} WORKING_DIRECTORY ${MSS_TEST_DIR}
 COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${MSS_LIB_NAME}_interop_test ${CT_TEST_CASES}
)
