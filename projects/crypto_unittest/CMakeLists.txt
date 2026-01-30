## Compile unit test executable for 'src/crypto'
##

cmake_minimum_required(VERSION 3.5)

## ON/OFF Options
option(CT_65_TEST_ONLY   "Only run v6.5.x API tests." OFF)
option(CT_CAP_TEST_ONLY  "Only run v7.x CAP API tests." OFF)

project(crypto_unittest)

## The library name of the tested code
set(MSS_LIB_NAME crypto)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../../lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../../bin")
set(MSS_UNITTEST_DIR "${CMAKE_SOURCE_DIR}/../../unit_tests")
set(MSS_SRC_DIR "${CMAKE_SOURCE_DIR}/../../src")
set(MSS_LIB_DIR "${MSS_SRC_DIR}/${MSS_LIB_NAME}")
set(MSS_TEST_DIR "${MSS_SRC_DIR}/${MSS_LIB_NAME}/test")
set(DEFS_FILE "${CMAKE_SOURCE_DIR}/defs.txt")
set(FLAGS_FILE "${CMAKE_SOURCE_DIR}/flags.txt")
set(SOURCES_FILE "${CMAKE_SOURCE_DIR}/test_sources.txt")
set(MSS_LIBRARY_TYPE STATIC)

## Find tool
find_package(Ruby)

## Include general definitions
include(${DEFS_FILE})

## Add flags from 'defs.txt'
add_definitions("${EXTRA_DEFINITIONS}")

## Read all test source file names
file(STRINGS ${SOURCES_FILE} MSS_TEST_SOURCES)
string(REGEX REPLACE "MSS_TEST_DIR/" "${MSS_TEST_DIR}/" MSS_TEST_SOURCES "${MSS_TEST_SOURCES}")

## How to make 'main.c'
if(EXISTS ${RUBY_EXECUTABLE})
  if(CT_65_TEST_ONLY)
    add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/main.c
      COMMAND ${RUBY_EXECUTABLE} ${MSS_UNITTEST_DIR}/unittest.rb
      . localhost "" ${CMAKE_CURRENT_SOURCE_DIR}/sub_set_65.txt | tee ${CMAKE_CURRENT_SOURCE_DIR}/main.c
      WORKING_DIRECTORY ${MSS_TEST_DIR}
      DEPENDS ${MSS_TEST_SOURCES}
      VERBATIM)
  elseif(CT_CAP_TEST_ONLY)
  add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    COMMAND ${RUBY_EXECUTABLE} ${MSS_UNITTEST_DIR}/unittest.rb
    . localhost "" ${CMAKE_CURRENT_SOURCE_DIR}/sub_set_cap.txt | tee ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    WORKING_DIRECTORY ${MSS_TEST_DIR}
    DEPENDS ${MSS_TEST_SOURCES}
    VERBATIM)
  else()
    add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/main.c
      COMMAND ${RUBY_EXECUTABLE} ${MSS_UNITTEST_DIR}/unittest.rb
      . localhost "" ${CMAKE_CURRENT_SOURCE_DIR}/test_sources.txt | tee ${CMAKE_CURRENT_SOURCE_DIR}/main.c
      WORKING_DIRECTORY ${MSS_TEST_DIR}
      DEPENDS ${MSS_TEST_SOURCES}
      VERBATIM)
  endif()
endif()

## Read and set flags
file(STRINGS ${FLAGS_FILE} project_flags)
foreach(flag ${project_flags})
  string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

if(NOT WIN32)
  add_definitions("${MOCANA_FLAGS} -D__ENABLE_DIGICERT_DEV_URANDOM__")
else()
  add_definitions("${MOCANA_FLAGS}")
endif()

# To enable code coverage set CM_ENV_CODE_COVERAGE=1 in the build environment
if ("$ENV{CM_ENV_CODE_COVERAGE}" STREQUAL "1")
    add_compile_options(-fprofile-arcs -ftest-coverage)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lgcov")
endif()

## Add include
include_directories("." ${MSS_SRC_DIR}
${MSS_LIB_DIR}
${MSS_TEST_DIR})

## Define test program
add_executable(${MSS_LIB_NAME}_test main.c ${MSS_TEST_SOURCES})

## Define supporting libs
file(GLOB ASN1_SRC ${MSS_SRC_DIR}/asn1/*.c)
file(GLOB PLATFORM_SRC ${MSS_SRC_DIR}/platform/*.c)
file(GLOB COMMON_SRC ${MSS_SRC_DIR}/common/*.c ${MSS_SRC_DIR}/common/vlong/*.c)
file(GLOB CRYPTO_SRC ${MSS_SRC_DIR}/crypto/*.c
 ${MSS_SRC_DIR}/crypto/pqc/*.c
 ${MSS_SRC_DIR}/crypto/mocasymkeys/mocsw/*.c
 ${MSS_SRC_DIR}/crypto/mocsymalgs/mocsw/*.c
 ${MSS_SRC_DIR}/crypto_interface/*.c)
file(GLOB CAP_SRC ${MSS_SRC_DIR}/cap/*.c)

file(GLOB CERTOPS_SRC ${MSS_SRC_DIR}/crypto/certops/*.c)
file(GLOB UNITTEST_SRC ${MSS_UNITTEST_DIR}/*.c)

add_library(asn1_${MSS_LIB_NAME} STATIC ${ASN1_SRC})
add_library(platform_${MSS_LIB_NAME} STATIC ${PLATFORM_SRC})
add_library(common_${MSS_LIB_NAME} STATIC ${COMMON_SRC})
add_library(crypto_${MSS_LIB_NAME} STATIC ${CRYPTO_SRC})
add_library(cap_${MSS_LIB_NAME} STATIC ${CAP_SRC})
add_library(certops_${MSS_LIB_NAME} STATIC ${CERTOPS_SRC})
add_library(unittest_${MSS_LIB_NAME} STATIC ${UNITTEST_SRC})

# Add 'pthread' lib when on Linux
if(UNIX)
set(EXTRA_LIBS
 pthread
)
else()
set(EXTRA_LIBS "")
endif()

## What to link
target_link_libraries(${MSS_LIB_NAME}_test
crypto_${MSS_LIB_NAME}
certops_${MSS_LIB_NAME}
crypto_${MSS_LIB_NAME}
cap_${MSS_LIB_NAME}
crypto_${MSS_LIB_NAME}
asn1_${MSS_LIB_NAME}
common_${MSS_LIB_NAME}
crypto_${MSS_LIB_NAME}
cap_${MSS_LIB_NAME}
platform_${MSS_LIB_NAME}
unittest_${MSS_LIB_NAME}
${EXTRA_LIBS})

## Use CTest
set(CT_VALGRIND_XML_OPTIONS "--xml=yes --xml-file=${CMAKE_SOURCE_DIR}/memcheck.xml")
set(CT_VALGRIND_MEMCHECK_OPTIONS "--tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=50")

## Set DART variableas
set(VALGRIND_COMMAND_OPTIONS "${CT_VALGRIND_XML_OPTIONS} ${CT_VALGRIND_MEMCHECK_OPTIONS}")

include(CTest)

## Set test cases
set(CT_TEST_CASES "")

if(CT_65_TEST_ONLY)
  message(STATUS "Restricting tests to V6.5 API")
  file(STRINGS "sub_set_65.txt" CT_TEST_CASES)
endif()
if(CT_CAP_TEST_ONLY)
  message(STATUS "Restricting tests to V7.0 CAP API")
  file(STRINGS "sub_set_cap.txt" CT_TEST_CASES)
endif()

enable_testing()
add_test(NAME ${MSS_LIB_NAME} WORKING_DIRECTORY ${MSS_TEST_DIR}
 COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${MSS_LIB_NAME}_test ${CT_TEST_CASES}
)
