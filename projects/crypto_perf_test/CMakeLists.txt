## Compile performance test executable for 'src/crypto'
##

cmake_minimum_required(VERSION 3.5)

## ON/OFF Options
option(CM_ENABLE_AES_NI           "Enable AES NI."                   OFF)
option(CMAKE_BUILD_OPENSSL        "Enable openssl comparison."       OFF)
option(CMAKE_BUILD_MBEDTLS        "Enable mbedtls comparison."       OFF)
option(CMAKE_BUILD_32BIT          "Enable 32-bit build."             OFF)
option(CM_ENABLE_OQS              "Enable OQS tests."                OFF)
option(CM_ENABLE_WOLF             "Enable WolfSSL perf tests."       OFF)
option(CM_ENABLE_LIBOQS           "Enable direct libOQS perf tests." OFF)
option(CM_ENABLE_CI               "Enable Crypto Interface tests."   OFF)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/../shared_cmake")
set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

## Include cross-compile options/flags (must be before project is defined)
include(MocPlatform)
include(locate_lib)

project(crypto_perf_test)

## The library name of the tested code
set(MSS_LIB_NAME crypto)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../../lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../../bin")
set(MSS_UNITTEST_DIR "${CMAKE_SOURCE_DIR}/../../unit_tests")
set(MSS_SRC_DIR "${CMAKE_SOURCE_DIR}/../../src")
set(MSS_LIB_DIR "${MSS_SRC_DIR}/${MSS_LIB_NAME}")
set(MSS_TEST_DIR "${MSS_SRC_DIR}/${MSS_LIB_NAME}/perf_test")
set(FLAGS_FILE "${CMAKE_SOURCE_DIR}/flags.txt")
set(MSS_LIBRARY_TYPE STATIC)

## Find tool
find_package(Ruby)

## Include general definitions
include(${DEFS_FILE})

## Add flags from 'defs.txt'
add_definitions("${EXTRA_DEFINITIONS}")

if(CMAKE_BUILD_32BIT)
add_definitions(" -O1")
endif()

if (CM_ENABLE_WOLF AND CM_ENABLE_LIBOQS)
    ## We could change this but it's simpler for now.
    message(FATAL_ERROR "You cannot build wolfssl tests and direct liboqs tests at the same time.")
endif()

## Read all test source file names
if(CM_ENABLE_WOLF)
    set(SOURCES_FILE "${CMAKE_CURRENT_SOURCE_DIR}/wolf_test_sources.txt")
    set(WOLF_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/")
    set(WOLF_LIBS "${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/src/.libs/libwolfssl.a")

    set(WOLF_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/wolf_flags.txt")

    # Read and set crypto interface flags
    file(STRINGS ${WOLF_FLAGS_FILE} wolf_flags)
    foreach(flag ${wolf_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
elseif(CM_ENABLE_LIBOQS)
    set(SOURCES_FILE "${CMAKE_CURRENT_SOURCE_DIR}/liboqs_test_sources.txt")
    set(LIBOQS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/liboqs/build/include")
    set(LIBOQS_LIBS "${CMAKE_CURRENT_SOURCE_DIR}/liboqs/build/lib/liboqs.a")

    set(LIBOQS_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/liboqs_flags.txt")

    # Read and set crypto interface flags
    file(STRINGS ${LIBOQS_FLAGS_FILE} liboqs_flags)
    foreach(flag ${liboqs_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
else()
    set(SOURCES_FILE "${CMAKE_CURRENT_SOURCE_DIR}/test_sources.txt")
endif()

file(STRINGS ${SOURCES_FILE} MSS_TEST_SOURCES)
string(REGEX REPLACE "MSS_TEST_DIR/" "${MSS_TEST_DIR}/" MSS_TEST_SOURCES "${MSS_TEST_SOURCES}")

## How to make 'main.c'
if(EXISTS ${RUBY_EXECUTABLE})
add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    COMMAND ${RUBY_EXECUTABLE} ${MSS_UNITTEST_DIR}/unittest.rb . localhost "" ${SOURCES_FILE} | tee ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    WORKING_DIRECTORY ${MSS_TEST_DIR}
    DEPENDS ${MSS_TEST_SOURCES}
    VERBATIM)
endif()

## Read and set flags
file(STRINGS ${FLAGS_FILE} project_flags)
foreach(flag ${project_flags})
  string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

if(CM_ENABLE_CI)
  set(CI_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ci_flags.txt")

  # Sanity check to make sure this file exists
  if(NOT EXISTS ${CI_FLAGS_FILE})
    message("ci_flags.txt not found\n")
  endif()

  # Read and set crypto interface flags
  file(STRINGS ${CI_FLAGS_FILE} ci_flags)
  foreach(flag ${ci_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
  endforeach()
endif()

if(CM_ENABLE_OQS)
  set(OQS_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/oqs_flags.txt")

  # Sanity check to make sure this file exists
  if(NOT EXISTS ${OQS_FLAGS_FILE})
    message("oqs_flags.txt not found\n")
  endif()

  message("\nMOCANA_OQS_FLAGS_FILE = ${OQS_FLAGS_FILE}")

  # Read and set oqs flags
  file(STRINGS ${OQS_FLAGS_FILE} project_flags)
  foreach(flag ${project_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
  endforeach()
endif()

if(CM_ENABLE_AES_NI)
  string(STRIP "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_AES_NI__" MOCANA_FLAGS)
endif()

message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

if(NOT WIN32)
  add_definitions("${MOCANA_FLAGS} -D__ENABLE_DIGICERT_DEV_URANDOM__")
else()
  add_definitions("${MOCANA_FLAGS}")
endif()

## Process oqs command line args
if(CM_ENABLE_OQS)
  if("${CM_OQS_PATH}" STREQUAL "")
    message(FATAL_ERROR "oqs option is enabled but no path has been provided")
  endif()

  # If this is a relative path, convert it to an absolute
  if(NOT IS_ABSOLUTE ${CM_OQS_PATH})
    get_filename_component(CM_OQS_PATH "${CM_OQS_PATH}" ABSOLUTE)
  endif()

  # Find out of the path provided ended with a '/', and remove it if so
  if("${CM_OQS_PATH}" MATCHES "/$")
    string(REGEX REPLACE "/$" "" CM_OQS_PATH "${CM_OQS_PATH}")
  endif()

  set(OQS_LIB_PATH ${CM_OQS_PATH}/build/lib/liboqs.a)
  set(OQS_ALL_LIBS ${OQS_LIB_PATH})
  set(OQS_INCLUDE_PATH ${CM_OQS_PATH}/build/include)
else()
  set(OQS_ALL_LIBS "")
  set(OQS_INCLUDE_PATH "")
endif()

if(CM_ENABLE_AES_NI)
  set(AES_NI_INCLUDE_PATH ${MSS_SRC_DIR}/crypto/intel_aes_ni/include)
else()
  set(AES_NI_INCLUDE_PATH "")
endif()

## Add include
include_directories("." ${MSS_SRC_DIR}
${MSS_LIB_DIR}
${MSS_TEST_DIR}
${OQS_INCLUDE_PATH}
${WOLF_INCLUDE_DIR}
${LIBOQS_INCLUDE_DIR}
${AES_NI_INCLUDE_PATH})

## Define test program
add_executable(${MSS_LIB_NAME}_perf_test main.c ${MSS_TEST_SOURCES})

## Define supporting libs
file(GLOB ASN1_SRC ${MSS_SRC_DIR}/asn1/*.c)
file(GLOB PLATFORM_SRC ${MSS_SRC_DIR}/platform/*.c)
file(GLOB COMMON_SRC ${MSS_SRC_DIR}/common/*.c ${MSS_SRC_DIR}/common/vlong/*.c)
if(CM_ENABLE_OQS)
file(GLOB CRYPTO_SRC ${MSS_SRC_DIR}/crypto/*.c
 ${MSS_SRC_DIR}/crypto/pqc/*.c
 ${MSS_SRC_DIR}/crypto/mocasymkeys/mocsw/*.c
 ${MSS_SRC_DIR}/crypto/mocasymkeys/oqs/*.c
 ${MSS_SRC_DIR}/crypto/mocsymalgs/mocsw/*.c
 ${MSS_SRC_DIR}/crypto_interface/*.c)
else()
file(GLOB CRYPTO_SRC ${MSS_SRC_DIR}/crypto/*.c
 ${MSS_SRC_DIR}/crypto/pqc/*.c
 ${MSS_SRC_DIR}/crypto/mocasymkeys/mocsw/*.c
 ${MSS_SRC_DIR}/crypto/mocsymalgs/mocsw/*.c
 ${MSS_SRC_DIR}/crypto_interface/*.c)
endif()
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

if(CM_ENABLE_AES_NI)
  if(EXISTS "${MSS_SRC_DIR}/crypto/intel_aes_ni/intel_aes_ni.a")
    set(LIBAESNI_PATH "${MSS_SRC_DIR}/crypto/intel_aes_ni/intel_aes_ni.a")
  elseif(EXISTS "${MSS_BIN_DIR}/intel_aes_ni.a")
    set(LIBAESNI_PATH "${MSS_BIN_DIR}/intel_aes_ni.a")
  else()
    message(FATAL_ERROR "intel_aes_ni.a not found in either ${MSS_BIN_DIR}/ "
            "or ${MSS_SRC_DIR}/crypto/intel_aes_ni/")
  endif()

  add_library(AESNI_LIB STATIC IMPORTED)
  set_property(TARGET AESNI_LIB PROPERTY IMPORTED_LOCATION ${LIBAESNI_PATH})

  message("\nLinking to intel_aes_ni.a")
  set(AES_NI_LIBS AESNI_LIB)
else()
  set(AES_NI_LIBS "")
endif()

if(CMAKE_BUILD_OPENSSL)
  find_library(crypto crypto)
  set(OSSL_LIBS crypto)
  add_definitions(" -D__ENABLE_PERF_TEST_OPENSSL__ -DOPENSSL_ENGINE")
else()
  set(OSSL_LIBS "")
endif()

if(CMAKE_BUILD_MBEDTLS)
  find_library(mbedcrypto mbedcrypto)
  set(MBED_LIBS mbedcrypto)
  add_definitions(" -D__ENABLE_PERF_TEST_MBEDTLS__")
else()
  set(MBED_LIBS "")
endif()

## Optimization flags
if("${CM_TOOLCHAIN}" STREQUAL "")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
endif()

## What to link

target_link_libraries(${MSS_LIB_NAME}_perf_test
common_${MSS_LIB_NAME}
crypto_${MSS_LIB_NAME}
certops_${MSS_LIB_NAME}
crypto_${MSS_LIB_NAME}
cap_${MSS_LIB_NAME}
crypto_${MSS_LIB_NAME}
asn1_${MSS_LIB_NAME}
common_${MSS_LIB_NAME}
cap_${MSS_LIB_NAME}
platform_${MSS_LIB_NAME}
unittest_${MSS_LIB_NAME}
${AES_NI_LIBS}
${OSSL_LIBS}
${MBED_LIBS}
${EXTRA_LIBS}
${WOLF_LIBS}
${LIBOQS_LIBS}
${OQS_ALL_LIBS})

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
 COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${MSS_LIB_NAME}_test ${CT_TEST_CASES}
)
