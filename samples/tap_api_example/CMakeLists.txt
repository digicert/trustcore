########################################################################
# CMake build script for DigiCert tap api example
#

cmake_minimum_required(VERSION 3.16)

option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../projects/shared_cmake)

if(CM_ENABLE_DEBUG)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
endif()

project (tap_api_example C)

include(MocPlatform)
include(locate_lib)

#set(CMAKE_VERBOSE_MAKEFILE "ON")

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
set(LIB_DIR  "${MSS_DIR}/lib")

link_directories(${LIB_DIR})
set(MSS_BIN_DIR "${LIB_DIR}")
set(CMAKE_INSTALL_RPATH "${MSS_BIN_DIR}")

set(LIB_TYPE "SHARED" CACHE STRING "Which lib type to build: SHARED (default) or STATIC")
message("LIB_TYPE           = ${LIB_TYPE}")
message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")

set(TAP_API_EXAMPLE_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${TAP_API_EXAMPLE_BUILD_DIR}/libs")
set(CMAKE_BINARY_DIR "${TAP_API_EXAMPLE_BUILD_DIR}")
set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

message("TAP_API_EXAMPLE_BUILD_DIR = ${TAP_API_EXAMPLE_BUILD_DIR}")

if(NOT EXISTS ${DEFS_FILE})
    message(FATAL_ERROR "\nDEFS_FILE = ${DEFS_FILE} does not exist")
endif()

message("\nDEFS_FILE = ${DEFS_FILE}")
include(${DEFS_FILE})

set(INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/common"
    )
include_directories(${INCLUDE_DIR})

set(SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/nanotap_api_example.c
)

add_definitions("-D__ENABLE_DIGICERT_TAP__")
add_definitions("-D__ENABLE_DIGICERT_SMP__")
add_definitions("-D__ENABLE_LOOKUP_TABLE__")
add_definitions("-D__ENABLE_DIGICERT_EXAMPLES__")
add_definitions("-D__ENABLE_DIGICERT_PKCS8__")
add_definitions("-D__ENABLE_DIGICERT_CRYPTO_INTERFACE__")
add_definitions("-D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA224_MAPPING__")
add_definitions("-D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA256_MAPPING__")
add_definitions("-D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA384_MAPPING__")
add_definitions("-D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA512_MAPPING__")
add_definitions("-D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA1_MAPPING__")
add_definitions("-D__ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC_MAPPING__")
add_definitions("-D__ENABLE_DIGICERT_TPM2__")

# adding extra definitions
message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")
add_definitions("${EXTRA_DEFINITIONS}")

set(ASN1_LIB            "${LIB_DIR}/libasn1.so")
set(COMMON_LIB          "${LIB_DIR}/libcommon.so")
set(INITIALIZE_LIB      "${LIB_DIR}/libinitialize.so")
set(PLATFORM_LIB        "${LIB_DIR}/libplatform.so")
set(NANOCAP_LIB         "${LIB_DIR}/libnanocap.so")
set(NANOCERT_LIB        "${LIB_DIR}/libnanocert.so")
set(CERT_ENROLL_LIB     "${LIB_DIR}/libcert_enroll.so")
set(NANOSSL_LIB         "${LIB_DIR}/libnanossl.so")
set(NANOCRYPTO_LIB      "${LIB_DIR}/libnanocrypto.so")
set(CRYPTOINTERFACE_LIB "${LIB_DIR}/libcryptointerface.so")
if(ENABLE_PKCS11_SOFTHSM OR ENABLE_PKCS11_TEE)
    set(SMP_LIB "${LIB_DIR}/libsmppkcs11.so")
    set(TPM2_LIB            "${LIB_DIR}/libtpm2.so")
elseif(ENABLE_TPM2)
    set(SMP_LIB "${LIB_DIR}/libsmptpm2.so")
    set(TPM2_LIB            "${LIB_DIR}/libtpm2.so")
endif()
set(NANOTAP2_COMMON_LIB "${LIB_DIR}/libnanotap2_common.so")
set(NANOTAP2_CONFIGPARSER_LIB "${LIB_DIR}/libnanotap2_configparser.so")
set(NANOTAP2_LIB        "${LIB_DIR}/libnanotap2.so")

set(libraryLists ${COMMON_LIB} ${PLATFORM_LIB} ${ASN1_LIB} ${INITIALIZE_LIB} ${TPM2_LIB} ${SMP_LIB}
                  ${NANOTAP2_COMMON_LIB} ${NANOTAP2_CONFIGPARSER_LIB} ${NANOTAP2_LIB} ${CRYPTOINTERFACE_LIB}
                  ${NANOCAP_LIB} ${NANOCERT_LIB} ${NANOCRYPTO_LIB} ${CERT_ENROLL_LIB} ${NANOSSL_LIB} )

if(UNIX AND NOT ANDROID)
    set(libraryLists ${libraryLists} pthread)
endif()

add_executable(tap_api_example ${SOURCE_FILES})
target_link_libraries(tap_api_example ${libraryLists})

set(SAMPLE_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../samples/bin")
set(SAMPLE_FILE_PATH "${SAMPLE_BIN_DIR}/tap_api_example")

file(MAKE_DIRECTORY ${SAMPLE_BIN_DIR})

add_custom_command(TARGET tap_api_example POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:tap_api_example> ${SAMPLE_FILE_PATH}
            COMMAND echo "Copied tap_api_example to ${SAMPLE_FILE_PATH}")
