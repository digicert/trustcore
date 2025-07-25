
cmake_minimum_required(VERSION 3.16)

project(SSHClient LANGUAGES C CXX)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(CRYPTO_LIB_ARCH_DIR "aarch64")
else()
    set(CRYPTO_LIB_ARCH_DIR "linux-x86_64")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

if (DEFINED SECURE_PATH)
  message("\nSECURE_PATH = ${SECURE_PATH}")
  add_definitions("-D__ENABLE_DIGICERT_SECURE_PATH__")
  add_definitions("-D__ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__")
  add_definitions("-DMANDATORY_BASE_PATH=\"${SECURE_PATH}\"")
endif()

set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
set(LIB_DIR       "${CMAKE_CURRENT_SOURCE_DIR}/../../lib")
set(CRYPTO_LIBS   "${CMAKE_CURRENT_SOURCE_DIR}/../../crypto_lib/${CRYPTO_LIB_ARCH_DIR}")
set(CMAKE_BUILD_RPATH "${LIB_DIR}")
set(SAMPLE_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../samples/bin")
set(SAMPLE_FILE_PATH "${SAMPLE_BIN_DIR}/ssh_client")

set(INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src"
    )
include_directories(${INCLUDE_DIR})

set(SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sshc_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sshc_shell_example.c
    ${SRC_DIR}/initialize/digicert_example.c
)

add_executable(ssh_client ${SOURCE_FILES})

set(ASN1_LIB          "${LIB_DIR}/libasn1.so")
set(COMMON_LIB        "${LIB_DIR}/libcommon.so")
set(INITIALIZE_LIB    "${LIB_DIR}/libinitialize.so")
set(PLATFORM_LIB      "${LIB_DIR}/libplatform.so")
set(NANOSSHC_LIB      "${LIB_DIR}/libnanosshc.so")

add_library(nanocap SHARED IMPORTED)
  set_target_properties(nanocap PROPERTIES
  IMPORTED_LOCATION "${CRYPTO_LIBS}/libnanocap.so")

add_library(nanocert SHARED IMPORTED)
  set_target_properties(nanocert PROPERTIES
  IMPORTED_LOCATION "${CRYPTO_LIBS}/libnanocert.so")

add_library(nanocrypto SHARED IMPORTED)
  set_target_properties(nanocrypto PROPERTIES
  IMPORTED_LOCATION "${CRYPTO_LIBS}/libnanocrypto.so")

add_library(cryptointerface SHARED IMPORTED)
  set_target_properties(cryptointerface PROPERTIES
  IMPORTED_LOCATION "${CRYPTO_LIBS}/libcryptointerface.so")

target_link_libraries(ssh_client PRIVATE
    ${PLATFORM_LIB}
    ${ASN1_LIB}
    ${COMMON_LIB}
    ${INITIALIZE_LIB}
    ${NANOSSHC_LIB}
    nanocap
    nanocert
    nanocrypto
    cryptointerface
    )

add_custom_command(
  TARGET ssh_client
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ssh_client> ${SAMPLE_FILE_PATH}
)
