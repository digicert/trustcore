
cmake_minimum_required(VERSION 3.16)

project(SSHServer LANGUAGES C CXX)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(CRYPTO_LIB_ARCH_DIR "aarch64")
else()
    set(CRYPTO_LIB_ARCH_DIR "linux-x86_64")
endif()

set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
set(LIB_DIR       "${CMAKE_CURRENT_SOURCE_DIR}/../../lib")
set(CRYPTO_LIBS   "${CMAKE_CURRENT_SOURCE_DIR}/../../crypto_lib/${CRYPTO_LIB_ARCH_DIR}")
set(CMAKE_BUILD_RPATH "${LIB_DIR}")
set(SAMPLE_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../samples/bin")
set(SAMPLE_FILE_PATH "${SAMPLE_BIN_DIR}/ssh_server")

set(INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src"
    )
include_directories(${INCLUDE_DIR})

set(SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ssh_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ssh_example_async.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sftp_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sftp_example_filesys.c
    ${SRC_DIR}/initialize/digicert_example.c
)

add_executable(ssh_server ${SOURCE_FILES})


set(ASN1_LIB          "${LIB_DIR}/libasn1.so")
set(COMMON_LIB        "${LIB_DIR}/libcommon.so")
set(INITIALIZE_LIB    "${LIB_DIR}/libinitialize.so")
set(PLATFORM_LIB      "${LIB_DIR}/libplatform.so")
set(NANOSSHS_LIB      "${LIB_DIR}/libnanosshs.so")
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

target_link_libraries(ssh_server PRIVATE
    ${PLATFORM_LIB}
    ${ASN1_LIB}
    ${COMMON_LIB}
    ${INITIALIZE_LIB}
    ${NANOSSHS_LIB}
    nanocap
    nanocert
    nanocrypto
    cryptointerface
    )

add_custom_command(
  TARGET ssh_server
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ssh_server> ${SAMPLE_FILE_PATH}
)
