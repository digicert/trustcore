
cmake_minimum_required(VERSION 3.16)

option(CM_ENABLE_TAP                                "Enable TAP"                          ON)

project(SSHServer LANGUAGES C CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

if (DEFINED SECURE_PATH)
  message("\nSECURE_PATH = ${SECURE_PATH}")
  add_definitions("-D__ENABLE_DIGICERT_SECURE_PATH__")
  add_definitions("-D__ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__")
  add_definitions("-DMANDATORY_BASE_PATH=\"${SECURE_PATH}\"")
endif()

set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
set(LIB_DIR       "${CMAKE_CURRENT_SOURCE_DIR}/../../lib")
set(CMAKE_BUILD_RPATH "${LIB_DIR}")
set(SAMPLE_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../samples/bin")
set(SAMPLE_FILE_PATH "${SAMPLE_BIN_DIR}/ssh_server")

set(INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/ssh"
    )
include_directories(${INCLUDE_DIR})

set(SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ssh_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ssh_example_async.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sftp_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sftp_example_filesys.c
    ${SRC_DIR}/../samples/common/digicert_example.c
)

add_executable(ssh_server ${SOURCE_FILES})

set(ASN1_LIB             "${LIB_DIR}/libasn1.so")
set(COMMON_LIB           "${LIB_DIR}/libcommon.so")
set(INITIALIZE_LIB       "${LIB_DIR}/libinitialize.so")
set(PLATFORM_LIB         "${LIB_DIR}/libplatform.so")
set(NANOSSHS_LIB         "${LIB_DIR}/libnanosshs.so")
set(PLATFORM_LIB         "${LIB_DIR}/libplatform.so")
set(NANOCRYPTO_LIB       "${LIB_DIR}/libnanocrypto.so")
set(NANOCAP_LIB          "${LIB_DIR}/libnanocap.so")
set(NANOCERT_LIB         "${LIB_DIR}/libnanocert.so")
set(CRYPTO_INTERFACE_LIB "${LIB_DIR}/libcryptointerface.so")
set(CERT_ENROLL_LIB      "${LIB_DIR}/libcert_enroll.so")

if(CM_ENABLE_SSL)
  set(NANOSSL_LIB          "${LIB_DIR}/libnanossl.so")
endif()

if(CM_ENABLE_TAP)
  set(NANOTAP2_COMMON_LIB "${LIB_DIR}/libnanotap2_common.so")
  set(NANOTAP2_CONFIGPARSER_LIB "${LIB_DIR}/libnanotap2_configparser.so")
  set(NANOTAP2_LIB "${LIB_DIR}/libnanotap2.so")
  if(ENABLE_PKCS11_SOFTHSM OR ENABLE_PKCS11_TEE)
    set(SMP_LIB "${LIB_DIR}/libsmppkcs11.so")
    set(TPM2_LIB "${LIB_DIR}/libtpm2.so")
  elseif(ENABLE_TPM2)
    set(SMP_LIB "${LIB_DIR}/libsmptpm2.so")
    set(TPM2_LIB "${LIB_DIR}/libtpm2.so")
  endif()

  target_link_libraries(ssh_server PRIVATE
      ${PLATFORM_LIB}
      ${ASN1_LIB}
      ${COMMON_LIB}
      ${INITIALIZE_LIB}
      ${NANOSSHS_LIB}
      ${NANOCRYPTO_LIB}
      ${NANOCAP_LIB}
      ${CRYPTO_INTERFACE_LIB}
      ${NANOCERT_LIB}
      $<$<BOOL:${CM_ENABLE_SSL}>:${NANOSSL_LIB}>
      ${CERT_ENROLL_LIB}
      ${NANOTAP2_COMMON_LIB}
      ${NANOTAP2_CONFIGPARSER_LIB}
      ${NANOTAP2_LIB}
      ${SMP_LIB}
      ${TPM2_LIB}
      )

else()

  target_link_libraries(ssh_server PRIVATE
      ${PLATFORM_LIB}
      ${ASN1_LIB}
      ${COMMON_LIB}
      ${INITIALIZE_LIB}
      ${NANOSSHS_LIB}
      ${NANOCRYPTO_LIB}
      ${NANOCAP_LIB}
      ${CRYPTO_INTERFACE_LIB}
      ${NANOCERT_LIB}
      $<$<BOOL:${CM_ENABLE_SSL}>:${NANOSSL_LIB}>
      ${CERT_ENROLL_LIB}
      )

endif()

add_custom_command(
  TARGET ssh_server
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ssh_server> ${SAMPLE_FILE_PATH}
)
