
cmake_minimum_required(VERSION 3.16)

option(CM_ENABLE_TAP                                "Enable TAP"                          OFF)

project(CIExample LANGUAGES C CXX)

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
set(SAMPLE_FILE_PATH "${SAMPLE_BIN_DIR}/crypto_interface_example")

set(INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/crypto_interface/example"
    )
include_directories(${INCLUDE_DIR})

set(SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_aes_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_rsa_pss_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_sha2_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_aes_gcm_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_sha3_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_cms_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_tap_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_dh_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_ecc_eg_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_tdes_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_ecc_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_ecdh_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_hmac_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_hybrid_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_keygen_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_moccms_streaming_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_random_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_interface_rsa_example.c
)

add_executable(crypto_interface_example ${SOURCE_FILES})

set(ASN1_LIB             "${LIB_DIR}/libasn1.so")
set(COMMON_LIB           "${LIB_DIR}/libcommon.so")
set(INITIALIZE_LIB       "${LIB_DIR}/libinitialize.so")
set(PLATFORM_LIB         "${LIB_DIR}/libplatform.so")
set(NANOCRYPTO_LIB       "${LIB_DIR}/libnanocrypto.so")
set(NANOCAP_LIB          "${LIB_DIR}/libnanocap.so")
set(CRYPTO_INTERFACE_LIB "${LIB_DIR}/libcryptointerface.so")
set(NANOCERT_LIB         "${LIB_DIR}/libnanocert.so")
set(NANOSSL_LIB          "${LIB_DIR}/libnanossl.so")
set(CERT_ENROLL_LIB      "${LIB_DIR}/libcert_enroll.so")

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

  target_link_libraries(crypto_interface_example PRIVATE
      ${PLATFORM_LIB}
      ${ASN1_LIB}
      ${COMMON_LIB}
      ${INITIALIZE_LIB}
      ${NANOCRYPTO_LIB}
      ${NANOCAP_LIB}
      ${CRYPTO_INTERFACE_LIB}
      ${NANOCERT_LIB}
      ${NANOSSL_LIB}
      ${CERT_ENROLL_LIB}
      ${NANOTAP2_COMMON_LIB}
      ${NANOTAP2_CONFIGPARSER_LIB}
      ${NANOTAP2_LIB}
      ${SMP_LIB}
      ${TPM2_LIB}
      )

else()

  target_link_libraries(crypto_interface_example PRIVATE
      ${PLATFORM_LIB}
      ${ASN1_LIB}
      ${COMMON_LIB}
      ${INITIALIZE_LIB}
      ${NANOCRYPTO_LIB}
      ${NANOCAP_LIB}
      ${CRYPTO_INTERFACE_LIB}
      ${NANOCERT_LIB}
      ${NANOSSL_LIB}
      ${CERT_ENROLL_LIB}
      )

endif()

add_custom_command(
  TARGET crypto_interface_example
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:crypto_interface_example> ${SAMPLE_FILE_PATH}
)
