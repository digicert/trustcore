cmake_minimum_required(VERSION 3.16)

option(CM_ENABLE_TAP                                "Enable TAP"                          ON)

project(ESTClient LANGUAGES C CXX)

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
set(SAMPLE_FILE_PATH "${SAMPLE_BIN_DIR}/est_sample")

set(INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/est"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/http"
    )
include_directories(${INCLUDE_DIR})

set(SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/est_example_client.c
    ${SRC_DIR}/../samples/common/digicert_example.c
)

add_executable(est_sample ${SOURCE_FILES})

target_compile_definitions(est_sample PRIVATE
  __RTOS_LINUX__
  __ENABLE_DIGICERT_EXAMPLES__
  __DISABLE_DIGICERT_AUTO_EXAMPLES__
  __ENABLE_DIGICERT_ECC__
  __ENABLE_DIGICERT_PQC__
  __ENABLE_DIGICERT_PKCS8__
  __ENABLE_DIGICERT_PEM_CONVERSION__
  __ENABLE_DIGICERT_DER_CONVERSION__
  __ENABLE_DIGICERT_HTTP_CLIENT__
  __ENABLE_DIGICERT_SSL_CLIENT__
  __ENABLE_DIGICERT_EST_CLIENT__
  __ENABLE_DIGICERT_ESTC__
  __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
  __ENABLE_DIGICERT_SSL_REHANDSHAKE__
  __ENABLE_DIGICERT_AEAD_CIPHER__
  __ENABLE_DIGICERT_PKCS10__
  __ENABLE_DIGICERT_PKCS7__
  __ENABLE_DIGICERT_URI__
  __DISABLE_DIGICERT_SSH_COMMON_NAME_CHECK__
  __DISABLE_DIGICERT_SSL_ALERTS__
  MIN_SSL_RSA_SIZE=1024
  __ENABLE_DIGICERT_TLS12_UNSECURE_HASH__
  __ENABLE_DIGICERT_PEM_DER_PRIVATE_KEY__
  __ENABLE_DIGICERT_PKCS1__
  __ENABLE_DIGICERT_PKCS12__
  __ENABLE_DIGICERT_PKCS5__
  __ENABLE_DIGICERT_SERIALIZE__
  __ENABLE_DIGICERT_DSA__
  __ENABLE_DIGICERT_CMS__
  __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
  $<$<BOOL:${CM_ENABLE_TAP}>:__ENABLE_DIGICERT_TAP__>
  $<$<BOOL:${CM_ENABLE_TAP}>:__ENABLE_DIGICERT_TPM2__>
  $<$<BOOL:${CM_ENABLE_TAP}>:__ENABLE_DIGICERT_CRYPTO_INTERFACE__>
)

# Set library paths based on build type
if("STATIC" STREQUAL "${LIB_TYPE}")
  message("Building est_sample with STATIC libraries")
  
  set(ASN1_LIB             "${LIB_DIR}/libasn1.a")
  set(COMMON_LIB           "${LIB_DIR}/libcommon.a")
  set(INITIALIZE_LIB       "${LIB_DIR}/libinitialize.a")
  set(PLATFORM_LIB         "${LIB_DIR}/libplatform.a")
  set(NANOCRYPTO_LIB       "${LIB_DIR}/libnanocrypto.a")
  set(NANOCAP_LIB          "${LIB_DIR}/libnanocap.a")
  set(CRYPTO_INTERFACE_LIB "${LIB_DIR}/libcryptointerface.a")
  set(NANOCERT_LIB         "${LIB_DIR}/libnanocert.a")
  set(CERT_ENROLL_LIB      "${LIB_DIR}/libcert_enroll.a")
  set(NANOSSL_LIB          "${LIB_DIR}/libnanossl.a")
  
  if(CM_ENABLE_TAP)
    set(NANOTAP2_COMMON_LIB "${LIB_DIR}/libnanotap2_common.a")
    set(NANOTAP2_CONFIGPARSER_LIB "${LIB_DIR}/libnanotap2_configparser.a")
    set(NANOTAP2_LIB "${LIB_DIR}/libnanotap2.a")
    if(ENABLE_PKCS11_SOFTHSM OR ENABLE_PKCS11_TEE)
      set(SMP_LIB "${LIB_DIR}/libsmppkcs11.a")
      set(TPM2_LIB "${LIB_DIR}/libtpm2.a")
    elseif(ENABLE_TPM2)
      set(SMP_LIB "${LIB_DIR}/libsmptpm2.a")
      set(TPM2_LIB "${LIB_DIR}/libtpm2.a")
    endif()
  endif()
  
else()
  message("Building est_sample with SHARED libraries")
  
  set(ASN1_LIB             "${LIB_DIR}/libasn1.so")
  set(COMMON_LIB           "${LIB_DIR}/libcommon.so")
  set(INITIALIZE_LIB       "${LIB_DIR}/libinitialize.so")
  set(PLATFORM_LIB         "${LIB_DIR}/libplatform.so")
  set(NANOCRYPTO_LIB       "${LIB_DIR}/libnanocrypto.so")
  set(NANOCAP_LIB          "${LIB_DIR}/libnanocap.so")
  set(CRYPTO_INTERFACE_LIB "${LIB_DIR}/libcryptointerface.so")
  set(NANOCERT_LIB         "${LIB_DIR}/libnanocert.so")
  set(CERT_ENROLL_LIB      "${LIB_DIR}/libcert_enroll.so")
  set(NANOSSL_LIB          "${LIB_DIR}/libnanossl.so")
  
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
  endif()
  
endif()

# Link libraries with proper order for static builds
if(CM_ENABLE_TAP)
  if("STATIC" STREQUAL "${LIB_TYPE}")
    # Static libraries with circular dependencies - use --start-group/--end-group
    target_link_libraries(est_sample PRIVATE
        ${NANOSSL_LIB}
        ${NANOCERT_LIB}
        ${CERT_ENROLL_LIB}
        ${NANOTAP2_LIB}
        ${NANOTAP2_CONFIGPARSER_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${SMP_LIB}
        ${TPM2_LIB}
        -Wl,--start-group
        ${INITIALIZE_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTO_INTERFACE_LIB}
        ${NANOCAP_LIB}
        -Wl,--end-group
        ${ASN1_LIB}
        ${COMMON_LIB}
        ${PLATFORM_LIB}
        pthread
        dl
    )
  else()
    # Shared libraries - order doesn't matter much
    target_link_libraries(est_sample PRIVATE
        ${PLATFORM_LIB}
        ${ASN1_LIB}
        ${COMMON_LIB}
        ${INITIALIZE_LIB}
        ${NANOSSL_LIB}
        ${NANOCERT_LIB}
        ${CERT_ENROLL_LIB}
        ${NANOCRYPTO_LIB}
        ${NANOCAP_LIB}
        ${CRYPTO_INTERFACE_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${NANOTAP2_CONFIGPARSER_LIB}
        ${NANOTAP2_LIB}
        ${SMP_LIB}
        ${TPM2_LIB}
    )
  endif()
else()
  if("STATIC" STREQUAL "${LIB_TYPE}")
    # Static libraries with circular dependencies - use --start-group/--end-group
    target_link_libraries(est_sample PRIVATE
        ${NANOSSL_LIB}
        ${NANOCERT_LIB}
        ${CERT_ENROLL_LIB}
        -Wl,--start-group
        ${INITIALIZE_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTO_INTERFACE_LIB}
        ${NANOCAP_LIB}
        -Wl,--end-group
        ${ASN1_LIB}
        ${COMMON_LIB}
        ${PLATFORM_LIB}
        pthread
        dl
    )
  else()
    # Shared libraries - order doesn't matter much
    target_link_libraries(est_sample PRIVATE
        ${PLATFORM_LIB}
        ${ASN1_LIB}
        ${COMMON_LIB}
        ${INITIALIZE_LIB}
        ${NANOSSL_LIB}
        ${NANOCERT_LIB}
        ${CERT_ENROLL_LIB}
        ${NANOCRYPTO_LIB}
        ${NANOCAP_LIB}
        ${CRYPTO_INTERFACE_LIB}
    )
  endif()
endif()

add_custom_command(
  TARGET est_sample
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:est_sample> ${SAMPLE_FILE_PATH}
)