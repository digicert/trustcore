cmake_minimum_required(VERSION 3.16)

option(CM_ENABLE_TAP                                "Enable TAP"                          ON)
option(CM_ENABLE_SSL_MAUTH_SUPPORT                  "Enable Mutual Authentication"       OFF)

project(SSLServer LANGUAGES C CXX)

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
set(SAMPLE_FILE_PATH "${SAMPLE_BIN_DIR}/ssl_server")

add_definitions("-D__ENABLE_DIGICERT_EXAMPLES__")
add_definitions("-D__ENABLE_DIGICERT_SSL_SERVER_EXAMPLE__")
add_definitions("-D__DISABLE_DIGICERT_AUTO_EXAMPLES__")
add_definitions("-D__ENABLE_DIGICERT_SSL_CLIENT__")

if (CM_ENABLE_SSL_MAUTH_SUPPORT)
  add_definitions("-D__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT_EXAMPLE__")
endif()

set(INCLUDE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/ssl
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )
include_directories(${INCLUDE_DIR})

set(SOURCE_FILES
    ${SRC_DIR}/../samples/common/digicert_example.c
    ${SRC_DIR}/../samples/common/ssl_cert_utils.c
    ${SRC_DIR}/../samples/common/ca_mgmt_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ssl_example.c
)

add_executable(ssl_server ${SOURCE_FILES})

# Set library paths based on build type
if("STATIC" STREQUAL "${LIB_TYPE}")
  message("Building ssl_server with STATIC libraries")
  
  set(ASN1_LIB             "${LIB_DIR}/libasn1.a")
  set(COMMON_LIB           "${LIB_DIR}/libcommon.a")
  set(INITIALIZE_LIB       "${LIB_DIR}/libinitialize.a")
  set(PLATFORM_LIB         "${LIB_DIR}/libplatform.a")
  set(NANOSSL_LIB          "${LIB_DIR}/libnanossl.a")
  set(NANOCRYPTO_LIB       "${LIB_DIR}/libnanocrypto.a")
  set(NANOCAP_LIB          "${LIB_DIR}/libnanocap.a")
  set(NANOCERT_LIB         "${LIB_DIR}/libnanocert.a")
  set(CERT_ENROLL_LIB      "${LIB_DIR}/libcert_enroll.a")
  set(CRYPTO_INTERFACE_LIB "${LIB_DIR}/libcryptointerface.a")
  
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
  message("Building ssl_server with SHARED libraries")
  
  set(ASN1_LIB             "${LIB_DIR}/libasn1.so")
  set(COMMON_LIB           "${LIB_DIR}/libcommon.so")
  set(INITIALIZE_LIB       "${LIB_DIR}/libinitialize.so")
  set(PLATFORM_LIB         "${LIB_DIR}/libplatform.so")
  set(NANOSSL_LIB          "${LIB_DIR}/libnanossl.so")
  set(NANOCRYPTO_LIB       "${LIB_DIR}/libnanocrypto.so")
  set(NANOCAP_LIB          "${LIB_DIR}/libnanocap.so")
  set(NANOCERT_LIB         "${LIB_DIR}/libnanocert.so")
  set(CERT_ENROLL_LIB      "${LIB_DIR}/libcert_enroll.so")
  set(CRYPTO_INTERFACE_LIB "${LIB_DIR}/libcryptointerface.so")
  
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
    target_link_libraries(ssl_server PRIVATE
        ${NANOSSL_LIB}
        ${CERT_ENROLL_LIB}
        ${NANOCERT_LIB}
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
    target_link_libraries(ssl_server PRIVATE
        ${PLATFORM_LIB}
        ${ASN1_LIB}
        ${COMMON_LIB}
        ${INITIALIZE_LIB}
        ${NANOCRYPTO_LIB}
        ${NANOCAP_LIB}
        ${CRYPTO_INTERFACE_LIB}
        ${NANOCERT_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${NANOTAP2_CONFIGPARSER_LIB}
        ${NANOTAP2_LIB}
        ${SMP_LIB}
        ${TPM2_LIB}
        ${NANOSSL_LIB}
        ${CERT_ENROLL_LIB}
    )
  endif()
else()
  if("STATIC" STREQUAL "${LIB_TYPE}")
    # Static libraries with circular dependencies - use --start-group/--end-group
    target_link_libraries(ssl_server PRIVATE
        ${NANOSSL_LIB}
        ${CERT_ENROLL_LIB}
        ${NANOCERT_LIB}
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
    target_link_libraries(ssl_server PRIVATE
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
endif()

add_custom_command(
  TARGET ssl_server
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ssl_server> ${SAMPLE_FILE_PATH}
)