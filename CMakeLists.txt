########################################################################
# CMake build script for TrustCore Libraries
#########################################################################

cmake_minimum_required(VERSION 3.16)

project(TrustCore LANGUAGES C CXX)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

option(WITH_LOGGING "Build with logging enabled." OFF)

# Crypto Interface Example options
option(ENABLE_CI_EXAMPLE "Build Crypto Interface Example." OFF)

# SSH build options
option(ENABLE_SSH_CLIENT "Build SSH Client." OFF)
option(ENABLE_SSH_SERVER "Build SSH Server." OFF)
option(ENABLE_SSH_SERVER_CERT_AUTH "Enable SSH Server certificate authentication." OFF)
option(ENABLE_SSH_CLIENT_CERT_AUTH "Enable SSH Client certificate authentication." OFF)
option(ENABLE_SSH_CLIENT_AUTH "Enable SSH Client public key authentication." OFF)
option(ENABLE_SSH_ASYNC_API_SUPPORT "Enable SSH Async API support." OFF)
option(ENABLE_SSH_CLIENT_SHELL_EXAMPLE "Build SSH client shell example." OFF)
option(ENABLE_SSH_UNITTEST "Enable SSH Unit Test" OFF)

# SCEP build options
option(ENABLE_SCEP "Enable SCEP support." OFF)
option(ENABLE_SCEP_UNITTEST "Enable SCEP Unit Test" OFF)

# EST build options
option(ENABLE_EST "Enable EST support." OFF)
option(ENABLE_EST_PROXY "Enable EST proxy support." OFF)
option(ENABLE_EST_UNITTEST "Enable EST Unit Test" OFF)

# SSL Build options
option(CM_ENABLE_SSL               "Enable SSL library build" ON)
option(CM_ENABLE_SSL_MAUTH_SUPPORT "Enable Mutual Authentication" OFF)
option(CM_ENABLE_SSL_OCSP          "Enable OCSP support" OFF)
if(CM_ENABLE_SSL)
  option(DISABLE_SSL_CLIENT "Disable SSL Client." OFF)
  option(DISABLE_SSL_SERVER "Disable SSL Server." OFF)
else()
  option(DISABLE_SSL_CLIENT "Disable SSL Client." ON)
  option(DISABLE_SSL_SERVER "Disable SSL Server." ON)
endif()
if(CM_ENABLE_SSL_OCSP)
  set(CM_ENABLE_URI ON CACHE BOOL "Build with URI support." FORCE)
  set(CM_ENABLE_OCSP ON CACHE BOOL "Build with OCSP support." FORCE)
endif()

# MQTT build options
option(ENABLE_MQTT_CLIENT "Build MQTT Client." OFF)
option(ENABLE_MQTT_TEST "Enable MQTT Client Test" OFF)
option(ENABLE_MQTT_UNITTEST "Enable MQTT Client Unit Test" OFF)
option(ENABLE_MQTT_STREAMING "Enable Streaming Support" OFF)

if (ENABLE_MQTT_CLIENT)
    set(CM_ENABLE_PROXY ON CACHE BOOL "Build with proxy support." FORCE)
    set(CM_ENABLE_ASYNC ON CACHE BOOL "Build with async support." FORCE)
    set(CM_ENABLE_PERSIST ON CACHE BOOL "Build with persist support." FORCE)
    set(CM_ENABLE_SCRAM ON CACHE BOOL "Build with SCRAM." FORCE)
    set(CM_ENABLE_SSL ON CACHE BOOL "Build with SSL." FORCE)
endif()

# NanoTAP API example
option(ENABLE_TAP_API_EXAMPLE "Build NanoTAP API Example." OFF)

# SMP build options
option(ENABLE_NANOROOT "Enable NanoROOT support" OFF)
option(ENABLE_PKCS11_SOFTHSM "Enable PKCS11 SoftHSM support" OFF)
option(ENABLE_PKCS11_TEE "Enable PKCS11 TEE support" OFF)
option(ENABLE_TPM2 "Enable TPM2 support" OFF)

# Global build options
option(BUILD_SAMPLES "Build samples." OFF)
option(DISABLE_SUITEB "Disable Suite B algorithms." OFF)
option(DISABLE_PQC "Disable Quantum Safe algorithms." OFF)
option(ENABLE_PQC_COMPOSITE "Enable PQC Composite" OFF)
option(DISABLE_EDDSA_25519_SUPPORT "Disable Ed25519 support." OFF)
option(DISABLE_ECDH_25519_SUPPORT "Disable ECDH with Curve25519 support." OFF)
option(ENABLE_TAP "Enable TAP" OFF)

# PQC and SSL/MQTT are not available without suiteb
if(DISABLE_SUITEB)
  set(DISABLE_PQC ON CACHE BOOL "Disable PQC." FORCE)
  set(DISABLE_SSL_CLIENT ON CACHE BOOL "Disable SSL client." FORCE)
  set(DISABLE_SSL_SERVER ON CACHE BOOL "Disable SSL server." FORCE)
  set(ENABLE_MQTT_CLIENT OFF CACHE BOOL "Enable MQTT client." FORCE)
endif()

# Build for OSI
option(BUILD_FOR_OSI "Build for OSI" ON)

if(
    NOT ENABLE_CI_EXAMPLE
    AND NOT ENABLE_SSH_CLIENT
    AND NOT ENABLE_SSH_SERVER
    AND NOT ENABLE_MQTT_CLIENT
    AND NOT ENABLE_NANOROOT
    AND NOT ENABLE_PKCS11_SOFTHSM
    AND NOT ENABLE_PKCS11_TEE
    AND NOT ENABLE_TPM2
    AND NOT ENABLE_TAP_API_EXAMPLE
    AND NOT ENABLE_SCEP
    AND NOT ENABLE_EST
    AND DISABLE_SSL_CLIENT
    AND DISABLE_SSL_SERVER
)
  message(FATAL_ERROR
    "No modules enabled. Please enable at least one of: ENABLE_CI_EXAMPLE, ENABLE_SSH_CLIENT, ENABLE_SSH_SERVER, "
    "ENABLE_MQTT_CLIENT, ENABLE_NANOROOT, ENABLE_PKCS11_SOFTHSM, ENABLE_PKCS11_TEE, ENABLE_TPM2, ENABLE_TAP_API_EXAMPLE, "
    "ENABLE_SCEP, ENABLE_EST, (set DISABLE_SSL_CLIENT and/or DISABLE_SSL_SERVER to OFF)")
endif()

if(ENABLE_TAP_API_EXAMPLE)
  set(ENABLE_TAP ON CACHE BOOL "Enable TAP" FORCE)
endif()

if(ENABLE_NANOROOT)
  set(ENABLE_TAP ON CACHE BOOL "Enable TAP" FORCE)
  set(CM_ENABLE_SMP_NANOROOT ON CACHE BOOL "Enable NANOROOT SMP." FORCE)
endif()

if(ENABLE_PKCS11_SOFTHSM)
  set(ENABLE_TAP ON CACHE BOOL "Enable TAP" FORCE)
  set(CM_ENABLE_SMP_PKCS11 ON CACHE BOOL "Enable PKCS11 SMP." FORCE)
  set(CM_ENABLE_SOFTHSM ON CACHE BOOL "Enable softhsm lib." FORCE)
endif()

if(ENABLE_PKCS11_TEE)
  set(ENABLE_TAP ON CACHE BOOL "Enable TAP" FORCE)
  set(CM_ENABLE_SMP_PKCS11 ON CACHE BOOL "Enable PKCS11 SMP." FORCE)
  set(CM_ENABLE_PKCS11_TEE ON CACHE BOOL "Enable TEE lib." FORCE)
endif()

if(ENABLE_TPM2)
  set(ENABLE_TAP ON CACHE BOOL "Enable TAP" FORCE)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL "Compile commands for auto generated header" FORCE)
set(CM_BUILD_SHARED_LIBS ON CACHE BOOL "Build NanoSSH Shared Library" FORCE)
set(CM_ENABLE_CRYPTOINTERFACE ON CACHE BOOL "Build with crypto interface." FORCE)
set(CM_ENABLE_DEBUG ${WITH_LOGGING} CACHE BOOL "Build with logging enabled." FORCE)
set(MACRO_SCRIPT ${CMAKE_SOURCE_DIR}/scripts/extract_define.py)
set(COMPILE_COMMANDS_JSON ${CMAKE_BINARY_DIR}/compile_commands.json)
set(MOPTIONS_CUSTOM_CI_EXAMPLE_FILE ${CMAKE_SOURCE_DIR}/src/common/moptions_custom_ci_example.h)
set(MOPTIONS_CUSTOM_SSH_SERVER_FILE ${CMAKE_SOURCE_DIR}/src/common/moptions_custom_ssh_server.h)
set(MOPTIONS_CUSTOM_SSH_CLIENT_FILE ${CMAKE_SOURCE_DIR}/src/common/moptions_custom_ssh_client.h)
set(MOPTIONS_CUSTOM_SSL_SERVER_FILE ${CMAKE_SOURCE_DIR}/src/common/moptions_custom_ssl_server.h)
set(MOPTIONS_CUSTOM_SSL_CLIENT_FILE ${CMAKE_SOURCE_DIR}/src/common/moptions_custom_ssl_client.h)
set(MOPTIONS_CUSTOM_MQTT_CLIENT_FILE ${CMAKE_SOURCE_DIR}/src/common/moptions_custom_mqtt_client.h)

set(CM_ENABLE_SERVER_CERT_AUTH ${ENABLE_SSH_SERVER_CERT_AUTH} CACHE BOOL "Enable SSH server certificate authentication" FORCE)
set(CM_ENABLE_CLIENT_CERT_AUTH ${ENABLE_SSH_CLIENT_CERT_AUTH} CACHE BOOL "Enable SSH client certificate authentication" FORCE)
set(CM_ENABLE_CLIENT_AUTH ${ENABLE_SSH_CLIENT_AUTH} CACHE BOOL "Enable SSH Client public key authentication" FORCE)
set(CM_ENABLE_SSH_UNITTEST ${ENABLE_SSH_UNITTEST} CACHE BOOL "Enable SSH Unit Test" FORCE)
set(CM_DISABLE_SUITEB ${DISABLE_SUITEB} CACHE BOOL "Disable Suite B algorithms" FORCE)
set(CM_DISABLE_PQC ${DISABLE_PQC} CACHE BOOL "Disable Quantum Safe algorithms" FORCE)
set(CM_DISABLE_DSA OFF CACHE BOOL "Disable DSA." FORCE)
set(CM_ENABLE_PQC_COMPOSITE ${ENABLE_PQC_COMPOSITE} CACHE BOOL "Enable PQC Composite" FORCE)
set(CM_DISABLE_EDDSA_25519_SUPPORT ${DISABLE_EDDSA_25519_SUPPORT} CACHE BOOL "Disable Ed25519 support" FORCE)
set(CM_DISABLE_ECDH_25519_SUPPORT ${DISABLE_ECDH_25519_SUPPORT} CACHE BOOL "Disable ECDH with Curve25519 support" FORCE)
set(CM_ENABLE_TAP ${ENABLE_TAP} CACHE BOOL "Enable TAP" FORCE)
set(CM_ENABLE_MQTT_TEST ${ENABLE_MQTT_TEST} CACHE BOOL "Enable MQTT Client Test" FORCE)
set(CM_ENABLE_MQTT_UNITTEST ${ENABLE_MQTT_UNITTEST} CACHE BOOL "Enable MQTT Unit Test" FORCE)
set(CM_ENABLE_STREAMING ${ENABLE_MQTT_STREAMING} CACHE BOOL "Enable MQTT Streaming Support" FORCE)
set(CM_ENABLE_SSH ON CACHE BOOL "Enable SSH support for nanocert" FORCE)
set(CM_ENABLE_PROCESS ON CACHE BOOL "Enable Process APIs." FORCE)

if(ENABLE_SCEP)
  set(CM_ENABLE_SCEP ON CACHE BOOL "Enable SCEP support." FORCE)
  if(BUILD_SAMPLES)
    set(CM_BUILD_SCEP_SAMPLE ON CACHE BOOL "Build SCEP sample." FORCE)
  endif()
  if(ENABLE_SCEP_UNITTEST)
    option(CM_ENABLE_COMMON_UTILS "Enable common utils for SCEP." ON)
  endif()
endif()

if(ENABLE_EST)
  set(CM_ENABLE_EST ON CACHE BOOL "Build EST." FORCE)
  set(CM_ENABLE_CMC ON CACHE BOOL "Enable CMC API for EST." FORCE)
  set(CM_ENABLE_MIME_PARSER ON CACHE BOOL "Enable MIME parser for EST." FORCE)
  set(CM_ENABLE_COMMON_UTILS ON CACHE BOOL "Enable common utils for EST." FORCE)
  if(BUILD_SAMPLES)
    set(CM_BUILD_EST_CLIENT ON CACHE BOOL "Build EST sample." FORCE)
    set(CM_ENABLE_PROXY ${ENABLE_EST_PROXY} CACHE BOOL "Build EST with proxy support." FORCE)
  endif()
endif()

if (DEFINED SECURE_PATH)
  message("\nSECURE_PATH = ${SECURE_PATH}")
  add_definitions("-D__ENABLE_DIGICERT_SECURE_PATH__")
  add_definitions("-DMANDATORY_BASE_PATH=\"${SECURE_PATH}\"")
  if(ENABLE_EST OR ENABLE_SCEP)
    add_definitions("-DMOCANA_TRUSTED_CONFIG_FILE=\"${SECURE_PATH}/keystore/conf/tpconf.json\"")
  endif()
else()
  if(ENABLE_EST OR ENABLE_SCEP)
    add_definitions("-DMOCANA_TRUSTED_CONFIG_FILE=\"${CMAKE_SOURCE_DIR}/keystore/conf/tpconf.json\"")
  endif()
endif()

add_subdirectory(projects/platform)
# Always build projects/common with debug logging APIs
set(CM_ENABLE_DEBUG ON CACHE BOOL "Build with logging enabled." FORCE)
add_subdirectory(projects/common)
set(CM_ENABLE_DEBUG ${WITH_LOGGING} CACHE BOOL "Build with logging enabled." FORCE)
add_subdirectory(projects/asn1)
add_subdirectory(projects/initialize)
add_subdirectory(projects/nanocap)
add_subdirectory(projects/crypto)
add_subdirectory(projects/nanocert)
add_subdirectory(projects/cert_enroll)
if(CM_ENABLE_SSL)
  set(CM_BUILD_NANOSSL_LIB ON CACHE BOOL "Build SSL Lib." FORCE)
  set(CM_BUILD_SSL_SERVER OFF CACHE BOOL "Build SSL Server" FORCE)
  set(CM_BUILD_SSL_CLIENT OFF CACHE BOOL "Build SSL Client" FORCE)
  add_subdirectory(projects/nanossl)
endif()
if(ENABLE_NANOROOT)
  add_subdirectory(projects/smp_nanoroot)
endif()
if(ENABLE_PKCS11_SOFTHSM OR ENABLE_PKCS11_TEE OR ENABLE_TPM2)
  add_subdirectory(projects/tpm2)
endif()
if(ENABLE_PKCS11_SOFTHSM OR ENABLE_PKCS11_TEE)
  add_subdirectory(projects/smp_pkcs11)
endif()
if(ENABLE_TPM2)
  add_subdirectory(projects/smp_tpm2)
endif()
if(ENABLE_TAP)
  add_subdirectory(projects/nanotap2)
  add_subdirectory(projects/nanotap2_configparser)
  add_subdirectory(projects/nanotap2_common)
endif()

if(CM_ENABLE_SERVER_CERT_AUTH OR CM_ENABLE_CLIENT_CERT_AUTH)
  set(CM_ENABLE_X509_CERTS ON CACHE BOOL "Enable X.509 certificates support" FORCE)
endif()

# Crypto Interface Example
set(CI_EXAMPLE_HEADER "")
set(CI_EXAMPLE_FILE ${CMAKE_BINARY_DIR}/ci_example_macros.h)
if(ENABLE_CI_EXAMPLE)
  set(CI_EXAMPLE_HEADER ${CI_EXAMPLE_FILE})
  add_custom_target(overwrite_for_ci_example
    COMMAND ${CMAKE_COMMAND} -E copy ${CI_EXAMPLE_HEADER} ${MOPTIONS_CUSTOM_CI_EXAMPLE_FILE}
    DEPENDS ${CI_EXAMPLE_HEADER} ${CMAKE_SOURCE_DIR}/lib/libcryptointerface.so
  )
endif()

# SSH client library
set(SSH_CLIENT_HEADER "")
set(SSH_CLIENT_FILE ${CMAKE_BINARY_DIR}/ssh_client_macros.h)
if(ENABLE_SSH_CLIENT)
  set(SSH_CLIENT_HEADER ${SSH_CLIENT_FILE})

  add_custom_target(overwrite_for_ssh_client
    COMMAND ${CMAKE_COMMAND} -E copy ${SSH_CLIENT_HEADER} ${MOPTIONS_CUSTOM_SSH_CLIENT_FILE}
    DEPENDS ${SSH_CLIENT_HEADER} ${CMAKE_SOURCE_DIR}/lib/libnanosshc.so
  )
  set(CM_BUILD_SSH_SERVER OFF CACHE BOOL "Build SSH Server" FORCE)
  set(CM_BUILD_SSH_CLIENT ON  CACHE BOOL "Build SSH Client" FORCE)
  add_subdirectory(projects/nanossh ${CMAKE_BINARY_DIR}/projects/nanossh/ssh_client)
endif()

# SSH server library
set(SSH_SERVER_HEADER "")
set(SSH_SERVER_FILE ${CMAKE_BINARY_DIR}/ssh_server_macros.h)
if(ENABLE_SSH_SERVER)
  set(SSH_SERVER_HEADER ${SSH_SERVER_FILE})

  # first header is server
  add_custom_target(overwrite_for_ssh_server
    COMMAND ${CMAKE_COMMAND} -E copy ${SSH_SERVER_HEADER} ${MOPTIONS_CUSTOM_SSH_SERVER_FILE}
    DEPENDS ${SSH_SERVER_HEADER} ${CMAKE_SOURCE_DIR}/lib/libnanosshs.so
  )

  set(CM_BUILD_SSH_SERVER ON  CACHE BOOL "Build SSH Server" FORCE)
  set(CM_BUILD_SSH_CLIENT OFF CACHE BOOL "Build SSH Client" FORCE)
  add_subdirectory(projects/nanossh ${CMAKE_BINARY_DIR}/projects/nanossh/ssh_server)
endif()

# SSL client
set(SSL_CLIENT_HEADER "")
set(SSL_CLIENT_FILE ${CMAKE_BINARY_DIR}/ssl_client_macros.h)
if(NOT DISABLE_SSL_CLIENT)
  set(SSL_CLIENT_HEADER ${SSL_CLIENT_FILE})

  add_custom_target(overwrite_for_ssl_client
    COMMAND ${CMAKE_COMMAND} -E copy ${SSL_CLIENT_HEADER} ${MOPTIONS_CUSTOM_SSL_CLIENT_FILE}
    DEPENDS ${SSL_CLIENT_HEADER} ${CMAKE_SOURCE_DIR}/lib/libnanossl.so
  )
endif()

# SSL server
set(SSL_SERVER_HEADER "")
set(SSL_SERVER_FILE ${CMAKE_BINARY_DIR}/ssl_server_macros.h)
if(NOT DISABLE_SSL_SERVER)
  set(SSL_SERVER_HEADER ${SSL_SERVER_FILE})

  # first header is server
  add_custom_target(overwrite_for_ssl_server
    COMMAND ${CMAKE_COMMAND} -E copy ${SSL_SERVER_HEADER} ${MOPTIONS_CUSTOM_SSL_SERVER_FILE}
    DEPENDS ${SSL_SERVER_HEADER} ${CMAKE_SOURCE_DIR}/lib/libnanossl.so
  )
endif()

# MQTT client library
set(MQTT_CLIENT_HEADER "")
set(MQTT_CLIENT_FILE ${CMAKE_BINARY_DIR}/mqtt_client_macros.h)
if(ENABLE_MQTT_CLIENT)
  set(MQTT_CLIENT_HEADER ${MQTT_CLIENT_FILE})

  add_custom_target(overwrite_for_mqtt_client
    COMMAND ${CMAKE_COMMAND} -E copy ${MQTT_CLIENT_HEADER} ${MOPTIONS_CUSTOM_MQTT_CLIENT_FILE}
    DEPENDS ${MQTT_CLIENT_HEADER} ${CMAKE_SOURCE_DIR}/lib/libnanomqtt.so
  )
  set(CM_BUILD_NANOMQTT ON  CACHE BOOL "Build MQTT Client" FORCE)
  add_subdirectory(projects/mqtt_client)
endif()

# MQTT unit tests
if(ENABLE_MQTT_CLIENT AND ENABLE_MQTT_UNITTEST)
    add_subdirectory(projects/mqtt_testunit)
endif()

# Samples must be build after the project libraries

# Crypto Interface Example
if(ENABLE_CI_EXAMPLE)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/crypto_interface_example)
    add_dependencies(crypto_interface_example overwrite_for_ci_example)
    target_compile_definitions(crypto_interface_example PUBLIC -DMOPTIONS_CUSTOM_HEADER="${MOPTIONS_CUSTOM_CI_EXAMPLE_FILE}")
  endif()
endif()

# SSH client sample
if(ENABLE_SSH_CLIENT)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/ssh_client)
    add_dependencies(ssh_client overwrite_for_ssh_client)
    target_compile_definitions(ssh_client PUBLIC -DMOPTIONS_CUSTOM_HEADER="${MOPTIONS_CUSTOM_SSH_CLIENT_FILE}")
  endif()
endif()

# SSH server sample
if(ENABLE_SSH_SERVER)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/ssh_server)
    add_dependencies(ssh_server overwrite_for_ssh_server)
    target_compile_definitions(ssh_server PUBLIC -DMOPTIONS_CUSTOM_HEADER="${MOPTIONS_CUSTOM_SSH_SERVER_FILE}")
  endif()
endif()

# SSL client sample
if(NOT DISABLE_SSL_CLIENT)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/ssl_client)
    add_dependencies(ssl_client overwrite_for_ssl_client)
    target_compile_definitions(ssl_client PUBLIC -DMOPTIONS_CUSTOM_HEADER="${MOPTIONS_CUSTOM_SSL_CLIENT_FILE}")
  endif()
endif()

# SSL server sample
if(NOT DISABLE_SSL_SERVER)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/ssl_server)
    add_dependencies(ssl_server overwrite_for_ssl_server)
    target_compile_definitions(ssl_server PUBLIC -DMOPTIONS_CUSTOM_HEADER="${MOPTIONS_CUSTOM_SSL_SERVER_FILE}")
  endif()
endif()

# SSH unit tests
if((ENABLE_SSH_CLIENT OR ENABLE_SSH_SERVER) AND ENABLE_SSH_UNITTEST)
    add_subdirectory(projects/nanossh_testunit)
endif()

# MQTT client sample
if(ENABLE_MQTT_CLIENT)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/mqtt_client)
    add_dependencies(mqtt_client overwrite_for_mqtt_client)
    target_compile_definitions(mqtt_client PUBLIC -DMOPTIONS_CUSTOM_HEADER="${MOPTIONS_CUSTOM_MQTT_CLIENT_FILE}")

    if(ENABLE_MQTT_TEST)
      add_dependencies(mqtt_client_test overwrite_for_mqtt_client)
      target_compile_definitions(mqtt_client_test PUBLIC -DMOPTIONS_CUSTOM_HEADER="${MOPTIONS_CUSTOM_MQTT_CLIENT_FILE}")
    endif()
  endif()
endif()

# NanoTAP API example
if(ENABLE_TAP_API_EXAMPLE)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/tap_api_example)
  endif()
endif()

# NanoROOT samples
if(ENABLE_NANOROOT)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/nanoroot)
  endif()
endif()

# SCEP sample
if(ENABLE_SCEP)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/nanocert_scep)
  endif()
endif()

# EST sample
if(ENABLE_EST)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/nanocert_est)
  endif()
endif()

# SCEP unit tests
if(ENABLE_SCEP AND ENABLE_SCEP_UNITTEST)
    add_subdirectory(projects/scep_testunit)
endif()

# EST unit tests
if(ENABLE_EST AND ENABLE_EST_UNITTEST)
    add_subdirectory(projects/est_testunit)
endif()

# Generate tpconf.json for SCEP and EST samples
if((ENABLE_SCEP OR ENABLE_EST) AND BUILD_SAMPLES)
  set(TPCONF_FILE "${CMAKE_SOURCE_DIR}/keystore/conf/tpconf.json")
  file(WRITE ${TPCONF_FILE} "{\n")
  file(APPEND ${TPCONF_FILE} "    \"http_proxy\": null,\n")
  file(APPEND ${TPCONF_FILE} "    \"root_dir\": \"${CMAKE_SOURCE_DIR}\",\n")
  file(APPEND ${TPCONF_FILE} "    \"keystore_dir\": \"${CMAKE_SOURCE_DIR}/keystore\",\n")
  file(APPEND ${TPCONF_FILE} "    \"conf_dir\": \"${CMAKE_SOURCE_DIR}/keystore/conf\",\n")
  file(APPEND ${TPCONF_FILE} "    \"truststore_dir\": \"${CMAKE_SOURCE_DIR}/keystore/ca\"\n")
  file(APPEND ${TPCONF_FILE} "}\n")
  message(STATUS "Generated tpconf.json in ${TPCONF_FILE}")
endif()

# generate both client and server macro headers
add_custom_command(
    OUTPUT ${CI_EXAMPLE_HEADER} ${SSH_SERVER_HEADER} ${SSH_CLIENT_HEADER} ${MQTT_CLIENT_HEADER} ${SSL_SERVER_HEADER} ${SSL_CLIENT_HEADER}
    COMMAND ${CMAKE_COMMAND} -E echo "Generating macros from compile_commands.json"
    COMMAND ${Python3_EXECUTABLE} ${MACRO_SCRIPT} ${COMPILE_COMMANDS_JSON} ${CI_EXAMPLE_FILE} ${SSH_SERVER_FILE} ${SSH_CLIENT_FILE} ${MQTT_CLIENT_FILE} ${SSL_SERVER_FILE} ${SSL_CLIENT_FILE}
    DEPENDS ${COMPILE_COMMANDS_JSON} ${MACRO_SCRIPT}
    COMMENT "Extracting macros from compile_commands.json"
)

# Custom target to run the script
add_custom_target(generate_macros_header ALL
    DEPENDS ${SSH_SERVER_HEADER} ${SSH_CLIENT_HEADER} ${MQTT_CLIENT_HEADER}
)
