########################################################################
# CMake build script for TrustCore Libraries
#########################################################################

cmake_minimum_required(VERSION 3.16)

project(TrustCore LANGUAGES C CXX)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

option(WITH_LOGGING "Build with logging enabled." OFF)
# SSH build options
option(DISABLE_SSH_CLIENT "Build SSH Client." OFF)
option(DISABLE_SSH_SERVER "Build SSH Server." OFF)
option(ENABLE_SSH_SERVER_CERT_AUTH "Enable SSH Server certificate authentication." OFF)
option(ENABLE_SSH_CLIENT_CERT_AUTH "Enable SSH Client certificate authentication." OFF)
option(ENABLE_SSH_CLIENT_AUTH "Enable SSH Client public key authentication." OFF)
option(ENABLE_SSH_ASYNC_API_SUPPORT "Enable SSH Async API support." OFF)
option(ENABLE_SSH_CLIENT_SHELL_EXAMPLE "Build SSH client shell example." OFF)
option(ENABLE_SSH_UNITTEST "Enable SSH Unit Test" OFF)

# MQTT build options
option(DISABLE_MQTT_CLIENT "Build MQTT Client." OFF)
option(ENABLE_MQTT_TEST "Enable MQTT Client Test" OFF)
option(ENABLE_MQTT_UNITTEST "Enable MQTT Client Unit Test" OFF)
option(ENABLE_MQTT_STREAMING "Enable Streaming Support" OFF)

# NanoROOT build option
option(ENABLE_NANOROOT "Enable NanoROOT support" OFF)

# Global build options
option(BUILD_SAMPLES "Build samples." OFF)
option(DISABLE_SUITEB "Disable Suite B algorithms." OFF)
option(DISABLE_PQC "Disable Quantum Safe algorithms." OFF)
option(ENABLE_PQC_COMPOSITE "Enable PQC Composite" OFF)
option(DISABLE_EDDSA_25519_SUPPORT "Disable Ed25519 support." OFF)
option(DISABLE_ECDH_25519_SUPPORT "Disable ECDH with Curve25519 support." OFF)
option(ENABLE_TAP "Enable TAP" OFF)

# Build for OSI
option(BUILD_FOR_OSI "Build for OSI" ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL "Compile commands for auto generated header" FORCE)
set(CM_BUILD_SHARED_LIBS ON CACHE BOOL "Build NanoSSH Shared Library" FORCE)
set(CM_ENABLE_DEBUG ${WITH_LOGGING} CACHE BOOL "Build with logging enabled." FORCE)
set(MACRO_SCRIPT ${CMAKE_SOURCE_DIR}/scripts/extract_define.py)
set(COMPILE_COMMANDS_JSON ${CMAKE_BINARY_DIR}/compile_commands.json)
set(MOPTIONS_CUSTOM_SSH_SERVER_FILE ${CMAKE_SOURCE_DIR}/src/common/moptions_custom_ssh_server.h)
set(MOPTIONS_CUSTOM_SSH_CLIENT_FILE ${CMAKE_SOURCE_DIR}/src/common/moptions_custom_ssh_client.h)
set(MOPTIONS_CUSTOM_MQTT_CLIENT_FILE ${CMAKE_SOURCE_DIR}/src/common/moptions_custom_mqtt_client.h)

if(ENABLE_NANOROOT)
  set(ENABLE_TAP ON CACHE BOOL "Enable TAP" FORCE)
  set(CM_ENABLE_SMP_NANOROOT ON CACHE BOOL "Enable NANOROOT SMP." FORCE)
  set(CM_ENABLE_PROCESS ON CACHE BOOL "Enable Process APIs." FORCE)
endif()

add_subdirectory(projects/platform)

# Always build projects/common with debug logging APIs
set(CM_ENABLE_DEBUG ON CACHE BOOL "Build with logging enabled." FORCE)
add_subdirectory(projects/common)
set(CM_ENABLE_DEBUG ${WITH_LOGGING} CACHE BOOL "Build with logging enabled." FORCE)
add_subdirectory(projects/asn1)
add_subdirectory(projects/initialize)

set(CM_ENABLE_SERVER_CERT_AUTH ${ENABLE_SSH_SERVER_CERT_AUTH} CACHE BOOL "Enable SSH server certificate authentication" FORCE)
set(CM_ENABLE_CLIENT_CERT_AUTH ${ENABLE_SSH_CLIENT_CERT_AUTH} CACHE BOOL "Enable SSH client certificate authentication" FORCE)
set(CM_ENABLE_CLIENT_AUTH ${ENABLE_SSH_CLIENT_AUTH} CACHE BOOL "Enable SSH Client public key authentication" FORCE)
set(CM_ENABLE_SSH_UNITTEST ${ENABLE_SSH_UNITTEST} CACHE BOOL "Enable SSH Unit Test" FORCE)
set(CM_DISABLE_SUITEB ${DISABLE_SUITEB} CACHE BOOL "Disable Suite B algorithms" FORCE)
set(CM_DISABLE_PQC ${DISABLE_PQC} CACHE BOOL "Disable Quantum Safe algorithms" FORCE)
set(CM_ENABLE_PQC_COMPOSITE ${ENABLE_PQC_COMPOSITE} CACHE BOOL "Enable PQC Composite" FORCE)
set(CM_DISABLE_EDDSA_25519_SUPPORT ${DISABLE_EDDSA_25519_SUPPORT} CACHE BOOL "Disable Ed25519 support" FORCE)
set(CM_DISABLE_ECDH_25519_SUPPORT ${DISABLE_ECDH_25519_SUPPORT} CACHE BOOL "Disable ECDH with Curve25519 support" FORCE)
set(CM_ENABLE_TAP ${ENABLE_TAP} CACHE BOOL "Enable TAP" FORCE)
set(CM_ENABLE_MQTT_TEST ${ENABLE_MQTT_TEST} CACHE BOOL "Enable MQTT Client Test" FORCE)
set(CM_ENABLE_MQTT_UNITTEST ${ENABLE_MQTT_UNITTEST} CACHE BOOL "Enable MQTT Unit Test" FORCE)
set(CM_ENABLE_STREAMING ${ENABLE_MQTT_STREAMING} CACHE BOOL "Enable MQTT Streaming Support" FORCE)

if(CM_ENABLE_SERVER_CERT_AUTH OR CM_ENABLE_CLIENT_CERT_AUTH)
  set(CM_ENABLE_X509_CERTS ON CACHE BOOL "Enable X.509 certificates support" FORCE)
endif()

if (DEFINED SECURE_PATH)
  message("\nSECURE_PATH = ${SECURE_PATH}")
  add_definitions("-D__ENABLE_DIGICERT_SECURE_PATH__")
  add_definitions("-DMANDATORY_BASE_PATH=\"${SECURE_PATH}\"")
endif()

# SSH client library
set(SSH_CLIENT_HEADER "")
set(SSH_CLIENT_FILE ${CMAKE_BINARY_DIR}/ssh_client_macros.h)
if(NOT DISABLE_SSH_CLIENT)
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
if(NOT DISABLE_SSH_SERVER)
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

# MQTT client library
set(MQTT_CLIENT_HEADER "")
set(MQTT_CLIENT_FILE ${CMAKE_BINARY_DIR}/mqtt_client_macros.h)
if(NOT DISABLE_MQTT_CLIENT)
  set(MQTT_CLIENT_HEADER ${MQTT_CLIENT_FILE})

  add_custom_target(overwrite_for_mqtt_client
    COMMAND ${CMAKE_COMMAND} -E copy ${MQTT_CLIENT_HEADER} ${MOPTIONS_CUSTOM_MQTT_CLIENT_FILE}
    DEPENDS ${MQTT_CLIENT_HEADER} ${CMAKE_SOURCE_DIR}/lib/libnanomqtt.so
  )
  set(CM_BUILD_NANOMQTT ON  CACHE BOOL "Build MQTT Client" FORCE)
  add_subdirectory(projects/mqtt_client)
endif()

# MQTT unit tests
if(NOT DISABLE_MQTT_CLIENT AND ENABLE_MQTT_UNITTEST)
    add_subdirectory(projects/mqtt_testunit)    
endif()

# Samples must be build after the project libraries

# SSH client sample
if(NOT DISABLE_SSH_CLIENT)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/ssh_client)
    add_dependencies(ssh_client overwrite_for_ssh_client)
    target_compile_definitions(ssh_client PUBLIC -DMOPTIONS_CUSTOM_HEADER="${MOPTIONS_CUSTOM_SSH_CLIENT_FILE}")
  endif()
endif()

# SSH server sample
if(NOT DISABLE_SSH_SERVER)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/ssh_server)
    add_dependencies(ssh_server overwrite_for_ssh_server)
    target_compile_definitions(ssh_server PUBLIC -DMOPTIONS_CUSTOM_HEADER="${MOPTIONS_CUSTOM_SSH_SERVER_FILE}")
  endif()
endif()

# SSH unit tests
if((NOT DISABLE_SSH_CLIENT OR NOT DISABLE_SSH_SERVER) AND ENABLE_SSH_UNITTEST)
    add_subdirectory(projects/nanossh_testunit)
endif()

# MQTT client sample
if(NOT DISABLE_MQTT_CLIENT)
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

# NanoROOT samples
if(ENABLE_NANOROOT)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/nanoroot)
  endif()
endif()

# generate both client and server macro headers
add_custom_command(
    OUTPUT ${SSH_SERVER_HEADER} ${SSH_CLIENT_HEADER} ${MQTT_CLIENT_HEADER}
    COMMAND ${CMAKE_COMMAND} -E echo "Generating macros from compile_commands.json"
    COMMAND ${Python3_EXECUTABLE} ${MACRO_SCRIPT} ${COMPILE_COMMANDS_JSON} ${SSH_SERVER_FILE} ${SSH_CLIENT_FILE} ${MQTT_CLIENT_FILE}
    DEPENDS ${COMPILE_COMMANDS_JSON} ${MACRO_SCRIPT}
    COMMENT "Extracting macros from compile_commands.json"
)

# Custom target to run the script
add_custom_target(generate_macros_header ALL
    DEPENDS ${SSH_SERVER_HEADER} ${SSH_CLIENT_HEADER} ${MQTT_CLIENT_HEADER}
)
