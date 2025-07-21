########################################################################
# CMake build script for NanoSSH Libraries
#########################################################################

cmake_minimum_required(VERSION 3.16)

project(NanoSSH LANGUAGES C CXX)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

option(WITH_LOGGING "Build with logging enabled." OFF)
option(DISABLE_SSH_CLIENT "Build SSH Client." OFF)
option(DISABLE_SSH_SERVER "Build SSH Server." OFF)
option(ENABLE_SSH_SERVER_CERT_AUTH "Enable SSH Server certificate authentication." OFF)
option(ENABLE_SSH_CLIENT_CERT_AUTH "Enable SSH Client certificate authentication." OFF)
option(ENABLE_SSH_ASYNC_API_SUPPORT "Enable SSH Async API support." OFF)
option(ENABLE_SSH_CLIENT_SHELL_EXAMPLE "Build SSH client shell example." OFF)
option(BUILD_SAMPLES "Build samples." OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL "Compile commands for auto generated header" FORCE)
set(CM_BUILD_SHARED_LIBS ON CACHE BOOL "Build NanoSSH Shared Library" FORCE)
set(CM_ENABLE_DEBUG ${WITH_LOGGING} CACHE BOOL "Build with logging enabled." FORCE)
set(MACRO_SCRIPT ${CMAKE_SOURCE_DIR}/scripts/extract_define.py)
set(COMPILE_COMMANDS_JSON ${CMAKE_BINARY_DIR}/compile_commands.json)
set(MOPTIONS_CUSTOM_SSH_SERVER_FILE ${CMAKE_SOURCE_DIR}/src/common/moptions_custom_ssh_server.h)
set(MOPTIONS_CUSTOM_SSH_CLIENT_FILE ${CMAKE_SOURCE_DIR}/src/common/moptions_custom_ssh_client.h)

add_subdirectory(projects/platform)
add_subdirectory(projects/common)
add_subdirectory(projects/asn1)
add_subdirectory(projects/initialize)

set(CM_ENABLE_SERVER_CERT_AUTH ${ENABLE_SSH_SERVER_CERT_AUTH} CACHE BOOL "Enable SSH server certificate authentication" FORCE)
set(CM_ENABLE_CLIENT_CERT_AUTH ${ENABLE_SSH_CLIENT_CERT_AUTH} CACHE BOOL "Enable SSH client certificate authentication" FORCE)

if(CM_ENABLE_SERVER_CERT_AUTH OR CM_ENABLE_CLIENT_CERT_AUTH)
  set(CM_ENABLE_X509_CERTS ON CACHE BOOL "Enable X.509 certificates support" FORCE)
endif()

set(CLIENT_HEADER "")
set(CLIENT_FILE ${CMAKE_BINARY_DIR}/client_macros.h)
if(NOT DISABLE_SSH_CLIENT)
  set(CLIENT_HEADER ${CLIENT_FILE})

  add_custom_target(overwrite_for_client
    COMMAND ${CMAKE_COMMAND} -E copy ${CLIENT_HEADER} ${MOPTIONS_CUSTOM_SSH_CLIENT_FILE}
    DEPENDS ${CLIENT_HEADER} ${CMAKE_SOURCE_DIR}/lib/libnanosshc.so
  )
  set(CM_BUILD_SSH_SERVER OFF CACHE BOOL "Build SSH Server" FORCE)
  set(CM_BUILD_SSH_CLIENT ON  CACHE BOOL "Build SSH Client" FORCE)
  add_subdirectory(projects/nanossh ${CMAKE_BINARY_DIR}/projects/nanossh/ssh_client)
endif()

set(SERVER_HEADER "")
set(SERVER_FILE ${CMAKE_BINARY_DIR}/server_macros.h)
if(NOT DISABLE_SSH_SERVER)
  set(SERVER_HEADER ${SERVER_FILE})

  # first header is server
  add_custom_target(overwrite_for_server
    COMMAND ${CMAKE_COMMAND} -E copy ${SERVER_HEADER} ${MOPTIONS_CUSTOM_SSH_SERVER_FILE}
    DEPENDS ${SERVER_HEADER} ${CMAKE_SOURCE_DIR}/lib/libnanosshs.so
  )

  set(CM_BUILD_SSH_SERVER ON  CACHE BOOL "Build SSH Server" FORCE)
  set(CM_BUILD_SSH_CLIENT OFF CACHE BOOL "Build SSH Client" FORCE)
  add_subdirectory(projects/nanossh ${CMAKE_BINARY_DIR}/projects/nanossh/ssh_server)
endif()

# Samples must be build after the project libraries
if(NOT DISABLE_SSH_CLIENT)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/ssh_client)
    add_dependencies(ssh_client overwrite_for_client)
    target_compile_definitions(ssh_client PUBLIC -DMOPTIONS_CUSTOM_HEADER="${MOPTIONS_CUSTOM_SSH_CLIENT_FILE}")
  endif()
endif()

if(NOT DISABLE_SSH_SERVER)
  if(BUILD_SAMPLES)
    add_subdirectory(samples/ssh_server)
    add_dependencies(ssh_server overwrite_for_server)
    target_compile_definitions(ssh_server PUBLIC -DMOPTIONS_CUSTOM_HEADER="${MOPTIONS_CUSTOM_SSH_SERVER_FILE}")
  endif()
endif()

# generate both client and server macro headers
add_custom_command(
    OUTPUT ${SERVER_HEADER} ${CLIENT_HEADER}
    COMMAND ${CMAKE_COMMAND} -E echo "Generating ${SERVER_HEADER} from compile_commands.json"
    COMMAND ${Python3_EXECUTABLE} ${MACRO_SCRIPT} ${COMPILE_COMMANDS_JSON} ${SERVER_FILE} ${CLIENT_FILE}
    DEPENDS ${COMPILE_COMMANDS_JSON} ${MACRO_SCRIPT}
    COMMENT "Extracting macros from compile_commands.json"
)

# Custom target to run the script
add_custom_target(generate_macros_header ALL
    DEPENDS ${SERVER_HEADER} ${CLIENT_HEADER}
)
