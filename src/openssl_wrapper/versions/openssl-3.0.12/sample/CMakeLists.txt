########################################################################
# CMake build script for DigiCert Common Library
#

cmake_minimum_required(VERSION 3.5)

option(CM_ENABLE_TAP "" OFF)
option(CM_ENABLE_TAP_LOCAL "" OFF)
option(CM_ENABLE_TAP_REMOTE "" OFF)
option(CM_ENABLE_TAP_EXTERN "" OFF)
option(CM_ENABLE_FIPS "" OFF)
option(CM_ENABLE_MAUTH "" OFF)
option(CM_ENABLE_ALL_ALGOS "" OFF)
option(CM_ENABLE_REHANDSHAKE "" OFF)
option(CM_ENABLE_SENDQUIT "" OFF)
option(CM_ENABLE_ALERTCB "" OFF)
option(CM_ENABLE_PEM_READ "" OFF)
option(CM_ENABLE_POSTHANDSHAKE_AUTH "" OFF)
option(CM_ENABLE_KEY_UPDATE "" OFF)
option(CM_ENABLE_PSK "" OFF)
option(CM_ENABLE_0RTT "" OFF)
option(CM_BUILD_X32    "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64    "Build for 64Bit Machine." OFF)
if (WIN32)
    option(CM_WIN_FORCE_LINKAGE "Force linkage for shared library." OFF)
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../../projects/shared_cmake)

# Include cross-compile options/flags
include(MocPlatform)
include(locate_lib)

project(openssl_connector C)

include(build_rc_file)

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
get_filename_component(MSS_DIR "${MSS_DIR}" ABSOLUTE)
set(MSS_SRC_DIR "${MSS_DIR}/src")

set(LIB_TYPE "SHARED" CACHE STRING "Type of library to build. (SHARED or STATIC)")
message("LIB_TYPE           = ${LIB_TYPE}")

message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")

set(BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIR}/libs")
set(CMAKE_BINARY_DIR "${BUILD_DIR}")
set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

message("BUILD_DIR = ${BUILD_DIR}")

if(NOT EXISTS ${DEFS_FILE})
  message(FATAL_ERROR "\nDEFS_FILE = ${DEFS_FILE} does not exist")
endif()

message("\nDEFS_FILE = ${DEFS_FILE}")
include(${DEFS_FILE})

# Initializing common flags

set(MOCANA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")
message("\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE}")

########################################################################
#
# MOCANA FLAGS
#
########################################################################

#file(STRINGS ${MOCANA_FLAGS_FILE} mocana_flags)
if(WIN32)
  set(mocana_flags ${mocana_flags} "-DWIN32_LEAN_AND_MEAN")
endif()

if(CM_ENABLE_TAP)
  set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_TAP__" "-D__ENABLE_DIGICERT_CRYPTO_INTERFACE__")
endif()

if(CM_ENABLE_TAP_REMOTE)
  set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_TAP_REMOTE__")
endif()

if(CM_ENABLE_TAP_EXTERN)
  set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_TAP_EXTERN__")
endif()

if(CM_ENABLE_FIPS)
  set(mocana_flags ${mocana_flags} "-D__EVP_NAMESPACE_CONFLICT__")
endif()

if(CM_ENABLE_MAUTH)
  set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__")
endif()

if(CM_ENABLE_ALL_ALGOS)
  set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_OSSL_LOAD_ALL_ALGORITHMS__")
endif()

if(CM_ENABLE_REHANDSHAKE)
  set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_SSL_REHANDSHAKE__")
endif()

if(CM_ENABLE_SENDQUIT)
  set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_SSL_SEND_QUIT_CMD__")
endif()

if(CM_ENABLE_ALERTCB)
  set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_SSL_ALERT_CALLBACK_SUPPORT__")
endif()

if(CM_ENABLE_PEM_READ)
  set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_PEM_READ_BIO_PRIVATE_KEY__")
endif()

if(CM_ENABLE_POSTHANDSHAKE_AUTH)
  set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__")
endif()

if(CM_ENABLE_KEY_UPDATE)
  set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_TLS13_KEYUPDATE__")
endif()

if(CM_ENABLE_PSK)
  set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_TLS13_PSK__")
endif()

if(CM_ENABLE_0RTT)
  set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_TLS13_0RTT__")
endif()

# Now load all flags into MOCANA_FLAGS
foreach(flag ${mocana_flags})
  string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

# Load the flags into the build
message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
add_definitions("${MOCANA_FLAGS}")

# Load the EXTRA_DEFINITIONS flags (from mss_defs.cmake) into the build
message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")
add_definitions("${EXTRA_DEFINITIONS}")

########################################################################
#
# MOCANA INCLUDES
#
########################################################################

set(MSS_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/.."
                 "${CMAKE_CURRENT_SOURCE_DIR}/../include")

if(CM_ENABLE_TAP)
  set(MSS_INCLUDES ${MSS_INCLUDES}
                   "${MSS_SRC_DIR}")
endif()

include_directories("." ${MSS_INCLUDES})

message("\nopenssl_connector includes")
message("----------------")
foreach(dir ${MSS_INCLUDES})
  message(${dir})
endforeach()

########################################################################
#
# MOCANA SOURCES
#
########################################################################

# Set Windows file properties
# if(WIN32)
#   build_rc_file("TrustPoint Shared Library")
#   set(MSS_SOURCES ${MSS_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
# endif()

# message("\nmss sources")
# message("-----------")
# foreach(file ${MSS_SOURCES})
#   message(${file})
# endforeach()

if(WIN32)
  link_directories(${MSS_SRC_DIR}/../bin_win32)
else()
  link_directories(${MSS_SRC_DIR}/../bin)
endif()

# Define build targets
add_executable(openssl_client
               ${CMAKE_CURRENT_SOURCE_DIR}/openssl_client.c)

add_executable(openssl_server
               ${CMAKE_CURRENT_SOURCE_DIR}/openssl_server.c
               ${CMAKE_CURRENT_SOURCE_DIR}/ossl_sample_utils.c)
target_compile_definitions(openssl_server PRIVATE
                           "-DOPENSSL_ENGINE")

add_executable(openssl_client_tpm
               ${CMAKE_CURRENT_SOURCE_DIR}/openssl_client_tpm.c)
target_compile_definitions(openssl_client_tpm PRIVATE
                           "-DOPENSSL_ENGINE"
                           "-D__ENABLE_DIGICERT_HW_SECURITY_MODULE__"
                           "-D__ENABLE_DIGICERT_TPM__")

add_executable(openssl_client_local
               ${CMAKE_CURRENT_SOURCE_DIR}/openssl_client_local.c
               ${CMAKE_CURRENT_SOURCE_DIR}/ossl_sample_utils.c)

add_executable(openssl_dtls_client
               ${CMAKE_CURRENT_SOURCE_DIR}/openssl_dtls_client.c
               ${CMAKE_CURRENT_SOURCE_DIR}/ossl_sample_utils.c)

add_executable(openssl_client_tap
              ${CMAKE_CURRENT_SOURCE_DIR}/openssl_client_tap.c
              ${CMAKE_CURRENT_SOURCE_DIR}/ossl_sample_utils.c)
target_compile_definitions(openssl_client_tap PRIVATE
                           "-DOPENSSL_ENGINE")

add_executable(openssl_dtls_server
               ${CMAKE_CURRENT_SOURCE_DIR}/openssl_dtls_server.c
               ${CMAKE_CURRENT_SOURCE_DIR}/ossl_sample_utils.c)

# Create 'all_sw' target
add_custom_target(all_sw
                  DEPENDS openssl_client openssl_dtls_client openssl_dtls_server openssl_client_local)

# Dependent libraries
locate_lib(OSSL_SHIM_LIB openssl_shim)
locate_lib(NANOSSL_LIB nanossl)
locate_lib(COMMON_LIB common)
locate_lib(PLATFORM_LIB platform)
if(WIN32)
  locate_lib(CRYPTO_LIB libcrypto)
  locate_lib(SSL_LIB libssl)
else()
  locate_lib(CRYPTO_LIB crypto)
  locate_lib(SSL_LIB ssl)
endif()

set(LIB_LINK_ORDER
    ${COMMON_LIB}
    ${PLATFORM_LIB}
    ${OSSL_SHIM_LIB}
    ${NANOSSL_LIB}
    ${CRYPTO_LIB}
    ${SSL_LIB}
    ${NCRYPTO_LIB})

if(CM_ENABLE_FIPS)
  locate_lib(MSS_LIB libmss)
  set(LIB_LINK_ORDER
      ${LIB_LINK_ORDER}
      ${MSS_LIB})
endif()

if(CM_ENABLE_TAP)
  locate_lib(NANOTAP2_LIB nanotap2)
  locate_lib(NANOTAP2_COMMON_LIB nanotap2_common)
  locate_lib(TPM2_LIB tpm2)
  locate_lib(SMPTPM2_LIB smptpm2)
  locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
  set(LIB_LINK_ORDER
      ${LIB_LINK_ORDER}
      ${NANOTAP2_LIB}
      ${NANOTAP2_COMMON_LIB}
      ${TPM2_LIB}
      ${SMPTPM2_LIB}
      ${CRYPTOINTERFACE_LIB})
endif()

if(CM_ENABLE_TAP_REMOTE)
  locate_lib(NANOTAP2_CLIENTCOMM_LIB nanotap2_clientcomm)
  set(LIB_LINK_ORDER
      ${LIB_LINK_ORDER}
      ${NANOTAP2_CLIENTCOMM_LIB})
endif()

if(WIN32)
  set(LIB_LINK_ORDER
      ${LIB_LINK_ORDER}
      Ws2_32.lib
      Shlwapi.lib)
endif()

target_link_libraries(openssl_client ${LIB_LINK_ORDER})
target_link_libraries(openssl_server ${LIB_LINK_ORDER})
target_link_libraries(openssl_client_tpm ${LIB_LINK_ORDER})
target_link_libraries(openssl_client_local ${LIB_LINK_ORDER})
target_link_libraries(openssl_client_tap ${LIB_LINK_ORDER})
target_link_libraries(openssl_dtls_client ${LIB_LINK_ORDER})
target_link_libraries(openssl_dtls_server ${LIB_LINK_ORDER})

if(WIN32)

    # Since it's hard to know where visual studio will place the bins, just
    # move the bins from sample through cmake. Some builds use hardcoded paths
    # to find files so they must be run from the sample directory.
    macro(move_to_sample_dir t_name)
      add_custom_command(
          TARGET ${t_name}
          POST_BUILD
          COMMAND ${CMAKE_COMMAND} -E copy_directory
              $<TARGET_FILE_DIR:${t_name}>
              ${MSS_DIR}/bin_win32)
    endmacro()

    move_to_sample_dir(openssl_client)
    move_to_sample_dir(openssl_server)
    move_to_sample_dir(openssl_client_tpm)
    move_to_sample_dir(openssl_client_local)
    move_to_sample_dir(openssl_client_tap)
    move_to_sample_dir(openssl_dtls_client)
    move_to_sample_dir(openssl_dtls_server)
endif()
