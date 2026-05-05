########################################################################
# CMake build script for Mocana moctee tools
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG                   "Enable Debug logs." OFF)
option(CM_ENABLE_TAP                     "Enable tap ." OFF)
option(CM_ENABLE_TAP_LOCAL               "Enable tap local." OFF)
option(CM_ENABLE_TAP_REMOTE              "Enable tap remote." OFF)
option(CM_BUILD_X32       "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64       "Build for 64Bit Machine." OFF)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

include(MocPlatform)

project (moctee_tools C)

include(cmakeflags.txt)
include(cmakefunctions.txt)
include(locate_lib)

# Make sure we do not have conflicting options in affect
if(CM_ENABLE_TAP_REMOTE AND CM_ENABLE_TAP_LOCAL)
        message(FATAL_ERROR "Only one of TAP Local or TAP Remote must be enabled")
endif()

if(NOT CM_ENABLE_TAP_REMOTE AND NOT CM_ENABLE_TAP_LOCAL)
        message(FATAL_ERROR "At least one of TAP Local or TAP Remote must be enabled")
endif()

#set(CMAKE_VERBOSE_MAKEFILE "ON")

# MSS_BIN_DIR is only used for where the executables go, so keep it to bin
if(BUILD_FOR_OSI)
  set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
else()
  if(WIN32)
    set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32")
  else()
    set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
  endif()
endif()

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
set(CMAKE_INSTALL_RPATH "${MSS_BIN_DIR}")

set(LIB_TYPE "SHARED" CACHE STRING "Which lib type to build: SHARED (default) or STATIC")
message("LIB_TYPE           = ${LIB_TYPE}")

message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")

set(MOCTEE_TOOLS_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${MOCTEE_TOOLS_BUILD_DIR}/libs")
set(CMAKE_BINARY_DIRECTORY "${MOCTEE_TOOLS_BUILD_DIR}")
set(MSS_DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

if(NOT EXISTS ${MSS_DEFS_FILE})
    message(FATAL_ERROR "\nMSS_DEFS_FILE = ${MSS_DEFS_FILE} does not exist")
endif()

message("\nMSS_DEFS_FILE = ${MSS_DEFS_FILE}")
include(${MSS_DEFS_FILE})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

locate_lib(COMMON_LIB common)
locate_lib(PLATFORM_LIB platform)
locate_lib(ASN1_LIB asn1)
locate_lib(INITIALIZE_LIB initialize)
locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
locate_lib(NANOCRYPTO_LIB nanocrypto)
locate_lib(NANOCERT_LIB nanocert)
locate_lib(NANOCAP_LIB nanocap)
locate_lib(SMPTEE_LIB smptee)
locate_lib(SMPTPM2_LIB smptpm2)
locate_lib(TPM2_LIB tpm2)
locate_lib(NANOSSL_LIB nanossl)
locate_lib(NANOTAP2_LIB nanotap2)
locate_lib(NANOTAP2_COMMON_LIB nanotap2_common)
locate_lib(NANOTAP2_CLIENTCOMM_LIB nanotap2_clientcomm)
locate_lib(NANOTAP2_CONFIGPARSER_LIB nanotap2_configparser)
locate_lib(TEEC teec)

set(libraryLists ${COMMON_LIB} ${PLATFORM_LIB}
	${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB} ${NANOTAP2_CLIENTCOMM_LIB} ${NANOTAP2_CONFIGPARSER_LIB} ${SMPTEE_LIB} ${SMPTPM2_LIB} ${TPM2_LIB} ${ASN1_LIB} ${INITIALIZE_LIB} ${NANOCERT_LIB} ${CRYPTOINTERFACE_LIB} ${NANOCRYPTO_LIB} ${NANOCAP_LIB} ${TEEC})
set( libraryLists ${libraryLists} ${NANOSSL_LIB})

if(CM_ENABLE_HW_ACCEL)
    set( libraryLists ${libraryLists} ${HW_ACCEL_LIB})
endif()

########################################################################
# moctee_setpolicystorage
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/moctee_setpolicystorage")
set(TARGET_NAME moctee_setpolicystorage)
set(MOCANA_FLAGS "")
build_moctee_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTEE_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# moctee_delpolicystorage
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/moctee_delpolicystorage")
set(TARGET_NAME moctee_delpolicystorage)
set(MOCANA_FLAGS "")
build_moctee_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTEE_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# moctee_getpolicystorage
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/moctee_getpolicystorage")
set(TARGET_NAME moctee_getpolicystorage)
set(MOCANA_FLAGS "")
build_moctee_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTEE_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})
