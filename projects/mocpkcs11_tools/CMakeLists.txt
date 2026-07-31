########################################################################
# CMake build script for Mocana mocpkcs11 tools
#
if(BUILD_FOR_OSI)
    cmake_minimum_required(VERSION 3.16)
else()
    cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG                   "Enable Debug logs." OFF)
option(CM_ENABLE_TAP                     "Enable tap ." OFF)
option(CM_DATA_PROTECT                   "Enable data protect ." OFF)
option(CM_ENABLE_TAP_LOCAL               "Enable tap local." OFF)
option(CM_ENABLE_TAP_REMOTE              "Enable tap remote." OFF)
option(CM_ENABLE_DYNAMIC_LOAD            "Enable dynamic library loading." OFF)
option(CM_ENABLE_SOFTHSM                 "Enable softhsm lib ." OFF)
option(CM_ENABLE_CLOUDHSM                "Enable cloudhsm lib ." OFF)
option(CM_ENABLE_PKCS11_TEE              "Enable tee pkcs11 lib ." OFF)
option(CM_ENABLE_DSSM                    "Enable Digicert ssm lib ." OFF)
option(CM_BUILD_X32                      "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64                      "Build for 64Bit Machine." OFF)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

include(MocPlatform)

project (mocpkcs11_tools C)

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

set(MOCPKCS11_TOOLS_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${MOCPKCS11_TOOLS_BUILD_DIR}/libs")
set(CMAKE_BINARY_DIRECTORY "${MOCPKCS11_TOOLS_BUILD_DIR}")
set(MSS_DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

if(NOT EXISTS ${MSS_DEFS_FILE})
    message(FATAL_ERROR "\nMSS_DEFS_FILE = ${MSS_DEFS_FILE} does not exist")
endif()

message("\nMSS_DEFS_FILE = ${MSS_DEFS_FILE}")
include(${MSS_DEFS_FILE})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

locate_lib(INITIALIZE_LIB initialize)
locate_lib(COMMON_LIB common)
locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
locate_lib(NANOCERT_LIB nanocert)
locate_lib(NANOTAP2_LIB nanotap2)
locate_lib(NANOTAP2_COMMON_LIB nanotap2_common)
locate_lib(SMPPKCS11_LIB smppkcs11)

set(libraryLists ${INITIALIZE_LIB} ${COMMON_LIB} ${CRYPTOINTERFACE_LIB}
                 ${NANOCERT_LIB} ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB} ${SMPPKCS11_LIB})

if(CM_DATA_PROTECT)
  locate_lib(DP_LIB dataprotect)
  set(libraryLists ${libraryLists} ${DP_LIB})
endif()

if(WIN32)
  set(libraryLists ${libraryLists} Shlwapi)
endif()

if(CM_ENABLE_SOFTHSM)
  locate_lib(SOFTHSM2_LIB softhsm2)
  set(libraryLists ${libraryLists} ${SOFTHSM2_LIB})
endif()

if(CM_ENABLE_DSSM)
  locate_lib(SMPKCS11_LIB smpkcs11)
  set(libraryLists ${libraryLists} ${SMPKCS11_LIB})
endif()

if(CM_ENABLE_CLOUDHSM)
  locate_lib(CLOUDHSM_LIB cloudhsm_pkcs11)
  set(libraryLists ${libraryLists} ${CLOUDHSM_LIB})
endif()

if(CM_ENABLE_PKCS11_TEE)
  locate_lib(CKTEEC_LIB ckteec)
  locate_lib(TEEC_LIB teec)
  set(libraryLists ${libraryLists} ${CKTEEC_LIB})
  set(libraryLists ${libraryLists} ${TEEC_LIB})
endif()

########################################################################
# mocpkcs11_keygen
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mocpkcs11_keygen")
set(TARGET_NAME mocpkcs11_keygen)
set(MOCANA_FLAGS "")
build_mocpkcs11_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCPKCS11_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# mocpkcs11_serializekey
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mocpkcs11_serializekey")
set(TARGET_NAME mocpkcs11_serializekey)
set(MOCANA_FLAGS "")
build_mocpkcs11_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCPKCS11_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# mocpkcs11_deletekey
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mocpkcs11_deletekey")
set(TARGET_NAME mocpkcs11_deletekey)
set(MOCANA_FLAGS "")
build_mocpkcs11_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCPKCS11_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# mocpkcs11_listallkeys
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mocpkcs11_listallkeys")
set(TARGET_NAME mocpkcs11_listallkeys)
set(MOCANA_FLAGS "")
build_mocpkcs11_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCPKCS11_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# smp_pkcs11_getmoduleidstr_bin
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/smp_pkcs11_getmoduleidstr_bin")
set(TARGET_NAME smp_pkcs11_getmoduleidstr_bin)
set(MOCANA_FLAGS "")
build_mocpkcs11_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCPKCS11_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# smp_pkcs11_getslotdesc_bin
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/smp_pkcs11_getslotdesc_bin")
set(TARGET_NAME smp_pkcs11_getslotdesc_bin)
set(MOCANA_FLAGS "")
build_mocpkcs11_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCPKCS11_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

