########################################################################
# CMake build script for Digicert digicert_tpm2 tools
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
option(CM_BUILD_X32       "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64       "Build for 64Bit Machine." OFF)
option(CM_ENABLE_HW_ACCEL "Build with hw-accel library." OFF)
option(CM_ENABLE_STRIP    "Strip symbols." OFF)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

include(MocPlatform)

project (digicert_tpm2_tools C)

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

if("STATIC" STREQUAL "${LIB_TYPE}" AND NOT BUILD_FOR_OSI)
  set(LINK_LIBS_IN_BIN_STATIC "ON")
endif()

message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")

set(MOCTPM2_TOOLS_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${MOCTPM2_TOOLS_BUILD_DIR}/libs")
set(CMAKE_BINARY_DIRECTORY "${MOCTPM2_TOOLS_BUILD_DIR}")
set(MSS_DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

if(NOT EXISTS ${MSS_DEFS_FILE})
    message(FATAL_ERROR "\nMSS_DEFS_FILE = ${MSS_DEFS_FILE} does not exist")
endif()

message("\nMSS_DEFS_FILE = ${MSS_DEFS_FILE}")
include(${MSS_DEFS_FILE})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
if(CM_ENABLE_STRIP)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s")
endif()

locate_lib(INITIALIZE_LIB initialize)
locate_lib(COMMON_LIB common)
locate_lib(PLATFORM_LIB platform)
if(CM_DATA_PROTECT)
  locate_lib(DP_LIB dataprotect)
endif()
if(CM_ENABLE_TAP_REMOTE)
  locate_lib(NANOSSL_LIB nanossl)
endif()
locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
locate_lib(NANOTAP2_LIB nanotap2)
locate_lib(NANOTAP2_COMMON_LIB nanotap2_common)
locate_lib(NANOCERT_LIB nanocert)
if(CM_ENABLE_HW_ACCEL)
  locate_lib(HW_ACCEL_LIB hw)
endif()

if("STATIC" STREQUAL "${LIB_TYPE}")
  locate_lib(NANOCRYPTO_LIB nanocrypto)
  locate_lib(LIBNANOCAP_LIB nanocap)
  locate_lib(LIBASN1_LIB asn1)
  locate_lib(TPM_LIB tpm2)
  locate_lib(CERTENROLL_LIB cert_enroll)
  locate_lib(SMPTPM2_LIB smptpm2)
endif()

set(libraryLists ${INITIALIZE_LIB} ${COMMON_LIB} ${PLATFORM_LIB} ${CRYPTOINTERFACE_LIB}
        ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB} ${NANOCERT_LIB})
if("STATIC" STREQUAL "${LIB_TYPE}")
  set(libraryLists ${libraryLists} ${NANOCRYPTO_LIB} ${LIBNANOCAP_LIB} ${LIBASN1_LIB} ${TPM_LIB} ${CERTENROLL_LIB} ${SMPTPM2_LIB})
  set(libraryLists "-Wl,--whole-archive" ${libraryLists} "-Wl,--no-whole-archive")
endif()
if(CM_DATA_PROTECT)
  set(libraryLists ${libraryLists} ${DP_LIB})
endif()
if (CM_ENABLE_TAP_REMOTE)
    set( libraryLists ${libraryLists} ${NANOSSL_LIB})
endif()
if(CM_ENABLE_HW_ACCEL)
    set( libraryLists ${libraryLists} ${HW_ACCEL_LIB})
endif()

########################################################################
# digicert_tpm2_version
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_version")
set(TARGET_NAME digicert_tpm2_version)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_createasymkey
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_createasymkey")
set(TARGET_NAME digicert_tpm2_createasymkey)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_getquote
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_getquote")
set(TARGET_NAME digicert_tpm2_getquote)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})


########################################################################
# digicert_tpm2_sealdata
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_sealdata")
set(TARGET_NAME digicert_tpm2_sealdata)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})


########################################################################
# digicert_tpm2_createpolicystorage
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_createpolicystorage")
set(TARGET_NAME digicert_tpm2_createpolicystorage)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_getrandom
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_getrandom")
set(TARGET_NAME digicert_tpm2_getrandom)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_selftest
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_selftest")
set(TARGET_NAME digicert_tpm2_selftest)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_createsymkey
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_createsymkey")
set(TARGET_NAME digicert_tpm2_createsymkey)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_gettrusteddata
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_gettrusteddata")
set(TARGET_NAME digicert_tpm2_gettrusteddata)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_setpolicystorage
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_setpolicystorage")
set(TARGET_NAME digicert_tpm2_setpolicystorage)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_decrypt
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_decrypt")
set(TARGET_NAME digicert_tpm2_decrypt)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_importduplicatekey
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_importduplicatekey")
set(TARGET_NAME digicert_tpm2_importduplicatekey)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_sign
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_sign")
set(TARGET_NAME digicert_tpm2_sign)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_delpolicystorage
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_delpolicystorage")
set(TARGET_NAME digicert_tpm2_delpolicystorage)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_stirrandom
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_stirrandom")
set(TARGET_NAME digicert_tpm2_stirrandom)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_duplicatekey
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_duplicatekey")
set(TARGET_NAME digicert_tpm2_duplicatekey)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_unsealdata
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_unsealdata")
set(TARGET_NAME digicert_tpm2_unsealdata)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_encrypt
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_encrypt")
set(TARGET_NAME digicert_tpm2_encrypt)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_updatetrusteddata
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_updatetrusteddata")
set(TARGET_NAME digicert_tpm2_updatetrusteddata)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_getcapability
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_getcapability")
set(TARGET_NAME digicert_tpm2_getcapability)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_verify
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_verify")
set(TARGET_NAME digicert_tpm2_verify)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_getpolicystorage
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_getpolicystorage")
set(TARGET_NAME digicert_tpm2_getpolicystorage)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_readpubek
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_readpubek")
set(TARGET_NAME digicert_tpm2_readpubek)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_verifyquote
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_verifyquote")
set(TARGET_NAME digicert_tpm2_verifyquote)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_getpolicystoragelist
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_getpolicystoragelist")
set(TARGET_NAME digicert_tpm2_getpolicystoragelist)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_readpublickeyblob
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_readpublickeyblob")
set(TARGET_NAME digicert_tpm2_readpublickeyblob)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# Provisioning tools use tpm2 library
########################################################################
if(NOT "STATIC" STREQUAL "${LIB_TYPE}")
  set (libraryLists ${libraryLists} tpm2)
endif()

########################################################################
# digicert_tpm2_takeownership
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_takeownership")
set(TARGET_NAME digicert_tpm2_takeownership)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_provision
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_provision")
set(TARGET_NAME digicert_tpm2_provision)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_resetdalock
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_resetdalock")
set(TARGET_NAME digicert_tpm2_resetdalock)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

if(NOT "STATIC" STREQUAL "${LIB_TYPE}")
  set (libraryLists ${libraryLists} smptpm2 tpm2)
endif()

########################################################################
# smp_tpm2_getidstr_bin
########################################################################
if(WIN32)
  set (libraryLists ${libraryLists} Shlwapi)
endif()
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/smp_tpm2_getidstr_bin")
set(TARGET_NAME smp_tpm2_getidstr_bin)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_evictkeyobject
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_evictkeyobject")
set(TARGET_NAME digicert_tpm2_evictkeyobject)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_persistkeyobject
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_persistkeyobject")
set(TARGET_NAME digicert_tpm2_persistkeyobject)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})

########################################################################
# digicert_tpm2_getpersistedkeyobject
########################################################################
set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/digicert_tpm2_getpersistedkeyobject")
set(TARGET_NAME digicert_tpm2_getpersistedkeyobject)
set(MOCANA_FLAGS "")
build_digicert_tpm2_tool(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${EXTRA_DEFINITIONS} ${MSS_SRC_DIR} ${MOCTPM2_TOOLS_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})




