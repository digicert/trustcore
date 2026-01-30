########################################################################
# CMake build script for Mocana smp_pkcs11 SHARED LIBRARY FOR NanoSMP
#

if(BUILD_FOR_OSI)
    cmake_minimum_required(VERSION 3.16)
else()
    cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
option(CM_DISABLE_SUITEB "Disable suiteb." OFF)
option(CM_ENABLE_SOFTHSM "Enable softhsm lib ." OFF)
option(CM_ENABLE_CLOUDHSM "Enable cloudhsm lib ." OFF)
option(CM_ENABLE_PKCS11_TEE "Enable pkcs11 tee lib ." OFF)
option(CM_ENABLE_DSSM "Enable ssm lib ." OFF)
option(CM_ENABLE_DYNAMIC_LOAD "Enable dynamic library loading." OFF)
option(CM_ENABLE_PKCS11_TOOLS "Enable support for pkcs11 tools ." OFF)

include(cmakeflags.txt)

# Make sure we do not have conflicting options in affect
if(CM_ENABLE_TAP_REMOTE AND CM_ENABLE_TAP_LOCAL)
    message(FATAL_ERROR "Either TAP Local or TAP Remote must be enabled")
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

include(MocPlatform)
include(locate_lib)
include(build_library)

project (smppkcs11 C)

if(WIN32)
    set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32")
else()
    if("STATIC" STREQUAL "${LIB_TYPE}")
        set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_static")
    else()
        set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
    endif()
endif()

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../bin)

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
if(BUILD_FOR_OSI)
  set(LIB_DIR "${MSS_DIR}/lib")
  set(MSS_BIN_DIR "${LIB_DIR}")
endif()
set(CMAKE_INSTALL_RPATH "${MSS_BIN_DIR}")

set(LIB_TYPE "SHARED" CACHE STRING "Which lib type to build: SHARED (default) or STATIC")
message("LIB_TYPE           = ${LIB_TYPE}")

message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")

#set(CMAKE_MAKE_PROGRAM "/usr/local/bin/cmake")
if("STATIC" STREQUAL "${LIB_TYPE}")
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
set(SMP_PKCS11_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${SMP_PKCS11_BUILD_DIR}/libs")
if(NOT WIN32)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${SMP_PKCS11_BUILD_DIR}/libs")
endif()
set(CMAKE_BINARY_DIRECTORY "${SMP_PKCS11_BUILD_DIR}")
set(SMP_PKCS11_DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

if(NOT EXISTS ${SMP_PKCS11_DEFS_FILE})
    message(FATAL_ERROR "\nSMP_PKCS11_DEFS_FILE = ${SMP_PKCS11_DEFS_FILE} does not exist")
endif()

message("\nSMP_PKCS11_DEFS_FILE = ${SMP_PKCS11_DEFS_FILE}")
include(${SMP_PKCS11_DEFS_FILE})

set(LIB_SUFFIX "a")
if("SHARED" STREQUAL "${LIB_TYPE}")
    set(LIB_SUFFIX "so")
    if(APPLE)
        set(LIB_SUFFIX "dylib")
    endif()
endif()

########################################################################
# Mocana smp pkcs11 SHARED LIBRARY building
########################################################################

set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
message("TARGET_DIR = ${TARGET_DIR}")

set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt")
set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt")

set(TARGET_NAME smppkcs11)

set(MOCANA_FLAGS "")
init_flags()
buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)

if(CM_ENABLE_PKCS11_TOOLS)
    string(STRIP "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_PKCS11_SMP_TOOLS__" MOCANA_FLAGS)
endif()

if(CM_ENABLE_DYNAMIC_LOAD)
    string(STRIP "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__" MOCANA_FLAGS)
endif()

if("SHARED" STREQUAL "${LIB_TYPE}")
    if(BUILD_FOR_OSI)
        set(TPM2_LIB "${LIB_DIR}/libtpm2.so")
    else()
        locate_lib(TPM2_LIB tpm2)
    endif()
    set(libraryLists ${TPM2_LIB})

    if(CM_ENABLE_SOFTHSM)
        set(libraryLists ${libraryLists} softhsm2)
    endif()

    if(CM_ENABLE_CLOUDHSM)
        set(libraryLists ${libraryLists} cloudhsm_pkcs11)
    endif()

    if(CM_ENABLE_DSSM)
        set(libraryLists ${libraryLists} smpkcs11)
    endif()

    if(CM_ENABLE_PKCS11_TEE)
        set(libraryLists ${libraryLists} ckteec)
        set(libraryLists ${libraryLists} teec)
        string(STRIP "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_PKCS11_TEE__" MOCANA_FLAGS)
    endif()
else()
    set(libraryLists "")
endif()

message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "")

buildLibrary(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
            ${SMP_PKCS11_BUILD_DIR} ${MSS_BIN_DIR}  ${libraryLists})
# adding mocana flags
target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
