########################################################################
# CMake build script for DigiCert smpnanoroot Library
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
option(CM_DISABLE_SUITEB "Disable suiteb." OFF)
if (DEFINED SECURE_PATH)
option(CM_ENABLE_ABSOLUTE_PATH                      "Enable absolute path support." ON)
else()
option(CM_ENABLE_ABSOLUTE_PATH                      "Enable absolute path support." OFF)
endif()

include(cmakeflags.txt)

# Make sure we do not have conflicting options in affect
if(CM_ENABLE_TAP_REMOTE)
    message(FATAL_ERROR "TAP Remote must not be enabled")
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

include(MocPlatform)
include(locate_lib)
include(build_library)

project (smpnanoroot C)

#set(CMAKE_VERBOSE_MAKEFILE "ON")

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
if(BUILD_FOR_OSI)
  set(LIB_DIR  "${MSS_DIR}/lib")
else()
  set(LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
endif()

link_directories(${LIB_DIR})
set(MSS_BIN_DIR "${LIB_DIR}")
set(CMAKE_INSTALL_RPATH "${MSS_BIN_DIR}")

set(LIB_TYPE "SHARED" CACHE STRING "Which lib type to build: SHARED (default) or STATIC")
message("LIB_TYPE           = ${LIB_TYPE}")
message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")

#set(CMAKE_MAKE_PROGRAM "/usr/local/bin/cmake")
if("STATIC" STREQUAL "${LIB_TYPE}")
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
set(SMP_NANOROOT_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${SMP_NANOROOT_BUILD_DIR}/libs")
if(NOT WIN32)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${SMP_NANOROOT_BUILD_DIR}/libs")
endif()
set(CMAKE_BINARY_DIRECTORY "${SMP_NANOROOT_BUILD_DIR}")
set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

if(NOT EXISTS ${DEFS_FILE})
    message(FATAL_ERROR "\nDEFS_FILE = ${DEFS_FILE} does not exist")
endif()

message("\nDEFS_FILE = ${DEFS_FILE}")
include(${DEFS_FILE})

set(LIB_SUFFIX "a")
if("SHARED" STREQUAL "${LIB_TYPE}")
    set(LIB_SUFFIX "so")
    if(APPLE)
        set(LIB_SUFFIX "dylib")
    endif()
endif()

########################################################################
# Mocana smp nanoroot SHARED LIBRARY building
########################################################################

set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
message("TARGET_DIR = ${TARGET_DIR}")

set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt")
set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt")

set(TARGET_NAME smpnanoroot)

if(CM_ENABLE_ABSOLUTE_PATH)
  set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -D__ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__")
endif()

if (DEFINED SECURE_PATH)
  set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -D__ENABLE_DIGICERT_SECURE_PATH__")
  message("\nSECURE_PATH = ${SECURE_PATH}")
  add_definitions("-DMANDATORY_BASE_PATH=\"${SECURE_PATH}\"")
endif()

set(MOCANA_FLAGS "")
init_flags()
buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)

set(libraryLists "")

message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "")

buildLibrary(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
            ${SMP_NANOROOT_BUILD_DIR} ${MSS_BIN_DIR}  ${libraryLists})
# adding mocana flags
target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
