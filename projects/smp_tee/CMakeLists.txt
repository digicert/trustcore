########################################################################
# CMake build script for Mocana smp_tee SHARED LIBRARY FOR NanoSMP
#

if(BUILD_FOR_OSI)
    cmake_minimum_required(VERSION 3.16)
else()
    cmake_minimum_required(VERSION 3.5)
endif()

project (smp_tee)

cmake_minimum_required (VERSION 3.5)

option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
option(CM_ENABLE_TEE   "Enable tee lib ." OFF)

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
set(SMP_TEE_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${SMP_TEE_BUILD_DIR}/libs")
if(NOT WIN32)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${SMP_TEE_BUILD_DIR}/libs")
endif()
set(CMAKE_BINARY_DIRECTORY "${SMP_TEE_BUILD_DIR}")
set(SMP_TEE_DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

if(NOT EXISTS ${SMP_TEE_DEFS_FILE})
    message(FATAL_ERROR "\nSMP_TEE_DEFS_FILE = ${SMP_TEE_DEFS_FILE} does not exist")
endif()

message("\nSMP_TEE_DEFS_FILE = ${SMP_TEE_DEFS_FILE}")
include(${SMP_TEE_DEFS_FILE})

set(LIB_SUFFIX "a")
if("SHARED" STREQUAL "${LIB_TYPE}")
    set(LIB_SUFFIX "so")
    if(APPLE)
        set(LIB_SUFFIX "dylib")
    endif()
endif()

########################################################################
# Mocana smp tee SHARED LIBRARY building
########################################################################

set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
message("TARGET_DIR = ${TARGET_DIR}")

set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt")
set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt")

set(TARGET_NAME smptee)

set(MOCANA_FLAGS "")
init_flags()
buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)

set(libraryLists "")
if("SHARED" STREQUAL "${LIB_TYPE}")
    if(CM_ENABLE_TEE)
        set(libraryLists ${libraryLists} teec)
    endif()
endif()

message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "")

buildLibrary(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
            ${SMP_TEE_BUILD_DIR} ${MSS_BIN_DIR}  ${libraryLists})
# adding mocana flags
target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
