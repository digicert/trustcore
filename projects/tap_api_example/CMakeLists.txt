########################################################################
# CMake build script for Mocana tap_api_example
#

cmake_minimum_required (VERSION 3.5)

option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
option(CM_ENABLE_TAP_REMOTE "Enable tap remote." OFF)
option(CM_ENABLE_TPM2 "Enable tpm2 ." OFF)
option(CM_ENABLE_SMP_NANOROOT "Enable nanoroot." OFF)
option(CM_ENABLE_HW_ACCEL "Build with hw-accel library." OFF)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

include(MocPlatform)

project (tap_api_example C)

#set(CMAKE_VERBOSE_MAKEFILE "ON")
include(locate_lib)

if(WIN32)
    set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32")
else()
    set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
endif()

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

set(NCRYPTO_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${NCRYPTO_BUILD_DIR}/libs")
set(CMAKE_BINARY_DIR "${NCRYPTO_BUILD_DIR}")
set(NCRYPTO_DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

message("NCRYPTO_BUILD_DIR = ${NCRYPTO_BUILD_DIR}")

if(NOT EXISTS ${NCRYPTO_DEFS_FILE})
    message(FATAL_ERROR "\nNCRYPTO_DEFS_FILE = ${NCRYPTO_DEFS_FILE} does not exist")
endif()

message("\nNCRYPTO_DEFS_FILE = ${NCRYPTO_DEFS_FILE}")
include(${NCRYPTO_DEFS_FILE})

set(MOCANA_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_flags.txt")

if (CM_ENABLE_DEBUG)
    set(MOCANA_DEBUG_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_debug_flags.txt")
    message("\nMOCANA_DEBUG_FLAGS_FILE = ${MOCANA_DEBUG_FLAGS_FILE}")
endif()

if (CM_ENABLE_TAP_REMOTE)
    set(MOCANA_TAP_REMOTE_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_tap_remote_flags.txt")
    message("\nMOCANA_TAP_REMOTE_FLAGS_FILE = ${MOCANA_TAP_REMOTE_FLAGS_FILE}")
endif()

if (CM_ENABLE_TPM2)
    set(MOCANA_TPM2_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_tpm2_flags.txt")
    message("\nMOCANA_TPM2_FLAGS_FILE = ${MOCANA_TPM2_FLAGS_FILE}")
endif()

if (CM_ENABLE_SMP_NANOROOT)
    set(MOCANA_NANOROOT_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_nanoroot_flags.txt")
    message("\nMOCANA_NANOROOT_FLAGS_FILE = ${MOCANA_NANOROOT_FLAGS_FILE}")
endif()

if(NOT EXISTS ${MOCANA_FLAGS_FILE})
    message(FATAL_ERROR "\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE} does not exist")
endif()

message("\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE}")

# initializing tap_api_example flags


########################################################################
#
# MOCANA FLAGS
#
########################################################################

file(STRINGS ${MOCANA_FLAGS_FILE} mocana_flags)

# Adding debug flags
if (CM_ENABLE_DEBUG)
    file(STRINGS ${MOCANA_DEBUG_FLAGS_FILE} mocana_debug_flags)
    if(WIN32)
        string(REGEX REPLACE "-D__ENABLE_DIGICERT_VALGRIND_SUPPORT__" "" mocana_debug_flags "${mocana_debug_flags}")
    endif()
    set(mocana_flags ${mocana_flags} ${mocana_debug_flags})
endif()

if (CM_ENABLE_TAP_REMOTE)
    file(STRINGS ${MOCANA_TAP_REMOTE_FLAGS_FILE} mocana_tap_remote_flags)
    set(mocana_flags ${mocana_flags} ${mocana_tap_remote_flags})
endif()

if(CM_ENABLE_TPM2)
    file(STRINGS ${MOCANA_TPM2_FLAGS_FILE} mocana_tpm2_flags)
    set(mocana_flags ${mocana_flags} ${mocana_tpm2_flags})
endif()

if(CM_ENABLE_SMP_NANOROOT)
    file(STRINGS ${MOCANA_NANOROOT_FLAGS_FILE} mocana_nanoroot_flags)
    set(mocana_flags ${mocana_flags} ${mocana_nanoroot_flags})
endif()

foreach(flag ${mocana_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

# adding mocana flags

message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

add_definitions("${MOCANA_FLAGS}")

# adding extra definitions

message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")

add_definitions("${EXTRA_DEFINITIONS}")

# adding dsf include directories listed in dsf_includes.txt
file(STRINGS "${NCRYPTO_BUILD_DIR}/../mss_includes.txt" DSF_INCLUDES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" DSF_INCLUDES "${DSF_INCLUDES}")

include_directories("." ${DSF_INCLUDES})

message("tap_api_example includes")
message("----------------")
foreach(dir ${DSF_INCLUDES})
    message(${dir})
endforeach()


if (CM_ENABLE_SMP_NANOROOT)
    file(STRINGS "${NCRYPTO_BUILD_DIR}/../mss_nanoroot_sources.txt" DSF_SOURCES)
else()
    file(STRINGS "${NCRYPTO_BUILD_DIR}/../mss_sources.txt" DSF_SOURCES)
endif()
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" DSF_SOURCES "${DSF_SOURCES}")
message("dsf sources")
message("-----------")
foreach(file ${DSF_SOURCES})
    message(${file})
endforeach()

locate_lib(COMMON_LIB common)
locate_lib(INITIALIZE_LIB initialize)
locate_lib(NANOCERT_LIB nanocert)
locate_lib(NANOTAP2_LIB nanotap2)
locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
locate_lib(NANOTAP2_COMMON_LIB nanotap2_common)
if(CM_ENABLE_HW_ACCEL)
  locate_lib(HW_ACCEL_LIB hw)
endif()

set(libraryLists ${COMMON_LIB} ${INITIALIZE_LIB} ${NANOCERT_LIB} ${NANOTAP2_LIB}
                 ${CRYPTOINTERFACE_LIB} ${NANOTAP2_COMMON_LIB})

if(CM_ENABLE_HW_ACCEL)
    set( libraryLists ${libraryLists} ${HW_ACCEL_LIB})
endif()

if(UNIX AND NOT ANDROID)
    set(libraryLists ${libraryLists} pthread)
endif()

add_executable(tap_api_example ${DSF_SOURCES})
target_link_libraries(tap_api_example ${libraryLists} )

if(NOT WIN32)
      add_custom_command(TARGET tap_api_example POST_BUILD
                  COMMAND cp ${NCRYPTO_BUILD_DIR}/tap_api_example ${MSS_BIN_DIR}/
                  COMMAND echo "Copied tap_api_example to ${MSS_BIN_DIR}/")
endif()
