########################################################################
# CMake build script for DigiCert tap_nanoroot_example
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
option(CM_ENABLE_HW_ACCEL "Build with hw-accel library." OFF)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../projects/shared_cmake)

if(CM_ENABLE_DEBUG)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
endif()

project (tap_nanoroot_example C)

include(MocPlatform)
include(locate_lib)

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

set(NANOROOT_EXAMPLE_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${NANOROOT_EXAMPLE_BUILD_DIR}/libs")
set(CMAKE_BINARY_DIR "${NANOROOT_EXAMPLE_BUILD_DIR}")
set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

message("NANOROOT_EXAMPLE_BUILD_DIR = ${NANOROOT_EXAMPLE_BUILD_DIR}")

if(NOT EXISTS ${DEFS_FILE})
    message(FATAL_ERROR "\nDEFS_FILE = ${DEFS_FILE} does not exist")
endif()

message("\nDEFS_FILE = ${DEFS_FILE}")
include(${DEFS_FILE})

set(MOCANA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")

if (CM_ENABLE_DEBUG)
    set(MOCANA_DEBUG_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt")
    message("\nMOCANA_DEBUG_FLAGS_FILE = ${MOCANA_DEBUG_FLAGS_FILE}")
endif()

if(NOT EXISTS ${MOCANA_FLAGS_FILE})
    message(FATAL_ERROR "\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE} does not exist")
endif()

message("\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE}")

# initializing tap_nanoroot_example flags


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
        string(REGEX REPLACE "-D__ENABLE_MOCANA_VALGRIND_SUPPORT__" "" mocana_debug_flags "${mocana_debug_flags}")
    endif()
    set(mocana_flags ${mocana_flags} ${mocana_debug_flags})
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

# adding mss include directories listed in mss_includes.txt
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt" MSS_INCLUDES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")

include_directories("." ${MSS_INCLUDES})

message("tap_nanoroot_example includes")
message("----------------")
foreach(dir ${MSS_INCLUDES})
    message(${dir})
endforeach()


file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt" MSS_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")
message("tap_nanoroot_example sources")
message("-----------")
foreach(file ${MSS_SOURCES})
    message(${file})
endforeach()

locate_lib(COMMON_LIB common)
locate_lib(ASN1_LIB asn1)
locate_lib(INITIALIZE_LIB initialize)
locate_lib(NANOCERT_LIB nanocert)
locate_lib(NANOTAP2_LIB nanotap2)
locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
locate_lib(NANOTAP2_COMMON_LIB nanotap2_common)
locate_lib(SMPNANOROOT smpnanoroot)
if(CM_ENABLE_HW_ACCEL)
  locate_lib(HW_ACCEL_LIB hw)
endif()

if(BUILD_FOR_OSI)
    set(ASN1_LIB            "${LIB_DIR}/libasn1.so")
    set(COMMON_LIB          "${LIB_DIR}/libcommon.so")
    set(INITIALIZE_LIB      "${LIB_DIR}/libinitialize.so")
    set(PLATFORM_LIB        "${LIB_DIR}/libplatform.so")
    set(NANOCAP_LIB         "${LIB_DIR}/libnanocap.so")
    set(NANOCERT_LIB        "${LIB_DIR}/libnanocert.so")
    set(NANOCRYPTO_LIB      "${LIB_DIR}/libnanocrypto.so")
    set(CRYPTOINTERFACE_LIB "${LIB_DIR}/libcryptointerface.so")
    set(SMPNANOROOT         "${LIB_DIR}/libsmpnanoroot.so")
    set(NANOTAP2_COMMON_LIB "${LIB_DIR}/libnanotap2_common.so")
    set(NANOTAP2_CONFIGPARSER_LIB "${LIB_DIR}/libnanotap2_configparser.so")
    set(NANOTAP2_LIB        "${LIB_DIR}/libnanotap2.so")

    set(libraryLists ${COMMON_LIB} ${PLATFORM_LIB} ${ASN1_LIB} ${INITIALIZE_LIB} ${NANOROOT_LIB}
                     ${NANOTAP2_COMMON_LIB} ${NANOTAP2_CONFIGPARSER_LIB} ${NANOTAP2_LIB} ${CRYPTOINTERFACE_LIB}
                     ${NANOCAP_LIB} ${NANOCERT_LIB} ${NANOCRYPTO_LIB})
else()
    set(libraryLists ${COMMON_LIB} ${ASN1_LIB} ${INITIALIZE_LIB} ${NANOCERT_LIB} ${NANOTAP2_LIB}
                     ${CRYPTOINTERFACE_LIB} ${NANOTAP2_COMMON_LIB})
endif()

if(CM_ENABLE_HW_ACCEL)
    set( libraryLists ${libraryLists} ${HW_ACCEL_LIB})
endif()

if(UNIX AND NOT ANDROID)
    set(libraryLists ${libraryLists} pthread)
endif()

add_executable(tap_nanoroot_example ${MSS_SOURCES})
target_link_libraries(tap_nanoroot_example ${libraryLists})

if(BUILD_FOR_OSI)
        set(SAMPLE_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../samples/bin")
        set(SAMPLE_FILE_PATH "${SAMPLE_BIN_DIR}/tap_nanoroot_example")

        file(MAKE_DIRECTORY ${SAMPLE_BIN_DIR})

        add_custom_command(TARGET tap_nanoroot_example POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:tap_nanoroot_example> ${SAMPLE_FILE_PATH}
                    COMMAND echo "Copied tap_nanoroot_example to ${SAMPLE_FILE_PATH}")
elseif(NOT WIN32)
      add_custom_command(TARGET tap_nanoroot_example POST_BUILD
                  COMMAND cp ${NANOROOT_EXAMPLE_BUILD_DIR}/tap_nanoroot_example ${MSS_BIN_DIR}/
                  COMMAND echo "Copied tap_nanoroot_example to ${MSS_BIN_DIR}/")
endif()
