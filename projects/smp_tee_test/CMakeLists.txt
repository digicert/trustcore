########################################################################
# CMake build script for Mocana tee_test application
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
option(CM_BUILD_X32 "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64 "Build for 64Bit Machine." OFF)

string(TIMESTAMP BUILDTIME "%Y-%m-%d %H:%M")

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/../shared_cmake)

include(MocPlatform)
include(build_library)
include(locate_lib)

project (tee_test)

if(BUILD_FOR_OSI)
  set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../lib")
else()
  if(WIN32)
    set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32")
  else()
    set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
  endif()
endif()

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
get_filename_component(MSS_DIR "${MSS_DIR}" ABSOLUTE)
set(MSS_SRC_DIR "${MSS_DIR}/src")

message("MSS_SRC_DIR = ${MSS_SRC_DIR}")

message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")

set(NCRYPTO_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_BINARY_DIRECTORY "${NCRYPTO_BUILD_DIR}")
set(NCRYPTO_DEFS_FILE "${NCRYPTO_BUILD_DIR}/../../shared_cmake/mss_defs.cmake")

message("NCRYPTO_BUILD_DIR = ${NCRYPTO_BUILD_DIR}")

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	set(MACOSX TRUE)
	set(SHARED_LIB_EXT dylib)
else()
	set(SHARED_LIB_EXT so)
endif()

if(NOT EXISTS ${NCRYPTO_DEFS_FILE})
	message(FATAL_ERROR "\nNCRYPTO_DEFS_FILE = ${NCRYPTO_DEFS_FILE} does not exist")
endif()

message("\nNCRYPTO_DEFS_FILE = ${NCRYPTO_DEFS_FILE}")
include(${NCRYPTO_DEFS_FILE})

########################################################################
# Locate base libraries
########################################################################

# Get the full path to our base libraries
# Note: If library is not found, variable will be empty.

locate_lib(COMMON_LIB common)
locate_lib(PLATFORM_LIB platform)
locate_lib(ASN1 asn1)
locate_lib(INITIALIZE initialize)
locate_lib(CRYPTO_INTERFACE cryptointerface)
locate_lib(NANOCRYPTO nanocrypto)
locate_lib(NANOCAP nanocap)
locate_lib(NANOCERT nanocert)
locate_lib(NANOTAP2_LIB nanotap2)
locate_lib(NANOTAP2_COMMON_LIB nanotap2_common)
locate_lib(TEEC teec)

if (CM_ENABLE_DEBUG)
	set(MOCANA_DEBUG_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_debug_flags.txt")
	message("\nMOCANA_DEBUG_FLAGS_FILE = ${MOCANA_DEBUG_FLAGS_FILE}")
endif()

########################################################################
#
# MOCANA FLAGS, TARGET_NAME, LIBRARYLISTS
#
########################################################################

# Adding debug flags
if (CM_ENABLE_DEBUG)
	file(STRINGS ${MOCANA_DEBUG_FLAGS_FILE} mocana_flags)
endif()

foreach(flag ${mocana_flags})
	string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

set(TARGET_NAME "tee_test")

set(libraryLists ${COMMON_LIB} ${PLATFORM_LIB} ${INITIALIZE} ${ASN1} ${CRYPTO_INTERFACE} ${NANOCRYPTO} ${NANOCAP} ${NANOCERT} ${NANOTAP2_COMMON_LIB} ${NANOTAP2_LIB} ${TEEC})

message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

add_definitions("${MOCANA_FLAGS}")

# adding extra definitions
if(WIN32)
  set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DWIN_FP_UTIL_EXPORT")
endif()
message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")

add_definitions("${EXTRA_DEFINITIONS}")

# adding dsf include directories listed in dsf_includes.txt
set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt")
set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt")

set(MSS_INCLUDES "" )
foreach(include_file ${includelist})
# adding mss include directories listed in mss_includes.txt
    file(STRINGS "${include_file}" INCLUDE_FOLDER)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" INCLUDE_FOLDER "${INCLUDE_FOLDER}")
    set(MSS_INCLUDES ${MSS_INCLUDES} ${INCLUDE_FOLDER} )
endforeach()

include_directories("." ${MSS_INCLUDES})
message("${TARGET_NAME} includes")
message("----------------")
foreach(dir ${MSS_INCLUDES})
    message(${dir})
endforeach()

set(MSS_SOURCES)
file(STRINGS ${srclist} SRC_FILES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" SRC_FILES "${SRC_FILES}")
set(MSS_SOURCES ${SRC_FILES})

message("${TARGET_NAME} sources")
message("-----------")
foreach(file ${MSS_SOURCES})
    message(${file})
endforeach()

add_executable(${TARGET_NAME} ${MSS_SOURCES})
target_link_libraries(${TARGET_NAME} ${libraryLists})

if (WIN32)
    add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE_DIR:${TARGET_NAME}>/${TARGET_NAME}.exe ${MSS_BIN_DIR}/
                  COMMAND ${CMAKE_COMMAND} -E echo "Copied ${TARGET_NAME}.exe to ${MSS_BIN_DIR}/")
endif()
