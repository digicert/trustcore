########################################################################
# CMake build script for Mocana nanotap2_configparser SHARED LIBRARY FOR NanoSMP
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
option(CM_BUILD_X32 "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64 "Build for 64Bit Machine." OFF)
if (WIN32)
    option(CM_WIN_FORCE_LINKAGE "Force linkage for shared library." OFF)
endif()

include(cmakeflags.txt)

#set (CMAKE_VERBOSE_MAKEFILE "ON")

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
include(MocPlatform)

project (nanotap2_configparser C)

include(locate_lib)
include(build_library)
include(build_rc_file)

if(WIN32)
    set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32")
else()
    if("STATIC" STREQUAL "${LIB_TYPE}")
        set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_static")
    else()
        set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
    endif()
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

#set(CMAKE_MAKE_PROGRAM "/usr/local/bin/cmake")
if("STATIC" STREQUAL "${LIB_TYPE}")
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
set(NTAP2_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${NTAP2_BUILD_DIR}/libs")
if(NOT WIN32)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${NTAP2_BUILD_DIR}/libs")
endif()
set(CMAKE_BINARY_DIR "${NTAP2_BUILD_DIR}")
set(NTAP2_DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
set(VERSION_FILE "${MSS_DIR}/projects/shared_cmake/set_cpack_version.cmake")
include(${VERSION_FILE})
if(DEFINED ENV{BUILD_NUMBER})
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "$ENV{BUILD_NUMBER}")
else()
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "0")
endif()

message("NTAP2_BUILD_DIR = ${NTAP2_BUILD_DIR}")

if(NOT EXISTS ${NTAP2_DEFS_FILE})
    message(FATAL_ERROR "\nNTAP2_DEFS_FILE = ${NTAP2_DEFS_FILE} does not exist")
endif()

message("\nNTAP2_DEFS_FILE = ${NTAP2_DEFS_FILE}")
include(${NTAP2_DEFS_FILE})

set(MOCANA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")

if (CM_ENABLE_DEBUG)
    set(MOCANA_DEBUG_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt")
    message("\nMOCANA_DEBUG_FLAGS_FILE = ${MOCANA_DEBUG_FLAGS_FILE}")
endif()

if(NOT EXISTS ${MOCANA_FLAGS_FILE})
    message(FATAL_ERROR "\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE} does not exist")
endif()

message("\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE}")

# initializing nanotap2_configparser flags



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
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt" DSF_INCLUDES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" DSF_INCLUDES "${DSF_INCLUDES}")

include_directories("." ${DSF_INCLUDES})

message("nanotap2_configparser includes")
message("----------------")
foreach(dir ${DSF_INCLUDES})
    message(${dir})
endforeach()


file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt" DSF_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" DSF_SOURCES "${DSF_SOURCES}")
message("dsf sources")
message("-----------")
foreach(file ${DSF_SOURCES})
    message(${file})
endforeach()

# Set Windows file properties
if(WIN32)
  build_rc_file("TrustPoint Shared Library")
  set(DSF_SOURCES ${DSF_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
endif()

#if("SHARED" STREQUAL "${LIB_TYPE}")
#    add_library(nanotap2_configparser SHARED ${DSF_SOURCES})
#	target_link_libraries(nanotap2_configparser nanocrypto common nanotap2_common)
#    if (WIN32)
#        target_link_libraries(nanotap2_configparser Shlwapi Ws2_32)
#    endif()
#else()
#    add_library(nanotap2_configparser nanocryptocore STATIC ${DSF_SOURCES})
#endif()

if(BUILD_FOR_OSI)
    set(COMMON_LIB "${LIB_DIR}/libcommon.so")
    set(NANOCERT_LIB "${LIB_DIR}/libnanocert.so")
else()
    locate_lib(COMMON_LIB common)
    locate_lib(NANOCERT_LIB nanocert)
endif()

set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
message("TARGET_DIR = ${TARGET_DIR}")

set(TARGET_NAME nanotap2_configparser)

set(MOCANA_FLAGS "")
init_flags()
buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

set(libraryLists ${COMMON_LIB} ${NANOCERT_LIB})
if(WIN32)
    locate_lib(INITIALIZE_LIB initialize)
    locate_lib(NANOTAP2COMMON_LIB nanotap2_common)
    set(libraryLists ${libraryLists} ${INITIALIZE_LIB} ${NANOTAP2COMMON_LIB})
    if(CM_ENABLE_FIPS)
      locate_lib(LIBMSS_LIB libmss)
      set(libraryLists ${libraryLists} ${LIBMSS_LIB})
    endif()
endif()
if (ANDROID)
    locate_lib(INITIALIZE_LIB initialize)
    set(libraryLists ${libraryLists} ${INITIALIZE_LIB})
endif()
message ("Using libraries ${libraryLists}")

set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt")
set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt")

buildLibrary(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR} ${NTAP2_BUILD_DIR} ${MSS_BIN_DIR}  ${libraryLists})

# adding mocana flags
if(WIN32)
    #target_compile_definitions had problems in parsing multiple preprocessor
    #flags if CMAKE generator Visual Studio is used (NMAKE works fine).
    #Ref: https://cmake.org/cmake/help/v3.0/prop_tgt/COMPILE_DEFINITIONS.html
    add_definitions("${MOCANA_FLAGS}")
else()
    target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
endif()

if(BUILD_FOR_OSI)
    add_custom_command(
      TARGET ${PROJECT_NAME}
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy
          $<TARGET_FILE:${PROJECT_NAME}>
          "${LIB_DIR}")
endif()
