########################################################################
# CMake build script for Digicert/Mocana's cert_enroll Library
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG  "Enable Debug logs." OFF)
option(CM_ENABLE_TAP    "Enable TAP."        OFF)
option(CM_BUILD_X32     "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64     "Build for 64Bit Machine." OFF)
if (WIN32)
    option(CM_WIN_FORCE_LINKAGE "Force linkage for shared library." OFF)
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH  ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

include(MocPlatform)
include(locate_lib)
include(build_rc_file)

project(cert_enroll C)

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${MSS_DIR}/src")
if(BUILD_FOR_OSI)
  set(LIB_DIR "${MSS_DIR}/lib")
endif()

# 'CACHE STRING' allows us to override this var's value through the bash script
set(LIB_TYPE "SHARED" CACHE STRING "Which lib type to build: SHARED (default) or STATIC")
message("LIB_TYPE           = ${LIB_TYPE}")

message("CMAKE_PROJECT_NAME = ${PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")
message("")

# Set the directory where to deposit build files
if("STATIC" STREQUAL "${LIB_TYPE}")
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
set(CAP_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
set(VERSION_FILE "${MSS_DIR}/projects/shared_cmake/set_cpack_version.cmake")
include(${VERSION_FILE})
if(DEFINED ENV{BUILD_NUMBER})
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "$ENV{BUILD_NUMBER}")
else()
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "0")
endif()

# Set the path for where the libraries should be written to
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CAP_BUILD_DIR}/libs")
if (NOT WIN32)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CAP_BUILD_DIR}/libs")
endif()

# Set the path to the "top level of the cmake build tree"
set(CMAKE_BINARY_DIR "${CAP_BUILD_DIR}")

message("CAP_BUILD_DIR = ${CAP_BUILD_DIR}")

if (NOT EXISTS ${DEFS_FILE})
  message(FATAL_ERROR "\nDEFS_FILE = ${DEFS_FILE} does not exist.")
endif()

message("\nDEFS_FILE = ${DEFS_FILE}")

# Include general (and compiler-specific) definitions
include(${DEFS_FILE})
add_compile_options(${WERROR})

set(MOCANA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")

if (CM_ENABLE_DEBUG)
  set(MOCANA_DEBUG_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt")
  message("\nMOCANA_DEBUG_FLAGS_FILE = ${MOCANA_DEBUG_FLAGS_FILE}")
endif()

if (CM_ENABLE_TAP)
  set(MOCANA_TAP_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_tap_flags.txt")
  message("\nMOCANA_TAP_FLAGS_FILE = ${MOCANA_TAP_FLAGS_FILE}")
endif()

if (NOT EXISTS ${MOCANA_FLAGS_FILE})
  message(FATAL_ERROR "\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE} does not exist")
endif()

message("\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE}")

########################################################################
#
# MOCANA FLAGS
#
########################################################################

file(STRINGS ${MOCANA_FLAGS_FILE} mocana_flags)

# Adding debug flags
if (CM_ENABLE_DEBUG)
  file(STRINGS ${MOCANA_DEBUG_FLAGS_FILE} mocana_debug_flags)
  set(mocana_flags ${mocana_flags} ${mocana_debug_flags})
endif()

# Adding TAP flags
if (CM_ENABLE_TAP)
  file(STRINGS ${MOCANA_TAP_FLAGS_FILE} mocana_tap_flags)
  set(mocana_flags ${mocana_flags} ${mocana_tap_flags})
endif()

# Remove any possible duplicates
list(REMOVE_DUPLICATES mocana_flags)

foreach(flag ${mocana_flags})
  string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

# adding mocana flags

message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

add_definitions("${MOCANA_FLAGS}")

# adding extra definitions from DEFS_FILE

message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")

add_definitions("${EXTRA_DEFINITIONS}")

# adding include directories listed in mss_includes.txt
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt" MSS_INCLUDES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")

include_directories("." ${MSS_INCLUDES})

message("\ncert_enroll includes")
message("----------------")
foreach(dir ${MSS_INCLUDES})
  message(${dir})
endforeach()

########################################################################
#
# MOCANA SOURCES
#
########################################################################

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt" MSS_SOURCES)

string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")

# Set Windows file properties
if(WIN32)
  build_rc_file("TrustPoint Shared Library")
  set(MSS_SOURCES ${MSS_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
endif()

message("\nmss sources")
message("-----------")
foreach(file ${MSS_SOURCES})
  message(${file})
endforeach()
message("")

if(WIN32)
  link_directories(${MSS_SRC_DIR}/../bin_win32)
else()
  link_directories(${MSS_SRC_DIR}/../bin)
endif()

if("SHARED" STREQUAL "${LIB_TYPE}")
  add_library(${PROJECT_NAME} SHARED ${MSS_SOURCES})

  if(BUILD_FOR_OSI)
    add_custom_command(
      TARGET ${PROJECT_NAME}
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy
          $<TARGET_FILE:${PROJECT_NAME}>
          "${LIB_DIR}")
  endif()

  locate_lib(COMMON_LIB common)
  locate_lib(ASN1_LIB asn1)
  set(LIB_LINK_ORDER ${COMMON_LIB} ${ASN1_LIB})
  target_link_libraries(${PROJECT_NAME} ${LIB_LINK_ORDER})

  if(WIN32)
    # Dependent libraries for common lib
    locate_lib(COMMON_LIB common)
    locate_lib(ASN1_LIB asn1)
    locate_lib(NANOCRYPTO_LIB nanocrypto)
    locate_lib(CRYPTO_MW_LIB cryptomw)
    locate_lib(NANOCERT_LIB nanocert)
    locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
    set(LIB_LINK_ORDER
        ${COMMON_LIB}
        ${ASN1_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTO_MW_LIB}
        ${NANOCERT_LIB}
        ${CRYPTOINTERFACE_LIB}
        Shlwapi.lib
        Ws2_32.lib)
    target_link_libraries(${PROJECT_NAME} ${LIB_LINK_ORDER})
  endif()

  if(ANDROID)
    # Dependent libraries for common lib
    locate_lib(NANOCRYPTO_LIB nanocrypto)
    locate_lib(CRYPTO_MW_LIB cryptomw)
    locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
    set(LIB_LINK_ORDER
        ${NANOCRYPTO_LIB}
        ${CRYPTO_MW_LIB}
        ${CRYPTOINTERFACE_LIB}
        )
    target_link_libraries(${PROJECT_NAME} ${LIB_LINK_ORDER})
  endif()

else()
  add_library(${PROJECT_NAME} STATIC ${MSS_SOURCES})
endif()
