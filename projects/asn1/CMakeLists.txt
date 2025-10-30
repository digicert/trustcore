########################################################################
# CMake build script for DigiCert ASN1 Library
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
option(CM_ENABLE_CMS "Enable CMS." OFF)
option(CM_ENABLE_IPV6 "Enable IPV6." OFF)
option(CM_DISABLE_PQC "Disable PQC support" OFF)
option(CM_BUILD_DATALIB "Build data library for global symbols." ON)
option(CM_DISABLE_CI   "Disable crypto interface." OFF)
option(CM_ENABLE_CVC   "Enable CV Certificates." OFF)
option(CM_BUILD_X32    "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64    "Build for 64Bit Machine." OFF)
if (WIN32)
    option(CM_WIN_FORCE_LINKAGE "Force linkage for shared library." OFF)
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

# Include cross-compile options/flags
include(MocPlatform)

project(asn1 C)

include(build_rc_file)

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${MSS_DIR}/src")
if(BUILD_FOR_OSI)
  set(LIB_DIR "${MSS_DIR}/lib")
endif()

include(locate_lib)

set(LIB_TYPE "SHARED" CACHE STRING "Type of library to build. (SHARED or STATIC)")
message("LIB_TYPE           = ${LIB_TYPE}")

message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")

if("STATIC" STREQUAL "${LIB_TYPE}")
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
set(ASN_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${ASN_BUILD_DIR}/libs")
set(CMAKE_BINARY_DIR "${ASN_BUILD_DIR}")
set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
set(VERSION_FILE "${MSS_DIR}/projects/shared_cmake/set_cpack_version.cmake")
include(${VERSION_FILE})
if(DEFINED ENV{BUILD_NUMBER})
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "$ENV{BUILD_NUMBER}")
else()
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "0")
endif()

message("ASN_BUILD_DIR = ${ASN_BUILD_DIR}")

if(NOT EXISTS ${DEFS_FILE})
  message(FATAL_ERROR "\nDEFS_FILE = ${DEFS_FILE} does not exist")
endif()

message("\nDEFS_FILE = ${DEFS_FILE}")
include(${DEFS_FILE})
add_compile_options(${WERROR})

# Initializing asn1 flags

set(MOCANA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")

if(CM_ENABLE_DEBUG)
  set(MOCANA_DEBUG_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt")
  message("\nMOCANA_DEBUG_FLAGS_FILE = ${MOCANA_DEBUG_FLAGS_FILE}")
endif()

if(CM_ENABLE_CMS)
  set(MOCANA_CMS_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cms/mocana_flags.txt")
  message("\nMOCANA_CMS_FLAGS_FILE = ${MOCANA_CMS_FLAGS_FILE}")
endif()

if(CM_ENABLE_IPV6)
  set(MOCANA_IPV6_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ipv6/mocana_flags.txt")
  message("\nMOCANA_IPV6_FLAGS_FILE = ${MOCANA_IPV6_FLAGS_FILE}")
endif()

if(NOT CM_DISABLE_CI)
  set(MOCANA_CI_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_ci_flags.txt")
  message("\nMOCANA_CI_FLAGS_FILE = ${MOCANA_CI_FLAGS_FILE}")
endif()

if(CM_ENABLE_CVC)
  set(MOCANA_CV_CERT_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_cv_cert_flags.txt")
  message("\nMOCANA_CV_CERT_FLAGS_FILE = ${MOCANA_CV_CERT_FLAGS_FILE}")
endif()

if(NOT EXISTS ${MOCANA_FLAGS_FILE})
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
if(CM_ENABLE_DEBUG)
  file(STRINGS ${MOCANA_DEBUG_FLAGS_FILE} mocana_debug_flags)
  set(mocana_flags ${mocana_flags} ${mocana_debug_flags})
endif()

if(CM_ENABLE_CMS)
  file(STRINGS ${MOCANA_CMS_FLAGS_FILE} mocana_cms_flags)
  set(mocana_flags ${mocana_flags} ${mocana_cms_flags})
endif()

if(CM_ENABLE_IPV6)
  file(STRINGS ${MOCANA_IPV6_FLAGS_FILE} mocana_ipv6_flags)
  set(mocana_flags ${mocana_flags} ${mocana_ipv6_flags})
endif()

if(NOT CM_DISABLE_CI)
  file(STRINGS ${MOCANA_CI_FLAGS_FILE} mocana_ci_flags)
  set(mocana_flags ${mocana_flags} ${mocana_ci_flags})
endif()

if(CM_ENABLE_CVC)
  file(STRINGS ${MOCANA_CV_CERT_FLAGS_FILE} mocana_cvc_flags)
  set(mocana_flags ${mocana_flags} ${mocana_cvc_flags})
endif()

# override the enable flag if pqc is disabled
if (CM_DISABLE_PQC)
    list(REMOVE_ITEM mocana_flags "-D__ENABLE_MOCANA_PQC__")
endif()

# Now load all flags into MOCANA_FLAGS
foreach(flag ${mocana_flags})
  string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

# Load the flags into the build
message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
add_definitions("${MOCANA_FLAGS}")

# Load the EXTRA_DEFINITIONS flags (from mss_defs.cmake) into the build
if(WIN32)
  set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DWIN_ASN1_EXPORT")
endif()

message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")
add_definitions("${EXTRA_DEFINITIONS}")

########################################################################
#
# MOCANA INCLUDES
#
########################################################################

# Add include directories defined in mss_includes.txt
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt" MSS_INCLUDES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")

include_directories("." ${MSS_INCLUDES})

message("\nasn1 includes")
message("----------------")
foreach(dir ${MSS_INCLUDES})
  message(${dir})
endforeach()

########################################################################
#
# MOCANA SOURCES
#
########################################################################

# Add file sources from mss_sources.txt
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

if(WIN32)
  if("STATIC" STREQUAL "${LIB_TYPE}")
    set(MSS_BIN_DIR ${MSS_SRC_DIR}/../bin_win32_static)
  else()
    set(MSS_BIN_DIR ${MSS_SRC_DIR}/../bin_win32)
  endif()
else()
  if(BUILD_FOR_OSI)
    set(MSS_BIN_DIR ${MSS_SRC_DIR}/../lib)
  else()
    set(MSS_BIN_DIR ${MSS_SRC_DIR}/../bin)
  endif()
endif()
link_directories(${MSS_BIN_DIR})

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
  if(CM_ENABLE_FIPS)
    locate_lib(LIBMSS_LIB libmss)
    target_link_libraries(${PROJECT_NAME} ${LIBMSS_LIB})
  endif()
  if(BUILD_FOR_OSI)
    set(COMMON_LIB "${LIB_DIR}/libcommon.so")
  else()
    locate_lib(COMMON_LIB common)
  endif()
  target_link_libraries(${PROJECT_NAME} ${COMMON_LIB})

else()
  add_library(${PROJECT_NAME} STATIC ${MSS_SOURCES})
endif()

# Add a static library with the appropriate OID defs for Windows.
if(("SHARED" STREQUAL "${LIB_TYPE}") AND WIN32 AND CM_BUILD_DATALIB)

  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_win_data_sources.txt" MSS_WIN_DATA_SOURCES)
  string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_WIN_DATA_SOURCES "${MSS_WIN_DATA_SOURCES}")

  add_library(${PROJECT_NAME}data STATIC ${MSS_WIN_DATA_SOURCES})

  add_custom_command(
    TARGET ${PROJECT_NAME}data
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        $<TARGET_FILE_DIR:${PROJECT_NAME}data>
        ${MSS_BIN_DIR})
endif()
