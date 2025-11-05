########################################################################
# CMake build script for DigiCert Platform Library
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
option(CM_ENABLE_GLOBAL_MUTEX "Enabling Global Mutex." ON)
option(CM_ENABLE_FIPS  "Build with FIPS." OFF)
option(CM_ENABLE_IPV6  "Enable IPV6." OFF)
option(CM_ENABLE_PROCESS "Enable Process APIs." OFF)
option(CM_ENABLE_MPART "Enable memory partition flags." OFF)
option(CM_ENABLE_TPM2  "Enable TPM2"        OFF)
option(CM_BUILD_X32    "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64    "Build for 64Bit Machine." OFF)
if (DEFINED SECURE_PATH)
option(CM_ENABLE_ABSOLUTE_PATH    "Enable absolute path support." ON)
else()
option(CM_ENABLE_ABSOLUTE_PATH    "Enable absolute path support." OFF)
endif()
if (WIN32)
    option(CM_WIN_FORCE_LINKAGE "Force linkage for shared library." OFF)
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

include(MocPlatform)
include(locate_lib)

project(platform C)

include(build_rc_file)

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${MSS_DIR}/src")
if(BUILD_FOR_OSI)
  set(LIB_DIR "${MSS_DIR}/lib")
endif()

set(LIB_TYPE "SHARED" CACHE STRING "Type of library to build. (SHARED or STATIC)")
message("LIB_TYPE           = ${LIB_TYPE}")

message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")

if("STATIC" STREQUAL "${LIB_TYPE}")
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
set(PLATFORM_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PLATFORM_BUILD_DIR}/libs")
set(CMAKE_BINARY_DIR "${PLATFORM_BUILD_DIR}")
set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
set(VERSION_FILE "${MSS_DIR}/projects/shared_cmake/set_cpack_version.cmake")
include(${VERSION_FILE})
if(DEFINED ENV{BUILD_NUMBER})
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "$ENV{BUILD_NUMBER}")
else()
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "0")
endif()

message("PLATFORM_BUILD_DIR = ${PLATFORM_BUILD_DIR}")

if(NOT EXISTS ${DEFS_FILE})
  message(FATAL_ERROR "\nDEFS_FILE = ${DEFS_FILE} does not exist")
endif()

message("\nDEFS_FILE = ${DEFS_FILE}")
include(${DEFS_FILE})
add_compile_options(${WERROR})

# Initializing platform flags

set(MOCANA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")

if(CM_ENABLE_DEBUG)
  set(MOCANA_DEBUG_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt")
  message("\nMOCANA_DEBUG_FLAGS_FILE = ${MOCANA_DEBUG_FLAGS_FILE}")
endif()

if(CM_ENABLE_MPART)
  set(MOCANA_MPART_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_mpart_flags.txt")
  message("\nMOCANA_MPART_FLAGS_FILE = ${MOCANA_MPART_FLAGS_FILE}")
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

if(CM_ENABLE_IPV6)
  set(mocana_flags ${mocana_flags} -D__ENABLE_MOCANA_IPV6__)
endif()

if(CM_ENABLE_ABSOLUTE_PATH)
  set(mocana_flags ${mocana_flags} -D__ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__)
endif()

if (DEFINED SECURE_PATH)
  set(mocana_flags ${mocana_flags} -D__ENABLE_DIGICERT_SECURE_PATH__)
  message("\nSECURE_PATH = ${SECURE_PATH}")
  add_definitions("-DMANDATORY_BASE_PATH=\"${SECURE_PATH}\"")
endif()

if(CM_ENABLE_PROCESS)
  set(mocana_flags ${mocana_flags} -D__ENABLE_MOCANA_RTOS_PROCESS__)
endif()

if(CM_ENABLE_MPART)
  file(STRINGS ${MOCANA_MPART_FLAGS_FILE} mocana_mpart_flags)
  set(mocana_flags ${mocana_flags} ${mocana_mpart_flags})
endif()

if(CM_ENABLE_GLOBAL_MUTEX)
  set(mocana_flags ${mocana_flags} -D__ENABLE_MOCANA_GLOBAL_MUTEX__)
else()
  set(mocana_flags ${mocana_flags} -D__DISABLE_MOCANA_TPM_MUTEX__)
endif()

# Now load all flags into MOCANA_FLAGS
foreach(flag ${mocana_flags})
  string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

# Load the flags into the build
message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
add_definitions("${MOCANA_FLAGS}")

# Load the EXTRA_DEFINITIONS flags (from mss_defs.cmake) into the build
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

message("\nplatform includes")
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
if(BUILD_FOR_OSI)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_osi_sources.txt" MSS_SOURCES)
else()
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt" MSS_SOURCES)
endif()

if(CM_ENABLE_PROCESS)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_process_sources.txt" PROCESS_SOURCES)
  set(MSS_SOURCES ${MSS_SOURCES} ${PROCESS_SOURCES})
endif()

# Remove FIPS files if this is a FIPS build. Must be done last once all
# other source files have been appended to the source list.
if(CM_ENABLE_FIPS)
  include(mss_fips)
  get_fips_source(FIPS_SOURCES)
  list(REMOVE_ITEM MSS_SOURCES ${FIPS_SOURCES})
endif()
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

  if(WIN32)
    # Dependent libraries for platform lib
    locate_lib(COMMON_LIB common)
    set(LIB_LINK_ORDER
        ${COMMON_LIB}
        Ws2_32.lib)
    target_link_libraries(${PROJECT_NAME} ${LIB_LINK_ORDER})
  else()
    locate_lib(COMMON_LIB common)
    target_link_libraries(${PROJECT_NAME} ${COMMON_LIB})
  endif()

  if(CM_ENABLE_FIPS)
    locate_lib(LIBMSS_LIB libmss)
    target_link_libraries(${PROJECT_NAME} ${LIBMSS_LIB})
  endif()

else()
  add_library(${PROJECT_NAME} STATIC ${MSS_SOURCES})
endif()

if(UNIX AND NOT ANDROID)
  if("${CM_TARGET_PLATFORM}" MATCHES "qnx-x86" OR "${CM_TARGET_PLATFORM}" MATCHES "qnx-6-5-x86")
  else()
    # thread apis are available in libc itself for Android
    target_link_libraries(${PROJECT_NAME} pthread)
  endif()
endif()
