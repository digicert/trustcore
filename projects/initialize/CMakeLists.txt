########################################################################
# CMake build script for Mocana Initialize Library
#

cmake_minimum_required(VERSION 3.5)

option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
option(CM_ENABLE_CUSTOM_ENTROPY "Enable Custom Entropy." OFF)
option(CM_ENABLE_IPV6 "Enable IPV6." OFF)
option(CM_DISABLE_CI "Disable crypto interface" OFF)
option(CM_ENABLE_DATA_PROTECT "Enable Data Protect." OFF)
option(CM_ENABLE_MPART "Enable MEM PART." OFF)
option(CM_ENABLE_MEM_PROFILE "Enable Memory Profiling." OFF)
option(CM_ENABLE_FORCE_ENTROPY "Enable force entropy." OFF)
option(CM_DISABLE_TCP_INIT "Disable Mocana TCP init." OFF)
option(CM_BUILD_X32    "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64    "Build for 64Bit Machine." OFF)
if (WIN32)
    option(CM_WIN_FORCE_LINKAGE "Force linkage for shared library." OFF)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
include(MocPlatform)

project(initialize C)

include(locate_lib)
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
set(INITIALIZE_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${INITIALIZE_BUILD_DIR}/libs")
set(CMAKE_BINARY_DIR "${INITIALIZE_BUILD_DIR}")
set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
set(VERSION_FILE "${MSS_DIR}/projects/shared_cmake/set_cpack_version.cmake")
include(${VERSION_FILE})
if(DEFINED ENV{BUILD_NUMBER})
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "$ENV{BUILD_NUMBER}")
else()
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "0")
endif()

message("INITIALIZE_BUILD_DIR = ${INITIALIZE_BUILD_DIR}")

if(NOT EXISTS ${DEFS_FILE})
  message(FATAL_ERROR "\nDEFS_FILE = ${DEFS_FILE} does not exist")
endif()

message("\nDEFS_FILE = ${DEFS_FILE}")
include(${DEFS_FILE})
add_compile_options(${WERROR})

# Initializing libinitialize flags

set(MOCANA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")

if(CM_ENABLE_DEBUG)
  set(MOCANA_DEBUG_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt")
  message("\nMOCANA_DEBUG_FLAGS_FILE = ${MOCANA_DEBUG_FLAGS_FILE}")
endif()

if(CM_ENABLE_MPART)
    set(MOCANA_MPART_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_mempart_flags.txt")
    message("\nMOCANA_MPART_FLAGS_FILE = ${MOCANA_MPART_FLAGS_FILE}")
endif()

if(CM_ENABLE_MEM_PROFILE)
    set(MOCANA_MEM_PROFILE_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_mem_profile_flags.txt")
    message("\nMOCANA_MEM_PROFILE_FLAGS_FILE = ${MOCANA_MEM_PROFILE_FLAGS_FILE}")
endif()

if(CM_ENABLE_DATA_PROTECT)
    set(MOCANA_DATA_PROTECT_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_data_protect_flags.txt")
    message("\nMOCANA_DATA_PROTECT_FLAGS_FILE = ${MOCANA_DATA_PROTECT_FLAGS_FILE}")
endif()

if(NOT CM_DISABLE_CI)
  set(MOCANA_CI_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_ci_flags.txt")
  message("\nMOCANA_CI_FLAGS_FILE = ${MOCANA_CI_FLAGS_FILE}")
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

# Now load all flags into MOCANA_FLAGS
foreach(flag ${mocana_flags})
  string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

# Toggle MOC_EXTERN_DATA_DEF/DECL to map to '__declspec(dllexport)'
if(WIN32)
    set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DWIN_IMPORT -DWIN_EXPORT_INITIALIZE")
endif()

if (CM_ENABLE_TAP_DATA_PROTECT)
  set(MOCANA_FLAGS "${MOCANA_FLAGS} -D__ENABLE_MOCANA_TAP__")
endif()

if(CM_ENABLE_MEM_PROFILE)
  file(STRINGS ${MOCANA_MEM_PROFILE_FLAGS_FILE} mocana_mem_profile_flags)
  foreach(flag ${mocana_mem_profile_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
  endforeach()
endif()

if(CM_ENABLE_MPART)
  file(STRINGS ${MOCANA_MPART_FLAGS_FILE} mocana_mpart_flags)
  foreach(flag ${mocana_mpart_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
  endforeach()
endif()

if(CM_ENABLE_DATA_PROTECT)
  file(STRINGS ${MOCANA_DATA_PROTECT_FLAGS_FILE} mocana_data_protect_flags)
  foreach(flag ${mocana_data_protect_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
  endforeach()
endif()

if(NOT CM_DISABLE_CI)
  file(STRINGS ${MOCANA_CI_FLAGS_FILE} mocana_ci_flags)
  foreach(flag ${mocana_ci_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
  endforeach()
endif()

if (CM_ENABLE_FORCE_ENTROPY)
    set(MOCANA_FLAGS "${MOCANA_FLAGS} -D__MOCANA_FORCE_ENTROPY__")
endif()

if (CM_ENABLE_CUSTOM_ENTROPY)
    set(MOCANA_FLAGS "${MOCANA_FLAGS} -D__ENABLE_MOCANA_CUSTOM_ENTROPY_INJECT__")
endif()

if (CM_ENABLE_IPV6)
    set(MOCANA_FLAGS "${MOCANA_FLAGS} -D__ENABLE_MOCANA_IPV6__")
endif()

if (CM_DISABLE_TCP_INIT)
    set(MOCANA_FLAGS "${MOCANA_FLAGS} -D__DISABLE_MOCANA_TCP_INTERFACE__")
endif()

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

message("\ninitialize includes")
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
if(BUILD_FOR_OSI)
  string(REGEX REPLACE "EXTERNAL_RAND_THREAD_DIR/" "initialize/" MSS_SOURCES "${MSS_SOURCES}")
else()
  string(REGEX REPLACE "EXTERNAL_RAND_THREAD_DIR/" "examples/" MSS_SOURCES "${MSS_SOURCES}")
endif()

# Set Windows file properties
if(WIN32)
  build_rc_file("TrustPoint Shared Library")
  set(MSS_SOURCES ${MSS_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
endif()
if (CM_ENABLE_CUSTOM_ENTROPY)
  set(MSS_SOURCES ${MSS_SOURCES} ${MSS_SRC_DIR}/examples/custom_entropy.c)
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

if(BUILD_FOR_OSI)
  set(PLATFORM_LIB        "${LIB_DIR}/libplatform.so")
  set(COMMON_LIB          "${LIB_DIR}/libcommon.so")

  set(LIB_LINK_ORDER
    ${PLATFORM_LIB}
    ${COMMON_LIB}
  )
else()
  locate_lib(COMMON_LIB common)
  locate_lib(PLATFORM_LIB platform)
  set(LIB_LINK_ORDER ${COMMON_LIB} ${PLATFORM_LIB})
endif()
if("SHARED" STREQUAL "${LIB_TYPE}")
  # Locate any needed libraries to link against

  if(CM_ENABLE_DATA_PROTECT)
    locate_lib(DATA_PROTECT_LIB dataprotect)
    set(LIB_LINK_ORDER ${LIB_LINK_ORDER} ${DATA_PROTECT_LIB})
  endif()
  if(CM_ENABLE_TAP_DATA_PROTECT)
    locate_lib(TAP_LIB nanotap2)
    set(LIB_LINK_ORDER ${LIB_LINK_ORDER} ${TAP_LIB})
  endif()
  if(CM_ENABLE_FIPS)
    if(WIN32)
      locate_lib(LIBMSS_LIB libmss)
    else()
      locate_lib(LIBMSS_LIB mss)
    endif()

    set(LIB_LINK_ORDER ${LIB_LINK_ORDER} ${LIBMSS_LIB})
  endif()

  add_library(${PROJECT_NAME} SHARED ${MSS_SOURCES})

  if(BUILD_FOR_OSI)
    add_custom_command(
      TARGET ${PROJECT_NAME}
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy
          $<TARGET_FILE:${PROJECT_NAME}>
          "${LIB_DIR}")
  endif()

  target_link_libraries(${PROJECT_NAME} ${LIB_LINK_ORDER})

  if(WIN32)
      locate_lib(NANOCRYPTO_LIB nanocrypto)
      locate_lib(CRYPTO_MW_LIB cryptomw)
      locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
      target_link_libraries(${PROJECT_NAME} ${PLATFORM_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB}
                         ${CRYPTOINTERFACE_LIB} Shlwapi.lib Ws2_32.lib tbs.lib)
  endif()

  if(ANDROID)
      locate_lib(NANOCRYPTO_LIB nanocrypto)
      locate_lib(CRYPTO_MW_LIB cryptomw)
      locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
      target_link_libraries(${PROJECT_NAME} ${PLATFORM_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB}
                         ${CRYPTOINTERFACE_LIB})
  endif()


else()
  add_library(${PROJECT_NAME} STATIC ${MSS_SOURCES})
  message ("${PROJECT_NAME} ${LIB_LINK_ORDER}")
  target_link_libraries(${PROJECT_NAME} ${LIB_LINK_ORDER})
endif()
