########################################################################
# CMake build script for Mocana nanotap2_common SHARED LIBRARY FOR NanoSMP
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG      "Enable Debug logs." OFF)
option(CM_DISABLE_SUITEB    "Disable suiteb" OFF)
option(CM_ENABLE_SMP_PKCS11 "Enable PKCS11 SMP." OFF)
option(CM_ENABLE_SMP_NANOROOT "Enable NANOROOT SMP." OFF)
option(CM_ENABLE_SMP_TEE    "Enable TEE SMP." OFF)
option(CM_ENABLE_TAP_REMOTE "Enable TAP remote." OFF)
option(CM_ENABLE_TAP_MIN    "Enable TAP small version." OFF)
option(CM_BUILD_X32         "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64         "Build for 64Bit Machine." OFF)
option(CM_ENABLE_TPM        "Enable tpm12." OFF)
option(CM_ENABLE_DATA_PROTECT "Enable TAP Data Protection APIs." OFF)
if(BUILD_FOR_OSI)
    if (NOT CM_ENABLE_TAP_REMOTE)
        option(CM_ENABLE_TPM2 "Enable tpm2 ." ON)
    endif()
else()
    option(CM_ENABLE_TPM2 "Enable tpm2 ." OFF)
endif()

if (WIN32)
    option(CM_WIN_FORCE_LINKAGE "Force linkage for shared library." OFF)
endif()

include(cmakeflags.txt)
include(cmakefunctions.txt)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
include(MocPlatform)

project (nanotap2_common C)

include(locate_lib)
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

# Need MSS_DIR for locate_lib
if("STATIC" STREQUAL "${LIB_TYPE}")
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${MSS_DIR}/src")
if(BUILD_FOR_OSI)
  set(LIB_DIR "${MSS_DIR}/lib")
endif()
set(CMAKE_INSTALL_RPATH "${MSS_BIN_DIR}")

set(LIB_TYPE "SHARED" CACHE STRING "Which lib type to build: SHARED (default) or STATIC")
message("LIB_TYPE           = ${LIB_TYPE}")

message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")

#set(CMAKE_MAKE_PROGRAM "/usr/local/bin/cmake")
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


########################################################################
# Mocana nanotap2_common SHARED LIBRARY building
########################################################################

if(BUILD_FOR_OSI)
    set(COMMON_LIB "${LIB_DIR}/libcommon.so")
    set(PLATFORM_LIB "${LIB_DIR}/libplatform.so")
    if(CM_ENABLE_SMP_PKCS11)
      set(SMP_LIB "${LIB_DIR}/libsmppkcs11.so")
    endif()
    if(CM_ENABLE_TPM2)
      set(SMP_LIB "${LIB_DIR}/libsmptpm2.so")
    endif()
    if (CM_ENABLE_SMP_NANOROOT)
        set(SMP_NANOROOT "${LIB_DIR}/libsmpnanoroot.so")
    endif()
else()
    locate_lib(COMMON_LIB common)
    locate_lib(PLATFORM_LIB platform)
    if (CM_ENABLE_SMP_PKCS11)
      locate_lib(SMP_LIB smppkcs11)
    elseif (CM_ENABLE_TPM2)
      locate_lib(SMP_LIB smptpm2)
    elseif (CM_ENABLE_TPM)
        locate_lib(SMP_LIB smptpm12)
    endif()

    if (CM_ENABLE_SMP_NANOROOT)
      locate_lib(SMP_NANOROOT smpnanoroot)
    endif()

    if (CM_ENABLE_SMP_TEE)
      locate_lib(SMP_LIB_TZ smptee)
    endif()

    if (CM_ENABLE_DATA_PROTECT)
      locate_lib(DATAPROTECT_LIB dataprotect)
    endif()
    if(WIN32)
      if(CM_ENABLE_FIPS)
        locate_lib(LIBMSS_LIB libmss)
      endif()
    endif()
endif()

set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
message("TARGET_DIR = ${TARGET_DIR}")

set(TARGET_NAME nanotap2_common)

# adding mocana flags

if(CM_ENABLE_DATA_PROTECT)
  set(MOCANA_FLAGS "-D__ENABLE_DIGICERT_DATA_PROTECTION__")
else()
  set(MOCANA_FLAGS "")
endif()

init_flags()
buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

if("SHARED" STREQUAL "${LIB_TYPE}")
    set(libraryLists ${COMMON_LIB} ${PLATFORM_LIB} ${SMP_LIB} ${SMP_LIB_TZ} ${SMP_NANOROOT})
    if(WIN32 OR ANDROID)
        locate_lib(INITIALIZE_LIB initialize)
        locate_lib(NANOCERT_LIB nanocert)
        set(libraryLists ${libraryLists} ${INITIALIZE_LIB} ${NANOCERT_LIB})
        if(CM_ENABLE_FIPS)
          set(libraryLists ${libraryLists} ${LIBMSS_LIB})
        endif()
    endif()
endif()

if(CM_ENABLE_DATA_PROTECT)
  set(libraryLists ${libraryLists} ${DATAPROTECT_LIB})
endif()

# Set Windows file properties
if(WIN32)
  build_rc_file("TrustPoint Shared Library")
endif()

buildLibrary(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${MSS_SRC_DIR} ${NTAP2_BUILD_DIR} ${MSS_BIN_DIR}  ${libraryLists})
# adding mocana flags

if(WIN32)
    #target_compile_definitions had problems in parsing multiple preprocessor
    #flags if CMAKE generator Visual Studio is used (NMAKE works fine).
    #Ref: https://cmake.org/cmake/help/v3.0/prop_tgt/COMPILE_DEFINITIONS.html
    add_definitions("${MOCANA_FLAGS}")
else()
    target_compile_definitions(${TARGET_NAME}   PRIVATE ${MOCANA_FLAGS})
endif()

if(BUILD_FOR_OSI)
    add_custom_command(
      TARGET ${PROJECT_NAME}
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy
          $<TARGET_FILE:${PROJECT_NAME}>
          "${LIB_DIR}")
endif()
