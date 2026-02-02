########################################################################
# CMake build script for Mocana SMP_TPM2 SHARED LIBRARY FOR NanoSMP
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_DISABLE_SUITEB "Disable Mocana SuiteB." OFF)
option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
option(CM_ENABLE_SMP_PKCS11 "Enable PKCS11 SMP." OFF)
option(CM_BUILD_X32 "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64 "Build for 64Bit Machine." OFF)
if (WIN32)
    option(CM_WIN_FORCE_LINKAGE "Force linkage for shared library." OFF)
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
include(MocPlatform)

project (smptpm2 C)

include(locate_lib)
include(build_rc_file)
include(cmakeflags.txt)
include(cmakefunctions.txt)

if(WIN32)
    set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32")
else()
    if("STATIC" STREQUAL "${LIB_TYPE}")
        set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_static")
    else()
        set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
    endif()
endif()

# MSS_DIR needed by locate_lib
set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
if(BUILD_FOR_OSI)
  set(LIB_DIR "${MSS_DIR}/lib")
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
set(SMP_TPM2_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${SMP_TPM2_BUILD_DIR}/libs")
if(NOT WIN32)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${SMP_TPM2_BUILD_DIR}/libs")
endif()
set(CMAKE_BINARY_DIR "${SMP_TPM2_BUILD_DIR}")
set(SMP_TPM2_DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
set(VERSION_FILE "${MSS_DIR}/projects/shared_cmake/set_cpack_version.cmake")
include(${VERSION_FILE})
if(DEFINED ENV{BUILD_NUMBER})
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "$ENV{BUILD_NUMBER}")
else()
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "0")
endif()

message("SMP_TPM2_BUILD_DIR = ${SMP_TPM2_BUILD_DIR}")

if(NOT EXISTS ${SMP_TPM2_DEFS_FILE})
    message(FATAL_ERROR "\nSMP_TPM2_DEFS_FILE = ${SMP_TPM2_DEFS_FILE} does not exist")
endif()

message("\nSMP_TPM2_DEFS_FILE = ${SMP_TPM2_DEFS_FILE}")
include(${SMP_TPM2_DEFS_FILE})

set(MOCANA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")

if (NOT CM_DISABLE_SUITEB)
    set(MOCANA_SUITEB_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_suiteb_flags.txt")
    message("\nMOCANA_SUITEB_FLAGS_FILE = ${MOCANA_SUITEB_FLAGS_FILE}")
endif()

if (CM_ENABLE_DEBUG)
    set(MOCANA_DEBUG_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt")
    message("\nMOCANA_DEBUG_FLAGS_FILE = ${MOCANA_DEBUG_FLAGS_FILE}")
endif()

if(CM_ENABLE_OPENSSL_SHIM )
    set(MOCANA_OPENSSL_SHIM_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_openssl_shim_flags.txt")
    message("\nMOCANA_OPENSSL_SHIM_FLAGS_FILE = ${MOCANA_OPENSSL_SHIM_FLAGS_FILE}")
endif()

if(NOT EXISTS ${MOCANA_FLAGS_FILE})
    message(FATAL_ERROR "\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE} does not exist")
endif()

message("\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE}")

# initializing smptpm2 flags

message("")
foreach(stem CXX_FLAGS
        CXX_FLAGS_DEBUG
        CXX_FLAGS_RELEASE
        C_FLAGS
        C_FLAGS_DEBUG
        C_FLAGS_RELEASE
        MODULE_LINKER_FLAGS
        MODULE_LINKER_FLAGS_DEBUG
        EXE_LINKER_FLAGS
        EXE_LINKER_FLAGS_DEBUG
        SHARED_LINKER_FLAGS
        SHARED_LINKER_FLAGS_DEBUG)
    set(CMAKE_${stem} "${CMAKE_${stem}} ${${stem}_MOCANA}")
    string(STRIP "${CMAKE_${stem}}" CMAKE_${stem})
    message("----------------")
    message("${stem}_MOCANA = ${${stem}_MOCANA}")
    message("CMAKE_${stem}  = ${CMAKE_${stem}}")
endforeach()

########################################################################
#
# MOCANA FLAGS
#
########################################################################

file(STRINGS ${MOCANA_FLAGS_FILE} mocana_flags)

if (CM_ENABLE_SMP_PKCS11)
    set(mocana_flags ${mocana_flags} " -D__ENABLE_DIGICERT_SMP_PKCS11__")
   else()
    set(mocana_flags ${mocana_flags} " -D__ENABLE_DIGICERT_TPM2__")
endif()

# Adding suiteb flags
if (NOT CM_DISABLE_SUITEB)
    file(STRINGS ${MOCANA_SUITEB_FLAGS_FILE} mocana_suiteb_flags)
    set(mocana_flags ${mocana_flags} ${mocana_suiteb_flags})
endif()

# Adding debug flags
if (CM_ENABLE_DEBUG)
    file(STRINGS ${MOCANA_DEBUG_FLAGS_FILE} mocana_debug_flags)
    if(WIN32)
        string(REGEX REPLACE "-D__ENABLE_DIGICERT_VALGRIND_SUPPORT__" "" mocana_debug_flags "${mocana_debug_flags}")
    endif()
    set(mocana_flags ${mocana_flags} ${mocana_debug_flags})
endif()

if(CM_ENABLE_OPENSSL_SHIM )
    file(STRINGS ${MOCANA_OPENSSL_SHIM_FLAGS_FILE} mocana_openssl_shim_flags)
    set(mocana_flags ${mocana_flags} ${mocana_openssl_shim_flags})
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

message("smptpm2 includes")
message("----------------")
foreach(dir ${DSF_INCLUDES})
    message(${dir})
endforeach()


file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt" DSF_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" DSF_SOURCES "${DSF_SOURCES}")

# Set Windows file properties
if(WIN32)
  build_rc_file("TrustPoint Shared Library")
  set(DSF_SOURCES ${DSF_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
endif()

message("dsf sources")
message("-----------")
foreach(file ${DSF_SOURCES})
    message(${file})
endforeach()

#if("SHARED" STREQUAL "${LIB_TYPE}")
#    add_library(smptpm2 SHARED ${DSF_SOURCES})
#	target_link_libraries(smptpm2 tpm2 nanocrypto common platform)
#else()
#    add_library(smptpm2 tpm2 nanocryptocore STATIC ${DSF_SOURCES})
#endif()

if(BUILD_FOR_OSI)
    set(COMMON_LIB "${LIB_DIR}/libcommon.so")
    set(TPM2_LIB "${LIB_DIR}/libtpm2.so")
else()
    locate_lib(TPM2_LIB tpm2)
    locate_lib(COMMON_LIB common)
endif()

set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
message("TARGET_DIR = ${TARGET_DIR}")

set(TARGET_NAME smptpm2)

set(MOCANA_FLAGS "")
init_flags()
buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

if("SHARED" STREQUAL "${LIB_TYPE}")
    set(libraryLists ${COMMON_LIB} ${TPM2_LIB})
    if (WIN32 OR ANDROID)
        locate_lib(NANOCRYPTO_LIB nanocrypto)
        locate_lib(CRYPTO_MW_LIB cryptomw)
        locate_lib(NANOCERT_LIB nanocert)
        locate_lib(PLATFORM_LIB platform)
        locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
        set(libraryLists ${libraryLists} ${PLATFORM_LIB} ${NANOCERT_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB} ${CRYPTOINTERFACE_LIB})
        if(CM_ENABLE_FIPS)
          locate_lib(LIBMSS_LIB libmss)
          set(libraryLists ${libraryLists} ${LIBMSS_LIB})
        endif()
    endif()
else()
        set(libraryLists "")
endif()

buildLibrary(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${MSS_SRC_DIR} ${SMP_TPM2_BUILD_DIR} ${MSS_BIN_DIR}  ${libraryLists})
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
