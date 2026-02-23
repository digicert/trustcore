########################################################################
# CMake build script for Mocana digiprov_test application
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required (VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
option(CM_ENABLE_TAP "Enable TAP." OFF)
option(CM_ENABLE_PKCS11 "Enable TAP PKCS11." OFF)
option(CM_BUILD_X32 "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64 "Build for 64Bit Machine." OFF)
option(CM_ENABLE_EXPORT_ED "Enable export edition." OFF)
option(CM_ENABLE_CVC "Enable CV Certificates." OFF)
option(CM_ENABLE_OQS "Enable OQS Hybrid Support." OFF)
option(CM_ENABLE_PKCS11 "Enable pkcs11." OFF)
option(CM_ENABLE_PKCS11_TEE "Enable tee pkcs11." OFF)
option(CM_ENABLE_FIPS "Enable FIPS." OFF)

string(TIMESTAMP BUILDTIME "%Y-%m-%d %H:%M")

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/../shared_cmake)

include(MocPlatform)
include(build_library)
include(locate_lib)

project (digiprov_test)

if(WIN32)
    set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32")
else()
    if(BUILD_FOR_OSI)
      set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../lib")
    else()
      set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
    endif()
endif()

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
get_filename_component(MSS_DIR "${MSS_DIR}" ABSOLUTE)
set(MSS_SRC_DIR "${MSS_DIR}/src")
set(CM_OPENSSL_LIB_DIR "${CM_OPENSSL_LIB}")

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
if(BUILD_FOR_OSI)
  set(COMMON_LIB "${MSS_BIN_DIR}/libcommon.so")
  set(ASN1_LIB "${MSS_BIN_DIR}/libasn1.so")
  set(NANOCERT_LIB "${MSS_BIN_DIR}/libnanocert.so")
  if (CM_ENABLE_FIPS)
    set(MSS_LIB "${MSS_BIN_DIR}/libmss.so")
  endif()
  if (CM_ENABLE_EXPORT_ED)
    set(NANOCRYPTO_LIB "${MSS_BIN_DIR}/libcryptomw.so")
  else ()
    set(NANOCRYPTO_LIB "${MSS_BIN_DIR}/libnanocrypto.so")
  endif()
  if(CM_ENABLE_PKCS11)
    set(NANOTAP2_COMMON "${MSS_BIN_DIR}/libnanotap2_common.so")
    set(NANOTAP2_CONFIGPARSER "${MSS_BIN_DIR}/libnanotap2_configparser.so")
    set(NANOTAP2 "${MSS_BIN_DIR}/libnanotap2.so")
  elseif(CM_ENABLE_TAP)
    set(NANOTAP2_COMMON "${MSS_BIN_DIR}/libnanotap2_common.so")
    set(NANOTAP2_CONFIGPARSER "${MSS_BIN_DIR}/libnanotap2_configparser.so")
    set(NANOTAP2 "${MSS_BIN_DIR}/libnanotap2.so")
  endif()
  set(PLATFORM_LIB "${MSS_BIN_DIR}/libplatform.so")
  set(INITIALIZE_LIB "${MSS_BIN_DIR}/libinitialize.so")
  set(CRYPTOINTERFACE_LIB "${MSS_BIN_DIR}/libcryptointerface.so")
  if(WIN32)
    set(OSSL_CRYPTO_LIB "${MSS_BIN_DIR}/libcrypto.dll")
  else()
    set(OSSL_CRYPTO_LIB "${MSS_BIN_DIR}/libcrypto.so")
  endif()
else()
  locate_lib(COMMON_LIB common)
  locate_lib(ASN1_LIB asn1)
  locate_lib(NANOCERT_LIB nanocert)
  if (CM_ENABLE_FIPS)
    locate_lib(MSS_LIB mss)
  endif()
  if (CM_ENABLE_EXPORT_ED)
    locate_lib(NANOCRYPTO_LIB cryptomw)
  else ()
    locate_lib(NANOCRYPTO_LIB nanocrypto)
  endif()
  if(CM_ENABLE_PKCS11)
    locate_lib(NANOTAP2_COMMON nanotap2_common)
    locate_lib(NANOTAP2_CONFIGPARSER nanotap2_configparser)
    locate_lib(NANOTAP2 nanotap2)
  elseif(CM_ENABLE_TAP)
    locate_lib(NANOTAP2_COMMON nanotap2_common)
    locate_lib(NANOTAP2_CONFIGPARSER nanotap2_configparser)
    locate_lib(NANOTAP2 nanotap2)
  endif()
  locate_lib(PLATFORM_LIB platform)
  locate_lib(INITIALIZE_LIB initialize)
  locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
  if(WIN32)
    locate_lib(OSSL_CRYPTO_LIB libcrypto)
  else()
    locate_lib(OSSL_CRYPTO_LIB crypto)
  endif()
endif()

set(MOCANA_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_flags.txt")

if (CM_ENABLE_DEBUG)
	set(MOCANA_DEBUG_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_debug_flags.txt")
	message("\nMOCANA_DEBUG_FLAGS_FILE = ${MOCANA_DEBUG_FLAGS_FILE}")
endif()

if(NOT EXISTS ${MOCANA_FLAGS_FILE})
	message(FATAL_ERROR "\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE} does not exist")
endif()

message("\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE}")


########################################################################
#
# MOCANA FLAGS, TARGET_NAME, LIBRARYLISTS
#
########################################################################

file(STRINGS ${MOCANA_FLAGS_FILE} mocana_flags)

# Adding debug flags
if (CM_ENABLE_DEBUG)
	file(STRINGS ${MOCANA_DEBUG_FLAGS_FILE} mocana_debug_flags)
	set(mocana_flags ${mocana_flags} ${mocana_debug_flags})
endif()

if (CM_ENABLE_TAP)
    set(mocana_flags "${mocana_flags} -D__ENABLE_DIGICERT_TAP__")
endif()

if (CM_ENABLE_PKCS11)
    set(mocana_flags "${mocana_flags} -D__ENABLE_DIGICERT_SMP_PKCS11__")
else()
    set(mocana_flags "${mocana_flags} -D__ENABLE_DIGICERT_TPM2__")
endif()

if (CM_ENABLE_FIPS)
     set(mocana_flags "${mocana_flags} -D__ENABLE_DIGICERT_FIPS_MODULE__")
endif()

foreach(flag ${mocana_flags})
	string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

set(TARGET_NAME "digiprov_test")

set(libraryLists ${COMMON_LIB} ${PLATFORM_LIB} ${INITIALIZE_LIB} ${CRYPTOINTERFACE_LIB} 
                 ${ASN1_LIB} ${NANOCERT_LIB} ${NANOCRYPTO_LIB} ${MSS_LIB} ${NANOTAP2_COMMON} ${NANOTAP2_CONFIGPARSER} ${NANOTAP2} ${OSSL_CRYPTO_LIB} ${PROV_LIB})

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
    string(REGEX REPLACE "CM_OPENSSL_LIB_DIR/" "${CM_OPENSSL_LIB_DIR}/" INCLUDE_FOLDER "${INCLUDE_FOLDER}")
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
string(REGEX REPLACE "CM_OPENSSL_LIB_DIR/" "${CM_OPENSSL_LIB_DIR}/" SRC_FILES "${SRC_FILES}")
set(MSS_SOURCES ${SRC_FILES})

message("${TARGET_NAME} sources")
message("-----------")
foreach(file ${MSS_SOURCES})
    message(${file})
endforeach()

message("CM_OPENSSL_LIB_DIR = ${CM_OPENSSL_LIB_DIR}")

add_executable(${TARGET_NAME} ${MSS_SOURCES})
target_link_libraries(${TARGET_NAME} ${libraryLists})

if (WIN32)
    add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE_DIR:${TARGET_NAME}>/${TARGET_NAME}.exe ${MSS_BIN_DIR}/
                  COMMAND ${CMAKE_COMMAND} -E echo "Copied ${TARGET_NAME}.exe to ${MSS_BIN_DIR}/")
else()
    add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
                  COMMAND cp ${NCRYPTO_BUILD_DIR}/${TARGET_NAME} ${MSS_BIN_DIR}/
                  COMMAND echo "Copied ${TARGET_NAME} to ${MSS_BIN_DIR}/")
endif()
