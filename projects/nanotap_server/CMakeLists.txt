########################################################################
# CMake build script for Mocana nanotap
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG              "Enable Debug logs." OFF)
option(CM_ENABLE_TAP_REMOTE         "Enable tap remote." OFF)
option(CM_ENABLE_TPM2               "Enable tpm2 ." OFF)
option(CM_ENABLE_TPM                "Enable tpm12 ." OFF)
option(CM_ENABLE_PKCS11             "Enable pkcs11 ." OFF)
option(CM_ENABLE_TEE                "Enable TEE ." OFF)
option(CM_BUILD_X32                 "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64                 "Build for 64Bit Machine." OFF)
option(CM_ENABLE_DATA_PROTECT       "Build with data protection enabled." OFF)
option(CM_ENABLE_CRED_EV            "Build with extended credential validation." OFF)
option(CM_ENABLE_TAPS_WIN_SERVICE   "Enable TAP server as Windows service program" OFF)
option(CM_ENABLE_TAPS_LOOPBACK      "Build TAP server to listen only on Loopback address" OFF)
option(CM_ENABLE_HW_ACCEL           "Build with hw-accel library." OFF)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

include(MocPlatform)

project (nanotap_server C)

include(locate_lib)

# MSS_BIN_DIR is only used for where the executables go, so keep it to bin
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
set(MSS_SRC_DIR "${MSS_DIR}/src")
if(BUILD_FOR_OSI)
  set(LIB_DIR "${MSS_DIR}/lib")
endif()
set(CMAKE_INSTALL_RPATH "${MSS_BIN_DIR}")

set(LIB_TYPE "SHARED" CACHE STRING "Which lib type to build: SHARED (default) or STATIC")
message("LIB_TYPE           = ${LIB_TYPE}")

message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")

set(NCRYPTO_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${NCRYPTO_BUILD_DIR}/libs")
set(CMAKE_BINARY_DIR "${NCRYPTO_BUILD_DIR}")
set(NCRYPTO_DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

message("NCRYPTO_BUILD_DIR = ${NCRYPTO_BUILD_DIR}")

if(NOT EXISTS ${NCRYPTO_DEFS_FILE})
    message(FATAL_ERROR "\nNCRYPTO_DEFS_FILE = ${NCRYPTO_DEFS_FILE} does not exist")
endif()

message("\nNCRYPTO_DEFS_FILE = ${NCRYPTO_DEFS_FILE}")
include(${NCRYPTO_DEFS_FILE})

set(MOCANA_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_flags.txt")

if (CM_ENABLE_DEBUG)
    set(MOCANA_DEBUG_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_debug_flags.txt")
    message("\nMOCANA_DEBUG_FLAGS_FILE = ${MOCANA_DEBUG_FLAGS_FILE}")
endif()

if (CM_ENABLE_TAP_REMOTE)
    set(MOCANA_TAP_REMOTE_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_tap_remote_flags.txt")
    message("\nMOCANA_TAP_REMOTE_FLAGS_FILE = ${MOCANA_TAP_REMOTE_FLAGS_FILE}")
endif()

if (CM_ENABLE_TPM2)
    set(MOCANA_TPM2_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_tpm2_flags.txt")
    message("\nMOCANA_TPM2_FLAGS_FILE = ${MOCANA_TPM2_FLAGS_FILE}")
endif()

if (CM_ENABLE_PKCS11)
    set(MOCANA_PKCS11_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_pkcs11_flags.txt")
    message("\nMOCANA_PKCS11_FLAGS_FILE = ${MOCANA_PKCS11_FLAGS_FILE}")
endif()

if (CM_ENABLE_TEE)
    set(MOCANA_TEE_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_tee_flags.txt")
    message("\nMOCANA_TEE_FLAGS_FILE = ${MOCANA_TEE_FLAGS_FILE}")
endif()

if (CM_ENABLE_TPM)
    set(MOCANA_TPM12_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_tpm12_flags.txt")
    message("\nMOCANA_TPM12_FLAGS_FILE = ${MOCANA_TPM12_FLAGS_FILE}")
endif()

if (CM_ENABLE_TAPS_LOOPBACK)
    set(MOCANA_TAPS_LOOPBACK_FILE "${NCRYPTO_BUILD_DIR}/../mocana_taps_loopback_flags.txt")
    message("\nMOCANA_TAPS_LOOPBACK_FILE = ${MOCANA_TAPS_LOOPBACK_FILE}")
endif()

if(NOT EXISTS ${MOCANA_FLAGS_FILE})
    message(FATAL_ERROR "\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE} does not exist")
endif()

message("\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE}")

if ((NOT WIN32) AND CM_ENABLE_TAPS_WIN_SERVICE)
    message("\nCM_ENABLE_TAPS_WIN_SERVICE is windows only flag, Ignoring it.")
endif()
if (CM_ENABLE_TAPS_WIN_SERVICE)
    set(MOCANA_WIN_SERVICE_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_win_service_flags.txt")
    message("\nMOCANA_WIN_SERVICE_FLAGS_FILE= ${MOCANA_WIN_SERVICE_FLAGS_FILE}")
    if(CM_ENABLE_DEBUG)
        set(MOCANA_WIN_SERVICE_DEBUG_FLAGS_FILE "${NCRYPTO_BUILD_DIR}/../mocana_win_service_debug_flags.txt")
        message("\nMOCANA_WIN_SERVICE_DEBUG_FLAGS_FILE= ${MOCANA_WIN_SERVICE_DEBUG_FLAGS_FILE}")
    endif()
endif()

# initializing nanotap_server flags


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

if(CM_ENABLE_DATA_PROTECT)
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_DATA_PROTECTION__")
endif()

if(CM_ENABLE_CRED_EV)
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_EXTENDED_CRED_VALIDATION__")
endif()

if (CM_ENABLE_TAP_REMOTE)
    file(STRINGS ${MOCANA_TAP_REMOTE_FLAGS_FILE} mocana_tap_remote_flags)
    set(mocana_flags ${mocana_flags} ${mocana_tap_remote_flags})
if(UNIX)
    set(mocana_flags ${mocana_flags} "-D__ENABLE_TAP_REMOTE_UNIX_DOMAIN__")
endif()
endif()

if(CM_ENABLE_TPM2)
    file(STRINGS ${MOCANA_TPM2_FLAGS_FILE} mocana_tpm2_flags)
    set(mocana_flags ${mocana_flags} ${mocana_tpm2_flags})
endif()

if(CM_ENABLE_TPM)
    file(STRINGS ${MOCANA_TPM12_FLAGS_FILE} mocana_tpm12_flags)
    set(mocana_flags ${mocana_flags} ${mocana_tpm12_flags})
endif()

if(CM_ENABLE_PKCS11)
    file(STRINGS ${MOCANA_PKCS11_FLAGS_FILE} mocana_pkcs11_flags)
    set(mocana_flags ${mocana_flags} ${mocana_pkcs11_flags})
endif()

if(CM_ENABLE_TEE)
    file(STRINGS ${MOCANA_TEE_FLAGS_FILE} mocana_tee_flags)
    set(mocana_flags ${mocana_flags} ${mocana_tee_flags})
endif()

if(CM_ENABLE_TAPS_LOOPBACK)
    file(STRINGS ${MOCANA_TAPS_LOOPBACK_FILE} mocana_taps_loopback_flags)
    set(mocana_flags ${mocana_flags} ${mocana_taps_loopback_flags})
endif()

if(CM_ENABLE_TAPS_WIN_SERVICE)
    file(STRINGS ${MOCANA_WIN_SERVICE_FLAGS_FILE} mocana_win_service_flags)
    set(mocana_flags ${mocana_flags} ${mocana_win_service_flags})
    if(CM_ENABLE_DEBUG)
        file(STRINGS ${MOCANA_WIN_SERVICE_DEBUG_FLAGS_FILE} mocana_win_service_debug_flags)
        set(mocana_flags ${mocana_flags} ${mocana_win_service_debug_flags})
    endif()
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
file(STRINGS "${NCRYPTO_BUILD_DIR}/../mss_includes.txt" DSF_INCLUDES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" DSF_INCLUDES "${DSF_INCLUDES}")

include_directories("." ${DSF_INCLUDES})

message("nanotap_server includes")
message("----------------")
foreach(dir ${DSF_INCLUDES})
    message(${dir})
endforeach()


file(STRINGS "${NCRYPTO_BUILD_DIR}/../mss_sources.txt" DSF_SOURCES)

if (CM_ENABLE_TAP_REMOTE)
    file(STRINGS "${NCRYPTO_BUILD_DIR}/../mss_tap_remote_sources.txt" DSF_TAP_REMOTE_SOURCES)
    set(DSF_SOURCES ${DSF_SOURCES} ${DSF_TAP_REMOTE_SOURCES})
endif()

if(CM_ENABLE_TAPS_WIN_SERVICE)
    ENABLE_LANGUAGE(RC)
    file(STRINGS "${NCRYPTO_BUILD_DIR}/../mss_win_service_sources.txt" DSF_TAP_WIN_SERVICE_SOURCES)
    set(DSF_SOURCES ${DSF_SOURCES} ${DSF_TAP_WIN_SERVICE_SOURCES})
endif()

string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" DSF_SOURCES "${DSF_SOURCES}")
message("dsf sources")
message("-----------")
foreach(file ${DSF_SOURCES})
    message(${file})
endforeach()

locate_lib(ASN1_LIB asn1)
locate_lib(COMMON_LIB common)
locate_lib(INITIALIZE_LIB initialize)
locate_lib(PLATFORM_LIB platform)
locate_lib(NANOCRYPTO_LIB nanocrypto)
locate_lib(CRYPTO_MW_LIB cryptomw)
if(CM_ENABLE_DATA_PROTECT)
    locate_lib(DATAPROTECT_LIB dataprotect)
endif()
locate_lib(NANOCERT_LIB nanocert)
locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
locate_lib(NANOCAP_LIB nanocap)
locate_lib(NANOSSL_LIB nanossl)
locate_lib(NANOTAP2_LIB nanotap2)
locate_lib(NANOTAP2_COMMON_LIB nanotap2_common)
if(CM_ENABLE_PKCS11)
    locate_lib(PKCS11_SMP_LIB smppkcs11)
endif()
if(CM_ENABLE_TEE)
    locate_lib(TEE_SMP_LIB smptee)
endif()
if(CM_ENABLE_TPM2)
    locate_lib(TPM2_LIB tpm2)
    locate_lib(SMPTPM2_LIB smptpm2)
endif()
if(CM_ENABLE_TPM)
    locate_lib(TPM12_LIB tpm12)
    locate_lib(SMPTPM12_LIB smptpm12)
endif()
if(CM_ENABLE_HW_ACCEL)
  locate_lib(HW_ACCEL_LIB hw)
endif()

locate_lib(NANOTAP2_CONFIGPARSER_LIB nanotap2_configparser)
locate_lib(NANOTAP2_CLIENTCOMM_LIB nanotap2_clientcomm)
set(libraryLists ${COMMON_LIB} ${ASN1_LIB} ${INITIALIZE_LIB} ${PLATFORM_LIB}
                 ${CRYPTOINTERFACE_LIB} ${NANOCERT_LIB} ${NANOCAP_LIB}
                 ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB} ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB}
		 ${NANOTAP2_CONFIGPARSER_LIB} ${NANOTAP2_CLIENTCOMM_LIB})

if(CM_ENABLE_DATA_PROTECT)
    set(libraryLists ${libraryLists} ${DATAPROTECT_LIB} )
endif()

if(CM_ENABLE_PKCS11)
    set(libraryLists ${libraryLists} ${PKCS11_SMP_LIB} )
endif()

if(CM_ENABLE_TEE)
    set(libraryLists ${libraryLists} ${TEE_SMP_LIB} )
endif()

if(CM_ENABLE_TPM2)
    set(libraryLists ${libraryLists} ${TPM2_LIB} ${SMPTPM2_LIB} )
elseif(CM_ENABLE_TPM)
    set(libraryLists ${libraryLists} ${TPM12_LIB} ${SMPTPM12_LIB} )
endif()

if (CM_ENABLE_TAP_REMOTE)
    set( libraryLists ${libraryLists} ${NANOSSL_LIB})
endif()

if(CM_ENABLE_HW_ACCEL)
    set( libraryLists ${libraryLists} ${HW_ACCEL_LIB})
endif()

if(UNIX AND NOT ANDROID)
    set(libraryLists ${libraryLists} pthread)
endif()

if (WIN32)
    set(libraryLists ${libraryLists} Shlwapi)
endif()

add_executable(nanotap_server_bin ${DSF_SOURCES})
target_link_libraries(nanotap_server_bin ${libraryLists} )

if (NOT WIN32)
      add_custom_command(TARGET nanotap_server_bin POST_BUILD
                  COMMAND cp ${NCRYPTO_BUILD_DIR}/nanotap_server_bin ${MSS_BIN_DIR}/
                  COMMAND echo "Copied nanotap_server_bin to ${MSS_BIN_DIR}/")
endif()
