## Compile libraries and executables for the 'IKE/MCP  binary'
##

cmake_minimum_required(VERSION 3.5)

## ON/OFF Options
option(CM_ENABLE_TAP_LOCAL  "Enable Tap Local" OFF)
option(CM_ENABLE_TAP_REMOTE "Enable Tap Remote" OFF)
option(CM_ENABLE_DEBUG      "Enable Debug Console in application code." OFF)
option(CM_ENABLE_SUITEB     "Enable Suite-B Crypto." OFF)
option(CM_ENABLE_RFC4806    "Enable RFC 4806 support. " OFF)
option(CM_ENABLE_FIPS       "Building with FIPS enabled." OFF)
option(CM_ENABLE_DUAL_MODE  "Enable Suite-B Crypto." OFF)
option(CM_ENABLE_NW_RED     "Enable NW redundancy." OFF)
option(CM_ENABLE_EAPA       "Building with EAP authenticator" OFF)
option(CM_ENABLE_EAPS       "Building with EAP supplicant" OFF)
option(CM_ENABLE_EXPORT     "Building in export mode" OFF)
option(CM_ENABLE_TLSA       "Building with TLS" OFF)
option(CM_ENABLE_TLSS       "Building with TLS" OFF)
option(CM_ENABLE_IPV6       "Enable IPV6." OFF)
option(CM_ENABLE_DATA_PROTECTION "Building with Data Protection" OFF)
option(CM_ENABLE_OQS        "Building Open Quantum Safe algorithms" OFF)
option(CM_ENABLE_TRUSTEDGE  "Building with TrustEdge mode enabled" OFF)
option(CM_BUILD_SHARED_LIBS "Build NanoSec Shared Library"       OFF)
option(CM_BUILD_IKE         "Building ike" OFF)
option(CM_BUILD_IKE_SP800_135 "Building ike for testing SP800-135" OFF)
option(CM_BUILD_MCPA        "Building mcpagent" OFF)
option(CM_BUILD_MCPK        "Building kdc" OFF)
option(CM_BUILD_MCPK2       "Building kdc_secondary" OFF)
option(CM_ENABLE_MOCANA_IKE_REF_IDENTIFIER_MATCH "Enable Reference Identifier match capability." OFF)

option(CM_BUILD_X32           "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64           "Build for 64Bit Machine." OFF)

## Default
if(NOT DEFINED CM_CLIENT_TAP)
  set(CM_CLIENT_TAP OFF)
endif()

if(WIN32)
  set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../bin_win32")
else()
  set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../bin")
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../shared_cmake)
set(PLATFORMS_FILE "${CMAKE_MODULE_PATH}/platforms.txt")
include(MocPlatform)

project(nanosec_target)
set(LIB_TYPE "SHARED" CACHE STRING "Type of library to build. (SHARED or STATIC)")
message("LIB_TYPE           = ${LIB_TYPE}")

include(locate_lib)

set(MSS_LIBRARY_PATH ${MSS_BIN_DIR})

set(BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../build")
set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
set(MSS_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../src")
set(CMAKE_INSTALL_RPATH "${MSS_BIN_DIR}")
#set(MSS_LIBRARY_TYPE STATIC)

set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
if(NOT EXISTS ${DEFS_FILE})
  message(FATAL_ERROR "\nDEFS_FILE = ${DEFS_FILE} does not exist")
endif()

message("\nDEFS_FILE = ${DEFS_FILE}")
## Include general definitions
include(${DEFS_FILE})
add_compile_options(${WERROR})

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIR}/libs")
## Set PATHs
#set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${MSS_BIN_DIR}")
#set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${MSS_BIN_DIR}")
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${MSS_BIN_DIR}")
#set(CMAKE_BINARY_DIR "${BUILD_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${MSS_BIN_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${MSS_BIN_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${MSS_BIN_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${MSS_BIN_DIR})

if(WIN32)
  set(SHARED_LIB_EXT "dll")
  set(STATIC_LIB_EXT "lib")
  set(LIB_PREFIX "")
  set(WSOCK_LIB "wsock32")
  set(WS32_LIB "Ws2_32")
  set(IP_LIB "iphlpapi")
else()
  set(SHARED_LIB_EXT "so")
  set(STATIC_LIB_EXT "a")
  set(LIB_PREFIX "lib")
  if("${CM_TARGET_PLATFORM}" STREQUAL "qnx-x86")
    set(LIB_PTHREAD "")
  else()
    set(LIB_PTHREAD "pthread")
  endif()
  if("${CM_TARGET_PLATFORM}" STREQUAL "qnx-x86")
    set(WSOCK_LIB "socket")
  else()
    set(WSOCK_LIB "")
  endif()
  set(WS32_LIB "")
  set(NDISAPI_LIB "")
  set(IP_LIB "")
endif()
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(MACOSX TRUE)
  set(SHARED_LIB_EXT "dylib")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(SHARED_LIB_EXT "dll")
  set(STATIC_LIB_EXT "lib")
  set(LIB_PREFIX "")
endif()


if(UNIX AND NOT APPLE)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
endif()

# Create version.h from the above.
#configure_file(${CMAKE_SOURCE_DIR}/../../src/ipsec/ipsec_version.h.in
#               ${CMAKE_SOURCE_DIR}/../../src/ipsec/ipsec_version.h)

## Locate tools
if(WIN32)
  get_filename_component(sdk_dir
                         "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsKits\\Installed Roots;KitsRoot10]"
                         REALPATH)

  find_program(CMAKE_MC_COMPILER mc.exe HINTS "${sdk_dir}"
               DOC "path to message compiler")

  if(NOT CMAKE_MC_COMPILER)
    message(FATAL_ERROR "Message compiler not found")
  endif()

  message(STATUS "Found message compiler: ${CMAKE_MC_COMPILER}")

  find_program(CMAKE_SIGNTOOL signtool.exe HINTS "${sdk_dir}"
               DOC "path to signing tool")

  if(NOT CMAKE_SIGNTOOL)
    message(STATUS "Found NO signing tool")
  else()
    message(STATUS "Found signing tool: ${CMAKE_SIGNTOOL}")
  endif()
endif()

########################################################################
# Mocana Flags
########################################################################

if(CM_ENABLE_SUITEB)
  if(CM_ENABLE_EXPORT AND EXISTS "${CMAKE_SOURCE_DIR}/mocana_export_suiteb_flags.txt")
    set(SUITEB_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_export_suiteb_flags.txt")
    file(STRINGS ${SUITEB_FLAGS_FILE} suiteb_flags)
    foreach(flag ${suiteb_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
  else()
    set(SUITEB_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_suiteb_flags.txt")
    file(STRINGS ${SUITEB_FLAGS_FILE} suiteb_flags)
    foreach(flag ${suiteb_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
  endif()
endif()

if(CM_ENABLE_RFC4806)
    string(APPEND MOCANA_FLAGS " -D__ENABLE_IKE_OCSP_EXT__ -D__ENABLE_DIGICERT_OCSP_CLIENT__  -D__ENABLE_DIGICERT_OCSP_STORE__ -D__ENABLE_DIGICERT_OCSP_CERT_STORE_EXT__")
endif()

if(CM_ENABLE_DUAL_MODE)
    set(DUAL_MODE_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_dual_mode_flags.txt")
    file(STRINGS ${DUAL_MODE_FLAGS_FILE} dual_mode_flags)
    foreach(flag ${dual_mode_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_ENABLE_NW_RED)
    string(APPEND MOCANA_FLAGS " -D__ENABLE_DIGICERT_NW_REDUNDANCY__ ")
endif()

if(CM_ENABLE_MOCANA_IKE_REF_IDENTIFIER_MATCH)
    string(APPEND MOCANA_FLAGS " -D__ENABLE_DIGICERT_IKE_REF_IDENTIFIER_MATCH__ ")
endif()

if(CM_ENABLE_TRUSTEDGE)
    string(APPEND MOCANA_FLAGS " -D__ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__ ")
endif()

if(CM_BUILD_IKE_SP800_135)
    string(APPEND MOCANA_FLAGS " -D__ENABLE_DIGICERT_SP800_135_ACVP__ ")
endif()
########################################################################
# Mocana EAP and TLS Flags
########################################################################
if(CM_ENABLE_EAPA)
    set(EAP_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_eap_flags.txt")
    file(STRINGS ${EAP_FLAGS_FILE} eap_flags)
    foreach(flag ${eap_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()

    set(EAPA_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_eap_auth_flags.txt")
    file(STRINGS ${EAPA_FLAGS_FILE} eapa_flags)
    foreach(flag ${eapa_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_ENABLE_EAPS)
    set(EAP_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_eap_flags.txt")
    file(STRINGS ${EAP_FLAGS_FILE} eap_flags)
    foreach(flag ${eap_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()

    set(EAPS_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_eap_supplicant_flags.txt")
    file(STRINGS ${EAPS_FLAGS_FILE} eaps_flags)
    foreach(flag ${eaps_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_ENABLE_OQS)
    set(OQS_FLAGS_FILE "${CMAKE_SOURCE_DIR}/../mocana_oqs_flags.txt")
    file(STRINGS ${OQS_FLAGS_FILE} oqs_flags)
    foreach(flag ${oqs_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
    message("OQS_FLAGS_FILE=${OQS_FLAGS_FILE}")
endif()

if(CM_ENABLE_EXPORT)
    set(EXPORT_FLAGS_FILE "${CMAKE_SOURCE_DIR}/../mocana_export_flags.txt")
    file(STRINGS ${EXPORT_FLAGS_FILE} export_flags)
    foreach(flag ${export_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
    message("EXPORT_FLAGS_FILE=${EXPORT_FLAGS_FILE}")
endif()

if(CM_ENABLE_TLSA)
    set(TLS_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_tls_flags.txt")
    file(STRINGS ${TLS_FLAGS_FILE} tls_flags)
    foreach(flag ${tls_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()

    set(TLSA_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_tls_eap_auth_flags.txt")
    file(STRINGS ${TLSA_FLAGS_FILE} tlsa_flags)
    foreach(flag ${tlsa_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_ENABLE_TLSS)
    set(TLS_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_tls_flags.txt")
    file(STRINGS ${TLS_FLAGS_FILE} tls_flags)
    foreach(flag ${tls_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_ENABLE_IPV6)
    set(IPV6_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_ipv6_flags.txt")
    file(STRINGS ${IPV6_FLAGS_FILE} ipv6_flags)
    foreach(flag ${ipv6_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_ENABLE_DATA_PROTECTION)
    string(APPEND MOCANA_FLAGS " -D__ENABLE_DIGICERT_DATA_PROTECTION__ ")
endif()

## Read and set flags
#file(STRINGS ${FLAGS_FILE} project_flags)
#foreach(flag ${project_flags})
#string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
#endforeach()
if (CM_ENABLE_TAP_LOCAL OR CM_ENABLE_TAP_REMOTE)
    set(TAP_FLAGS_FILE "${CMAKE_SOURCE_DIR}/../mocana_tap_flags.txt")
    file(STRINGS ${TAP_FLAGS_FILE} tap_flags)
    foreach(flag ${tap_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
    if (CM_ENABLE_TAP_REMOTE)
        set(TAP_REMOTE_FLAGS_FILE "${CMAKE_SOURCE_DIR}/../mocana_tap_remote_flags.txt")
        file(STRINGS ${TAP_REMOTE_FLAGS_FILE} tap_remote_flags)
        foreach(flag ${tap_remote_flags})
            string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
        endforeach()
    endif()
endif()

if (CM_ENABLE_DEBUG)
    set(DEBUG_FLAGS_FILE "${CMAKE_SOURCE_DIR}/../mocana_debug_flags.txt")
    file(STRINGS ${DEBUG_FLAGS_FILE} debug_flags)
    foreach(flag ${debug_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_ENABLE_FIPS)
    string(STRIP "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_FIPS_MODULE__" MOCANA_FLAGS)
endif()

## To silence the warning message in mocana.c DIGICERT_initLog():
##   __ENABLE_DIGICERT_PRODUCT_DEBUG_CONSOLE__

add_definitions("-D__ENABLE_DIGICERT_PRODUCT_DEBUG_CONSOLE__")

## Switch CONSOLE debug flags
if (CM_ENABLE_DEBUG)
  ## Switch CONSOLE debug flags at this level to affect libraries and all source code in executables...
  add_definitions("-D__ENABLE_DIGICERT_DEBUG_CONSOLE__ -D__DIGICERT_DUMP_CONSOLE_TO_STDOUT__ -D__ENABLE_ALL_DEBUGGING__")
  ## No private flags for UM executable for debug log
endif()

# Toggle MOC_EXTERN_P to map to '__declspec(dllimport)'
if(WIN32)
  add_definitions("-DWIN_IMPORT")
  add_definitions("-DWIN_STATIC")
endif()

message("EXTRA_DEFINITIONS: ${EXTRA_DEFINITIONS}")
## Add flags from 'defs.txt'
add_definitions("${EXTRA_DEFINITIONS}")

if(CMAKE_CROSSCOMPILING)
  add_definitions(${PLATFORM_CPU_FLAGS})
endif()

## Add resources for events on supported platforms
if(WIN32)
  include_directories("${MSS_SRC_DIR}/../thirdparty/winpkfilter/include")
  include_directories("${MSS_SRC_DIR}/../thirdparty/cng_lib/include")
  set(EVENTS_SOURCES
      ${PROJECT_BINARY_DIR}/events.h
      ${PROJECT_BINARY_DIR}/events.rc)
  set(EVENTS_DEFINES -D__ENABLE_DIGICERT_WIN32_EVENTS__)
  add_custom_command(
      OUTPUT ${EVENTS_SOURCES}
      DEPENDS ${MSS_SRC_DIR}/um/events.mc
      COMMAND ${CMAKE_MC_COMPILER}
      ARGS -h ${PROJECT_BINARY_DIR}
      -r ${PROJECT_BINARY_DIR}
      ${MSS_SRC_DIR}/um/events.mc
      VERBATIM
  )
else()
  set(EVENTS_SOURCES "")
  set(EVENTS_DEFINES "")
endif()

## If requested to build a 'service', set the needed defines
if(CMAKE_MOCANA_SERVICE)
  if(WIN32)
    set(SERVICE_DEFINES -D__ENABLE_DIGICERT_WIN32_SERVICE__)
  else()
    set(SERVICE_DEFINES "")
  endif(WIN32)
else()
  set(SERVICE_DEFINES "")
endif()

## Add header defines for events/service
add_definitions("${EVENTS_DEFINES} ${SERVICE_DEFINES}")

########################################################################
# Building and linking
########################################################################
# Add in all of the required external libraries
add_library(common SHARED IMPORTED)
set_property(TARGET common PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}common.${SHARED_LIB_EXT})

add_library(asn1 SHARED IMPORTED)
set_property(TARGET asn1 PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}asn1.${SHARED_LIB_EXT})

add_library(nanocrypto SHARED IMPORTED)
set_property(TARGET nanocrypto PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}nanocrypto.${SHARED_LIB_EXT})

add_library(nanocert SHARED IMPORTED)
set_property(TARGET nanocert PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}nanocert.${SHARED_LIB_EXT})

add_library(nanossl SHARED IMPORTED)
set_property(TARGET nanossl PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}nanossl.${SHARED_LIB_EXT})

add_library(nanotap2_common SHARED IMPORTED)
set_property(TARGET nanotap2_common PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}nanotap2_common.${SHARED_LIB_EXT})

add_library(nanotap2_configparser SHARED IMPORTED)
set_property(TARGET nanotap2_configparser PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}nanotap2_configparser.${SHARED_LIB_EXT})

add_library(nanotap2 SHARED IMPORTED)
set_property(TARGET nanotap2 PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}nanotap2.${SHARED_LIB_EXT})

add_library(smptpm2 SHARED IMPORTED)
set_property(TARGET smptpm2 PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}smptpm2.${SHARED_LIB_EXT})

add_library(tpm2 SHARED IMPORTED)
set_property(TARGET tpm2 PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}tpm2.${SHARED_LIB_EXT})

# Add the GCC flags for the LInux build when needs to build 32 bit binaries on 64 bit machine
#TODO need to verify it doesn't have any bad impact on the 32 bit machine
if("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
  SET(x86_64 "TRUE")
else()
  SET(x86 "TRUE")
endif()
if(UNIX AND NOT APPLE AND CM_BUILD_X32 AND x86_64)
  SET(CMAKE_CXX_FLAGS           "-m32" CACHE STRING "C++ compiler flags" FORCE)
# this is probably unlikely to be needed, but just in case
#  SET(CMAKE_EXE_LINKER_FLAGS    "-m32 -L${LIB32}" CACHE STRING "executable linker flags"     FORCE)
endif()


if(CM_ENABLE_SMP_PKCS11)
  add_library(smppkcs11 SHARED IMPORTED)
  set_property(TARGET smppkcs11 PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}smppkcs11.${SHARED_LIB_EXT})

  add_library(softhsm2 SHARED IMPORTED)
  set_property(TARGET softhsm2 PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}softhsm2.${SHARED_LIB_EXT})
endif()

if(WIN32)
  #include_directories(${MSS_BIN_DIR})
  if (CM_BUILD_X64)
  message("winpkfilter: building for x64 platform")
	include_directories("${MSS_SRC_DIR}/../thirdparty/winpkfilter/lib/amd64")
	set (NDIS_LOCATION  "${MSS_SRC_DIR}/../thirdparty/winpkfilter/lib/amd64/")
  else()
  message("winpkfilter: building for x32 platform")
	include_directories("${MSS_SRC_DIR}/../thirdparty/winpkfilter/lib/i386")
	set (NDIS_LOCATION  "${MSS_SRC_DIR}/../thirdparty/winpkfilter/lib/i386/")
  endif()
  find_library(NDISAPI_LIB
    NAMES ndisapi
    HINTS "${NDIS_LOCATION}")
 # add_library(ndisapi SHARED IMPORTED)
  #locate_lib(NDISAPI_LIB ndisapi)
endif()

if(WIN32)
  if (CM_BUILD_X64)
    message("Building for x64 Platform")
    include_directories("${MSS_SRC_DIR}/../thirdparty/cng_lib/lib/win8/x64")
    set(CNG_LOCATION "${MSS_SRC_DIR}/../thirdparty/cng_lib/lib/win8/x64/")
  else()
    message("Building for x32 Platform")
    include_directories("${MSS_SRC_DIR}/../thirdparty/cng_lib/lib/win8/x86")
    set(CNG_LOCATION "${MSS_SRC_DIR}/../thirdparty/cng_lib/lib/win8/x86/")
  endif()
  find_library(BCRYPT_LIB
    NAMES bcrypt_provider
    HINTS "${CNG_LOCATION}"
  )
  find_library(NCRYPT_LIB
    NAMES ncrypt_provider
    HINTS "${CNG_LOCATION}"
  )
  find_library(CNG_LIB
    NAMES cng_provider
    HINTS "${CNG_LOCATION}"
  )
endif()

########################################################################
# Locate base libraries
########################################################################

locate_lib(ASN1_LIB asn1)
locate_lib(COMMON_LIB common)
locate_lib(INITIALIZE_LIB initialize)
locate_lib(DATAPROTECT_LIB dataprotect)
locate_lib(PLATFORM_LIB platform)
locate_lib(CRYPTOMW_LIB cryptomw)
locate_lib(NANOCRYPTO_LIB nanocrypto)
locate_lib(NANOCAP_LIB nanocap)
if(CM_ENABLE_TLSA OR CM_ENABLE_TLSS)
  locate_lib(NANOSSL_LIB nanossl)
else()
  set(NANOSSL_LIB "")
endif()
locate_lib(NANOCERT_LIB nanocert)
locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
if(CM_ENABLE_TAP_LOCAL OR CM_ENABLE_TAP_REMOTE)
  locate_lib(NANOTAP2_LIB nanotap2)
  locate_lib(NANOTAP2_COMMON_LIB nanotap2_common)
endif()
if(CM_ENABLE_TAP_LOCAL)
  locate_lib(TPM2_LIB tpm2)
  locate_lib(SMPTPM2_LIB smptpm2)
endif()
if(CM_ENABLE_TAP_REMOTE)
  locate_lib(NANOTAP2_CLIENTCOMM_LIB nanotap2_common)
endif()
if(CM_ENABLE_FIPS)
  locate_lib(FIPS_LIB mss)
endif()

if (CM_BUILD_SHARED_LIBS)
    set(BUILD_TGT "${BUILD_TGT}_example")
endif()

message ("TARGET NAME=${BUILD_TGT}") 

locate_lib(IKE_LIB ${LIB_TGT})

if(NOT WIN32)
  set(INSTALL_PERSIST_FILES ${INSTALL_PERSIST_FILES} sample/tpuc_data/persist/config.json)
endif()

if(WIN32)
	# add mcp tool flags and files here    
    set(MCPTOOL_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_mcptool_flags.txt")
    file(STRINGS ${MCPTOOL_FLAGS_FILE} mcptool_flags)
    foreach(flag ${mcptool_flags})
        string(STRIP "${MCPTOOL_FLAGS} ${flag}" MCPTOOL_FLAGS)
    endforeach()
	
	# get sources
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_mcptool_sources.txt" MCPTOOL_SRC)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/"  MCPTOOL_SRC "${MCPTOOL_SRC}")
endif()

if(CM_BUILD_IKE OR CM_BUILD_IKE_SP800_135)
    set(IKE_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_ike_flags.txt")
    file(STRINGS ${IKE_FLAGS_FILE} ike_flags)
    foreach(flag ${ike_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()

    if(CM_BUILD_IKE_SP800_135)
      file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_ike_sp800_135_sources.txt" IKE_SRC)
    else()
      file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_ike_sources.txt" IKE_SRC)
    endif()
    if("${CM_TARGET_PLATFORM}" STREQUAL "qnx-x86")
        list(APPEND IKE_SRC "MSS_SRC_DIR/examples/ipseckey_example_qnx.c")
    endif()
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/"  IKE_SRC "${IKE_SRC}")
    
    message("IKE_SRC= ${IKE_SRC}")
    message("EXAMPLE_FLAGS= ${MOCANA_FLAGS}")

    if (NOT CM_BUILD_SHARED_LIBS)
        add_executable(${BUILD_TGT} "${IKE_SRC}")
    else()
        add_library(${BUILD_TGT} SHARED "${IKE_SRC}")
    endif()

if(CM_ENABLE_TAP_LOCAL)
    target_link_libraries(${BUILD_TGT}
        ${COMMON_LIB}
        ${ASN1_LIB}
        ${PLATFORM_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTOMW_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${NANOCAP_LIB}
        ${NANOSSL_LIB}
        ${NANOCERT_LIB}
        ${NANOTAP2_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${TPM2_LIB}
        ${SMPTPM2_LIB}
        ${INITIALIZE_LIB}
        ${DATAPROTECT_LIB}
        ${IKE_LIB}
        ${LIB_PTHREAD}
        ${FIPS_LIB}
        ${WSOCK_LIB}
        )
elseif(CM_ENABLE_TAP_REMOTE)
    target_link_libraries(${BUILD_TGT}
        ${COMMON_LIB}
        ${ASN1_LIB}
        ${PLATFORM_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTOMW_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${NANOCAP_LIB}
        ${NANOSSL_LIB}
        ${NANOCERT_LIB}
        ${NANOTAP2_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${NANOTAP2_CLIENTCOMM_LIB}
        ${INITIALIZE_LIB}
        ${DATAPROTECT_LIB}
        ${IKE_LIB}
        ${LIB_PTHREAD}
        ${FIPS_LIB}
        ${WSOCK_LIB}
        )
else()
    target_link_libraries(${BUILD_TGT}
        ${COMMON_LIB}
        ${ASN1_LIB}
        ${PLATFORM_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTOMW_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${NANOCAP_LIB}
        ${NANOSSL_LIB}
        ${NANOCERT_LIB}
        ${INITIALIZE_LIB}
        ${DATAPROTECT_LIB}
        ${IKE_LIB}
        ${LIB_PTHREAD}
        ${FIPS_LIB}
        ${WSOCK_LIB}
        )
endif()

    target_compile_definitions(${BUILD_TGT} PRIVATE "${MOCANA_FLAGS}")
endif()

if(CM_BUILD_MCPA)
    # get flags	
    set(MCPA_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_mcpagent_flags.txt")
    file(STRINGS ${MCPA_FLAGS_FILE} mcpa_flags)
    if(WIN32)
        list(APPEND mcpa_flags -DENABLE_PACKET_PROCESSOR)
    endif()
    foreach(flag ${mcpa_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()

    # get sources
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_mcpagent_sources.txt" IKE_SRC)

    if(WIN32)
        file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_win_mcp_sources.txt" IKE_WIN_SRC)
        list(APPEND IKE_SRC ${IKE_WIN_SRC})
        list(APPEND IKE_SRC "MSS_SRC_DIR/mcp/win32/ndis_queue.cpp")
    endif()
    if(UNIX AND NOT APPLE)
        list(APPEND IKE_SRC "MSS_SRC_DIR/examples/mocana_example.c")
        list(APPEND IKE_SRC "MSS_SRC_DIR/examples/ipseckey_example_linux.c")
        list(APPEND IKE_SRC "MSS_SRC_DIR/examples/mcp_example.c")
        list(APPEND IKE_SRC "MSS_SRC_DIR/ipsec/script.c")
    endif()
    if("${CM_TARGET_PLATFORM}" STREQUAL "qnx-x86")
        list(APPEND IKE_SRC "MSS_SRC_DIR/examples/mocana_example.c")
        list(APPEND IKE_SRC "MSS_SRC_DIR/examples/mcp_example.c")
        list(APPEND IKE_SRC "MSS_SRC_DIR/examples/ipseckey_example_qnx.c")
        list(APPEND IKE_SRC "MSS_SRC_DIR/ipsec/script.c")
    endif()

    list(REMOVE_DUPLICATES IKE_SRC)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" IKE_SRC "${IKE_SRC}")

    message("EXAMPLE_FLAGS= ${MOCANA_FLAGS}")
    message("EXAMPLE_SRC= ${IKE_SRC}")

	if(WIN32)
		set(RESOURCE_FILE "${MSS_SRC_DIR}/mcp/win32/resource/Mocana-NANOMCP-Agent.man")
		set(RC1_FILE "${MSS_SRC_DIR}/mcp/win32/agent/MCPAgentRes.rc")
		set(RC2_FILE "${CMAKE_CURRENT_SOURCE_DIR}/MCPAgentEvents.rc")		
		add_custom_command(
			OUTPUT  MCPAgentEvents.rc
			COMMAND MC "${MSS_SRC_DIR}/mcp/win32/resource/Mocana-NANOMCP-Agent.man" -um -z MCPAgentEvents
			COMMENT "Code generation for MCP Agent events")
	
		add_definitions("-DEVENT_HEADER=\"${CMAKE_CURRENT_SOURCE_DIR}/MCPAgentEvents.h\"")				
	endif()
	
    if (NOT CM_BUILD_SHARED_LIBS)
	    add_executable(${BUILD_TGT} "${IKE_SRC}" "${RC1_FILE}" "${RC2_FILE}")
    else()
        add_library(${BUILD_TGT} SHARED "${IKE_SRC}" "${RC1_FILE}" "${RC2_FILE}")
    endif()
    # add flags to compilation mode
	set_target_properties(${BUILD_TGT} PROPERTIES COMPILE_FLAGS "${MOCANA_FLAGS}") 
	
    #add_definitions("${MOCANA_FLAGS}")
if(WIN32)
	#post build commands execution
	#add_dependencies(${BUILD_TGT} events) # add pre build commands here
	message("res file is : ${RESOURCE_FILE}")
	message("MSS BIN DIR is : ${MSS_BIN_DIR}")
	if(POSTBUILD_CMD)
	message("inside POST build command")
	if(CM_ENABLE_DEBUG)
	
		add_custom_command(TARGET ${BUILD_TGT}
				   POST_BUILD
				   COMMAND WEVTUTIL um ${RESOURCE_FILE}
				   COMMAND ICACLS ${MSS_BIN_DIR} /grant "BUILTIN\\Users:(OI)(CI)(RX)"
				   COMMAND WEVTUTIL im ${RESOURCE_FILE} /rf:"${MSS_BIN_DIR}/${BUILD_TGT}" /mf:"${MSS_BIN_DIR}/${BUILD_TGT}"
				   COMMENT "Event publisher installation"
				   VERBATIM)
	else()
		add_custom_command(TARGET ${BUILD_TGT}
				   POST_BUILD
				   COMMAND signtool  sign /n "Digicert Inc" /fd SHA256 /tr http://tsa.starfieldtech.com /td SHA256 $(TargetPath)			   			  
				   COMMENT "sign the mcp release target")
	endif()
	endif()
endif()

  if(CM_ENABLE_TAP_LOCAL)
    target_link_libraries(${BUILD_TGT}
        ${COMMON_LIB}
        ${ASN1_LIB}
        ${PLATFORM_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTOMW_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${NANOCAP_LIB}
        ${NANOCERT_LIB}
        ${NANOTAP2_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${TPM2_LIB}
        ${SMPTPM2_LIB}
        ${INITIALIZE_LIB}
        ${DATAPROTECT_LIB}
        ${IKE_LIB}
        ${LIB_PTHREAD}
        ${WSOCK_LIB}
        ${WS32_LIB}
        ${IP_LIB}
        ${NDISAPI_LIB}
        ${BCRYPT_LIB}
        ${NCRYPT_LIB}
        ${CNG_LIB}
        )
  elseif(CM_ENABLE_TAP_REMOTE)
    target_link_libraries(${BUILD_TGT}
        ${COMMON_LIB}
        ${ASN1_LIB}
        ${PLATFORM_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTOMW_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${NANOCAP_LIB}
        ${NANOCERT_LIB}
        ${NANOTAP2_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${NANOTAP2_CLIENTCOMM_LIB}
        ${INITIALIZE_LIB}
        ${DATAPROTECT_LIB}
        ${IKE_LIB}
        ${LIB_PTHREAD}
        ${WSOCK_LIB}
        ${WS32_LIB}
        ${IP_LIB}
        ${NDISAPI_LIB}
        ${BCRYPT_LIB}
        ${NCRYPT_LIB}
        ${CNG_LIB}
        )
  else()
    target_link_libraries(${BUILD_TGT}
        ${COMMON_LIB}
        ${ASN1_LIB}
        ${PLATFORM_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTOMW_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${NANOCAP_LIB}
        ${NANOCERT_LIB}
        ${INITIALIZE_LIB}
        ${DATAPROTECT_LIB}
        ${IKE_LIB}
        ${LIB_PTHREAD}
        ${WSOCK_LIB}
        ${NDISAPI_LIB}
        ${BCRYPT_LIB}
        ${NCRYPT_LIB}
        ${CNG_LIB}
        ${WS32_LIB}
        ${IP_LIB}
        )
  endif()

    target_compile_definitions(${BUILD_TGT} PRIVATE )
endif()

if(CM_BUILD_MCPK OR CM_BUILD_MCPK2)
    # get flags	
    set(MCPK_FLAGS_FILE "${CMAKE_SOURCE_DIR}/mocana_kdc_flags.txt")
    file(STRINGS ${MCPK_FLAGS_FILE} mcpk_flags)
    foreach(flag ${mcpk_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()

    # get sources
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_kdc_sources.txt" IKE_SRC)
	
    if(WIN32)
        file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_win_mcp_sources.txt" IKE_WIN_SRC)
        list(APPEND IKE_SRC ${IKE_WIN_SRC})
    endif()
    if(UNIX AND NOT APPLE)
        list(APPEND IKE_SRC "MSS_SRC_DIR/examples/mocana_example.c")
        list(APPEND IKE_SRC "MSS_SRC_DIR/examples/ipseckey_example_linux.c")
        list(APPEND IKE_SRC "MSS_SRC_DIR/examples/mcp_example.c")
        list(APPEND IKE_SRC "MSS_SRC_DIR/ipsec/script.c")
    endif()

    list(REMOVE_DUPLICATES IKE_SRC)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/"  IKE_SRC "${IKE_SRC}")

    message("EXAMPLE_FLAGS= ${MOCANA_FLAGS}")
    message("EXAMPLE_SRC= ${IKE_SRC}")

if(WIN32)
	if(CM_BUILD_MCPK)
		add_custom_command(
			   OUTPUT KDCEvents.rc
			   COMMAND MC "${MSS_SRC_DIR}/mcp/win32/resource/Mocana-NANOMCP-KDC.man" -um -z KDCEvents
			   COMMENT "Code generation for KDC events")
		#set_target_properties(${BUILD_TGT} PROPERTIES COMPILE_FLAGS "-DEVENT_HEADER=\"${CMAKE_CURRENT_SOURCE_DIR}/KDCEvents.h\"") 
		add_definitions("-DEVENT_HEADER=\"${CMAKE_CURRENT_SOURCE_DIR}/KDCEvents.h\"")	
		set(RESOURCE_FILE "${MSS_SRC_DIR}/mcp/win32/resource/Mocana-NANOMCP-KDC.man")
		set(RC1_FILE "${MSS_SRC_DIR}/mcp/win32/kdc/KDCRes.rc")
		set(RC2_FILE "${CMAKE_CURRENT_SOURCE_DIR}/KDCEvents.rc")
	else()
		add_custom_command(
			   OUTPUT KDCSecondaryEvents.rc
			   COMMAND MC "${MSS_SRC_DIR}/mcp/win32/resource/Mocana-NANOMCP-KDCSecondary.man" -um -z KDCSecondaryEvents
			   COMMENT "Code generation for KDCSecondary events")
		#set_target_properties(${BUILD_TGT} PROPERTIES COMPILE_FLAGS "-DEVENT_HEADER=\""${CMAKE_CURRENT_SOURCE_DIR}/KDCSecondaryEvents.h\""") 
		add_definitions("-DEVENT_HEADER=\"${CMAKE_CURRENT_SOURCE_DIR}/KDCSecondaryEvents.h\"")

		set(RESOURCE_FILE "${MSS_SRC_DIR}/mcp/win32/resource/Mocana-NANOMCP-KDCSecondary.man")
		set(RC1_FILE "${MSS_SRC_DIR}/mcp/win32/kdc_secondary/KDCSecondaryRes.rc")
		set(RC2_FILE "${CMAKE_CURRENT_SOURCE_DIR}/KDCSecondaryEvents.rc")
	endif()
endif()   
	
    if (NOT CM_BUILD_SHARED_LIBS)
	    add_executable(${BUILD_TGT} "${IKE_SRC}" "${RC1_FILE}" "${RC2_FILE}" )
    else()
        add_library(${BUILD_TGT} SHARED "${IKE_SRC}" "${RC1_FILE}" "${RC2_FILE}" )
    endif()
	
    # IF secondary kdc
if(CM_BUILD_MCPK2)
    #add_definitions("-D__ENABLE_DIGICERT_GDOI_CLIENT__")
	set_target_properties(${BUILD_TGT} PROPERTIES COMPILE_FLAGS "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_GDOI_CLIENT__")
else()
    set_target_properties(${BUILD_TGT} PROPERTIES COMPILE_FLAGS "${MOCANA_FLAGS}") 
endif()	

if(WIN32)
	#post build commands execution
	#add_dependencies(${BUILD_TGT} events) # add pre build commands here
	message("res file is : ${RESOURCE_FILE}")
	if(POSTBUILD_CMD)
	message("inside POST build command")
	if(CM_ENABLE_DEBUG)
		message ("ICACLS ${MSS_BIN_DIR} /grant BUILTIN/Users:(OI)(CI)(RX)")
		add_custom_command(TARGET ${BUILD_TGT}
				   POST_BUILD
				   COMMAND WEVTUTIL um ${RESOURCE_FILE}
				   COMMAND ICACLS ${MSS_BIN_DIR} /grant "BUILTIN\\Users:(OI)(CI)(RX)"
				   COMMAND WEVTUTIL im ${RESOURCE_FILE} /rf:"${MSS_BIN_DIR}/${BUILD_TGT}" /mf:"${MSS_BIN_DIR}/${BUILD_TGT}"
				   COMMENT "Event publisher installation"
				   VERBATIM)
	else()
		add_custom_command(TARGET ${BUILD_TGT}
				   POST_BUILD
				   COMMAND signtool  sign /n "Digicert Inc" /fd SHA256 /tr http://tsa.starfieldtech.com /td SHA256 $(TargetPath)			   			  
				   COMMENT "sign the mcp relese target")
	endif()
	endif()
endif()

  if(CM_ENABLE_TAP_LOCAL)
    target_link_libraries(${BUILD_TGT}
        ${COMMON_LIB}
        ${ASN1_LIB}
        ${PLATFORM_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTOMW_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${NANOCAP_LIB}
        ${NANOCERT_LIB}
        ${INITIALIZE_LIB}
        ${DATAPROTECT_LIB}
        ${IKE_LIB}
        ${LIB_PTHREAD}
        ${NANOTAP2_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${TPM2_LIB}
        ${SMPTPM2_LIB}
        ${WSOCK_LIB}
        ${WS32_LIB}
        ${BCRYPT_LIB}
        ${NCRYPT_LIB}
        ${CNG_LIB}
        )
  elseif(CM_ENABLE_TAP_REMOTE)
    target_link_libraries(${BUILD_TGT}
        ${COMMON_LIB}
        ${ASN1_LIB}
        ${PLATFORM_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTOMW_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${NANOCAP_LIB}
        ${NANOCERT_LIB}
        ${INITIALIZE_LIB}
        ${DATAPROTECT_LIB}
        ${IKE_LIB}
        ${LIB_PTHREAD}
        ${NANOTAP2_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${NANOTAP2_CLIENTCOMM_LIB}
        ${WSOCK_LIB}
        ${WS32_LIB}
        ${BCRYPT_LIB}
        ${NCRYPT_LIB}
        ${CNG_LIB}
        )
  else()
    target_link_libraries(${BUILD_TGT}
        ${COMMON_LIB}
        ${ASN1_LIB}
        ${PLATFORM_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTOMW_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${NANOCAP_LIB}
        ${NANOCERT_LIB}
        ${INITIALIZE_LIB}
        ${DATAPROTECT_LIB}
        ${IKE_LIB}
        ${LIB_PTHREAD}
        ${WSOCK_LIB}
        ${WS32_LIB}
        ${BCRYPT_LIB}
        ${NCRYPT_LIB}
        ${CNG_LIB}
        )
  endif()

    target_compile_definitions(${BUILD_TGT} PRIVATE )
endif()

if(WIN32)	
    # for Windows
    #add_definitions("${MCPTOOL_FLAGS} ${EXTRA_DEFINITIONS}") 

    add_executable(mcptool "${MCPTOOL_SRC}" )

    set_target_properties(mcptool PROPERTIES COMPILE_FLAGS "${MCPTOOL_FLAGS} ") 
    target_link_libraries(mcptool
        ${COMMON_LIB}
        ${PLATFORM_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTOMW_LIB}
        )

    target_compile_definitions(mcptool PRIVATE)
endif()

if(NOT CM_BUILD_IKE AND NOT CM_BUILD_IKE_SP800_135)
	# build mcping here
	set(MCPING_SRC "MSS_SRC_DIR/mcp/test_multicast/mcping.c")
if(WIN32)
	list(APPEND MCPING_SRC "MSS_SRC_DIR/mcp/win32/mcping/main.cpp")
endif()
	string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/"  MCPING_SRC "${MCPING_SRC}")
	add_executable(mcping "${MCPING_SRC}")
        target_link_libraries(mcping
        ${WSOCK_LIB}
        )
	target_compile_definitions(mcping PRIVATE "")

endif()

