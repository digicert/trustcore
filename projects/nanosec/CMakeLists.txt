## Compile libraries and executables for NanoSEC targets
##

cmake_minimum_required(VERSION 3.5)
## ON/OFF Options
option(CM_ENABLE_TAP_LOCAL  "Enable Tap Local" OFF)
option(CM_ENABLE_TAP_REMOTE "Enable Tap Remote" OFF)
option(CM_ENABLE_DEBUG      "Enable Debug Console in application code." OFF)
option(CM_DISABLE_SUITEB    "Disable Suite-B Crypto." OFF)
option(CM_DISABLE_PQC       "Disable PQC." OFF)
option(CM_ENABLE_RFC4806    "Enable RFC 4806 support. " OFF)
option(CM_ENABLE_FIPS       "Building with FIPS enabled." OFF)
option(CM_ENABLE_DUAL_MODE  "Enable DUAL mode." OFF)
option(CM_ENABLE_NW_RED     "Enable NW redundancy." OFF)
option(CM_ENABLE_EAPA       "Building with EAP authenticator" OFF)
option(CM_ENABLE_EAPS       "Building with EAP supplicant" OFF)
option(CM_ENABLE_EXPORT     "Building in export mode" OFF)
option(CM_ENABLE_TLSA       "Building with TLS" OFF)
option(CM_ENABLE_TLSS       "Building with TLS" OFF)
option(CM_ENABLE_IPV6       "Enable IPV6." OFF)
option(CM_ENABLE_STRONGSWAN "Building support for Strongswan 5.6.2" OFF)
option(CM_ENABLE_UNSECURE   "Building with unsecure algorithms" OFF)
option(CM_ENABLE_TRUSTEDGE  "Building with TrustEdge mode enabled" OFF)
option(CM_BUILD_IKE         "Building ike" OFF)
option(CM_BUILD_IKE_SP800_135 "Building ike for testing SP800-135" OFF)
option(CM_BUILD_MCPA        "Building mcpagent" OFF)
option(CM_BUILD_MCPK        "Building kdc" OFF)
option(CM_BUILD_MCPK2       "Building kdc_secondary" OFF)

option(CM_BUILD_X32           "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64           "Build for 64Bit Machine." OFF)
option(CM_ENABLE_MOCANA_IKE_REF_IDENTIFIER_MATCH "Enable Reference Identifier match capability." OFF)

if (WIN32)
    option(CM_WIN_FORCE_LINKAGE "Force linkage for shared library." OFF)
endif()

## Default
if(NOT DEFINED CM_CLIENT_TAP)
  set(CM_CLIENT_TAP OFF)
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
include(MocPlatform)

project(nanosec C)

include(locate_lib)

set(LIB_TYPE "SHARED" CACHE STRING "Type of library to build. (SHARED or STATIC)")
message("LIB_TYPE           = ${LIB_TYPE}")

if(WIN32)
  set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32")
else()
  set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
endif()
set(MSS_LIBRARY_PATH ${MSS_BIN_DIR})

set(BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")

# Use samples/nanosec if present, otherwise fall back to src/examples
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../samples/nanosec")
  set(NANOSEC_SRC_DIR "${MSS_SRC_DIR}/../samples/nanosec/src")
  set(NANOSEC_LINUX_DIR "${MSS_SRC_DIR}/../samples/nanosec/src/linux")
else()
  set(NANOSEC_SRC_DIR "${MSS_SRC_DIR}/examples")
  set(NANOSEC_LINUX_DIR "${MSS_SRC_DIR}/examples/ipsec/linux")
endif()
if(BUILD_FOR_OSI)
  set(LIB_DIR "${MSS_DIR}/lib")
endif()
set(CMAKE_INSTALL_RPATH "${MSS_BIN_DIR}")
set(MSS_LIBRARY_TYPE STATIC)
set(RC1_FILE "")
set(RC2_FILE "")

set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
if(NOT EXISTS ${DEFS_FILE})
  message(FATAL_ERROR "\nDEFS_FILE = ${DEFS_FILE} does not exist")
endif()

message("\nDEFS_FILE = ${DEFS_FILE}")
include(${DEFS_FILE})
add_compile_options(${WERROR})

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIR}/libs")
## Set PATHs
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${MSS_BIN_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${MSS_BIN_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${MSS_BIN_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${MSS_BIN_DIR})

set(SHARED_LIB_EXT "so")
set(STATIC_LIB_EXT "a")
set(LIB_PREFIX "lib")
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(MACOSX TRUE)
  set(SHARED_LIB_EXT "dylib")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(SHARED_LIB_EXT "dll")
  set(STATIC_LIB_EXT "lib")
  set(LIB_PREFIX "")
endif()


set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
if(NOT EXISTS ${DEFS_FILE})
  message(FATAL_ERROR "\nDEFS_FILE = ${DEFS_FILE} does not exist")
endif()

message("\nDEFS_FILE = ${DEFS_FILE}")
## Include general definitions
include(${DEFS_FILE})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

message("\nCMAKE_C_FLAGS = ${CMAKE_C_FLAGS}")
# Create version.h from the above.
#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../../src/ipsec/ipsec_version.h.in
#               ${CMAKE_CURRENT_SOURCE_DIR}/../../src/ipsec/ipsec_version.h)

## Locate tools
if(WIN32)
  message ("inisde WIN32 flag")
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

if (WIN32)
  if (CM_WIN_FORCE_LINKAGE)
    # Force to link even if unresolved symbols encountered in first pass
    foreach(item SHARED_LINKER_FLAGS
          SHARED_LINKER_FLAGS_DEBUG
          )
      message("----------------")
      message("CMAKE_${item}  = ${CMAKE_${item}}")
      set(CMAKE_${item} "${CMAKE_${item}} /FORCE:UNRESOLVED")
      message("CMAKE_${item}  = ${CMAKE_${item}}")
    endforeach()
  endif() #if(CM_WIN_FORCE_LINKAGE)
endif()
########################################################################
# Mocana Flags
########################################################################

# ADD LINUX FLAG AFTER OS CHECK HERE

# flags that are needed by all targets
set(FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")

## Read and set flags
file(STRINGS ${FLAGS_FILE} project_flags)
foreach(flag ${project_flags})
  string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

if(NOT CM_DISABLE_SUITEB)
  if(CM_ENABLE_EXPORT AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_export_suiteb_flags.txt")
    set(SUITEB_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_export_suiteb_flags.txt")
    file(STRINGS ${SUITEB_FLAGS_FILE} suiteb_flags)
    foreach(flag ${suiteb_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
  else()
    set(SUITEB_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_suiteb_flags.txt")
    file(STRINGS ${SUITEB_FLAGS_FILE} suiteb_flags)
    foreach(flag ${suiteb_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
  endif()
endif()

if(CM_ENABLE_STRONGSWAN)
    string(APPEND MOCANA_FLAGS " -D__ENABLE_DIGICERT_IKE_STRONGSWAN_562__ ")
endif()

if(CM_BUILD_IKE_SP800_135)
    string(APPEND MOCANA_FLAGS " -D__ENABLE_DIGICERT_SP800_135_ACVP__ ")
    string(REGEX REPLACE "-D__ENABLE_IPSEC_MARGIN_LIFETIME__" "" MOCANA_FLAGS "${MOCANA_FLAGS}")
endif()

if (CM_ENABLE_UNSECURE)
    string(APPEND MOCANA_FLAGS " -D__ENABLE_DIGICERT_IKE_UNSECURE_HASH__ ")
    if (CM_ENABLE_SUITEB)
        string(APPEND MOCANA_FLAGS " -D__ENABLE_DIGICERT_ECC_P192__ ")
    endif()
endif()

if(CM_ENABLE_RFC4806)
    string(APPEND MOCANA_FLAGS " -D__ENABLE_IKE_OCSP_EXT__ -D__ENABLE_DIGICERT_OCSP_CLIENT__ -D__ENABLE_DIGICERT_OCSP_STORE__ -D__ENABLE_DIGICERT_OCSP_CERT_STORE_EXT__")
endif()

if(CM_ENABLE_DUAL_MODE)
    set(DUAL_MODE_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_dual_mode_flags.txt")
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

if (CM_ENABLE_TAP_LOCAL OR CM_ENABLE_TAP_REMOTE)
    set(TAP_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_tap_flags.txt")
    file(STRINGS ${TAP_FLAGS_FILE} tap_flags)
    foreach(flag ${tap_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
    if (CM_ENABLE_TAP_REMOTE)
        set(TAP_REMOTE_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_tap_remote_flags.txt")
        file(STRINGS ${TAP_REMOTE_FLAGS_FILE} tap_remote_flags)
        foreach(flag ${tap_remote_flags})
            string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
        endforeach()
    endif()
endif()

if (CM_ENABLE_DEBUG)
    set(DEBUG_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt")
    file(STRINGS ${DEBUG_FLAGS_FILE} debug_flags)
    foreach(flag ${debug_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_ENABLE_FIPS)
    string(STRIP "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_FIPS_MODULE__" MOCANA_FLAGS)
endif()

if(CM_ENABLE_EAPA)
    set(EAP_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_eap_flags.txt")
    file(STRINGS ${EAP_FLAGS_FILE} eap_flags)
    foreach(flag ${eap_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()

    set(EAPA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_eap_auth_flags.txt")
    file(STRINGS ${EAPA_FLAGS_FILE} eapa_flags)
    foreach(flag ${eapa_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_ENABLE_EAPS)
    set(EAP_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_eap_flags.txt")
    file(STRINGS ${EAP_FLAGS_FILE} eap_flags)
    foreach(flag ${eap_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()

    set(EAPS_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_eap_supplicant_flags.txt")
    file(STRINGS ${EAPS_FLAGS_FILE} eaps_flags)
    foreach(flag ${eaps_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_ENABLE_TLSA)
    set(TLS_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_tls_flags.txt")
    file(STRINGS ${TLS_FLAGS_FILE} tls_flags)
    foreach(flag ${tls_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()

    set(TLSA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_tls_eap_auth_flags.txt")
    file(STRINGS ${TLSA_FLAGS_FILE} tlsa_flags)
    foreach(flag ${tlsa_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_ENABLE_TLSS)
    set(TLS_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_tls_flags.txt")
    file(STRINGS ${TLS_FLAGS_FILE} tls_flags)
    foreach(flag ${tls_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_ENABLE_IPV6)
    set(IPV6_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_ipv6_flags.txt")
    file(STRINGS ${IPV6_FLAGS_FILE} ipv6_flags)
    foreach(flag ${ipv6_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_ENABLE_EXPORT)
    set(EXPORT_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_export_flags.txt")
    file(STRINGS ${EXPORT_FLAGS_FILE} export_flags)
    foreach(flag ${export_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_BUILD_MCPA)
    set(MCPA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mcpagent/mocana_flags.txt")
    file(STRINGS ${MCPA_FLAGS_FILE} mcpa_flags)
    if(WIN32)
	    list(APPEND mcpa_flags -D__DYNAMIC_IKE_DEFAULT_UDP_PORT__)
    endif()

    foreach(flag ${mcpa_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_BUILD_MCPK)
    set(MCPK_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/kdc/mocana_flags.txt")
    file(STRINGS ${MCPK_FLAGS_FILE} mcpk_flags)
    foreach(flag ${mcpk_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_BUILD_MCPK2)
    set(MCPK2_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/kdc_secondary/mocana_flags.txt")
    file(STRINGS ${MCPK2_FLAGS_FILE} mcpk2_flags)
    foreach(flag ${mcpk2_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if (NOT CM_DISABLE_PQC)
    set(PQC_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_pqc_flags.txt")
    file(STRINGS ${PQC_FLAGS_FILE} pqc_flags)
    foreach(flag ${pqc_flags})
        string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
    endforeach()
endif()

if(CM_BUILD_IKE OR CM_BUILD_IKE_SP800_135)
    add_definitions(" -D__ENABLE_IPSEC_NAT_T__ ")
    add_definitions(" -D__ENABLE_IKE_PPK_RFC8784__ ")
endif()

if(CMAKE_CROSSCOMPILING)
  add_definitions(${PLATFORM_CPU_FLAGS})
endif()

## To silence the warning message in mocana.c DIGICERT_initLog():
##   __ENABLE_DIGICERT_PRODUCT_DEBUG_CONSOLE__
add_definitions("${MOCANA_FLAGS} -D__ENABLE_DIGICERT_PRODUCT_DEBUG_CONSOLE__")

# Enabled flags that do not have export version
if(NOT CM_ENABLE_EXPORT)
if (CM_BUILD_X64)
    add_definitions(" -D__ENABLE_DIGICERT_BLAKE_2B__ ")
endif()
    add_definitions(" -D__ENABLE_DIGICERT_BLAKE_2S__ ")
endif()


# Load the EXTRA_DEFINITIONS flags (from mss_defs.cmake) into the build
message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")
add_definitions("${EXTRA_DEFINITIONS}")

# IF LINUX!!!!
#add_definitions("${MOCANA_FLAGS} -D__RTOS_LINUX__")

# Toggle MOC_EXTERN_P to map to '__declspec(dllimport)'
if(WIN32)
  add_definitions("-DWIN_IMPORT")
endif()


## Add resources for events on supported platforms
if(WIN32)
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
if(NOT TARGET common)
  add_library(common SHARED IMPORTED)
  set_property(TARGET common PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}common.${SHARED_LIB_EXT})
endif()

if(NOT TARGET asn1)
  add_library(asn1 SHARED IMPORTED)
  set_property(TARGET asn1 PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}asn1.${SHARED_LIB_EXT})
endif()

if(NOT TARGET nanocrypto)
  add_library(nanocrypto SHARED IMPORTED)
  set_property(TARGET nanocrypto PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}nanocrypto.${SHARED_LIB_EXT})
endif()

if(NOT TARGET nanocert)
  add_library(nanocert SHARED IMPORTED)
  set_property(TARGET nanocert PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}nanocert.${SHARED_LIB_EXT})
endif()

if(NOT TARGET nanossl)
  add_library(nanossl SHARED IMPORTED)
  set_property(TARGET nanossl PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}nanossl.${SHARED_LIB_EXT})
endif()

if(NOT TARGET nanotap2_common)
  add_library(nanotap2_common SHARED IMPORTED)
  set_property(TARGET nanotap2_common PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}nanotap2_common.${SHARED_LIB_EXT})
endif()

if(NOT TARGET nanotap2_configparser)
  add_library(nanotap2_configparser SHARED IMPORTED)
  set_property(TARGET nanotap2_configparser PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}nanotap2_configparser.${SHARED_LIB_EXT})
endif()

if(NOT TARGET nanotap2)
  add_library(nanotap2 SHARED IMPORTED)
  set_property(TARGET nanotap2 PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}nanotap2.${SHARED_LIB_EXT})
endif()

if(NOT TARGET smptpm2)
  add_library(smptpm2 SHARED IMPORTED)
  set_property(TARGET smptpm2 PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}smptpm2.${SHARED_LIB_EXT})
endif()

if(NOT TARGET tpm2)
  add_library(tpm2 SHARED IMPORTED)
  set_property(TARGET tpm2 PROPERTY IMPORTED_LOCATION ${MSS_LIBRARY_PATH}/${LIB_PREFIX}tpm2.${SHARED_LIB_EXT})
endif()

# Add include directories defined in mss_includes.txt
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt" MSS_INCLUDES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")
string(REGEX REPLACE "${MSS_SRC_DIR}/../samples/nanosec/src/linux" "${NANOSEC_LINUX_DIR}" MSS_INCLUDES "${MSS_INCLUDES}")
string(REGEX REPLACE "${MSS_SRC_DIR}/../samples/nanosec/src" "${NANOSEC_SRC_DIR}" MSS_INCLUDES "${MSS_INCLUDES}")
include_directories("." ${MSS_INCLUDES})

# These fils are used by all
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt" IKE_SRC)
if(WIN32 AND NOT CM_BUILD_IKE)
    list(APPEND IKE_SRC "MSS_SRC_DIR/common/win32crypto.c")
endif()
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/"  IKE_SRC "${IKE_SRC}")
string(REGEX REPLACE "${MSS_SRC_DIR}/../samples/nanosec/src/linux" "${NANOSEC_LINUX_DIR}" IKE_SRC "${IKE_SRC}")
string(REGEX REPLACE "${MSS_SRC_DIR}/../samples/nanosec/src" "${NANOSEC_SRC_DIR}" IKE_SRC "${IKE_SRC}")

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
message("IKE_SRC= ${IKE_SRC}")

# add custom files for eap and tls here
if(CM_ENABLE_EAPA OR CM_ENABLE_EAPS)
    # add eap and radius files here
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_eap_sources.txt" IKE_EAP_SRC)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/"  IKE_EAP_SRC "${IKE_EAP_SRC}")

    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_radius_sources.txt" IKE_RADIUS_SRC)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/"  IKE_RADIUS_SRC "${IKE_RADIUS_SRC}")

    if(CM_ENABLE_TLSA OR CM_ENABLE_TLSS)
        # add files for ssl non tls environment
        file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_ssl_sources.txt" IKE_SSL_SRC)
        string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/"  IKE_SSL_SRC "${IKE_SSL_SRC}")
    endif()
endif()


if(CM_BUILD_MCPA)
    # These fils are used by all
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mcpagent/mss_sources.txt" MCPA_SRC)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_mcp_sources.txt" MCP_ONLY_SRC)
    list(APPEND MCPA_SRC ${MCP_ONLY_SRC})
    if(WIN32)
        file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_win_mcp_sources.txt" IKE_WIN_SRC)
        list(APPEND MCPA_SRC ${IKE_WIN_SRC})
    endif()
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/"  MCPA_SRC "${MCPA_SRC}")
endif()

if(CM_BUILD_MCPK)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/kdc/mss_sources.txt" MCPK_SRC)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_mcp_sources.txt" MCP_ONLY_SRC)
    list(APPEND MCPK_SRC ${MCP_ONLY_SRC})
	if(WIN32)
        file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_win_mcp_sources.txt" IKE_WIN_SRC)
        list(APPEND MCPK_SRC ${IKE_WIN_SRC})
    endif()
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/"  MCPK_SRC "${MCPK_SRC}")
endif()

if(CM_BUILD_MCPK2)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/kdc_secondary/mss_sources.txt" MCPK2_SRC)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_mcp_sources.txt" MCP_ONLY_SRC)
    list(APPEND MCPK2_SRC ${MCP_ONLY_SRC})
    if(WIN32)
        file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_win_mcp_sources.txt" IKE_WIN_SRC)
        list(APPEND MCPK2_SRC ${IKE_WIN_SRC})
    endif()
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/"  MCPK2_SRC "${MCPK2_SRC}")
endif()

message(" IKE_SRC= ${IKE_SRC}")
########################################################################
# Locate base libraries
########################################################################


## Add symlink for non-Windows platforms
if(NOT WIN32)
  set(INSTALL_PERSIST_FILES ${INSTALL_PERSIST_FILES} sample/tpuc_data/persist/config.json)
endif()
if(WIN32)
  link_directories(${MSS_SRC_DIR}/../bin_win32)
else()
  link_directories(${MSS_SRC_DIR}/../bin)
endif()

if(CM_BUILD_IKE)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
	# merge all the sources into a single variable
	set(MSS_SOURCES ${IKE_SRC} ${IKE_EAP_SRC} ${IKE_SSL_SRC} ${IKE_RADIUS_SRC})
	set(PROJECT_NAME ike)
    #add_library(ike SHARED ${IKE_SRC} ${IKE_EAP_SRC} ${IKE_SSL_SRC} ${IKE_RADIUS_SRC})
endif()

if(CM_BUILD_IKE_SP800_135)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
	# merge all the sources into a single variable
	set(MSS_SOURCES ${IKE_SRC} ${IKE_EAP_SRC} ${IKE_SSL_SRC} ${IKE_RADIUS_SRC})
	set(PROJECT_NAME ike_sp800_135)
    #add_library(ike SHARED ${IKE_SRC} ${IKE_EAP_SRC} ${IKE_SSL_SRC} ${IKE_RADIUS_SRC})
endif()

if(CM_BUILD_MCPA)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
	set(MSS_SOURCES ${IKE_SRC} ${IKE_EAP_SRC} ${IKE_SSL_SRC} ${IKE_RADIUS_SRC} ${MCPA_SRC})
	set(PROJECT_NAME "${BUILD_TGT}")
endif()

if(CM_BUILD_MCPK)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
    set(MSS_SOURCES ${IKE_SRC} ${MCPK_SRC})
    set(PROJECT_NAME "${BUILD_TGT}")
endif()

if(CM_BUILD_MCPK2)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
    set(MSS_SOURCES ${IKE_SRC} ${MCPK2_SRC})
    set(PROJECT_NAME "${BUILD_TGT}")
endif()


  # Locate any needed libraries to link against

if("SHARED" STREQUAL "${LIB_TYPE}")
  # Locate any needed libraries to link against
  message("MSS_SOURCES = ${MSS_SOURCES}")
  message("PROJECT_NAME = ${PROJECT_NAME}")
  add_library(${PROJECT_NAME} SHARED ${MSS_SOURCES})

  if(BUILD_FOR_OSI)
    add_custom_command(
      TARGET ${PROJECT_NAME}
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy
          $<TARGET_FILE:${PROJECT_NAME}>
          "${LIB_DIR}")
  endif()

  locate_lib(PLATFORM_LIB platform)
  locate_lib(CRYPTOMW_LIB cryptomw)
  locate_lib(NANOCRYPTO_LIB nanocrypto)
  locate_lib(NANOCAP_LIB nanocap)
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
    locate_lib(NANOTAP2_CLIENTCOMM_LIB tpm2)
  endif()
  if(CM_ENABLE_FIPS)
    locate_lib(FIPS_LIB mss)
  endif()

  if(WIN32)
      if(CM_ENABLE_TAP_LOCAL)
        target_link_libraries(${PROJECT_NAME}
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
             ${IKE_LIB}
             ${NCRYPT_LIB}
             ${BCRYPT_LIB}
             ${CNG_LIB}
             Shlwapi.lib Ws2_32.lib tbs.lib )
      elseif(CM_ENABLE_TAP_REMOTE)
        target_link_libraries(${PROJECT_NAME}
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
             ${IKE_LIB}
             ${NCRYPT_LIB}
             ${BCRYPT_LIB}
             ${CNG_LIB}
             Shlwapi.lib Ws2_32.lib tbs.lib )
      else()
        target_link_libraries(${PROJECT_NAME}
            ${COMMON_LIB}
            ${ASN1_LIB}
            ${PLATFORM_LIB}
            ${NANOCRYPTO_LIB}
            ${CRYPTOMW_LIB}
            ${CRYPTOINTERFACE_LIB}
            ${NANOCAP_LIB}
            ${NANOCERT_LIB}
            ${INITIALIZE_LIB}
            ${IKE_LIB}
            ${NCRYPT_LIB}
            ${BCRYPT_LIB}
            ${CNG_LIB}
            ${FIPS_LIB}
            Shlwapi.lib Ws2_32.lib tbs.lib )
    endif()
  endif()
else()
  add_library(${PROJECT_NAME} STATIC ${MSS_SOURCES})

  if(BUILD_FOR_OSI)
    add_custom_command(
      TARGET ${PROJECT_NAME}
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy
          $<TARGET_FILE:${PROJECT_NAME}>
          "${LIB_DIR}"
      COMMENT "Copied lib${PROJECT_NAME}.a to ${LIB_DIR}")
  endif()
endif()
