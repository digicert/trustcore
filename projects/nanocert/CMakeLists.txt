########################################################################
# CMake build script for Mocana CRYPTO SHARED LIBRARY FOR NANO EST
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

# Targets

option(CM_BUILD_SCEP_EXAMPLE_CLIENT "Build SCEP Example Client" OFF)
option(CM_BUILD_SCEP_SAMPLE_CLIENT  "Build SCEP Sample Client"  OFF)

#options
option(CM_DISABLE_SUITEB      "Disable Mocana SuiteB."    OFF)
option(CM_ENABLE_IPV6         "Enable IPV6." OFF)
option(CM_ENABLE_DEBUG        "Enable Debug logs."        OFF)
option(CM_ENABLE_FIPS         "Build with FIPS enabled."  OFF)
option(CM_ENABLE_TAP          "Enable TAP "               OFF)
option(CM_ENABLE_TAP_EXTERN   "Enable TAP extern"         OFF)
option(CM_ENABLE_CERT_BLOB_EXTRACT "Enable with certificate blob extract support" OFF)
option(CM_ENABLE_DATA_PROTECT "Enable data protect support" OFF)
option(CM_DISABLE_PQC         "Disable PQC support"       OFF)
option(CM_ENABLE_CMC          "Enable CMC API"            OFF)
option(CM_ENABLE_OCSP         "Enable OCSP API"           OFF)
option(CM_ENABLE_PROXY        "Enable PROXY"              OFF)
option(CM_ENABLE_CVC          "Enable CV certificates"    OFF)
option(CM_ENABLE_CERT_PRINT "Enable Certificate/CSR printing." OFF)
option(CM_ENABLE_MINIMAL_CA   "Enable minimal CA API"     OFF)
option(CM_ENABLE_AIDE         "Enable AIDE SERVER API"    OFF)
option(CM_ENABLE_SCEP         "Enable SCEP Client"        OFF)
option(CM_ENABLE_EST          "Enable EST Client"         OFF)
option(CM_ENABLE_EXPORT_ED       "Build Export Edition"  OFF)
option(CM_BUILD_X32           "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64           "Build for 64Bit Machine." OFF)
option(CM_ENABLE_DES          "Build with single DES."   OFF)
option(CM_ENABLE_ARC4         "Build with ARC4."         OFF)
option(CM_ENABLE_RSA_8K       "Enable RSA 8K support."   OFF)
option(CM_DISABLE_CI          "Disable crypto interface" OFF)
option(CM_ENABLE_STATUS_LOG   "Enable status logging."   OFF)
if(BUILD_FOR_OSI)
  option(CM_ENABLE_CERT         "Enable with certificate search support" ON)
  option(CM_ENABLE_CMS       "Enable CMS API"             ON)
  option(CM_ENABLE_SSH       "Build with SSH for OSI."    ON)
  if(BUILD_FOR_OSI AND NOT (CM_ENABLE_EXPORT_ED AND CM_ENABLE_OPENSSL_SHIM))
    option(CM_ENABLE_SCRAM_CLIENT "Enable SCRAM client."    ON)
  else()
    option(CM_ENABLE_SCRAM_CLIENT "Enable SCRAM client."   OFF)
  endif()
else()
  option(CM_ENABLE_CERT         "Enable with certificate search support" OFF)
  option(CM_ENABLE_CMS       "Enable CMS API"            OFF)
  option(CM_ENABLE_SSH       "Build with SSH for OSI."   OFF)
  option(CM_ENABLE_SCRAM_CLIENT "Enable SCRAM client."   OFF)
endif()

option(CM_ENABLE_COMPOUND_LIB "Build as a compound lib"   OFF)
option(CM_DISABLE_STRICT_CA_CHECK  "Disable strict CA check ." OFF)
option(CM_DISABLE_CERT_EXT_CHECK "Disable certificate extension check." OFF)
option(CM_ENABLE_JSON_VERIFY  "Build with JSON sign and verify API." OFF)
option(CM_BUILD_MOCANA_NO_PUBKEY_NAME "Build with no public key name"       OFF)

if (WIN32)
    option(CM_WIN_FORCE_LINKAGE "Force linkage for shared library." OFF)
endif()

# Where to find other cmake files (helpers)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
include(MocPlatform)

project (nanocert C)

include(locate_lib)
include(build_rc_file)

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${MSS_DIR}/src")
if(BUILD_FOR_OSI)
  set(LIB_DIR "${MSS_DIR}/lib")
endif()

# 'CACHE STRING' allows us to override this var's value through the bash script
set(LIB_TYPE "SHARED" CACHE STRING "Which lib type to build: SHARED (default) or STATIC")
message("LIB_TYPE           = ${LIB_TYPE}")

message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")
message("")

# Set the directory where to deposit build files
if("STATIC" STREQUAL "${LIB_TYPE}")
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
set(NANOCERT_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(NANOCERT_DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

set(VERSION_FILE "${MSS_DIR}/projects/shared_cmake/set_cpack_version.cmake")
include(${VERSION_FILE})
if(DEFINED ENV{BUILD_NUMBER})
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "$ENV{BUILD_NUMBER}")
else()
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "0")
endif()

# Set the path for where the libraries should be written to
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${NANOCERT_BUILD_DIR}/libs")
if (NOT WIN32)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${NANOCERT_BUILD_DIR}/libs")
endif()

# Set the path to the "top level of the cmake build tree"
set(CMAKE_BINARY_DIR "${NANOCERT_BUILD_DIR}")

message("NANOCERT_BUILD_DIR = ${NANOCERT_BUILD_DIR}")

if(NOT EXISTS ${NANOCERT_DEFS_FILE})
    message(FATAL_ERROR "\nNANOCERT_DEFS_FILE = ${NANOCERT_DEFS_FILE} does not exist")
endif()

message("\nNANOCERT_DEFS_FILE = ${NANOCERT_DEFS_FILE}")

if(CM_ENABLE_CMC AND NOT CM_ENABLE_CMS)
    set(CM_ENABLE_CMS ON)
endif()

# Include general (and compiler-specific) definitions
include(${NANOCERT_DEFS_FILE})
add_compile_options(${WERROR})

set(MOCANA_SERIAL_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_serialize_flags.txt")

# Set export flags if building for export
if(CM_ENABLE_EXPORT_ED)
    set(MOCANA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/export/mocana_flags.txt")
else()
    set(MOCANA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")
endif()

if(NOT EXISTS ${MOCANA_FLAGS_FILE})
    message(FATAL_ERROR "\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE} does not exist")
endif()

message("\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE}")

if (CM_ENABLE_TAP)
    set(MOCANA_TAP_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/tap/mocana_flags.txt")
    message("\nMOCANA_TAP_FLAGS_FILE = ${MOCANA_TAP_FLAGS_FILE}")
endif()

if (CM_ENABLE_CMS)
    set(MOCANA_CMS_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cms/mocana_flags.txt")
    message("\nMOCANA_CMS_FLAGS_FILE = ${MOCANA_CMS_FLAGS_FILE}")
endif()

if(CM_ENABLE_OCSP)
    set(MOCANA_OCSP_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ocsp/mocana_flags.txt")
    message("\nMOCANA_OCSP_FLAGS_FILE = ${MOCANA_OCSP_FLAGS_FILE}")
endif()

if(CM_ENABLE_PROXY)
    set(MOCANA_PROXY_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/httpc/mocana_flags.txt")
    message("\nMOCANA_PROXY_FLAGS_FILE = ${MOCANA_PROXY_FLAGS_FILE}")
endif()

if(CM_ENABLE_MINIMAL_CA)
    set(MOCANA_MINIMAL_CA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/minimal_ca/mocana_flags.txt")
    message("\nMOCANA_MINIMAL_CA_FLAGS_FILE = ${MOCANA_MINIMAL_CA_FLAGS_FILE}")
endif()

if (CM_ENABLE_CMC)
    set(MOCANA_CMC_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cmc/mocana_flags.txt")
    message("\nMOCANA_CMC_FLAGS_FILE = ${MOCANA_CMC_FLAGS_FILE}")
endif()

if (CM_ENABLE_CERT)
    set(MOCANA_CERT_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_cert_flags.txt")
    message("\nMOCANA_CERT_FLAGS_FILE = ${MOCANA_CERT_FLAGS_FILE}")
endif()

if (CM_ENABLE_CVC)
    set(MOCANA_CV_CERT_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_cv_cert_flags.txt")
    message("\nMOCANA_CV_CERT_FLAGS_FILE = ${MOCANA_CV_CERT_FLAGS_FILE}")
endif()

if (CM_ENABLE_CERT_PRINT)
    set(MOCANA_CERT_PRINT_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_cert_print_flags.txt")
    message("\nMOCANA_CERT_PRINT_FLAGS_FILE = ${MOCANA_CERT_PRINT_FLAGS_FILE}")
endif()

if (CM_ENABLE_SCRAM_CLIENT)
    set(MOCANA_SCRAM_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_scram_flags.txt")
    message("\nMOCANA_SCRAM_FLAGS_FILE = ${MOCANA_SCRAM_FLAGS_FILE}")
endif()

if (CM_ENABLE_CERT_BLOB_EXTRACT)
    set(MOCANA_CERT_BLOB_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_cert_blob_extract_flags.txt")
    message("\nMOCANA_CERT_BLOB_FLAGS_FILE = ${MOCANA_CERT_BLOB_FLAGS_FILE}")
endif()

if (CM_ENABLE_DATA_PROTECT)
    set(MOCANA_DATA_PROTECT_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_data_protect_flags.txt")
    message("\nMOCANA_DATA_PROTECT_FLAGS_FILE = ${MOCANA_DATA_PROTECT_FLAGS_FILE}")
endif()

if (CM_ENABLE_AIDE)
    set(MOCANA_AIDE_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/aide/mocana_flags.txt")
    message("\nMOCANA_AIDE_FLAGS_FILE = ${MOCANA_AIDE_FLAGS_FILE}")

    if (NOT CM_ENABLE_TAP)
        set(MOCANA_ATTEST_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/attest/mocana_flags.txt")
        message("\nMOCANA_ATTEST_FLAGS_FILE = ${MOCANA_ATTEST_FLAGS_FILE}")
    endif()
endif()

if (CM_ENABLE_DEBUG)
    set(MOCANA_DEBUG_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt")
    message("\nMOCANA_DEBUG_FLAGS_FILE = ${MOCANA_DEBUG_FLAGS_FILE}")
endif()

if(CM_ENABLE_OPENSSL_SHIM )
    set(MOCANA_OPENSSL_SHIM_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ossl_shim/mocana_flags.txt")
    message("\nMOCANA_OPENSSL_SHIM_FLAGS_FILE = ${MOCANA_OPENSSL_SHIM_FLAGS_FILE}")
endif()

if(CM_ENABLE_SCEP )
    set(MOCANA_SCEP_CLIENT_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/scep/mocana_flags.txt")
    message("\nMOCANA_SCEP_CLIENT_FLAGS_FILE = ${MOCANA_SCEP_CLIENT_FLAGS_FILE}")
endif()

if(CM_ENABLE_EST )
    set(MOCANA_EST_CLIENT_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/est/mocana_flags.txt")
    message("\nMOCANA_EST_CLIENT_FLAGS_FILE = ${MOCANA_EST_CLIENT_FLAGS_FILE}")
endif()

if(CM_ENABLE_SSH)
    set(MOCANA_SSH_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ssh/mocana_flags.txt")
    message("\nMOCANA_SSH_FLAGS_FILE = ${MOCANA_SSH_FLAGS_FILE}")
endif()

if (CM_DISABLE_STRICT_CA_CHECK)
    set(MOCANA_DISABLE_STRICT_CA_CHECK_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/disable_strict_ca_check/mocana_flags.txt")
    message("\nMOCANA_DISABLE_STRICT_CA_CHECK_FLAGS_FILE = ${MOCANA_DISABLE_STRICT_CA_CHECK_FLAGS_FILE}")
endif()

if(CM_DISABLE_CERT_EXT_CHECK)
    set(MOCANA_CERT_EXT_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/disable_cert_ext_check/mocana_flags.txt")
  message("\nMOCANA_CERT_EXT_FLAGS_FILE = ${MOCANA_CERT_EXT_FLAGS_FILE}")
endif()

if(CM_ENABLE_JSON_VERIFY)
    set(MOCANA_ENABLE_JSON_VERIFY_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/json_verify/mocana_flags.txt")
    message("\nMOCANA_ENABLE_JSON_VERIFY_FLAGS_FILE = ${MOCANA_ENABLE_JSON_VERIFY_FLAGS_FILE}")
endif()

if(NOT CM_DISABLE_CI)
  set(MOCANA_CI_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_ci_flags.txt")
  message("\nMOCANA_CI_FLAGS_FILE = ${MOCANA_CI_FLAGS_FILE}")
endif()

if(CM_ENABLE_STATUS_LOG)
    set(MOCANA_STATUS_LOG_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/status_log/mocana_flags.txt")
    message("\nMOCANA_STATUS_LOG_FLAGS_FILE = ${MOCANA_STATUS_LOG_FLAGS_FILE}")
endif()

if(CM_ENABLE_FIPS)
    set(MOCANA_FIPS_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_fips.txt")
    message("\nMOCANA_FIPS_FLAGS_FILE = ${MOCANA_FIPS_FLAGS_FILE}")
endif()

########################################################################
#
# MOCANA FLAGS
#
########################################################################

file(STRINGS ${MOCANA_FLAGS_FILE} mocana_flags)

if (NOT CM_DISABLE_HTTP)
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_HTTP_CLIENT__")
endif()

# Adding IPV6 flags
if (CM_ENABLE_IPV6)
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_IPV6__")
endif()

# Add pkcs5 mapping if CI is enabled but its not export ed
if (NOT CM_DISABLE_CI AND NOT CM_ENABLE_EXPORT_ED)
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_CRYPTO_INTERFACE_PKCS5_MAPPING__")
endif()

# Adding OpenSSL Shim flags
if (CM_ENABLE_OPENSSL_SHIM)
    file(STRINGS ${MOCANA_OPENSSL_SHIM_FLAGS_FILE} mocana_openssl_flags)
    set(mocana_flags ${mocana_flags} ${mocana_openssl_flags})
    if (CM_ENABLE_PROXY)
        set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_SSL_SSLCONNECT_RENAME__")
    endif()
endif()

# Adding TAP flags
if(CM_ENABLE_TAP)
    file(STRINGS ${MOCANA_TAP_FLAGS_FILE} mocana_tap_flags)
    set(mocana_flags ${mocana_flags} ${mocana_tap_flags})
endif()

# Adding CMS flags
if(CM_ENABLE_CMS)
    file(STRINGS ${MOCANA_CMS_FLAGS_FILE} mocana_cms_flags)
    set(mocana_flags ${mocana_flags} ${mocana_cms_flags})
endif()

# Adding OCSP flags
if(CM_ENABLE_OCSP)
    file(STRINGS ${MOCANA_OCSP_FLAGS_FILE} mocana_ocsp_flags)
    set(mocana_flags ${mocana_flags} ${mocana_ocsp_flags})
endif()

# Adding PROXY flags
if(CM_ENABLE_PROXY)
    file(STRINGS ${MOCANA_PROXY_FLAGS_FILE} mocana_proxy_flags)
    set(mocana_flags ${mocana_flags} ${mocana_proxy_flags})
endif()

# Adding minimal CA flags
if(CM_ENABLE_MINIMAL_CA)
    file(STRINGS ${MOCANA_MINIMAL_CA_FLAGS_FILE} mocana_minimal_ca_flags)
    set(mocana_flags ${mocana_flags} ${mocana_minimal_ca_flags})
endif()

# Adding CMC flags
if(CM_ENABLE_CMC)
    file(STRINGS ${MOCANA_CMC_FLAGS_FILE} mocana_cmc_flags)
    set(mocana_flags ${mocana_flags} ${mocana_cmc_flags})
endif()

# Adding certificate search support flags
if(CM_ENABLE_CERT)
    file(STRINGS ${MOCANA_CERT_FLAGS_FILE} mocana_cert_flags)
    set(mocana_flags ${mocana_flags} ${mocana_cert_flags})
endif()

if (CM_ENABLE_CVC)
    file(STRINGS ${MOCANA_CV_CERT_FLAGS_FILE} mocana_cv_cert_flags)
    set(mocana_flags ${mocana_flags} ${mocana_cv_cert_flags})
endif()

if (CM_ENABLE_CERT_PRINT)
    file(STRINGS ${MOCANA_CERT_PRINT_FLAGS_FILE} mocana_cert_print_flags)
    set(mocana_flags ${mocana_flags} ${mocana_cert_print_flags})
endif()

if (CM_ENABLE_SCRAM_CLIENT)
    file(STRINGS ${MOCANA_SCRAM_FLAGS_FILE} mocana_scram_flags)
    set(mocana_flags ${mocana_flags} ${mocana_scram_flags})
endif()

if(CM_ENABLE_CERT_BLOB_EXTRACT)
    file(STRINGS ${MOCANA_CERT_BLOB_FLAGS_FILE} mocana_cert_blob_flags)
    set(mocana_flags ${mocana_flags} ${mocana_cert_blob_flags})
endif()

if(CM_ENABLE_DATA_PROTECT)
    file(STRINGS ${MOCANA_DATA_PROTECT_FLAGS_FILE} mocana_data_protect_flags)
    set(mocana_flags ${mocana_flags} ${mocana_data_protect_flags})
endif()

# Adding Aide server flags
if(CM_ENABLE_AIDE)
    file(STRINGS ${MOCANA_AIDE_FLAGS_FILE} mocana_aide_flags)
    set(mocana_flags ${mocana_flags} ${mocana_aide_flags})

    if (NOT CM_ENABLE_TAP)
        file(STRINGS ${MOCANA_ATTEST_FLAGS_FILE} mocana_attest_flags)
        set(mocana_flags ${mocana_flags} ${mocana_attest_flags})
    endif()
endif()

if(CM_ENABLE_SSH AND CM_ENABLE_OCSP)
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_OCSP_CERT_VERIFY__")
endif()

if (CM_ENABLE_OCSP_CERT)
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_OCSP_CERT_VERIFY__")
endif()

# Adding TAP_extern flag
if (CM_ENABLE_TAP_EXTERN)
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_TAP_EXTERN__")
endif()

if(CM_BUILD_MOCANA_NO_PUBKEY_NAME)
    message("add flag for no Public Key Algorithm name")
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_SSH_NO_PUBKEY_NAME__")
endif()

if (CM_ENABLE_DES)
    message("add flag to enable DES")
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DES_CIPHER__")
endif()

if (CM_ENABLE_RSA_8K)
    message("Adding flag to enable RSA 8K")
    set(mocana_flags ${mocana_flags} "-DMOCANA_MAX_MODULUS_SIZE=1024")
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_RSA_ALL_KEYSIZE__")
endif()

# Adding scep flags
if(CM_ENABLE_SCEP )
    file(STRINGS ${MOCANA_SCEP_CLIENT_FLAGS_FILE} mocana_scep_flags)
    set(mocana_flags ${mocana_flags} ${mocana_scep_flags})
endif()

# Adding est flags
if(CM_ENABLE_EST )
    file(STRINGS ${MOCANA_EST_CLIENT_FLAGS_FILE} mocana_est_flags)
    set(mocana_flags ${mocana_flags} ${mocana_est_flags})
endif()

# Adding ssh flags
if(CM_ENABLE_SSH)
    file(STRINGS ${MOCANA_SSH_FLAGS_FILE} mocana_ssh_flags)
    set(mocana_flags ${mocana_flags} ${mocana_ssh_flags})
endif()

# Adding debug flags
if (CM_ENABLE_DEBUG)
    file(STRINGS ${MOCANA_DEBUG_FLAGS_FILE} mocana_debug_flags)
    set(mocana_flags ${mocana_flags} ${mocana_debug_flags})
endif()

#adding Non Strict ca check flags
if (CM_DISABLE_STRICT_CA_CHECK)
    file(STRINGS ${MOCANA_DISABLE_STRICT_CA_CHECK_FLAGS_FILE} mocana_disable_strict_ca_check_flags)
    set(mocana_flags ${mocana_flags} ${mocana_disable_strict_ca_check_flags})
endif()

if(CM_DISABLE_CERT_EXT_CHECK)
    file(STRINGS ${MOCANA_CERT_EXT_FLAGS_FILE} mocana_cert_ext_flags)
  set(mocana_flags ${mocana_flags} ${mocana_cert_ext_flags})
endif()

# Adding JSON verify flags
if(CM_ENABLE_JSON_VERIFY)
    file(STRINGS ${MOCANA_ENABLE_JSON_VERIFY_FLAGS_FILE} mocana_json_verify_flags)
    set(mocana_flags ${mocana_flags} ${mocana_json_verify_flags})
endif()

if(NOT CM_DISABLE_CI)
  file(STRINGS ${MOCANA_CI_FLAGS_FILE} mocana_ci_flags)
  set(mocana_flags ${mocana_flags} ${mocana_ci_flags})
endif()

if(CM_ENABLE_STATUS_LOG)
    file(STRINGS ${MOCANA_STATUS_LOG_FLAGS_FILE} mocana_status_log_flags)
    set(mocana_flags ${mocana_flags} ${mocana_status_log_flags})
endif()

if(NOT BUILD_FOR_OSI)
  set(mocana_flags ${mocana_flags} "-D__DISABLE_DIGICERT_INIT__")
endif()

if(CM_DISABLE_RSA)
    set(mocana_flags ${mocana_flags} "-D__DISABLE_DIGICERT_RSA__")
else()
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_PKCS1__")
endif()

if(CM_DISABLE_TDES)
    set(mocana_flags ${mocana_flags} "-D__DISABLE_3DES_CIPHERS__")
    set(mocana_flags ${mocana_flags} "-D__DISABLE_3DES_TWO_KEY_CIPHER__")
endif()

if(NOT CM_DISABLE_DSA AND NOT CM_ENABLE_EXPORT_ED)
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_DSA__")
    set(mocana_flags ${mocana_flags} "-D__ENABLE_DIGICERT_DSA_ALL_KEYSIZE__")
endif()

# Adding FIPS flags
if(CM_ENABLE_FIPS)
    file(STRINGS ${MOCANA_FIPS_FLAGS_FILE} mocana_fips_flags)
    set(mocana_flags ${mocana_flags} ${mocana_fips_flags})
endif()

# Adding serialization flags
file(STRINGS ${MOCANA_SERIAL_FLAGS_FILE} mocana_serial_flags)
set(mocana_flags ${mocana_flags} ${mocana_serial_flags})

# Remove any possible duplicates
list(REMOVE_DUPLICATES mocana_flags)

# override the disable flag if rc4 is enabled
if(CM_ENABLE_ARC4)
    list(REMOVE_ITEM mocana_flags "-D__DISABLE_ARC4_CIPHERS__")
endif()

#override the flags if suiteb is disabled
if (CM_DISABLE_SUITEB)
    list(REMOVE_ITEM mocana_flags "-D__ENABLE_DIGICERT_ECC__")
    list(REMOVE_ITEM mocana_flags "-D__ENABLE_DIGICERT_ECC_P192__")
    list(REMOVE_ITEM mocana_flags "-D__ENABLE_DIGICERT_ECC_EDDH_448__")
    list(REMOVE_ITEM mocana_flags "-D__ENABLE_DIGICERT_ECC_EDDH_25519__")
    list(REMOVE_ITEM mocana_flags "-D__ENABLE_DIGICERT_ECC_EDDSA_25519__")
    list(REMOVE_ITEM mocana_flags "-D__ENABLE_DIGICERT_ECC_EDDSA_448__")
    list(REMOVE_ITEM mocana_flags "-D__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC_MAPPING__")
    list(REMOVE_ITEM mocana_flags "-D__ENABLE_DIGICERT_GCM__")
    list(REMOVE_ITEM mocana_flags "-D__ENABLE_DIGICERT_SSL_ECDH_SUPPORT__")
    list(REMOVE_ITEM mocana_flags "-D__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__")
endif()

# override the enable flag if pqc is disabled
if (CM_DISABLE_PQC)
    list(REMOVE_ITEM mocana_flags "-D__ENABLE_DIGICERT_PQC__")
endif()

foreach(flag ${mocana_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

# adding mocana flags

message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

add_definitions("${MOCANA_FLAGS}")

# adding extra definitions from DEFS_FILE

if(WIN32)
    set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DWIN_IMPORT -DWIN_EXPORT_HTTP")
endif()

message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")

add_definitions("${EXTRA_DEFINITIONS}")

# adding include directories listed in mss_includes.txt
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt" MSS_INCLUDES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")

include_directories("." ${MSS_INCLUDES})

message("\nnanocert includes")
message("----------------")
foreach(dir ${MSS_INCLUDES})
    message(${dir})
endforeach()

########################################################################
#
# MOCANA SOURCES
#
########################################################################

if(CM_ENABLE_EXPORT_ED)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/export/mss_sources.txt" MSS_SOURCES)
    if(WIN32 AND "SHARED" STREQUAL "${LIB_TYPE}")
        file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_win_sources.txt" MSS_WIN_SOURCES)
        set(MSS_SOURCES ${MSS_SOURCES} ${MSS_WIN_SOURCES})
    endif()
else()
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt" MSS_SOURCES)
    if(WIN32 AND "SHARED" STREQUAL "${LIB_TYPE}")
        file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_win_sources.txt" MSS_WIN_SOURCES)
        set(MSS_SOURCES ${MSS_SOURCES} ${MSS_WIN_SOURCES})
    endif()
endif()

if(CM_ENABLE_CMS)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/cms/mss_sources.txt" MSS_CMS_SOURCES)
    set(MSS_SOURCES ${MSS_SOURCES} ${MSS_CMS_SOURCES})
endif()

if(CM_ENABLE_OCSP)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/ocsp/mss_sources.txt" MSS_OCSP_SOURCES)
    set(MSS_SOURCES ${MSS_SOURCES} ${MSS_OCSP_SOURCES})
endif()

# The library is being built for AIDE but TAP is disabled. Since the AIDE
# library requires the attest feature, build the TAP attest sources into the
# NanoCert library.
if(CM_ENABLE_AIDE AND NOT CM_ENABLE_TAP)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/attest/mss_sources.txt" MSS_ATTEST_SOURCES)
    set(MSS_SOURCES ${MSS_SOURCES} ${MSS_ATTEST_SOURCES})
endif()

if(CM_ENABLE_STATUS_LOG)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/status_log/mss_sources.txt" STATUS_LOG_SOURCES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" STATUS_LOG_SOURCES "${STATUS_LOG_SOURCES}")
    set(MSS_SOURCES ${MSS_SOURCES} ${STATUS_LOG_SOURCES})
endif()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/asn1/mss_sources.txt" MSS_ASN1_SOURCES)
set(MSS_SOURCES ${MSS_SOURCES} ${MSS_ASN1_SOURCES})
if(WIN32 AND "SHARED" STREQUAL "${LIB_TYPE}")
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/asn1/mss_win_sources.txt" MSS_ASN1_WIN_SOURCES)
    set(MSS_SOURCES ${MSS_SOURCES} ${MSS_ASN1_WIN_SOURCES})
endif()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/httpc/mss_sources.txt" MSS_HTTPC_SOURCES)
set(MSS_SOURCES ${MSS_SOURCES} ${MSS_HTTPC_SOURCES})

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/pkcs/mss_sources.txt" MSS_PKCS_SOURCES)
set(MSS_SOURCES ${MSS_SOURCES} ${MSS_PKCS_SOURCES})

if(CM_ENABLE_EST)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/est/mss_sources.txt" MSS_EST_SOURCES)
    set(MSS_SOURCES ${MSS_SOURCES} ${MSS_EST_SOURCES})
endif()

# Adding SCEP Client sources
if(CM_ENABLE_SCEP)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/scep/mss_sources.txt" MSS_SCEP_SOURCES)
    set(MSS_SOURCES ${MSS_SOURCES} ${MSS_SCEP_SOURCES})
endif()

string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")

# Adding SCEP Example Client sources
if(CM_BUILD_SCEP_EXAMPLE_CLIENT)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/scep_example_client/mss_sources.txt"
        MSS_SCEP_EXMAPLE_CLIENT_SOURCES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/"
           MSS_SCEP_EXAMPLE_CLIENT_SOURCES "${MSS_SCEP_EXAMPLE_CLIENT_SOURCES}")

    add_executable(scep_example_client ${MSS_SOURCES} ${MSS_SCEP_EXMAPLE_CLIENT_SOURCES})
endif()

# Adding SCEP Sample Client sources
if(CM_BUILD_SCEP_SAMPLE_CLIENT)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/scep_sample_client/mss_sources.txt"
        MSS_SCEP_SAMPLE_CLIENT_SOURCES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/"
           MSS_SCEP_SAMPLE_CLIENT_SOURCES "${MSS_SCEP_SAMPLE_CLIENT_SOURCES}")

    add_executable(scep_sample_client ${MSS_SOURCES} ${MSS_SCEP_SAMPLE_CLIENT_SOURCES})
endif()

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
    set(ASN1_LIB "${LIB_DIR}/libasn1.so")
    set(COMMON_LIB "${LIB_DIR}/libcommon.so")
    if(CM_ENABLE_EXPORT_ED)
        set(CRYPTO_MW_LIB "${LIB_DIR}/libcryptomw.so")
    else()
        set(NANOCRYPTO_LIB "${LIB_DIR}/libnanocrypto.so")
    endif()
    if(NOT CM_DISABLE_CI)
      set(CRYPTOINTERFACE_LIB "${LIB_DIR}/libcryptointerface.so")
      set(NANOCAP_LIB "${LIB_DIR}/libnanocap.so")
    endif()
    set(INITIALIZE_LIB "${LIB_DIR}/libinitialize.so")
  else()
    # Get the full path of our base libraries.
    # Note: If library is not found, variable will be empty.
    locate_lib(ASN1_LIB asn1)
    locate_lib(COMMON_LIB common)
    locate_lib(NANOCRYPTO_LIB nanocrypto)
    if(NOT CM_DISABLE_CI)
        locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
        locate_lib(NANOCAP_LIB nanocap)
    endif()
    locate_lib(INITIALIZE_LIB initialize)
  endif()
    locate_lib(ASN1DATA_LIB asn1data)
    locate_lib(CRYPTO_MW_LIB cryptomw)
    if (CM_ENABLE_DATA_PROTECT)
        locate_lib(DATA_PROTECT_LIB dataprotect)
    endif()
    if(CM_ENABLE_FIPS)
      locate_lib(LIBMSS_LIB libmss)
    endif()

    # If AIDE is enabled and TAP is enabled then link against the TPM2 library
    # to get the attest feature.
    #
    # If AIDE is enabled and TAP is disabled then the attest sources will be
    # built into the NanoCert library itself.
    if (CM_ENABLE_AIDE AND CM_ENABLE_TAP)
        locate_lib(TPM2_LIB tpm2)
    endif()

    # Build the of list shared libraries to link against based on the command-line
    # options we were passed
    set(LIB_LINK_ORDER
        ${CRYPTOINTERFACE_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTO_MW_LIB}
        ${ASN1_LIB}
        ${ASN1DATA_LIB}
        ${COMMON_LIB}
        ${INITIALIZE_LIB}
        ${NANOCAP_LIB}
        )

    if (CM_ENABLE_AIDE AND CM_ENABLE_TAP)
        set(LIB_LINK_ORDER ${LIB_LINK_ORDER} ${TPM2_LIB})
    endif()

    if (CM_ENABLE_DATA_PROTECT)
        set(LIB_LINK_ORDER ${LIB_LINK_ORDER} ${DATA_PROTECT_LIB})
    endif()

    if (CM_ENABLE_FIPS)
        set(LIB_LINK_ORDER ${LIB_LINK_ORDER} ${LIBMSS_LIB})
    endif()

    #if(CM_ENABLE_TAP)
    #    set(LIB_LINK_ORDER nanotap2 smptpm2 tpm2 nanotap2_common ${LIB_LINK_ORDER})
    #endif()
    if(WIN32)
        locate_lib(INITIALIZE_LIB initialize)
        locate_lib(PLATFORM_LIB platform)
        set(LIB_LINK_ORDER ${LIB_LINK_ORDER}
            ${INITIALIZE_LIB}
            ${PLATFORM_LIB}
            Shlwapi.lib
            Ws2_32.lib)
    endif()

    if(ANDROID)
        locate_lib(INITIALIZE_LIB initialize)
        locate_lib(PLATFORM_LIB platform)
        set(LIB_LINK_ORDER ${LIB_LINK_ORDER}
            ${INITIALIZE_LIB}
            ${PLATFORM_LIB})
    endif()

    message("Libraries link order: ${LIB_LINK_ORDER}")
    target_link_libraries(${PROJECT_NAME} ${LIB_LINK_ORDER})

else()
    add_library(${PROJECT_NAME} STATIC ${MSS_SOURCES})

    if(CM_ENABLE_COMPOUND_LIB)
        set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)
    endif()
endif()
