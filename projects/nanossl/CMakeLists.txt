########################################################################
# CMake build script for Mocana nanossl SHARED LIBRARY FOR NanoSMP
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_TLS13                   "Enable TLS 1.3."                 ON)
option(CM_ENABLE_TLS13_PSK               "Enable TLS 1.3 PSK feature."     ON)
option(CM_ENABLE_TLS13_0RTT              "Enable TLS 1.3 0-RTT feature."   ON)
option(CM_ENABLE_PSK                     "Enable TLS 1.2 and below PSK."   OFF)
option(CM_ENABLE_IPV6                    "Enable IPV6." OFF)
option(CM_ENABLE_NIL                     "Enable Nil Cipher."              OFF)
option(CM_ENABLE_DEBUG                   "Enable Debug logs."              OFF)
option(CM_ENABLE_TAP                     "Enable tap ."                    OFF)
option(CM_ENABLE_TAP_LOCAL               "Enable tap local."               OFF)
option(CM_ENABLE_TAP_REMOTE              "Enable tap remote."              OFF)
option(CM_ENABLE_OPENSSL_SHIM            "Enable openssl_shim."            OFF)
option(CM_ENABLE_TAP_EXTERN              "Enable tap extern."              OFF)
option(CM_ENABLE_PSS_AUTO_RECOVER        "Allow NanoSSL to recover salt length for RSA PSS." OFF)
option(CM_ENABLE_OSSL_TLS_UNIQUE         "Enable additional TLS unique support in OpenSSL." OFF)
option(CM_ENABLE_COMMON_LINK             "Enable linking to common libnanossl.so" OFF)
option(CM_BUILD_SSL_CLIENT               "Build ssl client."               OFF)
option(CM_BUILD_SSL_CLIENT_ASYNC         "Build ssl async client."         OFF)
option(CM_BUILD_SSL_CLIENT_SP800_135     "Build ssl client for testing SP800-135"         OFF)
option(CM_BUILD_SSL_SERVER               "Build ssl server."               OFF)
option(CM_BUILD_SSL_SERVER_GW            "Build ssl server for GW."        OFF)
option(CM_BUILD_SSL_SERVER_ASYNC         "Build ssl async server."         OFF)
option(CM_ENABLE_NANOSSL_TAP             "Enable tap."                     OFF)
option(CM_BUILD_OPENSSL_SHIM_LIB         "Enable OPENSSL_SHIM lib."        OFF)
option(CM_ENABLE_DTLS                    "Enable DTLS."                    OFF)
option(CM_ENABLE_EXPORT_ED               "Build Export Edition."           OFF)
option(CM_DISABLE_PQC                    "Disbale Post Quantum Cryptography." OFF)
option(CM_ENABLE_PQC_COMPOSITE           "Enable PQC Composite." OFF)
option(CM_ENABLE_TAP_REMOTE_TCP          "Enable tap remote tcp"           OFF)
option(CM_ENABLE_SSL_SELF_SIGNED_CERT    "Enable self signed "             OFF)
option(CM_ENABLE_SSL_NONTRUSTED_CERT     "Enable non trusted cert"         OFF)
option(CM_ENABLE_SSL_CERT_STATUS_OVERRIDE "Override the OpenSSL shim with NanoSSL certificate status.")
option(CM_ENABLE_SSL_OCSP                "Enable OCSP"                     OFF)
option(CM_ENABLE_GCC_PROFILING           "Enable gcc profiling"            OFF)
option(CM_ENABLE_FIPS                    "Enable fips module"              OFF)
option(CM_ENABLE_EAP_FAST                "Enable EAP fast"                 OFF)
option(CM_ENABLE_RSA_1024_SUPPORT        "Enable 1024 RSA keys."           OFF)
option(CM_ENABLE_SHA1_SUPPORT            "Enable SHA-1 support."           OFF)
option(CM_DISABLE_3DES_SUPPORT           "Disable Triple-DES support."     ON)
option(CM_ENABLE_DES_SUPPORT             "Enable DES support."             OFF)
option(CM_ENABLE_ECP192_SUPPORT          "Enable EC P-192 support."        OFF)
option(CM_DISABLE_RSA_SUPPORT            "Disable RSA support"             OFF)
option(CM_ENABLE_AES_GCM_4K              "Enable AES-GCM 4K table"         OFF)
option(CM_ENABLE_AES_GCM_256B            "Enable AES-GCM 256b table"       OFF)
option(CM_DISABLE_CI                     "Disable crypto interface"        OFF)
option(CM_ENABLE_TLS12_FALLBACK          "Enable TLS 1.2 fallback support" OFF)
option(CM_ENABLE_SSL_PEM_R_BIO_REDEFINE  "Enable pem redefine support"     OFF)
option(CM_BUILD_DTLS_CLIENT              "Build dtls client."              OFF)
option(CM_BUILD_DTLS_SERVER              "Build dtls server."              OFF)
option(CM_BUILD_NANO_DTLS_CLIENT         "Build dtls client."              OFF)
option(CM_BUILD_NANO_DTLS_SERVER         "Build dtls server."              OFF)
option(CM_ENABLE_SSL_REHANDSHAKE         "Enable Rehandshake."             OFF)
option(CM_ENABLE_SSL_SESSION_CACHE       "Enable session cache."           OFF)
option(CM_ENABLE_SSL_ANON                "Enable anonymous suite support." OFF)
option(CM_DISABLE_WEAK_CIPHERS           "Build with ssl weak ciphers disabled." OFF)
option(CM_ENABLE_SSL_OPENSSL_LIB_1_1_X   "Build openssl 1.1.x"             OFF)
option(CM_ENABLE_SSL_OPENSSL_LIB_1_1_1   "Build openssl 1.1.1"             OFF)
option(CM_ENABLE_SSL_OPENSSL_LIB_1_1_1F  "Build openssl 1.1.1f"            OFF)
option(CM_ENABLE_SSL_OPENSSL_LIB_1_1_1K  "Build openssl 1.1.1k"            OFF)
option(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2U  "Build openssl 1.0.2u"            OFF)
option(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2T  "Build openssl 1.0.2t"            OFF)
option(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2N  "Build openssl 1.0.2n"            OFF)
option(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2J  "Build openssl 1.0.2j"            OFF)
option(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2P  "Build openssl 1.0.2p"            OFF)
option(CM_ENABLE_SSL_OPENSSL_LIB_3_0_7   "Build openssl 3.0.7"             OFF)
option(CM_ENABLE_SSL_OPENSSL_LIB_3_0_12   "Build openssl 3.0.12"            OFF)
option(CM_ENABLE_SSL_EXTENDED_KEYUSAGE   "Enable extended key usage."      OFF)
option(CM_DISABLE_SSL_SERVER_NAME        "Server flag to ignore the certificate common name." OFF)
option(CM_DISABLE_SSL_CLIENT_COMMON_NAME_VALIDATION "Client flag to ignore the certificate common name check." OFF)
option(CM_ENABLE_DEFER_CLIENT_AUTH       "Defer encoding client cert authentication." OFF)
option(CM_ENABLE_SSL_SRP                 "Enable SSL SRP."                 OFF)
option(CM_ENABLE_SSL_KEYLOG_FILE         "Enable SSL keylog file."         OFF)
option(CM_ENABLE_SSL_KEYLOG_ENV_VAR      "Enable SSL keylog environment variable." OFF)
option(CM_ENABLE_OSSLC_THREAD_SAFE       "Enable OpenSSL shim client thread safety" OFF)
option(CM_ENABLE_SESSION_TICKET_RFC_5077 "Enable server side session tickets" OFF)
option(CM_ENABLE_SSL_HEARTBEAT_RFC_6520  "Enable heartbeat protocol" OFF)
option(CM_ENABLE_OSSL_RX_BUF_8K          "Enable 8K OpenSSL buffer"        OFF)
option(CM_ENABLE_OSSL_LD_OVERRIDE        "Enable OpenSSL shim ld override" OFF)
option(CM_DISABLE_OSSL_READ_AHEAD        "Disable read ahead by default"   OFF)
option(CM_ENABLE_ENFORCE_CERT_SIG_ALGO   "Build with certificate signature check." OFF)
option(CM_ENABLE_MONOLITHIC_BUILD        "Build as a single binary with no dependencies." OFF)
option(CM_ENABLE_SP800_135               "Build for testing SP800-135"         OFF)
option(CM_ENABLE_RSA_8K                  "Build with RSA 8K." OFF)
option(CM_ENABLE_CVC                     "Build with CVC." OFF)
option(CM_ENABLE_DH_PUB_PAD              "Build with DH public key padding." OFF)
option(CM_ENABLE_CLIENT_CERT_CB          "Build with example client cert callback." OFF)
option(CM_ENABLE_MOCANA_SSL_EXAMPLE_GRACEFUL_SHUTDOWN "Build with server or client example shutdown gracefully." OFF)
option(CM_ENABLE_MOCANA_SSL_POST_CLIENT_AUTH_EXAMPLE "Enable Post Client Authentication example." OFF)
option(CM_ENABLE_MOCANA_PKCS12_CERT     "Build with server example using PKCS12 cert." OFF)
option(CM_BUILD_X32           "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64           "Build for 64Bit Machine." OFF)
option(CM_ENABLE_MOCANA_SSL_EXAMPLE_SMART_CARD  "Build with ssl example using smart card. " OFF)
option(CM_ENABLE_ERR_SSL_NO_CIPHER_MATCH  "Build DTLS server for no cipher match to stop the timer. " OFF)
option(CM_BUILD_NANOSSL_LIB              "Enable nanossl."                 OFF)
option(CM_ENABLE_DSA_SUPPORT             "Enable DSA support"              OFF)
option(CM_ENABLE_SSL_MAUTH_SUPPORT       "Enable mutual auth."             OFF)
if(BUILD_FOR_OSI)
    option(CM_ENABLE_SSL_PROXY_CONNECT       "Enable ssl proxy support."       ON)
else()
    option(CM_ENABLE_SSL_PROXY_CONNECT       "Enable ssl proxy support."       OFF)
endif()

include(../shared_cmake/osi.txt)

if (WIN32)
    option(CM_WIN_FORCE_LINKAGE      "Force linkage for shared library." OFF)
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
include(MocPlatform)

project (nanossl C)

# Make sure we do not have conflicting options in affect
if(CM_ENABLE_TAP_REMOTE AND CM_ENABLE_TAP_LOCAL)
    message(FATAL_ERROR "Either TAP Local or TAP Remote must be enabled")
endif()

include(cmakeflags.txt)
include(build_executable)
include(build_library)
include(locate_lib)
include(build_rc_file)
include(combined_archive)

if(CM_ENABLE_MONOLITHIC_BUILD)
    set(LIB_TYPE "STATIC")
    set(LINK_LIBS_IN_BIN_STATIC "ON")
endif()

if(WIN32)
    if("STATIC" STREQUAL "${LIB_TYPE}")
        set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32_static")
    else()
        set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32")
    endif()
else()
    if("STATIC" STREQUAL "${LIB_TYPE}")
        set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_static")
    else()
        set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
    endif()
endif()

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
if(BUILD_FOR_OSI)
  set(LIB_DIR "${MSS_DIR}/lib")
  set(MSS_BIN_DIR "${LIB_DIR}")
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
set(NSSL_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${NSSL_BUILD_DIR}/libs")
if(NOT WIN32)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${NSSL_BUILD_DIR}/libs")
endif()
set(CMAKE_BINARY_DIR "${NSSL_BUILD_DIR}")
set(NSSL_DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
set(VERSION_FILE "${MSS_DIR}/projects/shared_cmake/set_cpack_version.cmake")
include(${VERSION_FILE})
if(DEFINED ENV{BUILD_NUMBER})
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "$ENV{BUILD_NUMBER}")
else()
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "0")
endif()
set(STATIC_LIB_DIR "${MSS_DIR}/bin_static")

if(NOT EXISTS ${NSSL_DEFS_FILE})
    message(FATAL_ERROR "\nNSSL_DEFS_FILE = ${NSSL_DEFS_FILE} does not exist")
endif()

# initializing flags
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

if (WIN32)
    message("---- CFLAGS update for windows ----")
    #Ensure that the library is built using static version of the run-time library msvcrt
    foreach(item CXX_FLAGS
            CXX_FLAGS_RELEASE
            C_FLAGS
            C_FLAGS_RELEASE
            )
    message("----------------")
    message("CMAKE_${item}  = ${CMAKE_${item}}")
    if ("$ENV{CM_ENV_FORCE_STATIC_LINK}" STREQUAL "1")
        set(CMAKE_${item} "${CMAKE_${item}} /MT")
        string(REPLACE "/MD" "/MT" CMAKE_${item} "${CMAKE_${item}}")
    endif()
    message("CMAKE_${item}  = ${CMAKE_${item}}")
    endforeach()

    foreach(item CXX_FLAGS_DEBUG
            C_FLAGS_DEBUG
            )
    message("----------------")
    message("CMAKE_${item}  = ${CMAKE_${item}}")
    if ("$ENV{CM_ENV_FORCE_STATIC_LINK}" STREQUAL "1")
        set(CMAKE_${item} "${CMAKE_${item}} /MTd")
        string(REPLACE "/MDd" "/MTd" CMAKE_${item} "${CMAKE_${item}}")
    endif()
    message("CMAKE_${item}  = ${CMAKE_${item}}")
    endforeach()

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

message("\nNSSL_DEFS_FILE = ${NSSL_DEFS_FILE}")
include(${NSSL_DEFS_FILE})
add_compile_options(${WERROR})

if(WIN32)
    add_definitions("-DWIN_IMPORT")
endif()

if(NOT CM_DISABLE_PQC)
    add_definitions(" -D__ENABLE_DIGICERT_PQC__ ")
endif()

if(CM_ENABLE_PQC_COMPOSITE)
    add_definitions(" -D__ENABLE_DIGICERT_PQC_COMPOSITE__ ")
endif()

if(CM_ENABLE_CVC)
    add_definitions(" -D__ENABLE_DIGICERT_CV_CERT__ ")
endif()

if(CM_ENABLE_CLIENT_CERT_CB)
    add_definitions(" -D__ENABLE_DIGICERT_SSL_CLIENT_CERTIFICATE_CALLBACK__ ")
endif()

if(CM_ENABLE_MOCANA_SSL_EXAMPLE_GRACEFUL_SHUTDOWN)
    add_definitions(" -D__ENABLE_DIGICERT_SSL_EXAMPLE_GRACEFUL_SHUTDOWN__ ")
endif()

if(CM_ENABLE_MOCANA_SSL_POST_CLIENT_AUTH_EXAMPLE)
    add_definitions(" -D__ENABLE_DIGICERT_SSL_POST_CLIENT_AUTH_EXAMPLE__ ")
endif()

if(CM_ENABLE_MOCANA_PKCS12_CERT)
	add_definitions(" -D__ENABLE_DIGICERT_PKCS12_CERT__ -D__ENABLE_DIGICERT_PKCS12__ ")
endif()

if(CM_ENABLE_DEFER_CLIENT_AUTH)
	add_definitions(" -D__ENABLE_DIGICERT_DEFER_CLIENT_CERT_VERIFY_ENCODING__ ")
endif()

if(CM_ENABLE_DH_PUB_PAD)
    add_definitions(" -D__ENABLE_DIGICERT_SSL_DH_PUBLIC_KEY_PAD__ ")
endif()

if(DEFINED ENV{NANOSSL_TEST_MONKEY})
    add_definitions(" -D__ENABLE_DIGICERT_SSL_INTERNAL_STRUCT_ACCESS__")
endif()
########################################################################
# Locate base libraries
########################################################################

# Get the full path to our base libraries
# Note: If library is not found, variable will be empty.
locate_lib(ASN1_LIB asn1)
locate_lib(COMMON_LIB common)
locate_lib(INITIALIZE_LIB initialize)
locate_lib(PLATFORM_LIB platform)
locate_lib(NANOCRYPTO_LIB nanocrypto)
locate_lib(CRYPTO_MW_LIB cryptomw)
locate_lib(NANOCERT_LIB nanocert)
if(NOT CM_DISABLE_CI)
    locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
    locate_lib(NANOCAP_LIB nanocap)
endif()
locate_lib(NANOSSL_LIB nanossl)
if (CM_ENABLE_COMMON_LINK)
    set(NANODTLS_CLIENT_LIB ${NANOSSL_LIB})
    set(NANODTLS_SERVER_LIB ${NANOSSL_LIB})
else()
    locate_lib(NANODTLS_CLIENT_LIB nanodtls_client)
    locate_lib(NANODTLS_SERVER_LIB nanodtls_server)
endif()
if(WIN32)
  if(CM_ENABLE_SSL_OPENSSL_LIB_1_1_X OR CM_ENABLE_SSL_OPENSSL_LIB_1_1_1 OR
          CM_ENABLE_SSL_OPENSSL_LIB_1_1_1F OR CM_ENABLE_SSL_OPENSSL_LIB_1_1_1I OR
         CM_ENABLE_SSL_OPENSSL_LIB_1_1_1K OR CM_ENABLE_SSL_OPENSSL_LIB_3_0_7 OR
         CM_ENABLE_SSL_OPENSSL_LIB_3_0_12)
    locate_lib(OSSL_CRYPTO_LIB libcrypto)
  else()
    locate_lib(OSSL_CRYPTO_LIB libeay32)
  endif()
else()
  locate_lib(OSSL_CRYPTO_LIB crypto)
endif()
locate_lib(NANOTAP2_LIB nanotap2)
locate_lib(NANOTAP2_COMMON_LIB nanotap2_common)
locate_lib(TPM2_LIB tpm2)
locate_lib(SMPTPM2_LIB smptpm2)
locate_lib(SMPPKCS11_LIB smppkcs11)
locate_lib(NANOTAP2_CONFIGPARSER_LIB nanotap2_configparser)
locate_lib(NANOTAP2_CLIENTCOMM_LIB nanotap2_clientcomm)
locate_lib(TAP_EXTERN_LIB tap_extern)
locate_lib(HW_ACCEL_LIB hw)
if(WIN32)
    locate_lib(ASN1_DATA_LIB asn1data)
    locate_lib(CRYPTO_MW_DATA_LIB cryptomwdata)
endif()
if(CM_ENABLE_FIPS)
    if(WIN32)
        locate_lib(LIBMSS_LIB libmss)
    else()
        locate_lib(LIBMSS_LIB mss)
    endif()
endif()
locate_lib(DATA_PROTECT_LIB dataprotect)

# Macro to move any target's artifacts to either:
# - mss/bin for Unix
# - mss/bin_win32 for Windows
set(BIN_DIR "${MSS_BIN_DIR}")
if(BUILD_FOR_OSI)
    macro(move_to_bin t_name)
    add_custom_command(
        TARGET ${t_name}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            $<TARGET_FILE_DIR:${t_name}>
            ${LIB_DIR})
    endmacro()
else()
    macro(move_to_bin t_name)
    add_custom_command(
        TARGET ${t_name}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            $<TARGET_FILE_DIR:${t_name}>
            ${BIN_DIR})
    endmacro()
endif()

########################################################################
# Mocana nanossl SHARED LIBRARY building
########################################################################
if(CM_BUILD_NANOSSL_LIB)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/nanossl")
    message("TARGET_DIR = ${TARGET_DIR}")

    set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/nanossl/mss_includes.txt")
    set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/nanossl/mss_sources.txt")
    if(WIN32)
      if("SHARED" STREQUAL "${LIB_TYPE}")
        set(srclist ${srclist} "${CMAKE_CURRENT_SOURCE_DIR}/nanossl/mss_win_sources.txt")
      endif()
    endif()
    set(TARGET_NAME nanossl)

    set(MOCANA_FLAGS "")

    if(CM_ENABLE_SSL_EXTENDED_KEYUSAGE)
        message("**** ENABLED CM_ENABLE_SSL_EXTENDED_KEYUSAGE ****")
        string(STRIP "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_SSL_KEY_EXPANSION__" MOCANA_FLAGS)
    endif()

    if(CM_ENABLE_SP800_135)
        add_definitions(" -D__ENABLE_DIGICERT_SP800_135_ACVP__")
    endif()

    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    if(BUILD_FOR_OSI)
        set(ASN1_LIB             "${LIB_DIR}/libasn1.so")
        set(COMMON_LIB           "${LIB_DIR}/libcommon.so")
        set(PLATFORM_LIB         "${LIB_DIR}/libplatform.so")
        set(INITIALIZE_LIB       "${LIB_DIR}/libinitialize.so")
        if(CM_ENABLE_EXPORT_ED)
            set(CRYPTO_MW_LIB        "${LIB_DIR}/libcryptomw.so")
        else()
            set(NANOCRYPTO_LIB       "${LIB_DIR}/libnanocrypto.so")
        endif()
        set(NANOCAP_LIB          "${LIB_DIR}/libnanocap.so")
        set(CRYPTOINTERFACE_LIB  "${LIB_DIR}/libcryptointerface.so")
        set(NANOCERT_LIB         "${LIB_DIR}/libnanocert.so")
    endif()

    set(libraryLists ${INITIALIZE_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB} ${NANOCERT_LIB}
                     ${ASN1_LIB} ${CRYPTOINTERFACE_LIB} ${COMMON_LIB} ${PLATFORM_LIB})
    if(CM_ENABLE_FIPS)
      set(libraryLists ${libraryLists} ${LIBMSS_LIB})
    endif()

    if(CM_ENABLE_DTLS)
        set(includelist ${includelist} "${CMAKE_CURRENT_SOURCE_DIR}/dtls/mss_includes.txt")
        set(srclist ${srclist} "${CMAKE_CURRENT_SOURCE_DIR}/dtls/mss_sources.txt")
    endif()

    #set(libraryLists initialize nanocrypto nanocert asn1 cryptointerface platform common)

    buildLibrary(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
                 ${NSSL_BUILD_DIR} ${MSS_BIN_DIR}  ${libraryLists})
    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

    move_to_bin(${TARGET_NAME})
endif()

########################################################################
# Mocana nanodtls client SHARED LIBRARY building
########################################################################
if(CM_BUILD_NANO_DTLS_CLIENT)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/nanodtls_client")
    message("TARGET_DIR = ${TARGET_DIR}")

    set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/nanodtls_client/mss_includes.txt")
    set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/nanodtls_client/mss_sources.txt")

    set(TARGET_NAME nanodtls_client)

    set(MOCANA_FLAGS "")

    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    set(libraryLists ${INITIALIZE_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB} ${NANOCERT_LIB}
            ${ASN1_LIB} ${CRYPTOINTERFACE_LIB} ${PLATFORM_LIB}
            ${COMMON_LIB})
    if(CM_ENABLE_FIPS)
      set(libraryLists ${libraryLists} ${LIBMSS_LIB})
    endif()

    #set(libraryLists initialize nanocrypto nanocert asn1 cryptointerface platform common)

    buildLibrary(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
            ${NSSL_BUILD_DIR} ${MSS_BIN_DIR}  ${libraryLists})
    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

    move_to_bin(${TARGET_NAME})
endif()

########################################################################
# Mocana nanossl SHARED LIBRARY building
########################################################################
if(CM_BUILD_NANO_DTLS_SERVER)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/nanodtls_server")
    message("TARGET_DIR = ${TARGET_DIR}")

    set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/nanodtls_server/mss_includes.txt")
    set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/nanodtls_server/mss_sources.txt")

    set(TARGET_NAME nanodtls_server)

    set(MOCANA_FLAGS "")

    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    set(libraryLists ${INITIALIZE_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB} ${NANOCERT_LIB}
            ${ASN1_LIB} ${CRYPTOINTERFACE_LIB} ${PLATFORM_LIB}
            ${COMMON_LIB})
    if(CM_ENABLE_FIPS)
      set(libraryLists ${libraryLists} ${LIBMSS_LIB})
    endif()

    #set(libraryLists initialize nanocrypto nanocert asn1 cryptointerface platform common)

    buildLibrary(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
            ${NSSL_BUILD_DIR} ${MSS_BIN_DIR}  ${libraryLists})
    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

    move_to_bin(${TARGET_NAME})
endif()
########################################################################

########################################################################
# Mocana openssl shim SHARED LIBRARY building
########################################################################
if(CM_BUILD_OPENSSL_SHIM_LIB)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim")
    set(TARGET_NAME openssl_shim)
    if(CM_ENABLE_SSL_OPENSSL_LIB_3_0_12)
       set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_3_0_12_includes.txt")
    elseif(CM_ENABLE_SSL_OPENSSL_LIB_3_0_7)
       set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_3_0_7_includes.txt")
    elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_1_1)
       set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_1_1_1_includes.txt")
    elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_1_1F)
       set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_1_1_1f_includes.txt")
    elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_1_1I)
       set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_1_1_1i_includes.txt")
    elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_1_1K)
       set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_1_1_1k_includes.txt")
    elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_1_X)
       set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_1_1_x_includes.txt")
    elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2U)
        if(WIN32)
            set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_1_0_2u_includes_win.txt")
        else()
            set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_1_0_2u_includes.txt")
        endif()
    elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2T)
        if(WIN32)
            set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_1_0_2t_includes_win.txt")
        else()
            set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_1_0_2t_includes.txt")
        endif()
    elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2N)
        set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_1_0_2n_includes.txt")
    elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2P)
        set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_1_0_2p_includes.txt")
    elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2J)
        set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_openssl_1_0_2j_includes.txt")
    else()
       set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_includes.txt")
    endif()

    set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/openssl_shim/mss_sources.txt")

    if(NOT WIN32 AND NOT APPLE)
        if(CM_ENABLE_OSSL_LD_OVERRIDE)
            if(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2U)
                set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/openssl-1.0.2u/openssl-override.ld")
            elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2T)
                set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/openssl-1.0.2t/openssl-override.ld")
            elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2N)
                set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/openssl-1.0.2n/openssl-override.ld")
            elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2P)
                set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/openssl-1.0.2p/openssl-override.ld")
            elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_0_2J)
                set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/openssl-1.0.2j/openssl-override.ld")
            else()
                set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/openssl-1.0.2l/openssl-override.ld")
            endif()
        else()
            if(CM_ENABLE_SSL_OPENSSL_LIB_3_0_12)
                set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../src/openssl_wrapper/openssl-3.0.12.ld -Wl,-znodelete")
            elseif(CM_ENABLE_SSL_OPENSSL_LIB_3_0_7)
		set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../src/openssl_wrapper/openssl-3.0.7.ld -Wl,-znodelete")
            elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_1_1)
                set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../src/openssl_wrapper/openssl-1.1.1c.ld -Wl,-znodelete")
            elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_1_1F)
                set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../src/openssl_wrapper/openssl-1.1.1f.ld -Wl,-znodelete")
            elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_1_1I)
                set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../src/openssl_wrapper/openssl-1.1.1i.ld -Wl,-znodelete")
            elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_1_1K)
                set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../src/openssl_wrapper/openssl-1.1.1k.ld -Wl,-znodelete")
            elseif(CM_ENABLE_SSL_OPENSSL_LIB_1_1_X)
                set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../src/openssl_wrapper/openssl-1.1.0.ld -Wl,-znodelete")
            else()
                set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../../src/openssl_wrapper/openssl.ld")
            endif()
        endif()
    endif()
    set(MOCANA_FLAGS "")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    if (CM_ENABLE_TAP_LOCAL)

        if (CM_ENABLE_TAP_EXTERN)
            set(libraryLists ${NANOSSL_LIB} ${OSSL_CRYPTO_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB}
                             ${INITIALIZE_LIB} ${TAP_EXTERN_LIB} ${CRYPTOINTERFACE_LIB}
                             ${NANOCERT_LIB} ${NANOTAP2_LIB} ${SMPTPM2_LIB} ${TPM2_LIB}
                             ${NANOTAP2_COMMON_LIB} ${PLATFORM_LIB} ${COMMON_LIB} ${ASN1_LIB})
        else()
            set(libraryLists ${NANOSSL_LIB} ${OSSL_CRYPTO_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB}
                             ${NANOCERT_LIB} ${INITIALIZE_LIB} ${CRYPTOINTERFACE_LIB}
                             ${NANOTAP2_LIB} ${SMPTPM2_LIB} ${TPM2_LIB}
                             ${NANOTAP2_COMMON_LIB} ${PLATFORM_LIB} ${COMMON_LIB} ${ASN1_LIB})
        endif()

    elseif(CM_ENABLE_TAP_REMOTE)

        if (CM_ENABLE_TAP_EXTERN)
            set(libraryLists ${NANOSSL_LIB} ${OSSL_CRYPTO_LIB} ${INITIALIZE_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB}
                             ${TAP_EXTERN_LIB} ${CRYPTOINTERFACE_LIB} ${NANOCERT_LIB}
                             ${NANOTAP2_LIB} ${SMPTPM2_LIB} ${TPM2_LIB}
                             ${NANOTAP2_COMMON_LIB} ${COMMON_LIB}
                             ${NANOTAP2_CONFIGPARSER_LIB} ${NANOTAP2_CLIENTCOMM_LIB})
        else()
            set(libraryLists ${NANOSSL_LIB} ${INITIALIZE_LIB} ${OSSL_CRYPTO_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB}
                             ${CRYPTOINTERFACE_LIB} ${NANOCERT_LIB} ${NANOTAP2_LIB}
                             ${SMPTPM2_LIB} ${TPM2_LIB} ${NANOTAP2_COMMON_LIB}
                             ${COMMON_LIB} ${NANOTAP2_CONFIGPARSER_LIB}
                             ${NANOTAP2_CLIENTCOMM_LIB})
        endif()
    else()
        set(libraryLists ${NANOSSL_LIB} ${INITIALIZE_LIB} ${OSSL_CRYPTO_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB}
                         ${CRYPTOINTERFACE_LIB} ${NANOCERT_LIB}
                         ${COMMON_LIB})
    endif()

    if(WIN32)
        set(libraryLists ${libraryLists} Ws2_32.lib)
        if(CM_ENABLE_FIPS)
          set(libraryLists ${libraryLists} ${LIBMSS_LIB})
        endif()
    endif()

    buildLibrary(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
                 ${NSSL_BUILD_DIR} ${MSS_BIN_DIR}  ${libraryLists})
    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()
    if(ANDROID)
        set_target_properties(${TARGET_NAME} PROPERTIES NO_SONAME ON)
        if(CM_ENABLE_SSL_OPENSSL_LIB_1_1_1 OR CM_ENABLE_SSL_OPENSSL_LIB_1_1_1F OR CM_ENABLE_SSL_OPENSSL_LIB_1_1_1I OR CM_ENABLE_SSL_OPENSSL_LIB_1_1_1K OR CM_ENABLE_SSL_OPENSSL_LIB_1_1_X)
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-soname,libssl.so.1.1")
        elseif(CM_ENABLE_SSL_OPENSSL_LIB_3_0_7 OR CM_ENABLE_SSL_OPENSSL_LIB_3_0_12)
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-soname,libssl.so.3")
        else()
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-soname,libssl.so.1.0.0")
        endif()
    endif()
    move_to_bin(${TARGET_NAME})
endif()

########################################################################

########################################################################
# Mocana ssl client  building
########################################################################
if (CM_BUILD_SSL_CLIENT)
    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ssl-client")
    set(TARGET_NAME ssl_client)
    set(MOCANA_FLAGS "")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    if ((CM_ENABLE_TAP_LOCAL) OR (CM_ENABLE_TAP_REMOTE) OR (CM_ENABLE_TAP_REMOTE_TCP))

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB}
                         ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB}
                         ${NANOCERT_LIB} ${CRYPTOINTERFACE_LIB} ${NANOCRYPTO_LIB}
                         ${CRYPTO_MW_LIB} ${COMMON_LIB}  ${NANOCAP_LIB}
                         ${ASN1_LIB} ${PLATFORM_LIB} ${COMMON_LIB})

        #set(libraryLists initialize nanossl nanotap2 nanotap2_common smptpm2 tpm2 nanocert cryptointerface nanocap asn1 common platform)
    else()

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB} ${NANOCERT_LIB}
                         ${CRYPTOINTERFACE_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB}
                         ${COMMON_LIB} ${PLATFORM_LIB} ${NANOCAP_LIB}
                         ${ASN1_LIB} ${HW_ACCEL_LIB})
        #set(libraryLists initialize nanossl nanocert cryptointerface nanocap asn1 common platform)
    endif()

    if(CM_ENABLE_FIPS)
       set(MOCANA_FLAGS ${MOCANA_FLAGS} " __ENABLE_DIGICERT_FIPS_MODULE__")
       set(libraryLists ${libraryLists} ${LIBMSS_LIB})
    endif()

    if(WIN32)
        set(libraryLists ${libraryLists} ${ASN1_DATA_LIB} ${CRYPTO_MW_DATA_LIB})
    endif()

    if(CM_ENABLE_MOCANA_DATA_PROTECTION)
        set(libraryLists ${libraryLists} ${DATA_PROTECT_LIB})
    endif()

    # adding mss include directories listed in mss_includes.txt
    file(STRINGS "${TARGET_DIR}/mss_includes.txt" MSS_INCLUDES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")
    if(BUILD_FOR_OSI OR USE_OSI_PATH)
      string(REGEX REPLACE "EXAMPLE_DIR" "../samples/common/" MSS_INCLUDES "${MSS_INCLUDES}")
    else()
      string(REGEX REPLACE "EXAMPLE_DIR" "examples" MSS_INCLUDES "${MSS_INCLUDES}")
    endif()

    include_directories("." ${MSS_INCLUDES})

    message("${TARGET_NAME} includes")
    message("----------------")
    foreach(dir ${MSS_INCLUDES})
        message(${dir})
    endforeach()

    message("${TARGET_NAME} libs")
    message("----------------")
    foreach(dir ${libraryLists})
        message(${dir})
    endforeach()

    file(STRINGS "${TARGET_DIR}/mss_sources.txt" MSS_SOURCES)
    if (NOT WIN32)
      if(BUILD_FOR_OSI OR USE_OSI_PATH)
        set(MSS_SOURCES ${MSS_SOURCES} "MSS_SRC_DIR/../samples/common/digicert_example.c")
      else()
        set(MSS_SOURCES ${MSS_SOURCES} "MSS_SRC_DIR/examples/mocana_example.c")
      endif()
    endif()

    if(CM_ENABLE_FIPS)
      set(MSS_SOURCES ${MSS_SOURCES} "MSS_SRC_DIR/examples/fips_utils.c")
    endif()

    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")
    if(BUILD_FOR_OSI OR USE_OSI_PATH)
      string(REGEX REPLACE "EXAMPLE_DIR/" "../samples/common/" MSS_SOURCES "${MSS_SOURCES}")
      string(REGEX REPLACE "CLIENT_DIR/" "../samples/ssl_client/src/" MSS_SOURCES "${MSS_SOURCES}")
    else()
      string(REGEX REPLACE "EXAMPLE_DIR/" "examples/" MSS_SOURCES "${MSS_SOURCES}")
      string(REGEX REPLACE "CLIENT_DIR/" "examples/" MSS_SOURCES "${MSS_SOURCES}")
    endif()

    message("mss sources")
    message("-----------")
    foreach(file ${MSS_SOURCES})
        message(${file})
    endforeach()

    add_executable(${TARGET_NAME} "${MSS_SOURCES}")

    if(UNIX AND NOT ANDROID)
      if("${CM_TARGET_PLATFORM}" STREQUAL "qnx-x86" OR "${CM_TARGET_PLATFORM}" STREQUAL "qnx-x86_64" OR "${CM_TARGET_PLATFORM}" STREQUAL "qnx-6-5-x86")
      else()
        set(libraryLists ${libraryLists} pthread)
      endif()
    endif()

    target_link_libraries(${TARGET_NAME} ${libraryLists})

    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

    move_to_bin(${TARGET_NAME})

endif()

if (CM_BUILD_SSL_CLIENT_ASYNC)
    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ssl-client")
    set(TARGET_NAME ssl_client_async)
    set(MOCANA_FLAGS "")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    if ((CM_ENABLE_TAP_LOCAL) OR (CM_ENABLE_TAP_REMOTE) OR (CM_ENABLE_TAP_REMOTE_TCP))

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB}
                         ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB}
                         ${NANOCERT_LIB} ${CRYPTOINTERFACE_LIB} ${NANOCRYPTO_LIB}
                         ${CRYPTO_MW_LIB} ${COMMON_LIB}
                         ${ASN1_LIB} ${PLATFORM_LIB} ${COMMON_LIB})

        #set(libraryLists initialize nanossl nanotap2 nanotap2_common smptpm2 tpm2 nanocert cryptointerface nanocap asn1 common platform)
    else()

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB} ${NANOCERT_LIB}
                         ${CRYPTOINTERFACE_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB}
                         ${COMMON_LIB} ${PLATFORM_LIB}
                         ${ASN1_LIB})
        #set(libraryLists initialize nanossl nanocert cryptointerface nanocap asn1 common platform)
    endif()

    if(WIN32)
        set(libraryLists ${libraryLists} ${ASN1_DATA_LIB} ${CRYPTO_MW_DATA_LIB})
        if(CM_ENABLE_FIPS)
          set(libraryLists ${libraryLists} ${LIBMSS_LIB})
        endif()
    endif()

    # adding mss include directories listed in mss_includes.txt
    file(STRINGS "${TARGET_DIR}/mss_includes.txt" MSS_INCLUDES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")
    string(REGEX REPLACE "EXAMPLE_DIR" "examples" MSS_INCLUDES "${MSS_INCLUDES}")

    include_directories("." ${MSS_INCLUDES})

    message("${TARGET_NAME} includes")
    message("----------------")
    foreach(dir ${MSS_INCLUDES})
        message(${dir})
    endforeach()


    file(STRINGS "${TARGET_DIR}/mss_sources_async.txt" MSS_SOURCES)
    if (NOT WIN32)
      set(MSS_SOURCES ${MSS_SOURCES} "MSS_SRC_DIR/examples/mocana_example.c")
    endif()
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")
    message("mss sources")
    message("-----------")
    foreach(file ${MSS_SOURCES})
        message(${file})
    endforeach()

    add_executable(${TARGET_NAME} "${MSS_SOURCES}")

    if(UNIX AND NOT ANDROID)
        set(libraryLists ${libraryLists} pthread)
    endif()

    target_link_libraries(${TARGET_NAME} ${libraryLists})

    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

    move_to_bin(${TARGET_NAME})

endif()

if (CM_BUILD_SSL_CLIENT_ASYNC_EXTERNAL_PSK)
    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ssl-client")
    set(TARGET_NAME ssl_client_async_external_psk)
    set(MOCANA_FLAGS "")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    if ((CM_ENABLE_TAP_LOCAL) OR (CM_ENABLE_TAP_REMOTE) OR (CM_ENABLE_TAP_REMOTE_TCP))

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB}
                         ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB}
                         ${NANOCERT_LIB} ${CRYPTOINTERFACE_LIB} ${NANOCRYPTO_LIB}
                         ${CRYPTO_MW_LIB} ${COMMON_LIB}
                         ${ASN1_LIB} ${PLATFORM_LIB} ${COMMON_LIB})

        #set(libraryLists initialize nanossl nanotap2 nanotap2_common smptpm2 tpm2 nanocert cryptointerface nanocap asn1 common platform)
    else()

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB} ${NANOCERT_LIB}
                         ${CRYPTOINTERFACE_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB}
                         ${COMMON_LIB} ${PLATFORM_LIB}
                         ${ASN1_LIB})
        #set(libraryLists initialize nanossl nanocert cryptointerface nanocap asn1 common platform)
    endif()

    if(WIN32)
        set(libraryLists ${libraryLists} ${ASN1_DATA_LIB} ${CRYPTO_MW_DATA_LIB})
        if(CM_ENABLE_FIPS)
          set(libraryLists ${libraryLists} ${LIBMSS_LIB})
        endif()
    endif()

    # adding mss include directories listed in mss_includes.txt
    file(STRINGS "${TARGET_DIR}/mss_includes.txt" MSS_INCLUDES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")
    string(REGEX REPLACE "EXAMPLE_DIR" "examples" MSS_INCLUDES "${MSS_INCLUDES}")

    include_directories("." ${MSS_INCLUDES})

    message("${TARGET_NAME} includes")
    message("----------------")
    foreach(dir ${MSS_INCLUDES})
        message(${dir})
    endforeach()


    file(STRINGS "${TARGET_DIR}/mss_sources_async_external_psk.txt" MSS_SOURCES)
    if (NOT WIN32)
        set(MSS_SOURCES ${MSS_SOURCES} "MSS_SRC_DIR/examples/mocana_example.c")
    endif()
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")
    message("mss sources")
    message("-----------")
    foreach(file ${MSS_SOURCES})
        message(${file})
    endforeach()

    add_executable(${TARGET_NAME} "${MSS_SOURCES}")

    if(UNIX AND NOT ANDROID)
        set(libraryLists ${libraryLists} pthread)
    endif()

    target_link_libraries(${TARGET_NAME} ${libraryLists})

    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

    move_to_bin(${TARGET_NAME})

endif()

if (CM_BUILD_SSL_SERIALIZE_PSK)
    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ssl-server")
    set(TARGET_NAME ssl_serialize_psk)
    set(MOCANA_FLAGS "")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    if ((CM_ENABLE_TAP_LOCAL) OR (CM_ENABLE_TAP_REMOTE) OR (CM_ENABLE_TAP_REMOTE_TCP))

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB}
                         ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB}
                         ${NANOCERT_LIB} ${CRYPTOINTERFACE_LIB} ${NANOCRYPTO_LIB}
                         ${CRYPTO_MW_LIB} ${COMMON_LIB}
                         ${ASN1_LIB} ${PLATFORM_LIB} ${COMMON_LIB})

        #set(libraryLists initialize nanossl nanotap2 nanotap2_common smptpm2 tpm2 nanocert cryptointerface nanocap asn1 common platform)
    else()

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB} ${NANOCERT_LIB}
                         ${CRYPTOINTERFACE_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB}
                         ${COMMON_LIB} ${PLATFORM_LIB}
                         ${ASN1_LIB})
        #set(libraryLists initialize nanossl nanocert cryptointerface nanocap asn1 common platform)
    endif()

    if(WIN32)
        set(libraryLists ${libraryLists} ${ASN1_DATA_LIB} ${CRYPTO_MW_DATA_LIB})
        if(CM_ENABLE_FIPS)
          set(libraryLists ${libraryLists} ${LIBMSS_LIB})
        endif()
    endif()

    # adding mss include directories listed in mss_includes.txt
    file(STRINGS "${TARGET_DIR}/mss_includes.txt" MSS_INCLUDES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")
    string(REGEX REPLACE "EXAMPLE_DIR" "examples" MSS_INCLUDES "${MSS_INCLUDES}")

    include_directories("." ${MSS_INCLUDES})

    message("${TARGET_NAME} includes")
    message("----------------")
    foreach(dir ${MSS_INCLUDES})
        message(${dir})
    endforeach()


    file(STRINGS "${TARGET_DIR}/mss_sources_serialize_psk.txt" MSS_SOURCES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")
    message("mss sources")
    message("-----------")
    foreach(file ${MSS_SOURCES})
        message(${file})
    endforeach()

    add_executable(${TARGET_NAME} "${MSS_SOURCES}")

    if(UNIX AND NOT ANDROID)
        set(libraryLists ${libraryLists} pthread)
    endif()

    target_link_libraries(${TARGET_NAME} ${libraryLists})

    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
        target_compile_definitions(${TARGET_NAME}   PRIVATE "-D__ENABLE_DIGICERT_SSL_SERIALIZE_PSK_EXAMPLE__")
    endif()

    move_to_bin(${TARGET_NAME})

endif()

if (CM_BUILD_SSL_CLIENT_SP800_135)
    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ssl-client")
    set(TARGET_NAME ssl_client_sp800_135)
    set(MOCANA_FLAGS "")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)

    if ((CM_ENABLE_TAP_LOCAL) OR (CM_ENABLE_TAP_REMOTE) OR (CM_ENABLE_TAP_REMOTE_TCP))

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB}
                         ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB}
                         ${NANOCERT_LIB} ${CRYPTOINTERFACE_LIB} ${NANOCRYPTO_LIB}
                         ${CRYPTO_MW_LIB} ${COMMON_LIB}  ${NANOCAP_LIB}
                         ${ASN1_LIB} ${PLATFORM_LIB} ${COMMON_LIB})

        #set(libraryLists initialize nanossl nanotap2 nanotap2_common smptpm2 tpm2 nanocert cryptointerface nanocap asn1 common platform)
    else()

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB} ${NANOCERT_LIB}
                         ${CRYPTOINTERFACE_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB}
                         ${COMMON_LIB} ${PLATFORM_LIB} ${NANOCAP_LIB}
                         ${ASN1_LIB} ${HW_ACCEL_LIB})
        #set(libraryLists initialize nanossl nanocert cryptointerface nanocap asn1 common platform)
    endif()

    if(CM_ENABLE_FIPS)
       set(MOCANA_FLAGS ${MOCANA_FLAGS} " __ENABLE_DIGICERT_FIPS_MODULE__")
       set(libraryLists ${libraryLists} ${LIBMSS_LIB})
    endif()

    if(WIN32)
        set(libraryLists ${libraryLists} ${ASN1_DATA_LIB} ${CRYPTO_MW_DATA_LIB})
    endif()

    if(CM_ENABLE_MOCANA_DATA_PROTECTION)
        set(libraryLists ${libraryLists} ${DATA_PROTECT_LIB})
    endif()

    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    # adding mss include directories listed in mss_includes.txt
    file(STRINGS "${TARGET_DIR}/mss_includes.txt" MSS_INCLUDES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")
    string(REGEX REPLACE "EXAMPLE_DIR" "examples" MSS_INCLUDES "${MSS_INCLUDES}")

    include_directories("." ${MSS_INCLUDES})

    message("${TARGET_NAME} includes")
    message("----------------")
    foreach(dir ${MSS_INCLUDES})
        message(${dir})
    endforeach()

    message("${TARGET_NAME} libs")
    message("----------------")
    foreach(dir ${libraryLists})
        message(${dir})
    endforeach()

    file(STRINGS "${TARGET_DIR}/mss_sources_sp800_135.txt" MSS_SOURCES)

    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")
    message("mss sources")
    message("-----------")
    foreach(file ${MSS_SOURCES})
        message(${file})
    endforeach()

    add_executable(${TARGET_NAME} "${MSS_SOURCES}")

    if(UNIX AND NOT ANDROID)
      if("${CM_TARGET_PLATFORM}" STREQUAL "qnx-x86" OR "${CM_TARGET_PLATFORM}" STREQUAL "qnx-x86_64" OR "${CM_TARGET_PLATFORM}" STREQUAL "qnx-6-5-x86")
      else()
        set(libraryLists ${libraryLists} pthread)
      endif()
    endif()

    target_link_libraries(${TARGET_NAME} ${libraryLists})

    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

    move_to_bin(${TARGET_NAME})

endif()

########################################################################
# Mocana ssl server  building
########################################################################

# Set Windows file properties
if(WIN32)
  build_rc_file("TrustPoint Shared Library")
endif()

if (CM_BUILD_SSL_SERVER)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ssl-server")

    set(TARGET_NAME ssl_server)

    set(MOCANA_FLAGS "")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    if ((CM_ENABLE_TAP_LOCAL) OR (CM_ENABLE_TAP_REMOTE) OR (CM_ENABLE_TAP_REMOTE_TCP))

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB} ${ASN1_LIB}
                         ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB}
                         ${NANOCERT_LIB} ${CRYPTOINTERFACE_LIB}  ${COMMON_LIB}
                         ${PLATFORM_LIB} ${COMMON_LIB})

        #set(libraryLists initialize nanossl nanotap2 nanotap2_common smptpm2 tpm2 nanocert cryptointerface nanocap asn1 common platform)
    else()
        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB} ${NANOCERT_LIB}
                         ${CRYPTOINTERFACE_LIB} ${HW_ACCEL_LIB}
                         ${COMMON_LIB} ${PLATFORM_LIB} ${ASN1_LIB})
        #set(libraryLists initialize nanossl nanocert cryptointerface nanocap asn1 common platform)
    endif()

    if(WIN32)
        set(libraryLists ${libraryLists} ${ASN1_DATA_LIB} ${CRYPTO_MW_DATA_LIB})
    endif()

    if(CM_ENABLE_FIPS)
        set(libraryLists ${libraryLists} ${LIBMSS_LIB})
    endif()

    if(CM_ENABLE_MOCANA_DATA_PROTECTION)
        set(libraryLists ${libraryLists} ${DATA_PROTECT_LIB})
    endif()

    # adding mss include directories listed in mss_includes.txt
    file(STRINGS "${TARGET_DIR}/mss_includes.txt" MSS_INCLUDES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")
    if(BUILD_FOR_OSI OR USE_OSI_PATH)
      string(REGEX REPLACE "EXAMPLE_DIR" "../samples/common/" MSS_INCLUDES "${MSS_INCLUDES}")
    else()
      string(REGEX REPLACE "EXAMPLE_DIR" "examples" MSS_INCLUDES "${MSS_INCLUDES}")
    endif()

    include_directories("." ${MSS_INCLUDES})

    message("${TARGET_NAME} includes")
    message("----------------")
    foreach(dir ${MSS_INCLUDES})
        message(${dir})
    endforeach()


    file(STRINGS "${TARGET_DIR}/mss_sources.txt" MSS_SOURCES)
    if (NOT WIN32)
      if(BUILD_FOR_OSI OR USE_OSI_PATH)
        set(MSS_SOURCES ${MSS_SOURCES} "MSS_SRC_DIR/../samples/common/digicert_example.c")
      else()
        set(MSS_SOURCES ${MSS_SOURCES} "MSS_SRC_DIR/examples/mocana_example.c")
      endif()
    endif()

    if(CM_ENABLE_FIPS)
      set(MSS_SOURCES ${MSS_SOURCES} "MSS_SRC_DIR/examples/fips_utils.c")
    endif()

    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")
    if(BUILD_FOR_OSI OR USE_OSI_PATH)
      string(REGEX REPLACE "EXAMPLE_DIR/" "../samples/common/" MSS_SOURCES "${MSS_SOURCES}")
      string(REGEX REPLACE "SERVER_DIR/" "../samples/ssl_server/src/" MSS_SOURCES "${MSS_SOURCES}")
    else()
      string(REGEX REPLACE "EXAMPLE_DIR/" "examples/" MSS_SOURCES "${MSS_SOURCES}")
      string(REGEX REPLACE "SERVER_DIR/" "examples/" MSS_SOURCES "${MSS_SOURCES}")
    endif()

    # Set Windows file properties
    if(WIN32)
      set(MSS_SOURCES ${MSS_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
    endif()

    message("mss sources")
    message("-----------")
    foreach(file ${MSS_SOURCES})
        message(${file})
    endforeach()

    add_executable(${TARGET_NAME} "${MSS_SOURCES}")

    if(UNIX AND NOT ANDROID)
        set(libraryLists ${libraryLists} pthread)
    endif()

    target_link_libraries(${TARGET_NAME} ${libraryLists})

    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

    move_to_bin(${TARGET_NAME})

endif()

if (CM_BUILD_SSL_SERVER_GW)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ssl-server")

    set(TARGET_NAME ssl_server_gw)

    set(MOCANA_FLAGS "")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    if ((CM_ENABLE_TAP_LOCAL) OR (CM_ENABLE_TAP_REMOTE) OR (CM_ENABLE_TAP_REMOTE_TCP))

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB} ${ASN1_LIB}
                         ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB}
                         ${NANOCERT_LIB} ${CRYPTOINTERFACE_LIB}  ${COMMON_LIB}
                         ${PLATFORM_LIB} ${COMMON_LIB})

        #set(libraryLists initialize nanossl nanotap2 nanotap2_common smptpm2 tpm2 nanocert cryptointerface nanocap asn1 common platform)
    else()
        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB} ${NANOCERT_LIB}
                         ${CRYPTOINTERFACE_LIB}
                         ${COMMON_LIB} ${PLATFORM_LIB} ${ASN1_LIB})
        #set(libraryLists initialize nanossl nanocert cryptointerface nanocap asn1 common platform)
    endif()
    if(CM_ENABLE_FIPS)
      set(libraryLists ${libraryLists} ${LIBMSS_LIB})
    endif()

    # adding mss include directories listed in mss_includes.txt
    file(STRINGS "${TARGET_DIR}/mss_includes.txt" MSS_INCLUDES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")
    string(REGEX REPLACE "EXAMPLE_DIR" "examples" MSS_INCLUDES "${MSS_INCLUDES}")

    include_directories("." ${MSS_INCLUDES})

    message("${TARGET_NAME} includes")
    message("----------------")
    foreach(dir ${MSS_INCLUDES})
        message(${dir})
    endforeach()


    file(STRINGS "${TARGET_DIR}/mss_sources_gw.txt" MSS_SOURCES)
    if (NOT WIN32)
      set(MSS_SOURCES ${MSS_SOURCES} "MSS_SRC_DIR/examples/mocana_example.c")
    endif()
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")

    # Set Windows file properties
    if(WIN32)
      set(MSS_SOURCES ${MSS_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
    endif()

    if(CM_ENABLE_FIPS)
      set(MSS_SOURCES ${MSS_SOURCES} "${MSS_SRC_DIR}//examples/fips_utils.c")
    endif()

    message("mss sources")
    message("-----------")
    foreach(file ${MSS_SOURCES})
        message(${file})
    endforeach()

    add_executable(${TARGET_NAME} "${MSS_SOURCES}")

    if(UNIX AND NOT ANDROID)
        set(libraryLists ${libraryLists} pthread)
    endif()

    target_link_libraries(${TARGET_NAME} ${libraryLists})

    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

    move_to_bin(${TARGET_NAME})

endif()

if (CM_BUILD_SSL_SERVER_ASYNC)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ssl-server")

    set(TARGET_NAME ssl_server_async)

    set(MOCANA_FLAGS "")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    if ((CM_ENABLE_TAP_LOCAL) OR (CM_ENABLE_TAP_REMOTE) OR (CM_ENABLE_TAP_REMOTE_TCP))

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB} ${ASN1_LIB}
                         ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB}
                         ${NANOCERT_LIB} ${CRYPTOINTERFACE_LIB}  ${COMMON_LIB}
                         ${PLATFORM_LIB} ${COMMON_LIB})

        #set(libraryLists initialize nanossl nanotap2 nanotap2_common smptpm2 tpm2 nanocert cryptointerface nanocap asn1 common platform)
    else()
        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB} ${NANOCERT_LIB}
                         ${CRYPTOINTERFACE_LIB}
                         ${COMMON_LIB} ${PLATFORM_LIB} ${ASN1_LIB})
        #set(libraryLists initialize nanossl nanocert cryptointerface nanocap asn1 common platform)
    endif()
    if(CM_ENABLE_FIPS)
      set(libraryLists ${libraryLists} ${LIBMSS_LIB})
    endif()

    # adding mss include directories listed in mss_includes.txt
    file(STRINGS "${TARGET_DIR}/mss_includes.txt" MSS_INCLUDES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")
    string(REGEX REPLACE "EXAMPLE_DIR" "examples" MSS_INCLUDES "${MSS_INCLUDES}")

    include_directories("." ${MSS_INCLUDES})

    message("${TARGET_NAME} includes")
    message("----------------")
    foreach(dir ${MSS_INCLUDES})
        message(${dir})
    endforeach()


    file(STRINGS "${TARGET_DIR}/mss_sources_async.txt" MSS_SOURCES)
    if (NOT WIN32)
      set(MSS_SOURCES ${MSS_SOURCES} "MSS_SRC_DIR/examples/mocana_example.c")
    endif()
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")

    # Set Windows file properties
    if(WIN32)
      set(MSS_SOURCES ${MSS_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
    endif()

    if(CM_ENABLE_FIPS)
      set(MSS_SOURCES ${MSS_SOURCES} "${MSS_SRC_DIR}/examples/fips_utils.c")
    endif()

    message("mss sources")
    message("-----------")
    foreach(file ${MSS_SOURCES})
        message(${file})
    endforeach()

    add_executable(${TARGET_NAME} "${MSS_SOURCES}")

    if(UNIX AND NOT ANDROID)
        set(libraryLists ${libraryLists} pthread)
    endif()

    target_link_libraries(${TARGET_NAME} ${libraryLists})

    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

    move_to_bin(${TARGET_NAME})

endif()

if (CM_BUILD_SSL_SERVER_ASYNC_EXTERNAL_PSK)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ssl-server")

    set(TARGET_NAME ssl_server_async_external_psk)

    set(MOCANA_FLAGS "")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    if ((CM_ENABLE_TAP_LOCAL) OR (CM_ENABLE_TAP_REMOTE) OR (CM_ENABLE_TAP_REMOTE_TCP))

        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB} ${ASN1_LIB}
                         ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB}
                         ${NANOCERT_LIB} ${CRYPTOINTERFACE_LIB}  ${COMMON_LIB}
                         ${PLATFORM_LIB} ${COMMON_LIB})

        #set(libraryLists initialize nanossl nanotap2 nanotap2_common smptpm2 tpm2 nanocert cryptointerface nanocap asn1 common platform)
    else()
        set(libraryLists ${INITIALIZE_LIB} ${NANOSSL_LIB} ${NANOCERT_LIB}
                         ${CRYPTOINTERFACE_LIB}
                         ${COMMON_LIB} ${PLATFORM_LIB} ${ASN1_LIB})
        #set(libraryLists initialize nanossl nanocert cryptointerface nanocap asn1 common platform)
    endif()
    if(CM_ENABLE_FIPS)
      set(libraryLists ${libraryLists} ${LIBMSS_LIB})
    endif()

    # adding mss include directories listed in mss_includes.txt
    file(STRINGS "${TARGET_DIR}/mss_includes.txt" MSS_INCLUDES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")
    string(REGEX REPLACE "EXAMPLE_DIR" "examples" MSS_INCLUDES "${MSS_INCLUDES}")

    include_directories("." ${MSS_INCLUDES})

    message("${TARGET_NAME} includes")
    message("----------------")
    foreach(dir ${MSS_INCLUDES})
        message(${dir})
    endforeach()


    file(STRINGS "${TARGET_DIR}/mss_sources_async_external_psk.txt" MSS_SOURCES)
    if (NOT WIN32)
        set(MSS_SOURCES ${MSS_SOURCES} "MSS_SRC_DIR/examples/mocana_example.c")
    endif()
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")

    # Set Windows file properties
    if(WIN32)
      set(MSS_SOURCES ${MSS_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
    endif()

    if(CM_ENABLE_FIPS)
      set(MSS_SOURCES ${MSS_SOURCES} "${MSS_SRC_DIR}/examples/fips_utils.c")
    endif()

    message("mss sources")
    message("-----------")
    foreach(file ${MSS_SOURCES})
        message(${file})
    endforeach()

    add_executable(${TARGET_NAME} "${MSS_SOURCES}")

    if(UNIX AND NOT ANDROID)
        set(libraryLists ${libraryLists} pthread)
    endif()

    target_link_libraries(${TARGET_NAME} ${libraryLists})

    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

    move_to_bin(${TARGET_NAME})

endif()


########################################################################
# Mocana dtls client  building
########################################################################
if (CM_BUILD_DTLS_CLIENT)
    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dtls_client")
    set(TARGET_NAME dtls_client)
    set(MOCANA_FLAGS "")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/dtls_client/mss_includes.txt")
    set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/dtls_client/mss_sources.txt")

    if (CM_ENABLE_TAP_LOCAL)

        set(libraryLists ${INITIALIZE_LIB} ${NANODTLS_CLIENT_LIB}
                ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB}
                ${NANOCERT_LIB} ${CRYPTOINTERFACE_LIB} ${COMMON_LIB}
                ${ASN1_LIB} ${PLATFORM_LIB} ${COMMON_LIB})
    else()
        set(libraryLists ${INITIALIZE_LIB} ${NANODTLS_CLIENT_LIB} ${NANOCERT_LIB}
            ${CRYPTOINTERFACE_LIB}  ${COMMON_LIB} ${PLATFORM_LIB}
            ${ASN1_LIB})
    endif()
    if(CM_ENABLE_FIPS)
      set(libraryLists ${libraryLists} ${LIBMSS_LIB})
    endif()

    if(CM_ENABLE_MONOLITHIC_BUILD)
        set(MSS_INCLUDES "" )
        foreach(include_file ${includelist})
        # adding mss include directories listed in mss_includes.txt
            file(STRINGS "${include_file}" INCLUDE_FOLDER)
            string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" INCLUDE_FOLDER "${INCLUDE_FOLDER}")
            string(REGEX REPLACE "EXAMPLE_DIR" "examples" INCLUDE_FOLDER "${INCLUDE_FOLDER}")
            set(MSS_INCLUDES ${MSS_INCLUDES} ${INCLUDE_FOLDER} )
        endforeach()

        include_directories("." ${MSS_INCLUDES})
        message("${TARGET_NAME} includes")
        message("----------------")
        foreach(dir ${MSS_INCLUDES})
            message(${dir})
        endforeach()

        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${MSS_DIR}/bin_static")

        set(MSS_SOURCES "")
        foreach(src_files ${srclist})
            # adding src files listed in mss_sources
            file(STRINGS "${src_files}" SRC_FILES)
            string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" SRC_FILES "${SRC_FILES}")
            set(MSS_SOURCES ${MSS_SOURCES} ${SRC_FILES} )
        endforeach()

        link_directories("${MSS_DIR}/bin_static")

        add_executable(${TARGET_NAME} "${MSS_SOURCES}")
        set_target_properties(${TARGET_NAME} PROPERTIES COMPILE_FLAGS "${MOCANA_FLAGS}")
        if (CM_ENABLE_COMMON_LINK)
            target_link_libraries(${TARGET_NAME} PUBLIC nanossl nanocap nanocert initialize nanocrypto cryptointerface nanocap nanocrypto asn1 platform common pthread)
        else()
            target_link_libraries(${TARGET_NAME} PUBLIC nanodtls_client nanocap nanocert initialize nanocrypto cryptointerface nanocap nanocrypto asn1 platform common pthread)
        endif()
    else()
        buildexecutable(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
                ${NSSL_BUILD_DIR} "ssl-client" ${MSS_BIN_DIR} ${libraryLists})
    endif()

    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

    move_to_bin(${TARGET_NAME})
endif()

########################################################################
# Mocana dtls server  building
########################################################################

if (CM_BUILD_DTLS_SERVER)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dtls_server")

    set(TARGET_NAME dtls_server)

    set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/dtls_server/mss_includes.txt")
    set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/dtls_server/mss_sources.txt")

    set(MOCANA_FLAGS "")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    if (CM_ENABLE_TAP_LOCAL)

        set(libraryLists ${INITIALIZE_LIB} ${NANODTLS_SERVER_LIB}
                ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB}
                ${NANOCERT_LIB} ${CRYPTOINTERFACE_LIB} ${COMMON_LIB}
                ${ASN1_LIB} ${PLATFORM_LIB} ${COMMON_LIB})
    else()
        set(libraryLists ${INITIALIZE_LIB} ${NANODTLS_SERVER_LIB} ${NANOCERT_LIB}
            ${CRYPTOINTERFACE_LIB}
            ${COMMON_LIB} ${PLATFORM_LIB} ${ASN1_LIB})
    endif()
    if(CM_ENABLE_FIPS)
      set(libraryLists ${libraryLists} ${LIBMSS_LIB})
    endif()

    if(CM_ENABLE_MONOLITHIC_BUILD)
        set(MSS_INCLUDES "" )
        foreach(include_file ${includelist})
        # adding mss include directories listed in mss_includes.txt
            file(STRINGS "${include_file}" INCLUDE_FOLDER)
            string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" INCLUDE_FOLDER "${INCLUDE_FOLDER}")
            string(REGEX REPLACE "EXAMPLE_DIR" "examples" INCLUDE_FOLDER "${INCLUDE_FOLDER}")
            set(MSS_INCLUDES ${MSS_INCLUDES} ${INCLUDE_FOLDER} )
        endforeach()

        include_directories("." ${MSS_INCLUDES})
        message("${TARGET_NAME} includes")
        message("----------------")
        foreach(dir ${MSS_INCLUDES})
            message(${dir})
        endforeach()

        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${MSS_DIR}/bin_static")

        set(MSS_SOURCES "")
        foreach(src_files ${srclist})
            # adding src files listed in mss_sources
            file(STRINGS "${src_files}" SRC_FILES)
            string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" SRC_FILES "${SRC_FILES}")
            set(MSS_SOURCES ${MSS_SOURCES} ${SRC_FILES} )
        endforeach()

        link_directories("${MSS_DIR}/bin_static" "${MSS_DIR}/bin")

        add_executable(${TARGET_NAME} "${MSS_SOURCES}")
        set_target_properties(${TARGET_NAME} PROPERTIES COMPILE_FLAGS "${MOCANA_FLAGS}")
        if (CM_ENABLE_COMMON_LINK)
            target_link_libraries(${TARGET_NAME} PUBLIC nanossl nanocap nanocert initialize nanocrypto cryptointerface nanocap nanocrypto asn1 platform common pthread) 
        else()
            target_link_libraries(${TARGET_NAME} PUBLIC nanodtls_server nanocap nanocert initialize nanocrypto cryptointerface nanocap nanocrypto asn1 platform common pthread)
        endif()
    else()
        buildexecutable(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
                ${NSSL_BUILD_DIR} "ssl-server" ${MSS_BIN_DIR} ${libraryLists})
    endif()

    # adding mocana flags
    if (WIN32)
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

    move_to_bin(${TARGET_NAME})
endif()
