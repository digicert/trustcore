########################################################################
# CMake build script for DigiCert NanoSSH SHARED LIBRARY
#

if(BUILD_FOR_OSI)
    cmake_minimum_required(VERSION 3.16)
else()
    cmake_minimum_required(VERSION 3.2)
endif()

option(CM_ENABLE_DEBUG                              "Enable Debug logs."                  OFF)
option(CM_DISABLE_SUITEB                            "Disable Mocana Suite B algorithms"   OFF)
option(CM_ENABLE_TAP                                "Enable TAP"                          OFF)
option(CM_ENABLE_TAP_LOCAL                          "Enable Tap Local"                    OFF)
option(CM_ENABLE_TAP_REMOTE                         "Enable Tap Remote"                   OFF)
option(CM_ENABLE_X509_CERTS                         "Enable support for X509 Certificates" OFF)
option(CM_ENABLE_SERVER_CERT_AUTH                   "Enable Server Certificate Authentication" OFF)
option(CM_ENABLE_OCSP_CERT                          "Enable OCSP support for Certificates" OFF)
option(CM_ENABLE_OCSP_TIMEOUT_CONFIG                "Enable OCSP timeout"                 OFF)
option(CM_ENABLE_CLIENT_AUTH                        "Enable Client Public Key Authentication"  OFF)
option(CM_ENABLE_CLIENT_CERT_AUTH                   "Enable Client Certficiate authentication" OFF)
option(CM_ENABLE_MOCANA_PORT_FORWARD                "Enable Port Forwarding"              OFF)
option(CM_ENABLE_MOCANA_REMOTE_PORT_FORWARD         "Enable Remote Port Forwarding"       OFF)
option(CM_ENABLE_RADIUS                             "Enable Radius"                       OFF)
option(CM_ENABLE_SCP_EXAMPLE                        "Enable SCP example"                  OFF)
option(CM_ENABLE_EMULATOR                           "Enable Emulator"                     OFF)
option(CM_ENABLE_EXPORT_ED                          "Enable Export Edition"               OFF)
option(CM_DISABLE_PQC                               "Disable Quantum Safe algorithms"     OFF)
option(CM_ENABLE_PQC_COMPOSITE                      "Enable PQC Composite."               OFF)
option(CM_ENABLE_KEYBOARD_INTERACTIVE               "Enable keyboard-interactive protocol" OFF)
option(CM_ENABLE_MOCANA_NO_PUBKEY_NAME              "Enable no public key name verification" OFF)
option(CM_ENABLE_FIPS                               "Enable FIPS"                         OFF)
option(CM_ENABLE_DATA_PROTECTION                    "Enable Data Protection"              OFF)
if(BUILD_FOR_OSI)
option(CM_ENABLE_CHACHAPOLY                         "Enable ChaCha20 and Poly1305 support" ON)
else()
option(CM_ENABLE_CHACHAPOLY                         "Enable ChaCha20 and Poly1305 support" OFF)
endif()
option(CM_ENABLE_BLOWFISH                           "Enable Blowfish support" OFF)
option(CM_ENABLE_DSA_SUPPORT                        "Enable DSA support in NanoSSH" OFF)
option(CM_ENABLE_SSH_UNITTEST                       "Build unittest"                      OFF)
option(CM_DISABLE_EDDSA_25519_SUPPORT               "Disable Ed25519 support in NanoSSH" OFF)
option(CM_DISABLE_EDDSA_448_SUPPORT                 "Disable Ed448 support in NanoSSH" OFF)
option(CM_DISABLE_ECDH_25519_SUPPORT                "Disable ECDH with Curve25519 support in NanoSSH" OFF)
option(CM_ENABLE_MOCANA_SSH_EXAMPLE_GRACEFUL_SHUTDOWN "Build with server or client example shutdown gracefully." OFF)
option(CM_ENABLE_WEAK_CIPHERS                       "Build with weak ciphers enabled."   OFF)
option(CM_ENABLE_SERIAL_CHANNEL                     "Enable support for serial channels"  OFF)
option(CM_BUILD_SHARED_LIBS                         "Build NanoSSH Shared Library"        OFF)
option(CM_BUILD_SSH_CLIENT                          "Build NanoSSH client"                OFF)
option(CM_BUILD_SSH_SERVER                          "Build NanoSSH server"                OFF)
option(CM_BUILD_SSH_SERVER_SP800_135                "Build NanoSSH server for testing SP800-135"                OFF)
if (DEFINED SECURE_PATH)
option(CM_ENABLE_ABSOLUTE_PATH                      "Enable absolute path support." ON)
else()
option(CM_ENABLE_ABSOLUTE_PATH                      "Enable absolute path support." OFF)
endif()


option(CM_BUILD_X32                                 "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64                                 "Build for 64Bit Machine." OFF)

project (nanossh)

include(cmakeflags.txt)

# Make sure we do not have conflicting options in affect
if(CM_ENABLE_TAP_REMOTE AND CM_ENABLE_TAP_LOCAL)
    message(FATAL_ERROR "Either TAP Local or TAP Remote must be enabled")
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

include(MocPlatform)
include(build_executable)
include(build_library)
include(locate_lib)

if(WIN32)
    set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32")
else()
    set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
endif()

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
set(CMAKE_INSTALL_RPATH "${MSS_BIN_DIR}")

if(BUILD_FOR_OSI)
    set(LIB_DIR  "${MSS_DIR}/lib")
    set(MSS_BIN_DIR "${LIB_DIR}")
endif()

set(LIB_TYPE "SHARED" CACHE STRING "Which lib type to build: SHARED (default) or STATIC")
message("LIB_TYPE           = ${LIB_TYPE}")

message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")

#set(CMAKE_MAKE_PROGRAM "/usr/local/bin/cmake")
set(NSSH_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${NSSH_BUILD_DIR}/libs")
set(CMAKE_BINARY_DIR "${NSSH_BUILD_DIR}")
set(NSSH_DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")

if(NOT EXISTS ${NSSH_DEFS_FILE})
    message(FATAL_ERROR "\nNSSH_DEFS_FILE = ${NSSH_DEFS_FILE} does not exist")
endif()

message("\nNSSH_DEFS_FILE = ${NSSH_DEFS_FILE}")
include(${NSSH_DEFS_FILE})


add_compile_options(${WERROR})

########################################################################
# Locate base libraries
########################################################################

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(CRYPTO_LIB_ARCH_DIR "aarch64")
else()
    set(CRYPTO_LIB_ARCH_DIR "linux-x86_64")
endif()
# Get the full path to our base libraries
# Note: If library is not found, variable will be empty.
locate_lib(ASN1_LIB asn1)
locate_lib(COMMON_LIB common)
locate_lib(INITIALIZE_LIB initialize)
locate_lib(PLATFORM_LIB platform)
locate_lib(NANOCRYPTO_LIB nanocrypto)
locate_lib(CRYPTO_MW_LIB cryptomw)
locate_lib(NANOCERT_LIB nanocert)
locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
locate_lib(OSSL_CRYPTO_LIB crypto)
locate_lib(NANOTAP2_LIB nanotap2)
locate_lib(NANOTAP2_COMMON_LIB nanotap2_common)
locate_lib(TPM2_LIB tpm2)
locate_lib(SMPTPM2_LIB smptpm2)
locate_lib(NANOTAP2_CONFIGPARSER_LIB nanotap2_configparser)
locate_lib(NANOTAP2_CLIENTCOMM_LIB nanotap2_clientcomm)
locate_lib(HW_ACCEL_LIB hw)
locate_lib(DATAPROTECT_LIB dataprotect)
if(WIN32)
set(WS32_LIB "Ws2_32")
else()
set(WS32_LIB "")
endif()
if(CM_ENABLE_FIPS)
    locate_lib(FIPS_LIB mss)
endif()

if(CM_ENABLE_ABSOLUTE_PATH)
  set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -D__ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__")
endif()

if (DEFINED SECURE_PATH)
  set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -D__ENABLE_DIGICERT_SECURE_PATH__")
  message("\nSECURE_PATH = ${SECURE_PATH}")
  add_definitions("-DMANDATORY_BASE_PATH=\"${SECURE_PATH}\"")
endif()

if(CM_ENABLE_PQC_COMPOSITE)
  add_definitions(" -D__ENABLE_MOCANA_PQC_COMPOSITE__ ")
endif()

########################################################################
# Mocana ssh client  building
########################################################################
if (CM_BUILD_SSH_CLIENT)
    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ssh_client")
    set(TARGET_NAME ssh_client)
    set(MOCANA_FLAGS "")

    if ((NOT CM_ENABLE_MOCANA_PORT_FORWARD) AND (NOT CM_ENABLE_MOCANA_REMOTE_PORT_FORWARD))
      if(NOT BUILD_FOR_OSI OR (BUILD_FOR_OSI AND NOT ENABLE_SSH_CLIENT_SHELL_EXAMPLE))
        set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -D__ENABLE_MOCANA_SSH_FTP_CLIENT__")
      endif()
    endif()

    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)

    string(APPEND MY_FLAGS " -Werror=shadow")
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/ssh_client/mss_includes.txt")
    if(BUILD_FOR_OSI)
        set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/ssh_client/mss_osi_sources.txt")
    else()
        set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/ssh_client/mss_sources.txt")
    endif()

    if (NOT CM_DISABLE_PQC)
      set(srclist ${srclist} "${CMAKE_CURRENT_SOURCE_DIR}/pqc/mss_sources.txt")
    endif()

    if (WIN32)
      set(srclist ${srclist} "${CMAKE_CURRENT_SOURCE_DIR}/ssh_client/mss_win_sources.txt")
    endif()

    set(libraryLists
        ${ASN1_LIB}
        ${COMMON_LIB}
        ${CRYPTO_MW_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${DATAPROTECT_LIB}
        ${FIPS_LIB}
        ${HW_ACCEL_LIB}
        ${INITIALIZE_LIB}
        ${NANOCRYPTO_LIB}
        ${NANOCERT_LIB}
        ${NANOTAP2_LIB}
        ${NANOTAP2_CLIENTCOMM_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${NANOTAP2_CONFIGPARSER_LIB}
        ${PLATFORM_LIB}
        ${SMPTPM2_LIB}
        ${TPM2_LIB})

	if(NOT CM_BUILD_SHARED_LIBS)
        buildexecutable(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
                        ${NSSH_BUILD_DIR} "ssh_client" ${MSS_BIN_DIR} ${libraryLists})
        if(BUILD_FOR_OSI)
            target_link_libraries(${TARGET_NAME} nanocert)
            target_link_libraries(${TARGET_NAME} cryptointerface)
            target_link_libraries(${TARGET_NAME} nanocap)
            target_link_libraries(${TARGET_NAME} nanocrypto)
        endif()
    else()
        set(TARGET_NAME "nanosshc")

        if(BUILD_FOR_OSI)
            set(ASN1_LIB            "${LIB_DIR}/libasn1.so")
            set(COMMON_LIB          "${LIB_DIR}/libcommon.so")
            set(INITIALIZE_LIB      "${LIB_DIR}/libinitialize.so")

            add_library(nanocap SHARED IMPORTED)
            set_target_properties(nanocap PROPERTIES
                IMPORTED_LOCATION "${MSS_DIR}/crypto_lib/${CRYPTO_LIB_ARCH_DIR}/libnanocap.so")

            add_library(nanocert SHARED IMPORTED)
            set_target_properties(nanocert PROPERTIES
                IMPORTED_LOCATION "${MSS_DIR}/crypto_lib/${CRYPTO_LIB_ARCH_DIR}/libnanocert.so")

            add_library(nanocrypto SHARED IMPORTED)
            set_target_properties(nanocrypto PROPERTIES
                IMPORTED_LOCATION "${MSS_DIR}/crypto_lib/${CRYPTO_LIB_ARCH_DIR}/libnanocrypto.so")

            add_library(cryptointerface SHARED IMPORTED)
            set_target_properties(cryptointerface PROPERTIES
                IMPORTED_LOCATION "${MSS_DIR}/crypto_lib/${CRYPTO_LIB_ARCH_DIR}/libcryptointerface.so")

            set(libraryLists
                ${ASN1_LIB}
                ${COMMON_LIB}
                ${INITIALIZE_LIB}
                nanocap
                nanocert
                nanocrypto
                cryptointerface
                )
        endif()
        buildLibrary(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
                        ${NSSH_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})
    endif()
    # adding mocana flags
    set_target_properties(${TARGET_NAME} PROPERTIES COMPILE_FLAGS "${MOCANA_FLAGS} -D__ENABLE_CMAKE_BUILD__")

endif()

########################################################################
# Mocana ssh server  building
########################################################################

if (CM_BUILD_SSH_SERVER)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ssh_server")
    set(TARGET_NAME ssh_server)

    set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/ssh_server/mss_includes.txt")
    if(BUILD_FOR_OSI)
        set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/ssh_server/mss_osi_sources.txt")
    else()
        set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/ssh_server/mss_sources.txt")
    endif()

    if(CM_ENABLE_MOCANA_NO_PUBKEY_NAME)
        set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -D__ENABLE_MOCANA_SSH_NO_PUBKEY_NAME__")
    endif()

    if(BUILD_FOR_OSI)
        if(ENABLE_SSH_ASYNC_API_SUPPORT)
            set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -D__ENABLE_MOCANA_SSH_ASYNC_SERVER_API__")
        endif()

        if (NOT CM_ENABLE_SSH_UNITTEST)
            set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -D__ENABLE_MOCANA_SSH_FTP_SERVER__")
        endif()
    else()
        set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -D__ENABLE_MOCANA_SSH_FTP_SERVER__")
    endif()

    set(MOCANA_FLAGS "")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    set(libraryLists
        ${ASN1_LIB}
        ${COMMON_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${CRYPTO_MW_LIB}
        ${DATAPROTECT_LIB}
        ${FIPS_LIB}
        ${HW_ACCEL_LIB}
        ${INITIALIZE_LIB}
        ${NANOCRYPTO_LIB}
        ${NANOCERT_LIB}
        ${NANOTAP2_LIB}
        ${NANOTAP2_CLIENTCOMM_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${NANOTAP2_CONFIGPARSER_LIB}
        ${PLATFORM_LIB}
        ${SMPTPM2_LIB}
        ${TPM2_LIB}
        ${WS32_LIB})

    if (NOT CM_DISABLE_PQC)
      set(srclist ${srclist} "${CMAKE_CURRENT_SOURCE_DIR}/pqc/mss_sources.txt")
    endif()

    if(CM_ENABLE_RADIUS)
        set(includelist ${includelist} "${CMAKE_CURRENT_SOURCE_DIR}/radius/mss_includes.txt")
        set(srclist ${srclist} "${CMAKE_CURRENT_SOURCE_DIR}/radius/mss_sources.txt")
    endif()

    if(NOT CM_BUILD_SHARED_LIBS)
        buildexecutable(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
                         ${NSSH_BUILD_DIR} "ssh_server" ${MSS_BIN_DIR} ${libraryLists})

        if(BUILD_FOR_OSI)
            target_link_libraries(${TARGET_NAME} nanocert)
            target_link_libraries(${TARGET_NAME} cryptointerface)
            target_link_libraries(${TARGET_NAME} nanocap)
            target_link_libraries(${TARGET_NAME} nanocrypto)
        endif()
    else()
        set(TARGET_NAME "nanosshs")

        if(BUILD_FOR_OSI)
            set(ASN1_LIB            "${LIB_DIR}/libasn1.so")
            set(COMMON_LIB          "${LIB_DIR}/libcommon.so")
            set(INITIALIZE_LIB      "${LIB_DIR}/libinitialize.so")

            add_library(nanocap SHARED IMPORTED)
            set_target_properties(nanocap PROPERTIES
                IMPORTED_LOCATION "${MSS_DIR}/crypto_lib/${CRYPTO_LIB_ARCH_DIR}/libnanocap.so")

            add_library(nanocert SHARED IMPORTED)
            set_target_properties(nanocert PROPERTIES
                IMPORTED_LOCATION "${MSS_DIR}/crypto_lib/${CRYPTO_LIB_ARCH_DIR}/libnanocert.so")

            add_library(nanocrypto SHARED IMPORTED)
            set_target_properties(nanocrypto PROPERTIES
                IMPORTED_LOCATION "${MSS_DIR}/crypto_lib/${CRYPTO_LIB_ARCH_DIR}/libnanocrypto.so")

            add_library(cryptointerface SHARED IMPORTED)
            set_target_properties(cryptointerface PROPERTIES
                IMPORTED_LOCATION "${MSS_DIR}/crypto_lib/${CRYPTO_LIB_ARCH_DIR}/libcryptointerface.so")

            set(libraryLists
                ${ASN1_LIB}
                ${COMMON_LIB}
                ${INITIALIZE_LIB}
                nanocap
                nanocert
                nanocrypto
                cryptointerface
                )
        endif()
        buildLibrary(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
                        ${NSSH_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})
    endif()
    # adding mocana flags
    set_target_properties(${TARGET_NAME} PROPERTIES COMPILE_FLAGS "${MOCANA_FLAGS} -D__ENABLE_CMAKE_BUILD__")  

endif()

if (CM_BUILD_SSH_SERVER_SP800_135)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ssh_server")
    set(TARGET_NAME ssh_server_sp800_135)

    set(includelist "${CMAKE_CURRENT_SOURCE_DIR}/ssh_server/mss_includes.txt")
    set(srclist "${CMAKE_CURRENT_SOURCE_DIR}/ssh_server/mss_sources_sp800_135.txt")

    if(CM_ENABLE_MOCANA_NO_PUBKEY_NAME)
        set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -D__ENABLE_MOCANA_SSH_NO_PUBKEY_NAME__")
    endif()

    set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -D__ENABLE_MOCANA_SSH_FTP_SERVER__")

    set(MOCANA_FLAGS "-D__ENABLE_MOCANA_SP800_135_ACVP__")
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    set(libraryLists
        ${ASN1_LIB}
        ${COMMON_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${CRYPTO_MW_LIB}
        ${DATAPROTECT_LIB}
        ${FIPS_LIB}
        ${HW_ACCEL_LIB}
        ${INITIALIZE_LIB}
        ${NANOCRYPTO_LIB}
        ${NANOCERT_LIB}
        ${NANOTAP2_LIB}
        ${NANOTAP2_CLIENTCOMM_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${NANOTAP2_CONFIGPARSER_LIB}
        ${PLATFORM_LIB}
        ${SMPTPM2_LIB}
        ${TPM2_LIB}
        ${WS32_LIB})

    if (NOT CM_DISABLE_PQC)
      set(srclist ${srclist} "${CMAKE_CURRENT_SOURCE_DIR}/pqc/mss_sources.txt")
    endif()

    if(CM_ENABLE_RADIUS)
        set(includelist ${includelist} "${CMAKE_CURRENT_SOURCE_DIR}/radius/mss_includes.txt")
        set(srclist ${srclist} "${CMAKE_CURRENT_SOURCE_DIR}/radius/mss_sources.txt")
    endif()

    if(NOT CM_BUILD_SHARED_LIBS)
        buildexecutable(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
                         ${NSSH_BUILD_DIR} "ssh_server" ${MSS_BIN_DIR} ${libraryLists})
    else()
        set(TARGET_NAME "nanosshs")
        buildLibrary(${LIB_TYPE} ${TARGET_NAME} "${includelist}" "${srclist}" ${MSS_SRC_DIR}
                        ${NSSH_BUILD_DIR} ${MSS_BIN_DIR} ${libraryLists})
    endif()
    # adding mocana flags
    set_target_properties(${TARGET_NAME} PROPERTIES COMPILE_FLAGS "${MOCANA_FLAGS} -D__ENABLE_CMAKE_BUILD__")  

endif()
