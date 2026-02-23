########################################################################
# CMake build script for Mocana nanotap2 SHARED LIBRARY FOR NanoSMP
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
option(CM_ENABLE_SUITEB "Enable suiteb" OFF)
option(CM_ENABLE_TAP "Enable tap" OFF)
option(CM_ENABLE_TAP_REMOTE "Enable tap remote." OFF)
option(CM_ENABLE_TAP_EXTERN "Enable tap extern." OFF)
option(CM_ENABLE_CLIENTCOMM "Enable client comm." OFF)
option(CM_ENABLE_SMP_PKCS11 "Enable PKCS11 SMP." OFF)
option(CM_ENABLE_SMP_NANOROOT "Enable NANOROOT SMP." OFF)
option(CM_ENABLE_SMP_TEE "Enable TEE SMP." OFF)
option(CM_ENABLE_TAP_MIN "Enable TAP small version." OFF)
option(CM_ENABLE_TAP_LOCAL "Enable tap local." OFF)
option(CM_ENABLE_OPENSSL "Enable OpenSSL build for TAP remote." OFF)
option(CM_ENABLE_DATA_PROTECT "Enable TAP Data Protection APIs." OFF)
option(CM_ENABLE_TCP_CLOSE_MSG "Enable TCP close message." OFF)
option(CM_BUILD_X32    "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64    "Build for 64Bit Machine." OFF)
option(CM_ENABLE_TAP_EXTERN_LIB "Build tap extern library ." OFF)
option(CM_ENABLE_TPM "Enable tpm12." OFF)
option(CM_ENABLE_FIPS "Build with FIPS." OFF)
if(BUILD_FOR_OSI)
    option(CM_BUILD_TAP_LIB "Enable nanotap build libs." ON)
    if (NOT CM_ENABLE_TAP_REMOTE)
        option(CM_ENABLE_TPM2 "Enable tpm2 ." ON)
    endif()
    option(CM_ENABLE_TAP_LOCAL "Enable tap local" ON)
else()
    option(CM_BUILD_TAP_LIB "Enable nanotap build libs." OFF)
    option(CM_ENABLE_TPM2 "Enable tpm2 ." OFF)
    option(CM_ENABLE_TAP_LOCAL "Enable tap local" OFF)
endif()
if (WIN32)
    option(CM_WIN_FORCE_LINKAGE "Force linkage for shared library." OFF)
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
include(MocPlatform)

project (nanotap2 C)

include(locate_lib)
include(build_rc_file)
include(cmakeflags.txt)
include(cmakefunctions.txt)

# Make sure we do not have conflicting options in affect
if(CM_ENABLE_TAP_REMOTE AND CM_ENABLE_TAP_LOCAL)
    message(FATAL_ERROR "Either TAP Local or TAP Remote must be enabled")
endif()

if(WIN32)
    set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32")
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

if(NOT EXISTS ${NTAP2_DEFS_FILE})
    message(FATAL_ERROR "\nNTAP2_DEFS_FILE = ${NTAP2_DEFS_FILE} does not exist")
endif()

message("\nNTAP2_DEFS_FILE = ${NTAP2_DEFS_FILE}")
include(${NTAP2_DEFS_FILE})

########################################################################
# Mocana nanotap2 client comm SHARED LIBRARY building
########################################################################
if(BUILD_FOR_OSI)
    set(ASN1_LIB "${LIB_DIR}/libasn1.so")
    set(COMMON_LIB "${LIB_DIR}/libcommon.so")
    set(INITIALIZE_LIB "${LIB_DIR}/libinitialize.so")
    set(PLATFORM_LIB "${LIB_DIR}/libplatform.so")
    set(CRYPTOINTERFACE_LIB "${LIB_DIR}/libcryptointerface.so")
    set(NANOCAP_LIB "${LIB_DIR}/libnanocap.so")
    if (CM_ENABLE_EXPORT_ED)
        set(CRYPTO_MW_LIB "${LIB_DIR}/libcryptomw.so")
    else()
        set(NANOCRYPTO_LIB "${LIB_DIR}/libnanocrypto.so")
    endif()
    set(NANOCERT_LIB "${LIB_DIR}/libnanocert.so")
    set(NANOSSL_LIB "${LIB_DIR}/libnanossl.so")
    set(NANOTAP2_LIB "${LIB_DIR}/libnanotap2.so")
    set(NANOTAP2_COMMON_LIB "${LIB_DIR}/libnanotap2_common.so")
    set(NANOTAP2_CONFIGPARSER_LIB "${LIB_DIR}/libnanotap2_configparser.so")
if(CM_ENABLE_CLIENTCOMM)
    set(NANOTAP2_CLIENTCOMM_LIB "${LIB_DIR}/libnanotap2_clientcomm.so")
endif()
if (CM_ENABLE_TPM2)
    set(TPM2_LIB "${LIB_DIR}/libtpm2.so")
    set(SMP_LIB "${LIB_DIR}/libsmptpm2.so")
endif()
    if (CM_ENABLE_SMP_NANOROOT)
        set(SMP_NANOROOT "${LIB_DIR}/libsmpnanoroot.so")
    endif()
else()
    locate_lib(ASN1_LIB asn1)
    locate_lib(COMMON_LIB common)
    locate_lib(PLATFORM_LIB platform)
    locate_lib(NANOCRYPTO_LIB nanocrypto)
    locate_lib(CRYPTO_MW_LIB cryptomw)
    locate_lib(NANOSSL_LIB nanossl)
    locate_lib(NANOTAP2_COMMON_LIB nanotap2_common)
    locate_lib(NANOTAP2_CONFIGPARSER_LIB nanotap2_configparser)
    locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
    locate_lib(NANOCERT_LIB nanocert)
    if (CM_ENABLE_DATA_PROTECT)
      locate_lib(DATAPROTECT_LIB dataprotect)
    endif()

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

    if(CM_ENABLE_FIPS)
      locate_lib(LIBMSS_LIB libmss)
    endif()
endif()

# Set Windows file properties
if(WIN32)
  build_rc_file("TrustPoint Shared Library")
endif()

if(CM_ENABLE_CLIENTCOMM)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/client_common")
    message("TARGET_DIR = ${TARGET_DIR}")

    set(TARGET_NAME nanotap2_clientcomm)

    set(MOCANA_FLAGS "")
    init_flags()
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    set(libraryLists ${NANOTAP2_CONFIGPARSER_LIB} ${NANOTAP2_COMMON_LIB} ${NANOSSL_LIB} ${PLATFORM_LIB} ${COMMON_LIB})
    #set(libraryLists nanotap2_common nanocrypto common platform nanotap2_configparser)
    if(WIN32 OR ANDROID)
        locate_lib(INITIALIZE_LIB initialize)
        set(libraryLists ${libraryLists} ${INITIALIZE_LIB})
        if(CM_ENABLE_FIPS)
          set(libraryLists ${libraryLists} ${LIBMSS_LIB})
        endif()
    endif()

    buildLibrary(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${MSS_SRC_DIR} ${NTAP2_BUILD_DIR} ${MSS_BIN_DIR}  ${libraryLists})
    # adding mocana flags
    if(WIN32)
        #target_compile_definitions had problems in parsing multiple preprocessor
        #flags if CMAKE generator Visual Studio is used (NMAKE works fine).
        #Ref: https://cmake.org/cmake/help/v3.0/prop_tgt/COMPILE_DEFINITIONS.html
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

endif()

########################################################################
# Mocana nanotap2 SHARED LIBRARY building
########################################################################
if(CM_BUILD_TAP_LIB)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tap2")
    message("TARGET_DIR = ${TARGET_DIR}")

    set(TARGET_NAME nanotap2)

    if(CM_ENABLE_DATA_PROTECT)
      set(MOCANA_FLAGS "-D__ENABLE_DIGICERT_DATA_PROTECTION__")
    else()
      set(MOCANA_FLAGS "")
    endif()

    init_flags()
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)

    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    if("SHARED" STREQUAL "${LIB_TYPE}")
        if (CM_ENABLE_TAP_LOCAL)
            set(libraryLists ${NANOTAP2_COMMON_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB} ${COMMON_LIB} ${PLATFORM_LIB} ${NANOTAP2_CONFIGPARSER_LIB} ${SMP_LIB} ${SMP_LIB_TZ} ${SMP_NANOROOT})
            #set(libraryLists nanocrypto common platform asn1 nanotap2_common)
        elseif (CM_ENABLE_TAP_REMOTE)
            locate_lib(NANOTAP2_CLIENTCOMM_LIB nanotap2_clientcomm)
            set(libraryLists ${NANOTAP2_COMMON_LIB} ${NANOTAP2_CLIENTCOMM_LIB} ${NANOCRYPTO_LIB} ${CRYPTO_MW_LIB} ${COMMON_LIB} ${PLATFORM_LIB} ${NANOTAP2_CONFIGPARSER_LIB} ${SMP_LIB})
            #set(libraryLists nanotap2_clientcomm nanocrypto common platform asn1 nanotap2_common)
        endif()
        if(WIN32 OR ANDROID)
            locate_lib(INITIALIZE_LIB initialize)
            set(libraryLists ${libraryLists} ${NANOCERT_LIB} ${CRYPTOINTERFACE_LIB} ${INITIALIZE_LIB} ${ASN1_LIB})
            if(CM_ENABLE_FIPS)
                set(libraryLists ${libraryLists} ${LIBMSS_LIB})
            endif()
        endif()

        if(CM_ENABLE_DATA_PROTECT)
            set(libraryLists ${libraryLists} ${DATAPROTECT_LIB} )
        endif()
    else()
        set(libraryLists "")
    endif()

    buildLibrary(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${MSS_SRC_DIR} ${NTAP2_BUILD_DIR} ${MSS_BIN_DIR}  ${libraryLists})
    # adding mocana flags
    if(WIN32)
        #target_compile_definitions had problems in parsing multiple preprocessor
        #flags if CMAKE generator Visual Studio is used (NMAKE works fine).
        #Ref: https://cmake.org/cmake/help/v3.0/prop_tgt/COMPILE_DEFINITIONS.html
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

endif()
########################################################################

########################################################################
# Mocana tap_extern SHARED LIBRARY building
########################################################################
if(CM_ENABLE_TAP_EXTERN_LIB)

    set(TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tap_extern")
    message("TARGET_DIR = ${TARGET_DIR}")

    set(TARGET_NAME tap_extern)

    set(MOCANA_FLAGS "")
    init_flags()
    buildflags(${TARGET_DIR} ${EXTRA_DEFINITIONS} MOCANA_FLAGS)
    message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

    if("SHARED" STREQUAL "${LIB_TYPE}")
        locate_lib(NANOTAP2_LIB nanotap2)
        set(libraryLists ${NANOTAP2_LIB} ${NANOTAP2_COMMON_LIB} ${NANOCRYPTO_LIB} ${COMMON_LIB} ${PLATFORM_LIB})
        #set(libraryLists nanotap2 common nanotap2_common nanocrypto)
        if(WIN32 OR ANDROID)
            locate_lib(INITIALIZE_LIB initialize)
            set(libraryLists ${libraryLists} ${INITIALIZE_LIB})
        endif()
    else()
        set(libraryLists)
    endif()

    buildLibrary(${LIB_TYPE} ${TARGET_NAME} ${TARGET_DIR} ${MSS_SRC_DIR} ${NTAP2_BUILD_DIR} ${MSS_BIN_DIR}  ${libraryLists})

    # adding mocana flags
    if(WIN32)
        #target_compile_definitions had problems in parsing multiple preprocessor
        #flags if CMAKE generator Visual Studio is used (NMAKE works fine).
        #Ref: https://cmake.org/cmake/help/v3.0/prop_tgt/COMPILE_DEFINITIONS.html
        add_definitions("${MOCANA_FLAGS}")
    else()
        target_compile_definitions(${TARGET_NAME}   PRIVATE "${MOCANA_FLAGS}")
    endif()

endif()
########################################################################

if(BUILD_FOR_OSI)
    add_custom_command(
      TARGET ${PROJECT_NAME}
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy
          $<TARGET_FILE:${PROJECT_NAME}>
          "${LIB_DIR}")
    if(CM_ENABLE_CLIENTCOMM)
        add_custom_command(
            TARGET nanotap2_clientcomm
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
                $<TARGET_FILE:nanotap2_clientcomm>
                "${LIB_DIR}")
    endif()
    if(CM_ENABLE_TAP_EXTERN_LIB)
        add_custom_command(
            TARGET tap_extern
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
                $<TARGET_FILE:tap_extern>
                "${LIB_DIR}")
    endif()
endif()
