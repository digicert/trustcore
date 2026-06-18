########################################################################
# CMake build script for Mocana cryptographic libraries
#
# This project builds the cryptointerface libraries and the relevant crypto
# libraries required by the cryptointerface depending on the options passed in
# by the caller.
########################################################################

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

option(CM_BUILD_X32        "Build for 32-bit Machine."         OFF)
option(CM_BUILD_X64        "Build for 64-bit Machine."         OFF)
option(CM_WIN_FORCE_LINKAGE "Force linkage for shared library." OFF)
option(CM_DISABLE_RC5      "Build with RC5 disabled."          OFF)
option(CM_BUILD_DATALIB    "Build data library for global symbols." ON)
option(CM_ENABLE_FIPS_700_U1_COMPAT    "Build library with backwards compatibility for REL-700-U1 binary." OFF)
if(BUILD_FOR_OSI)
  option(CM_ENABLE_SSL          "Build with SSL support." ON)
  option(CM_ENABLE_PSS_VAR_SALT "Build with var saltlen." ON)
endif()

# Get the list of all the directories in the options directory
file(GLOB project_options ${CMAKE_CURRENT_SOURCE_DIR}/options/*)

# Loop through each directory and convert it into an option
foreach(option ${project_options})

    # If its a directory convert it into a CMake option
    if(IS_DIRECTORY ${option})

        # Extract the directory name
        get_filename_component(option_name ${option} NAME)

        # Convert the name to all uppercase
        string(TOUPPER ${option_name} option_cmake_name)

        # Replace - with _
        string(REPLACE "-" "_" option_cmake_name ${option_cmake_name})

        # Create the option with CM_ prepended
        option(CM_${option_cmake_name} "${option_name}." OFF)

        # If the option is enabled then check that directory for any flag files
        # to bring in. There is also special handling for the default directory.
        # The default directory flags are always added and cannot be disabled.
        if(CM_${option_cmake_name} OR
           "CM_DEFAULT" STREQUAL "CM_${option_cmake_name}")

            message("--------------------------------------")
            message("CM_${option_cmake_name} Option Specified")

            if(EXISTS ${option}/mocana_flags.txt)
                file(STRINGS ${option}/mocana_flags.txt flags)
                message("    FLAGS FILE = ${option}/mocana_flags.txt")
                message("    FLAGS = ${flags}")
                set(OPTIONS_MOCANA_FLAGS ${OPTIONS_MOCANA_FLAGS} ${flags})
            endif()

        endif()

    endif()

endforeach()

message("--------------------------------------")

# Remove any possible duplicates
list(REMOVE_DUPLICATES OPTIONS_MOCANA_FLAGS)

# If AES CCM is not disabled, add __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CCM__
list(FIND OPTIONS_MOCANA_FLAGS "-D__DISABLE_AES_CCM__" INDEX)
if (${INDEX} EQUAL -1)
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CCM__")
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

# Must be included before the project is specified
include(MocPlatform)

project(crypto C)

include(build_rc_file)

# Get releveant CMake files/modules
include(locate_lib)

# Set the path to the mss directory and source directory
set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${MSS_DIR}/src")
if(BUILD_FOR_OSI)
  set(LIB_DIR "${MSS_DIR}/lib")
endif()
if("STATIC" STREQUAL "${LIB_TYPE}")
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# Set the library type
set(LIB_TYPE "SHARED" CACHE STRING "Type of library to build. (SHARED or STATIC)")
message("LIB_TYPE           = ${LIB_TYPE}")

# Include the mss_defs file. This will take care of setting the system flags.
set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
if(NOT EXISTS ${DEFS_FILE})
    message(FATAL_ERROR "\nDEFS_FILE = ${DEFS_FILE} does not exist")
endif()

message("\nDEFS_FILE = ${DEFS_FILE}")
include(${DEFS_FILE})
set(VERSION_FILE "${MSS_DIR}/projects/shared_cmake/set_cpack_version.cmake")
include(${VERSION_FILE})
if(DEFINED ENV{BUILD_NUMBER})
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "$ENV{BUILD_NUMBER}")
else()
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "0")
endif()

# Add flag to enable RSA 8K support
if(CM_ENABLE_RSA_8K)
    add_definitions("-DMOCANA_MAX_MODULUS_SIZE=1024")
    add_definitions("-D__ENABLE_DIGICERT_RSA_ALL_KEYSIZE__")
endif()

if(CM_ENABLE_OPENSSL_SHIM AND NOT CM_DISABLE_RC5)
    add_definitions("-D__ENABLE_DIGICERT_RC5__")
    add_definitions("-D__ENABLE_DIGICERT_WEAK_RC5__")
endif()

# If the production entropy flag is enabled then remove the disable entropy
# flag
if(CM_ENABLE_PROD_RNG)
    message("\n** REMOVING __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__ FROM FLAGS **\n")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__")
endif()

if (CM_BUILD_X64 OR CM_ENABLE_CITESTS)
    if(CM_ENABLE_IKE OR CM_ENABLE_MCPA OR CM_ENABLE_CITESTS)
        list(APPEND OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_BLAKE_2B__")
    endif()
endif()

# Special handling for OpenSSL algorithms and export
if(CM_ENABLE_EXPORT_ED AND CM_ENABLE_OPENSSL_SHIM)
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_MD2__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_ARC2_CIPHERS__")
endif()

if(CM_DISABLE_CHACHA20)
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_CHACHA20__")
endif()

if(CM_DISABLE_POLY1305)
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_POLY1305__")
endif()

if(CM_DISABLE_DES)
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DES_CIPHER__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DES_ALGORITHM__")
endif()

if(CM_DISABLE_PKCS1)
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_PKCS1__")
endif()

if(CM_DISABLE_DSA)
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_DSA__")
endif()

if(CM_DISABLE_NIST_KDF)
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__DISABLE_DIGICERT_NIST_KDF__")
endif()

if(CM_DISABLE_FIPS186_RNG)
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__DISABLE_DIGICERT_FIPS186_RNG__")
endif()

if(CM_DISABLE_MATH)
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__DISABLE_DIGICERT_COMMON_LUCAS_PRIME__")
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__DISABLE_DIGICERT_PRIME_TEST__")
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__DISABLE_DIGICERT_KARATSUBA__")
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__DISABLE_DIGICERT_VLONG_MATH__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_PRIME_SIEVE__")
endif()

if(CM_ENABLE_AES_GCM_4K)
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_GCM_256B__")
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_GCM_4K__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_GCM_64K__")
elseif(CM_ENABLE_AES_GCM_256B)
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_GCM_256B__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_GCM_4K__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_GCM_64K__")
endif()

if(CM_DISABLE_EC_ELGAMAL)
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_ECC_ELGAMAL__")
endif()

if(CM_DISABLE_EC_MQV)
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__DISABLE_DIGICERT_ECC_MQV__")
endif()

if(CM_DISABLE_ED)
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_ECC_EDDH_448__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_ECC_EDDSA_448__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_ECC_EDDH_25519__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_ECC_EDDSA_25519__")
endif()

if(CM_ENABLE_SMALL_FOOTPRINT)
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__")
endif()

if(CM_DISABLE_SHA3)
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_SHA3__")
endif()

if(CM_DISABLE_AES_CCM)
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__DISABLE_AES_CCM__")
endif()

if(CM_DISABLE_AES_EAX)
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__DISABLE_AES_EAX__")
endif()

if(CM_DISABLE_AES_MMO)
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__DISABLE_AES_MMO__")
endif()

if(CM_DISABLE_AES_XCBC_MAC_96)
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__DISABLE_AES_XCBC_MAC_96__")
endif()

if(CM_DISABLE_RC4)
    list(APPEND OPTIONS_MOCANA_FLAGS "-D__DISABLE_ARC4_CIPHERS__")
endif()

if(CM_DISABLE_SUITEB)
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_ECC__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_ECC_P192__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_ECC_EDDH_448__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_ECC_EDDH_25519__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_ECC_EDDSA_25519__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_ECC_EDDSA_448__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_ECC_ELGAMAL__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_SHA3__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_GCM__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_GCM_256B__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_GCM_4K__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_GCM_64K__")
endif()

if(CM_DISABLE_PQC)
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_PQC__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_PQC_KEM__")
    list(REMOVE_ITEM OPTIONS_MOCANA_FLAGS "-D__ENABLE_DIGICERT_PQC_SIG__")
endif()

if(CM_ENABLE_FIPS)
    add_definitions("-D__ENABLE_DIGICERT_FIPS_MODULE__")
endif()

if(CM_ENABLE_FIPS_700_U1_COMPAT)
    add_definitions("-D__ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__")
endif()

# Build the appropriate crypto libraries
add_subdirectory(nanocrypto)

if(CM_ENABLE_MBED)
    add_subdirectory(nanocap_mbed)
endif()
if(CM_ENABLE_OQS)
    add_subdirectory(nanocap_oqs)
endif()
if(CM_ENABLE_CRYPTOINTERFACE)
    add_subdirectory(cryptointerface)
endif()
if(CM_ENABLE_HW_ACCEL)
    add_subdirectory(hw_accel)
endif()

# Mapping flags only apply to NanoCrypto for the export build. They always apply
# to the CryptoInterface build.
file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/options/mapping/mocana_flags.txt CI_MAPPING_FLAGS)
if(CM_ENABLE_CRYPTOINTERFACE)
    target_compile_definitions(cryptointerface PRIVATE ${CI_MAPPING_FLAGS})
endif()
if(CM_ENABLE_EXPORT_ED)
    target_compile_definitions(cryptomw PRIVATE ${CI_MAPPING_FLAGS})
endif()
