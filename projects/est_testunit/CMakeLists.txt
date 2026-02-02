cmake_minimum_required(VERSION 3.5)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
include(MocPlatform)
include(locate_lib)

project(est_testunit C)

if(NOT DEFINED BUILD_FOR_OSI)
  set(BUILD_FOR_OSI OFF)
endif()

if(BUILD_FOR_OSI)
set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../lib")
else()
set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_static")
endif()
set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${MSS_DIR}/src")

set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
message("\nDEFS_FILE = ${DEFS_FILE}")
include(${DEFS_FILE})

# Load the EXTRA_DEFINITIONS flags (from mss_defs.cmake) into the build
message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")
add_definitions("${EXTRA_DEFINITIONS}")

# Apply coverage flags for Debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-fprofile-arcs -ftest-coverage)
    add_link_options(-fprofile-arcs -ftest-coverage)
endif()

########################################################################
#
# FLAGS
#
########################################################################

set(MOCANA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")
file(STRINGS ${MOCANA_FLAGS_FILE} mocana_flags)

# Now load all flags into MOCANA_FLAGS
foreach(flag ${mocana_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()


# Load the flags into the build
message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
add_definitions("${MOCANA_FLAGS}")

########################################################################
#
# CMocka Library Setup
#
########################################################################

# Using shared CMocka library from bin/ directory

########################################################################
#
# INCLUDES
#
########################################################################

# Add include directories
include_directories(${MSS_SRC_DIR})
if(BUILD_FOR_OSI)
include_directories(${MSS_SRC_DIR}/../cmocka-1.1.5/include)
else()
include_directories(${MSS_SRC_DIR}/../thirdparty/cmocka-1.1.5/include)
endif()

########################################################################
#
# LINK DIRECTORY
#
########################################################################

if(BUILD_FOR_OSI)
link_directories(${MSS_DIR}/lib)
else()
link_directories(${MSS_DIR}/bin_static)
link_directories(${MSS_DIR}/bin)
endif()

########################################################################
#
# TESTS
#
########################################################################

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${MSS_SRC_DIR}/est/testunit)

if(BUILD_FOR_OSI)
    set(PLATFORM_LIB      "${MSS_DIR}/lib/libplatform.so")
    set(ASN1_LIB          "${MSS_DIR}/lib/libasn1.so")
    set(COMMON_LIB        "${MSS_DIR}/lib/libcommon.so")
    set(INITIALIZE_LIB    "${MSS_DIR}/lib/libinitialize.so")
    set(NANOCAP_LIB       "${MSS_DIR}/lib/libnanocap.so")
    set(NANOCERT_LIB      "${MSS_DIR}/lib/libnanocert.so")
    set(NANOCRYPTO_LIB    "${MSS_DIR}/lib/libnanocrypto.so")
    set(CRYPTOINTERFACE_LIB "${MSS_DIR}/lib/libcryptointerface.so")
    set(CERT_ENROLL_LIB   "${MSS_DIR}/lib/libcert_enroll.so")
    set(NANOSSL_LIB       "${MSS_DIR}/lib/libnanossl.so")
    set(SMPTPM2_LIB       "${MSS_DIR}/lib/libsmptpm2.so")
    set(TPM2_LIB          "${MSS_DIR}/lib/libtpm2.so")
    set(NANOTAP2_LIB      "${MSS_DIR}/lib/libnanotap2.so")
    set(NANOTAP2_COMMON_LIB "${MSS_DIR}/lib/libnanotap2_common.so")

    set(COMMON_TEST_LIBS
        "-Wl,--start-group"
        ${PLATFORM_LIB}
        ${ASN1_LIB}
        ${COMMON_LIB}
        ${INITIALIZE_LIB}
        ${NANOCAP_LIB}
        ${NANOCERT_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${CERT_ENROLL_LIB}
        ${NANOSSL_LIB}
        ${SMPTPM2_LIB}
        ${TPM2_LIB}
        ${NANOTAP2_LIB}
        ${NANOTAP2_COMMON_LIB}
        cmocka
        pthread
        "-Wl,--end-group"
    )
else()
    set(PLATFORM_LIB      "${MSS_DIR}/bin/libplatform.so")
    set(ASN1_LIB          "${MSS_DIR}/bin/libasn1.so")
    set(COMMON_LIB        "${MSS_DIR}/bin/libcommon.so")
    set(INITIALIZE_LIB    "${MSS_DIR}/bin/libinitialize.so")
    set(NANOCAP_LIB       "${MSS_DIR}/bin/libnanocap.so")
    set(NANOCERT_LIB      "${MSS_DIR}/bin/libnanocert.so")
    set(NANOCRYPTO_LIB    "${MSS_DIR}/bin/libnanocrypto.so")
    set(CRYPTOINTERFACE_LIB "${MSS_DIR}/bin/libcryptointerface.so")
    set(CERT_ENROLL_LIB   "${MSS_DIR}/bin/libcert_enroll.so")
    set(NANOSSL_LIB       "${MSS_DIR}/bin/libnanossl.so")
    set(SMPTPM2_LIB       "${MSS_DIR}/bin/libsmptpm2.so")
    set(TPM2_LIB          "${MSS_DIR}/bin/libtpm2.so")
    set(NANOTAP2_LIB      "${MSS_DIR}/bin/libnanotap2.so")
    set(NANOTAP2_COMMON_LIB "${MSS_DIR}/bin/libnanotap2_common.so")

    set(COMMON_TEST_LIBS
        "-Wl,--start-group"
        ${NANOTAP2_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${SMPTPM2_LIB}
        ${TPM2_LIB}
        ${NANOSSL_LIB}
        ${CERT_ENROLL_LIB}
        ${NANOCERT_LIB}
        ${NANOCAP_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${INITIALIZE_LIB}
        ${COMMON_LIB}
        ${ASN1_LIB}
        ${PLATFORM_LIB}
        cmocka
        pthread
        "-Wl,--end-group"
    )
endif()

# Create EST client API sanity tests
add_executable(test_est_client_api
    ${MSS_DIR}/src/est/testunit/test_est_client_api.c
    ${MSS_DIR}/src/common/debug_console.c
)
target_link_libraries(test_est_client_api ${COMMON_TEST_LIBS})
target_link_options(test_est_client_api PRIVATE)

# Create EST utils unit tests
add_executable(test_est_utils
    ${MSS_DIR}/src/est/testunit/test_est_utils.c
)
target_link_libraries(test_est_utils ${COMMON_TEST_LIBS})
target_link_options(test_est_utils PRIVATE)

# Create EST cert utils unit tests
add_executable(test_est_cert_utils
    ${MSS_DIR}/src/est/testunit/test_est_cert_utils.c
)
target_link_libraries(test_est_cert_utils ${COMMON_TEST_LIBS})
target_link_options(test_est_cert_utils PRIVATE)

# Create EST context unit tests
add_executable(test_est_context
    ${MSS_DIR}/src/est/testunit/test_est_context.c
)
target_link_libraries(test_est_context ${COMMON_TEST_LIBS})
target_link_options(test_est_context PRIVATE)

# Create EST message unit tests
add_executable(test_est_message
    ${MSS_DIR}/src/est/testunit/test_est_message.c
)
target_link_libraries(test_est_message ${COMMON_TEST_LIBS})
target_link_options(test_est_message PRIVATE)

# Create EST client operations unit tests
add_executable(test_est_client_operations
    ${MSS_DIR}/src/est/testunit/test_est_client_operations.c
)
target_link_libraries(test_est_client_operations ${COMMON_TEST_LIBS})
target_link_options(test_est_client_operations PRIVATE)

# Set RPATH for non-OSI builds
if(NOT BUILD_FOR_OSI)
    set_target_properties(test_est_client_api PROPERTIES
        INSTALL_RPATH "${MSS_DIR}/bin"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
    set_target_properties(test_est_utils PROPERTIES
        INSTALL_RPATH "${MSS_DIR}/bin"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
    set_target_properties(test_est_cert_utils PROPERTIES
        INSTALL_RPATH "${MSS_DIR}/bin"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
    set_target_properties(test_est_context PROPERTIES
        INSTALL_RPATH "${MSS_DIR}/bin"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
    set_target_properties(test_est_message PROPERTIES
        INSTALL_RPATH "${MSS_DIR}/bin"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
    set_target_properties(test_est_client_operations PROPERTIES
        INSTALL_RPATH "${MSS_DIR}/bin"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
endif()

# Enable testing
enable_testing()

# Add the tests
add_test(NAME est_client_api_test COMMAND test_est_client_api)
add_test(NAME est_utils_test COMMAND test_est_utils)
add_test(NAME est_cert_utils_test COMMAND test_est_cert_utils)
add_test(NAME est_context_test COMMAND test_est_context)
add_test(NAME est_message_test COMMAND test_est_message)
add_test(NAME est_client_operations_test COMMAND test_est_client_operations)

