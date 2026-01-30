cmake_minimum_required(VERSION 3.5)

project(smp_nanoroot_unit_test C)

# Options
option(ENABLE_COVERAGE "Enable code coverage reporting" OFF)

# Paths
set(MSS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${MSS_ROOT}/src")
set(MSS_LIB_DIR "${MSS_ROOT}/lib")
set(MSS_BIN_DIR "${MSS_ROOT}/bin")

# Find cmocka
find_package(PkgConfig REQUIRED)
pkg_check_modules(CMOCKA REQUIRED cmocka>=1.1.0)

# Include directories
include_directories(
    ${MSS_SRC_DIR}
    ${CMOCKA_INCLUDE_DIRS}
)

# Link directories
link_directories(
    ${MSS_LIB_DIR}
    ${CMOCKA_LIBRARY_DIRS}
)

# Test source file
set(TEST_SOURCES
    ${MSS_SRC_DIR}/smp/smp_nanoroot/smp_nanoroot_unittest/smp_nanoroot_unit_test.c
)

# Create test executable
add_executable(smp_nanoroot_unit_test ${TEST_SOURCES})

# Set rpath so executable can find shared libraries
set_target_properties(smp_nanoroot_unit_test PROPERTIES
    INSTALL_RPATH "${MSS_LIB_DIR}:${MSS_BIN_DIR}"
    BUILD_WITH_INSTALL_RPATH TRUE
)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-error=sign-compare -Wno-error=pointer-sign")
if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
endif()

# Preprocessor definitions
target_compile_definitions(smp_nanoroot_unit_test PRIVATE
    __RTOS_LINUX__
    __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
    __ENABLE_DIGICERT_SMP__
    __ENABLE_DIGICERT_SMP_NANOROOT__
    __ENABLE_DIGICERT_TAP__
    __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    __ENABLE_DIGICERT_ECC__
    __ENABLE_DIGICERT_PQC__
    __ENABLE_DIGICERT_ECDSA__
    __ENABLE_DIGICERT_RSA__
    
    # SMP feature defines to enable API functions in smp_nanoroot_api.c
    __SMP_ENABLE_SMP_CC_DELETE_OBJECT__
    __SMP_ENABLE_SMP_CC_FREE_MODULE_LIST__
    __SMP_ENABLE_SMP_CC_GET_MODULE_INFO__
    __SMP_ENABLE_SMP_CC_GET_MODULE_LIST__
    __SMP_ENABLE_SMP_CC_GET_PRIVATE_KEY__
    __SMP_ENABLE_SMP_CC_GET_PUBLIC_KEY__
    __SMP_ENABLE_SMP_CC_GET_TOKEN_LIST__
    __SMP_ENABLE_SMP_CC_INIT_MODULE__
    __SMP_ENABLE_SMP_CC_INIT_OBJECT__
    __SMP_ENABLE_SMP_CC_INIT_TOKEN__
    __SMP_ENABLE_SMP_CC_SEAL_WITH_TRUSTED_DATA__
    __SMP_ENABLE_SMP_CC_SIGN_BUFFER__
    __SMP_ENABLE_SMP_CC_SIGN_DIGEST__
    __SMP_ENABLE_SMP_CC_UNINIT_MODULE__
    __SMP_ENABLE_SMP_CC_UNINIT_TOKEN__
    __SMP_ENABLE_SMP_CC_UNSEAL_WITH_TRUSTED_DATA__
)

# Link against libraries
target_link_libraries(smp_nanoroot_unit_test
    smpnanoroot
    cryptointerface
    nanotap2
    nanotap2_common
    nanocert
    nanocap
    nanocrypto
    initialize
    common
    platform
    asn1
    ${CMOCKA_LIBRARIES}
    pthread
    m
)

# Add test
enable_testing()
add_test(NAME smp_nanoroot_unit_test COMMAND smp_nanoroot_unit_test)

# Install target
install(TARGETS smp_nanoroot_unit_test
        RUNTIME DESTINATION ${MSS_BIN_DIR})

# Coverage target - text output only
if(ENABLE_COVERAGE)
    find_program(LCOV lcov)
    find_program(GCOVR gcovr)
    
    # Path to library build directory where .gcda files are located
    set(LIBRARY_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../build/projects/smp_nanoroot")
    
    if(GCOVR)
        # Prefer gcovr for cleaner text output
        add_custom_target(coverage
            COMMAND ${CMAKE_COMMAND} -E echo "Generating coverage report (text)..."
            COMMAND ${GCOVR} -r ${MSS_SRC_DIR}/smp/smp_nanoroot 
                --object-directory=${LIBRARY_BUILD_DIR}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating text-based code coverage report"
            VERBATIM
        )
        message(STATUS "Coverage target added (using gcovr for text output)")
        message(STATUS "  Library .gcda files expected in: ${LIBRARY_BUILD_DIR}")
        message(STATUS "  To generate coverage: cd build && cmake --build . --target coverage")
    elseif(LCOV)
        # Detect lcov version for compatibility
        execute_process(
            COMMAND ${LCOV} --version
            OUTPUT_VARIABLE LCOV_VERSION_OUTPUT
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        string(REGEX MATCH "([0-9]+)\\.([0-9]+)" LCOV_VERSION "${LCOV_VERSION_OUTPUT}")
        set(LCOV_MAJOR ${CMAKE_MATCH_1})

        # Set ignore-errors flag for lcov 2.0+
        set(LCOV_IGNORE_ERRORS "")
        if(LCOV_MAJOR GREATER_EQUAL 2)
            set(LCOV_IGNORE_ERRORS --ignore-errors unused,mismatch,empty,negative)
            message(STATUS "Detected lcov ${LCOV_MAJOR}.x - using --ignore-errors for compatibility")
        endif()

        add_custom_target(coverage
            COMMAND ${CMAKE_COMMAND} -E echo "Generating coverage report (text)..."
            COMMAND ${LCOV} ${LCOV_IGNORE_ERRORS}
                --capture
                --directory ${LIBRARY_BUILD_DIR}
                --output-file coverage.info
            COMMAND ${LCOV} ${LCOV_IGNORE_ERRORS}
                --remove coverage.info
                '/usr/*' '*/thirdparty/*' '*/cmocka*' '*/test/*' '*_test.c' '*_unittest.c' 
                --output-file coverage.info
            COMMAND ${LCOV} --list coverage.info
            COMMAND ${CMAKE_COMMAND} -E echo "Coverage report generated in coverage.info"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating text-based code coverage report"
        )
        message(STATUS "Coverage target added (using lcov for text output)")
        message(STATUS "  Library .gcda files expected in: ${LIBRARY_BUILD_DIR}")
        message(STATUS "  To generate coverage: cd build && cmake --build . --target coverage")
    else()
        message(WARNING "lcov or gcovr not found. Coverage report target will not be available.")
        message(WARNING "Install with: sudo apt-get install lcov OR pip3 install gcovr")
    endif()
else()
    message(STATUS "Coverage reporting: DISABLED")
    message(STATUS "  To enable: cmake -B build -DENABLE_COVERAGE=ON")
endif()

# Print build configuration
message(STATUS "")
message(STATUS "Build Configuration:")
message(STATUS "  Source directory: ${MSS_SRC_DIR}")
message(STATUS "  Library directory: ${MSS_LIB_DIR}")
message(STATUS "  Binary directory: ${MSS_BIN_DIR}")
message(STATUS "  CMocka version: ${CMOCKA_VERSION}")
message(STATUS "  Coverage reporting: ${ENABLE_COVERAGE}")
if(ENABLE_COVERAGE)
    message(STATUS "")
    message(STATUS "IMPORTANT:")
    message(STATUS "  1. Build libsmpnanoroot.so with coverage:")
    message(STATUS "     export CM_ENV_CODE_COVERAGE=1")
    message(STATUS "     cmake -S . -B build -DENABLE_NANOROOT=ON")
    message(STATUS "     cmake --build build")
    message(STATUS "")
    message(STATUS "  2. Run tests with coverage:")
    message(STATUS "     cd projects/smp_nanoroot_unittest")
    message(STATUS "     ./run_unit_tests.sh --coverage")
    message(STATUS "")
endif()
