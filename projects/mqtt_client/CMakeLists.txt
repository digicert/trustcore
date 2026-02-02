################################################################################
# CMake file for building MQTT client artifacts
################################################################################

# Set minimum required version of CMake
if(BUILD_FOR_OSI)
    cmake_minimum_required(VERSION 3.16)
else()
    cmake_minimum_required(VERSION 3.5)
endif()

# CMake build options
option(CM_ENABLE_DEBUG      "Enable debug logging."     OFF)
option(CM_BUILD_X32         "Build for 32-bit."         OFF)
option(CM_BUILD_X64         "Build for 64-bit."         OFF)
option(CM_ENABLE_PROXY      "Build with proxy support." OFF)
option(CM_ENABLE_SSL        "Build with SSL."           OFF)
option(CM_ENABLE_PQC        "Build with PQC for SSL key exchange." OFF)
option(CM_ENABLE_ASYNC      "Build with async support." OFF)
option(CM_ENABLE_SCRAM      "Build with SCRAM."         OFF)
option(CM_ENABLE_PERSIST    "Build with persist support." OFF)
option(CM_ENABLE_MQTT_TEST  "Build with test support." OFF)
option(CM_ENABLE_STREAMING  "Build with streaming support." OFF)
option(CM_ENABLE_UNITTEST   "Build with unittest. OFF")
option(CM_ENABLE_COVERAGE   "Build with code coverage. OFF")
# CMake build targets
option(CM_BUILD_NANOMQTT    "Build NanoMQTT library."   OFF)
option(CM_BUILD_LIBRARY     "Build sample as library."  OFF)
option(CM_BUILD_MQTT_CLIENT_SAMPLE "Build MQTT client sample." OFF)
option(CM_BUILD_MQTT_CLIENT_TEST "Build MQTT client test." OFF)
# Library build type option
set(LIB_TYPE "SHARED" CACHE STRING "Type of library to build. Can be SHARED or STATIC")

# Include Builder.cmake file for helper methods and build configuration setup
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
include(MocPlatform)
include(build_rc_file)
project(nanomqtt C)
include(locate_lib)
include(mss_defs)
include(Builder)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(CRYPTO_LIB_ARCH_DIR "aarch64")
else()
    set(CRYPTO_LIB_ARCH_DIR "linux-x86_64")
endif()

# Print variables/configuration
builder_print_configuration()

# Add build flags
builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")
if(CM_ENABLE_DEBUG)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt")
endif()
if(CM_ENABLE_PROXY)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_proxy_flags.txt")
endif()
if(CM_ENABLE_SSL)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_ssl_flags.txt")
endif()
if(CM_ENABLE_PQC)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_pqc_flags.txt")
endif()
if(CM_ENABLE_ASYNC)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_async_flags.txt")
endif()
if(CM_ENABLE_SCRAM)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_scram_flags.txt")
endif()
if(CM_BUILD_LIBRARY)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_library_flags.txt")
endif()
if(CM_ENABLE_PERSIST)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_persist_flags.txt")
endif()
if(CM_ENABLE_MQTT_TEST)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_test_flags.txt")
endif()
if(CM_ENABLE_STREAMING)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_streaming_flags.txt")
endif()
builder_finalize_flags(MOCANA_FLAGS)
add_definitions("${MOCANA_FLAGS}")

# Add extra definitions
builder_finalize_flags(EXTRA_DEFINITIONS)
add_definitions("${EXTRA_DEFINITIONS}")

# Add include directories
builder_add_includes(MOCANA_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt")
builder_finalize_incudes(MOCANA_INCLUDES)
include_directories("${MOCANA_INCLUDES}")

# Build nanomqtt library
if(CM_BUILD_NANOMQTT)
    builder_add_sources(NANOMQTT_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/nanomqtt/mss_sources.txt")
    builder_finialize_sources(NANOMQTT_SOURCES)
    add_library(${PROJECT_NAME} ${LIB_TYPE} "${NANOMQTT_SOURCES}")

    if("SHARED" STREQUAL "${LIB_TYPE}")
        if(CM_ENABLE_SSL)
            builder_add_library_link(NANOMQTT_LINK_LIBS nanossl cryptointerface)
        endif()
        builder_add_library_link(NANOMQTT_LINK_LIBS common platform)

        builder_finalize_library_link(NANOMQTT_LINK_LIBS)
        target_link_libraries(${PROJECT_NAME} ${NANOMQTT_LINK_LIBS})
    endif()

    builder_finalize_target(${PROJECT_NAME})
endif()

# Build MQTT client sample
if(CM_BUILD_MQTT_CLIENT_SAMPLE)
    if(CM_BUILD_LIBRARY AND CM_ENABLE_COVERAGE)
        builder_add_sources(CLIENT_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/client/mss_sources.txt")
        builder_add_sources(CLIENT_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/nanomqtt/mss_sources.txt")
    else()
        builder_add_sources(CLIENT_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/client/mss_sources.txt")
    endif()
    builder_finialize_sources(CLIENT_SOURCES)
    if(CM_BUILD_LIBRARY)
        add_library(mqtt_client_sample ${LIB_TYPE} "${CLIENT_SOURCES}")
        builder_finalize_target(mqtt_client_sample)
    else()
        add_executable(mqtt_client_sample "${CLIENT_SOURCES}")

        builder_add_library_link(CLIENT_LINK_LIBS nanomqtt)
        if(CM_ENABLE_SSL)
            builder_add_library_link(CLIENT_LINK_LIBS nanossl)
        endif()
        builder_add_library_link(CLIENT_LINK_LIBS nanocert cryptointerface nanocap nanocrypto initialize platform asn1 common
                                                cryptointerface nanocrypto
                                                cryptointerface nanocrypto)
        builder_finalize_library_link(CLIENT_LINK_LIBS)
        target_link_libraries(mqtt_client_sample ${CLIENT_LINK_LIBS} pthread)

        builder_finalize_target(mqtt_client_sample)
    endif()
endif()

if(CM_BUILD_MQTT_CLIENT_TEST)
    builder_add_sources(TEST_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/test/mss_sources.txt")
    builder_finialize_sources(TEST_SOURCES)
    add_executable(mqtt_client_test "${TEST_SOURCES}")

    builder_add_library_link(TEST_LINK_LIBS nanomqtt)
    if(CM_ENABLE_SSL)
        builder_add_library_link(TEST_LINK_LIBS nanossl)
    endif()
    builder_add_library_link(TEST_LINK_LIBS nanocert cryptointerface nanocap nanocrypto initialize platform asn1 common
                                                cryptointerface nanocrypto
                                                cryptointerface nanocrypto)
    builder_finalize_library_link(TEST_LINK_LIBS)
    target_link_libraries(mqtt_client_test ${TEST_LINK_LIBS} pthread)

    builder_finalize_target(mqtt_client_test)
endif()
