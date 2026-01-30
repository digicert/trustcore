cmake_minimum_required(VERSION 3.5)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
include(MocPlatform)
include(locate_lib)

project(mqtt_testunit C)

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
endif()

########################################################################
#
# CONDITIONAL FLAGS 
#
########################################################################

# streaming
if (DEFINED CM_ENABLE_STREAMING AND CM_ENABLE_STREAMING)
    add_definitions("-D__ENABLE_MQTT_STREAMING__")
endif()

# async client
if ((DEFINED CM_ENABLE_ASYNC AND CM_ENABLE_ASYNC) OR (NOT BUILD_FOR_OSI))
    add_definitions("-D__ENABLE_MQTT_ASYNC_CLIENT__")
endif()

# persist
if ((DEFINED CM_ENABLE_PERSIST AND CM_ENABLE_PERSIST) OR (NOT BUILD_FOR_OSI))
    add_definitions("-D__MQTT_ENABLE_FILE_PERSIST__")
endif()

########################################################################
#
# TESTS
#
########################################################################

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${MSS_SRC_DIR}/mqtt/testunit)

if(BUILD_FOR_OSI)

    set(ASN1_LIB          "${MSS_DIR}/lib/libasn1.so")
    set(COMMON_LIB        "${MSS_DIR}/lib/libcommon.so")
    set(INITIALIZE_LIB    "${MSS_DIR}/lib/libinitialize.so")
    set(PLATFORM_LIB      "${MSS_DIR}/lib/libplatform.so")
    set(NANOMQTT_LIB      "${MSS_DIR}/lib/libnanomqtt.so")
    set(NANOCAP_LIB       "${MSS_DIR}/lib/libnanocap.so")
    set(NANOCERT_LIB      "${MSS_DIR}/lib/libnanocert.so")
    set(NANOCRYPTO_LIB    "${MSS_DIR}/lib/libnanocrypto.so")
    set(CRYPTOINTERFACE_LIB "${MSS_DIR}/lib/libcryptointerface.so")
    set(NANOSSL_LIB       "${MSS_DIR}/lib/libnanossl.so")

    set(COMMON_TEST_LIBS 
        "-Wl,--start-group" 
        ${PLATFORM_LIB}
        ${ASN1_LIB}
        ${COMMON_LIB}
        ${INITIALIZE_LIB}
        ${NANOMQTT_LIB}
        ${NANOCAP_LIB}
        ${NANOCERT_LIB}
        ${NANOCRYPTO_LIB}
        ${CRYPTOINTERFACE_LIB}
        ${NANOSSL_LIB}
        cmocka 
        pthread 
        "-Wl,--end-group"
    )

    if (DEFINED CM_ENABLE_STREAMING AND CM_ENABLE_STREAMING)
        add_executable(test_mqtt_msg_streaming  ${MSS_SRC_DIR}/mqtt/testunit/test_mqtt_msg_streaming.c)
        target_link_libraries(test_mqtt_msg_streaming ${COMMON_TEST_LIBS})
        target_link_options(test_mqtt_msg_streaming PRIVATE)
    else()
        add_executable(test_mqtt_client  ${MSS_SRC_DIR}/mqtt/testunit/test_mqtt_client.c)
        add_executable(test_mqtt_utils  ${MSS_SRC_DIR}/mqtt/testunit/test_mqtt_utils.c)
        add_executable(test_mqtt_core  ${MSS_SRC_DIR}/mqtt/testunit/test_mqtt_core.c)
        add_executable(test_mqtt_msg  ${MSS_SRC_DIR}/mqtt/testunit/test_mqtt_msg.c)
        target_link_libraries(test_mqtt_client ${COMMON_TEST_LIBS})
        target_link_libraries(test_mqtt_utils ${COMMON_TEST_LIBS})
        target_link_libraries(test_mqtt_core ${COMMON_TEST_LIBS})
        target_link_libraries(test_mqtt_msg ${COMMON_TEST_LIBS})
        target_link_options(test_mqtt_client PRIVATE)
        target_link_options(test_mqtt_utils PRIVATE)
        target_link_options(test_mqtt_core PRIVATE)
        target_link_options(test_mqtt_msg PRIVATE)
    endif()
else()
    file(GLOB STATIC_LIBS
        ${MSS_DIR}/bin_static/*.a)
    message("STATIC_LIBS=${STATIC_LIBS}")

    if (DEFINED CM_ENABLE_STREAMING AND CM_ENABLE_STREAMING)
        add_executable(test_mqtt_msg_streaming  ${MSS_SRC_DIR}/mqtt/testunit/test_mqtt_msg_streaming.c)
        target_link_libraries(test_mqtt_msg_streaming "-Wl,--start-group" ${STATIC_LIBS} cmocka-static mock pthread "-Wl,--end-group")
        target_link_options(test_mqtt_msg_streaming PRIVATE)

    else()
        add_executable(test_mqtt_client  ${MSS_SRC_DIR}/mqtt/testunit/test_mqtt_client.c)
        add_executable(test_mqtt_utils  ${MSS_SRC_DIR}/mqtt/testunit/test_mqtt_utils.c)
        add_executable(test_mqtt_core  ${MSS_SRC_DIR}/mqtt/testunit/test_mqtt_core.c)
        add_executable(test_mqtt_msg  ${MSS_SRC_DIR}/mqtt/testunit/test_mqtt_msg.c)
        target_link_libraries(test_mqtt_client "-Wl,--start-group" ${STATIC_LIBS} cmocka-static mock pthread "-Wl,--end-group")
        target_link_libraries(test_mqtt_utils "-Wl,--start-group" ${STATIC_LIBS} cmocka-static mock pthread "-Wl,--end-group")
        target_link_libraries(test_mqtt_core "-Wl,--start-group" ${STATIC_LIBS} cmocka-static mock pthread "-Wl,--end-group")
        target_link_libraries(test_mqtt_msg "-Wl,--start-group" ${STATIC_LIBS} cmocka-static mock pthread "-Wl,--end-group")
        target_link_options(test_mqtt_client PRIVATE)
        target_link_options(test_mqtt_utils PRIVATE)
        target_link_options(test_mqtt_core PRIVATE)
        target_link_options(test_mqtt_msg PRIVATE)
    endif()
endif()