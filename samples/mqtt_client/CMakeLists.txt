
cmake_minimum_required(VERSION 3.16)

project(MQTTClient LANGUAGES C CXX)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(CRYPTO_LIB_ARCH_DIR "aarch64")
else()
    set(CRYPTO_LIB_ARCH_DIR "linux-x86_64")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

if (DEFINED SECURE_PATH)
  message("\nSECURE_PATH = ${SECURE_PATH}")
  add_definitions("-D__ENABLE_DIGICERT_SECURE_PATH__")
  add_definitions("-D__ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__")
  add_definitions("-DMANDATORY_BASE_PATH=\"${SECURE_PATH}\"")
endif()

set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
set(LIB_DIR       "${CMAKE_CURRENT_SOURCE_DIR}/../../lib")
set(CRYPTO_LIBS   "${CMAKE_CURRENT_SOURCE_DIR}/../../crypto_lib/${CRYPTO_LIB_ARCH_DIR}")
set(CMAKE_BUILD_RPATH "${LIB_DIR}")
set(SAMPLE_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../samples/bin")
set(SAMPLE_FILE_PATH "${SAMPLE_BIN_DIR}/mqtt_client")
set(TEST_FILE_PATH "${SAMPLE_BIN_DIR}/mqtt_client_test")

set(INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/mqtt"
    )
include_directories(${INCLUDE_DIR})

set(SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mqtt_client_example.c
)

add_executable(mqtt_client ${SOURCE_FILES})

if(CM_ENABLE_MQTT_TEST)
    set(TEST_SOURCE_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/../../src/mqtt/test/mqtt_client_test.c
    )
    add_executable(mqtt_client_test ${TEST_SOURCE_FILES})
    set(MQTT_TARGETS mqtt_client mqtt_client_test)
else()
    set(MQTT_TARGETS mqtt_client)
endif()

set(ASN1_LIB          "${LIB_DIR}/libasn1.so")
set(COMMON_LIB        "${LIB_DIR}/libcommon.so")
set(INITIALIZE_LIB    "${LIB_DIR}/libinitialize.so")
set(PLATFORM_LIB      "${LIB_DIR}/libplatform.so")
set(NANOMQTT_LIB      "${LIB_DIR}/libnanomqtt.so")

add_library(nanocap SHARED IMPORTED)
  set_target_properties(nanocap PROPERTIES
  IMPORTED_LOCATION "${CRYPTO_LIBS}/libnanocap.so")

add_library(nanocert SHARED IMPORTED)
  set_target_properties(nanocert PROPERTIES
  IMPORTED_LOCATION "${CRYPTO_LIBS}/libnanocert.so")

add_library(nanocrypto SHARED IMPORTED)
  set_target_properties(nanocrypto PROPERTIES
  IMPORTED_LOCATION "${CRYPTO_LIBS}/libnanocrypto.so")

add_library(cryptointerface SHARED IMPORTED)
  set_target_properties(cryptointerface PROPERTIES
  IMPORTED_LOCATION "${CRYPTO_LIBS}/libcryptointerface.so")

add_library(nanossl SHARED IMPORTED)
  set_target_properties(nanossl PROPERTIES
  IMPORTED_LOCATION "${CRYPTO_LIBS}/libnanossl.so")

# Link libraries to all MQTT targets
foreach(target ${MQTT_TARGETS})
    target_link_libraries(${target} PRIVATE
        ${PLATFORM_LIB}
        ${ASN1_LIB}
        ${COMMON_LIB}
        ${INITIALIZE_LIB}
        ${NANOMQTT_LIB}
        nanocap
        nanocert
        nanocrypto
        cryptointerface
        nanossl
    )
endforeach()

add_custom_command(
  TARGET mqtt_client
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:mqtt_client> ${SAMPLE_FILE_PATH}
)

if(CM_ENABLE_MQTT_TEST)
  add_custom_command(
    TARGET mqtt_client_test
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:mqtt_client_test> ${TEST_FILE_PATH}
  )
endif()
