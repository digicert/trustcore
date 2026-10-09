cmake_minimum_required(VERSION 3.16)

project(WebsocketSample LANGUAGES C)

set(SRC_DIR  "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
set(LIB_DIR  "${CMAKE_CURRENT_SOURCE_DIR}/../../lib")
set(CMAKE_BUILD_RPATH "${LIB_DIR}")
set(SAMPLE_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../samples/bin")
set(SAMPLE_FILE_PATH "${SAMPLE_BIN_DIR}/websocket_sample")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../projects/shared_cmake")
set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
include(Builder)
include(mss_defs)
builder_finalize_flags(EXTRA_DEFINITIONS)
add_definitions(${EXTRA_DEFINITIONS})

add_definitions(
    -D__ENABLE_DIGICERT_WEBSOCKET_CLIENT__
    -D__ENABLE_DIGICERT_SSL_CLIENT__
    -D__ENABLE_DIGICERT_DEBUG_CONSOLE__
    -D__ENABLE_MQTT_CLIENT__
    -D__ENABLE_MQTT_HASH_TABLE__
)


set(INCLUDE_DIRS
    "${SRC_DIR}/common"
    "${SRC_DIR}/websocket"
    "${SRC_DIR}/mqtt"
    "${SRC_DIR}/ssl"
    "${SRC_DIR}/crypto"
)
include_directories(${INCLUDE_DIRS})

add_executable(websocket_sample
    ${CMAKE_CURRENT_SOURCE_DIR}/websocket_sample.c
)

if("STATIC" STREQUAL "${LIB_TYPE}")
    set(NANOWS_LIB           "${LIB_DIR}/libnanows.a")
    set(NANOMQTT_LIB         "${LIB_DIR}/libnanomqtt.a")
    set(ASN1_LIB             "${LIB_DIR}/libasn1.a")
    set(COMMON_LIB           "${LIB_DIR}/libcommon.a")
    set(INITIALIZE_LIB       "${LIB_DIR}/libinitialize.a")
    set(PLATFORM_LIB         "${LIB_DIR}/libplatform.a")
    set(NANOCRYPTO_LIB       "${LIB_DIR}/libnanocrypto.a")
    set(NANOCAP_LIB          "${LIB_DIR}/libnanocap.a")
    set(CRYPTO_INTERFACE_LIB "${LIB_DIR}/libcryptointerface.a")
    set(NANOCERT_LIB         "${LIB_DIR}/libnanocert.a")
    set(NANOSSL_LIB          "${LIB_DIR}/libnanossl.a")
    set(CERT_ENROLL_LIB      "${LIB_DIR}/libcert_enroll.a")

    if(CM_ENABLE_TAP)
        set(NANOTAP2_COMMON_LIB "${LIB_DIR}/libnanotap2_common.a")
        set(NANOTAP2_CONFIGPARSER_LIB "${LIB_DIR}/libnanotap2_configparser.a")
        set(NANOTAP2_LIB "${LIB_DIR}/libnanotap2.a")
        if(ENABLE_PKCS11_SOFTHSM OR ENABLE_PKCS11_TEE)
            set(SMP_LIB "${LIB_DIR}/libsmppkcs11.a")
            set(TPM2_LIB "${LIB_DIR}/libtpm2.a")
        elseif(ENABLE_TPM2)
            set(SMP_LIB "${LIB_DIR}/libsmptpm2.a")
            set(TPM2_LIB "${LIB_DIR}/libtpm2.a")
        endif()

        target_link_libraries(websocket_sample PRIVATE
            ${NANOWS_LIB}
            ${NANOMQTT_LIB}
            ${NANOSSL_LIB}
            ${CERT_ENROLL_LIB}
            ${NANOCERT_LIB}
            ${NANOTAP2_LIB}
            ${NANOTAP2_CONFIGPARSER_LIB}
            ${NANOTAP2_COMMON_LIB}
            ${SMP_LIB}
            ${TPM2_LIB}
            -Wl,--start-group
            ${INITIALIZE_LIB}
            ${NANOCRYPTO_LIB}
            ${CRYPTO_INTERFACE_LIB}
            ${NANOCAP_LIB}
            ${ASN1_LIB}
            ${COMMON_LIB}
            ${PLATFORM_LIB}
            -Wl,--end-group
            pthread
            dl
        )
    else()
        target_link_libraries(websocket_sample PRIVATE
            ${NANOWS_LIB}
            ${NANOMQTT_LIB}
            ${NANOSSL_LIB}
            ${CERT_ENROLL_LIB}
            ${NANOCERT_LIB}
            -Wl,--start-group
            ${INITIALIZE_LIB}
            ${NANOCRYPTO_LIB}
            ${CRYPTO_INTERFACE_LIB}
            ${NANOCAP_LIB}
            ${ASN1_LIB}
            ${COMMON_LIB}
            ${PLATFORM_LIB}
            -Wl,--end-group
            pthread
            dl
        )
    endif()
else()
    set(NANOWS_LIB           "${LIB_DIR}/libnanows.so")
    set(NANOMQTT_LIB         "${LIB_DIR}/libnanomqtt.so")
    set(ASN1_LIB             "${LIB_DIR}/libasn1.so")
    set(COMMON_LIB           "${LIB_DIR}/libcommon.so")
    set(INITIALIZE_LIB       "${LIB_DIR}/libinitialize.so")
    set(PLATFORM_LIB         "${LIB_DIR}/libplatform.so")
    set(NANOCRYPTO_LIB       "${LIB_DIR}/libnanocrypto.so")
    set(NANOCAP_LIB          "${LIB_DIR}/libnanocap.so")
    set(CRYPTO_INTERFACE_LIB "${LIB_DIR}/libcryptointerface.so")
    set(NANOCERT_LIB         "${LIB_DIR}/libnanocert.so")
    set(NANOSSL_LIB          "${LIB_DIR}/libnanossl.so")
    set(CERT_ENROLL_LIB      "${LIB_DIR}/libcert_enroll.so")

    if(CM_ENABLE_TAP)
        set(NANOTAP2_COMMON_LIB "${LIB_DIR}/libnanotap2_common.so")
        set(NANOTAP2_CONFIGPARSER_LIB "${LIB_DIR}/libnanotap2_configparser.so")
        set(NANOTAP2_LIB "${LIB_DIR}/libnanotap2.so")
        if(ENABLE_PKCS11_SOFTHSM OR ENABLE_PKCS11_TEE)
            set(SMP_LIB "${LIB_DIR}/libsmppkcs11.so")
            set(TPM2_LIB "${LIB_DIR}/libtpm2.so")
        elseif(ENABLE_TPM2)
            set(SMP_LIB "${LIB_DIR}/libsmptpm2.so")
            set(TPM2_LIB "${LIB_DIR}/libtpm2.so")
        endif()

        target_link_libraries(websocket_sample PRIVATE
            ${PLATFORM_LIB}
            ${ASN1_LIB}
            ${COMMON_LIB}
            ${INITIALIZE_LIB}
            ${NANOWS_LIB}
            ${NANOMQTT_LIB}
            ${NANOCRYPTO_LIB}
            ${NANOCAP_LIB}
            ${CRYPTO_INTERFACE_LIB}
            ${NANOCERT_LIB}
            ${NANOSSL_LIB}
            ${CERT_ENROLL_LIB}
            ${NANOTAP2_COMMON_LIB}
            ${NANOTAP2_CONFIGPARSER_LIB}
            ${NANOTAP2_LIB}
            ${SMP_LIB}
            ${TPM2_LIB}
        )
    else()
        target_link_libraries(websocket_sample PRIVATE
            ${PLATFORM_LIB}
            ${ASN1_LIB}
            ${COMMON_LIB}
            ${INITIALIZE_LIB}
            ${NANOWS_LIB}
            ${NANOMQTT_LIB}
            ${NANOCRYPTO_LIB}
            ${NANOCAP_LIB}
            ${CRYPTO_INTERFACE_LIB}
            ${NANOCERT_LIB}
            ${NANOSSL_LIB}
            ${CERT_ENROLL_LIB}
        )
    endif()
endif()

add_custom_command(
    TARGET websocket_sample
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SAMPLE_BIN_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:websocket_sample> ${SAMPLE_FILE_PATH}
)
