cmake_minimum_required(VERSION 3.5)

project(nanossl_test C)

option(CM_TEST_FRAMEWORK "Test option." ON)

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_BIN_DIR "${MSS_DIR}/bin")

add_definitions("-g -O0")

set(CM_ENABLE_SSLSERV_EXAMPLE   OFF)
set(CM_ENABLE_RSA_1024_SUPPORT  ON  CACHE BOOL "")
set(CM_ENABLE_TLS12_FALLBACK    ON  CACHE BOOL "")
set(CM_ENABLE_SSL_ANON          ON  CACHE BOOL "")
set(CM_ENABLE_SSL_SESSION_CACHE ON  CACHE BOOL "")

if(CM_SSLSERV)
    message("build sslserv")
    include("sslserv/CMakeLists.txt")
    set(CM_ENABLE_SSLSERV_EXAMPLE ON)
endif()
if(CM_SSLSERV_EXPIRED)
    message("build sslserv_expired")
    include("sslserv_expired/CMakeLists.txt")
    set(CM_ENABLE_SSLSERV_EXAMPLE ON)
endif()
if(CM_SSLSERV_MUTAUTH)
    message("build sslserv_mutauth")
    include("sslserv_mutauth/CMakeLists.txt")
    set(CM_ENABLE_SSLSERV_EXAMPLE ON)
endif()
if(CM_SSLSERV_VERSIONSET)
    message("build sslserv_versionset")
    include("sslserv_versionset/CMakeLists.txt")
    set(CM_ENABLE_SSLSERV_EXAMPLE ON)
endif()
if(CM_SSLSERV_SRP)
    message("build sslserv_srp")
    include("sslserv_srp/CMakeLists.txt")
    set(CM_ENABLE_SSLSERV_EXAMPLE ON)
endif()
if(CM_SSLSERV_TLS13)
    message("build sslserv_tls13")
    include("sslserv_tls13/CMakeLists.txt")
    set(CM_ENABLE_SSLSERV_EXAMPLE ON)
endif()
if(CM_SSLSERV_TLS13_OCSP)
    message("build sslserv_tls13_ocsp")
    include("sslserv_tls13_ocsp/CMakeLists.txt")
    set(CM_ENABLE_SSLSERV_EXAMPLE ON)
endif()
if(CM_SSLSERV_OCSP_VALID)
    message("build sslserv_ocsp_valid")
    include("sslserv_ocsp_valid/CMakeLists.txt")
    set(CM_ENABLE_SSLSERV_EXAMPLE ON)
endif()
if(CM_SSLSERV_OCSP_CERTCHAIN)
    message("build sslserv_ocsp_certchain")
    include("sslserv_ocsp_certchain/CMakeLists.txt")
    set(CM_ENABLE_SSLSERV_EXAMPLE ON)
endif()
if(CM_SSLSERV_OCSP_REVOKED)
    message("build sslserv_ocsp_revoked")
    include("sslserv_ocsp_revoked/CMakeLists.txt")
    set(CM_ENABLE_SSLSERV_EXAMPLE ON)
endif()
if(CM_SSLSERV_OCSP_MISSING_ISSUER)
    message("build sslserv_ocsp_missing_issuer")
    include("sslserv_ocsp_missing_issuer/CMakeLists.txt")
    set(CM_ENABLE_SSLSERV_EXAMPLE ON)
endif()

if(CM_SSLCLIENT)
    message("build client")
    include("sslclient/CMakeLists.txt")
endif()

find_package(Ruby)

if(NOT EXISTS ${RUBY_EXECUTABLE})
    message(FATAL_ERROR "RUBY_EXECUTABLE does not exist. Exiting...")
endif()

################################################################################
# Build client test binaries

if(CM_SSLCLIENT)            
file(GLOB SSL_CLIENT_SRC ${MSS_DIR}/src/ssl/test/*.c)
message("SSL_CLIENT_FLAGS=" ${SSL_CLIENT_FLAGS})

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/build/main.c
                  COMMAND ${RUBY_EXECUTABLE} ${MSS_DIR}/unit_tests/unittest.rb
                  . localhost | tee ${CMAKE_CURRENT_SOURCE_DIR}/build/main.c
                  WORKING_DIRECTORY ${MSS_DIR}/src/ssl/test
                  DEPENDS ${SSL_CLIENT_SRC}
                  VERBATIM)

    add_executable(ssl_client ${SSL_CLIENT_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/build/main.c)
    target_compile_definitions(ssl_client PRIVATE ${SSL_CLIENT_FLAGS})
    link_directories(${MSS_BIN_DIR})
    target_link_libraries(ssl_client nanossl nanocert cryptointerface nanocap nanocrypto initialize asn1 platform common unittest nanotap2_common nanotap2_configparser nanotap2 smptpm2 tpm2)
    set_target_properties(ssl_client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
endif()

################################################################################
# Copy dependency files over. Any files that the test depends on (or files which
# generate files that the test depends on) are copied over to the appropriate
# directory. These files are used during test setup.

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/testaux/makefile_openssl_server
                   COMMAND ${CMAKE_COMMAND} -E copy ${MSS_DIR}/src/ssl/testaux/makefile_openssl_server
                   ${CMAKE_CURRENT_SOURCE_DIR}/testaux/makefile_openssl_server
                   DEPENDS ${MSS_DIR}/src/ssl/testaux/makefile_openssl_server)
add_custom_target(makefile_openssl_server DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/testaux/makefile_openssl_server)

if(CM_SSLCLIENT)            
add_dependencies(ssl_client makefile_openssl_server)
endif()

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/testaux/config.ssl
                   COMMAND ${CMAKE_COMMAND} -E copy ${MSS_DIR}/src/ssl/testaux/config.ssl
                   ${CMAKE_CURRENT_SOURCE_DIR}/testaux/config.ssl
                   DEPENDS ${MSS_DIR}/src/ssl/testaux/config.ssl)
add_custom_target(config.ssl DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/testaux/config.ssl)
add_dependencies(makefile_openssl_server config.ssl)

################################################################################
# Build main server test binaries

set(UNIT_TEST_FLAGS "-D__RTOS_LINUX__")
file(GLOB UNITTEST_SRC ${MSS_DIR}/unit_tests/*.c)
add_library(unittest STATIC ${UNITTEST_SRC})
target_compile_definitions(unittest PRIVATE ${UNIT_TEST_FLAGS})
set_target_properties(unittest PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

if(CM_ENABLE_SSLSERV_EXAMPLE)
    message("SSL_SERV_FLAGS= ${SSL_SERV_FLAGS}")
    add_executable(${SSL_EXECUTABLE} ${SSL_SERV_SRC})
    target_compile_definitions(${SSL_EXECUTABLE} PRIVATE ${SSL_SERV_FLAGS})
    link_directories(${MSS_BIN_DIR})
    target_link_libraries(${SSL_EXECUTABLE} nanossl nanocert cryptointerface nanocap nanocrypto initialize asn1 platform common nanotap2_common nanotap2_configparser nanotap2 smptpm2 tpm2)
    set_target_properties(${SSL_EXECUTABLE} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/testaux)
endif()

################################################################################
