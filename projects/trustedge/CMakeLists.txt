################################################################################
# CMake file for building TrustEdge
################################################################################

# Set minimum required version of CMake
if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.31")
    cmake_policy(SET CMP0177 NEW)
endif()

option(CM_ENABLE_DEBUG              "Enable debug logs."                    OFF)
option(CM_ENABLE_DEBUG_INTERNALS    "Enable internal debug logs."           OFF)
option(CM_BUILD_LIBRARY             "Build as library."                     OFF)
option(CM_BUILD_UNITTEST            "Build unittest."                       OFF)
option(CM_ENABLE_EXPORT_ED          "Enable export edition."                OFF)
option(CM_ENABLE_CVC                "Enable CV Certificates."               OFF)
option(CM_ENABLE_CERT_PRINT         "Enable Cert/CSR printing."             OFF)
option(CM_ENABLE_PQC                "Enable PQC Support."                   OFF)
option(CM_ENABLE_OQS                "Enable PQC/OQS Support."               OFF)
option(CM_ENABLE_CUSTOM_HEAP        "Enable custom heap support."           OFF)
option(CM_ENABLE_K_MALLOC           "Enable k_malloc mapping support."      OFF)
option(CM_ENABLE_PKCS11             "Enable pkcs11."                        OFF)
option(CM_ENABLE_SOFTHSM            "Enable softhms2."                      OFF)
option(CM_ENABLE_CLOUDHSM           "Enable cloudhsm."                      OFF)
option(CM_ENABLE_DSSM               "Enable dssm."                          OFF)
option(CM_ENABLE_PKCS11_TEE         "Enable pkcs11 tee."                    OFF)
option(CM_ENABLE_TEE                "Enable tee."                           OFF)
option(CM_ENABLE_TPM2               "Enable tpm2."                          OFF)
option(CM_ENABLE_NANOROOT           "Enable NANOROOT."                      OFF)
option(CM_ENABLE_TAP_REMOTE         "Enable TAP-Remote."                    OFF)
option(CM_ENABLE_DIGICERT_SCEP      "Enable Digicert SCEP."                 OFF)
option(CM_ENABLE_MONOLITHIC_BUILD   "Build monolithic binary."              OFF)
option(CM_ENABLE_VALGRIND_MEMCHECK  "Use valgrind memcheck tool"            OFF)
option(CM_ENABLE_VALGRIND_MASSIF    "Use valgrind massif tool"              OFF)
option(CM_ENABLE_COVERAGE           "Enable code coverage"                  OFF)
option(CM_ENABLE_TOKEN_FALLBACK     "Enable authorization token fallback"   OFF)
option(CM_ENABLE_PERSIST_ARTIFACT   "Enable persisting artifact payload"    OFF)
option(CM_ENABLE_ZEPHYR_OS          "Build for Zephyr OS target."           OFF)
option(CM_ENABLE_ZEPHYR_PACKAGING   "package /etc/digicert for Zephyr."     OFF)
option(CM_ENABLE_PROXY              "Enable proxy"                          OFF)
option(CM_ENABLE_MINIMAL            "Build minimal TrustEdge build"         OFF)
option(CM_DISABLE_EST               "Disable EST support"                   OFF)
option(CM_DISABLE_REST_API          "Disable REST API support"              OFF)
option(CM_ENABLE_MEM_PROFILE        "Enable memory profiling support"       OFF)
set(CM_GENERATOR_BUILD "DEB" CACHE STRING "Build for generator")

# Include Builder.cmake file for helper methods and build configuration setup
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
include(MocPlatform)
include(build_rc_file)

if(CM_ENABLE_ZEPHYR_OS)
  find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
endif()
# project command must be after MocPlatform and before mss_defs

project(trustedge C)
include(locate_lib)
include(mss_defs)
include(Builder)

# Print variables/configuration
builder_print_configuration()

# Add extra definitions
builder_finalize_flags(EXTRA_DEFINITIONS)
foreach(EXTRA_DEF ${EXTRA_DEFINITIONS})
    add_definitions("${EXTRA_DEF}")
endforeach()

if (NOT CM_ENABLE_ZEPHYR_PACKAGING)
if (NOT CM_ENABLE_ZEPHYR_OS)
if (MSVC)
    # MSVC-specific warning flags
    add_compile_options(/W4)
elseif ("${CM_TARGET_PLATFORM}" MATCHES "esp32")
    add_definitions(-Wextra -Wall -Wno-pointer-sign -Wno-missing-field-initializers -Wno-switch)
else()
    add_definitions(-Wextra -Wall -Werror -Wno-pointer-sign -Wno-missing-field-initializers -Wno-switch)
endif()
else()
    add_definitions(-Wextra -Wall -Wno-pointer-sign -Wno-missing-field-initializers -Wno-switch -Wno-array-parameter -Wno-implicit-fallthrough -Wno-format-security -Wno-unused-parameter -Wno-empty-body)
endif()
endif()

if (CM_ENABLE_TOKEN_FALLBACK)
  add_definitions("-D__ENABLE_DIGICERT_TOKEN_MISSING_FALLBACK__")
endif()
if (CM_ENABLE_PERSIST_ARTIFACT)
  add_definitions("-D__DISABLE_DIGICERT_ARTIFACT_PAYLOAD_CLEANUP__")
endif()
if (CM_ENABLE_PROXY)
  add_definitions("-D__ENABLE_DIGICERT_HTTP_PROXY__")
  add_definitions("-D__ENABLE_DIGICERT_SSL_PROXY_CONNECT__")
endif()
set(PACKAGE_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/packages")

if (CM_DISABLE_REST_API)
  add_definitions("-D__DISABLE_TRUSTEDGE_REST_API__")
else()
  add_definitions("-D__ENABLE_DIGICERT_SSL_SERVER__")
endif()

if (CM_ENABLE_CUSTOM_HEAP)
  add_definitions("-D__ENABLE_DIGICERT_CUSTOM_MALLOC__")
endif()

if (CM_ENABLE_K_MALLOC)
  add_definitions("-D__ENABLE_DIGICERT_K_MALLOC__")
endif()

if (CM_DISABLE_EST)
  add_definitions("-D__DISABLE_TRUSTEDGE_SCEP__")
  add_definitions("-D__DISABLE_TRUSTEDGE_EST__")
else()
  add_definitions("-D__ENABLE_DIGICERT_EST_CLIENT__")
  add_definitions("-D__ENABLE_DIGICERT_SCEP_CLIENT__")
endif()

if(CM_ENABLE_MEM_PROFILE)
  add_definitions("-D__ENABLE_DIGICERT_MEM_PROFILE__")
endif()

set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Digicert Inc. <trustedge@digicert.com>")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://www.digicert.com")
set(CPACK_DEBIAN_PACKAGE_NAME "trustedge")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${PACKAGE_ROOT_DIR}/preinst" ; "${PACKAGE_ROOT_DIR}/postinst" ; "${PACKAGE_ROOT_DIR}/prerm" ; "${PACKAGE_ROOT_DIR}/postrm" )

# Common flags between both TrustEdge shared library and binary
if(CM_ENABLE_DEBUG)
  if(NOT CM_ENABLE_ZEPHYR_OS)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt")
  else()
    builder_add_flags_to_files("${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt" "${CMAKE_CURRENT_SOURCE_DIR}/utils/mss_sources.txt")
    builder_add_flags_to_files("${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt" "${CMAKE_CURRENT_SOURCE_DIR}/agent/mss_sources.txt")
    if(NOT CM_DISABLE_EST)
      builder_add_flags_to_files("${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt" "${CMAKE_CURRENT_SOURCE_DIR}/scep/mss_sources.txt")
      builder_add_flags_to_files("${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt" "${CMAKE_CURRENT_SOURCE_DIR}/est/mss_sources.txt")
    endif()
    builder_add_flags_to_files("${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt" "${CMAKE_CURRENT_SOURCE_DIR}/main/mss_sources.txt")
    builder_add_flags_to_files("${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt" "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/mss_sources.txt")

  endif()
endif()
if(CM_ENABLE_DEBUG_INTERNALS)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_internals_flags.txt")
endif()
if(CM_ENABLE_EXPORT_ED)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_export_flags.txt")
endif()
if(CM_ENABLE_OQS OR CM_ENABLE_PQC)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_qs_flags.txt")
endif()
if(CM_ENABLE_CVC)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_cvc_flags.txt")
endif()
if(CM_ENABLE_CERT_PRINT)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_cert_print_flags.txt")
endif()
if(CM_ENABLE_PKCS11)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_pkcs11_flags.txt")
elseif(CM_ENABLE_TPM2)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_tpm2_flags.txt")
elseif(CM_ENABLE_TEE)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_tee_flags.txt")
elseif(CM_ENABLE_NANOROOT)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_nanoroot_flags.txt")
endif()
if(CM_ENABLE_TAP_REMOTE)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_tap_remote_flags.txt")
endif()
if(CM_ENABLE_DIGICERT_SCEP)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_digicert_flags.txt")
endif()
if(CM_ENABLE_COVERAGE)
    add_compile_options(--coverage)
    add_link_options("--coverage")
endif()
if(CM_ENABLE_ZEPHYR_OS)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/main/mocana_library_flags.txt")
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/mocana_flags.txt")
    if (CM_ENABLE_MINIMAL)
      builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/mocana_minimal_flags.txt")
    else()
      builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/mocana_non_minimal_flags.txt")
    endif()

    builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/asn1_sources.txt")
    builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/cert_enroll_sources.txt")
    builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/common_sources.txt")
    builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/crypto_sources.txt")
    builder_add_flags_to_files("${CMAKE_CURRENT_SOURCE_DIR}/zephyr/crypto_tool_flags.txt" "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/crypto_tool_sources.txt")
    builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/crypto_tool_sources.txt")
    builder_add_flags_to_files("${CMAKE_CURRENT_SOURCE_DIR}/zephyr/initialize_flags.txt" "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/initialize_sources.txt")
    builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/initialize_sources.txt")
    builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/mqtt_sources.txt")
    builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/nanocap_sources.txt")
    builder_add_flags_to_files("${CMAKE_CURRENT_SOURCE_DIR}/zephyr/nanocert_flags.txt" "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/nanocert_sources.txt")
    builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/nanocert_sources.txt")
    builder_add_flags_to_files("${CMAKE_CURRENT_SOURCE_DIR}/zephyr/nanossl_flags.txt" "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/nanossl_sources.txt")
    builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/nanossl_sources.txt")
    builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/platform_sources.txt")
elseif(CM_ENABLE_ZEPHYR_PACKAGING)
    if (CM_ENABLE_MINIMAL)
      builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/mocana_minimal_flags.txt")
    else()
      builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/mocana_non_minimal_flags.txt")
    endif()
endif()
# add the certificate flags here too
builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/certificate/mocana_flags.txt")
builder_finalize_flags(MOCANA_FLAGS)
foreach(MOCANA_FLAG ${MOCANA_FLAGS})
    add_definitions("${MOCANA_FLAG}")
endforeach()

# Create TrustEdge shared library from static archives
## Define target and add sources
builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/utils/mss_sources.txt")
builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/agent/mss_sources.txt")
if(NOT CM_DISABLE_EST)
  builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/scep/mss_sources.txt")
  builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/est/mss_sources.txt")
endif()
if(CM_ENABLE_ZEPHYR_OS)
  # add trustedge_agent_zephyr.c to build for artifact handling
  builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/zephyr/mss_sources.txt")
  # when building for zephyr add main sources to lib
  builder_add_sources(TRUSTEDGE_LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/main/mss_sources.txt")
endif()
builder_finialize_sources(TRUSTEDGE_LIB_SOURCES)

# this file is needed for compressing and unocompressing archive files
if(NOT CM_ENABLE_ZEPHYR_PACKAGING)
  set(TRUSTEDGE_LIB_SOURCES ${TRUSTEDGE_LIB_SOURCES} "${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/miniz/miniz.c")
endif()

if(CM_ENABLE_ZEPHYR_OS)
  # add source files
  target_sources(app PRIVATE ${TRUSTEDGE_LIB_SOURCES})

  # set the build target to a static library
  set_target_properties(app PROPERTIES OUTPUT_NAME trustedge)
  set_target_properties(app PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

  # Add optimization compile options
  # target_compile_options(app PUBLIC
  #   -Oz
  #   -ffunction-sections
  #   -fdata-sections
  #   -flto
  #   -fmerge-all-constants
  #   -fno-jump-tables
  #   -fno-tree-switch-conversion
  #   -finline-functions
  #   -finline-small-functions
  # )

 # Add optimization link options
  # target_link_options(app PUBLIC
  #   -Wl,--gc-sections
  #   -Wl,--relax
  #   -Wl,--sort-section=alignment
  #   -Wl,--sort-common
  #   -Wl,--strip-discarded
  # )

  # suppress application entry point to build as a library
  unset(CONF_FILE CACHE)
elseif(NOT CM_ENABLE_MONOLITHIC_BUILD)
  add_library(trustedge_lib SHARED "${TRUSTEDGE_LIB_SOURCES}")
endif()
## Add compile flags
builder_add_flags(TRUSTEDGE_LIB_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/agent/mocana_flags.txt")
if(NOT CM_DISABLE_EST)
  builder_add_flags(TRUSTEDGE_LIB_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/scep/mocana_flags.txt")
  builder_add_flags(TRUSTEDGE_LIB_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/est/mocana_flags.txt")
endif()
builder_add_flags(TRUSTEDGE_LIB_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/certificate/mocana_flags.txt")
builder_finalize_flags(TRUSTEDGE_LIB_FLAGS)
if (CM_ENABLE_ZEPHYR_OS)
  foreach(LIB_FLAG ${TRUSTEDGE_LIB_FLAGS})
    add_definitions("${LIB_FLAG}")
  endforeach()
elseif(NOT CM_ENABLE_MONOLITHIC_BUILD)
  target_compile_definitions(trustedge_lib PUBLIC ${TRUSTEDGE_LIB_FLAGS})
endif()
## Define libraries required for linking

if (NOT CM_ENABLE_ZEPHYR_OS AND NOT CM_ENABLE_ZEPHYR_PACKAGING)
builder_add_library_link_static(TRUSTEDGE_LIBS nanomqtt nanossl nanocert cert_enroll cryptointerface nanocap initialize asn1 platform common)
if (CM_ENABLE_EXPORT_ED)
    builder_add_library_link_static(TRUSTEDGE_LIBS cryptomw nanocap_mbed mbedcrypto)
else ()
    builder_add_library_link_static(TRUSTEDGE_LIBS nanocrypto)
endif()
if (CM_ENABLE_OQS)
    builder_add_library_link_static(TRUSTEDGE_LIBS nanocap_oqs oqs)
endif()
if(CM_ENABLE_PKCS11 OR CM_ENABLE_TPM2 OR CM_ENABLE_TEE OR CM_ENABLE_NANOROOT OR CM_ENABLE_TAP_REMOTE)
    builder_add_library_link_static(TRUSTEDGE_LIBS nanotap2_common nanotap2_configparser nanotap2)
endif()
if (CM_ENABLE_TAP_REMOTE)
    builder_add_library_link_static(TRUSTEDGE_LIBS nanotap2_clientcomm)
endif()
if (CM_ENABLE_TPM2 OR CM_ENABLE_PKCS11)
    builder_add_library_link_static(TRUSTEDGE_LIBS tpm2)
endif()
if (CM_ENABLE_TPM2)
    builder_add_library_link_static(TRUSTEDGE_LIBS smptpm2)
endif()
if (CM_ENABLE_PKCS11)
    builder_add_library_link_static(TRUSTEDGE_LIBS smppkcs11)
endif()
if (CM_ENABLE_TEE)
    builder_add_library_link_static(TRUSTEDGE_LIBS smptee)
endif()
if (CM_ENABLE_NANOROOT)
    builder_add_library_link_static(TRUSTEDGE_LIBS smpnanoroot)
endif()
if (CM_ENABLE_SOFTHSM)
    locate_lib(SOFTHSM softhsm2)
endif()
if (CM_ENABLE_CLOUDHSM)
    locate_lib(CLOUDHSM cloudhsm_pkcs11)
endif()
if (CM_ENABLE_DSSM)
    locate_lib(DSSM smpkcs11)
endif()
if (CM_ENABLE_PKCS11_TEE)
    locate_lib(CKTEEC ckteec)
    locate_lib(TEEC teec)
endif()
if (CM_ENABLE_TEE)
    locate_lib(TEEC teec)
endif()

builder_finalize_library_link(TRUSTEDGE_LIBS)
if (CM_ENABLE_SOFTHSM)
    builder_add_library_link(TRUSTEDGE_DEP_LIBS softhsm2)
    builder_finalize_library_link(TRUSTEDGE_DEP_LIBS)
elseif (CM_ENABLE_CLOUDHSM)
    builder_add_library_link(TRUSTEDGE_DEP_LIBS cloudhsm_pkcs11)
    builder_finalize_library_link(TRUSTEDGE_DEP_LIBS)
elseif(CM_ENABLE_DSSM)
    builder_add_library_link(TRUSTEDGE_DEP_LIBS smpkcs11)
    builder_finalize_library_link(TRUSTEDGE_DEP_LIBS)
elseif(CM_ENABLE_PKCS11_TEE)
    builder_add_library_link(TRUSTEDGE_DEP_LIBS teec ckteec)
    builder_finalize_library_link(TRUSTEDGE_DEP_LIBS)
elseif(CM_ENABLE_TEE)
    builder_add_library_link(TRUSTEDGE_DEP_LIBS teec)
    builder_finalize_library_link(TRUSTEDGE_DEP_LIBS)
endif()
endif() # zephyr OS
if(NOT CM_ENABLE_MONOLITHIC_BUILD AND NOT CM_ENABLE_ZEPHYR_OS)
    target_link_libraries(trustedge_lib PRIVATE ${ARCHIVE_TO_SHARED_LIB_LINK_FLAG_START} ${TRUSTEDGE_LIBS} ${ARCHIVE_TO_SHARED_LIB_LINK_FLAG_END} ${TRUSTEDGE_DEP_LIBS})
    if(WIN32)
        target_link_libraries(trustedge_lib PRIVATE ws2_32 shlwapi tbs)
    endif()
    ## Set target output name
    set_property(TARGET trustedge_lib PROPERTY OUTPUT_NAME trustedge)
    if(CMAKE_BUILD_TYPE STREQUAL Release)
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libtrustedge.map -Wl,--retain-symbols-file=${CMAKE_CURRENT_SOURCE_DIR}/trustedge_symbols.txt")
    endif()
    ## Finialize target
    builder_finalize_target(trustedge_lib)
endif()

if(DEFINED CM_VERSION_STRING)
    file(WRITE "${PACKAGE_ROOT_DIR}/version.txt" "${CM_VERSION_STRING}\n")
else()
    file(WRITE "${PACKAGE_ROOT_DIR}/version.txt" "0.0.1-0\n")
endif()

if (CM_ENABLE_ZEPHYR_OS)
## START - Building tp_version.h
set(VERSION_FILE "${MSS_DIR}/projects/shared_cmake/set_cpack_version.cmake")
include(${VERSION_FILE})

# Set all fields to be replaced in tp_version.h.in

if(DEFINED ENV{BUILD_NUMBER})
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "$ENV{BUILD_NUMBER}")
else()
  set(CPACK_PACKAGE_VERSION_BUILD_ENV "0")
endif()
set(CM_BUILD_VERSION "${CPACK_PACKAGE_VERSION}.${CPACK_PACKAGE_VERSION_BUILD_ENV}")

# Set platform name from shell param if present
set(TP_BUILD_PLATFORM "${CM_SYSTEM_NAME}")
if(TP_BUILD_PLATFORM STREQUAL "")
  set(TP_BUILD_PLATFORM "${CMAKE_SYSTEM_NAME}")
  if(WIN32)
    if("${CMAKE_GENERATOR}" MATCHES "Win64")
      set(TP_BUILD_PLATFORM "Win64")
    endif()
  endif()
endif()

set(TP_BUILD_VERSION "${CM_BUILD_VERSION}")
if (DEFINED CM_VERSION_STRING)
  set(TP_BUILD_VERSION "${CM_VERSION_STRING}")
endif()
if(TP_BUILD_VERSION STREQUAL "")
  set(TP_BUILD_VERSION "0.0.0.${CPACK_PACKAGE_VERSION_BUILD_ENV}")
endif()

# Debug / Release
set(TP_BUILD_TYPE "${CMAKE_BUILD_TYPE}")
if(DEFINED CM_TAP_TYPE)
  if("${CM_TAP_TYPE}" MATCHES "LOCAL")
    set(TP_BUILD_TAPINFO "TAP-Local")
  elseif("${CM_TAP_TYPE}" MATCHES "REMOTE")
    set(TP_BUILD_TAPINFO "TAP-Remote")
  endif()
else()
  set(TP_BUILD_TAPINFO "TAP-Off")
endif()

# Set build date/time
string(TIMESTAMP TP_BUILD_DATE "%Y-%m-%d %H:%M")

# copyright year
string(TIMESTAMP CURR_YEAR "%Y")
configure_file(${MSS_SRC_DIR}/common/tp_version.h.in
               ${MSS_SRC_DIR}/common/tp_version.h
               @ONLY)

## END - Building tp_version.h

  configure_file(${MSS_SRC_DIR}/common/build_info.h.in
                 ${MSS_SRC_DIR}/common/build_info.h
                 @ONLY)
endif()

# Create TrustEdge binary
if (NOT CM_ENABLE_ZEPHYR_OS AND NOT CM_ENABLE_ZEPHYR_PACKAGING)
## Define target and add sources
builder_add_sources(TRUSTEDGE_MAIN_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/main/mss_sources.txt")
builder_finialize_sources(TRUSTEDGE_MAIN_SOURCES)

# Add Windows service support source file
if(WIN32)
    list(APPEND TRUSTEDGE_MAIN_SOURCES "${MSS_SRC_DIR}/trustedge/trustedge_service_win.c")
    list(APPEND TRUSTEDGE_MAIN_SOURCES "${MSS_SRC_DIR}/trustedge/trustedge_eventlog.c")

    # Find message compiler for Windows Event Log support
    get_filename_component(sdk_dir
                           "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsKits\\Installed Roots;KitsRoot10]"
                           REALPATH)
    find_program(CMAKE_MC_COMPILER mc.exe HINTS "${sdk_dir}"
                 DOC "path to message compiler")

    if(CMAKE_MC_COMPILER)
        message(STATUS "Found message compiler: ${CMAKE_MC_COMPILER}")

        # Compile trustedge_events.mc to generate .h and .rc files
        set(TRUSTEDGE_EVENTS_SOURCES
            ${PROJECT_BINARY_DIR}/trustedge_events.h
            ${PROJECT_BINARY_DIR}/trustedge_events.rc)

        add_custom_command(
            OUTPUT ${TRUSTEDGE_EVENTS_SOURCES}
            DEPENDS ${MSS_SRC_DIR}/trustedge/trustedge_events.mc
            COMMAND ${CMAKE_MC_COMPILER}
            ARGS -h ${PROJECT_BINARY_DIR}
                 -r ${PROJECT_BINARY_DIR}
                 ${MSS_SRC_DIR}/trustedge/trustedge_events.mc
            VERBATIM
        )

        # Add generated files to sources
        list(APPEND TRUSTEDGE_MAIN_SOURCES ${TRUSTEDGE_EVENTS_SOURCES})

        # Add include path for generated header
        include_directories(${PROJECT_BINARY_DIR})

        # Enable event log support
        add_definitions(-D__ENABLE_TRUSTEDGE_WIN32_EVENTS__)
        message(STATUS "Windows Event Log support enabled for TrustEdge")
    else()
        message(WARNING "Message compiler not found - Windows Event Log support disabled")
    endif()
endif()

if(CM_BUILD_LIBRARY)
    add_library(trustedge_main SHARED "${TRUSTEDGE_MAIN_SOURCES}")
    builder_add_flags(TRUSTEDGE_MAIN_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/main/mocana_library_flags.txt")
    builder_finalize_flags(TRUSTEDGE_MAIN_FLAGS)
    target_compile_definitions(trustedge_main PUBLIC "${TRUSTEDGE_MAIN_FLAGS}")
else()
    add_executable(trustedge_main "${TRUSTEDGE_MAIN_SOURCES}")
endif()

## Define libraries required for linking
builder_add_library_link_static(TRUSTEDGE_BIN_LINK_LIBS mqtt_client_sample)
builder_finalize_library_link(TRUSTEDGE_BIN_LINK_LIBS)

if(CM_ENABLE_MONOLITHIC_BUILD)
    target_link_libraries(trustedge_main PRIVATE ${ARCHIVE_TO_SHARED_LIB_LINK_FLAG_START} ${TRUSTEDGE_BIN_LINK_LIBS} ${TRUSTEDGE_LIBS} ${ARCHIVE_TO_SHARED_LIB_LINK_FLAG_END} ${TRUSTEDGE_DEP_LIBS})
    if(WIN32)
        target_link_libraries(trustedge_main PRIVATE ws2_32 shlwapi tbs ncrypt crypt32 bcrypt advapi32)
    else()
        target_link_libraries(trustedge_main PRIVATE pthread dl)
    endif()
else()
    if(WIN32)
        # On Windows, link static libraries directly since DLL symbol export isn't configured
        target_link_libraries(trustedge_main PUBLIC ${TRUSTEDGE_BIN_LINK_LIBS} ${TRUSTEDGE_LIBS} ${TRUSTEDGE_DEP_LIBS} ws2_32 shlwapi tbs advapi32)
    else()
        target_link_libraries(trustedge_main PUBLIC ${TRUSTEDGE_BIN_LINK_LIBS} trustedge_lib pthread dl)
    endif()
endif()

## Set target output name
set_property(TARGET trustedge_main PROPERTY OUTPUT_NAME trustedge)
if(CM_ENABLE_MONOLITHIC_BUILD)
    target_sources(trustedge_main PRIVATE "${TRUSTEDGE_LIB_SOURCES}")
    target_compile_definitions(trustedge_main PUBLIC ${TRUSTEDGE_LIB_FLAGS})

    if(CMAKE_BUILD_TYPE STREQUAL Release AND NOT WIN32)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s")
    endif()
endif()
## Finialize target
builder_finalize_target(trustedge_main)
if(CM_BUILD_UNITTEST)
    builder_add_test_sources(trustedge_main)
    builder_add_test(trustedge_main trustedge_main_unittest ${MSS_SRC_DIR}/trustedge/test/trustedge_main_unittest_main.c)
    builder_add_test(trustedge_main trustedge_agent_unittest ${MSS_SRC_DIR}/trustedge/test/trustedge_agent_unittest_main.c)
    builder_add_test(trustedge_main trustedge_agent_policy_unittest ${MSS_SRC_DIR}/trustedge/test/trustedge_agent_policy_unittest_main.c)
    builder_add_test(trustedge_main trustedge_agent_mime_unittest ${MSS_SRC_DIR}/trustedge/test/trustedge_agent_mime_unittest_main.c)
    builder_add_test(trustedge_main trustedge_agent_generate_data ${MSS_SRC_DIR}/trustedge/test/trustedge_agent_generate_data.c)
    builder_add_test(trustedge_main trustedge_agent_updatepolicy_unittest ${MSS_SRC_DIR}/trustedge/test/trustedge_agent_updatepolicy_unittest_main.c)
endif()

file(READ ${CMAKE_CURRENT_SOURCE_DIR}/eula.txt EULA_FILE_CONTENT)
if(CM_GENERATOR_BUILD STREQUAL DEB)
configure_file(${CMAKE_SOURCE_DIR}/packaging/DEB/deb_preinst.sh ${PACKAGE_ROOT_DIR}/preinst @ONLY)
configure_file(${CMAKE_SOURCE_DIR}/packaging/DEB/deb_postinst.sh ${PACKAGE_ROOT_DIR}/postinst @ONLY)
configure_file(${CMAKE_SOURCE_DIR}/packaging/DEB/deb_prerm.sh ${PACKAGE_ROOT_DIR}/prerm @ONLY)
configure_file(${CMAKE_SOURCE_DIR}/packaging/DEB/deb_postrm.sh ${PACKAGE_ROOT_DIR}/postrm @ONLY)
endif()
endif() # NOT CM_ENABLE_ZEPHYR_OS
if(DEFINED CM_GENERATOR_BUILD AND NOT CM_ENABLE_ZEPHYR_OS)
    # Configure generator specific settings
    if(CM_GENERATOR_BUILD STREQUAL DEB)
        set(CPACK_GENERATOR                     DEB)
        set(CPACK_PACKAGING_INSTALL_PREFIX "/")
        set(TRUSTEDGE_BIN_PREFIX "usr/")
        set(TRUSTEDGE_CONF_PREFIX "etc/digicert/")
    elseif(CM_GENERATOR_BUILD STREQUAL TGZ)
        set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY    OFF)
        set(CPACK_GENERATOR                     TGZ)
        set(CPACK_PACKAGING_INSTALL_PREFIX "")
        set(TRUSTEDGE_BIN_PREFIX "")
        set(TRUSTEDGE_CONF_PREFIX "./")
        set(TRUSTEDGE_DOCS_PREFIX "./")
    elseif(CM_GENERATOR_BUILD STREQUAL ZIP)
        set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY    OFF)
        set(CPACK_GENERATOR                     ZIP)
        set(CPACK_PACKAGING_INSTALL_PREFIX "")
        set(TRUSTEDGE_BIN_PREFIX "")
        set(TRUSTEDGE_CONF_PREFIX "etc/digicert/")
    elseif(CM_GENERATOR_BUILD STREQUAL MSI)
        set(CPACK_GENERATOR                     WIX)
        set(CPACK_PACKAGING_INSTALL_PREFIX "")
        # Executable: C:\Program Files\DigiCert\TrustEdge\bin\trustedge.exe
        # Config/Data: C:\ProgramData\DigiCert\TrustEdge\ (created by WIX installer)
        set(CPACK_PACKAGE_INSTALL_DIRECTORY "DigiCert/TrustEdge")
        set(TRUSTEDGE_BIN_PREFIX "")
        set(TRUSTEDGE_CONF_PREFIX "")

        # Find PowerShell (prefer pwsh for PS7, fallback to powershell for Windows PS 5.1)
        find_program(POWERSHELL_EXECUTABLE NAMES pwsh powershell)
        if(NOT POWERSHELL_EXECUTABLE)
            message(FATAL_ERROR "PowerShell not found. MSI builds require PowerShell (pwsh or powershell) to generate license.rtf")
        endif()
        message(STATUS "Using PowerShell: ${POWERSHELL_EXECUTABLE}")

        # WIX/MSI specific configuration
        set(CPACK_PACKAGE_NAME "DigiCert TrustEdge")
        set(CPACK_WIX_UPGRADE_GUID "A1B2C3D4-E5F6-7890-ABCD-EF1234567890")
        set(CPACK_WIX_PROGRAM_MENU_FOLDER "DigiCert TrustEdge")
        set(CPACK_WIX_PROPERTY_ARPHELPLINK "https://www.digicert.com/support")
        set(CPACK_WIX_PROPERTY_ARPURLINFOABOUT "https://www.digicert.com")
        set(CPACK_WIX_CULTURES "en-US")
        set(CPACK_WIX_PROPERTY_ARPCOMMENTS "TrustEdge - Device Identity and Certificate Management")
        
        # Custom WiX template with AllowDowngrades enabled for rollback support
        set(CPACK_WIX_TEMPLATE "${CMAKE_CURRENT_SOURCE_DIR}/installer/MSI/WIX.template.in")
        
        # Use standard WiX minimal UI
        # Note: EULA is shown on both fresh install and upgrade
        set(CPACK_WIX_UI_REF "WixUI_Minimal")

        # WIX extra sources for ProgramData directory structure
        # Use configure_file to substitute CMake variables in the WXS templates
        set(CPACK_WIX_EXTRA_SOURCES "")
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/installer/MSI/programdata_dirs.wxs.in")
            configure_file(
                "${CMAKE_CURRENT_SOURCE_DIR}/installer/MSI/programdata_dirs.wxs.in"
                "${CMAKE_BINARY_DIR}/programdata_dirs.wxs"
                @ONLY
            )
            list(APPEND CPACK_WIX_EXTRA_SOURCES "${CMAKE_BINARY_DIR}/programdata_dirs.wxs")
        endif()
        
        # WIX extensions needed for utility functions
        set(CPACK_WIX_EXTENSIONS "WixUtilExtension")
        
        # WIX patch to add ProgramData components to the feature
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/installer/MSI/wix_patch.xml")
            set(CPACK_WIX_PATCH_FILE "${CMAKE_CURRENT_SOURCE_DIR}/installer/MSI/wix_patch.xml")
        endif()

        # Generate license.rtf from eula.txt for MSI installer (output to build dir)
        set(EULA_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/eula.txt")
        set(LICENSE_RTF_OUTPUT "${CMAKE_BINARY_DIR}/license.rtf")
        set(LICENSE_RTF_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/installer/MSI/generate_license_rtf.ps1")
        set(LICENSE_RTF_GENERATED FALSE)
        
        if(EXISTS "${EULA_SOURCE}" AND EXISTS "${LICENSE_RTF_SCRIPT}")
            message(STATUS "Generating license.rtf from eula.txt...")
            execute_process(
                COMMAND "${POWERSHELL_EXECUTABLE}" -ExecutionPolicy Bypass -File "${LICENSE_RTF_SCRIPT}"
                        -EulaPath "${EULA_SOURCE}"
                        -OutputPath "${LICENSE_RTF_OUTPUT}"
                RESULT_VARIABLE LICENSE_RTF_RESULT
                OUTPUT_VARIABLE LICENSE_RTF_OUTPUT_MSG
                ERROR_VARIABLE LICENSE_RTF_ERROR_MSG
            )
            if(LICENSE_RTF_RESULT EQUAL 0 AND EXISTS "${LICENSE_RTF_OUTPUT}")
                message(STATUS "license.rtf generated successfully at ${LICENSE_RTF_OUTPUT}")
                set(LICENSE_RTF_GENERATED TRUE)
            else()
                message(FATAL_ERROR "Failed to generate license.rtf for MSI packaging: ${LICENSE_RTF_ERROR_MSG}")
            endif()
        else()
            message(FATAL_ERROR "Cannot generate license.rtf: eula.txt or generate_license_rtf.ps1 not found")
        endif()

        # Optional MSI assets - only set if files exist
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/installer/MSI/trustedge.ico")
            set(CPACK_WIX_PRODUCT_ICON "${CMAKE_CURRENT_SOURCE_DIR}/installer/MSI/trustedge.ico")
        endif()
        if(LICENSE_RTF_GENERATED)
            set(CPACK_WIX_LICENSE_RTF "${LICENSE_RTF_OUTPUT}")
        endif()
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/installer/MSI/banner.bmp")
            set(CPACK_WIX_UI_BANNER "${CMAKE_CURRENT_SOURCE_DIR}/installer/MSI/banner.bmp")
        endif()
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/installer/MSI/dialog.bmp")
            set(CPACK_WIX_UI_DIALOG "${CMAKE_CURRENT_SOURCE_DIR}/installer/MSI/dialog.bmp")
        endif()

    elseif(CM_GENERATOR_BUILD STREQUAL RPM)
        set(CPACK_GENERATOR                     RPM)
        set(CPACK_PACKAGING_INSTALL_PREFIX "/")
        set(TRUSTEDGE_BIN_PREFIX "usr/")
        set(TRUSTEDGE_CONF_PREFIX "etc/digicert/")

        # RPM specific configuration
        set(CPACK_RPM_PACKAGE_REQUIRES "systemd")
        set(CPACK_RPM_PACKAGE_GROUP "System Environment/Daemons")
        set(CPACK_RPM_PACKAGE_LICENSE "Proprietary")
        set(CPACK_RPM_PACKAGE_AUTOREQ "no")
        set(CPACK_RPM_PACKAGE_VENDOR "Digicert Inc.")
        set(CPACK_RPM_PACKAGE_URL "https://www.digicert.com")

       # Read EULA content
       set(EULA_SOURCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/eula.txt")
       if(EXISTS ${EULA_SOURCE_FILE})
           file(READ ${EULA_SOURCE_FILE} EULA_CONTENT)
           message(STATUS "✓ EULA content loaded from ${EULA_SOURCE_FILE}")
       else()
           message(WARNING "✗ EULA file not found at ${EULA_SOURCE_FILE}")
           set(EULA_CONTENT "EULA content not available")
       endif()

        # Configure RPM scripts
        configure_file(${CMAKE_SOURCE_DIR}/packaging/RPM/rpm_preinst.sh ${PACKAGE_ROOT_DIR}/rpm_preinst.sh @ONLY)
        configure_file(${CMAKE_SOURCE_DIR}/packaging/RPM/rpm_postinst.sh ${PACKAGE_ROOT_DIR}/rpm_postinst.sh @ONLY)
        configure_file(${CMAKE_SOURCE_DIR}/packaging/RPM/rpm_prerm.sh ${PACKAGE_ROOT_DIR}/rpm_prerm.sh @ONLY)
        configure_file(${CMAKE_SOURCE_DIR}/packaging/RPM/rpm_postrm.sh ${PACKAGE_ROOT_DIR}/rpm_postrm.sh @ONLY)
	
        set(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE ${PACKAGE_ROOT_DIR}/rpm_preinst.sh)
        set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE ${PACKAGE_ROOT_DIR}/rpm_postinst.sh)
        set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE ${PACKAGE_ROOT_DIR}/rpm_prerm.sh)
        set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE ${PACKAGE_ROOT_DIR}/rpm_postrm.sh)

    else()
        message(FATAL_ERROR "Unsupported generator build: ${CM_GENERATOR_BUILD}")
    endif()

    if (NOT CM_ENABLE_ZEPHYR_PACKAGING)
        if(NOT CM_ENABLE_MONOLITHIC_BUILD)
            install(TARGETS trustedge_lib
                    RUNTIME)
        endif()

        install(TARGETS trustedge_main
                DESTINATION ${TRUSTEDGE_BIN_PREFIX}bin)
        if(CM_GENERATOR_BUILD STREQUAL DEB)
            configure_file(${MSS_DIR}/docs/trustedge.1 ${CMAKE_BINARY_DIR}/trustedge.1 COPYONLY)
            execute_process(COMMAND gzip -f ${CMAKE_BINARY_DIR}/trustedge.1)
            install(FILES ${CMAKE_BINARY_DIR}/trustedge.1.gz DESTINATION usr/share/man/man1)
            install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/installer/DEB/config/trustedge
                DESTINATION usr/share/bash-completion/completions/)
        elseif(CM_GENERATOR_BUILD STREQUAL TGZ)
            install(FILES ${MSS_DIR}/docs/trustedge.1 DESTINATION ${TRUSTEDGE_DOCS_PREFIX})
        endif()
        # Install platform-specific config file
        # MSI skipped here - WIX fragment (programdata_dirs.wxs) handles ProgramData install
        if(NOT CM_GENERATOR_BUILD STREQUAL MSI)
            install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/installer/DEB/config/trustedge.json
                DESTINATION ${TRUSTEDGE_CONF_PREFIX})
        endif()
    else()
        if(CM_DISABLE_EST)
          install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/installer/ZEPHYR/config/trustedge_minimal.json
              DESTINATION ${TRUSTEDGE_CONF_PREFIX}
              RENAME trustedge.json)
        else()
          install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/installer/ZEPHYR/config/trustedge.json
              DESTINATION ${TRUSTEDGE_CONF_PREFIX})
        endif()
    endif()

    # Install data directories (skip for MSI - app creates in ProgramData at runtime)
    if(NOT CM_GENERATOR_BUILD STREQUAL MSI)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}service)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}service/request)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}service/completed)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}service/failed)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}service/processing)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}conf)
    if (NOT CM_ENABLE_ZEPHYR_OS)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}scripts)
    endif()
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}keystore)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}keystore/ca)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}keystore/certs)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}keystore/conf)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}keystore/crls)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}keystore/keys)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}keystore/psks)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}keystore/req)
    install(DIRECTORY
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}/cloudprovider)

    install(FILES ${PACKAGE_ROOT_DIR}/version.txt
            DESTINATION ${TRUSTEDGE_CONF_PREFIX}conf)
    if (NOT CM_ENABLE_ZEPHYR_PACKAGING)
        install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/eula.txt
                DESTINATION ${TRUSTEDGE_CONF_PREFIX}conf)
        # Linux-specific service scripts (skip for MSI/Windows)
        if (CM_ENABLE_VALGRIND_MASSIF)
        install(FILES ${CMAKE_SOURCE_DIR}/packaging/DEB/trustedge_valgrind_massif.service
                DESTINATION ${TRUSTEDGE_CONF_PREFIX}scripts RENAME trustedge.service)
        elseif(CM_ENABLE_VALGRIND_MEMCHECK)
        install(FILES ${CMAKE_SOURCE_DIR}/packaging/DEB/trustedge_valgrind.service
                DESTINATION ${TRUSTEDGE_CONF_PREFIX}scripts RENAME trustedge.service)
        else()
        install(FILES ${CMAKE_SOURCE_DIR}/packaging/DEB/trustedge.service
                DESTINATION ${TRUSTEDGE_CONF_PREFIX}scripts)
        endif()
        install(PROGRAMS ${CMAKE_SOURCE_DIR}/packaging/DEB/start_trustedge.sh
                DESTINATION ${TRUSTEDGE_CONF_PREFIX}scripts)
        install(PROGRAMS ${CMAKE_SOURCE_DIR}/packaging/DEB/configure_trustedge.sh
                DESTINATION ${TRUSTEDGE_CONF_PREFIX}scripts)
    endif()
    endif() # NOT CM_GENERATOR_BUILD STREQUAL MSI

    if(NOT CM_GENERATOR_BUILD STREQUAL MSI)
        set(CPACK_PACKAGE_NAME              "trustedge")
    endif()
    set(CPACK_PACKAGE_VENDOR                "DigiCert Inc.")
    # TODO: Update contact email
    set(CPACK_PACKAGE_CONTACT               "trustedge@digicert.com")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY   "TrustEdge package for security and device management.")

    if(DEFINED CM_VERSION_STRING)
        set(CPACK_PACKAGE_VERSION               "${CM_VERSION_STRING}")
    else()
        set(CPACK_PACKAGE_VERSION               "2.0.2")
    endif()

    set(METADATA_TAP "TAPOff")
    if(CM_TARGET_PLATFORM STREQUAL "rpi64")
        set(METADATA_OS "Rpi")
    elseif(CM_TARGET_PLATFORM STREQUAL "rpi32")
        set(METADATA_OS "Rpi")
    else()
        set(METADATA_OS "linux")
    endif()
    set(METADATA_INSTRUCTION_SET "x86")
    if(CM_TARGET_PLATFORM STREQUAL "rpi32" OR CM_ENABLE_ZEPHYR_PACKAGING)
    set(METADATA_ARCH "arm")
    elseif(CM_TARGET_PLATFORM STREQUAL "rpi64")
    set(METADATA_ARCH "aarch64")
    else()
    set(METADATA_ARCH "x86_64")
    endif()

    if(CM_TARGET_PLATFORM STREQUAL "rpi64")
        set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "arm64")
    elseif(CM_TARGET_PLATFORM STREQUAL "rpi32")
        set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "armhf")
    endif()

    if(CM_PRE_RELEASE_STRING)
        set(CM_PRE_RELEASE_STRING "-${CM_PRE_RELEASE_STRING}")
    endif()

    set(CPACK_PACKAGE_FILE_NAME "trustedge_${CPACK_PACKAGE_VERSION}.${METADATA_ARCH}")

    include(CPack)
endif()
