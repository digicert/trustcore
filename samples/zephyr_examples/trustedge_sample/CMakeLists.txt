# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

option(CM_ENABLE_BOOTLOADER              "Enable bootloader support."                    OFF)
option(CM_ENABLE_CUSTOM_HEAP             "Enable custom heap."                           OFF)
option(CM_ENABLE_MEM_PROFILE             "Enable heap profiling."                        OFF)
option(CM_ENABLE_STACK_PROFILE           "Enable stack profiling."                       OFF)

if(DEFINED ENV{ZEPHYR_DNS_SERVER} OR DEFINED ENV{ZEPHYR_DNS_SERVER_2} OR DEFINED ENV{ZEPHYR_HOST_IP})
  set(EXTRA_CONF_CONTENT "")
  if(DEFINED ENV{ZEPHYR_DNS_SERVER})
    string(APPEND EXTRA_CONF_CONTENT "CONFIG_DNS_SERVER1=\"$ENV{ZEPHYR_DNS_SERVER}:53\"\n")
  endif()
  if(DEFINED ENV{ZEPHYR_DNS_SERVER_2})
    string(APPEND EXTRA_CONF_CONTENT "CONFIG_DNS_SERVER2=\"$ENV{ZEPHYR_DNS_SERVER_2}:53\"\n")
  endif()
  if(DEFINED ENV{ZEPHYR_HOST_IP})
    string(APPEND EXTRA_CONF_CONTENT "CONFIG_NET_CONFIG_PEER_IPV4_ADDR=\"$ENV{ZEPHYR_HOST_IP}\"\n")
  endif()
  set(ENV_CONF_FILE ${CMAKE_BINARY_DIR}/env_override.conf)
  file(WRITE ${ENV_CONF_FILE} ${EXTRA_CONF_CONTENT})
  set(CONF_FILE "prj.conf;${ENV_CONF_FILE}")
endif()

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(trustedge_sample C)


set(MSS_DIR  "${CMAKE_CURRENT_SOURCE_DIR}/../../../..")
set(MSS_SRC_DIR "${MSS_DIR}/src")
set(TRUSTCORE_LIB_DIR "${MSS_DIR}/bin_static")

include_directories(
  ${MSS_SRC_DIR}
  ${MSS_SRC_DIR}/trustedge
)

function(builder_add_flags FLAGS_VAR)
    message("----------------")
    foreach(FLAGS_FILE IN LISTS ARGN)
        message("${FLAGS_VAR} - adding flags in ${FLAGS_FILE}")
        file(STRINGS ${FLAGS_FILE} FLAGS_TO_ADD)
        set(FLAGS_LIST "${FLAGS_LIST} ${FLAGS_TO_ADD}")
    endforeach()
    set(${FLAGS_VAR} "${${FLAGS_VAR}} ${FLAGS_LIST}" PARENT_SCOPE)
endfunction()

function(builder_finalize_flags FLAGS_VAR)
    message("----------------")
    foreach(FLAG ${${FLAGS_VAR}})
        string(STRIP "${STRIPPED_FLAGS} ${FLAG}" STRIPPED_FLAGS)
    endforeach()
    set(${FLAGS_VAR} "${STRIPPED_FLAGS}" PARENT_SCOPE)
    message("${FLAGS_VAR} = ${${FLAGS_VAR}}")
endfunction()

if ("${BOARD}" STREQUAL "native_sim")
  add_definitions("-D__ENABLE_DIGICERT_NATIVE_SIM__")
elseif ("${BOARD}" STREQUAL "esp32s3_devkitc")
  add_definitions("-D__ENABLE_DIGICERT_ESP32S3__")
endif()

if (CM_ENABLE_BOOTLOADER)
  add_definitions("-D__ENABLE_DIGICERT_BOOTLOADER_SUPPORT__")
endif()

if (CM_ENABLE_MEM_PROFILE)
  add_definitions("-D__ENABLE_DIGICERT_MEM_PROFILE__")
endif()

if (CM_ENABLE_STACK_PROFILE)
  add_definitions("-D__ENABLE_DIGICERT_STACK_PROFILE__")
endif()

if (CM_ENABLE_CUSTOM_HEAP)
  add_definitions("-D__ENABLE_DIGICERT_CUSTOM_MALLOC__")
endif()

target_compile_definitions(app PRIVATE "-DIMAGE_NAME=\"${TRUSTEDGE_IMAGE_NAME}\"")

builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/digicert_flags.txt")
builder_finalize_flags(MOCANA_FLAGS)

add_definitions("${MOCANA_FLAGS}")

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
  #   -Wl,--orphan-handling=place
  #   -Wl,--print-memory-usage
  # )

if("${BOARD}" STREQUAL "esp32s3_devkitc")
  target_link_options(app PUBLIC
    -Wl,--wrap=malloc
    -Wl,--wrap=free
    -Wl,--wrap=calloc
    -Wl,--wrap=TRUSTEDGE_utilsGetHostByName
  )
endif()

set(app_sources src/main.c src/dns.c)
target_sources(app PRIVATE ${app_sources})

if("${BOARD}" STREQUAL "esp32s3_devkitc")
  target_sources(app PRIVATE src/heap_allocator.c)
endif()

file(GLOB EXTERNAL_LIBS "${TRUSTCORE_LIB_DIR}/*.a")

foreach(lib_path ${EXTERNAL_LIBS})
  get_filename_component(lib_name ${lib_path} NAME_WE)
  message(STATUS "Linking library: ${lib_name} => ${lib_path}")

  add_library(${lib_name} STATIC IMPORTED GLOBAL)
  set_target_properties(${lib_name} PROPERTIES IMPORTED_LOCATION ${lib_path})
  target_link_libraries(app PUBLIC ${lib_name})
endforeach()
