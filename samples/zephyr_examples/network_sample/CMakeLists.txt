# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

if(DEFINED ENV{ZEPHYR_HOST_IP})
  set(EXTRA_CONF_CONTENT "")
  if(DEFINED ENV{ZEPHYR_HOST_IP})
    string(APPEND EXTRA_CONF_CONTENT "CONFIG_NET_CONFIG_PEER_IPV4_ADDR=\"$ENV{ZEPHYR_HOST_IP}\"\n")
  endif()
  set(ENV_CONF_FILE ${CMAKE_BINARY_DIR}/env_override.conf)
  file(WRITE ${ENV_CONF_FILE} ${EXTRA_CONF_CONTENT})
  set(CONF_FILE "prj.conf;${ENV_CONF_FILE}")
endif()

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(fs_shell)

set(MSS_DIR  "${CMAKE_CURRENT_SOURCE_DIR}/../../../..")
set(MSS_SRC_DIR "${MSS_DIR}/src")
set(TRUSTCORE_LIB_DIR "${MSS_DIR}/bin_static")

include_directories(
  ${MSS_SRC_DIR}
)

FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})

file(GLOB EXTERNAL_LIBS "${TRUSTCORE_LIB_DIR}/*.a")

if("${BOARD}" STREQUAL "native_sim")
  add_definitions("-D__DIGICERT_SAMPLE_NATIVE_SIM__")
elseif ("${BOARD}" STREQUAL "esp32s3_devkitc")
  add_definitions("-D__ENABLE_DIGICERT_ESP32S3__")
endif()

function(add_and_link_library lib_path lib_name app_target)
  message(STATUS "Linking library: ${lib_name} => ${lib}")

  add_library(${lib_name} STATIC IMPORTED GLOBAL)
  set_target_properties(${lib_name} PROPERTIES IMPORTED_LOCATION ${lib_path})
  target_link_libraries(${app_target} PUBLIC ${lib_name})
endfunction()

foreach(lib_path ${EXTERNAL_LIBS})
  get_filename_component(lib_name ${lib_path} NAME_WE)
  # add_and_link_library(${lib_path} ${lib_name} app)
  message(STATUS "Linking library: ${lib_name} => ${lib_path}")

  add_library(${lib_name} STATIC IMPORTED GLOBAL)
  set_target_properties(${lib_name} PROPERTIES IMPORTED_LOCATION ${lib_path})
  target_link_libraries(app PUBLIC ${lib_name})
endforeach()
