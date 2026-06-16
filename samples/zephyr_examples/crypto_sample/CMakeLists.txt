# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

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

foreach(lib_path ${EXTERNAL_LIBS})
  get_filename_component(lib_name ${lib_path} NAME_WE)
  message(STATUS "Linking library: ${lib_name} => ${lib_path}")

  add_library(${lib_name} STATIC IMPORTED GLOBAL)
  set_target_properties(${lib_name} PROPERTIES IMPORTED_LOCATION ${lib_path})
  target_link_libraries(app PUBLIC ${lib_name})
endforeach()
