# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

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
endif()

builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/digicert_flags.txt")
builder_finalize_flags(MOCANA_FLAGS)

add_definitions("${MOCANA_FLAGS}")

if (NOT DEFINED IMAGE_NAME)
  set(IMAGE_NAME "test application")
endif()

target_compile_definitions(app PRIVATE "-DMY_IMAGE_NAME=\"${IMAGE_NAME}\"")

FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})

file(GLOB EXTERNAL_LIBS "${TRUSTCORE_LIB_DIR}/*.a")

foreach(lib_path ${EXTERNAL_LIBS})
  get_filename_component(lib_name ${lib_path} NAME_WE)
  # add_and_link_library(${lib_path} ${lib_name} app)
  message(STATUS "Linking library: ${lib_name} => ${lib_path}")

  add_library(${lib_name} STATIC IMPORTED GLOBAL)
  set_target_properties(${lib_name} PROPERTIES IMPORTED_LOCATION ${lib_path})
  target_link_libraries(app PUBLIC ${lib_name})
endforeach()
