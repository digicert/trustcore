################################################################################
# CMake file for building WebSocket client artifacts
################################################################################

if(BUILD_FOR_OSI)
    cmake_minimum_required(VERSION 3.16)
else()
    cmake_minimum_required(VERSION 3.5)
endif()

option(CM_ENABLE_DEBUG           "Enable debug logging."             OFF)
option(CM_BUILD_X32              "Build for 32-bit."                 OFF)
option(CM_BUILD_X64              "Build for 64-bit."                 OFF)
option(CM_ENABLE_SSL             "Build with SSL (WSS support)."     OFF)
option(CM_BUILD_NANOWS           "Build NanoWS library."             OFF)
option(CM_ENABLE_SSL_KEYLOG_FILE "Write NSS key log file for TLS traffic decryption." OFF)

set(LIB_TYPE "SHARED" CACHE STRING "Type of library to build. Can be SHARED or STATIC")

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
if(BUILD_FOR_OSI)
    set(LIB_DIR "${MSS_DIR}/lib")
endif()
include(MocPlatform)
include(build_rc_file)
project(nanows C)
include(locate_lib)
include(mss_defs)
include(Builder)

builder_print_configuration()

# Flags
builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")
if(CM_ENABLE_DEBUG)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt")
endif()
if(CM_ENABLE_SSL)
    builder_add_flags(MOCANA_FLAGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_ssl_flags.txt")
endif()
if(CM_ENABLE_SSL_KEYLOG_FILE)
    add_definitions(-D__ENABLE_DIGICERT_SSL_KEYLOG_FILE__)
endif()
builder_finalize_flags(MOCANA_FLAGS)
add_definitions(${MOCANA_FLAGS})

builder_finalize_flags(EXTRA_DEFINITIONS)
add_definitions(${EXTRA_DEFINITIONS})

# Includes
builder_add_includes(MOCANA_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt")
builder_finalize_incudes(MOCANA_INCLUDES)
include_directories(${MOCANA_INCLUDES})

# NanoWS library
if(CM_BUILD_NANOWS)
    builder_add_sources(NANOWS_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/nanows/mss_sources.txt")
    builder_finialize_sources(NANOWS_SOURCES)
    add_library(${PROJECT_NAME} ${LIB_TYPE} ${NANOWS_SOURCES})

    if(BUILD_FOR_OSI)
        add_custom_command(
            TARGET ${PROJECT_NAME}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
                $<TARGET_FILE:${PROJECT_NAME}>
                "${LIB_DIR}")
    endif()

    if("SHARED" STREQUAL "${LIB_TYPE}")
        if(CM_ENABLE_SSL)
            builder_add_library_link(NANOWS_LINK_LIBS nanossl)
        endif()
        builder_add_library_link(NANOWS_LINK_LIBS common platform)
        builder_finalize_library_link(NANOWS_LINK_LIBS)
        target_link_libraries(${PROJECT_NAME} ${NANOWS_LINK_LIBS})
    endif()

    builder_finalize_target(${PROJECT_NAME})
endif()
