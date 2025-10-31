########################################################################
# CMake build script for DigiCert Common Library
#

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

if(BUILD_FOR_OSI)
  option(CM_ENABLE_DEBUG "Enable Debug logs." ON)
else()
  option(CM_ENABLE_DEBUG "Enable Debug logs." OFF)
endif()
option(CM_ENABLE_FIPS "Build with FIPS enabled." OFF)
if(BUILD_FOR_OSI)
  option(CM_ENABLE_URI "Enable URI ." ON)
else()
  option(CM_ENABLE_URI "Enable URI ." OFF)
endif()
option(CM_ENABLE_MPART "Enable MEM PART ." OFF)
option(CM_ENABLE_MPART_TPLA "Enable MEM PART configured for TPLA." OFF)
option(CM_ENABLE_MEM_PROFILE "Enable Memory Profiling." OFF)
option(CM_DISABLE_MALLOC_LIMIT "Disable malloc limit." OFF)
option(CM_ENABLE_JSON "Enable JSON." OFF)
option(CM_ENABLE_DATA_PROTECT "Enable Data Protect." OFF)
option(CM_ENABLE_DYNAMIC_LOAD "Enable dynamic library loading." OFF)
option(CM_ENABLE_FIPS "Build with FIPS" OFF)
option(CM_DISABLE_MSTDLIB "Disable mstdlib APIs." OFF)
option(CM_DISABLE_CI "Disable crypto interface" OFF)
option(CM_ENABLE_IPV6 "Enable IPV6." OFF)
option(CM_DISABLE_ERROR_CODE_LOOKUP "Disable error code lookup." OFF)
option(CM_ENABLE_BUILD_INFO "Build info." OFF)
option(CM_ENABLE_ARG_PARSER "Argument parser." OFF)
option(CM_ENABLE_MSG_LOG "Message logger." OFF)
option(CM_ENABLE_MSG_LOG_TIMESTAMP "Enable message logger timestamp." OFF)
option(CM_ENABLE_PROTOBUF "Protobuf APIs." OFF)
option(CM_ENABLE_MIME_PARSER "Mime parser APIs." OFF)
option(CM_ENABLE_COMMON_UTILS "Common utility." OFF)
option(CM_ENABLE_VLONG_CONST "Enable vlong const time ops." OFF)
option(CM_BUILD_X32    "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64    "Build for 64Bit Machine." OFF)
if (DEFINED SECURE_PATH)
option(CM_ENABLE_ABSOLUTE_PATH    "Enable absolute path support." ON)
else()
option(CM_ENABLE_ABSOLUTE_PATH    "Enable absolute path support." OFF)
endif()
if(BUILD_FOR_OSI)
  option(CM_ENABLE_POSIX_SUPPORT    "Enable posix support." ON)
else()
  option(CM_ENABLE_POSIX_SUPPORT    "Enable posix support." OFF)
endif()
if (WIN32)
    option(CM_WIN_FORCE_LINKAGE "Force linkage for shared library." OFF)
endif()
option(CM_ENABLE_DEBUG_FORWARD "Enable forwarding Debug logs." OFF)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

# Include cross-compile options/flags
include(MocPlatform)
include(locate_lib)

project(common C)

include(build_rc_file)

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${MSS_DIR}/src")
if(BUILD_FOR_OSI)
  set(LIB_DIR "${MSS_DIR}/lib")
endif()

set(LIB_TYPE "SHARED" CACHE STRING "Type of library to build. (SHARED or STATIC)")
message("LIB_TYPE           = ${LIB_TYPE}")

message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")

if("STATIC" STREQUAL "${LIB_TYPE}")
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
set(COMMON_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${COMMON_BUILD_DIR}/libs")
set(CMAKE_BINARY_DIR "${COMMON_BUILD_DIR}")
set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
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
else()
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
if(NOT BUILD_FOR_OSI)
  configure_file(${MSS_SRC_DIR}/common/tp_version.h.in
                 ${MSS_SRC_DIR}/common/tp_version.h
                 @ONLY)
endif()

## END - Building tp_version.h

# Construct build_info.h
if(CM_ENABLE_BUILD_INFO)
  configure_file(${MSS_SRC_DIR}/common/build_info.h.in
                 ${MSS_SRC_DIR}/common/build_info.h
                 @ONLY)
endif()

message("COMMON_BUILD_DIR = ${COMMON_BUILD_DIR}")

if(NOT EXISTS ${DEFS_FILE})
  message(FATAL_ERROR "\nDEFS_FILE = ${DEFS_FILE} does not exist")
endif()

message("\nDEFS_FILE = ${DEFS_FILE}")
include(${DEFS_FILE})
add_compile_options(${WERROR})

# Initializing common flags

set(MOCANA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")

if(CM_ENABLE_DEBUG)
  set(MOCANA_DEBUG_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_flags.txt")
  message("\nMOCANA_DEBUG_FLAGS_FILE = ${MOCANA_DEBUG_FLAGS_FILE}")
endif()

if(CM_ENABLE_DEBUG_FORWARD)
    set(MOCANA_DEBUG_FORWARD_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_debug_forward_flags.txt")
    message("\nMOCANA_DEBUG_FORWARD_FLAGS_FILE = ${MOCANA_DEBUG_FORWARD_FLAGS_FILE}")
endif()

if(CM_ENABLE_URI)
  set(MOCANA_URI_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/uri/mocana_flags.txt")
  message("\nMOCANA_URI_FLAGS_FILE = ${MOCANA_URI_FLAGS_FILE}")
endif()

if(CM_ENABLE_MPART)
    set(MOCANA_MPART_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_mempart_flags.txt")
    message("\nMOCANA_MPART_FLAGS_FILE = ${MOCANA_MPART_FLAGS_FILE}")
endif()

if(CM_ENABLE_MPART_TPLA AND (NOT CM_BUILD_X32))
    set(MOCANA_MPART_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_mempart_tpla_flags.txt")
    message("\nMOCANA_MPART_FLAGS_FILE = ${MOCANA_MPART_FLAGS_FILE}")
endif()

if(CM_ENABLE_MPART_TPLA AND CM_BUILD_X32)
    set(MOCANA_MPART_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_mempart_tpla_flags_32.txt")
    message("\nMOCANA_MPART_FLAGS_FILE = ${MOCANA_MPART_FLAGS_FILE}")
endif()

if(CM_ENABLE_MEM_PROFILE)
    set(MOCANA_MEM_PROFILE_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_mem_profile_flags.txt")
    message("\nMOCANA_MEM_PROFILE_FLAGS_FILE = ${MOCANA_MEM_PROFILE_FLAGS_FILE}")
endif()

if(CM_DISABLE_MALLOC_LIMIT)
  set(MOCANA_MALLOC_LIMIT_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/malloc/mocana_flags.txt")
  message("\nMOCANA_MALLOC_LIMIT_FLAGS_FILE = ${MOCANA_MALLOC_LIMIT_FLAGS_FILE}")
endif()

if(CM_ENABLE_JSON)
  set(MOCANA_JSON_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/json/mocana_flags.txt")
  message("\nMOCANA_JSON_FLAGS_FILE = ${MOCANA_JSON_FLAGS_FILE}")
endif()

if(CM_ENABLE_DYNAMIC_LOAD)
  set(MOCANA_DL_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/dynamic_load/mocana_flags.txt")
  message("\nMOCANA_DL_FLAGS_FILE = ${MOCANA_DL_FLAGS_FILE}")
endif()

if(CM_ENABLE_DATA_PROTECT)
  set(MOCANA_DP_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/dp/mocana_flags.txt")
  message("\nMOCANA_DP_FLAGS_FILE = ${MOCANA_DP_FLAGS_FILE}")
endif()

if(NOT CM_DISABLE_CI)
  set(MOCANA_CI_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_ci_flags.txt")
  message("\nMOCANA_CI_FLAGS_FILE = ${MOCANA_CI_FLAGS_FILE}")
endif()

if(NOT CM_DISABLE_ERROR_CODE_LOOKUP)
  set(MOCANA_LOOKUP_TABLE_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_lookup_table_flags.txt")
  message("\nMOCANA_LOOKUP_TABLE_FLAGS_FILE = ${MOCANA_LOOKUP_TABLE_FLAGS_FILE}")
endif()

if(CM_ENABLE_BUILD_INFO)
  set(MOCANA_BUILD_INFO_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/build_info/mocana_flags.txt")
  message("\nMOCANA_BUILD_INFO_FLAGS_FILE = ${MOCANA_BUILD_INFO_FLAGS_FILE}")
endif()

if(CM_ENABLE_ARG_PARSER)
  set(MOCANA_ARG_PARSER_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/arg_parser/mocana_flags.txt")
  message("\nMOCANA_ARG_PARSER_FLAGS_FILE = ${MOCANA_ARG_PARSER_FLAGS_FILE}")
endif()

if(CM_ENABLE_MSG_LOG)
  set(MOCANA_MSG_LOG_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/msg_logger/mocana_flags.txt")
  message("\nMOCANA_MSG_LOG_FLAGS_FILE = ${MOCANA_MSG_LOG_FLAGS_FILE}")
endif()

if(CM_ENABLE_PROTOBUF)
  set(MOCANA_PROTOBUF_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/protobuf/mocana_flags.txt")
  message("\nMOCANA_PROTOBUF_FLAGS_FILE = ${MOCANA_PROTOBUF_FLAGS_FILE}")
endif()

if(CM_ENABLE_MIME_PARSER)
  set(MOCANA_MIME_PARSER_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mime_parser/mocana_flags.txt")
  message("\nMOCANA_MIME_PARSER_FLAGS_FILE = ${MOCANA_MIME_PARSER_FLAGS_FILE}")
endif()

if(CM_ENABLE_COMMON_UTILS)
  set(MOCANA_COMMON_UTILS_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/common_utils/mocana_flags.txt")
  message("\nMOCANA_COMMON_UTILS_FLAGS_FILE = ${MOCANA_COMMON_UTILS_FLAGS_FILE}")
endif()

if (CM_ENABLE_VLONG_CONST)
  set(MOCANA_VLONG_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_vlong_flags.txt")
  message("\nMOCANA_VLONG_FLAGS_FILE = ${MOCANA_VLONG_FLAGS_FILE}")
endif()

if(NOT EXISTS ${MOCANA_FLAGS_FILE})
  message(FATAL_ERROR "\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE} does not exist")
endif()

message("\nMOCANA_FLAGS_FILE = ${MOCANA_FLAGS_FILE}")

########################################################################
#
# MOCANA FLAGS
#
########################################################################

file(STRINGS ${MOCANA_FLAGS_FILE} mocana_flags)

if(WIN32)
  set(mocana_flags ${mocana_flags} -DWIN_COMMON_EXPORT)
endif()

# Adding debug flags
if(CM_ENABLE_DEBUG)
  file(STRINGS ${MOCANA_DEBUG_FLAGS_FILE} mocana_debug_flags)
  set(mocana_flags ${mocana_flags} ${mocana_debug_flags})
endif()

if(CM_ENABLE_DEBUG_FORWARD)
  file(STRINGS ${MOCANA_DEBUG_FORWARD_FLAGS_FILE} mocana_debug_forward_flags)
  set(mocana_flags ${mocana_flags} ${mocana_debug_forward_flags})
endif()

if(CM_ENABLE_URI)
  file(STRINGS ${MOCANA_URI_FLAGS_FILE} mocana_uri_flags)
  set(mocana_flags ${mocana_flags} ${mocana_uri_flags})
endif()

if(CM_ENABLE_MPART OR CM_ENABLE_MPART_TPLA)
  file(STRINGS ${MOCANA_MPART_FLAGS_FILE} mocana_mpart_flags)
  set(mocana_flags ${mocana_flags} ${mocana_mpart_flags})
endif()

if(CM_ENABLE_MEM_PROFILE)
  file(STRINGS ${MOCANA_MEM_PROFILE_FLAGS_FILE} mocana_mem_profile_flags)
  set(mocana_flags ${mocana_flags} ${mocana_mem_profile_flags})
endif()

if(CM_DISABLE_MALLOC_LIMIT)
  file(STRINGS ${MOCANA_MALLOC_LIMIT_FLAGS_FILE} mocana_malloc_flags)
  set(mocana_flags ${mocana_flags} ${mocana_malloc_flags})
endif()

if(CM_ENABLE_JSON)
  file(STRINGS ${MOCANA_JSON_FLAGS_FILE} mocana_json_flags)
  set(mocana_flags ${mocana_flags} ${mocana_json_flags})
endif()

if(CM_ENABLE_DYNAMIC_LOAD)
  file(STRINGS ${MOCANA_DL_FLAGS_FILE} mocana_dl_flags)
  set(mocana_flags ${mocana_flags} ${mocana_dl_flags})
endif()

if(CM_ENABLE_DATA_PROTECT)
  file(STRINGS ${MOCANA_DP_FLAGS_FILE} mocana_dp_flags)
  set(mocana_flags ${mocana_flags} ${mocana_dp_flags})
endif()

if(NOT CM_DISABLE_CI)
  file(STRINGS ${MOCANA_CI_FLAGS_FILE} mocana_ci_flags)
  set(mocana_flags ${mocana_flags} ${mocana_ci_flags})
endif()

if(NOT CM_DISABLE_ERROR_CODE_LOOKUP)
  file(STRINGS ${MOCANA_LOOKUP_TABLE_FLAGS_FILE} mocana_lookup_table_flags)
  set(mocana_flags ${mocana_flags} ${mocana_lookup_table_flags})
endif()

if(CM_ENABLE_BUILD_INFO)
  file(STRINGS ${MOCANA_BUILD_INFO_FLAGS_FILE} mocana_build_info_flags)
  set(mocana_flags ${mocana_flags} ${mocana_build_info_flags})
endif()

if(CM_ENABLE_ARG_PARSER)
  file(STRINGS ${MOCANA_ARG_PARSER_FLAGS_FILE} mocana_arg_parser_flags)
  set(mocana_flags ${mocana_flags} ${mocana_arg_parser_flags})
endif()

if(CM_ENABLE_MSG_LOG)
  file(STRINGS ${MOCANA_MSG_LOG_FLAGS_FILE} mocana_msg_log_flags)
  set(mocana_flags ${mocana_flags} ${mocana_msg_log_flags})
endif()

if(CM_ENABLE_PROTOBUF)
  file(STRINGS ${MOCANA_PROTOBUF_FLAGS_FILE} mocana_protobuf_flags)
  set(mocana_flags ${mocana_flags} ${mocana_protobuf_flags})
endif()

if(CM_ENABLE_MIME_PARSER)
  file(STRINGS ${MOCANA_MIME_PARSER_FLAGS_FILE} mocana_mime_parser_flags)
  set(mocana_flags ${mocana_flags} ${mocana_mime_parser_flags})
endif()

if(CM_ENABLE_COMMON_UTILS)
  file(STRINGS ${MOCANA_COMMON_UTILS_FLAGS_FILE} mocana_common_utils_flags)
  set(mocana_flags ${mocana_flags} ${mocana_common_utils_flags})
endif()

if (CM_ENABLE_VLONG_CONST)
  file(STRINGS ${MOCANA_VLONG_FLAGS_FILE} mocana_vlong_flags)
  set(mocana_flags ${mocana_flags} ${mocana_vlong_flags})
endif()

if(CM_ENABLE_FIPS AND CM_DISABLE_MSTDLIB)
  set(mocana_flags ${mocana_flags} -D__DISABLE_MOCANA_MSTD_LIB_DEP__)
endif()

if(CM_ENABLE_IPV6)
  set(mocana_flags ${mocana_flags} -D__ENABLE_MOCANA_IPV6__)
endif()

if(CM_ENABLE_MSG_LOG_TIMESTAMP)
  set(mocana_flags ${mocana_flags} -D__ENABLE_DIGICERT_MSG_LOG_TIMESTAMP__)
endif()

if(CM_ENABLE_POSIX_SUPPORT)
  set(mocana_flags ${mocana_flags} -D__ENABLE_DIGICERT_POSIX_SUPPORT__)
endif()

if(CM_ENABLE_ABSOLUTE_PATH)
  set(mocana_flags ${mocana_flags} -D__ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__)
endif()

if (DEFINED SECURE_PATH)
  set(mocana_flags ${mocana_flags} -D__ENABLE_DIGICERT_SECURE_PATH__)
  message("\nSECURE_PATH = ${SECURE_PATH}")
  add_definitions("-DMANDATORY_BASE_PATH=\"${SECURE_PATH}\"")
endif()

# Now load all flags into MOCANA_FLAGS
foreach(flag ${mocana_flags})
  string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

# Load the flags into the build
message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
add_definitions("${MOCANA_FLAGS}")

# Load the EXTRA_DEFINITIONS flags (from mss_defs.cmake) into the build
message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")
add_definitions("${EXTRA_DEFINITIONS}")

########################################################################
#
# MOCANA INCLUDES
#
########################################################################

# Add include directories defined in mss_includes.txt
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_includes.txt" MSS_INCLUDES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_INCLUDES "${MSS_INCLUDES}")

include_directories("." ${MSS_INCLUDES})

message("\ncommon includes")
message("----------------")
foreach(dir ${MSS_INCLUDES})
  message(${dir})
endforeach()

########################################################################
#
# MOCANA SOURCES
#
########################################################################

# Add file sources from mss_sources.txt
if(BUILD_FOR_OSI)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_osi_sources.txt" MSS_SOURCES)
else()
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt" MSS_SOURCES)
endif()

string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")
if(BUILD_FOR_OSI)
  string(REGEX REPLACE "PARSE_PEM_DIR/" "common/" MSS_SOURCES "${MSS_SOURCES}")
else()
  string(REGEX REPLACE "PARSE_PEM_DIR/" "crypto/" MSS_SOURCES "${MSS_SOURCES}")
endif()

if(WIN32)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_win_sources.txt" MSS_WIN_SOURCES)
  string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_WIN_SOURCES "${MSS_WIN_SOURCES}")
  set(MSS_SOURCES ${MSS_SOURCES} ${MSS_WIN_SOURCES})
endif()

if(CM_ENABLE_JSON)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/json/mss_sources.txt" JSON_SOURCES)
  string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" JSON_SOURCES "${JSON_SOURCES}")
  set(MSS_SOURCES ${MSS_SOURCES} ${JSON_SOURCES})
endif()

if(CM_ENABLE_DYNAMIC_LOAD)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/dynamic_load/mss_sources.txt" DL_SOURCES)
  string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" DL_SOURCES "${DL_SOURCES}")
  set(MSS_SOURCES ${MSS_SOURCES} ${DL_SOURCES})
endif()

if(CM_ENABLE_MEM_PROFILE)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_mem_profile_sources.txt" MEM_PROFILE_SOURCES)
  string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MEM_PROFILE_SOURCES "${MEM_PROFILE_SOURCES}")
  set(MSS_SOURCES ${MSS_SOURCES} ${MEM_PROFILE_SOURCES})
endif()

if(CM_ENABLE_BUILD_INFO)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/build_info/mss_sources.txt" BUILD_INFO_SOURCES)
  string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" BUILD_INFO_SOURCES "${BUILD_INFO_SOURCES}")
  set(MSS_SOURCES ${MSS_SOURCES} ${BUILD_INFO_SOURCES})
endif()

if(CM_ENABLE_ARG_PARSER)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/arg_parser/mss_sources.txt" ARG_PARSER_SOURCES)
  string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" ARG_PARSER_SOURCES "${ARG_PARSER_SOURCES}")
  set(MSS_SOURCES ${MSS_SOURCES} ${ARG_PARSER_SOURCES})
endif()

if(CM_ENABLE_MSG_LOG)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/msg_logger/mss_sources.txt" MSG_LOG_SOURCES)
  string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSG_LOG_SOURCES "${MSG_LOG_SOURCES}")
  set(MSS_SOURCES ${MSS_SOURCES} ${MSG_LOG_SOURCES})
endif()

if(CM_ENABLE_PROTOBUF)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/protobuf/mss_sources.txt" PROTOBUF_SOURCES)
  string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" PROTOBUF_SOURCES "${PROTOBUF_SOURCES}")
  set(MSS_SOURCES ${MSS_SOURCES} ${PROTOBUF_SOURCES})
endif()

if(CM_ENABLE_MIME_PARSER)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mime_parser/mss_sources.txt" MIME_PARSER_SOURCES)
  string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MIME_PARSER_SOURCES "${MIME_PARSER_SOURCES}")
  set(MSS_SOURCES ${MSS_SOURCES} ${MIME_PARSER_SOURCES})
endif()

if(CM_ENABLE_COMMON_UTILS)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/common_utils/mss_sources.txt" COMMON_UTILS_SOURCES)
  string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" COMMON_UTILS_SOURCES "${COMMON_UTILS_SOURCES}")
  set(MSS_SOURCES ${MSS_SOURCES} ${COMMON_UTILS_SOURCES})
endif()

# Set Windows file properties
if(WIN32)
  build_rc_file("TrustPoint Shared Library")
  set(MSS_SOURCES ${MSS_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
endif()

# Remove FIPS files if this is a FIPS build. Must be done last once all
# other source files have been appended to the source list.
if(CM_ENABLE_FIPS)
  include(mss_fips)
  get_fips_source(FIPS_SOURCES)
  string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" FIPS_SOURCES "${FIPS_SOURCES}")
  list(REMOVE_ITEM MSS_SOURCES ${FIPS_SOURCES})
  if(CM_DISABLE_MSTDLIB)
    set(MSS_SOURCES ${MSS_SOURCES} MSS_SRC_DIR/common/mstdlib.c)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")
  endif()
endif()

message("\nmss sources")
message("-----------")
foreach(file ${MSS_SOURCES})
  message(${file})
endforeach()

if(WIN32)
  link_directories(${MSS_SRC_DIR}/../bin_win32)
else()
  link_directories(${MSS_SRC_DIR}/../bin)
endif()

if("SHARED" STREQUAL "${LIB_TYPE}")
  add_library(${PROJECT_NAME} SHARED ${MSS_SOURCES})

  if(BUILD_FOR_OSI)
    add_custom_command(
      TARGET ${PROJECT_NAME}
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy
          $<TARGET_FILE:${PROJECT_NAME}>
          "${LIB_DIR}")
    set(PLATFORM_LIB "${LIB_DIR}/libplatform.so")
  else()
    locate_lib(PLATFORM_LIB platform)
  endif()

  if(CM_ENABLE_FIPS)
    if(WIN32)
      locate_lib(FIPS_LIB libmss)
    else()
      locate_lib(FIPS_LIB mss)
    endif()
  endif()

  set(LIB_LINK_ORDER ${PLATFORM_LIB})
  if(CM_ENABLE_FIPS)
    set(LIB_LINK_ORDER ${LIB_LINK_ORDER} ${FIPS_LIB})
  endif()

  # Dependent libraries for common lib
  if(WIN32)
    locate_lib(NANOCRYPTO_LIB nanocrypto)
    locate_lib(CRYPTO_MW_LIB cryptomw)
    set(LIB_LINK_ORDER
        ${LIB_LINK_ORDER}
        ${NANOCRYPTO_LIB}
        ${CRYPTO_MW_LIB}
        Ws2_32.lib
        Shlwapi.lib)
    target_link_libraries(${PROJECT_NAME} ${LIB_LINK_ORDER})
  elseif(ANDROID)
    set(LIB_LINK_ORDER
        ${LIB_LINK_ORDER}
        log)
    target_link_libraries(${PROJECT_NAME} ${LIB_LINK_ORDER})
  elseif("${CM_TARGET_PLATFORM}" MATCHES "qnx-x86" OR "${CM_TARGET_PLATFORM}" MATCHES "qnx-6-5-x86")
  else()
    target_link_libraries(${PROJECT_NAME} ${LIB_LINK_ORDER} dl)
  endif()

else()
  add_library(${PROJECT_NAME} STATIC ${MSS_SOURCES})
endif()
