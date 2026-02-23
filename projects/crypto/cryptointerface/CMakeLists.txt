########################################################################
# CMake build script for cryptointerface library
########################################################################

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

project(cryptointerface C)

# Load options flags
message("\nOPTIONS_MOCANA_FLAGS = ${OPTIONS_MOCANA_FLAGS}")
add_definitions(${OPTIONS_MOCANA_FLAGS})

# Load the EXTRA_DEFINITIONS flags (from mss_defs.cmake) into the build
message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")
add_definitions("${EXTRA_DEFINITIONS}")
add_compile_options(${WERROR})

########################################################################
#
# MOCANA SOURCES
#
########################################################################

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt" MSS_SOURCES)

if("STATIC" STREQUAL "${LIB_TYPE}")
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

if(CM_ENABLE_TAP)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_tap_sources.txt" MSS_TAP_SOURCES)
    set(MSS_SOURCES ${MSS_SOURCES} ${MSS_TAP_SOURCES})
endif()

# Remove any possible duplicates
list(REMOVE_DUPLICATES MSS_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")

# Set Windows file properties
if(WIN32)
  build_rc_file("TrustPoint Shared Library")
  set(MSS_SOURCES ${MSS_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
endif()

message("\nmss sources")
message("-----------")
foreach(file ${MSS_SOURCES})
    message(${file})
endforeach()

if(NOT WIN32)
    if (BUILD_FOR_OSI)
        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${MSS_DIR}/lib")
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${MSS_DIR}/lib")
    else()
      if("STATIC" STREQUAL "${LIB_TYPE}")
          set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${MSS_DIR}/bin_static")
      else()
          set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${MSS_DIR}/bin")
      endif()
      set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${MSS_DIR}/bin")
    endif()
endif()

if(WIN32)
    if("STATIC" STREQUAL "${LIB_TYPE}")
        set(BIN_WIN32_OUTPUT bin_win32_static)
    else()
        set(BIN_WIN32_OUTPUT bin_win32)
        link_directories(${MSS_SRC_DIR}/../bin_win32)
    endif()
else()
    link_directories(${MSS_SRC_DIR}/../bin)
endif()

if(CM_ENABLE_OPERATORS)
  if("${CM_OPERATOR_PATH}" STREQUAL "")
    message(FATAL_ERROR "operator option is enabled but no path has been provided")
  endif()

  # If this is a relative path, convert it to an absolute
  if(NOT IS_ABSOLUTE ${CM_OPERATOR_PATH})
    get_filename_component(CM_OPERATOR_PATH "${CM_OPERATOR_PATH}" ABSOLUTE)
  endif()

  # Check if it exists
  if(NOT EXISTS "${CM_OPERATOR_PATH}")
    message(FATAL_ERROR "Operator library not found.")
  endif()

  add_library(OP_LIB STATIC IMPORTED)
  set_property(TARGET OP_LIB PROPERTY IMPORTED_LOCATION ${CM_OPERATOR_PATH}})
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
    set(ASN1_LIB "${LIB_DIR}/libasn1.so")
    set(COMMON_LIB "${LIB_DIR}/libcommon.so")
    if(CM_ENABLE_MBED)
      set(NANOCRYPTO_LIB "${LIB_DIR}/libcryptomw.so")
    else()
      set(NANOCRYPTO_LIB "${LIB_DIR}/libnanocrypto.so")
    endif()
    set(NANOCAP_LIB "${LIB_DIR}/libnanocap.so")
  else()
    # Get the full path to our base libraries
    # Note: If library is not found, variable will be empty.
    locate_lib(ASN1_LIB asn1)
    locate_lib(COMMON_LIB common)
    if(CM_ENABLE_MBED)
      locate_lib(NANOCRYPTO_LIB cryptomw)
    else()
      locate_lib(NANOCRYPTO_LIB nanocrypto)
    endif()
    locate_lib(NANOCAP_LIB nanocap)
  endif()

    locate_lib(NANOCERT_LIB nanocert)
    locate_lib(NANOCAP_MBED_LIB nanocap_mbed)
    locate_lib(NANOTAP2_LIB nanotap2)
    locate_lib(TAP_EXTERN_LIB tap_extern)
    locate_lib(NANOTAP2_COMMON_LIB nanotap2_common)
    locate_lib(NANOCAP_OQS_LIB nanocap_oqs)
    locate_lib(HW_ACCEL_LIB hw)
    if(CM_ENABLE_FIPS)
        if(WIN32)
          locate_lib(FIPS_LIB libmss)
        else()
          locate_lib(FIPS_LIB mss)
        endif()
    endif()

    set(LIBS_TO_LINK ${NANOCAP_LIB} ${NANOCERT_LIB} ${NANOCRYPTO_LIB} ${OP_LIB}
                     ${ASN1_LIB} ${COMMON_LIB} ${HW_ACCEL_LIB})

    if(CM_ENABLE_MBED)
        set(LIBS_TO_LINK ${LIBS_TO_LINK} ${NANOCAP_MBED_LIB})
    endif()

    if(CM_ENABLE_TAP)
        set(LIBS_TO_LINK ${NANOTAP2_LIB} ${LIBS_TO_LINK})
    endif()

    if(CM_ENABLE_TAP_EXTERN)
        set(LIBS_TO_LINK ${LIBS_TO_LINK} ${TAP_EXTERN_LIB})
    endif()

    if(CM_ENABLE_OQS)
        set(LIBS_TO_LINK ${LIBS_TO_LINK} ${NANOCAP_OQS_LIB})
    endif()

    if(CM_ENABLE_FIPS)
        set(LIBS_TO_LINK ${LIBS_TO_LINK} ${FIPS_LIB})
    endif()

    if (WIN32 OR ANDROID)
        set(LIBS_TO_LINK ${LIBS_TO_LINK} ${NANOTAP2_COMMON_LIB})
	if(WIN32)
            set(LIBS_TO_LINK ${LIBS_TO_LINK} Shlwapi.lib Ws2_32.lib)
        endif()
    endif()

    target_link_libraries(${PROJECT_NAME} ${LIBS_TO_LINK})
else()
    add_library(${PROJECT_NAME} STATIC ${MSS_SOURCES})
endif()

if(WIN32 AND CM_WIN_FORCE_LINKAGE)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/FORCE:UNRESOLVED")
endif()

if(WIN32)
    add_custom_command(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            $<TARGET_FILE_DIR:${PROJECT_NAME}>
            ${MSS_DIR}/${BIN_WIN32_OUTPUT})
endif()
