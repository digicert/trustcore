########################################################################
# CMake build script for nanocap_oqs library
########################################################################

cmake_minimum_required(VERSION 3.5)

project(nanocap_oqs C)

########################################################################
#
# SET OQS LIBRARY OPTIONS
#
########################################################################

if("${LIB_TYPE}" STREQUAL "STATIC")
    set(LIB_SUFFIX "a")
    set (MSS_BIN_DIR "${MSS_BIN_DIR}/../bin_static")
else()
    set(LIB_SUFFIX "so")
    if(APPLE)
        set(LIB_SUFFIX "dylib")
    endif()
endif()

if(DEFINED CM_OQS_PATH)

    # If this is a relative path, convert it to an absolute
    if (NOT WIN32)
        get_filename_component(CM_OQS_PATH "${CM_OQS_PATH}" ABSOLUTE)
    endif()

    message("\nCM_OQS_PATH = ${CM_OQS_PATH}\n")

    # Find out if the path provided ended with a '/', and remove it if so
    if(WIN32)
        set(ENDING_SLASH "\\$")
    else()
        set(ENDING_SLASH "/$")
    endif()

    if("${CM_OQS_PATH}" MATCHES ${ENDING_SLASH})
        string(REGEX REPLACE ${ENDING_SLASH} "" CM_OQS_PATH "${CM_OQS_PATH}")
    endif()

    if(WIN32)
        set(OQS_ALL_LIBS_NAMES "oqs.dll" "oqs.lib")
    else()
        set(OQS_ALL_LIBS_NAMES "liboqs.${LIB_SUFFIX}")
    endif()

    get_filename_component(bin_dir "${MSS_BIN_DIR}" ABSOLUTE)

    set(oqs_libs_path)
    if(WIN32)
      set(oqs_libs_path ${CM_OQS_PATH}/build/lib/oqs.lib ${CM_OQS_PATH}/build/lib/oqs.exp ${CM_OQS_PATH}/build/bin/oqs.dll)
    else()
      set(oqs_libs_path ${CM_OQS_PATH}/build/lib/liboqs.${LIB_SUFFIX})
    endif()

    # If any of the libs are not in the provided oqs-path either, that's a fatal
    # error and the user must build these themselves
    message("Looking for these oqs libs:")
    foreach(lib ${oqs_libs_path})
        message("${lib}")
        if(NOT EXISTS ${lib})
            get_filename_component(lib_name "${lib}" NAME)
            message(FATAL_ERROR "Could not find a needed oqs library (${lib_name}) in ${CM_OQS_PATH}/build")
        endif()
    endforeach()

    message("\nAll oqs libs found! Copying to ${bin_dir}\n")

    # If we've gotten to here, the oqs libs are located within the oqs-path,
    # so copy them to MSS_BIN_DIR
    foreach(lib ${oqs_libs_path})

        # Get all the versions of this lib
        file(GLOB LIB_ALL_VERSIONS "${lib}*")

        # Get just the filename of the lib
        get_filename_component(lib_name "${lib}" NAME)

        # Copy the lib from its original directory to MSS_BIN_DIR
        file(COPY ${LIB_ALL_VERSIONS} DESTINATION ${MSS_BIN_DIR})

        message("Copying ${lib} to ${bin_dir}/${lib_name}")
    endforeach()

    # Build the path to these oqs libs
    set(OQS_ALL_LIBS_PATHS)
    foreach(lib ${OQS_ALL_LIBS_NAMES})
        set(OQS_ALL_LIBS_PATHS ${OQS_ALL_LIBS_PATHS} ${MSS_BIN_DIR}/${lib})
    endforeach()

    # Sanity check to make sure all oqs libs have been moved to MSS_BIN_DIR
    foreach(lib ${OQS_ALL_LIBS_PATHS})
        if(NOT EXISTS ${lib})
            message(FATAL_ERROR "${lib} not found.")
        endif()
    endforeach()

endif()

# Load options flags
message("\nOPTIONS_MOCANA_FLAGS = ${OPTIONS_MOCANA_FLAGS}")
add_definitions(${OPTIONS_MOCANA_FLAGS})

# Load the EXTRA_DEFINITIONS flags (from mss_defs.cmake) into the build
message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")
add_definitions("${EXTRA_DEFINITIONS}")

########################################################################
#
# MOCANA SOURCES
#
########################################################################

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt" MSS_SOURCES)

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
    if("STATIC" STREQUAL "${LIB_TYPE}")
        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${MSS_DIR}/bin_static")
    else()
        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${MSS_DIR}/bin")
    endif()
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${MSS_DIR}/bin")
endif()

if(WIN32)
    link_directories(${MSS_SRC_DIR}/../bin_win32)
else()
    link_directories(${MSS_SRC_DIR}/../bin)
endif()

if("SHARED" STREQUAL "${LIB_TYPE}")
  add_library(${PROJECT_NAME} SHARED ${MSS_SOURCES})

  locate_lib(ASN1_LIB asn1)
  if(WIN32)
      locate_lib(MSS_COMMON_LIB common)
      locate_lib(MSS_NANNOCAP_LIB nanocap)
      locate_lib(OQS_LIB oqs)
  else()
      locate_lib(OQS_LIB oqs)
  endif()

  target_link_libraries(${PROJECT_NAME} ${ASN1_LIB} ${OQS_LIB})

  if(WIN32)
    target_link_libraries(${PROJECT_NAME} ${MSS_COMMON_LIB} ${MSS_NANNOCRYPTO_LIB} ${MSS_NANNOCAP_LIB} ${MSS_PLATFORM_LIB} Shlwapi.lib Ws2_32.lib tbs.lib)
  endif()

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
            ${MSS_DIR}/bin_win32)
endif()
