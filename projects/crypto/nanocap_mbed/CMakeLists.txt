########################################################################
# CMake build script for nanocap_mbed library
########################################################################

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

project(nanocap_mbed C)

########################################################################
#
# SET MBED LIBRARY OPTIONS
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

if(DEFINED CM_MBED_PATH)

    # If this is a relative path, convert it to an absolute
    if (NOT WIN32)
        get_filename_component(CM_MBED_PATH "${CM_MBED_PATH}" ABSOLUTE)
    endif()

    message("\nCM_MBED_PATH = ${CM_MBED_PATH}\n")

    # Find out if the path provided ended with a '/', and remove it if so
    if(WIN32)
        set(ENDING_SLASH "\\$")
    else()
        set(ENDING_SLASH "/$")
    endif()

    if("${CM_MBED_PATH}" MATCHES ${ENDING_SLASH})
        string(REGEX REPLACE ${ENDING_SLASH} "" CM_MBED_PATH "${CM_MBED_PATH}")
    endif()

    if(WIN32)
        set(MBED_ALL_LIBS_NAMES "mbedTLS.dll" "mbedTLS.lib")
    else()
        set(MBED_ALL_LIBS_NAMES "libmbedcrypto.${LIB_SUFFIX}"
                                "libmbedtls.${LIB_SUFFIX}"
                                "libmbedx509.${LIB_SUFFIX}")
    endif()

    if(BUILD_FOR_OSI)
        set(TARGET_LIB_DIR "${MSS_DIR}/lib")
    else()
        set(TARGET_LIB_DIR "${MSS_BIN_DIR}")
    endif()

    get_filename_component(bin_dir "${TARGET_LIB_DIR}" ABSOLUTE)

    message("mbed libs not found in ${bin_dir}, now checking ${CM_MBED_PATH}\n")

    set(mbed_libs_path)
    foreach(lib ${MBED_ALL_LIBS_NAMES})
        if (WIN32)
            # Visual Studio builds into 'Debug' and 'Release' subdirectories
            if (CM_BUILD_X64)
                set(mbed_libs_path ${mbed_libs_path} ${CM_MBED_PATH}/visualc/VS2010/x64/${CMAKE_BUILD_TYPE}/${lib})
            else ()
                set(mbed_libs_path ${mbed_libs_path} ${CM_MBED_PATH}/visualc/VS2010/${CMAKE_BUILD_TYPE}/${lib})
            endif()
        else()
            set(mbed_libs_path ${mbed_libs_path} ${CM_MBED_PATH}/library/${lib})
        endif()
    endforeach()

    # If any of the libs are not in the provided mbed-path either, that's a fatal
    # error and the user must build these themselves
    message("Looking for these mbed libs:")
    foreach(lib ${mbed_libs_path})
        message("${lib}")
        if(NOT EXISTS ${lib})
            get_filename_component(lib_name "${lib}" NAME)
            message(FATAL_ERROR "Could not find a needed mbed library (${lib_name}) in either \
                             ${bin_dir} or ${CM_MBED_PATH}/library")
        endif()
    endforeach()

    message("\nAll mbed libs found! Copying to ${bin_dir}\n")

    # If we've gotten to here, the mbed libs are located within the mbed-path,
    # so copy them to MSS_BIN_DIR
    foreach(lib ${mbed_libs_path})

        # Get all the versions of this lib
        file(GLOB LIB_ALL_VERSIONS "${lib}*")

        # Get just the filename of the lib
        get_filename_component(lib_name "${lib}" NAME)

        # Copy the lib from its original directory to MSS_BIN_DIR
        if(APPLE)
          file(COPY ${LIB_ALL_VERSIONS} DESTINATION ${MSS_BIN_DIR} FOLLOW_SYMLINK_CHAIN)
        else()
          file(COPY ${LIB_ALL_VERSIONS} DESTINATION ${TARGET_LIB_DIR})
        endif()

        message("Copying ${lib} to ${bin_dir}/${lib_name}")
    endforeach()

    # Build the path to these mbed libs
    set(MBED_ALL_LIBS_PATHS)
    foreach(lib ${MBED_ALL_LIBS_NAMES})
        set(MBED_ALL_LIBS_PATHS ${MBED_ALL_LIBS_PATHS} ${TARGET_LIB_DIR}/${lib})
    endforeach()

    # Sanity check to make sure all mbed libs have been moved to MSS_BIN_DIR
    foreach(lib ${MBED_ALL_LIBS_PATHS})
        if(NOT EXISTS ${lib})
            message(FATAL_ERROR "${lib} not found.")
        endif()
    endforeach()

    include_directories(${CM_MBED_PATH}/include)

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
    if(BUILD_FOR_OSI)
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
    link_directories(${MSS_SRC_DIR}/../bin_win32)
else()
    if(BUILD_FOR_OSI)
        link_directories(${MSS_SRC_DIR}/../lib)
    else()
        link_directories(${MSS_SRC_DIR}/../bin)
    endif()
endif()

if("SHARED" STREQUAL "${LIB_TYPE}")
  add_library(${PROJECT_NAME} SHARED ${MSS_SOURCES})

  locate_lib(ASN1_LIB asn1)
  if(WIN32)
      locate_lib(MSS_COMMON_LIB common)
      locate_lib(MSS_NANNOCAP_LIB nanocap)
      locate_lib(MBED_TLS_LIB mbedTLS)
  else()
      locate_lib(MBED_CRYPTO_LIB mbedcrypto)
      locate_lib(MBED_TLS_LIB mbedtls)
      locate_lib(MBED_X509_LIB mbedx509)
      if(ANDROID)
          locate_lib(MSS_COMMON_LIB common)
          locate_lib(MSS_NANNOCAP_LIB nanocap)
      endif()
  endif()

  target_link_libraries(${PROJECT_NAME} ${ASN1_LIB}
                                        ${MBED_CRYPTO_LIB} ${MBED_TLS_LIB}
                                        ${MBED_X509_LIB})

  if(WIN32)
    target_link_libraries(${PROJECT_NAME} ${MSS_COMMON_LIB} ${MSS_NANNOCRYPTO_LIB} ${MSS_NANNOCAP_LIB} ${MSS_PLATFORM_LIB} Shlwapi.lib Ws2_32.lib tbs.lib)
  endif()
  if(ANDROID)
    target_link_libraries(${PROJECT_NAME} ${MSS_COMMON_LIB} ${MSS_NANNOCAP_LIB})
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

if(BUILD_FOR_OSI)
    add_custom_command(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
            $<TARGET_FILE:${PROJECT_NAME}>
            "${MSS_DIR}/lib")
endif()