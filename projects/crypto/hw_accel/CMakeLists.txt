########################################################################
# CMake build script for cryptointerface library
########################################################################

cmake_minimum_required(VERSION 3.5)

project(hw C)

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

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/custom_sources.txt" MSS_SOURCES)

# Remove any possible duplicates
list(REMOVE_DUPLICATES MSS_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")

message("\ncustom sources")
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

    # Get the full path to our base libraries
    # Note: If library is not found, variable will be empty.
    locate_lib(ASN1_LIB asn1)
    locate_lib(COMMON_LIB common)
    if(CM_ENABLE_MBED)
      locate_lib(NANOCRYPTO_LIB cryptomw)
    else()
      locate_lib(NANOCRYPTO_LIB nanocrypto)
    endif()
    locate_lib(NANOCERT_LIB nanocert)
    locate_lib(NANOCAP_LIB nanocap)
    locate_lib(NANOCAP_MBED_LIB nanocap_mbed)

    set(LIBS_TO_LINK ${NANOCAP_LIB} ${NANOCERT_LIB} ${NANOCRYPTO_LIB}
                     ${ASN1_LIB} ${COMMON_LIB} ${HW_ACCEL_LIB})


    if (WIN32)
        set(LIBS_TO_LINK ${LIBS_TO_LINK} ${NANOTAP2_COMMON_LIB})
        set(LIBS_TO_LINK ${LIBS_TO_LINK} Shlwapi.lib Ws2_32.lib)
    endif()

    target_link_libraries(${PROJECT_NAME} ${LIBS_TO_LINK})
else()
    add_library(${PROJECT_NAME} STATIC ${MSS_SOURCES})
endif()

file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/custom_flags.txt HW_ACCEL_FLAGS)
target_compile_definitions(${PROJECT_NAME} PRIVATE ${HW_ACCEL_FLAGS})

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
