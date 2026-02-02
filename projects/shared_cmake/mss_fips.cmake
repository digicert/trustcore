########################################################################
#
# CMake helper script for fips builds
#
########################################################################

function(get_fips_source FIPS_SOURCES)

    if(NOT DEFINED MSS_DIR)
        message(FATAL_ERROR "MSS_DIR not defined, which is needed by get_fips_source")
    endif()

    set(FIPS_PROJECT_DIR ${MSS_DIR}/projects/crypto/fips)

    # List of .txt containing fips sources
    set(FIPS_SOURCES_TXT
        ${FIPS_PROJECT_DIR}/common_sources.txt
        ${FIPS_PROJECT_DIR}/crypto_sources.txt
        ${FIPS_PROJECT_DIR}/platform_sources.txt
        ${FIPS_PROJECT_DIR}/rng_sources.txt
        ${FIPS_PROJECT_DIR}/vlong_sources.txt)

    set(REAL_FIPS_PROJECT_DIR ${MSS_DIR}/projects/fips)

    # Only check if the fips files are in sync if the fips directory exists
    if(EXISTS ${REAL_FIPS_PROJECT_DIR})
        # List of .txt containing real fips sources
        set(REAL_FIPS_SOURCES_TXT
            ${REAL_FIPS_PROJECT_DIR}/common_sources.txt
            ${REAL_FIPS_PROJECT_DIR}/crypto_sources.txt
            ${REAL_FIPS_PROJECT_DIR}/platform_sources.txt
            ${REAL_FIPS_PROJECT_DIR}/rng_sources.txt
            ${REAL_FIPS_PROJECT_DIR}/vlong_sources.txt)

        list(LENGTH FIPS_SOURCES_TXT FIPS_FILE_COUNT_TMP)
        math(EXPR FIPS_FILE_COUNT "${FIPS_FILE_COUNT_TMP} - 1")

        message("\nfips sync check")
        message("----------------")

        # Loop through and ensure the fips files are in sync
        foreach(FIPS_FILE_ITER RANGE ${FIPS_FILE_COUNT})
            list(GET FIPS_SOURCES_TXT ${FIPS_FILE_ITER} CUR_FIPS_SRC)
            list(GET REAL_FIPS_SOURCES_TXT ${FIPS_FILE_ITER} CUR_REAL_FIPS_SRC)

            execute_process(
                COMMAND ${CMAKE_COMMAND} -E compare_files ${CUR_FIPS_SRC} ${CUR_REAL_FIPS_SRC}
                RESULT_VARIABLE FIPS_CMP_RESULT
            )

            if(FIPS_CMP_RESULT EQUAL 0)
                message("${CUR_FIPS_SRC} and ${CUR_REAL_FIPS_SRC} match")
            elseif(FIPS_CMP_RESULT EQUAL 1)
                message(FATAL_ERROR "${CUR_FIPS_SRC} and ${CUR_REAL_FIPS_SRC} are not in sync")
            else()
                message(FATAL_ERROR "Error while comparing files ${CUR_FIPS_SRC} and ${CUR_REAL_FIPS_SRC}")
            endif()

        endforeach()
    endif()


    # Loop through each file and get the list of sources
    foreach(CUR_TXT_FILE ${FIPS_SOURCES_TXT})
        file(STRINGS ${CUR_TXT_FILE} CUR_SOURCES)
        set(FIPS_SOURCES_FILES ${FIPS_SOURCES_FILES} ${CUR_SOURCES})
    endforeach()

    # AES-NI not available from in text file. Add to list directly (Any file
    # which are not added to text files must also be added here).
    set(FIPS_SOURCES_FILES ${FIPS_SOURCES_FILES} MSS_SRC_DIR/crypto/aesalgo_intel_ni.c)

    # Allow debug_console.c to be built as part of other libraries.
    list(REMOVE_ITEM FIPS_SOURCES_FILES MSS_SRC_DIR/common/debug_console.c)

    # Set the list of FIPS sources so whoever invoked this function can use it
    set(FIPS_SOURCES ${FIPS_SOURCES_FILES} PARENT_SCOPE)

endfunction()

function(get_fips_flags FIPS_FLAGS)
    if(NOT DEFINED MSS_DIR)
        message(FATAL_ERROR "MSS_DIR not defined, which is needed by get_fips_flags")
    endif()

    set(FIPS_LIBMSS_FLAGS ${MSS_DIR}/projects/crypto/fips/flags.txt)

    # Loop through each file and get the list of flags
    file(STRINGS ${FIPS_LIBMSS_FLAGS} FIPS_FLAG_LIST)
    set(FIPS_FLAGS)
    foreach(flag ${FIPS_FLAG_LIST})
      set(FIPS_FLAGS "${FIPS_FLAGS} ${flag}")
    endforeach()

    # Set the list of FIPS flags so whoever invoked this function can use it
    set(FIPS_FLAGS "${FIPS_FLAGS}" PARENT_SCOPE)

endfunction()
