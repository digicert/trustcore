# Set mss root directory
set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
# Set mss source directory
set(MSS_SRC_DIR "${MSS_DIR}/src")
# Set mss unittest directory
set(MSS_UNITTEST_DIR "${MSS_DIR}/unit_tests")

# Set paths to output directories
if(WIN32)
    set(MSS_BIN_DIR_OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32")
    set(MSS_BIN_STATIC_DIR_OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_win32_static")
else()
    set(MSS_BIN_DIR_OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
    set(MSS_BIN_STATIC_DIR_OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/../../bin_static")
endif()

# Determine bin directory based on build type
if("STATIC" STREQUAL "${LIB_TYPE}")
    set(MSS_BIN_DIR "${MSS_BIN_STATIC_DIR_OUTPUT}")
    set(LINK_LIBS_IN_BIN_STATIC "ON")
else()
    set(MSS_BIN_DIR "${MSS_BIN_DIR_OUTPUT}")
endif()

# Compile static libraries with position independent code (-fPIC), required for
# converting static archives into shared libraries
if("STATIC" STREQUAL "${LIB_TYPE}")
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# Enable testing
enable_testing()

function(builder_print_configuration)
    message("----------------")
    message("CMAKE_PROJECT_NAME = ${CMAKE_PROJECT_NAME}")
    message("CMAKE_BUILD_TYPE   = ${CMAKE_BUILD_TYPE}")
    message("LIB_TYPE           = ${LIB_TYPE}")
    message("MSS_DIR            = ${MSS_DIR}")
    message("MSS_SRC_DIR        = ${MSS_SRC_DIR}")
endfunction()

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

function(builder_add_includes INCLUDE_VAR)
    message("----------------")
    foreach(INCLUDE_FILE IN LISTS ARGN)
        message("${INCLUDE_VAR} - adding includes in ${INCLUDE_FILE}")
        file(STRINGS ${INCLUDE_FILE} INCLUDES_TO_ADD)
        string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" INCLUDES_TO_ADD "${INCLUDES_TO_ADD}")
        set(INCLUDE_LIST ${INCLUDE_LIST} ${INCLUDES_TO_ADD})
    endforeach()
    set(${INCLUDE_VAR} ${${INCLUDE_VAR}} ${INCLUDE_LIST} PARENT_SCOPE)
endfunction()

function(builder_finalize_incudes INCLUDE_VAR)
    message("----------------")
    message("${INCLUDE_VAR} =")
    foreach(INCLUDE ${${INCLUDE_VAR}})
        message("${INCLUDE}")
    endforeach()
endfunction()

function(builder_add_sources SOURCES_VAR)
    message("----------------")
    foreach(SOURCE_FILE IN LISTS ARGN)
        message("${SOURCES_VAR} - adding sources in ${SOURCE_FILE}")
        file(STRINGS ${SOURCE_FILE} SOURCES_TO_ADD)
        string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" SOURCES_TO_ADD "${SOURCES_TO_ADD}")
        set(SOURCE_LIST ${SOURCE_LIST} ${SOURCES_TO_ADD})
    endforeach()
    set(${SOURCES_VAR} ${${SOURCES_VAR}} ${SOURCE_LIST} PARENT_SCOPE)
endfunction()

function(builder_finialize_sources SOURCES_VAR)
    message("----------------")
    message("${SOURCES_VAR} =")
    foreach(SOURCE ${${SOURCES_VAR}})
        message("${SOURCE}")
    endforeach()
endfunction()

function(builder_add_library_link LINK_VAR)
    message("----------------")
    foreach(LINK_LIB IN LISTS ARGN)
        message("${LINK_VAR} - linking against ${LINK_LIB}")
        locate_lib(CUR_LINK_LIB ${LINK_LIB})
        set(LINK_LIST ${LINK_LIST} ${CUR_LINK_LIB})
    endforeach()
    set(${LINK_VAR} ${${LINK_VAR}} ${LINK_LIST} PARENT_SCOPE)
endfunction()

function(builder_add_library_link_static LINK_VAR)
    set(LIB_TYPE "STATIC")
    set(LINK_LIBS_IN_BIN_STATIC "ON")
    message("----------------")
    foreach(LINK_LIB IN LISTS ARGN)
        message("${LINK_VAR} - linking against ${LINK_LIB}")
        locate_lib(CUR_LINK_LIB ${LINK_LIB})
        set(LINK_LIST ${LINK_LIST} ${CUR_LINK_LIB})
    endforeach()
    set(${LINK_VAR} ${${LINK_VAR}} ${LINK_LIST} PARENT_SCOPE)
endfunction()

function(builder_finalize_library_link LINK_VAR)
    message("----------------")
    message("${LINK_VAR} =")
    foreach(LINK ${${LINK_VAR}})
        message("${LINK}")
    endforeach()
endfunction()

function(builder_finalize_target)
    message("----------------")
    foreach(CUR_TARGET IN LISTS ARGN)
        get_target_property(TARGET_TYPE ${CUR_TARGET} TYPE)
        if(TARGET_TYPE STREQUAL "EXECUTABLE")
            message("${CUR_TARGET} - Finalizing executable")
        else()
            message("${CUR_TARGET} - Finalizing library")
        endif()
        add_custom_command(
            TARGET ${CUR_TARGET}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
                $<TARGET_FILE:${CUR_TARGET}>
                ${MSS_BIN_DIR})
    endforeach()
endfunction()

function(builder_add_test_sources CUR_TARGET)
    get_target_property(TARGET_TYPE ${CUR_TARGET} TYPE)
    if(TARGET_TYPE STREQUAL "EXECUTABLE")
        message(ERROR "Target ${CUR_TARGET} is of type ${TARGET_TYPE}. Must be library")
    endif()
    message("----------------")
    # Modify the target output with test suffix
    set_property(TARGET ${CUR_TARGET} PROPERTY OUTPUT_NAME ${CUR_TARGET}_test)
    target_compile_options(${CUR_TARGET} PRIVATE "-D__ENABLE_MOCANA_UNITTEST__")
    # Add _unittest suffix to sources
    get_target_property(CUR_TARGET_SOURCES ${CUR_TARGET} SOURCES)
    set(UNITTEST_SOURCES "")
    foreach(SRC_FILE ${CUR_TARGET_SOURCES})
        string(REPLACE ".c" "_unittest.c" UNITTEST_SRC_FILE "${SRC_FILE}")
        if(EXISTS "${UNITTEST_SRC_FILE}")
            list(APPEND UNITTEST_SOURCES "${UNITTEST_SRC_FILE}")
        else()
            list(APPEND UNITTEST_SOURCES "${SRC_FILE}")
        endif()
    endforeach()
    set_target_properties(${CUR_TARGET} PROPERTIES SOURCES "${UNITTEST_SOURCES}")
endfunction()

function(builder_add_test CUR_TARGET TEST_TARGET TEST_MAIN)
    # Create test executable target
    add_executable(${TEST_TARGET} ${TEST_MAIN} ../../unit_tests/unittest.c)
    target_compile_options(${TEST_TARGET} PRIVATE "-D__ENABLE_MOCANA_UNITTEST__")

    find_library(JANSSON_LIB jansson)
    if(JANSSON_LIB)
        message(STATUS "Jansson library found: ${JANSSON_LIB}")
        target_link_libraries(${TEST_TARGET} PRIVATE ${CUR_TARGET} ${JANSSON_LIB})
    else()
        target_link_libraries(${TEST_TARGET} PRIVATE ${CUR_TARGET})
    endif()

    add_test(
        NAME ${TEST_TARGET}
        COMMAND ${MSS_BIN_DIR}/${TEST_TARGET}
        WORKING_DIRECTORY ${MSS_DIR})
    builder_finalize_target(${TEST_TARGET})
endfunction()
