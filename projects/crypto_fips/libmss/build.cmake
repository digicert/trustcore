#
# Usage: cmake -P build.cmake
#
cmake_minimum_required(VERSION 3.5)

# Get name of CMake file
get_filename_component(CM_CUR_FILE ${CMAKE_CURRENT_LIST_FILE} NAME)

# Defaults
set(CM_BUILD_TYPE "Release")
set(CM_BUILD_ARCH "64")
set(CM_VS_VERSION "2017")

# Add options here
#
#   <build option>\;<help message>\;<cmake option>
#
# Specifying the <cmake option> is optional. If this is left blank then it must
# be handled during the loop where the caller arguments are being processed. If
# it is not empty then whatever is placed there will automatically be appended
# to the cmake build command.
set(CM_BUILD_ARGS
    "--?                                     \;Display help.\;"
    "--gdb                                   \;Build with debug symbols.\;"
    "--static                                \;Build a static library instead of shared.\;-DCM_LIB_TYPE=STATIC"
    "--x64                                   \;Build for 64 bit (x64 is default).\;"
    "--x32                                   \;Build for 32 bit.\;"
    "--vs2010                                \;Build with Visual Studio 2010.\;"
    "--debug                                 \;Build with Mocana debug console logging APIs.\;-DCM_ENABLE_DEBUG=ON"
    "--disable-integ-test                    \;Disable FIPS integrity test.\;-DCM_DISABLE_INTEG_TEST=ON"
    )

# Function to print help menu
function(print_help_menu error_msg)
    message("Usage:")
    message("")
    foreach(CM_ARG ${CM_BUILD_ARGS})
        list(GET CM_ARG 0 CM_CUR_ARG)
        list(GET CM_ARG 1 CM_CUR_ARG_HELP)
        message("  ${CM_CUR_ARG} - ${CM_CUR_ARG_HELP}")
    endforeach()
    message(FATAL_ERROR "${error_msg}")
endfunction()

string(FIND "$ENV{VSINSTALLDIR}" "2019" IS_VS_2019)
if(NOT ${IS_VS_2019} EQUAL -1)
    set(CM_VS_VERSION "2019")
endif()

set(CM_BUILD_CMD "cmake")

set(ARG_NUM 0)

math(EXPR ARGC_COUNT "${CMAKE_ARGC}")

# Loop through caller arguments
while (ARG_NUM LESS ARGC_COUNT)

    set(CURRENT_ARG ${CMAKE_ARGV${ARG_NUM}})

    set(CM_FOUND_ARG OFF)
    foreach(CM_ARG ${CM_BUILD_ARGS})

        list(GET CM_ARG 0 CM_CUR_ARG)
        string(STRIP "${CM_CUR_ARG}" CM_CUR_ARG)

        if("${CURRENT_ARG}" STREQUAL "${CM_CUR_ARG}")
            set(CM_FOUND_ARG ON)
            list(GET CM_ARG 1 CM_CUR_ARG_HELP)
            list(GET CM_ARG 2 CM_CUR_ARG_BUILD_OPTION)

            if("${CM_CUR_ARG_BUILD_OPTION}" STREQUAL "") # Empty string. Handle the argument here.
                if("${CM_CUR_ARG}" STREQUAL "--?")
                    print_help_menu("--? argument provided")
                elseif("${CM_CUR_ARG}" STREQUAL "--x64")
                    set(CM_BUILD_ARCH "64")
                elseif("${CM_CUR_ARG}" STREQUAL "--x32")
                    set(CM_BUILD_ARCH "32")
                elseif("${CM_CUR_ARG}" STREQUAL "--vs2010")
                    set(CM_VS_VERSION "2010")
                elseif("${CM_CUR_ARG}" STREQUAL "--gdb")
                    set(CM_BUILD_TYPE "Debug")
                else()
                    print_help_menu("Error: ${CM_CUR_ARG} option not handled")
                endif()
            else() # String it not empty. Add it as is to the build arguments.
                set(CM_BUILD_CMD ${CM_BUILD_CMD} "${CM_CUR_ARG_BUILD_OPTION}")
            endif()
        endif()

    endforeach()

    # Argument not found. Make sure it isn't anything part or the normal CMake
    # script syntax
    if(NOT CM_FOUND_ARG)
        if("${CURRENT_ARG}" STREQUAL "cmake" OR "${CURRENT_ARG}" STREQUAL "-P" OR "${CURRENT_ARG}" STREQUAL "${CM_CUR_FILE}")
            set(CM_FOUND_ARG ON)
        endif()
    endif()

    if(NOT CM_FOUND_ARG)
        print_help_menu("Unrecognized option: ${CURRENT_ARG}")
    endif()

    # Increment arg count
    math(EXPR ARG_NUM "${ARG_NUM}+1")

endwhile()

# Set any options which couldn't be set during argument processing
if("${CM_VS_VERSION}" STREQUAL "2019")
    set(CM_VS_GENERATOR "Visual Studio 16 2019")
    if("${CM_BUILD_ARCH}" STREQUAL "64")
        set(CM_VS_GENERATOR ${CM_VS_GENERATOR} "-A" "x64")
        set(CM_VS_PLATFORM "x64")
    elseif("${CM_BUILD_ARCH}" STREQUAL "32")
        set(CM_VS_GENERATOR ${CM_VS_GENERATOR} "-A" "Win32")
        set(CM_VS_PLATFORM "Win32")
    endif()
elseif("${CM_VS_VERSION}" STREQUAL "2017")
    set(CM_VS_GENERATOR "Visual Studio 15 2017")
    if("${CM_BUILD_ARCH}" STREQUAL "64")
        set(CM_VS_GENERATOR "${CM_VS_GENERATOR} Win64")
        set(CM_VS_PLATFORM "x64")
    elseif("${CM_BUILD_ARCH}" STREQUAL "32")
        set(CM_VS_PLATFORM "Win32")
    endif()
elseif("${CM_VS_VERSION}" STREQUAL "2010")
    set(CM_VS_GENERATOR "Visual Studio 10 2010")
    if("${CM_BUILD_ARCH}" STREQUAL "64")
        set(CM_VS_GENERATOR "${CM_VS_GENERATOR}" "-A" "x64")
        set(CM_VS_PLATFORM "x64")
    elseif("${CM_BUILD_ARCH}" STREQUAL "32")
        set(CM_VS_GENERATOR "${CM_VS_GENERATOR}" "-A" "Win32")
        set(CM_VS_PLATFORM "Win32")
    endif()
endif()

set(CM_BUILD_CMD ${CM_BUILD_CMD} "-DCMAKE_BUILD_TYPE=${CM_BUILD_TYPE}")
set(CM_BUILD_CMD ${CM_BUILD_CMD} "-G" "${CM_VS_GENERATOR}")

set(CM_BUILD_CMD  ${CM_BUILD_CMD} "..")

set(CM_MSBUILD_CMD "msbuild" "libmss.sln" "/property:Configuration=${CM_BUILD_TYPE}" "/p:Platform=${CM_VS_PLATFORM}")

# Delete build directory
file(REMOVE_RECURSE ${CMAKE_CURRENT_LIST_DIR}/build)

# Create build directory
file(MAKE_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/build)

# Invoke CMake
execute_process(
  COMMAND ${CM_BUILD_CMD}
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/build
  RESULT_VARIABLE rv
)
if(NOT rv EQUAL "0")
  message(FATAL_ERROR "${rv}")
endif()

# Invoke build system
execute_process(
  COMMAND ${CM_MSBUILD_CMD}
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/build
  RESULT_VARIABLE rv
)
if(NOT rv EQUAL "0")
  message(FATAL_ERROR "${rv}")
endif()
