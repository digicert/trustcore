cmake_minimum_required(VERSION 3.5)

# Defaults
set(CM_BUILD_TYPE "Release")
set(CM_BUILD_ARCH "64")
set(CM_VS_VERSION "2017")

function(show_usage)
    message("Build digiprov test")
    message("./build.bat")
    message("OPTIONS:")
    message("   --help      - Build options information")
    message("   --gdb       - Build a Debug version (Release is default)")
    message("   --debug     - Build with Mocana logging enabled")
    message("   --tpm2      - Build examples for TPM2")
    message("   --pkcs11    - Build examples for PKCS11")
    message("   --x32       - Creates build for 32Bit machine")
    message("   --x64       - Creates build for 64Bit machine (default)")
    message(FATAL_ERROR "")
endfunction()

string(FIND "$ENV{VSINSTALLDIR}" "2019" IS_VS_2019)
if(NOT ${IS_VS_2019} EQUAL -1)
    set(CM_VS_VERSION "2019")
endif()

message("Building digiprov test.")

set(CM_BUILD_CMD "cmake")

# Skip first 3 arguments - (cmake -P <file>)
set(ARG_NUM 3)

math(EXPR ARGC_COUNT "${CMAKE_ARGC}")

# Loop through caller arguments
while (ARG_NUM LESS ARGC_COUNT)

    set(CURRENT_ARG ${CMAKE_ARGV${ARG_NUM}})

    if("${CURRENT_ARG}" STREQUAL "--help")
        show_usage()
    elseif("${CURRENT_ARG}" STREQUAL "--gdb")
        set(CM_BUILD_TYPE "Debug")
    elseif("${CURRENT_ARG}" STREQUAL "--debug")
       set(CM_BUILD_CMD ${CM_BUILD_CMD} "-DCM_ENABLE_DEBUG=ON")
    elseif("${CURRENT_ARG}" STREQUAL "--tpm2")
       set(CM_BUILD_CMD ${CM_BUILD_CMD} "-DCM_ENABLE_TPM2=ON")
    elseif("${CURRENT_ARG}" STREQUAL "--pkcs11")
       set(CM_BUILD_CMD ${CM_BUILD_CMD} "-DCM_ENABLE_PKCS11=ON")
    elseif("${CURRENT_ARG}" STREQUAL "--x64")
        set(CM_BUILD_ARCH "64")
    elseif("${CURRENT_ARG}" STREQUAL "--x32")
        set(CM_BUILD_ARCH "32")
    else()
        message("Invalid option: ${CURRENT_ARG}")
        show_usage()
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
endif()

set(CM_BUILD_CMD ${CM_BUILD_CMD} "-DCMAKE_BUILD_TYPE=${CM_BUILD_TYPE}")
set(CM_BUILD_CMD ${CM_BUILD_CMD} "-G" "${CM_VS_GENERATOR}")

set(CM_BUILD_CMD  ${CM_BUILD_CMD} "..")

set(CM_MSBUILD_CMD "msbuild" "digiprov_test.sln" "/property:Configuration=${CM_BUILD_TYPE}" "/p:Platform=${CM_VS_PLATFORM}")

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