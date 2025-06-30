########################################################################
#
# Cross compile flags  - Set from corresponding toolchain
# Native compile flags - Set in this file
#
########################################################################

message(STATUS "CMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "CMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
message(STATUS "CM_TARGET_PLATFORM=${CM_TARGET_PLATFORM}")

## Add any processor dependent platform flags, here
if ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86")

elseif ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")

elseif ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "AMD64")

elseif ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "ARM")

elseif ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "ARM64")

endif()

########################################################################
#
# choosing 32 vs 64 bit
#
########################################################################

if((NOT CM_BUILD_X32) AND (NOT CM_BUILD_X64))
    # Native compilation requested -> Check with the host (when not cross compiling)
    if(NOT CMAKE_CROSSCOMPILING)
        # Native host size
        if(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
            set(CM_BUILD_X64 ON)
            set(MX3264_GCC_FLAG "")
        elseif(${CMAKE_SIZEOF_VOID_P} EQUAL 4)
            set(CM_BUILD_X32 ON)
            set(MX3264_GCC_FLAG "")
        else()
            message(FATAL_ERROR "unexpected void pointer size\n")
        endif()
    endif()
endif()

# If above condition has NOT been met and the 'MX3264_GCC_FLAG' has NOT
# already been set
if(NOT DEFINED MX3264_GCC_FLAG)
  ## GNU bit size flag
    if(${CMAKE_C_COMPILER_ID} MATCHES GNU)
        if(NOT CMAKE_CROSSCOMPILING)
            # X86?
            if (${CMAKE_SYSTEM_PROCESSOR} MATCHES x86_64)
                if (CM_BUILD_X32)
                  set(MX3264_GCC_FLAG "-m32")
                elseif (CM_BUILD_X64)
                  set(MX3264_GCC_FLAG "-m64")
                endif()
            endif()
        else()
            # Cross compile check
            if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "^arm|^ARM")
                set(MX3264_GCC_FLAG "")
                if (${CMAKE_C_COMPILER} MATCHES "aarch64")
                    set(CM_BUILD_X64 ON)
                elseif (${CMAKE_C_COMPILER} MATCHES "arm|ARM")
                    set(CM_BUILD_X32 ON)
                else()
                    message(FATAL_ERROR "(1) Unexpected compiler '${CMAKE_C_COMPILER}' and processor '${CMAKE_SYSTEM_PROCESSOR}'\n")
                endif()
            elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
                if (CM_BUILD_X32)
                  set(MX3264_GCC_FLAG "-m32")
                elseif (CM_BUILD_X64)
                  set(MX3264_GCC_FLAG "-m64")
                endif()
            elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86")
                set(MX3264_GCC_FLAG "")
                if (CM_BUILD_X32)
                  if (${CMAKE_C_COMPILER} MATCHES "i686-poky-linux-gcc")
                    set(MX3264_GCC_FLAG "-m32")
                  endif()
                elseif (${CMAKE_C_COMPILER} MATCHES "ntox86")
                    set(CM_BUILD_X32 ON)
                elseif(${CMAKE_C_COMPILER} MATCHES "xtensa-esp32-elf-gcc")
                    set(CM_BUILD_X32 ON)
                else()
                    message(FATAL_ERROR "(1) Unexpected compiler '${CMAKE_C_COMPILER}' and processor '${CMAKE_SYSTEM_PROCESSOR}'\n")
                endif()
            elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64-oe")
                set(CM_BUILD_X64 ON)
            else()
                message(FATAL_ERROR "(2) Unexpected compiler '${CMAKE_C_COMPILER}' and processor '${CMAKE_SYSTEM_PROCESSOR}'\n")
            endif()
        endif()
    endif()
endif()

if(CMAKE_C_COMPILER_ID MATCHES GNU)
  if(NOT ${CMAKE_CROSSCOMPILING})
    # X86?
    if (${CMAKE_SYSTEM_PROCESSOR} MATCHES x86_64)
      if(UNIX AND NOT APPLE)
        set(MX3264_GCC_FLAG "${MX3264_GCC_FLAG} -mno-sse2")
      endif()
    endif()
  endif()
endif()

if (${CMAKE_C_COMPILER} MATCHES "arm-oe-linux-gnueabi-gcc")
    # This is platform-dependent, not compiler dependent. Should be set in 'platform.txt'?
    set(ARM_OE_GCC_FLAG "-march=armv7ve -marm -mfpu=neon-vfpv4  -mfloat-abi=softfp -mcpu=cortex-a7")
    # set the GCC flags
    set(MX3264_GCC_FLAG "${ARM_OE_GCC_FLAG}")
    set(CM_BUILD_X32 ON)
endif()

if(CM_BUILD_X64)
    set(EXTRA_DEFINITIONS "-D__ENABLE_MOCANA_64_BIT__")
endif()

# Set the endianness if we are not cross compiling
if(NOT CMAKE_CROSSCOMPILING)
  include(TestBigEndian)
  TEST_BIG_ENDIAN(IS_BIG_ENDIAN)

  if(IS_BIG_ENDIAN)
    set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DMOC_BIG_ENDIAN")
  else()
    set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DMOC_LITTLE_ENDIAN")
  endif()
endif()

########################################################################
#
# RTOS selection
#
########################################################################

if(ANDROID)
    set(ANDROID_NDK_PROP_FILE "${ANDROID_NDK}/source.properties")
    set(NDK_PROPERTY_NAME "Pkg.Revision")

    message(STATUS "ANDROID NDK Property File: ${ANDROID_NDK_PROP_FILE}")

    file(STRINGS "${ANDROID_NDK_PROP_FILE}" NDK_PROPERTIES)

    foreach(NDK_PROP_NAME_VALUE ${NDK_PROPERTIES})
        string(REGEX REPLACE "[ \t\r\n]" "" NDK_PROP_NAME_VALUE ${NDK_PROP_NAME_VALUE})
        string(REGEX MATCH "^[^=]+"  "${NDK_PROPERTY_NAME}" ${NDK_PROP_NAME_VALUE})
        string(REPLACE "${NDK_PROPERTY_NAME}=" "" NDK_PROPERTY_VALUE ${NDK_PROP_NAME_VALUE})
    endforeach()
endif()

if(APPLE)
    if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        set(RTOS_FLAG_MOCANA "-D__RTOS_OSX__")
    else()
        message(FATAL_ERROR "Apple OS is not Darwin\n")
    endif()
elseif(WIN32)
    set(RTOS_FLAG_MOCANA "-D__RTOS_WIN32__ -D__ENABLE_MOCANA_WIN_STUDIO_BUILD__ -DWIN32")
else()
    if("${CM_TARGET_PLATFORM}" MATCHES "qnx-x86_64")
        set(RTOS_FLAG_MOCANA "-D__RTOS_QNX__")
        set(RTOS_FLAG_MOCANA "${RTOS_FLAG_MOCANA} -D__RTOS_QNX_7__")
        set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DMOC_LITTLE_ENDIAN")
    elseif("${CM_TARGET_PLATFORM}" MATCHES "qnx-x86")
        set(RTOS_FLAG_MOCANA "-D__RTOS_QNX__")
        set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DMOC_LITTLE_ENDIAN")
    elseif("${CM_TARGET_PLATFORM}" MATCHES "qnx-6-5-x86")
	set(RTOS_FLAG_MOCANA "-D__RTOS_QNX__")
        set(RTOS_FLAG_MOCANA "${RTOS_FLAG_MOCANA} -D__RTOS_QNX_6_5__")
        set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DMOC_LITTLE_ENDIAN")
    elseif("${CM_TARGET_PLATFORM}" MATCHES "esp32")
        set(RTOS_FLAG_MOCANA "-D__RTOS_FREERTOS__ -D__RTOS_FREERTOS_ESP32__")
        set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DMOC_LITTLE_ENDIAN -D__LWIP_STACK__ -D__MOCANA_MAX_INT_32__")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -fdata-sections -ffunction-sections -Wl,--gc-sections")
    else()
    # we assume generic Linux
        set(RTOS_FLAG_MOCANA "-D__RTOS_LINUX__")
    # Adding Android RTOS flag too for android specific checks
        if (ANDROID)
            set(RTOS_FLAG_MOCANA "${RTOS_FLAG_MOCANA} -D__RTOS_ANDROID__")
        endif()
    endif()
endif()

########################################################################
#
# language flags
#
########################################################################

if("${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
  set(CMAKE_SHARED_LIBRARY_CREATE_CXX_FLAGS "${CMAKE_SHARED_LIBRARY_CREATE_CXX_FLAGS} -undefined dynamic_lookup")
  set(CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "${CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS} -undefined dynamic_lookup")
endif()

if(NOT WIN32)
 set(CXX_FLAGS_MOCANA              "-Werror=return-type -Wall")
else()
# /Werror=return-type returns 'invalid numeric argument' on some Windows builds.
 set(CXX_FLAGS_MOCANA              "-Wall")
endif()

#set(CXX_FLAGS_MOCANA              "${CXX_FLAGS_MOCANA} -D_LARGEFILE64_SOURCE")
#set(CXX_FLAGS_MOCANA              "${CXX_FLAGS_MOCANA} -DLIBUTILS_NATIVE=1")
#set(CXX_FLAGS_MOCANA              "${CXX_FLAGS_MOCANA} -DOFF_T_IS_64_BIT")
#set(CXX_FLAGS_MOCANA              "${CXX_FLAGS_MOCANA} -Wno-implicit")

 set(CXX_FLAGS_DEBUG_MOCANA        "-fprofile-arcs -ftest-coverage -rdynamic")
#set(CXX_FLAGS_DEBUG_MOCANA        "${CXX_FLAGS_DEBUG_MOCANA} -DENABLE_LIBDEX_LOGS")
				   # to disable log messages
#set(CXX_FLAGS_DEBUG_MOCANA        "${CXX_FLAGS_DEBUG_MOCANA} -DLOG_NDEBUG=1")

# /Werror=uninitialized returns 'invalid numeric argument' on some Windows builds.
if(NOT WIN32)
 set(CXX_FLAGS_RELEASE_MOCANA      "-Werror=uninitialized")
endif()
				   # CMAKE RELEASE flags turn on optimization.
				   # By some compilers Werror=uninitialized is
				   # only supported with optimizations enabled.

 set(C_FLAGS_MOCANA                "${MX3264_GCC_FLAG}")

 set(MODULE_LINKER_FLAGS_MOCANA    "${MX3264_GCC_FLAG}")

 set(SHARED_LINKER_FLAGS_MOCANA    "${MX3264_GCC_FLAG}")

 set(EXE_LINKER_FLAGS_MOCANA       "${MX3264_GCC_FLAG}")

 message(STATUS "Android NDK Version: ${NDK_PROPERTY_VALUE}")
 if (ANDROID AND NDK_PROPERTY_VALUE LESS "22")
     set(EXE_LINKER_FLAGS_MOCANA       "${EXE_LINKER_FLAGS_MOCANA} -fuse-ld=gold")
 endif()

 set(EXE_LINKER_FLAGS_DEBUG_MOCANA "-fprofile-arcs -ftest-coverage")

# Try to derive MSS_BIN_DIR if not provided
if(NOT DEFINED MSS_BIN_DIR)
  set(BIN_STR "bin")
  if(WIN32)
    set(BIN_STR "bin_win32")
  endif()
  if(DEFINED MSS_DIR)
    set(MSS_BIN_DIR "${MSS_DIR}/${BIN_STR}")
  elseif(DEFINED MSS_SRC_DIR)
    set(MSS_BIN_DIR "${MSS_SRC_DIR}/../${BIN_STR}")
  else()
    message(WARNING "Variable MSS_BIN_DIR not defined! This is needed when \
configuring library paths.")
  endif()
endif()

 link_directories(${MSS_BIN_DIR})

# The DEFS_FILE has all compiler flag names suffixed with '_MOCANA', so take the
# standard compiler flags we want to set, strip '_MOCANA' from the flag, then
# prefix the flag with 'CMAKE_' so cmake will recognize it.
message("")
foreach(stem CXX_FLAGS
        CXX_FLAGS_DEBUG
        CXX_FLAGS_RELEASE
        C_FLAGS
        C_FLAGS_DEBUG
        C_FLAGS_RELEASE
        MODULE_LINKER_FLAGS
        MODULE_LINKER_FLAGS_DEBUG
        EXE_LINKER_FLAGS
        EXE_LINKER_FLAGS_DEBUG
        SHARED_LINKER_FLAGS
        SHARED_LINKER_FLAGS_DEBUG)
    set(CMAKE_${stem} "${CMAKE_${stem}} ${${stem}_MOCANA}")
    string(STRIP "${CMAKE_${stem}}" CMAKE_${stem})
    message("----------------")
    message("${stem}_MOCANA = ${${stem}_MOCANA}")
    message("CMAKE_${stem}  = ${CMAKE_${stem}}")
endforeach()

if (WIN32)
    message("---- CFLAGS update for windows ----")
    #Ensure that the library is built using static version of the run-time library msvcrt
    foreach(item CXX_FLAGS
            CXX_FLAGS_RELEASE
            C_FLAGS
            C_FLAGS_RELEASE
            )
    message("----------------")
    message("CMAKE_${item}  = ${CMAKE_${item}}")
    if ("$ENV{CM_ENV_FORCE_STATIC_LINK}" STREQUAL "1")
        set(CMAKE_${item} "${CMAKE_${item}} /MT")
        string(REPLACE "/MD" "/MT" CMAKE_${item} "${CMAKE_${item}}")
    endif()
    message("CMAKE_${item}  = ${CMAKE_${item}}")
    endforeach()

    foreach(item CXX_FLAGS_DEBUG
            C_FLAGS_DEBUG
            )
    message("----------------")
    message("CMAKE_${item}  = ${CMAKE_${item}}")
    # Force static linkage
    if ("$ENV{CM_ENV_FORCE_STATIC_LINK}" STREQUAL "1")
        set(CMAKE_${item} "${CMAKE_${item}} /MTd")
        string(REPLACE "/MDd" "/MTd" CMAKE_${item} "${CMAKE_${item}}")
    endif()
    message("CMAKE_${item}  = ${CMAKE_${item}}")
    endforeach()

    if (CM_WIN_FORCE_LINKAGE)
      # Force to link even if unresolved symbols encountered in first pass
      foreach(item SHARED_LINKER_FLAGS
            SHARED_LINKER_FLAGS_DEBUG
            )
        message("----------------")
        message("CMAKE_${item}  = ${CMAKE_${item}}")
        set(CMAKE_${item} "${CMAKE_${item}} /FORCE:UNRESOLVED")
        message("CMAKE_${item}  = ${CMAKE_${item}}")
      endforeach()
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /DEF:NUL")
    endif() #if(CM_WIN_FORCE_LINKAGE)
endif()

if(WIN32)
  if(CMAKE_GENERATOR MATCHES "Visual Studio")
    string(APPEND CMAKE_C_FLAGS " /MP")
    string(APPEND CMAKE_CXX_FLAGS " /MP")
  endif()
endif()

########################################################################
#
# extra preprocessor definitions
#
########################################################################

 set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} ${RTOS_FLAG_MOCANA}")
 if(DEFINED ENV{CM_ENV_WERROR})
    if(WIN32)
        set(WERROR "")
    else()
        set(WERROR -Werror)
    endif()
 endif()

#set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -O3")
#set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -funroll-all-loops")

#adding windows specific macro for dynamic/static link builds
if (WIN32)
    if (LIB_TYPE MATCHES "SHARED")
        set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -D_USRDLL")
    elseif (LIB_TYPE MATCHES "STATIC")
        set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DWIN_STATIC")
    endif()
endif()

# To enable memory sanitizer set CM_ENV_FSANITIZE=1 in the build environment
if ("$ENV{CM_ENV_FSANITIZE}" STREQUAL "1")
    add_compile_options(-fsanitize=address)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")

    set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -D__ENABLE_FSANITIZE__")
endif()

# To enable code coverage set CM_ENV_CODE_COVERAGE=1 in the build environment
if ("$ENV{CM_ENV_CODE_COVERAGE}" STREQUAL "1")
    add_compile_options(-fprofile-arcs -ftest-coverage)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lgcov")
endif()

# To strip out code at the function level set CM_ENV_STRIP_FUNC=1 in the build
# environment
if ("$ENV{CM_ENV_STRIP_FUNC}" STREQUAL "1")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -fdata-sections -ffunction-sections -Wl,--gc-sections")
endif()

if("$ENV{CM_ENV_NO_OPTIMIZATION}" STREQUAL "1")
    string(REGEX REPLACE "(\-O[011123456789])" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
endif()

set(ARCHIVE_TO_SHARED_LIB_LINK_FLAG_START           "-Wl,--whole-archive")
set(ARCHIVE_TO_SHARED_LIB_LINK_FLAG_END             "-Wl,--no-whole-archive")
