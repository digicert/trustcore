# Find tool
find_program(YASM_EXE NAMES yasm)

# Do not record RPATH
set(CMAKE_SKIP_BUILD_RPATH TRUE)

## Create version
if(NOT DEFINED MSS_VERSION_STR)
  set(MSS_VERSION_STR "8.0.0f")
endif()

########################################################################
#
# choosing 32 vs 64 bit
#
########################################################################

if(NOT DEFINED CM_SELECT_64BIT)
  if(NOT ${CMAKE_CROSSCOMPILING})
    # Native host size
    if(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
      set(CM_SELECT_64BIT ON)
    elseif(${CMAKE_SIZEOF_VOID_P} EQUAL 4)
      set(CM_SELECT_64BIT OFF)
    else()
      message(FATAL_ERROR "unexpected void pointer size\n")
    endif()
  endif()
endif()

if(CMAKE_C_COMPILER_ID MATCHES GNU)
  if(NOT ${CMAKE_CROSSCOMPILING})
    # X86?
    if (${CMAKE_SYSTEM_PROCESSOR} MATCHES x86_64)
      if(NOT DEFINED MX3264_GCC_FLAG)
        if (CM_SELECT_64BIT)
          set(MX3264_GCC_FLAG "-m64 -mno-sse2")
        else()
          set(MX3264_GCC_FLAG "-m32 -mno-sse2")
        endif()
      endif()
    endif()
  else()
    if (${CMAKE_C_COMPILER} MATCHES "aarch64-linux-gnu-gcc")
      set(MX3264_GCC_FLAG "")
      set(CM_SELECT_64BIT ON)
    elseif ("${CMAKE_C_COMPILER}" MATCHES "arm-linux-gnueabihf-gcc")
      set(MX3264_GCC_FLAG "")
      set(CM_SELECT_64BIT OFF)
    elseif ("${CMAKE_C_COMPILER}" MATCHES "arm-oemllib32-linux-gnueabi-gcc")
      set(MX3264_GCC_FLAG "")
      set(CM_SELECT_64BIT OFF)
    endif()
  endif()

  if(MX3264_GCC_FLAG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${MX3264_GCC_FLAG}")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${MX3264_GCC_FLAG}")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${MX3264_GCC_FLAG}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${MX3264_GCC_FLAG}")
  endif()
endif()

#if(CMAKE_C_COMPILER_ID MATCHES MSVC)
#endif()

#if(CMAKE_C_COMPILER_ID MATCHES AppleClang)
#endif()

## Force the tools to use 32 bit types, only
#if(CM_SELECT_64BIT)
# set(EXTRA_DEFINITIONS "-D__ENABLE_DIGICERT_64_BIT__")
#endif()

########################################################################
# Endianess
########################################################################

if(NOT ${CMAKE_CROSSCOMPILING})
  include(TestBigEndian)
  TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
endif()

if(IS_BIG_ENDIAN)
  set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DMOC_BIG_ENDIAN")
else()
  set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DMOC_LITTLE_ENDIAN")
endif()

########################################################################
#
# RTOS selection
#
########################################################################

## 'CMAKE_SYSTEM_NAME' is set by the cross compilation toolchain, as well.

if(APPLE)
    if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        set(RTOS_FLAG_MOCANA "-D__RTOS_OSX__")
    else()
        message(FATAL_ERROR "Apple OS is not Darwin\n")
    endif()
elseif(WIN32)
    set(RTOS_FLAG_MOCANA "-D__RTOS_WIN32__ -D__ENABLE_DIGICERT_WIN_STUDIO_BUILD__")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(RTOS_FLAG_MOCANA "-D__RTOS_LINUX__")
else()
    # we assume generic Linux
    set(RTOS_FLAG_MOCANA "-D__RTOS_LINUX__")
endif()

set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} ${RTOS_FLAG_MOCANA}")

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
    endif() #if(CM_WIN_FORCE_LINKAGE)
endif()
