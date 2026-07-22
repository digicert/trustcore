## Compile sources and create shared library for FIPS
##

cmake_minimum_required(VERSION 3.5)

option(CM_DISABLE_INTEG_TEST "Disable integrity test" OFF)
set(CM_LIB_TYPE "SHARED" CACHE STRING "")
message(STATUS "print_all_variables------------------------------------------{")
get_cmake_property(_variableNames VARIABLES)
foreach (_variableName ${_variableNames})
   message(STATUS "${_variableName}=${${_variableName}}")
endforeach()
message(STATUS "print_all_variables------------------------------------------}")

if("${CM_LIB_TYPE}" STREQUAL "STATIC")
  set(ENV{CM_ENV_FORCE_STATIC_LINK} "1")
endif()

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/../../shared_cmake)

# Include cross-compile options/flags
include(MocPlatform)

project(libmss)

## Get linker version
execute_process(
    COMMAND ${CMAKE_LINKER} --version
    OUTPUT_VARIABLE LD_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "Linker version: ${LD_VERSION}")

## Set PATHs
set(MSS_DIR "${CMAKE_SOURCE_DIR}/../../..")
set(MSS_SRC_DIR "${MSS_DIR}/src")
if("${CM_LIB_TYPE}" STREQUAL "STATIC")
  if(WIN32)
    set(MSS_BIN_DIR "${MSS_DIR}/bin_win32_static")
  else()
    set(MSS_BIN_DIR "${MSS_DIR}/bin_static")
  endif()
else()
  if(WIN32)
    set(MSS_BIN_DIR "${MSS_DIR}/bin_win32")
  else()
    set(MSS_BIN_DIR "${MSS_DIR}/bin")
  endif()
endif()
set(FLAGS_FILE "${CMAKE_SOURCE_DIR}/flags.txt")
##set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
set(DEFS_FILE "${CMAKE_SOURCE_DIR}/../fips_defs.cmake")
set(INTEG_FILE "${CMAKE_SOURCE_DIR}/../integ_file.cmake")

## Include general definitions
include(${DEFS_FILE})

# Name of FIPS shared library
set(MSS_TGT_LIBNAME libmss)
include(${INTEG_FILE})

## Add flags from 'defs.txt'
add_definitions("${EXTRA_DEFINITIONS}")

## Read and set flags
file(STRINGS ${FLAGS_FILE} project_flags)
foreach(flag ${project_flags})
  string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

if(${CM_ENABLE_JENT_LKM})
  add_definitions("-D__FIPS_ALWAYS_ADD_ENTROPY_NIST_RNG__")
  add_definitions("-D__ENABLE_DIGICERT_FIPS_JITTERENTROPY_LKM__ -D__DISABLE_DIGICERT_FIPS_LINUX_RAND__")
endif()
if(${CM_ENABLE_JENT_LIB})
  add_definitions("-D__FIPS_ALWAYS_ADD_ENTROPY_NIST_RNG__")
  add_definitions("-D__ENABLE_DIGICERT_FIPS_JITTERENTROPY_LIB__ -D__DISABLE_DIGICERT_FIPS_LINUX_RAND__")
endif()
if(${CM_ENABLE_URANDOM})
  add_definitions("-D__FIPS_ALWAYS_ADD_ENTROPY_NIST_RNG__")
endif()

if(CM_DISABLE_PQC)
  string(REPLACE "-D__ENABLE_DIGICERT_PQC__" "" MOCANA_FLAGS "${MOCANA_FLAGS}")
  string(REPLACE "-D__ENABLE_DIGICERT_PQC_KEM__" "" MOCANA_FLAGS "${MOCANA_FLAGS}")
  string(REPLACE "-D__ENABLE_DIGICERT_PQC_SIG__" "" MOCANA_FLAGS "${MOCANA_FLAGS}")
  string(REPLACE "-D__ENABLE_DIGICERT_FIPS_MLDSA__" "" MOCANA_FLAGS "${MOCANA_FLAGS}")
  string(REPLACE "-D__ENABLE_DIGICERT_FIPS_MLKEM__" "" MOCANA_FLAGS "${MOCANA_FLAGS}")
  string(REPLACE "-D__ENABLE_DIGICERT_FIPS_SLHDSA__" "" MOCANA_FLAGS "${MOCANA_FLAGS}")
endif()

add_definitions("${MOCANA_FLAGS}")

if(${CM_FIPS_PERSIST})
  add_definitions("-D__ENABLE_DIGICERT_FIPS_ALWAYS_IMPORT_FIRST__")
  add_definitions(-D__DIGICERT_PERSIST_FILEPATH__=\"${MSS_FINAL_PERSIST_PATH}\")
endif()

if(${CMAKE_CROSSCOMPILING})
  add_definitions(${PLATFORM_CPU_FLAGS})
endif()

if(NOT CM_DISABLE_INTEG_TEST)
  add_definitions(" -D__ENABLE_DIGICERT_FIPS_INTEG_TEST__")
endif()

if(WIN32)
  add_definitions("-DWIN_EXPORT_CRYPTO -DWIN_EXPORT_RANDOM_H \
                   -DWIN_EXPORT_PRIMEEC_H -DWIN_EXPORT_PRIMEFLD_H \
                   -DWIN_EXPORT_PKCS1_INT -DWIN_EXPORT_CRYPTO_H")
  if("${CM_LIB_TYPE}" STREQUAL "STATIC")
    add_definitions("-DWIN_STATIC")
  else()
    add_definitions("-D_USRDLL")
  endif()
endif()

## Add integrity file
add_definitions(-DFIPS_INTEG_TEST_BINARY_FILENAME=\"${MSS_FINAL_LIB_NAME}\")
add_definitions(-DFIPS_INTEG_TEST_HASH_FILENAME=\"${MSS_FINAL_SIG_NAME}\")
## Add version
add_definitions(-D__DIGICERT_DSF_VERSION_STR__=\"${MSS_VERSION_STR}\")
if(DEFINED MSS_BUILD_STR)
  add_definitions(-D__DIGICERT_DSF_BUILD_STR__=\"${MSS_BUILD_STR}\")
endif()
if(DEFINED MSS_BUILDTIME_STR)
  add_definitions(-D__DIGICERT_DSF_BUILDTIME_STR__=\"${MSS_BUILDTIME_STR}\")
endif()

## Setup include paths
include_directories("." ${MSS_SRC_DIR})

## Set source files for FIPS library
## Read all source file names
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../common_sources.txt" LIBMSS_COMMON_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" LIBMSS_COMMON_SOURCES "${LIBMSS_COMMON_SOURCES}")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../crypto_sources.txt" LIBMSS_CRYPTO_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" LIBMSS_CRYPTO_SOURCES "${LIBMSS_CRYPTO_SOURCES}")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../platform_sources.txt" LIBMSS_PLATFORM_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" LIBMSS_PLATFORM_SOURCES "${LIBMSS_PLATFORM_SOURCES}")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../vlong_sources.txt" LIBMSS_VLONG_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" LIBMSS_VLONG_SOURCES "${LIBMSS_VLONG_SOURCES}")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../rng_sources.txt" LIBMSS_RNG_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" LIBMSS_RNG_SOURCES "${LIBMSS_RNG_SOURCES}")

set(LIBMSS_SRC
  ${LIBMSS_COMMON_SOURCES}
  ${LIBMSS_CRYPTO_SOURCES}
  ${LIBMSS_PLATFORM_SOURCES}
  ${LIBMSS_VLONG_SOURCES}
  ${LIBMSS_RNG_SOURCES}
  )

## Host specific sources/flags
set(HOST_SRC "")
if(NOT ${CMAKE_CROSSCOMPILING})
  if(UNIX)
    if(${CMAKE_SYSTEM_PROCESSOR} MATCHES x86_64)
       if("${CMAKE_MOCANA_PLATFORM}" STREQUAL "x86_64")
          message(STATUS "PAA: FIPS: CMAKE_MOCANA_PLATFORM == x86_64 : Self-hosted. Enabling AES_NI & FORCE_PAA_MODE")
          add_definitions(-D__ASM_386_GCC__ -D__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__ -D__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__)
          set (HOST_SRC ${MSS_SRC_DIR}/crypto/aesalgo_intel_ni.c)
          set(HOST_LIB iaesx64.o)
          add_custom_command(OUTPUT iaesx64.o COMMAND ${YASM_EXE}
             ARGS -D__linux__ -g dwarf2 -f elf64 -o iaesx64.o ${MSS_SRC_DIR}/crypto/intel_aes_ni/asm/x64/iaesx64.s)
          ##JENT: Find libraries here...
          if(CM_ENABLE_JENT_LIB)
            set (JENT_LOCATION  "/usr/local/lib/")
            find_library(JENT_LIB NAMES jitterentropy HINTS "${JENT_LOCATION}")
          endif()
       endif()
       if("${CMAKE_MOCANA_PLATFORM}" STREQUAL "x86_32")
          message(STATUS "PAA: FIPS: CMAKE_MOCANA_PLATFORM == x86_32 : Self-hosted. Enabling AES_NI & FORCE_PAA_MODE")
          add_definitions(-D__ASM_386_GCC__ -D__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__ -D__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__)
          set (HOST_SRC ${MSS_SRC_DIR}/crypto/aesalgo_intel_ni.c)
          set(HOST_LIB iaesx86.o)
          add_custom_command(OUTPUT iaesx86.o COMMAND ${YASM_EXE}
              ARGS -D__linux__ -g dwarf2 -f elf32 -o iaesx86.o ${MSS_SRC_DIR}/crypto/intel_aes_ni/asm/x86/iaesx86.s)
          ##JENT: Find libraries here...
          if(CM_ENABLE_JENT_LIB)
            set (JENT_LOCATION  "/lib32/")
            find_library(JENT_LIB NAMES jitterentropy HINTS "${JENT_LOCATION}")
          endif()
       endif()
    endif()
  endif()
endif()

## Target specific sources/flags
if(${CMAKE_CROSSCOMPILING})
  if("${CMAKE_MOCANA_PLATFORM}" STREQUAL "voss-x86-64")
    message(STATUS "PAA: FIPS: aries64_poky_x86-64: Cross-compiling. Enabling AES_NI & FORCE_PAA_MODE")
    add_definitions(-D__ASM_386_GCC__ -D__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__ -D__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__)
    set (HOST_SRC
      ${MSS_SRC_DIR}/crypto/aesalgo_intel_ni.c
      )
    set(HOST_LIB iaesx64.o)
    add_custom_command(OUTPUT iaesx64.o COMMAND ${YASM_EXE}
      ARGS -D__linux__ -g dwarf2 -f elf64 -o iaesx64.o ${MSS_SRC_DIR}/crypto/intel_aes_ni/asm/x64/iaesx64.s)
    ##JENT: Find libraries here...
    if(CM_ENABLE_JENT_LIB)
      set (JENT_LOCATION  "/usr/local/lib/")
      find_library(JENT_LIB NAMES jitterentropy HINTS "${JENT_LOCATION}")
    endif()
  endif()
endif()

if(${CMAKE_CROSSCOMPILING})
  if("${CMAKE_MOCANA_PLATFORM}" STREQUAL "wrs_x86_64")
    message(STATUS "PAA: FIPS: wrs_x86_64: Cross-compiling. Enabling AES_NI & FORCE_PAA_MODE")
    add_definitions(-D__ASM_386_GCC__ -D__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__ -D__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__)
    set (HOST_SRC
      ${MSS_SRC_DIR}/crypto/aesalgo_intel_ni.c
      )
    set(HOST_LIB iaesx64.o)
    add_custom_command(OUTPUT iaesx64.o COMMAND ${YASM_EXE}
      ARGS -D__linux__ -g dwarf2 -f elf64 -o iaesx64.o ${MSS_SRC_DIR}/crypto/intel_aes_ni/asm/x64/iaesx64.s)
    ##JENT: Find libraries here...
    if(CM_ENABLE_JENT_LIB)
      set (JENT_LOCATION  "/usr/local/lib/")
      find_library(JENT_LIB NAMES jitterentropy HINTS "${JENT_LOCATION}")
    endif()
  endif()
  if("${CMAKE_MOCANA_PLATFORM}" STREQUAL "wrs_x86")
    message(STATUS "PAA: FIPS: wrs_x86: Cross-compiling. Enabling AES_NI & FORCE_PAA_MODE")
    add_definitions(-D__ASM_386_GCC__ -D__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__ -D__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__)
    set (HOST_SRC
      ${MSS_SRC_DIR}/crypto/aesalgo_intel_ni.c
      )
    set(HOST_LIB iaesx86.o)
    add_custom_command(OUTPUT iaesx86.o COMMAND ${YASM_EXE}
      ARGS -D__linux__ -g dwarf2 -f elf32 -o iaesx86.o ${MSS_SRC_DIR}/crypto/intel_aes_ni/asm/x86/iaesx86.s)
    ##JENT: Find libraries here...
    if(CM_ENABLE_JENT_LIB)
      set (JENT_LOCATION  "/lib32/")
      find_library(JENT_LIB NAMES jitterentropy HINTS "${JENT_LOCATION}")
    endif()
  endif()
endif()

if(${CMAKE_CROSSCOMPILING})
  if("${CMAKE_MOCANA_PLATFORM}" STREQUAL "Xerox-x86-32" OR "${CMAKE_MOCANA_PLATFORM}" STREQUAL "Xerox-x86-64")
    message(STATUS "PAA: FIPS: Xerox-x86-32 or Xerox-x86-64: Cross-compiling. Enabling AES_NI & FORCE_PAA_MODE")
    add_definitions(-D__ASM_386_GCC__ -D__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__ -D__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__)
    set(HOST_SRC ${MSS_SRC_DIR}/crypto/aesalgo_intel_ni.c ${MSS_SRC_DIR}/common/sse2.c)
    #set(LIBMSS_SRC ${MSS_SRC_DIR}/common/sse2.c)
    execute_process(COMMAND gcc -E -o ${MSS_SRC_DIR}/common/sse2_routines.s ${MSS_SRC_DIR}/common/sse2_routines.S)
    if("${CMAKE_MOCANA_PLATFORM}" STREQUAL "Xerox-x86-64")
      add_custom_command(OUTPUT iaesx64.o COMMAND ${YASM_EXE}
        ARGS -D__linux__ -g dwarf2 -f elf64 -o iaesx64.o ${MSS_SRC_DIR}/crypto/intel_aes_ni/asm/x64/iaesx64.s)
      add_custom_command(OUTPUT sse2_routines.o COMMAND ${CM_TOOL_PATH}/${CMAKE_AS_ASM}
        ARGS --64 -g -o sse2_routines.o ${MSS_SRC_DIR}/common/sse2_routines.s)
      set(HOST_LIB iaesx64.o sse2_routines.o)
      ##JENT: Find libraries here...
      if(CM_ENABLE_JENT_LIB)
        set (JENT_LOCATION  "/usr/local/lib/")
        find_library(JENT_LIB NAMES jitterentropy HINTS "${JENT_LOCATION}")
      endif()
    endif()
    if("${CMAKE_MOCANA_PLATFORM}" STREQUAL "Xerox-x86-32")
      add_custom_command(OUTPUT iaesx86.o COMMAND ${YASM_EXE}
        ARGS -D__linux__ -g dwarf2 -f elf32 -o iaesx86.o ${MSS_SRC_DIR}/crypto/intel_aes_ni/asm/x86/iaesx86.s)
      add_custom_command(OUTPUT sse2_routines.o COMMAND ${CM_TOOL_PATH}/${CMAKE_AS_ASM}
        ARGS --32 -g -o sse2_routines.o ${MSS_SRC_DIR}/common/sse2_routines.s)
      set(HOST_LIB iaesx86.o sse2_routines.o)
      ##JENT: Find libraries here...
      if(CM_ENABLE_JENT_LIB)
        set (JENT_LOCATION  "/lib32/")
        find_library(JENT_LIB NAMES jitterentropy HINTS "${JENT_LOCATION}")
      endif()
    endif()
  endif()
endif()

##JENT: Add libraries here...
if(${CM_ENABLE_JENT_LIB})
  set(EXTRA_LIBS ${JENT_LIB})
endif()

## Define library
set(TARGET_NAME mss)
if(WIN32)
  set(TARGET_NAME libmss)
endif()
add_library(${TARGET_NAME} ${CM_LIB_TYPE} ${LIBMSS_SRC} ${HOST_SRC} ${HOST_LIB})
target_link_libraries(${TARGET_NAME} ${EXTRA_LIBS})

# Move the library to bin_win32
if(WIN32)
  add_custom_command(
    TARGET ${TARGET_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        $<TARGET_FILE_DIR:${TARGET_NAME}>
        ${MSS_BIN_DIR})
endif()
