## Compile libraries and executable for 'so_sign' tool
##

cmake_minimum_required(VERSION 3.5)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/../../shared_cmake)

project(so_sign)

# Find tool
find_program(YASM_EXE NAMES yasm)

# Do not record RPATH
set(CMAKE_SKIP_BUILD_RPATH TRUE)

## Set PATHs
set(MSS_SRC_DIR "${CMAKE_SOURCE_DIR}/../../../src")
set(FLAGS_FILE "${CMAKE_SOURCE_DIR}/flags.txt")
set(DEFS_FILE "${CMAKE_SOURCE_DIR}/defs.txt")

## Include general definitions
include(${DEFS_FILE})

## Add flags from 'defs.txt'
add_definitions("${EXTRA_DEFINITIONS}")

## Read and set flags
file(STRINGS ${FLAGS_FILE} project_flags)
foreach(flag ${project_flags})
  string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

add_definitions("${MOCANA_FLAGS}")
if(${CMAKE_CROSSCOMPILING})
  add_definitions(${PLATFORM_CPU_FLAGS})
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

## Set source files for static linking
## Read all source file names
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../common_sources.txt" SOSIGN_COMMON_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" SOSIGN_COMMON_SOURCES "${SOSIGN_COMMON_SOURCES}")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../crypto_sources.txt" SOSIGN_CRYPTO_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" SOSIGN_CRYPTO_SOURCES "${SOSIGN_CRYPTO_SOURCES}")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../platform_sources.txt" SOSIGN_PLATFORM_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" SOSIGN_PLATFORM_SOURCES "${SOSIGN_PLATFORM_SOURCES}")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../vlong_sources.txt" SOSIGN_VLONG_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" SOSIGN_VLONG_SOURCES "${SOSIGN_VLONG_SOURCES}")

set(SOSIGN_LIB_SRC
  ${SOSIGN_COMMON_SOURCES}
  ${SOSIGN_CRYPTO_SOURCES}
  ${SOSIGN_PLATFORM_SOURCES}
  ${SOSIGN_VLONG_SOURCES}
  )

## Set source files for tools
set(SOSIGN_SRC
  ${MSS_SRC_DIR}/common/rng_seed.c
  ${MSS_SRC_DIR}/fips/host_tools/so_sign.c
  )

## Add executable rules
add_executable(so_sign ${SOSIGN_SRC} ${SOSIGN_LIB_SRC} ${HOST_SRC} ${HOST_LIB})

# Add 'pthread' lib when on Linux
if(UNIX)
  set(EXTRA_LIBS pthread)
else()
  set(EXTRA_LIBS "")
endif()

## Link rules
target_link_libraries(so_sign ${EXTRA_LIBS})

## Installation rules
install(TARGETS so_sign RUNTIME
  DESTINATION bin
  COMPONENT applications
)
