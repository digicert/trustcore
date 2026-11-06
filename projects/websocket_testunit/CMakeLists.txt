cmake_minimum_required(VERSION 3.16)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
include(MocPlatform)

project(websocket_testunit C)

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${MSS_DIR}/src")

include(mss_defs)
add_definitions(${EXTRA_DEFINITIONS})

########################################################################
#
# FLAGS
#
########################################################################

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt" MOCANA_FLAGS)
add_definitions(${MOCANA_FLAGS})

########################################################################
#
# INCLUDES
#
########################################################################

include_directories(${MSS_SRC_DIR})

find_package(PkgConfig REQUIRED)
pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka>=1.1.0)

########################################################################
#
# TESTS
#
########################################################################

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${MSS_SRC_DIR}/websocket/testunit)

add_library(websocket_test_mocks STATIC ${MSS_SRC_DIR}/websocket/testunit/test_mocks.c)
target_compile_definitions(websocket_test_mocks PRIVATE NANOWS_UNIT_TEST_MOCKS)

set(NANOWS_TEST_DEPS nanows nanossl nanocert cryptointerface nanocap nanocrypto initialize asn1 common platform)

set(NANOWS_TEST_LIBS)
foreach(dependency IN LISTS NANOWS_TEST_DEPS)
    list(APPEND NANOWS_TEST_LIBS "$<TARGET_FILE:${dependency}>")
endforeach()

set(COMMON_TEST_LIBS
    websocket_test_mocks
    "-Wl,--start-group"
    ${NANOWS_TEST_LIBS}
    PkgConfig::CMOCKA
    pthread
    "-Wl,--end-group"
)

enable_testing()

foreach(test_name frame handshake websocket)
    add_executable(test_websocket_${test_name} ${MSS_SRC_DIR}/websocket/testunit/test_websocket_${test_name}.c)
    target_link_libraries(test_websocket_${test_name} ${COMMON_TEST_LIBS})
    add_dependencies(test_websocket_${test_name} ${NANOWS_TEST_DEPS})
    add_test(NAME websocket_${test_name} COMMAND test_websocket_${test_name})
endforeach()
