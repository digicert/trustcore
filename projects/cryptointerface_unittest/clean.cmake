cmake_minimum_required(VERSION 3.5)

set(MSS_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
get_filename_component(MSS_DIR ${MSS_DIR} ABSOLUTE)

message("Cleaning up...")

if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/build)
    file(REMOVE_RECURSE build)
endif()


if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/main.c)
    file(REMOVE ${CMAKE_CURRENT_LIST_DIR}/main.c)
endif()

# Remove the test binary
if(EXISTS ${MSS_DIR}/bin/crypto_interface_test.exe)
    message("Removing test binary...")
    file(REMOVE ${MSS_DIR}/bin/crypto_interface_test.*)
endif()
