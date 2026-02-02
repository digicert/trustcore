cmake_minimum_required(VERSION 3.5)

# Where to find CMake files
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)
include(MocPlatform)
include(locate_lib)

project(nanossh_testunit C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

set(MSS_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../lib")
set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(MSS_SRC_DIR "${MSS_DIR}/src")

set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
message("\nDEFS_FILE = ${DEFS_FILE}")
include(${DEFS_FILE})

# Load the EXTRA_DEFINITIONS flags (from mss_defs.cmake) into the build
message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")
add_definitions("${EXTRA_DEFINITIONS}")

########################################################################
#
# FLAGS
#
########################################################################

set(MOCANA_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mocana_flags.txt")
file(STRINGS ${MOCANA_FLAGS_FILE} mocana_flags)

# Now load all flags into MOCANA_FLAGS
foreach(flag ${mocana_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()


# Load the flags into the build
message("MOCANA_FLAGS = ${MOCANA_FLAGS}")
add_definitions("${MOCANA_FLAGS}")



########################################################################
#
# INCLUDES
#
########################################################################

# Add include directories
include_directories(${MSS_SRC_DIR})
include_directories(${MSS_SRC_DIR}/../cmocka-1.1.5/include)

########################################################################
#
# LINK DIRECTORY
#
########################################################################

link_directories(${MSS_DIR}/lib)

########################################################################
#
# CONDITIONAL FLAGS 
#
########################################################################

########################################################################
#
# TESTS
#
########################################################################

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${MSS_SRC_DIR}/ssh/testunit)

set(ASN1_LIB          "${MSS_DIR}/lib/libasn1.so")
set(COMMON_LIB        "${MSS_DIR}/lib/libcommon.so")
set(INITIALIZE_LIB    "${MSS_DIR}/lib/libinitialize.so")
set(PLATFORM_LIB      "${MSS_DIR}/lib/libplatform.so")
set(NANOSSHC_LIB      "${MSS_DIR}/lib/libnanosshc.so")
set(NANOSSHS_LIB      "${MSS_DIR}/lib/libnanosshs.so")

set(COMMON_TEST_LIBS 
    "-Wl,--start-group"
    ${PLATFORM_LIB}
    ${ASN1_LIB}
    ${COMMON_LIB}
    ${INITIALIZE_LIB}
    ${NANOSSHS_LIB}
    nanocap
    nanocert
    nanocrypto
    cryptointerface
    cmocka
    pthread
    "-Wl,--end-group"
)

message("NANOSSHC_LIB = ${COMMON_TEST_LIBS} ${NANOSSHC_LIB}")
message("NANOSSHS_LIB = ${COMMON_TEST_LIBS} ${NANOSSHS_LIB}")

# Server tests
add_executable(test_ssh_utils   ${MSS_SRC_DIR}/ssh/testunit/ssh_utils_test.c)
target_link_libraries(test_ssh_utils  ${COMMON_TEST_LIBS} ${NANOSSHS_LIB})
target_link_options(test_ssh_utils  PRIVATE)

# Client tests
add_executable(test_sshc_auth ${MSS_SRC_DIR}/ssh/testunit/sshc_auth_test.c)
add_executable(test_sshc_str_house ${MSS_SRC_DIR}/ssh/testunit/sshc_str_house_test.c)
add_executable(test_sshc_utils ${MSS_SRC_DIR}/ssh/testunit/sshc_utils_test.c)
add_executable(test_sshc_context  ${MSS_SRC_DIR}/ssh/testunit/sshc_context_test.c)
add_executable(test_sshc_in_mesg ${MSS_SRC_DIR}/ssh/testunit/sshc_in_mesg_test.c)
add_executable(test_sshc_out_mesg ${MSS_SRC_DIR}/ssh/testunit/sshc_out_mesg_test.c)
add_executable(test_sshc_trans ${MSS_SRC_DIR}/ssh/testunit/sshc_trans_test.c)
add_executable(test_sshc_session ${MSS_SRC_DIR}/ssh/testunit/sshc_session_test.c)

set(CLIENT_TEST_TARGETS
    test_sshc_auth
    test_sshc_str_house
    test_sshc_utils
    test_sshc_context
    test_sshc_in_mesg
    test_sshc_out_mesg
    test_sshc_trans
    test_sshc_session
)
if(NOT DISABLE_SSH_CLIENT)
    foreach(target IN LISTS CLIENT_TEST_TARGETS)
        add_dependencies(${target} overwrite_for_ssh_client)    
    endforeach()
endif()

foreach(target IN LISTS CLIENT_TEST_TARGETS)
    target_compile_definitions(${target} PRIVATE MOPTIONS_CUSTOM_HEADER=\"${MOPTIONS_CUSTOM_SSH_CLIENT_FILE}\")
endforeach()

target_link_libraries(test_sshc_auth ${COMMON_TEST_LIBS} ${NANOSSHC_LIB})
target_link_libraries(test_sshc_str_house ${COMMON_TEST_LIBS} ${NANOSSHC_LIB})
target_link_libraries(test_sshc_utils ${COMMON_TEST_LIBS} ${NANOSSHC_LIB})
target_link_libraries(test_sshc_context ${COMMON_TEST_LIBS} ${NANOSSHC_LIB})
target_link_libraries(test_sshc_in_mesg ${COMMON_TEST_LIBS} ${NANOSSHC_LIB})
target_link_libraries(test_sshc_out_mesg ${COMMON_TEST_LIBS} ${NANOSSHC_LIB})
target_link_libraries(test_sshc_trans ${COMMON_TEST_LIBS} ${NANOSSHC_LIB})
target_link_libraries(test_sshc_session ${COMMON_TEST_LIBS} ${NANOSSHC_LIB})
