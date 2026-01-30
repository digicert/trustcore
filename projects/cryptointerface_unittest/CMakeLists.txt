## Compile unit test executable for 'src/cryptointerface'
##

cmake_minimum_required(VERSION 3.5)

# Default values for command line options
option(CM_DISABLE_CI        "Disable CryptoInterface"      OFF)
option(CM_DISABLE_PQC       "Build with PQC disabled"      OFF)
option(CM_DISABLE_SCRAM     "Build with SCRAM disabled"    OFF)
option(CM_ENABLE_OPERATORS  "Build with external operators" OFF)
option(CM_ENABLE_MBED       "Enable mbed tls"              OFF)
option(CM_ENABLE_OQS        "Enable oqs"                   OFF)
option(CM_ENABLE_TAP_EXTERN "Enable TAP extern"            OFF)
option(CM_ENABLE_TPM2       "Enable tpm2"                  OFF)
option(CM_ENABLE_PKCS11     "Enable pkcs11 hsm"            OFF)
option(CM_ENABLE_SOFTHSM    "Enable softhsm lib ."         OFF)
option(CM_ENABLE_CLOUDHSM   "Enable cloudhsm lib ."        OFF)
option(CM_ENABLE_PKCS11_TEE "Enable pkcs11 tee."           OFF)
option(CM_ENABLE_DSSM       "Enable Digicert SSM."         OFF)
option(CM_ENABLE_TAP_PRINT  "Enable TAP feature prints."   OFF)
option(CM_ENABLE_HW_SIM     "Enable hw simulator"          OFF)
option(CM_ENABLE_AIDE       "Enable aide."                 OFF)
option(CM_ENABLE_SPEEDTEST  "Enable unit test speed tests" OFF)
option(CM_ENABLE_QUICKTEST  "Enable unit test quick tests" OFF)
option(CM_ENABLE_QA_PROD    "Enable certificate store serilization tests" OFF)
option(CM_ENABLE_AES_NI     "" OFF)
option(CM_CLIENT_TAP        "Values may be: OFF, LOCAL or REMOTE" OFF)
option(CM_ENABLE_FIPS       "Build with FIPS"              OFF)

option(CM_BUILD_X32           "Build for 32Bit Machine." OFF)
option(CM_BUILD_X64           "Build for 64Bit Machine." OFF)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_cmake)

# Include cross-compile options/flags (must be before project is defined)
include(MocPlatform)
include(locate_lib)

project(cryptointerface_test C)

## The library name of the tested code
set(MSS_LIB_NAME crypto_interface)

set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
get_filename_component(MSS_DIR "${MSS_DIR}" ABSOLUTE)
set(MSS_SRC_DIR "${MSS_DIR}/src")
if(WIN32)
  set(MSS_BIN_DIR "${MSS_DIR}/bin_win32")
else()
  set(MSS_BIN_DIR "${MSS_DIR}/bin")
endif()
set(MSS_UNITTEST_DIR "${MSS_DIR}/unit_tests")
set(MSS_LIB_DIR "${MSS_SRC_DIR}/${MSS_LIB_NAME}")
set(MSS_TEST_DIR "${MSS_SRC_DIR}/${MSS_LIB_NAME}/test")
set(DEFS_FILE "${CMAKE_MODULE_PATH}/mss_defs.cmake")
set(MSS_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mss_flags.txt")
set(SOURCES_FILE "${CMAKE_CURRENT_SOURCE_DIR}/test_sources.txt")

# Set the flags file only if CM_DISABLE_CI is not turned ON
if(NOT CM_DISABLE_CI)
  set(CI_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cryptointerface_flags.txt")

  # Sanity check to make sure this file exists
  if(NOT EXISTS ${CI_FLAGS_FILE})
    message("cryptointerface_flags.txt not found\n")
  endif()

endif()

# Set the flags file only if CM_ENABLE_MBED is turned ON
if(CM_ENABLE_MBED)
  set(MBED_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mbed_flags.txt")

  # Sanity check to make sure this file exists
  if(NOT EXISTS ${MBED_FLAGS_FILE})
    message("mbed_flags.txt not found\n")
  endif()

  message("\nMOCANA_MBED_FLAGS_FILE = ${MBED_FLAGS_FILE}")
endif()

if(CM_ENABLE_OQS)
  set(OQS_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/oqs_flags.txt")

  # Sanity check to make sure this file exists
  if(NOT EXISTS ${OQS_FLAGS_FILE})
    message("oqs_flags.txt not found\n")
  endif()

  message("\nMOCANA_OQS_FLAGS_FILE = ${OQS_FLAGS_FILE}")
endif()

if(CM_ENABLE_PKCS11 OR CM_ENABLE_TPM2)
  set(TAP_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/tap_flags.txt")

  # Sanity check to make sure this file exists
  if(NOT EXISTS ${TAP_FLAGS_FILE})
    message("tap_flags.txt not found\n")
  endif()

  message("\nMOCANA_TAP_FLAGS_FILE = ${TAP_FLAGS_FILE}")
endif()

if(CM_ENABLE_HW_SIM)
  set(HW_SIM_FLAGS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/hw_sim_flags.txt")

  # Sanity check to make sure this file exists
  if(NOT EXISTS ${HW_SIM_FLAGS_FILE})
    message("hw_sim_flags.txt not found\n")
  endif()

  message("\nMOCANA_HW_SIM_FLAGS_FILE = ${HW_SIM_FLAGS_FILE}")
endif()

set(MSS_LIBRARY_TYPE STATIC)

# Make sure we have all needed files
if( (NOT EXISTS ${DEFS_FILE}) OR
    (NOT EXISTS ${MSS_FLAGS_FILE}) OR
    (NOT EXISTS ${SOURCES_FILE}) )
  message(FATAL_ERROR "\nA needed file was not found :(\n")
endif()

# Set the path for where the libraries should be written to
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY  "${MSS_DIR}/lib")

# Set the path for where the test binary should be written to
if(NOT WIN32)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${MSS_BIN_DIR}")
endif()

## Make sure Ruby is installed since we need it to build the tests
find_package(Ruby)

# -----------------------------------------------------------------------------

## Include general definitions
include(${DEFS_FILE})

## Add flags from 'defs.cmake'
add_definitions("${EXTRA_DEFINITIONS}")

## Read all test source file names
file(STRINGS ${SOURCES_FILE} MSS_TEST_SOURCES)
# Remove lines starting with '#'
foreach(src ${MSS_TEST_SOURCES})
  if("${src}" MATCHES "#.+")
    list(REMOVE_ITEM MSS_TEST_SOURCES ${src})
  endif()
endforeach()
string(REGEX REPLACE "MSS_TEST_DIR/" "${MSS_TEST_DIR}/"
       MSS_TEST_SOURCES "${MSS_TEST_SOURCES}")
if(WIN32)
  set(MSS_TEST_SOURCES ${MSS_TEST_SOURCES} ${MSS_SRC_DIR}/common/win32oid.c)
endif()

# -----------------------------------------------------------------------------

## How to make 'main.c'
if(EXISTS ${RUBY_EXECUTABLE})
  add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/main.c
                     COMMAND ${RUBY_EXECUTABLE} ${MSS_UNITTEST_DIR}/unittest.rb
                     . localhost "" ${CMAKE_CURRENT_SOURCE_DIR}/test_sources.txt | tee ${CMAKE_CURRENT_SOURCE_DIR}/main.c
                     WORKING_DIRECTORY ${MSS_TEST_DIR}
                     DEPENDS ${MSS_TEST_SOURCES}
                     VERBATIM)
else()
  message(FATAL_ERROR "Cannot create main.c, Ruby executable not found. Exiting...")
endif()

## Process mbed command line args, build the mbed lib if its not already done
if(CM_ENABLE_MBED)
  if("${CM_MBED_PATH}" STREQUAL "")
    message(FATAL_ERROR "mbed option is enabled but no path has been provided")
  endif()

  # If this is a relative path, convert it to an absolute
  if(NOT IS_ABSOLUTE ${CM_MBED_PATH})
    get_filename_component(CM_MBED_PATH "${CM_MBED_PATH}" ABSOLUTE)
  endif()

  # Find out of the path provided ended with a '/', and remove it if so
  if("${CM_MBED_PATH}" MATCHES "/$")
    string(REGEX REPLACE "/$" "" CM_MBED_PATH "${CM_MBED_PATH}")
  endif()

  set(MBED_LIB_PATH ${CM_MBED_PATH}/library/libmbedtls.a)
  set(MBED_ALL_LIBS ${MBED_LIB_PATH}
                    ${CM_MBED_PATH}/library/libmbedx509.a
                    ${CM_MBED_PATH}/library/libmbedcrypto.a)
  set(MBED_INCLUDE_PATH ${CM_MBED_PATH}/include)

  # Build the mbed static library
  if( (NOT EXISTS "${MBED_LIB_PATH}") OR (NOT EXISTS ${MSS_DIR}/lib/libmbedtls.a) )
    execute_process(COMMAND bash -c "cd ${CM_MBED_PATH} && cmake ${MBED_CM_ARGS} . \
                                   && make ${MBED_CM_LIB_TARGETS}")
    # Make sure all libraries built
    foreach(lib ${MBED_ALL_LIBS})
      if(NOT EXISTS "${lib}")
        message(FATAL_ERROR "${lib} did not get generated, which is needed.")
      endif()
    endforeach()

  endif()
endif()

## Process oqs command line args, build the oqs lib if its not already done
if(CM_ENABLE_OQS)
  if("${CM_OQS_PATH}" STREQUAL "")
    message(FATAL_ERROR "oqs option is enabled but no path has been provided")
  endif()

  # If this is a relative path, convert it to an absolute
  if(NOT IS_ABSOLUTE ${CM_OQS_PATH})
    get_filename_component(CM_OQS_PATH "${CM_OQS_PATH}" ABSOLUTE)
  endif()

  # Find out of the path provided ended with a '/', and remove it if so
  if("${CM_OQS_PATH}" MATCHES "/$")
    string(REGEX REPLACE "/$" "" CM_OQS_PATH "${CM_OQS_PATH}")
  endif()

  if (APPLE)
      set(OQS_LIB_PATH ${CM_OQS_PATH}/build/lib/liboqs.dylib)
  else()
      set(OQS_LIB_PATH ${CM_OQS_PATH}/build/lib/liboqs.so)
  endif()
  set(OQS_ALL_LIBS ${OQS_LIB_PATH})
endif()

if(CM_BUILD_X64)
    add_definitions(" -D__ENABLE_DIGICERT_BLAKE_2B__ ")
endif()

if(CM_ENABLE_TAP_EXTERN)
    add_definitions(" -D__ENABLE_DIGICERT_TAP_EXTERN__ ")
endif()

# -----------------------------------------------------------------------------

## Read and set mss flags
file(STRINGS ${MSS_FLAGS_FILE} project_flags)

#remove disabled stuff before adding in more enabled stuff
if(CM_DISABLE_PQC)
   list(REMOVE_ITEM project_flags "-D__ENABLE_DIGICERT_PQC__")
   list(REMOVE_ITEM project_flags "-D__ENABLE_DIGICERT_PQC_KEM__")
   list(REMOVE_ITEM project_flags "-D__ENABLE_DIGICERT_PQC_SIG__")
endif()

if (CM_DISABLE_SCRAM)
   list(REMOVE_ITEM project_flags "-D__ENABLE_DIGICERT_SCRAM_CLIENT__")
endif()

if (CM_DISABLE_CI OR CM_ENABLE_HW_SIM)
   list(REMOVE_ITEM project_flags "-D__ENABLE_DIGICERT_CRYPTO_KEYGEN_LIB__")
   list(REMOVE_ITEM project_flags "-D__ENABLE_DIGICERT_CV_CERT__")
endif()

foreach(flag ${project_flags})
  ## Concatenate each flag onto the existing ${MOCANA_FLAGS} list while stripping
  ## leading and trailing whitespace
  string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
endforeach()

# Read and set cryptointerface flags
if(NOT CM_DISABLE_CI)
  file(STRINGS ${CI_FLAGS_FILE} project_flags)
  foreach(flag ${project_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
  endforeach()
endif()

# Read and set mbed flags
if(CM_ENABLE_MBED)
  file(STRINGS ${MBED_FLAGS_FILE} project_flags)
  foreach(flag ${project_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
  endforeach()
endif()

# Read and set oqs flags
if(CM_ENABLE_OQS)
  file(STRINGS ${OQS_FLAGS_FILE} project_flags)
  foreach(flag ${project_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
  endforeach()
endif()

# Read and set tap flags
if(CM_ENABLE_PKCS11 OR CM_ENABLE_TPM2)
  file(STRINGS ${TAP_FLAGS_FILE} project_flags)
  foreach(flag ${project_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
  endforeach()
  # Set SMP specific flag
  if(CM_ENABLE_PKCS11)
    add_definitions(-D__ENABLE_DIGICERT_SMP_PKCS11__)
  elseif(CM_ENABLE_TPM2)
    add_definitions(-D__ENABLE_DIGICERT_TPM2__)
  endif()
  if (CM_CLIENT_TAP STREQUAL "REMOTE")
    add_definitions(-D__ENABLE_DIGICERT_TAP_REMOTE__)
  endif()
endif()

if(CM_ENABLE_CLOUDHSM)
  add_definitions(-D__ENABLE_DIGICERT_CLOUDHSM_TEST_SET__)
endif()

if(CM_ENABLE_SOFTHSM)
  add_definitions(-D__ENABLE_DIGICERT_SOFTHSM_TEST_SET__)
endif()

if(CM_ENABLE_DSSM)
  add_definitions(-D__ENABLE_DIGICERT_DIGICERT_SSM__)
endif()

# Read and set the hw-sim flags
if(CM_ENABLE_HW_SIM)
  file(STRINGS ${HW_SIM_FLAGS_FILE} project_flags)
  foreach(flag ${project_flags})
    string(STRIP "${MOCANA_FLAGS} ${flag}" MOCANA_FLAGS)
  endforeach()
endif()

if(CM_ENABLE_AIDE)
  add_definitions(-D__ENABLE_DIGICERT_AIDE_SERVER__)
endif()

if(CM_DISABLE_CI)
    string(STRIP "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_DSA__ "
          MOCANA_FLAGS)
endif()

# Set the speedtest flag
if(CM_ENABLE_SPEEDTEST)
  string(STRIP "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_UNITTEST_SPEEDTEST__"
         MOCANA_FLAGS)
endif()

if(CM_ENABLE_TAP_PRINT)
  string(STRIP "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_UNITTEST_CI_TAP_PRINT__"
         MOCANA_FLAGS)
endif()

# Set the quicktest flag
if(CM_ENABLE_QUICKTEST)
  string(STRIP "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__"
         MOCANA_FLAGS)
endif()

if(CM_QA_PATH)
 message("${MOCANA_FLAGS} -DQA_M_PRODUCTS_DIR=${CM_QA_PATH}")
  string(STRIP "${MOCANA_FLAGS} -DQA_M_PRODUCTS_DIR=${CM_QA_PATH}"
         MOCANA_FLAGS)
endif()

if(CM_ENABLE_AES_NI)
  string(STRIP "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_AES_NI__" MOCANA_FLAGS)
endif()

if(CM_ENABLE_FIPS)
  string(STRIP "${MOCANA_FLAGS} -D__ENABLE_DIGICERT_FIPS_MODULE__" MOCANA_FLAGS)
endif()

# Now add all our flags to the build
if(NOT WIN32)
  add_definitions("${MOCANA_FLAGS} -D__ENABLE_DIGICERT_DEV_URANDOM__")
else()
  add_definitions("${MOCANA_FLAGS}")
endif()

add_definitions(-DTEST_DIR=${MSS_TEST_DIR}/)

message("MOCANA_FLAGS = ${MOCANA_FLAGS}")

## Add include directories
set(MSS_INCLUDE_DIRS "." ${MSS_SRC_DIR} ${MSS_LIB_DIR} ${MSS_TEST_DIR})
if(CM_ENABLE_MBED)
  set(MSS_INCLUDE_DIRS ${MSS_INCLUDE_DIRS} ${MBED_INCLUDE_PATH})
endif()
if(CM_ENABLE_AES_NI)
  set(MSS_INCLUDE_DIRS ${MSS_INCLUDE_DIRS} ${MSS_SRC_DIR}/crypto/intel_aes_ni/include)
endif()
if(CM_ENABLE_PKCS11 OR CM_ENABLE_TPM2)
  set(MSS_INCLUDE_DIRS ${MSS_INCLUDE_DIRS} ${MSS_SRC_DIR}/crypto_interface/example/)
endif()

include_directories(${MSS_INCLUDE_DIRS})

## Define the test program
add_executable(${MSS_LIB_NAME}_test main.c ${MSS_TEST_SOURCES})

add_custom_target(main_c ALL
                  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/main.c)
add_dependencies(${MSS_LIB_NAME}_test main_c)

file(GLOB UNITTEST_SRC ${MSS_UNITTEST_DIR}/*.c)
add_library(unittest STATIC ${UNITTEST_SRC})

if(CM_ENABLE_OPERATORS)
  if("${CM_OPERATOR_PATH}" STREQUAL "")
    message(FATAL_ERROR "operator option is enabled but no path has been provided")
  endif()

  # If this is a relative path, convert it to an absolute
  if(NOT IS_ABSOLUTE ${CM_OPERATOR_PATH})
    get_filename_component(CM_OPERATOR_PATH "${CM_OPERATOR_PATH}" ABSOLUTE)
  endif()

  # Check if it exists 
  if(NOT EXISTS "${CM_OPERATOR_PATH}")
    message(FATAL_ERROR "Operator library not found.")
  endif()

  add_library(OP_LIB STATIC IMPORTED)
  set_property(TARGET OP_LIB PROPERTY IMPORTED_LOCATION ${CM_OPERATOR_PATH})
  set(OPERATOR_LIB OP_LIB)
else()
  set(OPERATOR_LIB "")
endif()

create_target_import_lib(common)
create_target_import_lib(platform)
create_target_import_lib(nanocrypto)
create_target_import_lib(asn1)
create_target_import_lib(cryptointerface)
create_target_import_lib(nanocert)
create_target_import_lib(nanocap)
create_target_import_lib(initialize)
if(CM_ENABLE_FIPS)
  if(WIN32)
    create_target_import_lib(libmss)
  else()
    create_target_import_lib(mss)
  endif()
endif()

## What to link
set(LIB_LINK_ORDER
    common
    platform
    asn1
    cryptointerface
    nanocrypto
    nanocert
    nanocap
    initialize
    unittest
    ${OPERATOR_LIB})
if(CM_ENABLE_FIPS)
  if(WIN32)
    set(LIB_LINK_ORDER ${LIB_LINK_ORDER} libmss)
  else()
    set(LIB_LINK_ORDER ${LIB_LINK_ORDER} mss)
  endif()
endif()

if(CM_ENABLE_HW_SIM)
  create_target_import_lib(hw)
  set(LIB_LINK_ORDER ${LIB_LINK_ORDER} hw)
endif()

if ( (CM_CLIENT_TAP STREQUAL "LOCAL") OR (CM_CLIENT_TAP STREQUAL "REMOTE") )
  create_target_import_lib(nanotap2_common)
  create_target_import_lib(nanotap2_configparser)
  create_target_import_lib(nanotap2)
  set(LIB_LINK_ORDER ${LIB_LINK_ORDER} nanotap2_common nanotap2_configparser nanotap2)
endif()

if(CM_ENABLE_PKCS11_TEE)
  create_target_import_lib(ckteec)
  create_target_import_lib(teec)
  set(LIB_LINK_ORDER ${LIB_LINK_ORDER} ckteec teec)
endif()

# Add 'pthread' lib when on Linux and socket on qnx

if("${CM_TOOLCHAIN}" STREQUAL "qnx-x86")
  set(EXTRA_LIBS socket)
else()
  if(UNIX)
    set(EXTRA_LIBS pthread)
  else()
    set(EXTRA_LIBS "")
  endif()
endif()

# Add mbed static libs if enabled
if(CM_ENABLE_MBED)
  create_target_import_lib(nanocap_mbed)
  set(LIB_LINK_ORDER ${LIB_LINK_ORDER}
      nanocap_mbed
      ${MBED_ALL_LIBS})
endif()

# Add oqs static libs if enabled
if(CM_ENABLE_OQS)
  create_target_import_lib(nanocap_oqs)
  set(LIB_LINK_ORDER ${LIB_LINK_ORDER}
      nanocap_oqs
      ${OQS_ALL_LIBS})
endif()

if(CM_ENABLE_AES_NI)
  if(EXISTS "${MSS_SRC_DIR}/crypto/intel_aes_ni/intel_aes_ni.a")
    set(LIBAESNI_PATH "${MSS_SRC_DIR}/crypto/intel_aes_ni/intel_aes_ni.a")
  elseif(EXISTS "${MSS_BIN_DIR}/intel_aes_ni.a")
    set(LIBAESNI_PATH "${MSS_BIN_DIR}/intel_aes_ni.a")
  else()
    message(FATAL_ERROR "intel_aes_ni.a not found in either ${MSS_BIN_DIR}/ "
            "or ${MSS_SRC_DIR}/crypto/intel_aes_ni/")
  endif()

  add_library(AESNI_LIB STATIC IMPORTED)
  set_property(TARGET AESNI_LIB PROPERTY IMPORTED_LOCATION ${LIBAESNI_PATH})

  message("\nLinking to intel_aes_ni.a")
  set(LIB_LINK_ORDER ${LIB_LINK_ORDER} AESNI_LIB)
endif()

target_link_libraries(${MSS_LIB_NAME}_test
                      ${LIB_LINK_ORDER}
                      ${EXTRA_LIBS})

## Use CTest
set(CT_VALGRIND_XML_OPTIONS
    "--xml=yes --xml-file=${CMAKE_SOURCE_DIR}/memcheck.xml")
set(CT_VALGRIND_MEMCHECK_OPTIONS
    "--tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=50")

## Set DART variableas
set(VALGRIND_COMMAND_OPTIONS
    "${CT_VALGRIND_XML_OPTIONS} ${CT_VALGRIND_MEMCHECK_OPTIONS}")

include(CTest)

## Set test cases
set(CT_TEST_CASES "")

enable_testing()
add_test(NAME ${MSS_LIB_NAME} WORKING_DIRECTORY ${MSS_TEST_DIR}
    COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${MSS_LIB_NAME}_test ${CT_TEST_CASES}
    )

# Get a list of all the certs/keys in mss/src/crypto/test
file(GLOB DER_FILES ${MSS_SRC_DIR}/crypto/test/*.der)
file(GLOB PEM_FILES ${MSS_SRC_DIR}/crypto/test/*.pem)
file(GLOB DAT_FILES ${MSS_SRC_DIR}/crypto/test/*.dat)
set(CRYPTO_CREDS ${DER_FILES} ${PEM_FILES} ${DAT_FILES})

# Move all the creds to src/crypto_interface/test
add_custom_command(
    TARGET ${MSS_LIB_NAME}_test
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${CRYPTO_CREDS} ${MSS_TEST_DIR})

if(WIN32)
  # Move the binary to the bin dir
  add_custom_command(
      TARGET ${MSS_LIB_NAME}_test
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_directory
          $<TARGET_FILE_DIR:${MSS_LIB_NAME}_test>
          ${MSS_BIN_DIR})
endif()
