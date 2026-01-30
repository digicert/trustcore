cmake_minimum_required(VERSION 3.5)

function(show_usage)
  message("Build Crypto Interface unit tests")
  message("cmake -P build.cmake [OPTIONS]")
  message("OPTIONS:")
  message("--no-ci               - Build with Crypto Interface disabled.")
  message("--speedtest           - Get execution time for operations.")
  message("--quick               - Reduces the number of tests executed.")
  message("--mbedtls             - Adds test with MbedTLS as the crypto.")
  message("--mbed-path           - Argument for path to MbedTLS. Must be followed by the path.")
  message("--oqs                 - Adds oqs tests")
  message("--oqs-path            - Argument for path to OQS Library. Must be followed by the path.")
  message("--pkcs11              - Build with PKCS11 TAP")
  message("--pkcs11-path         - Argument for path to the softhsm2 pkcs11 Library. Must be followed by the path.")
  message("--hw-sim              - Build with hardware acceleration simulator")
  message("--qa-products-path    - Arguent for path to m-qa-products. Optional.")
  message(FATAL_ERROR "")
endfunction()

set(MSS_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)

message("Building CryptoInterface Unit Test project.")
execute_process(
  COMMAND clean.bat
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})

# Create the build dir
file(MAKE_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/build)

set(BUILD_OPTIONS "")
set(MBED_BUILD OFF)
set(MBED_PATH "")
set(OQS_BUILD OFF)
set(OQS_PATH "")
set(QA_PROD_PATH "")
set(FULL_EXPORT_ARG "")
set(PKCS11_BUILD OFF)
set(PKCS11_PATH "")
set(PKCS11_ARG "")
set(DATA_PROTECT_ARG "")
set(TAP_DATA_PROTECT_ARG "")
set(FIPS_ARG "")
set(REBUILD_LIBS ON)
set(INV_OPT OFF)

# Skip first 3 arguments - (cmake -P <file>)
set(ARG_NUM 3)

math(EXPR ARGC_COUNT "${CMAKE_ARGC}")

# Loop through caller arguments
while (ARG_NUM LESS ARGC_COUNT)

  set(CURRENT_ARG ${CMAKE_ARGV${ARG_NUM}})

  if("${CURRENT_ARG}" STREQUAL "--no-ci")
    message("-- Building w/ CryptoInterface disabled...")
    set(BUILD_OPTIONS ${BUILD_OPTIONS} "-DCM_DISABLE_CI=ON")

  elseif("${CURRENT_ARG}" STREQUAL "--speedtest")
    message("-- Building w/ speedtests enabled...")
    set(BUILD_OPTIONS ${BUILD_OPTIONS} "-DCM_ENABLE_SPEEDTEST=ON")
  
  elseif("${CURRENT_ARG}" STREQUAL "--quick")
    message("-- Building w/ quicktest enabled...")
    set(BUILD_OPTIONS ${BUILD_OPTIONS} "-DCM_ENABLE_QUICKTEST=ON")

  elseif("${CURRENT_ARG}" STREQUAL "--mbedtls")
    message("-- Building w/ mbedtls enabled...")
    set(BUILD_OPTIONS ${BUILD_OPTIONS} "-DCM_ENABLE_MBED=ON")

  elseif("${CURRENT_ARG}" STREQUAL "--mbed-path")
    math(EXPR ARG_NUM "${ARG_NUM}+1")
    set(MBED_PATH "${CMAKE_ARGV${ARG_NUM}}")
    set(BUILD_OPTIONS ${BUILD_OPTIONS} "-DCM_MBED_PATH=${MBED_PATH}")
    set(FULL_EXPORT_ARG ${FULL_EXPORT_ARG} "--export" "--mbed" "--mbed-path" "${MBED_PATH}")

  elseif("${CURRENT_ARG}" STREQUAL "--oqs")
    message("-- Building with oqs enabled...")
    set(BUILD_OPTIONS ${BUILD_OPTIONS} "-DCM_ENABLE_OQS=ON")
    set(OQS_BUILD ON)

  elseif("${CURRENT_ARG}" STREQUAL "--oqs-path")
    math(EXPR ARG_NUM "${ARG_NUM}+1")
    set(OQS_PATH "${CMAKE_ARGV${ARG_NUM}}")
    set(BUILD_OPTIONS ${BUILD_OPTIONS} "-DCM_OQS_PATH=${OQS_PATH}")
    set(FULL_EXPORT_ARG ${FULL_EXPORT_ARG} "--oqs" "--oqs-path" "${OQS_PATH}")

  elseif("${CURRENT_ARG}" STREQUAL "--pkcs11")
    message(FATAL_ERROR "${CURRENT_ARG} not implemented.")

  elseif("${CURRENT_ARG}" STREQUAL "--pkcs11-path")
    message(FATAL_ERROR "${CURRENT_ARG} not implemented.")

  elseif("${CURRENT_ARG}" STREQUAL "--data-protect")
    message(FATAL_ERROR "${CURRENT_ARG} not implemented.")

  elseif("${CURRENT_ARG}" STREQUAL "--tap-data-protect")
    message(FATAL_ERROR "${CURRENT_ARG} not implemented.")

  elseif("${CURRENT_ARG}" STREQUAL "--qa-products-path")
    message(FATAL_ERROR "${CURRENT_ARG} not implemented.")

  elseif("${CURRENT_ARG}" STREQUAL "--hw-sim")
    message(FATAL_ERROR "${CURRENT_ARG} not implemented.")

  elseif("${CURRENT_ARG}" STREQUAL "--fips")
    message("-- Building w/ FIPS enabled...")
    set(BUILD_OPTIONS ${BUILD_OPTIONS} "-DCM_ENABLE_FIPS=ON")
    set(FIPS_ARG "${CURRENT_ARG}")

  elseif("${CURRENT_ARG}" STREQUAL "--no-lib-rebuild")
    set(REBUILD_LIBS OFF)

  else()
    message("Invalid option: ${CURRENT_ARG}")
    set(INV_OPT ON)

  endif()

  # Increment arg count
  math(EXPR ARG_NUM "${ARG_NUM}+1")

endwhile()

if(INV_OPT)
    show_usage()
endif()

message("Building dependent libs")

if(REBUILD_LIBS)
  execute_process(
    COMMAND build_crypto_shared_libs.bat --gdb --debug --cert ${DATA_PROTECT_ARG} ${TAP_DATA_PROTECT_ARG} ${FIPS_ARG} ${FULL_EXPORT_ARG}
    WORKING_DIRECTORY ${MSS_DIR}/scripts
    RESULT_VARIABLE rc)
  if(NOT rc EQUAL "0")
    message(FATAL_ERROR "${rc}")
  endif()
  file(REMOVE ${MSS_DIR}/bin_win32/nanocrypto.*)
  file(REMOVE ${MSS_DIR}/bin_win32/cryptointerface.*)
  execute_process(
    COMMAND build.bat --gdb --debug --ci-tests --x64 ${FIPS_ARG} ${FULL_EXPORT_ARG}
    WORKING_DIRECTORY ${MSS_DIR}/projects/crypto
    RESULT_VARIABLE rc)
  if(NOT rc EQUAL "0")
    message(FATAL_ERROR "${rc}")
  endif()
endif()

message("BUILD_OPTIONS=${BUILD_OPTIONS}")

execute_process(
  COMMAND cmake -G "Visual Studio 15 2017 Win64" -DCMAKE_BUILD_TYPE=Debug ${BUILD_OPTIONS} ..
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/build
  RESULT_VARIABLE rc)
if(NOT rc EQUAL "0")
  message(FATAL_ERROR "${rc}")
endif()

execute_process(
  COMMAND msbuild cryptointerface_test.sln /p:Configuration=Debug /p:Platform=x64
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/build
  RESULT_VARIABLE rc)
if(NOT rc EQUAL "0")
  message(FATAL_ERROR "${rc}")
endif()
