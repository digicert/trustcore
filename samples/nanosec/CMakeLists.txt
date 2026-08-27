cmake_minimum_required(VERSION 3.16)

project(NanoSec LANGUAGES C)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
endif()

if (DEFINED SECURE_PATH)
  message("\nSECURE_PATH = ${SECURE_PATH}")
  add_definitions("-D__ENABLE_DIGICERT_SECURE_PATH__")
  add_definitions("-D__ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__")
  add_definitions("-DMANDATORY_BASE_PATH=\"${SECURE_PATH}\"")
endif()

set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
set(MSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(LIB_DIR       "${CMAKE_CURRENT_SOURCE_DIR}/../../lib")
set(BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../bin")
set(CMAKE_BUILD_RPATH "${LIB_DIR}")
set(SAMPLE_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../samples/bin")

# The IKE library/target is named after the selected variant. The SP800-135 test
# build produces lib<ike_sp800_135> and its executable, otherwise the default ike.
if(CM_BUILD_IKE_SP800_135)
  set(IKE_TARGET_NAME "ike_sp800_135")
else()
  set(IKE_TARGET_NAME "ike")
endif()
set(SAMPLE_FILE_PATH "${SAMPLE_BIN_DIR}/${IKE_TARGET_NAME}")

###############################################################################################
# Kernel module builds (when CM_BUILD_IPSECMOD=ON, set via BUILD_KERNELMOD in top-level CMake)
###############################################################################################
if(CM_BUILD_IPSECMOD)
  execute_process(COMMAND uname -r OUTPUT_VARIABLE KERNEL_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(KDIR "/lib/modules/${KERNEL_VERSION}/build")
  set(MODDIR "/lib/modules/${KERNEL_VERSION}/kernel/mocana")

  # Out-of-tree kernel modules must be built with the same compiler the
  # running kernel was built with. The kernel injects flags such as
  # -ftrivial-auto-var-init=zero that older gcc versions reject, so detect the
  # kernel's gcc major version and use a matching gcc-<major> binary if present.
  # KMOD_CC_ARG is passed on the module make command lines; GNU make forwards
  # command-line overrides (CC=...) to every recursive/sub-make via MAKEFLAGS,
  # so it reaches the inner "make -C $(KDIR) ... modules" invocation as well.
  set(KMOD_CC_ARG)
  set(_kernel_cc_line "")
  if(EXISTS "${KDIR}/.config")
    file(STRINGS "${KDIR}/.config" _kernel_cc_line REGEX "^CONFIG_CC_VERSION_TEXT=.*gcc")
  endif()
  if(_kernel_cc_line MATCHES "gcc-([0-9]+)")
    set(_kernel_gcc_major "${CMAKE_MATCH_1}")
    find_program(KERNEL_CC "gcc-${_kernel_gcc_major}")
    if(KERNEL_CC)
      set(KMOD_CC_ARG "CC=${KERNEL_CC}")
      message(STATUS "Kernel modules will be built with ${KERNEL_CC} (matches kernel compiler)")
    else()
      message(WARNING
        "The running kernel was built with gcc-${_kernel_gcc_major}, but that "
        "compiler was not found. Install gcc-${_kernel_gcc_major} if the kernel "
        "module build fails with an 'unrecognized command-line option' error.")
    endif()
  endif()


  foreach(_dir common crypto harness platform)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_dir}")
      execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink
        "${SRC_DIR}/${_dir}"
        "${CMAKE_CURRENT_SOURCE_DIR}/${_dir}")
    endif()
  endforeach()

  foreach(_dir common crypto harness platform)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/linux/${_dir}")
      execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink
        "${SRC_DIR}/${_dir}"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/linux/${_dir}")
    endif()
  endforeach()

  # 1. moc_platform_mod.ko (+ moc_ipsec_bridge.ko in FIPS builds)
  if(CM_ENABLE_FIPS)
    set(_fips_symvers_default "${MSS_DIR}/src/fips/crypto_module/kernel_modules/crypto/Module.symvers")
    if(DEFINED ENV{KBUILD_EXTRA_SYMBOLS} AND NOT "$ENV{KBUILD_EXTRA_SYMBOLS}" STREQUAL "")
      set(FIPS_CRYPTO_SYMVERS "$ENV{KBUILD_EXTRA_SYMBOLS}")
    else()
      set(FIPS_CRYPTO_SYMVERS "${_fips_symvers_default}")
    endif()
    if(NOT EXISTS "${FIPS_CRYPTO_SYMVERS}")
      message(FATAL_ERROR
        "FIPS kernel-module build requires the prebuilt FIPS crypto "
        "Module.symvers. Set KBUILD_EXTRA_SYMBOLS to its path before "
        "configuring, or place it at ${_fips_symvers_default}.")
    endif()
    message(STATUS "FIPS crypto Module.symvers = ${FIPS_CRYPTO_SYMVERS}")

    # NOTE: moc_ipsec_bridge.o is an obsolete pre-rename compatibility shim.
    # It imports literal MOC_* symbols and re-exports them as DIGI_*, which only
    # made sense when moc_platform.c exported MOC_* names. In this (renamed) tree
    # moc_platform.c exports the DIGI_* platform symbols directly, so the bridge
    # is redundant and would fail modpost with undefined MOC_* symbols. We build
    # moc_platform_mod.ko WITHOUT NO_CRYPTO so the bridge is not compiled.
    add_custom_target(moc_platform_mod
      COMMAND make TGTNAME=x86_64 KERNEL=${KERNEL_VERSION} RTOS=__RTOS_LINUX__
              KDIR=${KDIR} MODDIR=${MODDIR} MSS_DIR=${MSS_DIR}
              ${KMOD_CC_ARG}
              clean all
      COMMAND ${CMAKE_COMMAND} -E copy
              ${CMAKE_CURRENT_SOURCE_DIR}/src/moc_platform_module/moc_platform_mod.ko ${BIN_DIR}/
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/moc_platform_module
      COMMENT "Building moc_platform_mod.ko (FIPS, DIGI_* platform exports)"
    )
  else()
    add_custom_target(moc_platform_mod
      COMMAND make TGTNAME=x86_64 KERNEL=${KERNEL_VERSION} RTOS=__RTOS_LINUX__
              KDIR=${KDIR} MODDIR=${MODDIR} MSS_DIR=${MSS_DIR} ${KMOD_CC_ARG} all
      COMMAND ${CMAKE_COMMAND} -E copy
              ${CMAKE_CURRENT_SOURCE_DIR}/src/moc_platform_module/moc_platform_mod.ko ${BIN_DIR}/
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/moc_platform_module
      COMMENT "Building moc_platform_mod.ko"
    )
  endif()

  # 2. moc_crypto.ko
  if(CM_ENABLE_FIPS)
    add_custom_target(moc_crypto
      DEPENDS moc_platform_mod
      COMMENT "Skipping moc_crypto build (FIPS uses prebuilt moc_crypto.ko)"
    )
  else()
    # The crypto sources are symlinked in-place and use relative includes like
    # "../common/moptions.h" and "../crypto/aes.h". The example Makefile normally
    # resolves these via its own `CC=gcc -I$(PWD)/../`, but our ${KMOD_CC_ARG}
    # (CC=gcc-<major>) is a command-line override that supersedes the Makefile's
    # CC and drops that -I. We restore it through KCFLAGS, but must use -iquote
    # (not -I): kbuild appends KCFLAGS *after* the kernel's own -I paths, and the
    # kernel tree ships a conflicting crypto/aes.h that would otherwise shadow
    # Mocana's aes.h. For quoted includes gcc searches -iquote dirs before all -I
    # dirs, so the absolute path below wins and "../common"/"../crypto" resolve to
    # the samples/nanosec/{common,crypto} symlinks regardless of the build cwd.
    add_custom_target(moc_crypto
      COMMAND ${CMAKE_COMMAND} -E env
              "KCFLAGS=-iquote${CMAKE_CURRENT_SOURCE_DIR}/src"
              make TGTNAME=x86_64 KERNEL=${KERNEL_VERSION} RTOS=__RTOS_LINUX__
              KDIR=${KDIR} MODDIR=${MODDIR} MSS_DIR=${MSS_DIR}
              KBUILD_EXTRA_SYMBOLS=${CMAKE_CURRENT_SOURCE_DIR}/src/moc_platform_module/Module.symvers
              ${KMOD_CC_ARG}
              links all
      COMMAND ${CMAKE_COMMAND} -E copy
              ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_module_example/moc_crypto.ko ${BIN_DIR}/
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_module_example
      DEPENDS moc_platform_mod
      COMMENT "Building moc_crypto.ko"
    )
  endif()

  # 3. IPsec kernel modules (moc_ipsec.ko, moc_ipsec_mod.ko, moc_memdrv.ko)
  # FIPS builds need NO_CRYPTO=true and KBUILD_EXTRA_SYMBOLS pointing at both
  # the FIPS crypto Module.symvers and the moc_platform_module Module.symvers
  if(CM_ENABLE_FIPS)
    set(_ipsec_extra_symvers "${FIPS_CRYPTO_SYMVERS} ${CMAKE_CURRENT_SOURCE_DIR}/src/moc_platform_module/Module.symvers")
    add_custom_target(ipsec_modules
      COMMAND ${CMAKE_COMMAND} -E env
              "KBUILD_EXTRA_SYMBOLS=${_ipsec_extra_symvers}"
              "KCFLAGS=-Wno-error=strict-prototypes -Wno-error=old-style-definition -Wno-error=missing-prototypes"
              make NO_CRYPTO=true BUILD_IPSEC_MOD=y SUITEB=y CUSTOM_ENTROPY=y CLEAN=
                   MSS_DIR=${MSS_DIR} ${KMOD_CC_ARG} -f make/Makefile.linux.ipsec.qa modules
      COMMAND make CLEAN= MSS_DIR=${MSS_DIR} -f make/Makefile.linux.ipsec.qa loadConfig
      COMMAND ${CMAKE_COMMAND} -E copy
              ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/mocana/moc_ipsec.ko ${BIN_DIR}/
      WORKING_DIRECTORY ${MSS_DIR}
      DEPENDS moc_crypto
      COMMENT "Building IPsec kernel modules and loadConfig (FIPS)"
    )
  else()
    add_custom_target(ipsec_modules
      COMMAND make BUILD_IPSEC_MOD=y SUITEB=y CLEAN= MSS_DIR=${MSS_DIR} ${KMOD_CC_ARG} -f make/Makefile.linux.ipsec.qa modules
      COMMAND make CLEAN= MSS_DIR=${MSS_DIR} -f make/Makefile.linux.ipsec.qa loadConfig
      COMMAND ${CMAKE_COMMAND} -E copy
              ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/mocana/moc_ipsec.ko ${BIN_DIR}/
      WORKING_DIRECTORY ${MSS_DIR}
      DEPENDS moc_crypto
      COMMENT "Building IPsec kernel modules and loadConfig"
    )
  endif()

endif()

set(INCLUDE_DIR
    ${SRC_DIR}/ike
    ${SRC_DIR}/ike2
    ${SRC_DIR}/ipsec
    ${SRC_DIR}/common
    ${SRC_DIR}/crypto
    ${SRC_DIR}/asn1
    ${SRC_DIR}/platform
    ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/gpl
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )
include_directories(${INCLUDE_DIR})

# IKE compile definitions (shared between library and example)
set(IKE_DEFINITIONS
    __RTOS_LINUX__
    __ENABLE_DIGICERT_64_BIT__
    MOC_LITTLE_ENDIAN
    __ENABLE_DIGICERT_IKE_SERVER__
    __ENABLE_DIGICERT_EXAMPLES__
    __ENABLE_IPSEC_NAT_T__
    __ENABLE_IKE_PPK_RFC8784__
    __ENABLE_IPSEC_MARGIN_LIFETIME__
    __ENABLE_DIGICERT_MEM_PART__
)

if(WITH_LOGGING)
  list(APPEND IKE_DEFINITIONS
    __ENABLE_ALL_DEBUGGING__
    __ENABLE_DIGICERT_DEBUG_CONSOLE__
    __DIGICERT_DUMP_CONSOLE_TO_STDOUT__
  )
endif()

# Compile in EAP support
function(_append_eap_flags_from_file flags_file)
  file(STRINGS "${flags_file}" _flags)
  foreach(_flag ${_flags})
    string(STRIP "${_flag}" _flag)
    string(REGEX REPLACE "^-D" "" _flag "${_flag}")
    list(APPEND IKE_DEFINITIONS ${_flag})
  endforeach()
  set(IKE_DEFINITIONS ${IKE_DEFINITIONS} PARENT_SCOPE)
endfunction()

set(_EAP_FLAGS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../projects/nanosec")

if(CM_ENABLE_EAPA)
  _append_eap_flags_from_file("${_EAP_FLAGS_DIR}/mocana_eap_flags.txt")
  _append_eap_flags_from_file("${_EAP_FLAGS_DIR}/mocana_eap_auth_flags.txt")
endif()

if(CM_ENABLE_EAPS)
  _append_eap_flags_from_file("${_EAP_FLAGS_DIR}/mocana_eap_flags.txt")
  _append_eap_flags_from_file("${_EAP_FLAGS_DIR}/mocana_eap_supplicant_flags.txt")
endif()

if(CM_ENABLE_TLSA)
  _append_eap_flags_from_file("${_EAP_FLAGS_DIR}/mocana_tls_flags.txt")
  _append_eap_flags_from_file("${_EAP_FLAGS_DIR}/mocana_tls_eap_auth_flags.txt")
endif()

if(CM_ENABLE_TLSS)
  _append_eap_flags_from_file("${_EAP_FLAGS_DIR}/mocana_tls_flags.txt")
endif()

########################################################################
# Build nanosec example executable
########################################################################
# The default sample provides the full IKE server: digicert_example.c holds
# main(), which calls IKE_EXAMPLE_main() from ike_example.c.
#
# The SP800-135 test variant instead builds the NIST KDF known-answer harness
# (ike2/nist/test/ike2_nist_sample.c). That file carries its own main() which
# runs sampleUsageIKE() and prints "sampleUsageIKE status = 0" then exits, so it
# must NOT be linked with digicert_example.c/ike_example.c (duplicate main). Its
# body is fully guarded by __ENABLE_DIGICERT_SP800_135_ACVP__, added below. This
# source set mirrors projects/nanosec/example/mss_ike_sp800_135_sources.txt.
set(SOURCE_FILES
    ${SRC_DIR}/../samples/common/ca_mgmt_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ike_cert_utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ikeadm_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ikecfg_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ipseckey_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mcp_example.c
    ${SRC_DIR}/common/mstdlib.c
    ${SRC_DIR}/common/mem_part.c
    ${SRC_DIR}/platform/kmem_part.c
)

if(CM_BUILD_IKE_SP800_135)
  list(APPEND SOURCE_FILES ${SRC_DIR}/ike2/nist/test/ike2_nist_sample.c)
  list(APPEND IKE_DEFINITIONS __ENABLE_DIGICERT_SP800_135_ACVP__)
else()
  list(APPEND SOURCE_FILES
      ${SRC_DIR}/../samples/common/digicert_example.c
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ike_example.c
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ipseckey_example_linux.c
  )
endif()

add_executable(nanosec ${SOURCE_FILES})
set_target_properties(nanosec PROPERTIES OUTPUT_NAME "${IKE_TARGET_NAME}")

if(TARGET ${IKE_TARGET_NAME})
  add_dependencies(nanosec ${IKE_TARGET_NAME})
  set_source_files_properties("${LIB_DIR}/lib${IKE_TARGET_NAME}.so" PROPERTIES GENERATED TRUE)
  set_source_files_properties("${LIB_DIR}/lib${IKE_TARGET_NAME}.a"  PROPERTIES GENERATED TRUE)
endif()

if(CM_BUILD_IPSECMOD)
  add_dependencies(nanosec ipsec_modules)
endif()

if(CM_ENABLE_TAP)
  add_dependencies(nanosec nanotap2 nanotap2_common nanotap2_configparser)
  if(ENABLE_TPM2)
    add_dependencies(nanosec smptpm2 tpm2)
  endif()
endif()

target_compile_definitions(nanosec PRIVATE ${IKE_DEFINITIONS})

if("STATIC" STREQUAL "${LIB_TYPE}")
  message("Building nanosec with STATIC libraries")

  set(ASN1_LIB             "${LIB_DIR}/libasn1.a")
  set(COMMON_LIB           "${LIB_DIR}/libcommon.a")
  set(INITIALIZE_LIB       "${LIB_DIR}/libinitialize.a")
  set(PLATFORM_LIB         "${LIB_DIR}/libplatform.a")
  set(NANOSSL_LIB          "${LIB_DIR}/libnanossl.a")
  set(NANOCRYPTO_LIB       "${LIB_DIR}/libnanocrypto.a")
  set(NANOCAP_LIB          "${LIB_DIR}/libnanocap.a")
  set(NANOCERT_LIB         "${LIB_DIR}/libnanocert.a")
  set(CERT_ENROLL_LIB      "${LIB_DIR}/libcert_enroll.a")
  set(CRYPTO_INTERFACE_LIB "${LIB_DIR}/libcryptointerface.a")
  set(IKE_LIB              "${LIB_DIR}/lib${IKE_TARGET_NAME}.a")
  if(CM_ENABLE_TAP)
    set(NANOTAP2_COMMON_LIB  "${LIB_DIR}/libnanotap2_common.a")
    set(NANOTAP2_CONFIGPARSER_LIB "${LIB_DIR}/libnanotap2_configparser.a")
    set(NANOTAP2_LIB         "${LIB_DIR}/libnanotap2.a")
    if(ENABLE_TPM2)
      set(SMP_LIB            "${LIB_DIR}/libsmptpm2.a")
      set(TPM2_LIB           "${LIB_DIR}/libtpm2.a")
    endif()
  endif()
  if(CM_ENABLE_FIPS)
    set(FIPS_LIB           "${LIB_DIR}/libmss.so")
    if(NOT EXISTS "${FIPS_LIB}")
      message(FATAL_ERROR "FIPS build requires libmss.so in ${LIB_DIR}. Copy your FIPS-enabled libmss.so there before building.")
    endif()
    list(APPEND CMAKE_BUILD_RPATH "${LIB_DIR}")
    list(APPEND CMAKE_INSTALL_RPATH "${LIB_DIR}")
  endif()

else()
  message("Building nanosec with SHARED libraries")

  set(ASN1_LIB             "${LIB_DIR}/libasn1.so")
  set(COMMON_LIB           "${LIB_DIR}/libcommon.so")
  set(INITIALIZE_LIB       "${LIB_DIR}/libinitialize.so")
  set(PLATFORM_LIB         "${LIB_DIR}/libplatform.so")
  set(NANOSSL_LIB          "${LIB_DIR}/libnanossl.so")
  set(NANOCRYPTO_LIB       "${LIB_DIR}/libnanocrypto.so")
  set(NANOCAP_LIB          "${LIB_DIR}/libnanocap.so")
  set(NANOCERT_LIB         "${LIB_DIR}/libnanocert.so")
  set(CERT_ENROLL_LIB      "${LIB_DIR}/libcert_enroll.so")
  set(CRYPTO_INTERFACE_LIB "${LIB_DIR}/libcryptointerface.so")
  set(IKE_LIB              "${LIB_DIR}/lib${IKE_TARGET_NAME}.so")
  if(CM_ENABLE_FIPS)
    set(FIPS_LIB           "${LIB_DIR}/libmss.so")
    if(NOT EXISTS "${FIPS_LIB}")
      message(FATAL_ERROR "FIPS build requires libmss.so in ${LIB_DIR}. Copy your FIPS-enabled libmss.so there before building.")
    endif()
    list(APPEND CMAKE_BUILD_RPATH "${LIB_DIR}")
    list(APPEND CMAKE_INSTALL_RPATH "${LIB_DIR}")
  endif()
  if(CM_ENABLE_TAP)
    set(NANOTAP2_COMMON_LIB  "${LIB_DIR}/libnanotap2_common.so")
    set(NANOTAP2_CONFIGPARSER_LIB "${LIB_DIR}/libnanotap2_configparser.so")
    set(NANOTAP2_LIB         "${LIB_DIR}/libnanotap2.so")
    if(ENABLE_TPM2)
      set(SMP_LIB            "${LIB_DIR}/libsmptpm2.so")
      set(TPM2_LIB           "${LIB_DIR}/libtpm2.so")
    endif()
  endif()

endif()

if("STATIC" STREQUAL "${LIB_TYPE}")
  target_link_libraries(nanosec PRIVATE
      ${IKE_LIB}
      ${NANOSSL_LIB}
      ${CERT_ENROLL_LIB}
      ${NANOCERT_LIB}
      -Wl,--start-group
      ${INITIALIZE_LIB}
      ${NANOCRYPTO_LIB}
      ${CRYPTO_INTERFACE_LIB}
      ${NANOCAP_LIB}
      ${FIPS_LIB}
      -Wl,--end-group
      ${ASN1_LIB}
      ${COMMON_LIB}
      ${PLATFORM_LIB}
      pthread
      dl
  )
  if(CM_ENABLE_TAP)
    target_link_libraries(nanosec PRIVATE
        ${NANOTAP2_LIB}
        ${NANOTAP2_CONFIGPARSER_LIB}
        ${NANOTAP2_COMMON_LIB}
        ${SMP_LIB}
        ${TPM2_LIB}
    )
  endif()
else()
  target_link_libraries(nanosec PRIVATE
      ${IKE_LIB}
      ${PLATFORM_LIB}
      ${ASN1_LIB}
      ${COMMON_LIB}
      ${INITIALIZE_LIB}
      ${NANOCRYPTO_LIB}
      ${NANOCAP_LIB}
      ${CRYPTO_INTERFACE_LIB}
      ${NANOCERT_LIB}
      ${NANOSSL_LIB}
      ${CERT_ENROLL_LIB}
      ${FIPS_LIB}
      pthread
      dl
  )
  if(CM_ENABLE_TAP)
    target_link_libraries(nanosec PRIVATE
        ${NANOTAP2_COMMON_LIB}
        ${NANOTAP2_CONFIGPARSER_LIB}
        ${NANOTAP2_LIB}
        ${SMP_LIB}
        ${TPM2_LIB}
    )
  endif()
endif()

add_custom_command(
  TARGET nanosec
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:nanosec> ${SAMPLE_FILE_PATH}
)
