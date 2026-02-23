########################################################################
# CMake build script for nanocrypto library
########################################################################

if(BUILD_FOR_OSI)
  cmake_minimum_required(VERSION 3.16)
else()
  cmake_minimum_required(VERSION 3.5)
endif()

if(CM_ENABLE_EXPORT_ED)
    project(cryptomw C)
else()
    project(nanocrypto C)
endif()

# Load options flags
message("\nOPTIONS_MOCANA_FLAGS = ${OPTIONS_MOCANA_FLAGS}")
add_definitions(${OPTIONS_MOCANA_FLAGS})

# Toggle MOC_EXTERN_DATA_DEF/DECL to map to '__declspec(dllexport)'
if(WIN32)
    set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DWIN_EXPORT_CRYPTO")
    if(NOT CM_ENABLE_FIPS)
      set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS} -DWIN_EXPORT_PKCS1_INT -DWIN_EXPORT_RANDOM_H -DWIN_EXPORT_PRIMEEC_H -DWIN_EXPORT_PRIMEFLD_H")
    endif()
endif()

# Load the EXTRA_DEFINITIONS flags (from mss_defs.cmake) into the build
message("\nEXTRA_DEFINITIONS = ${EXTRA_DEFINITIONS}")
add_definitions("${EXTRA_DEFINITIONS}")

add_compile_options(${WERROR})
########################################################################
#
# MOCANA SOURCES
#
########################################################################

if(CM_ENABLE_EXPORT_ED)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_export_sources.txt" MSS_SOURCES)
else()
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_sources.txt" MSS_SOURCES)

    if(CM_ENABLE_AES_NI)
        file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_aes_ni_sources.txt" MSS_AES_NI_SOURCES)
        set(MSS_SOURCES ${MSS_SOURCES} ${MSS_AES_NI_SOURCES})
    endif()

    # Remove FIPS files if this is a FIPS build. Must be done last once all
    # other source files have been appended to the source list.
    if(CM_ENABLE_FIPS)
        include(mss_fips)
        get_fips_source(FIPS_SOURCES)
        list(REMOVE_ITEM MSS_SOURCES ${FIPS_SOURCES})
    endif()
endif()

if(CM_ENABLE_KEYGEN)
    if(CM_DISABLE_SUITEB)
        message(FATAL_ERROR "Must enable suiteb in order to enable keygen")
    else()
        file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_keygen_sources.txt" MSS_KEYGEN_SOURCES)
        set(MSS_SOURCES ${MSS_SOURCES} ${MSS_KEYGEN_SOURCES})
    endif()
endif()

# Remove any possible duplicates
list(REMOVE_DUPLICATES MSS_SOURCES)
string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_SOURCES "${MSS_SOURCES}")

# Set Windows file properties
if(WIN32)
  build_rc_file("TrustPoint Shared Library")
  set(MSS_SOURCES ${MSS_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
endif()

message("\nmss sources")
message("-----------")
foreach(file ${MSS_SOURCES})
    message(${file})
endforeach()

if(NOT WIN32)
    if(BUILD_FOR_OSI)
        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${MSS_DIR}/lib")
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${MSS_DIR}/lib")
    else()
        if("STATIC" STREQUAL "${LIB_TYPE}")
            set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${MSS_DIR}/bin_static")
        else()
            set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${MSS_DIR}/bin")
        endif()
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${MSS_DIR}/bin")
    endif()
endif()

if(WIN32)
    if("STATIC" STREQUAL "${LIB_TYPE}")
        set(BIN_WIN32_OUTPUT bin_win32_static)
    else()
        set(BIN_WIN32_OUTPUT bin_win32)
        link_directories(${MSS_SRC_DIR}/../bin_win32)
    endif()
else()
    link_directories(${MSS_SRC_DIR}/../bin)
endif()

if("SHARED" STREQUAL "${LIB_TYPE}")

  add_library(${PROJECT_NAME} SHARED ${MSS_SOURCES})

  if(BUILD_FOR_OSI)
    add_custom_command(
      TARGET ${PROJECT_NAME}
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy
          $<TARGET_FILE:${PROJECT_NAME}>
          "${LIB_DIR}")
    set(ASN1_LIB "${LIB_DIR}/libasn1.so")
    set(PLATFORM_LIB "${LIB_DIR}/libplatform.so")
    set(COMMON_LIB "${LIB_DIR}/libcommon.so")
    set(CRYPTO_INTERFACE_LIB "${LIB_DIR}/libcryptointerface.so")
    set(NANOCAP_LIB "${LIB_DIR}/libnanocap.so")
  else()
    # Dependent libraries for libnanocrypto
    locate_lib(ASN1_LIB asn1)
    locate_lib(PLATFORM_LIB platform)
    locate_lib(COMMON_LIB common)
    locate_lib(CRYPTOINTERFACE_LIB cryptointerface)
    locate_lib(NANOCAP_LIB nanocap)
  endif()
    if(CM_ENABLE_FIPS)
        if(WIN32)
          locate_lib(FIPS_LIB libmss)
        else()
          locate_lib(FIPS_LIB mss)
        endif()
    endif()
    
    if(CM_ENABLE_KEYGEN)
        locate_lib(CERT_ENROLL_LIB cert_enroll)
    endif()

    set(LIB_LINK_ORDER
        ${ASN1_LIB}
        ${PLATFORM_LIB}
        ${COMMON_LIB}
        ${CRYPTOINTERFACE_LIB})

    if(CM_ENABLE_FIPS)
        set(LIB_LINK_ORDER ${LIB_LINK_ORDER} ${FIPS_LIB})
    endif()

    if(CM_ENABLE_KEYGEN)
        set(LIB_LINK_ORDER ${LIB_LINK_ORDER} ${CERT_ENROLL_LIB})
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

    if(WIN32)
        # Setting dependency nanocap
        set(LIB_LINK_ORDER ${LIB_LINK_ORDER} ${NANOCAP_LIB})
        # Setting windows specific lib dependencies
        set(LIB_LINK_ORDER ${LIB_LINK_ORDER} Shlwapi.lib Ws2_32.lib)
    endif()

    if(ANDROID)
        # Setting dependency nanocap
        set(LIB_LINK_ORDER ${LIB_LINK_ORDER} ${NANOCAP_LIB})
    endif()

    target_link_libraries(${PROJECT_NAME} ${LIB_LINK_ORDER})

    if(CM_ENABLE_AES_NI)
        target_include_directories(${PROJECT_NAME} PRIVATE ${MSS_SRC_DIR}/crypto/intel_aes_ni/include)
    endif()

else()
    add_library(${PROJECT_NAME} STATIC ${MSS_SOURCES})
endif()

if(WIN32 AND CM_WIN_FORCE_LINKAGE)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/FORCE:UNRESOLVED")
endif()

if(WIN32)
    add_custom_command(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            $<TARGET_FILE_DIR:${PROJECT_NAME}>
            ${MSS_DIR}/${BIN_WIN32_OUTPUT})
endif()

# Add a static library with the appropriate crypto defs for Windows.
if(("SHARED" STREQUAL "${LIB_TYPE}") AND WIN32 AND CM_BUILD_DATALIB)

  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/mss_win_data_sources.txt" MSS_WIN_DATA_SOURCES)
  string(REGEX REPLACE "MSS_SRC_DIR/" "${MSS_SRC_DIR}/" MSS_WIN_DATA_SOURCES "${MSS_WIN_DATA_SOURCES}")

  add_library(cryptomwdata STATIC ${MSS_WIN_DATA_SOURCES})

  add_custom_command(
    TARGET cryptomwdata
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        $<TARGET_FILE_DIR:cryptomwdata>
        ${MSS_DIR}/${BIN_WIN32_OUTPUT})
endif()
