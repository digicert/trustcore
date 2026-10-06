function(digicert_generate_build_info MSS_DIR)
  set(MSS_SRC_DIR "${MSS_DIR}/src")

  include("${MSS_DIR}/projects/shared_cmake/set_cpack_version.cmake")

  if(DEFINED ENV{BUILD_NUMBER})
    set(CPACK_PACKAGE_VERSION_BUILD_ENV "$ENV{BUILD_NUMBER}")
  else()
    set(CPACK_PACKAGE_VERSION_BUILD_ENV "0")
  endif()
  set(CM_BUILD_VERSION "${CPACK_PACKAGE_VERSION}.${CPACK_PACKAGE_VERSION_BUILD_ENV}")

  set(TP_BUILD_PLATFORM "${CM_SYSTEM_NAME}")
  if(TP_BUILD_PLATFORM STREQUAL "")
    set(TP_BUILD_PLATFORM "${CMAKE_SYSTEM_NAME}")
    if(WIN32 AND "${CMAKE_GENERATOR}" MATCHES "Win64")
      set(TP_BUILD_PLATFORM "Win64")
    endif()
  endif()

  set(TP_BUILD_VERSION "${CM_BUILD_VERSION}")
  if(DEFINED CM_VERSION_STRING)
    set(TP_BUILD_VERSION "${CM_VERSION_STRING}")
  endif()
  if(TP_BUILD_VERSION STREQUAL "")
    set(TP_BUILD_VERSION "0.0.0.${CPACK_PACKAGE_VERSION_BUILD_ENV}")
  endif()

  set(TP_BUILD_TYPE "${CMAKE_BUILD_TYPE}")
  if(DEFINED CM_TAP_TYPE)
    if("${CM_TAP_TYPE}" MATCHES "LOCAL")
      set(TP_BUILD_TAPINFO "TAP-Local")
    elseif("${CM_TAP_TYPE}" MATCHES "REMOTE")
      set(TP_BUILD_TAPINFO "TAP-Remote")
    endif()
  else()
    set(TP_BUILD_TAPINFO "TAP-Off")
  endif()

  string(TIMESTAMP TP_BUILD_DATE "%Y-%m-%d %H:%M")
  string(TIMESTAMP CURR_YEAR "%Y")

  configure_file("${MSS_SRC_DIR}/common/build_info.h.in"
                 "${MSS_SRC_DIR}/common/build_info.h"
                 @ONLY)
endfunction()