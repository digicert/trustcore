
##
#  Given the base name of a library for lib_name (e.g., nanocrypto), this
#  function will attempt to locate the full name of the library
#  (e.g., libnanocrypto.so) in the mss/bin directory ONLY (will not check standard
#  library path).  If the library was not found, the variable passed in for
#  LIB_PATH_RET will remain blank.  If the library was found, the variable passed
#  in for the parameter LIB_PATH_RET will be set to the full path of the library.
#
#  NOTE: You MUST define the CMake variable MSS_DIR in the calling CMakeLists.txt
#        file that contains the path to the root of "mss"

#############################################################

## Setup pathing for different platforms
set(LOCATE_LIB_SUFFIX_SHARED "so")
set(LOCATE_LIB_SUFFIX_STATIC "a")
if(BUILD_FOR_OSI)
  set(LOCATE_LIB_SEARCH_PATH "lib")
else()
  set(LOCATE_LIB_SEARCH_PATH "bin")
endif()
set(LIB_PREFIX "lib")

if(NOT CMAKE_CROSSCOMPILING)
  if(WIN32)
      set(LOCATE_LIB_SUFFIX_STATIC "lib")
      set(LOCATE_LIB_SUFFIX_SHARED "lib")
      if("STATIC" STREQUAL "${LIB_TYPE}")
        set(LOCATE_LIB_SEARCH_PATH "bin_win32_static")
      else()
        set(LOCATE_LIB_SEARCH_PATH "bin_win32")
      endif()
      set(LIB_PREFIX "")
  elseif(APPLE)
      set(LOCATE_LIB_SUFFIX_SHARED "dylib")
  endif()
endif()

function(locate_lib LIB_PATH_RET lib_name)

  if(NOT DEFINED MSS_DIR)
    message(FATAL_ERROR "MSS_DIR not defined, which is needed by locate_lib")
  endif()

  set(LIB_SUFFIX ${LOCATE_LIB_SUFFIX_SHARED})
  if("STATIC" STREQUAL "${LIB_TYPE}")
    set(LIB_SUFFIX ${LOCATE_LIB_SUFFIX_STATIC})
    if("ON" STREQUAL "${LINK_LIBS_IN_BIN_STATIC}")
      set(LOCATE_LIB_SEARCH_PATH "bin_static")
    endif()
  endif()

  # Convert the search path to an absolute path.
  get_filename_component(FULL_SEARCH_PATH ${MSS_DIR}/${LOCATE_LIB_SEARCH_PATH} ABSOLUTE)

  find_library(${lib_name}_path
               NAMES ${LIB_PREFIX}${lib_name}.${LIB_SUFFIX}
               HINTS "${FULL_SEARCH_PATH}"
               NO_DEFAULT_PATH
               NO_CMAKE_FIND_ROOT_PATH )


  # If the library was found, set the return value
  if(NOT "${${lib_name}_path}" STREQUAL "${lib_name}_path-NOTFOUND")
    set(${LIB_PATH_RET} ${${lib_name}_path} PARENT_SCOPE)
  else()
    message("\n library ${LIB_PREFIX}${lib_name}.${LIB_SUFFIX} not found in ${FULL_SEARCH_PATH}")
    set(${lib_name}_path "")
    set(${lib_name}_path "" PARENT_SCOPE)
  endif()

endfunction()

# Search through mss/bin or mss/bin_win32, create a target named "lib_name",
# and set the import property for it.
macro(create_target_import_lib lib_name)
  add_library(${lib_name} SHARED IMPORTED)
  if(CM_ENABLE_MBED AND ("${lib_name}" STREQUAL "nanocrypto"))
    set_property(TARGET ${lib_name}
                 PROPERTY IMPORTED_LOCATION
                 ${MSS_DIR}/${LOCATE_LIB_SEARCH_PATH}/${LIB_PREFIX}cryptomw.${LOCATE_LIB_SUFFIX_SHARED})
    if(WIN32)
      set_property(TARGET ${lib_name}
                  PROPERTY IMPORTED_IMPLIB
                  ${MSS_DIR}/${LOCATE_LIB_SEARCH_PATH}/${LIB_PREFIX}cryptomw.${LOCATE_LIB_SUFFIX_SHARED})
    endif()
  else()
    set_property(TARGET ${lib_name}
                 PROPERTY IMPORTED_LOCATION
                 ${MSS_DIR}/${LOCATE_LIB_SEARCH_PATH}/${LIB_PREFIX}${lib_name}.${LOCATE_LIB_SUFFIX_SHARED})
    if(WIN32)
      set_property(TARGET ${lib_name}
                  PROPERTY IMPORTED_IMPLIB
                  ${MSS_DIR}/${LOCATE_LIB_SEARCH_PATH}/${LIB_PREFIX}${lib_name}.${LOCATE_LIB_SUFFIX_SHARED})
    endif()
  endif()
endmacro()
