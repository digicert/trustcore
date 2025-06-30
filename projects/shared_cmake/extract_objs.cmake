##
# With inlib given as a full path to a static library built with PIC, extract
# all object (.o) files from the library, store them in this CMake project's
# build directory, then populate the OBJ_FILE_LIST_RET list with the full paths
# to these object files.
function(extract_objs OBJ_FILE_LIST_RET inlib)
  get_filename_component(basename "${inlib}" NAME_WE)

  # Create the folder to place the .o files in
  set(DEPO_DIR "${CRYPTO_BUILD_DIR}/${basename}")
  file(MAKE_DIRECTORY ${DEPO_DIR})

  message("\nExtracting object files from ${inlib}\n")

  # Extract the .o files and place in the build directory
  execute_process(COMMAND ${CMAKE_AR} -x ${inlib}
                  WORKING_DIRECTORY ${DEPO_DIR})

  # Get a list of the files in this directory
  file(GLOB OBJ_FILE_LIST ${DEPO_DIR}/*.o)
  foreach(f ${OBJ_FILE_LIST})
    message("${f}")
  endforeach()
  message("")

  # Set the parameter in the parent scope to be this file list
  set(${OBJ_FILE_LIST_RET} ${OBJ_FILE_LIST} PARENT_SCOPE)

endfunction()

