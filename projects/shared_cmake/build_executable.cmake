function(buildexecutable libType targetName includeLists sourcesList mssSrcDir buildDir apptype mssBinDir  ${libraryLists})

  set(MSS_INCLUDES "" )
  foreach(include_file ${includeLists})
    # adding mss include directories listed in mss_includes.txt
    file(STRINGS "${include_file}" INCLUDE_FOLDER)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${mssSrcDir}/" INCLUDE_FOLDER "${INCLUDE_FOLDER}")
    set(MSS_INCLUDES ${MSS_INCLUDES} ${INCLUDE_FOLDER} )
  endforeach()

  include_directories("." ${MSS_INCLUDES})

  message("${targetName} includes")
  message("----------------")
  foreach(dir ${MSS_INCLUDES})
    message(${dir})
  endforeach()


  set(MSS_SOURCES "")
  foreach(src_files ${sourcesList})
    # adding src files listed in mss_sources
    file(STRINGS "${src_files}" SRC_FILES)
    string(REGEX REPLACE "MSS_SRC_DIR/" "${mssSrcDir}/" SRC_FILES "${SRC_FILES}")
    set(MSS_SOURCES ${MSS_SOURCES} ${SRC_FILES} )
  endforeach()

  # Set Windows file properties
  if(WIN32)
    set(MSS_SOURCES ${MSS_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
  endif()

  message("${targetName} sources")
  message("-----------")
  foreach(file ${MSS_SOURCES})
    message(${file})
  endforeach()

  add_executable(${targetName} "${MSS_SOURCES}")
  target_link_libraries(${targetName} ${libraryLists})

  if (NOT WIN32)
      add_custom_command(TARGET ${targetName} POST_BUILD
                  COMMAND cp ${buildDir}/${targetName} ${mssBinDir}/
                  COMMAND echo "Copied ${targetName} to ${mssBinDir}/")
  endif()

endfunction()

