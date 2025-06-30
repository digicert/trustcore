function(buildLibrary libType targetName includeLists sourcesList mssSrcDir buildDir mssBinDir ${libraryLists})

    set(SHARED_LIB_EXT "so")
    if(APPLE)
        set(SHARED_LIB_EXT "dylib")
    endif()

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
      if(NOT DEFINED CPACK_PACKAGE_VERSION_BUILD_ENV)
        set(VERSION_FILE "${MSS_DIR}/projects/shared_cmake/version.txt")
        include(${VERSION_FILE})
        if(DEFINED ENV{BUILD_NUMBER})
          set(CPACK_PACKAGE_VERSION_BUILD_ENV "$ENV{BUILD_NUMBER}")
        else()
          set(CPACK_PACKAGE_VERSION_BUILD_ENV "0")
        endif()
      endif()

      if(NOT EXISTS ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
        include(${MSS_DIR}/projects/shared_cmake/build_rc_file.cmake)
        build_rc_file("TrustPoint Shared Library")
      endif()
      set(MSS_SOURCES ${MSS_SOURCES} ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
    endif()

    message("${targetName} sources")
    message("-----------")
    foreach(file ${MSS_SOURCES})
        message(${file})
    endforeach()

    if("SHARED" STREQUAL "${libType}")
        add_library(${targetName} SHARED ${MSS_SOURCES})
        target_link_libraries(${targetName} ${libraryLists})
        if (NOT WIN32)
            if (ANDROID)
               target_link_libraries(${targetName} dl)
            elseif("${CM_TARGET_PLATFORM}" STREQUAL "qnx-x86" OR "${CM_TARGET_PLATFORM}" STREQUAL "qnx-x86_64" OR "${CM_TARGET_PLATFORM}" STREQUAL "qnx-6-5-x86")
            else()
               target_link_libraries(${targetName} pthread dl)
            endif()
            if(NOT CM_TEST_FRAMEWORK) # Test framework will handle copying of files
              add_custom_command(TARGET ${targetName} POST_BUILD
                          COMMAND cp ${buildDir}/libs/lib${targetName}.${SHARED_LIB_EXT} ${mssBinDir}/
                          COMMAND echo "Copied lib${targetName}.${SHARED_LIB_EXT} to ${mssBinDir}/")
            endif()
        endif()
    else()
        add_library(${targetName} STATIC ${MSS_SOURCES})
        if (NOT WIN32)
            if(NOT CM_TEST_FRAMEWORK) # Test framework will handle copying of files
                add_custom_command(TARGET ${targetName} POST_BUILD
                            COMMAND cp ${buildDir}/libs/lib${targetName}.a ${mssBinDir}/
                            COMMAND echo "Copied lib${targetName}.a to ${mssBinDir}/")
            endif()
        endif()
    endif()
endfunction()

