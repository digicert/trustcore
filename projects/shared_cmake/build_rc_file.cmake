
# Create a *.rc file for a given Windows build in order to set the verion
# info for the binary
macro(build_rc_file package_name)
  # Delete the existing rc file if it exists
  if(EXISTS ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
    file(REMOVE ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc)
  endif()

  set(rc_contents "1 VERSIONINFO\n"
                  "FILEVERSION ${CPACK_PACKAGE_VERSION_MAJOR},${CPACK_PACKAGE_VERSION_MINOR},${CPACK_PACKAGE_VERSION_PATCH},0\n"
                  "PRODUCTVERSION ${CPACK_PACKAGE_VERSION_MAJOR},${CPACK_PACKAGE_VERSION_MINOR},${CPACK_PACKAGE_VERSION_PATCH},0\n"
                  "FILEFLAGSMASK      0x3fL\n"
                  "FILESUBTYPE        0x0L\n"
                  "BEGIN\n"
                      "BLOCK \"StringFileInfo\"\n"
                      "BEGIN\n"
                          "BLOCK \"040904b0\"\n"
                          "BEGIN\n"
                              "VALUE \"CompanyName\",     \"Mocana Corporation\\0\"\n"
                              "VALUE \"ProductName\",     \"${package_name}\\0\"\n"
                              "VALUE \"FileDescription\", \"${package_name} for Windows\\0\"\n"
                              "VALUE \"ProductVersion\",  \"${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}.${CPACK_PACKAGE_VERSION_BUILD_ENV}\\0\"\n"
                              "VALUE \"FileVersion\",     \"${CPACK_PACKAGE_VERSION}.0\\0\"\n"
                              "VALUE \"LegalCopyright\",  \"Mocana Corporation\\0\"\n"
                          "END\n"
                      "END\n"
                      "BLOCK \"VarFileInfo\"\n"
                      "BEGIN\n"
                          "VALUE \"Translation\", 0x409, 1200\n"
                      "END\n"
                  "END\n")
  file(WRITE ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.rc ${rc_contents})
endmacro()
