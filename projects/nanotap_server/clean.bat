@echo OFF

set BUILD_DIR=build
set PROJECT_NAME=%1

if "%PROJECT_NAME%"=="" (
    set PROJECT_NAME=nanotap_server
)

set TOOL_BIN_NAME=%PROJECT_NAME%_bin
set LOG_FILE_PATTERN="build_bat.out"

echo "Cleaning up..."

echo "Deleting CMakeFiles dir"
RMDIR /s /q CMakeFiles
RMDIR /s /q _CPack_Packages
RMDIR /s /q %PROJECT_NAME%.dir
RMDIR /s /q %TOOL_BIN_NAME%.dir
RMDIR /s /q Win32
RMDIR /s /q x64
RMDIR /s /q Debug
RMDIR /s /q Release

echo "Deleting CMake files"
DEL /s /q CMakeCache.txt
DEL /s /q cmake_install.cmake
DEL /s /q *.vcxproj*
DEL /q *.sln
DEL /s /q ..\..\bin_win32\%TOOL_BIN_NAME%.exe

echo Deleting log files by executing - "del /s /q %LOG_FILE_PATTERN%"
del /s /q %LOG_FILE_PATTERN%
