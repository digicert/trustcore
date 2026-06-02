@echo OFF

set BUILD_DIR=build
set PROJECT_NAME=nanotap2
set TARGET_NAME=%1
set BIN_DIR=..\..\bin_win32
set BAT_DIR=%~dp0
set LOG_FILE_PATTERN="build_bat.out"

echo Navigating to dir "%BAT_DIR%" ...
pushd %BAT_DIR%

echo Cleaning up...

echo Deleting CMakeFiles dir
RMDIR /s /q CMakeFiles
RMDIR /s /q _CPack_Packages

echo Deleting CMakeCache
DEL /s /q CMakeCache.txt

echo Deleting cmake_install 
DEL /s /q cmake_install.cmake

echo Deleting build directories
RMDIR /s /q %PROJECT_NAME%.dir
RMDIR /s /q Win32
RMDIR /s /q x64
RMDIR /s /q Debug
RMDIR /s /q Release

echo Deleting CMake files
DEL /s /q *.vcxproj*
DEL /q *.sln
DEL /q *.slnx

if NOT "%TARGET_NAME%"=="" (
    DEL /s /q %BIN_DIR%\%TARGET_NAME%.lib
    DEL /s /q %BIN_DIR%\%TARGET_NAME%.dll
)

echo Deleting log files by executing - "del /s /q %LOG_FILE_PATTERN%"
del /s /q %LOG_FILE_PATTERN%

popd

