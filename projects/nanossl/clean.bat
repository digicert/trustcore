@echo OFF

set BUILD_DIR=build
set LOG_FILE_PATTERN="build_bat.out"
set PROJECT_NAME=%1
set TARGET_TYPE=%2

if "%PROJECT_NAME%"=="" (
	set PROJECT_NAME=nanossl
)
if "%TARGET_TYPE%"=="" (
	set TARGET_TYPE=LIB
)

echo "Cleaning up..."

echo "Deleting CMakeFiles dir"
RMDIR /s /q CMakeFiles
RMDIR /s /q _CPack_Packages
RMDIR /s /q %PROJECT_NAME%.dir
RMDIR /s /q Win32
RMDIR /s /q x64
RMDIR /s /q Debug
RMDIR /s /q Release

echo "Deleting CMake files"
DEL /s /q CMakeCache.txt
DEL /s /q cmake_install.cmake
DEL /s /q *.vcxproj*
DEL /q *.sln
DEL /q *.slnx

if "%TARGET_TYPE%"=="LIB" (
    DEL /s /q ..\..\bin_win32\%PROJECT_NAME%.lib
    DEL /s /q ..\..\bin_win32\%PROJECT_NAME%.dll
)
if "%TARGET_TYPE%"=="EXE" (
    DEL /s /q ..\..\bin_win32\%PROJECT_NAME%.exe
)

echo Deleting log files by executing - "del /s /q %LOG_FILE_PATTERN%"
del /s /q %LOG_FILE_PATTERN%
