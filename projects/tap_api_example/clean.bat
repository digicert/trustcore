@echo OFF


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Constants
set BUILD_DIR=build
set TOOL_NAME=tap_api_example
set BAT_DIR=%~dp0
set LOG_FILE_PATTERN=build_%TOOL_NAME%_*.log

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Execution starts here
set PROJECT_NAME=%1
if "%PROJECT_NAME%"=="" (
set PROJECT_NAME=%TOOL_NAME%
)

echo Navigating to dir "%BAT_DIR%" ...
pushd %BAT_DIR%

echo Deleting build directories
RMDIR /s /q %BUILD_DIR%
RMDIR /s /q %PROJECT_NAME%.dir

echo Deleting CMakeFiles dir
RMDIR /s /q CMakeFiles

echo Deleting Makefile
del /s /q Makefile

echo Deleting CMakeCache
del /s /q CMakeCache.txt

echo Deleting cmake_install
del /s /q cmake_install.cmake

echo Deleting tool binaries 
del /s /q %TOOL_NAME%.exe

echo Deleting Visual Studio project files
RMDIR /s /q Win32
RMDIR /s /q x64
RMDIR /s /q Debug
RMDIR /s /q Release
DEL /s /q *.vcxproj*
DEL /q *.sln

echo Deleting log files by executing - "del /s /q %LOG_FILE_PATTERN%"
del /s /q %LOG_FILE_PATTERN%

popd

