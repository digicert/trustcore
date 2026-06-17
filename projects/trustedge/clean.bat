@echo OFF

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Constants
set BUILD_DIR=build
set LIB_NAME=trustedge
set BAT_DIR=%~dp0
set LOG_FILE_PATTERN=build_trustedge_*.log

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Execution starts here

echo Cleaning up trustedge project...
pushd %BAT_DIR%

echo Deleting build directory
if exist %BUILD_DIR% RMDIR /s /q %BUILD_DIR%

echo Deleting CMakeFiles dir
if exist CMakeFiles RMDIR /s /q CMakeFiles

echo Deleting CMakeCache
if exist CMakeCache.txt del /q CMakeCache.txt

echo Deleting cmake_install
if exist cmake_install.cmake del /q cmake_install.cmake

echo Deleting Visual Studio project files
if exist Win32 RMDIR /s /q Win32
if exist x64 RMDIR /s /q x64
if exist Debug RMDIR /s /q Debug
if exist Release RMDIR /s /q Release
if exist *.vcxproj DEL /q *.vcxproj*
if exist *.sln DEL /q *.sln

echo Deleting log files
if exist %LOG_FILE_PATTERN% del /q %LOG_FILE_PATTERN%

popd
echo Cleanup complete.
