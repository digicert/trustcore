@echo OFF

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Constants
set BUILD_DIR=build
set LIB_NAME=nanocert
set BAT_DIR=%~dp0
set LOG_FILE_PATTERN=build_bat.out


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Execution starts here
set PROJECT_NAME=%1
if "%PROJECT_NAME%"=="" (
    set PROJECT_NAME=%LIB_NAME%
)

echo Navigating to dir "%BAT_DIR%" ...
pushd %BAT_DIR%

echo Deleting build directories
RMDIR /s /q %BUILD_DIR%
RMDIR /s /q %PROJECT_NAME%.dir

echo "Deleting CMakeFiles dir"
RMDIR /s /q CMakeFiles

echo "Deleting Makefile"
del /s /q Makefile

echo "Deleting CMakeCache"
del /s /q CMakeCache.txt 

echo "Deleting cmake_install"
del /s /q cmake_install.cmake

echo Deleting libraries
del /s /q %PROJECT_NAME%.*

echo Deleting Visual Studio project files
RMDIR /s /q Win32
RMDIR /s /q x64
RMDIR /s /q Debug
RMDIR /s /q Release
DEL /s /q *.vcxproj*
DEL /q *.sln
DEL /q *.slnx

echo Deleting log files by executing - "del /s /q %LOG_FILE_PATTERN%"
del /s /q %LOG_FILE_PATTERN%

popd

