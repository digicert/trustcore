@echo OFF

set BUILD_DIR=build

echo "Cleaning up..."
call msbuild common_unittest.sln /t:Clean

echo "Deleting CMakeFiles dir"
RMDIR /s /q CMakeFiles

echo "Deleting CMake files"
DEL /s /q CMakeCache.txt
DEL /s /q cmake_install.cmake
DEL /s /q Makefile
DEL /s /q *.vcxproj*
DEL /q *.sln
