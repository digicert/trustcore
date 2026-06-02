@echo OFF

echo "Cleaning up..."

call msbuild crypto_keygen.sln /t:Clean /property:Configuration=Release
call msbuild crypto_keygen.sln /t:Clean /property:Configuration=Debug

echo "Deleting CMakeFiles dir"
RMDIR /s /q CMakeFiles
RMDIR /s /q _CPack_Packages
RMDIR /s /q Win32
RMDIR /s /q x64
RMDIR /s /q Debug
RMDIR /s /q Release

echo "Deleting CMake files"
DEL /s /q CMakeCache.txt
DEL /s /q install_manifest_*.txt
DEL /s /q cmake_install.cmake
DEL /s /q Makefile
DEL /s /q CPackConfig.cmake
DEL /s /q CPackSourceConfig.cmake
DEL /s /q *.vcxproj*
DEL /q *.sln

:: TO DO delete the executables similar to that in clean.sh

