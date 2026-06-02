@echo OFF

set "BUILD_DIR=%~dp0build"
set "SAMPLE_DIR=%~dp0"

echo "Cleaning up OpenSSL Connector..."
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"

echo "Removing CMake cache..."
if exist "%SAMPLE_DIR%CMakeCache.txt" del /q "%SAMPLE_DIR%CMakeCache.txt"
if exist "%SAMPLE_DIR%CMakeFiles" rmdir /s /q "%SAMPLE_DIR%CMakeFiles"
echo "Cleanup complete."
