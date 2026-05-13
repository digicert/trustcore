@echo OFF

set BUILD_DIR=%~dp0build

echo "Cleaning up OpenSSL Connector..."
rmdir /s /q %BUILD_DIR%
