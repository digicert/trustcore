@echo ON

set CMAKE_PATH=C:\Program Files\CMake\bin
set CMAKE_BIN="%CMAKE_PATH%\cmake.exe"

echo "Building Unit Test project."
call clean.bat

call %CMAKE_BIN% -G "Visual Studio 15 2017" -DCMAKE_BUILD_TYPE=Debug CMakeLists.txt

call msbuild asn1_unittest.sln
