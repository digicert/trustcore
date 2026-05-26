@echo OFF
SETLOCAL ENABLEDELAYEDEXPANSION

:: Check if VSINSTALLDIR is set (Visual Studio environment required)
if not defined VSINSTALLDIR (
    echo ERROR: VSINSTALLDIR is not set. Visual Studio build environment is required.
    echo Please run this script from a Visual Studio Developer Command Prompt or use vsdevcmd.bat
    exit /b 1
)

:: Detect VS version using string substitution (most reliable method)
set "VS_PATH=%VSINSTALLDIR%"

:: Check for VS 2026 (path contains \18\)
if not "!VS_PATH:\18\=!"=="!VS_PATH!" (
    echo Detected Visual Studio 2026
    set VSIDE_GENERATOR_x64="Visual Studio 18 2026" -A x64
    set VSIDE_GENERATOR_x32="Visual Studio 18 2026" -A Win32
    goto :VS_DETECTED
)

:: Check for VS 2022 (path contains \2022\)
if not "!VS_PATH:\2022\=!"=="!VS_PATH!" (
    echo Detected Visual Studio 2022
    set VSIDE_GENERATOR_x64="Visual Studio 17 2022" -A x64
    set VSIDE_GENERATOR_x32="Visual Studio 17 2022" -A Win32
    goto :VS_DETECTED
)

:: Check for VS 2019 (path contains \2019\)
if not "!VS_PATH:\2019\=!"=="!VS_PATH!" (
    echo Detected Visual Studio 2019
    set VSIDE_GENERATOR_x64="Visual Studio 16 2019" -A x64
    set VSIDE_GENERATOR_x32="Visual Studio 16 2019" -A Win32
    goto :VS_DETECTED
)

:: If we get here, VSINSTALLDIR is set but version is unknown
echo ERROR: Unsupported Visual Studio version. VSINSTALLDIR=%VSINSTALLDIR%
echo Supported versions: Visual Studio 2019, 2022, 2026
exit /b 1

:VS_DETECTED
:: Set CMAKE path based on VSINSTALLDIR
set "CMAKE_PATH=%VSINSTALLDIR%Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
set CMAKE_BIN="!CMAKE_PATH!\cmake.exe"

:: Check if CMAKE binary exists at the VS path
if exist "!CMAKE_PATH!\cmake.exe" (
    echo Using CMake from Visual Studio: !CMAKE_BIN!
    goto :CMAKE_READY
)

:: CMAKE not found in VS, check if it's in PATH
where cmake >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo CMake not found in Visual Studio installation, using cmake from PATH
    set CMAKE_BIN=cmake.exe
    goto :CMAKE_READY
)

:: CMAKE not found anywhere
echo ERROR: CMake is required but not found.
echo CMake was not found in Visual Studio installation at: !CMAKE_PATH!
echo CMake is also not available in PATH.
echo Please install CMake or use a Visual Studio installation that includes CMake.
exit /b 1

:CMAKE_READY

set BUILD_OPTIONS=
set BUILD_TYPE=Release
set BUILD_TARGET=x64
set LOG_FILE="build_bat.out"
set VS_PLATFORM=x64
set PROJECT_NAME=nanomqtt
set IS_64BIT_BUILD=0
set IS_32BIT_BUILD=0
set IS_STATIC_BUILD=0
set ADD_ARGS=

:argactionstart
if "-%~1-"=="--" goto argactionend

if "%~1"=="--help" call:usage & EXIT /B %ERRORLEVEL%
if "%~1"=="--gdb" echo Enabling Debug build...& set BUILD_TYPE=Debug& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCMAKE_BUILD_TYPE=Debug& goto next
if "%~1"=="--debug" echo Building with Debug logs enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DEBUG=ON& goto next
if "%~1"=="--pqc" echo Building with PQC enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PQC=ON& goto next
if "%~1"=="--disable-pqc" goto next
if "%~1"=="--libtype" goto handle_libtype
if "%~1"=="--x32" set IS_32BIT_BUILD=1& set BUILD_TARGET=x32& set VS_PLATFORM=Win32& echo Building for x32 machine...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_X32=ON& goto next
if "%~1"=="--x64" set IS_64BIT_BUILD=1& set BUILD_TARGET=x64& echo Building for x64 machine...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_X64=ON& goto next
if "%~1"=="--cmake-opt" echo Setting extra flags for cmake execution...& set BUILD_OPTIONS=%BUILD_OPTIONS% %~2& shift& goto next
if "%~1"=="--ssl" echo Building with SSL enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SSL=ON& goto next
if "%~1"=="--proxy" echo Building with proxy support enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PROXY=ON& goto next
if "%~1"=="--async" echo Building with asynchronous support enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_ASYNC=ON& goto next
if "%~1"=="--scram" echo Building with SCRAM authentication support enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SCRAM=ON& goto next
if "%~1"=="--library" echo Building client sample in library mode...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_LIBRARY=ON& goto next
if "%~1"=="--persist" echo Building with persistence support enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PERSIST=ON& goto next
if "%~1"=="--test" echo Building with test validation enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MQTT_TEST=ON& goto next
if "%~1"=="--streaming" echo Building with streaming support enabled...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_STREAMING=ON& goto next
if "%~1"=="--unittest" echo Building with unittesting...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_UNITTEST=ON& goto next
if "%~1"=="--enable-coverage" echo Building with gcov code coverage support...& set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_COVERAGE=ON& goto next
if "%~1"=="nanomqtt" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_NANOMQTT=ON& set PROJECT_NAME=nanomqtt& set ADD_ARGS=%ADD_ARGS% nanomqtt& goto next
if "%~1"=="mqtt_client_sample" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_MQTT_CLIENT_SAMPLE=ON& set PROJECT_NAME=mqtt_client_sample& set ADD_ARGS=%ADD_ARGS% mqtt_client_sample& goto next
if "%~1"=="mqtt_client_test" set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_BUILD_MQTT_CLIENT_TEST=ON& set PROJECT_NAME=mqtt_client_test& set ADD_ARGS=%ADD_ARGS% mqtt_client_test& goto next
if "%~1"=="--log" goto handle_log

echo invalid option %1
call:usage
EXIT /B 1

:handle_libtype
if "%~2"=="static" (
    set IS_STATIC_BUILD=1
    echo Building static library...
    set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=STATIC
) else if "%~2"=="shared" (
    echo Building shared library...
    set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
) else (
    echo "Error reading libtype %2 switching to default - shared"
    set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
)
shift
goto next

:handle_log
if "%~2"=="" (
    echo "Error reading log file path %2"
    exit /b 1
)
set LOG_FILE="%~2"
shift
goto next

:next
shift
goto argactionstart

:argactionend

if %IS_32BIT_BUILD%==1 (
  if %IS_64BIT_BUILD%==1 (
    echo "Error: Both the flags --x32 and --x64 should not be passed. Either one of the flags --x32 or x64 flag should be passed."
    EXIT /B 1
  )
)

echo Building %PROJECT_NAME%...

if exist build rmdir /s /q build
mkdir build
cd build

echo ********** Building %PROJECT_NAME% ********** >>%LOG_FILE%
if %BUILD_TARGET%==x64 (
    call %CMAKE_BIN% -G %VSIDE_GENERATOR_x64% -DCMAKE_BUILD_TYPE=%BUILD_TYPE% %BUILD_OPTIONS% CMakeLists.txt ../. 1>>%LOG_FILE% 2>>&1
) else (
    call %CMAKE_BIN% -G %VSIDE_GENERATOR_x32% -DCMAKE_BUILD_TYPE=%BUILD_TYPE% %BUILD_OPTIONS% CMakeLists.txt ../. 1>>%LOG_FILE% 2>>&1
)

call msbuild nanomqtt.sln /property:Configuration=%BUILD_TYPE% /p:Platform=%VS_PLATFORM% 1>>%LOG_FILE% 2>>&1

if NOT %ERRORLEVEL% == 0 (
   echo Build failed
   echo Exited with error %ERRORLEVEL%
   echo Refer file "%LOG_FILE%" for details.
   cd ..
   exit /b %ERRORLEVEL%
)

cd ..
echo Build Successful

EXIT /B %ERRORLEVEL%

:usage
  echo.
  echo    "./build.bat --help --gdb --debug --libtype <static | shared> [--x32 | --x64]"
  echo.
  echo "   --help            - Build options information"
  echo "   --gdb             - Build a Debug version. (Release is default)"
  echo "   --debug           - Build with Mocana logging enabled."
  echo "   --libtype <static | shared> - Build a library either static or shared (default is shared)."
  echo "   --x32             - Creates build for 32Bit machine."
  echo "   --x64             - Creates build for 64Bit machine. (default)"
  echo "   --cmake-opt       - Use this parameter to pass extra CMAKE parameters."
  echo "                        exa: --cmake-opt -D<MACRO>=<VALUE>"
  echo "   --ssl             - Build with SSL enabled."
  echo "   --proxy           - Build with proxy support enabled."
  echo "   --async           - Build with asynchronous support enabled."
  echo "   --scram           - Build with SCRAM authentication support enabled."
  echo "   --library         - Build client sample in library mode."
  echo "   --persist         - Build with persistence support enabled."
  echo "   --test            - Build with test validation enabled. DO NOT USE FOR PRODUCTION BUILD."
  echo "   --streaming       - Build with streaming support enabled."
  echo "   --unittest        - Build mqtt unittests."
  echo "   --enable-coverage - Build with gcov code coverage support."
  echo "   --pqc             - Build with PQC enabled."
  echo "   --disable-pqc     - Build without PQC."
  echo "     nanomqtt        - Build nanomqtt library."
  echo "     mqtt_client_sample - Build mqtt client sample application."
  echo "     mqtt_client_test   - Build mqtt client test application."
  echo "   --log <log_file>  - Dump compilation logs to specified log file."
  echo.
EXIT /B 0
