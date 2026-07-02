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

set TAP_OPT_ALLOWED=1
set CopyBAT=..\..\scripts\win32\copy_build_to_bin.bat
set BUILD_OPTIONS=
set BUILD_TYPE=
set BUILD_TARGET=
::Log file path
set LOG_FILE="build_bat.out"
set IS_STATIC_BUILD=0
set PROJECT_NAME=tpm2
set IS_32BIT_BUILD=0
set IS_64BIT_BUILD=0
set VS_PLATFORM=x64
set LIB_TYPE=shared

:argactionstart
if "-%~1-"=="--" goto argactionend
if "%~1"=="--help" (
  call:usage
  EXIT /B %ERRORLEVEL%
)
if "%~1"=="--gdb" (
  set BUILD_TYPE=Debug
  goto next
)
if "%~1"=="--pg" (
  echo Enabling callstack tracing build...
  set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PG=ON
  goto next
)
if "%~1"=="--debug" (
  set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DEBUG=ON
  goto next
)
if "%~1"=="--suiteb" (
  goto next
)
if "%~1"=="--disable-suiteb" (
  set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_SUITEB=ON
  goto next
)
if "%~1"=="--openssl_shim" (
  set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_OPENSSL_SHIM=ON
  goto next
)
if "%~1"=="--x64" (
  set IS_64BIT_BUILD=1
  set BUILD_TARGET=x64
  goto next
)
if "%~1"=="--x32" (
  set IS_32BIT_BUILD=1
  set BUILD_TARGET=x32
  set VS_PLATFORM=Win32
  goto next
)
if "%~1" == "--libtype" (
	if "%~2"=="static" (
		set IS_STATIC_BUILD=1
		set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=STATIC
        set LIB_TYPE=static
	) else (
		set IS_STATIC_BUILD=0
		if "%~2"=="shared" (
			set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
		) else (
			echo "Error reading libtype %~2 switching to default - shared"
			set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
		)
        set LIB_TYPE=shared
	)
	shift
	goto next
)
if "%~1"=="--tap-off" (
  goto next
)
if "%~1"=="--tap-local" (
  goto next
)
if "%~1"=="--tap-remote" (
  goto next
)
if "%~1"=="--tc" (
  set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TRUST_CENTER=ON
  goto next
)
if "%~1"=="--pkcs11" (
  echo Building with smp_pkcs11 support...
  set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SMP_PKCS11=ON
  goto next
)
if "%~1"=="--cmake-opt" (
  echo Setting extra flags for cmake execution...
  set BUILD_OPTIONS=%BUILD_OPTIONS% %~2
  shift
  goto next
)
if "%~1"=="--forcelink" (
    echo Setting flags to force linkage ...
    set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_WIN_FORCE_LINKAGE=ON
    goto next
)
if "%~1"=="--fips" (
    echo Linking to libmss ...
    set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_FIPS=ON
    goto next
)
if "%~1"=="--log" (
	IF "%~2"=="" (
		echo "Error reading log file path %~2"
		exit /b 1
	)
	set LOG_FILE="%~2"
	shift
	goto next
)
if "%~1"=="--build-for-osi" (
    echo Building for OSI
    set BUILD_OPTIONS=%BUILD_OPTIONS% -DBUILD_FOR_OSI=ON
    shift
    goto next
)
echo invalid option %~1
call:usage
EXIT /B %ERRORLEVEL%
:next
shift
goto argactionstart
:argactionend

if ""== "%BUILD_TYPE%" (
  set BUILD_TYPE=Release
)

if ""== "%BUILD_TARGET%" (
  set IS_64BIT_BUILD=1
  set BUILD_TARGET=x64
)

if %IS_32BIT_BUILD%==1 (
  if %IS_64BIT_BUILD%==1 (
    echo "Error: Both the flags --x32 and --x64 should not be passed. Either one of the flags --x32 or x64 flag should be passed."
    EXIT /B 1
  )
)

echo "Building %PROJECT_NAME% library."
echo "args: %*"
call clean.bat %PROJECT_NAME%

echo ********** Building %PROJECT_NAME% library ********** >>%LOG_FILE%
if %BUILD_TARGET%==x64 (
    call %CMAKE_BIN% -G %VSIDE_GENERATOR_x64% -DCMAKE_BUILD_TYPE=%BUILD_TYPE% %BUILD_OPTIONS% CMakeLists.txt 1>>%LOG_FILE% 2>>&1
) else (
    call %CMAKE_BIN% -G %VSIDE_GENERATOR_x32% -DCMAKE_BUILD_TYPE=%BUILD_TYPE% %BUILD_OPTIONS% CMakeLists.txt 1>>%LOG_FILE% 2>>&1
)

call %CMAKE_BIN% --build . --config !BUILD_TYPE! 1>>!LOG_FILE! 2>>&1

if NOT %ERRORLEVEL% == 0 (
   set BUILD_ERR=%ERRORLEVEL%
   echo Build failed
   echo Exited with error %BUILD_ERR%
   echo Refer file "%LOG_FILE%" for details.
   call :printLogOnFailure %LOG_FILE%
   exit /b %BUILD_ERR%
)

echo Build Successful

call:copyToBin
IF ERRORLEVEL 1 (
    echo Failed copying %PROJECT_NAME% library binaries
)

EXIT /B %ERRORLEVEL%

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: printLogOnFailure() - call this to print log file contents when VERBOSE_BUILD_LOG is set
:: Usage: call :printLogOnFailure "path\to\logfile.log"
:: Note: Prints last 200 lines to avoid GitHub Actions truncation

:printLogOnFailure
if defined VERBOSE_BUILD_LOG (
    if "%VERBOSE_BUILD_LOG%"=="1" (
        echo.
        echo ================================================================================
        echo BUILD LOG - ERRORS AND WARNINGS SUMMARY
        echo ================================================================================
        if exist "%~1" (
            findstr /i /c:"error" /c:"fatal" /c:"failed" "%~1" 2>nul
        )
        echo.
        echo ================================================================================
        echo BUILD LOG - LAST 200 LINES - %~1
        echo ================================================================================
        if exist "%~1" (
            powershell -NoProfile -Command "Get-Content '%~1' -Tail 200"
        ) else (
            echo Log file not found: %~1
        )
        echo ================================================================================
        echo END OF BUILD LOG
        echo ================================================================================
        echo.
    )
)
goto:EOF

:usage
  echo.
  echo    "./build.bat --help --gdb --debug --openssl_shim --libtype <static | shared> [--x64 | --x32] --log <log_file>"
  echo.
  echo    "--help          - Help with usage"
  echo    "--gdb           - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo    "--debug         - Build with Mocana logging enabled for specific build executable."
  echo    "--disable-suiteb - Build with suiteb disabled."
  echo    "--openssl_shim  - Build with openssl_shim enabled."
  echo    "--libtype <static | shared> - Build a library either static or shared, defaul is shared."
  echo    "--x64           - Build x64 executables. By default creates build for 64Bit machine."
  echo    "--x32           - Build x32 executables. By default creates build for 64Bit machine."
  echo    "--log <log_file>- Dump compilation logs to specifed log file."
  echo.
EXIT /B 0

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Function to copy build target to bin dir
:copyToBin
    set src_dir=%BUILD_TYPE%
    echo Executing copy bat - %CopyBAT% --srcDir=!src_dir! --linkType=%LIB_TYPE% --binName=%PROJECT_NAME% --binType=lib
    call %CopyBAT% --srcDir=!src_dir! --linkType=%LIB_TYPE% --binName=%PROJECT_NAME% --binType=lib
    echo Finished execution of copy bat
EXIT /B %ERRORLEVEL%

