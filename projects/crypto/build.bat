:: file: crypto/build.bat
::
:: Summary:
::  BAT file to build crypto libraries on windows.
::  Capable of building the static lib file using CMAKE and NMAKE
::
:: Pre-Requisites:
::  CMAKE
::  NMAKE (Bundled with Visual Studio installation)
::

@echo OFF
SETLOCAL ENABLEEXTENSIONS
SETLOCAL ENABLEDELAYEDEXPANSION

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Variables -- Modify the values as appropriate here

::Out dir
set BUILD_DIR=build

::NMAKE paths
set NMAKE_PATH=
set NMAKE_BIN=nmake.exe
IF NOT [%NMAKE_PATH%]==[] (
    set NMAKE_BIN="%NMAKE_PATH%\nmake.exe"
)

::Log file path
set LOG_FILE="build_bat.out"

::VERBOSE_MODE - Set this variable to non-zero in order to print verbose messages, else set it to 0.
set VERBOSE_MODE=1

::Path to vcvarsall.bat of the Visual-Studio version to use.
:: Refer details in - https://docs.microsoft.com/en-us/cpp/build/building-on-the-command-line
set VCVARSALL_BAT=C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvarsall.bat

::"x86" / "x64"
set TARGET_PLATFORM=x64

:: "Release" / "Debug"
set TARGET_CONFIG=Release
set LIBEXT=dll

set IS_TAP_ENABLED=0
set ADD_ARGS=
set CMAKE_TARGET=all
set IS_64BIT_BUILD=0
set IS_32BIT_BUILD=0
set IS_STATIC_BUILD=0
set PROJECT_NAME=crypto
set LINK_NO_DEP=0
set LIB_TYPE=shared
set BUILD_TYPE=Release
set SUCCESS=0
set ERR_EXIT=1
set ERR_INV_ARGS=2
set ERR_BUILD_ERROR=3
set VS_PLATFORM=x64
set IS_EXPORT=0
set IS_OQS=0

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

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Execution begins here.

set BAT_DIR=%~dp0
::set "BUILD_OPTIONS=-DLIB_TYPE:STRING=STATIC"
set "BUILD_OPTIONS= -DCM_ENABLE_CRYPTOINTERFACE=ON"
call:echoIfVerbose BAT_DIR: %BAT_DIR%


GOTO:MAIN

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: end() - call this to exit from the script

:end
endlocal
if %ERRORLEVEL% NEQ 0 (echo.&echo Failure^(%errorlevel%^) encountered!)
echo.&echo Exiting....
::echo.&pause&exit /b %1
exit /b %ERRORLEVEL%


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


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: echoIfVerbose() - call this to echo a statement needed only in verbose mode

:echoIfVerbose
IF %VERBOSE_MODE% NEQ 0 (
    echo %*
)
goto:EOF


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: parseArguments() - parses arguments to bat file

:parseArguments
    :parseArgumentsLoop
        set arg1=%1
        IF "%~1"=="" GOTO parseArgumentsLoopEnd
        if "%~1"=="--gdb" (
            echo Enabling Debug build...
            set BUILD_TYPE=Debug
            set BUILD_OPTIONS=%BUILD_OPTIONS% -DCMAKE_BUILD_TYPE=Debug
            SHIFT
            GOTO parseArgumentsLoop
        )
        IF "%~1"=="--pg" (
            echo Enabling callstack tracing build...
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_PG=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        IF "%~1"=="--debug" (
            set TARGET_CONFIG=DEBUG
            set BUILD_TYPE=Debug
            echo Building debug build with with debug logs enabled...
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_DEBUG=ON -DCMAKE_BUILD_TYPE=Debug"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--release" (
            set TARGET_CONFIG=RELEASE
            set BUILD_TYPE=Release
            echo Building Release build without debug logs ...
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCMAKE_BUILD_TYPE=Release "
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--log" (
            IF "%~2"=="" (
                echo "Error reading log file path %2"
                exit /b 1
            )
            set LOG_FILE="%~2"
            SHIFT & SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--libtype" (
            IF "%~2"=="static" (
                set IS_STATIC_BUILD=1
                set "BUILD_OPTIONS=!BUILD_OPTIONS! -DLIB_TYPE:STRING=STATIC"
                set LIBEXT=lib
                set LIB_TYPE=static
            ) ELSE IF "%~2"=="shared" (
                set IS_STATIC_BUILD=0
                set "BUILD_OPTIONS=!BUILD_OPTIONS! -DLIB_TYPE:STRING=SHARED"
                set LIBEXT=dll
                set LIB_TYPE=shared
            ) ELSE (
                echo "Error reading libtype %2"
                set "BUILD_OPTIONS=!BUILD_OPTIONS! -DLIB_TYPE:STRING=SHARED"
                set LIBEXT=dll
                set LIB_TYPE=shared
            )
            SHIFT & SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--no-datalib" (
            echo "Building without data library ..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_BUILD_DATALIB=OFF"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--suiteb" (
            echo "suiteb is enabled by default. Ignoring legacy --suiteb flag."
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--disable-suiteb" (
            echo "Building with suiteb disabled..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_DISABLE_SUITEB=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--chacha20" (
            echo "Building with ChaCha20 enabled..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_CHACHA20=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--rsa_8k" (
            echo "Building with RSA 8K enabled..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_RSA_8K=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--blake2" (
            echo "Building with Blake2 enabled..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_BLAKE2=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--disable-rc5" (
            echo "Building with RC5 disabled..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_DISABLE_RC5=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--disable-pqc" (
            echo "Building with PQC disabled..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_DISABLE_PQC=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--pqc" (
            echo "PQC is enabled by default. Ignoring legacy --pqc flag."
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--keygen" (
            echo "Building with crypto keygen APIs..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_KEYGEN=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--aes-gcm-4k" (
            echo "Building for AES-GCM 4k"
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_AES_GCM_4K=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--aes-gcm-256b" (
            echo "Building for AES-GCM 256b"
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_AES_GCM_256B=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--small-footprint" (
            echo "Building with small footprint"
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_SMALL_FOOTPRINT=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--ipv6" (
            echo "Building with IPV6 enabled..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_IPV6=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--ipsec" (
            echo "Building with IPSEC support..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_IPSEC=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--cvc" (
            echo "Building with CV Cert functionality."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_CVC=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--enable-pc" (
            echo "Building with Certificate/CSR printing enabled."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_CERT_PRINT=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--cmake-opt" (
            echo "Setting extra flags for cmake execution..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! %~2"
            SHIFT
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--build-for-osi" (
            echo "Enabling BUILD_FOR_OSI..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DBUILD_FOR_OSI=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--tap" (
            echo "Building with TAP..."
            set IS_TAP_ENABLED=1
            set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_TAP=ON
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--tap-local" (
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--ssl" (
            echo "Building with ssl flags & sources..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_SSL=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--fips" (
            echo "Building subset of nanocrypto & linking to libmss"
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_FIPS=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--tpm2" (
            echo "Building with tpm2 flags & sources..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_TPM2=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--ssh" (
            echo "Building with ssh flags & sources..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_SSH=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--ssh-no-chachapoly" (
            echo "Building with ssh flags & sources (no chachapoly)..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_SSH_NO_CHACHAPOLY=ON"
            SHIFT
            GOTO parseArgumentsLoop        
        )
        if "%~1"=="--scep" (
            echo "Building with scep flags & sources..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_SCEP=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--ike" (
            echo "Building with ike flags & sources..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_IKE=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--mcp" (
            echo "Building with MCPA flags & sources..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_MCPA=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--ci-tests" (
            echo "Enable all algorithms for Crypto Interface unit tests..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_CITESTS=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--eap" (
            echo "Building with eap flags & sources..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_EAP=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--openssl" (
            echo "Building with openssl flags & sources..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_OPENSSL_SHIM=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--openssl3" (
            echo "Building with Digicert OpenSSL 3.0 provider support..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_OPENSSL3=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--wpa2" (
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_WPA2=ON"
            shift
            goto parseArgumentsLoop
        )
        if "%~1"=="--vlong-const" (
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_VLONG_CONST=ON"
            shift
            goto parseArgumentsLoop
        )
        if "%~1"=="--tap-extern" (
            echo "Building with extern TAP..."
            SET IS_TAP_EXTERN_ENABLED=1
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_TAP_EXTERN=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--tap-hybrid-sign" (
            echo "Building with TAP hybrid sign..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_TAP_HYBRID_SIGN=ON"
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--export" (
            echo "Building Export Edition library..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_EXPORT_ED=ON"
            set IS_EXPORT=1
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--oqs" (
            set IS_OQS=1
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--oqs-path" (
            echo "Building with OQS..."
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_OQS=ON -DCM_OQS_PATH=%2"
            SHIFT
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--x64" (
            set IS_64BIT_BUILD=1
            set TARGET_PLATFORM=x64
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--x32" (
            set IS_32BIT_BUILD=1
            set TARGET_PLATFORM=x32
            set VS_PLATFORM=Win32
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1"=="--opts" (
             IF "%~2"=="" (
                echo "Error reading extra options from --opts: %2"
                exit /b 1
            )
            set "BUILD_OPTIONS=!BUILD_OPTIONS! %~2"
            SHIFT & SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1" == "--forcelink" (
            echo Setting flags to force linkage ...
            set LINK_NO_DEP=1
            set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_WIN_FORCE_LINKAGE=ON
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1" == "--prod-rng" (
            set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PROD_RNG=ON
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1" == "--mbed" (
            set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MBED=ON
            SHIFT
            GOTO parseArgumentsLoop
        )
        if "%~1" == "--mbed-path" (
            echo "Setting mbed-path to: %2"
            set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_MBED_PATH=%2
            SHIFT
            SHIFT
            GOTO parseArgumentsLoop
        ) ELSE IF NOT "%arg1:~0,2%" == "--" (
            echo Adding Argument: %~1
            set ADD_ARGS=%ADD_ARGS% %~1
            SHIFT
            GOTO parseArgumentsLoop
        ) ELSE (
            echo "Error: Invalid argument %~1"
            exit /b 1
        )
    :parseArgumentsLoopEnd
exit /b 0

:set_logFile
   set LOG_FILE=%BAT_DIR%build_bat.out
   set logFile=%logFile: =%
exit /b 0

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Function to validate arguments

:validate_args
    set RET_VAL=%SUCCESS%

    :: Check target architecture
    if %IS_64BIT_BUILD%==1 (
        if %IS_32BIT_BUILD%==1 (
            echo Choose either of 64 bit ^(--x64^) or 32-bit ^(--x32^), Both cannot be set.
            set RET_VAL=%ERR_INV_ARGS%
            goto validate_args_end
        )
    )
    
    if %IS_EXPORT%==1 (
        if %IS_OQS%==0 (
            echo Export build without OQS, disabling PQC.
            set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_DISABLE_PQC=ON"
        )
    )

    :: Set build-target to the specified targets else set to 'all'
    if -%ADD_ARGS%-==-- (
        set CMAKE_TARGET=all
    ) else (
        set BUILD_TARGET=%ADD_ARGS%
    )

    ::Check for mandatory values to be present
    if -%CMAKE_TARGET%-==-- (
        set RET_VAL=%ERR_INV_ARGS%
        goto validate_args_end
    )
:validate_args_end
EXIT /B %RET_VAL%

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: printLocalEnvs

:printLocalEnvs
    call:echoIfVerbose TARGET_CONFIG: %TARGET_CONFIG%
    call:echoIfVerbose LOG_FILE: %LOG_FILE%
    call:echoIfVerbose BUILD_OPTIONS: %BUILD_OPTIONS%
exit /b 0


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: build_crypto

:build_crypto
    call:echoIfVerbose %0:Starts
    set build_status=%SUCCESS%
    echo Building Crypto Libraries
    ::pushd %BAT_DIR%

        if "%TARGET_PLATFORM%" == "x64" (
            echo Executing -  %CMAKE_BIN% -G %VSIDE_GENERATOR_x64% -DCMAKE_BUILD_TYPE=%BUILD_TYPE% %BUILD_OPTIONS% .. 1>>!LOG_FILE! 2>>&1
            call %CMAKE_BIN% -G  %VSIDE_GENERATOR_x64% -DCMAKE_BUILD_TYPE=%BUILD_TYPE% %BUILD_OPTIONS% .. 1>>!LOG_FILE! 2>>&1
        ) else (
            echo Executing - %CMAKE_BIN% -G  %VSIDE_GENERATOR_x32% -DCMAKE_BUILD_TYPE=%BUILD_TYPE% %BUILD_OPTIONS% .. 1>>!LOG_FILE! 2>>&1
            call %CMAKE_BIN% -G %VSIDE_GENERATOR_x32% -DCMAKE_BUILD_TYPE=%BUILD_TYPE% %BUILD_OPTIONS% .. 1>>!LOG_FILE! 2>>&1
        )

        echo Executing - call %CMAKE_BIN% --build . --config !BUILD_TYPE! 1>>!LOG_FILE! 2>>&1
        call %CMAKE_BIN% --build . --config !BUILD_TYPE! 1>>!LOG_FILE! 2>>&1

        if %LINK_NO_DEP% EQU 0 (
            if %ERRORLEVEL% NEQ 0 (
               set BUILD_ERR=%ERRORLEVEL%
               echo Build failed
               echo Exited with error %BUILD_ERR%
               echo Refer file "!LOG_FILE!" for details.
               call :printLogOnFailure "!LOG_FILE!"
               exit /b %BUILD_ERR%
            )
        )

        if EXIST %~dp0build\nanocrypto\%BUILD_TYPE%\nanocrypto.lib if EXIST %~dp0build\cryptointerface\%BUILD_TYPE%\cryptointerface.lib  (
            echo Build Successful
            set build_status=%SUCCESS%
        ) else (
            echo Build failed
            echo Failure code = %ERRORLEVEL%
            call :printLogOnFailure "!LOG_FILE!"
            set build_status=%ERR_BUILD_ERROR%
        )

        EXIT /B %ERRORLEVEL%

    ::popd
    call:echoIfVerbose %0:Ends
exit /b 0


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: MAIN() - main entry point, called first

:MAIN

echo Received arguments: "%*"

::Parse arguments
call:parseArguments %* & IF ERRORLEVEL 1 goto:end %errorlevel%
call:validate_args & IF ERRORLEVEL 1 goto:end %errorlevel%
call:printLocalEnvs

call:set_logFile & IF ERRORLEVEL 1 goto:end %errorlevel%

::Clean directories
call clean.bat 1>NUL 2>&1

if not exist "%BUILD_DIR%" mkdir %BUILD_DIR%
cd %BUILD_DIR%

echo ********** Building Crypto library ********** >>%LOG_FILE%
call:build_crypto & IF ERRORLEVEL 1 goto:end %errorlevel%

GOTO:end 0
