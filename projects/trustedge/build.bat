::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: This BAT intends to -
::   > Build the "trustedge" library and binary
::
:: Usage:
::  build.bat [options]
::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

@echo OFF
SETLOCAL ENABLEEXTENSIONS
SETLOCAL ENABLEDELAYEDEXPANSION


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- CONSTANTS

set SUCCESS=0
set ERR_EXIT=1
set ERR_INV_ARGS=2

set CopyBAT=..\..\scripts\win32\copy_build_to_bin.bat

::VERBOSE_MODE - Set this variable to non-zero in order to print verbose messages, else set it to 0.
set VERBOSE_MODE=1

::WIN_BUILD_MODE values - VSIDE is for building VisualStudio generator
set WIN_BUILD_MODE=VSIDE

:: Check if VSINSTALLDIR is set (Visual Studio environment required)
if not defined VSINSTALLDIR (
    echo ERROR: VSINSTALLDIR is not set. Visual Studio build environment is required.
    echo Please run this script from a Visual Studio Developer Command Prompt or use vsdevcmd.bat
    exit /b %ERR_EXIT%
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
exit /b %ERR_EXIT%

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
exit /b %ERR_EXIT%

:CMAKE_READY

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Variables

set BAT_DIR=%~dp0
set BUILD_TYPE=Release
set BUILD_OPTIONS=
set IS_STATIC_BUILD=0
set IS_BUILD_FOR_OSI=0
set BUILD_TARGET=all
set BUILD_ARCH=x64
set LOG_FILE=build.out
set LIB_NAME=trustedge
set LIB_EXT=exe
set LIB_TYPE=static
set ADD_ARGS=
set VS_PLATFORM=x64
set VERSION_STRING=
set GENERATOR_BUILD=

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Execution starts here

echo %0 - BEGINS
echo Navigating to "%BAT_DIR%" ...
pushd %BAT_DIR%

echo.
echo Building trustedge library and binary.
echo.

popd
GOTO:MAIN


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: echoIfVerbose() - call this to echo a statement needed only in verbose mode

:echoIfVerbose
IF %VERBOSE_MODE% NEQ 0 (
    echo %*
)
goto:EOF


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
:: printWixLog() - print WIX log when packaging fails
:printWixLog
if defined VERBOSE_BUILD_LOG (
    if "%VERBOSE_BUILD_LOG%"=="1" (
        set "WIX_LOG=%BAT_DIR%build\_CPack_Packages\win64\WIX\wix.log"
        if exist "!WIX_LOG!" (
            echo.
            echo ================================================================================
            echo WIX LOG CONTENTS - !WIX_LOG!
            echo ================================================================================
            type "!WIX_LOG!"
            echo ================================================================================
            echo END OF WIX LOG
            echo ================================================================================
            echo.
        ) else (
            echo WIX log not found at: !WIX_LOG!
        )
    )
)
goto:EOF


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Function to parse arguments

:argactionstart
    set arg1=%~1
    set arg2=%2
    if "-%~1-"=="--" goto argactionend
    echo Parsing argument: %~1
    if "%~1"=="--help" (
      call:show_usage
      EXIT /B %ERR_EXIT%
    )
    if "%~1"=="--gdb" (
      echo Enabling Debug build...
      set BUILD_TYPE=Debug
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCMAKE_BUILD_TYPE=Debug
      goto next
    )
    if "%~1"=="--debug" (
      echo Building with Debug logs enabled...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_DEBUG=ON
      goto next
    )
    if "%~1"=="--custom-heap" (
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_CUSTOM_HEAP=ON
      goto next
    )
    if "%~1"=="--minimal" (
      echo Building with minimal code footprint...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_MINIMAL=ON
      goto next
    )
    if "%~1"=="--export" (
      echo Building Export Edition library...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_EXPORT_ED=ON
      goto next
    )
    if "%~1"=="--cvc" (
      echo Building with CV Certificate support...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_CVC=ON
      goto next
    )
    if "%~1"=="--enable-pc" (
      echo Building with Certificate/CSR printing enabled...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_CERT_PRINT=ON
      goto next
    )
    if "%~1"=="--oqs" (
      echo Building with PQC/OQS hybrid support...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_OQS=ON
      goto next
    )
    if "%~1"=="--pqc" (
      echo Building with PQC hybrid support...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_PQC=ON
      goto next
    )
    if "%~1"=="--disable-pqc" (
      echo Building without PQC hybrid support...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_PQC=OFF
      goto next
    )
    if "%~1"=="--disable-rest-api" (
      echo Building without REST API support...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_DISABLE_REST_API=ON
      goto next
    )
    if "%~1"=="--pkcs11" (
      echo Building with pkcs11 enabled...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_PKCS11=ON
      goto next
    )
    if "%~1"=="--pkcs11-dynamic" (
      goto next
    )
    if "%~1"=="--mem-prof" (
      echo Building with memory profiling support...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_MEM_PROFILE=ON
      goto next
    )
    if "%~1"=="--softhsm2" (
      echo Building with softhsm2...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_SOFTHSM=ON
      goto next
    )
    if "%~1"=="--cloudhsm" (
      echo Building with cloudhsm...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_CLOUDHSM=ON
      goto next
    )
    if "%~1"=="--dssm" (
      echo Building with Digicert ssm...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_DSSM=ON
      goto next
    )
    if "%~1"=="--pkcs11-tee" (
      echo Building with tee pkcs11 enabled...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_PKCS11_TEE=ON
      goto next
    )
    if "%~1"=="--tpm2" (
      echo Building with tpm2 enabled...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_TPM2=ON
      goto next
    )
    if "%~1"=="--tap-local" (
      echo Building TAP local...
      goto next
    )
    if "%~1"=="--tap-remote" (
      echo Building TAP remote...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_TAP_REMOTE=ON
      goto next
    )
    if "%~1"=="--digicert" (
      echo Building with Digicert scep support...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_DIGICERT_SCEP=ON
      goto next
    )
    if "%~1"=="--library" (
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_BUILD_LIBRARY=ON
      goto next
    )
    if "%~1"=="--unittest" (
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_BUILD_UNITTEST=ON
      goto next
    )
    if "%~1"=="--debug-internals" (
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_DEBUG_INTERNALS=ON
      goto next
    )
    if "%~1"=="--monolithic" (
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_MONOLITHIC_BUILD=ON
      goto next
    )
    if "%~1"=="--build-for-osi" (
      echo Enabling BUILD_FOR_OSI...
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DBUILD_FOR_OSI=ON
      set IS_BUILD_FOR_OSI=1
      goto next
    )
    if "%~1"=="--persist-artifact" (
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_PERSIST_ARTIFACT=ON
      goto next
    )
    if "%~1"=="--generator" (
      If "!arg2!"=="" (
        echo Error reading generator
        exit /b %ERR_EXIT%
      )
      set GENERATOR_BUILD=!arg2!
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_GENERATOR_BUILD=!arg2!
      shift
      goto next
    )
    if "%~1"=="--libtype" (
      if "!arg2!"=="static" (
        echo Building static library...
        set BUILD_OPTIONS=!BUILD_OPTIONS! -DLIB_TYPE:STRING=STATIC
        set LIB_TYPE=static
        set IS_STATIC_BUILD=1
      ) else (
        echo Building shared library...
        set BUILD_OPTIONS=!BUILD_OPTIONS! -DLIB_TYPE:STRING=SHARED
        set LIB_TYPE=shared
      )
      shift
      goto next
    )
    if "%~1"=="--proxy" (
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_PROXY=ON
      goto next
    )
    if "%~1"=="--disable-est" (
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_DISABLE_EST=ON
      goto next
    )
    if "%~1"=="--service-certificate" (
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_CERTMODE_SERVICE_BUILD=ON
      goto next
    )
    if "%~1"=="--valgrind-tool" (
      if "!arg2!"=="memcheck" (
        set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_VALGRIND_MEMCHECK=ON
      ) else if "!arg2!"=="massif" (
        set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_VALGRIND_MASSIF=ON
      ) else (
        echo Unknown valgrind tool: !arg2!
        exit /b %ERR_EXIT%
      )
      shift
      goto next
    )
    if "%~1"=="--pre-release" (
      If "!arg2!"=="" (
        echo Error reading pre-release string
        exit /b %ERR_EXIT%
      )
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_PRE_RELEASE_STRING=!arg2!
      shift
      goto next
    )
    if "%~1"=="--x32" (
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_BUILD_X32=ON
      set BUILD_ARCH=x32
      set VS_PLATFORM=Win32
      echo Building for x32 machine...
      goto next
    )
    if "%~1"=="--x64" (
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_BUILD_X64=ON
      set BUILD_ARCH=x64
      echo Building for x64 machine...
      goto next
    )
    if "%~1"=="--version-string" (
      echo Setting version string to !arg2!...
      set "VERSION_STRING=!arg2!"
      shift
      goto next
    )
    if "%~1"=="--enable-coverage" (
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_COVERAGE=ON
      goto next
    )
    if "%~1"=="--enable-token-fallback" (
      set BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_ENABLE_TOKEN_FALLBACK=ON
      goto next
    )
    if "%~1"=="--cmake-opt" (
      If "!arg2!"=="" (
        echo Error reading cmake opt
        exit /b %ERR_EXIT%
      )
      echo Setting additional cmake option: !arg2!
      set "BUILD_OPTIONS=!BUILD_OPTIONS! !arg2!"
      shift
      goto next
    )
    :: Check for unknown options or additional arguments
    if not "%arg1:~0,2%"=="--" (
      echo Adding Argument: %~1
      set ADD_ARGS=!ADD_ARGS! %~1
      goto next
    )
    if not "%arg1:~0,1%"=="-" (
      echo Adding Argument: %~1
      set ADD_ARGS=!ADD_ARGS! %~1
      goto next
    )
    :: Skip unknown -D options (cmake options passed through)
    echo "%arg1%" | findstr /C:"-D" 1>/NUL
    if %ERRORLEVEL% EQU 0 (
      set "BUILD_OPTIONS=!BUILD_OPTIONS! %~1"
      goto next
    )
    echo Invalid option: %1
    call:show_usage
    EXIT /B %ERR_EXIT%
    :next
    shift
    goto argactionstart
:argactionend


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Function to validate arguments

:validate_args
    set RET_VAL=%SUCCESS%
    :: Set build-target to the specified targets else set to 'all'
    if -!ADD_ARGS!-==-- (
        set BUILD_TARGET=all
    ) else (
        set BUILD_TARGET=!ADD_ARGS!
    )
:validate_args_end
EXIT /B %RET_VAL%


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Function to print usage of this BAT script

:show_usage
    echo.
    echo build.bat [options]
    echo.
    echo    --help                 - Display this help menu
    echo    --gdb                  - Build a Debug version ^(Release is default^)
    echo    --debug                - Build with Mocana logging enabled
    echo    --export               - Build export edition
    echo    --cvc                  - Build with CV Certificate support
    echo    --enable-pc            - Enable Certificate/CSR printing
    echo    --pqc                  - Build with pqc hybrid key support
    echo    --oqs                  - Build with pqc/oqs hybrid key support
    echo    --pkcs11               - Build with pkcs11 support
    echo    --pkcs11-dynamic       - Build with pkcs11 dynamic load support
    echo    --softhsm2             - Build with pkcs11 softhsm2 support
    echo    --cloudhsm             - Build with pkcs11 cloudhsm support
    echo    --mem-prof             - Build with memory profiling support
    echo    --custom-heap          - Build with custom heap support
    echo    --pkcs11-tee           - Build with pkcs11 tee support
    echo    --dssm                 - Build with Digicert SSM support
    echo    --minimal              - Build with minimal code footprint
    echo    --tpm2                 - Build with tpm2 support
    echo    --digicert             - Build with Digicert scep support
    echo    --library              - Build trustedge binary as library
    echo    --unittest             - Build trustedge unittests
    echo    --debug-internals      - Build with internal debugging
    echo    --monolithic           - Build monolithic binary
    echo    --build-for-osi        - Build for OSI ^(Open Source^) repository
    echo    --disable-est          - Disable EST support
    echo    --pre-release          - Specify pre-release string
    echo    --persist-artifact     - Enable persisting artifact payload
    echo    --generator ^<name^>     - Specify the generator ^(TGZ, MSI^)
    echo    --proxy                - Build with proxy support
    echo    --x32                  - Build for 32-bit platforms
    echo    --x64                  - Build for 64-bit platforms
    echo    --version-string       - Version information for release
    echo    --service-certificate  - Build with service certificate mode conf
    echo    --valgrind-tool ^<tool^> - Enable valgrind with selected tool
    echo    --enable-coverage      - Build with gcov code coverage support
    echo    --enable-token-fallback - Enable fallback when authorization token missing
    echo    --cmake-opt            - Additional cmake options
    echo.
EXIT /B %ERRORLEVEL%


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: print_vars - Function to print the variables used for build operation

:print_vars
    echo BUILD_TYPE= %BUILD_TYPE%
    echo BUILD_OPTIONS= %BUILD_OPTIONS%
    echo BUILD_ARCH= %BUILD_ARCH%
    echo IS_STATIC_BUILD= %IS_STATIC_BUILD%
    echo LOG_FILE= %LOG_FILE%
    echo ADD_ARGS= %ADD_ARGS%
EXIT /B 0


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: set_logFile() - set the log file path

:set_logFile
   set myts=%time::=_%
   set myts=%myts:~0,8%
   set nowyear=%date:~10,4%
   set nowmonth=%date:~4,2%
   set nowday=%date:~7,2%
   set LOG_FILE=%BAT_DIR%build_%LIB_NAME%_%nowyear%%nowmonth%%nowday%_%myts%.log
   set logFile=%logFile: =%
exit /b 0


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: end() - call this to exit from the script

:end
endlocal
if %ERRORLEVEL% NEQ 0 (echo.&echo Failure^(%errorlevel%^) encountered!)
echo.&echo Exiting....
exit /b %ERRORLEVEL%


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: build_trustedge - Function to execute CMAKE files and build trustedge

:build_trustedge
    call:echoIfVerbose %0:Starts
    
    echo Building trustedge...
    
    :: Create build directory if it doesn't exist
    if not exist build mkdir build
    pushd build
    
    echo ********** Building trustedge ********** >>!LOG_FILE!
    
    if !BUILD_ARCH!==x64 (
        set "CMAKE_CMD=%CMAKE_BIN% -G %VSIDE_GENERATOR_x64% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS!"
    ) else (
        set "CMAKE_CMD=%CMAKE_BIN% -G %VSIDE_GENERATOR_x32% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS!"
    )
    
    if not "!VERSION_STRING!"=="" set "CMAKE_CMD=!CMAKE_CMD! -DCM_VERSION_STRING=!VERSION_STRING!"
    
    echo Executing - "!CMAKE_CMD! .. 1>>!LOG_FILE! 2>>&1"
    call !CMAKE_CMD! .. 1>>!LOG_FILE! 2>>&1
    
    if !ERRORLEVEL! NEQ 0 (
       set BUILD_ERR=!ERRORLEVEL!
       echo CMake generation failed
       echo Refer file "!LOG_FILE!" for details.
       call :printLogOnFailure "!LOG_FILE!"
       popd
       exit /b !BUILD_ERR!
    )
    
    echo Building trustedge...
    call %CMAKE_BIN% --build . --config !BUILD_TYPE! 1>>!LOG_FILE! 2>>&1
    if !ERRORLEVEL! NEQ 0 (
       set BUILD_ERR=!ERRORLEVEL!
       echo Build failed
       echo Exited with error !BUILD_ERR!
       echo Refer file "!LOG_FILE!" for details.
       call :printLogOnFailure "!LOG_FILE!"
       popd
       exit /b !BUILD_ERR!
    )
    
    :: Build PACKAGE target if generator was specified (for creating TGZ/package)
    if not "!GENERATOR_BUILD!"=="" (
       echo Building package with generator: !GENERATOR_BUILD!
       call %CMAKE_BIN% --build . --config !BUILD_TYPE! --target PACKAGE 1>>!LOG_FILE! 2>>&1
       
       if !ERRORLEVEL! NEQ 0 (
          set BUILD_ERR=!ERRORLEVEL!
          echo Package build failed
          echo Exited with error !BUILD_ERR!
          echo Refer file "!LOG_FILE!" for details.
          call :printLogOnFailure "!LOG_FILE!"
          call :printWixLog
          popd
          exit /b !BUILD_ERR!
       )
       echo Package created successfully
    )
    
    echo trustedge built successfully
    popd
    
    call:echoIfVerbose %0:Ends
exit /b 0


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: copyToBin - Function to copy build target to bin dir

:copyToBin
    set src_dir=build\%BUILD_TYPE%
    
    :: Determine target directory based on build flags
    if "%IS_BUILD_FOR_OSI%"=="1" (
        set "target_dir=..\..\lib\"
    ) else if "%IS_STATIC_BUILD%"=="1" (
        set "target_dir=..\..\bin_win32_static\"
    ) else (
        set "target_dir=..\..\bin_win32\"
    )
    
    :: Create target directory if it doesn't exist
    if not exist "!target_dir!" mkdir "!target_dir!"
    
    :: Copy executable if it exists
    if exist "!src_dir!\trustedge.exe" (
        echo Copying trustedge.exe to !target_dir!
        xcopy /Y "!src_dir!\trustedge.exe" "!target_dir!"
    )
    
    :: Copy library if it exists
    if exist "!src_dir!\trustedge.lib" (
        echo Copying trustedge.lib to !target_dir!
        xcopy /Y "!src_dir!\trustedge.lib" "!target_dir!"
    )
    
    echo Finished copying binaries
EXIT /B %ERRORLEVEL%


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: clean_trustedge() - call this to clean the build targets and files

:clean_trustedge
    echo Calling: clean.bat ...
    call clean.bat 1>NUL 2>&1
exit /b 0


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: MAIN() - main entry point

:MAIN

pushd %BAT_DIR%

echo args: %*

call:argactionstart %* & IF ERRORLEVEL 1 goto:end %errorlevel%

call:validate_args & IF ERRORLEVEL 1 goto:end %errorlevel%

call:set_logFile & IF ERRORLEVEL 1 goto:end %errorlevel%

call:print_vars & IF ERRORLEVEL 1 goto:end %errorlevel%

call:clean_trustedge & IF ERRORLEVEL 1 goto:end %errorlevel%

call:build_trustedge & IF ERRORLEVEL 1 goto:end %errorlevel%

call:copyToBin & IF ERRORLEVEL 1 goto:end %errorlevel%

popd
GOTO:end 0
