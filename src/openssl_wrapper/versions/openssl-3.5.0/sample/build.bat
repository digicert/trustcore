::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: This BAT intends to -
::   > Build the openssl connector
::
:: Usage:
::  build.bat --gdb --debug --suiteb --libtype <static|shared> "--x32"|"--x64" --platform <string> <MAKETARGETS>
::
::  Example 1: To build 64 bit DLL execute this command:
::      build.bat --libtype shared --x64
::  Example 2: To build 32 bit LIB execute this command:
::      build.bat --libtype static --x32
::
::  To print help -
::   build.bat --help
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

::VERBOSE_MODE - Set this variable to non-zero in order to print verbose messages, else set it to 0.
set VERBOSE_MODE=1

::CMAKE paths
set CMAKE_PATH=C:\Program Files\CMake\bin
set CMAKE_BIN="%CMAKE_PATH%\cmake.exe"

::WIN_BUILD_MODE values - VSIDE is for building VisualStudio generator, and NMAKE for nmake generator
set WIN_BUILD_MODE=VSIDE
set VSIDE_GENERATOR_x64="Visual Studio 15 2017 Win64"
set VSIDE_GENERATOR_x32="Visual Studio 15 2017"

echo "%VSINSTALLDIR%" | findstr /C:"2019" 1>/NUL
if %ERRORLEVEL% EQU 0 (
    set VSIDE_GENERATOR_x64="Visual Studio 16 2019" -A x64
    set VSIDE_GENERATOR_x32="Visual Studio 16 2019" -A Win32
)

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Variables

set BAT_DIR=%~dp0
set "BUILD_DIR=%BAT_DIR%build\"
set BUILD_TYPE=Release
set BUILD_OPTIONS=
set IS_STATIC_BUILD=0
set BUILD_TARGET=all
set BUILD_ARCH=x64
set LOG_FILE=build.out
set "PROJ_NAME=OpenSSL Connector"
set LIB_EXT=dll
set LIB_TYPE=shared
set ADD_ARGS=
set VS_PLATFORM=x64

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Execution starts here

echo %0 - BEGINS
echo Navigating to "%BAT_DIR%" ...
pushd %BAT_DIR%

echo.
echo Building %PROJ_NAME%.
echo.

popd REM pushd %BAT_DIR%
GOTO:MAIN


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: echoIfVerbose() - call this to echo a statement needed only in verbose mode

:echoIfVerbose
IF %VERBOSE_MODE% NEQ 0 (
    echo %*
)
goto:EOF


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Function to parse arguments

:argactionstart
    set arg1=%1
    set arg2=%2
    if -%1-==-- goto argactionend
    if "%1"=="--help" (
      call:show_usage
      EXIT /B %ERR_EXIT%
    )
    if "%1"=="--gdb" (
      echo Enabling Debug build...
      set BUILD_TYPE=Debug
      set BUILD_OPTIONS=%BUILD_OPTIONS% -DCMAKE_BUILD_TYPE=Debug
      goto next
    )
    if "%1"=="--debug" (
      echo Building with Debug logs enabled...
      set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DEBUG=ON
      goto next
    )
    if "%1" == "--libtype" (
        if "!arg2!"=="static" (
            set IS_STATIC_BUILD=1
            echo Building static library...
            set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=STATIC
            set LIB_TYPE=static
            set LIB_EXT=lib
        ) else (
            set IS_STATIC_BUILD=0
            set LIB_TYPE=shared
            set LIB_EXT=dll
            if "!arg2!"=="shared" (
                set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
            ) else (
                echo Error reading libtype !arg2! switching to default - shared
                set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
            )
        )
        shift
        goto next
    )
    if "%1" == "--forcelink" (
        echo Setting flags to force linkage ...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_WIN_FORCE_LINKAGE=ON
        goto next
    )
    if "%1" == "--toolchain" (
        echo Setting toolchain for !arg2!
        set_toolchain_file !arg2!
        shift
        goto next
    )
    if "%1" == "--tap" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TAP=ON
        goto next
    )
    if "%1" == "--tap-local" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TAP_LOCAL=ON
        goto next
    )
    if "%1" == "--tap-remote" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TAP_REMOTE=ON
        goto next
    )
    if "%1" == "--fips" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_FIPS=ON
        goto next
    )
    if "%1" == "--mauth" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MAUTH=ON
        goto next
    )
    if "%1" == "--load-all-algos" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_ALL_ALGOS=ON
        goto next
    )
    if "%1" == "--rehandshake" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_REHANDSHAKE=ON
        goto next
    )
    if "%1" == "--sendquit" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SENDQUIT=ON
        goto next
    )
    if "%1" == "--alertcb" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_ALERTCB=ON
        goto next
    )
    if "%1" == "--pem-read" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PEM_READ=ON
        goto next
    )
    if "%1" == "--posthandshake-auth" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_POSTHANDSHAKE_AUTH=ON
        goto next
    )
    if "%1" == "--key-update" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_KEY_UPDATE=ON
        goto next
    )
    if "%1" == "--psk" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PSK=ON
        goto next
    )
    if "%1" == "--0rtt" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_0RTT=ON
        goto next
    )
    if "%~1" == "--force-static" (
        echo Setting CM_ENV_FORCE_STATIC_LINK to preserve '/MD'
        set CM_ENV_FORCE_STATIC_LINK=1
        goto next
    )
    if %1==--x64 (
      set IS_64BIT_BUILD=1
      set BUILD_ARCH=x64
      goto next
    )
    if %1==--x32 (
      set IS_32BIT_BUILD=1
      set BUILD_ARCH=x32
      set VS_PLATFORM=Win32
      goto next
    )
    if %1==--cmake-opt (
      If "!arg2!"=="" (
            echo Error reading cmake opt !arg2!
            exit /b %ERR_EXIT%
        )
        set "BUILD_OPTIONS=%BUILD_OPTIONS% !arg2!"
        shift
      goto next
    )
    if %1==--log (
        If "!arg2!"=="" (
            echo Error reading log file path !arg2!
            exit /b %ERR_EXIT%
        )
        set LOG_FILE="!arg2!"
        shift
        goto next
    )
    :: This case should be checked and parsed in the end only
    if not "%arg1:~0,2%" == "--" (
        echo Adding Argument: %1
        set ADD_ARGS=%ADD_ARGS% %1
        goto next
    )
    echo invalid option %1
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
    if "-%ADD_ARGS%-"=="--" (
        set BUILD_TARGET=all
    ) else (
        set BUILD_TARGET=%ADD_ARGS%
    )

    ::Check for mandatory values to be present
    if "-%BUILD_TARGET%-"=="--" (
        set RET_VAL=%ERR_INV_ARGS%
        goto validate_args_end
    )
:validate_args_end
    if %RET_VAL% NEQ %SUCCESS% (
        call:show_usage
    )
EXIT /B %RET_VAL%

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Function to print usage of this BAT script

:show_usage
    echo.
    echo build.bat --gdb --debug --suiteb --libtype ^<static^|shared^> "--x32"^|"--x64" --platform ^<string^> --log ^<build-log-filepath^> --forcelink ^<MAKETARGETS^>
    echo.
    echo    --gdb             - Build a Debug version or Makefiles ^& Projects. ^(Release is default^)
    echo    --debug           - Build with Mocana logging enabled for specific build executable.
    echo    --tap             - Enable TAP.
    echo    --tap-local       - Enable TAP-Local.
    echo    --tap-remote      - Enable TAP-Remote.
    echo    --fips            - Enable FIPS-build (links to libmss).
    echo    --mauth           - Enable mutual authentication.
    echo    --load-all-algos  - Enable all OpenSSL algorithms.
    echo    --rehandshake     - Enable re-handshake.
    echo    --sendquit        - Enable SendQuit command.
    echo    --alertcb         - Enable Alert Callback support.
    echo    --pem-read        - Enable PEM read BIO private key.
    echo    --posthandshake-auth   - Enable TLS1.3 post-handshake authentication.
    echo    --key-update      - Enable TLS1.3 key update.
    echo    --psk             - Enable TLS1.3 PSK.
    echo    --0rtt            - Enable 0RTT
    echo    --libtype ^<static^|shared^> - Build a library either static type or shared type default is shared.
    echo    --x32 ^| --x64      - Choose x32 for 32 bit build, and x64 for 64 bit. ^(x64 is default^)
    echo    --forcelink         - Set this option only when attempting to force ignore unresolved linker errors ^(typically in first pass build^).
    echo    --log ^<filepath^>  - Log file path to use for build output.
    echo    ^<MAKETARGETS^>     - Make targets to build. ^('all' is default^)
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
    REM echo TOOLCHAIN_FILE= %TOOLCHAIN_FILE%
    REM echo CMAKE_MOCANA_PLATFORM_NAME= %CMAKE_MOCANA_PLATFORM_NAME%
EXIT /B 0


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: set_logFile() - main entry point, called first

:set_logFile
   set myts=%time::=_%
   set myts=%myts:~0,8%

   set nowyear=%date:~10,4%
   set nowmonth=%date:~4,2%
   set nowday=%date:~7,2%

   set LOG_FILE=%BAT_DIR%build\build_%PROJ_NAME%_%nowyear%%nowmonth%%nowday%_%myts%.log
   set logFile=%logFile: =%
exit /b 0


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: end() - call this to exit from the script

:end
endlocal
if ERRORLEVEL 1 (echo.&echo Failure^(%errorlevel%^) encountered!)
echo.&echo Exiting....
::echo.&pause&exit /b %1
exit /b %1

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: build_proj - Function to execute CMAKE files and build the openssl connector

:build_proj
    call:echoIfVerbose %0:Starts
    echo "Building openssl connector"

    mkdir %BUILD_DIR%
    pushd %BUILD_DIR%

    echo ********** Building OpenSSL Connector ********** >>!LOG_FILE!
    if !BUILD_ARCH!==x64 (
        echo Executing - "%CMAKE_BIN% -G %VSIDE_GENERATOR_x64% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS! ..\CMakeLists.txt -B ..\. 1>>!LOG_FILE! 2>>&1 ...."
        call %CMAKE_BIN% -G %VSIDE_GENERATOR_x64% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS! ..\CMakeLists.txt -B ..\. 1>>!LOG_FILE! 2>>&1
    ) else (
        echo Executing - "%CMAKE_BIN% -G %VSIDE_GENERATOR_x32% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS! ..\CMakeLists.txt -B ..\. 1>>!LOG_FILE! 2>>&1"
        call %CMAKE_BIN% -G !VSIDE_GENERATOR_x32! -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS! ..\CMakeLists.txt -B ..\. 1>>!LOG_FILE! 2>>&1
    )

    pushd ..
    call msbuild %BUILD_TARGET%.vcxproj /property:Configuration=!BUILD_TYPE! /p:Platform=%VS_PLATFORM% 1>>!LOG_FILE! 2>>&1
    popd

    if !ERRORLEVEL! NEQ 0 (
        echo Build failed
        echo Exited with error !ERRORLEVEL!
        echo Refer file "!LOG_FILE!" for details.
        popd
        exit /b !ERRORLEVEL!
    )
    echo "openssl_connector built successfully"

    popd

    call:echoIfVerbose %0:Ends
exit /b 0

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: clean_proj() - call this to clean the build targets and files

:clean_proj
    echo Calling: clean.bat ...
    ::Clean directories
    call clean.bat 1>NUL 2>&1
exit /b 0


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: MAIN() - main entry point, called first

:MAIN

echo args: %*

call:argactionstart %* & IF ERRORLEVEL 1 goto:end %errorlevel%

call:validate_args & IF ERRORLEVEL 1 goto:end %errorlevel%

call:set_logFile & IF ERRORLEVEL 1 goto:end %errorlevel%

call:print_vars & IF ERRORLEVEL 1 goto:end %errorlevel%

call:clean_proj & IF ERRORLEVEL 1 goto:end %errorlevel%

echo ********** Building OpenSSL Connector ********** >>%LOG_FILE%
call:build_proj & IF ERRORLEVEL 1 goto:end %errorlevel%

GOTO:end 0


