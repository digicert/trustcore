::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: This BAT intends to -
::   > Build the "platform" library
::
:: Usage:
::  build.bat --gdb --debug --suiteb --libtype <static|shared> "--x32"|"--x64" --platform <string> <MAKETARGETS>
::
::  Example 1: To build 64 bit DLL execute this command:
::      build.bat --suiteb --libtype shared --x64
::  Example 2: To build 32 bit LIB execute this command:
::      build.bat --suiteb --libtype static --x32
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

set CopyBAT=..\..\scripts\win32\copy_build_to_bin.bat

::VERBOSE_MODE - Set this variable to non-zero in order to print verbose messages, else set it to 0.
set VERBOSE_MODE=1

::NMAKE paths
set NMAKE_PATH=
set NMAKE_BIN=nmake.exe
IF NOT "%NMAKE_PATH%"=="" (
    set NMAKE_BIN="%NMAKE_PATH%\nmake.exe"
)

::WIN_BUILD_MODE values - VSIDE is for building VisualStudio generator, and NMAKE for nmake generator
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
set BUILD_TARGET=all
set BUILD_ARCH=x64
set LOG_FILE=build.out
set LIB_NAME=platform
set LIB_EXT=dll
set LIB_TYPE=shared
set ADD_ARGS=
set VS_PLATFORM=x64
set SECURE_PATH_VAR=

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Execution starts here

echo %0 - BEGINS
echo Navigating to "%BAT_DIR%" ...
pushd %BAT_DIR%

echo.
echo Building %LIB_NAME% library.
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
    call:echoIfVerbose %0:Starts
    set arg1=%1
    if "-%~1-"=="--" goto argactionend
    if "%~1"=="--help" (
        call:show_usage
        EXIT /B %ERR_EXIT%
    )
    if "%~1"=="--gdb" (
        echo Enabling Debug build...
        set BUILD_TYPE=Debug
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCMAKE_BUILD_TYPE=Debug
        goto next
    )
    if "%~1"=="--debug" (
        echo Building with Debug logs enabled...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DEBUG=ON
        goto next
    )
    if "%~1"=="--tpm2" (
        echo Building with TPM2 enabled...
        set BUILD_OPTIONS=%BUILD_OPTIONS%  -DCM_ENABLE_TPM2=ON
        goto next
    )
    if "%~1"=="--pg" (
        echo Enabling callstack tracing build...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PG=ON
        goto next
    )
    if "%~1"=="--ipv6" (
        echo Building with IPV6 enabled...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_IPV6=ON
        goto next
    )
    if "%~1"=="--process" (
        echo Building with process APIs...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PROCESS=ON
        goto next
    )
    if "%~1"=="--term" (
        echo Building with terminal APIs...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TERM=ON
        goto next
    )
    if "%~1"=="--signal" (
        echo Building with signal APIs...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SIGNAL=ON
        goto next
    )
    if "%~1"=="--absolute-path" (
        echo Building with absolute path enabled...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_ABSOLUTE_PATH=ON
        goto next
    )
    if "%~1"=="--secure-path" (
        echo Building with secure path enabled...
        set "SECURE_PATH_VAR=-DSECURE_PATH=%~2"
        shift
        goto next
    )
    if "%~1"=="--mpart" (
        echo Building with memory partition enabled...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MPART=ON
        goto next
    )
    if "%~1"=="--build-for-osi" (
        echo Enabling BUILD_FOR_OSI...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DBUILD_FOR_OSI=ON
        goto next
    )
    if "%~1" == "--libtype" (
        if "%~2"=="static" (
            set IS_STATIC_BUILD=1
            echo Building static library...
            set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=STATIC
            set LIB_TYPE=static
            set LIB_EXT=lib
        ) else (
            set IS_STATIC_BUILD=0
            set LIB_TYPE=shared
            set LIB_EXT=dll
            if "%~2"=="shared" (
                set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
            ) else (
                echo Error reading libtype %2 switching to default - shared
                set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
            )
        )
        shift
        goto next
    )
    if "%~1" == "--forcelink" (
        echo Setting flags to force linkage ...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_WIN_FORCE_LINKAGE=ON
        goto next
    )
    if "%~1" == "--fips" (
        echo Building subset lib and linking to libmss
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_FIPS=ON
        goto next
    )
    if "%~1" == "--toolchain" (
        echo Setting toolchain for %2
        set_toolchain_file %2
        shift
        goto next
    )
    if "%~1" == "--mbed" (
        goto next
    )
    if "%~1" == "--mbed-path" (
        goto next
    )
    if "%~1" == "--suiteb" (
        REM set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_SUITEB=ON
        goto next
    )
    if "%~1"=="--x64" (
      set IS_64BIT_BUILD=1
      set BUILD_ARCH=x64
      goto next
    )
    if "%~1"=="--x32" (
      set IS_32BIT_BUILD=1
      set BUILD_ARCH=x32
      set VS_PLATFORM=Win32
      goto next
    )
    if "%~1"=="--cmake-opt" (
        echo Setting extra flags for cmake execution...
        set "BUILD_OPTIONS=%BUILD_OPTIONS% %~2"
        shift
        goto next
    )
    if "%~1"=="--log" (
        IF "%~2"=="" (
            echo Error reading log file path %2
            exit /b ERR_INV_ARGS
        )
        set LOG_FILE="%~2"
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
    if -%ADD_ARGS%-==-- (
        set BUILD_TARGET=all
    ) else (
        set BUILD_TARGET=%ADD_ARGS%
    )

    ::Check for mandatory values to be present
    if -%BUILD_TARGET%-==-- (
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
    echo build.bat --gdb --debug --libtype ^<static^|shared^> "--x32"^|"--x64" ^<MAKETARGETS^>
    echo.
    echo    --help            - Build options information
    echo    --gdb             - Build a Debug version or Makefiles ^& Projects. ^(Release is default^)
    echo    --pg              - Build with call stack tracing.
    echo    --debug           - Build with Mocana logging enabled for specific build executable.
    echo    --fips            - Build with FIPS.
    echo    --ipv6            - Build with IPV6 enabled.
    echo    --process         - Build with process APIs.
    echo    --term            - Build with terminal APIs.
    echo    --signal          - Build with signal APIs.
    echo    --absolute-path   - Build with absolute path enabled.
    echo    --secure-path     - Build with secure path enabled.
    echo    --mpart           - Build with memory partition enabled.
    echo    --tpm2            - Build with TPM2 enabled.
    echo    --libtype ^<static^|shared^> - Build a library either static type or shared type default is shared.
    echo    --toolchain ^<rpi32^|rpi64^|bbb^|android^> - Specify the toolchain to be used.
    echo    --x32             - Creates build for 32Bit machine. By default creates build for 64Bit machine.
    echo    --x64             - Creates build for 64Bit machine. By default creates build for 64Bit machine.
    echo    --cmake-opt       - Use this parameter to pass extra CMAKE parameters.
    echo    --build-for-osi   - Enabling BUILD_FOR_OSI.
    echo    --forcelink       - Set this option only when attempting to force ignore unresolved linker errors.
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

   set LOG_FILE=%BAT_DIR%build_%LIB_NAME%_%nowyear%%nowmonth%%nowday%_%myts%.log
   set logFile=%logFile: =%
exit /b 0


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: end() - call this to exit from the script

:end
endlocal
if %errorlevel% NEQ 0 (echo.&echo Failure^(%errorlevel%^) encountered!)
echo.&echo Exiting....
::echo.&pause&exit /b %1
exit /b %ERRORLEVEL%


:: function set_toolchain_file()
:: {
::    case "$1" in
::        rpi32)
::            echo "-- Setting toolchain for Raspberry Pi 32-bit";
::            TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=../shared_cmake/toolchains/arm-linux-gnu-toolchain.cmake"
::            CMAKE_MOCANA_PLATFORM_NAME="-DCMAKE_MOCANA_PLATFORM=rpi3_raspbian_9.4"
::            ;;
::        rpi64)
::            echo "-- Setting toolchain for Raspberry Pi 64-bit";
::            TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=../shared_cmake/toolchains/aarch64-linux-gnu-toolchain.cmake"
::            CMAKE_MOCANA_PLATFORM_NAME="-DCMAKE_MOCANA_PLATFORM=rpi3_raspbian_9.4"
::            ;;
::        bbb)
::            echo "-- Setting toolchain for BeagleBone Black";
::            TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=../shared_cmake/toolchains/arm-linux-gnu-toolchain.cmake"
::            CMAKE_MOCANA_PLATFORM_NAME="-DCMAKE_MOCANA_PLATFORM=bbb_ubuntu_16.04"
::            ;;
::    esac
::}


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Function to copy build target to bin dir
:copyToBin
    set src_dir=.
    if "%WIN_BUILD_MODE%"=="VSIDE" (
        set src_dir=%BUILD_TYPE%
    )
    echo Executing copy bat - %CopyBAT% --srcDir=!src_dir! --linkType=%LIB_TYPE% --binName=%LIB_NAME% --binType=lib
    call %CopyBAT% --srcDir=!src_dir! --linkType=%LIB_TYPE% --binName=%LIB_NAME% --binType=lib
    echo Finished execution of copy bat
EXIT /B %ERRORLEVEL%


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: clean_platform() - call this to clean the build targets and files

:clean_platform
    echo Calling: clean.bat ...
    ::Clean directories
    call clean.bat 1>NUL 2>&1
exit /b %ERRORLEVEL%


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: build_platform - Function to execute CMAKE files and build the platform library

:build_platform
    call:echoIfVerbose %0:Starts
    set libPlatformFileName=%LIB_NAME%.%LIB_EXT%
    echo Building "%libPlatformFileName%"

    if "%WIN_BUILD_MODE%"=="VSIDE" (
        echo ********** Building %LIB_NAME% library ********** >>!LOG_FILE!
        if !BUILD_ARCH!==x64 (
            set "CMAKE_CMD=%CMAKE_BIN% -G %VSIDE_GENERATOR_x64% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS!"
            if not "!SECURE_PATH_VAR!"=="" set "CMAKE_CMD=!CMAKE_CMD! !SECURE_PATH_VAR!"
            echo Executing - "!CMAKE_CMD! CMakeLists.txt 1>>!LOG_FILE! 2>>&1 ...."
            call !CMAKE_CMD! CMakeLists.txt 1>>!LOG_FILE! 2>>&1
        ) else (
            set "CMAKE_CMD=%CMAKE_BIN% -G %VSIDE_GENERATOR_x32% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS!"
            if not "!SECURE_PATH_VAR!"=="" set "CMAKE_CMD=!CMAKE_CMD! !SECURE_PATH_VAR!"
            echo Executing - "!CMAKE_CMD! CMakeLists.txt 1>>!LOG_FILE! 2>>&1"
            call !CMAKE_CMD! CMakeLists.txt 1>>!LOG_FILE! 2>>&1
        )

        call %CMAKE_BIN% --build . --config !BUILD_TYPE! 1>>!LOG_FILE! 2>>&1

        if !ERRORLEVEL! NEQ 0 (
           echo Build failed
           echo Exited with error !ERRORLEVEL!
           echo Refer file "!LOG_FILE!" for details.
           exit /b !ERRORLEVEL!
        )
        echo "nanoplatform library built successfully at !BUILD_TYPE!\!libPlatformFileName!"
    ) else (
        REM %CMAKE_BIN% %TOOLCHAIN_FILE% %CMAKE_MOCANA_PLATFORM_NAME% CMakeLists.txt --build ../. -DCMAKE_BUILD_TYPE=${BUILD_TYPE} %BUILD_OPTIONS%
        echo Executing - "%CMAKE_BIN% -G "NMake Makefiles" !BUILD_OPTIONS! CMakeLists.txt 1>>!LOG_FILE! 2>>&1 ...."
        %CMAKE_BIN% -G "NMake Makefiles"  !BUILD_OPTIONS!  CMakeLists.txt 1>>!LOG_FILE! 2>>&1
        if !ERRORLEVEL! NEQ 0 (
           echo Failure: CMake Failed to create Makefile
           echo Refer file "!LOG_FILE!" for details.
           exit /b !ERRORLEVEL!
        )
        if not exist "Makefile" (
           echo Failure: CMake Failed to create Makefile
           echo Refer file "!LOG_FILE!" for details.
           exit /b 2
        )

        echo Executing - "%NMAKE_BIN% clean" ...
        %NMAKE_BIN% clean 1>>!LOG_FILE! 2>>&1

        echo Executing - "%NMAKE_BIN% !BUILD_TARGET!" ...
        %NMAKE_BIN% !BUILD_TARGET! 1>>!LOG_FILE! 2>>&1

        if !ERRORLEVEL! NEQ 0 (
           echo Failure: NMake Failed to build "!libPlatformFileName!" from "Makefile"
           echo Failure: NMAKE exited with error !ERRORLEVEL!
           echo Refer file "!LOG_FILE!" for details.
           exit /b !ERRORLEVEL!
        )

        if NOT exist !libPlatformFileName! (
           echo Failure: NMake Failed to build "!libPlatformFileName!" from "Makefile"
           echo Refer file "!LOG_FILE!" for details.
           exit /b 2
        )

        echo "nanoplatform library built successfully at !libPlatformFileName!"
    )
    ::popd
    call:echoIfVerbose %0:Ends
exit /b 0


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: MAIN() - main entry point, called first

:MAIN

echo args: %*

call:argactionstart %* & IF ERRORLEVEL 1 goto:end %errorlevel%

call:validate_args & IF ERRORLEVEL 1 goto:end %errorlevel%

call:set_logFile & IF ERRORLEVEL 1 goto:end %errorlevel%

call:print_vars & IF ERRORLEVEL 1 goto:end %errorlevel%

call:clean_platform & IF ERRORLEVEL 1 goto:end %errorlevel%

echo ********** Building platform library ********** >>%LOG_FILE%
call:build_platform & IF ERRORLEVEL 1 goto:end %errorlevel%

call:copyToBin & IF ERRORLEVEL 1 goto:end %errorlevel%

GOTO:end 0


