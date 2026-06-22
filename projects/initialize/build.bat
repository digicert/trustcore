::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: This BAT intends to -
::   > Build the "initialize" library
::
:: Usage:
::  build.bat --gdb --debug --libtype <static|shared> "--x32"|"--x64" --platform <string> <MAKETARGETS>
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
set LIB_NAME=initialize
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
    set arg1=%1
    if -%1-==-- goto argactionend
    if %1==--help (
      call:show_usage
      EXIT /B %ERR_EXIT%
    )
    if "%1"=="--gdb" (
      echo Enabling Debug build...
      set BUILD_TYPE=Debug
      set BUILD_OPTIONS=%BUILD_OPTIONS% -DCMAKE_BUILD_TYPE=Debug
      goto next
    )
    if "%1"=="--pg" (
      echo Enabling callstack tracing build...
      set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_PG=ON
      goto next
    )
    if "%1"=="--debug" (
      echo Building with Debug logs enabled...
      set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DEBUG=ON
      goto next
    )
    if "%1" == "--libtype" (
        if "%2"=="static" (
            set IS_STATIC_BUILD=1
            echo Building static library...
            set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=STATIC
            set LIB_TYPE=static
            set LIB_EXT=lib
        ) else (
            set IS_STATIC_BUILD=0
            set LIB_TYPE=shared
            set LIB_EXT=dll
            if "%2"=="shared" (
                set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
            ) else (
                echo Error reading libtype %2 switching to default - shared
                set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
            )
        )
        shift
        goto next
    )
    if "%1" == "--data-protect" (
        echo Building with data protect enabled...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DATA_PROTECT=ON
        goto next
    )
    if "%1" == "--force-data-protect" (
        echo Building with force data protect enabled...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_FORCE_DATA_PROTECT=ON
        goto next
    )
    if "%1" == "--forcelink" (
        echo Setting flags to force linkage ...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_WIN_FORCE_LINKAGE=ON
        goto next
    )
    if "%1" == "--fips" (
        echo Linking to libmss ...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_FIPS=ON
        goto next
    )
    if "%1" == "--mem-profile" (
        echo Building with memory profiling enabled ...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MEM_PROFILE=ON
        goto next
    )
    REM if "%1" == "--platform" (
    REM    BUILD_OPTIONS=%BUILD_OPTIONS% -DCP_SYSTEM_NAME=%2%"
    REM    shift
    REM    goto next
    REM )
    if "%1" == "--toolchain" (
        echo Setting toolchain for %2
        set_toolchain_file %2
        shift
        goto next
    )
    if "%1" == "--mbed" (
        goto next
    )
    if "%1" == "--mbed-path" (
        goto next
    )
    if "%1" == "--suiteb" (
        goto next
    )
    if "%1" == "--custom-entropy" (
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_CUSTOM_ENTROPY=ON
        goto next
    )
    if "%1" == "--ipv6" (
        echo Building with IPV6 enabled ...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_IPV6=ON
        goto next
    )
    if "%1" == "--no-cryptointerface" (
        echo Building with crypto interface disabled ...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_CI=ON
        goto next
    )
    if "%1" == "--mpart" (
        echo Building with memory partitioning enabled ...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_MPART=ON
        goto next
    )
    if "%1" == "--force-entropy" (
        echo Enable forced entropy
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_FORCE_ENTROPY=ON
        goto next
    )
    if "%1" == "--disable-tcp-init" (
        echo Disable Mocana TCP init
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_DISABLE_TCP_INIT=ON
        goto next
    )
    if "%1" == "--cmake-opt" (
        echo Setting extra flags for cmake execution...
        set BUILD_OPTIONS=%BUILD_OPTIONS% %~2
        shift
        goto next
    )
    if "%1" == "--build-for-osi" (
        echo Enabling BUILD_FOR_OSI...
        set BUILD_OPTIONS=%BUILD_OPTIONS% -DBUILD_FOR_OSI=ON
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
    if %1==--log (
        IF "%~2"=="" (
            echo Error reading log file path %2
            exit /b %ERR_EXIT%
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

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Function to print usage of this BAT script

:show_usage
    echo.
    echo build.bat --gdb --debug --libtype ^<static^|shared^> "--x32"^|"--x64" --log ^<build-log-filepath^> --forcelink ^<MAKETARGETS^>
    echo.
    echo    --gdb               - Build a Debug version or Makefiles ^& Projects. ^(Release is default^)
    echo    --pg                - Build with call stack tracing.
    echo    --debug             - Build with Mocana logging enabled for specific build executable.
    echo    --libtype ^<static^|shared^> - Build a library either static type or shared type default is shared.
    echo    --x32 ^| --x64       - Choose x32 for 32 bit build, and x64 for 64 bit. ^(x64 is default^)
    echo    --custom-entropy    - Build with callback to inject external entropy.
    echo    --ipv6              - Build with IPV6 enabled.
    echo    --no-cryptointerface - Build with Crypto Interface disabled.
    echo    --mpart             - Build with memory partition enabled.
    echo    --force-entropy     - Enable force entropy.
    echo    --disable-tcp-init  - Disable Mocana TCP init.
    echo    --mem-profile       - Build with memory profiling capability.
    echo    --data-protect      - Build with data protection.
    echo    --forcelink         - Set this option only when attempting to force ignore unresolved linker errors ^(typically in first pass build^).
    echo    --cmake-opt         - Use this parameter to pass extra CMAKE parameters.
    echo    --build-for-osi     - Enable BUILD_FOR_OSI.
    echo    --log ^<filepath^>    - Log file path to use for build output.
    echo    ^<MAKETARGETS^>       - Make targets to build. ^('all' is default^)
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
if %ERRORLEVEL% NEQ 0 (echo.&echo Failure^(%errorlevel%^) encountered!)
echo.&echo Exiting....
::echo.&pause&exit /b %1
exit /b %ERRORLEVEL%


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: build_initialize - Function to execute CMAKE files and build the initialize library

:build_initialize
    call:echoIfVerbose %0:Starts
    set libInitializeFileName=%LIB_NAME%.%LIB_EXT%
    echo Building "%libInitializeFileName%"

    if "%WIN_BUILD_MODE%"=="VSIDE" (
        echo ********** Building %LIB_NAME% library ********** >>!LOG_FILE!
        if !BUILD_ARCH!==x64 (
            echo Executing - "%CMAKE_BIN% -G %VSIDE_GENERATOR_x64% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS! CMakeLists.txt 1>>!LOG_FILE! 2>>&1 ...."
            call %CMAKE_BIN% -G %VSIDE_GENERATOR_x64% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS! CMakeLists.txt 1>>!LOG_FILE! 2>>&1
        ) else (
            echo Executing - "%CMAKE_BIN% -G %VSIDE_GENERATOR_x32% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS! CMakeLists.txt 1>>!LOG_FILE! 2>>&1"
            call %CMAKE_BIN% -G %VSIDE_GENERATOR_x32% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS! CMakeLists.txt 1>>!LOG_FILE! 2>>&1
        )

        call %CMAKE_BIN% --build . --config !BUILD_TYPE! 1>>!LOG_FILE! 2>>&1

        if !ERRORLEVEL! NEQ 0 (
           set BUILD_ERR=!ERRORLEVEL!
           echo Build failed
           echo Exited with error !BUILD_ERR!
           echo Refer file "!LOG_FILE!" for details.
           call :printLogOnFailure "!LOG_FILE!"
           exit /b !BUILD_ERR!
        )
        echo "%LIB_NAME% library built successfully at !BUILD_TYPE!\!libInitializeFileName!"
    ) else (
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
           echo Failure: NMake Failed to build "%libInitializeFileName%" from "Makefile"
           echo Failure: NMAKE exited with error !ERRORLEVEL!
           echo Refer file "!LOG_FILE!" for details.
           exit /b !ERRORLEVEL!
        )

        if NOT exist %libInitializeFileName% (
           echo Failure: NMake Failed to build "%libInitializeFileName%" from "Makefile"
           echo Refer file "!LOG_FILE!" for details.
           exit /b 2
        )

        echo "%LIB_NAME% library built successfully at %libInitializeFileName%"
    )
    ::popd
    call:echoIfVerbose %0:Ends
exit /b 0


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
:: clean_initialize() - call this to clean the build targets and files

:clean_initialize
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

call:clean_initialize & IF ERRORLEVEL 1 goto:end %errorlevel%

echo ********** Building Common library ********** >>%LOG_FILE%
call:build_initialize & IF ERRORLEVEL 1 goto:end %errorlevel%

call:copyToBin & IF ERRORLEVEL 1 goto:end %errorlevel%

GOTO:end 0

