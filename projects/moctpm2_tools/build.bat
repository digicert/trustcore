::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: This BAT intends to -
::   > Build the "moctpm2_tools" library
::
:: Usage:
::  build.bat --gdb --debug --< tap-local | tap-remote > <MAKETARGETS>
::
::  --gdb           - Build a Debug version or Makefiles & Projects. (Release is default)
::  --debug         - Build with Mocana logging enabled for specific build executable
::  <MAKETARGETS>   - Make targets to build. ('all' is default)
::
::  To print help -
::   build.bat --help::
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

::VERBOSE_MODE - Set this variable to non-zero in order to print verbose messages,
::else set it to 0.
set VERBOSE_MODE=1

::CMAKE paths
set CMAKE_PATH=C:\Program Files\CMake\bin
set CMAKE_BIN="%CMAKE_PATH%\cmake.exe"

::NMAKE paths
set NMAKE_PATH=
set NMAKE_BIN=nmake.exe
IF NOT "%NMAKE_PATH%"=="" (
    set NMAKE_BIN="%NMAKE_PATH%\nmake.exe"
)

::WIN_BUILD_MODE values - VSIDE is for building VisualStudio generator,
::and NMAKE for nmake generator
set VS_PLATFORM=
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
set BUILD_TYPE=Release
set BUILD_OPTIONS=
set BUILD_TARGET=all
set BUILD_ARCH=x64
set LOG_FILE=build.out
set LINK_TYPE=shared
set LIB_EXT=dll
set ADD_ARGS=
set TOOL_NAME=moctpm2_tools
set TOOL_BIN_NAME_PATTERN_1=moctpm2_*
set TOOL_BIN_NAME_PATTERN_2=smp_tpm2_*

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Execution starts here

echo %0 - BEGINS
echo Navigating to "%BAT_DIR%" ...
pushd %BAT_DIR%

echo.
echo Building %TOOL_NAME% tools.
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
    if "%1"=="--debug" (
      echo Building with Debug logs enabled...
      set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DEBUG=ON
      goto next
    )
    if "%1" == "--tap-local" (
      echo Building with tap local...
      set  BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_LOCAL=ON
      goto next
   )
   if "%1" == "--tap-remote" (
      echo Building with tap remote...
      set  BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_REMOTE=ON
      goto next
   )
   if %1==--x64 (
      set IS_64BIT_BUILD=1
      set BUILD_ARCH=x64
      set VS_PLATFORM=x64
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
:: -- Function to print usage of this BAT script

:show_usage
    echo.
    echo build.bat --gdb --debug --^< tap-local^| tap-remote ^> ^<MAKETARGETS^>
    echo.
    echo    --gdb             - Build a Debug version or Makefiles & Projects.
    echo                        (Release is default)
    echo    --debug           - Build with Mocana logging enabled for
    echo                        specific build executable.
    echo    ^<MAKETARGETS^>   - Make targets to build. ^('all' is default^)
    echo.
EXIT /B %ERRORLEVEL%


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: print_vars - Function to print the variables used for build operation

:print_vars
    echo BUILD_TYPE= %BUILD_TYPE%
    echo BUILD_OPTIONS= %BUILD_OPTIONS%
    echo BUILD_ARCH= %BUILD_ARCH%BUILD_TARGET
    echo IS_STATIC_BUILD= %IS_STATIC_BUILD%
    echo LOG_FILE= %LOG_FILE%
    echo ADD_ARGS= %ADD_ARGS%
EXIT /B 0


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: set_logFile() - main entry point, called first

:set_logFile
   set myts=%time::=_%
   set myts=%myts:~0,8%

   set nowyear=%date:~10,4%
   set nowmonth=%date:~4,2%
   set nowday=%date:~7,2%

   set LOG_FILE=%BAT_DIR%build_%TOOL_NAME%_%nowyear%%nowmonth%%nowday%_%myts%.log
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
:: build_moctpm2_tools - Function to execute CMAKE files and build moctpm2 tools

:build_moctpm2_tools
    call:echoIfVerbose %0:Starts
    echo Building "%TOOL_NAME%"

    if "%WIN_BUILD_MODE%"=="VSIDE" (
        echo ********** Building %TOOL_NAME% ********** >>!LOG_FILE!
        if !BUILD_ARCH!==x64 (
            echo Executing - "%CMAKE_BIN% -G %VSIDE_GENERATOR_x64% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS! CMakeLists.txt 1>>!LOG_FILE! 2>>&1 ...."
            call %CMAKE_BIN% -G %VSIDE_GENERATOR_x64% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS! CMakeLists.txt 1>>!LOG_FILE! 2>>&1
        ) else (
            echo Executing - "%CMAKE_BIN% -G %VSIDE_GENERATOR_x32% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS! CMakeLists.txt 2>>!LOG_FILE! 2>>&1"
            call %CMAKE_BIN% -G %VSIDE_GENERATOR_x32% -DCMAKE_BUILD_TYPE=!BUILD_TYPE! !BUILD_OPTIONS! CMakeLists.txt 1>>!LOG_FILE! 2>>&1
        )

        call msbuild %TOOL_NAME%.sln /property:Configuration=!BUILD_TYPE! /p:Platform=%VS_PLATFORM% 1>>!LOG_FILE! 2>>&1

        if !ERRORLEVEL! NEQ 0 (
           echo Build failed
           echo Exited with error !ERRORLEVEL!
           echo Refer file "!LOG_FILE!" for details.
           exit /b !ERRORLEVEL!
        )
        echo "%TOOL_NAME% built successfully at !BUILD_TYPE!\"
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
           echo Failure: NMake Failed to build "%TOOL_NAME%" from "Makefile"
           echo Failure: NMAKE exited with error !ERRORLEVEL!
           echo Refer file "!LOG_FILE!" for details.
           exit /b !ERRORLEVEL!
        )

        if NOT exist %TOOL_BIN_NAME_PATTERN_1% (
           echo Failure: NMake Failed to build "%TOOL_NAME%" from "Makefile"
           echo Refer file "!LOG_FILE!" for details.
           exit /b 2
        )

        echo moctpm2_tools library built successfully at %%
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

    echo Executing copy bat - %CopyBAT% --srcDir=!src_dir! --linkType=%LINK_TYPE% --binName=%TOOL_BIN_NAME_PATTERN_1% --binType=app
    call %CopyBAT% --srcDir=!src_dir! --linkType=%LINK_TYPE% --binName=%TOOL_BIN_NAME_PATTERN_1% --binType=app
    echo Finished execution of copy bat

    echo Executing copy bat - %CopyBAT% --srcDir=!src_dir! --linkType=%LINK_TYPE% --binName=%TOOL_BIN_NAME_PATTERN_2% --binType=app
    call %CopyBAT% --srcDir=!src_dir! --linkType=%LINK_TYPE% --binName=%TOOL_BIN_NAME_PATTERN_2% --binType=app
    echo Finished execution of copy bat
EXIT /B %ERRORLEVEL%


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: clean_moctpm2_tools() - call this to clean the build targets and files

:clean_moctpm2_tools
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

call:clean_moctpm2_tools & IF ERRORLEVEL 1 goto:end %errorlevel%

echo ********** Building Moctpm2_tools library ********** >>%LOG_FILE%
call:build_moctpm2_tools & IF ERRORLEVEL 1 goto:end %errorlevel%

call:copyToBin & IF ERRORLEVEL 1 goto:end %errorlevel%

GOTO:end 0


