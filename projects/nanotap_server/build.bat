::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: This BAT intends to build TAP Server program 'nanotap_server_bin'
::
:: Usage:
::  build.bat --gdb --debug --libtype <static|shared> "--x32"|"--x64" --tpm2
::
::  Example: To build 64 bit EXEs, execute this command:
::      build.bat --x64 --tpm2
::
::  To print help -
::   build.bat --help
::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

@echo OFF
SETLOCAL ENABLEEXTENSIONS
SETLOCAL ENABLEDELAYEDEXPANSION


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Constants
set CopyBAT=..\..\scripts\win32\copy_build_to_bin.bat
set CMAKE_PATH=C:\Program Files\CMake\bin
set CMAKE_BIN="%CMAKE_PATH%\cmake.exe"
set PROJECT_NAME=nanotap_server
set TOOL_BIN_NAME=%PROJECT_NAME%_bin


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Variables
set TAP_OPT_ALLOWED=1
set BUILD_OPTIONS=
set BUILD_TYPE=
set BUILD_TARGET=
::Log file path
set LOG_FILE="build_bat.out"
set IS_STATIC_BUILD=0
set IS_32BIT_BUILD=0
set IS_64BIT_BUILD=0
set LINK_TYPE=shared

set VS_PLATFORM=x86

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Function to parse arguments
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
if "%~1"=="--debug" (
  set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DEBUG=ON
  goto next
)
if "%~1"=="--suiteb" (
  goto next
)
if "%~1"=="--x64" (
  set IS_64BIT_BUILD=1
  set BUILD_TARGET=x64
  set VS_PLATFORM=x64
  goto next
)
if "%~1"=="--x32" (
  set IS_32BIT_BUILD=1
  set BUILD_TARGET=x32
  set VS_PLATFORM=Win32
  goto next
)
if "%~1" == "--libtype" (
	if "%2"=="static" (
		set IS_STATIC_BUILD=1
		set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=STATIC
        set LINK_TYPE=static
	) else (
		set IS_STATIC_BUILD=0
		if "%2"=="shared" (
			set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
		) else (
            echo Error reading libtype %2 switching to default - shared
			set BUILD_OPTIONS=%BUILD_OPTIONS% -DLIB_TYPE:STRING=SHARED
		)
        set LINK_TYPE=shared
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
  echo Building with tap remote enabled...
  set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TAP_REMOTE=ON
  goto next
)
if "%~1"=="--tpm2" (
  echo Building with tpm2...
  set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TPM2=ON
  goto next
)
if "%~1"=="--tpm12" (
  echo Building with tpm12...
  set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TPM=ON
  goto next
)
if "%~1"=="--cred-ev" (
  set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_CRED_EV=ON
  goto next
)
if "%~1"=="--data-protect" (
  set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_DATA_PROTECT=ON
  goto next
)
if "%~1"=="--log" (
	IF "%~2"=="" (
        echo Error reading log file path %2
		exit /b 1
	)
	set LOG_FILE="%~2"
	shift
	goto next
)
if "%~1"=="--win-service" (
  echo Building tap server as windows service...
  set BUILD_OPTIONS=%BUILD_OPTIONS% -DCM_ENABLE_TAPS_WIN_SERVICE=ON
  goto next
)
echo invalid option %1
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
    echo Error: Both the flags --x32 and --x64 should not be passed. Either one of the flags --x32 or x64 flag should be passed
    EXIT /B 1
  )
)

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Build steps

echo Building %PROJECT_NAME% ...
call clean.bat %PROJECT_NAME%

echo ********** Building %PROJECT_NAME% ********** >>%LOG_FILE%
if %BUILD_TARGET%==x64 (
    call %CMAKE_BIN% -G "Visual Studio 15 2017 Win64" -DCMAKE_BUILD_TYPE=%BUILD_TYPE% %BUILD_OPTIONS% CMakeLists.txt 1>>%LOG_FILE% 2>>&1
) else (
    call %CMAKE_BIN% -G "Visual Studio 15 2017" -DCMAKE_BUILD_TYPE=%BUILD_TYPE% %BUILD_OPTIONS% CMakeLists.txt 1>>%LOG_FILE% 2>>&1
)

call msbuild %PROJECT_NAME%.sln /property:Configuration=%BUILD_TYPE% /p:Platform=%VS_PLATFORM% 1>>%LOG_FILE% 2>>&1

if %ERRORLEVEL% NEQ 0 (
   echo Build failed
   echo Exited with error %ERRORLEVEL%
   echo Refer file "%LOG_FILE%" for details.
   exit /b %ERRORLEVEL%
)

echo Build Successful

call:copyToBin & IF ERRORLEVEL 1 goto:end %errorlevel%

EXIT /B %ERRORLEVEL%


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Function to print usage
:usage
    echo.
    echo build.bat --gdb --debug --libtype ^<static^|shared^> "--x32"^|"--x64" ---log ^<build-log-filepath^>
    echo.
    echo "   --help            - Build options information"
    echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
    echo "   --debug           - Build with Mocana logging enabled for specific build executable."
    echo "   --libtype <static | shared> - Build a library either static type or shared type default is shared."
    echo "   --toolchain <rpi32 | rpi64 | bbb> - Specify the toolchain to be used"
    echo "                        rpi32     For Raspberry Pi 32-bit"
    echo "                        rpi64     For Raspberry Pi 64-bit"
    echo "                        bbb       For BeagleBone Black"
    echo "   --tpm2            - Building with tpm2"
    echo "   --tpm12           - Building with tpm12"
    echo "   --tap-remote      - Building with tpm remote"
    echo "   --clean           - Clean Build"
    echo "   --x32             - Creates build for 32Bit machine. By default creates build for 64Bit machine."
    echo "   --x64             - Creates build for 64Bit machine. By default creates build for 64Bit machine."
    echo "   --data-protect    - Build with data protection for the configuration files."
    echo "   --cred-ev         - Build with extended credential verification."
    echo    --log ^<filepath^>  - Log file path to use for build output.
    echo.
EXIT /B %ERRORLEVEL%


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Function to copy build target to bin dir
:copyToBin
    set src_dir=%BUILD_TYPE%
    echo Executing copy bat - %CopyBAT% --srcDir=!src_dir! --linkType=%LINK_TYPE% --binName=%TOOL_BIN_NAME% --binType=app
    call %CopyBAT% --srcDir=!src_dir! --linkType=%LINK_TYPE% --binName=%TOOL_BIN_NAME% --binType=app
    echo Finished execution of copy bat
EXIT /B %ERRORLEVEL%


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: end() - call this to exit from the script

:end
endlocal
if ERRORLEVEL 1 (echo.&echo Failure^(%errorlevel%^) encountered!)
echo.&echo Exiting....
::echo.&pause&exit /b %1
exit /b %1

