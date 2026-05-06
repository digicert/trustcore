
@echo off
SETLOCAL ENABLEEXTENSIONS
SETLOCAL ENABLEDELAYEDEXPANSION

set SCRIPT_DIR=%~dp0
set ROOT_DIR=%SCRIPT_DIR%\..\..\..
set "EXAMPLE_DIR=%ROOT_DIR%/src/examples/zephyr_examples"

set BUILD_TYPE="Release"
set FMGMT_SAMPLE=0
set "IMAGE_NAME=test application"
:: 0 - trustedge sample, 1 - fmgmt + network sample, 2 - OTA handler sample
set APP_SAMPLE=0
set BUILD_TRUSTEDGE_LIB=1
set "TRUSTEDGE_MINIMAL_ARGS="
set "BOARD_TYPE=native_sim/native/64"
set "BOARD_ARG=native"
set "BOARD_OVERLAY=./boards/flash_size.overlay"
set "BOARD_CONF_FILE="
set CLEAN=0
set "ZEPHYR_VENV="

echo %0 - BEGINS
GOTO:MAIN

:argactionstart
    set arg1=%1
    if -%1-==-- goto argactionend
    if %1==--help (
      call:show_usage
      EXIT /B %ERR_EXIT%
    )
	  if "%1"=="--board" (
      if "%2"=="stm32h745i_disco" (
        echo "board: stm32h745i_disco"
        set "BOARD_TYPE=stm32h745i_disco/stm32h745xx/m7"
        set "BOARD_ARG=%BOARD%"
        set "BOARD_OVERLAY=./boards/stm32h745i_disco_stm32h745xx_m7.overlay"
        set "BOARD_CONF_FILE=stm32_prj.conf"
      )
      if "%2"=="nucleo_h745zi_q" (
        echo "board: nucleo_h745zi_q"
        set "BOARD_TYPE=nucleo_h745zi_q/stm32h745xx/m7"
        set "BOARD_ARG=%BOARD%"
        set "BOARD_OVERLAY=./boards/nucleo_h745zi_q_stm32h745xx_m7.overlay"
        set "BOARD_CONF_FILE=stm32_prj.conf"
      )

      shift
      GOTO next
	  )
    if "%1"=="--new" (
      set "IMAGE_NAME=new application"
      goto next
    )
    if "%1"=="--gdb" (
      set BUILD_TYPE="Debug"
      goto next
    )
    if "%1"=="--skip-lib" (
      set BUILD_TRUSTEDGE_LIB=0
      goto next
    )
    if "%1"=="--trustedge" (
      set APP_SAMPLE=0
      goto next
    )
    if "%1"=="--tests" (
      set APP_SAMPLE=1
      goto next
    )
    if "%1"=="--ota-sample" (
      set APP_SAMPLE=2
      goto next
    )
    if "%1"=="--minimal" (
      set "TRUSTEDGE_MINIMAL_ARGS=-DCM_ENABLE_MINIMAL=ON"
      goto next
    )
    if "%1"=="--clean" (
      set CLEAN=1
      goto next
    )
    if "%1"=="--zephyr-env" (
        set "ZEPHYR_ENV=%2"
        shift
        goto next
    )
    echo invalid option %1
    call:show_usage
    EXIT /B %ERR_EXIT%
:next
    shift
    goto argactionstart
:argactionend
    exit /b %errorlevel%

:MAIN

if "%1"=="" (
  ::call:show_usage %ERR_EXIT%
  echo "empty arguments"
  exit /b %ERRORLEVEL%
)
call:argactionstart %* & IF ERRORLEVEL 1 goto:end %errorlevel%
:: Check if 'west' command is available
where west >nul 2>&1
if %errorlevel% neq 0 (
    echo 'west' command not found. Please ensure it is installed and in your PATH.
    exit /b 1
)

if %BUILD_TRUSTEDGE_LIB%==0 (
    set CLEAN=0
)

if %CLEAN%==1 (
    pushd %ROOT_DIR%
    git clean -xfd
    popd
)

if %BUILD_TRUSTEDGE_LIB%==1 (
    pushd %ROOT_DIR%\projects\trustedge
    echo "building Trustedge archive file"
    echo "board:        %BOARD_TYPE%"
    echo "overlay file: %BOARD_OVERLAY%"
    echo "build type:   %BUILD_TYPE%"
    echo ""
    west build -b %BOARD_TYPE% --pristine -- -DDTC_OVERLAY_FILE="%BOARD_OVERLAY%" -DCMAKE_BUILD_TYPE=%BUILD_TYPE% -DCM_DISABLE_REST_API=ON -DCM_ENABLE_ZEPHYR_OS=ON -DCM_GENERATOR_BUILD=ZIP -DCM_BUILD_X32=ON !TRUSTEDGE_MINIMAL_ARGS!
    popd

    xcopy %ROOT_DIR%\projects\trustedge\build\lib\libtrustedge.a %ROOT_DIR%\bin_static\
:: Run the 'west build' command
::west build -b stm32h745i_disco/stm32h745xx/m7 --pristine -- -DDTC_OVERLAY_FILE=boards/stm32h745i_disco_stm32h745xx_m7.overlay
)

if %APP_SAMPLE%==0 (
    echo "building trustedge sample"
    set "SAMPLE_DIR=%ROOT_DIR%\src\examples\zephyr_examples\trustedge_sample\"
)
if %APP_SAMPLE%==1 (
    echo "building tests sample"
    set "SAMPLE_DIR=%ROOT_DIR%\src\examples\zephyr_examples\network_sample\"
)
if %APP_SAMPLE%==2 (
    echo "building OTA sample"
    set "SAMPLE_DIR=%ROOT_DIR%\src\examples\zephyr_examples\trustedge_dfu_handler_sample\"
)

echo sample directory: !SAMPLE_DIR!
pushd !SAMPLE_DIR!
west build -b !BOARD_TYPE! -p --build-dir !SAMPLE_DIR!\build -- -DDTC_OVERLAY_FILE=!BOARD_OVERLAY! -DEXTRA_CONF_FILE=!BOARD_CONF_FILE! -DIMAGE_NAME="!IMAGE_NAME!"

::west build -t ram_report > ram_report.txt
::west build -t rom_report > rom_report.txt
popd
