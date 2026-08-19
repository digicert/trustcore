::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: This BAT intends to -
::   > Build dependent shared libraries and nanosec library/target.
::
:: Usage:
::  build_target_tap_local_ncrypto.bat --gdb --debug --suiteb --dual-mode --x64|x32 --example --data-protect 
::
::  To print help -
::   build_target_tap_local_ncrypto.bat --help
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
set DO_CLEAN=1

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Variables

set BAT_DIR=%~dp0

set MSS_PROJECTS_DIR=%BAT_DIR%\..\..\..\projects
set BIN_DIR=bin_win32

set WITH_GDB=0
set WITH_DEBUG=0
set GDB_ARG=
set DEBUG_ARG=
set SUITEB_ARG=
set DUAL_MODE_ARG=

set PASS_PARAM=
set FIRST_PASS_PARAM=--forcelink
set "ADD_ARGS="
set "BUILD_OPTIONS="
set TARGET_NAME=
set /A NO_TARGET=0
set /A EAP_ENABLED=0
set /A DUAL_MODE_ENABLED=0
set /A TLS=0
set BUILD_TARGET=
set SSL_OPTION=
set IKE_OPTION=
set EAP_CRYPTO_OPTION=
set MCP_ARG=
set PROD_RNG=
set DATA_PROTECT_ARG=
set CRYPTO_SSH_ARG=--ssh-no-chachapoly
set CHACHAPOLY=

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Execution starts here

echo %0 - BEGINS
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
      echo Enabling GDB
      set WITH_GDB=1
      set GDB_ARG=--gdb
      goto next
    )
    if "%1"=="--debug" (
      echo Enabling Debug
      set WITH_DEBUG=1
      set DEBUG_ARG=--debug
      goto next
    )
    if "%1" == "--suiteb" (
      echo Suiteb enabled by default
      goto next
    )    
    if "%1" == "--disable-suiteb" (
      set SUITEB_ARG=--disable-suiteb
      goto next
    )
    if "%1" == "--enable-chachapoly" (
      set CRYPTO_SSH_ARG=--ssh
      set CHACHAPOLY=--enable-chachapoly
      goto next
    )
	if "%1" == "--dual-mode" (      
	  echo Building with dual mode...
	  set /A DUAL_MODE_ENABLED=1      
      goto next
    )
	if "%1"=="--example" (
      echo Building with example...
	  set BUILD_TARGET=--example
      ::set "BUILD_OPTIONS=!BUILD_OPTIONS! -DCM_BUILD_EXAMPLE=ON"
      GOTO next
	)
	if "%~1"=="--library" (
		echo "Building with library enabled..."
		set LIBRARY_OPTION=%LIBRARY_OPTION%%1
		GOTO next
	) 

  if "%1"=="--data-protect" (
    echo Enabling data protection
    set DATA_PROTECT_ARG=--data-protect
    GOTO next
  )
	if %1==--x64 (
          set IS_64BIT_BUILD=1
          set BUILD_ARCH=--x64
          goto next
        )
        if %1==--x32 (
          set IS_32BIT_BUILD=1
          set BUILD_ARCH=--x32
          set VS_PLATFORM=Win32
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

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Function to print usage of this BAT script

:show_usage
  echo .
  echo Usage: %0 [--OPTIONS] TARGET_NAME
  echo .
  echo Options:
  echo    --suiteb        Enable Suite-B algos
  echo    --library       build ssh_client library
  echo    --x64           64 bit build and DLL's.
  echo    --x32           32 bit build and DLL's.
  echo    --data-protect  Enable Data Protection
  echo
  
  echo
  echo .
exit /b %ERR_EXIT%



:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Buils all dependent and nanosec libraries
:build_nanosec
  echo ***************************************
  echo *** Building nanosec and dependent libraries...
  echo ***************************************

  FOR %%G IN (first second) DO (
    if %%G==first (
        echo ***************************************************************
        echo *** Cleaning binaries and libraries
        echo ***************************************************************

        del /s /q %MSS_PROJECTS_DIR%\..\%BIN_DIR%\*.dll
        del /s /q %MSS_PROJECTS_DIR%\..\%BIN_DIR%\*.lib

        echo Setting extra parameters for first pass
        set PASS_PARAM=!FIRST_PASS_PARAM!
    ) else (
        set PASS_PARAM=
    )


	pushd "%MSS_PROJECTS_DIR%/common"
	call build.bat %GDB_ARG% %DEBUG_ARG% %DATA_PROTECT_ARG% !PASS_PARAM! --uri %BUILD_ARCH%
	IF ERRORLEVEL 1 exit /b !ERRORLEVEL!
	popd
	
	pushd "%MSS_PROJECTS_DIR%/platform"
	call build.bat %GDB_ARG% %DEBUG_ARG% !PASS_PARAM! %BUILD_ARCH%
	IF ERRORLEVEL 1 exit /b !ERRORLEVEL!
	popd
	
	pushd "%MSS_PROJECTS_DIR%/asn1"
	call build.bat %GDB_ARG% %DEBUG_ARG% %BUILD_ARCH%
	IF ERRORLEVEL 1 exit /b !ERRORLEVEL!
	popd
	
	pushd "%MSS_PROJECTS_DIR%/crypto"
	call build.bat %GDB_ARG% %DEBUG_ARG% !PASS_PARAM! --suiteb %BUILD_ARCH% %SSL_OPTION% %IKE_OPTION% %MCP_ARG% %EAP_CRYPTO_OPTION% %PROD_RNG% %CRYPTO_SSH_ARG% --tap --tpm2
	IF ERRORLEVEL 1 exit /b !ERRORLEVEL!
	popd

	pushd "%MSS_PROJECTS_DIR%/initialize"
	call build.bat %GDB_ARG% %DEBUG_ARG% %DATA_PROTECT_ARG% !PASS_PARAM! %SUITEB_ARG% %BUILD_ARCH%
	IF ERRORLEVEL 1 exit /b !ERRORLEVEL!
	popd
	
	echo Building nanotap2_common library in %%G pass
	pushd "%MSS_PROJECTS_DIR%\nanotap2_common"
	if %DO_CLEAN%==1 call clean.bat
	echo Executing: build.bat %GDB_ARG% %DEBUG_ARG% !PASS_PARAM! %BUILD_ARCH% --tap-local --tpm2
	call build.bat %GDB_ARG% %DEBUG_ARG% !PASS_PARAM! %BUILD_ARCH% --tap-local --tpm2
	IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
	popd
	
	echo Building nanotap2_configparser library in %%G pass
	pushd "%MSS_PROJECTS_DIR%\nanotap2_configparser"
	if %DO_CLEAN%==1 call clean.bat
	echo Executing: build.bat %GDB_ARG% %DEBUG_ARG% !PASS_PARAM! %BUILD_ARCH%
	call build.bat !PASS_PARAM! %GDB_ARG% %DEBUG_ARG% %BUILD_ARCH%
	IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
	popd

	echo Building nanotap2 library in %%G pass
	pushd "%MSS_PROJECTS_DIR%\nanotap2"
	if %DO_CLEAN%==1 call clean.bat
	echo Executing: build.bat %GDB_ARG% %DEBUG_ARG% !PASS_PARAM! %BUILD_ARCH% --tap-local --tpm2 nanotap2
	call build.bat %GDB_ARG% %DEBUG_ARG% !PASS_PARAM! %BUILD_ARCH% --tap-local --tpm2 nanotap2
	IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
	popd
	
	echo Building tpm2 library in %%G pass
	pushd "%MSS_PROJECTS_DIR%\tpm2"
	if %DO_CLEAN%==1 call clean.bat
	echo Executing: build.bat %GDB_ARG% %DEBUG_ARG% !PASS_PARAM! %BUILD_ARCH% --suiteb 
	call build.bat %GDB_ARG% %DEBUG_ARG% !PASS_PARAM! %BUILD_ARCH% --suiteb 
	IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
	popd
	
	echo Building smp_tpm2 library in %%G pass
	pushd "%MSS_PROJECTS_DIR%\smp_tpm2"
	if %DO_CLEAN%==1 call clean.bat
	echo Executing: build.bat %GDB_ARG% %DEBUG_ARG% !PASS_PARAM! %BUILD_ARCH% --suiteb
	call build.bat %GDB_ARG% %DEBUG_ARG% !PASS_PARAM! %BUILD_ARCH% --suiteb
	IF ERRORLEVEL 1 EXIT /B !ERRORLEVEL!
	popd
	
	pushd "%MSS_PROJECTS_DIR%/nanocap"
	call build.bat %GDB_ARG% %DEBUG_ARG% !PASS_PARAM! --suiteb %BUILD_ARCH%
	IF ERRORLEVEL 1 exit /b !ERRORLEVEL!
	popd
		
	
	pushd "%MSS_PROJECTS_DIR%/nanocert"
	call build.bat %GDB_ARG% %DEBUG_ARG% %DATA_PROTECT_ARG% !PASS_PARAM! --suiteb --cert --tap --ssh %BUILD_ARCH%
	IF ERRORLEVEL 1 exit /b !ERRORLEVEL!
	popd

	if "%DATA_PROTECT_ARG%"=="--data-protect" (
	  pushd "%MSS_PROJECTS_DIR%/data_protection"
	  call clean.bat
	  call build.bat %GDB_ARG% %DEBUG_ARG% %EXPORT_ARG% !PASS_PARAM! %BUILD_ARCH%
	  IF ERRORLEVEL 1 exit /b !ERRORLEVEL!
	  popd
	)
	if %%G==first (
		pushd "%MSS_PROJECTS_DIR%/nanossh"
        call clean.bat
		call build.bat %GDB_ARG% %DEBUG_ARG% %DATA_PROTECT_ARG% !PASS_PARAM! %SUITEB_ARG% %BUILD_OPTIONS% %BUILD_TARGET% %BUILD_ARCH% %CHACHAPOLY% --library --tap-local ssh_client
		IF ERRORLEVEL 1 exit /b !ERRORLEVEL!
        popd
	)
	
	if %%G==second (
        echo ***************************************************************
        echo *** buliding binary
        echo ***************************************************************

	    pushd "%MSS_PROJECTS_DIR%/nanossh"
        call clean.bat
        call build.bat %GDB_ARG% %DEBUG_ARG% %DATA_PROTECT_ARG% !PASS_PARAM! %SUITEB_ARG% %BUILD_OPTIONS% %BUILD_TARGET% %BUILD_ARCH% %LIBRARY_OPTION% %CHACHAPOLY% --tap-local ssh_client
	    IF ERRORLEVEL 1 exit /b !ERRORLEVEL!
        popd
    )
  )
exit /b %SUCCESS%

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: end() - call this to exit from the script
:end
endlocal
if ERRORLEVEL 1 (echo.&echo Failure^(%errorlevel%^) encountered!)
echo.&echo Exiting....
::echo.&pause&exit /b %1
exit /b %1

:MAIN

echo args: %*
if "%1"=="" (
    call:show_usage %ERR_EXIT%
    exit /b %ERRORLEVEL%
)
call:argactionstart %* & IF ERRORLEVEL 1 goto:end %errorlevel%

::call:validate_nanosec & IF ERRORLEVEL 1 goto:end %errorlevel%

call:build_nanosec & IF ERRORLEVEL 1 goto:end %errorlevel%

GOTO:end 0
