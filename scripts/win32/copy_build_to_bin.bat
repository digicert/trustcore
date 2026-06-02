:: file: scripts\win32\copy_build_to_bin.bat
::
:: This BAT file should be used mostly with VISUAL STUDIO projects.
:: Copies relevant binary files from Target folder into bin_win32 dir.
:: Usage
::
::  1) To copy shared binaries use BAT as below
::
::  copy_build_to_bin \
::      --srcDir=d:\mss\src\examples\tpm2\win32\nano_common_crypto\x64\Debug_DLL
::      --binType=shared
::      --binName=nano_common
::      --binType=[lib | app]
::
::  2) To copy shared binaries use BAT as below
::
::  copy_build_to_bin \
::      --srcDir=d:\mss\src\examples\tpm2\win32\nano_common_crypto\x64\Debug
::      --binType=static
::      --binName=nano_common
::      --binType=[lib | app]
::
:: Parameters
::  > dir : Dir path to copy the library/binary from
::  > type : build type - shared(dynamic) / static
::  > name : the target file name (extensions to be excluded, just the name)
::  > binType : configuration type - [lib | app], "lib" for .libs and "app" for .exes

@echo OFF
SETLOCAL ENABLEEXTENSIONS
SETLOCAL ENABLEDELAYEDEXPANSION

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: -- Variables

set SourceDir=
set LinkType=
set TargetDir=
set TargetFileName=
set BinType=

::VERBOSE_MODE -    Set this variable to non-zero in order to
::                  print verbose messages, else set it to 0.
set VERBOSE_MODE=1

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Execution starts here

echo %0 - BEGINS
set BAT_DIR=%~dp0

echo %BAT_DIR%
GOTO:MAIN

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: echoIfVerbose() - call this to echo a statement needed only in verbose mode

:echoIfVerbose
IF %VERBOSE_MODE% NEQ 0 (
    echo %*
)
goto:EOF


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: end() - call this to exit from the script

:end
endlocal
if ERRORLEVEL 1 (echo.&echo Failure^(%errorlevel%^) encountered!)
echo.&echo Exiting....
::echo.&pause&exit /b %1


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: printLocalEnvs

:printLocalEnvs
    call:echoIfVerbose SourceDir: %SourceDir%
    call:echoIfVerbose LinkType: %LinkType%
    call:echoIfVerbose TargetDir: %TargetDir%
    call:echoIfVerbose TargetFileName: %TargetFileName%
exit /b 0


::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: parseArguments() - parses arguments to bat file

:parseArguments
    :parseArgumentsLoop
        IF "%~1"=="" GOTO parseArgumentsLoopEnd

        IF "%~1"=="--srcDir" (
            IF "%~2"=="" (
                echo "Error reading build directory path %2"
                exit /b 1
            )
            set SourceDir=%~2
            SHIFT & SHIFT
            GOTO parseArgumentsLoop
        ) ELSE IF "%~1"=="--linkType" (
            IF "%~2"=="static" (
                set LinkType=%~2
            ) ELSE IF "%~2"=="shared" (
                set LinkType=%~2
            ) ELSE (
                echo "Error reading build type %2"
                set LinkType="shared"
            )
            SHIFT & SHIFT
            GOTO parseArgumentsLoop
        ) ELSE IF "%~1"=="--binName" (
            IF "%~2"=="" (
                echo "Error reading target binary name %2"
                exit /b 1
            )
            set TargetFileName=%~2
            SHIFT & SHIFT
            GOTO parseArgumentsLoop
        ) ELSE IF "%~1"=="--binType" (
            IF "%~2"=="lib" (
                set BinType=%~2
            ) ELSE IF "%~2"=="app" (
                set BinType=%~2
            ) ELSE (
                echo "Error reading build directory path %2"
                exit /b 1
            )
            set BinType=%~2
            SHIFT & SHIFT
            GOTO parseArgumentsLoop
        )
        ELSE (
            echo "Error: Invalid argument %1"
            exit /b 1
        )
    :parseArgumentsLoopEnd

    IF "%LinkType%"=="static" (
        set TargetDir=%BAT_DIR%..\..\bin_win32_static
    ) ELSE (
        set TargetDir=%BAT_DIR%..\..\bin_win32
    )

exit /b 0


:cleanDirPathStr
    set inStr=%~1
    ::for /f "delims=" %%F in ("%inStr%") do set "inStr=%%~dpF"
    :checkPathStr
    IF "%inStr:~-1%"=="\" (
        set inStr=%inStr:~0,-1%
        goto checkPathStr
    )

exit /b 0

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: copyFiles() - copies target files matching input-name into bin

:copyFiles
    call:cleanDirPathStr "%TargetDir%"
    set TargetDir=%inStr%
    call:cleanDirPathStr "%SourceDir%"
    set SourceDir=%inStr%

    set targetBinPath=%TargetDir%\
    set sourceBuildPath=%SourceDir%\%TargetFileName%

    if "%BinType%"=="lib" (
        if "%LinkType%"=="static" (
            set exts=lib
        ) else (
            set exts=lib dll exp def
        )
    ) else (
        set exts=exe
    )
    echo Copying file with extensions: %exts%
    for %%i in (%exts%) do (
        echo XCOPY /Y "%sourceBuildPath%.%%i" "%targetBinPath%"
        XCOPY /Y "%sourceBuildPath%.%%i" "%targetBinPath%" 1>NUL 2>&1
        if errorlevel 1 (
            echo Failed copying %TargetFileName% files
        REM TODO: Temp until I can figure out if libName.def files are getting made.
        REM    exit /b %errorlevel%
        )
    )

exit /b 0


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: MAIN() - main entry point, called first

:MAIN

echo Received arguments: "%*"

::Parse arguments
call:parseArguments %* & IF ERRORLEVEL 1 goto:end %errorlevel%
call:printLocalEnvs
call:copyFiles & IF ERRORLEVEL 1 goto:end %errorlevel%

goto:EOF

