@echo off
setlocal enabledelayedexpansion

REM install_trustedge.bat - Windows equivalent of install_trustedge.sh
REM Installs TrustEdge MSI package with upgrade, rollback, and service management

REM === Configuration ===
set "TRUSTEDGE=trustedge"
set "BACKUP_DIR=%ProgramData%\DigiCert\TrustEdge\backup"
set "ARTIFACT_DIR=%ProgramData%\DigiCert\TrustEdge\conf\artifacts"
set "SVC=DigiCertTrustEdge"
set "INSTALL_DIR=%ProgramFiles%\DigiCert\TrustEdge"
set "IS_NEW_MSI_LATEST_VERSION=0"
set "ARTIFACT_STATUS=Failed"
set "IS_DOWNGRADE_ALLOWED=0"
set "OLD_INSTALLED_VERSION="
set "BACKUP_FILE_VERSION="
set "NEW_MSI_VERSION="
set "NEW_MSI_FILE="
set "OLD_MSI_FILE="
set "ARTIFACT_ID="
set "ARTIFACT_FILE="
set "SLEEP_TIME=5"
set "SERVICE_MODE=FALSE"
set "TE_DEBUG=0"

REM === Parse command line arguments ===
:parse_args
if "%~1"=="" goto :after_parse
if /i "%~1"=="--help" goto :show_usage
if /i "%~1"=="--msi" (
    set "NEW_MSI_FILE=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--aId" (
    set "ARTIFACT_ID=%~2"
    set "ARTIFACT_FILE=%ARTIFACT_DIR%\%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--debug" (
    set "TE_DEBUG=1"
    shift
    goto :parse_args
)
if /i "%~1"=="--service" (
    set "SERVICE_MODE=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--allow_downgrade" (
    set "IS_DOWNGRADE_ALLOWED=1"
    shift
    goto :parse_args
)
echo Invalid option: %~1
goto :show_usage

:after_parse

REM === Normalize path separators (convert / to \) ===
if defined NEW_MSI_FILE set "NEW_MSI_FILE=%NEW_MSI_FILE:/=\%"

REM === Auto-discover MSI if not provided ===
if "%NEW_MSI_FILE%"=="" (
    for %%f in (*.msi) do set "NEW_MSI_FILE=%%f"
)
if "%NEW_MSI_FILE%"=="" (
    for %%f in (package\*.msi) do set "NEW_MSI_FILE=%%f"
)
if "%NEW_MSI_FILE%"=="" (
    for %%f in (payload\package\*.msi) do set "NEW_MSI_FILE=%%f"
)

REM === Validate MSI file ===
if "%NEW_MSI_FILE%"=="" (
    echo ERROR: No MSI file specified and none found automatically.
    goto :show_usage
)
if not exist "%NEW_MSI_FILE%" (
    echo ERROR: MSI file not found: %NEW_MSI_FILE%
    exit /b 1
)

REM === Main execution flow ===
call :check_admin
if %errorlevel% neq 0 goto :cleanup_exit_error
call :check_sc_command
if %errorlevel% neq 0 goto :cleanup_exit_error
call :print_service_status
call :get_new_msi_version
if %errorlevel% neq 0 goto :cleanup_exit_error
call :check_new_msi_package
call :check_memory_avbl
call :check_dependency
call :get_installed_version
call :get_backup_version
call :dump_version_info
call :verify_installed_health
call :check_new_msi_installation_allowed
if %errorlevel% neq 0 goto :cleanup_exit_error
call :package_installation

goto :cleanup_exit

REM === Functions ===

:dbg_msg
if "%TE_DEBUG%"=="1" echo DEBUG: %~1
goto :eof

:show_usage
echo Usage: %~nx0 [options]
echo Options:
echo   --help                 - Show help options
echo   --msi ^<trustedge.msi^>  - TrustEdge MSI installer file
echo   --allow_downgrade      - Allow TrustEdge to downgrade to older version
echo   --service ^<TRUE/FALSE^> - When TRUE stop/start service
echo   --aId ^<artifactId^>     - Artifact ID for status tracking
echo   --debug                - Enable debug output
exit /b 1

:check_admin
REM Check for admin by attempting to access a protected location
>nul 2>&1 "%SystemRoot%\System32\cacls.exe" "%SystemRoot%\System32\config\system"
if %errorlevel% neq 0 (
    echo ERROR: This script requires Administrator privileges.
    echo Please run as Administrator.
    exit /b 1
)
goto :eof

:check_sc_command
if /i "%SERVICE_MODE%"=="TRUE" (
    where sc >nul 2>&1
    if errorlevel 1 (
        echo sc command does not exist
        exit /b 1
    ) else (
        echo sc command exist
    )
)
goto :eof

:check_new_msi_package
echo TODO: Perform health check on new trustedge binary
goto :eof

:check_memory_avbl
echo Add check to ensure enough memory is available
goto :eof

:check_dependency
echo Add check to ensure dependencies are already installed
goto :eof

:start_service
if /i "%SERVICE_MODE%"=="TRUE" (
    call :dbg_msg "Starting %SVC% service"
    sc start %SVC% >nul 2>&1
)
goto :eof

:stop_service
if /i "%SERVICE_MODE%"=="TRUE" (
    call :dbg_msg "Stopping %SVC% service"
    sc stop %SVC% >nul 2>&1
    REM Wait for service to stop
    timeout /t 3 /nobreak >nul 2>&1
)
goto :eof

:print_service_status
sc query %SVC% >nul 2>&1
if %errorlevel%==0 (
    for /f "tokens=3" %%s in ('sc query %SVC% ^| findstr /i "STATE"') do (
        if "%%s"=="4" (
            call :dbg_msg "%SVC% is running"
        ) else (
            call :dbg_msg "%SVC% is not running"
        )
    )
) else (
    call :dbg_msg "%SVC% is not installed"
)
REM Reset errorlevel - service not existing is not a failure
cmd /c "exit /b 0"
goto :eof

:get_installed_version
REM Check if TrustEdge is installed via registry
REM Note: reg query /f only returns matching values, not all values in the key
REM So we first find the registry key, then query it directly for DisplayVersion
set "OLD_INSTALLED_VERSION="
set "TRUSTEDGE_REGKEY="

REM Find the registry key containing DigiCert TrustEdge
for /f "tokens=*" %%k in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "DigiCert TrustEdge" 2^>nul ^| findstr /i "HKEY_LOCAL_MACHINE"') do (
    set "TRUSTEDGE_REGKEY=%%k"
)
if defined TRUSTEDGE_REGKEY (
    REM Query the specific key for DisplayVersion
    for /f "tokens=2*" %%a in ('reg query "!TRUSTEDGE_REGKEY!" /v DisplayVersion 2^>nul ^| findstr /i "DisplayVersion"') do (
        set "OLD_INSTALLED_VERSION=%%b"
    )
)

if "%OLD_INSTALLED_VERSION%"=="" (
    REM Try WOW6432Node for 32-bit apps on 64-bit Windows
    set "TRUSTEDGE_REGKEY="
    for /f "tokens=*" %%k in ('reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "DigiCert TrustEdge" 2^>nul ^| findstr /i "HKEY_LOCAL_MACHINE"') do (
        set "TRUSTEDGE_REGKEY=%%k"
    )
    if defined TRUSTEDGE_REGKEY (
        for /f "tokens=2*" %%a in ('reg query "!TRUSTEDGE_REGKEY!" /v DisplayVersion 2^>nul ^| findstr /i "DisplayVersion"') do (
            set "OLD_INSTALLED_VERSION=%%b"
        )
    )
)
if "%OLD_INSTALLED_VERSION%"=="" (
    call :dbg_msg "TrustEdge is currently not installed."
) else (
    call :dbg_msg "Installed version: %OLD_INSTALLED_VERSION%"
    REM Verify installation health
    if exist "%INSTALL_DIR%\bin\trustedge.exe" (
        "%INSTALL_DIR%\bin\trustedge.exe" --version >nul 2>&1
        if errorlevel 1 (
            echo ERROR: Existing TrustEdge installation is corrupted.
            exit /b 1
        )
    )
)
goto :eof

:get_backup_version
set "OLD_MSI_FILE="
set "BACKUP_FILE_VERSION="
if exist "%BACKUP_DIR%" (
    for %%f in ("%BACKUP_DIR%\trustedge_*.msi") do (
        if defined OLD_MSI_FILE (
            echo ERROR: Multiple backup MSI files found in %BACKUP_DIR%
            exit /b 1
        )
        set "OLD_MSI_FILE=%%f"
    )
    if defined OLD_MSI_FILE (
        REM Extract version from backup MSI filename (trustedge_X.Y.Z.x86_64.msi)
        for %%f in ("!OLD_MSI_FILE!") do set "BACKUP_FILENAME=%%~nf"
        REM BACKUP_FILENAME is like "trustedge_2.0.0.x86_64"
        set "TEMP_BACKUP_VER=!BACKUP_FILENAME:trustedge_=!"
        REM Extract just the version (X.Y.Z)
        for /f "tokens=1,2,3 delims=." %%a in ("!TEMP_BACKUP_VER!") do (
            set "BACKUP_FILE_VERSION=%%a.%%b.%%c"
        )
        call :dbg_msg "Backup file version: !BACKUP_FILE_VERSION!"
    ) else (
        call :dbg_msg "No backup file found"
    )
) else (
    call :dbg_msg "%BACKUP_DIR% does not exist."
)
goto :eof

:get_new_msi_version
REM Extract version from MSI filename (trustedge_X.Y.Z.x86_64.msi)
REM First get filename without extension, then extract version between first _ and .x86 or next _
for %%f in ("%NEW_MSI_FILE%") do set "MSI_FILENAME=%%~nf"
REM MSI_FILENAME is now like "trustedge_2.0.0.x86_64"
REM Extract everything after "trustedge_" and before ".x86" or "_x86"
set "TEMP_VER=%MSI_FILENAME:trustedge_=%"
REM TEMP_VER is now like "2.0.0.x86_64" - extract just the version (X.Y.Z)
for /f "tokens=1,2,3 delims=." %%a in ("%TEMP_VER%") do (
    set "NEW_MSI_VERSION=%%a.%%b.%%c"
)
if "%NEW_MSI_VERSION%"=="" (
    echo ERROR: Could not extract version from MSI filename: %NEW_MSI_FILE%
    exit /b 1
)
call :dbg_msg "New MSI version: %NEW_MSI_VERSION%"
goto :eof

:dump_version_info
call :dbg_msg "Old installed version    : %OLD_INSTALLED_VERSION%"
call :dbg_msg "Backup MSI file name     : %OLD_MSI_FILE%"
call :dbg_msg "Backup MSI file version  : %BACKUP_FILE_VERSION%"
call :dbg_msg "New MSI file name        : %NEW_MSI_FILE%"
call :dbg_msg "New MSI version          : %NEW_MSI_VERSION%"
call :dbg_msg "Service mode             : %SERVICE_MODE%"
goto :eof

:verify_installed_health
if "%OLD_INSTALLED_VERSION%"=="" goto :eof
if "%BACKUP_FILE_VERSION%"=="" goto :eof
if "%OLD_INSTALLED_VERSION%"=="%BACKUP_FILE_VERSION%" (
    call :dbg_msg "Installed version matches backup version. Proceeding..."
) else (
    call :dbg_msg "Old installed version '%OLD_INSTALLED_VERSION%' and backup file version '%BACKUP_FILE_VERSION%' are not matching."
    call :dbg_msg "Exiting installation.."
    exit /b 1
)
goto :eof

:compare_versions
REM Compare two versions (ver1, ver2) - sets IS_NEW_MSI_LATEST_VERSION=1 if ver1 > ver2
set "ver1=%~1"
set "ver2=%~2"
set "IS_NEW_MSI_LATEST_VERSION=0"

REM Parse version components
for /f "tokens=1-4 delims=.-" %%a in ("%ver1%") do (
    set /a "major1=%%a" 2>nul
    set /a "minor1=%%b" 2>nul
    set /a "patch1=%%c" 2>nul
    set /a "build1=%%d" 2>nul
)
for /f "tokens=1-4 delims=.-" %%a in ("%ver2%") do (
    set /a "major2=%%a" 2>nul
    set /a "minor2=%%b" 2>nul
    set /a "patch2=%%c" 2>nul
    set /a "build2=%%d" 2>nul
)

REM Default to 0 if not set
if not defined major1 set /a major1=0
if not defined minor1 set /a minor1=0
if not defined patch1 set /a patch1=0
if not defined build1 set /a build1=0
if not defined major2 set /a major2=0
if not defined minor2 set /a minor2=0
if not defined patch2 set /a patch2=0
if not defined build2 set /a build2=0

if %major1% gtr %major2% set "IS_NEW_MSI_LATEST_VERSION=1" & goto :eof
if %major1% lss %major2% goto :eof
if %minor1% gtr %minor2% set "IS_NEW_MSI_LATEST_VERSION=1" & goto :eof
if %minor1% lss %minor2% goto :eof
if %patch1% gtr %patch2% set "IS_NEW_MSI_LATEST_VERSION=1" & goto :eof
if %patch1% lss %patch2% goto :eof
if %build1% gtr %build2% set "IS_NEW_MSI_LATEST_VERSION=1" & goto :eof
goto :eof

:check_new_msi_installation_allowed
if "%OLD_INSTALLED_VERSION%"=="" goto :eof
if "%IS_DOWNGRADE_ALLOWED%"=="1" goto :eof
call :compare_versions "%NEW_MSI_VERSION%" "%OLD_INSTALLED_VERSION%"
if "%IS_NEW_MSI_LATEST_VERSION%"=="1" (
    call :dbg_msg "MSI file has latest version: %NEW_MSI_VERSION%"
    REM Reset errorlevel to 0 after successful version check
    cmd /c "exit /b 0"
) else (
    echo ERROR: New version ^(%NEW_MSI_VERSION%^) is not newer than installed ^(%OLD_INSTALLED_VERSION%^).
    echo Use --allow_downgrade to force installation.
    cmd /c "exit /b 1"
)
goto :eof

:take_backup
if not exist "%BACKUP_DIR%" (
    mkdir "%BACKUP_DIR%" 2>nul
)
if exist "%BACKUP_DIR%\*.msi" (
    REM Move old backups to backup_1
    if exist "%BACKUP_DIR%_1" rd /s /q "%BACKUP_DIR%_1"
    move "%BACKUP_DIR%" "%BACKUP_DIR%_1" >nul 2>&1
    mkdir "%BACKUP_DIR%" 2>nul
)
copy /y "%NEW_MSI_FILE%" "%BACKUP_DIR%\" >nul
if errorlevel 1 (
    echo ERROR: Failed to backup MSI file.
    exit /b 1
)
call :dbg_msg "MSI file backed up to %BACKUP_DIR%"
goto :eof

:rollback
REM Update artifact status to Failed before rollback (so new service sees correct status)
set "ARTIFACT_STATUS=Failed"
call :update_artifact_status
echo Performing rollback to %OLD_INSTALLED_VERSION%...
if exist "%OLD_MSI_FILE%" (
    msiexec /i "%OLD_MSI_FILE%" /quiet /norestart
    if errorlevel 1 (
        echo ERROR: Rollback failed.
        exit /b 1
    )
    call :dbg_msg "Rollback successful."
    call :start_service
) else (
    echo ERROR: No backup MSI available for rollback.
)
exit /b 1

:post_install_health_check
REM Verify the installed version matches expected
call :get_installed_version
if not "%OLD_INSTALLED_VERSION%"=="%NEW_MSI_VERSION%" (
    echo ERROR: Installed version mismatch after installation.
    call :rollback
)
REM Verify binary works
if exist "%INSTALL_DIR%\bin\trustedge.exe" (
    "%INSTALL_DIR%\bin\trustedge.exe" --version >nul 2>&1
    if errorlevel 1 (
        echo ERROR: TrustEdge binary health check failed.
        call :rollback
    )
)
call :dbg_msg "Post-install health check passed."
goto :eof

:post_service_health_check
if /i not "%SERVICE_MODE%"=="TRUE" goto :eof
call :start_service
call :dbg_msg "Waiting %SLEEP_TIME% seconds for service to stabilize..."
timeout /t %SLEEP_TIME% /nobreak >nul
sc query %SVC% | findstr /i "RUNNING" >nul
if errorlevel 1 (
    echo ERROR: Service failed to start after installation.
    call :rollback
)
call :dbg_msg "Service is running."
goto :eof

:package_installation
echo Installing TrustEdge MSI: %NEW_MSI_FILE%

REM Fresh installation
if "%OLD_INSTALLED_VERSION%"=="" (
    call :dbg_msg "Performing fresh installation..."
    msiexec /i "%NEW_MSI_FILE%" /quiet /norestart /l*v "%TEMP%\trustedge_install.log"
    if errorlevel 1 (
        echo ERROR: Fresh installation failed. See %TEMP%\trustedge_install.log
        exit /b 1
    )
    call :post_install_health_check
    call :take_backup
    echo Installation completed successfully.
    goto :eof
)

REM Upgrade installation
call :dbg_msg "Performing upgrade installation..."
call :print_service_status
call :stop_service
REM Set Success BEFORE msiexec - Restart Manager may auto-start service during install
set "ARTIFACT_STATUS=Success"
call :update_artifact_status
msiexec /i "%NEW_MSI_FILE%" /quiet /norestart /l*v "%TEMP%\trustedge_install.log"
if errorlevel 1 (
    echo ERROR: Upgrade installation failed. See %TEMP%\trustedge_install.log
    call :rollback
)
call :post_install_health_check
call :post_service_health_check
call :take_backup
echo Upgrade completed successfully.
goto :eof

:update_artifact_status
if "%ARTIFACT_FILE%"=="" goto :eof
if not exist "%ARTIFACT_FILE%" goto :eof
REM Update status in JSON file using PowerShell with ConvertFrom-Json (cleaner than regex)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$f='%ARTIFACT_FILE%'; $s='%ARTIFACT_STATUS%'; " ^
    "$json = Get-Content $f -Raw | ConvertFrom-Json; " ^
    "$json.status = $s; " ^
    "$json.timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'); " ^
    "$json | ConvertTo-Json | Set-Content $f -NoNewline"
goto :eof

:cleanup_exit_error
set "ARTIFACT_STATUS=Failed"

:cleanup_exit
call :update_artifact_status
call :dbg_msg "Exiting with status %ARTIFACT_STATUS%"
endlocal
if "%ARTIFACT_STATUS%"=="Success" (exit /b 0) else (exit /b 1)
