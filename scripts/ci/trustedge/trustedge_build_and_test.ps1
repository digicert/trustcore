#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Builds multiple TrustEdge versions and runs install/upgrade/downgrade tests.

.DESCRIPTION
    This script:
    1. Builds three versions of TrustEdge (old, current, new)
    2. Runs fullclean to ensure clean environment
    3. Executes all install/upgrade/downgrade tests
    4. Reports results

.PARAMETER OldVersion
    Version string for the "old" build (default: 1.9.0)

.PARAMETER CurrentVersion
    Version string for the "current" build (default: 2.0.0)

.PARAMETER NewVersion
    Version string for the "new" build (default: 2.1.0)

.PARAMETER SkipBuild
    Skip the build step and use existing MSIs from OutputDir.

.PARAMETER StopOnFailure
    Stop execution on first test failure and preserve the system state for debugging.
    Does not run cleanup/uninstall so you can examine why the test failed.

.PARAMETER OutputDir
    Directory for build outputs (default: .\test_builds)

.PARAMETER VsVersion
    Visual Studio version year (default: 2022)

.EXAMPLE
    .\trustedge_build_and_test.ps1
    Builds all three versions and runs tests.

.EXAMPLE
    .\trustedge_build_and_test.ps1 -OldVersion "1.8.0" -CurrentVersion "1.9.0" -NewVersion "2.0.0"
    Builds with custom version numbers.

.EXAMPLE
    .\trustedge_build_and_test.ps1 -SkipBuild -OutputDir "C:\builds"
    Skips building and uses existing MSIs from C:\builds.

.NOTES
    Must be run as Administrator.
    Requires Visual Studio with C++ and CMake support.
    Requires WiX Toolset v3.14 installed and in PATH.
    Author: DigiCert
#>

param(
    [string]$OldVersion = "1.9.0",
    [string]$CurrentVersion = "2.0.0",
    [string]$NewVersion = "2.1.0",
    [switch]$SkipBuild,
    [switch]$StopOnFailure,
    [string]$OutputDir = ".\test_builds",
    [string]$VsVersion = "2022"
)

$ErrorActionPreference = "Stop"

# Paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Get-Item $ScriptDir).Parent.Parent.Parent.FullName
$BuildScript = Join-Path $RepoRoot "scripts\ci\trustedge\ci_trustedge_build.bat"
$TestScript = Join-Path $ScriptDir "test_update\windows\trustedge_test.ps1"
$FullCleanScript = Join-Path $ScriptDir "test_update\windows\trustedge_fullclean.ps1"

# Build output paths
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
$OldMsiDir = Join-Path $OutputDir "old"
$CurrentMsiDir = Join-Path $OutputDir "current"
$NewMsiDir = Join-Path $OutputDir "new"

function Write-Header {
    param([string]$Text)
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Find-VsVarsAll {
    # Common Visual Studio paths
    $vsPaths = @(
        "C:\Program Files\Microsoft Visual Studio\$VsVersion\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
        "C:\Program Files\Microsoft Visual Studio\$VsVersion\Professional\VC\Auxiliary\Build\vcvarsall.bat",
        "C:\Program Files\Microsoft Visual Studio\$VsVersion\Community\VC\Auxiliary\Build\vcvarsall.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\$VsVersion\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\$VsVersion\Professional\VC\Auxiliary\Build\vcvarsall.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\$VsVersion\Community\VC\Auxiliary\Build\vcvarsall.bat"
    )
    
    foreach ($path in $vsPaths) {
        if (Test-Path $path) {
            return $path
        }
    }
    
    # Try vswhere
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -property installationPath
        if ($vsPath) {
            $vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"
            if (Test-Path $vcvars) {
                return $vcvars
            }
        }
    }
    
    return $null
}

function Invoke-TrustEdgeBuild {
    param(
        [string]$Version,
        [string]$OutputDirectory
    )
    
    Write-Host "`nBuilding TrustEdge version $Version..." -ForegroundColor Yellow
    Write-Host "Output directory: $OutputDirectory" -ForegroundColor Gray
    
    # Create output directory
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    
    # Find vcvarsall.bat
    $vcvarsall = Find-VsVarsAll
    if (-not $vcvarsall) {
        throw "Could not find vcvarsall.bat. Ensure Visual Studio $VsVersion is installed."
    }
    
    # Create a batch file to set up environment and build
    $tempBatch = Join-Path $env:TEMP "trustedge_build_$Version.bat"
    
    @"
@echo off
call "$vcvarsall" x64
if errorlevel 1 exit /b 1

cd /d "$RepoRoot"
if errorlevel 1 exit /b 1

call "$BuildScript" --version-string $Version --monolithic --package --tpm2 --cvc --proxy --pqc --pqc-composite --enable-pc
if errorlevel 1 exit /b 1

REM Copy MSI to output directory
copy /y "dist\trustedge_*.msi" "$OutputDirectory\"
if errorlevel 1 exit /b 1

echo Build completed successfully
exit /b 0
"@ | Set-Content -Path $tempBatch -Encoding ASCII
    
    Write-Host "Running build script..." -ForegroundColor Gray
    
    # Use cmd /c directly to avoid hanging
    Push-Location $RepoRoot
    try {
        & cmd.exe /c "`"$tempBatch`""
        $exitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    
    Remove-Item $tempBatch -Force -ErrorAction SilentlyContinue
    
    if ($exitCode -ne 0) {
        throw "Build failed for version $Version with exit code $exitCode"
    }
    
    # Verify MSI was created
    $msiFiles = Get-ChildItem -Path $OutputDirectory -Filter "trustedge_*.msi" -ErrorAction SilentlyContinue
    if (-not $msiFiles) {
        throw "No MSI file found in $OutputDirectory after build"
    }
    
    Write-Host "Build successful: $($msiFiles[0].Name)" -ForegroundColor Green
    return $msiFiles[0].FullName
}

function Find-MsiInDirectory {
    param([string]$Directory)
    
    if (-not (Test-Path $Directory)) {
        return $null
    }
    
    $msiFiles = Get-ChildItem -Path $Directory -Filter "trustedge_*.msi" -ErrorAction SilentlyContinue
    if ($msiFiles) {
        return $msiFiles[0].FullName
    }
    return $null
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host @"

╔══════════════════════════════════════════════════════════════════════╗
║       TrustEdge Build and Test Automation Script                     ║
╚══════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Old Version:     $OldVersion"
Write-Host "  Current Version: $CurrentVersion"
Write-Host "  New Version:     $NewVersion"
Write-Host "  Output Dir:      $OutputDir"
Write-Host "  Skip Build:      $SkipBuild"
Write-Host "  Repo Root:       $RepoRoot"

# Verify prerequisites
if (-not (Test-Path $BuildScript)) {
    Write-Host "ERROR: Build script not found: $BuildScript" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $TestScript)) {
    Write-Host "ERROR: Test script not found: $TestScript" -ForegroundColor Red
    exit 1
}

# Check WiX is in PATH
$wixCandle = Get-Command "candle.exe" -ErrorAction SilentlyContinue
if (-not $wixCandle) {
    Write-Host "WARNING: WiX Toolset not found in PATH. Build may fail." -ForegroundColor Yellow
    Write-Host "         Ensure C:\Program Files (x86)\WiX Toolset v3.14\bin is in PATH" -ForegroundColor Yellow
}

$OldMsi = $null
$CurrentMsi = $null
$NewMsi = $null

if ($SkipBuild) {
    Write-Header "Using Existing MSI Files"
    
    $OldMsi = Find-MsiInDirectory -Directory $OldMsiDir
    $CurrentMsi = Find-MsiInDirectory -Directory $CurrentMsiDir
    $NewMsi = Find-MsiInDirectory -Directory $NewMsiDir
    
    if (-not $OldMsi) {
        Write-Host "ERROR: Old version MSI not found in $OldMsiDir" -ForegroundColor Red
        exit 1
    }
    if (-not $CurrentMsi) {
        Write-Host "ERROR: Current version MSI not found in $CurrentMsiDir" -ForegroundColor Red
        exit 1
    }
    if (-not $NewMsi) {
        Write-Host "ERROR: New version MSI not found in $NewMsiDir" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Found MSIs:" -ForegroundColor Green
    Write-Host "  Old:     $OldMsi"
    Write-Host "  Current: $CurrentMsi"
    Write-Host "  New:     $NewMsi"
} else {
    # Build all three versions
    Write-Header "Building TrustEdge Versions"
    
    try {
        $OldMsi = Invoke-TrustEdgeBuild -Version $OldVersion -OutputDirectory $OldMsiDir
        $CurrentMsi = Invoke-TrustEdgeBuild -Version $CurrentVersion -OutputDirectory $CurrentMsiDir
        $NewMsi = Invoke-TrustEdgeBuild -Version $NewVersion -OutputDirectory $NewMsiDir
    } catch {
        Write-Host "ERROR: Build failed - $_" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "`nAll builds completed successfully!" -ForegroundColor Green
    Write-Host "  Old:     $OldMsi"
    Write-Host "  Current: $CurrentMsi"
    Write-Host "  New:     $NewMsi"
}

# Run full cleanup before tests
Write-Header "Cleaning Environment"
if (Test-Path $FullCleanScript) {
    & powershell -ExecutionPolicy Bypass -File $FullCleanScript
    Start-Sleep -Seconds 2
} else {
    Write-Host "WARNING: Fullclean script not found, skipping cleanup" -ForegroundColor Yellow
}

# Run tests
Write-Header "Running Installation Tests"

# Ensure paths are strings, not arrays
$CurrentMsiStr = [string]$CurrentMsi
$OldMsiStr = [string]$OldMsi
$NewMsiStr = [string]$NewMsi

Write-Host "Test Configuration:" -ForegroundColor Yellow
Write-Host "  Current MSI: $CurrentMsiStr"
Write-Host "  Old MSI:     $OldMsiStr"
Write-Host "  New MSI:     $NewMsiStr"
Write-Host "  Test Script: $TestScript"

# Run test script directly
Write-Host "`nRunning tests..." -ForegroundColor Cyan
$testExitCode = 0
try {
    $testArgs = @(
        "-TestCase", "All",
        "-MsiPath", $CurrentMsiStr,
        "-OlderMsiPath", $OldMsiStr,
        "-NewerMsiPath", $NewMsiStr
    )
    if ($StopOnFailure) {
        $testArgs += "-StopOnFailure"
    }
    & powershell -ExecutionPolicy Bypass -File $TestScript @testArgs
    $testExitCode = $LASTEXITCODE
} catch {
    Write-Host "ERROR: Test execution failed - $_" -ForegroundColor Red
    $testExitCode = 1
}

# Final cleanup (skip if StopOnFailure was triggered - exit code 1 means test failed and stopped)
if (-not $StopOnFailure -or $testExitCode -eq 0) {
    Write-Header "Final Cleanup"
    if (Test-Path $FullCleanScript) {
        & powershell -ExecutionPolicy Bypass -File $FullCleanScript
    }
} else {
    Write-Host "`nSkipping final cleanup - StopOnFailure mode preserves system state" -ForegroundColor Yellow
}

# Summary
Write-Header "Build and Test Complete"

if ($testExitCode -eq 0) {
    Write-Host "All tests PASSED!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Some tests FAILED!" -ForegroundColor Red
    exit 1
}
