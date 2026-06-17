#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Tests TrustEdge install/uninstall/upgrade flows on Windows.

.DESCRIPTION
    Comprehensive test script for TrustEdge MSI installation scenarios:
    1. Fresh installation
    2. Upgrade installation
    3. Downgrade installation (with --allow_downgrade flag)

.PARAMETER MsiPath
    Path to the TrustEdge MSI file for testing. If not specified, looks in current directory.

.PARAMETER OlderMsiPath
    Path to an older version MSI for downgrade testing.

.PARAMETER NewerMsiPath
    Path to a newer version MSI for upgrade testing.

.PARAMETER InstallScript
    Path to install_trustedge.bat. Defaults to projects\trustedge\install_trustedge.bat.

.PARAMETER SkipCleanup
    Skip running fullclean between tests (not recommended for accurate testing).

.PARAMETER StopOnFailure
    Stop execution on first test failure and preserve the system state for debugging.
    TrustEdge installation is left in place so you can examine the system.

.PARAMETER TestCase
    Run specific test case: "Fresh", "Upgrade", "Downgrade", or "All" (default).

.EXAMPLE
    .\trustedge_test.ps1 -MsiPath "C:\builds\trustedge_2.0.0.x86_64.msi"
    Runs all tests with the specified MSI.

.EXAMPLE
    .\trustedge_test.ps1 -TestCase Fresh -MsiPath "C:\builds\trustedge_2.0.0.x86_64.msi"
    Runs only the fresh install test.

.EXAMPLE
    .\trustedge_test.ps1 -MsiPath "C:\builds\trustedge_2.0.0.x86_64.msi" -StopOnFailure
    Runs all tests but stops on first failure, preserving system state for debugging.

.NOTES
    Must be run as Administrator.
    Use trustedge_fullclean.ps1 between manual tests for clean state.
    Author: DigiCert
#>

param(
    [string]$MsiPath,
    [string]$OlderMsiPath,
    [string]$NewerMsiPath,
    [string]$InstallScript,
    [switch]$SkipCleanup,
    [switch]$StopOnFailure,
    [ValidateSet("Fresh", "Upgrade", "Downgrade", "All")]
    [string]$TestCase = "All"
)

$ErrorActionPreference = "Stop"
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestResults = @()
$script:StopOnFailure = $StopOnFailure

# Paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Get-Item $ScriptDir).Parent.Parent.Parent.Parent.Parent.FullName
$FullCleanScript = Join-Path $ScriptDir "trustedge_fullclean.ps1"

if (-not $InstallScript) {
    $InstallScript = Join-Path $RepoRoot "projects\trustedge\install_trustedge.bat"
}

# Service and installation paths
$ServiceName = "DigiCertTrustEdge"
$InstallDir = "$env:ProgramFiles\DigiCert\TrustEdge"
$TrustEdgeExe = "$InstallDir\bin\trustedge.exe"

function Write-TestHeader {
    param([string]$TestName)
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  TEST: $TestName" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Message = ""
    )
    
    $result = @{
        Name = $TestName
        Passed = $Passed
        Message = $Message
    }
    $script:TestResults += $result
    
    if ($Passed) {
        $script:TestsPassed++
        Write-Host "[PASS] $TestName" -ForegroundColor Green
    } else {
        $script:TestsFailed++
        Write-Host "[FAIL] $TestName" -ForegroundColor Red
        if ($Message) {
            Write-Host "       $Message" -ForegroundColor Yellow
        }
        
        if ($script:StopOnFailure) {
            Write-Host "`n" -NoNewline
            Write-Host ("=" * 70) -ForegroundColor Red
            Write-Host "  STOPPED ON FAILURE - System state preserved for debugging" -ForegroundColor Red
            Write-Host ("=" * 70) -ForegroundColor Red
            Write-Host "`nTrustEdge installation left in place for examination." -ForegroundColor Yellow
            Write-Host "Useful diagnostic commands:" -ForegroundColor Yellow
            Write-Host "  Test-Path `"`$env:ProgramFiles\DigiCert\TrustEdge\bin\trustedge.exe`"" -ForegroundColor Gray
            Write-Host "  Get-Service DigiCertTrustEdge" -ForegroundColor Gray
            Write-Host "  Get-ChildItem `"`$env:ProgramFiles\DigiCert`" -Recurse" -ForegroundColor Gray
            Write-Host "  Get-ItemProperty 'HKLM:\SOFTWARE\DigiCert\TrustEdge'" -ForegroundColor Gray
            exit 1
        }
    }
}

function Invoke-FullClean {
    Write-Host "`n--- Running Full Cleanup ---" -ForegroundColor Yellow
    if (Test-Path $FullCleanScript) {
        # Dot-source to run in current elevated session (not a new process)
        . $FullCleanScript
        Start-Sleep -Seconds 2
    } else {
        Write-Host "Warning: fullclean script not found at $FullCleanScript" -ForegroundColor Yellow
    }
}

function Test-TrustEdgeInstalled {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $exeExists = Test-Path $TrustEdgeExe
    return ($service -ne $null) -and $exeExists
}

function Wait-ForTrustEdgeReady {
    param(
        [int]$TimeoutSeconds = 30,
        [int]$PollIntervalSeconds = 2
    )
    
    $elapsed = 0
    Write-Host "Waiting for TrustEdge to be ready..." -ForegroundColor Gray
    
    while ($elapsed -lt $TimeoutSeconds) {
        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
        
        # Check if exe exists
        if (-not (Test-Path $TrustEdgeExe)) {
            Write-Host "  [$elapsed s] Waiting for exe..." -ForegroundColor Gray
            continue
        }
        
        # Check if service exists
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -eq $null) {
            Write-Host "  [$elapsed s] Waiting for service..." -ForegroundColor Gray
            continue
        }
        
        # Check if version is retrievable
        $version = Get-TrustEdgeVersion
        if ($version) {
            Write-Host "  [$elapsed s] TrustEdge ready (version: $version)" -ForegroundColor Green
            return $true
        }
        Write-Host "  [$elapsed s] Waiting for version response..." -ForegroundColor Gray
    }
    
    Write-Host "  Timeout after $TimeoutSeconds seconds" -ForegroundColor Yellow
    return $false
}

function Get-TrustEdgeVersion {
    if (Test-Path $TrustEdgeExe) {
        try {
            $output = & $TrustEdgeExe --version 2>&1
            # Convert array output to single string for reliable regex matching
            $outputStr = ($output | Out-String) -join ""
            if ($outputStr -match "(\d+\.\d+\.\d+)") {
                return $matches[1]
            }
        } catch {
            # Ignore errors
        }
    }
    return $null
}

function Get-MsiVersion {
    param([string]$MsiFile)
    
    if (-not (Test-Path $MsiFile)) {
        return $null
    }
    
    # Extract version from filename (trustedge_X.Y.Z.x86_64.msi or trustedge_X.Y.Z.msi)
    if ($MsiFile -match "trustedge_(\d+\.\d+\.\d+)[\.\-_x]") {
        return $matches[1]
    }
    # Fallback: just get digits after trustedge_
    if ($MsiFile -match "trustedge_(\d+\.\d+\.\d+)") {
        return $matches[1]
    }
    
    return $null
}

function Invoke-InstallScript {
    param(
        [string]$MsiFile,
        [switch]$AllowDowngrade,
        [switch]$Debug
    )
    
    $msiDir = Split-Path $MsiFile -Parent
    $argList = "--msi `"$MsiFile`""
    if ($AllowDowngrade) {
        $argList += " --allow_downgrade"
    }
    if ($Debug) {
        $argList += " --debug"
    }
    
    Write-Host "Running: $InstallScript $argList" -ForegroundColor Gray
    Write-Host "Working Directory: $msiDir" -ForegroundColor Gray
    
    # Create temp batch to run and capture exit code
    $tempBatch = Join-Path $env:TEMP "trustedge_install_test.bat"
    @"
@echo off
cd /d "$msiDir"
call "$InstallScript" $argList
exit /b %ERRORLEVEL%
"@ | Set-Content -Path $tempBatch -Encoding ASCII
    
    $process = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c `"$tempBatch`"" `
        -Wait -PassThru
    
    $exitCode = $process.ExitCode
    Remove-Item $tempBatch -Force -ErrorAction SilentlyContinue
    
    return $exitCode
}

# ============================================================================
# Test Case 1: Fresh Installation
# ============================================================================
function Test-FreshInstall {
    param([string]$MsiFile)
    
    Write-TestHeader "Fresh Installation"
    
    if (-not (Test-Path $MsiFile)) {
        Write-TestResult "Fresh Install" $false "MSI file not found: $MsiFile"
        return
    }
    
    # Ensure clean state
    if (-not $SkipCleanup) {
        Invoke-FullClean
    }
    
    # Verify TrustEdge is not installed
    if (Test-TrustEdgeInstalled) {
        Write-TestResult "Fresh Install - Pre-check" $false "TrustEdge is still installed after cleanup"
        return
    }
    Write-Host "Pre-check: TrustEdge not installed (expected)" -ForegroundColor Green
    
    # Run installation
    Write-Host "Installing TrustEdge..." -ForegroundColor Cyan
    $exitCode = Invoke-InstallScript -MsiFile $MsiFile -Debug
    
    if ($exitCode -ne 0) {
        Write-TestResult "Fresh Install" $false "Installation script returned exit code $exitCode"
        return
    }
    
    # Wait for installation to be fully ready
    if (-not (Wait-ForTrustEdgeReady -TimeoutSeconds 30)) {
        Write-TestResult "Fresh Install" $false "TrustEdge not ready after installation (timeout)"
        return
    }
    
    $version = Get-TrustEdgeVersion
    $expectedVersion = Get-MsiVersion -MsiFile $MsiFile
    
    if ($version -ne $expectedVersion) {
        Write-TestResult "Fresh Install" $false "Version mismatch: expected $expectedVersion, got $version"
        return
    }
    
    Write-TestResult "Fresh Install" $true "Installed version $version successfully"
}

# ============================================================================
# Test Case 2: Upgrade Installation
# ============================================================================
function Test-UpgradeInstall {
    param(
        [string]$OlderMsi,
        [string]$NewerMsi
    )
    
    Write-TestHeader "Upgrade Installation"
    
    if (-not (Test-Path $OlderMsi)) {
        Write-TestResult "Upgrade Install" $false "Older MSI file not found: $OlderMsi"
        return
    }
    if (-not (Test-Path $NewerMsi)) {
        Write-TestResult "Upgrade Install" $false "Newer MSI file not found: $NewerMsi"
        return
    }
    
    $olderVersion = Get-MsiVersion -MsiFile $OlderMsi
    $newerVersion = Get-MsiVersion -MsiFile $NewerMsi
    
    Write-Host "Testing upgrade from $olderVersion to $newerVersion" -ForegroundColor Cyan
    
    # Ensure clean state
    if (-not $SkipCleanup) {
        Invoke-FullClean
    }
    
    # Step 1: Install older version
    Write-Host "`n--- Step 1: Installing older version ($olderVersion) ---" -ForegroundColor Yellow
    $exitCode = Invoke-InstallScript -MsiFile $OlderMsi -Debug
    
    if ($exitCode -ne 0) {
        Write-TestResult "Upgrade Install - Initial Install" $false "Failed to install older version"
        return
    }
    
    if (-not (Wait-ForTrustEdgeReady -TimeoutSeconds 30)) {
        Write-TestResult "Upgrade Install - Initial Install" $false "TrustEdge not ready after initial install (timeout)"
        return
    }
    $currentVersion = Get-TrustEdgeVersion
    if ($currentVersion -ne $olderVersion) {
        Write-TestResult "Upgrade Install - Initial Install" $false "Version mismatch after initial install: expected $olderVersion, got $currentVersion"
        return
    }
    Write-Host "Initial install successful: version $currentVersion" -ForegroundColor Green
    
    # Step 2: Upgrade to newer version
    Write-Host "`n--- Step 2: Upgrading to newer version ($newerVersion) ---" -ForegroundColor Yellow
    $exitCode = Invoke-InstallScript -MsiFile $NewerMsi -Debug
    
    if ($exitCode -ne 0) {
        Write-TestResult "Upgrade Install" $false "Upgrade script returned exit code $exitCode"
        return
    }
    
    if (-not (Wait-ForTrustEdgeReady -TimeoutSeconds 30)) {
        Write-TestResult "Upgrade Install" $false "TrustEdge not ready after upgrade (timeout)"
        return
    }
    $finalVersion = Get-TrustEdgeVersion
    
    if ($finalVersion -ne $newerVersion) {
        Write-TestResult "Upgrade Install" $false "Version mismatch after upgrade: expected $newerVersion, got $finalVersion"
        return
    }
    
    Write-TestResult "Upgrade Install" $true "Successfully upgraded from $olderVersion to $newerVersion"
}

# ============================================================================
# Test Case 3: Downgrade Installation
# ============================================================================
function Test-DowngradeInstall {
    param(
        [string]$NewerMsi,
        [string]$OlderMsi
    )
    
    Write-TestHeader "Downgrade Installation"
    
    if (-not (Test-Path $NewerMsi)) {
        Write-TestResult "Downgrade Install" $false "Newer MSI file not found: $NewerMsi"
        return
    }
    if (-not (Test-Path $OlderMsi)) {
        Write-TestResult "Downgrade Install" $false "Older MSI file not found: $OlderMsi"
        return
    }
    
    $newerVersion = Get-MsiVersion -MsiFile $NewerMsi
    $olderVersion = Get-MsiVersion -MsiFile $OlderMsi
    
    Write-Host "Testing downgrade from $newerVersion to $olderVersion" -ForegroundColor Cyan
    
    # Ensure clean state
    if (-not $SkipCleanup) {
        Invoke-FullClean
    }
    
    # Step 1: Install newer version
    Write-Host "`n--- Step 1: Installing newer version ($newerVersion) ---" -ForegroundColor Yellow
    $exitCode = Invoke-InstallScript -MsiFile $NewerMsi -Debug
    
    if ($exitCode -ne 0) {
        Write-TestResult "Downgrade Install - Initial Install" $false "Failed to install newer version"
        return
    }
    
    if (-not (Wait-ForTrustEdgeReady -TimeoutSeconds 30)) {
        Write-TestResult "Downgrade Install - Initial Install" $false "TrustEdge not ready after initial install (timeout)"
        return
    }
    $currentVersion = Get-TrustEdgeVersion
    if ($currentVersion -ne $newerVersion) {
        Write-TestResult "Downgrade Install - Initial Install" $false "Version mismatch after initial install: expected $newerVersion, got $currentVersion"
        return
    }
    Write-Host "Initial install successful: version $currentVersion" -ForegroundColor Green
    
    # Step 2: Attempt downgrade WITHOUT flag (should fail or be blocked)
    Write-Host "`n--- Step 2: Attempting downgrade WITHOUT --allow_downgrade ---" -ForegroundColor Yellow
    $exitCode = Invoke-InstallScript -MsiFile $OlderMsi -Debug
    
    # Check if downgrade was blocked (expected behavior)
    Start-Sleep -Seconds 2
    $versionAfterBlockedDowngrade = Get-TrustEdgeVersion
    if ($versionAfterBlockedDowngrade -eq $newerVersion) {
        Write-Host "Downgrade correctly blocked without --allow_downgrade flag" -ForegroundColor Green
    } else {
        Write-Host "Warning: Downgrade was not blocked (may be expected with AllowDowngrades in WiX)" -ForegroundColor Yellow
    }
    
    # Step 3: Downgrade with --allow_downgrade flag
    Write-Host "`n--- Step 3: Downgrading with --allow_downgrade flag ---" -ForegroundColor Yellow
    $exitCode = Invoke-InstallScript -MsiFile $OlderMsi -AllowDowngrade -Debug
    
    if ($exitCode -ne 0) {
        Write-TestResult "Downgrade Install" $false "Downgrade script returned exit code $exitCode"
        return
    }
    
    if (-not (Wait-ForTrustEdgeReady -TimeoutSeconds 30)) {
        Write-TestResult "Downgrade Install" $false "TrustEdge not ready after downgrade (timeout)"
        return
    }
    $finalVersion = Get-TrustEdgeVersion
    
    if ($finalVersion -ne $olderVersion) {
        Write-TestResult "Downgrade Install" $false "Version mismatch after downgrade: expected $olderVersion, got $finalVersion"
        return
    }
    
    Write-TestResult "Downgrade Install" $true "Successfully downgraded from $newerVersion to $olderVersion"
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host @"

╔══════════════════════════════════════════════════════════════════════╗
║           TrustEdge Windows Installation Test Suite                  ║
╚══════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# Validate inputs
if (-not (Test-Path $InstallScript)) {
    Write-Host "ERROR: Install script not found: $InstallScript" -ForegroundColor Red
    exit 1
}

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Install Script: $InstallScript"
Write-Host "  Full Clean Script: $FullCleanScript"
Write-Host "  Test Case: $TestCase"
Write-Host "  Stop On Failure: $StopOnFailure"

# Auto-discover MSI files if not specified
if (-not $MsiPath) {
    $foundMsis = Get-ChildItem -Path "." -Filter "trustedge_*.msi" -ErrorAction SilentlyContinue
    if ($foundMsis) {
        $MsiPath = $foundMsis[0].FullName
        Write-Host "  Auto-discovered MSI: $MsiPath" -ForegroundColor Green
    }
}

# Run tests based on selection
switch ($TestCase) {
    "Fresh" {
        if ($MsiPath) {
            Test-FreshInstall -MsiFile $MsiPath
        } else {
            Write-Host "ERROR: No MSI path specified for fresh install test" -ForegroundColor Red
        }
    }
    "Upgrade" {
        if ($OlderMsiPath -and $NewerMsiPath) {
            Test-UpgradeInstall -OlderMsi $OlderMsiPath -NewerMsi $NewerMsiPath
        } else {
            Write-Host "ERROR: Both -OlderMsiPath and -NewerMsiPath required for upgrade test" -ForegroundColor Red
        }
    }
    "Downgrade" {
        if ($OlderMsiPath -and $NewerMsiPath) {
            Test-DowngradeInstall -NewerMsi $NewerMsiPath -OlderMsi $OlderMsiPath
        } else {
            Write-Host "ERROR: Both -OlderMsiPath and -NewerMsiPath required for downgrade test" -ForegroundColor Red
        }
    }
    "All" {
        if ($MsiPath) {
            Test-FreshInstall -MsiFile $MsiPath
        }
        
        if ($OlderMsiPath -and $NewerMsiPath) {
            Test-UpgradeInstall -OlderMsi $OlderMsiPath -NewerMsi $NewerMsiPath
            Test-DowngradeInstall -NewerMsi $NewerMsiPath -OlderMsi $OlderMsiPath
        } else {
            Write-Host "`nSkipping Upgrade/Downgrade tests: -OlderMsiPath and -NewerMsiPath not provided" -ForegroundColor Yellow
        }
    }
}

# ============================================================================
# Summary
# ============================================================================
Write-Host "`n" -NoNewline
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  TEST SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan

Write-Host "`nResults:" -ForegroundColor Yellow
foreach ($result in $script:TestResults) {
    $status = if ($result.Passed) { "[PASS]" } else { "[FAIL]" }
    $color = if ($result.Passed) { "Green" } else { "Red" }
    Write-Host "  $status $($result.Name)" -ForegroundColor $color
}

Write-Host "`nTotal: $($script:TestsPassed) passed, $($script:TestsFailed) failed" -ForegroundColor $(if ($script:TestsFailed -eq 0) { "Green" } else { "Red" })

if ($script:TestsFailed -gt 0) {
    exit 1
}
