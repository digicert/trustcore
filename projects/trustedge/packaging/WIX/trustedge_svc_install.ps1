# trustedge_svc_install.ps1
#
# PowerShell script to manually install TrustEdge as a Windows Service.
# 
# NOTE: If TrustEdge was installed via MSI, the service is already registered.
#       This script is for manual/standalone installations only.
#
# Usage: 
#   .\trustedge_svc_install.ps1 [-ExePath <path>] [-Start]
#
# Copyright (c) 2025-2026 DigiCert Corporation. All Rights Reserved.
#

param(
    [string]$ExePath = "",
    [switch]$Start = $false
)

$ErrorActionPreference = "Stop"

$SERVICE_NAME = "DigiCertTrustEdge"
$SERVICE_DISPLAY_NAME = "DigiCert TrustEdge Agent"
$SERVICE_DESCRIPTION = "Manages device identity and certificates via DigiCert Device Trust Manager"

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Find trustedge.exe
if ($ExePath -eq "") {
    # Try common locations
    $locations = @(
        "$env:ProgramFiles\DigiCert\TrustEdge\bin\trustedge.exe",
        ".\bin\trustedge.exe",
        ".\trustedge.exe"
    )
    foreach ($loc in $locations) {
        if (Test-Path $loc) {
            $ExePath = (Resolve-Path $loc).Path
            break
        }
    }
}

if ($ExePath -eq "" -or -not (Test-Path $ExePath)) {
    Write-Error "trustedge.exe not found. Specify path with -ExePath parameter."
    exit 1
}

Write-Host "Installing TrustEdge service..."
Write-Host "  Executable: $ExePath"

# Check if service already exists
$existingService = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue

if ($existingService) {
    Write-Host "  Service already exists."
    
    if ($existingService.Status -eq "Running") {
        Write-Host "  Stopping existing service..."
        Stop-Service -Name $SERVICE_NAME -Force
        Start-Sleep -Seconds 2
    }
    
    Write-Host "  Removing existing service..."
    & $ExePath --uninstall-service | Out-Null
    Start-Sleep -Seconds 2
}

# Install the service using trustedge --install-service
Write-Host "  Creating service..."
$result = & $ExePath --install-service 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create service: $result"
    exit 1
}

Write-Host "  Service installed successfully."
Write-Host ""
Write-Host "Service Details:"
Write-Host "  Name: $SERVICE_NAME"
Write-Host "  Display Name: $SERVICE_DISPLAY_NAME"
Write-Host "  Startup Type: Manual"
Write-Host ""

if ($Start) {
    Write-Host "Starting service..."
    Start-Service -Name $SERVICE_NAME
    $svc = Get-Service -Name $SERVICE_NAME
    Write-Host "  Service status: $($svc.Status)"
} else {
    Write-Host "To start the service:"
    Write-Host "  Start-Service -Name $SERVICE_NAME"
}

exit 0
