# trustedge_svc_uninstall.ps1
#
# PowerShell script to stop and remove the TrustEdge Windows Service.
#
# NOTE: If TrustEdge was installed via MSI, uninstalling the MSI
#       will automatically remove the service.
#
# Usage:
#   .\trustedge_svc_uninstall.ps1
#
# Copyright (c) 2025-2026 DigiCert Corporation. All Rights Reserved.
#

$ErrorActionPreference = "SilentlyContinue"

$SERVICE_NAME = "DigiCertTrustEdge"

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Host "Uninstalling TrustEdge service..."

# Check if service exists
$service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue

if (-not $service) {
    Write-Host "  Service not found. Nothing to uninstall."
    exit 0
}

# Stop the service if running
if ($service.Status -eq "Running") {
    Write-Host "  Stopping service..."
    Stop-Service -Name $SERVICE_NAME -Force
    $service.WaitForStatus('Stopped', '00:00:30')
}

# Try to find trustedge.exe to use --uninstall-service
$ExePath = ""
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

# Remove the service
Write-Host "  Removing service..."
if ($ExePath -ne "" -and (Test-Path $ExePath)) {
    & $ExePath --uninstall-service | Out-Null
} else {
    # Fallback to sc.exe if trustedge.exe not found
    sc.exe delete $SERVICE_NAME | Out-Null
}

if ($LASTEXITCODE -eq 0) {
    Write-Host "  Service removed successfully."
} else {
    Write-Host "  Warning: Service removal may require a reboot."
}

exit 0
