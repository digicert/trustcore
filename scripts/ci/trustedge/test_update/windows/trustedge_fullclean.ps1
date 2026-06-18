#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Completely removes all TrustEdge installation artifacts for clean testing.

.DESCRIPTION
    Removes TrustEdge service, registry entries, directories, files, and environment
    variables to provide a clean environment for MSI install/uninstall/upgrade testing.

.PARAMETER WhatIf
    Show what would be removed without actually removing anything.

.EXAMPLE
    .\trustedge_fullclean.ps1
    Performs full cleanup of TrustEdge artifacts.

.EXAMPLE
    .\trustedge_fullclean.ps1 -WhatIf
    Shows what would be removed without making changes.

.NOTES
    Must be run as Administrator.
    Author: DigiCert
#>

param(
    [switch]$WhatIf
)

$ErrorActionPreference = "Continue"

# TrustEdge identifiers
$ServiceName = "DigiCertTrustEdge"
$UpgradeCode = "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
$UpgradeCodeCompressed = "4D3C2B1A6F5E0987BADCFE2143658709"

# Known ProductCodes (add more as needed)
$ProductCodes = @(
    "E78368E3-333A-44FF-9171-B312B8AF0ABC"
)
$ProductCodesCompressed = @(
    "3E86387EA333FF4419173B218BFAA0CB"
)

# Directories to remove
$Directories = @(
    "$env:ProgramFiles\DigiCert\TrustEdge",
    "$env:ProgramFiles\DigiCert",
    "$env:ProgramData\DigiCert\TrustEdge",
    "$env:ProgramData\DigiCert",
    "$env:LOCALAPPDATA\DigiCert\TrustEdge",
    "$env:APPDATA\DigiCert\TrustEdge"
)

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    $color = switch ($Type) {
        "Info"    { "Cyan" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        default   { "White" }
    }
    Write-Host "[$Type] $Message" -ForegroundColor $color
}

function Remove-RegistryKeyIfExists {
    param([string]$Path)
    if (Test-Path $Path) {
        if ($WhatIf) {
            Write-Status "Would remove: $Path" "Warning"
        } else {
            try {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
                Write-Status "Removed: $Path" "Success"
            } catch {
                Write-Status "Failed to remove: $Path - $_" "Error"
            }
        }
    }
}

function Remove-DirectoryIfExists {
    param([string]$Path)
    if (Test-Path $Path) {
        if ($WhatIf) {
            Write-Status "Would remove directory: $Path" "Warning"
        } else {
            try {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
                Write-Status "Removed directory: $Path" "Success"
            } catch {
                Write-Status "Failed to remove directory: $Path - $_" "Error"
            }
        }
    }
}

# ============================================================================
# 1. Stop and remove TrustEdge service
# ============================================================================
Write-Host "`n=== Stopping and Removing TrustEdge Service ===" -ForegroundColor Magenta

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($WhatIf) {
        Write-Status "Would stop and remove service: $ServiceName" "Warning"
    } else {
        Write-Status "Stopping service: $ServiceName" "Info"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        Write-Status "Removing service: $ServiceName" "Info"
        sc.exe delete $ServiceName | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Service removed successfully" "Success"
        } else {
            Write-Status "Failed to remove service (may require reboot)" "Warning"
        }
    }
} else {
    Write-Status "Service not found: $ServiceName" "Info"
}

# ============================================================================
# 2. Remove Windows Installer registry entries (HKLM - per-machine)
# ============================================================================
Write-Host "`n=== Cleaning HKLM Windows Installer Registry ===" -ForegroundColor Magenta

# UpgradeCodes
Remove-RegistryKeyIfExists "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\$UpgradeCodeCompressed"
Remove-RegistryKeyIfExists "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\$UpgradeCodeCompressed"

# Find ALL DigiCert TrustEdge products dynamically (not just known ProductCodes)
Write-Host "`n--- Searching for ALL TrustEdge installer products ---" -ForegroundColor Yellow
$foundProducts = @()

# Search HKLM Classes Installer Products
$classesProducts = Get-ChildItem "HKLM:\SOFTWARE\Classes\Installer\Products" -ErrorAction SilentlyContinue
foreach ($p in $classesProducts) {
    $name = (Get-ItemProperty $p.PSPath -ErrorAction SilentlyContinue).ProductName
    if ($name -like "*TrustEdge*" -or $name -like "*DigiCert*") {
        $foundProducts += $p.PSChildName
        Write-Status "Found product: $($p.PSChildName) - $name" "Warning"
    }
}

# Add known products to list
$allProductCodes = $ProductCodesCompressed + $foundProducts | Select-Object -Unique

# Remove all found products
foreach ($pc in $allProductCodes) {
    Remove-RegistryKeyIfExists "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\$pc"
    Remove-RegistryKeyIfExists "HKLM:\SOFTWARE\Classes\Installer\Products\$pc"
    Remove-RegistryKeyIfExists "HKLM:\SOFTWARE\Classes\Installer\Features\$pc"
}
Remove-RegistryKeyIfExists "HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes\$UpgradeCodeCompressed"

# ============================================================================
# 3. Remove Windows Installer registry entries (HKCU - per-user)
# ============================================================================
Write-Host "`n=== Cleaning HKCU Windows Installer Registry ===" -ForegroundColor Magenta

Remove-RegistryKeyIfExists "HKCU:\Software\Microsoft\Installer\UpgradeCodes\$UpgradeCodeCompressed"

# Search HKCU for TrustEdge products
$hkcuProducts = Get-ChildItem "HKCU:\Software\Microsoft\Installer\Products" -ErrorAction SilentlyContinue
foreach ($p in $hkcuProducts) {
    $name = (Get-ItemProperty $p.PSPath -ErrorAction SilentlyContinue).ProductName
    if ($name -like "*TrustEdge*" -or $name -like "*DigiCert*") {
        Write-Status "Found HKCU product: $($p.PSChildName) - $name" "Warning"
        Remove-RegistryKeyIfExists $p.PSPath
        Remove-RegistryKeyIfExists ($p.PSPath -replace "Products", "Features")
    }
}

# Also remove known products
foreach ($pc in $ProductCodesCompressed) {
    Remove-RegistryKeyIfExists "HKCU:\Software\Microsoft\Installer\Products\$pc"
    Remove-RegistryKeyIfExists "HKCU:\Software\Microsoft\Installer\Features\$pc"
}

# ============================================================================
# 4. Remove Uninstall registry entries
# ============================================================================
Write-Host "`n=== Cleaning Uninstall Registry Entries ===" -ForegroundColor Magenta

# Search for TrustEdge uninstall entries by DisplayName
$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($basePath in $uninstallPaths) {
    if (Test-Path $basePath) {
        Get-ChildItem $basePath -ErrorAction SilentlyContinue | ForEach-Object {
            $displayName = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName
            if ($displayName -like "*TrustEdge*" -or $displayName -like "*DigiCert*") {
                Write-Status "Found uninstall entry: $displayName" "Warning"
                Remove-RegistryKeyIfExists $_.PSPath
            }
        }
    }
}

# Also remove known product codes
foreach ($pc in $ProductCodes) {
    Remove-RegistryKeyIfExists "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{$pc}"
    Remove-RegistryKeyIfExists "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{$pc}"
    Remove-RegistryKeyIfExists "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{$pc}"
}

# Search for TrustEdge entries by name
$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
)

foreach ($path in $uninstallPaths) {
    if (Test-Path $path) {
        Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
            $displayName = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName
            if ($displayName -match "TrustEdge|DigiCert") {
                Remove-RegistryKeyIfExists $_.PSPath
            }
        }
    }
}

# ============================================================================
# 5. Remove DigiCert application registry keys
# ============================================================================
Write-Host "`n=== Cleaning DigiCert Application Registry ===" -ForegroundColor Magenta

Remove-RegistryKeyIfExists "HKLM:\SOFTWARE\DigiCert\TrustEdge"
Remove-RegistryKeyIfExists "HKLM:\SOFTWARE\DigiCert"
Remove-RegistryKeyIfExists "HKLM:\SOFTWARE\WOW6432Node\DigiCert\TrustEdge"
Remove-RegistryKeyIfExists "HKLM:\SOFTWARE\WOW6432Node\DigiCert"
Remove-RegistryKeyIfExists "HKCU:\Software\DigiCert\TrustEdge"
Remove-RegistryKeyIfExists "HKCU:\Software\DigiCert"

# ============================================================================
# 6. Remove installation directories
# ============================================================================
Write-Host "`n=== Removing Installation Directories ===" -ForegroundColor Magenta

foreach ($dir in $Directories) {
    Remove-DirectoryIfExists $dir
}

# Also check for temp artifact directories
Remove-DirectoryIfExists "$env:ProgramData\DigiCert\TrustEdge\tmp"
Remove-DirectoryIfExists "$env:TEMP\TrustEdge"

# ============================================================================
# 7. Remove cached MSI files
# ============================================================================
Write-Host "`n=== Cleaning Windows Installer Cache ===" -ForegroundColor Magenta

$installerCache = "$env:SystemRoot\Installer"
if (Test-Path $installerCache) {
    # Find and remove TrustEdge MSI files from cache
    Get-ChildItem $installerCache -Filter "*.msi" -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $msiDb = New-Object -ComObject WindowsInstaller.Installer
            $db = $msiDb.OpenDatabase($_.FullName, 0)
            $view = $db.OpenView("SELECT Value FROM Property WHERE Property='ProductName'")
            $view.Execute()
            $record = $view.Fetch()
            if ($record) {
                $productName = $record.StringData(1)
                if ($productName -match "TrustEdge") {
                    if ($WhatIf) {
                        Write-Status "Would remove cached MSI: $($_.FullName)" "Warning"
                    } else {
                        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                        Write-Status "Removed cached MSI: $($_.Name)" "Success"
                    }
                }
            }
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($msiDb) | Out-Null
        } catch {
            # Skip files that can't be read
        }
    }
}

# ============================================================================
# 8. Clean up environment variables
# ============================================================================
Write-Host "`n=== Cleaning Environment Variables ===" -ForegroundColor Magenta

$pathVars = @("Path", "TRUSTEDGE_HOME", "DIGICERT_HOME")
foreach ($varName in $pathVars) {
    $machineValue = [Environment]::GetEnvironmentVariable($varName, "Machine")
    $userValue = [Environment]::GetEnvironmentVariable($varName, "User")
    
    if ($varName -eq "Path") {
        # Remove TrustEdge from PATH
        if ($machineValue -match "DigiCert|TrustEdge") {
            $newPath = ($machineValue -split ";" | Where-Object { $_ -notmatch "DigiCert|TrustEdge" }) -join ";"
            if (-not $WhatIf) {
                [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
            }
            Write-Status "Cleaned TrustEdge from Machine PATH" "Success"
        }
    } else {
        if ($machineValue) {
            if (-not $WhatIf) {
                [Environment]::SetEnvironmentVariable($varName, $null, "Machine")
            }
            Write-Status "Removed environment variable: $varName (Machine)" "Success"
        }
        if ($userValue) {
            if (-not $WhatIf) {
                [Environment]::SetEnvironmentVariable($varName, $null, "User")
            }
            Write-Status "Removed environment variable: $varName (User)" "Success"
        }
    }
}

# ============================================================================
# 9. Summary
# ============================================================================
Write-Host "`n=== Cleanup Complete ===" -ForegroundColor Green

if ($WhatIf) {
    Write-Host "`nThis was a dry run. No changes were made." -ForegroundColor Yellow
    Write-Host "Run without -WhatIf to perform actual cleanup." -ForegroundColor Yellow
} else {
    Write-Host "`nTrustEdge cleanup completed successfully." -ForegroundColor Green
    Write-Host "You may need to reboot if any files were locked." -ForegroundColor Yellow
}

Write-Host "`nYou can now perform a fresh TrustEdge MSI installation." -ForegroundColor Cyan
