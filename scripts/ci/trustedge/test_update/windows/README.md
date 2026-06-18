# TrustEdge Windows Update Test Scripts

Scripts for testing TrustEdge MSI install/uninstall/upgrade flows on Windows.

## Quick Start - Full Automation

To build multiple versions and run all tests automatically:

```powershell
# From repo root, run as Administrator
powershell -ExecutionPolicy Bypass -File .\scripts\ci\trustedge\trustedge_build_and_test.ps1
```

This will:
1. Build TrustEdge versions 1.9.0, 2.0.0, and 2.1.0
2. Run fresh install, upgrade, and downgrade tests
3. Clean up after testing

See `scripts\ci\trustedge\trustedge_build_and_test.ps1` for options.

## Scripts

### trustedge_fullclean.ps1

Completely removes all TrustEdge installation artifacts for clean testing.

**What it removes:**
- DigiCertTrustEdge service
- Windows Installer registry entries (HKLM and HKCU)
- Uninstall registry entries
- DigiCert application registry keys
- Installation directories (Program Files, ProgramData, AppData)
- Cached MSI files from Windows Installer cache
- Environment variables (PATH, TRUSTEDGE_HOME, DIGICERT_HOME)

**Usage:**
```powershell
# Dry run (see what would be removed)
powershell -ExecutionPolicy Bypass -File .\trustedge_fullclean.ps1 -WhatIf

# Actual cleanup (requires Admin)
powershell -ExecutionPolicy Bypass -File .\trustedge_fullclean.ps1
```

### trustedge_test.ps1

Tests all install/uninstall/upgrade flows using `install_trustedge.bat`.

**Test Cases:**
1. **Fresh Install** - Install TrustEdge on a clean system
2. **Upgrade Install** - Install older version, then upgrade to newer version
3. **Downgrade Install** - Install newer version, then downgrade to older version

**Usage:**
```powershell
# Run fresh install test only
powershell -ExecutionPolicy Bypass -File .\trustedge_test.ps1 `
    -TestCase Fresh `
    -MsiPath "C:\builds\trustedge_2.0.0.x86_64.msi"

# Run all tests
powershell -ExecutionPolicy Bypass -File .\trustedge_test.ps1 `
    -TestCase All `
    -MsiPath "C:\builds\trustedge_2.0.0.x86_64.msi" `
    -OlderMsiPath "C:\builds\trustedge_1.9.0.x86_64.msi" `
    -NewerMsiPath "C:\builds\trustedge_2.1.0.x86_64.msi"

# Run upgrade test only
powershell -ExecutionPolicy Bypass -File .\trustedge_test.ps1 `
    -TestCase Upgrade `
    -OlderMsiPath "C:\builds\trustedge_1.9.0.x86_64.msi" `
    -NewerMsiPath "C:\builds\trustedge_2.0.0.x86_64.msi"

# Run downgrade test only
powershell -ExecutionPolicy Bypass -File .\trustedge_test.ps1 `
    -TestCase Downgrade `
    -OlderMsiPath "C:\builds\trustedge_1.9.0.x86_64.msi" `
    -NewerMsiPath "C:\builds\trustedge_2.0.0.x86_64.msi"
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `-MsiPath` | Path to MSI file for fresh install test |
| `-OlderMsiPath` | Path to older version MSI for upgrade/downgrade tests |
| `-NewerMsiPath` | Path to newer version MSI for upgrade/downgrade tests |
| `-InstallScript` | Path to install_trustedge.bat (default: projects\trustedge\install_trustedge.bat) |
| `-SkipCleanup` | Skip running fullclean between tests (not recommended) |
| `-TestCase` | Specific test: "Fresh", "Upgrade", "Downgrade", or "All" |

## Prerequisites

1. **Administrator privileges** - Both scripts require elevation
2. **PowerShell execution policy** - Use `-ExecutionPolicy Bypass` or set permanently:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
3. **MSI files** - Have the appropriate TrustEdge MSI files ready for testing

## Typical Test Workflow

```powershell
# 1. Clean the system
powershell -ExecutionPolicy Bypass -File .\trustedge_fullclean.ps1

# 2. Run tests
powershell -ExecutionPolicy Bypass -File .\trustedge_test.ps1 -TestCase All `
    -MsiPath "trustedge_2.0.0.x86_64.msi" `
    -OlderMsiPath "trustedge_1.9.0.x86_64.msi" `
    -NewerMsiPath "trustedge_2.1.0.x86_64.msi"

# 3. Clean up after testing
powershell -ExecutionPolicy Bypass -File .\trustedge_fullclean.ps1
```

## Notes

- The fullclean script should be run between tests to ensure accurate results
- Downgrade testing requires `AllowDowngrades="yes"` in the WiX template
- The test script verifies installation by checking service status and binary version
- Test results are summarized at the end with pass/fail counts

## Full Automation Script

The `trustedge_build_and_test.ps1` script (in parent directory) automates everything:

```powershell
# Build and test with default versions (1.9.0, 2.0.0, 2.1.0)
powershell -ExecutionPolicy Bypass -File ..\trustedge_build_and_test.ps1

# Use custom versions
powershell -ExecutionPolicy Bypass -File ..\trustedge_build_and_test.ps1 `
    -OldVersion "1.8.0" `
    -CurrentVersion "1.9.0" `
    -NewVersion "2.0.0"

# Skip build and use existing MSIs
powershell -ExecutionPolicy Bypass -File ..\trustedge_build_and_test.ps1 `
    -SkipBuild `
    -OutputDir "C:\existing_builds"
```

**Parameters:**
| Parameter | Default | Description |
|-----------|---------|-------------|
| `-OldVersion` | 1.9.0 | Version string for "old" build |
| `-CurrentVersion` | 2.0.0 | Version string for "current" build |
| `-NewVersion` | 2.1.0 | Version string for "new" build |
| `-SkipBuild` | false | Skip building, use existing MSIs |
| `-OutputDir` | .\test_builds | Directory for build outputs |
| `-VsVersion` | 2022 | Visual Studio version year |
