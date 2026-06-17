# TrustEdge MSI Installer Assets

This directory contains assets for building the Windows MSI installer using WIX Toolset.

## Prerequisites

- WIX Toolset v3.14 (https://wixtoolset.org/releases/)
- Visual Studio with C++ build tools
- CMake 3.10+

## Directory Structure

```
installer/MSI/
├── config/
│   └── trustedge.json          # Windows-specific configuration file (template)
├── scripts/
│   └── update-config.ps1       # PowerShell script to update config paths
├── license.rtf                 # License agreement (RTF format for WIX)
├── programdata_dirs.wxs.in     # WIX fragment template for ProgramData structure
├── ui_datadir.wxs.in           # WIX UI extension for data directory dialog
├── wix_patch.xml               # CPack WIX patch to include ProgramData feature
└── README.md                   # This file
```

## Installation Paths

The MSI installer allows customization of both installation directories:

### Program Files (Executable) - Configurable
Default: `C:\Program Files\DigiCert\TrustEdge\`
```
└── bin\
    └── trustedge.exe
```

### ProgramData (Configuration & Data) - Configurable
Default: `C:\ProgramData\DigiCert\TrustEdge\`

The installer presents a dialog allowing users to select a custom data directory:
```
├── trustedge.json              # Main configuration file (paths auto-updated)
├── conf\
│   ├── version.txt
│   └── eula.txt
├── cloudprovider\
├── keystore\
│   ├── ca\
│   ├── certs\
│   ├── conf\
│   ├── crls\
│   ├── keys\
│   ├── psks\
│   └── req\
└── service\
    ├── request\
    ├── completed\
    ├── failed\
    └── processing\
```

## Silent Installation

For automated deployments, you can specify the data directory via command line:

```cmd
msiexec /i trustedge_X.Y.Z.x86_64.msi /quiet DATADIRECTORY="D:\TrustEdgeData"
```

The installer will:
1. Create the directory structure at the specified location
2. Automatically update `trustedge.json` with the correct paths
3. Store the data directory path in the registry for future reference

## Registry Keys

The installer stores configuration in:
```
HKLM\SOFTWARE\DigiCert\TrustEdge
  DataDirectory: <path to data directory>
  ServiceInstalled: 1 (if service is registered)
```

## Windows Service

The MSI installer automatically registers TrustEdge as a Windows service:

| Property | Value |
|----------|-------|
| Service Name | DigiCertTrustEdge |
| Display Name | DigiCert TrustEdge Agent |
| Startup Type | Automatic |
| Account | LocalSystem |
| Arguments | --daemon |

**Important**: The service is installed with **Automatic** startup type, matching Linux package behavior where the service is enabled during installation. It is configured to start automatically after system reboot, but it is not explicitly started by the MSI during installation. Users can start it immediately via:
- Services (services.msc)
- `sc start DigiCertTrustEdge`
- `Start-Service DigiCertTrustEdge`

## Upgrade Behavior

The MSI installer handles upgrades gracefully:

| Aspect | Behavior |
|--------|----------|
| EULA | Shown on upgrade (WiX limitation) |
| trustedge.json | Preserved (user modifications retained via `NeverOverwrite`) |
| Service | Stopped before upgrade, NOT auto-started (matches DEB) |
| Keystore data | Preserved (WiX component rules) |
| version.txt / eula.txt | Updated to new version |

### Upgrade Flow

1. Windows Installer detects existing installation via `UpgradeCode` GUID
2. Service is stopped (`sc stop DigiCertTrustEdge`)
3. Files are updated (trustedge.json preserved via `NeverOverwrite`)
4. Service is re-registered but NOT started (user must start manually)
5. EULA dialog shown (user must accept again)

To start the service after upgrade:
```cmd
sc start DigiCertTrustEdge
```

### Silent Upgrade

```cmd
msiexec /i trustedge_X.Y.Z.x86_64.msi /quiet
```

## Uninstall Behavior

The MSI supports two uninstall modes, matching Linux `apt` behavior:

### Standard Uninstall (like `apt remove`)

Keeps user configuration and data in `C:\ProgramData\DigiCert\TrustEdge\`:

```cmd
msiexec /x {ProductCode}
```

Or via Add/Remove Programs.

**Preserved files:**
- `trustedge.json` (configuration)
- `keystore/` (certificates, keys)
- `conf/` (additional config)
- `service/` (request queues)
- `cloudprovider/` (credentials)

### Purge Uninstall (like `apt purge`)

Removes ALL files including configuration and user data:

```cmd
msiexec /x {ProductCode} PURGE=1
```

Or silently:
```cmd
msiexec /x {ProductCode} /quiet PURGE=1
```

**Warning:** This permanently deletes all certificates, keys, and configuration.

## Building the MSI

```cmd
cd projects\trustedge
rmdir /s /q build
build.bat --monolithic --generator MSI --version-string X.Y.Z
```

The MSI will be created in `projects/trustedge/dist/`.

## Optional Assets

You can add these optional files to customize the installer UI:

- `banner.bmp` - 493x58 pixels, installer header banner
- `dialog.bmp` - 493x312 pixels, installer welcome/finish dialog background
- `trustedge.ico` - Product icon for Add/Remove Programs

## WIX Files

### programdata_dirs.wxs.in
CMake template that defines:
- `DATADIRECTORY` property with registry search for existing installations
- Directory structure components for the data directory
- Custom action to run PowerShell script for config update

### ui_datadir.wxs.in
WIX UI extension that adds:
- Custom dialog page for data directory selection
- Browse button functionality
- Reset to default button
- Integration into the standard WIX UI sequence

### wix_patch.xml
CPack patch file that adds FeatureRef to include the ProgramData components.

### scripts/update-config.ps1
PowerShell script that updates `trustedge.json` with the actual data directory paths
after installation completes.
