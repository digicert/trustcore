# TrustEdge Build & Run Guide

> **Note:** Run all commands from the root of the repository unless otherwise specified. Linux commands use a Bash shell. Windows commands use Command Prompt from a Visual Studio developer environment.

## Overview

TrustEdge is a versatile executable for secure IoT device communication, provisioning, and lifecycle management. Built with TrustCore SDK, it operates as a service via DigiCert® Device Trust Manager or as a CLI tool for tasks like CSR generation and MQTT communication.

## Prerequisites

### Linux

Install the required dependencies:

```bash
sudo apt update
sudo apt install -y build-essential cmake rpm
```

### Windows

Install the required dependencies:

- Visual Studio with MSVC C/C++ build tools
- Visual Studio C/C++ CMake development tools
- WiX Toolset v3.14 for `.msi` installer generation

Download WiX Toolset v3.14 from https://github.com/wixtoolset/wix3/releases/tag/wix3141rtm and use `wix314.exe` to install it. Add WiX to your system `PATH` after installation.

Default WiX install path to add to `PATH`:

```cmd
C:\Program Files (x86)\WiX Toolset v3.14\bin
```

Set up a 32-bit or 64-bit Visual Studio build environment before building TrustEdge. Replace `<version>` with your installed Visual Studio version, such as `2019`, `2022`, or `18`, and replace `<edition>` with `Professional`, `Enterprise`, or `Community`.

For a 32-bit build environment:

```cmd
call "C:\Program Files\Microsoft Visual Studio\<version>\<edition>\VC\Auxiliary\Build\vcvars32.bat"
```

For a 64-bit build environment:

```cmd
call "C:\Program Files\Microsoft Visual Studio\<version>\<edition>\VC\Auxiliary\Build\vcvars64.bat"
```

If Visual Studio is installed under `Program Files (x86)`, use that path instead:

```cmd
call "C:\Program Files (x86)\Microsoft Visual Studio\<version>\<edition>\VC\Auxiliary\Build\vcvars64.bat"
```

> **Note:** You can also open an installed **Developer Command Prompt for Visual Studio** and run the build commands from there. For TrustEdge installation, configuration, and execution on Windows, run Command Prompt with Administrator privileges.

## Build Steps

### Linux

Run the build script with the following options:

```bash
./scripts/ci/trustedge/ci_trustedge_build.sh --monolithic --package --cvc --proxy --pqc --pqc-composite --enable-pc
```

To build TrustEdge with NanoROOT TAP module support, include the `--nanoroot` option:

```bash
./scripts/ci/trustedge/ci_trustedge_build.sh --monolithic --package --nanoroot
```

For additional build options, run:

```bash
./scripts/ci/trustedge/ci_trustedge_build.sh --help
```

### Windows

From the Visual Studio developer environment, run the Windows build script:

```cmd
scripts\ci\trustedge\ci_trustedge_build.bat --version-string 0.0.0 --monolithic --package --tpm2 --cvc --proxy --pqc --pqc-composite --enable-pc
```

Set `--version-string` to the intended build or release version.

### Build Output

After a successful Linux build:

- The `trustedge` executable will be located in `bin/`
- With the `--package` option, distribution packages (`.deb`, `.tar.gz`, `.rpm`) will be located in `dist/`

After a successful Windows build:

- The `trustedge.exe` executable will be located in `lib\`
- The TrustEdge `.msi` installer will be located in `dist\`

## Installation and Configuration

### Linux Package Installation

Install the `.deb` package:

```bash
sudo DIGICERT_EULA_ACCEPT=yes dpkg -i dist/trustedge_*.deb
```

### Linux Installation Verification

Check that TrustEdge is installed correctly:

```bash
dpkg -s trustedge
trustedge --version
```

### Linux User Permissions

Add your user to the `trustedge` group:

```bash
sudo adduser $(whoami) trustedge
```

### Windows Package Installation

Run the following Windows installation, execution, and configuration commands from a Command Prompt with Administrator privileges.

Install TrustEdge using the `.msi` installer. When building TrustEdge from source, the MSI is generated in `dist\`. If you downloaded the MSI, use the folder where you saved the installer.

```cmd
msiexec /i "<path-to-trustedge-msi>" /qn ACCEPT_EULA=1 /l*v "msi_install.log"
```

Replace `<path-to-trustedge-msi>` with the path to the generated or downloaded TrustEdge MSI file. The MSI installer creates the `DigiCertTrustEdge` Windows service automatically.

To uninstall TrustEdge and remove the Windows service:

```cmd
msiexec /x "<path-to-trustedge-msi>" /qn
```

Add `C:\Program Files\DigiCert\TrustEdge\bin` (default MSI install location) to your system `PATH`

```cmd
set PATH=%PATH%;C:\Program Files\DigiCert\TrustEdge\bin
```


### Windows Local Execution

On Windows, the build output can be run directly from the repository:

```cmd
lib\trustedge.exe --version
```

To run the locally built `trustedge` executable from any Command Prompt session without installing the MSI, add the repository `lib` directory to the current session `PATH`:

```cmd
set PATH=%PATH%;C:\path\to\trustcore\lib
```

If you installed a downloaded MSI, you do not need to add the repository `lib` directory to `PATH`; use the installed TrustEdge location instead.

Verify that Windows can find the executable:

```cmd
where trustedge
trustedge --version
```

For more details on device management and obtaining the bootstrap configuration file, refer to the [Device Trust Manager documentation](https://docs.digicert.com/en/device-trust-manager/device-management.html).

### Configuration Files

TrustEdge uses the following configuration files.

#### Linux

- **`trustedge.json`**: Main configuration file for paths, proxy settings, agent behavior, and logging
  - Location: `/etc/digicert/trustedge.json`

- **`bootstrap_config.json`**: Device Trust Manager endpoints and credentials (do not edit manually)
  - Location: `/etc/digicert/conf/bootstrap_config.json`

- **Keystore files**: Keys, certificates, CSR configuration files, and CSR output
  - Location: `/etc/digicert/keystore/`

#### Windows

**Note:** The MSI installer can use a custom data directory (`DATADIRECTORY`). The paths below assume the default `C:\ProgramData\DigiCert\TrustEdge\`.

- **`trustedge.json`**: Main configuration file for paths, proxy settings, agent behavior, and logging
  - Location: `C:\ProgramData\DigiCert\TrustEdge\trustedge.json`

- **`bootstrap_config.json`**: Device Trust Manager endpoints and credentials (do not edit manually)
  - Location: `C:\ProgramData\DigiCert\TrustEdge\conf\bootstrap_config.json`

- **Keystore files**: Keys, certificates, CSR configuration files, and CSR output
  - Location: `C:\ProgramData\DigiCert\TrustEdge\keystore\`

---

## Usage

### Getting Help

View available commands and options.

For local Linux testing without installation:

```bash
./bin/trustedge --help
```

For local Windows testing without adding `lib\` to `PATH`:

```cmd
lib\trustedge.exe --help
```

If TrustEdge is installed or available on `PATH`:

```bash
trustedge --help
```

---

## TrustEdge Agent

The TrustEdge Agent acts as a client to DigiCert® Device Trust Manager. It can run interactively or as a service on supported platforms.

### Agent Help

```bash
trustedge agent --help
```

### Initialize Agent

1. Download the bootstrap configuration zip file (`<guid>.zip`) from Device Trust Manager:
   - Navigate to: **Device management > Devices > Device details > Configuration tab**

2. Bootstrap the agent.

On Linux:

```bash
trustedge agent --configure --bootstrap-zip ./<guid>.zip
```

On Windows:

Run this command from a Command Prompt with Administrator privileges.

```cmd
trustedge agent --configure --bootstrap-zip .\<guid>.zip
```

### Run as Service

On Linux, start the TrustEdge service:

```bash
sudo systemctl start trustedge.service
```

On Windows 11, the service name is `DigiCertTrustEdge`. Run the following commands from a Command Prompt with Administrator privileges.

Check whether the service exists and view its current status:

```cmd
sc query DigiCertTrustEdge
```

Start the service:

```cmd
sc start DigiCertTrustEdge
```

Verify that the service is running:

```cmd
sc query DigiCertTrustEdge
```

The `STATE` line should show `RUNNING`. If it shows `START_PENDING`, wait a few seconds and run `sc query DigiCertTrustEdge` again.

Stop the service:

```cmd
sc stop DigiCertTrustEdge
```

Verify that the service is stopped:

```cmd
sc query DigiCertTrustEdge
```

The `STATE` line should show `STOPPED`. If it shows `STOP_PENDING`, wait a few seconds and run `sc query DigiCertTrustEdge` again.

#### Check Applied Policies

On Linux:

```bash
cat /etc/digicert/conf/applied_policy.json
```

On Windows:

```cmd
type "C:\ProgramData\DigiCert\TrustEdge\conf\applied_policy.json"
```

#### Check Failed Policies

On Linux:

```bash
cat /etc/digicert/conf/failed_policy.json
```

On Windows:

```cmd
type "C:\ProgramData\DigiCert\TrustEdge\conf\failed_policy.json"
```

### Run Interactively

Run the agent in the foreground (logs to console):

```bash
trustedge agent
```

The agent will poll Device Trust Manager, perform required actions, and disconnect.

### Reset Agent

Reset the agent configuration:

```bash
trustedge agent --reset
```

---

## TrustEdge Certificate

TrustEdge certificate provides functionality for:
- Generating asymmetric keypairs
- Creating Certificate Signing Requests (CSRs)
- Submitting CSRs to a Certificate Authority (CA) via SCEP or EST protocols
- Requesting and downloading signed x.509 certificates

### Certificate Help

```bash
trustedge certificate --help
```

### Generate Private Keys

Generate an RSA private key:

```bash
trustedge certificate --algorithm RSA --size 2048 --output-file RSA_2048.pem
```
> **Note:**
> You can use the `-k` or `--key-store-path` option to specify the path to the keystore used for both input and output files.
> If not specified, the default is set by the TrustEdge configuration or is the current directory (`.`).
> On Linux, this example writes the output file to `/etc/digicert/keystore/keys` when the default TrustEdge configuration is used.
> On Windows, this example writes the output file to `C:\ProgramData\DigiCert\TrustEdge\keystore\keys` when the default TrustEdge configuration is used.

### Create CSR

1. Create a CSR configuration file (e.g., `sample_csr.cnf`).

On Linux:

```bash
tee /etc/digicert/keystore/conf/sample_csr.cnf > /dev/null <<EOF
##Subject
countryName=US
commonName=iot-device101
stateOrProvinceName=California
localityName=San Francisco
organizationName=DBA
organizationalUnitName=BU
##Requested Extensions
hasBasicConstraints=true
isCA=true
certPathLen=-1
keyUsage=keyEncipherment, digitalSignature, keyCertSign
subjectAltNames=2; *.mydomain.com, 2; *.mydomain.net, 2
EOF
```

On Windows Command Prompt:

```cmd
if not exist "C:\ProgramData\DigiCert\TrustEdge\keystore\conf" mkdir "C:\ProgramData\DigiCert\TrustEdge\keystore\conf"
(
echo ##Subject
echo countryName=US
echo commonName=iot-device101
echo stateOrProvinceName=California
echo localityName=San Francisco
echo organizationName=DBA
echo organizationalUnitName=BU
echo ##Requested Extensions
echo hasBasicConstraints=true
echo isCA=true
echo certPathLen=-1
echo keyUsage=keyEncipherment, digitalSignature, keyCertSign
echo subjectAltNames=2; *.mydomain.com, 2; *.mydomain.net, 2
) > "C:\ProgramData\DigiCert\TrustEdge\keystore\conf\sample_csr.cnf"
```

Verify the file content on Windows:

```cmd
type "C:\ProgramData\DigiCert\TrustEdge\keystore\conf\sample_csr.cnf"
```

2. Generate CSR for RSA:

```bash
trustedge certificate --cert-sign-req --output-file CSR_RSA_2048.pem --signing-key RSA_2048.pem --csr-conf sample_csr.cnf --digest SHA256
```

On Linux, find the output file in `/etc/digicert/keystore/req`.

On Windows, find the output file in `C:\ProgramData\DigiCert\TrustEdge\keystore\req`.

3. Verify the CSR.

On Linux:

```bash
trustedge certificate --print-cert /etc/digicert/keystore/req/CSR_RSA_2048.pem
```

On Windows:

```cmd
trustedge certificate --print-cert "C:\ProgramData\DigiCert\TrustEdge\keystore\req\CSR_RSA_2048.pem"
```

### Generate X.509 Certificate

Generate a self-signed certificate for RSA:

```bash
trustedge certificate --algorithm RSA --size 2048 --output-file RSA_CERT_2048.pem --csr-conf sample_csr.cnf --x509-cert RSA_CERT_2048.pem --days 365
```

On Linux, find the output file in `/etc/digicert/keystore/certs`.

On Windows, find the output file in `C:\ProgramData\DigiCert\TrustEdge\keystore\certs`.

### Verify Certificate

Verify and print certificate details.

On Linux:

```bash
trustedge certificate --print-cert /etc/digicert/keystore/certs/RSA_CERT_2048.pem
```

On Windows:

```cmd
trustedge certificate --print-cert "C:\ProgramData\DigiCert\TrustEdge\keystore\certs\RSA_CERT_2048.pem"
```

### TrustEdge SCEP

Use SCEP (Simple Certificate Enrollment Protocol) for certificate enrollment, renewal, and key rekeying.

View SCEP options:

```bash
trustedge certificate scep --help
```

### TrustEdge EST

Use EST (Enrollment over Secure Transport) for certificate enrollment, renewal, and key rekeying.

View EST options:

```bash
trustedge certificate est --help
```

### Using NanoROOT as a TAP Module (Linux Only)

NanoROOT can be used as a TrustCore TAP provider for TrustEdge certificate operations. With this configuration, TrustEdge uses NanoROOT-backed key material through a NanoROOT key handle.

Before running TrustEdge with NanoROOT, complete the NanoROOT setup, configuration, and environment preparation described in [NanoROOT TAP Example - Build and Run Instructions](../nanoroot/BUILD_RUN.md).

#### Certificate Flow

Build TrustEdge with NanoROOT support.

On Linux:

```bash
./scripts/ci/trustedge/ci_trustedge_build.sh --package --monolithic --nanoroot
```

When running a TrustEdge certificate EST enrollment flow with NanoROOT, append the TAP options to your `trustedge certificate est` command, for example:

```bash
trustedge certificate est <est_options> --tap --tap-provider nanoroot --tap-key-handle <nanoroot_key_handle>
```

For EST enrollment details, refer to the [TrustEdge EST enrollment tutorial](https://dev.digicert.com/trustedge/tutorials/est-enrollment.html).

#### Agent Flow

NanoROOT can also be used as the key source for TrustEdge Agent certificate operations through Device Trust Manager.

In Device Trust Manager, create or update the certificate profile to use NanoROOT as the key source and provide the matching NanoROOT key handle. For Device Trust Manager details, refer to the [Device Trust Manager documentation](https://docs.digicert.com/en/device-trust-manager.html).

After configuring the certificate profile, start TrustEdge as a service where supported or run the agent interactively using the steps in [TrustEdge Agent](#trustedge-agent).

---

## TrustEdge MQTT

TrustEdge MQTT provides functionality for managing MQTT communications. It supports both MQTT 3.1.1 and MQTT 5.0 protocols for:
- Publishing messages to an MQTT broker
- Subscribing to MQTT topics

### MQTT Help

```bash
trustedge mqtt --help
```

### Subscribe to a Topic

Subscribe to an MQTT topic:

```bash
trustedge mqtt --mqtt_servername broker.hivemq.com --mqtt_sub_topic house/bulb1 --mqtt_port 1883 --mqtt_clean_start
```

### Publish a Message

Publish a message to an MQTT topic:

```bash
trustedge mqtt --mqtt_servername broker.hivemq.com --mqtt_pub_topic house/bulb1 --mqtt_pub_message "Hello, MQTT!" --mqtt_port 1883 --mqtt_clean_start
```

