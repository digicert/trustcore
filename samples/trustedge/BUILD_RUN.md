# TrustEdge Build & Run Guide (Linux)

> **Note:** Run all commands from the root of the repository.

## Overview

TrustEdge is a versatile executable for secure IoT device communication, provisioning, and lifecycle management. Built with TrustCore SDK, it operates as a service via DigiCert® Device Trust Manager or as a CLI tool for tasks like CSR generation and MQTT communication.

## Prerequisites

Install the required dependencies:

```bash
sudo apt update
sudo apt install -y build-essential cmake rpm
```

## Build Steps

Run the build script with the following options:

```bash
./scripts/ci/trustedge/ci_trustedge_build.sh --monolithic --package --cvc --proxy --pqc --pqc-composite --enable-pc
```

To build TrustEdge with NanoROOT TAP module support, include the `--nanoroot` option:

```bash
./scripts/ci/trustedge/ci_trustedge_build.sh --monolithic --package --nanoroot
```

### Build Output

After a successful build:
- The `trustedge` executable will be located in `bin/`
- With `--package` option, distribution packages (`.deb`, `.tar.gz`, `.rpm`) will be located in `dist/`

For additional build options, run:

```bash
./scripts/ci/trustedge/ci_trustedge_build.sh --help
```

## Installation and Configuration

### Install the Package

Install the `.deb` package:

```bash
sudo DIGICERT_EULA_ACCEPT=yes dpkg -i dist/trustedge_*.deb
```

### Verify Installation

Check that TrustEdge is installed correctly:

```bash
dpkg -s trustedge
trustedge --version
```

### Configure User Permissions

Add your user to the `trustedge` group:

```bash
sudo adduser $(whoami) trustedge
```

For more details on device management and obtaining the bootstrap configuration file, refer to the [Device Trust Manager documentation](https://docs.digicert.com/en/device-trust-manager/device-management.html).

### Configuration Files

TrustEdge uses the following configuration files:

- **`trustedge.json`**: Main configuration file for paths, proxy settings, agent behavior, and logging
  - Location: `/etc/digicert/trustedge.json`

- **`bootstrap_config.json`**: Device Trust Manager endpoints and credentials (do not edit manually)
  - Location: `/etc/digicert/conf/bootstrap_config.json`

---

## Usage

### Getting Help

View available commands and options:

```bash
./bin/trustedge --help
# Or if installed:
trustedge --help
```

> **Note:** Use `./bin/trustedge` for local testing without installation.

---

## TrustEdge Agent

The TrustEdge Agent acts as a client to DigiCert® Device Trust Manager. It can run interactively or as a system service.

### Agent Help

```bash
trustedge agent --help
```

### Initialize Agent

1. Download the bootstrap configuration zip file (`<guid>.zip`) from Device Trust Manager:
   - Navigate to: **Device management > Devices > Device details > Configuration tab**

2. Bootstrap the agent:
   ```bash
   trustedge agent --configure --bootstrap-zip ./<guid>.zip
   ```

### Run as Service

Start the TrustEdge service:

```bash
sudo systemctl start trustedge.service
```

#### Check Applied Policies

```bash
cat /etc/digicert/conf/applied_policy.json
```

#### Check Failed Policies

```bash
cat /etc/digicert/conf/failed_policy.json
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
> If not specified, the default is set by the trustedge configuration or is the current directory (`.`).
> In this example, you can find the output file in `/etc/digicert/keystore/keys`.

### Create CSR

1. Create a CSR configuration file (e.g., `sample_csr.cnf`):

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

2. Generate CSR for RSA:
```bash
trustedge certificate --cert-sign-req --output-file CSR_RSA_2048.pem --signing-key RSA_2048.pem --csr-conf sample_csr.cnf --digest SHA256
```
Find the output file in `/etc/digicert/keystore/req`.

3. Verify the CSR:
```bash
trustedge certificate --print-cert /etc/digicert/keystore/req/CSR_RSA_2048.pem
```

### Generate X.509 Certificate

Generate a self-signed certificate for RSA:

```bash
trustedge certificate --algorithm RSA --size 2048 --output-file RSA_CERT_2048.pem --csr-conf sample_csr.cnf --x509-cert RSA_CERT_2048.pem --days 365
```
Find the output file in `/etc/digicert/keystore/certs`.

### Verify Certificate

Verify and print certificate details:

```bash
trustedge certificate --print-cert /etc/digicert/keystore/certs/RSA_CERT_2048.pem
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

### Using NanoROOT as a TAP Module

NanoROOT can be used as a TrustCore TAP provider for TrustEdge certificate operations. With this configuration, TrustEdge uses NanoROOT-backed key material through a NanoROOT key handle.

Before running TrustEdge with NanoROOT, complete the NanoROOT setup, configuration, and environment preparation described in [NanoROOT TAP Example - Build and Run Instructions](../nanoroot/BUILD_RUN.md).

#### Certificate Flow

Build TrustEdge with NanoROOT support:

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

After configuring the certificate profile, start TrustEdge as a service or run the agent interactively using the steps in [TrustEdge Agent](#trustedge-agent).

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

