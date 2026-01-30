# NanoROOT TAP Example - Build and Run Instructions

## 📦 Overview

This directory contains the **NanoROOT TAP Example**, demonstrating the NanoROOT SMP (Security Module Provider) for hardware-rooted cryptographic operations:

- **Seal/Unseal Operations**: Encrypt and decrypt data using device-specific credentials
- **Digital Signatures**: Generate and verify signatures using RSA, ECC, and Post-Quantum (MLDSA) algorithms
- **Hardware-Rooted Security**: Leverage device fingerprints for cryptographic key derivation

---

## 📂 Project Structure

```
samples/nanoroot/
├── src/
│   └── tap_nanoroot_example.c    # Main example implementation
├── config/
│   ├── nanoroot_smp.conf          # NanoROOT configuration file
│   ├── default-fingerprint.json   # Sample credential/fingerprint file
│   ├── setFingerPrintValues.sh    # Script to set environment variables
│   ├── get_mac_address.sh         # Helper script for MAC address
│   └── get_cpuid.sh               # Helper script for CPU ID
├── CMakeLists.txt                 # CMake build configuration
├── mss_sources.txt                # Source file list
├── mss_includes.txt               # Include directory list
├── mocana_flags.txt               # Compiler flags
└── BUILD_RUN.md                   # This file
```

---

## ⚙️ Build Options

| Option            | Description                                    | Default |
|-------------------|------------------------------------------------|---------|
| `ENABLE_NANOROOT` | Enable NanoROOT SMP library build              | `OFF`   |
| `SECURE_PATH`     | Restrict credential file access to secure path | `OFF`   |

---

## 🛠️ Build Instructions

### Prerequisites

- CMake 3.5 or higher
- GCC or compatible C compiler
- OpenSSL (optional, for cross-verification tests)

### 1. Configure the Project

**Standard build (credentials in `/etc/digicert/`):**

```bash
cmake -DENABLE_NANOROOT=ON -DBUILD_SAMPLES=ON -B build -S .
```

**Build with secure path enabled:**

```bash
cmake -DENABLE_NANOROOT=ON -DBUILD_SAMPLES=ON -DSECURE_PATH=/path/to/secure/directory -B build -S .
```

> **⚠️ Caution:** Before recompiling with the `SECURE_PATH` flag enabled, delete the existing `build/` directory to ensure a clean build:
> ```bash
> rm -rf build/
> ```
> This prevents configuration conflicts and ensures all components are rebuilt with the new secure path settings.

**Parameters and Flags:**

| Parameter           | Type  | Required | Description                                                              |
|---------------------|-------|----------|--------------------------------------------------------------------------|
| `-DENABLE_NANOROOT` | Flag  | Yes      | Enables NanoROOT SMP library compilation (value: `ON` or `OFF`)          |
| `-DBUILD_SAMPLES`   | Flag  | Yes      | Enables building of sample applications (value: `ON` or `OFF`)           |
| `-DSECURE_PATH`     | Input | Yes      | Absolute path to secure directory for credential files                   |
| `-B`                | Input | Yes      | Build directory path (typically `build`)                                 |
| `-S`                | Input | Yes      | Source directory path (`.` for current directory)                        |

### 2. Build the Project

```bash
cmake --build build
```

**Parameters and Flags:**

| Parameter  | Type  | Required | Description                                                              |
|------------|-------|----------|--------------------------------------------------------------------------|
| `--build`  | Input | Yes      | Path to build directory (must match directory from configure step)       |

**Output Files:**
- **Binary**: `samples/bin/tap_nanoroot_example` (executable application)
- **Shared Libraries**: `lib/libsmpnanoroot.so` and dependencies (`.so` format)

---

## 🔧 Configuration

### Configuration File

NanoROOT requires a configuration file. A sample is provided at [`samples/nanoroot/config/nanoroot_smp.conf`](config/nanoroot_smp.conf).

**Key configuration fields:**

- `providertype`: Must be set to `15` for NanoROOT SMP provider
- `credfile`: Path to the credential file
  - Without `SECURE_PATH`: Relative to `/etc/digicert/`
  - With `SECURE_PATH`: Relative to the specified secure path

### Credential File

A sample credential file is provided at [`samples/nanoroot/config/default-fingerprint.json`](config/default-fingerprint.json).

**Note:** This is a sample template for demonstration. You must prepare your own device fingerprint configuration file tailored to your hardware. See [Device Fingerprint File Format](#device-fingerprint-file-format) section for details.

This file contains device fingerprint information used for cryptographic key derivation.

### Environment Setup

**Step 1: Create Configuration Directory and Copy Files**

For standard build (without `SECURE_PATH`), create the `/etc/digicert/` directory, copy configuration files, and set appropriate permissions:

```bash
# Create directory
sudo mkdir -p /etc/digicert/

# Set ownership to current user
sudo chown -R $USER:$USER /etc/digicert/

# Copy required configuration files to /etc/digicert/
cp samples/nanoroot/config/default-fingerprint.json /etc/digicert/
cp samples/nanoroot/config/get_cpuid.sh /etc/digicert/
cp samples/nanoroot/config/get_mac_address.sh /etc/digicert/
cp samples/nanoroot/config/nanoroot_smp.conf /etc/digicert/

# Set directory permissions (owner only: read, write, execute)
chmod 700 /etc/digicert/

# Set configuration file permissions (owner only: read, write)
chmod 600 /etc/digicert/*.conf
chmod 600 /etc/digicert/*.json

# Set script permissions (owner only: read, write, execute)
chmod 700 /etc/digicert/*.sh
```

**Step 2: Set Environment Variables**

**When using the sample fingerprint file**, set the required environment variables using the provided script:

```bash
source samples/nanoroot/config/setFingerPrintValues.sh
```

This script sets fingerprint-related environment variables referenced in the sample [`default-fingerprint.json`](config/default-fingerprint.json).

**Note:** If you create your own custom device fingerprint configuration file, you must source or set the environment variables according to your specific configuration. Refer to [Device Fingerprint File Format](#device-fingerprint-file-format) section for details on configuring environment variables for custom fingerprint files.

### Editing Default Fingerprint Configuration

The [`default-fingerprint.json`](config/default-fingerprint.json) file contains device fingerprint information used for cryptographic key derivation. This file must be edited to match your system configuration.

**Required Edits:**

1. **Network Interface Name**: Update the network interface name to match your system (e.g., `eth0`, `eno1`, `wlan0`)


   Find your network interface name
   ```bash
   ip link show
   ```

2. **Helper Script Paths**: Both standard build and custom secure path use absolute paths to helper scripts.
   - **Standard build**: `/etc/digicert/get_cpuid.sh` and `/etc/digicert/get_mac_address.sh`
   - **Custom secure path**: `/opt/digicert/get_cpuid.sh` and `/opt/digicert/get_mac_address.sh`

**Example editing command:**

For standard build
```bash
vim /etc/digicert/default-fingerprint.json
```

For custom secure path
```bash
vim /opt/digicert/default-fingerprint.json
```

**Example JSON configuration:**
```json
{
          "attribute_name": "MAC ADDRESS",
          "attribute_value": {
              "type": "program",
              "path": "/etc/digicert/get_mac_address.sh",
              "argument": "eth0"
          }
}
```

**Note:** Update the paths and network interface name according to your configuration directory and system.

---

### Device Fingerprint File Format

The device fingerprint configuration file is required for collecting device attributes used for hardware-based cryptographic key derivation. The NanoROOT binary reads this file to gather the necessary device attributes and incorporates them into the cryptographic operations. A sample file is provided at [`samples/nanoroot/config/default-fingerprint.json`](config/default-fingerprint.json).

#### Structure Overview

The file contains an `attributes` array where each object represents a specific attribute of the device:

```json
{
  "attributes": [
    {
      "attribute_name": "longitude",
      "attribute_value": {
        "type": "ENV",
        "variable_name": "LONGITUDE"
      }
    },
    {
      "attribute_name": "tpm2id",
      "attribute_value": {
        "type": "program",
        "path": "/usr/bin/get_tpm2id",
        "argument": "--verbose"
      }
    },
    {
      "attribute_names": ["cpu_id", "hardware_model"],
      "attribute_value": {
        "type": "program",
        "path": "/usr/bin/get_device_info",
        "output_format": "JSON",
        "argument": "--all"
      }
    }
  ]
}
```

#### Key Structure Elements

| Field              | Type   | Required | Description                                                    |
|-------------------|--------|----------|----------------------------------------------------------------|
| `attributes`      | Array  | Yes      | Main array containing all attribute objects                    |
| `attribute_name`  | String | Yes*     | Name of a single attribute (e.g., "MAC Address", "Serial Number") |
| `attribute_names` | Array  | Yes*     | Array of multiple attribute names when using JSON output       |
| `attribute_value` | Object | Yes      | Specifies how to retrieve the attribute value                  |
| `type`            | String | Yes      | Retrieval method: `"ENV"` or `"program"`                       |

*Note: Use either `attribute_name` (for single attribute) or `attribute_names` (for multiple attributes from JSON output)

#### Attribute Value Types

**1. Environment Variable Type (`ENV`)**

Retrieves the value from an environment variable. This method is preferred for sensitive data to avoid hardcoding values in the JSON file.

```json
{
  "attribute_name": "serial_number",
  "attribute_value": {
    "type": "ENV",
    "variable_name": "SERIAL_NUMBER"
  }
}
```

**Fields:**
- `type`: Must be `"ENV"`
- `variable_name`: Name of the environment variable to read

**2. Program Execution Type (`program`)**

Executes a helper script or program to dynamically retrieve system information.

**Single Attribute Output:**

```json
{
  "attribute_name": "serial_number",
  "attribute_value": {
    "type": "program",
    "path": "/etc/digicert/serial_number.sh",
    "argument": "--verbose"
  }
}
```

**Multiple Attributes from JSON Output:**

```json
{
  "attribute_names": ["cpu_id", "hardware_model"],
  "attribute_value": {
    "type": "program",
    "path": "/usr/bin/get_device_info",
    "output_format": "JSON",
    "argument": "--all"
  }
}
```

**Fields:**
- `type`: Must be `"program"`
- `path`: Absolute path to the executable program or script
- `argument`: (Optional) Command-line arguments to pass to the program
- `output_format`: (Optional) Set to `"JSON"` when the program outputs multiple attributes in JSON format

#### Path Requirements

**Standard Build (without SECURE_PATH):**
- Helper scripts typically reside in `/etc/digicert/`
- Example: `/etc/digicert/get_mac_address.sh`

**SECURE_PATH Enabled:**
- All paths must use **absolute paths** within the SECURE_PATH directory
- Example: `/opt/digicert/get_mac_address.sh`

#### Setting Environment Variables

When using `ENV` type attributes, set the corresponding environment variables:

```bash
# Set environment variables for the current session
export HARDWARE_MODEL=sku_007
export SERIAL_NUMBER=sn-123
export LONGITUDE=103.8501
export LATITUDE=1.2897
export SECURE_ELEMENT=52c93637f731203b7cc7ea4faeed81edc94d4317004171d9c149dc49363de0de
```

Alternatively, use the provided script to set fingerprint values:

```bash
source samples/nanoroot/config/setFingerPrintValues.sh
```

#### Creating Helper Scripts

Helper scripts must start with a shebang line (e.g., `#!/bin/bash`) and should output the attribute value to stdout. The script output is captured and used as the attribute value.

**Example: Serial Number Script**

```bash
#!/bin/bash
set -e
echo -n "SN-123"
```

**Example: MAC Address Script**

```bash
#!/bin/bash
set -e
INTERFACE=$1
ip link show $INTERFACE | awk '/link\/ether/ {print $2}'
```

Make sure scripts are executable:

```bash
chmod +x /etc/digicert/get_mac_address.sh
chmod +x /etc/digicert/get_cpuid.sh
```

#### Best Practices

1. **Use Environment Variables for Sensitive Data**: Avoid hardcoding sensitive values directly in the JSON file
2. **Validate Helper Scripts**: Test scripts independently to ensure they produce expected output:
   ```bash
   /etc/digicert/get_mac_address.sh eth0
   /etc/digicert/get_cpuid.sh
   ```
3. **Use Absolute Paths**: Always use absolute paths for helper scripts
4. **Consistent Attribute Names**: Maintain the same set of attributes across all device configurations
5. **Error Handling in Scripts**: Use `set -e` in scripts to exit on errors and provide clear error messages
6. **JSON Output Validation**: When using `output_format: "JSON"`, ensure the script outputs valid JSON
7. **Automate Configuration**: Create setup scripts to automate environment variable configuration and file updates


#### Troubleshooting

**Environment Variable Not Set:**

```bash
# Check if variables are set
env | grep -E "SERIAL_NUMBER|HARDWARE_MODEL|LONGITUDE|LATITUDE"

# If missing, source the setup script
source samples/nanoroot/config/setFingerPrintValues.sh
```

**Script Execution Fails:**

```bash
# Check script permissions
ls -l /etc/digicert/*.sh

# Make executable if needed
chmod +x /etc/digicert/get_cpuid.sh
chmod +x /etc/digicert/get_mac_address.sh

# Test script output
/etc/digicert/get_mac_address.sh eth0
```

**Path Validation Error (SECURE_PATH):**

```bash
# Verify all paths are within SECURE_PATH
grep -E "\"path\":" /opt/digicert/default-fingerprint.json

# Ensure scripts exist in secure directory
ls -la /opt/digicert/get_*.sh
```

**Invalid Network Interface:**

```bash
# List available interfaces
ip link show

# Update JSON with correct interface name
vim /etc/digicert/default-fingerprint.json
```

---

### SECURE_PATH Deep Dive

The `SECURE_PATH` functionality provides enhanced security by restricting all file operations to a designated secure directory. This section provides a comprehensive breakdown of how SECURE_PATH manages directory structures, maintenance scripts, and system executables.

#### 🔐 Overview

When `SECURE_PATH` is enabled during compilation (e.g., `-DSECURE_PATH=/opt/digicert/`), the NanoROOT SMP restricts all file system access to the specified directory, preventing unauthorized access to sensitive cryptographic credentials and configuration files.

#### 📁 Directory Structure Management

**Note:** The examples below use `/opt/digicert/` as the SECURE_PATH directory to demonstrate the feature. You can use any secure directory path of your choice when configuring with `-DSECURE_PATH=/your/custom/path/`.

**Input Directory Structure:**

The SECURE_PATH directory must contain all required configuration and credential files:

```
/opt/digicert/                          # Example SECURE_PATH directory
├── nanoroot_smp.conf                   # Configuration file (INPUT)
├── default-fingerprint.json            # Credential/fingerprint file (INPUT)
├── get_cpuid.sh                        # CPU ID helper script (INPUT/EXECUTABLE)
├── get_mac_address.sh                  # MAC address helper script (INPUT/EXECUTABLE)
└── [application-specific files]        # Additional inputs as needed
```

**Output Directory Structure:**

All cryptographic outputs are written to the same SECURE_PATH directory:

```
/opt/digicert/                          # Example SECURE_PATH directory
├── [encrypted files]                   # Seal operation outputs (.bin, .enc)
├── [signature files]                   # Sign operation outputs (.bin, .sig)
├── [public key files]                  # Auto-generated public keys (.pem)
├── [decrypted files]                   # Unseal operation outputs
└── [application logs]                  # Optional: operation logs
```

**Access Control:**

| Operation Type | Input Location         | Output Location        | Path Restriction |
|----------------|------------------------|------------------------|------------------|
| Seal           | SECURE_PATH            | SECURE_PATH            | Enforced         |
| Unseal         | SECURE_PATH            | SECURE_PATH            | Enforced         |
| Sign           | SECURE_PATH            | SECURE_PATH            | Enforced         |
| Verify         | SECURE_PATH            | SECURE_PATH            | Enforced         |
| Config Read    | SECURE_PATH            | N/A                    | Enforced         |

**Directory Permissions:**

```bash
# Recommended permissions for SECURE_PATH directory
sudo mkdir -p /opt/digicert/
sudo cp -rf samples/nanoroot/config/* /opt/digicert/
sudo chown -R $USER:$USER /opt/digicert/
chmod 700 /opt/digicert/                # Owner only: read, write, execute
chmod 600 /opt/digicert/*.conf          # Owner only: read, write
chmod 600 /opt/digicert/*.json          # Owner only: read, write
chmod 700 /opt/digicert/*.sh            # Owner only: read, write, execute
```

#### 🛠️ Maintenance Scripts

**Helper Scripts Overview:**

SECURE_PATH requires helper scripts to extract device-specific fingerprint data. These scripts must be located within the SECURE_PATH directory and use **absolute paths** in the credential file.

**Required Scripts:**

1. **get_cpuid.sh** - Extracts CPU identification
   - **Type**: Executable bash script
   - **Location**: `${SECURE_PATH}/get_cpuid.sh`
   - **Purpose**: Retrieves unique CPU identifier for hardware fingerprinting
   - **Output**: CPU ID string (stdout)
   - **Usage in credential file**:
     ```json
     {
       "attribute_name": "CPU ID",
       "attribute_value": {
         "type": "program",
         "path": "/opt/digicert/get_cpuid.sh",
         "argument": ""
       }
     }
     ```

2. **get_mac_address.sh** - Extracts network interface MAC address
   - **Type**: Executable bash script
   - **Location**: `${SECURE_PATH}/get_mac_address.sh`
   - **Purpose**: Retrieves MAC address for hardware fingerprinting
   - **Input Parameter**: Network interface name (e.g., `eth0`, `eno1`)
   - **Output**: MAC address string (stdout)
   - **Usage in credential file**:
     ```json
     {
       "attribute_name": "MAC ADDRESS",
       "attribute_value": {
         "type": "program",
         "path": "/opt/digicert/get_mac_address.sh",
         "argument": "eth0"
       }
     }
     ```

**Script Deployment:**

```bash
# Copy helper scripts to SECURE_PATH
cp samples/nanoroot/config/get_cpuid.sh ${SECURE_PATH}/
cp samples/nanoroot/config/get_mac_address.sh ${SECURE_PATH}/

# Set executable permissions
chmod +x ${SECURE_PATH}/get_cpuid.sh
chmod +x ${SECURE_PATH}/get_mac_address.sh

# Verify scripts are executable
ls -l ${SECURE_PATH}/*.sh
```

**Script Execution Flow:**

```
NanoROOT Application
        ↓
Reads default-fingerprint.json
        ↓
Identifies "program" type attributes
        ↓
Executes helper scripts (get_cpuid.sh, get_mac_address.sh)
        ↓
Captures stdout output
        ↓
Combines with other fingerprint attributes
        ↓
Derives cryptographic keys
```

**Maintenance Considerations:**

- **Updates**: When updating scripts, ensure they remain within SECURE_PATH
- **Testing**: Test scripts independently before integration:
  ```bash
  ${SECURE_PATH}/get_cpuid.sh
  ${SECURE_PATH}/get_mac_address.sh eth0
  ```
- **Error Handling**: Scripts should return non-zero exit codes on failure
- **Logging**: Consider adding logging to scripts for debugging (output to SECURE_PATH)

#### ⚙️ System Executables

**Application Binary:**

The compiled NanoROOT TAP example executable remains in the standard build output location:
- **Path**: `samples/bin/tap_nanoroot_example`
- **Type**: Executable binary
- **SECURE_PATH Impact**: The executable itself is **not** restricted to SECURE_PATH, but all file operations it performs are restricted

**Shared Libraries:**

NanoROOT shared libraries are built with SECURE_PATH compiled in:
- **Path**: `lib/libsmpnanoroot.so` (and dependencies)
- **Type**: Shared object libraries (`.so` files)
- **SECURE_PATH Behavior**: 
  - Path is **hardcoded** at compile time
  - Cannot be overridden at runtime
  - All file I/O operations are restricted to the compiled SECURE_PATH

**Library Loading:**

```bash
# Set LD_LIBRARY_PATH to locate shared libraries
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH

# Verify library can be found
ldd samples/bin/tap_nanoroot_example | grep libsmpnanoroot
```

**Execution Model:**

```
User executes: ./samples/bin/tap_nanoroot_example --config /opt/digicert/nanoroot_smp.conf ...
        ↓
Application loads: lib/libsmpnanoroot.so (SECURE_PATH=/opt/digicert/ compiled in)
        ↓
Library validates: All paths must be within /opt/digicert/
        ↓
        ├─ Config file: /opt/digicert/nanoroot_smp.conf ✓
        ├─ Credential file: /opt/digicert/default-fingerprint.json ✓
        ├─ Input file: /opt/digicert/plaintext.txt ✓
        ├─ Output file: /opt/digicert/encrypted.bin ✓
        └─ Helper scripts: /opt/digicert/*.sh ✓
        ↓
Operations succeed if all paths are within SECURE_PATH
```

**Security Enforcement:**

| Attempt to Access                     | SECURE_PATH Enabled | Result          |
|---------------------------------------|---------------------|-----------------|
| `/opt/digicert/file.txt`             | `/opt/digicert/`    | ✅ Allowed      |
| `/opt/digicert/subdir/file.txt`      | `/opt/digicert/`    | ✅ Allowed      |
| `/etc/digicert/file.txt`             | `/opt/digicert/`    | ❌ Denied       |
| `/home/user/file.txt`                | `/opt/digicert/`    | ❌ Denied       |
| `../file.txt` (outside SECURE_PATH)  | `/opt/digicert/`    | ❌ Denied       |

**Recompilation Requirements:**

To change the SECURE_PATH:
1. Delete the existing build directory: `rm -rf build/`
2. Reconfigure with new SECURE_PATH: `cmake -DENABLE_NANOROOT=ON -DSECURE_PATH=/new/path/ -B build -S .`
3. Rebuild: `cmake --build build`
4. Deploy configuration files to the new SECURE_PATH


**Verification:**

```bash
# Verify SECURE_PATH is compiled into the library
strings lib/libsmpnanoroot.so | grep -i "secure\|/opt/digicert"

# Test with files outside SECURE_PATH (should fail)
./samples/bin/tap_nanoroot_example \
    --config /tmp/nanoroot_smp.conf \
    --infile /tmp/test.txt \
    --outfile /tmp/output.bin \
    --seal

# Test with files inside SECURE_PATH (should succeed)
./samples/bin/tap_nanoroot_example \
    --config /opt/digicert/nanoroot_smp.conf \
    --infile /opt/digicert/test.txt \
    --outfile /opt/digicert/output.bin \
    --seal
```

---

## 🚀 Running the Example

### Set Library Path

```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
```

**Parameters and Flags:**

| Parameter           | Type  | Required | Description                                                              |
|---------------------|-------|----------|--------------------------------------------------------------------------|
| `LD_LIBRARY_PATH`   | Input | Yes      | Environment variable pointing to shared library directories              |
| `lib/`              | Input | Yes      | Path to directory containing NanoROOT shared libraries                   |

**Purpose:** Configures the dynamic linker to locate NanoROOT shared libraries at runtime.

### Prepare `/etc/digicert/` for Standard Build (without secure path)

```bash
# Create directory and change ownership to current user
sudo mkdir -p /etc/digicert/
sudo chown -R $USER:$USER /etc/digicert/

# Copy required configuration files to /etc/digicert/
cp samples/nanoroot/config/default-fingerprint.json /etc/digicert/
cp samples/nanoroot/config/get_cpuid.sh /etc/digicert/
cp samples/nanoroot/config/get_mac_address.sh /etc/digicert/
cp samples/nanoroot/config/nanoroot_smp.conf /etc/digicert/

# Make helper scripts executable
chmod +x /etc/digicert/get_cpuid.sh
chmod +x /etc/digicert/get_mac_address.sh
```

**Note:** See [Editing Default Fingerprint Configuration](#editing-default-fingerprint-configuration) section to configure the network interface and other settings.

---

## 🔐 Cryptographic Operations

### Seal Operation

The seal operation encrypts data using device-specific credentials, binding the encrypted data to the hardware fingerprint.

**Prerequisites:**
- Configuration files prepared in `/etc/digicert/`
- Environment variables set (run `source samples/nanoroot/config/setFingerPrintValues.sh`)
- Library path configured (`export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH`)

**Command:**
```bash
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile <plaintext_input_file> \
    --outfile <encrypted_output_file> \
    --seal \
    --passphrase <password>
```

**Example:**
```bash
# Create test data
echo "Confidential data" > plaintext.txt

# Seal the data
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile plaintext.txt \
    --outfile encrypted.bin \
    --seal \
    --passphrase mySecretPassword
```

**Parameters and Flags:**

| Parameter      | Type   | Required | Description                                                                 |
|----------------|--------|----------|-----------------------------------------------------------------------------|
| `--config`     | Input  | Yes      | Path to NanoROOT configuration file (`.conf` format)                        |
| `--infile`     | Input  | Yes      | Plaintext data file to encrypt (any file type, text or binary)              |
| `--outfile`    | Output | Yes      | Encrypted output file (binary format, typically `.bin` or `.enc`)           |
| `--seal`       | Flag   | Yes      | Operation mode flag indicating seal/encryption operation                    |
| `--passphrase` | Input  | No       | Password string for encryption (optional, used to derive encryption key)    |

**File Type Details:**
- **Input (`--infile`)**: Any file type (text, binary, documents, etc.)
- **Output (`--outfile`)**: Binary encrypted file, device-specific format
- **Config (`--config`)**: Text configuration file in NanoROOT `.conf` format

---

### Unseal Operation

The unseal operation decrypts previously sealed data. This operation will only succeed on the same device where the data was sealed.

**Prerequisites:**
- Configuration files prepared in `/etc/digicert/`
- Environment variables set (run `source samples/nanoroot/config/setFingerPrintValues.sh`)
- Library path configured (`export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH`)
- Encrypted file created by seal operation

**Command:**
```bash
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile <encrypted_input_file> \
    --outfile <decrypted_output_file> \
    --unseal \
    --passphrase <password>
```

**Example:**
```bash
# Unseal the data
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile encrypted.bin \
    --outfile decrypted.txt \
    --unseal \
    --passphrase mySecretPassword
```

Verify the data integrity
```bash
diff plaintext.txt decrypted.txt
```

**Parameters and Flags:**

| Parameter      | Type   | Required | Description                                                                 |
|----------------|--------|----------|-----------------------------------------------------------------------------|
| `--config`     | Input  | Yes      | Path to NanoROOT configuration file (`.conf` format)                        |
| `--infile`     | Input  | Yes      | Encrypted file to decrypt (binary format, created by seal operation)        |
| `--outfile`    | Output | Yes      | Decrypted plaintext output file (matches original file type)                |
| `--unseal`     | Flag   | Yes      | Operation mode flag indicating unseal/decryption operation                  |
| `--passphrase` | Input  | No       | Password string used during seal (optional, must match if provided)         |

**File Type Details:**
- **Input (`--infile`)**: Binary encrypted file (`.bin`, `.enc`) created by seal operation
- **Output (`--outfile`)**: Plaintext file matching the original unsealed data format
- **Config (`--config`)**: Text configuration file in NanoROOT `.conf` format

**Important:** Unseal operation requires the same device fingerprint and passphrase used during seal operation.

---

### Sign Operation

The sign operation generates a hardware-rooted digital signature using RSA, ECC, or Post-Quantum (MLDSA) algorithms.

**Prerequisites:**
- Configuration files prepared in `/etc/digicert/`
- Environment variables set (run `source samples/nanoroot/config/setFingerPrintValues.sh`)
- Library path configured (`export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH`)

**Mandatory Setup (Before Every Sign Operation):**

```bash
# Source environment variables
source samples/nanoroot/config/setFingerPrintValues.sh

# Set library path
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
```

**Command:**
```bash
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile <data_to_sign> \
    --sigfile <signature_file> \
    --pubKey <public_key_output_file> \
    --keyId <key_identifier> \
    --signBuffer \
    --hashType <hash_algorithm>
```

**Example (RSA-2048):**
```bash
# Set up environment (mandatory)
source samples/nanoroot/config/setFingerPrintValues.sh
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH

# Create test document
echo "Document to sign" > document.txt

# Generate RSA-2048 signature
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile document.txt \
    --sigfile signature.bin \
    --pubKey rsa_public_key.pem \
    --keyId 0x100000002 \
    --signBuffer \
    --hashType 1
```

**Example (MLDSA-87 Post-Quantum):**
```bash
# Set up environment (mandatory)
source samples/nanoroot/config/setFingerPrintValues.sh
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH

# Generate MLDSA-87 signature
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile document.txt \
    --sigfile mldsa87_signature.bin \
    --pubKey mldsa87_public_key.pem \
    --keyId 0x200000003 \
    --signBuffer \
    --hashType 0
```

**Parameters and Flags:**

| Parameter      | Type   | Required | Description                                                                 |
|----------------|--------|----------|-----------------------------------------------------------------------------|
| `--config`     | Input  | Yes      | Path to NanoROOT configuration file (`.conf` format)                        |
| `--infile`     | Input  | Yes      | Data file to sign (any file type, text or binary)                           |
| `--sigfile`    | Output | Yes      | Digital signature output file (binary format, typically `.bin` or `.sig`)   |
| `--pubKey`     | Output | Yes      | Public key output file (PEM format, `.pem` extension, auto-generated)       |
| `--keyId`      | Input  | Yes      | Hexadecimal key identifier (required for sign/verify operations). Min: 9 chars, Max: 17 chars. Specifies cryptographic algorithm: RSA 2K-8K (`0x10000000X`), MLDSA (`0x20000000X`), ECC P-256/384/521 (`0x30000000X`). See supported algorithms table. |\n| `--signBuffer` | Flag   | Yes      | Operation mode flag indicating signature generation operation               |
| `--hashType`   | Input  | Yes      | Hash algorithm code: `0` (none), `1` (SHA-256), `2` (SHA-512)              |

**File Type Details:**
- **Input (`--infile`)**: Any file type to be signed (documents, executables, data files)
- **Output (`--sigfile`)**: Binary signature file (`.bin`, `.sig`), algorithm-specific format
- **Output (`--pubKey`)**: PEM-encoded public key file (`.pem`), base64 text format
- **Config (`--config`)**: Text configuration file in NanoROOT `.conf` format

**Algorithm Selection:**
- Use `--keyId` to select RSA (2048-8192 bit), ECC (P-256/384/521), or MLDSA (44/65/87)
- MLDSA algorithms require `--hashType 0` (no pre-hashing)
- RSA/ECC algorithms require appropriate hash type based on key size

**KeyID Details:**

The `--keyId` parameter is a hexadecimal key identifier with the following characteristics:
- **Format**: Hexadecimal string starting with `0x`
- **Length**: Minimum 9 characters, Maximum 17 characters (including `0x` prefix)
- **Purpose**: Identifies the cryptographic algorithm and key size for signature operations
- **Validation**: Application validates the length is between MIN_KEY_ID_LEN (9) and MAX_KEY_ID_LEN (18)

**Supported Key Identifiers:**

The following hexadecimal key identifiers are supported (as defined in `tap_nanoroot_example.c`):

| Algorithm  | Key Size | Key ID        | Hash Type | Description |
|------------|----------|---------------|-----------|-------------|
| RSA        | 2048-bit | `0x100000002` | `1`       | RSA 2K with SHA-256 |
| RSA        | 3072-bit | `0x100000003` | `1`       | RSA 3K with SHA-256 |
| RSA        | 4096-bit | `0x100000004` | `2`       | RSA 4K with SHA-512 |
| RSA        | 8192-bit | `0x100000005` | `2`       | RSA 8K with SHA-512 |
| ECC P-256  | 256-bit  | `0x300000001` | `1`       | P-256 curve with SHA-256 |
| ECC P-384  | 384-bit  | `0x300000002` | `1`       | P-384 curve with SHA-256 |
| ECC P-521  | 521-bit  | `0x300000003` | `2`       | P-521 curve with SHA-512 |
| MLDSA-44   | -        | `0x200000001` | `0`       | MLDSA44 (Post-Quantum) |
| MLDSA-65   | -        | `0x200000002` | `0`       | MLDSA65 (Post-Quantum) |
| MLDSA-87   | -        | `0x200000003` | `0`       | MLDSA87 (Post-Quantum) |

**Supported Hash Algorithms:**

- `0` - No pre-hashing (used for MLDSA algorithms)
- `1` - SHA-256
- `2` - SHA-512

---

### Verify Operation

The verify operation validates a digital signature against the original data and public key.

**Prerequisites:**
- Configuration files prepared in `/etc/digicert/`
- Environment variables set (run `source samples/nanoroot/config/setFingerPrintValues.sh`)
- Library path configured (`export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH`)
- Signature file and public key generated by sign operation

**Mandatory Setup (Before Every Verify Operation):**

```bash
# Source environment variables
source samples/nanoroot/config/setFingerPrintValues.sh

# Set library path
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
```

**Command:**
```bash
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile <data_to_verify> \
    --sigfile <signature_file> \
    --pubKey <public_key_file> \
    --keyId <key_identifier> \
    --verify \
    --hashType <hash_algorithm>
```

**Example (RSA-2048):**
```bash
# Set up environment (mandatory)
source samples/nanoroot/config/setFingerPrintValues.sh
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH

# Verify the signature
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile document.txt \
    --sigfile signature.bin \
    --pubKey rsa_public_key.pem \
    --keyId 0x100000002 \
    --verify \
    --hashType 1
```

**Example (MLDSA-87 Post-Quantum):**
```bash
# Set up environment (mandatory)
source samples/nanoroot/config/setFingerPrintValues.sh
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH

# Verify MLDSA-87 signature
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile document.txt \
    --sigfile mldsa87_signature.bin \
    --pubKey mldsa87_public_key.pem \
    --keyId 0x200000003 \
    --verify \
    --hashType 0
```

**Expected Output:**
```
SUCCESS! Signature verification PASS.
```

**Parameters and Flags:**

| Parameter    | Type   | Required | Description                                                                 |
|--------------|--------|----------|-----------------------------------------------------------------------------|
| `--config`   | Input  | Yes      | Path to NanoROOT configuration file (`.conf` format)                        |
| `--infile`   | Input  | Yes      | Original data file that was signed (must be identical to signed data)       |
| `--sigfile`  | Input  | Yes      | Signature file to verify (binary format, from sign operation)               |
| `--pubKey`   | Input  | Yes      | Public key file in PEM format (`.pem`, from sign operation)                 |
| `--keyId`    | Input  | Yes      | Hexadecimal key identifier (must match signing algorithm). Same format as used in sign: Min 9 chars, Max 17 chars. Must match the keyId used during signing. |
| `--verify`   | Flag   | Yes      | Operation mode flag indicating signature verification operation             |
| `--hashType` | Input  | Yes      | Hash algorithm code (must match the one used during signing)                |

**File Type Details:**
- **Input (`--infile`)**: Original data file (any type, must match signed data exactly)
- **Input (`--sigfile`)**: Binary signature file (`.bin`, `.sig`) from sign operation
- **Input (`--pubKey`)**: PEM-encoded public key file (`.pem`) from sign operation
- **Config (`--config`)**: Text configuration file in NanoROOT `.conf` format

**Verification Requirements:**
- All parameters (`--keyId`, `--hashType`) must match those used during signing
- Input data file must be byte-identical to the original signed data
- Public key must correspond to the private key used for signing
- Verification succeeds only if signature is valid and all parameters match

---

## 🧪 Running Tests

A comprehensive test suite is available at [`src/smp/smp_nanoroot/test/run_tap_nanoroot_test.sh`](../../src/smp/smp_nanoroot/test/run_tap_nanoroot_test.sh).

### Run All Tests

```bash
cd <repository_root>
./src/smp/smp_nanoroot/test/run_tap_nanoroot_test.sh
```

### Run Specific Test Suites

```bash
# Run only seal/unseal tests
./src/smp/smp_nanoroot/test/run_tap_nanoroot_test.sh --seal

# Run only RSA signature tests (2K, 3K, 4K)
./src/smp/smp_nanoroot/test/run_tap_nanoroot_test.sh --rsa

# Run RSA 8K signature tests (must be explicit)
./src/smp/smp_nanoroot/test/run_tap_nanoroot_test.sh --rsa8k

# Run Post-Quantum MLDSA tests
./src/smp/smp_nanoroot/test/run_tap_nanoroot_test.sh --mldsa

# Run ECC signature tests
./src/smp/smp_nanoroot/test/run_tap_nanoroot_test.sh --ecc

# Run with verbose output
./src/smp/smp_nanoroot/test/run_tap_nanoroot_test.sh --verbose

# Clean up test artifacts after completion
./src/smp/smp_nanoroot/test/run_tap_nanoroot_test.sh --cleanup
```

**Parameters and Flags:**

| Parameter    | Type | Required | Description                                                              |
|--------------|------|----------|--------------------------------------------------------------------------|
| `--seal`     | Flag | No       | Run only seal/unseal encryption/decryption tests                         |
| `--rsa`      | Flag | No       | Run RSA signature tests (2048, 3072, 4096-bit key sizes)                 |
| `--rsa8k`    | Flag | No       | Run RSA 8192-bit signature tests (explicit, not included in `--rsa`)     |
| `--mldsa`    | Flag | No       | Run Post-Quantum MLDSA signature tests (MLDSA-44, -65, -87)              |
| `--ecc`      | Flag | No       | Run ECC signature tests (P-256, P-384, P-521 curves)                     |
| `--verbose`  | Flag | No       | Enable verbose output showing detailed test execution information        |
| `--cleanup`  | Flag | No       | Remove test artifacts (temporary files, signatures, keys) after tests    |

**File Type Details:**
- **Input Script**: `run_tap_nanoroot_test.sh` (bash script)
- **Output**: Console test results, temporary test files (cleaned with `--cleanup`)

**Note:** The test script must be run from the repository root directory.

---

## 📚 Example Usage Scenarios

### Example 1: Seal and Unseal Data

```bash
# Set environment variables
source samples/nanoroot/config/setFingerPrintValues.sh
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH

# Create test data
echo "Confidential data" > plaintext.txt

# Seal the data
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile plaintext.txt \
    --outfile encrypted.bin \
    --seal \
    --passphrase mySecretPassword

# Unseal the data
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile encrypted.bin \
    --outfile decrypted.txt \
    --unseal \
    --passphrase mySecretPassword

# Verify the data integrity
diff plaintext.txt decrypted.txt
```

### Example 2: RSA Signature Generation and Verification

```bash
# Create test document
echo "Document to sign" > document.txt

# Generate RSA-2048 signature
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile document.txt \
    --sigfile signature.bin \
    --pubKey rsa_public_key.pem \
    --keyId 0x100000002 \
    --signBuffer \
    --hashType 1

# Verify the signature
./samples/bin/tap_nanoroot_example \
    --config /etc/digicert/nanoroot_smp.conf \
    --infile document.txt \
    --sigfile signature.bin \
    --pubKey rsa_public_key.pem \
    --keyId 0x100000002 \
    --verify \
    --hashType 1
```

### Example 3: MLDSA-87 Signature with Custom Secure Path

This example demonstrates Post-Quantum cryptographic operations using the MLDSA-87 algorithm with a custom secure path configuration.

**Prerequisites:**
- Custom secure directory: `/opt/digicert/`
- Required files: configuration, credential, and helper scripts
- MLDSA-87 algorithm support enabled

#### Step 1: Configure and Build with Secure Path

```bash
#remove the build directory
rm -rf build

# Configure NanoROOT SMP with secure path
cmake -DENABLE_NANOROOT=ON \
      -DSECURE_PATH=/opt/digicert/ \
      -DBUILD_SAMPLES=ON \
      -B build \
      -S .

# Build the project
cmake --build build
```

#### Step 2: Prepare Secure Directory

```bash
# Create the secure directory and change ownership to current user
sudo mkdir -p /opt/digicert/
sudo chown -R $USER:$USER /opt/digicert/

# Copy required configuration files
cp samples/nanoroot/config/default-fingerprint.json /opt/digicert/
cp samples/nanoroot/config/get_cpuid.sh /opt/digicert/
cp samples/nanoroot/config/get_mac_address.sh /opt/digicert/
cp samples/nanoroot/config/nanoroot_smp.conf /opt/digicert/

# Make helper scripts executable
chmod +x /opt/digicert/get_cpuid.sh
chmod +x /opt/digicert/get_mac_address.sh
```

**Note:** See [Editing Default Fingerprint Configuration](#editing-default-fingerprint-configuration) section to configure the network interface and update helper script paths to use absolute paths.

#### Step 3: Set Environment Variables

```bash
# Set library path
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH

# Source fingerprint environment variables
source samples/nanoroot/config/setFingerPrintValues.sh
```

#### Step 4: Create Test Data

```bash
# Create test document
echo "Document to sign with MLDSA-87" > /opt/digicert/document.txt
```

#### Step 5: Generate MLDSA-87 Signature

```bash
./samples/bin/tap_nanoroot_example \
    --config /opt/digicert/nanoroot_smp.conf \
    --infile /opt/digicert/document.txt \
    --sigfile /opt/digicert/mldsa87_signature.bin \
    --pubKey /opt/digicert/mldsa87_public_key.pem \
    --keyId 0x200000003 \
    --signBuffer \
    --hashType 0
```

**Parameters:**
- `--keyId 0x200000003`: MLDSA-87 algorithm identifier
- `--hashType 0`: No pre-hashing (MLDSA performs internal hashing)
- Public key is automatically generated and saved to the specified path

#### Step 6: Verify the Signature

```bash
./samples/bin/tap_nanoroot_example \
    --config /opt/digicert/nanoroot_smp.conf \
    --infile /opt/digicert/document.txt \
    --sigfile /opt/digicert/mldsa87_signature.bin \
    --pubKey /opt/digicert/mldsa87_public_key.pem \
    --keyId 0x200000003 \
    --verify \
    --hashType 0
```

**Expected Output:**
```
SUCCESS! Signature verification PASS.
```

#### Step 7: Verify File Permissions (Optional)

```bash
# List files in secure directory
ls -la /opt/digicert/

# Expected files:
# - nanoroot_smp.conf
# - default-fingerprint.json
# - get_cpuid.sh (executable)
# - get_mac_address.sh (executable)
# - document.txt
# - mldsa87_signature.bin
# - mldsa87_public_key.pem
```

#### Cleanup (Optional)

```bash
# Remove generated test files
rm -f /opt/digicert/document.txt
rm -f /opt/digicert/mldsa87_signature.bin
rm -f /opt/digicert/mldsa87_public_key.pem

# To remove all configuration files from secure directory:
# rm -rf /opt/digicert/*
```

---

## 📝 Important Notes

1. **Secure Path Behavior**: When `SECURE_PATH` is set, all file operations are restricted to the specified directory for enhanced security.

2. **Absolute Paths Required**: The credential file ([`default-fingerprint.json`](config/default-fingerprint.json)) must contain absolute paths to helper scripts when using a custom secure path.

3. **MLDSA Hash Type**: MLDSA algorithms use `--hashType 0` because they perform internal hashing as part of the signature scheme.

4. **Permissions**: Ensure the application has appropriate read/write access to the secure directory.

5. **Post-Quantum Security**: MLDSA-87 provides quantum-resistant digital signatures based on the Module-Lattice Digital Signature Algorithm (FIPS 204).

6. **Device Fingerprinting**: Cryptographic operations are bound to device-specific hardware identifiers, providing hardware-rooted security.

---

## 🔗 Related Documentation

- [NanoROOT SMP Test Suite](../../src/smp/smp_nanoroot/test/run_tap_nanoroot_test.sh)
- [Configuration File Reference](config/nanoroot_smp.conf)
- [Default Fingerprint Template](config/default-fingerprint.json)

---

## 📄 License

Copyright © Digicert Inc. All Rights Reserved.
