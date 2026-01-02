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

| Option            | Description                                    | Default   |
|-------------------|------------------------------------------------|-----------|
| `ENABLE_NANOROOT` | Enable NanoROOT SMP library build              | `OFF`     |
| `SECURE_PATH`     | Restrict credential file access to secure path | `Not Set` |

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

### 2. Build the Project

```bash
cmake --build build
```

**Output:**
- Binary : samples/bin/tap_nanoroot_example
- Shared libraries : lib/libsmpnanoroot.so and dependencies

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

This file contains device fingerprint information used for cryptographic key derivation.

### Environment Setup

Set environment variables required by [`samples/nanoroot/config/default-fingerprint.json`](config/default-fingerprint.json) using the provided script:

```bash
source samples/nanoroot/config/setFingerPrintValues.sh
```

This script sets fingerprint-related environment variables required by NanoROOT.

---

## 🚀 Running the Example

### Set Library Path

```bash
export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:$LD_LIBRARY_PATH
 ```

### Prepare `/etc/digicert/` for Standard Build (without secure path)

```bash
# Copy required configuration files to /etc/digicert/
sudo mkdir -p /etc/digicert/
sudo cp samples/nanoroot/config/default-fingerprint.json /etc/digicert/
sudo cp samples/nanoroot/config/get_cpuid.sh /etc/digicert/
sudo cp samples/nanoroot/config/get_mac_address.sh /etc/digicert/
sudo cp samples/nanoroot/config/nanoroot_smp.conf /etc/digicert/

# Make helper scripts executable
sudo chmod +x /etc/digicert/get_cpuid.sh
sudo chmod +x /etc/digicert/get_mac_address.sh

# Edit /etc/digicert/default-fingerprint.json with the network interface name
sudo vim /etc/digicert/default-fingerprint.json
```

### Seal Operation

Encrypt data using device-specific credentials:

```bash
./samples/bin/tap_nanoroot_example \
    --config samples/nanoroot/config/nanoroot_smp.conf \
    --infile <plaintext_input_file> \
    --outfile <encrypted_output_file> \
    --seal \
    --passphrase <password>
```

### Unseal Operation

Decrypt previously sealed data:

```bash
./samples/bin/tap_nanoroot_example \
    --config samples/nanoroot/config/nanoroot_smp.conf \
    --infile <encrypted_input_file> \
    --outfile <decrypted_output_file> \
    --unseal \
    --passphrase <password>
```

### Sign Operation

Generate a digital signature:

```bash
./samples/bin/tap_nanoroot_example \
    --config samples/nanoroot/config/nanoroot_smp.conf \
    --infile <data_to_sign> \
    --sigfile <signature_file> \
    --pubKey <public_key_output_file> \
    --keyId <key_identifier> \
    --signBuffer \
    --hashType <hash_algorithm>
```

**Supported Key Identifiers:**

| Algorithm  | Key Size | Key ID        | Hash Type |
|------------|----------|---------------|-----------|
| RSA        | 2048-bit | `0x100000002` | `1`       |
| RSA        | 3072-bit | `0x100000003` | `1`       |
| RSA        | 4096-bit | `0x100000004` | `2`       |
| RSA        | 8192-bit | `0x100000005` | `2`       |
| ECC P-256  | 256-bit  | `0x300000001` | `1`       |
| ECC P-384  | 384-bit  | `0x300000002` | `1`       |
| ECC P-521  | 521-bit  | `0x300000003` | `2`       |
| MLDSA-44   | -        | `0x200000001` | `0`       |
| MLDSA-65   | -        | `0x200000002` | `0`       |
| MLDSA-87   | -        | `0x200000003` | `0`       |

**Supported Hash Algorithms:**

- `0` - No pre-hashing (used for MLDSA algorithms)
- `1` - SHA-256
- `2` - SHA-512

### Verify Operation

Verify a digital signature:

```bash
./samples/bin/tap_nanoroot_example \
    --config samples/nanoroot/config/nanoroot_smp.conf \
    --infile <data_to_verify> \
    --sigfile <signature_file> \
    --pubKey <public_key_file> \
    --keyId <key_identifier> \
    --verify \
    --hashType <hash_algorithm>
```

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

**Note:** The test script must be run from the repository root directory.

---

## 📚 Example Usage Scenarios

### Example 1: Seal and Unseal Data

```bash
# Set environment variables
source samples/nanoroot/config/setFingerPrintValues.sh
export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:$LD_LIBRARY_PATH

# Create test data
echo "Confidential data" > plaintext.txt

# Seal the data
./samples/bin/tap_nanoroot_example \
    --config samples/nanoroot/config/nanoroot_smp.conf \
    --infile plaintext.txt \
    --outfile encrypted.bin \
    --seal \
    --passphrase mySecretPassword

# Unseal the data
./samples/bin/tap_nanoroot_example \
    --config samples/nanoroot/config/nanoroot_smp.conf \
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
    --config samples/nanoroot/config/nanoroot_smp.conf \
    --infile document.txt \
    --sigfile signature.bin \
    --pubKey rsa_public_key.pem \
    --keyId 0x100000002 \
    --signBuffer \
    --hashType 1

# Verify the signature
./samples/bin/tap_nanoroot_example \
    --config samples/nanoroot/config/nanoroot_smp.conf \
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
# Create the secure directory
sudo mkdir -p /opt/digicert/

# Copy required configuration files
sudo cp samples/nanoroot/config/default-fingerprint.json /opt/digicert/
sudo cp samples/nanoroot/config/get_cpuid.sh /opt/digicert/
sudo cp samples/nanoroot/config/get_mac_address.sh /opt/digicert/
sudo cp samples/nanoroot/config/nanoroot_smp.conf /opt/digicert/

# Make helper scripts executable
sudo chmod +x /opt/digicert/get_cpuid.sh
sudo chmod +x /opt/digicert/get_mac_address.sh

# Edit /opt/digicert/default-fingerprint.json with the network interface name
# Update the credential file with absolute paths
# Edit /opt/digicert/default-fingerprint.json to use:
# - /opt/digicert/get_cpuid.sh
# - /opt/digicert/get_mac_address.sh
sudo vim /opt/digicert/default-fingerprint.json

# Change ownership to current user for accessing files without sudo
sudo chown -R $(whoami):$(whoami) /opt/digicert/
```

**Important:** The [`default-fingerprint.json`](config/default-fingerprint.json) must contain absolute paths to helper scripts when using a custom secure path.

#### Step 3: Set Environment Variables

```bash
# Set library path
export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:$LD_LIBRARY_PATH

# Source fingerprint environment variables
source samples/nanoroot/config/setFingerPrintValues.sh
```

#### Step 4: Create Test Data

```bash
# Create test document
echo "Document to sign with MLDSA-87" | sudo tee /opt/digicert/document.txt
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
sudo rm -f /opt/digicert/document.txt
sudo rm -f /opt/digicert/mldsa87_signature.bin
sudo rm -f /opt/digicert/mldsa87_public_key.pem

# To remove all configuration files from secure directory:
# sudo rm -rf /opt/digicert/*
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
