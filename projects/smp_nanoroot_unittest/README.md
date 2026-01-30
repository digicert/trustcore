# NanoROOT SMP Unit Tests

Comprehensive unit tests for the NanoROOT SMP module using cmocka framework with text-based code coverage support.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Library Dependencies](#library-dependencies)
- [Configuration Setup](#configuration-setup)
- [Quick Start](#quick-start)
- [Building and Running Tests](#building-and-running-tests)
- [Code Coverage](#code-coverage)
  - [Building Library with Coverage](#building-library-with-coverage)
  - [Generating Coverage Reports](#generating-coverage-reports)
  - [Coverage Tools](#coverage-tools)
  - [Coverage Verification](#coverage-verification)
  - [Understanding Coverage](#understanding-coverage)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)
- [Project Structure](#project-structure)
- [Complete Workflow Example](#complete-workflow-example)
- [Quick Reference Card](#quick-reference-card)

---

## Overview

This test suite provides testing of the NanoROOT SMP (Secure Module Provider) library:
- Input validation and security checks
- Module and token lifecycle management
- SMP command dispatcher operations
- Device protection and fingerprinting
- Error handling and edge cases

**Key Feature:** Coverage measures **`libsmpnanoroot.so`** (production library), not test code.

---

## Features

- ✅ **Unit Testing**: Tests for all major NanoROOT SMP components
- ✅ **Text-Based Coverage**: Simple terminal output (no HTML/XML generation)
- ✅ **CMake Build System**: Modern, maintainable build configuration
- ✅ **Automated Test Runner**: Shell script with coverage generation

---

## Prerequisites

### Required

- **C Compiler**: gcc
- **CMake**: 3.5+
- **cmocka**: 1.1.0+
- **libsmpnanoroot.so**: Built from main project

### Optional (for Coverage)

- **lcov**, OR
- **gcovr** (recommended for cleaner text output)

### Installation

**Ubuntu/Debian:**
```bash
sudo apt-get install build-essential cmake libcmocka-dev lcov
# OR for gcovr (better text output):
pip3 install gcovr
```

**CentOS/RHEL:**
```bash
sudo yum install gcc cmake libcmocka-devel lcov
pip3 install gcovr
```

---

## Library Dependencies

The unit tests link against the following libraries (built automatically when `ENABLE_NANOROOT=ON`):

**Core Libraries:**
- **smpnanoroot** - NanoROOT SMP library (production code under test)
- **cryptointerface** - Crypto abstraction layer
- **nanotap2** - TAP2 library
- **nanotap2_common** - TAP2 common utilities

**Supporting Libraries:**
- **nanocert** - Certificate handling
- **nanocap** - Capability management
- **nanocrypto** - Cryptographic operations
- **initialize** - Initialization utilities
- **common** - Common utilities
- **platform** - Platform abstraction
- **asn1** - ASN.1 parser

**Test Framework:**
- **cmocka** - Unit testing framework

**Note:** These libraries are built automatically from the main project when building with `ENABLE_NANOROOT=ON`.

---

## Configuration Setup

**IMPORTANT:** Before running tests, you must set up the required configuration files and environment variables.

### Step 1: Set Environment Variables

Source the fingerprint environment variables:

```bash
source samples/nanoroot/config/setFingerPrintValues.sh
```

This script sets the following environment variables required by NanoROOT:
- `INTERNATIONAL_MOBILE_IDENTITY`
- `MOBILE_EQUIPMENT_IDENTIFIER`
- `ELECTRONIC_SERIAL_NUMBER`
- `INTERNATIONAL_MOBILE_SUBSCRIBER_IDENTITY`
- `MAC_ADDRESS`
- `SERIAL_NUMBER`
- `SECURE_ANDROID_ID`
- `UUID`

### Step 2: Copy Configuration Files to `/etc/digicert/`

Create the directory and copy required configuration files:

```bash
# Create directory
sudo mkdir -p /etc/digicert/

# Copy configuration files
sudo cp samples/nanoroot/config/default-fingerprint.json /etc/digicert/
sudo cp samples/nanoroot/config/get_cpuid.sh /etc/digicert/
sudo cp samples/nanoroot/config/get_mac_address.sh /etc/digicert/
sudo cp samples/nanoroot/config/nanoroot_smp.conf /etc/digicert/

# Make helper scripts executable
sudo chmod +x /etc/digicert/get_cpuid.sh
sudo chmod +x /etc/digicert/get_mac_address.sh
```

### Step 3: Edit Configuration File

Edit `/etc/digicert/default-fingerprint.json` to set your network interface name:

```bash
sudo vim /etc/digicert/default-fingerprint.json
```

Update the network interface name in the MAC address field (e.g., `eth0`, `wlan0`, `enp0s3`).

### Verify Configuration

Check that all required files are in place:

```bash
ls -la /etc/digicert/
```

Expected output:
```
-rw-r--r-- 1 root root  default-fingerprint.json
-rwxr-xr-x 1 root root  get_cpuid.sh
-rwxr-xr-x 1 root root  get_mac_address.sh
-rw-r--r-- 1 root root  nanoroot_smp.conf
```

---

## Quick Start

### Run Tests Without Coverage

```bash
cd projects/smp_nanoroot_unittest

# Ensure environment variables are set
source ../../samples/nanoroot/config/setFingerPrintValues.sh

# Run tests
./run_unit_tests.sh
```

### Run Tests With Coverage

```bash
cd projects/smp_nanoroot_unittest

# Ensure environment variables are set
source ../../samples/nanoroot/config/setFingerPrintValues.sh

# Run tests with coverage
./run_unit_tests.sh --coverage
```

### Verbose Mode

```bash
# Ensure environment variables are set
source ../../samples/nanoroot/config/setFingerPrintValues.sh

./run_unit_tests.sh --verbose --coverage
```

---

## Building and Running Tests

### Option 1: Using run_unit_tests.sh (Recommended)

```bash
cd projects/smp_nanoroot_unittest

# Set environment variables
source ../../samples/nanoroot/config/setFingerPrintValues.sh

./run_unit_tests.sh [OPTIONS]

# Options:
#   -v, --verbose      Verbose output
#   -c, --coverage     Enable coverage analysis (text format)
#   -h, --help         Display help
```

**What it does:**
1. Checks dependencies (cmocka, lcov/gcovr)
2. Verifies library has coverage instrumentation
3. Builds tests using CMake
4. Runs unit tests
5. Generates text-based coverage report

### Option 2: Manual CMake Build

```bash
cd projects/smp_nanoroot_unittest

# Set environment variables
source ../../samples/nanoroot/config/setFingerPrintValues.sh

# Build
cmake -B build
cmake --build build

# Run (tests execute from build directory for config file path resolution)
cd build
./smp_nanoroot_unit_test
cd ..

# OR run directly (may have issues with config paths)
./build/smp_nanoroot_unit_test
```

### Option 3: Using CTest

```bash
cd projects/smp_nanoroot_unittest

# Set environment variables
source ../../samples/nanoroot/config/setFingerPrintValues.sh

cmake -B build
cmake --build build
cd build
ctest --verbose
```

---

## Code Coverage

### Building Library with Coverage

For coverage to work, the library must be built with coverage instrumentation enabled:

```bash
# Enable coverage via environment variable
export CM_ENV_CODE_COVERAGE=1

# Clean previous build
rm -rf build lib/libsmpnanoroot.so

# Configure and build
cmake -S . -B build -DENABLE_NANOROOT=ON
cmake --build build

# Verify coverage instrumentation
find build/projects/smp_nanoroot -name "*.gcno" | wc -l
# Should show: 5 (one for each source file)
```

**How it works:**
- `CM_ENV_CODE_COVERAGE` is checked in `projects/shared_cmake/mss_defs.cmake`
- Adds `-fprofile-arcs -ftest-coverage` to library compilation
- Generates `.gcno` files (coverage metadata) in `build/projects/smp_nanoroot/`

Then build and run tests:

```bash
cd projects/smp_nanoroot_unittest

# Set environment variables
source ../../samples/nanoroot/config/setFingerPrintValues.sh

./run_unit_tests.sh --coverage
```

---

### Generating Coverage Reports

#### Option 1: Using run_unit_tests.sh (Recommended)

```bash
cd projects/smp_nanoroot_unittest

# Set environment variables
source ../../samples/nanoroot/config/setFingerPrintValues.sh

# Text coverage report
./run_unit_tests.sh --coverage

# Verbose output
./run_unit_tests.sh --verbose --coverage
```

**What the script does:**
1. Checks for required dependencies (cmocka, lcov/gcovr)
2. Verifies library has coverage instrumentation
3. Verifies configuration files are in place
4. Builds tests using CMake
5. Runs unit tests
6. Generates text-based coverage report

#### Option 2: Using CMake Target

```bash
cd projects/smp_nanoroot_unittest

# Build with coverage enabled (optional, defaults to OFF)
cmake -B build -DENABLE_COVERAGE=ON
cmake --build build

# Run tests (from build directory)
cd build
./smp_nanoroot_unit_test
cd ..

# Generate report
cd build
cmake --build . --target coverage
```

**Note:** The `-DENABLE_COVERAGE=ON` option is only needed if using the CMake `coverage` target directly. The `run_unit_tests.sh --coverage` script handles coverage automatically without this option.

#### Option 3: Manual with gcovr (Recommended for Text)

```bash
cd projects/smp_nanoroot_unittest

# Text summary
gcovr -r ../../src/smp/smp_nanoroot \
      --object-directory ../../build/projects/smp_nanoroot \
      --exclude '.*/test/.*' \
      --exclude '.*_test\.c' \
      --exclude '.*_unittest\.c'
```

#### Option 4: Manual with lcov

```bash
cd projects/smp_nanoroot_unittest

# Capture from library build directory
lcov --capture \
     --directory ../../build/projects/smp_nanoroot \
     --output-file coverage.info

# Filter unwanted files
lcov --remove coverage.info \
     '/usr/*' '*/thirdparty/*' '*/cmocka*' '*/test/*' '*_test.c' '*_unittest.c' \
     --output-file coverage.info

# View summary
lcov --list coverage.info

# Cleanup
rm -f coverage.info
```

---

## Troubleshooting

### cmocka not found

```bash
# Check
pkg-config --modversion cmocka

# Install
sudo apt-get install libcmocka-dev
```

### Coverage tools not found

```bash
# Check
which lcov gcovr

# Install lcov
sudo apt-get install lcov

# OR install gcovr (recommended)
pip3 install gcovr
```

### Library not found at runtime

```bash
# Set LD_LIBRARY_PATH
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH

# OR copy to system path
sudo cp lib/libsmpnanoroot.so /usr/local/lib/
sudo ldconfig
```

### Configuration files missing

```bash
# Check if files exist
ls -la /etc/digicert/

# If missing, copy them
sudo mkdir -p /etc/digicert/
sudo cp samples/nanoroot/config/*.{json,conf,sh} /etc/digicert/
sudo chmod +x /etc/digicert/*.sh
```

### Environment variables not set

```bash
# Check if variables are set
env | grep -E "INTERNATIONAL_MOBILE_IDENTITY|MAC_ADDRESS|SERIAL_NUMBER"

# If empty, source the script
source samples/nanoroot/config/setFingerPrintValues.sh
```

### No .gcno files found

**Cause:** Library not built with coverage

**Fix:**
```bash
rm -rf build lib/libsmpnanoroot.so

export CM_ENV_CODE_COVERAGE=1
cmake -S . -B build -DENABLE_NANOROOT=ON
cmake --build build

# Verify
find build/projects/smp_nanoroot -name "*.gcno" | wc -l
# Should show: 5
```

### No .gcda files found

**Cause:** Tests didn't run or didn't execute library code

**Fix:**
```bash
# 1. Verify .gcno files exist
find build/projects/smp_nanoroot -name "*.gcno" | wc -l
# Should show: 5

# 2. Set environment variables
source samples/nanoroot/config/setFingerPrintValues.sh

# 3. Run tests
cd projects/smp_nanoroot_unittest
./build/smp_nanoroot_unit_test

# 4. Check .gcda files created
find ../../build/projects/smp_nanoroot -name "*.gcda" | wc -l
# Should show: 5 after running tests
```

### Coverage shows 0% or very low

**Causes:**
1. Tests didn't run successfully
2. Library wasn't built with coverage
3. Environment variables not set
4. Wrong directory specified in lcov/gcovr

**Fix:**
```bash
# 1. Check .gcno files
find build/projects/smp_nanoroot -name "*.gcno"

# 2. Set environment variables
source samples/nanoroot/config/setFingerPrintValues.sh

# 3. Run tests
cd projects/smp_nanoroot_unittest
./run_unit_tests.sh

# 4. Check .gcda files
find ../../build/projects/smp_nanoroot -name "*.gcda"

# 5. Capture with correct directory
lcov --capture \
     --directory ../../build/projects/smp_nanoroot \
     -o coverage.info

lcov --list coverage.info
rm -f coverage.info
```

### Permission denied errors

```bash
# Ensure scripts are executable
sudo chmod +x /etc/digicert/get_cpuid.sh
sudo chmod +x /etc/digicert/get_mac_address.sh

# Ensure directory is readable
sudo chmod 755 /etc/digicert/
```


## Project Structure

```
projects/smp_nanoroot_unittest/
├── CMakeLists.txt              # CMake build configuration
├── README.md                   # This file
├── run_unit_tests.sh           # Automated test runner
├── build/                      # Build directory (generated)
│   ├── smp_nanoroot_unit_test  # Test executable ← tests run from here
│   ├── CMakeFiles/             # CMake build metadata
│   └── CTestTestfile.cmake     # CTest configuration
└── coverage.info               # Coverage data (generated, if using lcov)

src/smp/smp_nanoroot/smp_nanoroot_unittest/
└── smp_nanoroot_unit_test.c    # Unit test source (1958 lines, 74 tests)

samples/nanoroot/config/
├── default-fingerprint.json    # Device fingerprint configuration
├── get_cpuid.sh                # CPU ID extraction script
├── get_mac_address.sh          # MAC address extraction script
├── nanoroot_smp.conf           # NanoROOT SMP configuration
└── setFingerPrintValues.sh     # Environment setup script

build/projects/smp_nanoroot/    # Library build (coverage data location)
├── CMakeFiles/
│   └── smpnanoroot.dir/
│       └── __/__/src/smp/smp_nanoroot/
│           ├── smp_nanoroot_api.c.gcno              # Coverage metadata
│           ├── smp_nanoroot_api.c.gcda              # Coverage runtime data
│           ├── smp_nanoroot_device_protect.c.gcno
│           ├── smp_nanoroot_device_protect.c.gcda
│           ├── smp_nanoroot_interface.c.gcno
│           ├── smp_nanoroot_interface.c.gcda
│           ├── smp_nanoroot_parseConfig.c.gcno
│           ├── smp_nanoroot_parseConfig.c.gcda
│           ├── smp_nanoroot_util.c.gcno
│           └── smp_nanoroot_util.c.gcda
└── libsmpnanoroot.so           # Instrumented library (when CM_ENV_CODE_COVERAGE=1)

lib/
└── libsmpnanoroot.so           # Production library symlink
```

**Important Notes:**
- Tests execute from `projects/smp_nanoroot_unittest/build/` directory
- Config file path is relative: `../../../samples/nanoroot/config/nanoroot_smp.conf`
- Coverage data (`.gcda` files) are written to `build/projects/smp_nanoroot/` (library build dir)
- Coverage metadata (`.gcno` files) are created at library compile time

---

## Complete Workflow Example

### Full Workflow from Clean State

```bash
# Step 1: Navigate to repository root
cd <path to repo directory>

# Step 2: Set environment variables
source samples/nanoroot/config/setFingerPrintValues.sh

# Step 3: Ensure configuration files are in place
sudo mkdir -p /etc/digicert/
sudo cp samples/nanoroot/config/default-fingerprint.json /etc/digicert/
sudo cp samples/nanoroot/config/get_cpuid.sh /etc/digicert/
sudo cp samples/nanoroot/config/get_mac_address.sh /etc/digicert/
sudo cp samples/nanoroot/config/nanoroot_smp.conf /etc/digicert/
sudo chmod +x /etc/digicert/get_cpuid.sh /etc/digicert/get_mac_address.sh

# Step 4: Edit network interface name (if needed)
sudo vim /etc/digicert/default-fingerprint.json

# Step 5: Build library with coverage
export CM_ENV_CODE_COVERAGE=1
rm -rf build lib/libsmpnanoroot.so
cmake -S . -B build -DENABLE_NANOROOT=ON
cmake --build build

# Step 6: Verify coverage instrumentation
find build/projects/smp_nanoroot -name "*.gcno" | wc -l
# Expected: 5

# Step 7: Run tests with coverage
cd projects/smp_nanoroot_unittest
./run_unit_tests.sh --coverage

# Step 8: Verify coverage data
find ../../build/projects/smp_nanoroot -name "*.gcda" | wc -l
# Expected: 5
```

---

## See Also

- **[run_unit_tests.sh](run_unit_tests.sh)** - Automated test runner script
- **[samples/nanoroot/BUILD_RUN.md](../../samples/nanoroot/BUILD_RUN.md)** - NanoROOT example documentation
- **[projects/shared_cmake/mss_defs.cmake](../../projects/shared_cmake/mss_defs.cmake)** - CMake coverage configuration
- **[CMakeLists.txt](CMakeLists.txt)** - Unit test CMake configuration

---

## License

Copyright 2025 DigiCert Project Authors. All Rights Reserved.

DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
- **Open Source**: GNU AGPL v3
- **Commercial**: DigiCert Master Services Agreement

For commercial licensing, contact sales@digicert.com.

---

## Related Projects

- **[projects/smp_nanoroot](../smp_nanoroot/)** - NanoROOT SMP library source
- **[samples/nanoroot](../../samples/nanoroot/)** - Sample applications
