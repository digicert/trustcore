# Crypto Interface Example Build and Run Guide

## CMake Options

| Option                            | Description                                       | Default |
|-----------------------------------|---------------------------------------------------|---------|
| `BUILD_SAMPLES`                   | Build Samples including the CI Example            | `OFF`   |
| `ENABLE_CI_EXAMPLE`               | Build the supporting libraries for the CI example | `OFF`   |
| `ENABLE_TPM2`                     | Enable TAP/TPM2 for the CI Example                | `OFF`   |
| `ENABLE_PKCS11_SOFTHSM`           | Enable TAP/SOFTHSM2 for the CI Example            | `OFF`   |

> **Note:** Build commands are from the root of the repository.

### 1. Basic Example Build

```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_CI_EXAMPLE=ON -B build -S .
cmake --build build
```

### 2. With TAP/TPM2 Build

```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_CI_EXAMPLE=ON -DENABLE_TPM2=ON -B build -S .
cmake --build build
```

### 3. With TAP/PKCS11/SOFTHSM2 Build

```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_CI_EXAMPLE=ON -DENABLE_PKCS11_SOFTHSM=ON -B build -S .
cmake --build build
```

> **Note:** Run commands are from the src directory which contains the sample keys and certs.
> **Note:** If running a TAP enabled build, any needed configuration files must
            be placed in the /etc/digicert folder with your user access

### 3. Crypto Interface Example Run

```bash
export LD_LIBRARY_PATH=../../../lib/:$LD_LIBRARY_PATH
cd samples/crypto_interface_example/src/
./../../bin/crypto_interface_example 
```
