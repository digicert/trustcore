# OpenSSL Connector Build and Run Instructions

> **Note:** Run all commands from the root of the repository.

## Overview
By providing an OpenSSL compatibility layer, existing applications that use the OpenSSL APIs can transparently use NanoSSL as the underlying SSL/TLS protocol implementation. Such applications also leverage core library functions for symmetric and asymmetric ciphers, signatures, and message digests.

## Build Steps

The build process downloads OpenSSL source, applies patches, and compiles the connector. Supported versions are OpenSSL 1.1.1i, 3.0.7, and 3.0.12.

### General Build (for OpenSSL 3.0.7 Example)

1. Download the appropriate OpenSSL source:
    - For OpenSSL 3.0.7:
     ```bash
     wget https://github.com/openssl/openssl/releases/download/openssl-3.0.7/openssl-3.0.7.tar.gz
     ```
   - For OpenSSL 1.1.1i:
     ```bash
     wget https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1i/openssl-1.1.1i.tar.gz
     ```
   - For OpenSSL 3.0.12:
     ```bash
     wget https://github.com/openssl/openssl/releases/download/openssl-3.0.12/openssl-3.0.12.tar.gz
     ```

2. Create thirdparty directory and extract the source:
   ```bash
   mkdir -p thirdparty
   tar -xzf openssl-3.0.7.tar.gz -C thirdparty
   ```

3. Apply patches:
   ```bash
   cd scripts/openssl
   ./apply-patch.sh openssl-3.0.7
   cd ../../
   ```

4. Build the OpenSSL connector:  
   This command builds the OpenSSL compatibility shim library in `lib/` and the `openssl_client_local` sample binary in `thirdparty/openssl-3.0.7/sample/`.
   ```bash
   ./scripts/nanossl/openssl_connector/build_openssl_connector_cap.sh --openssl_3_0_7
   ```

**Note:** For other supported versions (3.0.12 or 1.1.1i), download the corresponding tar.gz, extract it, apply the patch with the version name (e.g., `./apply-patch.sh openssl-3.0.12`), and build with the matching flag (e.g., `--openssl_3_0_12`).

## Common Setup for OpenSSL s_server/s_client

Before running the examples, set up the OpenSSL s_server and s_client as follows:

1. Create thirdparty_app directory and extract OpenSSL:
   ```bash
   mkdir -p thirdparty_app
   tar -xzf openssl-3.0.7.tar.gz -C thirdparty_app
   cd thirdparty_app/openssl-3.0.7
   ```

2. Configure and build OpenSSL:
   ```bash
   ./config
   make
   sudo make install
   cd ../../
   ```

## Test Cases

### 1. OpenSSL s_server vs openssl_client_local (built from openssl_client_local.c) ECDSA Server Authentication

**Run OpenSSL s_server:**
```bash
export LD_LIBRARY_PATH=${PWD}/thirdparty_app/openssl-3.0.7:$LD_LIBRARY_PATH
${PWD}/thirdparty_app/openssl-3.0.7/apps/openssl s_server -accept 1440 -cert keystore/openssl_connector/openssl_ecdsa_crt.pem -certform PEM -key keystore/openssl_connector/openssl_ecdsa_key.pem -keyform PEM -msg -www
```

**In a new terminal, run the openssl_client_local sample:**
```bash
cd thirdparty/openssl-3.0.7/sample
export LD_LIBRARY_PATH=${PWD}/../../../lib:$LD_LIBRARY_PATH
./openssl_client_local --ssl_port 1440 --ssl_certpath ${PWD}/../../../keystore/openssl_connector --ssl_ca_cert openssl_ec_ca_crt.pem
```

**Expected Output:** You should see the HTTP response from the OpenSSL s_server in the client terminal, indicating a successful SSL/TLS connection.

**Tip:** Run `./openssl_client_local --h` to see all available command-line options.

---

### 2. OpenSSL s_server vs openssl_client_local (built from openssl_client_local.c) ECDSA Mutual Authentication

**Run OpenSSL s_server:**
```bash
export LD_LIBRARY_PATH=${PWD}/thirdparty_app/openssl-3.0.7:$LD_LIBRARY_PATH
${PWD}/thirdparty_app/openssl-3.0.7/apps/openssl s_server -accept 1440 -cert keystore/openssl_connector/openssl_ecdsa_crt.pem -certform PEM -key keystore/openssl_connector/openssl_ecdsa_key.pem -keyform PEM -CAfile keystore/openssl_connector/openssl_ec_ca_crt.pem -Verify 10 -msg -www
```

**In a new terminal, run the openssl_client_local sample:**
```bash
cd thirdparty/openssl-3.0.7/sample
export LD_LIBRARY_PATH=${PWD}/../../../lib:$LD_LIBRARY_PATH
./openssl_client_local --ssl_port 1440 --ssl_certpath ${PWD}/../../../keystore/openssl_connector --ssl_ca_cert openssl_ec_ca_crt.pem --ssl_client_cert openssl_ecdsa_crt.pem --ssl_client_keyblob openssl_ecdsa_key.pem
```

**Expected Output:** You should see the HTTP response from the OpenSSL s_server in the client terminal. Both server and client verify each other's certificates.

**Tip:** Run `./openssl_client_local --h` to see all available command-line options.

---

### 3. openssl_server (built from openssl_server.c) vs OpenSSL s_client ECDSA Server Authentication

**Build and run openssl_server:**
```bash
cd thirdparty/openssl-3.0.7/sample
make clean openssl_server
export LD_LIBRARY_PATH=${PWD}/../../../lib:$LD_LIBRARY_PATH
./openssl_server --ssl_port 1440 --ssl_certpath ${PWD}/../../../keystore/openssl_connector --ssl_server_cert openssl_ecdsa_crt.pem --ssl_server_keyblob openssl_ecdsa_key.pem
```

**In a new terminal, run the OpenSSL s_client:**
```bash
export LD_LIBRARY_PATH=${PWD}/thirdparty_app/openssl-3.0.7:$LD_LIBRARY_PATH
${PWD}/thirdparty_app/openssl-3.0.7/apps/openssl s_client -CAfile keystore/openssl_connector/openssl_ec_ca_crt.pem -servername openssl-ecdsa -connect localhost:1440 -msg
```

**Expected Output:** You should see the connection established and handshake messages in both terminals. The client verifies the server's ECDSA certificate.

**Note:** The `-servername` option specifies the Server Name Indication (SNI) hostname, which should match the subject name or SAN in the server certificate for proper certificate selection.

**Tip:** Run `./openssl_server --h` to see all available command-line options.

---

### 4. openssl_server vs OpenSSL s_client ECDSA Mutual Authentication

**Build and run openssl_server:**
```bash
cd thirdparty/openssl-3.0.7/sample
make mauth=true clean openssl_server
export LD_LIBRARY_PATH=${PWD}/../../../lib:$LD_LIBRARY_PATH
./openssl_server --ssl_port 1440 --ssl_certpath ${PWD}/../../../keystore/openssl_connector --ssl_server_cert openssl_ecdsa_crt.pem --ssl_server_keyblob openssl_ecdsa_key.pem --ssl_ca_cert openssl_ec_ca_crt.pem
```

**In a new terminal, run the OpenSSL s_client:**
```bash
export LD_LIBRARY_PATH=${PWD}/thirdparty_app/openssl-3.0.7:$LD_LIBRARY_PATH
${PWD}/thirdparty_app/openssl-3.0.7/apps/openssl s_client -CAfile keystore/openssl_connector/openssl_ec_ca_crt.pem -servername openssl-ecdsa -cert keystore/openssl_connector/openssl_ecdsa_crt.pem -key keystore/openssl_connector/openssl_ecdsa_key.pem -connect 127.0.0.1:1440 -msg
```

**Expected Output:** You should see the connection established and mutual authentication completed in both terminals. Both server and client verify each other's certificates.

**Tip:** Run `./openssl_server --h` to see all available command-line options.

---

## Additional Notes

- **Supported Versions:** OpenSSL 1.1.1i, 3.0.7, and 3.0.12. Build other versions by updating the version in the download, patch, and build script commands.
- **Scripts Location:** Build scripts are located in `scripts/nanossl/openssl_connector/` (e.g., `build_openssl_connector_cap.sh`, `build_openssl_connector_tap_local.sh`, `build_openssl_connector_tap_remote.sh`). Run any script with `--help` flag for more build options (e.g., `./scripts/nanossl/openssl_connector/build_openssl_connector_cap.sh --help`).
- **Keystore:** Ensure keystore files exist in `keystore/openssl_connector/`.
- **Troubleshooting:** 
  - If connections fail, verify certificate paths, and check that `-servername` matches the certificate subject/SAN.
  - Use `-msg` flag to see detailed handshake messages for debugging.