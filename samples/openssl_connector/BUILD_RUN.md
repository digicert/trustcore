# OpenSSL Connector Build and Run Instructions

> **Note:** Run all commands from the root of the repository.

## Overview
By providing an OpenSSL compatibility layer, existing applications that use the OpenSSL APIs can transparently use NanoSSL as the underlying SSL/TLS protocol implementation. Such applications also leverage core library functions for symmetric and asymmetric ciphers, signatures, and message digests.

## Build Steps

The build process downloads OpenSSL source, applies patches, and compiles the connector. Supported versions are OpenSSL 1.1.1i, 3.0.7, 3.0.12 and 3.5.0.

**Build instructions are available for:**
- [Linux](#linux)
- [Windows](#windows)
- [TAP Integration (Linux)](#tap-integration-linux)
- [Third-Party Application Integration](#third-party-application-integration)

## LINUX

### General Build (for OpenSSL 3.5.0 Example)

1. Download the appropriate OpenSSL source:
    - For OpenSSL 3.5.0:
     ```bash
     wget https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz
     ```
   - For OpenSSL 1.1.1i:
     ```bash
     wget https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1i/openssl-1.1.1i.tar.gz
     ```
   - For OpenSSL 3.0.12:
     ```bash
     wget https://github.com/openssl/openssl/releases/download/openssl-3.0.12/openssl-3.0.12.tar.gz
     ```
   - For OpenSSL 3.0.7:
      ```bash
       wget https://github.com/openssl/openssl/releases/download/openssl-3.0.7/openssl-3.0.7.tar.gz
      ```

2. Create thirdparty directory and extract the source:
   ```bash
   mkdir -p thirdparty
   tar -xzf openssl-3.5.0.tar.gz -C thirdparty
   ```

3. Apply patches:
   ```bash
   cd scripts/openssl
   ./apply-patch.sh openssl-3.5.0
   cd ../../
   ```

4. Build the OpenSSL connector:
   This command builds the OpenSSL compatibility shim library in `lib/` and the `openssl_client_local` sample binary in `thirdparty/openssl-3.5.0/sample/`.
   ```bash
   ./scripts/nanossl/openssl_connector/build_openssl_connector_cap.sh --openssl_3_5_0
   ```

**Note:** For other supported versions (3.0.7, 3.0.12 or 1.1.1i), download the corresponding tar.gz, extract it, apply the patch with the version name (e.g., `./apply-patch.sh openssl-3.0.12`), and build with the matching flag (e.g., `--openssl_3_0_12`).

## Common Setup for OpenSSL s_server/s_client

Before running the examples, set up the OpenSSL s_server and s_client as follows:

1. Create thirdparty_app directory and extract OpenSSL:
   ```bash
   mkdir -p thirdparty_app
   tar -xzf openssl-3.5.0.tar.gz -C thirdparty_app
   cd thirdparty_app/openssl-3.5.0
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
export LD_LIBRARY_PATH=${PWD}/thirdparty_app/openssl-3.5.0:$LD_LIBRARY_PATH
${PWD}/thirdparty_app/openssl-3.5.0/apps/openssl s_server -accept 1440 -cert keystore/openssl_connector/openssl_ecdsa_crt.pem -certform PEM -key keystore/openssl_connector/openssl_ecdsa_key.pem -keyform PEM -msg -www
```

**In a new terminal, run the openssl_client_local sample:**
```bash
cd thirdparty/openssl-3.5.0/sample
export LD_LIBRARY_PATH=${PWD}/../../../lib:$LD_LIBRARY_PATH
./openssl_client_local --ssl_port 1440 --ssl_certpath ${PWD}/../../../keystore/openssl_connector --ssl_ca_cert openssl_ec_ca_crt.pem
```

**Expected Output:** You should see the HTTP response from the OpenSSL s_server in the client terminal, indicating a successful SSL/TLS connection.

**Tip:** Run `./openssl_client_local --h` to see all available command-line options.

---

### 2. OpenSSL s_server vs openssl_client_local (built from openssl_client_local.c) ECDSA Mutual Authentication

**Run OpenSSL s_server:**
```bash
export LD_LIBRARY_PATH=${PWD}/thirdparty_app/openssl-3.5.0:$LD_LIBRARY_PATH
${PWD}/thirdparty_app/openssl-3.5.0/apps/openssl s_server -accept 1440 -cert keystore/openssl_connector/openssl_ecdsa_crt.pem -certform PEM -key keystore/openssl_connector/openssl_ecdsa_key.pem -keyform PEM -CAfile keystore/openssl_connector/openssl_ec_ca_crt.pem -Verify 10 -msg -www
```

**In a new terminal, run the openssl_client_local sample:**
```bash
cd thirdparty/openssl-3.5.0/sample
export LD_LIBRARY_PATH=${PWD}/../../../lib:$LD_LIBRARY_PATH
./openssl_client_local --ssl_port 1440 --ssl_certpath ${PWD}/../../../keystore/openssl_connector --ssl_ca_cert openssl_ec_ca_crt.pem --ssl_client_cert openssl_ecdsa_crt.pem --ssl_client_keyblob openssl_ecdsa_key.pem
```

**Expected Output:** You should see the HTTP response from the OpenSSL s_server in the client terminal. Both server and client verify each other's certificates.

**Tip:** Run `./openssl_client_local --h` to see all available command-line options.

---

### 3. openssl_server (built from openssl_server.c) vs OpenSSL s_client ECDSA Server Authentication

**Build and run openssl_server:**
```bash
cd thirdparty/openssl-3.5.0/sample
make clean openssl_server
export LD_LIBRARY_PATH=${PWD}/../../../lib:$LD_LIBRARY_PATH
./openssl_server --ssl_port 1440 --ssl_certpath ${PWD}/../../../keystore/openssl_connector --ssl_server_cert openssl_ecdsa_crt.pem --ssl_server_keyblob openssl_ecdsa_key.pem
```

**In a new terminal, run the OpenSSL s_client:**
```bash
export LD_LIBRARY_PATH=${PWD}/thirdparty_app/openssl-3.5.0:$LD_LIBRARY_PATH
${PWD}/thirdparty_app/openssl-3.5.0/apps/openssl s_client -CAfile keystore/openssl_connector/openssl_ec_ca_crt.pem -servername openssl-ecdsa -connect localhost:1440 -msg
```

**Expected Output:** You should see the connection established and handshake messages in both terminals. The client verifies the server's ECDSA certificate.

**Note:** The `-servername` option specifies the Server Name Indication (SNI) hostname, which should match the subject name or SAN in the server certificate for proper certificate selection.

**Tip:** Run `./openssl_server --h` to see all available command-line options.

---

### 4. openssl_server vs OpenSSL s_client ECDSA Mutual Authentication

**Build and run openssl_server:**
```bash
cd thirdparty/openssl-3.5.0/sample
make mauth=true clean openssl_server
export LD_LIBRARY_PATH=${PWD}/../../../lib:$LD_LIBRARY_PATH
./openssl_server --ssl_port 1440 --ssl_certpath ${PWD}/../../../keystore/openssl_connector --ssl_server_cert openssl_ecdsa_crt.pem --ssl_server_keyblob openssl_ecdsa_key.pem --ssl_ca_cert openssl_ec_ca_crt.pem
```

**In a new terminal, run the OpenSSL s_client:**
```bash
export LD_LIBRARY_PATH=${PWD}/thirdparty_app/openssl-3.5.0:$LD_LIBRARY_PATH
${PWD}/thirdparty_app/openssl-3.5.0/apps/openssl s_client -CAfile keystore/openssl_connector/openssl_ec_ca_crt.pem -servername openssl-ecdsa -cert keystore/openssl_connector/openssl_ecdsa_crt.pem -key keystore/openssl_connector/openssl_ecdsa_key.pem -connect 127.0.0.1:1440 -msg
```

**Expected Output:** You should see the connection established and mutual authentication completed in both terminals. Both server and client verify each other's certificates.

**Tip:** Run `./openssl_server --h` to see all available command-line options.

---

## Test EVP Functionality (Linux)

To ensure that the Encryption and Decryption (EVP) functionalities are operating
correctly with NanoSSL, rebuild the connector for OpenSSL 3.5.0 and run
OpenSSL's own `test_evp` suite against it.

1. **Build the OpenSSL connector with OpenSSL 3.5.0:**
   ```bash
   cd scripts/nanossl/openssl_connector/
   ./build_openssl_connector_cap.sh --openssl_3_5_0
   ```

2. **Navigate to the OpenSSL 3.5.0 directory:**
   ```bash
   cd thirdparty/openssl-3.5.0
   ```

3. **Run the EVP test**, pointing `LD_LIBRARY_PATH` at the shim library:
   ```bash
   LD_LIBRARY_PATH=${PWD}/../../lib make TESTS=test_evp test
   ```

This compiles and runs OpenSSL's own EVP tests against the shim, verifying that
encryption and decryption operations are functioning as expected.

## WINDOWS

### General Build (for OpenSSL 3.5.0 Example)

> **Note:** Run all steps from **Git Bash** (installed with [Git for Windows](https://gitforwindows.org/)). Avoid using CMD or PowerShell for the patch step (step 3) — if `bash` is mapped to WSL, CMD may invoke WSL instead of Git Bash, causing errors.

1. Download the appropriate OpenSSL source:
   - For OpenSSL 3.5.0:
     ```bash
     curl -LO https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz
     ```
   - For OpenSSL 1.1.1i:
     ```bash
     curl -LO https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1i/openssl-1.1.1i.tar.gz
     ```
   - For OpenSSL 3.0.12:
     ```bash
     curl -LO https://github.com/openssl/openssl/releases/download/openssl-3.0.12/openssl-3.0.12.tar.gz
     ```
   - For OpenSSL 3.0.7:
     ```bash
     curl -LO https://github.com/openssl/openssl/releases/download/openssl-3.0.7/openssl-3.0.7.tar.gz
     ```

2. Create thirdparty directory and extract the source:
   ```bash
   mkdir -p thirdparty
   tar -xzf openssl-3.5.0.tar.gz -C thirdparty
   ```

3. Apply patches:
   ```bash
   cd scripts/openssl
   ./apply-patch.sh openssl-3.5.0
   cd ../../
   ```

### Windows Prerequisites

**Supported Visual Studio versions:** 2019, 2022, 2026

**Prerequisites:**
- Administrator Command Prompt
- Set up 32-bit or 64-bit build environment by running the appropriate script (replace `<version>` with `2019`, `2022`, or `18`, and `<edition>` with your installed edition e.g. `Professional`, `Enterprise`, `Community`):

  - 32-bit:
    ```cmd
    call "C:\Program Files (x86)\Microsoft Visual Studio\<version>\<edition>\VC\Auxiliary\Build\vcvars32.bat"
    ```
    or
    ```cmd
    call "C:\Program Files\Microsoft Visual Studio\<version>\<edition>\VC\Auxiliary\Build\vcvars32.bat"
    ```
  - 64-bit:
    ```cmd
    call "C:\Program Files (x86)\Microsoft Visual Studio\<version>\<edition>\VC\Auxiliary\Build\vcvars64.bat"
    ```
    or
    ```cmd
    call "C:\Program Files\Microsoft Visual Studio\<version>\<edition>\VC\Auxiliary\Build\vcvars64.bat"
    ```

  > **Note:** Use `Program Files (x86)` if Visual Studio was installed as a 32-bit application (older installers), or `Program Files` for newer 64-bit installers.

### General Build (for OpenSSL 3.5.0 Example on Windows)

Run the build script from the repository root with the appropriate OpenSSL version flag (e.g., `--openssl_3_5_0`):

```cmd
cd path\to\repository
.\scripts\nanossl\openssl_connector\build_openssl_connector_cap.bat --openssl_3_5_0 <--x32|--x64> --mauth --build-for-osi
```

This command builds the OpenSSL compatibility shim library and `openssl_client_local` in `bin_win32/`.

**Note:** For other supported versions (3.0.7, 3.0.12 or 1.1.1i), download the corresponding tar.gz, extract it, apply the patch with the version name (e.g., `./apply-patch.sh openssl-3.0.12`), and build with the matching flag (e.g., `--openssl_3_0_12`).

## Common Setup for OpenSSL s_server/s_client (Windows)

Before running the examples, set up the OpenSSL s_server and s_client as follows:

1. Create thirdparty_app directory and extract OpenSSL (**Git Bash**):
   ```bash
   mkdir -p thirdparty_app
   tar -xzf openssl-3.5.0.tar.gz -C thirdparty_app
   ```

2. Configure and build OpenSSL (**Administrator CMD** — with Visual Studio environment set up as described in prerequisites):
   ```cmd
   cd path\to\repository\thirdparty_app\openssl-3.5.0
   perl Configure VC-WIN64A
   nmake
   nmake install
   cd ..\..
   ```

   > **Note:** Use `VC-WIN32` instead of `VC-WIN64A` for a 32-bit build.

## Test Cases (Windows)

> All commands below run from the **repository root** in a **CMD** terminal.

### 1. OpenSSL s_server vs openssl_client_local ECDSA Server Authentication

**Run OpenSSL s_server (CMD):**
```cmd
set PATH=%CD%\thirdparty_app\openssl-3.5.0;%PATH%
%CD%\thirdparty_app\openssl-3.5.0\apps\openssl.exe s_server -accept 1440 -cert keystore\openssl_connector\openssl_ecdsa_crt.pem -certform PEM -key keystore\openssl_connector\openssl_ecdsa_key.pem -keyform PEM -msg -www
```

**In a new CMD terminal, run the openssl_client_local sample:**
```cmd
set PATH=%CD%\bin_win32;%PATH%
bin_win32\openssl_client_local.exe --ssl_port=1440 --ssl_certpath=%CD%\keystore\openssl_connector --ssl_ca_cert=openssl_ec_ca_crt.pem
```

**Expected Output:** You should see the HTTP response from the OpenSSL s_server in the client terminal, indicating a successful SSL/TLS connection.

**Tip:** Run `openssl_client_local.exe --h` to see all available command-line options.

---

### 2. OpenSSL s_server vs openssl_client_local ECDSA Mutual Authentication

**Run OpenSSL s_server (CMD):**
```cmd
set PATH=%CD%\thirdparty_app\openssl-3.5.0;%PATH%
%CD%\thirdparty_app\openssl-3.5.0\apps\openssl.exe s_server -accept 1440 -cert keystore\openssl_connector\openssl_ecdsa_crt.pem -certform PEM -key keystore\openssl_connector\openssl_ecdsa_key.pem -keyform PEM -CAfile keystore\openssl_connector\openssl_ec_ca_crt.pem -Verify 10 -msg -www
```

**In a new CMD terminal, run the openssl_client_local sample:**
```cmd
set PATH=%CD%\bin_win32;%PATH%
bin_win32\openssl_client_local.exe --ssl_port=1440 --ssl_certpath=%CD%\keystore\openssl_connector --ssl_ca_cert=openssl_ec_ca_crt.pem --ssl_client_cert=openssl_ecdsa_crt.pem --ssl_client_keyblob=openssl_ecdsa_key.pem
```

**Expected Output:** You should see the HTTP response from the OpenSSL s_server in the client terminal. Both server and client verify each other's certificates.

**Tip:** Run `openssl_client_local.exe --h` to see all available command-line options.

---

### 3. openssl_server vs OpenSSL s_client ECDSA Mutual Authentication

**Run openssl_server (CMD):**
```cmd
set PATH=%CD%\bin_win32;%PATH%
bin_win32\openssl_server.exe --ssl_port=1440 --ssl_certpath=%CD%\keystore\openssl_connector --ssl_server_cert=openssl_ecdsa_crt.pem --ssl_server_keyblob=openssl_ecdsa_key.pem --ssl_ca_cert=openssl_ec_ca_crt.pem
```

**In a new CMD terminal, run the OpenSSL s_client:**
```cmd
set PATH=%CD%\thirdparty_app\openssl-3.5.0;%PATH%
%CD%\thirdparty_app\openssl-3.5.0\apps\openssl.exe s_client -CAfile keystore\openssl_connector\openssl_ec_ca_crt.pem -servername openssl-ecdsa -cert keystore\openssl_connector\openssl_ecdsa_crt.pem -key keystore\openssl_connector\openssl_ecdsa_key.pem -connect 127.0.0.1:1440 -msg
```

**Expected Output:** You should see the connection established and mutual authentication completed in both terminals. Both server and client verify each other's certificates.

**Tip:** Run `openssl_server.exe --h` to see all available command-line options.

---

### 4. openssl_server vs OpenSSL s_client ECDSA Server Authentication

**Rebuild openssl_server without mutual authentication:**
```cmd
cd thirdparty\openssl-3.5.0\sample
build.bat <--x32|--x64> openssl_server
cd ..\..\..
```

**Run openssl_server (CMD):**
```cmd
set PATH=%CD%\bin_win32;%PATH%
bin_win32\openssl_server.exe --ssl_port=1440 --ssl_certpath=%CD%\keystore\openssl_connector --ssl_server_cert=openssl_ecdsa_crt.pem --ssl_server_keyblob=openssl_ecdsa_key.pem
```

**In a new CMD terminal, run the OpenSSL s_client:**
```cmd
set PATH=%CD%\thirdparty_app\openssl-3.5.0;%PATH%
%CD%\thirdparty_app\openssl-3.5.0\apps\openssl.exe s_client -CAfile keystore\openssl_connector\openssl_ec_ca_crt.pem -servername openssl-ecdsa -connect localhost:1440 -msg
```

**Expected Output:** You should see the connection established and handshake messages in both terminals. The client verifies the server's ECDSA certificate.

**Note:** The `-servername` option specifies the SNI hostname, which should match the subject name or SAN in the server certificate.

**Tip:** Run `openssl_server.exe --h` to see all available command-line options.

## TAP Integration (Linux)

The steps below validate TAP support in the connector's own `openssl_server`/
`openssl_client_tap` samples. They aren't required for third-party application
integration (see above) — use them to confirm TAP is working end-to-end before
pointing a third-party application at it. Supported OpenSSL versions are the
same as above: 3.0.7, 3.0.12, 3.5.0.

### Local mode

This mode uses a local TPM2 instance for key operations.

#### Prerequisites

1. **Obtain test artifacts and keystore files**:
   - Test configuration files and keystores.
   - TPM2 configuration file (`tpm2.conf`)

   Copy these into the repository or reference them from external paths.

#### Configuration Setup (Terminal 1)

1. **Set up OpenSSL 3.5.0 source:**
   ```bash
   mkdir -p thirdparty
   wget https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz
   tar -xzf openssl-3.5.0.tar.gz -C thirdparty/
   ```

2. **Obtain keystore files** (certificates and keys for TAP local mode):
   - Copy or ensure these files exist in `keystore/`:
     - `<openssl-s-client-key>` - OpenSSL s_client test private key
     - `<openssl-s-client-cert>` - OpenSSL s_client certificate
     - `<tpm2-ca-cert>.pem` — Certificate Authority certificate
     - `<tpm2-cert>.pem` — TPM2-backed server certificate
     - `<tpm2-key>.pem` — TPM2-backed server test private key
     - `<openssl-s-client-ca-cert>.pem` — OpenSSL s_client CA certificate
     - `<tpm2-config>.conf` — TPM2 configuration file
     - `*.tpm2` files — TPM2-specific credential files

3. **Obtain TPM2 configuration**:
   - Copy `tpm2.conf` to a suitable location (e.g., `tap_remote_conf/tpm2.conf` or `/home/trustcore/tap_remote_conf/`)

4. **Apply patches:**
   ```bash
   cd scripts/openssl
   ./apply-patch.sh openssl-3.5.0
   cd ../../
   ```

5. **Build the connector with local TAP:**
   ```bash
   ./scripts/nanossl/openssl_connector/build_openssl_connector_tap_local.sh --gdb --debug --tap-hybrid-sign --openssl_3_5_0
   ```
   This builds the shim library to `lib/` and also builds `openssl_client_tap` to `thirdparty/openssl-3.5.0/sample/`. You can run `openssl_client_tap` against an OpenSSL s_server, or as shown in the example below, build and run `openssl_server` and test with OpenSSL s_client.

   Add other flags as needed (run with `--help` for the full list, e.g., `--redefine` for Node.js compatibility, `--self_signed` / `--non_trusted` for certificate validation).

#### Build and Start OpenSSL Server (Terminal 1)

```bash
export PWD_DIR=$PWD
export LD_LIBRARY_PATH=$PWD_DIR/lib

cd thirdparty/openssl-3.5.0/sample
make mauth=true tap=true clean openssl_server

./openssl_server \
  --ssl_port 1441 \
  --ssl_certpath <path-to-keystore> \
  --ssl_server_cert <tpm2-cert>.pem \
  --ssl_server_keyblob <tpm2-key>.pem \
  --ssl_ca_cert <openssl-s-client-ca-cert>.pem \
  --tap_config_file <path-to-tpm2-config>/tpm2.conf
```

**Example:**
```bash
./openssl_server \
  --ssl_port 1441 \
  --ssl_certpath /home/agent/trustcore/keystore \
  --ssl_server_cert rsa-tpm2-cert.pem \
  --ssl_server_keyblob rsa-tpm2-key.pem \
  --ssl_ca_cert athena_ca.pem \
  --tap_config_file /home/agent/trustcore/tap_remote_conf/tpm2.conf
```

#### Run OpenSSL s_client Test (Terminal 2)

With the openssl_server running, connect with an OpenSSL s_client using the pre-built OpenSSL:

```bash
export LD_LIBRARY_PATH=${PWD}/thirdparty_app/openssl-3.5.0/lib:$LD_LIBRARY_PATH
${PWD}/thirdparty_app/openssl-3.5.0/apps/openssl s_client \
  -tls1_3 \
  -connect 127.0.0.1:1441 \
  -ciphersuites TLS_CHACHA20_POLY1305_SHA256 \
  -CAfile <path-to-keystore>/<tpm2-ca-cert>.pem \
  -servername <server-name> \
  -cert <path-to-keystore>/<openssl-s-client-cert>.pem \
  -key <path-to-keystore>/<openssl-s-client-key>.pem \
  -msg
```

**Example:**
```bash
export LD_LIBRARY_PATH=${PWD}/thirdparty_app/openssl-3.5.0:$LD_LIBRARY_PATH
${PWD}/thirdparty_app/openssl-3.5.0/apps/openssl s_client \
  -tls1_3 \
  -connect 127.0.0.1:1441 \
  -ciphersuites TLS_CHACHA20_POLY1305_SHA256 \
  -CAfile keystore/tpm2_ca.pem \
  -servername jenkins-auto-trustcore \
  -cert keystore/athena_rsa_cert.pem \
  -key keystore/athena_rsa_key.pem \
  -msg
```

**Expected Output:** You should see the SSL/TLS handshake complete with messages from both the server and client, confirming successful TPM2-backed mutual authentication.

### Remote mode

This mode requires a remote TAP server.

#### Prerequisites

1. **Build the remote TAP server** (in a separate repository copy):

   Since building the remote TAP server and the OpenSSL connector would overwrite shared library files, build the TAP server in a separate copy of the repository:

   ```bash
   cd <path-to-separate-tap-server-repo>
   ./NanoTAP_scripts/nanotap2_build.sh
   ```

   This produces the TAP server binary and libraries in `lib/nanotap_server_bin` and related libraries that will be used to run the remote TAP server.

2. **Obtain TAP configuration files**:
   - `tapc_mauth.conf` — TAP client configuration
   - `taps_mauth.conf` — TAP server configuration

   Copy these into a `tap_remote_conf/` directory within the trustcore repository root.

#### Configuration Setup (Terminal 1)

1. **Set up OpenSSL 3.5.0 source:**
   ```bash
   mkdir -p thirdparty
   wget https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz
   tar -xzf openssl-3.5.0.tar.gz -C thirdparty/
   ```

2. **Apply patches:**
   ```bash
   cd scripts/openssl
   ./apply-patch.sh openssl-3.5.0
   cd ../../
   ```

3. **Obtain keystore files** (certificates and keys for TAP remote mode):
   - Copy or ensure these files exist in `keystore/`:
     - `<ca-cert>.pem` — Certificate Authority certificate
     - `<server-cert>.pem` — Server certificate
     - `<server-key>.pem` — Server private key
     - Additional client certificates/keys if using mutual authentication

4. **Set up TAP client configuration:**
   ```bash
   sudo cp tap_remote_conf/tapc_mauth.conf /etc/digicert/tapc.conf
   ```
   > **Note:** If replacing an existing config, back it up first: `sudo cp /etc/digicert/tapc.conf /etc/digicert/tapc.conf.orig`

5. **Build the connector for remote TAP:**
   ```bash
   ./scripts/nanossl/openssl_connector/build_openssl_connector_tap_remote.sh --gdb --debug --tap-hybrid-sign --openssl_3_5_0
   ```

   This builds the shim library to `lib/` and also builds `openssl_client_tap` to `thirdparty/openssl-3.5.0/sample/`. You can run `openssl_client_tap` against an OpenSSL s_server, or as shown in the example below, build and run `openssl_server` and test with OpenSSL s_client.

   Add other flags as needed (run with `--help` for the full list).

#### Start TAP Remote Server (Terminal 2)

Start the remote TAP server from the separate TAP server repository:

```bash
export TAP_SERVER_REPO=<path-to-separate-tap-server-repo>
export TRUSTCORE_REPO=<path-to-trustcore-repo>

sudo -S LD_LIBRARY_PATH="$TAP_SERVER_REPO/lib" "$TAP_SERVER_REPO/lib/nanotap_server_bin" --conf="$TRUSTCORE_REPO/tap_remote_conf/taps_mauth.conf"
```

#### Build and Start OpenSSL Server (Terminal 1)

```bash
export PWD_DIR=$PWD
export LD_LIBRARY_PATH=$PWD_DIR/lib

cd thirdparty/openssl-3.5.0/sample
make mauth=true tap=true tap_remote=true clean openssl_server

./openssl_server \
  --ssl_port 1441 \
  --ssl_certpath <path-to-keystore> \
  --ssl_server_cert <server-cert>.pem \
  --ssl_server_keyblob <server-key>.pem \
  --ssl_ca_cert <ca-cert>.pem \
  --tap_server_name <tap-server-hostname> \
  --tap_server_port <tap-server-port>
```

**Example:**
```bash
./openssl_server \
  --ssl_port 1441 \
  --ssl_certpath /home/trustcore/keystore \
  --ssl_server_cert rsa-tpm2-cert.pem \
  --ssl_server_keyblob rsa-tpm2-key.pem \
  --ssl_ca_cert ca.pem \
  --tap_server_name ssltest.example.com \
  --tap_server_port 8278
```

#### Run OpenSSL s_client Test (Terminal 3)

With the TAP remote server and openssl_server running, connect with an OpenSSL s_client using the pre-built OpenSSL from `thirdparty_app/`:

```bash
export LD_LIBRARY_PATH=${PWD}/thirdparty_app/openssl-3.5.0:$LD_LIBRARY_PATH
${PWD}/thirdparty_app/openssl-3.5.0/apps/openssl s_client \
  -tls1_3 \
  -connect 127.0.0.1:1441 \
  -ciphersuites TLS_CHACHA20_POLY1305_SHA256 \
  -CAfile <path-to-keystore>/<ca-cert>.pem \
  -servername <server-name> \
  -cert <path-to-keystore>/<client-cert>.pem \
  -key <path-to-keystore>/<client-key>.pem
```

**Example:**
```bash
export LD_LIBRARY_PATH=${PWD}/thirdparty_app/openssl-3.5.0:$LD_LIBRARY_PATH
${PWD}/thirdparty_app/openssl-3.5.0/apps/openssl s_client \
  -tls1_3 \
  -connect 127.0.0.1:1441 \
  -ciphersuites TLS_CHACHA20_POLY1305_SHA256 \
  -CAfile keystore/ca.pem \
  -servername test-server \
  -cert keystore/client-cert.pem \
  -key keystore/client-key.pem
```

**Expected Output:** You should see the SSL/TLS handshake complete with messages from both the server and client, confirming successful mutual authentication via the remote TAP server.

---

## Third-Party Application Integration

Integrating NanoSSL with third-party applications enables these applications to
utilize NanoSSL's SSL/TLS implementation and cryptographic operations. This
section will guide you through configuring NanoSSL for use with third-party
applications such as Python scripts or Apache web servers.

Any application that links against OpenSSL's `libssl`/`libcrypto` can use
NanoSSL this way by pointing `LD_LIBRARY_PATH` at the shim library built in the
*Linux* section above — no rebuild of the application is required, as long as
it was built against a compatible OpenSSL version.

### Tested applications

The shim has been verified to interoperate with:
- curl
- Apache httpd
- Node.js
- OpenLDAP
- Python

All of them follow the same pattern: build/install the application against a
standard OpenSSL as usual, then run it with `LD_LIBRARY_PATH` pointed at the
shim instead of that OpenSSL install.

### Example: curl (non-TAP)

```bash
# Build curl against a normal OpenSSL install (see curl's own build docs).

# Runs against the OpenSSL it was built with:
/opt/curl-openssl/bin/curl -v https://example.com

# Runs against the NanoSSL shim instead — no rebuild needed:
export LD_LIBRARY_PATH=${PWD}/lib:$LD_LIBRARY_PATH
/opt/curl-openssl/bin/curl -v https://example.com
```

### Using TAP keys (optional)

TAP lets the application use asymmetric keys and certificates backed by a
TPM or other secure element instead of plain software keys, for its secure operations. It is not
required for the plain integration above — add it only if the application
needs TAP-backed keys. Set the matching environment variables below before
running it, and build the
connector with `_extern` support so the shim reads them.

#### Local TAP

```bash
export MOCANA_TAPCONFIGFILE='/etc/digicert/tpm2.conf'
export MOCANA_TAPPROVIDER='TAP_PROVIDER_TPM2'
```

Build the extern-enabled connector:
```bash
cd scripts/nanossl/openssl_connector/
./build_openssl_connector_tap_local_extern.sh --openssl_3_5_0
```

#### Remote TAP

```bash
export MOCANA_TAPSERVERNAME='ssltest.example.com'
export MOCANA_TAPSERVERPORT='8277'
export MOCANA_TAPPROVIDER='TAP_PROVIDER_TPM2'
export MOCANA_TAPCCONFIG='/etc/digicert/tapc.conf'
```

Build the extern-enabled connector for remote TAP:
```bash
cd scripts/nanossl/openssl_connector/
./build_openssl_connector_tap_remote_extern.sh --openssl_3_5_0
```

---


## Additional Notes

- **Supported Versions:** OpenSSL 1.1.1i, 3.0.7, 3.0.12, 3.5.0. Build other versions by updating the version in the download, patch, and build script commands.
- **Scripts Location:** Build scripts are located in `scripts/nanossl/openssl_connector/` (e.g., `build_openssl_connector_cap.sh`/`build_openssl_connector_cap.bat`, `build_openssl_connector_tap_local.sh`/`build_openssl_connector_tap_local.bat`, `build_openssl_connector_tap_remote.sh`, `build_openssl_connector_tap_local_extern.sh`, `build_openssl_connector_tap_remote_extern.sh`). Run any script with `--help` flag for more build options (e.g., `./scripts/nanossl/openssl_connector/build_openssl_connector_cap.sh --help` on Linux, `scripts\nanossl\openssl_connector\build_openssl_connector_cap.bat --help` on Windows).
- **Keystore:** Ensure keystore files exist in `keystore/openssl_connector/`.
- **Troubleshooting:**
  - If connections fail, verify certificate paths, and check that `-servername` matches the certificate subject/SAN.
  - Use `-msg` flag to see detailed handshake messages for debugging.
