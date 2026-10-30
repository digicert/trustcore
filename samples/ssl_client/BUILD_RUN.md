# SSL Client Build and Run Guide

> **Note:** Run all commands from the root of the repository.

## CMake Options

| Option                            | Description                                  | Default |
|-----------------------------------|----------------------------------------------|---------|
| `ENABLE_TAP`                      | Enable TAP (tpm2) support                    | `OFF`   |
| `CM_ENABLE_SSL_MAUTH_SUPPORT`     | Enable Mutual Authentication                 | `OFF`   |
| `CM_ENABLE_SSL_OCSP`              | Enable OCSP support                          | `OFF`   |
| `ENABLE_PQC_COMPOSITE`            | Enable PQC composite algorithm support       | `OFF`   |
| `DISABLE_SSL_SERVER`              | Build the client only and disable the server | `OFF`   |

> **Note:** The Client is enabled by default, ie no enable flag is needed. For the complete list of options and their details, refer to [`projects/nanossl/CMakeLists.txt`](../../projects/nanossl/CMakeLists.txt).
> For common build options (e.g., `BUILD_SAMPLES`), see [`GUIDE.md`](../../GUIDE.md).

**Important:** The build commands above generate **both** `ssl_server` and `ssl_client` binaries in `build/samples/bin`. If you've already built from the [SSL Server guide](../ssl_server/BUILD_RUN.md) for the same authentication case, the binaries already exist. Rebuilding with different options may overwrite them and potentially cause compilation issues or runtime errors.

### 1. Build

```bash
cmake -DBUILD_SAMPLES=ON -B build -S .
cmake --build build
```

### 2. Run Client (default arguments)

Client command:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/ssl_client
```

### 3. Run Client (basic non-default arguments)

Client command:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/ssl_client -ssl_port ${SSL_SERVER_PORT} -ssl_servername ${SSL_SERVER_NAME} -ssl_server_cert ${SSL_SERVER_CERT}
```

## Docker

The client needs the server certificate in its keystore and cannot use `127.0.0.1` to reach a separate server container. The current NanoSSL Linux TCP implementation accepts numeric IP addresses and does not resolve Docker service names, so Compose assigns the server a fixed address on a private network. The setup builds separate server and client images, waits for the server port to become available, then copies only the public server certificate into a separate named volume for the client. The client's certificate volume is read-only and does not contain the server's private key. The client image also removes private-key artifacts from its cloned sample keystore.

Run the following command from the TrustCore repository root. The first run clones TrustCore and builds both images, so it requires network access to GitHub and may take several minutes.

```bash
docker compose -f samples/ssl_client/compose.yaml up --build --abort-on-container-exit --exit-code-from client
```

The client connects to `172.28.240.2:1440`, trusts `RSACertCA.der` from the exported public-certificate volume, and uses `webapptap.securitydemos.net` as the TLS server name. The server keystore and exported certificate volumes persist across runs. Remove the containers while keeping those volumes with:

```bash
docker compose -f samples/ssl_client/compose.yaml down
```

To remove the generated server keystore and exported certificate as well and start with fresh volumes on the next run:

```bash
docker compose -f samples/ssl_client/compose.yaml down --volumes
```

Sample private keys are for development/testing only. Do not use them in production or publish images containing production credentials.
