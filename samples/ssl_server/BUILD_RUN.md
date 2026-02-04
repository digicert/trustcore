# SSL Server Build and Run Guide

> **Note:** Run all commands from the root of the repository.

## CMake Options

| Option                            | Description                                  | Default |
|-----------------------------------|----------------------------------------------|---------|
| `ENABLE_TAP`                      | Enable TAP (tpm2) support                    | `OFF`   |
| `CM_ENABLE_SSL_MAUTH_SUPPORT`     | Enable Mutual Authentication                 | `OFF`   |
| `CM_ENABLE_SSL_OCSP`              | Enable OCSP support                          | `OFF`   |
| `DISABLE_SSL_CLIENT`              | Build the server only and disable the client | `OFF`   |

> **Note:** The Server is enabled by default, ie no enable flag is needed. For the complete list of options and their details, refer to [`projects/nanossl/CMakeLists.txt`](../../projects/nanossl/CMakeLists.txt).
> For common build options (e.g., `BUILD_SAMPLES`), see [`GUIDE.md`](../../GUIDE.md).

**Important:** The build commands above generate **both** `ssl_server` and `ssl_client` binaries in `build/samples/bin`. If you've already built from the [SSL Client guide](../ssl_client/BUILD_RUN.md) for the same authentication case, the binaries already exist. Rebuilding with different options may overwrite them and potentially cause compilation issues or runtime errors.

### 1. Build

```bash
cmake -DBUILD_SAMPLES=ON -B build -S .
cmake --build build
```

### 2. Run Server (default arguments with new key and cert generation)

Server command:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/ssl_server
```

### 3. Run Server (basic non-default arguments)

Server command:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/ssl_server -ssl_port ${SSL_SERVER_PORT} -ssl_servername ${SSL_SERVER_NAME} -ssl_server_cert ${SSL_SERVER_CERT} -ssl_server_keyblob ${SSL_SERVER_KEYBLOB}
```
