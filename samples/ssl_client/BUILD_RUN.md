# SSL Client Build and Run Guide

> **Note:** Run all commands from the root of the repository.

## CMake Options

| Option                            | Description                                  | Default |
|-----------------------------------|----------------------------------------------|---------|
| `ENABLE_TAP`                      | Enable TAP (tpm2) support                    | `OFF`   |
| `CM_ENABLE_SSL_MAUTH_SUPPORT`     | Enable Mutual Authentication                 | `OFF`   |
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
