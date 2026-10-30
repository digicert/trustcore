# SSL Server Build and Run Guide

> **Note:** Run all commands from the root of the repository.

## CMake Options

| Option                            | Description                                  | Default |
|-----------------------------------|----------------------------------------------|---------|
| `ENABLE_TAP`                      | Enable TAP (tpm2) support                    | `OFF`   |
| `CM_ENABLE_SSL_MAUTH_SUPPORT`     | Enable Mutual Authentication                 | `OFF`   |
| `CM_ENABLE_SSL_OCSP`              | Enable OCSP support                          | `OFF`   |
| `ENABLE_PQC_COMPOSITE`            | Enable PQC composite algorithm support       | `OFF`   |
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

## Docker (Ubuntu 22.04)

The `samples/ssl_server/Dockerfile` clones TrustCore from GitHub, builds the `ssl_server` sample, and starts it in the foreground on port `1440`. The commands below run on the host from a terminal with Docker Engine installed and running. The Docker build requires network access to GitHub.

### 1. Build the image

```bash
docker build --progress=plain -t trustcore-nanossl:local -f samples/ssl_server/Dockerfile .
```

Run the command from the TrustCore repository root. the TrustCore source is cloned from `https://github.com/digicert/trustcore.git` during the image build. The clone uses the repository's default branch at build time. The image installs Git, CA certificates, CMake, the C/C++ build toolchain, and Python 3 before building the samples.

### 2. Run the server

```bash
docker run --detach --name trustcore-nanossl -p 1440:1440 trustcore-nanossl:local
```

Port `1440` is the NanoSSL sample's default. The `-p` option publishes that container port on the host; `EXPOSE` in the Dockerfile alone does not publish it.

### 3. Check and follow logs

Confirm the container is running and inspect its recent output:

```bash
docker ps --filter name=trustcore-nanossl
docker logs --tail 50 trustcore-nanossl
```

Follow new output in real time with `Ctrl+C` to stop following without stopping the server:

```bash
docker logs --follow trustcore-nanossl
```

The sample reports `Server listening on port 1440` when startup succeeds. A client can connect to `localhost:1440` on the host.

### 4. Stop and remove the container

```bash
docker stop trustcore-nanossl
docker rm trustcore-nanossl
```

### Troubleshooting

- **Docker daemon unavailable:** Start Docker Engine and verify `docker info` succeeds, then retry the build.
- **Repository clone fails:** Verify Docker has network access to `github.com`, then retry the build. The image clones the repository's default branch during build.
- **CMake or compilation fails:** Keep the full build output and retry after checking for transient GitHub/network failures. The cloned repository supplies the `src/`, `projects/`, `samples/`, `thirdparty/`, and `keystore/` directories used by the build and sample.
- **Container exits during startup:** Run `docker ps -a --filter name=trustcore-nanossl` and `docker logs trustcore-nanossl`. Confirm the configured certificate and key paths are present in the cloned repository's `keystore/` directory.
- **Host port is already in use:** Publish another host port, for example `-p 1441:1440`, and connect to `localhost:1441`. The server still listens on `1440` inside the container.
- **Container is already named:** Remove the old container with `docker rm -f trustcore-nanossl`, then run the `docker run` command again.

This image includes the repository's sample keystore and is intended for development/testing. Do not deploy its sample keys or certificates in production.
