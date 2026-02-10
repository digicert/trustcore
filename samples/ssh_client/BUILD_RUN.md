# SSH Client Build and Run Guide

> **Note:** Run all commands from the root of the repository.

## CMake Options

| Option                            | Description                                  | Default |
|-----------------------------------|----------------------------------------------|---------|
| `ENABLE_SSH_CLIENT`               | Build SSH Client library and sample binaries | `OFF`   |
| `ENABLE_SSH_CLIENT_CERT_AUTH`     | Enable SSH Client certificate authentication | `OFF`   |
| `ENABLE_SSH_CLIENT_AUTH`          | Enable SSH Client public key authentication  | `OFF`   |
| `ENABLE_SSH_CLIENT_SHELL_EXAMPLE` | Build SSH client shell example               | `OFF`   |
| `ENABLE_PQC_COMPOSITE`            | Enable PQC composite algorithm support       | `OFF`   |

> **Note:** For the complete list of options and their details, refer to [`projects/nanossh/CMakeLists.txt`](../../projects/nanossh/CMakeLists.txt).
> For common build options (e.g., `BUILD_SAMPLES`), see [`GUIDE.md`](../../GUIDE.md).

## Environment Variables Setup (Example with RSA)

You can set environment variables pointing to your keystore files:

```bash
export SSH_SERVER_CA_CERT=keystore/ca/rsa_ca.pem
export SSH_CLIENT_CERT=keystore/certs/rsa_cert.pem
export SSH_CLIENT_KEYBLOB=keystore/keys/rsa_key.pem
```

## Authentication Cases

**Important:** The build commands above generate **both** `ssh_client` and `ssh_server` binaries in `build/samples/bin`. If you've already built from the [SSH Server guide](../ssh_server/BUILD_RUN.md) for the same authentication case, the binaries already exist. Rebuilding with different options may overwrite them and potentially cause compilation issues or runtime errors.

### 1. Password Based Authentication

**Build**
```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT=ON -DENABLE_SSH_SERVER=ON -B build -S .
cmake --build build
```

**Run**
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/ssh_client -ip 127.0.0.1 -port 8818 -username admin -password secure
```

### 2. Server X509 Certificate Authentication

**Build**
```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT=ON -DENABLE_SSH_SERVER=ON -DENABLE_SSH_SERVER_CERT_AUTH=ON -DDISABLE_SUITEB=ON -DDISABLE_PQC=ON -B build -S .
cmake --build build
```

**Run**
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/ssh_client -port 8818 -ssh_ca_cert ${SSH_SERVER_CA_CERT} -username admin
```

### 3. Client X509 Certificate Authentication

**Build**
```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT=ON -DENABLE_SSH_SERVER=ON -DENABLE_SSH_CLIENT_CERT_AUTH=ON -DDISABLE_SUITEB=ON -DDISABLE_PQC=ON -DCM_ENABLE_SSL=OFF -B build -S .
cmake --build build
```

**Run**
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/ssh_client -port 8818 -username admin -ssh_client_cert ${SSH_CLIENT_CERT} -ssh_client_blob ${SSH_CLIENT_KEYBLOB}
```

### 4. Server and Client X509 Certificate Authentication

**Build**
```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT=ON -DENABLE_SSH_SERVER=ON -DENABLE_SSH_CLIENT_CERT_AUTH=ON -DENABLE_SSH_SERVER_CERT_AUTH=ON -DDISABLE_SUITEB=ON -DDISABLE_PQC=ON -B build -S .
cmake --build build
```

**Run**
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/ssh_client -port 8818 -username admin -ssh_client_cert ${SSH_CLIENT_CERT} -ssh_client_blob ${SSH_CLIENT_KEYBLOB} -ssh_ca_cert ${SSH_SERVER_CA_CERT}
```

## Additional Notes
- Replace placeholders (e.g., `${SSH_SERVER_CA_CERT}`, `${SSH_CLIENT_CERT}`, `${SSH_CLIENT_KEYBLOB}`) with actual file paths from `keystore/` or set environment variables as shown above.
- Ensure the SSH server is running before executing client commands (see `samples/ssh_server/BUILD_RUN.md`).
