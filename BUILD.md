# Build Instructions

This project includes client, server, and sample applications. You can build them with different options using CMake.

## 📦 Project Structure

## ⚙️ Build Options

| Option                            | Description                               | Default |
|-----------------------------------|-------------------------------------------|---------|
| `DISABLE_SSH_SERVER`              | Disable building SSH server library       | `OFF`   |
| `DISABLE_SSH_CLIENT`              | Disable building SSH client library       | `OFF`   |
| `ENABLE_SSH_SERVER_CERT_AUTH`     | Enable server certificate authentication  | `OFF`   |
| `ENABLE_SSH_CLIENT_CERT_AUTH`     | Enable client certificate authentication  | `OFF`   |
| `ENABLE_SSH_ASYNC_API_SUPPORT`    | Enable asynchronous SSH APIs              | `OFF`   |
| `ENABLE_SSH_CLIENT_SHELL_EXAMPLE` | Build SSH client shell example            | `OFF`   |
| `DISABLE_MQTT_CLIENT`             | Disable building MQTT client library      | `OFF`   |
| `WITH_LOGGING`                    | Build with logging enabled                | `OFF`   |
| `SECURE_PATH`                     | Enable secure path restriction            |         |
| `BUILD_SAMPLES`                   | Build samples applications                | `OFF`   |

## 🛠️ Build Steps

### 1. Configure the Project

```bash
cmake -DBUILD_SAMPLES=ON -B build -S .
```

```bash
cmake -DBUILD_SAMPLES=ON -DSECURE_PATH="/path/to/directory" -B build -S .
```

```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_SSH_SERVER_CERT_AUTH=ON -B build -S .
```

```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_SSH_CLIENT_CERT_AUTH=ON -B build -S .
```

```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_SSH_SERVER_CERT_AUTH=ON -DENABLE_SSH_CLIENT_CERT_AUTH=ON -B build -S .
```

### 2. Build Project

```bash
pushd build
make
popd
```

Note: If `BUILD_SAMPLES=ON` then sample binaries can be found in `samples/bin`. For more information reference samples/ssh_server/RUN.md and samples/ssh_client/RUN.md respectively.
