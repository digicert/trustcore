# Build Instructions

> **Module-Specific Guides:** For detailed build and run instructions, select your module below.

---

## 📦 Modules

### 🔐 NanoSSH
| Component         | Description            | Guide                                                       |
|-------------------|------------------------|-------------------------------------------------------------|
| **SSH Server**    | Secure Shell server    | **[→ Build & Run](samples/ssh_server/BUILD_RUN.md)**        |
| **SSH Client**    | Secure Shell client    | **[→ Build & Run](samples/ssh_client/BUILD_RUN.md)**        |
| **SSH Unit Test** | Unit tests for NanoSSH | **[→ Build & Run](projects/nanossh_testunit/BUILD_RUN.md)** |

### 📡 NanoMQTT
| Component       | Description           | Guide                                                 |
|---------------- |-----------------------|-------------------------------------------------------|
| **MQTT Client** | MQTT client           | **[→ Build & Run](samples/mqtt_client/BUILD_RUN.md)** |

### ⚙️ NanoROOT
| Component       | Description           | Guide                                                 |
|---------------- |-----------------------|-------------------------------------------------------|
| **NanoROOT**    | NanoROOT SMP library  | **[→ Build & Run](samples/nanoroot/BUILD_RUN.md)**    |

## ⚙️ Commonly Used CMake Options

| Option                            | Description                               | Default |
|-----------------------------------|-------------------------------------------|---------|
| `BUILD_SAMPLES`                   | Build sample applications                 | `OFF`   |
| `WITH_LOGGING`                    | Build with logging enabled                | `OFF`   |
| `SECURE_PATH`                     | Enable secure path restriction            | Not set |

## 📝 Build Notes

- **BUILD_SAMPLES:** Builds sample applications only for enabled modules (e.g., SSH client sample requires ENABLE_SSH_CLIENT=ON).
- **SECURE_PATH:** When set (e.g., `-DSECURE_PATH="/path/to/directory"`), restricts file operations to the specified directory only.

**Note:** For module-specific CMake options, refer to the respective `BUILD_RUN.md` (e.g., `samples/nanoroot/BUILD_RUN.md`) in the `samples/<module>` directories. These may include additional flags tailored to individual components.

## 🛠️ Build Steps

For detailed build and run instructions, including specific CMake commands and examples, refer to the `BUILD_RUN.md` file for your selected module above.
