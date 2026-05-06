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
| Component                 | Description                   | Guide                                                    |
|---------------------------|-------------------------------|----------------------------------------------------------|
| **MQTT Client**           | MQTT client                   | **[→ Build & Run](samples/mqtt_client/BUILD_RUN.md)**    |
| **MQTT Functional Test**  | Functional tests for NanoMQTT | **[→ Build & Run](src/mqtt/test/BUILD_RUN.md)**          |
| **MQTT Unit Test**        | Unit tests for NanoMQTT       | **[→ Build & Run](projects/mqtt_testunit/BUILD_RUN.md)** |

### ⚙️ NanoROOT
| Component       | Description           | Guide                                                 |
|---------------- |-----------------------|-------------------------------------------------------|
| **NanoROOT**    | NanoROOT SMP library  | **[→ Build & Run](samples/nanoroot/BUILD_RUN.md)**    |

### 🔒 NanoCrypto Example
| Component              | Description                                        | Guide                                                              |
|------------------------|----------------------------------------------------|--------------------------------------------------------------------|
| **NanoCrypto Example** | Demonstrates NanoCrypto usage via crypto interface | **[→ Build & Run](samples/crypto_interface_example/BUILD_RUN.md)** |

### 🛠️ NanoSSL
| Component       | Description           | Guide                                                 |
|---------------- |-----------------------|-------------------------------------------------------|
| **SSL Server**  | SSL server            | **[→ Build & Run](samples/ssl_server/BUILD_RUN.md)**  |
| **SSL Client**  | SSL client            | **[→ Build & Run](samples/ssl_client/BUILD_RUN.md)**  |

### 🧩 TAP API Example
| Component          | Description                     | Guide                                                     |
|--------------------|---------------------------------|-----------------------------------------------------------|
| **TAP API Example** | Demonstrates TAP API with TPM2 | **[→ Build & Run](samples/tap_api_example/BUILD_RUN.md)** |

### 📜 NanoCert SCEP
| Component       | Description                                 | Guide                                                    |
|-----------------|---------------------------------------------|----------------------------------------------------------|
| **SCEP Sample** | SCEP certificate enrollment sample          | **[→ Build & Run](samples/nanocert_scep/BUILD_RUN.md)**  |

### 🔐 NanoCert EST
| Component      | Description                                  | Guide                                                   |
|----------------|----------------------------------------------|---------------------------------------------------------|
| **EST Sample** | EST certificate enrollment sample            | **[→ Build & Run](samples/nanocert_est/BUILD_RUN.md)**  |

### 🛡️ NanoSec
| Component     | Description                  | Guide                                              |
|---------------|------------------------------|----------------------------------------------------|
| **NanoSec**   | IPsec/IKE security sample    | **[→ Build & Run](samples/nanosec/BUILD_RUN.md)**  |

### 🔗 OpenSSL Connector
| Component            | Description                           | Guide                                                       |
|----------------------|---------------------------------------|-------------------------------------------------------------|
| **OpenSSL Connector** | Demonstrates OpenSSL Connector Usage | **[→ Build & Run](samples/openssl_connector/BUILD_RUN.md)** |

### 🏢 TrustEdge
| Component     | Description                                                 | Guide                                               |
|---------------|-------------------------------------------------------------|-----------------------------------------------------|
| **TrustEdge** | IoT device provisioning and lifecycle management executable | **[→ Build & Run](samples/trustedge/BUILD_RUN.md)** |


## ⚙️ Commonly Used CMake Options

| Option                            | Description                               | Default |
|-----------------------------------|-------------------------------------------|---------|
| `BUILD_SAMPLES`                   | Build sample applications                 | `OFF`   |
| `WITH_LOGGING`                    | Build with logging enabled                | `OFF`   |
| `SECURE_PATH`                     | Enable secure path restriction            | Not set |

## 📝 Build Notes

- **SSL Library:** Built by default (CM_ENABLE_SSL=ON).
- **BUILD_SAMPLES:** Builds sample applications only for enabled modules (e.g., SSH client sample requires ENABLE_SSH_CLIENT=ON).
- **SECURE_PATH:** When set (e.g., `-DSECURE_PATH="/path/to/directory"`), restricts file operations to the specified directory only.

**Note:** For module-specific CMake options, refer to the respective `BUILD_RUN.md` (e.g., `samples/ssh_client/BUILD_RUN.md`) in the `samples/<module>` directories. These may include additional flags tailored to individual components.

## 🛠️ Build Steps

For detailed build and run instructions, including specific CMake commands and examples, refer to the `BUILD_RUN.md` file for your selected module above.
