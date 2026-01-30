# TAP API Example Build and Run Guide

> **Note:** All commands are from the root of the repository.

## CMake Options

| Option                     | Description                                            | Default |
|----------------------------|--------------------------------------------------------|---------|
| `BUILD_SAMPLES`            | Build Samples including the TAP API Example            | `OFF`   |
| `ENABLE_TAP_API_EXAMPLE`   | Build the supporting libraries for the TAP API example | `OFF`   |


> **Note:** TAP will be enabled by default once ENABLE_TAP_API_EXAMPLE is defined as ON.

### 1. Build

```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_TAP_API_EXAMPLE=ON -B build -S .
cmake --build build
```

### 2. Setup

TPM2 configuration files such as tpm2.conf, creds.tpm2, creds.tpm2.sig.json, and/or default-creds.tpm2,
need to be setup ahead of time. For example they might be placed in the /etc/digicert folder with
your user's access to them. The example will take an argument to the path of tpm2.conf file, so one may
create an environment variable to it...

```bash
export TPM2_CONF_FILE=/etc/digicert/tpm2.conf
```

### 3. Run

```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/tap_api_example --tpm2conf ${TPM2_CONF_FILE}
```
