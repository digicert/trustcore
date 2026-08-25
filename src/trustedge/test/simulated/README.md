# TrustEdge Simulated Test Framework

This test framework allows you to run simulated integration tests for TrustEdge by sending MQTT messages and validating responses and side effects.

## Prerequisites

Build TrustEdge with the unittest option to generate required test binaries:

```bash
VERBOSE=1 ./scripts/ci/trustedge/ci_trustedge_build.sh --version-string 1.0.0 \
    --monolithic --tpm2 --cvc --proxy --pqc --pqc-composite \
    --enable-pc --package --azure-dps --gdb --unittest
```

## Running Tests

```bash
cd trustcore-test
./src/trustedge/test/simulated/run_test.sh --test-dir <test-dir>
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--test-dir <path>` | **Required.** Path to the test directory |
| `--build` | Build TrustEdge before running the test |
| `--gdb` | Enable GDB mode - pauses at key points for debugger attachment |
| `--valgrind` | Run TrustEdge under Valgrind for memory leak detection |

### Examples

```bash
# Run a test
./src/trustedge/test/simulated/run_test.sh --test-dir ./src/trustedge/test/cloud_platform_policy_azure_dps

# Run with GDB debugging
./src/trustedge/test/simulated/run_test.sh --test-dir ./src/trustedge/test/cloud_platform_policy_azure_dps --gdb

# Run with Valgrind memory checking
./src/trustedge/test/simulated/run_test.sh --test-dir ./src/trustedge/test/cloud_platform_policy_azure_dps --valgrind

# Build and run
./src/trustedge/test/simulated/run_test.sh --build --test-dir ./src/trustedge/test/cloud_platform_policy_azure_dps
```

## Test Execution Flow

1. **Setup**: Copies test directory to `<test-dir>_workspace` and substitutes `<path>` placeholders
2. **Start processes**: Mosquitto broker, Azure DPS mock server, TrustEdge agent
3. **Send messages**: Iterates through numbered request files, sends each via MQTT
4. **Capture responses**: Subscribes to NDATA topic and captures agent responses
5. **Validate**: Compares generated files against `.validate` expected files
6. **Cleanup**: Terminates all test processes

## Adding Tests

### 1. Create Test Directory Structure

```bash
mkdir -p src/trustedge/test/my_test/{conf,keystore,cloudprovider,messages}
```

### 2. Create Required Configuration Files

#### trustedge.json
TrustEdge configuration file. Use `<path>` placeholder for paths that need to reference the workspace directory:

```json
{
    "directory_paths": {
        "root_dir": "<path>",
        "conf_dir": "<path>/conf",
        "keystore_dir": "<path>/keystore"
    },
    "agent": {
        "bootstrap": "<path>/bootstrap_config.json"
    }
}
```

#### bootstrap_config.json
Must contain `account_id` and `device_id` used for MQTT topic construction:

```json
{
    "configuration": {
        "device_id": "DEVICE-ID-TEST-0",
        "account_id": "ACCOUNT-ID-TEST-0"
    }
}
```

### 3. Create Test Messages

Each test message requires three files in the `messages/` directory:

| File | Description |
|------|-------------|
| `{N}-req.uuid` | UUID for the message |
| `{N}-req.body` | JSON body of the message |
| `{N}-req.responses` | **Required.** Number of expected responses (0-N) |

Where `{N}` is the sequence number starting from 1.

#### Example: messages/1-req.uuid
```
550e8400-e29b-41d4-a716-446655440000
```

#### Example: messages/1-req.body
```json
{
    "timestamp": "*",
    "action": "provision"
}
```

> **Note**: The `"timestamp": "*"` pattern is automatically replaced with the current timestamp at runtime.

#### Example: messages/1-req.responses
```
1
```

Set to `0` if no response is expected for this message.

### 4. Add Validation Files

Create `.validate` files for any files that TrustEdge generates during the test. The test framework will compare the actual output against these expected files byte-by-byte.

```bash
# Example: validate a cloud provider configuration file
vim src/trustedge/test/my_test/cloudprovider/193850392.json.validate
```

The validation file should contain the exact expected content of the corresponding file (without the `.validate` extension).

### 5. Add Supporting Files

Add any additional files needed by your test:
- Certificates and keys in `keystore/`
- Configuration files in `conf/`
- Cloud provider credentials in `cloudprovider/`

## Test Output Files

During test execution, the following files are generated in `<test-dir>_workspace/messages/`:

| File | Description |
|------|-------------|
| `{N}-req.protobuf` | Generated protobuf message sent to TrustEdge |
| `{N}-resp.log` | Raw mosquitto_sub output for sequence N |
| `{N}-resp-{M}.topic` | Topic of response M for sequence N |
| `{N}-resp-{M}.hex` | Hex-encoded payload of response M |
| `{N}-resp-{M}.bin` | Binary payload of response M |

## Log Files

Log files are created in the working directory:

| File | Description |
|------|-------------|
| `trustedge.log` | TrustEdge agent stdout/stderr |
| `trustedge.valgrind` | Valgrind output (when using `--valgrind`) |
| `mosquitto.log` | Mosquitto broker output |
| `mock_azure_dps_server.log` | Azure DPS mock server output |

## Troubleshooting

### Test fails with "process is running" error
Kill any leftover processes from previous test runs:
```bash
pkill -f trustedge
pkill -f mosquitto
pkill -f mock_azure_dps_server.py
```

### Validation fails but content looks identical
Check for invisible differences (line endings, trailing newlines):
```bash
diff <(xxd file1) <(xxd file2)
```

### Test hangs waiting for responses
- Check `trustedge.log` for errors
- Verify the `.responses` file has the correct count
- Use `--gdb` mode to step through execution