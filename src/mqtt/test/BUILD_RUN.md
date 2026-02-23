# MQTT Client Test Build and Run Guide

> **Note:** Run all commands from the root of the repository.

## MQTT Client Test Usage

**Build**
```bash
cmake -DBUILD_SAMPLES=ON -DWITH_LOGGING=ON -DENABLE_MQTT_CLIENT=ON -DENABLE_MQTT_TEST=ON -B build -S .
cmake --build build
```

**Run**

The MQTT client tests use JSON configuration files to define test scenarios. Run individual tests with:

```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/mqtt_client_test --mqtt_config <config_file>
```

### Available Test Configurations

- **Basic Config**: `src/mqtt/test/test-config.json` - Basic MQTT operations.
- **Async Config**: `src/mqtt/test/test-config-async.json` - Asynchronous operations.
- **SSL Config**: `src/mqtt/test/test-config-ssl.json` - SSL/TLS operations.
- **Publish Extended Properties**: `src/mqtt/test/test-pub-ext.json` - Extended publish properties.
- **Publish Timeout**: `src/mqtt/test/test-pub-timeout.json` - Publish with timeout.
- **Publish Timeout Persist Mode**: `src/mqtt/test/test-pub-timeout-persist.json` - Timeout in persist mode.
- **Receive Maximum Test**: `src/mqtt/test/test-recv-max.json` - Receive maximum settings.
- **Retry Test**: `src/mqtt/test/test-retry.json` - Retry mechanisms.
- **Will Test**: `src/mqtt/test/test-will.json` - Will message tests.
- **Will Test QoS2**: `src/mqtt/test/test-will-qos2.json` - Will with QoS 2.
- **Will Test Extended**: `src/mqtt/test/test-will-ext.json` - Extended will tests.

Example:
```bash
./samples/bin/mqtt_client_test --mqtt_config src/mqtt/test/test-config.json
```

Ensure a local MQTT broker (e.g., Mosquitto on localhost) is running, or update the `serverAddress` field in the JSON configuration files to point to an available broker.
