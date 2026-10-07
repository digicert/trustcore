# MQTT Client Test Build and Run Guide

> **Note:** Run all commands from the root of the repository.

## Server Setup (EMQX)

Install and start a local EMQX broker using Docker:

```bash
sudo docker run -d --name emqx_local -p 1883:1883 -p 8883:8883 -p 8083:8083 -p 8084:8084 -p 18083:18083 \
--health-cmd "emqx_ctl status" --health-interval 10s --health-timeout 5s --health-retries 3 emqx/emqx:5.8.8
```

| Port  | Protocol       |
|-------|----------------|
| 1883  | MQTT (TCP)     |
| 8883  | MQTT over TLS  |
| 8083  | MQTT over WS   |
| 8084  | MQTT over WSS  |
| 18083 | Dashboard      |

Wait for the container to become healthy before running tests:

```bash
sudo docker inspect --format='{{.State.Health.Status}}' emqx_local
```

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

Ensure the local EMQX broker is running (see **Server Setup** above), or update the `serverAddress` field in the JSON configuration files to point to an available broker.

## WebSocket Transport

MQTT over WebSocket (WS/WSS) is supported when the build is enabled with `-DENABLE_WEBSOCKET_SUPPORT=ON`. The same test scenarios are available with a `-ws` suffix in the config file name:

- **Basic Config**: `src/mqtt/test/test-config-ws.json`
- **Async Config**: `src/mqtt/test/test-config-async-ws.json`
- **SSL Config**: `src/mqtt/test/test-config-ssl-ws.json`
- **Publish Extended Properties**: `src/mqtt/test/test-pub-ext-ws.json`
- **Publish Timeout**: `src/mqtt/test/test-pub-timeout-ws.json`
- **Publish Timeout Persist Mode**: `src/mqtt/test/test-pub-timeout-persist-ws.json`
- **Receive Maximum Test**: `src/mqtt/test/test-recv-max-ws.json`
- **Retry Test**: `src/mqtt/test/test-retry-ws.json`
- **Will Test**: `src/mqtt/test/test-will-ws.json`
- **Will Test QoS2**: `src/mqtt/test/test-will-qos2-ws.json`
- **Will Test Extended**: `src/mqtt/test/test-will-ext-ws.json`

Run them the same way:

```bash
./samples/bin/mqtt_client_test --mqtt_config src/mqtt/test/test-config-ws.json
```

WS configs connect over port `8083` (plain WebSocket) and WSS configs over port `8084` (WebSocket over TLS).
