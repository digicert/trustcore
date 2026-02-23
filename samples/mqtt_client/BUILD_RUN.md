# MQTT Client Build and Run Guide

> **Note:** Run all commands from the root of the repository.

## CMake Options

| Option                            | Description                                  | Default |
|-----------------------------------|----------------------------------------------|---------|
| `ENABLE_MQTT_CLIENT`              | Build MQTT Client library                    | `OFF`   |
| `ENABLE_MQTT_TEST`                | Enable MQTT Client Functional Test           | `OFF`   |
| `ENABLE_MQTT_UNITTEST`            | Enable MQTT Client Unit Test                 | `OFF`   |
| `ENABLE_MQTT_STREAMING`           | Enable Streaming Support                     | `OFF`   |

> **Note:** When `ENABLE_MQTT_CLIENT` is set to `ON`, it automatically enables proxy, async, persist, SCRAM, and SSL support.<br>
> For the complete list of options and their details, refer to [`projects/mqtt_client/CMakeLists.txt`](../../projects/mqtt_client/CMakeLists.txt).
> For common build options (e.g., `BUILD_SAMPLES`), see [`GUIDE.md`](../../GUIDE.md).

## Environment Variables Setup

```bash
export MQTT_SERVERNAME=test.mosquitto.org
export MQTT_PORT=1883
export MQTT_SSL_PORT=8883
```

## MQTT Client Usage

**Build**
```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_MQTT_CLIENT=ON -B build -S .
cmake --build build
```

**Run**

### 1. Help

For a list of all available options and their descriptions, run the MQTT client with the `--help` flag:

```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/mqtt_client --help
```

### 2. MQTT Subscribe (TCP)

This command subscribes to a topic and listens for messages. It runs continuously until interrupted (Ctrl+C).

Client command:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/mqtt_client --mqtt_servername ${MQTT_SERVERNAME} \
--mqtt_port ${MQTT_PORT} \
--mqtt_client_id sub_client \
--mqtt_sub_topic nanomqtt/sample \
--mqtt_clean_start
```

Expected output: Messages published to the topic will appear.

### 3. MQTT Publish (over TLS)

This command publishes a message to a topic. Run this in a separate terminal while the subscribe command is running to see the message received.

#### 3.1 Download CA Certificate

Get the CA certificate from the official Mosquitto test broker:

```bash
wget https://test.mosquitto.org/ssl/mosquitto.org.crt -O mosquitto_ca.crt
```

#### 3.2 Publish Command

Client command:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/mqtt_client --mqtt_servername ${MQTT_SERVERNAME} \
--mqtt_port ${MQTT_SSL_PORT} \
--mqtt_transport SSL \
--ssl_ca_file mosquitto_ca.crt \
--mqtt_client_id pub_client \
--mqtt_pub_topic nanomqtt/sample \
--mqtt_pub_message "Hello NanoMQTT" \
--mqtt_clean_start
```

Expected output: Confirmation of successful publish. The subscribe terminal should show the received message.

## Broker Options

### Public Brokers
- **test.mosquitto.org**
- **broker.hivemq.com**
- **mqtt.eclipseprojects.io**

### Local Brokers
For better control and testing, you can set up a local MQTT broker:
- **EMQX**: [EMQX Documentation](https://www.emqx.io/docs/en/latest/)
- **Mosquitto**: [Mosquitto Documentation](https://mosquitto.org/documentation/)
