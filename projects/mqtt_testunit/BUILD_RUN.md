# Build and Run Instructions for NanoMQTT Unit Test

This guide explains how to build and run the NanoMQTT Unit Test.

> **Note:** Run all commands from the root of the repository.

## Prerequisites
Install required dependencies:
```bash
sudo apt update
sudo apt install -y libcmocka-dev
```

### Build Instructions
```bash
cmake -DENABLE_MQTT_CLIENT=ON -DENABLE_MQTT_UNITTEST=ON  -B build -S .
cmake --build build
```

### Run Instructions
```bash
./projects/mqtt_testunit/run.sh
```

### Build with Streaming Support
```bash
cmake -DENABLE_MQTT_CLIENT=ON -DENABLE_MQTT_UNITTEST=ON -DENABLE_MQTT_STREAMING=ON -B build -S .
cmake --build build
```

### Run Instructions with Streaming Support
```bash
./projects/mqtt_testunit/run.sh --streaming
```