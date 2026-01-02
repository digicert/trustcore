# Build and Run Instructions for NanoSSH Unit Test

This guide explains how to build and run the NanoSSH Unit Test.

> **Note:** Run all commands from the root of the repository.

## Prerequisites
Install required dependencies:
```bash
sudo apt update
sudo apt install -y libcmocka-dev
```

### Build Instructions
```bash
cmake -DENABLE_SSH_SERVER=ON -DENABLE_SSH_CLIENT=ON -DENABLE_SSH_UNITTEST=ON  -B build -S .
cmake --build build
```

### Run Instructions
```bash
./projects/nanossh_testunit/run.sh
```