# WebSocket Client Build and Run Guide

> **Note:** Run all commands from the root of the repository.

## Prerequisites

Install [websocat](https://github.com/vi/websocat) to act as the WebSocket server:

```bash
sudo apt update
sudo apt install cargo rustup tshark pkg-config
rustup default stable
cargo install websocat
```

websocat will be installed in `$HOME/.cargo/bin` by default. Before using websocat in a terminal:
```bash
export PATH=$HOME/.cargo/bin:$PATH
```

## CMake Options

| Option                     | Description                                      | Default |
|----------------------------|--------------------------------------------------|---------|
| `BUILD_SAMPLES`            | Build sample binaries                            | `OFF`   |
| `ENABLE_WEBSOCKET_SUPPORT` | Build WebSocket Client library                   | `OFF`   |
| `WITH_LOGGING`             | Enable debug console logging                     | `OFF`   |
| `WRITE_KEYLOG_FILE`        | Write NSS key log file for TLS traffic decryption| `OFF`   |

> For common build options, see [`GUIDE.md`](../../GUIDE.md).

## Build

```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_WEBSOCKET_SUPPORT=ON -B build -S .
cmake --build build
```

To build with debug logging enabled.

```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_WEBSOCKET_SUPPORT=ON -DWITH_LOGGING=ON -B build -S .
cmake --build build
```

To build with key logging enabled (for TLS traffic decryption).

```bash
cmake -DBUILD_SAMPLES=ON -DWITH_LOGGING=ON -DENABLE_WEBSOCKET_SUPPORT=ON -DWRITE_KEYLOG_FILE=ON -B build -S .
cmake --build build
```

## Run

### 1. Help

```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/websocket_sample --help
```

---

### 2. Plain WebSocket (ws://)

**Terminal 1 — start the WS echo server:**

```bash
websocat --binary ws-listen:127.0.0.1:8080 mirror:
```

**Terminal 2 — run the client:**

```bash
./samples/bin/websocket_sample -h 127.0.0.1 -p 8080
```

Type messages and press Enter. Each message is echoed back by the server.
Press **Ctrl-D** to disconnect cleanly.

Expected output:
```
Connecting to ws://127.0.0.1:8080/ ...
Connected. Type messages and press Enter (Ctrl-D to quit).

Client sends -> hello
Server replies -> hello
Client sends -> ^D

Disconnecting...
```

---

### 3. WebSocket over TLS (wss://) — insecure (self-signed cert, no verification)

**Step 1 — generate a self-signed certificate:**

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=127.0.0.1"
openssl pkcs12 -export -out server.p12 -inkey key.pem -in cert.pem -passout pass:test
```

**Terminal 1 — start the WSS echo server:**

```bash
websocat --binary --pkcs12-der server.p12 --pkcs12-passwd test wss-listen:127.0.0.1:8443 mirror:
```

**Terminal 2 — run the client (skip cert verification):**

```bash
./samples/bin/websocket_sample --tls --insecure -h 127.0.0.1 -p 8443
```

**NOTE: To see TLS handshake messages pass `--ssl-log` flag to the websocket sample.**

Expected output:
```
Connecting to wss://127.0.0.1:8443/ (insecure) ...
Connected. Type messages and press Enter (Ctrl-D to quit).

Client sends -> hello
Server replies -> hello
Client sends -> ^D

Disconnecting...
```

---

### 4. WebSocket over TLS (wss://) — with CA certificate verification

**Step 1 — generate a self-signed certificate (skip if already done above):**

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=127.0.0.1"
openssl pkcs12 -export -out server.p12 -inkey key.pem -in cert.pem -passout pass:test
```

**Step 2 — export the CA cert in DER format:**

```bash
openssl x509 -in cert.pem -outform DER -out cert.der
```

**Terminal 1 — start the WSS echo server:**

```bash
websocat --binary --pkcs12-der server.p12 --pkcs12-passwd test wss-listen:127.0.0.1:8443 mirror:
```

**Terminal 2 — run the client with CA cert:**

```bash
./samples/bin/websocket_sample --tls --ca-cert cert.der -h 127.0.0.1 -p 8443
```

**NOTE: To see TLS handshake messages pass `--ssl-log` flag to the websocket sample.**

**NOTE: The client writes session keys to `client_keys.txt`in the current directory.**

Expected output:
```
Connecting to wss://127.0.0.1:8443/ ...
Connected. Type messages and press Enter (Ctrl-D to quit).

Client sends -> hello
Server replies -> hello
Client sends -> ^D

Disconnecting...
```

---

## Capture Traffic with tshark

### Plain WebSocket (ws://)

```bash
sudo tshark -i lo -d tcp.port==8080,http -Y websocket
```

### WebSocket over TLS (wss://)

Decrypting `wss://` traffic requires an NSS key log file. Build with `-DWRITE_KEYLOG_FILE=ON`.

Capture traffic:

```bash
sudo tshark -i lo -w /tmp/wss_data.pcap
```

Press Ctrl+C once traffic is captured. And then to decrypt the tls traffic:

```bash
sudo tshark -r /tmp/wss_data.pcap -o "tls.keylog_file:client_keys.txt" -Y websocket
```

