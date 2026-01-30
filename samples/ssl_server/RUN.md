### 1. Server (default arguments with new key and cert generation)

Server command:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/ssl_server
```

### 2. Server (basic non-default arguments)

Server command:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/ssl_server -ssl_port ${SSL_SERVER_PORT} -ssl_servername ${SSL_SERVER_NAME} -ssl_server_cert ${SSL_SERVER_CERT} -ssl_server_keyblob ${SSL_SERVER_KEYBLOB}
```
