### 1. Client (default arguments)

Client command:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/ssl_client
```

### 2. Client (basic non-default arguments)

Client command:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/ssl_client -ssl_port ${SSL_SERVER_PORT} -ssl_servername ${SSL_SERVER_NAME} -ssl_server_cert ${SSL_SERVER_CERT}
```
