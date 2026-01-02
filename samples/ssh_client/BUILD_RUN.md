Note: For ARM builds use aarch64 instead of linux-x86_64

### 1. Server Public Key Authentication

Client command:
```bash
export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:$LD_LIBRARY_PATH
./samples/bin/ssh_client -ip 127.0.0.1 -port 8818 -username admin -password secure
```

### 2. Server X509 Certificate Authentication

```bash
export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:$LD_LIBRARY_PATH
./samples/bin/ssh_client -port 8818 -ssh_ca_cert ${SSH_SERVER_CA_CERT} -username admin -password secure
```

### 3. Client X509 Certificate Authentication

```bash
export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:$LD_LIBRARY_PATH
./samples/bin/ssh_client -port 8818 -username admin -ssh_client_cert ${SSH_CLIENT_CERT} -ssh_client_blob ${SSH_CLIENT_KEYBLOB}
```

### 4. Server and Client X509 Certificate Authentication

```bash
export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:$LD_LIBRARY_PATH
./samples/bin/ssh_client -port 8818 -username admin -ssh_client_cert ${SSH_CLIENT_CERT} -ssh_client_blob ${SSH_CLIENT_KEYBLOB} -ssh_ca_cert ${SSH_SERVER_CA_CERT}
```
