Note: For ARM builds use aarch64 instead of linux-x86_64

### 1. Server Public Key Authentication

Server command:
```bash
export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:$LD_LIBRARY_PATH
./samples/bin/ssh_server -port 8818
```

Note: To connect to sample server use `admin`/`secure` as user/password.

### 2. Server X509 Certificate Authentication

Server command:
```bash
export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:$LD_LIBRARY_PATH
./samples/bin/ssh_server -port 8818 -ssh_server_cert ${SSH_SERVER_CERT} -ssh_server_blob ${SSH_SERVER_KEYBLOB}
```

Note: To connect to sample server use `admin`/`secure` as user/password.

### 3. Client X509 Certificate Authentication

Server command:
```bash
export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:$LD_LIBRARY_PATH
./samples/bin/ssh_server -port 8818 -ssh_ca_cert ${SSH_CLIENT_CA_CERT}
```

Note: To connect to sample server use `admin`/`secure` as user/password.

### 4. Server and Client X509 Certificate Authentication

Server command:
```bash
export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:$LD_LIBRARY_PATH
./samples/bin/ssh_server -port 8818 -ssh_server_cert ${SSH_SERVER_CERT} -ssh_server_blob ${SSH_SERVER_KEYBLOB} -ssh_ca_cert ${SSH_CLIENT_CA_CERT}
```

Note: To connect to sample server use `admin`/`secure` as user/password.