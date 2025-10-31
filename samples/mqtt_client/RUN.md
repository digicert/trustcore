Note: For ARM builds use aarch64 instead of linux-x86_64

### 1. MQTT Subscribe

Client command:
```bash
export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:$LD_LIBRARY_PATH
./samples/bin/mqtt_client --mqtt_servername <broker> --mqtt_port <port> --mqtt_client_id <client_id> --mqtt_sub_topic <topic>
```

### 2. MQTT Publish

```bash
export LD_LIBRARY_PATH=lib/:crypto_lib/linux-x86_64/:$LD_LIBRARY_PATH
./samples/bin/mqtt_client --mqtt_servername <broker> --mqtt_port <port> --mqtt_client_id <client_id> --mqtt_pub_topic <topic> --mqtt_pub_message <message>
```
