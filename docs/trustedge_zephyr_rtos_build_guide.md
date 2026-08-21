# TrustEdge Zephyr RTOS Build Guide

This guide describes how to install Zephyr RTOS support, build TrustEdge for Zephyr, provision the Zephyr flash file system, flash supported boards, and run TrustEdge from the Zephyr shell.

This guide uses `${TRUSTCORE}` to refer to the TrustCore package root.

## Scope

The DigiCert Developer procedure documents these Zephyr targets:

- `native_sim`, the Zephyr native simulator 64-bit board
- `stm32h745i_disco`, the STM32H745 Discovery Kit
- `esp32s3_devkitc`, the ESP32-S3-DevKitC

## Before You Begin

Ensure that you have the following:

- Ubuntu 64-bit. The minimum version tested is Ubuntu 22.04.
- At least 40 GB of disk space for the Zephyr tools, SDK, dependencies, and build artifacts.
- A TrustCore repository checkout.
- A bootstrap ZIP from DigiCert Device Trust Manager for device provisioning workflows.
- The `trustedge_zephyr.patch` file, located at `${TRUSTCORE}/projects/trustedge/boards/trustedge_zephyr.patch`.

Set `${TRUSTCORE}` to the root of this TrustCore repository:

```bash
export TRUSTCORE=/path/to/trustcore
cd ${TRUSTCORE}
```

Set `ZEPHYR_BASE` to the Zephyr root folder after Zephyr is installed:

```bash
export ZEPHYR_BASE=~/zephyrproject/zephyr
```

## Install Zephyr

The Zephyr build script installs Zephyr OS, the required dependencies, and the Zephyr SDK. It also writes Zephyr environment variables to `.bashrc` for TrustEdge development and builds.

The script automates the Zephyr [Getting Started Guide](https://docs.zephyrproject.org/latest/develop/getting_started/index.html) and [Beyond the Getting Started Guide](https://docs.zephyrproject.org/latest/develop/beyond-GSG.html) setup steps.

Run the installation from the repository root:

```bash
cd ${TRUSTCORE}
./scripts/ci/trustedge/ci_trustedge_build_zephyr.sh --zephyr-install
```

The current script performs the following setup actions:

- Updates Ubuntu packages with `sudo apt update` and `sudo apt upgrade -y`.
- Installs system dependencies, including `build-essential`, `git`, `cmake`, `ninja-build`, `gperf`, `ccache`, `dfu-util`, `device-tree-compiler`, `wget`, Python development packages, `libsdl2-dev`, `libmagic1`, `python3-venv`, `libfuse-dev`, and `minicom`.
- Creates a Python virtual environment under `${HOME}/zephyrproject/.venv`.
- Installs `west`.
- Initializes Zephyr from `https://github.com/zephyrproject-rtos/zephyr` at `v4.2.0`.
- Runs `west update` and `west zephyr-export`.
- Installs Python requirements from `projects/trustedge/zephyr_deps/*.txt`.
- Installs the Zephyr SDK under `${HOME}`.
- Appends these environment settings and aliases to `${HOME}/.bashrc`:
  - `ZEPHYR_BASE=${HOME}/zephyrproject/zephyr`
  - `ZEPHYR_TOOLCHAIN_VARIANT=zephyr`
  - `ZEPHYR_SDK_INSTALL_DIR=${HOME}/zephyr-sdk-<SDK_VERSION>`
  - Zephyr scripts added to `PATH`
  - `zephenv` alias for activating the Zephyr virtual environment

After installation, restart the shell or reload `.bashrc`, then activate the Zephyr virtual environment before using `west`:

```bash
source ~/.bashrc
zephenv
```

## Apply the TrustEdge Zephyr Patch

Apply `trustedge_zephyr.patch` to the Zephyr tree before building TrustEdge Zephyr applications:

```bash
cd ${ZEPHYR_BASE}
git apply ${TRUSTCORE}/projects/trustedge/boards/trustedge_zephyr.patch
cd ${TRUSTCORE}
```

## Build TrustEdge on Native Sim 64-Bit

The native simulator flow builds TrustEdge with the Zephyr runtime, places the TrustEdge binary in `bin/trustedge`, and builds the `device_provision` tool that prepares the flash file system.

Build TrustEdge for `native_sim`:

```bash
cd ${TRUSTCORE}
./scripts/ci/trustedge/ci_trustedge_build_zephyr.sh --board native_sim
```

Add a host entry to /etc/hosts for provisioning:

```text
127.0.0.1       provision.digicert.com
```

Prepare `flash.bin` with the bootstrap ZIP:

```bash
cd ${TRUSTCORE}
./samples/zephyr_examples/device_provision/provision_flash.sh --bootstrap <path/to/bootstrap/zip>
```

If flash provisioning is skipped, run the helper TCP server so the TrustEdge binary can fetch the bootstrap and file-system ZIP files:

```bash
cd ${TRUSTCORE}
cd ./samples/zephyr_examples/trustedge_sample/helper
python3 tcp_server.py --bootstrap <path-to-bootstrap-zip> --filesys <path-to-filesystem-zip>
```

The file-system ZIP is located at `${TRUSTCORE}/projects/trustedge/trustedge_2.0.2.arm.zip`.

Run TrustEdge in another terminal:

```bash
cd ${TRUSTCORE}
./bin/trustedge
```

The `trustedge start` command can be issued from another terminal by redirecting it to the UART pseudo-terminal used by `./bin/trustedge`.

For example:

```bash
printf 'trustedge start\r' > /dev/pts/16
```

When `./bin/trustedge` starts, it displays the UART pseudo-terminal:

```text
uart connected to pseudotty: /dev/pts/16
```

You can now test device provisioning and certificate policy handling scenarios.

### Native Sim REST API Examples

TrustEdge includes a REST API over HTTPS. Install the additional tools used by the examples:

```bash
sudo apt install zip unzip
```

To load certificates into flash and run TrustEdge:

```bash
cd ${TRUSTCORE}
./scripts/ci/trustedge/ci_trustedge_build_zephyr.sh --board native_sim
./samples/zephyr_examples/device_provision/provision_flash.sh --load-certs --bootstrap <path/to/bootstrap/zip>
```

This loads the Root CA certificate and the server private key and certificate into flash storage. The Root CA certificate is required for EST when connecting to DigiCert Device Trust Manager. The server key and certificate secure the TLS connection to the TrustEdge REST API server.

When the Zephyr shell prompt appears, run `trustedge start` before sending REST API requests to TrustEdge.

Confirm that the REST API is listening before running the HTTPS examples:

```bash
pgrep -af trustedge
ss -tlnp | grep ':8469'
nc -vz localhost 8469
openssl s_client -connect localhost:8469 \
  -servername localhost \
  -CAfile ${TRUSTCORE}/pki_certs/rootCA.pem
```

The TrustEdge log should show the REST API thread and HTTPS listener, for example:

```text
Launching agent rest api thread
HTTPS server listening on [https://localhost:8469]
Certificate & Key alias for TLS auth: te-api-server
```

If port `8469` is not listening, the REST API has not started yet or TrustEdge failed during initialization. Recheck that `trustedge start` was issued and that flash was provisioned with `--load-certs` so the `te-api-server` certificate and key exist in LittleFS.

Verify key generation with `curl`:

```bash
curl --cacert ${TRUSTCORE}/pki_certs/rootCA.pem \
  https://localhost:8469/v1/key/asymmetric \
  -H 'Content-Type: application/json' \
  -d '{
    "keyCertAttributes": {
      "outputMode": "buffered",
      "algorithm": "rsa+2048",
      "keySource": "SW"
    }
  }'
```

Trigger an EST enrollment flow:

```bash
curl --cacert ${TRUSTCORE}/pki_certs/rootCA.pem \
  https://localhost:8469/v1/certificate/enroll \
  -H 'Content-Type: application/json' \
  -d@${TRUSTCORE}/src/trustedge/test/data/est_request.json
```

Inspect the native simulator flash file system with the FUSE-based provisioning tool:

```bash
cd ${TRUSTCORE}
./samples/zephyr_examples/device_provision/build/zephyr/zephyr.exe
FUSE mounting flash in host flash/
uart connected to pseudotty: /dev/pts/8
[00:00:00.000,000] <inf> littlefs: littlefs partition at /lfs1
*** Booting Zephyr OS build v4.2.0 ***
[00:00:00.000,000] <inf> littlefs: LittleFS version 2.11, disk version 2.1
[00:00:00.000,000] <inf> littlefs: FS at flash-controller@0:0x100000 is 768 0x1000-byte blocks with 512 cycle
[00:00:00.000,000] <inf> littlefs: partition sizes: rd 16 ; pr 16 ; ca 64 ; la 32
[00:00:00.000,000] <inf> app: Total partition size: 12288 bytes
[00:00:00.000,000] <inf> app: Available size: 11392 bytes
```

In another terminal, inspect the mounted LittleFS directory:

```bash
$ cd ${TRUSTCORE}
$ tree flash/
flash
└── lfs1
    ├── bootstrap.zip
    ├── etc
    │   └── digicert
    │       ├── conf
    │       │   ├── applied_policy.json
    │       │   ├── bootstrap_config.json
    │       │   ├── failed_policy.json
    │       │   ├── metrics.pb
    │       │   ├── pending_policy.json
    │       │   ├── processing_policy.json
    │       │   └── version.txt
    │       ├── keystore
    │       │   ├── ca
    │       │   │   ├── devtm-integration-account-intermediate-ca.crt
    │       │   │   ├── devtm-integration-account-root-ca.crt
    │       │   │   ├── DigiCertGlobalRootCA.crt
    │       │   │   ├── DigiCertGlobalRootG2.crt
    │       │   │   ├── Rendezvous-zone-1-0.crt
    │       │   │   └── Rendezvous-zone-2-0.crt
    │       │   ├── certs
    │       │   │   ├── be_zephy00.crt
    │       │   │   └── te-api-server.pem
    │       │   ├── conf
    │       │   ├── crls
    │       │   ├── keys
    │       │   │   ├── be_zephy00-key.crt
    │       │   │   ├── server_key_gen.pem
    │       │   │   └── te-api-server.pem
    │       │   ├── psks
    │       │   └── req
    │       │       └── issued
    │       ├── scripts
    │       ├── service
    │       │   ├── completed
    │       │   ├── failed
    │       │   ├── processing
    │       │   └── request
    │       └── trustedge.json
    └── tmp

20 directories, 20 files

```

The `flash/lfs1` tree should include the bootstrap ZIP, the `/etc/digicert` configuration, keystore directories, service directories, logs, and temporary files.

## Build TrustEdge on STM32H745 Discovery Kit

Build TrustEdge for the STM32H745 Discovery Kit:

```bash
cd ${ZEPHYR_BASE}
git apply ${TRUSTCORE}/projects/trustedge/boards/trustedge_zephyr.patch
cd ${TRUSTCORE}
./scripts/ci/trustedge/ci_trustedge_build_zephyr.sh --board stm32h745i_disco
```

The build places the TrustEdge binary in `bin/trustedge`. Flash the board from the TrustEdge sample directory:

```bash
cd ${TRUSTCORE}/samples/zephyr_examples/trustedge_sample
west flash
```

Start the TCP server so the device can fetch the file-system and bootstrap files:

```bash
cd ${TRUSTCORE}
cd ./samples/zephyr_examples/trustedge_sample/helper
python3 tcp_server.py --bootstrap <path-to-bootstrap-zip> --filesys <path-to-filesystem-zip>
```

Connect to the UART shell:

```bash
minicom --device /dev/pts/<num>
```

Start TrustEdge from the UART shell:

```bash
uart:~$ trustedge start
```

Check TrustEdge logs:

```bash
uart:~$ fs cat /lfs1/log/log.0000
```

Optionally check TrustEdge status and connection state:

```bash
uart:~$ trustedge status
uart:~$ trustedge state
```

## Build TrustEdge on ESP32-S3-DevKitC

The following ESP32-S3-DevKitC features as tested:

- Device provisioning workflow with bootstrap certificates
- EST enrollment workflow

ESP32-S3 requirements and memory notes are as follows:

- Zephyr version `4.2.0`
- Zephyr SDK version `0.17.2`
- TrustEdge binary size: `1,487,308 bytes`, or approximately 1.5 MB for a full build
- Available flash: approximately 8 MB on ESP32-S3-DevKitC
- Internal RAM: 642 KB total (329 KB + 313 KB), with approximately 512 KB effectively usable

ESP32-S3 memory usage breakdown:

| Segment | Used | Available | Usage |
| --- | --- | --- | --- |
| `mcuboot_hdr` | 32 bytes | 32 bytes | 100 percent |
| `metadata` | 80 bytes | 96 bytes | 83.33 percent |
| `FLASH` | 1,487,180 bytes | 8,388,480 bytes | 17.73 percent |
| `iram0_0_seg` | 60,764 bytes | 329 KB | 18.04 percent |
| `dram0_0_seg` | 240,728 bytes | 313 KB | 75.11 percent |
| `irom0_0_seg` | 1,034,314 bytes | 32 MB | 3.08 percent |
| `drom0_0_seg` | 1,356,236 bytes | 32 MB | 4.04 percent |
| `ext_dram_seg` | 5,902,720 bytes | 8 MB | 70.37 percent |
| `ext_iram_seg` | 0 bytes | 8 MB | 0 percent |
| `rtc_iram_seg` | 0 bytes | 8 KB | 0 percent |
| `rtc_slow_seg` | 0 bytes | 8 KB | 0 percent |
| `IDT_LIST` | 0 bytes | 8 KB | 0 percent |

### ESP32-S3 Prerequisites

Fetch the Espressif HAL blobs required for networking support:

```bash
cd ~/zephyrproject
west blobs fetch hal_espressif
```

Add the current user to the `dialout` group to access the serial port:

```bash
sudo usermod -a -G dialout $USER
```

Log out and log back in for the group change to take effect.

After connecting the ESP32-S3 board, verify the serial device. The device is usually `/dev/ttyS*` or `/dev/ttyUSB*`. This guide uses `/dev/ttyUSB0` as an example:

```bash
/dev/ttyUSB0
```

### ESP32-S3 Build

Build all required libraries against Zephyr, compile the TrustEdge binary with the Zephyr runtime, and build the provisioning tool:

```bash
cd ${TRUSTCORE}
./scripts/ci/trustedge/ci_trustedge_build_zephyr.sh --board esp32s3_devkitc --clean
```

The ESP32-S3 build process auto-detects `ZEPHYR_HOST_IP` if it is not already set. If detection fails, export the host IP address manually and rerun the command:

```bash
export ZEPHYR_HOST_IP=<host-ip-address>
```

After a successful ESP32-S3 build, these build directories are created:

```text
./samples/zephyr_examples/trustedge_sample/build_mcuboot/
./samples/zephyr_examples/trustedge_sample/build/
```

The current script copies `trustedge.signed.bin` to `bin/trustedge`.

### ESP32-S3 Flash

Flash the ESP32-S3 in two stages.

Navigate to the TrustEdge sample directory:

```bash
cd ${TRUSTCORE}/samples/zephyr_examples/trustedge_sample
```

Flash the MCUboot bootloader:

```bash
west flash --esp-flash-bootloader build_mcuboot/zephyr/zephyr.bin --esp-boot-address 0x0
```

Flash the TrustEdge binary:

```bash
west flash
```

### ESP32-S3 Run

Prepare the file-system ZIP for EST enrollment:

```bash
cd ${TRUSTCORE}
cd ./samples/zephyr_examples/trustedge_sample/helper
./prepare_trustedge_est.sh <path-to-filesystem-zip>
```

Run the TCP server so the device can fetch the bootstrap and file-system files:

```bash
python3 tcp_server.py --bootstrap <path-to-bootstrap-zip> --filesys <path-to-filesystem-zip>
```

Connect to the ESP32-S3 serial port with `minicom`:

```bash
sudo minicom -b 115200 -D /dev/ttyUSB0
```

You can find the correct serial port in the output of the `west flash` command.

From the UART shell, reboot and connect to Wi-Fi:

```bash
uart:~$ kernel reboot
uart:~$ wifi connect -k <num> -s <SSID> -p <password>
```

Where:

- `-s <SSID>` is the wireless network SSID.
- `-p <password>` is the wireless network password.
- `-k <num>` is the key management type.

Valid `-k` values:

| Value | Key management type |
| --- | --- |
| `0` | None |
| `1` | WPA2-PSK |
| `2` | WPA2-PSK-256 |
| `3` | SAE-HNP |
| `4` | SAE-H2E |
| `5` | SAE-AUTO |
| `6` | WAPI |
| `7` | EAP-TLS |
| `8` | WEP |
| `9` | WPA-PSK |
| `10` | WPA-Auto-Personal |
| `11` | DPP |

Start TrustEdge:

```bash
uart:~$ trustedge start
```

Check logs, connection state, and provisioning status:

```bash
uart:~$ fs cat /lfs1/log/log.0000
uart:~$ trustedge state
uart:~$ trustedge status
```

During device provisioning, a known ESP32 Wi-Fi driver issue might cause the console to hang and drop the connection. If this happens, reconnect to Wi-Fi and restart TrustEdge to complete provisioning:

```bash
uart:~$ wifi connect -k <num> -s <SSID> -p <password>
uart:~$ trustedge start
```

If Wi-Fi connection fails with error `-120`, reboot the kernel and retry:

```bash
uart:~$ kernel reboot
uart:~$ wifi connect -k <num> -s <SSID> -p <password>
```

## Zephyr Shell FAQ

List available TrustEdge commands from the Zephyr shell:

```bash
uart:~$ trustedge
```

The expected subcommands include:

```text
trustedge - Demo commands
Subcommands:
  start    : Run TrustEdge.
  state    : Show TrustEdge state.
  status   : Show TrustEdge status.
  reboot   : reboot device.
  reset    : reset file system.
  confirm  : confirm image.
```

Reset the TrustEdge file system when switching to a different bootstrap or when a clean state is needed:

```bash
uart:~$ trustedge reset
```

## Build Script Reference

The Zephyr build script is:

```bash
./scripts/ci/trustedge/ci_trustedge_build_zephyr.sh
```

Supported board values in the current script:

| Board argument | Zephyr board type used by the script | Notes |
| --- | --- | --- |
| `native_sim` | `native_sim/native/64` | Default board. Uses `native_sim_prj.conf` and `boards/flash_size.overlay`. |
| `stm32h745i_disco` | `stm32h745i_disco/stm32h745xx/m7` | Uses STM32 overlay and `stm32_prj.conf`. |
| `esp32s3_devkitc` | `esp32s3_devkitc/esp32s3/procpu` | Builds MCUboot first and uses `esp32s3_prj.conf`. |

## Final Checklist

Before using the guide end to end, verify:

- `${TRUSTCORE}` points to the repository root.
- `ZEPHYR_BASE` points to the Zephyr checkout.
- The Zephyr virtual environment is active and `west` is available.
- `trustedge_zephyr.patch` has been applied to the Zephyr tree.
- The bootstrap ZIP path is correct.
- The board is connected and visible to the host before flashing.
- For ESP32-S3, `hal_espressif` blobs are fetched and the current user has serial-port access.
- For REST API checks, the Root CA certificate exists at `${TRUSTCORE}/pki_certs/rootCA.pem`.
- For REST API checks, the native_sim flash image was provisioned with `--load-certs` and `trustedge start` has been issued from the Zephyr shell.
