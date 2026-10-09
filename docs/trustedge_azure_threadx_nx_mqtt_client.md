# Adding TrustEdge Support to Azure RTOS/ThreadX (B-U585I-IOT02A, Nx_MQTT_Client)

This guide describes how to add TrustEdge support to an Azure RTOS/ThreadX application
running on the **B-U585I-IOT02A** board, using the **`Nx_MQTT_Client`** STM32CubeMX
example as the starting point. It covers setting up a clean Ubuntu 22.04 development
environment, generating the example project, integrating the TrustCore public
repository, applying the required patch, and building the final application.

The integration steps in this guide have been tested and verified on the
**B-U585I-IOT02A**, which is used as the reference board. Other STMicroelectronics
boards that support the `Nx_MQTT_Client` example should be able to follow a similar
integration process, with board-specific STM32CubeMX/STM32CubeIDE settings adjusted as
needed, including hardware initialization, peripheral configuration, and network
configuration. These instructions have not been tested on all STM32 boards.

## 1. Overview

TrustEdge is added to the Azure RTOS/ThreadX `Nx_MQTT_Client` example by:

- Generating the `Nx_MQTT_Client` example project for the B-U585I-IOT02A board with
  STM32CubeMX/STM32CubeIDE, using CMake as the build toolchain.
- Applying a syscalls patch to the generated project.
- Copying TrustEdge-specific CMake and application source files into the project.
- Copying the TrustCore public repository into a dedicated `Middlewares/DigiCert`
  directory so the project can build against it.
- Building the project with CMake/Ninja to produce the final `Nx_MQTT_Client.elf` image.

For general TrustEdge build information not specific to this board or example, see the
[TrustEdge Build & Run Guide](../samples/trustedge/BUILD_RUN.md).

## 2. Prerequisites

Before starting, ensure you have:

- A host machine running Ubuntu 22.04.
- A checkout of the TrustCore public repository. Its location is referred to throughout
  this guide as `<path-to-public-trustcore-repo>`.
- An ST account (required to download STM32CubeMX and STM32CubeIDE).
- Sufficient disk space for the ARM toolchain, STM32Cube tools, and build artifacts.

See also the [TrustEdge Build & Run Guide](../samples/trustedge/BUILD_RUN.md) for
additional TrustEdge build information.

## 3. Ubuntu 22.04 Development Environment

The following tools must be installed on the Ubuntu 22.04 host before generating and
building the `Nx_MQTT_Client` project:

- STM32CubeMX
- STM32CubeIDE
- ARM GNU (`arm-none-eabi`) toolchain
- CMake
- Ninja

Installation of each tool is described in the following sections.

## 4. Install STM32CubeMX

Download and install STM32CubeMX from ST:

- <https://www.st.com/en/development-tools/stm32cubemx.html>

You may need to sign in to an ST account to download the installer.

## 5. Install STM32CubeIDE

Download and install STM32CubeIDE from ST:

- <https://www.st.com/en/development-tools/stm32cubeide.html>

You may need to sign in to an ST account to download the installer.

## 6. Install ARM GNU Toolchain

Install the `arm-none-eabi` toolchain for your host architecture:

- **x86_64 Linux hosted cross toolchain:**
  `arm-gnu-toolchain-15.3.rel1-x86_64-arm-none-eabi.tar.xz`
- **AArch64 Linux hosted cross toolchain:**
  `arm-gnu-toolchain-15.3.rel1-aarch64-aarch64-none-elf.tar.xz`

Refer to the ARM toolchain release documentation for download links and details:

- [ARM GNU Toolchains for Arm documentation](https://gitlab.arm.com/tooling/gnu-toolchains-for-arm/-/blob/releases/15.3.rel1/README.md)

## 7. Configure PATH

Add the `arm-none-eabi` toolchain binaries to your `PATH` environment variable so that
`arm-none-eabi-gcc` and related tools are available on the command line.

## 8. Install CMake and Ninja

Install CMake and Ninja on Ubuntu 22.04 using your preferred package manager (for
example, `apt`).

## 9. Verify Development Tools

After installation, verify that the required tools are available and report expected
versions:

```bash
cmake --version
ninja --version
arm-none-eabi-gcc --version
```

## 10. Create the Nx_MQTT_Client Example

Launch STM32CubeMX and generate the `Nx_MQTT_Client` example project:

1. Under **New Project**, click **Start My Project from Example** to open the
   **Access to Example Selector**.
2. Under **Name**, select **Name** and choose `Nx_MQTT_Client`. In the **Middleware**
  tab, check **NetXDuo**, then select the board row for **B-U585I-IOT02A**.

   **Note:** Selecting **NetXDuo** for the `Nx_MQTT_Client` example on the
   **B-U585I-IOT02A** board provides `app_netxduo.c` and `app_netxduo.h` under
   `NetXDuo/App/` in the generated project. If these files are not available, obtain
   them from the [STM32CubeU5 v1.9.0 release](https://github.com/STMicroelectronics/STM32CubeU5/releases/tag/v1.9.0).
   Click **Source code (zip)** to download `STM32CubeU5-1.9.0.zip`, extract it, and
   copy the required files from:

   ```text
   STM32CubeU5-1.9.0/Projects/B-U585I-IOT02A/Applications/NetXDuo/Nx_MQTT_Client/NetXDuo/App/
   ```

3. Click **Start Project**.
4. In the **Start Project from Example** window, confirm that **Name** is
   `Nx_MQTT_Client` and **board** is `B-U585I-IOT02A`.
5. Set **Install Project Directory** to:

   ```text
   /home/<username>/STM32Cube/Example
   ```

6. Set **Open With** to `STM32CubeIDE`.
7. Click **Install**.
8. Read the license and click **Finish**.

## 11. Configure the B-U585I-IOT02A Board

The board is selected during project creation in the STM32CubeMX Example Selector (see
[Section 10](#10-create-the-nxmqttclient-example)). No additional board-specific
configuration is described beyond selecting **B-U585I-IOT02A** as the target board.

## 12. Configure CMake and Toolchain Settings

In STM32CubeMX, open the **Project Manager** tab and configure the following under
**Project**:

- **Toolchain Folder Location:**

  ```text
  /home/<username>/STM32Cube/Example/Nx_MQTT_Client/
  ```

- **Toolchain / IDE:** `CMake`
- **Default Compiler/Linker:** `gcc`

Once configured, click **Generate Code** to generate the project.

## 13. Add TrustEdge Support

With the `Nx_MQTT_Client` project generated, add TrustEdge support by integrating the
TrustCore public repository, applying a required patch, and copying TrustEdge-specific
files into the generated project, as described in the following sections.

## 14. Integrate the TrustCore Public Repository

The TrustCore public repository provides the TrustEdge sources and board-specific
integration files used by the `Nx_MQTT_Client` project. Throughout this guide, its
location is referred to as `<path-to-public-trustcore-repo>`.

Create a dedicated middleware directory for the TrustCore repository, then copy the
repository into it:

```bash
cd /home/<username>/STM32Cube/Example/Nx_MQTT_Client

mkdir Middlewares/DigiCert

cp -rf <path-to-public-trustcore-repo> \
   /home/<username>/STM32Cube/Example/Nx_MQTT_Client/Middlewares/DigiCert/
```

## 15. Apply the Required Patch

Apply the `Nx_MQTT_Client.patch` patch, located in the TrustCore public
repository under `samples/azure_examples/Nx_MQTT_Client/`, to the generated project:

```bash
cd /home/<username>/STM32Cube/Example/Nx_MQTT_Client

patch -p1 < <path-to-public-trustcore-repo>/samples/azure_examples/Nx_MQTT_Client/Nx_MQTT_Client.patch
```

## 16. Copy Required TrustEdge/CMake/Application Files

Copy the TrustEdge-specific `CMakeLists.txt` and application source/header files from the
TrustCore public repository into the generated project:

```bash
cp <path-to-public-trustcore-repo>/samples/azure_examples/Nx_MQTT_Client/CMakeLists.txt \
   /home/<username>/STM32Cube/Example/Nx_MQTT_Client/cmake/stm32cubemx/

cp <path-to-public-trustcore-repo>/samples/azure_examples/Nx_MQTT_Client/*.[ch] \
   /home/<username>/STM32Cube/Example/Nx_MQTT_Client/NetXDuo/App/
```

## 17. Build the Nx_MQTT_Client Project

From the project directory, perform a clean build using CMake presets:

```bash
cd /home/<username>/STM32Cube/Example/Nx_MQTT_Client
rm -rf build/Debug
cmake --preset Debug
cmake --build --preset Debug 2>&1 | tee build.log
```

These commands:

- `rm -rf build/Debug` — removes any existing `Debug` build directory for a clean build.
- `cmake --preset Debug` — configures the project using the `Debug` CMake preset.
- `cmake --build --preset Debug 2>&1 | tee build.log` — builds the project using the
  `Debug` preset, capturing combined stdout/stderr output to `build.log`.

## 18. Build Output

A successful build produces the following ELF image:

```text
./build/Debug/Nx_MQTT_Client.elf
```

## 19. Troubleshooting / Important Notes

- Replace `<username>` with your actual Ubuntu username in all paths.
- Replace `<path-to-public-trustcore-repo>` with the actual path to your TrustCore
  public repository checkout.
- Ensure the `arm-none-eabi` toolchain is on `PATH` before running CMake/Ninja builds;
  verify with `arm-none-eabi-gcc --version`.
- If the build directory is stale or the toolchain/board configuration changes, remove
  `build/Debug` before reconfiguring, as shown in [Section 17](#17-build-the-nxmqttclient-project).
- For additional TrustEdge build information, see the
  [TrustEdge Build & Run Guide](../samples/trustedge/BUILD_RUN.md).
