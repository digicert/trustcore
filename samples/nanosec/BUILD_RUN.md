# NanoSec (IKE) Build and Run Guide

> **Note:** Run all commands from the root of the repository.

## Table of Contents

1. [CMake Options](#cmake-options)
2. [Build Output Locations](#build-output-locations)
3. [Build](#build)
4. [Loading Kernel Modules](#loading-kernel-modules)
5. [Run](#run)

## CMake Options

| Option              | Description                                                                 | Default  |
|---------------------|-----------------------------------------------------------------------------|----------|
| `WITH_LOGGING`      | Enable logging output                                                       |   `OFF`  |
| `ENABLE_NANOSEC`    | Build the NanoSec IKE example                                               |   `OFF`  |
| `BUILD_KERNELMOD`   | Build the IPsec kernel modules                                              |   `OFF`  |
| `BUILD_SAMPLES`     | Build the sample applications                                               |   `OFF`  |

> **Note:** For common build options, see [`GUIDE.md`](../../GUIDE.md).

## Build Output Locations

After a successful build, artifacts are placed in the following directories:

| Artifact                                                              | Location          |
|-----------------------------------------------------------------------|-------------------|
| Kernel modules (`moc_platform_mod.ko`, `moc_memdrv.ko`, `moc_ipsec.ko`, `moc_ipsec_mod.ko`) | `bin/` |
| `loadConfig` utility                                                  | `bin/`            |
| Shared/static libraries (`libike.so`, `libnanossl.so`, etc.)          | `lib/`            |
| IKE sample executable (`ike`)                                         | `samples/bin/`    |

## Build

### Option 1: Build without kernel modules

```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_NANOSEC=ON -B build -S .
cmake --build build
```

### Option 2: Build with IPsec kernel modules

```bash
cmake -DBUILD_SAMPLES=ON -DENABLE_NANOSEC=ON -DBUILD_KERNELMOD=ON -B build -S .
cmake --build build
```

This also builds and copies the following to `bin/`:
- `moc_memdrv.ko` — Memory driver kernel module
- `moc_ipsec.ko` — IPsec core kernel module
- `moc_ipsec_mod.ko` — IPsec integration kernel module (hooks into the Linux network stack)
- `moc_platform_mod.ko` — Platform abstraction kernel module
- `loadConfig` — Utility to load IPsec policy/SA configuration into the kernel

## Loading Kernel Modules

Before running the IKE sample with kernel-mode IPsec, load the modules in order:

```bash
sudo insmod bin/moc_platform_mod.ko
sudo insmod bin/moc_memdrv.ko
sudo insmod bin/moc_ipsec.ko
sudo insmod bin/moc_ipsec_mod.ko
```
To verify the modules are loaded:

```bash
lsmod | grep moc
```

To load IPsec policy and SA configuration into the kernel:

```bash
sudo bin/loadConfig <config-file>
```

To unload the modules (in reverse order):

```bash
sudo rmmod moc_ipsec_mod
sudo rmmod moc_ipsec
sudo rmmod moc_memdrv
sudo rmmod moc_platform_mod
```

## Run

```bash
export LD_LIBRARY_PATH=lib/:bin/:$LD_LIBRARY_PATH
./samples/bin/ike
```
