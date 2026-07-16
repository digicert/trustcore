# How to Add New Toolchain Support to TrustEdge

## Overview

TrustEdge supports cross-compilation through a shared toolchain registry, CMake platform mapping, and per-project build wrappers. A toolchain is normally selected from the command line with `--toolchain <platform_id>`. The build scripts validate the platform identifier, convert it to a CMake option, and then CMake maps it to the TrustCore platform configuration used by the source tree.

The main flow is:

```text
Developer command
  -> scripts/ci/trustedge/ci_trustedge_build.sh --toolchain <platform_id>
  -> project build wrappers, such as projects/common/build.sh
  -> projects/shared_cmake/get_toolchain.sh
  -> -DCM_TARGET_PLATFORM=<platform_id>
  -> projects/shared_cmake/MocPlatform.cmake
  -> CMAKE_MOCANA_PLATFORM, CMAKE_TOOLCHAIN_FILE, sysroot, CPU flags
  -> CMake configure and build
```

There are two supported integration models:

| Model | When to use it | TrustEdge responsibilities | Example |
| --- | --- | --- | --- |
| Environment-driven SDK | The vendor SDK provides an environment script that exports `CC`, `CXX`, compiler flags, linker flags, sysroot, and PATH | Register the platform and map it in CMake; source the SDK environment in the shell before building | Arago |
| Explicit CMake toolchain file | TrustEdge must discover or set compiler paths itself | Register the platform, map it in CMake, and add a file under `projects/shared_cmake/toolchains/` | rpi64, QNX, WRS, Poky-style targets |

Use the environment-driven model only when the SDK setup script is the authoritative source for compilers, sysroot, and flags. Use the explicit CMake toolchain-file model when the repository must define compiler prefixes, sysroot paths, and cross-build behavior.

## Arago Toolchain Integration Example

Arago is integrated as an environment-driven SDK toolchain. It does not have a dedicated `projects/shared_cmake/toolchains/arago*.cmake` file. Install the Arago SDK, source the SDK environment script, and then invoke the normal TrustEdge build path with `--toolchain arago_linux_aarch64`.

### Arago Build Flow

1. Download `arago-2021.09-toolchain-2021.09.sh`.
2. Install the SDK to `/usr/local/arago-x86_64/`.
3. Source `/usr/local/arago-x86_64/environment-setup-aarch64-oe-linux`.
4. Run:

   ```bash
   ./scripts/ci/trustedge/ci_trustedge_build.sh \
     --monolithic \
     --cvc \
     --proxy \
     --pqc \
     --pqc-composite \
     --enable-pc \
     --toolchain arago_linux_aarch64 \
     --package \
     --tee \
     --tee-path /usr/local/arago-x86_64/sysroots/aarch64-oe-linux/usr/lib/
   ```

5. `ci_trustedge_build.sh` forwards `--toolchain arago_linux_aarch64` to module build scripts.
6. Module build scripts call `get_platform arago_linux_aarch64`, which returns `-DCM_TARGET_PLATFORM=arago_linux_aarch64`.
7. `MocPlatform.cmake` maps `CM_TARGET_PLATFORM=arago_linux_aarch64` to `CMAKE_MOCANA_PLATFORM=arago_linux_aarch64`.

## rpi64 Manual Toolchain Setup Example

The `rpi64` toolchain is the primary example of the explicit CMake toolchain-file model. Unlike Arago, you do not source a vendor SDK environment script. Instead, download the target sysroot and compiler archives, extract them into `/opt/sysroots/master`, and then invoke the normal TrustEdge build script with `--toolchain rpi64`.

### rpi64 Build-System Mapping

The repository build-system configuration uses these mappings:

| File | rpi64 configuration |
| --- | --- |
| [`projects/shared_cmake/get_toolchain.sh`](/projects/shared_cmake/get_toolchain.sh) | Registers `rpi64` in `PLATFORMS` and maps it to `gcc-linaro-6.5.0-2018.12-x86_64_aarch64-linux-gnu/bin` under `/opt/sysroots/master` |
| [`projects/shared_cmake/MocPlatform.cmake`](/projects/shared_cmake/MocPlatform.cmake) | Maps `CM_TARGET_PLATFORM=rpi64` to `aarch64-linux-gnu-toolchain.cmake`, `CMAKE_MOCANA_PLATFORM=linaro_2.23_aarch64_gnu`, `CMAKE_SYSROOT=/opt/sysroots/master/sysroot-glibc-linaro-2.23-2018.12-aarch64-linux-gnu`, and `CM_BUILD_X64 ON` |
| [`projects/shared_cmake/toolchains/aarch64-linux-gnu-toolchain.cmake`](/projects/shared_cmake/toolchains/aarch64-linux-gnu-toolchain.cmake) | Uses compiler prefix `aarch64-linux-gnu-` and discovers the compiler with `which aarch64-linux-gnu-gcc` |

For a new toolchain following the `rpi64` pattern, the archive extraction paths must line up with the `m_sysroots[...]` entry in `get_toolchain.sh` and the `CMAKE_SYSROOT` path in `MocPlatform.cmake`.

## Relevant Files and Responsibilities

### Shared Toolchain Registry

| File | Responsibility | Notes for new toolchains |
| --- | --- | --- |
| [`projects/shared_cmake/get_toolchain.sh`](/projects/shared_cmake/get_toolchain.sh) | Defines supported platform IDs in `PLATFORMS`; maps each platform to a sysroot/bin path in `m_sysroots`; exposes `get_platform()` and `get_sysroot_bin()` | Add the new platform ID to `PLATFORMS` and add an `m_sysroots[...]` entry |
| [`projects/shared_cmake/MocPlatform.cmake`](/projects/shared_cmake/MocPlatform.cmake) | Maps `CM_TARGET_PLATFORM` to CMake cross-compile settings and `CMAKE_MOCANA_PLATFORM` | Add a branch for the new platform and set all architecture/sysroot/toolchain values required by that target |
| [`projects/shared_cmake/toolchains/`](/projects/shared_cmake/toolchains/) | Contains explicit CMake toolchain files for compiler discovery and cross-compilation | Add a new file only when the SDK environment does not fully configure the compiler |
| [`projects/shared_cmake/toolchains/aarch64-linux-gnu-toolchain.cmake`](/projects/shared_cmake/toolchains/aarch64-linux-gnu-toolchain.cmake) | Reference pattern for explicit compiler discovery | Useful template for compiler prefix validation and utility setup |

### TrustEdge Build Entry Points

| File | Responsibility | Notes for new toolchains |
| --- | --- | --- |
| [`scripts/ci/trustedge/ci_trustedge_build.sh`](/scripts/ci/trustedge/ci_trustedge_build.sh) | Main Linux TrustEdge build script; accepts feature flags, `--toolchain`, `--tee`, and `--tee-path` | Use this as the primary command entry point after installing or sourcing the toolchain. Existing `--toolchain` handling forwards arbitrary supported platform IDs; help text may need updates |
| [`scripts/ci/trustedge/build_trustedge_tools.sh`](/scripts/ci/trustedge/build_trustedge_tools.sh) | Builds TrustEdge tools with optional toolchain forwarding | Use this when the new platform also needs TrustEdge tools |
| [`projects/common/build.sh`](/projects/common/build.sh) | Representative project build wrapper that resolves `--toolchain` through shared helpers | Most project wrappers follow this pattern |
| [`projects/*/build.sh`](/projects) | Module-specific build wrappers for libraries and tools | Use these to confirm module-level support |
| [`scripts/build_crypto_shared_libs.sh`](/scripts/build_crypto_shared_libs.sh) | Shared crypto library build script with `--toolchain` support | Update supported-platform help text if shared libraries are expected for the new target |

### Documentation

| File | Responsibility | Notes for new toolchains |
| --- | --- | --- |
| [`GUIDE.md`](/GUIDE.md) | Repository build-guide index | Link to this or another cross-compilation guide |
| [`samples/trustedge/BUILD_RUN.md`](/samples/trustedge/BUILD_RUN.md) | TrustEdge sample-level build/run guide | Link to root cross-compilation guidance if developers commonly start here |

### Legacy Makefiles and Other Configuration

| File | Responsibility | Notes for new toolchains |
| --- | --- | --- |
| [`make/Makefile.linux`](/make/Makefile.linux) | Legacy Linux make configuration | Usually no change for CMake-driven TrustEdge builds unless the target uses legacy make paths |
| [`make/Makefile.linux.cross`](/make/Makefile.linux.cross) | Legacy cross-compile settings | Review only if the new toolchain must support legacy make builds |
| [`make/Makefile.ssl`](/make/Makefile.ssl) | Legacy SSL/Crypto make logic with some toolchain-specific handling | Review if the new target needs special SSL/Crypto behavior outside CMake |

## Step-by-Step Guide

### 1. Choose the Platform Identifier

Pick a stable, descriptive platform ID. Existing names use patterns such as:

```text
arago_linux_aarch64
timesys_linux_armv7_x32
buildroot_armv7_cortex-a5_x32
pavo64_poky_arm64
aries64_poky_x86-64
```

Recommended format:

```text
<vendor_or_sdk>_<os>_<architecture_or_board>
```

Rationale: the platform ID becomes the value passed to `--toolchain`, the value validated by `get_toolchain.sh`, and the value checked in `MocPlatform.cmake`. Renaming it later affects build scripts, documentation, and possibly release package names.

### 2. Decide the Integration Model

Before changing files, answer these questions:

- Does the SDK provide an `environment-setup-*` script?
- Does that script export `CC`, `CXX`, `CFLAGS`, `CXXFLAGS`, `LDFLAGS`, and sysroot values?
- Does it put the compiler and binutils on `PATH`?
- Does CMake need an explicit `CMAKE_TOOLCHAIN_FILE` to find the compiler?
- Is the target 32-bit or 64-bit?
- Is the target little-endian or big-endian?
- Are hard-float, soft-float, CPU, FPU, or ABI flags required?

Use an Arago-style environment-driven integration only if the SDK setup script fully prepares the shell environment. Otherwise, add an explicit CMake toolchain file.

### 3. Register the Platform in `get_toolchain.sh`

Add the platform ID to `PLATFORMS` in [`projects/shared_cmake/get_toolchain.sh`](/projects/shared_cmake/get_toolchain.sh).

For an environment-driven SDK:

```bash
PLATFORMS=(... "newvendor_linux_aarch64")

m_sysroots["newvendor_linux_aarch64"]= # Leave empty for environment-driven SDKs.
```

For a toolchain installed under the default sysroot location, `/opt/sysroots/master`:

```bash
PLATFORMS=(... "newvendor_linux_aarch64")

m_sysroots["newvendor_linux_aarch64"]="newvendor/sdk/sysroots/x86_64-sdk-linux/usr/bin/aarch64-newvendor-linux/"
```

Rationale: project build wrappers call `get_platform()` and `get_sysroot_bin()` to validate the toolchain and prepare the CMake command. If the platform is missing here, `--toolchain <platform_id>` will fail before CMake can configure.

### 4. Add the CMake Platform Mapping

Add a branch in [`projects/shared_cmake/MocPlatform.cmake`](/projects/shared_cmake/MocPlatform.cmake).

Environment-driven SDK example:

```cmake
elseif("${CM_TARGET_PLATFORM}" STREQUAL "newvendor_linux_aarch64")
  set(CMAKE_MOCANA_PLATFORM "newvendor_linux_aarch64")
  set(CMAKE_CROSSCOMPILING true)
  set(CM_BUILD_X64 ON)
endif()
```

Explicit CMake toolchain file example:

```cmake
elseif("${CM_TARGET_PLATFORM}" STREQUAL "newvendor_linux_aarch64")
  set(CMAKE_TOOLCHAIN_FILE ${SHARED_CMAKE_DIR}/toolchains/newvendor-aarch64-linux-toolchain.cmake)
  set(CMAKE_MOCANA_PLATFORM "newvendor_linux_aarch64")
  set(CMAKE_CROSSCOMPILING true)
  set(CMAKE_SYSROOT "${CM_SYSROOTS}/newvendor/sdk/sysroots/aarch64-newvendor-linux")
  set(CM_BUILD_X64 ON)
endif()
```

Rationale: `MocPlatform.cmake` is where a generic platform ID becomes the build configuration used by CMake and TrustCore platform conditionals. This is also the right place to set 32/64-bit architecture, sysroot, CPU flags, and endianness when those values are not already reliable.

### 5. Add a CMake Toolchain File When Needed

If the new platform needs explicit compiler discovery, add a new file under [`projects/shared_cmake/toolchains/`](/projects/shared_cmake/toolchains/).

Minimal pattern:

```cmake
if("${CMAKE_SYSTEM_NAME}" STREQUAL "")
  set(CMAKE_SYSTEM_NAME Linux)
endif()

set(CMAKE_SYSTEM_PROCESSOR ARM64)
set(TOOLCHAIN_PREFIX aarch64-newvendor-linux-)

execute_process(
  COMMAND which ${TOOLCHAIN_PREFIX}gcc
  OUTPUT_VARIABLE BINUTILS_PATH
  ERROR_VARIABLE TOOLCHAIN_ERR
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

if(NOT BINUTILS_PATH)
  if(TOOLCHAIN_ERR)
    message("Error: ${TOOLCHAIN_ERR}\n")
  endif()
  message(FATAL_ERROR "Unable to find ${TOOLCHAIN_PREFIX}gcc during cross-compile")
endif()

get_filename_component(TOOLCHAIN_DIR ${BINUTILS_PATH} DIRECTORY)

set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}g++)
set(CMAKE_SYSROOT_COMPILE "${CMAKE_SYSROOT}")
set(CMAKE_SYSROOT_LINK "${CMAKE_SYSROOT}")

set(CMAKE_OBJCOPY ${TOOLCHAIN_DIR}/${TOOLCHAIN_PREFIX}objcopy CACHE INTERNAL "objcopy tool")
set(CMAKE_SIZE_UTIL ${TOOLCHAIN_DIR}/${TOOLCHAIN_PREFIX}size CACHE INTERNAL "size tool")
```

### 6. Update Build Script Help and Wrappers

The main build script already forwards arbitrary `--toolchain <value>` values, but some help text lists only older examples such as `rpi32 | rpi64 | bbb | android`.

Review and update:

- [`scripts/ci/trustedge/ci_trustedge_build.sh`](/scripts/ci/trustedge/ci_trustedge_build.sh)
- [`scripts/build_crypto_shared_libs.sh`](/scripts/build_crypto_shared_libs.sh)
- Relevant [`projects/*/build.sh`](/projects) wrappers

Use help text that points to the shared registry instead of duplicating long platform lists:

```bash
echo "  --toolchain <platform_id> - Cross-compile using a platform from projects/shared_cmake/get_toolchain.sh"
```

### 7. Add Repeatable Setup Commands

For an environment-driven SDK, document the exact installer, install path, environment setup command, and TrustEdge build command that the engineer should run.

For an explicit CMake toolchain-file model, document how to install or expose the compiler binaries and sysroot path expected by `get_toolchain.sh` and `MocPlatform.cmake`. For a new toolchain that follows the `rpi64` pattern, include these manual steps:

1. Download the new sysroot and compiler archives.
2. Extract the archives into `/opt/sysroots/master` or the path used by the new platform mapping.
3. Confirm the compiler `bin` path matches the `m_sysroots[...]` entry.
4. Confirm the target sysroot path matches the `CMAKE_SYSROOT` value.
5. Invoke the TrustEdge build with the new toolchain ID and required feature flags.
6. Verify that `dist/trustedge*.deb` and `dist/trustedge*.tar.gz` are generated when package output is required.

Rationale: repeatable setup commands prove that the documented steps work in a clean developer environment and give release engineering a reproducible package build.

### 8. Document Prerequisites and Developer Commands

Update or link from:

- [`GUIDE.md`](/GUIDE.md)
- [`samples/trustedge/BUILD_RUN.md`](/samples/trustedge/BUILD_RUN.md), if TrustEdge developers commonly start there

Include:

- SDK/toolchain name and version
- Download source or internal artifact location
- Required local credentials for internal downloads, if applicable
- Installation path
- Environment setup command
- Build command
- Required feature flags
- TEE or PKCS11 library paths, if applicable
- Expected output artifacts
- Known platform limitations

Example local command for an Arago-style SDK:

```bash
source /usr/local/newvendor/environment-setup-aarch64-newvendor-linux

./scripts/ci/trustedge/ci_trustedge_build.sh \
  --monolithic \
  --package \
  --toolchain newvendor_linux_aarch64
```

Example with TEE support:

```bash
./scripts/ci/trustedge/ci_trustedge_build.sh \
  --monolithic \
  --package \
  --toolchain newvendor_linux_aarch64 \
  --tee \
  --tee-path /usr/local/newvendor/sysroots/aarch64-newvendor-linux/usr/lib/
```

Rationale: toolchain support is not complete until developers can reproduce the build without reverse-engineering CMake files.

### 9. Validate the New Toolchain

Run these checks from a clean shell:

```bash
source <sdk-install-root>/environment-setup-<target>
which <target-prefix>gcc
which <target-prefix>g++
cmake --version
ninja --version
```

Then build TrustEdge:

```bash
./scripts/ci/trustedge/ci_trustedge_build.sh \
  --monolithic \
  --package \
  --toolchain <platform_id>
```

If TEE is required:

```bash
test -f <target-sysroot>/usr/lib/libteec.so

./scripts/ci/trustedge/ci_trustedge_build.sh \
  --monolithic \
  --package \
  --toolchain <platform_id> \
  --tee \
  --tee-path <target-sysroot>/usr/lib/
```

Rationale: a clean-shell build verifies the developer path, repeatability, and release readiness.

## Prerequisites and Assumptions

### General Prerequisites

- Linux shell environment for cross-toolchain builds.
- Build dependencies such as CMake, Ninja, RPM tools, and standard compiler/build utilities.
- Access to the toolchain installer or preinstalled compiler/sysroot.

### rpi64 Manual Setup Prerequisites

- Install CMake and Ninja.
- Download both a Linaro aarch64 sysroot archive and a Linaro aarch64 GCC archive.
- Both archives are extracted into `/opt/sysroots/master`.
- The extracted GCC path must match the `rpi64` `m_sysroots[...]` value in `projects/shared_cmake/get_toolchain.sh`.
- The extracted sysroot path must match the `rpi64` `CMAKE_SYSROOT` value in `projects/shared_cmake/MocPlatform.cmake`.

### Toolchain-Specific Assumptions to Confirm

- Target OS and architecture.
- Compiler prefix, such as `aarch64-oe-linux-` or `aarch64-linux-gnu-`.
- 32-bit versus 64-bit build mode.
- Endianness.
- ABI, FPU, hard-float or soft-float behavior.
- Required CPU flags, such as `-mcpu`, `-march`, `-mthumb`, or branch-protection flags.
- Sysroot path.
- Package format requirements.
- Whether `libteec.so`, PKCS11 libraries, TPM2 libraries, or other target libraries are required.

### Arago-Specific Assumptions

- SDK installer: `arago-2021.09-toolchain-2021.09.sh`.
- Default install root: `/usr/local/arago-x86_64/`.
- Environment setup script: `/usr/local/arago-x86_64/environment-setup-aarch64-oe-linux`.
- Target sysroot used for TEE: `/usr/local/arago-x86_64/sysroots/aarch64-oe-linux/usr/lib/`.
- Platform ID: `arago_linux_aarch64`.

## Developer Checklist

Use this checklist when adding a new toolchain:

- [ ] Choose and document the platform ID.
- [ ] Decide whether the toolchain is environment-driven or requires a CMake toolchain file.
- [ ] Add the platform ID to `PLATFORMS` in `projects/shared_cmake/get_toolchain.sh`.
- [ ] Add an `m_sysroots[...]` entry in `projects/shared_cmake/get_toolchain.sh`.
- [ ] Add a `CM_TARGET_PLATFORM` branch in `projects/shared_cmake/MocPlatform.cmake`.
- [ ] Set `CMAKE_MOCANA_PLATFORM`.
- [ ] Set `CMAKE_TOOLCHAIN_FILE`, if needed.
- [ ] Set `CMAKE_SYSROOT`, if needed.
- [ ] Set `CMAKE_CROSSCOMPILING`, if needed.
- [ ] Set `CM_BUILD_X32` or `CM_BUILD_X64`.
- [ ] Set `IS_BIG_ENDIAN` when the target is not the default little-endian case or when clarity is needed.
- [ ] Set target CPU or ABI flags when required.
- [ ] Add a new file under `projects/shared_cmake/toolchains/` if the compiler is not fully configured by the SDK environment.
- [ ] Update TrustEdge build-script help text.
- [ ] Update relevant module build-script help text.
- [ ] If following the `rpi64` pattern, document the new sysroot and compiler archive download sources.
- [ ] If following the `rpi64` pattern, document the extraction path, compiler path, sysroot path, and `--toolchain <platform_id>` build command.
- [ ] Document toolchain installation and environment setup.
- [ ] Document local build commands.
- [ ] Document `--tee-path`, PKCS11, TPM2, or other target library requirements.
- [ ] Run a local clean-shell configure/build.
- [ ] Verify generated package contents and architecture.

## Common Pitfalls and Troubleshooting

### Platform ID Not Found

Symptom:

```text
Target platform "<platform_id>" not found. Exiting...
```

Cause: the platform ID was not added to `PLATFORMS` in `projects/shared_cmake/get_toolchain.sh`, or the command uses a spelling that does not match the registry.

Fix: use one exact platform ID consistently in build scripts, CMake, docs, and package names.

### Host Compiler Used Accidentally

Symptom: CMake configures successfully, but build output shows `gcc` or `cc` from the host instead of the target compiler.

Cause: the SDK environment was not sourced, `PATH` was not updated, or the CMake toolchain file did not set `CMAKE_C_COMPILER` and `CMAKE_CXX_COMPILER` correctly.

Fix: run `which <target-prefix>gcc` before building and check CMake configure logs.

### Missing Sysroot or Target Libraries

Symptom: headers or libraries are missing during configure/link, often for TEE, PKCS11, TPM2, or OpenSSL-related paths.

Cause: incorrect `CMAKE_SYSROOT`, missing SDK environment, or incorrect `--tee-path`/library path.

Fix: verify the sysroot exists and contains target headers/libraries. For TEE, verify `libteec.so` exists before passing `--tee-path`.

### Stale CMake Cache

Symptom: CMake continues using an old compiler or sysroot after toolchain changes.

Cause: previous build directory was configured for another platform.

Fix: clean the build directory or use the build script's clean option before switching toolchains.

### Stale Help Text

Symptom: `--help` suggests only `rpi32`, `rpi64`, `bbb`, or `android`, even though the new platform works.

Cause: build-script help text duplicates a partial platform list.

Fix: update help text to point to `projects/shared_cmake/get_toolchain.sh` or include the new platform.

### Clean Host Setup Is Not Reproducible

Symptom: one developer can build the toolchain, but another clean host cannot reproduce it.

Cause: required dependencies, install paths, environment setup commands, or credentials are not documented.

Fix: document every setup step needed for reproduction, including SDK install path, environment setup command, archive extraction path, and required credentials.

### Build Host Cannot Find the Compiler or SDK

Symptom: the build host cannot find the compiler or SDK after the setup steps are complete.

Cause: the SDK is missing, the install path differs, required credentials are unavailable, or the shell did not source the environment script.

Fix: install or locate the toolchain explicitly and print compiler/tool versions before invoking the TrustEdge build.

## Best Practices

- Keep the platform ID stable and descriptive.
- Prefer one source of truth for supported platforms: `projects/shared_cmake/get_toolchain.sh`.
- Avoid duplicating long platform lists in help text; point developers to the shared registry.
- Use environment-driven integration only when the SDK setup script is complete and reliable.
- Use explicit CMake toolchain files for generic compilers or repo-managed sysroots.
- Fail early when compilers or sysroots are missing.
- Document all internal artifact URLs, required credentials, and host assumptions without exposing secret values.
- Keep package names target-specific, for example `trustedge-newvendor-aarch64.tar.gz`.
- Validate the setup with a local clean-shell build.
- Sanitize user-provided paths and never hardcode secrets in scripts or documentation examples.

## Recommended Documentation Updates for Each New Toolchain

When adding support for a new toolchain, update the following documentation surfaces as applicable:

| Documentation file | Required update |
| --- | --- |
| `BUILD_RUN.md` | Add or link cross-compilation prerequisites, setup, and build command |
| `GUIDE.md` | Link to the new or updated cross-compilation guide |
| `samples/trustedge/BUILD_RUN.md` | Link to root-level TrustEdge cross-compilation instructions if relevant |
| Release notes or release checklist | Document new package artifact, SDK version, target architecture, and support status |
| Build-script `--help` output | Ensure developer-visible help does not contradict the supported platform registry |

## Minimal Change Summary

At minimum, adding a new TrustEdge toolchain requires:

1. `projects/shared_cmake/get_toolchain.sh`: register the platform and sysroot/bin mapping.
2. `projects/shared_cmake/MocPlatform.cmake`: map the platform to CMake and TrustCore settings.
3. `projects/shared_cmake/toolchains/<toolchain>.cmake`: add only if the SDK environment does not fully configure the compiler.
4. `scripts/ci/trustedge/ci_trustedge_build.sh` and related scripts: update help text or forwarding behavior if needed.
5. Developer documentation: document installation, environment setup, local commands, prerequisites, and troubleshooting.

Treat the toolchain as fully supported only after the build succeeds in a clean developer environment and the documentation tells a developer exactly how to reproduce it.
