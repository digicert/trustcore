# TrustEdge Yocto Build Guide

## Overview

This guide explains how to integrate TrustEdge into a Yocto/Poky build environment as a prebuilt Debian package, build a Yocto image that includes TrustEdge, run the image with QEMU, and configure the TrustEdge agent inside the image.

The example workflow uses:

- Ubuntu 22.04 as the build host
- Poky `kirkstone`
- `meta-openembedded` `kirkstone`
- A custom `meta-trustedge` layer
- The `qemux86-64` machine
- A prebuilt TrustEdge x86_64 Debian package

> **Note:** The commands in this guide are intended to be run from a Linux Bash shell. Paths are shown with `~/yocto` as the Yocto workspace unless otherwise specified.

## Prerequisites

Install the Yocto host dependencies on Ubuntu 22.04:

```bash
sudo apt update
sudo apt install -y \
  gawk wget git diffstat unzip texinfo gcc build-essential \
  chrpath socat cpio python3 python3-pip python3-pexpect \
  xz-utils debianutils iputils-ping python3-git python3-jinja2 \
  libegl1-mesa libsdl1.2-dev pylint xterm zstd \
  liblz4-tool file locales
```

Configure the locale:

```bash
sudo locale-gen en_US.UTF-8
sudo update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8
```

Then either reboot the build host or reload the locale settings in the current shell:

```bash
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANGUAGE=en_US.UTF-8
```

You also need the following TrustEdge input files before creating the recipe:

- A TrustEdge Debian package, such as `trustedge_24.7.2-5230.x86_64.deb`
- A Device Trust Manager bootstrap archive, such as `<bootstrap>.zip`

> **Note:** The source notes reference TrustEdge release packages from `https://github.com/digicert/trustedge/releases` and bootstrap download steps from DigiCert Device Trust Manager.

## Setting Up the Yocto Environment

Create a Yocto workspace:

```bash
mkdir -p ~/yocto
cd ~/yocto
```

Clone Poky:

```bash
git clone -b kirkstone https://git.yoctoproject.org/poky
```

Clone `meta-openembedded`:

```bash
git clone -b kirkstone https://github.com/openembedded/meta-openembedded.git
```

Initialize the Poky build environment:

```bash
cd ~/yocto/poky
source oe-init-build-env
```

After initialization, the current directory is `~/yocto/poky/build`.

Add the required `meta-openembedded` layers:

```bash
bitbake-layers add-layer ../../meta-openembedded/meta-oe
bitbake-layers add-layer ../../meta-openembedded/meta-python
bitbake-layers add-layer ../../meta-openembedded/meta-networking
```

## Creating the Custom TrustEdge Layer

From the Poky directory, initialize the build environment if it is not already active:

```bash
cd ~/yocto/poky
source oe-init-build-env
```

Create and add a custom TrustEdge layer:

```bash
bitbake-layers create-layer ../meta-trustedge
bitbake-layers add-layer ../meta-trustedge
bitbake-layers show-layers
```

Create the TrustEdge recipe and class directories:

```bash
mkdir -p ../meta-trustedge/recipes-connectivity/trustedge/files
mkdir -p ../meta-trustedge/classes
```

## Adding the `lib64` Compatibility Class

Some prebuilt x86_64 applications expect the dynamic loader at `/lib64/ld-linux-x86-64.so.2`, while Yocto images may place it at `/lib/ld-linux-x86-64.so.2`. Add a small image post-processing class to create the compatibility symlink.

Create `../meta-trustedge/classes/lib64-fix.bbclass` with the following content:

```bitbake
ROOTFS_POSTPROCESS_COMMAND += "create_lib64_symlink;"

create_lib64_symlink() {
  install -d ${IMAGE_ROOTFS}/lib64
  ln -sf /lib/ld-linux-x86-64.so.2 ${IMAGE_ROOTFS}/lib64/ld-linux-x86-64.so.2
}
```

> **Note:** Verify that this symlink is still required for the TrustEdge package version and target machine you are using.

## Adding TrustEdge Input Files

Copy the TrustEdge Debian package and bootstrap archive into the recipe `files` directory:

```bash
cp /home/user/trustedge_24.7.2-5230.x86_64.deb ../meta-trustedge/recipes-connectivity/trustedge/files/
cp /home/user/bootstrap.zip ../meta-trustedge/recipes-connectivity/trustedge/files/
```

Replace `/home/user/trustedge_24.7.2-5230.x86_64.deb` and `/home/user/bootstrap.zip` with the actual paths to your files.

## Adding the TrustEdge Recipe

Create `../meta-trustedge/recipes-connectivity/trustedge/trustedge.bb`.

The recipe below:

- Extracts the prebuilt TrustEdge Debian package into the image root filesystem
- Installs the bootstrap archive to `/etc/digicert/bootstrap.zip`
- Installs the TrustEdge systemd service into the Yocto systemd unit directory
- Registers `trustedge.service` with systemd
- Keeps the service disabled by default
- Skips selected Yocto QA checks because the package contains prebuilt binaries

```bitbake
SUMMARY = "TrustEdge prebuilt package"
LICENSE = "CLOSED"
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI = " \
    file://trustedge_24.7.2-5230.x86_64.deb;unpack=0 \
    file://bootstrap.zip \
"

S = "${WORKDIR}"

DEPENDS += "dpkg-native"

RDEPENDS:${PN} += "bash"

INSANE_SKIP:${PN} += "already-stripped"
INSANE_SKIP:${PN} += "ldflags"

inherit systemd

SYSTEMD_SERVICE:${PN} = "trustedge.service"
SYSTEMD_AUTO_ENABLE:${PN} = "disable"

do_configure[noexec] = "1"
do_compile[noexec] = "1"

do_install() {
  # Extract deb package
  dpkg-deb -x ${WORKDIR}/trustedge_24.7.2-5230.x86_64.deb ${D}

  # Install bootstrap file
  install -d ${D}/etc/digicert
  install -m 0600 ${THISDIR}/files/bootstrap.zip \
      ${D}/etc/digicert/bootstrap.zip

  # Install systemd unit into correct location
  install -d ${D}${systemd_system_unitdir}

  install -m 0644 \
      ${D}/etc/digicert/scripts/trustedge.service \
      ${D}${systemd_system_unitdir}/trustedge.service

  rm -rf ${D}${datadir}/bash-completion
}

FILES:${PN} += " \
    /etc/digicert \
    ${systemd_system_unitdir}/trustedge.service \
    ${datadir}/bash-completion \
"
```

> **Note:** If you use a different TrustEdge package filename, update both `SRC_URI` and the `dpkg-deb -x` command.

## Configuring `local.conf`

Add or update the following settings in `~/yocto/poky/build/conf/local.conf`.

Before adding the `MACHINE` setting, check whether `local.conf` already contains a `MACHINE` line. If it does, verify that it is set to the target machine you intend to build, such as `qemux86-64`. If it does not exist, add the example line below.

```bitbake
# Check the existing MACHINE value before adding or changing this line.
MACHINE ??= "qemux86-64"
```

The example enables systemd, installs common Linux and debugging tools, adds TrustEdge to the image, inherits the `lib64-fix` class, and creates the `trustedge` user and group.


```bitbake
# Append the remaining settings to local.conf.
BB_NUMBER_THREADS = "2"
PARALLEL_MAKE = "-j 2"
DISTRO_FEATURES:append = " systemd"
VIRTUAL-RUNTIME_init_manager = "systemd"
IMAGE_INSTALL:append = " bash curl wget openssl ca-certificates iproute2 net-tools python3 glibc-utils binutils file procps util-linux coreutils findutils grep sed gawk less which strace lsof tcpdump ethtool bind iputils openssh unzip zip tar gzip xz"
IMAGE_INSTALL:append = " trustedge"
GIT_PROTOCOL = "https"
INHERIT += "own-mirrors"
SOURCE_MIRROR_URL = "https://downloads.yoctoproject.org/mirror/sources/"
INHERIT += "lib64-fix"
INHERIT += "extrausers"
EXTRA_USERS_PARAMS = "\
    groupadd -r trustedge; \
    useradd -r -g trustedge -s /bin/false trustedge; \
"
```

Adjust `BB_NUMBER_THREADS` and `PARALLEL_MAKE` based on the CPU and memory available on the build host.

## Building the Yocto Image

Build the final image:

```bash
bitbake core-image-full-cmdline
```

After a successful build, the image artifacts are available under:

```text
~/yocto/poky/build/tmp/deploy/images/qemux86-64/
```

## Verifying the Installation

Use `oe-pkgdata-util` from the Yocto build environment to confirm which files are packaged by the TrustEdge recipe:

```bash
oe-pkgdata-util list-pkg-files trustedge
```

The source workflow shows the following expected files:

```text
trustedge:
        /etc/digicert/bootstrap.zip
        /etc/digicert/conf/eula.txt
        /etc/digicert/conf/version.txt
        /etc/digicert/scripts/configure_trustedge.sh
        /etc/digicert/scripts/start_trustedge.sh
        /etc/digicert/scripts/trustedge.service
        /etc/digicert/trustedge.json
        /usr/bin/trustedge
```

## Running the Image

Start the QEMU image:

```bash
runqemu qemux86-64 nographic
```

Log in as `root`. The source workflow uses a root account with no password.

## Configuring and Running TrustEdge

Verify that the TrustEdge binary is installed:

```bash
trustedge --version
```

Configure the TrustEdge agent with the installed bootstrap archive:

```bash
trustedge agent --configure --trustedge-user trustedge --trustedge-group trustedge --bootstrap-zip /etc/digicert/bootstrap.zip
```

Run the TrustEdge agent interactively with verbose logging:

```bash
trustedge agent --log-level VERBOSE
```

If you want to use the systemd service, check its status and start it as needed:

```bash
systemctl status trustedge.service
systemctl start trustedge.service
systemctl status trustedge.service
```


## Directory Layout

The custom TrustEdge layer should resemble the following structure:

```text
cd ~/yocto/poky
tree meta-trustedge
meta-trustedge
|-- classes
|   `-- lib64-fix.bbclass
|-- conf
|   `-- layer.conf
|-- COPYING.MIT
|-- README
|-- recipes-connectivity
|   `-- trustedge
|       |-- files
|       |   |-- bootstrap.zip
|       |   `-- trustedge_24.7.2-5230.x86_64.deb
|       `-- trustedge.bb
`-- recipes-example
    `-- example
        `-- example_0.1.bb
```

The Poky build configuration directory should include:

```text
~/yocto/poky/build
conf
|-- bblayers.conf
|-- local.conf
`-- templateconf.cfg
```

## Troubleshooting

### Build the Recipe Alone

If the full image build fails, build only the TrustEdge recipe:

```bash
cd ~/yocto/poky
source oe-init-build-env
bitbake trustedge
```

### Rebuild After Recipe Changes

If you modify the TrustEdge recipe `trustedge.bb` , clean the recipe state and rebuild the image:

```bash
bitbake -c cleansstate trustedge
bitbake core-image-full-cmdline
```

### `TCP_LISTEN_SOCKET_ADDR` Service Error

The source workflow observed the following error when starting `trustedge.service` in the Yocto image:

```text
root@qemux86-64:~# systemctl status trustedge.service
trustedge.service - TrustEdge agent
     Loaded: loaded (/lib/systemd/system/trustedge.service; disabled; vendor preset: disabled)
     Active: active (running) since Thu 2026-05-28 04:53:18 UTC; 8s ago
   Main PID: 321 (trustedge)
      Tasks: 3 (limit: 263)
     Memory: 872.0K
        CPU: 359ms
     CGroup: /system.slice/trustedge.service
             `- 321 /usr/bin/trustedge --daemon
May 28 04:53:18 qemux86-64 systemd[1]: Started TrustEdge agent.
May 28 04:53:18 qemux86-64 trustedge[321]: ERROR: TCP_LISTEN_SOCKET_ADDR failed, status = ERR_TCP_BAD_ADDRESS (-5927)
```

The source workflow resolved this by changing `server_hostname` in `/etc/digicert/trustedge.json` from `localhost` to `127.0.0.1`, then restarting the service:

```bash
systemctl stop trustedge.service
systemctl start trustedge.service
systemctl status trustedge.service
```

After the change, the service started without the address error:

```text
root@qemux86-64:~# systemctl status trustedge.service
* trustedge.service - TrustEdge agent
     Loaded: loaded (/lib/systemd/system/trustedge.service; disabled; vendor preset: disabled)
     Active: active (running) since Thu 2026-05-28 13:48:26 UTC; 2s ago
   Main PID: 333 (trustedge)
      Tasks: 3 (limit: 263)
     Memory: 396.0K
        CPU: 130ms
     CGroup: /system.slice/trustedge.service
             `- 333 /usr/bin/trustedge --daemon
May 28 13:48:26 qemux86-64 systemd[1]: Started TrustEdge agent.
```

> **Note:** Verify the preferred TrustEdge configuration value for `server_hostname` before applying this change in production images.

## References

- [Yocto Project documentation](https://docs.yoctoproject.org/)
- [Poky repository](https://git.yoctoproject.org/poky)
- [meta-openembedded repository](https://github.com/openembedded/meta-openembedded)
- [TrustEdge Build & Run Guide](../samples/trustedge/BUILD_RUN.md)
- [DigiCert Device Trust Manager documentation](https://docs.digicert.com/en/device-trust-manager.html)

## Additional Notes

- Verify whether `kirkstone` is the required Yocto branch for your release.
- Verify whether `SYSTEMD_AUTO_ENABLE:${PN} = "disable"` is the desired default service behavior for your image.
