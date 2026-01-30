#!/usr/bin/env bash

PLATFORMS=("rpi32" "rpi64" "avnet" "bbb" "android" "wrs_x64" "wrs_x86" "xerox_poky_x32" "xerox_poky_x64" "xerox_poky_arm" "xerox_poky_arm64" "poky_x32" "poky_x64" "poky_arm" "poky_arm64" "qnx-x86" "qnx-6-5-x86" "qnx-x86_64" "esp32" "timesys_linux_armv7_x32" "buildroot_armv7_cortex-a5_x32" "arago_linux_aarch64" "pavo64_poky_arm64" "aries64_poky_x86-64");
TARGET_PLATFORM="-DCM_TARGET_PLATFORM=";
CM_SYSROOTS="/opt/sysroots/master"

# Don't even bother on osx
if [[ "$OSTYPE" == "darwin"* ]]; then
  return 0
fi

declare -A m_sysroots
m_sysroots["rpi32"]="gcc-linaro-6.5.0-2018.12-x86_64_arm-linux-gnueabihf/bin"
m_sysroots["rpi64"]="gcc-linaro-6.5.0-2018.12-x86_64_aarch64-linux-gnu/bin"
m_sysroots["avnet"]="oecore-x86_64/sysroots/x86_64-oesdk-linux/usr/bin/arm-oe-linux-gnueabi"
m_sysroots["bbb"]=
m_sysroots["android"]=
m_sysroots["wrs_x64"]="windriver/9.0/2018.330/i686_64/sysroots/x86_64-wrlinuxsdk-linux/usr/bin/x86_64-wrs-linux/"
m_sysroots["wrs_x86"]="windriver/9.0/2018.330/i686_64/sysroots/x86_64-wrlinuxsdk-linux/usr/bin/i686-wrs-linux/"
m_sysroots["xerox_poky_x32"]="yocto_tools/3.1.2/2021.125/i686/sysroots/x86_64-pokysdk-linux/usr/bin/i686-poky-linux/"
m_sysroots["xerox_poky_x64"]="yocto_tools/3.1.2/2021.125/i686_64/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-poky-linux/"
m_sysroots["xerox_poky_arm"]="yocto_tools/3.1.2/2021.207/arm/sysroots/x86_64-oesdk-linux/usr/bin/arm-oemllib32-linux-gnueabi/"
m_sysroots["xerox_poky_arm64"]="yocto_tools/3.1.2/2021.207/arm/sysroots/x86_64-oesdk-linux/usr/bin/aarch64-oemllib32-linux/"
m_sysroots["poky_x32"]="yocto_tools/3.1.2/2021.125/i686/sysroots/x86_64-pokysdk-linux/usr/bin/i686-poky-linux/"
m_sysroots["poky_x64"]="yocto_tools/3.1.2/2021.125/i686_64/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-poky-linux/"
m_sysroots["poky_arm"]="yocto_tools/3.1.2/2021.207/arm/sysroots/x86_64-oesdk-linux/usr/bin/arm-oemllib32-linux-gnueabi/"
m_sysroots["poky_arm64"]="yocto_tools/3.1.2/2021.207/arm/sysroots/x86_64-oesdk-linux/usr/bin/aarch64-oemllib32-linux/"
m_sysroots["qnx-x86"]="qnx660/host/linux/x86/usr/bin"
m_sysroots["qnx-6-5-x86"]="qnx650/host/linux/x86/usr/bin"
m_sysroots["qnx-x86_64"]="qnx710/host/linux/x86_64/usr/bin"
m_sysroots["esp32"]=
m_sysroots["timesys_linux_armv7_x32"]="timesys/hb6mxd_combo/toolchain/bin"
m_sysroots["buildroot_armv7_cortex-a5_x32"]="buildroot/arm-buildroot-linux-gnueabihf_sdk-buildroot/bin"
m_sysroots["arago_linux_aarch64"]=
m_sysroots["pavo64_poky_arm64"]="x86_64-pokysdk-linux/usr/bin/aarch64-poky-linux/"
m_sysroots["aries64_poky_x86-64"]="x86_64-pokysdk-linux/usr/bin/x86_64-poky-linux/"

## m_sysroots["xerox_poky_arm_old"]="gcc-linaro-7.4.1-2019.02-x86_64_arm-linux-gnueabihf/bin"
## m_sysroots["xerox_poky_arm64_old"]="gcc-linaro-7.3.1-2018.05-x86_64_aarch64-linux-gnu/bin"

##############################################################################

# Caller must provide a single argument to this bash function, which is the name
# of the target system to cross-compile for.  If a name is not provided, then an
# error will occur.
get_platform ()
{
  if [ "$#" -lt 1 ]; then
    echo "No target system provided, exiting..."
    exit 1
  fi

  local seeking="$1"
  local in=1
  for e in "${PLATFORMS[@]}"; do
    if [[ "$e" == "$seeking" ]]; then
      in=0
      break;
    fi
  done

  if [ $in -eq 0 ]; then
    echo "${TARGET_PLATFORM}${1}"
    return 0
  fi

  echo "Target platform \"${1}\" not found. Exiting..."
  return 255
}


##############################################################################

# Caller must provide a single argument to this bash function, which is the name
# of the target system to cross-compile for.  If a name is not provided, then an
# error will occur.
get_sysroot_bin ()
{
  if [ "$#" -lt 1 ]; then
    echo "No target system provided, exiting..."
    exit 1
  fi

  local seeking="$1"
  local in=1
  for e in "${PLATFORMS[@]}"; do
    if [[ "$e" == "$seeking" ]]; then
      in=0
      break;
    fi
  done

  if [ $in -eq 0 ]; then
    echo "${CM_SYSROOTS}/${m_sysroots["$1"]}"
    return 0
  fi

  return 255
}
