#########################################################
#  makefile_lkm.inc
#
# Copyright Mocana Corp 2009-2016. All Rights Reserved.
# Proprietary and Confidential Material.
#
#########################################################

EXTRA_CFLAGS += $(MOC_CFLAGS) 

# Distinquish between Android and Linux
ifeq (__RTOS_ANDROID__, $(RTOS))
  # Android Variants
  ifeq (CROSS_ANDROID2_ARM, $(OS_NAME))
        KBUILD_NOPEDANTIC=1
	ARCH=arm
	CROSS_COMPILE ?= arm-eabi-
	KERNEL ?= 2.6
	KDIR ?= /home/kblack/aaa_work/mocana/DELL/Streak/android/kernel
  endif

  ifeq (CROSS_ANDROID5_ARM64, $(OS_NAME))
        KBUILD_NOPEDANTIC=1
	ARCH=arm64
	CROSS_COMPILE ?= aarch64-linux-android-
	KERNEL ?= 2.6
	KDIR ?= /home/kblack/aaa_work/mocana/DELL/Streak/android/kernel
  endif
else
  # Normal linux
  #
  # For SNAPGEAR LINUX (customer specific) we leave ENTROPY THREADS in the kernel module
  # but for other LINUX modules, take them out.
  #
  ifeq (CROSS_SNAPGEAR_LINUX, $(OS_NAME))
	export ARCH=arm
	export CROSS_COMPILE=arm-linux-

	KERNEL ?= 2.6.19
	KDIR ?= /home/buildmaster/svn_snapgear/linux-2.6.x/
  else

  ifeq (CROSS_e500v2_WRLINUX, $(OS_NAME))
	export ARCH=powerpc
	export CROSS_COMPILE=ppc_e500v2-target-linux-gnu-
	export EXTRA_CFLAGS += -Wno-error -DMOC_BIG_ENDIAN

	KERNEL ?= 2.6.34
	KDIR ?= /opt/XOG_OS_DEV-for.mocana/os/explorer55.platform/distros/wrl40-wrt40-sr1/linux
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana

	KBUILD_EXTRA_SYMBOLS := $(PWD)/../crypto_linux/Module.symvers 
  else

  ifeq (CROSS_x86_64_WRLINUX, $(OS_NAME))
	TGTNAME ?= x86_64_wrs_linux
	KERNEL  ?= 3.10.62
 	KDIR ?= /home/apath_to_your_wrs_linux_dist/distros/wrl60-wrt60-x64-hd1/linux
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	## KBUILD_EXTRA_SYMBOLS := $(PWD)/../SomeOtherModule/Module.symvers
	export EXTRA_CFLAGS += -Wno-error
  else

  ifeq (CROSS_arm64_XEROX, $(OS_NAME))
	TGTNAME ?= armv7vet2hf-neon-poky-linux
	KERNEL  ?= 4.9.189
	KDIR ?= /opt/sysroots/master/XEROX/ARM/os/linux-$(KERNEL)
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	## KBUILD_EXTRA_SYMBOLS := $(PWD)/../SomeOtherModule/Module.symvers
	export EXTRA_CFLAGS += -Wno-error
  else

  ifeq (SELFHOST_X86_64_UBUNTU, $(OS_NAME))
	TGTNAME ?= x86_64
	KERNEL ?= 3.13.0-77-generic
 	KDIR ?= /lib/modules/$(KERNEL)/build
        MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	## KBUILD_EXTRA_SYMBOLS := $(PWD)/../SomeOtherModule/Module.symvers
	export EXTRA_CFLAGS +=-DMOC_LITTLE_ENDIAN
  else

  ifeq (UNKNOWN, $(OS_NAME))
	TGTNAME ?= x86_64
	KERNEL ?= YourKernelNameVersionHere
 	KDIR ?= /lib/modules/$(KERNEL)/build
        MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	## KBUILD_EXTRA_SYMBOLS := $(PWD)/../SomeOtherModule/Module.symvers
	export EXTRA_CFLAGS +=-DMOC_LITTLE_ENDIAN
  else

	#EXTRA_CFLAGS += -fPIC -O3 -fomit-frame-pointer
	EXTRA_CFLAGS +=-DMOC_LITTLE_ENDIAN

	KERNEL ?= 2.6.34.7
	KDIR ?= /lib/modules/$(KERNEL)/build
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana

  endif
  endif
  endif
  endif
  endif
  endif
endif


