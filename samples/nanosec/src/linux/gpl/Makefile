############################################################################
# File:        Makefile
# Created:     Tue Sep 12 09:24:45 PDT 2006
# Description: Makefile for IPsec linux build
############################################################################

# Need to include this first in case the sane defaults for the values
# below will overwrite them.
include $(PWD)/Makefile.linux.cross

# Common variables needed for both Linux kernel build and Mocana build
RTOS         ?= __RTOS_LINUX__
OS_NAME      ?= __RTOS_LINUX__
PWD          ?= $(shell pwd)

ifneq ($(BUILD_IPSEC_MOD),y)
ifeq ($(NO_CRYPTO),true)
# FIPS build should export and thus override KBUILD_EXTRA_SYMBOLS
KBUILD_EXTRA_SYMBOLS ?= ${PWD}/../../../crypto_module_example/Module.symvers ${PWD}/../../../moc_platform_module/Module.symvers
endif
endif


EXTRA_CFLAGS += -D$(RTOS) -g -Wall -I$(PWD)/../../..\
  -D__DISABLE_ARC4_CIPHERS__ \
  -D__ENABLE_DIGICERT_MEM_PART__ \
  -D__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__ \
  -D__DISABLE_DIGICERT_FILE_SYSTEM_HELPER__ \
  -D__ENABLE_DIGICERT_IKE_SERVER__ \
  -D__ENABLE_DIGICERT_SUPPORT_FOR_NATIVE_STDLIB__ \
  -D__ENABLE_DIGICERT_EXAMPLES__ \
  -D__ENABLE_DIGICERT_IPSEC_SERVICE__

export CC=$(CROSS_COMPILE)gcc

# Distinquish between Android and Linux
ifeq (__RTOS_ANDROID__, $(RTOS))
  # Android Variants
  ifeq (CROSS_ANDROID2_ARM, $(OS_NAME))
        KBUILD_NOPEDANTIC=1
	ARCH=arm
	CROSS_COMPILE=arm-eabi-
	KERNEL ?= 2.6
	KDIR ?= /home/kblack/aaa_work/mocana/DELL/Streak/android/kernel

	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform_module/Module.symvers
	MODDIR ?= /system/lib/modules

  endif
endif

ifeq (__RTOS_LINUX__, $(RTOS))
  # Normal linux
  #
  # For SNAPGEAR LINUX (customer specific) we leave ENTROPY THREADS in the kernel module
  # but for other LINUX modules, take them out.
  #
  ifeq (CROSS_SNAPGEAR_LINUX, $(OS_NAME))
	export ARCH=arm
	export CROSS_COMPILE=arm-linux-

	KERNEL ?= 2.6.19
	KDIR ?= /home/buildmaster/svn_snapgear/linux-2.6.x
	MODDIR ?= $(KDIR)/kernel
  endif

  ifeq (CROSS_e500v2_WRLINUX, $(OS_NAME))
    export ARCH=powerpc
    export CROSS_COMPILE=ppc_e500v2-target-linux-gnu-
    export EXTRA_CFLAGS += -Wno-error -DMOC_BIG_ENDIAN

	KERNEL ?= 2.6.34
	KDIR ?= /opt/XOG_OS_DEV-for.mocana/os/explorer55.platform/distros/wrl40-wrt40-sr1/linux
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana

	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform_module/Module.symvers
  endif

  ifeq (CROSS_x86_64_WRLINUX, $(OS_NAME))
	TGTNAME ?= x86_64_wrs_linux
	KERNEL  ?= 3.10.62
	KDIR ?= /home/apath_to_your_wrs_linux_dist/distros/wrl60-wrt60-x64-hd1/linux
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform/Module.symver
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN -D__ENABLE_DIGICERT_FIPS_STATUS_MESSAGES__ \
		-DFIPS_INTEG_TEST_BINARY_FILENAME="\"$(MODDIR)/$(LKM_NAME).$(KERNEL)\"" \
	    -DFIPS_INTEG_TEST_HASH_FILENAME="\"$(MODDIR)/$(LKM_NAME).sig.$(KERNEL)\""
  endif

  ifeq (CROSS_arm64_XEROX, $(OS_NAME))
	TGTNAME ?= armv7vet2hf-neon-poky-linux
	KERNEL  ?= 4.9.189
	KDIR ?= /opt/sysroots/master/XEROX/ARM/os/linux-$(KERNEL)
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform/Module.symver
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN -D__ENABLE_DIGICERT_FIPS_STATUS_MESSAGES__ \
		-DFIPS_INTEG_TEST_BINARY_FILENAME="\"$(MODDIR)/$(LKM_NAME).$(KERNEL)\"" \
	    -DFIPS_INTEG_TEST_HASH_FILENAME="\"$(MODDIR)/$(LKM_NAME).sig.$(KERNEL)\""
  endif

  ifeq (__RTOS_LINUX__, $(OS_NAME))
    KDIR         ?= /lib/modules/$(shell uname -r)/build
    ARCH         ?= x86
    ifeq ($(CROSS_COMPILE),)
    ifeq ($(shell uname -m),x86_64)
      EXTRA_CFLAGS += -D__ENABLE_DIGICERT_64_BIT__
    endif
    ifeq ($(shell (uname -m | cut -b -3)),arm)
      ARCH = arm
    endif
    ifeq ($(shell (uname -m)),aarch64)
      ARCH = arm64
    endif
    endif
    ifeq (true, $(NO_CRYPTO))
#      KBUILD_EXTRA_SYMBOLS := $(PWD)/../../../moc_platform_module/Module.symvers
    endif
  endif
endif

# Some sane defaults for the EXTRA_CFLAGS
IMG_EXT      ?= linux.native

# Linux kernel build
ifneq ($(KERNELRELEASE),)

# Note: the Linux kbuild system expects kernel moduels to be specified in
# this way, with obj-m indicating that this is a kernel module build,
# and moc_ipsec_mod-y indicating the modules that are required to be built
ifeq ($(BUILD_IPSEC_MOD),y)
obj-m := moc_ipsec_mod.o
else
obj-m := moc_ipsec.o
endif

DBG_CFLAGS += -g -DDEBUG

ccflags-y = $(EXTRA_CFLAGS)
ccflags-y += ${DBG_CFLAGS}

CC += ${DBG_CFLAGS}

# Regression watch: this was previously moc_ipsec_mod-objs, but the Linux
# kernel build uses that convention for compiling host programs, not
# kernel modules.
ifeq ($(BUILD_IPSEC_MOD),y)
moc_ipsec_mod-y := \
	nf_ipsecadm.o \
	nf_ipsec.o \
	debug_console.o \
	nf_ipsec_async.o
else
moc_ipsec-y := \
	nf_ipsecadm.o \
	nf_ipsec.o \
	nf_ipsec_async.o \
	linux_rtos_kn.o \
	_mocana_ipsec.o
endif

# Mocana build system
else

export CC=$(CROSS_COMPILE)gcc
CC += ${DBG_CFLAGS}

all_modules: links

all: links all_modules

clean: clean_modules clean_links
	-rm -f missiu

clean_links:
	-rm -f linux_rtos_kn.c
	-rm -f debug_console.c

links:
	# Need to pull in one file from the platform abstraction layer.
	[ -f linux_rtos_kn.c ] || ln -fs ../../../../../src/platform/linux_rtos_kn.c .
	[ -f debug_console.c ] || ln -fs ../../../../../src/common/debug_console.c .

all_modules:
	touch ._mocana_ipsec.o.cmd
	make V=1 -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		modules

clean_modules:
	-[ -d $(KDIR) ] && make -C $(KDIR) M=$(PWD) clean

endif

# Need this so that the first time make runs, it will link in the included Makefile
$(PWD)/Makefile.linux.cross:
	# Included Makefile does not exist. Linking in...
	test -f Makefile.linux.cross || ln -fs $(PWD)/../../../../../make/Makefile.linux.cross $(PWD)
