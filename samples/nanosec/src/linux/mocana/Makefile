############################################################################
# File:        Makefile
# Created:     Tue Sep 12 09:24:45 PDT 2006
# Description: Makefile for IPsec linux build
############################################################################

# Need to include this first in case the sane defaults for the values
# below will overwrite them.
include $(PWD)/../../../../../make/Makefile.linux.cross

# Common variables needed for both Linux kernel build and Mocana build
RTOS         ?= __RTOS_LINUX__
OS_NAME      ?= __RTOS_LINUX__
PWD          ?= $(shell pwd)

# MSS_DIR is the repo root; passed from cmake or computed as fallback.
MSS_DIR ?= $(realpath $(PWD)/../../../../..)
KBUILD_EXTRA_SYMBOLS ?= ${MSS_DIR}/samples/nanosec/src/crypto_module_example/Module.symvers ${MSS_DIR}/samples/nanosec/src/moc_platform_module/Module.symvers

export CC=$(CROSS_COMPILE)gcc -I$(PWD)/../../
EXTRA_CFLAGS += -D$(RTOS) -g -Wall -I$(PWD)/../.. -I$(PWD)/../../.. \
  -D__DISABLE_ARC4_CIPHERS__ \
  -D__ENABLE_DIGICERT_MEM_PART__ \
  -D__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__ \
  -D__DISABLE_DIGICERT_FILE_SYSTEM_HELPER__ \
  -D__ENABLE_DIGICERT_IKE_SERVER__ \
  -D__ENABLE_DIGICERT_SUPPORT_FOR_NATIVE_STDLIB__ \
  -D__ENABLE_DIGICERT_EXAMPLES__ \
  -D__ENABLE_DIGICERT_IPSEC_SERVICE__

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

	KBUILD_EXTRA_SYMBOLS := $(PWD)/../../../crypto_module_example/Module.symvers
  endif

  ifeq (CROSS_x86_64_WRLINUX, $(OS_NAME))
	TGTNAME ?= x86_64_wrs_linux
	KERNEL  ?= 3.10.62
	export EXTRA_CFLAGS += -Wno-error
	KDIR ?= /home/apath_to_your_wrs_linux_dist/distros/wrl60-wrt60-x64-hd1/linux
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../../../moc_platform_module/Module.symvers
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../../../crypto_module_example/Module.symvers
  endif

  ifeq (CROSS_arm64_XEROX, $(OS_NAME))
	TGTNAME ?= armv7vet2hf-neon-poky-linux
	KERNEL  ?= 4.9.189
	export EXTRA_CFLAGS += -Wno-error
	KDIR ?= /opt/sysroots/master/XEROX/ARM/os/linux-$(KERNEL)
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../../../moc_platform_module/Module.symvers
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../../../crypto_module_example/Module.symvers
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
    endif
    ifeq (true, $(NO_CRYPTO))
#      KBUILD_EXTRA_SYMBOLS := $(PWD)/../../../moc_platform_module/Module.symvers
#      KBUILD_EXTRA_SYMBOLS := $(PWD)/../../../crypto_module_example/Module.symvers
    endif
  endif
endif

# Some sane defaults for the EXTRA_CFLAGS
IMG_EXT      ?= linux.native


# if NO_CRYPTO is true, the crypto module symbols will not be included.
include $(PWD)/../Makefile.ipsec-obj.inc
export CC=$(CROSS_COMPILE)gcc -I$(PWD)/../../../


# Linux kernel build
ifneq ($(KERNELRELEASE),)

# Note: the Linux kbuild system expects kernel modules to be specified in
# this way, with obj-m indicating that this is a kernel module build,
# and moc_ipsec-y indicating the modules that are required to be built
ifeq ($(BUILD_IPSEC_MOD),y)
obj-m := moc_ipsec.o
moc_ipsec-objs := moc_ipsec_main.o
else
obj-m := _mocana_ipsec.o
endif

ccflags-y := $(EXTRA_CFLAGS)

# Regression watch: this was previously moc_ipsec-objs, but the Linux
# kernel build uses that convention for compiling host programs, not
# kernel modules.
ifeq ($(BUILD_IPSEC_MOD),y)
moc_ipsec-y := \
	linux_rtos_kn.o \
	$(IPSEC_OBJS)
else
_mocana_ipsec-y := \
	$(IPSEC_OBJS)
endif

# Mocana build system
else

all_modules: links

all: links all_modules
ifeq ($(BUILD_IPSEC_MOD),y)
	cp moc_ipsec.ko $(PWD)/../../../../../bin/moc_ipsec.ko
else
	cp _mocana_ipsec.o ../gpl/_mocana_ipsec.o_shipped
endif

clean_extra:
	-rm -f *.ko
	-rm -f Module.symvers
	-rm -f modules.order
	-rm -f *.mod.c
	-rm -f .*.cmd
	-rm -rf .tmp_versions

clean: clean_extra clean_links
	-rm -f missiu
	-rm -f *.o

# This defines the 'links' and 'clean_links' targets
include $(PWD)/../Makefile.links.inc

# This adds the all_modules and clean_modules targets
# include $(PWD)/../../../../../make/Makefile.linux.modules
all_modules:
ifeq ($(HW_ACCEL_DEV),)
  ifeq (CROSS_e500v2_WRLINUX, $(OS_NAME))
	make V=1 KBUILD_MODPOST_WARN=1 -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules
  else
    ifeq (CROSS_ANDROID2_ARM, $(OS_NAME))
	  make V=1 KBUILD_MODPOST_WARN=1 -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules
    else
      ifeq (CROSS_x86_64_WRLINUX, $(OS_NAME))
	  make V=1 KBUILD_MODPOST_WARN=1 -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules
      else
	  make V=1 KBUILD_MODPOST_WARN=1 -C $(KDIR) M=$(PWD) modules
      endif
    endif
  endif
else
	make V=1 KBUILD_MODPOST_WARN=1 -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules
endif

endif
