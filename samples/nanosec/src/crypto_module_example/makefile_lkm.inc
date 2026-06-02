#########################################################
#  makefile_lkm.inc
#
# Copyright Mocana Corp 2009-2016. All Rights Reserved.
# Proprietary and Confidential Material.
#
#########################################################

ifeq (,$(SRC_DIR))
SRC_DIR := .
endif

#---------------------------
# Build time-stamp and possibly git branch name.
#---------------------------
stamp = $(shell date +"%F")

MSS_VERSION_STR    ?= "6.4.1f.2"
MSS_BUILDTIME_STR  ?= "$(stamp)"
MSS_BUILD_STR      ?= "engineering"

include $(PWD)/makefile_defines_lkm.inc

LKM_NAME := default_moc_linux_crypto.ko
EXTRA_CFLAGS += \
        $(MOC_CFLAGS) \
	-D__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__ 


ifeq (CROSS_x86_64_WRLINUX, $(OS_NAME))
	TGTNAME ?= x86_64_wrs_linux
	KERNEL  ?= 3.10.62
	KDIR ?= /home/apath_to_your_wrs_linux_dist/distros/wrl60-wrt60-x64-hd1/linux
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform/Module.symver
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN 
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
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform/Module.symver
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN 
else

ifeq (SELFHOST_X86_64_U440, $(OS_NAME))
	TGTNAME ?= x86_64
	KERNEL ?= 4.4.0-131-generic
	KDIR ?= /lib/modules/$(KERNEL)/build
        MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform_module/Module.symvers
	export EXTRA_CFLAGS +=-DMOC_LITTLE_ENDIAN
else

ifeq (UNKNOWN, $(OS_NAME))
	TGTNAME ?= x86_64
	KERNEL ?= YourKernelNameVersionHere
	KDIR ?= /lib/modules/$(KERNEL)/build
        MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform/Module.symver
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN 
else

	KERNEL ?= `uname -r`
	KDIR ?= /lib/modules/$(KERNEL)/build
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN 
endif
endif
endif
endif
endif

