#########################################################
#  makefile_lkm.inc
#
# Copyright Mocana Corp 2009. All Rights Reserved.
# Proprietary and Confidential Material.
#
#########################################################

include $(PWD)/../makefile_defines_lkm.inc

EXTRA_CFLAGS += $(MOC_CFLAGS) 

ifeq (CROSS_ARM_POKY, $(OS_NAME))
	TGTNAME ?= armv7vet2hf-neon-poky-linux
	KERNEL  ?= 4.9.189
	KDIR ?= /opt/sysroots/master/XEROX/ARM/os/linux-$(KERNEL)
	MODDIR ?= /mnt/kernel_mods.sq/mocana
	export EXTRA_CFLAGS += -Wno-error -DMOC_USE_VFS_READ
endif

ifeq (CROSS_x86_64_WRLINUX, $(OS_NAME))
	TGTNAME ?= x86_64_wrs_linux
	KERNEL  ?= 4.8.28-rt16
 	KDIR ?= /opt/windriver/XEROX/os/wrl90-rt-x86_64
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	## KBUILD_EXTRA_SYMBOLS := $(PWD)/../SomeOtherModule/Module.symvers
	export EXTRA_CFLAGS += -Wno-error -DMOC_USE_VFS_READ
endif

ifeq (CROSS_arm64_XEROX, $(OS_NAME))
	TGTNAME ?= armv7vet2hf-neon-poky-linux
	KERNEL  ?= 4.9.189
        KDIR ?= /opt/sysroots/master/XEROX/ARM/os/linux-$(KERNEL)
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	## KBUILD_EXTRA_SYMBOLS := $(PWD)/../SomeOtherModule/Module.symvers
	export EXTRA_CFLAGS += -Wno-error -DMOC_USE_VFS_READ
endif

ifeq (CROSS_arm64_XEROX_a53, $(OS_NAME))
	TGTNAME ?= arm-oemllib32-poky-linux
	KERNEL  ?= 5.4.y
        KDIR ?= /opt/sysroots/master/CUSTOM/xrx_arm_cortex_a53/os/linux-v$(KERNEL)-master
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	## KBUILD_EXTRA_SYMBOLS := $(PWD)/../SomeOtherModule/Module.symvers
	export EXTRA_CFLAGS += -Wno-error -DMOC_USE_VFS_READ -D__DISABLE_DIGICERT_JSON_FLOAT_PARSER__
endif

ifeq (CROSS_x86_64_XEROX, $(OS_NAME))
	TGTNAME ?= x86_64-xerox-poky-linux
	KERNEL  ?= 5.4.66-intel-lts
        KDIR ?= /opt/sysroots/master/XEROX/x86_64/os/linux-$(KERNEL)
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	## KBUILD_EXTRA_SYMBOLS := $(PWD)/../SomeOtherModule/Module.symvers
	export EXTRA_CFLAGS += -m64 -march=corei7 -mtune=corei7 -mfpmath=sse -msse4.2 \
        -fstack-protector-strong  -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security \
        -Werror=format-security -Wno-error  -DMOC_USE_VFS_READ
endif

ifeq (SELFHOST_X86_64_RH, $(OS_NAME))
	TGTNAME ?= x86_64
	KERNEL ?= 3.17.4-301.fc21.x86_64
 	KDIR ?= /lib/modules/$(KERNEL)/build
        MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
        EXTRA_CFLAGS +=-DMOC_LITTLE_ENDIAN
endif

ifeq (SELFHOST_X86_64_UBUNTU, $(OS_NAME))
	TGTNAME ?= x86_64
	KERNEL ?= 3.13.0-77-generic
 	KDIR ?= /lib/modules/$(KERNEL)/build
        MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	## KBUILD_EXTRA_SYMBOLS := $(PWD)/../SomeOtherModule/Module.symvers 	
	export EXTRA_CFLAGS +=-DMOC_LITTLE_ENDIAN -DMOC_USE_VFS_READ
endif

ifeq (UNKNOWN, $(OS_NAME))
	TGTNAME ?= x86_64
	KERNEL ?= YourKernelNameVersionHere
 	KDIR ?= /lib/modules/$(KERNEL)/build
        MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	## KBUILD_EXTRA_SYMBOLS := $(PWD)/../SomeOtherModule/Module.symvers 	
	export EXTRA_CFLAGS +=-DMOC_LITTLE_ENDIAN
endif


