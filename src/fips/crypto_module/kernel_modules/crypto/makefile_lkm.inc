#########################################################
#  makefile_lkm.inc
#
# Copyright Mocana Corp 2009. All Rights Reserved.
# Proprietary and Confidential Material.
#
#########################################################

ifeq (,$(SRC_DIR))
SRC_DIR := .
endif

include $(PWD)/../makefile_defines_lkm.inc

LKM_NAME := default_moc_linux_crypto.ko
EXTRA_CFLAGS += $(MOC_CFLAGS) \
-D__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__ 

ifeq ($(MSS_FIPS_TESTING),CMVP)
  LKM_NAME := moc_crypto_cmvp.ko
else
  ifeq ($(MSS_FIPS_TESTING),ZEROIZE)
    LKM_NAME := moc_crypto_zero.ko
    EXTRA_CFLAGS +=  -D__DISABLE_FIPS_STARTUP_CALL__
  else
    ifeq ($(MSS_FIPS_TESTING),AUTO)
      LKM_NAME := moc_crypto_auto.ko
      EXTRA_CFLAGS +=  -D__DISABLE_FIPS_STARTUP_CALL__ \
         -D__ENABLE_FIPS_POWERUP_TEST__ 
    else
      ifeq ($(MSS_FIPS_TESTING),DEMO)
        LKM_NAME := moc_crypto.ko
        EXTRA_CFLAGS +=  -D__DISABLE_FIPS_STARTUP_CALL__ \
           -D__ENABLE_FIPS_POWERUP_TEST__ 
      endif
    endif
  endif
endif

ifeq (CROSS_ARM_POKY, $(OS_NAME))
	TGTNAME ?= armv7vet2hf-neon-poky-linux
	KERNEL  ?= 4.9.189
	KDIR ?= /opt/sysroots/master/XEROX/ARM/os/linux-$(KERNEL)
	MODDIR ?= /mnt/kernel_mods.sq/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform/Module.symvers
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN -DMOC_USE_VFS_READ \
	    -DFIPS_INTEG_TEST_BINARY_FILENAME="\"$(MODDIR)/$(LKM_NAME).$(KERNEL)\"" \
	    -DFIPS_INTEG_TEST_HASH_FILENAME="\"$(MODDIR)/$(LKM_NAME).sig.$(KERNEL)\""
endif

ifeq (CROSS_x86_64_WRLINUX, $(OS_NAME))
	TGTNAME ?= x86_64_wrs_linux
	KERNEL  ?= 4.8.28-rt16
	KDIR ?= /opt/windriver/XEROX/os/wrl90-rt-x86_64
	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform/Module.symvers
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN -DMOC_USE_VFS_READ \
	    -DFIPS_INTEG_TEST_BINARY_FILENAME="\"$(MODDIR)/$(LKM_NAME).$(KERNEL)\"" \
	    -DFIPS_INTEG_TEST_HASH_FILENAME="\"$(MODDIR)/$(LKM_NAME).sig.$(KERNEL)\""
endif

ifeq (CROSS_arm64_XEROX, $(OS_NAME))
	TGTNAME ?= armv7vet2hf-neon-poky-linux
	KERNEL  ?= 4.9.189
        KDIR ?= /opt/sysroots/master/XEROX/ARM/os/linux-$(KERNEL)

	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform/Module.symvers
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN -DMOC_USE_VFS_READ \
	    -DFIPS_INTEG_TEST_BINARY_FILENAME="\"$(MODDIR)/$(LKM_NAME).$(KERNEL)\"" \
	    -DFIPS_INTEG_TEST_HASH_FILENAME="\"$(MODDIR)/$(LKM_NAME).sig.$(KERNEL)\""	    
endif

ifeq (CROSS_arm64_XEROX_a53, $(OS_NAME))
	TGTNAME ?= arm-oemllib32-poky-linux
	KERNEL  ?= 5.4.y
        KDIR ?= /opt/sysroots/master/CUSTOM/xrx_arm_cortex_a53/os/linux-v$(KERNEL)-master

	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform/Module.symvers
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN -DMOC_USE_VFS_READ -D__DISABLE_DIGICERT_JSON_FLOAT_PARSER__ \
	    -DFIPS_INTEG_TEST_BINARY_FILENAME="\"$(MODDIR)/$(LKM_NAME).$(KERNEL)\"" \
	    -DFIPS_INTEG_TEST_HASH_FILENAME="\"$(MODDIR)/$(LKM_NAME).sig.$(KERNEL)\""	    
endif

ifeq (CROSS_x86_64_XEROX, $(OS_NAME))
	TGTNAME ?= x86_64-xerox-poky-linux
	KERNEL  ?= 5.4.66-intel-lts
        KDIR ?= /opt/sysroots/master/XEROX/x86_64/os/linux-$(KERNEL)

	MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform/Module.symvers
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN -DMOC_USE_VFS_READ \
	    -DFIPS_INTEG_TEST_BINARY_FILENAME="\"$(MODDIR)/$(LKM_NAME).$(KERNEL)\"" \
	    -DFIPS_INTEG_TEST_HASH_FILENAME="\"$(MODDIR)/$(LKM_NAME).sig.$(KERNEL)\""	    
endif


ifeq (SELFHOST_X86_64_RH, $(OS_NAME))
	TGTNAME ?= x86_64
	EXTRA_CFLAGS +=-DMOC_LITTLE_ENDIAN
	KERNEL ?= 3.17.4-301.fc21.x86_64
 	KDIR ?= /lib/modules/$(KERNEL)/build
    MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
    KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform/Module.symvers
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN \
	    -DFIPS_INTEG_TEST_BINARY_FILENAME="\"$(MODDIR)/$(LKM_NAME).$(KERNEL)\"" \
	    -DFIPS_INTEG_TEST_HASH_FILENAME="\"$(MODDIR)/$(LKM_NAME).sig.$(KERNEL)\""	    
endif


ifeq (SELFHOST_X86_64_UBUNTU, $(OS_NAME))
	TGTNAME ?= x86_64
	KERNEL ?= 3.13.0-77-generic
 	KDIR ?= /lib/modules/$(KERNEL)/build
        MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform/Module.symvers
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN -DMOC_USE_VFS_READ \
	    -DFIPS_INTEG_TEST_BINARY_FILENAME="\"$(MODDIR)/$(LKM_NAME).$(KERNEL)\"" \
	    -DFIPS_INTEG_TEST_HASH_FILENAME="\"$(MODDIR)/$(LKM_NAME).sig.$(KERNEL)\""	    
endif

ifeq (UNKNOWN, $(OS_NAME))
	TGTNAME ?= x86_64
	KERNEL ?= YourKernelNameVersionHere
 	KDIR ?= /lib/modules/$(KERNEL)/build
        MODDIR ?= /lib/modules/$(KERNEL)/kernel/mocana
	KBUILD_EXTRA_SYMBOLS := $(PWD)/../moc_platform/Module.symvers
	export EXTRA_CFLAGS += -DMOC_LITTLE_ENDIAN \
		-DFIPS_INTEG_TEST_BINARY_FILENAME="\"$(MODDIR)/$(LKM_NAME).$(KERNEL)\"" \
	    -DFIPS_INTEG_TEST_HASH_FILENAME="\"$(MODDIR)/$(LKM_NAME).sig.$(KERNEL)\""	    
endif


