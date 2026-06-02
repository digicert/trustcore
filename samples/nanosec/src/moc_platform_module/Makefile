############################################################################
# File:        Makefile
# Created:     Tue Jun 16 09:24:45 PDT 2009
# Description: Makefile for crypto linux fips build
############################################################################
RTOS   ?= __RTOS_LINUX__                # Var: OS to build
PWD    ?= $(shell pwd)
INSMOD  = sudo /sbin/insmod
RMMOD   = sudo /sbin/rmmod

# We need to define this up here before including other Makefiles.
# There is another block of ifeqs below too.
ifeq (CROSS_ANDROID2_ARM, $(OS_NAME))
  RTOS    = __RTOS_ANDROID__
endif
ifeq (CROSS_ANDROID5_ARM64, $(OS_NAME))
  RTOS    = __RTOS_ANDROID__
endif

include $(PWD)/makefile_lkm.inc
MSS_DIR ?= $(realpath $(PWD)/../../..)
include $(MSS_DIR)/make/Makefile.linux.modules

# Distinquish between Android and Linux
ifeq (__RTOS_ANDROID__, $(RTOS))
  # We are reversing the if nesting from the top.
  # Android Variants
  ifeq (CROSS_ANDROID2_ARM, $(OS_NAME))
    export ASSEMBLY_OPT := __ASM_ARM__
    export CC = arm-eabi-gcc
    EXTRA_CFLAGS+= -D$(RTOS) -I$(PWD)/.. \
          -g0 \
          -fno-exceptions \
          -fno-builtin -DMOC_LITTLE_ENDIAN \
          -D__ARM_ARCH_5__ -D__ARM_ARCH_5T__ -D__ARM_ARCH_5E__ -D__ARM_ARCH_5TE__ \
          -DANDROID
  endif

  ifeq (CROSS_ANDROID5_ARM64, $(OS_NAME))
    export ASSEMBLY_OPT := __ASM_ARM__
    export CC = aarch64-linux-android-gcc
    EXTRA_CFLAGS+= -D$(RTOS) -I$(PWD)/.. -DMOC_LITTLE_ENDIAN -fno-pic
  endif
else

  # Normal Linux variants
  ifeq (CROSS_SNAPGEAR_LINUX, $(OS_NAME))
    export CC = ucfront-gcc arm-linux-gcc
    EXTRA_CFLAGS += -D$(RTOS) -g0 -Wall -I$(PWD)/.. \
  	  -fno-builtin -DMOC_BIG_ENDIAN
  else

  ifeq (CROSS_e500v2_WRLINUX, $(OS_NAME))
    export CC = ppc_e500v2-target-linux-gnu-gcc
    EXTRA_CFLAGS += -D$(RTOS) -g -Wall -I$(PWD)/.. \
  	  -fno-builtin -DMOC_BIG_ENDIAN
  else

  ifeq (CROSS_x86_64_WRLINUX, $(OS_NAME))
    export CC=$(CROSS_COMPILE)gcc
    EXTRA_CFLAGS += -D$(RTOS) -g0 -Wall -I$(PWD)/.. -fno-builtin
  else

  ifeq (CROSS_arm64_XEROX, $(OS_NAME))
    export CC=$(CROSS_COMPILE)gcc
    EXTRA_CFLAGS += -D$(RTOS) -g0 -Wall -I$(PWD)/.. -fno-builtin
  else

    export CC=$(CROSS_COMPILE)gcc
    EXTRA_CFLAGS += -D$(RTOS) -g0 -Wall -I$(PWD)/..

  endif
  endif
  endif
  endif

endif ## ANDROID OR NORMAL LINUX

obj-m := moc_platform_mod.o

ifeq ($(NO_CRYPTO),true)
obj-m += moc_ipsec_bridge.o
endif

moc_platform_mod-objs := moc_platform.o \
	$(xtra_mssobjs)

all: all_modules

clean: clean_modules
	rm -f moc_platform_mod.ko* moc_ipsec_bridge.ko*

links:


