############################################################################
# File:        Makefile
# Created:     Tue Jun 16 09:24:45 PDT 2009
# Description: Makefile for crypto linux fips build
############################################################################
RTOS    ?= __RTOS_LINUX__                # Var: OS to build
OS_NAME ?= CROSS_x86_64_WRLINUX
PWD     ?= $(shell pwd)
INSMOD  = sudo /sbin/insmod
RMMOD   = sudo /sbin/rmmod

include $(PWD)/makefile_lkm.inc
include $(PWD)/../makefile.linux.modules

ifeq (CROSS_x86_64_WRLINUX, $(OS_NAME))
  export CC = $(CROSS_COMPILE)gcc
  EXTRA_CFLAGS += -D$(RTOS) -g0 -Wall -I$(PWD)/.. -fno-builtin 
else
  ifeq (CROSS_arm64_XEROX_a53, $(OS_NAME))
    export CC = $(CROSS_COMPILE)gcc
    EXTRA_CFLAGS += -D$(RTOS) -g0 -Wall -I$(PWD)/.. -fno-builtin
  else
    ifeq (CROSS_arm64_XEROX, $(OS_NAME))
      export CC = $(CROSS_COMPILE)gcc
      EXTRA_CFLAGS += -D$(RTOS) -g0 -Wall -I$(PWD)/.. -fno-builtin
    else
      ifeq (CROSS_x86_64_XEROX, $(OS_NAME))
        export CC = $(CROSS_COMPILE)gcc
        EXTRA_CFLAGS += -D$(RTOS) -g0 -Wall -I$(PWD)/.. -fno-builtin
      else
        export CC ?= gcc
        EXTRA_CFLAGS += -D$(RTOS) -g0 -Wall -I$(PWD)/..
      endif
    endif
  endif
endif

# Newer kernels (6.x Kbuild) no longer honor the legacy EXTRA_CFLAGS variable;
# forward the accumulated flags to ccflags-y so all -D defines (RTOS,
# MOC_USE_VFS_READ, etc.) still reach the compiler. Harmless on older kernels.
ccflags-y += $(EXTRA_CFLAGS)

# Kernel 6.x with CONFIG_MODVERSIONS generates symbol versions via gendwarfksyms,
# which requires DWARF debug info in the object; override the Makefile's -g0 so
# the tool can read it. Placed last so it wins. so_sign runs afterward, so the
# FIPS module integrity hash is computed over the final signed .ko regardless.
ccflags-y += -g

obj-m := moc_platform_mod.o

moc_platform_mod-objs := moc_platform.o \
	$(xtra_mssobjs)

all: all_modules
	mkdir -p ../../$(TGTNAME)/kernel_modules/crypto
	cp moc_platform_mod.ko ../../$(TGTNAME)/kernel_modules/crypto/moc_platform_mod.ko.$(KERNEL)

clean: clean_modules
	rm -f moc_platform_mod.ko*

links:


