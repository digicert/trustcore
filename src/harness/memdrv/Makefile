PWD   ?= $(shell pwd)
INSMOD = sudo /sbin/insmod
RMMOD  = sudo /sbin/rmmod

EXTRA_CFLAGS += -D__RTOS_LINUX__

ifneq ($(KERNELRELEASE),)

obj-m += moc_memdrv.o
moc_memdrv-objs := linux_memdrv.o

ccflags-y := $(EXTRA_CFLAGS)

else

ifneq ($(KBUILD_EXTMOD),)
include $(KBUILD_EXTMOD)/../../../make/Makefile.linux.modules
else
include $(PWD)/../../../make/Makefile.linux.modules
endif

all: all_modules

clean: clean_modules

load: all device unload
	$(INSMOD) moc_memdrv.ko

unload:
	-$(RMMOD) moc_memdrv

device:
	[ -e /dev/moc_memdrv ] || sudo mknod /dev/moc_memdrv c 250 0

endif
