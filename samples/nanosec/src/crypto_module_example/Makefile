############################################################################
# File:        Makefile
# Created:     Tue Jun 16 09:24:45 PDT 2009
# Description: Makefile for crypto linux example build
############################################################################
RTOS   ?= __RTOS_LINUX__                # Var: OS to build
PWD    ?= $(shell pwd)
INSMOD  = sudo /sbin/insmod
RMMOD   = sudo /sbin/rmmod

# We need to define this up here before including other Makefiles.
# There is another block of ifeqs below too.

include $(PWD)/makefile_lkm.inc
MSS_DIR ?= $(realpath $(PWD)/../../..)
include $(MSS_DIR)/make/Makefile.linux.modules

# Defines the HW accel chip to use.  For SW based, it should be commented out
ifneq ($(HW_ACCEL_DEV),)
  xtra_mssobjs  = harness.o harness_intf26_kn.o
endif
ifeq ($(HW_ACCEL_DEV),fsl8272)
  xtra_mssobjs += freescale_async_8272.o
endif
ifeq ($(HW_ACCEL_DEV),fsl8313)
  xtra_mssobjs += freescale_async_8313.o
endif
ifeq ($(HW_ACCEL_DEV),fsl8323)
  xtra_mssobjs += freescale_async_8323.o
endif
ifeq ($(HW_ACCEL_DEV),fsl8349)
  xtra_mssobjs += freescale_async_8349.o
endif
ifeq ($(HW_ACCEL_DEV),fsl8360)
  xtra_mssobjs += freescale_async_8360.o
endif
ifeq ($(HW_ACCEL_DEV),fsl8379)
  xtra_mssobjs += freescale_async_8379.o
endif
ifeq ($(HW_ACCEL_DEV),fsl8544)
  xtra_mssobjs += freescale_async_8544.o
endif
ifeq ($(HW_ACCEL_DEV),fsl8548)
  xtra_mssobjs += freescale_async_8548.o
endif
ifeq ($(HW_ACCEL_DEV),fsl8555)
  xtra_mssobjs += freescale_async_8555.o
endif
ifeq ($(HW_ACCEL_DEV),fsl8572)
  xtra_mssobjs += freescale_async_8572.o
endif
ifeq ($(HW_ACCEL_DEV),bcm5862)
  xtra_mssobjs += bcm5862_async.o
endif

export CC=$(CROSS_COMPILE)gcc -I$(PWD)/../
EXTRA_CFLAGS += -D$(RTOS) -g -Wall

xtra_mssobjs += linux_rtos_kn.o

ifneq ($(KERNELRELEASE),)

obj-m := moc_crypto.o

moc_crypto-objs :=  \
mod_crypto.o aesalgo.o aes_ccm.o aes_cmac.o aes_ctr.o aes_eax.o \
aes_ecb.o aes_xcbc_mac_96.o aes_xts.o aes.o des.o \
ffc.o gcm.o \
hmac.o hmac_kdf.o md45.o md5.o md4.o md2.o \
nist_rng.o prime.o sha1.o sha256.o sha512.o sha3.o three_des.o \
int64.o int128.o debug_console.o mversion.o mstdlib.o \
prime.o jacobi.o lucas.o random.o vlong_add.o vlong_cmp.o \
vlong_conv.o vlong_gcd.o vlong_misc.o vlong_modinv.o vlong_mul.o \
vlong_sub.o vlong_barrett.o vlong_common.o vlong_div.o \
vlong_karatsuba.o vlong_modexp.o vlong_monty.o vlong_shift.o \
initmocana.o crypto_init.o \
vlong_rand.o mrtos.o mjson.o mocctx.o oplistctx.o mocana.o rng_seed.o \
$(xtra_mssobjs)

ccflags-y := $(EXTRA_CFLAGS)

else

all: all_modules

clean: clean_modules
	-for file in *.c; do [ -L $$file ] && rm $$file; done
	rm -f moc_crypto.ko*

links:
	[ -L debug_console.c   ] || ln -fs ../../common/debug_console.c   .
	[ -L mocana.c          ] || ln -fs ../../common/mocana.c          .
	[ -L initmocana.c      ] || ln -fs ../../common/initmocana.c      .
	[ -L lucas.c           ] || ln -fs ../../common/lucas.c           .
	[ -L jacobi.c          ] || ln -fs ../../common/jacobi.c          .
	[ -L int64.c           ] || ln -fs ../../common/int64.c           .
	[ -L int128.c          ] || ln -fs ../../common/int128.c          .
	[ -L mocctx.c          ] || ln -fs ../../common/mocctx.c          .
	[ -L mversion.c        ] || ln -fs ../../common/mversion.c        .
	[ -L mstdlib.c         ] || ln -fs ../../common/mstdlib.c         .
	[ -L mrtos.c           ] || ln -fs ../../common/mrtos.c           .
	[ -L mjson.c           ] || ln -fs ../../common/mjson.c           .
	[ -L oplistctx.c       ] || ln -fs ../../common/oplistctx.c       .
	[ -L prime.c           ] || ln -fs ../../common/prime.c           .
	[ -L rng_seed.c        ] || ln -fs ../../common/rng_seed.c        .
	[ -L random.c          ] || ln -fs ../../common/random.c          .
	[ -L vlong_add.c       ] || ln -fs ../../common/vlong/vlong_add.c .
	[ -L vlong_cmp.c       ] || ln -fs ../../common/vlong/vlong_cmp.c .
	[ -L vlong_conv.c      ] || ln -fs ../../common/vlong/vlong_conv.c .
	[ -L vlong_gcd.c       ] || ln -fs ../../common/vlong/vlong_gcd.c .
	[ -L vlong_misc.c      ] || ln -fs ../../common/vlong/vlong_misc.c .
	[ -L vlong_modinv.c    ] || ln -fs ../../common/vlong/vlong_modinv.c .
	[ -L vlong_mul.c       ] || ln -fs ../../common/vlong/vlong_mul.c .
	[ -L vlong_sub.c       ] || ln -fs ../../common/vlong/vlong_sub.c .
	[ -L vlong_barrett.c   ] || ln -fs ../../common/vlong/vlong_barrett.c .
	[ -L vlong_common.c    ] || ln -fs ../../common/vlong/vlong_common.c .
	[ -L vlong_div.c       ] || ln -fs ../../common/vlong/vlong_div.c .
	[ -L vlong_karatsuba.c ] || ln -fs ../../common/vlong/vlong_karatsuba.c .
	[ -L vlong_modexp.c    ] || ln -fs ../../common/vlong/vlong_modexp.c .
	[ -L vlong_monty.c     ] || ln -fs ../../common/vlong/vlong_monty.c .
	[ -L vlong_shift.c     ] || ln -fs ../../common/vlong/vlong_shift.c .
	[ -L vlong_rand.c      ] || ln -fs ../../crypto/vlong_rand.c      .
	[ -L nist_rng.c        ] || ln -fs ../../crypto/nist_rng.c        .
	[ -L crypto_init.c     ] || ln -fs ../../crypto/crypto_init.c     .
	[ -L aes.c             ] || ln -fs ../../crypto/aes.c             .
	[ -L ffc.c             ] || ln -fs ../../crypto/ffc.c             .
	[ -L gcm.c             ] || ln -fs ../../crypto/gcm.c             .
	[ -L aes_ccm.c         ] || ln -fs ../../crypto/aes_ccm.c         .
	[ -L aes_ecb.c         ] || ln -fs ../../crypto/aes_ecb.c         .
	[ -L aes_xts.c         ] || ln -fs ../../crypto/aes_xts.c         .
	[ -L aes_cmac.c        ] || ln -fs ../../crypto/aes_cmac.c        .
	[ -L aes_eax.c         ] || ln -fs ../../crypto/aes_eax.c         .
	[ -L aes_ctr.c         ] || ln -fs ../../crypto/aes_ctr.c         .
	[ -L aes_xcbc_mac_96.c ] || ln -fs ../../crypto/aes_xcbc_mac_96.c .
	[ -L aesalgo.c         ] || ln -fs ../../crypto/aesalgo.c         .
	[ -L des.c             ] || ln -fs ../../crypto/des.c             .
	[ -L hmac.c            ] || ln -fs ../../crypto/hmac.c            .
	[ -L hmac_kdf.c        ] || ln -fs ../../crypto/hmac_kdf.c        .
	[ -L md2.c             ] || ln -fs ../../crypto/md2.c             .
	[ -L md4.c             ] || ln -fs ../../crypto/md4.c             .
	[ -L md45.c            ] || ln -fs ../../crypto/md45.c            .
	[ -L md5.c             ] || ln -fs ../../crypto/md5.c             .
	[ -L sha1.c            ] || ln -fs ../../crypto/sha1.c            .
	[ -L sha256.c          ] || ln -fs ../../crypto/sha256.c          .
	[ -L sha512.c          ] || ln -fs ../../crypto/sha512.c          .
	[ -L sha3.c            ] || ln -fs ../../crypto/sha3.c            .
	[ -L three_des.c       ] || ln -fs ../../crypto/three_des.c       .
	[ -L linux_rtos_kn.c   ] || ln -fs ../../platform/linux_rtos_kn.c .

ifneq ($(HW_ACCEL_DEV),)
	[ -L harness.c           ] || ln -s ../../harness/harness.c                 .
	[ -L harness_intf26_kn.c ] || ln -s ../../harness/harness_intf26_kn.c       .
endif

ifeq ($(HW_ACCEL_DEV),fsl8272)
	[ -L freescale_async_8272.c ] || ln -s ../../crypto/hw_offload/freescale_async_8272.c .
endif
ifeq ($(HW_ACCEL_DEV),fsl8313)
	[ -L freescale_async_8313.c ] || ln -s ../../crypto/hw_offload/freescale_async_8313.c .
endif
ifeq ($(HW_ACCEL_DEV),fsl8323)
	[ -L freescale_async_8323.c ] || ln -s ../../crypto/hw_offload/freescale_async_8323.c .
endif
ifeq ($(HW_ACCEL_DEV),fsl8349)
	[ -L freescale_async_8349.c ] || ln -s ../../crypto/hw_offload/freescale_async_8349.c .
endif
ifeq ($(HW_ACCEL_DEV),fsl8360)
	[ -L freescale_async_8360.c ] || ln -s ../../crypto/hw_offload/freescale_async_8360.c .
endif
ifeq ($(HW_ACCEL_DEV),fsl8379)
	[ -L freescale_async_8379.c ] || ln -s ../../crypto/hw_offload/freescale_async_8379.c .
endif
ifeq ($(HW_ACCEL_DEV),fsl8544)
	[ -L freescale_async_8544.c ] || ln -s ../../crypto/hw_offload/freescale_async_8544.c .
endif
ifeq ($(HW_ACCEL_DEV),fsl8548)
	[ -L freescale_async_8548.c ] || ln -s ../../crypto/hw_offload/freescale_async_8548.c .
endif
ifeq ($(HW_ACCEL_DEV),fsl8555)
	[ -L freescale_async_8555.c ] || ln -s ../../crypto/hw_offload/freescale_async_8555.c .
endif
ifeq ($(HW_ACCEL_DEV),fsl8572)
	[ -L freescale_async_8572.c ] || ln -s ../../crypto/hw_offload/freescale_async_8572.c .
endif
ifeq ($(HW_ACCEL_DEV),bcm5862)
	[ -L bcm5862_async.c        ] || ln -s ../../crypto/hw_offload/bcm5862_async.c .
endif

device:
	[ -e /dev/moc_ipsec ] || sudo mknod /dev/moc_ipsec   c 103 1

load: all device unload
	$(INSMOD) moc_ipsec.ko

unload:
	-$(RMMOD) moc_ipsec.ko

unloadall:
	-$(RMMOD) moc_ipsec.ko
ifneq ($(HW_ACCEL_DEV),)
	-$(MAKE) -C ../../harness unloadall
else
	-$(MAKE) -C ../../harness/memdrv unload
endif

loadall: unload device
ifneq ($(HW_ACCEL_DEV),)
	$(MAKE) -C ../../harness loadall
else
	$(MAKE) -C ../../harness/memdrv load
endif
	sudo $(INSMOD) moc_ipsec.ko

# Need to set moptions.h to ipsec_service then build mlibs first
loadConfig: loadConfig.c
	$(CC) $(CFLAGS) -ng -o $@ ioctl/$< -L../../../obj -lmipsec -lmcrypto -lmcommon -lmcrypto -lmcommon -lmplatform -lmcommon -lpthread

endif