############################################################################
# File:        Makefile
# Created:     Tue Sep 12 09:24:45 PDT 2006
# Description: Linux makefile for IPsec loadConfig
############################################################################

ifeq ($(HW_ACCEL_DEV),fsl8272)
  CROSS_COMPILE = fsl8272-
endif
ifeq ($(HW_ACCEL_DEV),fsl8313)
  CROSS_COMPILE = fsl8313-
endif
ifeq ($(HW_ACCEL_DEV),fsl8323)
  CROSS_COMPILE = fsl8323-
endif
ifeq ($(MVLINUX),fsl8349)
  CROSS_COMPILE = ppc_82xx-
else
ifeq ($(HW_ACCEL_DEV),fsl8349)
  CROSS_COMPILE = fsl8349-
endif
endif
ifeq ($(HW_ACCEL_DEV),fsl8360)
  CROSS_COMPILE = fsl8349-
endif
ifeq ($(HW_ACCEL_DEV),fsl8548)
  CROSS_COMPILE = fsl8548-
endif
ifeq ($(MVLINUX),fsl8555)
  CROSS_COMPILE = ppc_85xx-
else
ifeq ($(HW_ACCEL_DEV),fsl8555)
  CROSS_COMPILE = fsl8555-
endif
endif

export CC=$(CROSS_COMPILE)gcc
export LD=$(CROSS_COMPILE)gcc

PWD = $(shell pwd)

# EXTRA_CFLAGS += -I../..

# compiler flags
# will be overridden by external CFLAGS, if any
CFLAGS = -O0
CFLAGS += -D__RTOS_LINUX__
CFLAGS += -D__ENABLE_IPSEC_NAT_T__
CFLAGS += -D__ENABLE_DIGICERT_IKE_SERVER__
CFLAGS += -D__ENABLE_DIGICERT_IPSEC_SERVICE__
CFLAGS += -D__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
CFLAGS += -D__DISABLE_DIGICERT_RNG__
CFLAGS += -D__DISABLE_DIGICERT_INIT__
CFLAGS += -D__DISABLE_DIGICERT_ADD_ENTROPY__
CFLAGS += -D__PLATFORM_HAS_GETOPT__
CFLAGS += -D__ENABLE_DIGICERT_SUPPORT_FOR_NATIVE_STDLIB__
CFLAGS += -I$(PWD)
CFLAGS += -I$(PWD)/..
CFLAGS += $(EXTRA_CFLAGS)

SRC_DIR ?= ../..
CFLAGS += -I$(SRC_DIR)/examples
COMMON_PATH = $(SRC_DIR)/common/
PLATFORM_PATH = $(SRC_DIR)/platform/
IPSEC_PATH = $(SRC_DIR)/ipsec/
LINUX_GPL_PATH = $(SRC_DIR)/examples/ipsec/linux/gpl/
MISSIU_PATH = $(SRC_DIR)/examples/ipsec/linux/missiu/

# User specified object files
OBJS = loadConfig.o loadConfig_linux.o loadConfig_missiu.o missiu_com.o \
       script.o \
       debug_console.o mocana.o mstdlib.o int64.o dynarray.o utils.o \
       linux_rtos.o linux_udp.o linux_fmgmt.o \

# User specified libraries
LIBS = -lpthread


all: loadConfig

loadConfig: $(OBJS)
	$(LD) $(EXTRA_CFLAGS) -o $@ $(OBJS) -lrt $(LIBS)

%.o : $(COMMON_PATH)%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: $(IPSEC_PATH)%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: $(PLATFORM_PATH)%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: $(LINUX_GPL_PATH)%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: $(MISSIU_PATH)%.c
	$(CC) $(CFLAGS) -c -o $@ $<


clean:
	rm -f *.o

cleanall:
	rm -f *.o
	rm -f loadConfig

