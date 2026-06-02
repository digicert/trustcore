############################################################################
# File:        Makefile
# Created:     Tue Sep 12 09:24:45 PDT 2006
# Description: Linux makefile for IPsec missiu
############################################################################

# This will grab the CROSS_COMPILE define for the HW_ACCEL_DEV architecture,
# if it is defined.
include $(PWD)/../../../../../make/Makefile.linux.cross

CC	=$(CROSS_COMPILE)gcc
LD	=$(CROSS_COMPILE)gcc

SRC_DIR = ../../../..

# compiler flags
# TODO these may need to be updated. This has not been built in a long time.
CFLAGS = -O0
CFLAGS += -D__RTOS_LINUX__
CFLAGS += -D__ENABLE_IPSEC_NAT_T__
CFLAGS += -D__ENABLE_DIGICERT_IKE_SERVER__
CFLAGS += -D__ENABLE_DIGICERT_IPSEC_SERVICE__
CFLAGS += -D__PLATFORM_HAS_GETOPT__
CFLAGS += -D__ENABLE_DIGICERT_SUPPORT_FOR_NATIVE_STDLIB__
CFLAGS += -D__ENABLE_DIGICERT_MISSIU__
CFLAGS += -DMOC_LITTLE_ENDIAN

CFLAGS += -I$(SRC_DIR)/examples
CFLAGS += -I$(SRC_DIR)/examples/ipsec
CFLAGS += -I$(SRC_DIR)/examples/ipsec/linux/gpl
CFLAGS += $(EXTRA_CFLAGS)

ASN1_PATH = $(SRC_DIR)/asn1/
COMMON_PATH = $(SRC_DIR)/common/
CRYPTO_PATH = $(SRC_DIR)/crypto/
IKE_PATH = $(SRC_DIR)/ike/
IPSEC_PATH = $(SRC_DIR)/ipsec/
PLATFORM_PATH = $(SRC_DIR)/platform/
GPL_PATH = $(SRC_DIR)/examples/ipsec/linux/gpl/
MISSIU_PATH = $(SRC_DIR)/examples/ipsec/linux/missiu/

include $(PWD)/../Makefile.ipsec-obj.inc

# User specified object files
OBJS := \
        missiu.o \
        missiu_tap.o \
        missiu_com.o \
        nf_ipsecadm.o \
        linux_udp.o \
        linux_tcp.o \
        utils.o \
        $(IPSEC_OBJS)

# User specified libraries
ifneq ($(NO_CRYPTO),true)
OBJS += linux_rtos.o
LIBS = -lpthread
else
LIBS = -lmss -lpthread -L$(LIB_MSS)
endif

all: missiu

missiu: $(OBJS)
	$(LD) $(LIBS) -o $@ $(OBJS) -lrt

%.o : $(ASN1_PATH)%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o : $(COMMON_PATH)%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o : $(CRYPTO_PATH)%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: $(IKE_PATH)%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: $(IPSEC_PATH)%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: $(PLATFORM_PATH)%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: $(MISSIU_PATH)%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: $(GPL_PATH)%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o

cleanall:
	rm -f *.o 
	rm -f missiu

