# Check if sysroot argument is provided
ifneq ($(sysroot),)
	SYSROOT_ARG=" SYSROOT=${sysroot}"
endif

# If HOST_OS_NAME is not provided try to figure out the os/platform
ifeq (, $(HOST_OS_NAME))
  UNAME_O = $(shell uname -s)

  # Check for OSX
  ifneq (, $(findstring Darwin, $(UNAME_O)))
    HOST_OS_NAME = OSX
  endif

  # If HOST_OS_NAME couldn't be set, default to linux
  ifeq (, $(HOST_OS_NAME))
    HOST_OS_NAME = LINUX
  endif
endif

$(info HOST_OS_NAME="*****[$(HOST_OS_NAME)]*****")
$(info PLATFORM="*****[${PLATFORM}]*****")

# Determine toolchain based on platform
ifneq (,$(findstring android,$(PLATFORM)))
    TOOLCHAIN_ARG="toolchain=android"
    LD=clang
    AR_CMD=llvm-ar
else
ifneq ($(CROSS_COMPILE),)
    LD=${CROSS_COMPILE}ld
    AR_CMD=${CROSS_COMPILE}ar
else
    LD=gcc
    AR_CMD=ar
endif
endif

ifeq ($(HOST_OS_NAME), OSX)
  override CC     = gcc
endif

ifeq ($(HOST_OS_NAME), VXWORKS)
  CC              = cc
endif

ifeq ($(HOST_OS_NAME), ANDROID)
  CC              = cc
endif

ifeq ($(HOST_OS_NAME), LINUX)
  CC              ?= cc
endif

../../../../bin/libnanocrypto.so:
	$(MAKE) -C ../../../../ -f make/Makefile.ssl CC=${CC} LD=${LD} AR=${AR_CMD} ${SYSROOT_ARG} ${TOOLCHAIN_ARG} nanocrypto