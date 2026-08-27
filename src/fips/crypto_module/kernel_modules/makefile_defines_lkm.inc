#########################################################
#  makefile_defines_lkm.inc
#
# Copyright Mocana Corp 2016. All Rights Reserved.
# Proprietary and Confidential Material.
#
#########################################################
#---------------------------
# Build time-stamp and possibly git branch name.
#---------------------------
stamp = $(shell date +"%F %H:%M")
git-branch = $(shell cd $(PWD) ; git branch | grep "\*" | head -1 | cut -c3-43)

MSS_VERSION_STR    ?= "8.0.0f"
MSS_BUILDTIME_STR  ?= "$(stamp)"
MSS_BUILD_STR      ?= "git-[$(git-branch)]"


MOC_CFLAGS += \
-D__ENABLE_DIGICERT_JSON_PARSER__ \
-D__ENABLE_DIGICERT_GCM_64K__ \
-D__ENABLE_DIGICERT_GCM_4K__ \
-D__ENABLE_DIGICERT_GCM_256B__ \
-D__ENABLE_DES_CIPHER__ \
-D__ENABLE_DIGICERT_MD4__ \
-D__ENABLE_DIGICERT_MD2__ \
-D__ENABLE_DIGICERT_SHA3__ \
-D__ENABLE_DIGICERT_ECC__ \
-D__ENABLE_DIGICERT_ECC_P192__ \
-D__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__ \
-D__ENABLE_DIGICERT_IPSEC_SERVICE__ \
-D__DISABLE_DIGICERT_PUB_CRYPTO_SERIALIZATION__ \
-D__ENABLE_DIGICERT_RNG_DRBG_CTR__ \
-D__ENABLE_DIGICERT_FIPS_MODULE__ \
-D__ENABLE_DIGICERT_FIPS_RANDOM__ \
-D__ENABLE_DIGICERT_FIPS_SHA1__ \
-D__ENABLE_DIGICERT_FIPS_SHA256__ \
-D__ENABLE_DIGICERT_FIPS_SHA512__ \
-D__ENABLE_DIGICERT_FIPS_SHA3__ \
-D__ENABLE_DIGICERT_FIPS_HMAC__ \
-D__ENABLE_DIGICERT_FIPS_3DES__ \
-D__ENABLE_DIGICERT_FIPS_AES__ \
-D__ENABLE_FIPS_POWERUP_TEST__ \
-D__ENABLE_DIGICERT_FIPS_INTEG_TEST__ \
-D__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__ \
-D__MOC_PLATFORM_MODULE__ \
-D__DISABLE_DIGICERT_FILE_SYSTEM_HELPER__ \
-D__DISABLE_DIGICERT_INIT__ \
-D__DIGICERT_DSF_VERSION_STR__=\"$(MSS_VERSION_STR)\" \
-D__DIGICERT_DSF_BUILD_STR__=\"$(MSS_BUILD_STR)\" \
-D__DIGICERT_DSF_BUILDTIME_STR__=\"$(MSS_BUILDTIME_STR)\" 

########################
## Kernal module rationale
########################
## The following must be there in the final FIPS deliverable binaries.
## -D__ENABLE_DIGICERT_FIPS_INTEG_TEST__
## -D__ENABLE_DIGICERT_FIPS_MODULE__
## -D__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__  (NOTE: This -D is set in the fips crypto module makefile directly)
## -D__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__

## 6.4.1 Note: The following macro is needed for the portable CAVP applications which use ssh_client. (and likely real customers that use ssh)
## We are therefore adding this as part of the standard crypto shared lib.
## -D__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__ \

## The following are used by FIPS testing (and the so_sign utility) but don't impact the crypto lib:
## -Dx__ENABLE_FIPS_POWERUP_TEST__ (Used in CAVP & CMVP tests)
## -Dx__ENABLE_DIGICERT_FIPS_SOSIGN__ (Used by so_sign)

## The following are useful for debugging, and CAVP & Operational testing but should be disabled for final delivery:
## -Dx__ENABLE_DIGICERT_FIPS_STATUS_MESSAGES__
## -Dx__ENABLE_DIGICERT_DEBUG_CONSOLE__
## -Dx__DIGICERT_DUMP_CONSOLE_TO_STDOUT__
## -Dx__ZEROIZE_TEST__
## -Dx__FIPS_OPS_TEST__
########################

#---------------------------
# FIPS testing specifics.
#---------------------------
ifeq ($(MSS_FIPS_TESTING),CMVP)
  MOC_CFLAGS += \
  -D__DOING_CMVP_OPS_TEST__ \
  -D__ENABLE_DIGICERT_FIPS_STATUS_MESSAGES__ \
  -D__ENABLE_DIGICERT_DEBUG_CONSOLE__ \
  -D__DIGICERT_DUMP_CONSOLE_TO_STDOUT__ \
  -D__ENABLE_FIPS_POWERUP_TEST__ \
  -D__FIPS_OPS_TEST__
else
  ifeq ($(MSS_FIPS_TESTING),ZEROIZE)
    MOC_CFLAGS += \
    -D__DOING_ZEROIZE_TEST__ \
    -D__ENABLE_DIGICERT_FIPS_STATUS_MESSAGES__ \
    -D__ENABLE_DIGICERT_DEBUG_CONSOLE__ \
    -D__DIGICERT_DUMP_CONSOLE_TO_STDOUT__ \
    -D__ENABLE_FIPS_POWERUP_TEST__ \
    -D__ZEROIZE_TEST__ \
    -D__FIPS_OPS_TEST__
  else
    ifeq ($(MSS_FIPS_TESTING),CAVP)
      MOC_CFLAGS += \
      -D__DOING_CAVP_TESTING__ \
      -D__ENABLE_FIPS_POWERUP_TEST__ 
    else
      ifeq ($(MSS_FIPS_TESTING),SO_SIGN)
        MOC_CFLAGS += \
        -D__DOING_SO_SIGN__ \
        -D__ENABLE_DIGICERT_FIPS_SOSIGN__ 
      endif
    endif
  endif
endif

