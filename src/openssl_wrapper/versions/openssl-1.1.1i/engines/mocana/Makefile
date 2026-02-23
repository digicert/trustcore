$(info MOCANA_OSSL_NAME="*****[$(MOCANA_OSSL_NAME)]*****")

DIR=mocana
TOP=../..
OSSL_TOP=../../../$(MOCANA_OSSL_NAME)
OBJ_DIR=obj
MOCANA_BASE ?= $(OSSL_TOP)/../..
SEP= /
PRJ_DIR= .
CRYPTO_INTERFACE=

fips ?= false
$(info fips=$(fips))

suiteb ?= true
$(info suiteb=$(suiteb))

build_nanocrypto ?= false
ifneq (true, $(cryptointerface))
    $(info "cryptointerface=true not provided. Using Makefile.ssl to build libnanocrypto.so")
    build_nanocrypto = true
endif

ifneq ($(sysroot),)
	SYSROOT_ARG=" SYSROOT=${sysroot}"
endif

cryptointerface ?= true
$(info cryptointerface=$(cryptointerface))

$(info OSSL_TOP="*****[$(OSSL_TOP)]*****")
$(info disable_strict_ca_check is $(disable_strict_ca_check))

TAP_ARG=

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

# set tpm=true on command line to enable TPM1.2 support
SECMOD_ACCEL_DEV = 0
ifeq (true, $(tpm))
    $(info "Enabling TPM support")
    SECMOD_ACCEL_DEV = 1
endif

ifeq (, $(MOCANA_BASE))
$(error "Please define the env variable MOCANA_BASE to the rootdir of your Mocana source (typically called mss)")
endif

INCLUDES= -I$(MOCANA_BASE)/src -I../.. -I../../include
INCLUDES+=-I../../crypto/include
ifeq ($(HOST_OS_NAME), VXWORKS)
  INCLUDES+= -I$(VSB_DIR)/share/h -I. -Icrypto/include -Iinclude -I.. -I../crypto/include -I../include -I../../krnl/crypto/include
endif
MAKEFILE= Makefile
#override AR= ar q

ifeq ($(HOST_OS_NAME), OSX)
  override CC     = gcc
  PLATFORM_CFLAGS = -Os -D__RTOS_OSX__
  LINKFLAGS       = -liconv
  MOC_SHLIB_SUFFIX = .dylib
endif

ifeq ($(HOST_OS_NAME), VXWORKS)
  CC              = cc
  PLATFORM_CFLAGS = -D__RTOS_VXWORKS__ -DOPENSSL_SYS_VXWORKS_SUPPORT -D_VSB_CONFIG_FILE=\"$(VSB_DIR)/h/config/vsbConfig.h\" -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_BN_ASM_PART_WORDS -DOPENSSL_IA32_SSE2 -DNDEBUG -Dasm=__asm__ -D__vxworks -D__VXWORKS__ -D__ELF__ -D_HAVE_TOOL_XTORS -D_USE_INIT_ARRAY -DCPU=_VX_SIMLINUX -DTOOL_FAMILY=llvm -DTOOL=llvm -D_WRS_KERNEL -DINET -D_WRS_LIB_BUILD
  LINKFLAGS       = -ldl -lrt -Wl,--no-as-needed -lpthread 
  MOC_SHLIB_SUFFIX = .so
endif

ifeq ($(HOST_OS_NAME), ANDROID)
  CC              = cc
  PLATFORM_CFLAGS = -D__RTOS_LINUX__ -D__RTOS_ANDROID__
  LINKFLAGS       = -ldl -lrt -Wl,--no-as-needed
  MOC_SHLIB_SUFFIX = .so
endif

ifeq ($(HOST_OS_NAME), LINUX)
  CC              ?= cc
  PLATFORM_CFLAGS = -D__RTOS_LINUX__
  LINKFLAGS       = -ldl -lrt -Wl,--no-as-needed -lpthread
  MOC_SHLIB_SUFFIX = .so
endif

MOCANA_DEBUG_FLAGS = \
 -D__ENABLE_DIGICERT_DEBUG_CONSOLE__ \
 -D__DIGICERT_DUMP_CONSOLE_TO_STDOUT__ \
 -D__ENABLE_ALL_DEBUGGING__

ifeq ($(dbgdump),true)
 	MOCANA_DEBUG_FLAGS += -D__ENABLE_DIGICERT_DEBUG_MEMORY__
endif

MOCANA_SUITEB_FLAGS = \
 -D__ENABLE_DIGICERT_ECC__ \
 -D__ENABLE_DIGICERT_ECC_P192__ \
 -D__ENABLE_DIGICERT_GCM_64K__

ifeq ($(openssl_1_1_1),true)
MOCANA_SUITEB_FLAGS += \
 -D__ENABLE_DIGICERT_ECC_EDDH_25519__ \
 -D__ENABLE_DIGICERT_ECC_EDDSA_25519__ \
 -D__ENABLE_DIGICERT_ECC_EDDH_448__ \
 -D__ENABLE_DIGICERT_ECC_EDDSA_448__
endif

MOCANA_FIPS_LIBDIR =
MOCANA_FIPS_FLAGS = \
-Dxxx__ENABLE_DIGICERT_AES_NI__ \
-Dxxx__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__ \
-D__ENABLE_DIGICERT_GCM_64K__ \
-D__ENABLE_DIGICERT_GCM_4K__ \
-D__ENABLE_DIGICERT_GCM_256B__ \
-D__ENABLE_DIGICERT_ECC__ \
-D__ENABLE_DIGICERT_ECC_P192__ \
-D__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__ \
-D__ENABLE_DIGICERT_RSA_ALL_KEYSIZE__ \
-D__ENABLE_DIGICERT_DSA_ALL_KEYSIZE__ \
-D__ENABLE_DIGICERT_IPSEC_SERVICE__ \
-D__ENABLE_DIGICERT_RSA_SIMPLE__ \
-D__DISABLE_DIGICERT_PUB_CRYPTO_SERIALIZATION__ \
-D__ENABLE_DIGICERT_RNG_DRBG_CTR__ \
-D__ENABLE_DIGICERT_FIPS_MODULE__ \
-D__ENABLE_DIGICERT_FIPS_LIB_CONSTRUCTOR__ \
-D__ENABLE_DIGICERT_FIPS_RANDOM__ \
-D__ENABLE_DIGICERT_FIPS_SHA1__ \
-D__ENABLE_DIGICERT_FIPS_SHA256__ \
-D__ENABLE_DIGICERT_FIPS_SHA512__ \
-D__ENABLE_DIGICERT_FIPS_HMAC__ \
-D__ENABLE_DIGICERT_FIPS_3DES__ \
-D__ENABLE_DIGICERT_FIPS_AES__ \
-D__ENABLE_DIGICERT_FIPS_DSA__ \
-D__ENABLE_DIGICERT_FIPS_RSA__ \
-D__ENABLE_DIGICERT_FIPS_ECDH__ \
-D__ENABLE_DIGICERT_FIPS_ECDSA__ \
-D__ENABLE_DIGICERT_FIPS_INTEG_TEST__ \
-DFIPS_INTEG_TEST_BINARY_FILENAME=\"$(MSS_FINAL_LIB_NAME)\" \
-DFIPS_INTEG_TEST_HASH_FILENAME=\"$(MSS_FINAL_SIG_NAME)\" \
-D__DIGICERT_DSF_VERSION_STR__=\"$(MSS_VERSION_STR)\" \
-D__DIGICERT_DSF_BUILD_STR__=\"$(MSS_BUILD_STR)\" \
-D__DIGICERT_DSF_BUILDTIME_STR__=\"$(MSS_BUILDTIME_STR)\"

ifneq ($(export),true)
MOCANA_NON_FIPS_FLAGS= \
-D__ENABLE_ARC2_CIPHERS__

ifneq ($(disable_rc5),true)
MOCANA_NON_FIPS_FLAGS+= \
-D__ENABLE_DIGICERT_RC5__ \
-D__ENABLE_DIGICERT_WEAK_RC5__
endif

endif

ifneq ($(filter true,$(openssl_1_1_0) $(openssl_1_1_1)),)
	MOCANA_NON_FIPS_FLAGS += -D__ENABLE_DIGICERT_CHACHA20__ -D__ENABLE_DIGICERT_POLY1305__
endif

ifeq ($(debug),true)
 	DEBUG_FLAGS = $(MOCANA_DEBUG_FLAGS)
endif

ifeq ($(fips),true)
      FIPS_FLAGS = $(MOCANA_FIPS_FLAGS) $(MOCANA_NON_FIPS_FLAGS)
      LINKFLAGS += -L$(OSSL_TOP)/../../bin -lmss
      override suiteb = true
ifeq ($(strict_dh),true)
	  FIPS_FLAGS += -D__ENABLE_DIGICERT_STRICT_DH_GROUP__
endif
else
      FIPS_FLAGS = $(MOCANA_NON_FIPS_FLAGS)
endif

ifeq ($(suiteb),true)
        SUITEB_FLAGS = $(MOCANA_SUITEB_FLAGS)
else
        SUITEB_FLAGS = -D__DISABLE_DIGICERT_SUITE_B__
endif

ifeq ($(SECMOD_ACCEL_DEV),1)
override CFLAG += \
  -D__ENABLE_DIGICERT_TPM__ \
  -D__ENABLE_DIGICERT_HW_SECURITY_MODULE__
endif

ifeq (true,$(cryptointerface))
override CFLAG += \
  -D__ENABLE_DIGICERT_ASYM_KEY__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_GCM__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_ARC4__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_TDES__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_PKCS1__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD4__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD4_MAPPING__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD5__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD5_MAPPING__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA1__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA1_MAPPING__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA224__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA224_MAPPING__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA256__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA256_MAPPING__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA384__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA384_MAPPING__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA512__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA512_MAPPING__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES__ \
  -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CCM__
ifeq (true,$(tap))
	TAP_ARG=" tap=true"
override CFLAG += \
  -D__ENABLE_DIGICERT_TAP__
endif
endif

ifeq (true,$(export))
override CFLAG += $(PLATFORM_CFLAGS) $(DEBUG_FLAGS) $(SUITEB_FLAGS) $(FIPS_FLAGS) \
 -DOPENSSL_ENGINE \
 -DMOC_LITTLE_ENDIAN \
 -D__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ \
 -D__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__ \
 -D__DISABLE_DIGICERT_TCP_INTERFACE__ \
 -D__ENABLE_DIGICERT_PKCS1__ \
 -D__ENABLE_DIGICERT_PKCS5__ \
 -D__ENABLE_DIGICERT_PKCS7__ \
 -D__ENABLE_DIGICERT_PKCS12__ \
 -D__ENABLE_DIGICERT_SERIALIZE__ \
 -D__ENABLE_DIGICERT_DSA__ \
 -D__ENABLE_DIGICERT_DER_CONVERSION__ \
 -D__ENABLE_DIGICERT_PEM_CONVERSION__ \
 -D__ENABLE_UNICODE__ \
 -D__ENABLE_DIGICERT_64_BIT__ \
 -D__ENABLE_DIGICERT_RSA_ALL_KEYSIZE__ \
 -D__DISABLE_ARC4_CIPHERS__ \
 -D__DISABLE_AES_CMAC__ \
 -D__DISABLE_AES_CCM__ \
 -D__DISABLE_AES_XTS__
else
override CFLAG += $(PLATFORM_CFLAGS) $(DEBUG_FLAGS) $(SUITEB_FLAGS) $(FIPS_FLAGS) \
 -DOPENSSL_ENGINE \
 -DMOC_LITTLE_ENDIAN \
 -D__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__ \
 -D__DISABLE_DIGICERT_TCP_INTERFACE__ \
 -D__ENABLE_DIGICERT_MD2__ \
 -D__ENABLE_DIGICERT_MD4__ \
 -D__ENABLE_DIGICERT_PKCS1__ \
 -D__ENABLE_DIGICERT_PKCS5__ \
 -D__ENABLE_DIGICERT_PKCS7__ \
 -D__ENABLE_DIGICERT_PKCS12__ \
 -D__ENABLE_DES_CIPHER__ \
 -D__ENABLE_DIGICERT_SERIALIZE__ \
 -D__ENABLE_DIGICERT_DSA__ \
 -D__ENABLE_DIGICERT_DER_CONVERSION__ \
 -D__ENABLE_DIGICERT_PEM_CONVERSION__ \
 -D__ENABLE_UNICODE__ \
 -D__ENABLE_DIGICERT_64_BIT__ \
 -D__ENABLE_DIGICERT_RSA_ALL_KEYSIZE__
endif

ifeq ($(tls13),true)
override CFLAG += -D__ENABLE_DIGICERT_TLS13__
endif

ifeq ($(openssl_1_1_0),true)
  override CFLAG += -D__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__
  override CFLAG += -fPIC
endif

ifeq ($(openssl_1_1_1),true)
  override CFLAG += -D__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__
  override CFLAG += -fPIC
  override AR += $(ARFLAGS)
endif

ifeq ($(evp_engine_toggle),true)
  override CFLAG += -D__ENABLE_DIGICERT_EVP_ENGINE_TOGGLE__
endif

ifeq ($(evp_engine_default),true)
  override CFLAG += -D__ENABLE_DIGICERT_EVP_ENGINE_DEFAULT__
endif

override CFLAGS = $(INCLUDES) $(CFLAG)
#$(error "CFLAGS=$(CFLAGS)")

LIB=$(OSSL_TOP)/libcrypto.a
LIB_NANO=$(OSSL_TOP)/libnanocrypto.a

MOCANA_CRYPTO_DIR= $(MOCANA_BASE)/src/crypto
MOCANA_SECMOD_DIR= $(MOCANA_CRYPTO_DIR)/secmod
MOCANA_TPM_DIR= $(MOCANA_SECMOD_DIR)/tpm
MOCANA_SAPI_DIR= $(MOCANA_TPM_DIR)/sapi
MOCANA_FAPI_DIR= $(MOCANA_TPM_DIR)/fapi
MOCANA_TCTI_DIR= $(MOCANA_TPM_DIR)/tcti
MOCANA_TPM_ERROR_DIR= $(MOCANA_TPM_DIR)/tpm_error
MOCANA_TPM_TOOLS_DIR= $(MOCANA_TPM_DIR)/tools
MOCANA_TPM_COMMON_DIR= $(MOCANA_SECMOD_DIR)/tpm_common
MOCANA_COMMON_DIR= $(MOCANA_BASE)/src/common
MOCANA_ASN1_DIR= $(MOCANA_BASE)/src/asn1
MOCANA_CAP_DIR= $(MOCANA_BASE)/src/cap
MOCANA_PLATFORM_DIR= $(MOCANA_BASE)/src/platform
MOCANA_EXAMPLES_DIR= $(MOCANA_BASE)/src/examples
CRYPTO_CUSTOM_SRC_DIR = $(MOCANA_BASE)/src/crypto/mocsymalgs/mocsw
CRYPTO_MOC_ASYM_SRC_DIR = $(MOCANA_BASE)/src/crypto/mocasymkeys/mocsw
CRYPTO_HW_SRC_DIR = $(MOCANA_BASE)/src/crypto/hw_offload

LIBSRC= e_moc_EVP_ciphers.c mocana_glue.c e_moc_evp_err.c compat_funcs.c

LIBOBJ= $(LIBSRC:.c=.o)
LIBOBJ_RENAMED= $(join $(dir $(LIBOBJ)), $(addprefix MOCANA_,$(notdir $(LIBOBJ))))

SRC=$(LIBSRC)

LIBNAME=mocana

ASN_OBJ = \
  $(OBJ_DIR)$(SEP)ASN1TreeWalker.o \
  $(OBJ_DIR)$(SEP)derencoder.o \
  $(OBJ_DIR)$(SEP)oidutils.o \
  $(OBJ_DIR)$(SEP)oiddefs.o \
  $(OBJ_DIR)$(SEP)parseasn1.o \
  $(OBJ_DIR)$(SEP)parsecert.o \
  $(OBJ_DIR)$(SEP)createasn1.o \
  $(OBJ_DIR)$(SEP)mocencode.o \
  $(OBJ_DIR)$(SEP)mocdecode.o \
  $(OBJ_DIR)$(SEP)indefencode.o \
  $(OBJ_DIR)$(SEP)indefdecode.o \
  $(OBJ_DIR)$(SEP)tagandlen.o \
  $(OBJ_DIR)$(SEP)ofindef.o \
  $(OBJ_DIR)$(SEP)intasn1.o \
  $(OBJ_DIR)$(SEP)vlongasn1.o \
  $(OBJ_DIR)$(SEP)algid.o \
  $(OBJ_DIR)$(SEP)dsasig.o \
  $(OBJ_DIR)$(SEP)digestinfo.o \
  $(OBJ_DIR)$(SEP)digestflag.o \
  $(OBJ_DIR)$(SEP)digestsig.o \
  $(OBJ_DIR)$(SEP)copytemplate.o \
  $(OBJ_DIR)$(SEP)cmptemplate.o \

PLATFORM_RTOS_OBJ = \
  $(OBJ_DIR)$(SEP)cygwin_rtos.o \
  $(OBJ_DIR)$(SEP)mqx_rtos.o \
  $(OBJ_DIR)$(SEP)netburner_rtos.o \
  $(OBJ_DIR)$(SEP)nnos_rtos.o \
  $(OBJ_DIR)$(SEP)nucleus_rtos.o \
  $(OBJ_DIR)$(SEP)openbsd_rtos.o \
  $(OBJ_DIR)$(SEP)ose_rtos.o \
  $(OBJ_DIR)$(SEP)osx_rtos.o \
  $(OBJ_DIR)$(SEP)psos_rtos.o \
  $(OBJ_DIR)$(SEP)qnx_rtos.o \
  $(OBJ_DIR)$(SEP)solaris_rtos.o \
  $(OBJ_DIR)$(SEP)threadx_alt_rtos.o \
  $(OBJ_DIR)$(SEP)vxworks_rtos.o \
  $(OBJ_DIR)$(SEP)win32_rtos.o \
  $(OBJ_DIR)$(SEP)android_rtos.o \
  $(OBJ_DIR)$(SEP)freertos_rtos.o \

PLATFORM_TCP_OBJ = \
  $(OBJ_DIR)$(SEP)cygwin_tcp.o \
  $(OBJ_DIR)$(SEP)linux_tcp.o \
  $(OBJ_DIR)$(SEP)mocana_tcp.o \
  $(OBJ_DIR)$(SEP)nnos_tcp.o \
  $(OBJ_DIR)$(SEP)nucleus_tcp.o \
  $(OBJ_DIR)$(SEP)openbsd_tcp.o \
  $(OBJ_DIR)$(SEP)ose_tcp.o \
  $(OBJ_DIR)$(SEP)osx_tcp.o \
  $(OBJ_DIR)$(SEP)psos_tcp.o \
  $(OBJ_DIR)$(SEP)qnx_tcp.o \
  $(OBJ_DIR)$(SEP)rtcs_tcp.o \
  $(OBJ_DIR)$(SEP)solaris_tcp.o \
  $(OBJ_DIR)$(SEP)threadx_alt_tcp.o \
  $(OBJ_DIR)$(SEP)vxworks_tcp.o \
  $(OBJ_DIR)$(SEP)win32_tcp.o \
  $(OBJ_DIR)$(SEP)android_tcp.o \
  $(OBJ_DIR)$(SEP)lwip_tcp.o \
  $(OBJ_DIR)$(SEP)lwip_udp.o \

PLATFORM_TCP_ASYNC_OBJ = \
  $(OBJ_DIR)$(SEP)linux_tcp_async.o \
  $(OBJ_DIR)$(SEP)openbsd_tcp_async.o \
  $(OBJ_DIR)$(SEP)win32_tcp_async.o \
  $(OBJ_DIR)$(SEP)cygwin_tcp_async.o \
  $(OBJ_DIR)$(SEP)osx_tcp_async.o \
  $(OBJ_DIR)$(SEP)solaris_tcp_async.o \


COMMON_CRYPTO_OBJ = \
	$(OBJ_DIR)$(SEP)absstream.o \
	$(OBJ_DIR)$(SEP)custom_entropy.o \
	$(OBJ_DIR)$(SEP)debug_console.o \
	$(OBJ_DIR)$(SEP)dynarray.o \
	$(OBJ_DIR)$(SEP)mbitmap.o \
	$(OBJ_DIR)$(SEP)mem_part.o \
	$(OBJ_DIR)$(SEP)mem_pool.o \
	$(OBJ_DIR)$(SEP)memfile.o \
	$(OBJ_DIR)$(SEP)memory_debug.o \
	$(OBJ_DIR)$(SEP)merrors.o \
	$(OBJ_DIR)$(SEP)moc_net.o \
	$(OBJ_DIR)$(SEP)mocana.o \
	$(OBJ_DIR)$(SEP)external_rand_thread.o \
	$(OBJ_DIR)$(SEP)sizedbuffer.o \
	$(OBJ_DIR)$(SEP)tree.o \
	$(OBJ_DIR)$(SEP)utils.o


FIPS_COMMON_CRYPTO_OBJ = \
	$(OBJ_DIR)$(SEP)int64.o \
	$(OBJ_DIR)$(SEP)int128.o \
	$(OBJ_DIR)$(SEP)mversion.o \
	$(OBJ_DIR)$(SEP)mstdlib.o \
	$(OBJ_DIR)$(SEP)prime.o \
	$(OBJ_DIR)$(SEP)lucas.o \
	$(OBJ_DIR)$(SEP)jacobi.o \
	$(OBJ_DIR)$(SEP)random.o \
	$(OBJ_DIR)$(SEP)vlong_add.o \
	$(OBJ_DIR)$(SEP)vlong_barrett.o \
	$(OBJ_DIR)$(SEP)vlong_cmp.o \
	$(OBJ_DIR)$(SEP)vlong_common.o \
	$(OBJ_DIR)$(SEP)vlong_conv.o \
	$(OBJ_DIR)$(SEP)vlong_div.o \
	$(OBJ_DIR)$(SEP)vlong_gcd.o \
	$(OBJ_DIR)$(SEP)vlong_karatsuba.o \
	$(OBJ_DIR)$(SEP)vlong_misc.o \
	$(OBJ_DIR)$(SEP)vlong_modexp.o \
	$(OBJ_DIR)$(SEP)vlong_modinv.o \
	$(OBJ_DIR)$(SEP)vlong_monty.o \
	$(OBJ_DIR)$(SEP)vlong_mul.o \
	$(OBJ_DIR)$(SEP)vlong_shift.o \
	$(OBJ_DIR)$(SEP)vlong_sub.o \
	$(OBJ_DIR)$(SEP)hash_table.o \
	$(OBJ_DIR)$(SEP)hash_value.o \
	$(OBJ_DIR)$(SEP)mocctx.o \
	$(OBJ_DIR)$(SEP)initmocana.o \
	$(OBJ_DIR)$(SEP)oplistctx.o \

FIPS_PROD_OBJ = \
    $(OBJ_DIR)$(SEP)linux_rtos.o \
    $(OBJ_DIR)$(SEP)mrtos.o \
    $(OBJ_DIR)$(SEP)pkcs1.o \
    $(OBJ_DIR)$(SEP)rng_seed.o \

#########################################################################
##
#########################################################################
CRYPTO_CRYPTO_OBJ = \
  $(CRYPTO_AESNI_OBJ) \
  $(OBJ_DIR)$(SEP)aes_keywrap.o \
  $(OBJ_DIR)$(SEP)ansix9_63_kdf.o \
  $(OBJ_DIR)$(SEP)arc2.o \
  $(OBJ_DIR)$(SEP)arc4.o \
  $(OBJ_DIR)$(SEP)asn1cert.o \
  $(OBJ_DIR)$(SEP)base64m.o \
  $(OBJ_DIR)$(SEP)blowfish.o \
  $(OBJ_DIR)$(SEP)keyblob.o \
  $(OBJ_DIR)$(SEP)ca_mgmt.o \
  $(OBJ_DIR)$(SEP)chacha20.o \
  $(OBJ_DIR)$(SEP)cms_aux.o \
  $(OBJ_DIR)$(SEP)crypto.o \
  $(OBJ_DIR)$(SEP)nil.o \
  $(OBJ_DIR)$(SEP)pkcs.o \
  $(OBJ_DIR)$(SEP)pkcs_common.o \
  $(OBJ_DIR)$(SEP)pkcs_key.o \
  $(OBJ_DIR)$(SEP)malgo_id.o \
  $(OBJ_DIR)$(SEP)pkcs5.o \
  $(OBJ_DIR)$(SEP)pkcs7.o \
  $(OBJ_DIR)$(SEP)pkcs8.o \
  $(OBJ_DIR)$(SEP)pkcs10.o \
  $(OBJ_DIR)$(SEP)pkcs12.o \
  $(OBJ_DIR)$(SEP)poly1305.o \
  $(OBJ_DIR)$(SEP)rc2algo.o \
  $(OBJ_DIR)$(SEP)rc4algo.o \
  $(OBJ_DIR)$(SEP)rc5algo.o \
  $(OBJ_DIR)$(SEP)sec_key.o \
  $(OBJ_DIR)$(SEP)pubcrypto.o \
  $(OBJ_DIR)$(SEP)pubcrypto_data.o \
  $(OBJ_DIR)$(SEP)mocasym.o \
  $(OBJ_DIR)$(SEP)randomf.o \
  $(OBJ_DIR)$(SEP)aesalgo_intel_ni.o \
  $(OBJ_DIR)$(SEP)serialcommon.o \
  $(OBJ_DIR)$(SEP)serialrsa.o \
  $(OBJ_DIR)$(SEP)serialdsa.o \
  $(OBJ_DIR)$(SEP)rsaswserial.o \
  $(OBJ_DIR)$(SEP)rsaswdeserial.o \
  $(OBJ_DIR)$(SEP)dsaswdeserial.o \
  $(OBJ_DIR)$(SEP)dsaswserial.o \
  $(OBJ_DIR)$(SEP)eccoid.o \
  $(OBJ_DIR)$(SEP)serialecc.o \
  $(OBJ_DIR)$(SEP)eccswserial.o \
  $(OBJ_DIR)$(SEP)eccswdeserial.o \
  $(OBJ_DIR)$(SEP)vlong_rand.o

## The same source file cannot be added twice to the same list. During
## compilation each file is compiled and then the object file is added to the
## library. If the same file is listed twice, when the second file is built the
## object file with the same symbols is added to the library resulting in an
## error.
ifneq ($(filter true,$(tls13) $(openssl_1_1_1)),)
  CRYPTO_CRYPTO_OBJ += $(OBJ_DIR)$(SEP)hmac_kdf.o
endif

 # $(OBJ_DIR)$(SEP)des.o \


FIPS_CRYPTO_CRYPTO_OBJ = \
  $(CRYPTO_AESNI_OBJ) \
  $(OBJ_DIR)$(SEP)aes.o \
  $(OBJ_DIR)$(SEP)aes_ctr.o \
  $(OBJ_DIR)$(SEP)aes_ccm.o \
  $(OBJ_DIR)$(SEP)aes_cmac.o \
  $(OBJ_DIR)$(SEP)aes_eax.o \
  $(OBJ_DIR)$(SEP)aes_ecb.o \
  $(OBJ_DIR)$(SEP)aes_xts.o \
  $(OBJ_DIR)$(SEP)aesalgo.o \
  $(OBJ_DIR)$(SEP)aes_xcbc_mac_96.o \
  $(OBJ_DIR)$(SEP)crypto_rsa.o \
  $(OBJ_DIR)$(SEP)des.o \
  $(OBJ_DIR)$(SEP)dh.o \
  $(OBJ_DIR)$(SEP)dsa.o \
  $(OBJ_DIR)$(SEP)dsa2.o \
  $(OBJ_DIR)$(SEP)hmac.o \
  $(OBJ_DIR)$(SEP)md2.o \
  $(OBJ_DIR)$(SEP)md4.o \
  $(OBJ_DIR)$(SEP)md45.o \
  $(OBJ_DIR)$(SEP)md5.o \
  $(OBJ_DIR)$(SEP)nist_rng.o \
  $(OBJ_DIR)$(SEP)rsa.o \
  $(OBJ_DIR)$(SEP)sha1.o \
  $(OBJ_DIR)$(SEP)sha256.o \
  $(OBJ_DIR)$(SEP)sha512.o \
  $(OBJ_DIR)$(SEP)three_des.o \

CRYPTO_OFFLOAD_OBJ = \
 $(OBJ_DIR)$(SEP)cavium_sync_cn58xx.o \
 $(OBJ_DIR)$(SEP)bcm582x_accel_sync.o \
 $(OBJ_DIR)$(SEP)freescale_sync_8248.o \
 $(OBJ_DIR)$(SEP)freescale_sync_875.o \

CRYPTO_SECMOD_OBJ = \
    $(OBJ_DIR)$(SEP)secmod.o \
    $(OBJ_DIR)$(SEP)hsmrsainfo.o \
    $(OBJ_DIR)$(SEP)moctap.o \

CRYPTO_SUITEB_OBJ = \
 $(OBJ_DIR)$(SEP)gcm.o \
 $(OBJ_DIR)$(SEP)crypto_ecc.o \
 $(OBJ_DIR)$(SEP)ecc.o \
 $(OBJ_DIR)$(SEP)primeec.o \
 $(OBJ_DIR)$(SEP)primefld.o \

CRYPTO_TPM_OBJ = \
     $(OBJ_DIR)$(SEP)fapi_admin.o \
     $(OBJ_DIR)$(SEP)fapi_key.o \
     $(OBJ_DIR)$(SEP)fapi_pcr.o \
     $(OBJ_DIR)$(SEP)fapi_data.o \
     $(OBJ_DIR)$(SEP)fapi_nv.o \
     $(OBJ_DIR)$(SEP)fapi_mgmt.o \
     $(OBJ_DIR)$(SEP)sapi_context.o \
     $(OBJ_DIR)$(SEP)sapi_data.o \
     $(OBJ_DIR)$(SEP)sapi_key.o \
     $(OBJ_DIR)$(SEP)sapi_mgmt.o \
     $(OBJ_DIR)$(SEP)sapi_nv.o \
     $(OBJ_DIR)$(SEP)sapi_pcr.o \
     $(OBJ_DIR)$(SEP)sapi_session.o \
     $(OBJ_DIR)$(SEP)sapi_serialize.o \
     $(OBJ_DIR)$(SEP)sapi_utils.o \
     $(OBJ_DIR)$(SEP)sapi_aik.o \
     $(OBJ_DIR)$(SEP)tss2_tcti.o \
     $(OBJ_DIR)$(SEP)tcti_tis.o \
     $(OBJ_DIR)$(SEP)tpm_error.o \
     $(OBJ_DIR)$(SEP)tpm_error_utils.o \
     $(OBJ_DIR)$(SEP)tpm_tools_utils.o \
     $(OBJ_DIR)$(SEP)tpm_common_utils.o \
     $(OBJ_DIR)$(SEP)tpm_utils.o \
     $(OBJ_DIR)$(SEP)tpm12_rsa.o \
     $(OBJ_DIR)$(SEP)ekey_box.o \


ifneq ($(HW_ACCEL_DEV),)
   CRYPTO_OFFLOAD_OBJ += \
     $(OBJ_DIR)$(SEP)freescale_async_8272.o \
     $(OBJ_DIR)$(SEP)freescale_async_8313.o \
     $(OBJ_DIR)$(SEP)freescale_async_8315.o \
     $(OBJ_DIR)$(SEP)freescale_async_8323.o \
     $(OBJ_DIR)$(SEP)freescale_async_8349.o \
     $(OBJ_DIR)$(SEP)freescale_async_8360.o \
     $(OBJ_DIR)$(SEP)freescale_async_8544.o \
     $(OBJ_DIR)$(SEP)freescale_async_8548.o \
     $(OBJ_DIR)$(SEP)freescale_async_8555.o \
     $(OBJ_DIR)$(SEP)freescale_async_8572.o \
     $(OBJ_DIR)$(SEP)freescale_async_8379.o \
     $(OBJ_DIR)$(SEP)pkcs11_rsa.o \
     $(HARNESS_OBJ) \

endif

MOCANA_CRYPTO_OBJ = \
 $(ASN_OBJ) \
 $(PLATFORM_RTOS_OBJ) \
 $(COMMON_CRYPTO_OBJ) \
 $(CRYPTO_CRYPTO_OBJ) \
 $(CRYPTO_OFFLOAD_OBJ) \
 $(OBJ_DIR)$(SEP)moc_config.o \
 $(OBJ_DIR)$(SEP)redblack.o \

ifeq ($(fips),false)
  MOCANA_CRYPTO_OBJ += \
    $(FIPS_CRYPTO_CRYPTO_OBJ)
  MOCANA_CRYPTO_OBJ += \
    $(FIPS_COMMON_CRYPTO_OBJ)
  MOCANA_CRYPTO_OBJ += \
    $(FIPS_PROD_OBJ)
ifeq ($(suiteb),true)
  MOCANA_CRYPTO_OBJ += \
    $(CRYPTO_SUITEB_OBJ)
endif
endif


ifeq ($(SECMOD_ACCEL_DEV),1)
  MOCANA_CRYPTO_OBJ += \
    $(CRYPTO_SECMOD_OBJ) \
    $(CRYPTO_TPM_OBJ) \
    $(PLATFORM_TCP_OBJ)
endif

ifeq (true, $(tap))
	CRYPTO_INTERFACE= -L$(OSSL_TOP)/../../bin -lcryptointerface
endif

ifeq (true, $(cryptointerface))
	CRYPTO_INTERFACE= -L$(OSSL_TOP)/../../bin -lcryptointerface
endif

MOCCRYPTO_RENAMED_OBJ= $(join $(dir $(MOCANA_CRYPTO_OBJ)), $(addprefix MOCANA_,$(notdir $(MOCANA_CRYPTO_OBJ))))

$(OBJ_DIR)/%.o : $(MOCANA_PLATFORM_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_CRYPTO_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_CAP_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_COMMON_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_COMMON_DIR)/vlong/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_ASN1_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_SECMOD_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_TPM_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_TPM_COMMON_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_SAPI_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_FAPI_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_TCTI_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_TPM_ERROR_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_TPM_TOOLS_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(MOCANA_EXAMPLES_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(CRYPTO_CUSTOM_SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(CRYPTO_MOC_ASYM_SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

$(OBJ_DIR)/%.o : $(CRYPTO_HW_SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAG) -c -o $@ $<

top:
	(cd $(TOP); $(MAKE) DIRS=engines EDIRS=$(DIR) sub_all)

all: lib
ifeq ($(HOST_OS_NAME), VXWORKS)
	(echo "Copying Mocana EVP object files for VxWorks"; cp *.o ../../krnl/engines/mocana/)
endif

obj: $(LIBOBJ)

shared: $(LIBOBJ)
ifeq ($(export),true)
	gcc -shared -o mocana.so $(LIBOBJ)  -L ../../../../bin -lcryptomw -linitialize -lcrypto
else
	gcc -shared -o mocana.so $(LIBOBJ)  -L ../../../../bin -lnanocrypto -linitialize -lcrypto
endif

tags:
	ctags $(SRC)

errors:
	$(PERL) ../../util/mkerr.pl -conf mocana.ec -nostatic -write $(SRC)

../../../../bin/libnanocrypto.so:
ifeq (true,$(build_nanocrypto))
ifeq ($(fips),true)
	$(MAKE) -C ../../../../ -f make/Makefile.ssl ${TAP_ARG} CC=${CC} LD=${LD} AR=${AR_CMD} ${SYSROOT_ARG} fips=true ${TOOLCHAIN_ARG} nanocrypto
else
	$(MAKE) -C ../../../../ -f make/Makefile.ssl CC=${CC} LD=${LD} AR=${AR_CMD} ${SYSROOT_ARG} ${TAP_ARG} ${TOOLCHAIN_ARG} nanocrypto
endif
endif

ifeq (true,$(cryptointerface))
lib: $(LIBOBJ) ../../../../bin/libnanocrypto.so
	if [ -n "$(SHARED_LIBS)" ]; then \
		$(MAKE) -f $(OSSL_TOP)/Makefile.shared -e \
			LIBNAME=$(LIBNAME) \
			LIBEXTRAS='$(LIBOBJ)' \
			LIBDEPS='-L$(OSSL_TOP) -lcrypto $(CRYPTO_INTERFACE)' \
			link_o.$(SHLIB_TARGET); \
	else \
		for fil in $(LIBOBJ); do cp $$fil `dirname $$fil`/MOCANA_`basename $$fil`; done; \
		$(AR) $(LIB) $(LIBOBJ_RENAMED); \
	fi
	@touch lib
else
lib: $(LIBOBJ) $(MOCANA_CRYPTO_OBJ)
	if [ -n "$(SHARED_LIBS)" ]; then \
		$(MAKE) -f $(OSSL_TOP)/Makefile.shared -e \
			LIBNAME=$(LIBNAME) \
			LIBEXTRAS='$(LIBOBJ)' \
			LIBDEPS='-L$(OSSL_TOP) -lcrypto $(CRYPTO_INTERFACE)' \
			link_o.$(SHLIB_TARGET); \
	else \
		for fil in $(LIBOBJ); do cp $$fil `dirname $$fil`/MOCANA_`basename $$fil`; done; \
		for fil in $(MOCANA_CRYPTO_OBJ); do cp $$fil `dirname $$fil`/MOCANA_`basename $$fil`; done; \
		$(AR) $(LIB) $(LIBOBJ_RENAMED); \
		$(AR) $(LIB_NANO) $(MOCCRYPTO_RENAMED_OBJ); \
		$(CC) -shared $(LINKFLAGS) -o libnanocrypto$(SHLIB_EXT) $(MOCCRYPTO_RENAMED_OBJ) $(CRYPTO_INTERFACE); \
		mv libnanocrypto$(SHLIB_EXT) $(OSSL_TOP)/. ; \
		cd $(OSSL_TOP) && ln -sf libnanocrypto$(SHLIB_EXT) libnanocrypto$(MOC_SHLIB_SUFFIX); \
	fi
	@touch lib
endif


install:
	[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	if [ -n "$(SHARED_LIBS)" ]; then \
		set -e; \
		echo installing $(LIBNAME); \
		pfx=lib; \
		if expr "$(PLATFORM)" : "Cygwin" >/dev/null; then \
			sfx=".so"; \
			cp cyg$(LIBNAME).dll $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new; \
		else \
			case "$(CFLAGS)" in \
			*DSO_BEOS*) sfx=".so";; \
			*DSO_DLFCN*) sfx=`expr "$(SHLIB_EXT)" : '.*\(\.[a-z][a-z]*\)' \| ".so"`;; \
			*DSO_DL*) sfx=".sl";; \
			*DSO_WIN32*) sfx="eay32.dll"; pfx=;; \
			*) sfx=".bad";; \
			esac; \
			cp $${pfx}$(LIBNAME)$$sfx $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new; \
		fi; \
		chmod 555 $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new; \
		mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx.new $(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR)/engines/$${pfx}$(LIBNAME)$$sfx; \
	fi

links:

tests:

update: local_depend
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi

depend: local_depend
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi

local_depend:
	@[ -z "$(THIS)" ] || $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f $(LIBOBJ) $(LIBOBJ_RENAMED) $(OBJ_DIR)/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff *.so *.sl *.dll

# DO NOT DELETE THIS LINE -- make depend depends on it.
