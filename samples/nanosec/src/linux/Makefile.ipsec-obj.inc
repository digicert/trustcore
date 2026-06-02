#
# Makefile which defines the objects important to IPsec
#
# Copyright 2026 DigiCert Project Authors. All Rights Reserved.
#
# Defines variables which denote various sets of IPsec-related objects
# which must be built.
#

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

export CC=$(CROSS_COMPILE)gcc


# build IPsec without crypto module
ifeq (true, $(NO_CRYPTO))

IPSEC_ASN1_OBJS := \

IPSEC_COMMON_OBJS := \
	debug_console.o \
	dynarray.o \
	hash_table.o \
	hash_table_external.o \
	hash_value.o \
	initmocana.o \
	mem_part.o \
	mem_pool.o \
	crypto_init.o \
	mocana.o \
	mocctx.o \
	mrtos.o \
	mstdlib.o \
	oplistctx.o

ifeq ($(BUILD_IPSEC_MOD),y)
IPSEC_COMMON_OBJS += moc_ipsec_main.o
endif

IPSEC_CRYPTO_OBJS := \
	arc4.o \
	blowfish.o \
	blake2.o \
	chacha20.o \
	poly1305.o \
	crypto.o \
	rc4algo.o \
	$(xtra_mssobjs) \

IPSEC_IKE_OBJS := \
	ikekey.o \

IPSEC_IPSEC_OBJS := \
	ipsec.o \
	ipsec_crypto.o \
	ipsec_flow.o \
	ipsec_frag.o \
	ipsec_utils.o \
	ipsecconf.o \
	ipseckey.o \
	sadb.o \
	spd.o \
	ipsec6.o \

IPSEC_PLATFORM_OBJS := \
	kmem_part.o \

IPSEC_SUITEB_OBJS := \

else

IPSEC_ASN1_OBJS := \
	oiddefs.o \

IPSEC_COMMON_OBJS := \
        debug_console.o \
        dynarray.o \
        hash_table.o \
        hash_table_external.o \
        hash_value.o \
        initmocana.o \
        int64.o \
        int128.o \
        mem_part.o \
        mem_pool.o \
        mocana.o \
        mocctx.o \
        mrtos.o \
        mstdlib.o \
        oplistctx.o \
        random.o \
        rng_seed.o \
        vlong_add.o \
        vlong_barrett.o \
        vlong_cmp.o \
        vlong_common.o \
        vlong_conv.o \
        vlong_div.o \
        vlong_gcd.o \
        vlong_karatsuba.o \
        vlong_misc.o \
        vlong_modexp.o \
        vlong_modinv.o \
        vlong_monty.o \
        vlong_mul.o \
        vlong_shift.o \
        vlong_sub.o \
        crypto.o \
        crypto_init.o \
        cipherf.o \
        digestf.o \
        keyf.o \
        macf.o \
        mocasym.o \
        mocsym.o \
        randomf.o \
        crypto_interface_aes.o \
        crypto_interface_aes_tap.o \
        crypto_interface_sha384.o \
        crypto_interface_sha512.o \
        crypto_interface_aes_ctr.o \
        crypto_interface_aes_ctr_tap.o \
        crypto_interface_aes_ccm.o \
        crypto_interface_chacha20.o \
        crypto_interface_poly1305.o \
        crypto_interface_random.o \
        crypto_interface_nist_ctr_drbg.o \
        crypto_interface_aes_gcm.o \
        crypto_interface_aes_gcm_tap.o \
        crypto_interface_aes_xcbc_mac_96.o \
        crypto_interface_hmac.o \
        crypto_interface_hmac_tap.o \
        crypto_interface_hmac_common.o \
        crypto_interface_sha1.o \
        crypto_interface_md5.o \
        crypto_interface_sha224.o \
        crypto_interface_core.o \
        crypto_interface_sha256.o \
        crypto_interface_blake2.o \
        crypto_interface_blowfish.o \
        crypto_interface_des.o \
        crypto_interface_des_tap.o \
        crypto_interface_tdes.o \
        crypto_interface_tdes_tap.o

IPSEC_COMMON_EXPORT_OBJS := \
        mbeddigestcommon.o \
        mbedsha1.o \
        sha512mbedop.o \
        mbedhmac.o \
        md5mbedop.o \
        mbedaes.o \
        mbedhmaccommon.o \
        aesctrmbedop.o \
        ctrdrbgaesmbedop.o \
        sha1mbedop.o \
        sha224mbedop.o \
        aesgcmmbedop.o \
        hmacmbedop.o \
        mbedrandom.o \
        sha256mbedop.o \
        mbedctrdrbgaes.o \
        sha384mbedop.o \
        mbeddescommon.o \
        desecbmbedop.o \
        descbcmbedop.o \
        tdesecbmbedop.o \
        tdescbcmbedop.o \
        mbedblowfish.o \
        blowfishmbedop.o \
        mbedchacha20.o \
        mbedpoly1305.o \
        mbedchachapoly.o \
        aescbcmbedop.o \
        aescfb128mbedop.o \
        aescmacmbedop.o \
        aesecbmbedop.o \
        aesofbmbedop.o \
        aesxtsmbedop.o \
        arc4mbedop.o \
        chachapolymbedop.o \
        hmackdfmbedop.o \
        chacha20mbedop.o \
        poly1305mbedop.o \
        md4mbedop.o \
        dummy_pkcs5pbembedop.o \
        mbed_aes.o \
        mbed_blowfish.o \
        mbed_cipher.o \
        mbed_cipher_wrap.o \
        mbed_ctr_drbg.o \
        mbed_des.o \
        mbed_lk.o \
        mbed_md.o \
        mbed_md5.o \
        mbed_md_wrap.o \
        mbed_platform.o \
        mbed_platform_util.o \
        mbed_poly1305.o \
        mbed_chacha20.o \
        mbed_chachapoly.o \
        mbed_sha1.o \
        mbed_sha256.o \
        mbed_sha512.o

IPSEC_COMMON_EXPORT_SUITEB_OBJS := \
        mbedaesgcm.o \
        mbed_gcm.o \

IPSEC_CRYPTO_OBJS := \
	aes.o \
	aes_ecb.o \
	aes_xcbc_mac_96.o \
	aesalgo.o \
	aes_ctr.o \
	aes_ccm.o \
	arc4.o \
	base64m.o \
	blowfish.o \
	blake2.o \
	chacha20.o \
	crypto.o \
	des.o \
	hmac.o \
	md45.o \
	md5.o \
	nist_rng.o \
	nist_rng_ex.o \
	poly1305.o \
	rc4algo.o \
	sha1.o \
	sha256.o \
	sha512.o \
	three_des.o \
	$(xtra_mssobjs) \

IPSEC_IKE_OBJS := \
	ikekey.o \

IPSEC_IPSEC_OBJS := \
	ipsec.o \
	ipsec_crypto.o \
	ipsec_flow.o \
	ipsec_frag.o \
	ipsec_utils.o \
	ipsecconf.o \
	ipseckey.o \
	sadb.o \
	spd.o \
	ipsec6.o \

IPSEC_PLATFORM_OBJS := \
	kmem_part.o \

IPSEC_SUITEB_OBJS := \
	gcm.o \
	aes_cmac.o \

endif  #ifeq (true, $(NO_CRYPTO))


IPSEC_OBJS := \

IPSEC_OBJS += $(IPSEC_ASN1_OBJS)

IPSEC_OBJS += $(IPSEC_COMMON_OBJS)

ifeq (y, $(CUSTOM_ENTROPY))
IPSEC_CUSTOM_ENTROPY_OBJ := \
	custom_entropy.o
IPSEC_OBJS += $(IPSEC_CUSTOM_ENTROPY_OBJ)
endif

ifeq (${EXPORT},1)

  IPSEC_OBJS += $(IPSEC_COMMON_EXPORT_OBJS)
ifeq (${SUITEB},1)
  IPSEC_OBJS += $(IPSEC_COMMON_EXPORT_SUITEB_OBJS)
endif

else

  IPSEC_OBJS += $(IPSEC_CRYPTO_OBJS)
ifeq (${SUITEB},1)
  IPSEC_OBJS += $(IPSEC_SUITEB_OBJS)
endif

endif   # if EXPORT

IPSEC_OBJS += $(IPSEC_IKE_OBJS)

IPSEC_OBJS += $(IPSEC_IPSEC_OBJS)

IPSEC_OBJS += $(IPSEC_PLATFORM_OBJS)
