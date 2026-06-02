#
# Makefile which contains targets which will make symbolic links too
# source files which are important to compile the IPsec kernel module.
#
# Copyright 2026 DigiCert Project Authors. All Rights Reserved.
#
#
# Defines the following targets:
#     links
#     clean_links
#



ifeq (true, $(NO_CRYPTO))

links_common:
	[ -L ikekey.c          ] || ln -s ../../../../../src/ike/ikekey.c             .
	[ -L ipsec.c           ] || ln -s ../../../../../src/ipsec/ipsec.c            .
	[ -L ipsec_crypto.c    ] || ln -s ../../../../../src/ipsec/ipsec_crypto.c     .
	[ -L ipsec_flow.c      ] || ln -s ../../../../../src/ipsec/ipsec_flow.c       .
	[ -L ipsec_frag.c      ] || ln -s ../../../../../src/ipsec/ipsec_frag.c       .
	[ -L ipsec_utils.c     ] || ln -s ../../../../../src/ipsec/ipsec_utils.c      .
	[ -L ipsecconf.c       ] || ln -s ../../../../../src/ipsec/ipsecconf.c        .
	[ -L ipseckey.c        ] || ln -s ../../../../../src/ipsec/ipseckey.c         .
	[ -L sadb.c            ] || ln -s ../../../../../src/ipsec/sadb.c             .
	[ -L spd.c             ] || ln -s ../../../../../src/ipsec/spd.c              .
	[ -L ipsec6.c          ] || ln -s ../../../../../src/ipsec/ipsec6.c           .
	[ -L kmem_part.c       ] || ln -s ../../../../../src/platform/kmem_part.c     .
	[ -L debug_console.c   ] || ln -s ../../../../../src/common/debug_console.c   .
	[ -L dynarray.c        ] || ln -s ../../../../../src/common/dynarray.c        .
	[ -L hash_table.c      ] || ln -s ../../../../../src/common/hash_table.c      .
	[ -L hash_value.c      ] || ln -s ../../../../../src/common/hash_value.c      .
	[ -L initmocana.c      ] || ln -s ../../../../../src/common/initmocana.c      .
	[ -L mem_part.c        ] || ln -s ../../../../../src/common/mem_part.c        .
	[ -L mem_pool.c        ] || ln -s ../../../../../src/common/mem_pool.c        .
	[ -L mocana.c          ] || ln -s ../../../../../src/common/mocana.c          .
	[ -L mocctx.c          ] || ln -s ../../../../../src/common/mocctx.c          .
	[ -L mrtos.c           ] || ln -s ../../../../../src/common/mrtos.c           .
	[ -L mstdlib.c         ] || ln -s ../../../../../src/common/mstdlib.c         .
	[ -L oplistctx.c       ] || ln -s ../../../../../src/common/oplistctx.c       .
	[ -L arc4.c            ] || ln -s ../../../../../src/crypto/arc4.c            .
	[ -L blowfish.c        ] || ln -s ../../../../../src/crypto/blowfish.c        .
	[ -L blake2.c          ] || ln -s ../../../../../src/crypto/blake2.c          .
	[ -L chacha20.c        ] || ln -s ../../../../../src/crypto/chacha20.c        .
	[ -L poly1305.c        ] || ln -s ../../../../../src/crypto/poly1305.c        .
	[ -L crypto.c          ] || ln -s ../../../../../src/crypto/crypto.c          .
	[ -L crypto_init.c     ] || ln -s ../../../../../src/crypto/crypto_init.c     .
	[ -L rc4algo.c         ] || ln -s ../../../../../src/crypto/rc4algo.c         .
	# Note: The below files are part of the GPL code
	[ -L linux_rtos_kn.c   ] || ln -s ../../../../../src/platform/linux_rtos_kn.c .
	# Not currently used?
	# [ -L pfkey_ipsec.c     ] || ln -s ../../../../../src/pfkey/pfkey_ipsec.c      .
	# [ -L pfkey_utils.c     ] || ln -s ../../../../../src/pfkey/pfkey_utils.c      .
	[ -L hash_table_external.c ] || ln -s ../../../../../src/common/hash_table_external.c .

links_crypto:
links_export:

else

links_common:
	[ -L ikekey.c          ] || ln -s ../../../../../src/ike/ikekey.c             .
	[ -L ipsec.c           ] || ln -s ../../../../../src/ipsec/ipsec.c            .
	[ -L ipsec_crypto.c    ] || ln -s ../../../../../src/ipsec/ipsec_crypto.c     .
	[ -L ipsec_flow.c      ] || ln -s ../../../../../src/ipsec/ipsec_flow.c       .
	[ -L ipsec_frag.c      ] || ln -s ../../../../../src/ipsec/ipsec_frag.c       .
	[ -L ipsec_utils.c     ] || ln -s ../../../../../src/ipsec/ipsec_utils.c      .
	[ -L ipsecconf.c       ] || ln -s ../../../../../src/ipsec/ipsecconf.c        .
	[ -L ipseckey.c        ] || ln -s ../../../../../src/ipsec/ipseckey.c         .
	[ -L sadb.c            ] || ln -s ../../../../../src/ipsec/sadb.c             .
	[ -L spd.c             ] || ln -s ../../../../../src/ipsec/spd.c              .
	[ -L ipsec6.c          ] || ln -s ../../../../../src/ipsec/ipsec6.c           .
	[ -L kmem_part.c       ] || ln -s ../../../../../src/platform/kmem_part.c     .
	[ -L oiddefs.c         ] || ln -s ../../../../../src/asn1/oiddefs.c           .
	[ -L debug_console.c   ] || ln -s ../../../../../src/common/debug_console.c   .
	[ -L dynarray.c        ] || ln -s ../../../../../src/common/dynarray.c        .
	[ -L hash_table.c      ] || ln -s ../../../../../src/common/hash_table.c      .
	[ -L hash_value.c      ] || ln -s ../../../../../src/common/hash_value.c      .
	[ -L initmocana.c      ] || ln -s ../../../../../src/common/initmocana.c      .
	[ -L int64.c           ] || ln -s ../../../../../src/common/int64.c           .
	[ -L int128.c          ] || ln -s ../../../../../src/common/int128.c          .
	[ -L mem_part.c        ] || ln -s ../../../../../src/common/mem_part.c        .
	[ -L mem_pool.c        ] || ln -s ../../../../../src/common/mem_pool.c        .
	[ -L mocana.c          ] || ln -s ../../../../../src/common/mocana.c          .
	[ -L mocctx.c          ] || ln -s ../../../../../src/common/mocctx.c          .
	[ -L mrtos.c           ] || ln -s ../../../../../src/common/mrtos.c           .
	[ -L mstdlib.c         ] || ln -s ../../../../../src/common/mstdlib.c         .
	[ -L oplistctx.c       ] || ln -s ../../../../../src/common/oplistctx.c       .
	[ -L random.c          ] || ln -s ../../../../../src/common/random.c          .
	[ -L rng_seed.c        ] || ln -s ../../../../../src/common/rng_seed.c        .
	[ -L vlong_add.c       ] || ln -s ../../../../../src/common/vlong/vlong_add.c .
	[ -L vlong_barrett.c   ] || ln -s ../../../../../src/common/vlong/vlong_barrett.c .
	[ -L vlong_cmp.c       ] || ln -s ../../../../../src/common/vlong/vlong_cmp.c .
	[ -L vlong_common.c    ] || ln -s ../../../../../src/common/vlong/vlong_common.c .
	[ -L vlong_conv.c      ] || ln -s ../../../../../src/common/vlong/vlong_conv.c .
	[ -L vlong_div.c       ] || ln -s ../../../../../src/common/vlong/vlong_div.c .
	[ -L vlong_gcd.c       ] || ln -s ../../../../../src/common/vlong/vlong_gcd.c .
	[ -L vlong_karatsuba.c ] || ln -s ../../../../../src/common/vlong/vlong_karatsuba.c .
	[ -L vlong_misc.c      ] || ln -s ../../../../../src/common/vlong/vlong_misc.c .
	[ -L vlong_modexp.c    ] || ln -s ../../../../../src/common/vlong/vlong_modexp.c .
	[ -L vlong_modinv.c    ] || ln -s ../../../../../src/common/vlong/vlong_modinv.c .
	[ -L vlong_monty.c     ] || ln -s ../../../../../src/common/vlong/vlong_monty.c .
	[ -L vlong_mul.c       ] || ln -s ../../../../../src/common/vlong/vlong_mul.c .
	[ -L vlong_shift.c     ] || ln -s ../../../../../src/common/vlong/vlong_shift.c .
	[ -L vlong_sub.c       ] || ln -s ../../../../../src/common/vlong/vlong_sub.c .
	[ -L crypto.c          ] || ln -s ../../../../../src/crypto/crypto.c          .
	[ -L crypto_init.c     ] || ln -s ../../../../../src/crypto/crypto_init.c     .
	[ -L cipherf.c         ] || ln -s ../../../../../src/cap/cipherf.c            .
	[ -L digestf.c         ] || ln -s ../../../../../src/cap/digestf.c            .
	[ -L keyf.c            ] || ln -s ../../../../../src/cap/keyf.c               .
	[ -L macf.c            ] || ln -s ../../../../../src/cap/macf.c               .
	[ -L mocasym.c         ] || ln -s ../../../../../src/cap/mocasym.c            .
	[ -L mocsym.c          ] || ln -s ../../../../../src/cap/mocsym.c             .
	[ -L randomf.c         ] || ln -s ../../../../../src/cap/randomf.c            .
	[ -L hash_table_external.c ] || ln -s ../../../../../src/common/hash_table_external.c .
	[ -L crypto_interface_aes.c ]             || ln -s ../../../../../src/crypto_interface/crypto_interface_aes.c          .
	[ -L crypto_interface_aes_ctr.c ]         || ln -s ../../../../../src/crypto_interface/crypto_interface_aes_ctr.c      .
	[ -L crypto_interface_aes_ctr_tap.c ]     || ln -s ../../../../../src/crypto_interface/crypto_interface_aes_ctr_tap.c  .
	[ -L crypto_interface_aes_ccm.c ]         || ln -s ../../../../../src/crypto_interface/crypto_interface_aes_ccm.c      .
	[ -L crypto_interface_aes_tap.c ]         || ln -s ../../../../../src/crypto_interface/crypto_interface_aes_tap.c      .
	[ -L crypto_interface_chacha20.c ]        || ln -s ../../../../../src/crypto_interface/crypto_interface_chacha20.c      .
	[ -L crypto_interface_poly1305.c ]        || ln -s ../../../../../src/crypto_interface/crypto_interface_poly1305.c      .
	[ -L crypto_interface_nist_ctr_drbg.c ]   || ln -s ../../../../../src/crypto_interface/crypto_interface_nist_ctr_drbg.c .
	[ -L crypto_interface_aes_gcm.c ]         || ln -s ../../../../../src/crypto_interface/crypto_interface_aes_gcm.c      .
	[ -L crypto_interface_aes_gcm_tap.c ]     || ln -s ../../../../../src/crypto_interface/crypto_interface_aes_gcm_tap.c  .
	[ -L crypto_interface_aes_xcbc_mac_96.c ] || ln -s ../../../../../src/crypto_interface/crypto_interface_aes_xcbc_mac_96.c .
	[ -L crypto_interface_blake2.c ]          || ln -s ../../../../../src/crypto_interface/crypto_interface_blake2.c       .
	[ -L crypto_interface_blowfish.c ]        || ln -s ../../../../../src/crypto_interface/crypto_interface_blowfish.c     .
	[ -L crypto_interface_core.c ]            || ln -s ../../../../../src/crypto_interface/crypto_interface_core.c         .
	[ -L crypto_interface_des.c ]             || ln -s ../../../../../src/crypto_interface/crypto_interface_des.c          .
	[ -L crypto_interface_des_tap.c ]         || ln -s ../../../../../src/crypto_interface/crypto_interface_des_tap.c      .
	[ -L crypto_interface_hmac.c ]            || ln -s ../../../../../src/crypto_interface/crypto_interface_hmac.c         .
	[ -L crypto_interface_hmac_tap.c ]        || ln -s ../../../../../src/crypto_interface/crypto_interface_hmac_tap.c     .
	[ -L crypto_interface_hmac_common.c ]     || ln -s ../../../../../src/crypto_interface/crypto_interface_hmac_common.c  .
	[ -L crypto_interface_md5.c ]             || ln -s ../../../../../src/crypto_interface/crypto_interface_md5.c          .
	[ -L crypto_interface_random.c ]          || ln -s ../../../../../src/crypto_interface/crypto_interface_random.c       .
	[ -L crypto_interface_sha1.c ]            || ln -s ../../../../../src/crypto_interface/crypto_interface_sha1.c         .
	[ -L crypto_interface_sha224.c ]          || ln -s ../../../../../src/crypto_interface/crypto_interface_sha224.c       .
	[ -L crypto_interface_sha256.c ]          || ln -s ../../../../../src/crypto_interface/crypto_interface_sha256.c       .
	[ -L crypto_interface_sha384.c ]          || ln -s ../../../../../src/crypto_interface/crypto_interface_sha384.c       .
	[ -L crypto_interface_sha512.c ]          || ln -s ../../../../../src/crypto_interface/crypto_interface_sha512.c       .
	[ -L crypto_interface_tdes.c ]            || ln -s ../../../../../src/crypto_interface/crypto_interface_tdes.c         .
	[ -L crypto_interface_tdes_tap.c ]        || ln -s ../../../../../src/crypto_interface/crypto_interface_tdes_tap.c     .
	# Note: The below files are part of the GPL code
	[ -L linux_rtos_kn.c   ] || ln -s ../../../../../src/platform/linux_rtos_kn.c .
	# Not currently used?
	# [ -L pfkey_ipsec.c     ] || ln -s ../../../../../src/pfkey/pfkey_ipsec.c      .
	# [ -L pfkey_utils.c     ] || ln -s ../../../../../src/pfkey/pfkey_utils.c      .
	#
	# These used to be ifdef'd  based on HW_ACCEL_DEV, but there is no need
	# since they won't be compiled anyway.
	[ -L harness.c              ] || ln -s ../../../../../src/harness/harness.c                        .
	[ -L harness_intf26_kn.c    ] || ln -s ../../../../../src/harness/harness_intf26_kn.c              .
	[ -L freescale_async_8272.c ] || ln -s ../../../../../src/crypto/hw_offload/freescale_async_8272.c .
	[ -L freescale_async_8313.c ] || ln -s ../../../../../src/crypto/hw_offload/freescale_async_8313.c .
	[ -L freescale_async_8323.c ] || ln -s ../../../../../src/crypto/hw_offload/freescale_async_8323.c .
	[ -L freescale_async_8349.c ] || ln -s ../../../../../src/crypto/hw_offload/freescale_async_8349.c .
	[ -L freescale_async_8360.c ] || ln -s ../../../../../src/crypto/hw_offload/freescale_async_8360.c .
	[ -L freescale_async_8379.c ] || ln -s ../../../../../src/crypto/hw_offload/freescale_async_8379.c .
	[ -L freescale_async_8544.c ] || ln -s ../../../../../src/crypto/hw_offload/freescale_async_8544.c .
	[ -L freescale_async_8548.c ] || ln -s ../../../../../src/crypto/hw_offload/freescale_async_8548.c .
	[ -L freescale_async_8555.c ] || ln -s ../../../../../src/crypto/hw_offload/freescale_async_8555.c .
	[ -L freescale_async_8572.c ] || ln -s ../../../../../src/crypto/hw_offload/freescale_async_8572.c .
	[ -L bcm5862_async.c        ] || ln -s ../../../../../src/crypto/hw_offload/bcm5862_async.c        .

links_crypto:
	[ -L aes.c             ] || ln -s ../../../../../src/crypto/aes.c             .
	[ -L aes_xcbc_mac_96.c ] || ln -s ../../../../../src/crypto/aes_xcbc_mac_96.c .
	[ -L aesalgo.c         ] || ln -s ../../../../../src/crypto/aesalgo.c         .
	[ -L aes_cmac.c        ] || ln -s ../../../../../src/crypto/aes_cmac.c        .
	[ -L aes_ecb.c         ] || ln -s ../../../../../src/crypto/aes_ecb.c         .
	[ -L aes_ctr.c         ] || ln -s ../../../../../src/crypto/aes_ctr.c         .
	[ -L aes_ccm.c         ] || ln -s ../../../../../src/crypto/aes_ccm.c         .
	[ -L arc4.c            ] || ln -s ../../../../../src/crypto/arc4.c            .
	[ -L base64m.c         ] || ln -s ../../../../../src/common/base64m.c         .
	[ -L blowfish.c        ] || ln -s ../../../../../src/crypto/blowfish.c        .
	[ -L blake2.c          ] || ln -s ../../../../../src/crypto/blake2.c          .
	[ -L chacha20.c        ] || ln -s ../../../../../src/crypto/chacha20.c        .
	[ -L crypto.c          ] || ln -s ../../../../../src/crypto/crypto.c          .
	[ -L des.c             ] || ln -s ../../../../../src/crypto/des.c             .
	[ -L gcm.c             ] || ln -s ../../../../../src/crypto/gcm.c             .
	[ -L hmac.c            ] || ln -s ../../../../../src/crypto/hmac.c            .
	[ -L md45.c            ] || ln -s ../../../../../src/crypto/md45.c            .
	[ -L md5.c             ] || ln -s ../../../../../src/crypto/md5.c             .
	[ -L nist_rng.c        ] || ln -s ../../../../../src/crypto/nist_rng.c        .
	[ -L nist_rng_ex.c     ] || ln -s ../../../../../src/crypto/nist_rng_ex.c     .
	[ -L poly1305.c        ] || ln -s ../../../../../src/crypto/poly1305.c        .
	[ -L rc4algo.c         ] || ln -s ../../../../../src/crypto/rc4algo.c         .
	[ -L sha1.c            ] || ln -s ../../../../../src/crypto/sha1.c            .
	[ -L sha256.c          ] || ln -s ../../../../../src/crypto/sha256.c          .
	[ -L sha512.c          ] || ln -s ../../../../../src/crypto/sha512.c          .
	[ -L three_des.c       ] || ln -s ../../../../../src/crypto/three_des.c       .

links_export:
	[ -L aesctrmbedop.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/aesctrmbedop.c       .
	[ -L aesgcmmbedop.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/aesgcmmbedop.c       .
	[ -L blowfishmbedop.c ]      || ln -s ../../../../../src/crypto/mocsymalgs/mbed/blowfishmbedop.c     .
	[ -L ctrdrbgaesmbedop.c ]    || ln -s ../../../../../src/crypto/mocsymalgs/mbed/ctrdrbgaesmbedop.c   .
	[ -L desecbmbedop.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/desecbmbedop.c       .
	[ -L descbcmbedop.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/descbcmbedop.c       .
	[ -L hmacmbedop.c ]          || ln -s ../../../../../src/crypto/mocsymalgs/mbed/hmacmbedop.c         .
	[ -L mbedaes.c ]             || ln -s ../../../../../src/crypto/mocsymalgs/mbed/mbedaes.c            .
	[ -L mbedaesgcm.c ]          || ln -s ../../../../../src/crypto/mocsymalgs/mbed/mbedaesgcm.c         .
	[ -L mbedblowfish.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/mbedblowfish.c       .
	[ -L mbedctrdrbgaes.c ]      || ln -s ../../../../../src/crypto/mocsymalgs/mbed/mbedctrdrbgaes.c     .
	[ -L mbeddescommon.c ]       || ln -s ../../../../../src/crypto/mocsymalgs/mbed/mbeddescommon.c      .
	[ -L mbedsha1.c ]            || ln -s ../../../../../src/crypto/mocsymalgs/mbed/mbedsha1.c           .
	[ -L mbeddigestcommon.c ]    || ln -s ../../../../../src/crypto/mocsymalgs/mbed/mbeddigestcommon.c   .
	[ -L mbedhmac.c ]            || ln -s ../../../../../src/crypto/mocsymalgs/mbed/mbedhmac.c           .
	[ -L mbedhmaccommon.c ]      || ln -s ../../../../../src/crypto/mocsymalgs/mbed/mbedhmaccommon.c     .
	[ -L mbedchacha20.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/mbedchacha20.c       .
	[ -L mbedpoly1305.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/mbedpoly1305.c       .
	[ -L mbedchachapoly.c ]      || ln -s ../../../../../src/crypto/mocsymalgs/mbed/mbedchachapoly.c     .
	[ -L mbedrandom.c ]          || ln -s ../../../../../src/crypto/mocsymalgs/mbed/mbedrandom.c         .
	[ -L md5mbedop.c ]           || ln -s ../../../../../src/crypto/mocsymalgs/mbed/md5mbedop.c          .
	[ -L sha1mbedop.c ]          || ln -s ../../../../../src/crypto/mocsymalgs/mbed/sha1mbedop.c         .
	[ -L sha224mbedop.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/sha224mbedop.c       .
	[ -L sha256mbedop.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/sha256mbedop.c       .
	[ -L sha384mbedop.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/sha384mbedop.c       .
	[ -L sha512mbedop.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/sha512mbedop.c       .
	[ -L tdesecbmbedop.c ]       || ln -s ../../../../../src/crypto/mocsymalgs/mbed/tdesecbmbedop.c      .
	[ -L tdescbcmbedop.c ]       || ln -s ../../../../../src/crypto/mocsymalgs/mbed/tdescbcmbedop.c      .
	# unabled operators are still needed to prevent undefined symbols
	[ -L aescbcmbedop.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/aescbcmbedop.c       .
	[ -L aescfb128mbedop.c ]     || ln -s ../../../../../src/crypto/mocsymalgs/mbed/aescfb128mbedop.c    .
	[ -L aescmacmbedop.c ]       || ln -s ../../../../../src/crypto/mocsymalgs/mbed/aescmacmbedop.c      .
	[ -L aesecbmbedop.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/aesecbmbedop.c       .
	[ -L aesofbmbedop.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/aesofbmbedop.c       .
	[ -L aesxtsmbedop.c ]        || ln -s ../../../../../src/crypto/mocsymalgs/mbed/aesxtsmbedop.c       .
	[ -L arc4mbedop.c ]          || ln -s ../../../../../src/crypto/mocsymalgs/mbed/arc4mbedop.c         .
	[ -L chachapolymbedop.c ]    || ln -s ../../../../../src/crypto/mocsymalgs/mbed/chachapolymbedop.c   .
	[ -L hmackdfmbedop.c ]       || ln -s ../../../../../src/crypto/mocsymalgs/mbed/hmackdfmbedop.c      .
	[ -L chacha20mbedop.c ]      || ln -s ../../../../../src/crypto/mocsymalgs/mbed/chacha20mbedop.c     .
	[ -L poly1305mbedop.c ]      || ln -s ../../../../../src/crypto/mocsymalgs/mbed/poly1305mbedop.c     .
	[ -L md4mbedop.c ]           || ln -s ../../../../../src/crypto/mocsymalgs/mbed/md4mbedop.c          .
	[ -L dummy_pkcs5pbembedop.c ] || ln -s ../../../../../src/ipsec/kernel_build/dummy_operators/pkcs5pbembedop.c      dummy_pkcs5pbembedop.c
	[ -L mbed_aes.c ]            || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/aes.c           mbed_aes.c
	[ -L mbed_blowfish.c ]       || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/blowfish.c      mbed_blowfish.c
	[ -L mbed_cipher.c ]         || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/cipher.c        mbed_cipher.c
	[ -L mbed_cipher_wrap.c ]    || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/cipher_wrap.c   mbed_cipher_wrap.c
	[ -L mbed_ctr_drbg.c ]       || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/ctr_drbg.c      mbed_ctr_drbg.c
	[ -L mbed_des.c ]            || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/des.c           mbed_des.c
	[ -L mbed_gcm.c ]            || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/gcm.c           mbed_gcm.c
	[ -L mbed_md.c ]             || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/md.c            mbed_md.c
	[ -L mbed_md5.c ]            || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/md5.c           mbed_md5.c
	[ -L mbed_md_wrap.c ]        || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/md_wrap.c       mbed_md_wrap.c
	[ -L mbed_platform.c ]       || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/platform.c      mbed_platform.c
	[ -L mbed_platform_util.c ]  || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/platform_util.c mbed_platform_util.c
	[ -L mbed_poly1305.c ]       || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/poly1305.c      mbed_poly1305.c
	[ -L mbed_chacha20.c ]       || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/chacha20.c      mbed_chacha20.c
	[ -L mbed_chachapoly.c     ] || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/chachapoly.c    mbed_chachapoly.c
	[ -L mbed_sha1.c ]           || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/sha1.c          mbed_sha1.c
	[ -L mbed_sha256.c ]         || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/sha256.c        mbed_sha256.c
	[ -L mbed_sha512.c ]         || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/sha512.c        mbed_sha512.c
	[ -L mbed_lk.c ]             || ln -s ../../../../../src/ipsec/kernel_build/mbedtls-2.13.0/library/lk.c            mbed_lk.c

endif

ifeq (y, $(CUSTOM_ENTROPY))
links_custom_entropy:
	[ -L custom_entropy.c  ] || ln -s ../../../../../src/examples/custom_entropy.c .
else
links_custom_entropy:
endif

ifeq (${EXPORT},1)
links: links_common links_export links_custom_entropy
else
links: links_common links_crypto links_custom_entropy
endif

clean_links:
	-for file in *.c; do [ -L $$file ] && rm $$file; done; true
