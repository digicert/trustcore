/*
 * hw_accel_custom_sim.h
 *
 * Use this file to add your own custom #defines to moptions.h without the
 * potential for merge conflicts.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#ifndef __HW_ACCEL_CUSTOM_SIM_HEADER__
#define __HW_ACCEL_CUSTOM_SIM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__

#ifndef  __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
#define __SHA1_HARDWARE_HASH__
#define __SHA256_HARDWARE_HASH__
#define __SHA512_HARDWARE_HASH__
#define __SHA3_HARDWARE_HASH__
#define __BLAKE2_HARDWARE_ACCELERATOR__
#define __MD4_HARDWARE_HASH__
#define __MD5_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define __ECC_HARDWARE_ACCELERATOR__
#define __RSA_HARDWARE_ACCELERATOR__
#define __DSA_HARDWARE_ACCELERATOR__
#define __DIFFIE_HELLMAN_HARDWARE__
#define __AES_HARDWARE_CIPHER__
#define __ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __BLOWFISH_HARDWARE_CIPHER__
#define __CHACHA20_HARDWARE_ACCELERATOR__
#define __POLY1305_HARDWARE_ACCELERATOR__
#endif

#define __HW_ACCEL_CUSTOM__
#define __HARDWARE_ACCEL_PROTOTYPES__

#define MD5init_HandShake   MD5Init_m
#define MD5update_HandShake MD5Update_m
#define MD5final_HandShake  MD5Final_m

#define SHA1_initDigestHandShake    SHA1_initDigest
#define SHA1_updateDigestHandShake  SHA1_updateDigest
#define SHA1_finalDigestHandShake   SHA1_finalDigest

typedef void * hwAccelDescr;

#define MOC_HW(X)           X,
#define MOC_SYM(X)          X,
#define MOC_HASH(X)         X,
#define MOC_ASYM(X)         X,
#define MOC_RNG(X)          X,
#define MOC_PRIME(X)        X,
#define MOC_MOD(X)          X,
#define MOC_DH(X)           X,
#define MOC_DSA(X)          X,
#define MOC_FFC(X)          X,
#define MOC_RSA(X)          X,
#define MOC_ECC(X)          X,

#define MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE \
    ubyte4     dummy;

#define HARDWARE_ACCEL_INIT                 HW_SIM_init
#define HARDWARE_ACCEL_UNINIT               HW_SIM_uninit
#define HARDWARE_ACCEL_OPEN_CHANNEL         HW_SIM_open
#define HARDWARE_ACCEL_CLOSE_CHANNEL        HW_SIM_close

#define MOC_DECLARE_HW_CTX(_hwCtx) hwAccelDescr _hwCtx = (hwAccelDescr)0; ((void)_hwCtx);

    /*------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif /* __HW_ACCEL_CUSTOM_SIM_HEADER__ */
