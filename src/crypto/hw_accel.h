/*
 * hw_accel.h
 *
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */


/*------------------------------------------------------------------*/

#ifndef __HW_ACCEL_HEADER__
#define __HW_ACCEL_HEADER__

enum hwCryptoAllocTypes
{
    hwCryptoAsymmetric,
    hwCryptoIV,
    hwCryptoMac,
    hwCrypto
};

#include "../crypto/hw_accel_custom.h"

#ifndef __HW_ACCEL_CUSTOM__

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_HARNESS_MEMORY_DEBUG__
#define TEST_MEMORY(HWACCELCTX,PTR)     HARNESS_testAddress(HWACCELCTX,PTR)
#else
#define TEST_MEMORY(HWACCELCTX,PTR)
#endif

#define HW_OFFLOAD_PAD_VERIFIED         (1)
#define HW_OFFLOAD_MAC_VERIFIED         (2)


/*------------------------------------------------------------------*/
#if (!defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && !defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)&& !defined(__ENABLE_DIGICERT_PKCS11_CRYPTO__))
typedef signed int          hwAccelDescr;

#define MOC_HW(X)
#define MOC_SYM(X)
#define MOC_HASH(X)
#define MOC_ASYM(X)
#define MOC_RNG(X)
#define MOC_PRIME(X)
#define MOC_MOD(X)
#define MOC_DH(X)
#define MOC_DSA(X)
#define MOC_FFC(X)
#define MOC_RSA(X)
#define MOC_ECC(X)


#elif (defined(__ENABLE_SYNERGY_3_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))

#define __HARDWARE_ACCEL_PROTOTYPES__

/* Enable your algs here */
/* #define __SHA256_HARDWARE_HASH__ */
/* #define __SHA1_HARDWARE_HASH__ */
/* #define __SHA1_ONE_STEP_HARDWARE_HASH__ */
/* #define __AES_HARDWARE_CIPHER__ */
/* #define __RSAINT_HARDWARE__ */

#if !defined(__SHA256_HARDWARE_HASH__) && !defined(__SHA1_HARDWARE_HASH__) && \
    !defined(__SHA1_ONE_STEP_HARDWARE_HASH__) && !defined(__AES_HARDWARE_CIPHER__) && \
    !defined(__RSAINT_HARDWARE__)

#error Synergy Hardware Acceleration is Enabled but No Algorithms are Active!

#endif

typedef ubyte4* hwAccelDescr;

#define MOC_HW(X)
#define MOC_SYM(X)
#define MOC_HASH(X)
#define MOC_ASYM(X)
#define MOC_RNG(X)
#define MOC_PRIME(X)
#define MOC_MOD(X)
#define MOC_DH(X)
#define MOC_DSA(X)
#define MOC_FFC(X)
#define MOC_RSA(X)
#define MOC_ECC(X)

/* Indicates to the crypto code that we'll be implementing the SHA1 functions */

#define SHA1_initDigestHandShake                SHA1_initDigest

#define HARDWARE_ACCEL_INIT                     SYNERGY_init
#define HARDWARE_ACCEL_UNINIT                   SYNERGY_uninit
#define HARDWARE_ACCEL_OPEN_CHANNEL             SYNERGY_openChannel
#define HARDWARE_ACCEL_CLOSE_CHANNEL            SYNERGY_closeChannel
#define SHA1_initDigestHandShake    SHA1_initDigest
#define SHA1_updateDigestHandShake  SHA1_updateDigest
#define SHA1_finalDigestHandShake   SHA1_finalDigest


#elif (defined(__ENABLE_TEST_HARDWARE_ACCEL_LAYER__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

typedef void* hwAccelDescr;

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
    ubyte4  dummy;

#elif (defined(__ENABLE_TEST_HARDWARE_ACCEL_LAYER__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))

typedef void* hwAccelDescr;

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

#elif (defined(__ENABLE_OCF_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))

typedef struct ocfAccelDescr
{
    int     devCryptoFd;        /* core file descriptor */
    int     workerFd;           /* worker file descriptor */

} ocfAccelDescr;

typedef ocfAccelDescr*      hwAccelDescr;

#define __HARDWARE_ACCEL_PROTOTYPES__

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

#define __AES_HARDWARE_CIPHER__
#define __ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define X__HMAC_MD5_HARDWARE_HASH__
#define X__HMAC_SHA1_HARDWARE_HASH__
#define __DISABLE_DIGICERT_RNG__
#define X__PRIME_GEN_HARDWARE__

#define X__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define X__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__

#define HARDWARE_ACCEL_INIT                     OCF_SYNC_init
#define HARDWARE_ACCEL_UNINIT                   OCF_SYNC_uninit
#define HARDWARE_ACCEL_OPEN_CHANNEL             OCF_SYNC_openChannel
#define HARDWARE_ACCEL_CLOSE_CHANNEL            OCF_SYNC_closeChannel

#elif (defined(__ENABLE_IXP420_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))

#define __HARDWARE_ACCEL_PROTOTYPES__
typedef sbyte4  hwAccelDescr;

#define HARDWARE_ACCEL_INIT                     IXP420_init
#define HARDWARE_ACCEL_UNINIT                   IXP420_uninit
#define HARDWARE_ACCEL_OPEN_CHANNEL             IXP420_openChannel
#define HARDWARE_ACCEL_CLOSE_CHANNEL            IXP420_closeChannel

#elif (defined(__ENABLE_BCM5823_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))

#define __HARDWARE_ACCEL_PROTOTYPES__
#define __ENABLE_BCM582x_HARDWARE_ACCEL__

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

#define __AES_HARDWARE_CIPHER__
#define __ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define __DISABLE_DIGICERT_RNG__
#define __PRIME_GEN_HARDWARE__

#define __VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__

#define HARDWARE_ACCEL_INIT                     BCM582x_init
#define HARDWARE_ACCEL_UNINIT                   BCM582x_uninit
#define HARDWARE_ACCEL_OPEN_CHANNEL             BCM582x_openChannel
#define HARDWARE_ACCEL_CLOSE_CHANNEL            BCM582x_closeChannel

#elif (defined(__ENABLE_BROADCOM_5862_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

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
    ubyte      mcrNumber;   \
    ubyte      hreserved[3];   \
    ubyte     *mcrContext;

#define __3DES_HARDWARE_CIPHER__
#define __AES_HARDWARE_CIPHER__
#define __ARC4_HARDWARE_CIPHER__
#define __RSAINT_HARDWARE__
#define __DES_HARDWARE_CIPHER__
#define __DISABLE_DIGICERT_ADD_ENTROPY__
#define __DISABLE_DIGICERT_RNG__
#define xx__HMAC_MD5_HARDWARE_HASH__
#define xx__HMAC_SHA1_HARDWARE_HASH__
#define __MD5_HARDWARE_HASH__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define x__PRIME_GEN_HARDWARE__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__

#define x__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__    /* DISABLED FOR NOW */
#define x__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__

#define MD_CTX_HASHDATA_SIZE       64

struct Command_t;
typedef struct {
    hwAccelDescr     hwAccelCtx;        /* Point to hw channel */
    ubyte4           algorithm;
    ubyte4           digestSize;
    ubyte            lastDigest[20];
    ubyte4           index;             /* index into cachedHashData */
    ubyte            cacheData[MD_CTX_HASHDATA_SIZE];
    ubyte4           totalSent;         /* Total byte sent before FIN */
    /*struct Command_t *command; */
    ubyte4           clientData;        /* For user to support async op */
} HwHashContext_t;

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake   MD5Init_m
#define MD5update_HandShake MD5Update_m
#define MD5final_HandShake  MD5Final_m

typedef struct
{
    HwHashContext_t  cctx;              /* Common hash context */
} MD5_CTX, MD5_CTXHS;
#endif                                  /* __MD5_HARDWARE_HASH__ */

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake    SHA1_initDigest
#define SHA1_updateDigestHandShake  SHA1_updateDigest
#define SHA1_finalDigestHandShake   SHA1_finalDigest

typedef struct
{
    HwHashContext_t  cctx;              /* Common hash context */
} shaDescr, shaDescrHS, SHA1_CTX;

#define HARNESS_WRAPPER_devioctl(a,b)   BCM5862_ioctl(a,b)

#endif                                  /* __SHA1_HARDWARE_HASH__ */

#elif (defined(__ENABLE_CAVIUM_CN58XX_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))

#define HW_MALLOC(PART,PTR,SIZE,TYPE)           DIGI_MALLOC(PTR,SIZE)
#define HW_FREE(PART,PTR,TYPE)                  DIGI_FREE(PTR)

typedef sbyte4  hwAccelDescr;

#define MOC_HW(X)
#define MOC_SYM(X)
#define MOC_HASH(X)
#define MOC_ASYM(X)
#define MOC_RNG(X)
#define MOC_PRIME(X)
#define MOC_MOD(X)
#define MOC_DH(X)
#define MOC_DSA(X)
#define MOC_FFC(X)
#define MOC_RSA(X)
#define MOC_ECC(X)

/* options enabled */
#define __AES_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define X__DISABLE_DIGICERT_RNG__
#define X__DISABLE_DIGICERT_ADD_ENTROPY__
#define __MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__

#ifndef __ASM_CAVIUM__
#define __ASM_CAVIUM__
#endif

#ifndef __ENABLE_DIGICERT_64_BIT__
#define __ENABLE_DIGICERT_64_BIT__
#endif

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake                       MD5Init_m
#define MD5update_HandShake                     MD5Update_m
#define MD5final_HandShake                      MD5Final_m

typedef struct
{
    unsigned long long  hashBlocks[2];
    unsigned long long  mesgLength;

    sbyte4              hashBufferIndex;
    unsigned long long  hashBuffer[8];

} MD5_CTX, MD5_CTXHS;
#endif

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake                SHA1_initDigest
#define SHA1_updateDigestHandShake              SHA1_updateDigest
#define SHA1_finalDigestHandShake               SHA1_finalDigest

typedef struct
{
    unsigned long long  hashBlocks[3];

    unsigned long long  mesgLength;

    sbyte4              hashBufferIndex;
    unsigned long long  hashBuffer[8];

} shaDescr, shaDescrHS, SHA1_CTX;
#endif

#elif (defined(__ENABLE_FREESCALE_8272_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

#define HW_MALLOC(PART,PTR,SIZE,TYPE)           DIGI_MALLOC(PTR,SIZE)
#define HW_FREE(PART,PTR,TYPE)                  DIGI_FREE(PTR)

#define MOC_HW(X)                               X,
#define MOC_SYM(X)                              X,
#define MOC_HASH(X)                             X,
#define MOC_ASYM(X)                             X,
#define MOC_RNG(X)                              X,
#define MOC_PRIME(X)                            X,
#define MOC_MOD(X)                              X,
#define MOC_DH(X)                               X,
#define MOC_DSA(X)                              X,
#define MOC_FFC(X)                              X,
#define MOC_RSA(X)                              X,
#define MOC_ECC(X)                              X,

#define MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE \
    ubyte4     header;      \
    ubyte4     length1;     \
    ubyte*     pointer1;    \
    ubyte4     length2;     \
    ubyte*     pointer2;    \
    ubyte4     length3;     \
    ubyte*     pointer3;    \
    ubyte4     length4;     \
    ubyte*     pointer4;    \
    ubyte4     length5;     \
    ubyte*     pointer5;    \
    ubyte4     length6;     \
    ubyte*     pointer6;    \
    ubyte4     length7;     \
    ubyte*     pointer7;    \
    ubyte*     pNextDpd;

#define __AES_HARDWARE_CIPHER__
#define x__ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define __DISABLE_DIGICERT_RNG__
#define __DISABLE_DIGICERT_ADD_ENTROPY__
#define __MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__
#define __RSAINT_HARDWARE__

#define x__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__    /* DISABLED FOR NOW */
#define x__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ /* DISABLED FOR NOW */
#define x__VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__

#define MD_CTX_HASHDATA_SIZE                    (0x00001000)
#define MD_CTX_HASHDATA_SIZE_MASK               (0x00000fff)
#define MD_CTX_FSL_CTX_SIZE                     40

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake                       MD5Init_m
#define MD5update_HandShake                     MD5Update_m
#define MD5final_HandShake                      MD5Final_m

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} MD5_CTX, MD5_CTXHS;
#endif

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake                SHA1_initDigest
#define SHA1_updateDigestHandShake              SHA1_updateDigest
#define SHA1_finalDigestHandShake               SHA1_finalDigest

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} shaDescr, shaDescrHS, SHA1_CTX;
#endif

#if 0   /* disabled temporarily */
/* mod exp depends on these so use __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */
#define __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__    __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_R2MODN_OPERATOR_HARDWARE_ACCELERATOR__      __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#endif

#elif (defined(__ENABLE_FREESCALE_8313_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

#define HW_MALLOC(PART,PTR,SIZE,TYPE)           DIGI_MALLOC(PTR,SIZE)
#define HW_FREE(PART,PTR,TYPE)                  DIGI_FREE(PTR)

#define MOC_HW(X)                               X,
#define MOC_SYM(X)                              X,
#define MOC_HASH(X)                             X,
#define MOC_ASYM(X)                             X,
#define MOC_RNG(X)                              X,
#define MOC_PRIME(X)                            X,
#define MOC_MOD(X)                              X,
#define MOC_DH(X)                               X,
#define MOC_DSA(X)                              X,
#define MOC_FFC(X)                              X,
#define MOC_RSA(X)                              X,
#define MOC_ECC(X)                              X,

#define MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE \
    ubyte4     header;      \
    ubyte4     reserved;    \
    ubyte4     length1;     \
    ubyte*     pointer1;    \
    ubyte4     length2;     \
    ubyte*     pointer2;    \
    ubyte4     length3;     \
    ubyte*     pointer3;    \
    ubyte4     length4;     \
    ubyte*     pointer4;    \
    ubyte4     length5;     \
    ubyte*     pointer5;    \
    ubyte4     length6;     \
    ubyte*     pointer6;    \
    ubyte4     length7;     \
    ubyte*     pointer7;    \
    ubyte*     pNextDpd;

#define __AES_HARDWARE_CIPHER__
#define x__ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define x__DISABLE_DIGICERT_RNG__
#define x__DISABLE_DIGICERT_ADD_ENTROPY__
#define __MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__
#define x__RSAINT_HARDWARE__

/* single pass configuration details */
#define __IPSEC_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_DECRYPT_ADJUST_SSL_RECORD_SIZE_SUPPORT__
#define __HW_OFFLOAD_SINGLE_PASS_SUPPORT__
typedef unsigned long   typeForSinglePass;

#define NO_SINGLE_PASS                          (0xffff)
#define SINGLE_PASS_AES_SHA1_IN                 (0)
#define SINGLE_PASS_AES_SHA1_OUT                (1)
#define SINGLE_PASS_AES_MD5_IN                  (2)
#define SINGLE_PASS_AES_MD5_OUT                 (3)
#define SINGLE_PASS_3DES_SHA1_IN                (4)
#define SINGLE_PASS_3DES_SHA1_OUT               (5)
#define SINGLE_PASS_3DES_MD5_IN                 (6)
#define SINGLE_PASS_3DES_MD5_OUT                (7)
#define SINGLE_PASS_DES_SHA1_IN                 (8)
#define SINGLE_PASS_DES_SHA1_OUT                (9)
#define SINGLE_PASS_DES_MD5_IN                  (10)
#define SINGLE_PASS_DES_MD5_OUT                 (11)
#define SINGLE_PASS_RC4_SHA1_IN                 NO_SINGLE_PASS /* (12) */
#define SINGLE_PASS_RC4_SHA1_OUT                NO_SINGLE_PASS /* (13) */
#define SINGLE_PASS_RC4_MD5_IN                  NO_SINGLE_PASS /* (14) */
#define SINGLE_PASS_RC4_MD5_OUT                 NO_SINGLE_PASS /* (15) */
#define SINGLE_PASS_NULL_SHA1_IN                NO_SINGLE_PASS
#define SINGLE_PASS_NULL_SHA1_OUT               NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_IN                 NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_OUT                NO_SINGLE_PASS

#if 0
#define SINGLE_PASS_NULL_SHA1_IN                (16)
#define SINGLE_PASS_NULL_SHA1_OUT               (17)
#define SINGLE_PASS_NULL_MD5_IN                 (18)
#define SINGLE_PASS_NULL_MD5_OUT                (19)
#endif

#define x__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__    /* DISABLED FOR NOW */
#define x__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ /* DISABLED FOR NOW */
#define x__VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__

#define MD_CTX_HASHDATA_SIZE                    (0x00001000)
#define MD_CTX_HASHDATA_SIZE_MASK               (0x00000fff)
#define MD_CTX_FSL_CTX_SIZE                     40

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake                       MD5Init_m
#define MD5update_HandShake                     MD5Update_m
#define MD5final_HandShake                      MD5Final_m

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} MD5_CTX, MD5_CTXHS;
#endif

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake                SHA1_initDigest
#define SHA1_updateDigestHandShake              SHA1_updateDigest
#define SHA1_finalDigestHandShake               SHA1_finalDigest

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} shaDescr, shaDescrHS, SHA1_CTX;
#endif

#if 0   /* disabled temporarily */
/* mod exp depends on these so use __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */
#define __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__    __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_R2MODN_OPERATOR_HARDWARE_ACCELERATOR__      __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#endif

#elif (defined(__ENABLE_FREESCALE_8315_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

#define HW_MALLOC(PART,PTR,SIZE,TYPE)           DIGI_MALLOC(PTR,SIZE)
#define HW_FREE(PART,PTR,TYPE)                  DIGI_FREE(PTR)

#define MOC_HW(X)                               X,
#define MOC_SYM(X)                              X,
#define MOC_HASH(X)                             X,
#define MOC_ASYM(X)                             X,
#define MOC_RNG(X)                              X,
#define MOC_PRIME(X)                            X,
#define MOC_MOD(X)                              X,
#define MOC_DH(X)                               X,
#define MOC_DSA(X)                              X,
#define MOC_FFC(X)                              X,
#define MOC_RSA(X)                              X,
#define MOC_ECC(X)                              X,

#define MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE \
ubyte4     header;      \
ubyte4     reserved;    \
ubyte4     length1;     \
ubyte*     pointer1;    \
ubyte4     length2;     \
ubyte*     pointer2;    \
ubyte4     length3;     \
ubyte*     pointer3;    \
ubyte4     length4;     \
ubyte*     pointer4;    \
ubyte4     length5;     \
ubyte*     pointer5;    \
ubyte4     length6;     \
ubyte*     pointer6;    \
ubyte4     length7;     \
ubyte*     pointer7;    \
ubyte*     pNextDpd;

#define __AES_HARDWARE_CIPHER__
#define x__ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define x__DISABLE_DIGICERT_RNG__
#define x__DISABLE_DIGICERT_ADD_ENTROPY__
#define __MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__
#define x__RSAINT_HARDWARE__

/* single pass configuration details */
#define __IPSEC_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_DECRYPT_ADJUST_SSL_RECORD_SIZE_SUPPORT__
#define __HW_OFFLOAD_SINGLE_PASS_SUPPORT__
typedef unsigned long   typeForSinglePass;

#define NO_SINGLE_PASS                          (0xffff)
#define SINGLE_PASS_AES_SHA1_IN                 (0)
#define SINGLE_PASS_AES_SHA1_OUT                (1)
#define SINGLE_PASS_AES_MD5_IN                  (2)
#define SINGLE_PASS_AES_MD5_OUT                 (3)
#define SINGLE_PASS_3DES_SHA1_IN                (4)
#define SINGLE_PASS_3DES_SHA1_OUT               (5)
#define SINGLE_PASS_3DES_MD5_IN                 (6)
#define SINGLE_PASS_3DES_MD5_OUT                (7)
#define SINGLE_PASS_DES_SHA1_IN                 (8)
#define SINGLE_PASS_DES_SHA1_OUT                (9)
#define SINGLE_PASS_DES_MD5_IN                  (10)
#define SINGLE_PASS_DES_MD5_OUT                 (11)
#define SINGLE_PASS_RC4_SHA1_IN                 NO_SINGLE_PASS /* (12) */
#define SINGLE_PASS_RC4_SHA1_OUT                NO_SINGLE_PASS /* (13) */
#define SINGLE_PASS_RC4_MD5_IN                  NO_SINGLE_PASS /* (14) */
#define SINGLE_PASS_RC4_MD5_OUT                 NO_SINGLE_PASS /* (15) */
#define SINGLE_PASS_NULL_SHA1_IN                NO_SINGLE_PASS
#define SINGLE_PASS_NULL_SHA1_OUT               NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_IN                 NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_OUT                NO_SINGLE_PASS

#if 0
#define SINGLE_PASS_NULL_SHA1_IN                (16)
#define SINGLE_PASS_NULL_SHA1_OUT               (17)
#define SINGLE_PASS_NULL_MD5_IN                 (18)
#define SINGLE_PASS_NULL_MD5_OUT                (19)
#endif

#define x__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__    /* DISABLED FOR NOW */
#define x__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ /* DISABLED FOR NOW */
#define x__VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__

#define MD_CTX_HASHDATA_SIZE                    (0x00001000)
#define MD_CTX_HASHDATA_SIZE_MASK               (0x00000fff)
#define MD_CTX_FSL_CTX_SIZE                     40

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake                       MD5Init_m
#define MD5update_HandShake                     MD5Update_m
#define MD5final_HandShake                      MD5Final_m

typedef struct
    {
        intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
        ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
        ubyte4      index;                                  /* index into cachedHashData */
        ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

    } MD5_CTX, MD5_CTXHS;
#endif

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake                SHA1_initDigest
#define SHA1_updateDigestHandShake              SHA1_updateDigest
#define SHA1_finalDigestHandShake               SHA1_finalDigest

typedef struct
    {
        intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
        ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
        ubyte4      index;                                  /* index into cachedHashData */
        ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

    } shaDescr, shaDescrHS, SHA1_CTX;
#endif

#if 0   /* disabled temporarily */
/* mod exp depends on these so use __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */
#define __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__    __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_R2MODN_OPERATOR_HARDWARE_ACCELERATOR__      __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#endif


#elif (defined(__ENABLE_FREESCALE_8323_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

#define HW_MALLOC(PART,PTR,SIZE,TYPE)           DIGI_MALLOC(PTR,SIZE)
#define HW_FREE(PART,PTR,TYPE)                  DIGI_FREE(PTR)

#define MOC_HW(X)                               X,
#define MOC_SYM(X)                              X,
#define MOC_HASH(X)                             X,
#define MOC_ASYM(X)                             X,
#define MOC_RNG(X)                              X,
#define MOC_PRIME(X)                            X,
#define MOC_MOD(X)                              X,
#define MOC_DH(X)                               X,
#define MOC_DSA(X)                              X,
#define MOC_FFC(X)                              X,
#define MOC_RSA(X)                              X,
#define MOC_ECC(X)                              X,

#define MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE \
    ubyte4     header;      \
    ubyte4     reserved;    \
    ubyte4     length1;     \
    ubyte*     pointer1;    \
    ubyte4     length2;     \
    ubyte*     pointer2;    \
    ubyte4     length3;     \
    ubyte*     pointer3;    \
    ubyte4     length4;     \
    ubyte*     pointer4;    \
    ubyte4     length5;     \
    ubyte*     pointer5;    \
    ubyte4     length6;     \
    ubyte*     pointer6;    \
    ubyte4     length7;     \
    ubyte*     pointer7;    \
    ubyte*     pNextDpd;

#define __AES_HARDWARE_CIPHER__
#define x__ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define x__DISABLE_DIGICERT_RNG__
#define x__DISABLE_DIGICERT_ADD_ENTROPY__
#define __MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__
#define x__RSAINT_HARDWARE__

/* single pass configuration details */
#define __IPSEC_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_DECRYPT_ADJUST_SSL_RECORD_SIZE_SUPPORT__
#define __HW_OFFLOAD_SINGLE_PASS_SUPPORT__
typedef unsigned long   typeForSinglePass;

#define NO_SINGLE_PASS                          (0xffff)
#define SINGLE_PASS_AES_SHA1_IN                 (0)
#define SINGLE_PASS_AES_SHA1_OUT                (1)
#define SINGLE_PASS_AES_MD5_IN                  (2)
#define SINGLE_PASS_AES_MD5_OUT                 (3)
#define SINGLE_PASS_3DES_SHA1_IN                (4)
#define SINGLE_PASS_3DES_SHA1_OUT               (5)
#define SINGLE_PASS_3DES_MD5_IN                 (6)
#define SINGLE_PASS_3DES_MD5_OUT                (7)
#define SINGLE_PASS_DES_SHA1_IN                 (8)
#define SINGLE_PASS_DES_SHA1_OUT                (9)
#define SINGLE_PASS_DES_MD5_IN                  (10)
#define SINGLE_PASS_DES_MD5_OUT                 (11)
#define SINGLE_PASS_RC4_SHA1_IN                 NO_SINGLE_PASS /* (12) */
#define SINGLE_PASS_RC4_SHA1_OUT                NO_SINGLE_PASS /* (13) */
#define SINGLE_PASS_RC4_MD5_IN                  NO_SINGLE_PASS /* (14) */
#define SINGLE_PASS_RC4_MD5_OUT                 NO_SINGLE_PASS /* (15) */
#define SINGLE_PASS_NULL_SHA1_IN                NO_SINGLE_PASS
#define SINGLE_PASS_NULL_SHA1_OUT               NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_IN                 NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_OUT                NO_SINGLE_PASS

#if 0
#define SINGLE_PASS_NULL_SHA1_IN                (16)
#define SINGLE_PASS_NULL_SHA1_OUT               (17)
#define SINGLE_PASS_NULL_MD5_IN                 (18)
#define SINGLE_PASS_NULL_MD5_OUT                (19)
#endif

#define x__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__    /* DISABLED FOR NOW */
#define x__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ /* DISABLED FOR NOW */
#define x__VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__

#define MD_CTX_HASHDATA_SIZE                    (0x00001000)
#define MD_CTX_HASHDATA_SIZE_MASK               (0x00000fff)
#define MD_CTX_FSL_CTX_SIZE                     40

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake                       MD5Init_m
#define MD5update_HandShake                     MD5Update_m
#define MD5final_HandShake                      MD5Final_m

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} MD5_CTX, MD5_CTXHS;
#endif

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake                SHA1_initDigest
#define SHA1_updateDigestHandShake              SHA1_updateDigest
#define SHA1_finalDigestHandShake               SHA1_finalDigest

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} shaDescr, shaDescrHS, SHA1_CTX;
#endif

#if 0   /* disabled temporarily */
/* mod exp depends on these so use __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */
#define __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__    __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_R2MODN_OPERATOR_HARDWARE_ACCELERATOR__      __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#endif

#elif (defined(__ENABLE_FREESCALE_8349_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

#define HW_MALLOC(PART,PTR,SIZE,TYPE)           DIGI_MALLOC(PTR,SIZE)
#define HW_FREE(PART,PTR,TYPE)                  DIGI_FREE(PTR)

#define MOC_HW(X)                               X,
#define MOC_SYM(X)                              X,
#define MOC_HASH(X)                             X,
#define MOC_ASYM(X)                             X,
#define MOC_RNG(X)                              X,
#define MOC_PRIME(X)                            X,
#define MOC_MOD(X)                              X,
#define MOC_DH(X)                               X,
#define MOC_DSA(X)                              X,
#define MOC_FFC(X)                              X,
#define MOC_RSA(X)                              X,
#define MOC_ECC(X)                              X,

#define MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE \
    ubyte4     header;      \
    ubyte4     reserved;    \
    ubyte4     length1;     \
    ubyte*     pointer1;    \
    ubyte4     length2;     \
    ubyte*     pointer2;    \
    ubyte4     length3;     \
    ubyte*     pointer3;    \
    ubyte4     length4;     \
    ubyte*     pointer4;    \
    ubyte4     length5;     \
    ubyte*     pointer5;    \
    ubyte4     length6;     \
    ubyte*     pointer6;    \
    ubyte4     length7;     \
    ubyte*     pointer7;

#define __AES_HARDWARE_CIPHER__
#define __ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define __DISABLE_DIGICERT_RNG__
#define __DISABLE_DIGICERT_ADD_ENTROPY__
#define __MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__
#define __RSAINT_HARDWARE__

/* single pass configuration details */
#define __IPSEC_SINGLE_PASS_SUPPORT__
#if (!defined(__ENABLE_FREESCALE_8349_E_HARDWARE_ACCEL__))
#define __SSL_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_DECRYPT_ADJUST_SSL_RECORD_SIZE_SUPPORT__
#endif
#define __HW_OFFLOAD_SINGLE_PASS_SUPPORT__
typedef unsigned long   typeForSinglePass;

#define NO_SINGLE_PASS                          (0xffff)
#define SINGLE_PASS_AES_SHA1_IN                 (0)
#define SINGLE_PASS_AES_SHA1_OUT                (1)
#define SINGLE_PASS_AES_MD5_IN                  (2)
#define SINGLE_PASS_AES_MD5_OUT                 (3)
#define SINGLE_PASS_3DES_SHA1_IN                (4)
#define SINGLE_PASS_3DES_SHA1_OUT               (5)
#define SINGLE_PASS_3DES_MD5_IN                 (6)
#define SINGLE_PASS_3DES_MD5_OUT                (7)
#define SINGLE_PASS_DES_SHA1_IN                 (8)
#define SINGLE_PASS_DES_SHA1_OUT                (9)
#define SINGLE_PASS_DES_MD5_IN                  (10)
#define SINGLE_PASS_DES_MD5_OUT                 (11)
#if (!defined(__ENABLE_FREESCALE_8349_E_HARDWARE_ACCEL__))
#define SINGLE_PASS_RC4_SHA1_IN                 NO_SINGLE_PASS /* (12) */
#else
#define SINGLE_PASS_RC4_SHA1_IN                 (12)
#endif
#define SINGLE_PASS_RC4_SHA1_OUT                (13)
#if (!defined(__ENABLE_FREESCALE_8349_E_HARDWARE_ACCEL__))
#define SINGLE_PASS_RC4_MD5_IN                  NO_SINGLE_PASS /* (14) */
#else
#define SINGLE_PASS_RC4_MD5_IN                  (14)
#endif
#define SINGLE_PASS_RC4_MD5_OUT                 (15)
#define SINGLE_PASS_NULL_SHA1_IN                NO_SINGLE_PASS
#define SINGLE_PASS_NULL_SHA1_OUT               NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_IN                 NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_OUT                NO_SINGLE_PASS

#if 0
#define SINGLE_PASS_NULL_SHA1_IN                (16)
#define SINGLE_PASS_NULL_SHA1_OUT               (17)
#define SINGLE_PASS_NULL_MD5_IN                 (18)
#define SINGLE_PASS_NULL_MD5_OUT                (19)
#endif

#define x__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__    /* DISABLED FOR NOW */
#define x__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ /* DISABLED FOR NOW */
#define __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__

#define MD_CTX_HASHDATA_SIZE                    (0x00001000)
#define MD_CTX_HASHDATA_SIZE_MASK               (0x00000fff)
#define MD_CTX_FSL_CTX_SIZE                     40

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake                       MD5Init_m
#define MD5update_HandShake                     MD5Update_m
#define MD5final_HandShake                      MD5Final_m

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} MD5_CTX, MD5_CTXHS;
#endif

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake                SHA1_initDigest
#define SHA1_updateDigestHandShake              SHA1_updateDigest
#define SHA1_finalDigestHandShake               SHA1_finalDigest

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} shaDescr, shaDescrHS, SHA1_CTX;
#endif

#if 0   /* disabled temporarily */
/* mod exp depends on these so use __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */
#define __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__    __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_R2MODN_OPERATOR_HARDWARE_ACCELERATOR__      __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#endif

#elif (defined(__ENABLE_FREESCALE_8360_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

#define HW_MALLOC(PART,PTR,SIZE,TYPE)           DIGI_MALLOC(PTR,SIZE)
#define HW_FREE(PART,PTR,TYPE)                  DIGI_FREE(PTR)

#define MOC_HW(X)                               X,
#define MOC_SYM(X)                              X,
#define MOC_HASH(X)                             X,
#define MOC_ASYM(X)                             X,
#define MOC_RNG(X)                              X,
#define MOC_PRIME(X)                            X,
#define MOC_MOD(X)                              X,
#define MOC_DH(X)                               X,
#define MOC_DSA(X)                              X,
#define MOC_FFC(X)                              X,
#define MOC_RSA(X)                              X,
#define MOC_ECC(X)                              X,

#define MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE \
    ubyte4     header;      \
    ubyte4     reserved;    \
    ubyte4     length1;     \
    ubyte*     pointer1;    \
    ubyte4     length2;     \
    ubyte*     pointer2;    \
    ubyte4     length3;     \
    ubyte*     pointer3;    \
    ubyte4     length4;     \
    ubyte*     pointer4;    \
    ubyte4     length5;     \
    ubyte*     pointer5;    \
    ubyte4     length6;     \
    ubyte*     pointer6;    \
    ubyte4     length7;     \
    ubyte*     pointer7;    \
    ubyte*     pNextDpd;

#define __AES_HARDWARE_CIPHER__
#define __ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define __DISABLE_DIGICERT_RNG__
#define __DISABLE_DIGICERT_ADD_ENTROPY__
#define __MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__
#define __RSAINT_HARDWARE__

/* single pass configuration details */
#define __IPSEC_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_DECRYPT_ADJUST_SSL_RECORD_SIZE_SUPPORT__
#define __HW_OFFLOAD_SINGLE_PASS_SUPPORT__
typedef unsigned long   typeForSinglePass;

#define NO_SINGLE_PASS                          (0xffff)
#define SINGLE_PASS_AES_SHA1_IN                 (0)
#define SINGLE_PASS_AES_SHA1_OUT                (1)
#define SINGLE_PASS_AES_MD5_IN                  (2)
#define SINGLE_PASS_AES_MD5_OUT                 (3)
#define SINGLE_PASS_3DES_SHA1_IN                (4)
#define SINGLE_PASS_3DES_SHA1_OUT               (5)
#define SINGLE_PASS_3DES_MD5_IN                 (6)
#define SINGLE_PASS_3DES_MD5_OUT                (7)
#define SINGLE_PASS_DES_SHA1_IN                 (8)
#define SINGLE_PASS_DES_SHA1_OUT                (9)
#define SINGLE_PASS_DES_MD5_IN                  (10)
#define SINGLE_PASS_DES_MD5_OUT                 (11)
#define SINGLE_PASS_RC4_SHA1_IN                 NO_SINGLE_PASS /* (12) */
#define SINGLE_PASS_RC4_SHA1_OUT                (13)
#define SINGLE_PASS_RC4_MD5_IN                  NO_SINGLE_PASS /* (14) */
#define SINGLE_PASS_RC4_MD5_OUT                 (15)
#define SINGLE_PASS_NULL_SHA1_IN                NO_SINGLE_PASS
#define SINGLE_PASS_NULL_SHA1_OUT               NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_IN                 NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_OUT                NO_SINGLE_PASS

#if 0
#define SINGLE_PASS_NULL_SHA1_IN                (16)
#define SINGLE_PASS_NULL_SHA1_OUT               (17)
#define SINGLE_PASS_NULL_MD5_IN                 (18)
#define SINGLE_PASS_NULL_MD5_OUT                (19)
#endif


#define x__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__    /* DISABLED FOR NOW */
#define x__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ /* DISABLED FOR NOW */
#define __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__

#define MD_CTX_HASHDATA_SIZE                    (0x00001000)
#define MD_CTX_HASHDATA_SIZE_MASK               (0x00000fff)
#define MD_CTX_FSL_CTX_SIZE                     40

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake                       MD5Init_m
#define MD5update_HandShake                     MD5Update_m
#define MD5final_HandShake                      MD5Final_m

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} MD5_CTX, MD5_CTXHS;
#endif

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake                SHA1_initDigest
#define SHA1_updateDigestHandShake              SHA1_updateDigest
#define SHA1_finalDigestHandShake               SHA1_finalDigest

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} shaDescr, shaDescrHS, SHA1_CTX;
#endif

#if 0   /* disabled temporarily */
/* mod exp depends on these so use __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */
#define __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__    __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_R2MODN_OPERATOR_HARDWARE_ACCELERATOR__      __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#endif

#elif (defined(__ENABLE_FREESCALE_8548_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

#define HW_MALLOC(PART,PTR,SIZE,TYPE)           DIGI_MALLOC(PTR,SIZE)
#define HW_FREE(PART,PTR,TYPE)                  DIGI_FREE(PTR)

#define MOC_HW(X)                               X,
#define MOC_SYM(X)                              X,
#define MOC_HASH(X)                             X,
#define MOC_ASYM(X)                             X,
#define MOC_RNG(X)                              X,
#define MOC_PRIME(X)                            X,
#define MOC_MOD(X)                              X,
#define MOC_DH(X)                               X,
#define MOC_DSA(X)                              X,
#define MOC_FFC(X)                              X,
#define MOC_RSA(X)                              X,
#define MOC_ECC(X)                              X,

#define MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE \
    ubyte4     header;      \
    ubyte4     reserved;    \
    ubyte4     length1;     \
    ubyte*     pointer1;    \
    ubyte4     length2;     \
    ubyte*     pointer2;    \
    ubyte4     length3;     \
    ubyte*     pointer3;    \
    ubyte4     length4;     \
    ubyte*     pointer4;    \
    ubyte4     length5;     \
    ubyte*     pointer5;    \
    ubyte4     length6;     \
    ubyte*     pointer6;    \
    ubyte4     length7;     \
    ubyte*     pointer7;

/* options enabled */
#define __AES_HARDWARE_CIPHER__
#define __ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define __DISABLE_DIGICERT_RNG__
#define __DISABLE_DIGICERT_ADD_ENTROPY__
#define __MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__
#define __RSAINT_HARDWARE__

/* single pass configuration details */
#define __IPSEC_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_DECRYPT_ADJUST_SSL_RECORD_SIZE_SUPPORT__
#define __HW_OFFLOAD_SINGLE_PASS_SUPPORT__
typedef unsigned long   typeForSinglePass;

#define NO_SINGLE_PASS                          (0xffff)
#define SINGLE_PASS_AES_SHA1_IN                 (0)
#define SINGLE_PASS_AES_SHA1_OUT                (1)
#define SINGLE_PASS_AES_MD5_IN                  (2)
#define SINGLE_PASS_AES_MD5_OUT                 (3)
#define SINGLE_PASS_3DES_SHA1_IN                (4)
#define SINGLE_PASS_3DES_SHA1_OUT               (5)
#define SINGLE_PASS_3DES_MD5_IN                 (6)
#define SINGLE_PASS_3DES_MD5_OUT                (7)
#define SINGLE_PASS_DES_SHA1_IN                 (8)
#define SINGLE_PASS_DES_SHA1_OUT                (9)
#define SINGLE_PASS_DES_MD5_IN                  (10)
#define SINGLE_PASS_DES_MD5_OUT                 (11)
#define SINGLE_PASS_RC4_SHA1_IN                 NO_SINGLE_PASS /* (12) */
#define SINGLE_PASS_RC4_SHA1_OUT                (13)
#define SINGLE_PASS_RC4_MD5_IN                  NO_SINGLE_PASS /* (14) */
#define SINGLE_PASS_RC4_MD5_OUT                 (15)
#define SINGLE_PASS_NULL_SHA1_IN                NO_SINGLE_PASS
#define SINGLE_PASS_NULL_SHA1_OUT               NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_IN                 NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_OUT                NO_SINGLE_PASS

#if 0
#define SINGLE_PASS_NULL_SHA1_IN                (16)
#define SINGLE_PASS_NULL_SHA1_OUT               (17)
#define SINGLE_PASS_NULL_MD5_IN                 (18)
#define SINGLE_PASS_NULL_MD5_OUT                (19)
#endif

#define x__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__    /* DISABLED FOR NOW */
#define x__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ /* DISABLED FOR NOW */
#define __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__

#define MD_CTX_HASHDATA_SIZE                    (0x00001000)
#define MD_CTX_HASHDATA_SIZE_MASK               (0x00000fff)

#define MD_CTX_FSL_CTX_SIZE                     40

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake                       MD5Init_m
#define MD5update_HandShake                     MD5Update_m
#define MD5final_HandShake                      MD5Final_m

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} MD5_CTX, MD5_CTXHS;
#endif

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake                SHA1_initDigest
#define SHA1_updateDigestHandShake              SHA1_updateDigest
#define SHA1_finalDigestHandShake               SHA1_finalDigest

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} shaDescr, shaDescrHS, SHA1_CTX;
#endif

#if 0   /* disabled temporarily */
/* mod exp depends on these so use __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */
#define __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__    __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_R2MODN_OPERATOR_HARDWARE_ACCELERATOR__      __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#endif

#elif (defined(__ENABLE_FREESCALE_8544_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

#define HW_MALLOC(PART,PTR,SIZE,TYPE)           DIGI_MALLOC(PTR,SIZE)
#define HW_FREE(PART,PTR,TYPE)                  DIGI_FREE(PTR)

#define MOC_HW(X)                               X,
#define MOC_SYM(X)                              X,
#define MOC_HASH(X)                             X,
#define MOC_ASYM(X)                             X,
#define MOC_RNG(X)                              X,
#define MOC_PRIME(X)                            X,
#define MOC_MOD(X)                              X,
#define MOC_DH(X)                               X,
#define MOC_DSA(X)                              X,
#define MOC_FFC(X)                              X,
#define MOC_RSA(X)                              X,
#define MOC_ECC(X)                              X,

#define MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE \
    ubyte4     header;      \
    ubyte4     reserved;    \
    ubyte4     length1;     \
    ubyte*     pointer1;    \
    ubyte4     length2;     \
    ubyte*     pointer2;    \
    ubyte4     length3;     \
    ubyte*     pointer3;    \
    ubyte4     length4;     \
    ubyte*     pointer4;    \
    ubyte4     length5;     \
    ubyte*     pointer5;    \
    ubyte4     length6;     \
    ubyte*     pointer6;    \
    ubyte4     length7;     \
    ubyte*     pointer7;

/* options enabled */
#define __AES_HARDWARE_CIPHER__
#define __ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define __DISABLE_DIGICERT_RNG__
#define __DISABLE_DIGICERT_ADD_ENTROPY__
#define __MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__
#define __RSAINT_HARDWARE__

/* single pass configuration details */
#define __IPSEC_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_DECRYPT_ADJUST_SSL_RECORD_SIZE_SUPPORT__
#define __HW_OFFLOAD_SINGLE_PASS_SUPPORT__
typedef unsigned long   typeForSinglePass;

#define NO_SINGLE_PASS                          (0xffff)
#define SINGLE_PASS_AES_SHA1_IN                 (0)
#define SINGLE_PASS_AES_SHA1_OUT                (1)
#define SINGLE_PASS_AES_MD5_IN                  (2)
#define SINGLE_PASS_AES_MD5_OUT                 (3)
#define SINGLE_PASS_3DES_SHA1_IN                (4)
#define SINGLE_PASS_3DES_SHA1_OUT               (5)
#define SINGLE_PASS_3DES_MD5_IN                 (6)
#define SINGLE_PASS_3DES_MD5_OUT                (7)
#define SINGLE_PASS_DES_SHA1_IN                 (8)
#define SINGLE_PASS_DES_SHA1_OUT                (9)
#define SINGLE_PASS_DES_MD5_IN                  (10)
#define SINGLE_PASS_DES_MD5_OUT                 (11)
#define SINGLE_PASS_RC4_SHA1_IN                 NO_SINGLE_PASS /* (12) */
#define SINGLE_PASS_RC4_SHA1_OUT                (13)
#define SINGLE_PASS_RC4_MD5_IN                  NO_SINGLE_PASS /* (14) */
#define SINGLE_PASS_RC4_MD5_OUT                 (15)
#define SINGLE_PASS_NULL_SHA1_IN                NO_SINGLE_PASS
#define SINGLE_PASS_NULL_SHA1_OUT               NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_IN                 NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_OUT                NO_SINGLE_PASS

#if 0
#define SINGLE_PASS_NULL_SHA1_IN                (16)
#define SINGLE_PASS_NULL_SHA1_OUT               (17)
#define SINGLE_PASS_NULL_MD5_IN                 (18)
#define SINGLE_PASS_NULL_MD5_OUT                (19)
#endif

#define x__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__    /* DISABLED FOR NOW */
#define x__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ /* DISABLED FOR NOW */
#define __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__

#define MD_CTX_HASHDATA_SIZE                    (0x00001000)
#define MD_CTX_HASHDATA_SIZE_MASK               (0x00000fff)

#define MD_CTX_FSL_CTX_SIZE                     40

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake                       MD5Init_m
#define MD5update_HandShake                     MD5Update_m
#define MD5final_HandShake                      MD5Final_m

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} MD5_CTX, MD5_CTXHS;
#endif

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake                SHA1_initDigest
#define SHA1_updateDigestHandShake              SHA1_updateDigest
#define SHA1_finalDigestHandShake               SHA1_finalDigest

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} shaDescr, shaDescrHS, SHA1_CTX;
#endif


#if 0   /* disabled temporarily */
/* mod exp depends on these so use __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */
#define __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__    __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_R2MODN_OPERATOR_HARDWARE_ACCELERATOR__      __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#endif

#elif (defined(__ENABLE_FREESCALE_8555_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

#define HW_MALLOC(PART,PTR,SIZE,TYPE)           DIGI_MALLOC(PTR,SIZE)
#define HW_FREE(PART,PTR,TYPE)                  DIGI_FREE(PTR)

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
    ubyte4     header;      \
    ubyte4     reserved;    \
    ubyte4     length1;     \
    ubyte*     pointer1;    \
    ubyte4     length2;     \
    ubyte*     pointer2;    \
    ubyte4     length3;     \
    ubyte*     pointer3;    \
    ubyte4     length4;     \
    ubyte*     pointer4;    \
    ubyte4     length5;     \
    ubyte*     pointer5;    \
    ubyte4     length6;     \
    ubyte*     pointer6;    \
    ubyte4     length7;     \
    ubyte*     pointer7;

#define __AES_HARDWARE_CIPHER__
#define __ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define __DISABLE_DIGICERT_RNG__
#define __DISABLE_DIGICERT_ADD_ENTROPY__
#define __MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__
#define __RSAINT_HARDWARE__

/* single pass configuration details */
#define __IPSEC_SINGLE_PASS_SUPPORT__
#define __HW_OFFLOAD_SINGLE_PASS_SUPPORT__
typedef unsigned long   typeForSinglePass;

#define NO_SINGLE_PASS                          (0xffff)
#define SINGLE_PASS_AES_SHA1_IN                 (0)
#define SINGLE_PASS_AES_SHA1_OUT                (1)
#define SINGLE_PASS_AES_MD5_IN                  (2)
#define SINGLE_PASS_AES_MD5_OUT                 (3)
#define SINGLE_PASS_3DES_SHA1_IN                (4)
#define SINGLE_PASS_3DES_SHA1_OUT               (5)
#define SINGLE_PASS_3DES_MD5_IN                 (6)
#define SINGLE_PASS_3DES_MD5_OUT                (7)
#define SINGLE_PASS_DES_SHA1_IN                 (8)
#define SINGLE_PASS_DES_SHA1_OUT                (9)
#define SINGLE_PASS_DES_MD5_IN                  (10)
#define SINGLE_PASS_DES_MD5_OUT                 (11)
#define SINGLE_PASS_RC4_SHA1_IN                 (12)
#define SINGLE_PASS_RC4_SHA1_OUT                (13)
#define SINGLE_PASS_RC4_MD5_IN                  (14)
#define SINGLE_PASS_RC4_MD5_OUT                 (15)
#define SINGLE_PASS_NULL_SHA1_IN                NO_SINGLE_PASS
#define SINGLE_PASS_NULL_SHA1_OUT               NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_IN                 NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_OUT                NO_SINGLE_PASS

#if 0
#define SINGLE_PASS_NULL_SHA1_IN                (16)
#define SINGLE_PASS_NULL_SHA1_OUT               (17)
#define SINGLE_PASS_NULL_MD5_IN                 (18)
#define SINGLE_PASS_NULL_MD5_OUT                (19)
#endif

#define x__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__    /* DISABLED FOR NOW */
#define x__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ /* DISABLED FOR NOW */
#define __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__

#if 1
#define MD_CTX_HASHDATA_SIZE       (0x00001000)
#define MD_CTX_HASHDATA_SIZE_MASK  (0x00000fff)
#else
#define MD_CTX_HASHDATA_SIZE       (0x00000040)
#define MD_CTX_HASHDATA_SIZE_MASK  (0x0000003f)
#endif

#define MD_CTX_FSL_CTX_SIZE        40

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake   MD5Init_m
#define MD5update_HandShake MD5Update_m
#define MD5final_HandShake  MD5Final_m

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} MD5_CTX, MD5_CTXHS;
#endif

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake    SHA1_initDigest
#define SHA1_updateDigestHandShake  SHA1_updateDigest
#define SHA1_finalDigestHandShake   SHA1_finalDigest

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} shaDescr, shaDescrHS, SHA1_CTX;
#endif

#if 0   /* disabled temporarily */
/* mod exp depends on these so use __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */
#define __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__    __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_R2MODN_OPERATOR_HARDWARE_ACCELERATOR__      __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#endif

#elif (defined(__ENABLE_FREESCALE_8572_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

#define HW_MALLOC(PART,PTR,SIZE,TYPE)           DIGI_MALLOC(PTR,SIZE)
#define HW_FREE(PART,PTR,TYPE)                  DIGI_FREE(PTR)

#define MOC_HW(X)                               X,
#define MOC_SYM(X)                              X,
#define MOC_HASH(X)                             X,
#define MOC_ASYM(X)                             X,
#define MOC_RNG(X)                              X,
#define MOC_PRIME(X)                            X,
#define MOC_MOD(X)                              X,
#define MOC_DH(X)                               X,
#define MOC_DSA(X)                              X,
#define MOC_FFC(X)                              X,
#define MOC_RSA(X)                              X,
#define MOC_ECC(X)                              X,

#define MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE \
    ubyte4     header;      \
    ubyte4     reserved;    \
    ubyte4     length1;     \
    ubyte*     pointer1;    \
    ubyte4     length2;     \
    ubyte*     pointer2;    \
    ubyte4     length3;     \
    ubyte*     pointer3;    \
    ubyte4     length4;     \
    ubyte*     pointer4;    \
    ubyte4     length5;     \
    ubyte*     pointer5;    \
    ubyte4     length6;     \
    ubyte*     pointer6;    \
    ubyte4     length7;     \
    ubyte*     pointer7;

/* options enabled */
#define __AES_HARDWARE_CIPHER__
#define __ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define __DISABLE_DIGICERT_RNG__
#define __DISABLE_DIGICERT_ADD_ENTROPY__
#define __MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__
#define __RSAINT_HARDWARE__

/* single pass configuration details */
#define __IPSEC_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_DECRYPT_ADJUST_SSL_RECORD_SIZE_SUPPORT__
#define __HW_OFFLOAD_SINGLE_PASS_SUPPORT__
typedef unsigned long   typeForSinglePass;

#define NO_SINGLE_PASS                          (0xffff)
#define SINGLE_PASS_AES_SHA1_IN                 (0)
#define SINGLE_PASS_AES_SHA1_OUT                (1)
#define SINGLE_PASS_AES_MD5_IN                  (2)
#define SINGLE_PASS_AES_MD5_OUT                 (3)
#define SINGLE_PASS_3DES_SHA1_IN                (4)
#define SINGLE_PASS_3DES_SHA1_OUT               (5)
#define SINGLE_PASS_3DES_MD5_IN                 (6)
#define SINGLE_PASS_3DES_MD5_OUT                (7)
#define SINGLE_PASS_DES_SHA1_IN                 (8)
#define SINGLE_PASS_DES_SHA1_OUT                (9)
#define SINGLE_PASS_DES_MD5_IN                  (10)
#define SINGLE_PASS_DES_MD5_OUT                 (11)
#define SINGLE_PASS_RC4_SHA1_IN                 NO_SINGLE_PASS /* (12) */
#define SINGLE_PASS_RC4_SHA1_OUT                (13)
#define SINGLE_PASS_RC4_MD5_IN                  NO_SINGLE_PASS /* (14) */
#define SINGLE_PASS_RC4_MD5_OUT                 (15)
#define SINGLE_PASS_NULL_SHA1_IN                NO_SINGLE_PASS
#define SINGLE_PASS_NULL_SHA1_OUT               NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_IN                 NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_OUT                NO_SINGLE_PASS

#if 0
#define SINGLE_PASS_NULL_SHA1_IN                (16)
#define SINGLE_PASS_NULL_SHA1_OUT               (17)
#define SINGLE_PASS_NULL_MD5_IN                 (18)
#define SINGLE_PASS_NULL_MD5_OUT                (19)
#endif

#define x__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__    /* DISABLED FOR NOW */
#define x__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ /* DISABLED FOR NOW */
#define __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__

#define MD_CTX_HASHDATA_SIZE                    (0x00001000)
#define MD_CTX_HASHDATA_SIZE_MASK               (0x00000fff)

#define MD_CTX_FSL_CTX_SIZE                     40

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake                       MD5Init_m
#define MD5update_HandShake                     MD5Update_m
#define MD5final_HandShake                      MD5Final_m

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} MD5_CTX, MD5_CTXHS;
#endif

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake                SHA1_initDigest
#define SHA1_updateDigestHandShake              SHA1_updateDigest
#define SHA1_finalDigestHandShake               SHA1_finalDigest

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} shaDescr, shaDescrHS, SHA1_CTX;
#endif

#if 0   /* disabled temporarily */
/* mod exp depends on these so use __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */
#define __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__    __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_R2MODN_OPERATOR_HARDWARE_ACCELERATOR__      __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#endif

/* 8379 begin */

#elif (defined(__ENABLE_FREESCALE_8379_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

#define HW_MALLOC(PART,PTR,SIZE,TYPE)           DIGI_MALLOC(PTR,SIZE)
#define HW_FREE(PART,PTR,TYPE)                  DIGI_FREE(PTR)

#define MOC_HW(X)                               X,
#define MOC_SYM(X)                              X,
#define MOC_HASH(X)                             X,
#define MOC_ASYM(X)                             X,
#define MOC_RNG(X)                              X,
#define MOC_PRIME(X)                            X,
#define MOC_MOD(X)                              X,
#define MOC_DH(X)                               X,
#define MOC_DSA(X)                              X,
#define MOC_FFC(X)                              X,
#define MOC_RSA(X)                              X,
#define MOC_ECC(X)                              X,

#define MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE \
    ubyte4     header;      \
    ubyte4     reserved;    \
    ubyte4     length1;     \
    ubyte*     pointer1;    \
    ubyte4     length2;     \
    ubyte*     pointer2;    \
    ubyte4     length3;     \
    ubyte*     pointer3;    \
    ubyte4     length4;     \
    ubyte*     pointer4;    \
    ubyte4     length5;     \
    ubyte*     pointer5;    \
    ubyte4     length6;     \
    ubyte*     pointer6;    \
    ubyte4     length7;     \
    ubyte*     pointer7;

/* options enabled */
#define __AES_HARDWARE_CIPHER__
#define __ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define __DISABLE_DIGICERT_RNG__
#define __DISABLE_DIGICERT_ADD_ENTROPY__
#define __MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__
#define __RSAINT_HARDWARE__

/* single pass configuration details */
#define __IPSEC_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_SUPPORT__
#define __SSL_SINGLE_PASS_DECRYPT_ADJUST_SSL_RECORD_SIZE_SUPPORT__
#define __HW_OFFLOAD_SINGLE_PASS_SUPPORT__
typedef unsigned long   typeForSinglePass;

#define NO_SINGLE_PASS                          (0xffff)
#define SINGLE_PASS_AES_SHA1_IN                 (0)
#define SINGLE_PASS_AES_SHA1_OUT                (1)
#define SINGLE_PASS_AES_MD5_IN                  (2)
#define SINGLE_PASS_AES_MD5_OUT                 (3)
#define SINGLE_PASS_3DES_SHA1_IN                (4)
#define SINGLE_PASS_3DES_SHA1_OUT               (5)
#define SINGLE_PASS_3DES_MD5_IN                 (6)
#define SINGLE_PASS_3DES_MD5_OUT                (7)
#define SINGLE_PASS_DES_SHA1_IN                 (8)
#define SINGLE_PASS_DES_SHA1_OUT                (9)
#define SINGLE_PASS_DES_MD5_IN                  (10)
#define SINGLE_PASS_DES_MD5_OUT                 (11)
#define SINGLE_PASS_RC4_SHA1_IN                 NO_SINGLE_PASS /* (12) */
#define SINGLE_PASS_RC4_SHA1_OUT                (13)
#define SINGLE_PASS_RC4_MD5_IN                  NO_SINGLE_PASS /* (14) */
#define SINGLE_PASS_RC4_MD5_OUT                 (15)
#define SINGLE_PASS_NULL_SHA1_IN                NO_SINGLE_PASS
#define SINGLE_PASS_NULL_SHA1_OUT               NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_IN                 NO_SINGLE_PASS
#define SINGLE_PASS_NULL_MD5_OUT                NO_SINGLE_PASS

#if 0
#define SINGLE_PASS_NULL_SHA1_IN                (16)
#define SINGLE_PASS_NULL_SHA1_OUT               (17)
#define SINGLE_PASS_NULL_MD5_IN                 (18)
#define SINGLE_PASS_NULL_MD5_OUT                (19)
#endif

#define x__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__    /* DISABLED FOR NOW */
#define x__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ /* DISABLED FOR NOW */
#define __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define x__VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__

#define MD_CTX_HASHDATA_SIZE                    (0x00001000)
#define MD_CTX_HASHDATA_SIZE_MASK               (0x00000fff)

#define MD_CTX_FSL_CTX_SIZE                     40

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake                       MD5Init_m
#define MD5update_HandShake                     MD5Update_m
#define MD5final_HandShake                      MD5Final_m

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} MD5_CTX, MD5_CTXHS;
#endif

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake                SHA1_initDigest
#define SHA1_updateDigestHandShake              SHA1_updateDigest
#define SHA1_finalDigestHandShake               SHA1_finalDigest

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} shaDescr, shaDescrHS, SHA1_CTX;
#endif

#if 0   /* disabled temporarily */
/* mod exp depends on these so use __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */
#define __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__    __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_R2MODN_OPERATOR_HARDWARE_ACCELERATOR__      __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#endif


/* 8379 end */


#elif (defined(__ENABLE_FREESCALE_8248_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

#define __HARDWARE_ACCEL_PROTOTYPES__
#define __ENABLE_FREESCALE_8248_HARDWARE_ACCEL__

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
    ubyte4     header;      \
    ubyte4     length1;     \
    ubyte*     pointer1;    \
    ubyte4     length2;     \
    ubyte*     pointer2;    \
    ubyte4     length3;     \
    ubyte*     pointer3;    \
    ubyte4     length4;     \
    ubyte*     pointer4;    \
    ubyte4     length5;     \
    ubyte*     pointer5;    \
    ubyte4     length6;     \
    ubyte*     pointer6;    \
    ubyte4     length7;     \
    ubyte*     pointer7;    \
    void*      pNext;

#define __AES_HARDWARE_CIPHER__
#define __ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__
#define __DISABLE_DIGICERT_RNG__
#define __DISABLE_DIGICERT_ADD_ENTROPY__
#define x__MD5_HARDWARE_HASH__
#define x__SHA1_HARDWARE_HASH__

#define x__VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__    /* DISABLED FOR NOW */
#define x__VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ /* DISABLED FOR NOW */
#define __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__

#define MD_CTX_HASHDATA_SIZE       64
#define MD_CTX_FSL_CTX_SIZE        40

#ifdef __MD5_HARDWARE_HASH__
#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake   MD5Init_m
#define MD5update_HandShake MD5Update_m
#define MD5final_HandShake  MD5Final_m

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} MD5_CTX, MD5_CTXHS;
#endif                                  /* __MD5_HARDWARE_HASH__ */

#ifdef __SHA1_HARDWARE_HASH__
#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake    SHA1_initDigest
#define SHA1_updateDigestHandShake  SHA1_updateDigest
#define SHA1_finalDigestHandShake   SHA1_finalDigest

typedef struct
{
    intBoolean  isAfterFirstBlock;                      /* are we working on the first 512 bits? */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte       fslCtx[MD_CTX_FSL_CTX_SIZE];            /* this buffer holds the ctx for FSL */

} shaDescr, shaDescrHS;
#endif

/* mod exp depends on these so use __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */
#define __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__    __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
#define __VLONG_R2MODN_OPERATOR_HARDWARE_ACCELERATOR__      __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__

#define HARDWARE_ACCEL_INIT                     FSL8248_init
#define HARDWARE_ACCEL_UNINIT                   FSL8248_uninit
#define HARDWARE_ACCEL_OPEN_CHANNEL             FSL8248_openChannel
#define HARDWARE_ACCEL_CLOSE_CHANNEL            FSL8248_closeChannel

#elif (defined(__ENABLE_FREESCALE_875_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))

#define __HARDWARE_ACCEL_PROTOTYPES__
typedef sbyte4  hwAccelDescr;

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
    ubyte4     header;      \
    ubyte4     length1;     \
    ubyte*     pointer1;    \
    ubyte4     length2;     \
    ubyte*     pointer2;    \
    ubyte4     length3;     \
    ubyte*     pointer3;    \
    ubyte4     length4;     \
    ubyte*     pointer4;    \
    ubyte4     length5;     \
    ubyte*     pointer5;    \
    ubyte4     length6;     \
    ubyte*     pointer6;    \
    ubyte4     length7;     \
    ubyte*     pointer7;    \
    void*      pNext;

#define __AES_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
#define __HMAC_MD5_HARDWARE_HASH__
#define __HMAC_SHA1_HARDWARE_HASH__

#define HARDWARE_ACCEL_INIT                     FSL875_init
#define HARDWARE_ACCEL_UNINIT                   FSL875_uninit
#define HARDWARE_ACCEL_OPEN_CHANNEL             FSL875_openChannel
#define HARDWARE_ACCEL_CLOSE_CHANNEL            FSL875_closeChannel

#elif (defined(__ENABLE_WIN32_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))

#define __HARDWARE_ACCEL_PROTOTYPES__
typedef sbyte4  hwAccelDescr;

#define MOC_HW(X)           X,
#define MOC_SYM(X)          X,
#define MOC_HASH(X)
#define MOC_ASYM(X)         X,
#define MOC_RNG(X)          X,
#define MOC_PRIME(X)
#define MOC_MOD(X)
#define MOC_DH(X)
#define MOC_DSA(X)
#define MOC_FFC(X)
#define MOC_RSA(X)
#define MOC_ECC(X)

#define __AES_HARDWARE_CIPHER__
#define __ARC4_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define X__MD5_ONE_STEP_HARDWARE_HASH__
#define X__SHA1_ONE_STEP_HARDWARE_HASH__
#define X__HMAC_MD5_HARDWARE_HASH__
#define X__HMAC_SHA1_HARDWARE_HASH__

#define HARDWARE_ACCEL_INIT                     HW_CRYPTO_WIN32_init
#define HARDWARE_ACCEL_UNINIT                   HW_CRYPTO_WIN32_uninit
#define HARDWARE_ACCEL_OPEN_CHANNEL             HW_CRYPTO_WIN32_openChannel
#define HARDWARE_ACCEL_CLOSE_CHANNEL            HW_CRYPTO_WIN32_closeChannel

#elif (defined(__ENABLE_IOS_CORECRYPTO_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>

typedef sbyte4  hwAccelDescr;

#define MOC_HW(X)
#define MOC_SYM(X)
#define MOC_HASH(X)
#define MOC_ASYM(X)
#define MOC_RNG(X)
#define MOC_PRIME(X)
#define MOC_MOD(X)
#define MOC_DH(X)
#define MOC_DSA(X)
#define MOC_FFC(X)
#define MOC_RSA(X)
#define MOC_ECC(X)

#define x__AES_HARDWARE_CIPHER__
#define x__DES_HARDWARE_CIPHER__
#define x__3DES_HARDWARE_CIPHER__
#define x__MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__
#define x__AES_XTS_HARDWARE_CIPHER__

#if (defined(__SHA1_HARDWARE_HASH__))

#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake                SHA1_initDigest
#define SHA1_updateDigestHandShake              SHA1_updateDigest
#define SHA1_finalDigestHandShake               SHA1_finalDigest

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

#define MAX_TWEAK_LENGTH AES_BLOCK_SIZE
#define MAX_AES_KEY_LENGTH AES_BLOCK_SIZE

typedef struct
{
    CC_SHA1_CTX c;

} shaDescr, shaDescrHS, SHA1_CTX;

typedef struct
{
    CCCryptorRef cccRef;
    sbyte4 encrypt;

    const ubyte pKeyMaterial[MAX_AES_KEY_LENGTH];
    sbyte4 keyLength;

#ifdef __AES_XTS_HARDWARE_CIPHER__
    const ubyte pTweak[MAX_TWEAK_LENGTH];
    sbyte4 tweakLength;
#endif


} iosCryptorDescr;

#endif /*__SHA1_HARDWARE_HASH__*/

#elif (defined(__ENABLE_FREESCALE_COLDFIRE_CAU_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))

typedef sbyte4  hwAccelDescr;

#define MOC_HW(X)
#define MOC_SYM(X)
#define MOC_HASH(X)
#define MOC_ASYM(X)
#define MOC_RNG(X)
#define MOC_PRIME(X)
#define MOC_MOD(X)
#define MOC_DH(X)
#define MOC_DSA(X)
#define MOC_FFC(X)
#define MOC_RSA(X)
#define MOC_ECC(X)

#define __AES_HARDWARE_CIPHER__
#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
#define __MD5_HARDWARE_HASH__
#define __SHA1_HARDWARE_HASH__
#define __SHA256_HARDWARE_HASH__

#define MD_CTX_HASHDATA_SIZE                    (64)

#if (defined(__MD5_HARDWARE_HASH__))

#define __CUSTOM_MD5_CONTEXT__
#define MD5init_HandShake                       MD5Init_m
#define MD5update_HandShake                     MD5Update_m
#define MD5final_HandShake                      MD5Final_m

typedef struct
{
    ubyte4      mesgLength;                             /* number of total bytes processed */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte4      hashBlocks[4];                          /* MD5 ctx for FSL */

} MD5_CTX, MD5_CTXHS;

#endif  /* (defined(__MD5_HARDWARE_HASH__)) */

#if (defined(__SHA1_HARDWARE_HASH__))

#define __CUSTOM_SHA1_CONTEXT__
#define SHA1_initDigestHandShake                SHA1_initDigest
#define SHA1_updateDigestHandShake              SHA1_updateDigest
#define SHA1_finalDigestHandShake               SHA1_finalDigest

typedef struct
{
    ubyte4      mesgLength;                             /* number of total bytes processed */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte4      hashBlocks[5];                          /* this buffer holds the ctx for FSL */

} shaDescr, shaDescrHS, SHA1_CTX;


#endif /* (defined(__SHA1_HARDWARE_HASH__)) */

#if (defined(__SHA256_HARDWARE_HASH__))

#define __CUSTOM_SHA256_CONTEXT__
#define SHA256_initDigestHandShake              SHA256_initDigest
#define SHA256_updateDigestHandShake            SHA256_updateDigest
#define SHA256_finalDigestHandShake             SHA256_finalDigest

typedef struct
{
    ubyte4      mesgLength;                             /* number of total bytes processed */
    ubyte       cachedHashData[MD_CTX_HASHDATA_SIZE];   /* FSL processes 512 bits at a time */
    ubyte4      index;                                  /* index into cachedHashData */
    ubyte4      hashBlocks[8];                          /* this buffer holds the ctx for FSL */

} sha256Descr, sha256DescrHS, SHA256_CTX;

#endif /* (defined(__SHA256_HARDWARE_HASH__)) */

#elif (defined(__ENABLE_FREESCALE_COLDFIRE_OLD_EU_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))

#define MOC_HW(X)
#define MOC_SYM(X)
#define MOC_HASH(X)
#define MOC_ASYM(X)
#define MOC_RNG(X)
#define MOC_PRIME(X)
#define MOC_MOD(X)
#define MOC_DH(X)
#define MOC_DSA(X)
#define MOC_FFC(X)
#define MOC_RSA(X)
#define MOC_ECC(X)

#define __AES_HARDWARE_CIPHER__
/* OLD EU only supports AES-128 */
#define __DISABLE_AES192_CIPHER__
#define __DISABLE_AES256_CIPHER__

#define __DES_HARDWARE_CIPHER__
#define __3DES_HARDWARE_CIPHER__
/*#define __MD5_ONE_STEP_HARDWARE_HASH__
#define __SHA1_ONE_STEP_HARDWARE_HASH__
*/

#endif /* END OF HARDWARE ACCELERATOR DEFINITIONS */

#if (defined(__ENABLE_DIGICERT_HARNESS__) && defined(__ENABLE_DIGICERT_PKCS11_CRYPTO__))

typedef sbyte4  hwAccelDescr;

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

#endif /* defined(__ENABLE_DIGICERT_HARNESS__) && defined(__ENABLE_DIGICERT_FIPS_MODULE__) */
#endif /* __HW_ACCEL_CUSTOM__ */

#ifndef MOC_DECLARE_HW_CTX
#if defined(__ENABLE_DIGICERT_HARNESS__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__)
#define MOC_DECLARE_HW_CTX(_hwCtx) hwAccelDescr _hwCtx = (hwAccelDescr)0; ((void)_hwCtx);
#else
#define MOC_DECLARE_HW_CTX(_hwCtx)
#endif /* defined(__ENABLE_DIGICERT_HARNESS__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) */
#endif


/*------------------------------------------------------------------*/

#ifndef HW_MALLOC    /* TYPE is a member of hwCryptoAllocTypes */
#define HW_MALLOC(PART,PTR,SIZE,TYPE)           DIGI_MALLOC(PTR,SIZE)
#endif

#ifndef HW_FREE      /* TYPE is a member of hwCryptoAllocTypes */
#define HW_FREE(PART,PTR,TYPE)                  DIGI_FREE(PTR)
#endif


/*------------------------------------------------------------------*/

#if (defined(__HARDWARE_ACCEL_PROTOTYPES__))
MOC_EXTERN sbyte4 HARDWARE_ACCEL_INIT(void);
MOC_EXTERN sbyte4 HARDWARE_ACCEL_UNINIT(void);
MOC_EXTERN sbyte4 HARDWARE_ACCEL_OPEN_CHANNEL(enum moduleNames moduleId, hwAccelDescr *pHwAccelCookie);
MOC_EXTERN sbyte4 HARDWARE_ACCEL_CLOSE_CHANNEL(enum moduleNames moduleId, hwAccelDescr *pHwAccelCookie);
#elif (defined(__ENABLE_DIGICERT_HARNESS__))

#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../harness/harness.h"

#define HARDWARE_ACCEL_INIT()                   HARNESS_init()
#define HARDWARE_ACCEL_UNINIT()                 HARNESS_uninit()
#define HARDWARE_ACCEL_OPEN_CHANNEL(x,y)        HARNESS_openChannel(x,y,16,16)
#define HARDWARE_ACCEL_CLOSE_CHANNEL(x,y)       HARNESS_closeChannel(x,y)
#else
#define HARDWARE_ACCEL_INIT()                   0
#define HARDWARE_ACCEL_UNINIT()                 0
#define HARDWARE_ACCEL_OPEN_CHANNEL(x,y)        ((*(y)) = 0)
#define HARDWARE_ACCEL_CLOSE_CHANNEL(x,y)       ((*(y)) = 0)
#endif /* __HARDWARE_ACCEL_PROTOTYPES__ */


/*------------------------------------------------------------------*/

#if defined(__HW_OFFLOAD_SINGLE_PASS_SUPPORT__)
MOC_EXTERN sbyte4 HWOFFLOAD_doSinglePassDecryption(MOC_SYM(hwAccelDescr hwAccelCtx) enum moduleNames protocol, typeForSinglePass singlePassInCookie,  ubyte4 protocolVersion, void* pSymCipherCtx, ubyte* pHashKey, ubyte4 hashKeyLength, ubyte* pHashData, ubyte4 hashDataLength, ubyte* pCryptData, ubyte4 cryptDataLength, ubyte *pCryptDataOut, ubyte* pCipherIV, ubyte4 cipherIvlength, ubyte* pMacOut, ubyte4 macHashSize, ubyte4* pRetVerfied);
MOC_EXTERN sbyte4 HWOFFLOAD_doSinglePassEncryption(MOC_SYM(hwAccelDescr hwAccelCtx) enum moduleNames protocol, typeForSinglePass singlePassOutCookie, ubyte4 protocolVersion, void* pSymCipherCtx, ubyte *pHashKey, ubyte4 hashKeyLength, ubyte* pHashData, ubyte4 hashDataLength, ubyte* pCryptData, ubyte4 cryptDataLength, ubyte *pCryptDataOut, ubyte* pCipherIV, ubyte4 cipherIvlength, ubyte4 macHashSize, ubyte4 padLength);
#endif

#if (defined(__SSL_SINGLE_PASS_SUPPORT__) && defined(__SSL_SINGLE_PASS_DECRYPT_ADJUST_SSL_RECORD_SIZE_SUPPORT__))
MOC_EXTERN sbyte4 HWOFFLOAD_doQuickBlockDecrypt(MOC_SYM(hwAccelDescr hwAccelCookie) typeForSinglePass singlePassInCookie, void* pSymCipherCtx, ubyte* pCipherIV, ubyte4 cipherIvlength, ubyte* pCryptData, ubyte* pMacOut);
#endif

/*----------------------------------------------------------------------------*/

/* If some hardware accelerator is defined, we make these calls. If no
 * accelerator is defined, the macros do nothing.
 * Note that these only work if the coding style follows the goto exit paradigm.
 */
#if defined(__HARDWARE_ACCEL_PROTOTYPES__)

/**
 * @def      MOC_HARDWARE_ACCEL_INIT(_status)
 * @details  This macro will initialize the hardware accelerator if available.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 *
 * @par Flags
 * To enable this macro, the following flag \b must be defined
 *   + \c \__HARDWARE_ACCEL_PROTOTYPES__
 */
#define MOC_HARDWARE_ACCEL_INIT(_status)                                       \
    _status = (MSTATUS)HARDWARE_ACCEL_INIT ();                                 \
    if (OK != _status)                                                         \
      goto exit;

/**
 * @def      MOC_HARDWARE_ACCEL_UNINIT(_status,_dStatus)
 * @details  This macro will uninitialize the hardware accelerator.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 * @param _dStatus  The temporary placeholder status used to check return values.
 *
 * @par Flags
 * To enable this macro, the following flag \b must be defined
 *   + \c \__HARDWARE_ACCEL_PROTOTYPES__
 */
#define MOC_HARDWARE_ACCEL_UNINIT(_status,_dStatus)                            \
    _dStatus = (MSTATUS)HARDWARE_ACCEL_UNINIT ();                              \
    if (OK != _dStatus)                                                        \
      _status = _dStatus;

#define MOC_HARDWARE_ACCEL_OPEN_CHANNEL(_status,_moduleId,_pHwCtx) \
    _status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL((_moduleId),(_pHwCtx)); \
    if (OK != _status) \
      goto exit;

#define MOC_HARDWARE_ACCEL_CLOSE_CHANNEL(_moduleId,_pHwCtx) \
    HARDWARE_ACCEL_CLOSE_CHANNEL((_moduleId),(_pHwCtx));

#else

#define MOC_HARDWARE_ACCEL_INIT(_status)
#define MOC_HARDWARE_ACCEL_UNINIT(_status,_dStatus)
#define MOC_HARDWARE_ACCEL_OPEN_CHANNEL(_status,_moduleId,_pHwCtx)
#define MOC_HARDWARE_ACCEL_CLOSE_CHANNEL(_moduleId,_pHwCtx)

#endif /* defined (__HARDWARE_ACCEL_PROTOTYPES__) */
#endif /* __HW_ACCEL_HEADER__ */

