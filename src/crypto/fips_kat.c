/*
 * fips_kat.c
 *
 * FIPS 140-3 Self Test Compliance
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

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/debug_console.h"
#include "../common/memory_debug.h"
#include "../crypto/crypto.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ecb.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/aes_ccm.h"
#include "../crypto/aes_cmac.h"
#include "../crypto/aes_xts.h"
#include "../crypto/gcm.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/sha3.h"
#include "../crypto/hmac.h"
#include "../crypto/hmac_kdf.h"
#include "../crypto/dh.h"
#include "../crypto/cryptodecl.h"
#include "../crypto/rsa.h"
#include "../crypto/dsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primefld_priv.h"
#include "../crypto/primeec.h"
#include "../crypto/ecc.h"
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
#include "../crypto/ecc_edwards.h"
#include "../crypto/ecc_edwards_dh.h"
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */
#include "../crypto/nist_rng.h"
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#include "../harness/harness.h"
#ifdef __ENABLE_DIGICERT_PQC__
#include "../crypto/pqc/mlkem.h"
#include "../crypto/pqc/mldsa.h"
#include "../crypto/pqc/slhdsa.h"
#endif /* __ENABLE_DIGICERT_PQC__ */

#if defined(__RTOS_LINUX__) || defined(__RTOS_ANDROID__)
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
#include <stdio.h>
#define __DIGICERT_LINUX_SHARED_LIBRARY__
#else
#include <linux/string.h>
#include <linux/slab.h>
#endif
#endif

#ifdef __RTOS_VXWORKS__
#include <stdio.h>
#endif

#ifdef __RTOS_WIN32__
#include <stdio.h>
/* Conflicts w/ def in WinNT.h */
#ifdef CR
#undef CR
#endif
#include <Windows.h>
#include <string.h>
#include <tchar.h>
#endif

#ifdef __RTOS_WINCE__
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <tchar.h>
#endif

FIPS_TESTLOG_IMPORT;

/*------------------------------------------------------------------*/

/* Supply the algorithm logic with a stream of pre-determined bits, in
 * place of an RNG source, for testing.
 */
typedef struct
{
    ubyte  *pBuf;
    ubyte4 offset;
    ubyte4 capacity;
} rng_buffer;

static sbyte4 FIPS_KAT_rngFun_Echo(void* rngFunArg, ubyte4 length, ubyte *buffer)
{
    MSTATUS status = ERR_BAD_LENGTH;
    rng_buffer* src = (rng_buffer*)rngFunArg;

    /* Running out of bytes? */
    if (length + src->offset > src->capacity)
        return status;

    /* Copy the requested number of bytes */
    status = DIGI_MEMCPY((void*)buffer, (void*)(src->pBuf + src->offset), length);
    src->offset += length;

    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN volatile FIPSStartupStatus sCurrStatus; /* What has passed (or not). */

static const BulkHashAlgo SHA1Suite =
{
    SHA1_RESULT_SIZE, SHA1_BLOCK_SIZE, SHA1_allocDigest, SHA1_freeDigest,
    (BulkCtxInitFunc)SHA1_initDigest, (BulkCtxUpdateFunc)SHA1_updateDigest, (BulkCtxFinalFunc)SHA1_finalDigest, NULL, NULL, NULL, ht_sha1
};

#if (!defined(__DISABLE_DIGICERT_SHA224__))
static const BulkHashAlgo SHA224Suite =
{
    SHA224_RESULT_SIZE, SHA224_BLOCK_SIZE, SHA224_allocDigest, SHA224_freeDigest,
    (BulkCtxInitFunc)SHA224_initDigest, (BulkCtxUpdateFunc)SHA224_updateDigest, (BulkCtxFinalFunc)SHA224_finalDigest, NULL, NULL, NULL, ht_sha224
};
#endif

#if (!defined(__DISABLE_DIGICERT_SHA256__))
static const BulkHashAlgo SHA256Suite =
{
    SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
    (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA256_finalDigest, NULL, NULL, NULL, ht_sha256
};
#endif

#if (!defined(__DISABLE_DIGICERT_SHA384__))
static const BulkHashAlgo SHA384Suite =
{
    SHA384_RESULT_SIZE, SHA384_BLOCK_SIZE, SHA384_allocDigest, SHA384_freeDigest,
    (BulkCtxInitFunc)SHA384_initDigest, (BulkCtxUpdateFunc)SHA384_updateDigest, (BulkCtxFinalFunc)SHA384_finalDigest, NULL, NULL, NULL, ht_sha384
};
#endif

#if (!defined(__DISABLE_DIGICERT_SHA512__))
static const BulkHashAlgo SHA512Suite =
{
    SHA512_RESULT_SIZE, SHA512_BLOCK_SIZE, SHA512_allocDigest, SHA512_freeDigest,
    (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest, (BulkCtxFinalFunc)SHA512_finalDigest, NULL, NULL, NULL, ht_sha512
};
#endif

#if defined(__ENABLE_DIGICERT_FIPS_SHA3__)
static MSTATUS SHA3_initDigest224(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx)
{
    return SHA3_initDigest(MOC_HASH(hwAccelCtx) (SHA3_CTX *) ctx, MOCANA_SHA3_MODE_SHA3_224);
}

static const BulkHashAlgo SHA3_224Suite =
{
    SHA3_224_RESULT_SIZE, SHA3_224_BLOCK_SIZE, SHA3_allocDigest, SHA3_freeDigest,
    SHA3_initDigest224, (BulkCtxUpdateFunc)SHA3_updateDigest, (BulkCtxFinalFunc) SHA3_finalDigest,
    NULL, NULL, NULL, ht_sha3_224
};

static MSTATUS SHA3_initDigest256(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx)
{
    return SHA3_initDigest(MOC_HASH(hwAccelCtx) (SHA3_CTX *) ctx, MOCANA_SHA3_MODE_SHA3_256);
}

static const BulkHashAlgo SHA3_256Suite =
{
    SHA3_256_RESULT_SIZE, SHA3_256_BLOCK_SIZE, SHA3_allocDigest, SHA3_freeDigest,
    SHA3_initDigest256, (BulkCtxUpdateFunc)SHA3_updateDigest, (BulkCtxFinalFunc) SHA3_finalDigest,
    NULL, NULL, NULL, ht_sha3_256
};

static MSTATUS SHA3_initDigest384(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx)
{
    return SHA3_initDigest(MOC_HASH(hwAccelCtx) (SHA3_CTX *) ctx, MOCANA_SHA3_MODE_SHA3_384);
}

static const BulkHashAlgo SHA3_384Suite =
{
    SHA3_384_RESULT_SIZE, SHA3_384_BLOCK_SIZE, SHA3_allocDigest, SHA3_freeDigest,
    SHA3_initDigest384, (BulkCtxUpdateFunc)SHA3_updateDigest, (BulkCtxFinalFunc) SHA3_finalDigest,
    NULL, NULL, NULL, ht_sha3_384
};

static MSTATUS SHA3_initDigest512(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx)
{
    return SHA3_initDigest(MOC_HASH(hwAccelCtx) (SHA3_CTX *) ctx, MOCANA_SHA3_MODE_SHA3_512);
}

static const BulkHashAlgo SHA3_512Suite =
{
    SHA3_512_RESULT_SIZE, SHA3_512_BLOCK_SIZE, SHA3_allocDigest, SHA3_freeDigest,
    SHA3_initDigest512, (BulkCtxUpdateFunc)SHA3_updateDigest, (BulkCtxFinalFunc) SHA3_finalDigest,
    NULL, NULL, NULL, ht_sha3_512

};

#endif /* defined(__ENABLE_DIGICERT_FIPS_SHA3__) */

static const BulkEncryptionAlgo AESECBSuite =
{
    AES_BLOCK_SIZE,
    (CreateBulkCtxFunc)CreateAESECBCtx, (DeleteBulkCtxFunc)DeleteAESECBCtx, (CipherFunc)DoAESECB
};

static const BulkEncryptionAlgo AESCBCSuite =
{
    AES_BLOCK_SIZE,
    (CreateBulkCtxFunc)CreateAESCtx, (DeleteBulkCtxFunc)DeleteAESCtx, (CipherFunc)DoAES
};

static const BulkEncryptionAlgo AESCFBSuite =
{
    AES_BLOCK_SIZE,
    (CreateBulkCtxFunc)CreateAESCFBCtx, (DeleteBulkCtxFunc)DeleteAESCtx, (CipherFunc)DoAES
};

static const BulkEncryptionAlgo AESOFBSuite =
{
    AES_BLOCK_SIZE,
    (CreateBulkCtxFunc)CreateAESOFBCtx, (DeleteBulkCtxFunc)DeleteAESCtx, (CipherFunc)DoAES
};

static const BulkEncryptionAlgo AESCTRSuite =
{
    AES_BLOCK_SIZE,
    (CreateBulkCtxFunc)CreateAESCTRCtx, (DeleteBulkCtxFunc)DeleteAESCTRCtx, (CipherFunc)DoAESCTR
};


static const BulkEncryptionAlgo TDESCBCSuite =
{
    THREE_DES_BLOCK_SIZE,
    (CreateBulkCtxFunc)Create3DESCtx, (DeleteBulkCtxFunc)Delete3DESCtx, (CipherFunc)Do3DES
};

typedef struct
{

    ubyte   key[32];
    ubyte   tweak[16];
    ubyte   plainText[32];
    ubyte   cipherText[32];
} aesXtsTestPacketDescr;

static aesXtsTestPacketDescr AES_XTS_TESTCASE =
{
    /* 32 bytes key */
    { 0xa6,0x41,0xc6,0x36,0x21,0x95,0x93,0x5b,0x07,0x4f,0xbd,0x71,0xc5,0xa4,0xa9,0xb8,
        0x45,0x36,0x81,0x9c,0xa3,0x8f,0x06,0x67,0x10,0x19,0x5a,0xc2,0xbf,0x10,0xbf,0x2a },
    /* 16 byte tweak value */
    { 0x4f,0xab,0x20,0x5f,0x60,0xf2,0x8a,0x2b,0xd0,0x5d,0xa4,0x84,0x6b,0xf2,0x05,0x60 },
    /* 32 bytes plaintext */
    { 0x16,0x2a,0x8e,0x94,0xcd,0x5c,0x71,0x63,0xc5,0x9e,0xc0,0x84,0x30,0x69,0x0d,0xdf,
        0xc4,0x10,0x01,0xdf,0x59,0x26,0x45,0xa4,0xc9,0xc1,0xc9,0x16,0x09,0x1d,0x58,0x15 },
    /* corr. 32 byte ciphertext */
    { 0x47,0x93,0x93,0x55,0x55,0x96,0xbb,0x45,0x4e,0x0d,0xd0,0x49,0xdc,0xe5,0x52,0xf1,
        0x42,0x6c,0x6e,0xf1,0x63,0x00,0x28,0xdd,0x28,0x08,0x38,0xc3,0x93,0x9a,0xe6,0xb3 }
};

/*------------------------------------------------------------------*/

typedef struct aesCcmTestPacketDescr
{
    ubyte4          keyLen;
    ubyte           key[32];
    ubyte4          nonceLen;
    ubyte           nonce[16];
    ubyte4          packetLen;
    ubyte4          packetHeaderLen;
    ubyte           packet[36];
    ubyte4          resultLen;
    ubyte           result[50];

} aesCcmTestPacketDescr;

static aesCcmTestPacketDescr mAesCcmTestPackets =
{
     16,        /* key */
     {0xD7,0x82,0x8D,0x13, 0xB2,0xB0,0xBD,0xC3, 0x25,0xA7,0x62,0x36, 0xDF,0x93,0xCC,0x6B},
     13,        /* nonce */
     {0x00,0x8D,0x49,0x3B, 0x30,0xAE,0x8B,0x3C, 0x96,0x96,0x76,0x6C, 0xFA},
     33, 12,    /* packet */
     {0x6E,0x37,0xA6,0xEF, 0x54,0x6D,0x95,0x5D, 0x34,0xAB,0x60,0x59, 0xAB,0xF2,0x1C,0x0B,
      0x02,0xFE,0xB8,0x8F, 0x85,0x6D,0xF4,0xA3, 0x73,0x81,0xBC,0xE3, 0xCC,0x12,0x85,0x17,
      0xD4},
     43,        /* result */
     {0x6E,0x37,0xA6,0xEF, 0x54,0x6D,0x95,0x5D, 0x34,0xAB,0x60,0x59, 0xF3,0x29,0x05,0xB8,
      0x8A,0x64,0x1B,0x04, 0xB9,0xC9,0xFF,0xB5, 0x8C,0xC3,0x90,0x90, 0x0F,0x3D,0xA1,0x2A,
      0xB1,0x6D,0xCE,0x9E, 0x82,0xEF,0xA1,0x6D, 0xA6,0x20,0x59}
};

/*------------------------------------------------------------------*/


/*------------------------------------------------------------------*/

typedef struct
{
    ubyte4  entropyInputLen;
    ubyte   entropyInput[48];
    ubyte4  nonceLen;
    ubyte   nonce[16];
    ubyte4  personalizationStrLen;
    ubyte   personalizationStr[48];
    ubyte4  additionalInput1Len;
    ubyte   additionalInput1[48];
    ubyte4  entropyInputPR1Len;
    ubyte   entropyInputPR1[48];
    ubyte4  additionalInput2Len;
    ubyte   additionalInput2[48];
    ubyte4  entropyInputPR2Len;
    ubyte   entropyInputPR2[48];
    ubyte4  resultLen;
    ubyte   result[32];
} NIST_DRBG_TestVectorPR;

static MSTATUS
FIPS_NIST_CTRDRBG_DoKAT(sbyte4 useDf, const NIST_DRBG_TestVectorPR *pTest, sbyte4 keyLen)
{
    MSTATUS             status = OK;
    sbyte4              cmpRes;
    randomContext*      pCtx = NULL;
    ubyte               result[256] = { 0 };
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
    hwAccelDescr        hwAccelCtx = 0;
#endif
    /* create appropriate context */
    if(useDf)
    {
        status = NIST_CTRDRBG_newDFContext( MOC_SYM(hwAccelCtx)
                                    &pCtx, keyLen, pTest->resultLen,
                                    pTest->entropyInput, pTest->entropyInputLen,
                                    pTest->nonce, pTest->nonceLen,
                                    pTest->personalizationStr, pTest->personalizationStrLen);
    }
    else
    {
        status = NIST_CTRDRBG_newContext( MOC_SYM(hwAccelCtx)
                                    &pCtx,
                                    pTest->entropyInput, 32, pTest->resultLen,
                                    pTest->personalizationStr, pTest->personalizationStrLen);
    }

    if (OK > status)
        goto exit;

    /* predictionResistance */
    /* generate with PR = reseed + normal generate */

    /* reseed, generate and throw away first time */
    status = NIST_CTRDRBG_reseed( MOC_SYM(hwAccelCtx)
                pCtx, pTest->entropyInputPR1, pTest->entropyInputPR1Len,
                pTest->additionalInput1, pTest->additionalInput1Len);

    if (OK > status)
        goto exit;

    if (OK > (status = NIST_CTRDRBG_generate( MOC_SYM(hwAccelCtx)
                pCtx, NULL, 0, result, pTest->resultLen * 8)))
    {
        goto exit;
    }

    /* reseed, regenerate and print */
    status = NIST_CTRDRBG_reseed( MOC_SYM(hwAccelCtx)
                pCtx, pTest->entropyInputPR2, pTest->entropyInputPR2Len,
                pTest->additionalInput2, pTest->additionalInput2Len);

    if (OK > status)
        goto exit;

    if (OK > (status = NIST_CTRDRBG_generate( MOC_SYM(hwAccelCtx)
                pCtx, NULL, 0, result, pTest->resultLen * 8)))
    {
        goto exit;
    }

    if (FIPS_FORCE_FAIL_DRBG_CTR_TEST)
    {
        *result ^= 0x01;
    }

    if (OK != DIGI_CTIME_MATCH(result, pTest->result, pTest->resultLen, &cmpRes))
    {
        status = ERR_FIPS_NISTRNG_KAT_FAILED;
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_FIPS_NISTRNG_KAT_FAILED;
        goto exit;
    }

exit:
    NIST_CTRDRBG_deleteContext( MOC_SYM(hwAccelCtx) &pCtx);

    setFIPS_Status_Once(FIPS_ALGO_DRBG_CTR, status);

    return status;
}

 /*------------------------------------------------------------------*/

/* NIST SP 800-90 DRBG testvectors */
static const NIST_DRBG_TestVectorPR kCTR_DRBG_AES256_DF_PR =
{
    /* CTR_DRBG.txt */
    /* [AES-256 use df] */
    /* [PredictionResistance = True] */
    /* [EntropyInputLen = 256] */
    /* [NonceLen = 128] */
    /* [PersonalizationStringLen = 256] */
    /* [AdditionalInputLen = 256] */
    /* COUNT = 0 */
    32,
    {0x2a,0x02,0xbe,0xaa, 0xba,0xb4,0x6a,0x73, 0x53,0x85,0xa9,0x2a, 0xae,0x4a,0xdc,0xeb,
     0xe8,0x07,0xfb,0xf3, 0xbc,0xe3,0xf4,0x2e, 0x00,0x53,0x46,0x00, 0x64,0x80,0xdd,0x57},    /* EntropyInput */
    16,
    {0x2c,0x86,0xa2,0xf9, 0x70,0xb5,0xca,0xd3, 0x9a,0x08,0xdc,0xb6, 0x6b,0xce,0xe5,0x05},    /* Nonce */
    32,
    {0xdb,0x6c,0xe1,0x84, 0xbe,0x07,0xae,0x55, 0x4e,0x34,0x5d,0xb8, 0x47,0x98,0x85,0xe0,
     0x3d,0x3e,0x9f,0x60, 0xfa,0x1c,0x7d,0x57, 0x19,0xe5,0x09,0xdc, 0xe2,0x10,0x41,0xab},    /* PersonalizationString */
    32,
    {0x1d,0xc3,0x11,0x93, 0xcb,0xc4,0xf6,0xbb, 0x57,0xb0,0x09,0x70, 0xb9,0xc6,0x05,0x86,
     0x4e,0x75,0x95,0x7d, 0x3d,0xec,0xce,0xb4, 0x0b,0xe4,0xef,0xd1, 0x7b,0xab,0x56,0x6f},    /* AdditionalInput */
    32,
    {0x8f,0xb9,0xab,0xf9, 0x33,0xcc,0xbe,0xc6, 0xbd,0x8b,0x61,0x5a, 0xec,0xc6,0x4a,0x5b,
     0x03,0x21,0xe7,0x37, 0x03,0x02,0xbc,0xa5, 0x28,0xb9,0xfe,0x7a, 0xa8,0xef,0x6f,0xb0},    /* EntropyInputPR */
    32,
    {0xd6,0x98,0x63,0x48, 0x94,0x9f,0x26,0xf7, 0x1f,0x44,0x13,0x23, 0xa7,0xde,0x09,0x12,
     0x90,0x04,0xce,0xbc, 0xac,0x82,0x70,0x58, 0xba,0x7d,0xdc,0x25, 0x1e,0xe4,0xbf,0x7c},    /* AdditionalInput */
    32,
    {0xe5,0x04,0xef,0x7c, 0x8d,0x02,0xd7,0x68, 0x95,0x4c,0x64,0x34, 0x30,0x3a,0xcb,0x07,
     0xc9,0x0a,0xef,0x26, 0xc6,0x57,0x43,0xfb, 0x7d,0xbe,0xe2,0x61, 0x75,0xcd,0xee,0x34},    /* EntropyInputPR */
    16,
    {0x75,0x6d,0x16,0xef, 0x14,0xae,0xd9,0xc2, 0x28,0x0b,0x66,0xff, 0x20,0x1f,0x21,0x33}     /* ReturnedBits */
};

/*------------------------------------------------------------------*/

static const NIST_DRBG_TestVectorPR kCTR_DRBG_AES256_NoDF_PR =
{
    /* CTR_DRBG.txt */
    /* [AES-256 no df] */
    /* [PredictionResistance = True] */
    /* [EntropyInputLen = 384] */
    /* [NonceLen = 128] */
    /* [PersonalizationStringLen = 384] */
    /* [AdditionalInputLen = 384] */
    /* COUNT = 0 */
    48,
    {0x7e,0x83,0x3f,0xa6, 0x39,0xdc,0xcb,0x38, 0x17,0x6a,0xa3,0x59, 0xa9,0x8c,0x1f,0x50,
     0xd3,0xdb,0x34,0xdd, 0xa4,0x39,0x65,0xe4, 0x77,0x17,0x08,0x57, 0x49,0x04,0xbd,0x68,
     0x5c,0x7d,0x2a,0xee, 0x0c,0xf2,0xfb,0x16, 0xef,0x16,0x18,0x4d, 0x32,0x6a,0x26,0x6c},    /* EntropyInput */
    16,
    {0xa3,0x8a,0xa4,0x6d, 0xa6,0xc1,0x40,0xf8, 0xa3,0x02,0xf1,0xac, 0xf3,0xea,0x7f,0x2d},    /* Nonce */
    48,
    {0xc0,0x54,0x1e,0xa5, 0x93,0xd9,0x8b,0x2b, 0x43,0x15,0x2c,0x07, 0x26,0x25,0xc7,0x08,
     0xf0,0xb3,0x4b,0x44, 0x96,0xfe,0xc7,0xc5, 0x64,0x27,0xaa,0x78, 0x5b,0xbc,0x40,0x51,
     0xce,0x89,0x6b,0xc1, 0x3f,0x9c,0xa0,0x5c, 0x75,0x98,0x24,0xc5, 0xe1,0x3e,0x86,0xdb},    /* PersonalizationString */
    48,
    {0x0e,0xe3,0x0f,0x07, 0x90,0xe2,0xde,0x20, 0xb6,0xf7,0x6f,0xef, 0x87,0xdc,0x7f,0xc4,
     0x0d,0x9d,0x05,0x31, 0x91,0x87,0x8c,0x9a, 0x19,0x53,0xd2,0xf8, 0x20,0x91,0xa0,0xef,
     0x97,0x59,0xea,0x12, 0x1b,0x2f,0x29,0x74, 0x76,0x35,0xf7,0x71, 0x5a,0x96,0xeb,0xbc},    /* AdditionalInput */
    48,
    {0x37,0x26,0x9a,0xa6, 0x28,0xe0,0x35,0x78, 0x12,0x42,0x44,0x5c, 0x55,0xbc,0xc8,0xb6,
     0x1f,0x24,0xf3,0x32, 0x88,0x02,0x69,0xa7, 0xed,0x1d,0xb7,0x4d, 0x8b,0x44,0x12,0x21,
     0x5e,0x60,0x53,0x96, 0x3b,0xb9,0x31,0x7f, 0x2a,0x87,0xbf,0x3c, 0x07,0xbb,0x27,0x22},    /* EntropyInputPR */
    48,
    {0xf1,0x24,0x35,0xa6, 0x8c,0x93,0x28,0x7e, 0x84,0xea,0x3d,0x27, 0x44,0x18,0xc9,0x13,
     0x73,0x49,0xb9,0x83, 0x79,0x15,0x29,0x53, 0x2f,0xef,0x43,0x06, 0xe7,0xcb,0x5c,0x0f,
     0x9f,0x10,0x4c,0x60, 0x7f,0xbf,0x0c,0x37, 0x9b,0xe4,0x94,0x26, 0xe5,0x3b,0xf5,0x63},    /* AdditionalInput */
    48,
    {0xdc,0x91,0x48,0x11, 0x63,0x7b,0x79,0x41, 0x36,0x8c,0x4f,0xe2, 0xc9,0x84,0x04,0x9c,
     0xdc,0x5b,0x6c,0x8d, 0x61,0x52,0xea,0xfa, 0x92,0x3b,0xb4,0x36, 0x4c,0x06,0x4a,0xd1,
     0xb1,0x8e,0x32,0x03, 0xfd,0xa4,0xf7,0x5a, 0xa6,0x5c,0x63,0xa1, 0xb9,0x96,0xfa,0x12},    /* EntropyInputPR */
    16,
    {0x1c,0xba,0xfd,0x48, 0x0f,0xf4,0x85,0x63, 0xd6,0x7d,0x91,0x14, 0xef,0x67,0x6b,0x7f}     /* ReturnedBits */
};

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_nistRngKat(void)
{
    MSTATUS status = OK;

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_nistRngKat", "NIST-RNG");


    if (OK > (status = FIPS_NIST_CTRDRBG_DoKAT(1, &kCTR_DRBG_AES256_DF_PR, 32)))
        goto exit;

    if (OK > (status = FIPS_NIST_CTRDRBG_DoKAT(0, &kCTR_DRBG_AES256_NoDF_PR, 32)))
        goto exit;

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_nistRngKat", "NIST-RNG", status);

    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_FIPS_RSA__
#if !defined( __DISABLE_DIGICERT_RSA_SIGN__) && \
    !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__) && \
    !defined(__ENABLE_DIGICERT_PKCS11_CRYPTO__)

#define MAX_KEYBLOBLEN 2000  /* More than enough */

static ubyte test_PrivateKeyBlob[] = {
  0x02, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01,
  0x00, 0xac, 0x78, 0x6c, 0x64, 0xd9, 0x3e, 0x8f, 0xd4, 0xf4, 0xc1, 0x67,
  0x5c, 0xaa, 0x7a, 0x3f, 0x1c, 0x64, 0x0b, 0x63, 0xb2, 0x45, 0xbf, 0x0c,
  0x40, 0xb8, 0x99, 0xea, 0x05, 0x2f, 0xaf, 0xfb, 0xa0, 0xbc, 0x33, 0xf9,
  0xa4, 0x8f, 0x8c, 0xcb, 0x6f, 0xd3, 0x53, 0xf8, 0x39, 0x09, 0xf3, 0xd2,
  0x40, 0x8f, 0xab, 0x74, 0x14, 0x92, 0x0d, 0x4b, 0xe2, 0x60, 0xaf, 0xfd,
  0x8d, 0xc2, 0x97, 0x59, 0x20, 0xfc, 0xb6, 0x25, 0x2c, 0x6f, 0x05, 0xa8,
  0x24, 0x80, 0xe8, 0xa1, 0xa6, 0x14, 0x1e, 0xed, 0xb9, 0x0e, 0xbd, 0x73,
  0xe5, 0xd8, 0x0b, 0x1c, 0x67, 0xdf, 0x3b, 0x2f, 0x40, 0x3b, 0xb2, 0xd7,
  0xa0, 0x24, 0x73, 0x5f, 0x80, 0x47, 0x42, 0x57, 0x8a, 0x72, 0x17, 0xe8,
  0x98, 0xaa, 0xfe, 0xe8, 0xe1, 0x98, 0x8f, 0x5b, 0x06, 0x9d, 0xe7, 0x23,
  0xc9, 0x09, 0x5a, 0x0d, 0x53, 0x8e, 0xf5, 0x19, 0x13, 0x9a, 0x8b, 0x4b,
  0x15, 0x93, 0xd8, 0x27, 0xa5, 0xcf, 0xa0, 0xc0, 0xdd, 0x1f, 0x55, 0x6d,
  0x4c, 0xf8, 0x93, 0xd9, 0x4a, 0xd2, 0x42, 0x18, 0x98, 0xa2, 0x17, 0x73,
  0x9b, 0x6f, 0x8f, 0xa4, 0x09, 0x24, 0x89, 0x6f, 0xef, 0x84, 0x96, 0xeb,
  0x37, 0x7c, 0xbf, 0x0d, 0xa9, 0x0f, 0x5e, 0x11, 0xe4, 0x6c, 0xfb, 0x7b,
  0x43, 0x82, 0x58, 0x94, 0xe2, 0x90, 0x31, 0x21, 0xb4, 0xfb, 0xba, 0x4a,
  0x9b, 0x3a, 0xa9, 0x75, 0xe0, 0x1f, 0xbd, 0xb2, 0x72, 0xae, 0xd1, 0x0e,
  0xe7, 0xe9, 0x26, 0x07, 0xcd, 0x18, 0x34, 0x9f, 0x4d, 0x27, 0x08, 0x39,
  0x25, 0xf4, 0xf1, 0xb9, 0x02, 0xe6, 0x43, 0x37, 0x75, 0x22, 0x16, 0x5f,
  0x31, 0x63, 0xab, 0xca, 0x71, 0xaa, 0x57, 0x50, 0x39, 0xec, 0x4a, 0xa0,
  0x29, 0x10, 0x21, 0x83, 0xcc, 0x9e, 0xe8, 0x72, 0xfd, 0x03, 0x6a, 0xe8,
  0x7c, 0x9d, 0x40, 0x21, 0x9d, 0x00, 0x00, 0x00, 0x80, 0xf8, 0x0f, 0x3f,
  0x62, 0x4f, 0xd4, 0xda, 0xdd, 0xee, 0x4a, 0xc2, 0x60, 0x31, 0xe1, 0x2f,
  0xbb, 0xa6, 0xaf, 0xca, 0xca, 0xfa, 0xf7, 0xb4, 0x01, 0xbc, 0x0d, 0xfb,
  0xb0, 0x74, 0xb3, 0x43, 0x3c, 0x2e, 0xc0, 0x53, 0x23, 0xfe, 0x57, 0x63,
  0xca, 0xba, 0x82, 0x7d, 0xe5, 0xef, 0x38, 0xe3, 0xbf, 0x0e, 0xd5, 0x28,
  0xd6, 0x61, 0x4d, 0x37, 0x24, 0x7e, 0x33, 0x6b, 0xec, 0xb8, 0xda, 0x80,
  0xe2, 0x25, 0x24, 0x84, 0xca, 0xe3, 0xd1, 0x55, 0xa9, 0x7c, 0x4a, 0xfc,
  0x99, 0xcc, 0x91, 0x43, 0x52, 0x19, 0xdc, 0xd9, 0x17, 0xd4, 0x28, 0x11,
  0x65, 0x97, 0xa3, 0x30, 0x0c, 0x15, 0x50, 0x14, 0x60, 0x5a, 0x3f, 0x23,
  0x9d, 0xe2, 0xa0, 0xaf, 0x73, 0x7f, 0x8e, 0x7a, 0x7f, 0x3a, 0x9d, 0x4f,
  0xa9, 0x21, 0x76, 0x71, 0x0d, 0x7f, 0xfc, 0x1d, 0x15, 0x9b, 0xd8, 0x59,
  0x74, 0xb7, 0x8e, 0xd6, 0x11, 0x00, 0x00, 0x00, 0x80, 0xb1, 0xfd, 0xc0,
  0x78, 0x89, 0x77, 0x99, 0xf4, 0x8b, 0x39, 0x7c, 0xe9, 0xda, 0xb1, 0xd9,
  0x2e, 0x8c, 0x8c, 0x05, 0xc0, 0x59, 0x61, 0xb7, 0x8b, 0x03, 0xb6, 0x1f,
  0xa0, 0x53, 0xb8, 0x2c, 0xd1, 0x2a, 0x6e, 0x33, 0x40, 0x45, 0x52, 0xdb,
  0x0e, 0x1d, 0xea, 0xd5, 0xe2, 0x4f, 0x59, 0x5e, 0x69, 0x0c, 0xb6, 0xa9,
  0xfb, 0x5a, 0x6d, 0xb5, 0xe3, 0x81, 0x88, 0x7f, 0x7d, 0x08, 0xde, 0x7f,
  0x2d, 0xfa, 0xcd, 0x8b, 0x09, 0x12, 0x69, 0x19, 0xbd, 0xe7, 0x53, 0x1b,
  0x6a, 0x58, 0x35, 0x33, 0x20, 0x74, 0xa7, 0xc0, 0xc7, 0xb1, 0x92, 0x56,
  0x1e, 0xf3, 0x7c, 0x52, 0xa4, 0xf9, 0x6e, 0x8d, 0xdc, 0x5d, 0x1a, 0x51,
  0x1e, 0x2c, 0xba, 0x37, 0x34, 0xc8, 0x45, 0xe7, 0xce, 0x71, 0xc2, 0x54,
  0x34, 0x38, 0xbd, 0xdf, 0x99, 0x65, 0x5d, 0xe3, 0x00, 0x4d, 0xfe, 0x31,
  0xd9, 0xfb, 0xa5, 0x56, 0xcd, 0x00, 0x00, 0x00, 0x80, 0xf4, 0x1b, 0xa5,
  0x27, 0x6d, 0x22, 0x2d, 0x84, 0x0a, 0x94, 0xdd, 0x35, 0x66, 0xc0, 0x90,
  0x85, 0x9c, 0xa2, 0x0f, 0xf1, 0xb2, 0x09, 0x82, 0xc5, 0xd6, 0x36, 0xf8,
  0x81, 0x0c, 0x46, 0xc0, 0x9a, 0x7f, 0xf3, 0x59, 0x9d, 0xe9, 0x14, 0x3c,
  0xaa, 0xea, 0xe1, 0xb1, 0x5d, 0x4e, 0x0d, 0xf0, 0xe9, 0x3a, 0x82, 0x7f,
  0xde, 0x80, 0x00, 0x49, 0x8c, 0x8a, 0xf8, 0xb5, 0x73, 0x4d, 0xf2, 0x10,
  0xb4, 0xfb, 0x12, 0x35, 0xef, 0xa7, 0x43, 0x80, 0x85, 0xfa, 0x3f, 0x9c,
  0xd7, 0x09, 0x1d, 0xc6, 0x5f, 0x0b, 0xfe, 0x6e, 0x50, 0xe9, 0xc1, 0xc8,
  0x64, 0xee, 0x55, 0x73, 0xd9, 0xe0, 0x3b, 0x5e, 0xe1, 0xf6, 0xcd, 0x7d,
  0x92, 0x48, 0xcc, 0x11, 0xfc, 0x9a, 0x01, 0x2f, 0x00, 0xf7, 0x40, 0x89,
  0x7d, 0x09, 0xe6, 0x11, 0x98, 0xd4, 0x62, 0xd8, 0x88, 0x44, 0x46, 0x22,
  0xba, 0x1e, 0x4c, 0xdc, 0xd1, 0x00, 0x00, 0x00, 0x80, 0x71, 0xb6, 0xda,
  0x96, 0xa7, 0xcc, 0xbf, 0x91, 0x5a, 0xb9, 0x79, 0xb2, 0xb6, 0x43, 0xd5,
  0xab, 0x45, 0xa3, 0xd7, 0xb0, 0xd1, 0xe9, 0xfa, 0x27, 0x58, 0x51, 0xac,
  0xd6, 0xf3, 0x65, 0xc1, 0x4c, 0x48, 0xbd, 0x6b, 0x04, 0xee, 0xc5, 0x46,
  0xaa, 0x38, 0x36, 0xe6, 0x3a, 0xd5, 0xd3, 0x14, 0xdc, 0x2c, 0x81, 0x2f,
  0x0c, 0x24, 0xf3, 0xde, 0xb6, 0xe0, 0xf4, 0xe1, 0xee, 0x72, 0x12, 0x24,
  0x52, 0xad, 0xdf, 0x4f, 0xaa, 0x96, 0x16, 0x8b, 0x99, 0xa6, 0x06, 0x94,
  0x87, 0x56, 0x9f, 0x76, 0x70, 0x8f, 0xd6, 0xf4, 0xf5, 0x1f, 0xdf, 0x8c,
  0x21, 0xee, 0x11, 0x49, 0x83, 0x98, 0xd0, 0x26, 0xd5, 0xd8, 0xad, 0x8d,
  0x91, 0xa7, 0xa5, 0xb8, 0xcb, 0x82, 0x00, 0x17, 0x5e, 0xef, 0x92, 0xe5,
  0xd5, 0x0f, 0x43, 0x4f, 0x6d, 0x63, 0x33, 0x9e, 0x69, 0x7d, 0x6a, 0x9f,
  0x52, 0xd2, 0xd1, 0x09, 0x29, 0x00, 0x00, 0x00, 0x80, 0x18, 0x85, 0x69,
  0x3e, 0x83, 0x19, 0x40, 0x97, 0xb9, 0xec, 0xce, 0x6f, 0x26, 0x44, 0x07,
  0x48, 0x5f, 0x76, 0xbe, 0x94, 0xa2, 0xd5, 0xb2, 0xf4, 0xb1, 0xcd, 0x59,
  0xf3, 0xce, 0xdc, 0x59, 0xa9, 0xe8, 0xe3, 0x1e, 0xc6, 0xbf, 0xb0, 0x66,
  0x97, 0x40, 0xef, 0x36, 0xdf, 0x28, 0x63, 0xfa, 0xf3, 0x0f, 0x8a, 0xad,
  0x17, 0xf3, 0xf3, 0x44, 0xf7, 0x31, 0x29, 0x48, 0xdd, 0xe3, 0x59, 0xbd,
  0xa9, 0x5c, 0x3a, 0x7d, 0xf6, 0x97, 0x63, 0x4f, 0xcf, 0x13, 0xa1, 0x9f,
  0x9a, 0xe2, 0x0f, 0x89, 0xff, 0x2d, 0x4a, 0xff, 0xf7, 0x6c, 0x04, 0x22,
  0x6c, 0x6e, 0xf1, 0xd1, 0xa3, 0x18, 0xde, 0x34, 0xe0, 0x28, 0x1b, 0xc3,
  0xa3, 0xf4, 0x45, 0xf8, 0xdd, 0xe5, 0x36, 0xa0, 0xe3, 0x92, 0x47, 0x9b,
  0xf9, 0xe0, 0x12, 0x43, 0x32, 0x62, 0xde, 0xa6, 0xbd, 0x31, 0xa3, 0x64,
  0x79, 0xf0, 0xae, 0x8a, 0xfd

};

static ubyte test_PublicKeyBlob[] = {
  0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01,
  0x00, 0xac, 0x78, 0x6c, 0x64, 0xd9, 0x3e, 0x8f, 0xd4, 0xf4, 0xc1, 0x67,
  0x5c, 0xaa, 0x7a, 0x3f, 0x1c, 0x64, 0x0b, 0x63, 0xb2, 0x45, 0xbf, 0x0c,
  0x40, 0xb8, 0x99, 0xea, 0x05, 0x2f, 0xaf, 0xfb, 0xa0, 0xbc, 0x33, 0xf9,
  0xa4, 0x8f, 0x8c, 0xcb, 0x6f, 0xd3, 0x53, 0xf8, 0x39, 0x09, 0xf3, 0xd2,
  0x40, 0x8f, 0xab, 0x74, 0x14, 0x92, 0x0d, 0x4b, 0xe2, 0x60, 0xaf, 0xfd,
  0x8d, 0xc2, 0x97, 0x59, 0x20, 0xfc, 0xb6, 0x25, 0x2c, 0x6f, 0x05, 0xa8,
  0x24, 0x80, 0xe8, 0xa1, 0xa6, 0x14, 0x1e, 0xed, 0xb9, 0x0e, 0xbd, 0x73,
  0xe5, 0xd8, 0x0b, 0x1c, 0x67, 0xdf, 0x3b, 0x2f, 0x40, 0x3b, 0xb2, 0xd7,
  0xa0, 0x24, 0x73, 0x5f, 0x80, 0x47, 0x42, 0x57, 0x8a, 0x72, 0x17, 0xe8,
  0x98, 0xaa, 0xfe, 0xe8, 0xe1, 0x98, 0x8f, 0x5b, 0x06, 0x9d, 0xe7, 0x23,
  0xc9, 0x09, 0x5a, 0x0d, 0x53, 0x8e, 0xf5, 0x19, 0x13, 0x9a, 0x8b, 0x4b,
  0x15, 0x93, 0xd8, 0x27, 0xa5, 0xcf, 0xa0, 0xc0, 0xdd, 0x1f, 0x55, 0x6d,
  0x4c, 0xf8, 0x93, 0xd9, 0x4a, 0xd2, 0x42, 0x18, 0x98, 0xa2, 0x17, 0x73,
  0x9b, 0x6f, 0x8f, 0xa4, 0x09, 0x24, 0x89, 0x6f, 0xef, 0x84, 0x96, 0xeb,
  0x37, 0x7c, 0xbf, 0x0d, 0xa9, 0x0f, 0x5e, 0x11, 0xe4, 0x6c, 0xfb, 0x7b,
  0x43, 0x82, 0x58, 0x94, 0xe2, 0x90, 0x31, 0x21, 0xb4, 0xfb, 0xba, 0x4a,
  0x9b, 0x3a, 0xa9, 0x75, 0xe0, 0x1f, 0xbd, 0xb2, 0x72, 0xae, 0xd1, 0x0e,
  0xe7, 0xe9, 0x26, 0x07, 0xcd, 0x18, 0x34, 0x9f, 0x4d, 0x27, 0x08, 0x39,
  0x25, 0xf4, 0xf1, 0xb9, 0x02, 0xe6, 0x43, 0x37, 0x75, 0x22, 0x16, 0x5f,
  0x31, 0x63, 0xab, 0xca, 0x71, 0xaa, 0x57, 0x50, 0x39, 0xec, 0x4a, 0xa0,
  0x29, 0x10, 0x21, 0x83, 0xcc, 0x9e, 0xe8, 0x72, 0xfd, 0x03, 0x6a, 0xe8,
  0x7c, 0x9d, 0x40, 0x21, 0x9d

};

static ubyte expect[] = {
  0x61, 0xba, 0xfd, 0xaa, 0xf4, 0x14, 0x63, 0xf7, 0xc2, 0x4a, 0x31, 0x13,
  0xa4, 0x94, 0x4f, 0x96, 0x78, 0x0f, 0xb0, 0x0d, 0x64, 0xdd, 0x56, 0xf7,
  0xc5, 0x9d, 0x78, 0x39, 0x14, 0x02, 0xe5, 0x5a, 0xb9, 0x88, 0x56, 0x85,
  0x9d, 0xf7, 0xb3, 0x0f, 0x51, 0x30, 0xde, 0xa9, 0x74, 0xe3, 0xa3, 0xf7,
  0x5b, 0x84, 0xa2, 0x7b, 0x37, 0x9d, 0x5d, 0x97, 0x75, 0x5b, 0xad, 0xf3,
  0xb5, 0x4a, 0x58, 0x0d, 0x99, 0x23, 0x4d, 0xbc, 0x5c, 0x0b, 0x54, 0xb6,
  0x33, 0x97, 0x97, 0xd1, 0x1a, 0xab, 0x7b, 0x4a, 0x4b, 0xa2, 0x16, 0x1a,
  0x82, 0x70, 0x84, 0xed, 0x5e, 0xfe, 0x60, 0x60, 0x49, 0xb6, 0xa7, 0xeb,
  0x9e, 0x84, 0xa1, 0xe9, 0xe3, 0xe8, 0x89, 0x72, 0xe7, 0x59, 0x2f, 0x4a,
  0xe5, 0x98, 0x53, 0xc9, 0x01, 0xcc, 0xea, 0x35, 0xa1, 0xcb, 0xe3, 0x02,
  0xa1, 0x13, 0xd3, 0xdb, 0x3d, 0xad, 0x68, 0x63, 0x5b, 0x81, 0x7d, 0x9a,
  0xca, 0x1b, 0xc5, 0x79, 0x79, 0x53, 0xfe, 0x03, 0xc4, 0x48, 0x3d, 0x35,
  0x8c, 0xae, 0x2d, 0x0d, 0x22, 0x5d, 0xc7, 0x8e, 0xf0, 0x5b, 0xdf, 0xc2,
  0x89, 0x05, 0xbf, 0x58, 0x7d, 0xf5, 0x43, 0x7a, 0x0f, 0xc3, 0x3e, 0xfc,
  0x56, 0xa4, 0xfe, 0xa4, 0x18, 0x58, 0x53, 0x85, 0x91, 0x7f, 0xee, 0x43,
  0x61, 0x45, 0x07, 0xf2, 0x38, 0x38, 0xb7, 0xdd, 0x1f, 0xab, 0xb4, 0x54,
  0x72, 0xd2, 0x10, 0x55, 0xde, 0x26, 0x30, 0x7a, 0x05, 0xcf, 0x0a, 0x20,
  0xb7, 0xf8, 0xbc, 0xa7, 0xd6, 0x42, 0xcb, 0x54, 0x61, 0x8e, 0x05, 0xe8,
  0x95, 0x52, 0x33, 0x45, 0xe0, 0x34, 0x0c, 0x6d, 0xf6, 0x97, 0x57, 0xa3,
  0xfa, 0xf7, 0x15, 0x4c, 0x49, 0xe9, 0xd8, 0xf1, 0xfb, 0xa9, 0xc0, 0xe9,
  0x29, 0x0d, 0x3b, 0x3f, 0x64, 0x2a, 0xa9, 0x75, 0x2a, 0xe8, 0xc3, 0x45,
  0x10, 0xf0, 0x50, 0x03
};

MOC_EXTERN MSTATUS FIPS_rsaKat(hwAccelDescr hwAccelCtx)
{

    sbyte           testmsg[] = "We attack at dawn and plan to succeed";
    ubyte*          pCipherText = NULL;
    ubyte*          pPlainText = NULL;
    RSAKey*         pRSAKey = NULL;
    RSAKey*         pRSAPublicKey = NULL;
    vlong*          pQueue  = NULL;
    sbyte4          cipherTextLen = 0;
    ubyte4          plainTextLen = 0;
    MSTATUS         status = OK;
    ubyte*          pKeyBlob = NULL;
    sbyte4          resCmp;

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_rsaKat", "RSA");

    /* Make a RSA Key from the test_PrivateKeyBlob */
    if (NULL == (pKeyBlob = MALLOC(MAX_KEYBLOBLEN)))
    {
        status = ERR_CRYPTO;
        goto exit;
    }
    DIGI_MEMSET(pKeyBlob, 0, MAX_KEYBLOBLEN);
    DIGI_MEMCPY(pKeyBlob, test_PrivateKeyBlob, sizeof(test_PrivateKeyBlob));

    /* Make key from Key Blob */
    if (OK > (status = RSA_keyFromByteString(MOC_RSA(hwAccelCtx) &pRSAKey, pKeyBlob, sizeof(test_PrivateKeyBlob), NULL)))
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - rsaKat - RSA_keyFromByteString - Failed");
        goto exit;
    }

    /* Get the cipher text length */
    if (OK > (status = RSA_getCipherTextLength(pRSAKey, &cipherTextLen)))
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - rsaKat - RSA_getCipherTextLength - Failed");
        status = ERR_FIPS_RSA_KAT_FAILED;
        goto exit;
    }

    /********** Signature Calculation and Verification ****************/

    /* Allocate memory for Cipher Text */
    pCipherText = MALLOC(cipherTextLen);
    if (NULL == pCipherText)
    {
        status = ERR_FIPS_RSA_KAT_FAILED;
        goto exit;
    }

    /* Allocate memory for Plain Text */
    pPlainText = MALLOC(cipherTextLen+1);
    if (NULL == pPlainText)
    {
        status = ERR_FIPS_RSA_KAT_FAILED;
        goto exit;
    }

    /* Clear all memory */
    DIGI_MEMSET(pCipherText, 0x00, cipherTextLen);
    DIGI_MEMSET(pPlainText, 0x00, cipherTextLen+1);
    plainTextLen = 0;


    if (FIPS_FORCE_FAIL_RSA_TEST)
    {
        testmsg[0] ^= 0x01;
    }

    /* RSA signature/verification API aren't taking care of message digest before calculating
     * the signature, we need to do it from our own
     */
    /* Calculate the signature */
    if (OK > (status = RSA_signMessage(MOC_RSA(hwAccelCtx) pRSAKey,
                                       (const ubyte*) testmsg,
                                       (sbyte4)DIGI_STRLEN(testmsg)+1,
                                       pCipherText, &pQueue)))
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - rsaKat - RSA_signMessage - Failed");
        status = ERR_FIPS_RSA_KAT_FAILED;
        goto exit;
    }

    /* Verify the Cipher Text with the expected data */
    DIGI_CTIME_MATCH( pCipherText, expect, cipherTextLen, &resCmp);
    if (0 != resCmp)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - rsaKat - DIGI_CTIME_MATCH(expect) - Failed");
        status = ERR_FIPS_RSA_KAT_FAILED;
        goto exit;
    }

    /* Make a Public RSA Key from the test_PublicKeyBlob */
    DIGI_MEMSET(pKeyBlob, 0, MAX_KEYBLOBLEN);
    DIGI_MEMCPY(pKeyBlob, test_PublicKeyBlob, sizeof(test_PublicKeyBlob));

    /* Make key from Key Blob */
    if (OK > (status = RSA_keyFromByteString(MOC_RSA(hwAccelCtx) &pRSAPublicKey, pKeyBlob, sizeof(test_PublicKeyBlob), NULL)))
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - rsaKat - RSA_keyFromByteString - Failed");
        status = ERR_CRYPTO;
        goto exit;
    }

    /* Verify the signature, it doesn't memory compare the output, we need to do that from our own */
    if (OK > (status = RSA_verifySignature(MOC_RSA(hwAccelCtx) pRSAPublicKey,
                                           pCipherText, pPlainText,
                                           &plainTextLen, &pQueue)))
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - rsaKat - RSA_verifySigature - Failed");
        status = ERR_FIPS_RSA_KAT_FAILED;
        goto exit;
    }

    if (0 != DIGI_STRCMP(testmsg, (const sbyte*) pPlainText))
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - rsaKat - DIGI_STRCMP(pPlainText) - Failed");
        status = ERR_CRYPTO;
        goto exit;
    }

exit:
    /* Release all resources */
    FREE(pKeyBlob);
    RSA_freeKey(&pRSAKey, 0);
    RSA_freeKey(&pRSAPublicKey, 0);
    VLONG_freeVlongQueue(&pQueue);
    FREE(pPlainText);
    FREE(pCipherText);

    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_rsaKat", "RSA", status);

    setFIPS_Status_Once(FIPS_ALGO_RSA, status);

    return status;

} /* FIPS_rsaKat */

#endif /* !defined( __DISABLE_DIGICERT_RSA_SIGN__) && \
    !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__) &&
    !defined(__ENABLE_DIGICERT_PKCS11_CRYPTO__) */

#endif /* __ENABLE_DIGICERT_FIPS_RSA__ */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DSA__))
MOC_EXTERN MSTATUS
FIPS_dsaKat(hwAccelDescr hwAccelCtx)
{
    randomContext*  pRandomContext = NULL;
    DSAKey*         pDSAKey = NULL;
    vlong*          pR = NULL;
    vlong*          pS = NULL;
    char            pMsg[] = "Attack at dawn";
    vlong*          pBuff = NULL;
    intBoolean      isGoodSig = 0;
    ubyte           bytestring[128] = {0};
    ubyte4          vlen = 128;
    sbyte4          cmpRes = 0;
    MSTATUS         status = OK;

    static const ubyte m_dsaKeyBlob[] = {
    0x00, 0x00, 0x00, 0x41, 0x00, 0x99, 0x6e, 0xf0, 0xeb, 0x5a, 0xd3, 0x39, 0x0b, 0x7b, 0x1b, 0xd6,
    0xb3, 0xe3, 0x5f, 0xe2, 0x54, 0x74, 0x30, 0xb0, 0x11, 0x52, 0xf3, 0xc3, 0x92, 0xcc, 0x45, 0x95,
    0x1e, 0x02, 0xca, 0x26, 0x71, 0x87, 0x2a, 0x66, 0xb6, 0x74, 0x6d, 0x1b, 0x88, 0xb6, 0x32, 0xb0,
    0x47, 0xc0, 0xeb, 0x82, 0xcc, 0xb2, 0x20, 0x36, 0x13, 0xbc, 0xaa, 0xbf, 0x0e, 0x9b, 0x8f, 0xef,
    0x34, 0x37, 0x32, 0x2c, 0x25, 0x00, 0x00, 0x00, 0x15, 0x00, 0xe2, 0x1c, 0xe1, 0x57, 0x83, 0x92,
    0xd3, 0xaa, 0xdf, 0xb8, 0x86, 0x52, 0x29, 0x6d, 0xee, 0xcc, 0xa8, 0xa5, 0xb2, 0x51, 0x00, 0x00,
    0x00, 0x40, 0x59, 0xba, 0x81, 0xdd, 0xa8, 0x29, 0x52, 0x3b, 0x12, 0x80, 0x0b, 0xfd, 0x53, 0x20,
    0x47, 0xe2, 0x75, 0x74, 0x26, 0x37, 0x68, 0x4a, 0x13, 0x32, 0x86, 0x94, 0x98, 0x7f, 0x25, 0x23,
    0xc8, 0x9a, 0xfb, 0x88, 0x0a, 0x4a, 0xa1, 0x2f, 0xc9, 0xa2, 0x44, 0x12, 0xfa, 0x33, 0x92, 0x00,
    0x83, 0xb4, 0xd2, 0x5e, 0xf9, 0x01, 0x8c, 0xd3, 0x1f, 0x62, 0x6c, 0xc9, 0x12, 0x1e, 0x26, 0x63,
    0xd1, 0x88, 0x00, 0x00, 0x00, 0x41, 0x00, 0x85, 0x67, 0x2d, 0xf6, 0xf6, 0xa0, 0xd4, 0xaa, 0x31,
    0x00, 0xa4, 0x37, 0x9b, 0x41, 0x1b, 0x75, 0x4c, 0x2f, 0x98, 0xd5, 0x85, 0xbf, 0x75, 0x7c, 0x36,
    0x10, 0x76, 0xd1, 0x8f, 0x19, 0xc3, 0xc5, 0xd9, 0x84, 0xc4, 0x49, 0xdc, 0x4a, 0x76, 0x40, 0x38,
    0x19, 0x88, 0xc4, 0x49, 0x77, 0xf3, 0xfb, 0xd4, 0x6a, 0x80, 0x96, 0x28, 0x28, 0x4c, 0x2d, 0x3d,
    0xf5, 0x02, 0xe0, 0x07, 0x12, 0x17, 0xc7, 0x00, 0x00, 0x00, 0x15, 0x00, 0x93, 0xd0, 0xb5, 0xe5,
    0x6f, 0x5a, 0x38, 0x5c, 0x7a, 0x8c, 0xa0, 0xab, 0xef, 0xdf, 0x90, 0x4b, 0x05, 0xb2, 0xd9, 0xe6 };

    /* DSA signature = 2 x 20 bytes, stored in 'pR' and 'pS' */
    static const ubyte pR_expect[] = {
      0xD1, 0xF2, 0xE6, 0x79, 0xFB, 0x78, 0xCF, 0x38, 0x9D, 0x6F,
      0x74, 0x57, 0xB9, 0x4E, 0x21, 0x93, 0x40, 0x01, 0x6A, 0xCC
    };

    static const ubyte pS_expect[] = {
      0x01, 0x32, 0x0A, 0xB8, 0x3C, 0x49, 0x78, 0x2B, 0x0A, 0xC5,
      0x88, 0xC6, 0x4E, 0xE0, 0xEC, 0xFB, 0xA2, 0x7A, 0x6C, 0x5B
    };

    typedef struct
    {
      ubyte4  entropyInputLen;
      ubyte   entropyInput[48];
      ubyte4  personalizationDIGI_STRLEN;
      ubyte   personalizationStr[48];
      ubyte4  resultLen;
    } NIST_DRBG_TestVectorPR;
 
    sbyte4          keyLen = 32;
    static const NIST_DRBG_TestVectorPR CTR_DRBG_NoDF_PR = {
      /* [EntropyInputLen = 384] */
      /* [PersonalizationStringLen = 384] */
      48,
      {0x7e,0x83,0x3f,0xa6, 0x39,0xdc,0xcb,0x38, 0x17,0x6a,0xa3,0x59, 0xa9,0x8c,0x1f,0x50,
       0xd3,0xdb,0x34,0xdd, 0xa4,0x39,0x65,0xe4, 0x77,0x17,0x08,0x57, 0x49,0x04,0xbd,0x68,
       0x5c,0x7d,0x2a,0xee, 0x0c,0xf2,0xfb,0x16, 0xef,0x16,0x18,0x4d, 0x32,0x6a,0x26,0x6c},    /* EntropyInput */
      48,
      {0xc0,0x54,0x1e,0xa5, 0x93,0xd9,0x8b,0x2b, 0x43,0x15,0x2c,0x07, 0x26,0x25,0xc7,0x08,
       0xf0,0xb3,0x4b,0x44, 0x96,0xfe,0xc7,0xc5, 0x64,0x27,0xaa,0x78, 0x5b,0xbc,0x40,0x51,
       0xce,0x89,0x6b,0xc1, 0x3f,0x9c,0xa0,0x5c, 0x75,0x98,0x24,0xc5, 0xe1,0x3e,0x86,0xdb},    /* PersonalizationString */
      16
    };

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_dsaKat", "DSA");

        /* Created NIST DRBG with seeded input */
    status = NIST_CTRDRBG_newContext(MOC_SYM(hwAccelCtx) &pRandomContext,
                                     CTR_DRBG_NoDF_PR.entropyInput, keyLen, CTR_DRBG_NoDF_PR.resultLen,
                                     CTR_DRBG_NoDF_PR.personalizationStr, CTR_DRBG_NoDF_PR.personalizationDIGI_STRLEN);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - dsaKat - NIST_CTRDRBG_newContext - Failed");
        goto exit;
    }

    status = DSA_extractKeyBlob(&pDSAKey, m_dsaKeyBlob, sizeof(m_dsaKeyBlob));
    if (OK != status)
      goto exit;
  
    if (FIPS_FORCE_FAIL_DSA_TEST)
    {
        pMsg[0] ^= 0x01;  
    }

    /* Converting the message string to VLONG */
    status = VLONG_vlongFromByteString((ubyte*)pMsg, (sbyte4)DIGI_STRLEN((sbyte*)pMsg), &pBuff, NULL);
    if (OK != status)
      goto exit;

    /* Create signature */
    status = DSA_computeSignature(MOC_DSA(hwAccelCtx) pRandomContext, pDSAKey, pBuff,
                                  &isGoodSig, &pR, &pS, NULL);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - dsaKat - DSA_computeSignature - Failed");
        goto exit;
    }

    if (FALSE == isGoodSig)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - dsaKat - isGoodSig - Failed");
        status = ERR_FIPS_DSA_FAIL;
        goto exit;
    }

    vlen = sizeof(pR_expect);
    status = VLONG_byteStringFromVlong(pR, bytestring, (sbyte4*)&vlen);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - dsaKat - VLONG_byteStringFromVlong(pR) - Failed");
        status = ERR_FIPS_DSA_FAIL;
        goto exit;
    }

    if (OK != DIGI_CTIME_MATCH(bytestring, pR_expect, vlen, &cmpRes))
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - dsaKat - DIGI_CTIME_MATCH(pR) - Failed");
        status = ERR_FIPS_DSA_FAIL;
        goto exit;
    }
    if (0 != cmpRes)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - dsaKat - cmpRes(pR) - Failed");
        status = ERR_FIPS_DSA_FAIL;
        goto exit;
    }

    vlen = sizeof(pS_expect);
    status = VLONG_byteStringFromVlong(pS, bytestring, (sbyte4*)&vlen);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - dsaKat - VLONG_byteStringFromVlong(pS) - Failed");
        status = ERR_FIPS_DSA_FAIL;
        goto exit;
    }

    if (OK != DIGI_CTIME_MATCH(bytestring, pS_expect, vlen, &cmpRes))
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - dsaKat - DIGI_CTIME_MATCH(pS) - Failed");
        status = ERR_FIPS_DSA_FAIL;
        goto exit;
    }
    if (0 != cmpRes)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - dsaKat - cmpRes(pS) - Failed");
        status = ERR_FIPS_DSA_FAIL;
        goto exit;
    }

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_dsaKat", "DSA", status);

    VLONG_freeVlong(&pR, NULL);
    VLONG_freeVlong(&pS, NULL);
    VLONG_freeVlong(&pBuff, NULL);
    DSA_freeKey(&pDSAKey, NULL);
    RANDOM_releaseContext(&pRandomContext);

    setFIPS_Status_Once(FIPS_ALGO_DSA, status);
    return status;
} /* FIPS_dsaKat */

#endif /* (defined(__ENABLE_DIGICERT_DSA__)) */

#if (defined(__ENABLE_DIGICERT_ECC__))

static sbyte4 RANDOM_rngFunFipsKat(void* rngFunArg, ubyte4 length, ubyte *buffer)
{
    pf_unit *pBuf = (pf_unit *) buffer;
    ubyte temp[72] = {0}; /* ok for curves up to P521 */
    sbyte4 ret = -1;
    ubyte4 i = 0;
    ubyte4 j = 0;
    const ubyte4 bpu = sizeof(pf_unit); /* bytes per unit */

    /* This is just used for ECC, sanity check on length though */
    if (length > 72)
        return -1;
    
    /* Get the little endian expected k byte array in temp */
    ret = RANDOM_rngFun(rngFunArg, length, temp);
    if (ret < 0)
        return ret;

    /* Now copy over to the buffer as pf_units in platform endianness */
    for (i = 0; i < ((length + bpu - 1) / bpu); i++, j += bpu)
    {
#ifdef __ENABLE_DIGICERT_64_BIT__   
        pBuf[i] = (pf_unit) temp[j] | 
                  (((pf_unit) temp[j+1]) << 8) | 
                  (((pf_unit) temp[j+2]) << 16) |
                  (((pf_unit) temp[j+3]) << 24) | 
                  (((pf_unit) temp[j+4]) << 32) | 
                  (((pf_unit) temp[j+5]) << 40) | 
                  (((pf_unit) temp[j+6]) << 48) |  
                  (((pf_unit) temp[j+7]) << 56);
#else
        pBuf[i] = (pf_unit) temp[j] | 
                  (((pf_unit) temp[j+1]) << 8) | 
                  (((pf_unit) temp[j+2]) << 16) | 
                  (((pf_unit) temp[j+3]) << 24);
#endif
    }

    /* zero out previous copy */
    (void) DIGI_MEMSET(temp, 0x00, length);

    return ret;
}

MOC_EXTERN MSTATUS
FIPS_ecdsaKat(hwAccelDescr hwAccelCtx)
{
    randomContext*  pRandomContext = NULL;
    PFEPtr          r       = NULL;
    PFEPtr          s       = NULL;
    PrimeFieldPtr   pPF     = NULL;
    ECCKey*         pNewKey = NULL;
    ubyte*          bytestring = NULL;
    ubyte4          vlen;
    sbyte4          cmpRes = 0;
    MSTATUS         status = OK;
    ubyte           msghash[28];

    const ubyte hash[28] =
    {
      0xFB,0x55,0x3D,0xE7,0x46,0xCE,0x92,0xEB,0x85,0x61,0x08,0xBA,0xAC,0x5C,0x83,0xFA,
      0x7E,0x09,0x0A,0xCD,0xEE,0xA7,0x6C,0xB6,0x01,0xE8,0xCC,0xED
    };
    ubyte4 hashLen = 28;
    
    /* P224 data */
    static const ubyte gpP224priv[28] =
    {
      0x53,0x95,0xFC,0x8C,0xF7,0x48,0xC9,0x75,0x31,0x0A,0x2A,0xE5,0xCB,0x47,0x97,0x2F,
      0xFC,0xD8,0x5F,0x2F,0x52,0xE3,0x78,0x20,0x5F,0x22,0x11,0x48
    };

    static const ubyte gpP224pubX[28] =
    {
      0x5C,0x02,0x54,0xFC,0xB8,0x4D,0xC1,0xEF,0x47,0x2A,0x9B,0x27,0x50,0xD3,0x10,0x6A,
      0xC4,0x02,0xC7,0x2D,0x1F,0x9A,0x5D,0xBC,0x50,0xF9,0xB7,0xF5
    };

    static const ubyte gpP224pubY[28] =
    {
      0x52,0x19,0xF9,0x98,0x1B,0x3F,0xF9,0x0A,0xE2,0xDC,0x7F,0x36,0xFD,0x7F,0x5C,0xF0,
      0x0D,0x7D,0x1B,0x15,0xAE,0x8B,0x54,0x7D,0xDA,0xEC,0xA5,0x36
    };

    /* ECDSA signature = 2 x 28 bytes, stored in 'r' and 'r' */
    static const ubyte pR_expect[] = {
      0xAC, 0xD4, 0x32, 0xA2, 0x23, 0x9D, 0xF7, 0xEA, 0xAC, 0x1B,
      0xEC, 0x6F, 0x72, 0x3F, 0x5B, 0x5C, 0x81, 0xC9, 0xF3, 0x18,
      0x06, 0xA1, 0xD7, 0x6A, 0x9D, 0x3B, 0xBB, 0x16
    };

    static const ubyte pS_expect[] = {
      0x4E, 0x55, 0x90, 0x9B, 0xB1, 0xF8, 0x74, 0x17, 0xCB, 0x53,
      0xA4, 0x91, 0xF4, 0xA1, 0x53, 0xB0, 0x92, 0x3C, 0x8E, 0x0A,
      0xE7, 0xED, 0xF1, 0x18, 0x51, 0x75, 0x7B, 0xA4
    };

    typedef struct
    {
      ubyte4  entropyInputLen;
      ubyte   entropyInput[48];
      ubyte4  personalizationDIGI_STRLEN;
      ubyte   personalizationStr[48];
      ubyte4  resultLen;
    } NIST_DRBG_TestVectorPR;
 
    sbyte4          keyLen = 32;
    static const NIST_DRBG_TestVectorPR CTR_DRBG_NoDF_PR = {
      /* [EntropyInputLen = 384] */
      /* [PersonalizationStringLen = 384] */
      48,
      {0x7e,0x83,0x3f,0xa6, 0x39,0xdc,0xcb,0x38, 0x17,0x6a,0xa3,0x59, 0xa9,0x8c,0x1f,0x50,
       0xd3,0xdb,0x34,0xdd, 0xa4,0x39,0x65,0xe4, 0x77,0x17,0x08,0x57, 0x49,0x04,0xbd,0x68,
       0x5c,0x7d,0x2a,0xee, 0x0c,0xf2,0xfb,0x16, 0xef,0x16,0x18,0x4d, 0x32,0x6a,0x26,0x6c},    /* EntropyInput */
      48,
      {0xc0,0x54,0x1e,0xa5, 0x93,0xd9,0x8b,0x2b, 0x43,0x15,0x2c,0x07, 0x26,0x25,0xc7,0x08,
       0xf0,0xb3,0x4b,0x44, 0x96,0xfe,0xc7,0xc5, 0x64,0x27,0xaa,0x78, 0x5b,0xbc,0x40,0x51,
       0xce,0x89,0x6b,0xc1, 0x3f,0x9c,0xa0,0x5c, 0x75,0x98,0x24,0xc5, 0xe1,0x3e,0x86,0xdb},    /* PersonalizationString */
      16
    };

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_ecdsaKat", "ECDSA-P224");

    /* Created NIST DRBG with seeded input */
    status = NIST_CTRDRBG_newContext(MOC_SYM(hwAccelCtx) &pRandomContext,
                                     CTR_DRBG_NoDF_PR.entropyInput, keyLen, CTR_DRBG_NoDF_PR.resultLen,
                                     CTR_DRBG_NoDF_PR.personalizationStr, CTR_DRBG_NoDF_PR.personalizationDIGI_STRLEN);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - NIST_CTRDRBG_newContext - Failed");
        goto exit;
    }

    status = EC_newKey(EC_P224, &pNewKey);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - EC_newKey - Failed");
        goto exit;
    }
    
    /* Create signature */
    pPF = EC_getUnderlyingField(pNewKey->pCurve);

    status = PRIMEFIELD_setToByteString(pPF, pNewKey->k, gpP224priv, sizeof(gpP224priv));
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - PRIMEFIELD_setToByteString - Failed");
        goto exit;
    }

    status = PRIMEFIELD_setToByteString(pPF, pNewKey->Qx, gpP224pubX, sizeof(gpP224pubX));
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - PRIMEFIELD_setToByteString - Failed");
        goto exit;
    }

    status = PRIMEFIELD_setToByteString(pPF, pNewKey->Qy, gpP224pubY, sizeof(gpP224pubY));
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - PRIMEFIELD_setToByteString - Failed");
        goto exit;
    }

    status = PRIMEFIELD_newElement(pPF, &r);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - PRIMEFIELD_newElement(r) - Failed");
        goto exit;
    }

    status = PRIMEFIELD_newElement(pPF, &s);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - PRIMEFIELD_newElement(s) - Failed");
        goto exit;
    }

    DIGI_MEMCPY((void*)msghash, (void*)hash, hashLen);

    if (FIPS_FORCE_FAIL_ECDSA_TEST)
    {
        msghash[0] ^= 0x01;
    }
 
    status = ECDSA_signDigestAux(pNewKey->pCurve, pNewKey->k, RANDOM_rngFunFipsKat,
                                 pRandomContext, msghash, hashLen, r, s);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - ECDSA_signDigestAux - Failed");
        goto exit;
    }

    status = PRIMEFIELD_getAsByteString(pPF, r, &bytestring, (sbyte4*)&vlen);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - PRIMEFIELD_getAsByteString(r) - Failed");
        goto exit;
    }

    if (OK != DIGI_CTIME_MATCH(bytestring, pR_expect, vlen, &cmpRes))
    {
      status = ERR_FIPS_ECDSA_FAIL;
      DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - DIGI_CTIME_MATCH(pR) - Failed");
      goto exit;
    }
    if (0 != cmpRes)
    {
      status = ERR_FIPS_ECDSA_FAIL;
      DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - cmpRes(pR) - Failed");
      goto exit;
    }

    if(bytestring)
    	FREE(bytestring);
    bytestring = NULL;

    status = PRIMEFIELD_getAsByteString(pPF, s, &bytestring, (sbyte4*)&vlen);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - PRIMEFIELD_getAsByteString(s) - Failed");
        goto exit;
    }

    if (OK != DIGI_CTIME_MATCH(bytestring, pS_expect, vlen, &cmpRes))
    {
      status = ERR_FIPS_ECDSA_FAIL;
      DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - DIGI_CTIME_MATCH(pS) - Failed");
      goto exit;
    }
    if (0 != cmpRes)
    {
      status = ERR_FIPS_ECDSA_FAIL;
      DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - ecdsaKat - cmpRes(pS) - Failed");
      goto exit;
    }

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_ecdsaKat", "ECDSA-P224", status);

    if(bytestring)
    	FREE(bytestring);
    PRIMEFIELD_deleteElement(pPF, &r);
    PRIMEFIELD_deleteElement(pPF, &s);
    EC_deleteKey(&pNewKey);
    RANDOM_releaseContext(&pRandomContext);

    setFIPS_Status_Once(FIPS_ALGO_ECC, status);  /* There is overlap. */
    setFIPS_Status_Once(FIPS_ALGO_ECDSA, status);
    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_ECC__)) */

#if (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__))
MOC_EXTERN MSTATUS
FIPS_eddsaKat(hwAccelDescr hwAccelCtx)
{
    BulkHashAlgo    shaSuite = {0};
    edECCKey*       pKey = NULL;
    ubyte           pSignature[57*2] = {0};
    ubyte4          signatureLen;
    sbyte4          cmpRes = 0;
    MSTATUS         status = OK;
    ubyte           msg[16];

    shaSuite.allocFunc = &SHA512_allocDigest;
    shaSuite.initFunc = (BulkCtxInitFunc) &SHA512_initDigest;
    shaSuite.updateFunc = (BulkCtxUpdateFunc) &SHA512_updateDigest;
    shaSuite.finalFunc = (BulkCtxFinalFunc) &SHA512_finalDigest;
    shaSuite.freeFunc = &SHA512_freeDigest;
    shaSuite.digestFunc = NULL;

    const ubyte mesg[] = 
    {
      0xD1,0x1C,0xA5,0xB4,0xC0,0xE6,0x10,0xD8,0x4B,0x14,0xCF,0xED,0x38,0xFF,0x64,0x58
    };

    ubyte4 mesgLen = 16;

    /* EdDSA signature = 64 bytes */
    static const ubyte pSig_expect[] = 
    {
      0x47,0x78,0x2a,0x79,0xe3,0x1e,0x4b,0xc9,0xc9,0x7d,0xc5,0x9d,0x11,0x8c,0xe2,0x21,
      0x78,0x33,0xfc,0xc2,0xc1,0xc0,0xaa,0x5c,0x04,0x51,0x6d,0x7c,0x8d,0x7b,0x1e,0x4e,
      0xf2,0x04,0x53,0x01,0xd3,0x8e,0x17,0xaf,0xa3,0x0e,0x23,0x4a,0xf1,0x14,0x0b,0xac,
      0xaa,0xc3,0x25,0x0d,0xbf,0xe3,0x14,0x81,0xd8,0xea,0x4d,0xf8,0x46,0x5d,0x12,0x05
    };

    static ubyte gpP25519priv[32] =
    {
      0x83,0x3f,0xe6,0x24,0x09,0x23,0x7b,0x9d,0x62,0xec,0x77,0x58,0x75,0x20,0x91,0x1e,
      0x9a,0x75,0x9c,0xec,0x1d,0x19,0x75,0x5b,0x7d,0xa9,0x01,0xb9,0x6d,0xca,0x3d,0x42
    };

    static ubyte gpP25519pub[32] =
    {
      0xec,0x17,0x2b,0x93,0xad,0x5e,0x56,0x3b,0xf4,0x93,0x2c,0x70,0xe1,0x24,0x50,0x34,
      0xc3,0x54,0x67,0xef,0x2e,0xfd,0x4d,0x64,0xeb,0xf8,0x19,0x68,0x34,0x67,0xe2,0xbf
    };

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_eddsaKat", "EdDSA-25519");

    status = edECC_newKey(&pKey, curveEd25519, NULL);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - eddsaKat - edECC_newKey - Failed");
        goto exit;
    }
    
    /* Create signature */
    status = edECC_setKeyParameters(pKey, gpP25519pub, sizeof(gpP25519pub),
                                    gpP25519priv, sizeof(gpP25519priv), NULL, NULL);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - eddsaKat - edECC_setKeyParameters - Failed");
        goto exit;
    }

    DIGI_MEMCPY((void*)msg, (void*)mesg, mesgLen);

    if (FIPS_FORCE_FAIL_EDDSA_TEST)
    {
        msg[0] ^= 0x01;
    }

    status = edDSA_Sign(pKey, (ubyte *) msg, mesgLen, pSignature,
                        sizeof(pSignature), &signatureLen, &shaSuite, FALSE, NULL, 0, NULL);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - eddsaKat - edDSA_Sign - Failed");
        goto exit;
    }

    if (OK != DIGI_CTIME_MATCH(pSignature, pSig_expect, signatureLen, &cmpRes))
    {
      status = ERR_FIPS_EDDSA_SIGN_VERIFY_FAIL;
      DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - eddsaKat - DIGI_CTIME_MATCH(pSig) - Failed");
      goto exit;
    }
    if (0 != cmpRes)
    {
      status = ERR_FIPS_EDDSA_SIGN_VERIFY_FAIL;
      DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - eddsaKat - cmpRes(pSig) - Failed");
      goto exit;
    }

 exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_eddsaKat", "EDDSA-25519", status);

    edECC_deleteKey(&pKey, NULL);
    
    setFIPS_Status_Once(FIPS_ALGO_EDDSA, status);
    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)) */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_PQC_KEM__))
#if defined(__ENABLE_DIGICERT_FIPS_MLKEM__)
MOC_EXTERN MSTATUS FIPS_mlkemKat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;

    status = FIPS_mlkem_key_Kat(hwAccelCtx);
    if (OK != status)
        goto exit;
    status = FIPS_mlkem_encap_Kat(hwAccelCtx);
    if (OK != status)
        goto exit;
    status = FIPS_mlkem_decap_Kat(hwAccelCtx);
exit:
    return status;
}

MOC_EXTERN MSTATUS FIPS_mlkem_key_Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;
    MLKEMCtx ctx = {0};
    sbyte4   cmpRes;

#include "fips_kat_mlkem_key_data.inc"

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_mlkem_key_Kat", "MLKEM-512");

    status = MLKEM_createCtx(MLKEM_TYPE_512, hwAccelCtx, &ctx);
    if (OK != status)
        goto exitRet; /* No clean up*/

    /* Run key creation test */
    rng_buffer fake = {0};
    ubyte  *pRNG = NULL;
    ubyte  *pK = NULL;
    size_t pKLen;
    ubyte  *sK = NULL;
    size_t sKLen;

    /* Allocate the RNG output buffer */
    status = DIGI_MALLOC((void **) &pRNG, zGenLen+dGenLen);
    if (OK != status)
        goto exit;

    /* Set 'z' and 'd' values */
    (void)DIGI_MEMCPY(pRNG, dGen, dGenLen);
    (void)DIGI_MEMCPY(pRNG+dGenLen, zGen, zGenLen);
    fake.offset = 0;
    fake.capacity = dGenLen+zGenLen;
    fake.pBuf = pRNG;

    if (FIPS_FORCE_FAIL_MLKEM_KEY_TEST)
    {
        pRNG[0] ^= 0x01;
    }

    /* Create key values from RNG */
    status = MLKEM_generateKeyPair(FIPS_KAT_rngFun_Echo, (void*)&fake, &ctx);
    if (OK != status)
        goto exit;

    /* Obtain generated keys */
    status = MLKEM_getPublicKeyLen(&ctx, &pKLen);
    if (OK != status)
        goto exit;
    status = MLKEM_getPrivateKeyLen(&ctx, &sKLen);
    if (OK != status)
        goto exit;

    /* Confirm expectation matches lengths */
    if (dkGenExpectLen != sKLen)
    {
        status = ERR_CRYPTO;
        goto exit;
    }
    if (ekGenExpectLen != pKLen)
    {
        status = ERR_CRYPTO;
        goto exit;
    }

    /* Allocate the key buffers */
    status = DIGI_MALLOC((void **) &pK, pKLen);
    if (OK != status)
        goto exit;
    status = DIGI_MALLOC((void **) &sK, sKLen);
    if (OK != status)
        goto exit;

    /* Obtain data */
    status = MLKEM_getPublicKey(&ctx, pK, pKLen);
    if (OK != status)
        goto exit;
    status = MLKEM_getPrivateKey(&ctx, sK, sKLen);
    if (OK != status)
        goto exit;

    /* Compare with expectation */
    if (OK != DIGI_CTIME_MATCH(dkGenExpect, sK, sKLen, &cmpRes))
    {
        status = ERR_FIPS_MLKEM_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mlkemKat/GEN - DIGI_CTIME_MATCH(dK) - Failed");
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_MLKEM_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mlkemKat/GEN - cmpRes(dK) - Failed");
        goto exit;
    }
    if (OK != DIGI_CTIME_MATCH(ekGenExpect, pK, pKLen, &cmpRes))
    {
        status = ERR_FIPS_MLKEM_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mlkemKat/GEN - DIGI_CTIME_MATCH(eK) - Failed");
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_MLKEM_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mlkemKat/GEN - cmpRes(eK) - Failed");
        goto exit;
    }

exit:
    DIGI_FREE((void**)&pK);
    DIGI_FREE((void**)&sK);
    DIGI_FREE((void**)&pRNG);
    MLKEM_destroyCtx(&ctx);

exitRet:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_mlkem_key_Kat", "MLKEM-512", status);

    setFIPS_Status_Once(FIPS_ALGO_MLKEM, status);
    return status;
}

MOC_EXTERN MSTATUS FIPS_mlkem_encap_Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS  status = OK;
    MLKEMCtx ctx = {0};
    sbyte4   cmpRes;

#include "fips_kat_mlkem_encap_data.inc"

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_mlkem_encap_Kat", "MLKEM-512");

    status = MLKEM_createCtx(MLKEM_TYPE_512, hwAccelCtx, &ctx);
    if (OK != status)
        goto exitRet;

    /* Run encapsulation test */
    rng_buffer fake = {0};
    ubyte   *pRNG = NULL;
    ubyte   *pKey = NULL;
    size_t  keyLen;
    ubyte   *pCrypt = NULL;
    size_t  cryptLen;

    /* Set encapsulation key */
    status = MLKEM_setPublicKey((uint8_t*)ekEnc, ekEncLen, &ctx);
    if (OK != status)
        goto exit;

    /* Create memory for cipher data output */
    status = MLKEM_getCipherTextLen(&ctx, &cryptLen);
    if (OK != status)
        goto exit;
    status = DIGI_CALLOC((void**)&pCrypt, 1, cryptLen);
    if (OK != status)
        goto exit;

    /* Create memory for shared key data output */
    status = MLKEM_getSharedSecretLen(&ctx, &keyLen);
    if (OK != status)
        goto exit;
    status = DIGI_CALLOC((void**)&pKey, 1, keyLen);
    if (OK != status)
        goto exit;

    /* Confirm expectation matches lengths */
    if (cryptEncExpectLen != cryptLen)
    {
        status = ERR_CRYPTO;
        goto exit;
    }
    if (keyEncExpectLen != keyLen)
    {
        status = ERR_CRYPTO;
        goto exit;
    }

    /* Allocate the RNG output buffer */
    status = DIGI_MALLOC((void **) &pRNG, msgEncLen);
    if (OK != status)
        goto exit;

    /* Set 'M' value */
    (void)DIGI_MEMCPY(pRNG, msgEnc, msgEncLen);
    fake.offset = 0;
    fake.capacity = msgEncLen;
    fake.pBuf = pRNG;

    if (FIPS_FORCE_FAIL_MLKEM_ENCAP_TEST)
    {
        pRNG[0] ^= 0x01;
    }

    status = MLKEM_encapsulate(&ctx, FIPS_KAT_rngFun_Echo, (void*)&fake,
			       pCrypt, cryptLen, pKey, keyLen);
    if (OK != status)
        goto exit;

    /* Compare with expectation */
    if (OK != DIGI_CTIME_MATCH(cryptEncExpect, pCrypt, cryptEncExpectLen, &cmpRes))
    {
        status = ERR_FIPS_MLKEM_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mlkemKat/ENCAP - DIGI_CTIME_MATCH(cipher) - Failed");
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_MLKEM_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mlkemKat/ENCAP - cmpRes(cipher) - Failed");
        goto exit;
    }
    if (OK != DIGI_CTIME_MATCH(keyEncExpect, pKey, keyEncExpectLen, &cmpRes))
    {
        status = ERR_FIPS_MLKEM_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mlkemKat/ENCAP - DIGI_CTIME_MATCH(key) - Failed");
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_MLKEM_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mlkemKat/ENCAP - cmpRes(key) - Failed");
        goto exit;
    }

exit:
    DIGI_FREE((void**)&pKey);
    DIGI_FREE((void**)&pCrypt);
    DIGI_FREE((void**)&pRNG);
    MLKEM_destroyCtx(&ctx);

exitRet:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_mlkem_encap_Kat", "MLKEM-512", status);

    setFIPS_Status_Once(FIPS_ALGO_MLKEM, status);
    return status;
}

MOC_EXTERN MSTATUS FIPS_mlkem_decap_Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;
    MLKEMCtx ctx = {0};
    sbyte4   cmpRes;

#include "fips_kat_mlkem_decap_data.inc"

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_mlkem_decap_Kat", "MLKEM-512");

    /* Make algo context for MLKEM-512 */
    status = MLKEM_createCtx(MLKEM_TYPE_512, hwAccelCtx, &ctx);
    if (OK != status)
        goto exitRet; /* No clean up*/

    /* Run decapsulation test */
    ubyte    *pShared = NULL;
    size_t   sharedLen;
    ubyte    *pCipher = NULL;

    /* Set decapsulation key */
    status = MLKEM_setPrivateKey((uint8_t*)decKey, decKeyLen, &ctx);
    if (OK != status)
        goto exit;

    /* Create memory for shared data output */
    status = MLKEM_getSharedSecretLen(&ctx, &sharedLen);
    if (OK != status)
        goto exit;
    if (checkLen != sharedLen)
    {
        status = ERR_FIPS_MLKEM_KAT_FAILED;
        goto exit;
    }
    status = DIGI_CALLOC((void**)&pShared, 1, sharedLen);
    if (OK != status)
        goto exit;

    /* Create cipher data */
    status = DIGI_MALLOC_MEMCPY((void**)&pCipher, cipherLen, (void*)cipher, cipherLen);
    if (OK != status)
        goto exit;

    if (FIPS_FORCE_FAIL_MLKEM_DECAP_TEST)
    {
        pCipher[0] ^= 0x01;
    }

    /* Obtain shared data */
    status = MLKEM_decapsulate(&ctx, pCipher, cipherLen, pShared, sharedLen);
    if (OK != status)
        goto exit;

    /* Compare with expectation */
    if (OK != DIGI_CTIME_MATCH(pShared, check, sharedLen, &cmpRes))
    {
        status = ERR_FIPS_MLKEM_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mlkemKat/DECAP - DIGI_CTIME_MATCH(pShared) - Failed");
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_MLKEM_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mlkemKat/DECAP - cmpRes(pShared) - Failed");
        goto exit;
    }

    /* 'Implicit Rejection' case => All zero cipher should be invalid */
    /* See: Note 21 for FIPS 140-3, IG 10.3.A, Resolution 14 and Algo 18 in FIPS 203 */
    status = DIGI_MEMSET(pCipher, 0, cipherLen);
    if (OK != status)
        goto exit;

    /* Obtain 'shared' data after 'rejection' */
    status = MLKEM_decapsulate(&ctx, pCipher, cipherLen, pShared, sharedLen);
    if (OK != status)
        goto exit;

    /* Compare with expectation */
    if (OK != DIGI_CTIME_MATCH(pShared, check_reject, sharedLen, &cmpRes))
    {
        status = ERR_FIPS_MLKEM_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mlkemKat/DECAP_REJ - DIGI_CTIME_MATCH(pShared) - Failed");
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_MLKEM_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mlkemKat/DECAP_REJ - cmpRes(pShared) - Failed");
        goto exit;
    }

exit:
    DIGI_FREE((void**)&pCipher);
    DIGI_FREE((void**)&pShared);
    MLKEM_destroyCtx(&ctx);

exitRet:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_mlkem_decap_Kat", "MLKEM-512", status);

    setFIPS_Status_Once(FIPS_ALGO_MLKEM, status);
    return status;
}

#endif /* defined(__ENABLE_DIGICERT_FIPS_MLKEM__) */
#endif /* defined(__ENABLE_DIGICERT_PQC_KEM__)) */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_PQC_SIG__))
#if defined(__ENABLE_DIGICERT_FIPS_MLDSA__)
MOC_EXTERN MSTATUS FIPS_mldsaKat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;

    /* Run all sub-KAT tests */
    status = FIPS_mldsa_key_Kat(hwAccelCtx);
    if (OK != status)
        goto exit;

    status = FIPS_mldsa_sign_Kat(hwAccelCtx);
    if (OK != status)
        goto exit;

    status = FIPS_mldsa_verify_Kat(hwAccelCtx);
exit:
    return status;
}

MOC_EXTERN MSTATUS FIPS_mldsa_key_Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;
    MLDSACtx ctx = {0};
    sbyte4   cmpRes;

#include "fips_kat_mldsa_key_data.inc"

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_mldsa_key_Kat", "MLDSA-44");

    /* Key creation test */
    rng_buffer fake = {0};
    ubyte      *pRNG = NULL;
    ubyte      *sKey = NULL;
    size_t     sKeyLen;
    ubyte      *pKey = NULL;
    size_t     pKeyLen;

    status = MLDSA_createCtx(MLDSA_TYPE_44, hwAccelCtx, &ctx);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - MLDSA create context - Failed");
        goto exitRet; /* No clean up*/
    }

    /* Allocate the RNG output buffer */
    status = DIGI_MALLOC((void **) &pRNG, XiGenLen);
    if (OK != status)
        goto exit;

    /* Set 'xi' value */
    (void)DIGI_MEMCPY(pRNG, XiGen, XiGenLen);
    fake.offset = 0;
    fake.capacity = XiGenLen;
    fake.pBuf = pRNG;

    if (FIPS_FORCE_FAIL_MLDSA_KEY_TEST)
    {
        pRNG[0] ^= 0x01;
    }

    /* Create both keys */
    status = MLDSA_generateKeyPair(FIPS_KAT_rngFun_Echo, (void*)&fake, &ctx);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - MLDSA_keyGen - Failed");
        goto exit;
    }

    /* Obtain generated key sizes */
    status = MLDSA_getPublicKeyLen(&ctx, &pKeyLen);
    if (OK != status)
        goto exit;
    status = MLDSA_getPrivateKeyLen(&ctx, &sKeyLen);
    if (OK != status)
        goto exit;

    if (pKeyLen != pubKeyGenLen)
    {
        status = ERR_FIPS_MLDSA_KAT_FAILED;
        goto exit;
    }
    /* Private key is stored as 'seed' */
    if (sKeyLen != XiGenLen)
    {
        status = ERR_FIPS_MLDSA_KAT_FAILED;
        goto exit;
    }

    /* Allocate the key buffers */
    status = DIGI_CALLOC((void**)&sKey, 1, privKeyGenLen);
    if (OK != status)
        goto exit;
    status = DIGI_CALLOC((void**)&pKey, 1, pubKeyGenLen);
    if (OK != status)
        goto exit;

    /* Obtain data */
    status = MLDSA_getPublicKey(&ctx, pKey, pKeyLen);
    if (OK != status)
        goto exit;
    status = MLDSA_getPrivateKey(&ctx, sKey, sKeyLen);
    if (OK != status)
        goto exit;

    /* Compare with expectation */
    if (OK != DIGI_CTIME_MATCH(pKey, pubKeyGen, pubKeyGenLen, &cmpRes))
    {
        status = ERR_FIPS_MLDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - DIGI_CTIME_MATCH(public) - Failed");
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_MLDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - cmpRes(public) - Failed");
        goto exit;
    }
    if (OK != DIGI_CTIME_MATCH(sKey, XiGen, XiGenLen, &cmpRes))
    {
        status = ERR_FIPS_MLDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - DIGI_CTIME_MATCH(secret) - Failed");
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_MLDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - cmpRes(secret) - Failed");
        goto exit;
    }

exit:
    DIGI_FREE((void**)&pKey);
    DIGI_FREE((void**)&sKey);
    DIGI_FREE((void**)&pRNG);
    MLDSA_destroyCtx(&ctx);
exitRet:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_mldsa_key_Kat", "MLDSA-44", status);

    setFIPS_Status_Once(FIPS_ALGO_MLDSA, status);
    return status;
}

MOC_EXTERN MSTATUS FIPS_mldsa_sign_Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;
    MLDSACtx ctx = {0};
    sbyte4   cmpRes;

#include "fips_kat_mldsa_sign_data.inc"

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_mldsa_sign_Kat", "MLDSA-44");

    /* Signing test */
    ubyte    *pSignature = NULL;
    ubyte    *pMsg = NULL;
    size_t   signatureLen;

    /* Make algo context for MLDSA-44 */
    status = MLDSA_createCtx(MLDSA_TYPE_44, hwAccelCtx, &ctx);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - MLDSA create context - Failed");
        goto exitRet; /* No clean up*/
    }

    /* Allocate signature buffer */
    status = MLDSA_getSignatureLen(&ctx, &signatureLen);
    if (OK != status)
        goto exit;
    if (signatureLen != checkLen)
    {
        status = ERR_FIPS_MLDSA_KAT_FAILED;
        goto exit;
    }

    status = DIGI_CALLOC((void**)&pSignature, 1, signatureLen);
    if (OK != status)
        goto exit;

    /* Create message */
    status = DIGI_MALLOC_MEMCPY((void**)&pMsg, msgLen, (void*)msg, msgLen);
    if (OK != status)
        goto exit;

    if (FIPS_FORCE_FAIL_MLDSA_SIGN_TEST)
    {
        pMsg[0] ^= 0x01;
    }

    /* Set secret key */
    status = MLDSA_setPrivateKey((uint8_t *)secretKey, secretKeyLen, &ctx);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - MLDSA_setPrivateKey - Failed");
        goto exit;
    }
    /* Set context */
    status = MLDSA_setContext(context, contextLen, &ctx);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - MLDSA_setContext - Failed");
        goto exit;
    }
    /* Create signature data */
    status = MLDSA_signMessage(&ctx, pMsg, msgLen,
                               NULL, 0,
                               pSignature, signatureLen);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - MLDSA_Sign - Failed");
        goto exit;
    }

    /* Compare with expectation */
    if (OK != DIGI_CTIME_MATCH(pSignature, check, signatureLen, &cmpRes))
    {
        status = ERR_FIPS_MLDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - DIGI_CTIME_MATCH(pSig) - Failed");
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_MLDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - cmpRes(pSig) - Failed");
        goto exit;
    }

exit:
    DIGI_FREE((void**)&pMsg);
    DIGI_FREE((void**)&pSignature);
    MLDSA_destroyCtx(&ctx);
exitRet:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_mldsa_sign_Kat", "MLDSA-44", status);

    setFIPS_Status_Once(FIPS_ALGO_MLDSA, status);
    return status;
}

MOC_EXTERN MSTATUS FIPS_mldsa_verify_Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;
    MLDSACtx ctx = {0};
    sbyte4   cmpRes;

#include "fips_kat_mldsa_verify_data.inc"

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_mldsa_verify_Kat", "MLDSA-44");

    /* Verification test */
    ubyte  *pContext = NULL;

    /* Make algo context for MLDSA-44 */
    status = MLDSA_createCtx(MLDSA_TYPE_44, hwAccelCtx, &ctx);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - MLDSA create context - Failed");
        goto exitRet; /* No clean up*/
    }

    status = MLDSA_setPublicKey((uint8_t *)publicKeyVer, publicKeyVerLen, &ctx);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - MLDSA_setPublicKey - Failed");
        goto exit;
    }

    /* Set context */
    status = DIGI_MALLOC_MEMCPY((void**)&pContext, contextVerLen, (void*)contextVer, contextVerLen);
    if (OK != status)
        goto exit;

    if (FIPS_FORCE_FAIL_MLDSA_VERIFY_TEST)
    {
        pContext[0] ^= 0x01;
    }

    status = MLDSA_setContext(pContext, contextVerLen, &ctx);
    if (OK != status)
        goto exit;

    /* Run verification */
    status = MLDSA_verifyMessage(&ctx, (uint8_t*)msgVer, msgVerLen, (uint8_t*)sigVer, sigVerLen);
    if (OK != status)
    {
        status = ERR_FIPS_MLDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - mldsaKat - MLDSA_verify - Failed");
        goto exit;
    }

exit:
    DIGI_FREE((void**)&pContext);
    MLDSA_destroyCtx(&ctx);

exitRet:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_mldsa_verify_Kat", "MLDSA-44", status);

    setFIPS_Status_Once(FIPS_ALGO_MLDSA, status);
    return status;
}

#endif /* defined(__ENABLE_DIGICERT_FIPS_MLDSA__) */

#if defined(__ENABLE_DIGICERT_FIPS_SLHDSA__)
MOC_EXTERN MSTATUS FIPS_slhdsaKat(hwAccelDescr hwAccelCtx)
{
    MSTATUS   status;

    /* Run all sub-KAT tests */
    status = FIPS_slhdsa_sha2_key_Kat(hwAccelCtx);
    if (OK != status)
        goto exit;
    status = FIPS_slhdsa_sha2_sign_Kat(hwAccelCtx);
    if (OK != status)
        goto exit;
    status = FIPS_slhdsa_sha2_verify_Kat(hwAccelCtx);
    if (OK != status)
        goto exit;

    status = FIPS_slhdsa_shake_key_Kat(hwAccelCtx);
    if (OK != status)
        goto exit;
    status = FIPS_slhdsa_shake_sign_Kat(hwAccelCtx);
    if (OK != status)
        goto exit;
    status = FIPS_slhdsa_shake_verify_Kat(hwAccelCtx);
exit:
    return status;
}

/* Sizes from Table 2. */
static size_t SLHDSA_getPrivKeyLen(SLHDSAType type)
{
    switch (type)
    {
        case SLHDSA_TYPE_SHA2_128S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_128F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_128S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_128F:
            return 2*32;
        case SLHDSA_TYPE_SHA2_192S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_192F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_192S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_192F:
            return 2*48;
        case SLHDSA_TYPE_SHA2_256S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_256F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_256S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_256F:
            return 2*64;
        default:
            return 0;
    }
}

MOC_EXTERN MSTATUS FIPS_slhdsa_sha2_key_Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS    status = OK;
    SLHDSACtx  ctx = {0};
    rng_buffer fake = {0};
    ubyte      *pRNG = NULL;
    sbyte4     cmpRes;
    ubyte      *pKey = NULL;
    size_t     keyLen;
    ubyte4     n;

#include "fips_kat_slhdsa_sha2_key_data.inc"

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_slhdsa_sha2_key_Kat", "SLHDSA-SHA2-128f");

    /* Make algo context for SLHDSA-SHA2-128f */
    status = SLHDSA_createCtx(SLHDSA_TYPE_SHA2_128F, hwAccelCtx, &ctx);
    if (OK != status)
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        goto exitRet; /* No clean up*/
    }

    /* Confirm sizes match */
    n = ctx.params.n;
    if (3*n != SKSeedLen+SKPrfLen+PKSeedLen)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Allocate the RNG output buffer */
    status = DIGI_MALLOC((void **) &pRNG, 3*n);
    if (OK != status)
        goto exit;

    /* Set three seed values */
    (void)DIGI_MEMCPY(pRNG, pSKSeed, SKSeedLen);
    (void)DIGI_MEMCPY(pRNG+SKSeedLen, pSKPrf, SKPrfLen);
    (void)DIGI_MEMCPY(pRNG+SKSeedLen+SKPrfLen, pPKSeed, PKSeedLen);
    fake.offset = 0;
    fake.capacity = SKSeedLen+SKPrfLen+PKSeedLen;
    fake.pBuf = pRNG;

    if (FIPS_FORCE_FAIL_SLHDSA_SHA2_KEY_TEST)
    {
        pRNG[0] ^= 0x01;
    }

    status = SLHDSA_generateKeyPair(FIPS_KAT_rngFun_Echo, (void*)&fake, &ctx);
    if (OK != status)
        goto exit;

    status = SLHDSA_getPrivateKeyLen(&ctx, &keyLen);
    if (OK != status)
        goto exit;

    if (skValLen != keyLen)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Allocate the privat key output buffer */
    status = DIGI_MALLOC((void **) &pKey, keyLen);
    if (OK != status)
        goto exit;

    status = SLHDSA_getPrivateKey(&ctx, pKey, keyLen);
    if (OK != status)
        goto exit;

    /* Compare with expectation */
    if (OK != DIGI_CTIME_MATCH(pKey, skVal, keyLen, &cmpRes))
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_sha2 - DIGI_CTIME_MATCH(secret) - Failed");
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_sha2 - cmpRes(secret) - Failed");
        goto exit;
    }

exit:
    DIGI_FREE((void**)&pKey);
    DIGI_FREE((void**)&pRNG);
    SLHDSA_destroyCtx(&ctx);

exitRet:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_slhdsa_sha2_key_Kat", "SLHDSA-SHA2-128f", status);

    setFIPS_Status_Once(FIPS_ALGO_SLHDSA, status);
    return status;
}

MOC_EXTERN MSTATUS FIPS_slhdsa_sha2_sign_Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS   status = OK;
    SLHDSACtx ctx = {0};
    ubyte     *pSignature = NULL;
    size_t    signatureLen;
    ubyte     *pMsg = NULL;
    sbyte4    cmpRes;

#include "fips_kat_slhdsa_sha2_sign_data.inc"

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_slhdsa_sha2_sign_Kat", "SLHDSA-SHA2-128f");

    /* Make algo context for SLHDSA/SHA2-128f */
    status = SLHDSA_createCtx(SLHDSA_TYPE_SHA2_128F, hwAccelCtx, &ctx);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_sha2 - SLHDSA create context - Failed");
        goto exitRet; /* No clean up*/
    }

    /* Allocate signature buffer */
    status = SLHDSA_getSignatureLen(&ctx, &signatureLen);
    if (OK != status)
        goto exit;
    if (signatureLen != checkLen)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = DIGI_CALLOC((void**)&pSignature, 1, signatureLen);
    if (OK != status)
        goto exit;

    /* Create message */
    status = DIGI_MALLOC_MEMCPY((void**)&pMsg, msgLen, (void*)msg, msgLen);
    if (OK != status)
        goto exit;

    if (FIPS_FORCE_FAIL_SLHDSA_SHA2_SIGN_TEST)
    {
        pMsg[0] ^= 0x01;
    }

    /* Set secret key */
    status = SLHDSA_setPrivateKey((uint8_t*)secretKey, secretKeyLen, &ctx);
    if (OK != status)
        goto exit;

    /* Set context */
    status = SLHDSA_setContext(context, contextLen, &ctx);
    if (OK != status)
        goto exit;

    /* Create signature data */
    status = SLHDSA_signMessage(&ctx, pMsg, msgLen,
                                NULL, 0,
                                pSignature, signatureLen);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_sha2 - SLHDSA_Sign - Failed");
        goto exit;
    }

    /* Compare with expectation */
    if (OK != DIGI_CTIME_MATCH(pSignature, check, signatureLen, &cmpRes))
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_sha2 - DIGI_CTIME_MATCH(pSig) - Failed");
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_sha2 - cmpRes(pSig) - Failed");
        goto exit;
    }

exit:
    DIGI_FREE((void**)&pMsg);
    DIGI_FREE((void**)&pSignature);
    SLHDSA_destroyCtx(&ctx);

exitRet:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_slhdsa_sha2_sign_Kat", "SLHDSA-SHA2-128f", status);

    setFIPS_Status_Once(FIPS_ALGO_SLHDSA, status);
    return status;
}

MOC_EXTERN MSTATUS FIPS_slhdsa_sha2_verify_Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS   status = OK;
    SLHDSACtx ctx = {0};
    ubyte     *pContext = NULL;

#include "fips_kat_slhdsa_sha2_verify_data.inc"

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_slhdsa_sha2_verify_Kat", "SLHDSA-SHA2-128s");

    /* Make algo context for SLHDSA-SHA2-128s */
    status = SLHDSA_createCtx(SLHDSA_TYPE_SHA2_128S, hwAccelCtx, &ctx);
    if (OK != status)
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        goto exitRet; /* No clean up*/
    }

    /* Set public key */
    status = SLHDSA_setPublicKey((uint8_t*)pPublicKey, publicKeyLen, &ctx);
    if (OK != status)
        goto exit;

    /* Set context */
    status = DIGI_MALLOC_MEMCPY((void**)&pContext, contextLen, (void*)context, contextLen);
    if (OK != status)
        goto exit;

    if (FIPS_FORCE_FAIL_SLHDSA_SHA2_VERIFY_TEST)
    {
        pContext[0] ^= 0x01;
    }

    status = SLHDSA_setContext(pContext, contextLen, &ctx);
    if (OK != status)
        goto exit;

    /* Verify */
    status = SLHDSA_verifyMessage(&ctx, (uint8_t*)msg, msgLen, (uint8_t*)pSignature, signatureLen);
    if (OK != status)
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_sha2 - SLHDSA_verify - Failed");
        goto exit;
    }

exit:
    DIGI_FREE((void**)&pContext);
    SLHDSA_destroyCtx(&ctx);

exitRet:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_slhdsa_sha2_verify_Kat", "SLHDSA-SHA2-128s", status);

    setFIPS_Status_Once(FIPS_ALGO_SLHDSA, status);
    return status;
}

MOC_EXTERN MSTATUS FIPS_slhdsa_shake_key_Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS    status = OK;
    SLHDSACtx  ctx = {0};
    rng_buffer fake = {0};
    ubyte      *pRNG = NULL;
    sbyte4     cmpRes;
    ubyte      *pKey = NULL;
    size_t     keyLen;
    ubyte4     n;

#include "fips_kat_slhdsa_shake_key_data.inc"

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_slhdsa_shake_key_Kat", "SLHDSA-SHAKE-128f");

    /* Make algo context for SLHDSA-SHAKE-128f */
    status = SLHDSA_createCtx(SLHDSA_TYPE_SHAKE_128F, hwAccelCtx, &ctx);
    if (OK != status)
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        goto exitRet; /* No clean up*/
    }

    /* Confirm sizes match */
    n = ctx.params.n;
    if (3*n != SKSeedLen+SKPrfLen+PKSeedLen)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Allocate the RNG output buffer */
    status = DIGI_MALLOC((void **) &pRNG, 3*n);
    if (OK != status)
        goto exit;

    /* Set three seed values */
    (void)DIGI_MEMCPY(pRNG, pSKSeed, SKSeedLen);
    (void)DIGI_MEMCPY(pRNG+SKSeedLen, pSKPrf, SKPrfLen);
    (void)DIGI_MEMCPY(pRNG+SKSeedLen+SKPrfLen, pPKSeed, PKSeedLen);
    fake.offset = 0;
    fake.capacity = SKSeedLen+SKPrfLen+PKSeedLen;
    fake.pBuf = pRNG;

    if (FIPS_FORCE_FAIL_SLHDSA_SHAKE_KEY_TEST)
    {
        pRNG[0] ^= 0x01;
    }

    status = SLHDSA_generateKeyPair(FIPS_KAT_rngFun_Echo, (void*)&fake, &ctx);
    if (OK != status)
        goto exit;

    status = SLHDSA_getPrivateKeyLen(&ctx, &keyLen);
    if (OK != status)
        goto exit;

    if (skValLen != keyLen)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Allocate the privat key output buffer */
    status = DIGI_MALLOC((void **) &pKey, keyLen);
    if (OK != status)
        goto exit;

    status = SLHDSA_getPrivateKey(&ctx, pKey, keyLen);
    if (OK != status)
        goto exit;

    /* Compare with expectation */
    if (OK != DIGI_CTIME_MATCH(pKey, skVal, keyLen, &cmpRes))
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_shake - DIGI_CTIME_MATCH(secret) - Failed");
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_shake - cmpRes(secret) - Failed");
        goto exit;
    }

exit:
    DIGI_FREE((void**)&pKey);
    DIGI_FREE((void**)&pRNG);
    SLHDSA_destroyCtx(&ctx);

exitRet:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_slhdsa_shake_key_Kat", "SLHDSA-SHAKE-128f", status);

    setFIPS_Status_Once(FIPS_ALGO_SLHDSA, status);
    return status;
}

MOC_EXTERN MSTATUS FIPS_slhdsa_shake_sign_Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS   status = OK;
    SLHDSACtx ctx = {0};
    ubyte     *pSignature = NULL;
    ubyte     *pMsg = NULL;
    size_t    signatureLen;
    sbyte4    cmpRes;

#include "fips_kat_slhdsa_shake_sign_data.inc"

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_slhdsa_shake_sign_Kat", "SLHDSA-SHAKE-128f");

    /* Make algo context for SLHDSA/SHAKE-128f */
    status = SLHDSA_createCtx(SLHDSA_TYPE_SHAKE_128F, hwAccelCtx, &ctx);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_shake - SLHDSA create context - Failed");
        goto exitRet; /* No clean up*/
    }

    /* Allocate signature buffer */
    status = SLHDSA_getSignatureLen(&ctx, &signatureLen);
    if (OK != status)
        goto exit;
    if (signatureLen != checkLen)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = DIGI_CALLOC((void**)&pSignature, 1, signatureLen);
    if (OK != status)
        goto exit;

    /* Create message */
    status = DIGI_MALLOC_MEMCPY((void**)&pMsg, msgLen, (void*)msg, msgLen);
    if (OK != status)
        goto exit;

    if (FIPS_FORCE_FAIL_SLHDSA_SHAKE_SIGN_TEST)
    {
        pMsg[0] ^= 0x01;
    }

    /* Set secret key */
    status = SLHDSA_setPrivateKey((uint8_t*)secretKey, secretKeyLen, &ctx);
    if (OK != status)
        goto exit;

    /* Set context */
    status = SLHDSA_setContext(context, contextLen, &ctx);
    if (OK != status)
        goto exit;

    /* Create signature data */
    status = SLHDSA_signMessage(&ctx, pMsg, msgLen,
                                NULL, 0,
                                pSignature, signatureLen);
    if (OK != status)
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_shake - SLHDSA_Sign - Failed");
        goto exit;
    }

    /* Compare with expectation */
    if (OK != DIGI_CTIME_MATCH(pSignature, check, signatureLen, &cmpRes))
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_shake - DIGI_CTIME_MATCH(pSig) - Failed");
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_shake - cmpRes(pSig) - Failed");
        goto exit;
    }

exit:
    DIGI_FREE((void**)&pMsg);
    DIGI_FREE((void**)&pSignature);
    SLHDSA_destroyCtx(&ctx);

exitRet:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_slhdsa_shake_sign_Kat", "SLHDSA-SHAKE-128f", status);

    setFIPS_Status_Once(FIPS_ALGO_SLHDSA, status);
    return status;
}

MOC_EXTERN MSTATUS FIPS_slhdsa_shake_verify_Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS   status = OK;
    SLHDSACtx ctx = {0};
    ubyte     *pContext = NULL;

#include "fips_kat_slhdsa_shake_verify_data.inc"

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_slhdsa_shake_verify_Kat", "SLHDSA-SHAKE-128f");

    /* Make algo context for SLHDSA-SHAKE-128f */
    status = SLHDSA_createCtx(SLHDSA_TYPE_SHAKE_128F, hwAccelCtx, &ctx);
    if (OK != status)
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        goto exitRet; /* No clean up*/
    }

    /* Set public key */
    status = SLHDSA_setPublicKey((uint8_t*)pPublicKey, publicKeyLen, &ctx);
    if (OK != status)
        goto exit;

    /* Set context */
    status = DIGI_MALLOC_MEMCPY((void**)&pContext, contextLen, (void*)context, contextLen);
    if (OK != status)
        goto exit;

    if (FIPS_FORCE_FAIL_SLHDSA_SHAKE_VERIFY_TEST)
    {
        pContext[0] ^= 0x01;
    }

    status = SLHDSA_setContext(pContext, contextLen, &ctx);
    if (OK != status)
        goto exit;

    /* Verify */
    status = SLHDSA_verifyMessage(&ctx, (uint8_t*)msg, msgLen, (uint8_t*)pSignature, signatureLen);
    if (OK != status)
    {
        status = ERR_FIPS_SLHDSA_KAT_FAILED;
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_KAT - slhdsaKat_shake - SLHDSA_verify - Failed");
        goto exit;
    }

exit:
    DIGI_FREE((void**)&pContext);
    SLHDSA_destroyCtx(&ctx);

exitRet:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_slhdsa_shake_verify_Kat", "SLHDSA-SHAKE-128f", status);

    setFIPS_Status_Once(FIPS_ALGO_SLHDSA, status);
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_FIPS_SLHDSA__) */
#endif /* (defined(__ENABLE_DIGICERT_PQC_SIG__)) */

/*------------------------------------------------------------------*/

static MSTATUS
FIPS_doKatHash(hwAccelDescr hwAccelCtx, const BulkHashAlgo *pHashSuite,
               ubyte *pData, ubyte4 dataLen, ubyte *pExpect,
               intBoolean isForceFail)
{
    ubyte*      pResult = NULL;
    BulkCtx     pCtx     = NULL;
    sbyte4      cmpRes = 0;
    MSTATUS     status = OK;

    if (NULL == pHashSuite)
    {
        return ERR_FIPS_HASH_KAT_NULL;
    }

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, pHashSuite->digestSize, TRUE, &pResult)))
        goto exit;

    if (OK > (status = pHashSuite->allocFunc(MOC_HASH(hwAccelCtx) &pCtx)))
        goto exit;

    if (OK > (status = pHashSuite->initFunc(MOC_HASH(hwAccelCtx) pCtx)))
        goto exit;

    if (OK > (status = pHashSuite->updateFunc(MOC_HASH(hwAccelCtx) pCtx, pData, dataLen)))
        goto exit;

    if (OK > (status = pHashSuite->finalFunc(MOC_HASH(hwAccelCtx) pCtx, pResult)))
        goto exit;

    if (TRUE == isForceFail)
        *pResult ^= 0x80;

    if (OK != DIGI_CTIME_MATCH(pResult, pExpect, pHashSuite->digestSize, &cmpRes))
    {
        status = ERR_FIPS_HASH_KAT_FAILED;
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_FIPS_HASH_KAT_FAILED;
        goto exit;
    }

exit:

    if (NULL != pCtx)
    {
        (void) pHashSuite->freeFunc(MOC_HASH(hwAccelCtx) &pCtx);
    }
    if (NULL != pResult)
    {
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &pResult);
    }
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
FIPS_createHashCtx(hwAccelDescr hwAccelCtx, ubyte **ppRetHashData, ubyte4 *pRetHashDataLen)
{
    MSTATUS status;

    *pRetHashDataLen = 32;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, *pRetHashDataLen, TRUE, ppRetHashData)))
        goto exit;

    status = DIGI_MEMSET(*ppRetHashData, 0x00, *pRetHashDataLen);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static void
FIPS_deleteHashCtx(hwAccelDescr hwAccelCtx, ubyte **ppFreeHashData)
{
    CRYPTO_FREE(hwAccelCtx, TRUE, ppFreeHashData);
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hashKat(hwAccelDescr hwAccelCtx,
             const char *pTestName,
             const BulkHashAlgo *pHashSuite,
             ubyte *pExpect, ubyte4 expectLen,
             intBoolean isForceFail)
{
    ubyte*              pData = NULL;
    ubyte4              dataLen;
    MSTATUS             status = OK;

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_hashKat", pTestName);

    if (expectLen != pHashSuite->digestSize)
    {
        status = ERR_FIPS_HASH_KAT_LEN_FAILED;
        goto exit;
    }

    if (OK > (status = FIPS_createHashCtx(hwAccelCtx, &pData, &dataLen)))
        goto exit;

    if (OK > (status = FIPS_doKatHash(hwAccelCtx, pHashSuite, pData, dataLen, pExpect, isForceFail)))
        goto exit;

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_hashKat", pTestName, status);

    FIPS_deleteHashCtx(hwAccelCtx, &pData);

    return status;

} /* FIPS_hashKat */


/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS
FIPS_sha1Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0xde,0x8a,0x84,0x7b,0xff,0x8c,0x34,0x3d,
        0x69,0xb8,0x53,0xa2,0x15,0xe6,0xee,0x77,
        0x5e,0xf2,0xef,0x96
    };

    MSTATUS status = FIPS_hashKat(hwAccelCtx, "SHA-1", &SHA1Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_SHA1_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA1, status);
    return status;

} /* FIPS_sha1Kat */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_sha224Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0xb3,0x38,0xc7,0x6b,0xcf,0xfa,0x1a,0x0b,
        0x3e,0xad,0x8d,0xe5,0x8d,0xfb,0xff,0x47,
        0xb6,0x3a,0xb1,0x15,0x0e,0x10,0xd8,0xf1,
        0x7f,0x2b,0xaf,0xdf
    };

    MSTATUS status = FIPS_hashKat(hwAccelCtx, "SHA-224", &SHA224Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_SHA224_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA256, status);
    return status;

} /* FIPS_sha224Kat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_sha256Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0x66,0x68,0x7a,0xad,0xf8,0x62,0xbd,0x77,
        0x6c,0x8f,0xc1,0x8b,0x8e,0x9f,0x8e,0x20,
        0x08,0x97,0x14,0x85,0x6e,0xe2,0x33,0xb3,
        0x90,0x2a,0x59,0x1d,0x0d,0x5f,0x29,0x25
    };

    MSTATUS status = FIPS_hashKat(hwAccelCtx, "SHA-256", &SHA256Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_SHA256_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA256, status);
    return status;

} /* FIPS_sha256Kat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_sha384Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0xa3,0x8f,0xff,0x4b,0xa2,0x6c,0x15,0xe4,
        0xac,0x9c,0xde,0x8c,0x03,0x10,0x3a,0xc8,
        0x90,0x80,0xfd,0x47,0x54,0x5f,0xde,0x94,
        0x46,0xc8,0xf1,0x92,0x72,0x9e,0xab,0x7b,
        0xd0,0x3a,0x4d,0x5c,0x31,0x87,0xf7,0x5f,
        0xe2,0xa7,0x1b,0x0e,0xe5,0x0a,0x4a,0x40
    };

    MSTATUS status = FIPS_hashKat(hwAccelCtx, "SHA-384", &SHA384Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_SHA384_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA512, status);
    return status;

} /* FIPS_sha384Kat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_sha512Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0x50,0x46,0xad,0xc1,0xdb,0xa8,0x38,0x86,
        0x7b,0x2b,0xbb,0xfd,0xd0,0xc3,0x42,0x3e,
        0x58,0xb5,0x79,0x70,0xb5,0x26,0x7a,0x90,
        0xf5,0x79,0x60,0x92,0x4a,0x87,0xf1,0x96,
        0x0a,0x6a,0x85,0xea,0xa6,0x42,0xda,0xc8,
        0x35,0x42,0x4b,0x5d,0x7c,0x8d,0x63,0x7c,
        0x00,0x40,0x8c,0x7a,0x73,0xda,0x67,0x2b,
        0x7f,0x49,0x85,0x21,0x42,0x0b,0x6d,0xd3
    };

    MSTATUS status = FIPS_hashKat(hwAccelCtx, "SHA-512", &SHA512Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_SHA512_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA512, status);
    return status;

} /* FIPS_sha512Kat */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_sha224_256Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;

#if (!defined(__DISABLE_DIGICERT_SHA224__))
    if (OK > (status = FIPS_sha224Kat(hwAccelCtx)))
         goto exit;
#endif
#if (!defined(__DISABLE_DIGICERT_SHA256__))
     if (OK > (status = FIPS_sha256Kat(hwAccelCtx)))
         goto exit;
#endif

exit:
    return status;

} /* FIPS_sha224_256Kat */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_sha384_512Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;

#if (!defined(__DISABLE_DIGICERT_SHA384__))
    if (OK > (status = FIPS_sha384Kat(hwAccelCtx)))
         goto exit;
#endif
#if (!defined(__DISABLE_DIGICERT_SHA512__))
     if (OK > (status = FIPS_sha512Kat(hwAccelCtx)))
         goto exit;
#endif

exit:
    return status;

} /* FIPS_sha384_512Kat */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SHA3__))
static MSTATUS
FIPS_doSha3Kat(hwAccelDescr hwAccelCtx,
      const char* testId,
      ubyte *pMsg, ubyte4 msgLen,
      ubyte4 mode, ubyte4 outSize,
      ubyte *pExpect, ubyte4 expectLen,
      intBoolean isForceFail)
{
   MSTATUS status;
   sbyte4  cmpRes;
   ubyte digest[64];

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_sha3Kat", testId);

   status = SHA3_completeDigest(mode, pMsg, msgLen, digest, outSize);
   if (OK != status)
      goto exit;

   if (TRUE == isForceFail)
   {
      *digest ^= 0x80;
   }

   cmpRes = 0;
   if (OK != DIGI_CTIME_MATCH(digest, pExpect, expectLen, &cmpRes))
   {
       status = ERR_FIPS_HASH_KAT_FAILED;
       goto exit;
   }
   if (0 != cmpRes)
   {
       status = ERR_FIPS_HASH_KAT_FAILED;
       goto exit;
   }

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_sha3Kat", testId, status);

   return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_sha3_224Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;
    ubyte inMsg[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    ubyte expect_224[] = {
            0x73, 0xE0, 0x87, 0xAE, 0x12, 0x71, 0xB2, 0xC5,
            0xF6, 0x85, 0x46, 0xC9, 0x3A, 0xB4, 0x25, 0x14,
            0xA6, 0x9E, 0xEF, 0x25, 0x2B, 0xFD, 0xD1, 0x37,
            0x55, 0x74, 0x8A, 0x00
    };

    /* SHA3-224 mode */
    status = FIPS_doSha3Kat(hwAccelCtx, "SHA3-224", inMsg, sizeof(inMsg),
            MOCANA_SHA3_MODE_SHA3_224, 0, expect_224, sizeof(expect_224),
            FIPS_FORCE_FAIL_SHA3_224_TEST);
    if (OK != status)
        goto exit;

exit:
    setFIPS_Status_Once(FIPS_ALGO_SHA3_224, status);
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_sha3_256Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;
    ubyte inMsg[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    ubyte expect_256[] = {
            0x9E, 0x62, 0x91, 0x97, 0x0C, 0xB4, 0x4D, 0xD9,
            0x40, 0x08, 0xC7, 0x9B, 0xCA, 0xF9, 0xD8, 0x6F,
            0x18, 0xB4, 0xB4, 0x9B, 0xA5, 0xB2, 0xA0, 0x47,
            0x81, 0xDB, 0x71, 0x99, 0xED, 0x3B, 0x9E, 0x4E
    };

    /* SHA3-256 mode */
    status = FIPS_doSha3Kat(hwAccelCtx, "SHA3-256", inMsg, sizeof(inMsg),
            MOCANA_SHA3_MODE_SHA3_256, 0, expect_256, sizeof(expect_256),
            FIPS_FORCE_FAIL_SHA3_256_TEST);
    if (OK != status)
        goto exit;

exit:
    setFIPS_Status_Once(FIPS_ALGO_SHA3_256, status);
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_sha3_384Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;
    ubyte inMsg[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    ubyte expect_384[] = {
            0x4B, 0xDA, 0xAB, 0xF7, 0x88, 0xD3, 0xAD, 0x1A,
            0xD8, 0x3D, 0x6D, 0x93, 0xC7, 0xE4, 0x49, 0x37,
            0xC2, 0xE6, 0x49, 0x6A, 0xF2, 0x3B, 0xE3, 0x35,
            0x4D, 0x75, 0x69, 0x87, 0xF4, 0x51, 0x60, 0xFC,
            0x40, 0x23, 0xBD, 0xA9, 0x5E, 0xCD, 0xCB, 0x3C,
            0x7E, 0x31, 0xA6, 0x2F, 0x72, 0x6D, 0x70, 0x2C
    };

    /* SHA3-384 mode */
    status = FIPS_doSha3Kat(hwAccelCtx, "SHA3-384", inMsg, sizeof(inMsg),
            MOCANA_SHA3_MODE_SHA3_384, 0, expect_384, sizeof(expect_384),
            FIPS_FORCE_FAIL_SHA3_384_TEST);
    if (OK != status)
        goto exit;

exit:
    setFIPS_Status_Once(FIPS_ALGO_SHA3_384, status);
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_sha3_512Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;
    ubyte inMsg[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    ubyte expect_512[] = {
            0xAD, 0x56, 0xC3, 0x5C, 0xAB, 0x50, 0x63, 0xB9,
            0xE7, 0xEA, 0x56, 0x83, 0x14, 0xEC, 0x81, 0xC4,
            0x0B, 0xA5, 0x77, 0xAA, 0xE6, 0x30, 0xDE, 0x90,
            0x20, 0x04, 0x00, 0x9E, 0x88, 0xF1, 0x8D, 0xA5,
            0x7B, 0xBD, 0xFD, 0xAA, 0xA0, 0xFC, 0x18, 0x9C,
            0x66, 0xC8, 0xD8, 0x53, 0x24, 0x8B, 0x6B, 0x11,
            0x88, 0x44, 0xD5, 0x3F, 0x7D, 0x0B, 0xA1, 0x1D,
            0xE0, 0xF3, 0xBF, 0xAF, 0x4C, 0xDD, 0x9B, 0x3F
    };

    /* SHA3-512 mode */
    status = FIPS_doSha3Kat(hwAccelCtx, "SHA3-512", inMsg, sizeof(inMsg),
            MOCANA_SHA3_MODE_SHA3_512, 0, expect_512, sizeof(expect_512),
            FIPS_FORCE_FAIL_SHA3_512_TEST);
    if (OK != status)
        goto exit;

exit:
    setFIPS_Status_Once(FIPS_ALGO_SHA3_512, status);
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_sha3_shake128Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;
    ubyte inMsg[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    ubyte expect_SHAKE128[] = {
            0x24, 0xA7, 0xCA, 0x4B, 0x75, 0xE3, 0x89, 0x8D,
            0x4F, 0x12, 0xE7, 0x4D, 0xEA, 0x8C, 0xBB, 0x65,
            0x07, 0x33, 0xBD, 0x34, 0x52, 0x5B, 0x28, 0x1E,
            0x4B, 0x64, 0x88, 0xD4, 0x29, 0x1C, 0x0F, 0xDB
    };

    /* SHAKE-128 mode */
    status = FIPS_doSha3Kat(hwAccelCtx, "SHAKE-128", inMsg, sizeof(inMsg),
            MOCANA_SHA3_MODE_SHAKE128, sizeof(expect_SHAKE128), expect_SHAKE128, sizeof(expect_SHAKE128),
            FIPS_FORCE_FAIL_SHAKE_128_TEST);
    if (OK != status)
        goto exit;

exit:
    setFIPS_Status_Once(FIPS_ALGO_SHA3_SHAKE128, status);
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_sha3_shake256Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;
    ubyte inMsg[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    ubyte expect_SHAKE256[] = {
            0xF5, 0x97, 0x7C, 0x82, 0x83, 0x54, 0x6A, 0x63,
            0x72, 0x3B, 0xC3, 0x1D, 0x26, 0x19, 0x12, 0x4F,
            0x11, 0xDB, 0x46, 0x58, 0x64, 0x33, 0x36, 0x74,
            0x1D, 0xF8, 0x17, 0x57, 0xD5, 0xAD, 0x30, 0x62
    };

    /* SHAKE-256 mode */
    status = FIPS_doSha3Kat(hwAccelCtx, "SHAKE-256", inMsg, sizeof(inMsg),
            MOCANA_SHA3_MODE_SHAKE256, sizeof(expect_SHAKE256), expect_SHAKE256, sizeof(expect_SHAKE256),
            FIPS_FORCE_FAIL_SHAKE_256_TEST);

    setFIPS_Status_Once(FIPS_ALGO_SHA3_SHAKE256, status);
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_SHA3__) */

/*------------------------------------------------------------------*/

static MSTATUS
FIPS_createSymCtx(hwAccelDescr hwAccelCtx,
                  const BulkEncryptionAlgo *pBulkEncAlgo,
                  ubyte **ppRetKey, ubyte4 keyLen,
                  ubyte **ppRetData, ubyte4 *pRetDataLen,
                  ubyte **ppRetIv)
{
    ubyte*  pTempKey = NULL;
    ubyte*  pTempData = NULL;
    ubyte*  pTempIv = NULL;
    MSTATUS status;

    *pRetDataLen = 32;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, keyLen, TRUE, &pTempKey)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, *pRetDataLen, TRUE, &pTempData)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, pBulkEncAlgo->blockSize, TRUE, &pTempIv)))
        goto exit;

    if (OK > (status = DIGI_MEMSET(pTempKey, 0x00, keyLen)))
        goto exit;

    if (OK > (status = DIGI_MEMSET(pTempData, 0x00, *pRetDataLen)))
        goto exit;

    if (OK > (status = DIGI_MEMSET(pTempIv, 0x00, pBulkEncAlgo->blockSize)))
        goto exit;

    *ppRetKey = pTempKey;
    *ppRetData = pTempData;
    *ppRetIv = pTempIv;

    pTempKey = NULL;
    pTempData = NULL;
    pTempIv = NULL;

exit:
    CRYPTO_FREE(hwAccelCtx, TRUE, &pTempIv);
    CRYPTO_FREE(hwAccelCtx, TRUE, &pTempData);
    CRYPTO_FREE(hwAccelCtx, TRUE, &pTempKey);

    return status;
}


/*------------------------------------------------------------------*/

static void
FIPS_deleteSymCtx(hwAccelDescr hwAccelCtx, ubyte **ppFreeKey, ubyte **ppFreeHashData, ubyte **ppFreeIv)
{
    CRYPTO_FREE(hwAccelCtx, TRUE, ppFreeHashData);
    CRYPTO_FREE(hwAccelCtx, TRUE, ppFreeKey);
    CRYPTO_FREE(hwAccelCtx, TRUE, ppFreeIv);
}


/*------------------------------------------------------------------*/

static MSTATUS
FIPS_doKatSymmetric(hwAccelDescr hwAccelCtx,
                    const BulkEncryptionAlgo *pBulkEncAlgo,
                    ubyte* pKey, sbyte4 keyLen,
                    ubyte* pData, sbyte4 dataLen,
                    sbyte4 encrypt, ubyte* pIv,
                    ubyte* pExpect,
                    intBoolean isForceFail)
{
    BulkCtx ctx = NULL;
    sbyte4  cmpRes = 0;
    MSTATUS status = OK;

    if (NULL == pBulkEncAlgo)
    {
        return ERR_FIPS_SYM_KAT_NULL;
    }

    ctx = pBulkEncAlgo->createFunc(MOC_SYM(hwAccelCtx) pKey, keyLen, encrypt);

    if (NULL == ctx)
    {
        return ERR_FIPS_SYM_KAT_NULL;
    }

    if (OK > (status = pBulkEncAlgo->cipherFunc(MOC_SYM(hwAccelCtx) ctx, pData, dataLen, encrypt, pIv)))
        goto exit;

    if (TRUE == isForceFail)
        *pData ^= 0x80;

    if (OK != DIGI_CTIME_MATCH(pData, pExpect, dataLen, &cmpRes))
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
    }

exit:

    (void) pBulkEncAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &ctx);

    return status;

} /* FIPS_doKatSymmetric */

/*------------------------------------------------------------------*/

static MSTATUS
FIPS_createHmacHashCtx(hwAccelDescr hwAccelCtx, ubyte **ppRetKey, ubyte4 *pRetKeyLen,
                       ubyte **ppRetHashData, ubyte4 *pRetHashDataLen)
{
    ubyte*  pTempKey = NULL;
    ubyte*  pTempData = NULL;
    MSTATUS status;

    *pRetKeyLen = 32;
    *pRetHashDataLen = 32;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, *pRetKeyLen, TRUE, &pTempKey)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, *pRetHashDataLen, TRUE, &pTempData)))
        goto exit;

    if (OK > (status = DIGI_MEMSET(pTempKey, 0x00, *pRetKeyLen)))
        goto exit;

    if (OK > (status = DIGI_MEMSET(pTempData, 0x00, *pRetHashDataLen)))
        goto exit;

    *ppRetKey = pTempKey;
    *ppRetHashData = pTempData;

    pTempKey = NULL;
    pTempData = NULL;

exit:
    CRYPTO_FREE(hwAccelCtx, TRUE, &pTempData);
    CRYPTO_FREE(hwAccelCtx, TRUE, &pTempKey);

    return status;
}


/*------------------------------------------------------------------*/

static void
FIPS_deleteHmacHashCtx(hwAccelDescr hwAccelCtx, ubyte **ppFreeKey, ubyte **ppFreeHashData)
{
    CRYPTO_FREE(hwAccelCtx, TRUE, ppFreeHashData);
    CRYPTO_FREE(hwAccelCtx, TRUE, ppFreeKey);
}


/*------------------------------------------------------------------*/

static MSTATUS
FIPS_doKatHmacHash(hwAccelDescr hwAccelCtx, const BulkHashAlgo *pHashSuite, ubyte* pKey, ubyte4 keyLen, ubyte* pData, ubyte4 dataLen, ubyte* pExpect, intBoolean isForceFail)
{
    HMAC_CTX*   pHMACCtx = NULL;
    sbyte4      cmpRes = 0;
    ubyte*      pResult = NULL;
    MSTATUS     status = OK;

    if (NULL == pHashSuite)
    {
        status = ERR_FIPS_HMAC_HASH_KAT_NULL;
        goto exit;
    }

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, pHashSuite->digestSize, TRUE, &pResult)))
        goto exit;

    if (OK > (status = HmacCreate(MOC_HASH(hwAccelCtx) &pHMACCtx, pHashSuite)))
        goto exit;

    if (OK > (status = HmacKey(MOC_HASH(hwAccelCtx) pHMACCtx, pKey, keyLen)))
        goto exit;

    if (OK > (status = HmacUpdate(MOC_HASH(hwAccelCtx) pHMACCtx, pData, dataLen)))
        goto exit;

    if (OK > (status = HmacFinal(MOC_HASH(hwAccelCtx) pHMACCtx, pResult)))
        goto exit;

    if (TRUE == isForceFail)
        *pResult ^= 0x80;

    if (OK != DIGI_CTIME_MATCH(pResult, pExpect, pHashSuite->digestSize, &cmpRes))
    {
        status = ERR_FIPS_HMAC_HASH_KAT_FAILED;
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_FIPS_HMAC_HASH_KAT_FAILED;
        goto exit;
    }

exit:
    HmacDelete(MOC_HASH(hwAccelCtx) &pHMACCtx);
    CRYPTO_FREE(hwAccelCtx, TRUE, &pResult);

    return status;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacHashKat(hwAccelDescr hwAccelCtx,
                 const char *pTestName,
                 const BulkHashAlgo *pHmacSuite,
                 ubyte *pExpect, ubyte4 expectLen,
                 intBoolean isForceFail)
{
    ubyte*              pKey = NULL;
    ubyte4              keyLen;
    ubyte*              pData = NULL;
    ubyte4              dataLen;
    MSTATUS             status = OK;

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_hmacHashKat", pTestName);

    if (expectLen != pHmacSuite->digestSize)
    {
        status = ERR_FIPS_HMAC_HASH_KAT_LEN_FAILED;
        goto exit;
    }

    if (OK > (status = FIPS_createHmacHashCtx(hwAccelCtx, &pKey, &keyLen, &pData, &dataLen)))
        goto exit;

    if (OK > (status = FIPS_doKatHmacHash(hwAccelCtx, pHmacSuite, pKey, keyLen, pData, dataLen, pExpect, isForceFail)))
        goto exit;

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_hmacHashKat", pTestName, status);

    FIPS_deleteHmacHashCtx(hwAccelCtx, &pKey, &pData);

    setFIPS_Status_Once(FIPS_ALGO_HMAC, status);

    return status;

} /* FIPS_hmacHashKat */


/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS
FIPS_hmacSha1Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0x66,0x04,0x09,0x90,0xc7,0x99,0x2a,0x2a,
        0x00,0xd0,0x37,0xd0,0xb8,0x63,0x1c,0x0d,
        0xb1,0x78,0x58,0x97
    };

    MSTATUS status = FIPS_hmacHashKat(hwAccelCtx, "HMAC-SHA-1", &SHA1Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_SHA1_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA1, status);
    return status;


} /* FIPS_hmacSha1Kat */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacSha224Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0xc8,0xed,0x8a,0x8b,0xca,0xaf,0xad,0x43,
        0xcb,0xd9,0x7d,0x82,0x95,0x04,0x3d,0xd2,
        0x31,0x34,0xcc,0xd9,0xc3,0x90,0x00,0x0e,
        0xd4,0x70,0xbb,0x48
    };

    MSTATUS status = FIPS_hmacHashKat(hwAccelCtx, "HMAC-SHA-224", &SHA224Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_SHA224_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA256, status);
    return status;

} /* FIPS_hmacSha224Kat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacSha256Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0x33,0xad,0x0a,0x1c,0x60,0x7e,0xc0,0x3b,
        0x09,0xe6,0xcd,0x98,0x93,0x68,0x0c,0xe2,
        0x10,0xad,0xf3,0x00,0xaa,0x1f,0x26,0x60,
        0xe1,0xb2,0x2e,0x10,0xf1,0x70,0xf9,0x2a
    };

    MSTATUS status = FIPS_hmacHashKat(hwAccelCtx, "HMAC-SHA-256", &SHA256Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_SHA256_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA256, status);
    return status;

} /* FIPS_hmacSha256Kat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacSha384Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0xe6,0x65,0xec,0x75,0xdc,0xa3,0x23,0xdf,
        0x31,0x80,0x40,0x60,0xe1,0xb0,0xd8,0x28,
        0xb5,0x0a,0x6a,0x8a,0x53,0x9c,0xfe,0xdd,
        0x9a,0xa0,0x07,0x4b,0x5b,0x36,0x44,0x5d,
        0xef,0xbc,0x47,0x45,0x3d,0xf8,0xd0,0xc1,
        0x4b,0x7a,0xd2,0x06,0x2e,0x7b,0xbd,0xb1
    };

    MSTATUS status = FIPS_hmacHashKat(hwAccelCtx, "HMAC-SHA-384", &SHA384Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_SHA384_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA512, status);
    return status;

} /* FIPS_hmacSha384Kat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacSha512Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0xba,0xe4,0x6c,0xeb,0xeb,0xbb,0x90,0x40,
        0x9a,0xbc,0x5a,0xcf,0x7a,0xc2,0x1f,0xdb,
        0x33,0x9c,0x01,0xce,0x15,0x19,0x2c,0x52,
        0xfb,0x9e,0x8a,0xa1,0x1a,0x8d,0xe9,0xa4,
        0xea,0x15,0xa0,0x45,0xf2,0xbe,0x24,0x5f,
        0xbb,0x98,0x91,0x6a,0x9a,0xe8,0x1b,0x35,
        0x3e,0x33,0xb9,0xc4,0x2a,0x55,0x38,0x0c,
        0x51,0x58,0x24,0x1d,0xae,0xb3,0xc6,0xdd
    };

    MSTATUS status = FIPS_hmacHashKat(hwAccelCtx, "HMAC-SHA-512", &SHA512Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_SHA512_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA512, status);
    return status;

} /* FIPS_hmacSha512Kat */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_FIPS_SHA3__)
MOC_EXTERN MSTATUS
FIPS_hmacSha3_224Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0x20,0x35,0x50,0xcb,0xba,0x31,0x7d,0x88,
        0xe0,0x6b,0x99,0x33,0xdc,0x4a,0xe0,0xab,
        0xa9,0xd3,0x48,0x61,0x50,0x71,0x41,0x1f,
        0x6d,0x61,0x8f,0xec
    };

    MSTATUS status = FIPS_hmacHashKat(hwAccelCtx, "HMAC-SHA3-224", &SHA3_224Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_SHA3_224_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA3_224, status);
    return status;

} /* FIPS_hmacSha3_224Kat */

MOC_EXTERN MSTATUS
FIPS_hmacSha3_256Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0xb1,0x6b,0x08,0xd9,0x47,0x26,0x20,0xed,
        0x17,0x12,0x35,0x4b,0x6d,0x2b,0xc4,0x76,
        0xfb,0xd6,0xb0,0x3e,0xd9,0x0e,0xd5,0x47,
        0x55,0x1e,0xc1,0x55,0xb9,0xac,0xe0,0x83
    };

    MSTATUS status = FIPS_hmacHashKat(hwAccelCtx, "HMAC-SHA3-256", &SHA3_256Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_SHA3_256_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA3_256, status);
    return status;

} /* FIPS_hmacSha3_256Kat */

MOC_EXTERN MSTATUS
FIPS_hmacSha3_384Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0xe8,0xc6,0xb2,0x13,0x91,0xbb,0xfc,0x07,
        0x55,0xce,0x62,0x4b,0xda,0xe7,0xe1,0x97,
        0xb5,0xee,0xba,0xe8,0xa1,0x7f,0x85,0x37,
        0x7f,0xed,0x0e,0xeb,0x0d,0xca,0xce,0x87,
        0x75,0x81,0x41,0x71,0xda,0x5f,0xf0,0xa0,
        0x0e,0xd9,0x61,0x2f,0xf5,0xea,0x73,0x3d
    };

    MSTATUS status = FIPS_hmacHashKat(hwAccelCtx, "HMAC-SHA3-384", &SHA3_384Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_SHA3_384_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA3_384, status);
    return status;

} /* FIPS_hmacSha3_384Kat */

MOC_EXTERN MSTATUS
FIPS_hmacSha3_512Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
        0x4b,0xc4,0x36,0x19,0x98,0x01,0xbe,0xa7,
        0xff,0xaf,0xe4,0x1a,0x18,0xf8,0xb2,0xce,
        0x99,0xdd,0xdb,0x45,0xa3,0xbc,0xff,0x4c,
        0xaf,0x2c,0x11,0xe6,0xc4,0x69,0x1e,0x2a,
        0x87,0x28,0x9b,0xc7,0x8f,0xae,0x94,0x72,
        0xdb,0x03,0x74,0xb6,0xdd,0x90,0x9f,0xf5,
        0x07,0x0f,0xe5,0xa8,0x61,0x13,0x23,0xd3,
        0x80,0xac,0x33,0x67,0x81,0x4f,0xab,0x4d
    };

    MSTATUS status = FIPS_hmacHashKat(hwAccelCtx, "HMAC-SHA3-512", &SHA3_512Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_SHA3_512_TEST);
    setFIPS_Status_Once(FIPS_ALGO_SHA3_512, status);
    return status;

} /* FIPS_hmacSha3_512Kat */

#endif /* defined(__ENABLE_DIGICERT_FIPS_SHA3__) */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacShaAllKat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;

    if (OK > (status = FIPS_hmacSha1Kat(hwAccelCtx)))
        goto exit;
    if (OK > (status = FIPS_hmacSha224Kat(hwAccelCtx)))
        goto exit;
    if (OK > (status = FIPS_hmacSha256Kat(hwAccelCtx)))
        goto exit;
    if (OK > (status = FIPS_hmacSha384Kat(hwAccelCtx)))
        goto exit;
    if (OK > (status = FIPS_hmacSha512Kat(hwAccelCtx)))
        goto exit;

#if defined(__ENABLE_DIGICERT_FIPS_SHA3__)
    if (OK > (status = FIPS_hmacSha3_224Kat(hwAccelCtx)))
         goto exit;
    if (OK > (status = FIPS_hmacSha3_256Kat(hwAccelCtx)))
         goto exit;
    if (OK > (status = FIPS_hmacSha3_384Kat(hwAccelCtx)))
         goto exit;
    if (OK > (status = FIPS_hmacSha3_512Kat(hwAccelCtx)))
         goto exit;
#endif /* defined(__ENABLE_DIGICERT_FIPS_SHA3__) */

exit:
    return status;

} /* FIPS_hmacShaAllKat */

/*------------------------------------------------------------------*/

static MSTATUS
FIPS_symKat(hwAccelDescr hwAccelCtx,
            const char *pTestName,
            const BulkEncryptionAlgo *pBulkEncAlgo, ubyte4 keyLen,
            sbyte4 encrypt,
            ubyte *pExpect, ubyte4 expectLen,
            intBoolean isForceFail)
{
    ubyte*              pKey = NULL;
    ubyte*              pData = NULL;
    ubyte4              dataLen = expectLen;
    ubyte*              pIv = NULL;
    MSTATUS             status = OK;

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_symKat", pTestName);

    if ((0 < pBulkEncAlgo->blockSize) && (0 != (expectLen % pBulkEncAlgo->blockSize)))
    {
        status = ERR_FIPS_SYM_KAT_LEN_FAILED;
        goto exit;
    }

    if (OK > (status = FIPS_createSymCtx(hwAccelCtx, pBulkEncAlgo, &pKey, keyLen, &pData, &dataLen, &pIv)))
        goto exit;

     if (OK > (status = FIPS_doKatSymmetric(hwAccelCtx, pBulkEncAlgo,
                                            pKey, keyLen, pData, dataLen,
                                            encrypt, pIv,
                                            pExpect, isForceFail)))
     {
         goto exit;
     }

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_symKat", pTestName, status);

    FIPS_deleteSymCtx(hwAccelCtx, &pKey, &pData, &pIv);

    return status;

} /* FIPS_symKat */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_aes256CbcKat(hwAccelDescr hwAccelCtx)
{
    ubyte expect_enc[] = {
        0xdc,0x95,0xc0,0x78,0xa2,0x40,0x89,0x89,
        0xad,0x48,0xa2,0x14,0x92,0x84,0x20,0x87,
        0x08,0xc3,0x74,0x84,0x8c,0x22,0x82,0x33,
        0xc2,0xb3,0x4f,0x33,0x2b,0xd2,0xe9,0xd3
    };
    ubyte expect_dec[] = {
        0x67,0x67,0x1c,0xe1,0xfa,0x91,0xdd,0xeb,
        0x0f,0x8f,0xbb,0xb3,0x66,0xb5,0x31,0xb4,
        0x67,0x67,0x1c,0xe1,0xfa,0x91,0xdd,0xeb,
        0x0f,0x8f,0xbb,0xb3,0x66,0xb5,0x31,0xb4
    };

    MSTATUS status;

    if (OK > (status = FIPS_symKat(hwAccelCtx, "AES-CBC-256-ENC", &AESCBCSuite, 32,
       DO_ENCRYPT, expect_enc, sizeof(expect_enc), FIPS_FORCE_FAIL_AES_CBC_ENC_TEST)))
    {
        goto exit;
    }

    status = FIPS_symKat(hwAccelCtx, "AES-CBC-256-DEC", &AESCBCSuite, 32,
       DO_DECRYPT, expect_dec, sizeof(expect_dec), FIPS_FORCE_FAIL_AES_CBC_DEC_TEST);

exit:
    setFIPS_Status_Once(FIPS_ALGO_AES_CBC, status);
    return status;

} /* FIPS_aes256CbcKat */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_aesCfbKat(hwAccelDescr hwAccelCtx)
{
    ubyte expect_enc[] = {
        0xdc,0x95,0xc0,0x78,0xa2,0x40,0x89,0x89,
        0xad,0x48,0xa2,0x14,0x92,0x84,0x20,0x87,
        0x08,0xc3,0x74,0x84,0x8c,0x22,0x82,0x33,
        0xc2,0xb3,0x4f,0x33,0x2b,0xd2,0xe9,0xd3
    };

    ubyte expect_dec[] = {
        0xDC,0x95,0xC0,0x78,0xA2,0x40,0x89,0x89,
        0xAD,0x48,0xA2,0x14,0x92,0x84,0x20,0x87,
        0xDC,0x95,0xC0,0x78,0xA2,0x40,0x89,0x89,
        0xAD,0x48,0xA2,0x14,0x92,0x84,0x20,0x87
    };

    MSTATUS status;

    if (OK > (status = FIPS_symKat(hwAccelCtx, "AES-CFB-128-ENC", &AESCFBSuite, 32, DO_ENCRYPT, expect_enc, sizeof(expect_enc), FIPS_FORCE_FAIL_AES_CFB_ENC_TEST)))
        goto exit;

    status = FIPS_symKat(hwAccelCtx, "AES-CFB-128-DEC", &AESCFBSuite, 32, DO_DECRYPT, expect_dec, sizeof(expect_dec), FIPS_FORCE_FAIL_AES_CFB_DEC_TEST);

exit:
    setFIPS_Status_Once(FIPS_ALGO_AES_CFB, status);
    return status;

} /* FIPS_aesCfbKat */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_aes256CtrKat(hwAccelDescr hwAccelCtx)
{
    ubyte expect_enc[] = {
        0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,
        0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e,
        0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,
        0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a
    };
    ubyte expect_dec[] = {
        0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,
        0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e,
        0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,
        0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a
    };

    MSTATUS status;

    if (OK > (status = FIPS_symKat(hwAccelCtx, "AES-CTR-256-ENC", &AESCTRSuite, 32, DO_ENCRYPT, expect_enc, sizeof(expect_enc), FIPS_FORCE_FAIL_AES_CTR_ENC_TEST)))
        goto exit;

    status = FIPS_symKat(hwAccelCtx, "AES-CTR-256-DEC", &AESCTRSuite, 32, DO_DECRYPT, expect_dec, sizeof(expect_dec), FIPS_FORCE_FAIL_AES_CTR_DEC_TEST);

exit:
    setFIPS_Status_Once(FIPS_ALGO_AES_CTR, status);
    return status;

} /* FIPS_aes256CtrKat */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_aesOfbKat(hwAccelDescr hwAccelCtx)
{
    ubyte expect_enc[] = {
        0xdc,0x95,0xc0,0x78,0xa2,0x40,0x89,0x89,
        0xad,0x48,0xa2,0x14,0x92,0x84,0x20,0x87,
        0x08,0xc3,0x74,0x84,0x8c,0x22,0x82,0x33,
        0xc2,0xb3,0x4f,0x33,0x2b,0xd2,0xe9,0xd3
    };

    ubyte expect_dec[] = {
        0xdc,0x95,0xc0,0x78,0xa2,0x40,0x89,0x89,
        0xad,0x48,0xa2,0x14,0x92,0x84,0x20,0x87,
        0x08,0xc3,0x74,0x84,0x8c,0x22,0x82,0x33,
        0xc2,0xb3,0x4f,0x33,0x2b,0xd2,0xe9,0xd3
    };

    MSTATUS status;

    if (OK > (status = FIPS_symKat(hwAccelCtx, "AES-OFB-128-ENC", &AESOFBSuite, 32, DO_ENCRYPT, expect_enc, sizeof(expect_enc), FIPS_FORCE_FAIL_AES_OFB_ENC_TEST)))
        goto exit;

    status = FIPS_symKat(hwAccelCtx, "AES-OFB-128-DEC", &AESOFBSuite, 32, DO_DECRYPT, expect_dec, sizeof(expect_dec), FIPS_FORCE_FAIL_AES_OFB_DEC_TEST);

exit:
    setFIPS_Status_Once(FIPS_ALGO_AES_OFB, status);
    return status;

} /* FIPS_aesOfbKat */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_aes256EcbKat(hwAccelDescr hwAccelCtx)
{
    ubyte expect_enc[] = {
        0xdc,0x95,0xc0,0x78,0xa2,0x40,0x89,0x89,
        0xad,0x48,0xa2,0x14,0x92,0x84,0x20,0x87,
        0xdc,0x95,0xc0,0x78,0xa2,0x40,0x89,0x89,
        0xad,0x48,0xa2,0x14,0x92,0x84,0x20,0x87
    };
    ubyte expect_dec[] = {
        0x67,0x67,0x1c,0xe1,0xfa,0x91,0xdd,0xeb,
        0x0f,0x8f,0xbb,0xb3,0x66,0xb5,0x31,0xb4,
        0x67,0x67,0x1c,0xe1,0xfa,0x91,0xdd,0xeb,
        0x0f,0x8f,0xbb,0xb3,0x66,0xb5,0x31,0xb4
    };

    MSTATUS status;

    if (OK > (status = FIPS_symKat(hwAccelCtx, "AES-ECB-256-ENC", &AESECBSuite, 32, DO_ENCRYPT, expect_enc, sizeof(expect_enc), FIPS_FORCE_FAIL_AES_ECB_ENC_TEST)))
        goto exit;

    status = FIPS_symKat(hwAccelCtx, "AES-ECB-256-DEC", &AESECBSuite, 32, DO_DECRYPT, expect_dec, sizeof(expect_dec), FIPS_FORCE_FAIL_AES_ECB_DEC_TEST);

exit:
    setFIPS_Status_Once(FIPS_ALGO_AES_ECB, status);
    return status;

} /* FIPS_aes256EcbKat */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_aesXtsKat(hwAccelDescr hwAccelCtx)
{
    aesXtsTestPacketDescr   testPacket;
    sbyte4                  resCmp;
    MSTATUS                 status;
    BulkCtx                 ctx = 0;

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_aesXtsKat", "AES-XTS");

    /* make a copy because we are going to be modifying it */
    DIGI_MEMCPY(&testPacket, &AES_XTS_TESTCASE, sizeof(AES_XTS_TESTCASE));

    /* do encrypt first */
    ctx = CreateAESXTSCtx(MOC_SYM(hwAccelCtx) testPacket.key, sizeof(testPacket.key), 1);
    if(0 == ctx)
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    status = DoAESXTS(MOC_SYM(hwAccelCtx) ctx, testPacket.plainText, sizeof(testPacket.plainText), 1, testPacket.tweak);
    if(status < OK)
    {
        goto exit;
    }
    DeleteAESXTSCtx(MOC_SYM(hwAccelCtx) &ctx);

    if (FIPS_FORCE_FAIL_AES_XTS_TEST)
    {
        testPacket.plainText[0] ^= 0x01;
    }

    /* verify encryption */
    DIGI_CTIME_MATCH(testPacket.plainText, AES_XTS_TESTCASE.cipherText, sizeof(AES_XTS_TESTCASE.cipherText), &resCmp);

    if (0 != resCmp)
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    /* decryption now --> decrypt what we just encrypted */
    ctx = CreateAESXTSCtx(MOC_SYM(hwAccelCtx) testPacket.key, sizeof(testPacket.key), 0);
    if(0 == ctx)
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    status = DoAESXTS(MOC_SYM(hwAccelCtx) ctx, testPacket.plainText, sizeof(testPacket.plainText), 0, testPacket.tweak);
    if(status < OK)
    {
        goto exit;
    }
    DeleteAESXTSCtx(MOC_SYM(hwAccelCtx) &ctx);

    /* verify decryption */
    DIGI_CTIME_MATCH(testPacket.plainText, AES_XTS_TESTCASE.plainText, sizeof(AES_XTS_TESTCASE.plainText), &resCmp);

    if (0 != resCmp)
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_aesXtsKat", "AES-XTS", status);

    setFIPS_Status_Once(FIPS_ALGO_AES_XTS, status);
    return status;

} /* FIPS_aesXtsKat */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_aesCcmKat(hwAccelDescr hwAccelCtx)
{
    aesCcmTestPacketDescr   testPacket;
    aesCcmTestPacketDescr*  pRefPacket;
    ubyte                   M, L;
    ubyte                   output[16];
    sbyte4                  resCmp;
    MSTATUS                 status;

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_aesCcmKat", "AES-CCM");

    /* make a copy because we are going to be modifying it */
    DIGI_MEMCPY(&testPacket, (pRefPacket = &mAesCcmTestPackets), sizeof(aesCcmTestPacketDescr));

    M = testPacket.resultLen - testPacket.packetLen;
    L = 15 - testPacket.nonceLen;

    status = AESCCM_encrypt(MOC_SYM(hwAccelCtx) M, L, testPacket.key, testPacket.keyLen,
                            testPacket.nonce,
                            testPacket.packet + testPacket.packetHeaderLen,
                            testPacket.packetLen - testPacket.packetHeaderLen,
                            testPacket.packet, testPacket.packetHeaderLen, output);

    if (OK > status)
        goto exit;

    DIGI_CTIME_MATCH(testPacket.packet, testPacket.result, testPacket.packetLen, &resCmp);

    if (0 != resCmp)
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    DIGI_CTIME_MATCH(output, testPacket.result + testPacket.packetLen, M, &resCmp);

    if (0 != resCmp)
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    if (FIPS_FORCE_FAIL_AES_CCM_TEST)
    {
        output[0] ^= 0x01;
    }

    /* decryption now --> decrypt what we just encrypted */
    status = AESCCM_decrypt(MOC_SYM(hwAccelCtx) M, L, testPacket.key, testPacket.keyLen,
                            testPacket.nonce,
                            testPacket.packet + testPacket.packetHeaderLen,
                            testPacket.packetLen - testPacket.packetHeaderLen,
                            testPacket.packet, testPacket.packetHeaderLen, output);

    if (OK > status)
        goto exit;

    DIGI_CTIME_MATCH(testPacket.packet, pRefPacket->packet, testPacket.packetLen, &resCmp);

    if (0 != resCmp)
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_aesCcmKat", "AES-CCM", status);

    setFIPS_Status_Once(FIPS_ALGO_AES_CCM, status);
    return status;

} /* FIPS_aesCcmKat */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_aesCmacKat(hwAccelDescr hwAccelCtx)
{
    AESCMAC_Ctx ctx = {0};
    ubyte       cmacOutput[CMAC_RESULT_SIZE];
    ubyte*       pTestMessage2 = (ubyte*) "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    ubyte       key[16] = { 0x11,0x01,0x01,0x01, 0x01,0x01,0x01,0x31, 0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01 };
    ubyte       expected[CMAC_RESULT_SIZE] = { 0x85,0x58,0x16,0xad, 0xaa,0x5c,0x3b,0xbe, 0xce,0x75,0xbc,0xfd, 0xcd,0x48,0x45,0x75 };
    sbyte4      result;
    MSTATUS     status = OK;

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_aesCmacKat", "AES-CMAC");

    /******* AES-CMAC in steps ***************************/
    DIGI_MEMSET(cmacOutput, 0x00, CMAC_RESULT_SIZE);

    if (OK > (status = AESCMAC_init(MOC_SYM(hwAccelCtx) key, sizeof(key), &ctx)))
        goto exit;

    if (OK > (status = AESCMAC_update(MOC_SYM(hwAccelCtx) pTestMessage2, 10, &ctx)))
        goto exit;

    if (OK > (status = AESCMAC_update(MOC_SYM(hwAccelCtx) pTestMessage2+10 ,
                                      (sbyte4)DIGI_STRLEN((const sbyte*)pTestMessage2) -  10,
                                      &ctx)))
    {
        goto exit;
    }

    if (OK > (status = AESCMAC_final(MOC_SYM(hwAccelCtx) cmacOutput, &ctx)))
        goto exit;

    if (FIPS_FORCE_FAIL_AES_CMAC_TEST)
    {
        cmacOutput[0] ^= 0x01;
    }

    if ((OK > DIGI_CTIME_MATCH(cmacOutput, expected, CMAC_RESULT_SIZE, &result)) || (0 != result))
    {
        status = ERR_FIPS_HASH_KAT_FAILED;
        goto exit;
    }

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_aesCmacKat", "AES-CMAC", status);
 
    if (OK != status)
    {
        AESCMAC_clear (MOC_SYM(hwAccelCtx) &ctx);
    }

    setFIPS_Status_Once(FIPS_ALGO_AES_CMAC, status);

    return status;

} /* FIPS_aesCmacKat */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_tdesCbcKat(hwAccelDescr hwAccelCtx)
{
    ubyte expect_enc[] = {
        0x8c,0xa6,0x4d,0xe9,0xc1,0xb1,0x23,0xa7,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x8c,0xa6,0x4d,0xe9,0xc1,0xb1,0x23,0xa7,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    ubyte expect_dec[] = {
        0x8c,0xa6,0x4d,0xe9,0xc1,0xb1,0x23,0xa7,
        0x8c,0xa6,0x4d,0xe9,0xc1,0xb1,0x23,0xa7,
        0x8c,0xa6,0x4d,0xe9,0xc1,0xb1,0x23,0xa7,
        0x8c,0xa6,0x4d,0xe9,0xc1,0xb1,0x23,0xa7
    };

    MSTATUS status;

    if (OK > (status = FIPS_symKat(hwAccelCtx, "3DES-168-EDE-CBC-ENC", &TDESCBCSuite, 24, DO_ENCRYPT, expect_enc, sizeof(expect_enc), FIPS_FORCE_FAIL_3DES_CBC_ENC_TEST)))
        goto exit;

    status = FIPS_symKat(hwAccelCtx, "3DES-168-EDE-CBC-DEC", &TDESCBCSuite, 24, DO_DECRYPT, expect_dec, sizeof(expect_dec), FIPS_FORCE_FAIL_3DES_CBC_DEC_TEST);

exit:
    setFIPS_Status_Once(FIPS_ALGO_3DES, status);
    return status;

} /* FIPS_tdesCbcKat */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_GCM__)
MOC_EXTERN MSTATUS
FIPS_aesGcmKat(hwAccelDescr hwAccelCtx)
{
    ubyte expectedCipherText[16] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
    };
    ubyte expectedTag[AES_BLOCK_SIZE] = {
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
    };

    ubyte           key[16];
    ubyte           nonce[12];
    ubyte           data[16];
    ubyte           plainText[16];
    ubyte           tag[AES_BLOCK_SIZE];
    sbyte4          result;
    MSTATUS         status = OK;
#if defined(__ENABLE_DIGICERT_GCM_4K__)
    gcm_ctx_4k*   pC = NULL;
#endif /* __ENABLE_DIGICERT_GCM_4K__ */

#if defined(__ENABLE_DIGICERT_GCM_64K__)
    gcm_ctx_64k*   pC_64k = NULL;
#endif /* __ENABLE_DIGICERT_GCM_64K__ */

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_aesGcmKat", "AES-GCM");

#if defined(__ENABLE_DIGICERT_GCM_4K__)
    DIGI_MEMSET(key, 0x00, 16);
    DIGI_MEMSET(nonce, 0x00, 12);
    DIGI_MEMSET(plainText, 0x00, 16);

    DIGI_MEMCPY(data, plainText, 16);

    /* Encrypt test */
    if (NULL == (pC = GCM_createCtx_4k(MOC_SYM(hwAccelCtx) key, 16, TRUE)))
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    if (OK > (status = GCM_init_4k(MOC_SYM(hwAccelCtx) pC, nonce, 12, NULL, 0)))
        goto exit;

    if (OK > (status = GCM_update_encrypt_4k(MOC_SYM(hwAccelCtx) pC, data, 16)))
        goto exit;

    if (OK > (status = GCM_final_4k(pC, tag)))
        goto exit;

    if (OK > (status = GCM_deleteCtx_4k(MOC_SYM(hwAccelCtx) (BulkCtx*)&pC)))
        goto exit;

    if (FIPS_FORCE_FAIL_AES_GCM_ENC_TEST)
    {
        *data ^= 0x01;
    }

    if ((OK > DIGI_CTIME_MATCH(data, expectedCipherText, 16, &result)) || (0 != result))
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    if ((OK > DIGI_CTIME_MATCH(tag, expectedTag, AES_BLOCK_SIZE, &result)) || (0 != result))
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    /* Decrypt test */
    if (NULL == (pC = GCM_createCtx_4k(MOC_SYM(hwAccelCtx) key, 16, FALSE)))
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    if (OK > (status = GCM_init_4k(MOC_SYM(hwAccelCtx) pC, nonce, 12, NULL, 0)))
        goto exit;

    if (OK > (status = GCM_update_decrypt_4k(MOC_SYM(hwAccelCtx) pC, data, 16)))
        goto exit;

    if (OK > (status = GCM_final_4k(pC, tag)))
        goto exit;

    if (OK > (status = GCM_deleteCtx_4k(MOC_SYM(hwAccelCtx) (BulkCtx*)&pC)))
        goto exit;

    if (FIPS_FORCE_FAIL_AES_GCM_DEC_TEST)
    {
        *data ^= 0x01;
    }

    if ((OK > DIGI_CTIME_MATCH(data, plainText, 16, &result)) || (0 != result))
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    if ((OK > DIGI_CTIME_MATCH(tag, expectedTag, AES_BLOCK_SIZE, &result)) || (0 != result))
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }
    /* End of 4K version */
#endif /* __ENABLE_DIGICERT_GCM_4K__ */

#if defined(__ENABLE_DIGICERT_GCM_64K__)
    /* Do 64K version of GCM KAT */

    DIGI_MEMSET(key, 0x00, 16);
    DIGI_MEMSET(nonce, 0x00, 12);
    DIGI_MEMSET(plainText, 0x00, 16);

    DIGI_MEMCPY(data, plainText, 16);

    /* Encrypt test */
    if (NULL == (pC_64k = GCM_createCtx_64k(MOC_SYM(hwAccelCtx) key, 16, TRUE)))
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    if (OK > (status = GCM_init_64k(MOC_SYM(hwAccelCtx) pC_64k, nonce, 12, NULL, 0)))
        goto exit;

    if (OK > (status = GCM_update_encrypt_64k(MOC_SYM(hwAccelCtx) pC_64k, data, 16)))
        goto exit;

    if (OK > (status = GCM_final_64k(pC_64k, tag)))
        goto exit;

    if (OK > (status = GCM_deleteCtx_64k(MOC_SYM(hwAccelCtx) (BulkCtx*)&pC_64k)))
        goto exit;

    if (FIPS_FORCE_FAIL_AES_GCM_ENC_TEST)
    {
        *data ^= 0x01;
    }

    if ((OK > DIGI_CTIME_MATCH(data, expectedCipherText, 16, &result)) || (0 != result))
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    if ((OK > DIGI_CTIME_MATCH(tag, expectedTag, AES_BLOCK_SIZE, &result)) || (0 != result))
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    /* Decrypt test */
    if (NULL == (pC_64k = GCM_createCtx_64k(MOC_SYM(hwAccelCtx) key, 16, FALSE)))
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    if (OK > (status = GCM_init_64k(MOC_SYM(hwAccelCtx) pC_64k, nonce, 12, NULL, 0)))
        goto exit;

    if (OK > (status = GCM_update_decrypt_64k(MOC_SYM(hwAccelCtx) pC_64k, data, 16)))
        goto exit;

    if (OK > (status = GCM_final_64k(pC_64k, tag)))
        goto exit;

    if (OK > (status = GCM_deleteCtx_64k(MOC_SYM(hwAccelCtx) (BulkCtx*)&pC_64k)))
        goto exit;

    if (FIPS_FORCE_FAIL_AES_GCM_DEC_TEST)
    {
        *data ^= 0x01;
    }

    if ((OK > DIGI_CTIME_MATCH(data, plainText, 16, &result)) || (0 != result))
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    if ((OK > DIGI_CTIME_MATCH(tag, expectedTag, AES_BLOCK_SIZE, &result)) || (0 != result))
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

    /* End of 64K version */
#endif /* __ENABLE_DIGICERT_GCM_64K__ */

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_aesGcmKat", "AES-GCM", status);

#if defined(__ENABLE_DIGICERT_GCM_4K__)
    if (NULL != pC)
    {
        GCM_deleteCtx_4k(MOC_SYM(hwAccelCtx) (BulkCtx*)&pC);
    }
#endif /* __ENABLE_DIGICERT_GCM_4K__ */

#if defined(__ENABLE_DIGICERT_GCM_64K__)
    if (NULL != pC_64k)
    {
        GCM_deleteCtx_64k(MOC_SYM(hwAccelCtx) (BulkCtx*)&pC_64k);
    }
#endif /* __ENABLE_DIGICERT_GCM_64K__ */

    setFIPS_Status_Once(FIPS_ALGO_AES_GCM, status);
    return status;

} /* FIPS_aesGcmKAT */
#endif /* defined(__ENABLE_DIGICERT_GCM__) */

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__))

/* Group 14- Generator value */
static ubyte gp14DhG[1] =
{
   0x02
};

/* Group 14- Large prime number value */
static ubyte gp14DhP[256] =
{
   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xc9,0x0f,0xda,0xa2,0x21,0x68,0xc2,0x34,
   0xc4,0xc6,0x62,0x8b,0x80,0xdc,0x1c,0xd1,0x29,0x02,0x4e,0x08,0x8a,0x67,0xcc,0x74,
   0x02,0x0b,0xbe,0xa6,0x3b,0x13,0x9b,0x22,0x51,0x4a,0x08,0x79,0x8e,0x34,0x04,0xdd,
   0xef,0x95,0x19,0xb3,0xcd,0x3a,0x43,0x1b,0x30,0x2b,0x0a,0x6d,0xf2,0x5f,0x14,0x37,
   0x4f,0xe1,0x35,0x6d,0x6d,0x51,0xc2,0x45,0xe4,0x85,0xb5,0x76,0x62,0x5e,0x7e,0xc6,
   0xf4,0x4c,0x42,0xe9,0xa6,0x37,0xed,0x6b,0x0b,0xff,0x5c,0xb6,0xf4,0x06,0xb7,0xed,
   0xee,0x38,0x6b,0xfb,0x5a,0x89,0x9f,0xa5,0xae,0x9f,0x24,0x11,0x7c,0x4b,0x1f,0xe6,
   0x49,0x28,0x66,0x51,0xec,0xe4,0x5b,0x3d,0xc2,0x00,0x7c,0xb8,0xa1,0x63,0xbf,0x05,
   0x98,0xda,0x48,0x36,0x1c,0x55,0xd3,0x9a,0x69,0x16,0x3f,0xa8,0xfd,0x24,0xcf,0x5f,
   0x83,0x65,0x5d,0x23,0xdc,0xa3,0xad,0x96,0x1c,0x62,0xf3,0x56,0x20,0x85,0x52,0xbb,
   0x9e,0xd5,0x29,0x07,0x70,0x96,0x96,0x6d,0x67,0x0c,0x35,0x4e,0x4a,0xbc,0x98,0x04,
   0xf1,0x74,0x6c,0x08,0xca,0x18,0x21,0x7c,0x32,0x90,0x5e,0x46,0x2e,0x36,0xce,0x3b,
   0xe3,0x9e,0x77,0x2c,0x18,0x0e,0x86,0x03,0x9b,0x27,0x83,0xa2,0xec,0x07,0xa2,0x8f,
   0xb5,0xc5,0x5d,0xf0,0x6f,0x4c,0x52,0xc9,0xde,0x2b,0xcb,0xf6,0x95,0x58,0x17,0x18,
   0x39,0x95,0x49,0x7c,0xea,0x95,0x6a,0xe5,0x15,0xd2,0x26,0x18,0x98,0xfa,0x05,0x10,
   0x15,0x72,0x8e,0x5a,0x8a,0xac,0xaa,0x68,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

/* Group 14- Server private key value */
static ubyte gp14DhY[28] =
{
    0x0f,0xd3,0x09,0x61,0xba,0x35,0x09,0xff,0xf8,0x71,0xce,0x55,0xaa,0x01,0xc3,0x35,
    0x91,0xf3,0xb8,0xc5,0x6c,0x38,0xd6,0x07,0x0a,0xfc,0x75,0x96
};

/* Group 14- Client public key value */
static ubyte gp14DhE[256] =
{
    0x88,0xbd,0x68,0xe0,0x11,0xbd,0x89,0x95,0xf2,0xca,0xa8,0x1f,0xc4,0x59,0xe1,0x87,
    0x19,0x42,0x27,0x3c,0x5b,0xfb,0x51,0xc2,0x0d,0xe2,0x33,0xb0,0x72,0x6a,0x30,0x3f,
    0x56,0xec,0x89,0x13,0x2b,0x7e,0x60,0x38,0x1d,0x9d,0x4b,0x88,0xca,0x9b,0xfc,0x6d,
    0xb5,0xc0,0x11,0xa6,0xdd,0xf1,0x9b,0x4e,0x25,0xa3,0x2e,0x4b,0xa4,0x27,0x33,0x7a,
    0x4c,0x43,0x7f,0x6b,0x00,0xde,0xf6,0xac,0xd0,0x25,0xae,0xc0,0xb4,0x4b,0x89,0x09,
    0xd0,0x91,0xbd,0x0f,0xf0,0x4b,0x90,0x76,0x75,0x1d,0x9c,0xb1,0x9a,0x23,0x49,0x99,
    0x4d,0xa0,0x3a,0xd3,0x6c,0xa5,0xac,0x48,0x1a,0x67,0x19,0x79,0x29,0xcd,0x37,0xd2,
    0x2b,0xd3,0x94,0xf0,0x20,0xf3,0x00,0x75,0x4e,0xec,0xbb,0xe2,0x46,0xc4,0x2b,0x67,
    0xfe,0x51,0xd8,0x07,0x75,0x12,0x7f,0xd4,0x04,0x07,0x0f,0x4a,0xa8,0x2e,0x25,0x36,
    0x82,0x20,0x12,0x27,0xcb,0x35,0x59,0x1d,0x09,0x95,0x68,0x15,0x21,0x39,0xc9,0x36,
    0x75,0x4a,0x76,0xd0,0x76,0x35,0xd9,0xab,0xae,0xa2,0xa4,0xde,0x76,0xe7,0x0d,0x77,
    0xab,0x60,0xd3,0x9e,0xab,0xa2,0x15,0x1b,0xa1,0xb6,0xb0,0x63,0x33,0xd1,0x83,0xe2,
    0x08,0x86,0x91,0x6e,0x48,0xb1,0xe4,0x86,0xbc,0xfe,0xf3,0x60,0xea,0x51,0xe6,0xf6,
    0x02,0x7d,0x8b,0x83,0x65,0x40,0x8c,0xd1,0xd3,0x73,0xdd,0xbf,0xde,0x62,0x4e,0xd0,
    0x9a,0x9d,0x2f,0xdb,0x86,0x70,0x14,0x12,0xf0,0xee,0x60,0x81,0xa7,0x3b,0xe8,0x0d,
    0x1b,0x71,0xf4,0x9c,0xa2,0x4a,0x39,0x78,0xab,0xae,0x82,0xec,0xdf,0x3b,0x97,0x76

};

/* Group 14- Shared secret value */
static ubyte gp14DhK[256] =
{
        0x48,0xfe,0x88,0xa2,0xd3,0xcb,0x74,0x7a,0xab,0x64,0xac,0xcd,0x2e,0x4c,0x3c,0x3f,
        0x19,0xe0,0x54,0x5b,0x89,0x2c,0x74,0xba,0x12,0xc3,0x57,0x3f,0xd0,0xfb,0xdb,0x43,
        0x80,0xc1,0x13,0x26,0x13,0xd5,0x8c,0xde,0x16,0x28,0x9b,0x82,0x66,0x3c,0xce,0xdf,
        0x89,0x04,0x0c,0xd2,0x29,0xbe,0x7e,0xf4,0xa6,0x47,0x7c,0xbf,0xdb,0x53,0xf6,0xb9,
        0x7c,0xef,0x12,0x66,0x7c,0x74,0x46,0xd6,0xb8,0xa1,0xb5,0xd1,0x92,0x6c,0x50,0xd6,
        0xaa,0xca,0xe8,0xc1,0xf9,0x8c,0x7e,0x72,0x0c,0xcb,0x05,0x68,0x4e,0x7c,0xbf,0x47,
        0x67,0x36,0xc8,0x68,0x05,0xb0,0x77,0x28,0x9f,0xa9,0x1c,0xed,0x67,0xdd,0xa0,0xb9,
        0x3a,0x11,0x11,0xa9,0xe8,0x4c,0x17,0xef,0x40,0xbb,0xd4,0x4b,0xcd,0xea,0x77,0xdc,
        0xaf,0x46,0xc3,0xd4,0xd0,0xf8,0x17,0x4b,0x37,0x27,0x0a,0xf8,0xc1,0x39,0x9d,0xa3,
        0xf7,0x50,0x69,0x81,0x8a,0x29,0x7c,0xd0,0x08,0x13,0xfd,0x28,0x16,0x33,0x6d,0x14,
        0x09,0x38,0x5a,0x92,0x75,0x66,0x17,0x80,0xab,0xd5,0xe3,0xdc,0xb1,0x08,0x3f,0x32,
        0xe5,0xa3,0x4f,0x71,0x72,0xf1,0x6c,0x60,0xbb,0xa4,0xba,0x89,0x7f,0xfe,0x67,0xf3,
        0x3f,0x33,0x2e,0xbf,0x94,0x20,0x88,0x89,0x71,0xe8,0x9f,0x9a,0x87,0xd3,0x1b,0xe1,
        0x41,0xc2,0xf7,0xe1,0x1a,0x0c,0x44,0x3a,0x6c,0xf8,0x84,0xb7,0x93,0x5e,0x6b,0x34,
        0xfb,0x95,0x0d,0x0d,0xf8,0x9e,0x15,0x48,0x0a,0xc2,0x7c,0x42,0x0d,0xcb,0x4a,0x55,
        0x10,0xdd,0xad,0x95,0xf4,0x8b,0x69,0xd5,0xb0,0x4e,0x98,0xcb,0x85,0xb5,0xcd,0x29
};

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_dhKat(hwAccelDescr hwAccelCtx)
{
    diffieHellmanContext*   pDhCtx = NULL;
    vlong*                  pVlongQueue = NULL;
    sbyte4                  comparisonResult;
    MSTATUS                 status = OK;

    /* KDF related data */
    ubyte*              pResult = NULL;
    ubyte*              pSS = NULL;
    sbyte4              sslen;
    const BulkHashAlgo *pHashSuite = &SHA224Suite;

    ubyte expect[] = {
      0x28, 0x1B, 0x29, 0x18, 0xA8, 0xFA, 0xE8, 0xFF,
      0x37, 0xAA, 0x44, 0x04, 0x35, 0x05, 0xD7, 0x2F,
      0x89, 0xA0, 0x59, 0x11, 0x34, 0xBE, 0xB4, 0x21,
      0xB9, 0x12, 0x11, 0x1F, 0xCF, 0xFF, 0xF9, 0xD5
    };

    ubyte info[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    ubyte IV[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_dhKat", "DH-group14");

    /* Allocate an empty context */
    if (OK > (status = DH_allocate(&pDhCtx)))
        goto exit;

    /* Set P */
    if (OK > (status = VLONG_vlongFromByteString (gp14DhP, sizeof(gp14DhP), &(COMPUTED_VLONG_P(pDhCtx)), &pVlongQueue)))
        goto exit;

    /* Set G */
    if (OK > (status = VLONG_vlongFromByteString (gp14DhG, sizeof(gp14DhG), &(COMPUTED_VLONG_G(pDhCtx)), &pVlongQueue)))
        goto exit;

    /* Set Y, our private key */
    if (OK > (status = VLONG_vlongFromByteString (gp14DhY, sizeof(gp14DhY), &(COMPUTED_VLONG_Y(pDhCtx)), &pVlongQueue)))
        goto exit;

    /* Set E, their public key */
    if (OK > (status = VLONG_vlongFromByteString (gp14DhE, sizeof(gp14DhE), &(COMPUTED_VLONG_E(pDhCtx)), &pVlongQueue)))
        goto exit;

    if (FIPS_FORCE_FAIL_DH_TEST)
    {
        (COMPUTED_VLONG_E(pDhCtx))->pUnits[0] ^= 0x01;
    }

    /* Compute the shared secret */
    if (OK > (status = DH_computeKeyExchange(MOC_DH(hwAccelCtx) pDhCtx, &pVlongQueue)))
        goto exit;

    /* Get length in bytes */
    if (OK != VLONG_byteStringFromVlong(COMPUTED_VLONG_K(pDhCtx), NULL, &sslen))
    {
        goto exit;
    }
    /* Create shared secret as byte string */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, sslen, TRUE, &pSS)))
    {
        goto exit;
    }
    if (OK != VLONG_byteStringFromVlong(COMPUTED_VLONG_K(pDhCtx), pSS, &sslen))
    {
        goto exit;
    }
    
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, sizeof(expect), TRUE, &pResult)))
    {
        goto exit;
    }
    
    if (OK > (status = HmacKdfExpand(MOC_HASH(hwAccelCtx)
                                     pHashSuite, pSS, sslen, info, sizeof(info), IV, sizeof(IV),
                                     pResult, sizeof(expect))))
    {
        goto exit;
    }

    DIGI_CTIME_MATCH(pResult, expect, sizeof(expect), &comparisonResult);
    if (0 != comparisonResult)
    {
        status = ERR_FIPS_DH_PCT_FAILED;
        goto exit;
    }

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_dhKat", "DH-group14", status);

    setFIPS_Status_Once(FIPS_ALGO_DH, status);

    if (NULL != pResult)
        FREE(pResult);

    if (NULL != pSS)
        FREE(pSS);

    if (NULL != pDhCtx)
        DH_freeDhContext(&pDhCtx, NULL);

    if (NULL != pVlongQueue)
        VLONG_freeVlongQueue( &pVlongQueue);

    return status;

} /* FIPS_dhKat */

/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))

/* P224 data */
static const ubyte gpP224priv[28] =
{
    0x53,0x95,0xFC,0x8C,0xF7,0x48,0xC9,0x75,0x31,0x0A,0x2A,0xE5,0xCB,0x47,0x97,0x2F,
    0xFC,0xD8,0x5F,0x2F,0x52,0xE3,0x78,0x20,0x5F,0x22,0x11,0x48
};

static const ubyte gpP224pubXOther[28] =
{
    0x0A,0x40,0x65,0xBE,0x26,0xC0,0xDC,0xEE,0xF7,0xE4,0x5A,0x6E,0xFE,0xB5,0x37,0x7D,
    0x97,0x24,0x2E,0x6A,0x76,0x00,0x39,0x40,0x22,0x3E,0x9D,0xEC
};

static const ubyte gpP224pubYOther[28] =
{
    0xB0,0xA1,0x11,0xC6,0xCC,0x78,0x50,0x39,0xAC,0x33,0x5D,0x79,0x17,0x6E,0x23,0xB4,
    0xE3,0xD9,0x8F,0x28,0x45,0x64,0x4A,0x3E,0x1F,0xB7,0xB8,0x40
};

static const ubyte gpP224z[28] =
{
    0x4F,0xB9,0x3A,0xE1,0x36,0xB4,0x0E,0xD1,0xEE,0xAE,0x3C,0x13,0xA9,0xCA,0xE0,0x23,
    0xB5,0x10,0xE3,0xBD,0x04,0xAE,0x9B,0xA2,0xE4,0x11,0x70,0xE6
};

/*---------------------------------------------------------------------------*/

static MSTATUS FIPS_getECDHtestVector224(PrimeFieldPtr pPF, PFEPtr pK, PFEPtr pQx, PFEPtr pQy, ubyte **ppSS, ubyte4 *pSSLen)
{
    MSTATUS status = OK;

    /* Our private key */
    status = PRIMEFIELD_setToByteString(pPF, pK, gpP224priv, sizeof(gpP224priv));
    if (OK != status)
        goto exit;

    /* Other guys public key */
    status = PRIMEFIELD_setToByteString(pPF, pQx, gpP224pubXOther, sizeof(gpP224pubXOther));
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_setToByteString(pPF, pQy, gpP224pubYOther, sizeof(gpP224pubYOther));
    if (OK != status)
        goto exit;

    /* The expected shared secret */
    *ppSS = (ubyte *) gpP224z;
    *pSSLen = (ubyte4) sizeof(gpP224z);

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
FIPS_doEcdhTest(hwAccelDescr hwAccelCtx, intBoolean isForceFail)
{
    PEllipticCurvePtr pEC = EC_P224;
    PrimeFieldPtr pPF = EC_getUnderlyingField(pEC);
    PFEPtr pK = NULL;
    PFEPtr pQx = NULL;
    PFEPtr pQy = NULL;
    ubyte* pSS = 0;
    ubyte* pResult = 0;
    sbyte4 ssLen = 0;

    ubyte *pExpectedSS = NULL;
    ubyte4 expectedSSLen = 0;
    sbyte4  res = -1;
    MSTATUS status = OK;

    /* KDF related data */
    const BulkHashAlgo *pHashSuite = &SHA224Suite;
    ubyte expect[] = {
      0xB7, 0x8F, 0xD9, 0x49, 0xEF, 0x68, 0xAF, 0xFE,
      0x7D, 0xCA, 0xA3, 0x65, 0xAE, 0x62, 0x6E, 0xDF,
      0x6A, 0x4B, 0x4F, 0x7F, 0x82, 0x42, 0x09, 0x4F,
      0xC7, 0x44, 0xEB, 0x34, 0xC6, 0xFC, 0x7E, 0x8E
    };

    ubyte info[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    ubyte IV[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    if (OK > (status = PRIMEFIELD_newElement(pPF, &pK)))
    {
        goto exit;
    }

    if (OK > (status = PRIMEFIELD_newElement(pPF, &pQx)))
    {
        goto exit;
    }

    if (OK > (status = PRIMEFIELD_newElement(pPF, &pQy)))
    {
        goto exit;
    }

    if (OK > (status = FIPS_getECDHtestVector224(pPF, pK, pQx, pQy, &pExpectedSS, &expectedSSLen)))
    {
        goto exit;
    }

    if (OK > (status = ECDH_generateSharedSecretAux(pEC, pQx, pQy, pK, &pSS, &ssLen, 1)))
    {
        goto exit;
    }

    if (ssLen != (sbyte4) expectedSSLen)
    {
        status = ERR_FIPS_ECDH_PCT_FAILED;
        goto exit;
    }

    if (isForceFail)
    {
        *pSS ^= 0x01;
    }

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, sizeof(expect), TRUE, &pResult)))
    {
        goto exit;
    }
    
    if (OK > (status = HmacKdfExpand(MOC_HASH(hwAccelCtx)
                                     pHashSuite, pSS, ssLen, info, sizeof(info), IV, sizeof(IV),
                                     pResult, sizeof(expect))))
    {
        goto exit;
    }

    DIGI_CTIME_MATCH(pResult, expect, sizeof(expect), &res);
    if (res != 0)
    {
        status = ERR_FIPS_ECDH_PCT_FAILED;
        goto exit;
    }

exit:

    /* pExpectedSS is not allocated */

    if (pResult)
    {
        FREE(pResult);
    }

    if (pSS)
    {
        FREE(pSS);
    }

    if (pK)
    {
        PRIMEFIELD_deleteElement(pPF, &pK);
    }

    if (pQx)
    {
        PRIMEFIELD_deleteElement(pPF, &pQx);
    }

    if (pQy)
    {
        PRIMEFIELD_deleteElement(pPF, &pQy);
    }

    return status;

} /* FIPS_doEcdhTest */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_ecdhKat(hwAccelDescr hwAccelCtx)
{
    MSTATUS         status;

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_ecdhKat", "ECDH-p-curves");

    if (OK > (status = FIPS_doEcdhTest(hwAccelCtx, FIPS_FORCE_FAIL_ECDH_TEST)))
        goto exit;

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_ecdhKat", "ECDH-p-curves", status);

    setFIPS_Status_Once(FIPS_ALGO_ECC, status);  /* There is overlap. */
    setFIPS_Status_Once(FIPS_ALGO_ECDH, status);

    return status;
}

/*---------------------------------------------------------------------------*/

static ubyte FIPS_ValOfHexChar( sbyte c)
{
    if ('0' <= c && c <= '9')
    {
        return (ubyte) (c - '0');
    }
    else if ( 'A' <= c && c <= 'F')
    {
        return (ubyte) ( c + 10 - 'A');
    }
    else if ( 'a' <= c && c <= 'f')
    {
        return (ubyte) ( c + 10 - 'a');
    }
    return 0; /* ??? */
}

/*---------------------------------------------------------------------------*/

ubyte4 FIPS_str_to_byteStr( const sbyte* s, ubyte** bs)
{
    ubyte* buffer = 0;
    ubyte4 bsLen;
    ubyte4 sLen = DIGI_STRLEN( s);
    ubyte* pTemp;

    bsLen = (sLen+1)/2;
    buffer = MALLOC( bsLen + 1); /* to prevent a malloc 0 */
    if (!buffer)
    {
        *bs = 0;
        return 0;
    }

    pTemp = buffer;

    if ( sLen & 1)
    {
        *pTemp++ = FIPS_ValOfHexChar(*s++);
    }
    while ( *s)
    {
        *pTemp = (ubyte) ((FIPS_ValOfHexChar(*s++)) << 4);
        *pTemp++ |= (FIPS_ValOfHexChar(*s++));
    }
    *bs = buffer;
    return bsLen;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
FIPS_doEddhTest(hwAccelDescr hwAccelCtx, intBoolean isForceFail)
{
    MSTATUS status = OK;
    edECCKey *pPrivKey = NULL;

    ubyte *pPrivKeyBytes = NULL;
    ubyte4 privKeyLen = 0;
    ubyte *pPubKeyBytes = NULL;
    ubyte4 pubKeyLen = 0;

    ubyte *pSharedSecret = NULL;
    ubyte4 ssLen = 0;
    sbyte4 compare;

    /* KDF related data */
    ubyte* pResult = NULL;
    const BulkHashAlgo *pHashSuite = &SHA224Suite;

    ubyte expect[] = {
      0x98, 0x22, 0xEE, 0x62, 0xAC, 0x37, 0xE5, 0x9F,
      0xA0, 0xFF, 0x0A, 0x99, 0xC8, 0xD4, 0x8B, 0xBF,
      0xD5, 0xC6, 0xAE, 0xAA, 0xB3, 0xBA, 0xA7, 0x68,
      0x70, 0x3F, 0xD5, 0xE1, 0x9D, 0xCB, 0x88, 0x8C
    };

    ubyte info[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    ubyte IV[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    /* https://tools.ietf.org/pdf/rfc7748.pdf */
    /* Curve25519 */
    const char *p25519PrivKey = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const char *p25519PubKey = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

    int encodingX25519Size = 32;

    privKeyLen = FIPS_str_to_byteStr((sbyte *)p25519PrivKey, &pPrivKeyBytes);
    pubKeyLen = FIPS_str_to_byteStr((sbyte *)p25519PubKey, &pPubKeyBytes);

    /* Test edDH on curve25519 */
    status = edECC_newKey(&pPrivKey, curveX25519, NULL);
    if (OK != status)
        goto exit;

    /* will incorrectly set our public key, but that is not used anyway */
    status = edECC_setKeyParameters(pPrivKey, pPubKeyBytes, pubKeyLen,
            pPrivKeyBytes, privKeyLen, NULL, NULL);
    if (OK != status)
        goto exit;

    status = edDH_GenerateSharedSecret(pPrivKey, pPubKeyBytes, pubKeyLen,
            &pSharedSecret, &ssLen, NULL);
    if (OK != status)
        goto exit;

    if(encodingX25519Size != ssLen)
    {
        status = ERR_FIPS_EDDH_FAILED;
        goto exit;
    }

    if (isForceFail)
    {
        pSharedSecret[0] ^= 0x55;
    }

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, sizeof(expect), TRUE, &pResult)))
    {
        goto exit;
    }

    if (OK > (status = HmacKdfExpand(MOC_HASH(hwAccelCtx)
                                     pHashSuite, pSharedSecret, ssLen, info, sizeof(info), IV, sizeof(IV),
                                     pResult, sizeof(expect))))
    {
        goto exit;
    }
    
    DIGI_CTIME_MATCH(pResult, expect, sizeof(expect), &compare);
    if (0 != compare)
    {
        status = ERR_FIPS_SYM_KAT_FAILED;
        goto exit;
    }

exit:
    DIGI_FREE((void**)&pSharedSecret);
    if (NULL != pResult)
    {
        DIGI_FREE((void **) &pResult);
    }
    if (NULL != pPrivKey)
    {
        edECC_deleteKey(&pPrivKey, NULL);
    }
    if (NULL != pPrivKeyBytes)
    {
        DIGI_FREE((void **) &pPrivKeyBytes);
    }
    if (NULL != pPubKeyBytes)
    {
        DIGI_FREE((void **) &pPubKeyBytes);
    }
    return status;

} /* FIPS_doEddhTest */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_eddhKat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_eddhKat", "EDDH-p-curves");

    if (OK > (status = FIPS_doEddhTest(hwAccelCtx, FIPS_FORCE_FAIL_EDDH_TEST)))
        goto exit;

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_eddhKat", "EDDH-p-curves", status);

    setFIPS_Status_Once(FIPS_ALGO_EDDH, status);

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_ECC__)) */
#endif /* !defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__) */

/*------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__))

/* HMAC-KDF algorithm (In Suite-B library only) */
static MSTATUS
FIPS_createHmacKdfCtx(hwAccelDescr hwAccelCtx, ubyte **ppRetKey, ubyte4 *pRetKeyLen,
                      ubyte **ppRetInfo, ubyte4 *pRetInfoLen,
                      ubyte **ppRetIV, ubyte4 *pRetIVLen)
{
   ubyte* pTempKey = NULL;
   ubyte* pTempInfo = NULL;
   ubyte* pTempIV = NULL;
   MSTATUS status;

   *pRetKeyLen = 32;
   *pRetInfoLen = 32;
   *pRetIVLen = 32;

   if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, *pRetKeyLen, TRUE, &pTempKey)))
      goto exit;

   if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, *pRetInfoLen, TRUE, &pTempInfo)))
      goto exit;

   if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, *pRetIVLen, TRUE, &pTempIV)))
      goto exit;

   if (OK > (status = DIGI_MEMSET(pTempKey, 0x00, *pRetKeyLen)))
      goto exit;

   if (OK > (status = DIGI_MEMSET(pTempInfo, 0x00, *pRetInfoLen)))
      goto exit;

   if (OK > (status = DIGI_MEMSET(pTempIV, 0x00, *pRetIVLen)))
      goto exit;

   *ppRetKey = pTempKey;
   *ppRetInfo = pTempInfo;
   *ppRetIV = pTempIV;

    pTempKey = NULL;
    pTempInfo = NULL;
    pTempIV = NULL;

exit:
   CRYPTO_FREE(hwAccelCtx, TRUE, &pTempIV);
   CRYPTO_FREE(hwAccelCtx, TRUE, &pTempInfo);
   CRYPTO_FREE(hwAccelCtx, TRUE, &pTempKey);

   return status;
} /* FIPS_createHmacKdfCtx */

/*------------------------------------------------------------------*/

static void
FIPS_deleteHmacKdfCtx(hwAccelDescr hwAccelCtx, ubyte **ppFreeKey, ubyte **ppFreeInfo, ubyte **ppFreeIV)
{
   CRYPTO_FREE(hwAccelCtx, TRUE, ppFreeIV);
   CRYPTO_FREE(hwAccelCtx, TRUE, ppFreeInfo);
   CRYPTO_FREE(hwAccelCtx, TRUE, ppFreeKey);
} /* FIPS_deleteHmacKdfCtx */

/*------------------------------------------------------------------*/

static MSTATUS
FIPS_doKatHmacKdf(hwAccelDescr hwAccelCtx, const BulkHashAlgo *pHashSuite, ubyte* pKey, ubyte4 keyLen,
      ubyte* pInfo, ubyte4 infoLen, ubyte* pIV, ubyte4 ivLen, ubyte* pExpect, ubyte4 expectLen,
      intBoolean isForceFail)
{
    sbyte4      cmpRes = 0;
    ubyte*      pResult = NULL;
    MSTATUS     status = OK;
    ubyte4      outLen = expectLen;

    if (NULL == pHashSuite)
    {
        status = ERR_FIPS_HMAC_KDF_KAT_NULL;
        goto exit;
    }

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, outLen, TRUE, &pResult)))
        goto exit;

    if (OK > (status = HmacKdfExpand(MOC_HASH(hwAccelCtx)
          pHashSuite,
          pKey, keyLen, pInfo, infoLen, pIV, ivLen,
          pResult, outLen)))
       goto exit;

    if (TRUE == isForceFail)
        *pResult ^= 0x80;

    if (OK != DIGI_CTIME_MATCH(pResult, pExpect, outLen, &cmpRes))
    {
        status = ERR_FIPS_HMAC_KDF_KAT_FAILED;
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_FIPS_HMAC_KDF_KAT_FAILED;
        goto exit;
    }

exit:
    CRYPTO_FREE(hwAccelCtx, TRUE, &pResult);
    return status;
} /* FIPS_doKatHmacKdf */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacKdfKat(hwAccelDescr hwAccelCtx,
                const char *pTestName,
                const BulkHashAlgo *pHmacSuite,
                ubyte *pExpect, ubyte4 expectLen,
                intBoolean isForceFail)
{
    ubyte*              pKey = NULL;
    ubyte4              keyLen;
    ubyte*              pInfo = NULL;
    ubyte4              infoLen;
    ubyte*              pIV = NULL;
    ubyte4              ivLen;
    MSTATUS             status = OK;

    if (FIPS_TESTLOG_ENABLED)
        FIPS_startTestMsg("FIPS_hmacKdfKat", pTestName);

    if (OK > (status = FIPS_createHmacKdfCtx(hwAccelCtx, &pKey, &keyLen, &pInfo, &infoLen, &pIV, &ivLen)))
        goto exit;

    if (OK > (status = FIPS_doKatHmacKdf(hwAccelCtx, pHmacSuite, pKey, keyLen, pInfo, infoLen, pIV, ivLen,
                                         pExpect, expectLen, isForceFail)))
        goto exit;

exit:
    if (FIPS_TESTLOG_ENABLED)
        FIPS_endTestMsg("FIPS_hmacKdfKat", pTestName, status);

    FIPS_deleteHmacKdfCtx(hwAccelCtx, &pKey, &pInfo, &pIV);

    setFIPS_Status_Once(FIPS_ALGO_HMAC_KDF, status);

    return status;
} /* FIPS_hmacKdfKat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacKdfSha1Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
          0x98, 0xCD, 0x79, 0x8C, 0xB7, 0x54, 0x9C, 0x59,
          0x39, 0x02, 0xA0, 0xE0, 0x67, 0x2B, 0x67, 0xF1,
          0x49, 0xF8, 0xC7, 0x51, 0xFF, 0xBB, 0x7A, 0xCA,
          0x5D, 0x92, 0x2C, 0x40, 0x8C, 0x4A, 0x65, 0x3A
    };

    MSTATUS status = FIPS_hmacKdfKat(hwAccelCtx, "HMAC-KDF-SHA-1", &SHA1Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_KDF_SHA1_TEST);
    setFIPS_Status_Once(FIPS_ALGO_HMAC_KDF, status);
    return status;
} /* FIPS_hmacKdfSha1Kat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacKdfSha224Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
          0x2C, 0x24, 0x48, 0x6E, 0x75, 0xAF, 0xD7, 0x1E,
          0xD2, 0x45, 0x57, 0x53, 0xF4, 0x7D, 0xC8, 0x52,
          0xD7, 0x1E, 0xFF, 0x87, 0x19, 0x02, 0x9D, 0x9D,
          0xC1, 0x55, 0xC9, 0xE4, 0x8D, 0xE2, 0xEF, 0x98
    };

    MSTATUS status = FIPS_hmacKdfKat(hwAccelCtx, "HMAC-KDF-SHA-224", &SHA224Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_KDF_SHA224_TEST);
    setFIPS_Status_Once(FIPS_ALGO_HMAC_KDF, status);
    return status;
} /* FIPS_hmacKdfSha224Kat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacKdfSha256Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
          0xE0, 0x55, 0x4D, 0xBB, 0x52, 0x1E, 0xD1, 0x60,
          0x8B, 0xB4, 0x5C, 0x62, 0x76, 0x6F, 0x88, 0x44,
          0x0E, 0x2F, 0x3A, 0xE4, 0x67, 0xD7, 0x4D, 0xBA,
          0x1F, 0xD3, 0x97, 0xF4, 0xA4, 0x2E, 0x98, 0xFD
    };

    MSTATUS status = FIPS_hmacKdfKat(hwAccelCtx, "HMAC-KDF-SHA-256", &SHA256Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_KDF_SHA256_TEST);
    setFIPS_Status_Once(FIPS_ALGO_HMAC_KDF, status);
    return status;
} /* FIPS_hmacKdfSha256Kat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacKdfSha384Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
          0x59, 0x33, 0x34, 0xA7, 0x6C, 0x6F, 0x53, 0xD3,
          0xE1, 0x68, 0x01, 0x29, 0xCC, 0xA6, 0x14, 0x8B,
          0xAD, 0x32, 0xE3, 0x6A, 0xCF, 0x51, 0xB4, 0x0E,
          0xC0, 0xB3, 0xD8, 0x37, 0x2D, 0x01, 0x4C, 0xC9
    };

    MSTATUS status = FIPS_hmacKdfKat(hwAccelCtx, "HMAC-KDF-SHA-384", &SHA384Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_KDF_SHA384_TEST);
    setFIPS_Status_Once(FIPS_ALGO_HMAC_KDF, status);
    return status;
} /* FIPS_hmacKdfSha384Kat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacKdfSha512Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
          0x9D, 0x0E, 0x15, 0x54, 0x65, 0x65, 0xE4, 0xB5,
          0x16, 0x61, 0x30, 0xDC, 0xB9, 0x08, 0xDE, 0x99,
          0xA9, 0xE0, 0x89, 0xD5, 0x15, 0xD7, 0x2B, 0x6F,
          0x14, 0xF0, 0x9A, 0x52, 0xD6, 0x45, 0x6B, 0xC5
    };

    MSTATUS status = FIPS_hmacKdfKat(hwAccelCtx, "HMAC-KDF-SHA-512", &SHA512Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_KDF_SHA512_TEST);
    setFIPS_Status_Once(FIPS_ALGO_HMAC_KDF, status);
    return status;
} /* FIPS_hmacKdfSha512Kat */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_FIPS_SHA3__)

MOC_EXTERN MSTATUS
FIPS_hmacKdfSha3_224Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
          0x39, 0x81, 0xa9, 0x2b, 0xc6, 0xdf, 0xe1, 0x2e,
          0x7f, 0xa4, 0x74, 0x55, 0x61, 0xf4, 0x9c, 0x30,
          0xf8, 0x88, 0x17, 0x94, 0x8a, 0x4c, 0xdc, 0xa8,
          0x2b, 0xe4, 0x26, 0x1c, 0x7f, 0x09, 0xc5, 0xc4
    };

    MSTATUS status = FIPS_hmacKdfKat(hwAccelCtx, "HMAC-KDF-SHA3-224",
        &SHA3_224Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_KDF_SHA3_224_TEST);
    setFIPS_Status_Once(FIPS_ALGO_HMAC_KDF, status);
    return status;
} /* FIPS_hmacKdfSha3_224Kat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacKdfSha3_256Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
          0xb8, 0xb0, 0x45, 0xd6, 0x7e, 0x5d, 0x53, 0xff,
          0x30, 0x44, 0x75, 0xb8, 0x12, 0xbd, 0xa0, 0x3f,
          0xda, 0xb8, 0xbd, 0x96, 0x3d, 0x0d, 0x1b, 0xc4,
          0x05, 0x4c, 0x5a, 0xf3, 0x9a, 0x75, 0x7f, 0xa8
    };

    MSTATUS status = FIPS_hmacKdfKat(hwAccelCtx, "HMAC-KDF-SHA3-256",
        &SHA3_256Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_KDF_SHA3_256_TEST);
    setFIPS_Status_Once(FIPS_ALGO_HMAC_KDF, status);
    return status;
} /* FIPS_hmacKdfSha3_256Kat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacKdfSha3_384Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
          0x91, 0xdf, 0x25, 0xf7, 0x8c, 0xc1, 0x3c, 0x81,
          0x80, 0x73, 0x3a, 0x5a, 0xac, 0x08, 0x09, 0xd4,
          0x22, 0x1c, 0x0c, 0xb9, 0x92, 0x47, 0xa1, 0xa8,
          0x18, 0x74, 0x41, 0x7d, 0xe1, 0xf5, 0xf2, 0x93
    };

    MSTATUS status = FIPS_hmacKdfKat(hwAccelCtx, "HMAC-KDF-SHA3-384",
        &SHA3_384Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_KDF_SHA3_384_TEST);
    setFIPS_Status_Once(FIPS_ALGO_HMAC_KDF, status);
    return status;
} /* FIPS_hmacKdfSha3_384Kat */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacKdfSha3_512Kat(hwAccelDescr hwAccelCtx)
{
    ubyte expect[] = {
          0xfb, 0xbb, 0x03, 0x89, 0x0b, 0xbc, 0x98, 0xb9,
          0x9c, 0x52, 0x47, 0x00, 0x9b, 0x30, 0xfc, 0x51,
          0x2b, 0xd5, 0x15, 0xf6, 0xf5, 0x31, 0xae, 0x59,
          0xa2, 0x0d, 0x9e, 0x36, 0xd2, 0xff, 0xaa, 0x56
    };

    MSTATUS status = FIPS_hmacKdfKat(hwAccelCtx, "HMAC-KDF-SHA3-512",
        &SHA3_512Suite, expect, sizeof(expect), FIPS_FORCE_FAIL_HMAC_KDF_SHA3_512_TEST);
    setFIPS_Status_Once(FIPS_ALGO_HMAC_KDF, status);
    return status;
} /* FIPS_hmacKdfSha3_512Kat */
#endif /* defined(__ENABLE_DIGICERT_FIPS_SHA3__) */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_hmacKdfAll_Kat(hwAccelDescr hwAccelCtx)
{
    MSTATUS status = OK;

    if (OK > (status = FIPS_hmacKdfSha1Kat(hwAccelCtx)))
         goto exit;
#if (!defined(__DISABLE_DIGICERT_SHA224__))
    if (OK > (status = FIPS_hmacKdfSha224Kat(hwAccelCtx)))
         goto exit;
#endif
#if (!defined(__DISABLE_DIGICERT_SHA256__))
     if (OK > (status = FIPS_hmacKdfSha256Kat(hwAccelCtx)))
         goto exit;
#endif
#if (!defined(__DISABLE_DIGICERT_SHA384__))
     if (OK > (status = FIPS_hmacKdfSha384Kat(hwAccelCtx)))
         goto exit;
#endif
#if (!defined(__DISABLE_DIGICERT_SHA512__))
     if (OK > (status = FIPS_hmacKdfSha512Kat(hwAccelCtx)))
         goto exit;
#endif

#if defined(__ENABLE_DIGICERT_FIPS_SHA3__)
     if (OK > (status = FIPS_hmacKdfSha3_224Kat(hwAccelCtx)))
         goto exit;
     if (OK > (status = FIPS_hmacKdfSha3_256Kat(hwAccelCtx)))
         goto exit;
     if (OK > (status = FIPS_hmacKdfSha3_384Kat(hwAccelCtx)))
         goto exit;
     if (OK > (status = FIPS_hmacKdfSha3_512Kat(hwAccelCtx)))
         goto exit;
#endif /* defined(__ENABLE_DIGICERT_FIPS_SHA3__) */

exit:
    return status;

} /* FIPS_hmacKdfAll_Kat */

#endif /* !defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__) */

/*------------------------------------------------------------------*/

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

