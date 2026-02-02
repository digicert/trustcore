/*
 * nist_kdf_test.c
 *
 * unit test for nist_kdf.c
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
#include "../nist_kdf.c"

#include "../../common/mrtos.h"
#include "../md5.h"
#include "../sha1.h"
#include "../sha256.h"
#include "../sha512.h"
#include "../crypto.h"
#include "../hmac.h"

#include "../../../unit_tests/unittest.h"

typedef struct NIST_KDF_TestVector 
{
    ubyte4 hashAlgo;
    ubyte* key;
    ubyte4 keySize;
    ubyte4 counterSize;
    ubyte* label;
    ubyte4 labelSize;
    ubyte* context;
    ubyte4 contextSize;
    ubyte4 outputSizeEncodingSize;
    ubyte4 littleEndian;
    ubyte* output;
    ubyte4 outputSize;
} NIST_KDF_TestVector;

static const NIST_KDF_TestVector gCounterModeTestVectors[] =
{
    { 
        ht_sha256, 
        (ubyte*)    "\x66\x29\x4a\x74\x9d\xce\x89\x0a"
                    "\x0a\x3f\x0d\x26\x7c\x99\x0e\x97"
                    "\x6f\x5a\x36\x53\x9b\xf0\xa1\xb2" 
                    "\xc7\xbc\xbd\xb7\x2a\xe3\x1b\x10",
        32, 2,
        (ubyte*) "Pairwise key expansion", 22,
        (ubyte*)    "\x0c\x42\x3a\xea\x93\x00\x21"
                    "\x6a\x6b\xba\x8c\x49\x1a\xc0\xe0"
                    "\xdb\xa7\xf6\xa5\x8a\xe8\xa1\x56"
                    "\xce\x03\xbd\xfb\xd9\x87\x30\xe7"
                    "\xdf\xb9\x55\x0a\x88\xe2\x12\x31"
                    "\x78\x1d\xfb\xca\xb6\x48\x8c\x4f"
                    "\x98\x21\x34\x37\x83\x92\x6e\x76"
                    "\x97\x20\x0d\xbd\xc1\xb1\xc1\xcc"
                    "\x63\xb9\x0e\xe4\x65\x94\x54\xf6"
                    "\x2d\xb7\x02\xdd",
        75, 2, 1,
        (ubyte*)    "\xb9\xb8\xf6\x89\xfa\x21\x26\xab"
                    "\xcd\x13\x68\x3f\x01\xc3\x0d\x20"
                    "\x78\x2b\xaa\x1b\x01\x3f\xac\x8d"
                    "\xb5\x90\x7a\x48\xdf\xa8\x16\xa3"
                    "\xa8\x16\x7d\x5a\x23\xf7\x24\x3d"
                    "\x42\x6f\x99\x81\x96\x8b\xfc\xcd"
                    "\xc2\xf4\x67\xbf\x2d\x0d\x42\x1d"
                    "\x7f\x41\x4b\x71\xbe\x3c\xc8\x95",
        64                               
    }                                    
};


/*-------------------------------------------------------------------------*/

int hash_counter_mode_test_vector(  MOC_SYM(hwAccelDescr hwAccelCtx)
                                    int hint, const NIST_KDF_TestVector* pV)
{
    int retVal = 0;
    HMAC_CTX *ctx = 0;
    const BulkHashAlgo *pBHA;
    ubyte* output = 0;
    sbyte4 resCmp;

    output = MALLOC( pV->outputSize);
    retVal += UNITTEST_TRUE( hint, output != 0 );
    if (retVal) goto exit;

    /* create a context */
    retVal += UNITTEST_STATUS(hint, CRYPTO_getRSAHashAlgo( pV->hashAlgo, &pBHA));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(hint, HmacCreate(MOC_HASH(hwAccelCtx) &ctx, pBHA));
    if (retVal) goto exit;

    /* set the key */
    retVal += UNITTEST_STATUS(hint, HmacKey(MOC_HASH(hwAccelCtx) ctx, 
                                pV->key, pV->keySize));
    if (retVal) goto exit;


    retVal += UNITTEST_STATUS(hint, 
            KDF_NIST_CounterMode( MOC_SYM(hwAccelCtx) pV->counterSize, ctx,
                                &NIST_PRF_Hmac, pV->label, pV->labelSize,
                                pV->context, pV->contextSize,
                                pV->outputSizeEncodingSize, pV->littleEndian,
                                output, pV->outputSize));
    if (retVal) goto exit;

    DIGI_MEMCMP( pV->output, output, pV->outputSize, &resCmp);

    retVal += UNITTEST_TRUE(hint, 0 == resCmp);
    
exit:

    HmacDelete(MOC_HASH(hwAccelCtx) &ctx);

    FREE(output);
    return retVal;
}


/*-------------------------------------------------------------------------*/

int nist_kdf_test_counter_mode_vectors()
{
    int i, retVal = 0;
    hwAccelDescr hwAccelCtx;

    retVal += UNITTEST_STATUS(0, 
            HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));    
    if (retVal) goto exit;

    for (i = 0; i < COUNTOF(gCounterModeTestVectors); ++i)
    {
        retVal += hash_counter_mode_test_vector(MOC_SYM(hwAccelCtx)
                                                i, gCounterModeTestVectors+i);
    }

exit:

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*-------------------------------------------------------------------------*/

int nist_kdf_test_counter_mode()
{
    int retVal = 0;
    hwAccelDescr hwAccelCtx;
    HMAC_CTX *ctx = 0;
    const BulkHashAlgo *SHA256_Algo;
    ubyte keyMaterial[65];

    DIGI_MEMSET(keyMaterial+32, 0xFF, 33);

    retVal += UNITTEST_STATUS(0, 
            HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));
    if (retVal) goto exit;

    /* create a HMAC SHA256 context */
    retVal += UNITTEST_STATUS(0, CRYPTO_getRSAHashAlgo( ht_sha256, &SHA256_Algo));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(0, HmacCreate(MOC_HASH(hwAccelCtx) &ctx, SHA256_Algo));
    if (retVal) goto exit;

    /* set the key */
    retVal += UNITTEST_STATUS(0, HmacKey(MOC_HASH(hwAccelCtx) ctx, 
                                (ubyte*) "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
                                10));

    /* invalid values */
    retVal += UNITTEST_TRUE( 0, ERR_NIST_KDF_INVALID_COUNTER_SIZE == 
                                    KDF_NIST_CounterMode( MOC_SYM(hwAccelCtx) 5, ctx,
                                    &NIST_PRF_Hmac, 
                                    (ubyte*) "test", 4,
                                    (ubyte*) "NIST_KDF_test_counter", 21, 2, 0, 
                                    keyMaterial, 32));


    retVal += UNITTEST_TRUE( 0, ERR_NIST_KDF_COUNTER_KEY_SIZES == 
                                    KDF_NIST_CounterMode( MOC_SYM(hwAccelCtx) 1, ctx,
                                    &NIST_PRF_Hmac, 
                                    (ubyte*) "test", 4,
                                    (ubyte*) "NIST_KDF_test_counter", 21, 2, 0, 
                                    keyMaterial, 256*32));

    /* one round */
    retVal += UNITTEST_STATUS(0, 
            KDF_NIST_CounterMode( MOC_SYM(hwAccelCtx) 2, ctx,
                                &NIST_PRF_Hmac, 
                                (ubyte*) "test", 4,
                                (ubyte*) "NIST_KDF_test_counter", 21, 2, 0, 
                                keyMaterial, 32));
    if (retVal) goto exit;                             
    retVal += UNITTEST_TRUE(0, keyMaterial[32] == 0xFF);

    /* partial round */
    retVal += UNITTEST_STATUS(0, 
            KDF_NIST_CounterMode( MOC_SYM(hwAccelCtx) 2, ctx,
                                &NIST_PRF_Hmac, 
                                (ubyte*) "test", 4,
                                (ubyte*) "NIST_KDF_test_counter", 21, 2, 0, 
                                keyMaterial, 40));
    if (retVal) goto exit;                             
    retVal += UNITTEST_TRUE(0, keyMaterial[40] == 0xFF);

    /* 2 rounds */
    retVal += UNITTEST_STATUS(0, 
            KDF_NIST_CounterMode( MOC_SYM(hwAccelCtx) 2, ctx,
                                &NIST_PRF_Hmac, 
                                (ubyte*) "test", 4,
                                (ubyte*) "NIST_KDF_test_counter", 21, 2, 0, 
                                keyMaterial, 64));
    if (retVal) goto exit;                             
    retVal += UNITTEST_TRUE(0, keyMaterial[64] == 0xFF);

exit:

    HmacDelete(MOC_HASH(hwAccelCtx) &ctx);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    return retVal;
}


/*-------------------------------------------------------------------------*/

int nist_kdf_test_feedback_mode()
{
    int retVal = 0;
    hwAccelDescr hwAccelCtx;
    HMAC_CTX *ctx = 0;
    const BulkHashAlgo *SHA256_Algo;
    ubyte keyMaterial[65];

    DIGI_MEMSET(keyMaterial+32, 0xFF, 33);

    retVal += UNITTEST_STATUS(0, 
            HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));
    if (retVal) goto exit;

    /* create a HMAC SHA256 context */
    retVal += UNITTEST_STATUS(0, CRYPTO_getRSAHashAlgo( ht_sha256, &SHA256_Algo));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(0, HmacCreate(MOC_HASH(hwAccelCtx) &ctx, SHA256_Algo));
    if (retVal) goto exit;

    /* set the key */
    retVal += UNITTEST_STATUS(0, HmacKey(MOC_HASH(hwAccelCtx) ctx, 
                                (ubyte*) "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
                                10));

    /* invalid values */
    retVal += UNITTEST_TRUE( 0, ERR_NIST_KDF_INVALID_COUNTER_SIZE == 
                                    KDF_NIST_FeedbackMode( MOC_SYM(hwAccelCtx) 5, ctx,
                                    &NIST_PRF_Hmac, 
                                     (ubyte*) "some_arbitrary_iv", 17,
                                    (ubyte*) "test", 4,
                                    (ubyte*) "NIST_KDF_test_counter", 21, 2, 0, 
                                    keyMaterial, 32));

    /* one round */
    retVal += UNITTEST_STATUS(0, 
            KDF_NIST_FeedbackMode( MOC_SYM(hwAccelCtx) 2, ctx,
                                &NIST_PRF_Hmac, 
                                NULL, 0, 
                                (ubyte*) "test", 4,
                                (ubyte*) "NIST_KDF_test_counter", 21, 2, 0,  
                                keyMaterial, 32));
    if (retVal) goto exit;                             
    retVal += UNITTEST_TRUE(0, keyMaterial[32] == 0xFF);

    /* partial round with iv */
    retVal += UNITTEST_STATUS(0, 
            KDF_NIST_FeedbackMode( MOC_SYM(hwAccelCtx) 2, ctx,
                                &NIST_PRF_Hmac, 
                                (ubyte*) "some_arbitrary_iv", 17,
                                (ubyte*) "test", 4,
                                (ubyte*) "NIST_KDF_test_counter", 21, 2, 0, 
                                keyMaterial, 40));
    if (retVal) goto exit;                             
    retVal += UNITTEST_TRUE(0, keyMaterial[40] == 0xFF);

    /* 2 rounds no counter, iv */
    retVal += UNITTEST_STATUS(0, 
            KDF_NIST_FeedbackMode( MOC_SYM(hwAccelCtx) 0, ctx,
                                &NIST_PRF_Hmac, 
                                (ubyte*) "some_arbitrary_iv", 17,
                                (ubyte*) "test", 4,
                                (ubyte*) "NIST_KDF_test_counter", 21, 2, 0,
                                keyMaterial, 64));
    if (retVal) goto exit;                             
    retVal += UNITTEST_TRUE(0, keyMaterial[64] == 0xFF);

exit:

    HmacDelete(MOC_HASH(hwAccelCtx) &ctx);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    return retVal;
}


/*-------------------------------------------------------------------------*/

int nist_kdf_test_double_pipeline_mode()
{
    int retVal = 0;
    hwAccelDescr hwAccelCtx;
    HMAC_CTX *ctx = 0;
    const BulkHashAlgo *SHA256_Algo;
    ubyte keyMaterial[65];

    DIGI_MEMSET(keyMaterial+32, 0xFF, 33);

    retVal += UNITTEST_STATUS(0, 
            HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));
    if (retVal) goto exit;

    /* create a HMAC SHA256 context */
    retVal += UNITTEST_STATUS(0, CRYPTO_getRSAHashAlgo( ht_sha256, &SHA256_Algo));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(0, HmacCreate(MOC_HASH(hwAccelCtx) &ctx, SHA256_Algo));
    if (retVal) goto exit;

    /* set the key */
    retVal += UNITTEST_STATUS(0, HmacKey(MOC_HASH(hwAccelCtx) ctx, 
                                (ubyte*) "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
                                10));

    /* invalid values */
    retVal += UNITTEST_TRUE( 0, ERR_NIST_KDF_INVALID_COUNTER_SIZE == 
                                    KDF_NIST_DoublePipelineMode( MOC_SYM(hwAccelCtx) 5, ctx,
                                    &NIST_PRF_Hmac, 
                                    (ubyte*) "test", 4,
                                    (ubyte*) "NIST_KDF_test_counter", 21, 2, 0,
                                    keyMaterial, 32));

    /* one round */
    retVal += UNITTEST_STATUS(0, 
            KDF_NIST_DoublePipelineMode( MOC_SYM(hwAccelCtx) 2, ctx,
                                &NIST_PRF_Hmac, 
                                (ubyte*) "test", 4,
                                (ubyte*) "NIST_KDF_test_counter", 21, 2, 0,
                                keyMaterial, 32));
    if (retVal) goto exit;                             
    retVal += UNITTEST_TRUE(0, keyMaterial[32] == 0xFF);

    /* partial round  */
    retVal += UNITTEST_STATUS(0, 
            KDF_NIST_DoublePipelineMode( MOC_SYM(hwAccelCtx) 2, ctx,
                                &NIST_PRF_Hmac, 
                                (ubyte*) "test", 4,
                                (ubyte*) "NIST_KDF_test_counter", 21, 2, 0, 
                                keyMaterial, 40));
    if (retVal) goto exit;                             
    retVal += UNITTEST_TRUE(0, keyMaterial[40] == 0xFF);

    /* 2 rounds no counter */
    retVal += UNITTEST_STATUS(0, 
            KDF_NIST_DoublePipelineMode( MOC_SYM(hwAccelCtx) 0, ctx,
                                &NIST_PRF_Hmac, 
                                (ubyte*) "test", 4,
                                (ubyte*) "NIST_KDF_test_counter", 21, 2, 0, 
                                keyMaterial, 64));
    if (retVal) goto exit;                             
    retVal += UNITTEST_TRUE(0, keyMaterial[64] == 0xFF);

exit:

    HmacDelete(MOC_HASH(hwAccelCtx) &ctx);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    return retVal;
}

