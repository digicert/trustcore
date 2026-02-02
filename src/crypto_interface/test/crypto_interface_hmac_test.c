/*
 * crypto_interface_hmac_test.c
 *
 * test cases for crypto interface API for hmac.h
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
#include "../../../unit_tests/unittest.h"

#include "../../common/initmocana.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/md5.h"
#include "../../crypto/crypto.h"
#include "../../crypto/hmac.h"

#include "../../../unit_tests/unittest_utils.h"

#include "../../crypto_interface/test/hmac_ci_tests.h"

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#include "../../crypto_interface/crypto_interface_hmac.h"
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
#include "crypto_interface_tap_example.h"
#include "../../crypto/mocsymalgs/tap/symtap.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_hmac.h"
#include "../../crypto_interface/crypto_interface_hmac_tap.h"
#endif

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
MSTATUS TAP_freeKeyEx(TAP_Key **ppKey);
#endif

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

/* test if it work */
const BulkHashAlgo SHA1Suite =
{
    SHA1_RESULT_SIZE, SHA1_BLOCK_SIZE, SHA1_allocDigest, SHA1_freeDigest,
    (BulkCtxInitFunc)SHA1_initDigest, (BulkCtxUpdateFunc)SHA1_updateDigest, (BulkCtxFinalFunc)SHA1_finalDigest, NULL, NULL, NULL, ht_sha1
};

const BulkHashAlgo SHA224Suite =
{
    SHA224_RESULT_SIZE, SHA224_BLOCK_SIZE, SHA224_allocDigest, SHA224_freeDigest,
    (BulkCtxInitFunc)SHA224_initDigest, (BulkCtxUpdateFunc)SHA224_updateDigest, (BulkCtxFinalFunc)SHA224_finalDigest, NULL, NULL, NULL, ht_sha224
};

const BulkHashAlgo SHA256Suite =
{
    SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
    (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA256_finalDigest, NULL, NULL, NULL, ht_sha256
};

const BulkHashAlgo SHA384Suite =
{
    SHA384_RESULT_SIZE, SHA384_BLOCK_SIZE, SHA384_allocDigest, SHA384_freeDigest,
    (BulkCtxInitFunc)SHA384_initDigest, (BulkCtxUpdateFunc)SHA384_updateDigest, (BulkCtxFinalFunc)SHA384_finalDigest, NULL, NULL, NULL, ht_sha384
};

const BulkHashAlgo SHA512Suite =
{
    SHA512_RESULT_SIZE, SHA512_BLOCK_SIZE, SHA512_allocDigest, SHA512_freeDigest,
    (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest, (BulkCtxFinalFunc)SHA512_finalDigest, NULL, NULL, NULL, ht_sha512
};

static int gSha1ExIndices[][3] =
{
    { 0,    0,    0},
    { 0,    0,    1},
    { 0,    1,    2},
    { 0,   10,   15},
    { 5,    6,   10},
    { 0,    0,   20},
    {11,   12,   13},
    { 3,    4,    6}
};


/*----------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC__))
static int testCryptoInterface()
{
    MSTATUS status = OK;

    HMAC_CTX *pCtx = NULL;
    MocSymCtx pMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HMAC_MBED__

    /* create context for HMAC */
    status = HmacCreate(MOC_HASH(gpHwAccelCtx) &pCtx, &SHA256Suite);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    pMocCtx = pCtx->pMocSymCtx;
    if(NULL == pMocCtx)
    {
        status = ERR_INVALID_ARG;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if(FALSE == pCtx->enabled)
    {
        status = ERR_INVALID_ARG;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

#endif

exit:

    if(NULL != pCtx)
    {
        HmacDelete(MOC_HASH(gpHwAccelCtx) (HMAC_CTX**)&pCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}
#endif


/*----------------------------------------------------------------------------*/

int runHmacTests8()
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = -1;
    HMAC_CTX *pCtx = NULL;

    ubyte pKey[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

    ubyte4 keyLen = 20;

    ubyte pData[4] = {0x48, 0x69, 0x20, 0x54};
    ubyte4 dataLen = 4;

    ubyte pData2[4] = {0x68, 0x65, 0x72, 0x65};
    ubyte4 data2Len = 4;

    ubyte pExpected[32] = {0xE4, 0x84, 0x11, 0x26, 0x27, 0x15, 0xC8, 0x37,
                           0x0C, 0xD5, 0xE7, 0xBF, 0x8E, 0x82, 0xBE, 0xF5,
                           0x3B, 0xD5, 0x37, 0x12, 0xD0, 0x07, 0xF3, 0x42,
                           0x93, 0x51, 0x84, 0x3B, 0x77, 0xC7, 0xBB, 0x9B};

    ubyte4 expectedLen = 32;

    ubyte pOutput[32];

    DIGI_MEMSET(pOutput, 0, 32);

    /* create context for HMAC */
    status = HmacCreate(MOC_HASH(gpHwAccelCtx) &pCtx, &SHA256Suite);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = HmacQuickerEx(MOC_HASH(gpHwAccelCtx) NULL, 0, pData, dataLen, pData2, data2Len, pOutput, &SHA256Suite, pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    DIGI_MEMCMP(pExpected, pOutput, expectedLen, &cmpRes);

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        goto exit;
    }

exit:

    if(NULL != pCtx)
    {
        HmacDelete(MOC_HASH(gpHwAccelCtx) (HMAC_CTX**)&pCtx);
    }

    return (OK == status)? 0 : 1;
}


/*----------------------------------------------------------------------------*/

int runHmacTests7()
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = -1;

    SHA256_CTX *pShaCtx = NULL;

    ubyte pKey[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

    ubyte4 keyLen = 20;


    ubyte pData[4] = {0x48, 0x69, 0x20, 0x54};
    ubyte4 dataLen = 4;

    ubyte pData2[4] = {0x68, 0x65, 0x72, 0x65};
    ubyte4 data2Len = 4;

    ubyte pExpected[32] = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                           0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};

    ubyte4 expectedLen = 32;

    ubyte pOutput[32];

    DIGI_MEMSET(pOutput, 0, 32);

    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(NULL == pShaCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = HmacQuickerInlineEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pData, dataLen, pData2, data2Len, pOutput, &SHA256Suite, (BulkCtx)pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    DIGI_MEMCMP(pExpected, pOutput, expectedLen, &cmpRes);

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        goto exit;
    }

exit:

    if (NULL != pShaCtx)
    {
        SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
    }

    return (OK == status)? 0 : 1;
}


/*----------------------------------------------------------------------------*/

int runHmacTests6()
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = -1;

    SHA256_CTX *pShaCtx = NULL;

    ubyte pKey[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

    ubyte4 keyLen = 20;

    ubyte pData[8] = {0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65};
    ubyte4 dataLen = 8;

    ubyte pExpected[32] = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                           0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};

    ubyte4 expectedLen = 32;

    ubyte pOutput[32];

    DIGI_MEMSET(pOutput, 0, 32);

    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(NULL == pShaCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }


    status = HmacQuickerInline(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pData, dataLen, pOutput, &SHA256Suite, (BulkCtx)pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    DIGI_MEMCMP(pExpected, pOutput, expectedLen, &cmpRes);

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        goto exit;
    }

exit:

    if (NULL != pShaCtx)
    {
        SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
    }

    return (OK == status)? 0 : 1;
}


/*----------------------------------------------------------------------------*/

int runHmacTests5()
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = -1;
    HMAC_CTX *pCtx = NULL;

    ubyte pKey[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

    ubyte4 keyLen = 20;

    ubyte pData[4] = {0x48, 0x69, 0x20, 0x54};
    ubyte4 dataLen = 4;

    ubyte pData2[4] = {0x68, 0x65, 0x72, 0x65};
    ubyte4 data2Len = 4;

    ubyte pExpected[32] = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                           0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};

    ubyte4 expectedLen = 32;

    ubyte pOutput[32];

    DIGI_MEMSET(pOutput, 0, 32);

    /* create context for HMAC */
    status = HmacCreate(MOC_HASH(gpHwAccelCtx) &pCtx, &SHA256Suite);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = HmacQuickerEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pData, dataLen, pData2, data2Len, pOutput, &SHA256Suite, pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    DIGI_MEMCMP(pExpected, pOutput, expectedLen, &cmpRes);

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        goto exit;
    }

exit:

    if(NULL != pCtx)
    {
        HmacDelete(MOC_HASH(gpHwAccelCtx) (HMAC_CTX**)&pCtx);
    }

    return (OK == status)? 0 : 1;
}


/*----------------------------------------------------------------------------*/

int runHmacTests4()
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = -1;
    HMAC_CTX *pCtx = NULL;

    ubyte pKey[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

    ubyte4 keyLen = 20;

    ubyte pData[8] = {0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65};
    ubyte4 dataLen = 8;

    ubyte pExpected[32] = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                           0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};

    ubyte4 expectedLen = 32;

    ubyte pOutput[32];

    DIGI_MEMSET(pOutput, 0, 32);

    /* create context for HMAC */
    status = HmacCreate(MOC_HASH(gpHwAccelCtx) &pCtx, &SHA256Suite);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = HmacQuicker(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pData, dataLen, pOutput, &SHA256Suite, pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    DIGI_MEMCMP(pExpected, pOutput, expectedLen, &cmpRes);

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        goto exit;
    }

exit:

    if(NULL != pCtx)
    {
        HmacDelete(MOC_HASH(gpHwAccelCtx) (HMAC_CTX**)&pCtx);
    }

    return (OK == status)? 0 : 1;
}


/*----------------------------------------------------------------------------*/

int runHmacTests3()
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = -1;
    HMAC_CTX *pCtx = NULL;

    ubyte pKey[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

    ubyte4 keyLen = 20;

    ubyte pData[4] = {0x48, 0x69, 0x20, 0x54};
    ubyte4 dataLen = 4;

    ubyte pData2[4] = {0x68, 0x65, 0x72, 0x65};
    ubyte4 data2Len = 4;

    ubyte pExpected[32] = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                           0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};

    ubyte4 expectedLen = 32;

    ubyte pOutput[32];

    DIGI_MEMSET(pOutput, 0, 32);

    status = HmacQuickEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pData, dataLen, pData2, data2Len, pOutput, &SHA256Suite);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    DIGI_MEMCMP(pExpected, pOutput, expectedLen, &cmpRes);

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        goto exit;
    }

exit:
    return (OK == status)? 0 : 1;
}

/*----------------------------------------------------------------------------*/

int runHmacTests2()
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = -1;
    HMAC_CTX *pCtx = NULL;

    ubyte pKey[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

    ubyte4 keyLen = 20;

    ubyte pData[8] = {0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65};

    ubyte4 dataLen = 8;

    ubyte pExpected[32] = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                           0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};

    ubyte4 expectedLen = 32;

    ubyte pOutput[32];

    DIGI_MEMSET(pOutput, 0, 32);

    status = HmacQuick(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pData, dataLen, pOutput, &SHA256Suite);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    DIGI_MEMCMP(pExpected, pOutput, expectedLen, &cmpRes);

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        goto exit;
    }

exit:
    return (OK == status)? 0 : 1;
}


/*----------------------------------------------------------------------------*/

int runHmacTests()
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = -1;
    HMAC_CTX *pCtx = NULL;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    HMAC_CTX *pClone = NULL;
#endif

    ubyte pKey[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

    ubyte4 keyLen = 20;

    ubyte pData[8] = {0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65};

    ubyte4 dataLen = 8;

    ubyte pExpected[32] = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                           0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};

    ubyte4 expectedLen = 32;

    ubyte pOutput[32];
    ubyte4 outputLen = 32;

    DIGI_MEMSET(pOutput, 0, 32);

    /* create context for HMAC */
    status = HmacCreate(MOC_HASH(gpHwAccelCtx) &pCtx, &SHA256Suite);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* load key that will be used */
    status = HmacKey(MOC_HASH(gpHwAccelCtx) pCtx, pKey, keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* load message */
    status = HmacUpdate(MOC_HASH(gpHwAccelCtx) pCtx, pData, (sbyte4)dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = HmacFinal(MOC_HASH(gpHwAccelCtx) pCtx, pOutput);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    DIGI_MEMCMP(pExpected, pOutput, expectedLen, &cmpRes);

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        goto exit;
    }

    status = HmacReset(MOC_HASH(gpHwAccelCtx) pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMSET(pOutput, 0, outputLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;


    /* repeat hash step */
    status = HmacUpdate(MOC_HASH(gpHwAccelCtx) pCtx, pData, (sbyte4)dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* test clone if not export. Clone can be added to mbed operator at a later date */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    status = CRYPTO_INTERFACE_HmacCloneCtx(MOC_HASH(gpHwAccelCtx) &pClone, pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacFinal(MOC_HASH(gpHwAccelCtx) pClone, pOutput);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
#else    
    status = HmacFinal(MOC_HASH(gpHwAccelCtx) pCtx, pOutput);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
#endif

    cmpRes = -1;
    DIGI_MEMCMP(pExpected, pOutput, expectedLen, &cmpRes);

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        goto exit;
    }

exit:

    if(NULL != pCtx)
    {
        HmacDelete(MOC_HASH(gpHwAccelCtx) (HMAC_CTX**)&pCtx);
    }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    if(NULL != pClone)
    {
        CRYPTO_INTERFACE_HmacDelete(MOC_HASH(gpHwAccelCtx) &pClone);
    }
#endif

    return (OK == status)? 0 : 1;
}


/*----------------------------------------------------------------------------*/

int runHmacSha1Tests()
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte pOutput[SHA_HASH_RESULT_SIZE];
    int errorCount = 0;
    sbyte4 cmpRes = -1;

    ubyte *pMsg = NULL;
    sbyte4 msgLen = 0;

    ubyte *pKey = NULL;
    sbyte4 keyLen = 0;

    ubyte *pMac = NULL;
    sbyte4 macLen = 0;

    int j;
    for(j = 0;j < 300; j++)
    {
        msgLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha1HmacTests[j].pMsg, &pMsg);
        keyLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha1HmacTests[j].pKey, &pKey);
        macLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha1HmacTests[j].pMac, &pMac);

        DIGI_MEMSET(pOutput, 0, SHA_HASH_RESULT_SIZE);

        status = HMAC_SHA1(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, NULL, 0, pOutput);
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);

        if(OK == status)
        {
            cmpRes = -1;
            DIGI_MEMCMP(pOutput, pMac, macLen, &cmpRes);

            if(0 != cmpRes)
            {
                status = ERR_CMP;
                errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
            }
        }

        DIGI_FREE((void**)&pMsg);
        DIGI_FREE((void**)&pKey);
        DIGI_FREE((void**)&pMac);
    }
    return errorCount;
}


/*----------------------------------------------------------------------------*/

int runHmacSha256Tests()
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte pOutput[SHA256_RESULT_SIZE];
    int errorCount = 0;
    sbyte4 cmpRes = -1;

    ubyte *pMsg = NULL;
    sbyte4 msgLen = 0;

    ubyte *pKey = NULL;
    sbyte4 keyLen = 0;

    ubyte *pMac = NULL;
    sbyte4 macLen = 0;

    int j;
    for(j = 0;j < 225; j++)
    {
        msgLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha256HmacTests[j].pMsg, &pMsg);
        keyLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha256HmacTests[j].pKey, &pKey);
        macLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha256HmacTests[j].pMac, &pMac);

        DIGI_MEMSET(pOutput, 0, SHA_HASH_RESULT_SIZE);

        status = HMAC_SHA256(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, NULL, 0, pOutput);
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);

        if(OK == status)
        {
            cmpRes = -1;
            DIGI_MEMCMP(pOutput, pMac, macLen, &cmpRes);

            if(0 != cmpRes)
            {
                status = ERR_CMP;
                errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
            }
        }

        DIGI_FREE((void**)&pMsg);
        DIGI_FREE((void**)&pKey);
        DIGI_FREE((void**)&pMac);
    }
    return errorCount;
}


/*----------------------------------------------------------------------------*/

int runHmacSha512Tests()
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte pOutput[SHA512_RESULT_SIZE];
    int errorCount = 0;
    sbyte4 cmpRes = -1;

    ubyte *pMsg = NULL;
    sbyte4 msgLen = 0;

    ubyte *pKey = NULL;
    sbyte4 keyLen = 0;

    ubyte *pMac = NULL;
    sbyte4 macLen = 0;

    int j;
    for(j = 0;j < 225; j++)
    {
        msgLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha512HmacTests[j].pMsg, &pMsg);
        keyLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha512HmacTests[j].pKey, &pKey);
        macLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha512HmacTests[j].pMac, &pMac);

        DIGI_MEMSET(pOutput, 0, SHA_HASH_RESULT_SIZE);

        status = HMAC_SHA512(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, NULL, 0, pOutput);
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);

        if(OK == status)
        {
            cmpRes = -1;
            DIGI_MEMCMP(pOutput, pMac, macLen, &cmpRes);

            if(0 != cmpRes)
            {
                status = ERR_CMP;
                errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
            }
        }

        DIGI_FREE((void**)&pMsg);
        DIGI_FREE((void**)&pKey);
        DIGI_FREE((void**)&pMac);
    }
    return errorCount;
}


/*----------------------------------------------------------------------------*/

int testHmacSha1Quick()
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte pOutput[SHA_HASH_RESULT_SIZE];
    int errorCount = 0;
    sbyte4 cmpRes = -1;

    ubyte *pMsg = NULL;
    sbyte4 msgLen = 0;

    ubyte *pKey = NULL;
    sbyte4 keyLen = 0;

    ubyte *pMac = NULL;
    sbyte4 macLen = 0;

    int j;
    for(j = 0;j < 300; j++)
    {
        msgLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha1HmacTests[j].pMsg, &pMsg);
        keyLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha1HmacTests[j].pKey, &pKey);
        macLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha1HmacTests[j].pMac, &pMac);

        DIGI_MEMSET(pOutput, 0, SHA_HASH_RESULT_SIZE);

        status = HMAC_SHA1_quick(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, pOutput);
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);

        if(OK == status)
        {
            cmpRes = -1;
            DIGI_MEMCMP(pOutput, pMac, macLen, &cmpRes);

            if(0 != cmpRes)
            {
                status = ERR_CMP;
                errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
            }
        }

        DIGI_FREE((void**)&pMsg);
        DIGI_FREE((void**)&pKey);
        DIGI_FREE((void**)&pMac);
    }
    return errorCount;
}


/*----------------------------------------------------------------------------*/


int testHmacSha1Ex()
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte pOutput[SHA_HASH_RESULT_SIZE];
    int errorCount = 0;
    sbyte4 cmpRes = -1;

    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;

    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;

    ubyte *pMac = NULL;
    ubyte4 macLen = 0;

    ubyte *ppText[4];
    sbyte4 pTextLen[4];
    int i,j;
    for(j = 0;j < 300; j++)
    {
        msgLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha1HmacTests[j].pMsg, &pMsg);
        keyLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha1HmacTests[j].pKey, &pKey);
        macLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pSha1HmacTests[j].pMac, &pMac);

        if(20 <= msgLen)
        {
            DIGI_MEMSET(pOutput, 0, SHA_HASH_RESULT_SIZE);
            for(i = 0; i < 7; i++)
            {

                ppText[0] = pMsg;
                pTextLen[0] = gSha1ExIndices[i][0];

                ppText[1] = pMsg + gSha1ExIndices[i][0];
                pTextLen[1] = gSha1ExIndices[i][1] - gSha1ExIndices[i][0];

                ppText[2] = pMsg + gSha1ExIndices[i][1];
                pTextLen[2] = gSha1ExIndices[i][2] - gSha1ExIndices[i][1];

                ppText[3] = pMsg + gSha1ExIndices[i][2];
                pTextLen[3] = msgLen - gSha1ExIndices[i][2];

                status = HMAC_SHA1Ex(MOC_HASH(gpHwAccelCtx) pKey, keyLen, (const ubyte**)ppText, pTextLen, 4, pOutput);
                errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
                if(OK == status)
                {
                    cmpRes = -1;
                    DIGI_MEMCMP(pOutput, pMac, macLen, &cmpRes);

                    if(0 != cmpRes)
                    {
                        status = ERR_CMP;
                        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
                    }
                }
            }
        }

        DIGI_FREE((void**)&pMsg);
        DIGI_FREE((void**)&pKey);
        DIGI_FREE((void**)&pMac);
    }

    return errorCount;
}


/*----------------------------------------------------------------------------*/

/* tests for MD5 were generated by passing hmac-sha1 tests through HMAC_MD5
 * without using the crypto interface. The output of this is in pMd5HmacTests
 * array in hmac_ci_tests.h file. */
int runMd5Tests()
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte pOutput[MD5_RESULT_SIZE];
    int errorCount = 0;
    sbyte4 cmpRes = -1;

    ubyte *pMsg = NULL;
    sbyte4 msgLen = 0;

    ubyte *pKey = NULL;
    sbyte4 keyLen = 0;

    ubyte *pMac = NULL;
    sbyte4 macLen = 0;

    int j;
    for(j = 0;j < 300; j++)
    {
        msgLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pMd5HmacTests[j].pMsg, &pMsg);
        keyLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pMd5HmacTests[j].pKey, &pKey);
        macLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pMd5HmacTests[j].pMac, &pMac);

        DIGI_MEMSET(pOutput, 0, MD5_RESULT_SIZE);

        status = HMAC_MD5(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, NULL, 0, pOutput);
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);

        if(OK == status)
        {
            cmpRes = -1;
            DIGI_MEMCMP(pOutput, pMac, macLen, &cmpRes);

            if(0 != cmpRes)
            {
                status = ERR_CMP;
                errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
            }
        }

        DIGI_FREE((void**)&pMsg);
        DIGI_FREE((void**)&pKey);
        DIGI_FREE((void**)&pMac);
    }
    return errorCount;
}


/*----------------------------------------------------------------------------*/

int runMd5TestsQuick()
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte pOutput[MD5_RESULT_SIZE];
    int errorCount = 0;
    sbyte4 cmpRes = -1;

    ubyte *pMsg = NULL;
    sbyte4 msgLen = 0;

    ubyte *pKey = NULL;
    sbyte4 keyLen = 0;

    ubyte *pMac = NULL;
    sbyte4 macLen = 0;

    int j;
    for(j = 0;j < 300; j++)
    {
        msgLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pMd5HmacTests[j].pMsg, &pMsg);
        keyLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pMd5HmacTests[j].pKey, &pKey);
        macLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)pMd5HmacTests[j].pMac, &pMac);

        DIGI_MEMSET(pOutput, 0, MD5_RESULT_SIZE);

        status = HMAC_MD5_quick(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, pOutput);
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);

        if(OK == status)
        {
            cmpRes = -1;
            DIGI_MEMCMP(pOutput, pMac, macLen, &cmpRes);

            if(0 != cmpRes)
            {
                status = ERR_CMP;
                errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
            }
        }

        DIGI_FREE((void**)&pMsg);
        DIGI_FREE((void**)&pKey);
        DIGI_FREE((void**)&pMac);
    }
    return errorCount;
}


/*----------------------------------------------------------------------------*/

int negativeTests()
{
    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;
    HMAC_CTX *pCtx = NULL;
    HMAC_CTX *pValidCtx = NULL;

    ubyte pMsg[100] = {0xff};
    sbyte4 msgLen = 100;

    ubyte pKey[33] = {0xff};
    sbyte4 keyLen = 33;

    ubyte pOptData[50];
    sbyte4 optDataLen = 50;

    ubyte pResult[MD5_DIGESTSIZE];
    ubyte pResult1[SHA_HASH_RESULT_SIZE];
    ubyte pResult256[SHA256_RESULT_SIZE];
    ubyte pResult512[SHA512_RESULT_SIZE];

    /* initialize to avoid NULL error */
    ubyte *ppText[4];
    ppText[0] = (ubyte*)"a";
    ppText[1] = (ubyte*)"b";
    ppText[2] = (ubyte*)"c";
    ppText[3] = (ubyte*)"d";
    sbyte4 pTextLen[4];
    pTextLen[0] = 1;
    pTextLen[1] = 1;
    pTextLen[2] = 1;
    pTextLen[3] = 1;

    /* create a valid context to use for testing */
    status = HmacCreate(MOC_HASH(gpHwAccelCtx) &pValidCtx, &SHA256Suite);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = HmacKey(MOC_HASH(gpHwAccelCtx) pValidCtx, pKey, keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* null tests begin here */

    /* HmacCreate */
    status = HmacCreate(MOC_HASH(gpHwAccelCtx) NULL, &SHA256Suite);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacCreate(MOC_HASH(gpHwAccelCtx) &pCtx, NULL);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* HmacKey */
    status = HmacKey(MOC_HASH(gpHwAccelCtx) NULL, pKey, keyLen);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacKey(MOC_HASH(gpHwAccelCtx) pValidCtx, NULL, keyLen);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* HmacReset */
    status = HmacReset(MOC_HASH(gpHwAccelCtx) NULL);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* HmacUpdate */
    status = HmacUpdate(MOC_HASH(gpHwAccelCtx) NULL, pMsg, msgLen);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacUpdate(MOC_HASH(gpHwAccelCtx) pValidCtx, NULL, msgLen);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* HmacFinal */
    status = HmacFinal(MOC_HASH(gpHwAccelCtx) NULL, pResult);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacFinal(MOC_HASH(gpHwAccelCtx) pValidCtx, NULL);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* HmacQuickEx, HmacQuick calls HmacQuickEx */
    status = HmacQuickEx(MOC_HASH(gpHwAccelCtx) NULL, keyLen, pMsg, msgLen, NULL, 0, pResult256,
        &SHA256Suite);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacQuickEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, msgLen, NULL, 0, pResult256,
        &SHA256Suite);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacQuickEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, NULL, 0, NULL,
        &SHA256Suite);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacQuickEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, NULL, 0, pResult, NULL);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* HmacQuickerEx, HmacQuicker calls this */
    status = HmacQuickerEx(MOC_HASH(gpHwAccelCtx) NULL, keyLen, pMsg, msgLen, NULL, 0, pResult256, NULL,
        pValidCtx);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacQuickerEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, msgLen, NULL, 0, pResult256, NULL,
        pValidCtx);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacQuickerEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, NULL, 0, NULL, NULL,
        pValidCtx);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacQuickerEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, NULL, 0, pResult256, NULL,
        NULL);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* HmacQuickerInline */
    SHA256_CTX *pShaCtx = NULL;
    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = HmacQuickerInlineEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, NULL, 0, pResult,
        &SHA256Suite, NULL);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacQuickerInlineEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, NULL, 0, pResult,
        NULL, (BulkCtx)pShaCtx);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacQuickerInlineEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, NULL, 0, NULL,
        &SHA256Suite, (BulkCtx)pShaCtx);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacQuickerInlineEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, msgLen, NULL, 0, pResult256,
        &SHA256Suite, (BulkCtx)pShaCtx);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HmacQuickerInlineEx(MOC_HASH(gpHwAccelCtx) NULL, keyLen, pMsg, msgLen, NULL, 0, pResult256,
        &SHA256Suite, (BulkCtx)pShaCtx);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_MD5(MOC_HASH(gpHwAccelCtx) NULL, keyLen, pMsg, msgLen, pOptData, optDataLen,
        pResult);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_MD5(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, msgLen, pOptData, optDataLen,
        pResult);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_MD5(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, pOptData, optDataLen, NULL);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_SHA1(MOC_HASH(gpHwAccelCtx) NULL, keyLen, pMsg, msgLen, pOptData, optDataLen,
        pResult1);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_SHA1(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, msgLen, pOptData, optDataLen,
        pResult1);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_SHA1(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, pOptData, optDataLen, NULL);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_SHA256(MOC_HASH(gpHwAccelCtx) NULL, keyLen, pMsg, msgLen, pOptData, optDataLen,
        pResult256);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_SHA256(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, msgLen, pOptData, optDataLen,
        pResult256);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_SHA256(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, pOptData, optDataLen,
        NULL);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_SHA512(MOC_HASH(gpHwAccelCtx) NULL, keyLen, pMsg, msgLen, pOptData, optDataLen,
        pResult512);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_SHA512(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, msgLen, pOptData, optDataLen,
        pResult512);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_SHA512(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, msgLen, pOptData, optDataLen,
        NULL);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_SHA1Ex(MOC_HASH(gpHwAccelCtx) NULL, keyLen, (const ubyte**)ppText, pTextLen, 4, pResult1);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_SHA1Ex(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, pTextLen, 4, pResult1);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_SHA1Ex(MOC_HASH(gpHwAccelCtx) pKey, keyLen, (const ubyte**)ppText, NULL, 4, pResult1);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = HMAC_SHA1Ex(MOC_HASH(gpHwAccelCtx) pKey, keyLen, (const ubyte**)ppText, pTextLen, 4, NULL);
    if(OK == status)
    {
        status = ERR_INVALID_ARG;
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    }

exit:

    if (NULL != pValidCtx)
    {
        HmacDelete(MOC_HASH(gpHwAccelCtx) &pValidCtx);
    }
    if (NULL != pShaCtx)
    {
        SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
    }

    return errorCount;
}


/*----------------------------------------------------------------------------*/

int validEdgeCases()
{
    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;
    sbyte4 cmpRes = -1;
    HMAC_CTX *pCtx = NULL;
    HMAC_CTX *pValidCtx = NULL;

    ubyte pMsg[64] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
        0x01, 0x02, 0x03, 0x04
    };
    sbyte4 msgLen = 64;

    ubyte pKey[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    sbyte4 keyLen = 32;

    /* md5 no key, with message */
    ubyte pMd5Mac1[] = {
        0xd8, 0xc6, 0x5b, 0x3e, 0xb2, 0x65, 0x98, 0x42, 0x54, 0xfa, 0x62, 0x4f,
        0x00, 0x8f, 0x89, 0x3c
    };

    /* md5 with key, no message */
    ubyte pMd5Mac2[] = {
        0xcd, 0xbe, 0x9c, 0x7d, 0x49, 0x81, 0x58, 0xde, 0x6b, 0xd0, 0xec, 0xbc,
        0x9a, 0xc2, 0x01, 0x73
    };

    /* md5 no key, no message */
    ubyte pMd5Mac3[] = {
        0x74, 0xe6, 0xf7, 0x29, 0x8a, 0x9c, 0x2d, 0x16, 0x89, 0x35, 0xf5, 0x8c,
        0x00, 0x1b, 0xad, 0x88
    };

    /* sha 1 no key, with message */
    ubyte pSha1Mac1[] = {
        0x70, 0xf5, 0x50, 0x1c, 0x90, 0xab, 0xb7, 0xac, 0x4c, 0x33, 0x2f, 0x1e,
        0xed, 0xda, 0x1d, 0x73, 0xd0, 0x9b, 0xf7, 0x76
    };

    /* sha 1 with key, no message */
    ubyte pSha1Mac2[] = {
        0x3e, 0x99, 0x97, 0x5c, 0xe4, 0xf5, 0xb5, 0x3f, 0x25, 0x40, 0xa4, 0x3d,
        0xd7, 0x40, 0x8b, 0xd4, 0x7d, 0xa5, 0x9c, 0x2f
    };

    /* sha 1 no key, no message */
    ubyte pSha1Mac3[] = {
        0xfb, 0xdb, 0x1d, 0x1b, 0x18, 0xaa, 0x6c, 0x08, 0x32, 0x4b, 0x7d, 0x64,
        0xb7, 0x1f, 0xb7, 0x63, 0x70, 0x69, 0x0e, 0x1d
    };

    ubyte pSha1Mac4[] = {
        0xaf, 0xa2, 0x9a, 0xb8, 0x53, 0x44, 0x95, 0x25, 0x1a, 0xc8, 0x34, 0x6a,
        0x98, 0x57, 0x17, 0xc5, 0x4b, 0xc4, 0x9c, 0x26
    };

    /* sha 256 no key, with message */
    ubyte pSha256Mac1[] = {
        0x3d, 0x8d, 0xf3, 0x23, 0x1c, 0x27, 0x26, 0x2b, 0x82, 0x10, 0x4a, 0x84,
        0x54, 0x27, 0x16, 0x31, 0xaa, 0x35, 0x70, 0x50, 0xf3, 0xc3, 0x59, 0x3f,
        0xfa, 0xd0, 0x0a, 0xc5, 0xb0, 0x3d, 0xbd, 0x1c
    };

    /* sha 256 with key, no message */
    ubyte pSha256Mac2[] = {
        0xb2, 0x0a, 0xe8, 0x0e, 0x1d, 0x70, 0xf4, 0x9e, 0x9b, 0xb5, 0x66, 0x25,
        0xa4, 0xc9, 0xcf, 0x02, 0xa5, 0x54, 0x7b, 0xd2, 0xe2, 0xef, 0x7c, 0xf0,
        0x65, 0x7e, 0x59, 0xf4, 0x4c, 0xc0, 0xc0, 0x17
    };

    /* sha 256 no key, no message */
    ubyte pSha256Mac3[] = {
        0xb6, 0x13, 0x67, 0x9a, 0x08, 0x14, 0xd9, 0xec, 0x77, 0x2f, 0x95, 0xd7,
        0x78, 0xc3, 0x5f, 0xc5, 0xff, 0x16, 0x97, 0xc4, 0x93, 0x71, 0x56, 0x53,
        0xc6, 0xc7, 0x12, 0x14, 0x42, 0x92, 0xc5, 0xad
    };

    /* sha 512 no key, with message */
    ubyte pSha512Mac1[] = {
        0xfe, 0x9b, 0xe5, 0x5c, 0xf1, 0xf9, 0xf2, 0x7d, 0x74, 0x09, 0xca, 0xa8,
        0x51, 0x39, 0x90, 0x0e, 0xf7, 0x95, 0x0a, 0xca, 0x45, 0xaf, 0xfb, 0xa9,
        0xbe, 0x32, 0xec, 0xa4, 0x9b, 0x46, 0xda, 0x48, 0xa5, 0x8b, 0x17, 0x22,
        0x47, 0x6a, 0xe0, 0x11, 0x6b, 0xfa, 0x96, 0x9d, 0x84, 0xc3, 0x08, 0x11,
        0x53, 0x94, 0x41, 0x68, 0x1f, 0x45, 0x66, 0x29, 0x9a, 0x5a, 0x14, 0xe0,
        0xfe, 0x4c, 0xd9, 0x4a
    };

    /* sha 512 with key, no message */
    ubyte pSha512Mac2[] = {
        0x9e, 0xb6, 0x4f, 0x7e, 0xe4, 0xfa, 0xd7, 0xaa, 0xf8, 0x91, 0xe7, 0xd0,
        0x8a, 0x19, 0x6a, 0x2d, 0x74, 0x3a, 0xc7, 0x1f, 0x2a, 0x9d, 0x5d, 0x09,
        0x6d, 0x9f, 0x4c, 0xb7, 0xe9, 0x1e, 0xab, 0xf4, 0x24, 0x8d, 0xad, 0x51,
        0x21, 0x08, 0x02, 0x1e, 0x8d, 0x2e, 0x9e, 0x9e, 0x48, 0x12, 0x58, 0xcf,
        0x77, 0xb3, 0xef, 0x08, 0xad, 0x27, 0x47, 0x27, 0xf7, 0x0b, 0xca, 0xbf,
        0xa4, 0x42, 0x10, 0xb4
    };

    /* sha 512 no key, no message */
    ubyte pSha512Mac3[] = {
        0xb9, 0x36, 0xce, 0xe8, 0x6c, 0x9f, 0x87, 0xaa, 0x5d, 0x3c, 0x6f, 0x2e,
        0x84, 0xcb, 0x5a, 0x42, 0x39, 0xa5, 0xfe, 0x50, 0x48, 0x0a, 0x6e, 0xc6,
        0x6b, 0x70, 0xab, 0x5b, 0x1f, 0x4a, 0xc6, 0x73, 0x0c, 0x6c, 0x51, 0x54,
        0x21, 0xb3, 0x27, 0xec, 0x1d, 0x69, 0x40, 0x2e, 0x53, 0xdf, 0xb4, 0x9a,
        0xd7, 0x38, 0x1e, 0xb0, 0x67, 0xb3, 0x38, 0xfd, 0x7b, 0x0c, 0xb2, 0x22,
        0x47, 0x22, 0x5d, 0x47
    };

    ubyte *pOptData = NULL;
    sbyte4 optDataLen = 0;

    ubyte pResult[MD5_DIGESTSIZE];
    ubyte pResult1[SHA_HASH_RESULT_SIZE];
    ubyte pResult256[SHA256_RESULT_SIZE];
    ubyte pResult512[SHA512_RESULT_SIZE];

    /* initialize to avoid NULL error */
    ubyte *ppText[4];
    ppText[0] = (ubyte*)"a";
    ppText[1] = (ubyte*)"b";
    ppText[2] = (ubyte*)"c";
    ppText[3] = (ubyte*)"d";
    sbyte4 pTextLen[4];
    pTextLen[0] = 1;
    pTextLen[1] = 1;
    pTextLen[2] = 1;
    pTextLen[3] = 1;

    /* create a valid context to use for testing */
    status = HmacCreate(MOC_HASH(gpHwAccelCtx) &pValidCtx, &SHA256Suite);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = HmacKey(MOC_HASH(gpHwAccelCtx) pValidCtx, pKey, keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* null tests begin here */

    /* HmacKey */
    status = HmacKey(MOC_HASH(gpHwAccelCtx) pValidCtx, pKey, 0);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);

    /* HmacUpdate */
    status = HmacUpdate(MOC_HASH(gpHwAccelCtx) pValidCtx, pMsg, 0);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);

    /* HmacQuickEx, HmacQuick calls HmacQuickEx */
    status = HmacQuickEx(MOC_HASH(gpHwAccelCtx) NULL, 0, pMsg, msgLen, NULL, 0, pResult256,
        &SHA256Suite);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac1, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacQuickEx(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, msgLen, NULL, 0, pResult256,
        &SHA256Suite);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac1, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacQuickEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, 0, NULL, 0, pResult256,
        &SHA256Suite);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac2, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacQuickEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, 0, NULL, 0, pResult256,
        &SHA256Suite);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac2, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacQuickEx(MOC_HASH(gpHwAccelCtx) NULL, 0, NULL, 0, NULL, 0, pResult256,
        &SHA256Suite);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac3, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacQuickEx(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, 0, NULL, 0, pResult256,
        &SHA256Suite);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac3, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacDelete(MOC_HASH(gpHwAccelCtx) &pValidCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;


    /* create a valid context to use for testing */
    status = HmacCreate(MOC_HASH(gpHwAccelCtx) &pValidCtx, &SHA256Suite);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = HmacQuickerEx(MOC_HASH(gpHwAccelCtx) NULL, 0, pMsg, msgLen, NULL, 0, pResult256, NULL,
        pValidCtx);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac1, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacQuickerEx(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, msgLen, NULL, 0, pResult256, NULL,
        pValidCtx);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac1, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacDelete(MOC_HASH(gpHwAccelCtx) &pValidCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;


    /* create a valid context to use for testing */
    status = HmacCreate(MOC_HASH(gpHwAccelCtx) &pValidCtx, &SHA256Suite);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = HmacQuickerEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, 0, NULL, 0, pResult256, NULL,
        pValidCtx);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac2, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacQuickerEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, 0, NULL, 0, pResult256, NULL,
        pValidCtx);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac2, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacDelete(MOC_HASH(gpHwAccelCtx) &pValidCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;


    /* create a valid context to use for testing */
    status = HmacCreate(MOC_HASH(gpHwAccelCtx) &pValidCtx, &SHA256Suite);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = HmacQuickerEx(MOC_HASH(gpHwAccelCtx) NULL, 0, NULL, 0, NULL, 0, pResult256, NULL,
        pValidCtx);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac3, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacDelete(MOC_HASH(gpHwAccelCtx) &pValidCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;


    /* create a valid context to use for testing */
    status = HmacCreate(MOC_HASH(gpHwAccelCtx) &pValidCtx, &SHA256Suite);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;


    status = HmacQuickerEx(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, 0, NULL, 0, pResult256, NULL,
        pValidCtx);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac3, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    /* Needed for HmacQuickerInline */
    SHA256_CTX *pShaCtx = NULL;
    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = HmacQuickerInlineEx(MOC_HASH(gpHwAccelCtx) NULL, 0, pMsg, msgLen, NULL, 0, pResult256,
        &SHA256Suite, (BulkCtx)pShaCtx);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac1, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacQuickerInlineEx(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, msgLen, NULL, 0, pResult256,
        &SHA256Suite, (BulkCtx)pShaCtx);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac1, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacQuickerInlineEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, 0, NULL, 0, pResult256,
        &SHA256Suite, (BulkCtx)pShaCtx);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac2, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacQuickerInlineEx(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, 0, NULL, 0, pResult256,
        &SHA256Suite, (BulkCtx)pShaCtx);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac2, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacQuickerInlineEx(MOC_HASH(gpHwAccelCtx) NULL, 0, NULL, 0, NULL, 0, pResult256,
        &SHA256Suite, (BulkCtx)pShaCtx);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac3, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HmacQuickerInlineEx(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, 0, NULL, 0, pResult256,
        &SHA256Suite, (BulkCtx)pShaCtx);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac3, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_MD5(MOC_HASH(gpHwAccelCtx) NULL, 0, pMsg, msgLen, pOptData, optDataLen, pResult);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult, pMd5Mac1, MD5_DIGESTSIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_MD5(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, msgLen, pOptData, optDataLen, pResult);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult, pMd5Mac1, MD5_DIGESTSIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_MD5(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, 0, pOptData, optDataLen, pResult);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult, pMd5Mac2, MD5_DIGESTSIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }


    status = HMAC_MD5(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, 0, pOptData, optDataLen, pResult);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult, pMd5Mac2, MD5_DIGESTSIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_MD5(MOC_HASH(gpHwAccelCtx) NULL, 0, NULL, 0, pOptData, optDataLen, pResult);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult, pMd5Mac3, MD5_DIGESTSIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_MD5(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, 0, pOptData, optDataLen, pResult);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult, pMd5Mac3, MD5_DIGESTSIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA1(MOC_HASH(gpHwAccelCtx) NULL, 0, pMsg, msgLen, pOptData, optDataLen, pResult1);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult1, pSha1Mac1, SHA_HASH_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA1(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, msgLen, pOptData, optDataLen, pResult1);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult1, pSha1Mac1, SHA_HASH_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA1(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, 0, pOptData, optDataLen, pResult1);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult1, pSha1Mac2, SHA_HASH_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA1(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, 0, pOptData, optDataLen, pResult1);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult1, pSha1Mac2, SHA_HASH_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA1(MOC_HASH(gpHwAccelCtx) NULL, 0, NULL, 0, pOptData, optDataLen, pResult1);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult1, pSha1Mac3, SHA_HASH_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA1(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, 0, pOptData, optDataLen, pResult1);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult1, pSha1Mac3, SHA_HASH_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA256(MOC_HASH(gpHwAccelCtx) NULL, 0, pMsg, msgLen, pOptData, optDataLen, pResult256);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac1, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA256(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, msgLen, pOptData, optDataLen, pResult256);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac1, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA256(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, 0, pOptData, optDataLen, pResult256);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac2, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA256(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, 0, pOptData, optDataLen, pResult256);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac2, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA256(MOC_HASH(gpHwAccelCtx) NULL, 0, NULL, 0, pOptData, optDataLen, pResult256);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac3, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA256(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, 0, pOptData, optDataLen, pResult256);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult256, pSha256Mac3, SHA256_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA512(MOC_HASH(gpHwAccelCtx) NULL, 0, pMsg, msgLen, pOptData, optDataLen, pResult512);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult512, pSha512Mac1, SHA512_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA512(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, msgLen, pOptData, optDataLen, pResult512);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult512, pSha512Mac1, SHA512_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA512(MOC_HASH(gpHwAccelCtx) pKey, keyLen, NULL, 0, pOptData, optDataLen, pResult512);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult512, pSha512Mac2, SHA512_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA512(MOC_HASH(gpHwAccelCtx) pKey, keyLen, pMsg, 0, pOptData, optDataLen, pResult512);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult512, pSha512Mac2, SHA512_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA512(MOC_HASH(gpHwAccelCtx) NULL, 0, NULL, 0, pOptData, optDataLen, pResult512);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult512, pSha512Mac3, SHA512_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA512(MOC_HASH(gpHwAccelCtx) pKey, 0, pMsg, 0, pOptData, optDataLen, pResult512);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult512, pSha512Mac3, SHA512_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA1Ex(MOC_HASH(gpHwAccelCtx) NULL, 0, (const ubyte**)ppText, pTextLen, 4, pResult1);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult1, pSha1Mac4, SHA1_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

    status = HMAC_SHA1Ex(MOC_HASH(gpHwAccelCtx) pKey, 0, (const ubyte**)ppText, pTextLen, 4, pResult1);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK == status)
    {
        DIGI_MEMCMP(pResult1, pSha1Mac4, SHA1_RESULT_SIZE, &cmpRes);
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }

exit:

    if (NULL != pValidCtx)
    {
        HmacDelete(MOC_HASH(gpHwAccelCtx) &pValidCtx);
    }
    if (NULL != pShaCtx)
    {
        SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
    }

    return errorCount;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
/* known answer test by comparing TAP (Hw) results with Sw results */
static int tapKAT(ubyte4 keySize, TAP_HASH_ALG hashAlg)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    sbyte4 retLen = 0;
    int i;

    HMAC_CTX *pCtxHw = NULL;
    HMAC_CTX *pCtxSw = NULL;

    SymmetricKey *pSymWrapper = NULL;

    ubyte pData[90] = {0};
    ubyte pMacHw[64] = {0}; /* big enough for any sha */
    ubyte pMacSw[64] = {0};
    ubyte4 macLen = 20;  /* sha1 by default */

    const BulkHashAlgo *pHashAlgo = &SHA1Suite; /* sha1 by default */

    MSymTapKeyGenArgs tapArgs = {0};
    void *pTapArgs = (void *) &tapArgs;

    TAP_KeyInfo keyInfo = {0};
    MSymTapCreateArgs createArgs = {0};
    ubyte pKey[4096] = {0}; /* big enough for all tests */

    tapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    tapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    tapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    tapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
    tapArgs.hashAlg = hashAlg;

    /* make a pseduo random looking plaintext of 8 blocks */
    for (i = 0; i < sizeof(pData); ++i)
    {
        pData[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    for (i = 0; i < keySize; ++i)
    {
        pKey[i] = (ubyte) (i+1);
    }

    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
    keyInfo.algKeyInfo.hmacInfo.hashAlg = hashAlg;
    createArgs.pKeyInfo = &keyInfo;
    createArgs.pKeyData = (ubyte *)pKey;
    createArgs.keyDataLen = keySize;
    createArgs.token = FALSE;

    switch (hashAlg)
    {
        /*  SHA1 as default is already set */
        case TAP_HASH_ALG_SHA224:
            pHashAlgo = &SHA224Suite;
            macLen = 28;
            break;

        case TAP_HASH_ALG_SHA256:
            pHashAlgo = &SHA256Suite;
            macLen = 32;
            break;

        case TAP_HASH_ALG_SHA384:
            pHashAlgo = &SHA384Suite;
            macLen = 48;
            break;

        case TAP_HASH_ALG_SHA512:
            pHashAlgo = &SHA512Suite;
            macLen = 64;
            break;
    }

    //status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, keySize * 8, pTapArgs);
    status = CRYPTO_INTERFACE_TAP_SymImportExternalKey(&pSymWrapper, pTapArgs, (void *)&createArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_getHmacCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtxHw);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacCreate (MOC_HASH(gpHwAccelCtx) &pCtxSw, pHashAlgo);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacKey (MOC_HASH(gpHwAccelCtx) pCtxSw, pKey, keySize);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtxHw, pData, 5);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtxHw, pData + 5, 16);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtxHw, pData + 21, 42);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtxHw, pData + 63, 27);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacFinal(MOC_SYM(gpHwAccelCtx) pCtxHw, pMacHw);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtxSw, pData, 27);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtxSw, pData + 27, 42);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtxSw, pData + 69, 16);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtxSw, pData + 85, 5);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacFinal(MOC_SYM(gpHwAccelCtx) pCtxSw, pMacSw);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pMacSw, pMacHw, macLen, &compare);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

exit:

    status = CRYPTO_INTERFACE_HmacDelete(MOC_SYM(gpHwAccelCtx) &pCtxHw);
    retVal += UNITTEST_STATUS(keySize, status);

    status = CRYPTO_INTERFACE_HmacDelete(MOC_SYM(gpHwAccelCtx) &pCtxSw);
    retVal += UNITTEST_STATUS(keySize, status);

    if (NULL != pSymWrapper)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }

    return retVal;
}
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
/* known answer test by comparing TAP (Hw) results with Sw results */
static int tapKATExtended(ubyte4 keySize, TAP_HASH_ALG hashAlg, byteBoolean testKeyCreds)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    sbyte4 retLen = 0;
    int i;

    HMAC_CTX *pCtx = NULL;

    SymmetricKey *pSymWrapper = NULL;

    ubyte pData[90] = {0};
    ubyte pMac[64] = {0}; /* big enough for any sha */
    ubyte pMac2[64] = {0};
    ubyte4 macLen = 20;  /* sha1 by default */

    const BulkHashAlgo *pHashAlgo = &SHA1Suite; /* sha1 by default */

    MSymTapKeyGenArgs tapArgs = {0};
    void *pTapArgs = (void *) &tapArgs;

    TAP_KeyInfo keyInfo = {0};
    MSymTapCreateArgs createArgs = {0};
    ubyte pKey[4096] = {0}; /* big enough for all tests */
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;

    TAP_CredentialList *pCredList = NULL;
    TAP_Credential *pCred = NULL;
    ubyte pPassword[10] = {109,121,32,112,97,115,115,111,114,100}; /* "my password" */
    ubyte4 passwordLen = 10;

    if (testKeyCreds)
    {
        status = DIGI_CALLOC((void **) &pCredList, 1, sizeof(TAP_CredentialList));
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        /* allocate the credential list */
        status = DIGI_CALLOC((void **) &pCredList->pCredentialList, 1, sizeof(TAP_Credential));
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        pCredList->numCredentials = 1;

        pCred = pCredList->pCredentialList;
        
        status = DIGI_MALLOC((void **) &pCred->credentialData.pBuffer, passwordLen);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        pCred->credentialData.bufferLen = passwordLen;
        
        status = DIGI_MEMCPY(pCred->credentialData.pBuffer, pPassword, passwordLen);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        pCred->credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
        pCred->credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
        pCred->credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
    }


    tapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    tapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    tapArgs.pKeyCredentials = pCredList; /* TAP_EXAMPLE returns NULL anyway */
    tapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
    tapArgs.hashAlg = hashAlg;

    /* make a pseduo random looking plaintext of 8 blocks */
    for (i = 0; i < sizeof(pData); ++i)
    {
        pData[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    for (i = 0; i < keySize; ++i)
    {
        pKey[i] = (ubyte) (i+1);
    }

    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
    keyInfo.algKeyInfo.hmacInfo.hashAlg = hashAlg;
    keyInfo.keyUsage = TAP_KEY_USAGE_SIGNING;
    createArgs.pKeyInfo = &keyInfo;
    createArgs.pKeyData = (ubyte *)pKey;
    createArgs.keyDataLen = keySize;
    createArgs.token = TRUE;

    switch (hashAlg)
    {
        /*  SHA1 as default is already set */
        case TAP_HASH_ALG_SHA224:
            pHashAlgo = &SHA224Suite;
            macLen = 28;
            break;

        case TAP_HASH_ALG_SHA256:
            pHashAlgo = &SHA256Suite;
            macLen = 32;
            break;

        case TAP_HASH_ALG_SHA384:
            pHashAlgo = &SHA384Suite;
            macLen = 48;
            break;

        case TAP_HASH_ALG_SHA512:
            pHashAlgo = &SHA512Suite;
            macLen = 64;
            break;
    }

    status = CRYPTO_INTERFACE_HmacQuick (pKey, keySize, pData, 90, pMac, &SHA256Suite);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    //status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, keySize * 8, pTapArgs);
    status = CRYPTO_INTERFACE_TAP_SymImportExternalKey(&pSymWrapper, pTapArgs, (void *)&createArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testKeyCreds)
    {
        status = CRYPTO_INTERFACE_TAP_SymKeyLoadWithCreds(pSymWrapper, pPassword, passwordLen);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
           goto exit;
    }

    /* Transfer control of the SymmetricKey underlying data into a usable HMAC context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getHmacCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacSingle(MOC_SYM(gpHwAccelCtx) pCtx, pData, 90, pMac2);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pMac, pMac2, macLen, &compare);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

    /* reset and mac again */
    status = CRYPTO_INTERFACE_HmacReset(MOC_SYM(gpHwAccelCtx) pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* no way at the moment to add creds to an HMAC context */
    if (!testKeyCreds)
    {
        status = CRYPTO_INTERFACE_HmacSingle(MOC_SYM(gpHwAccelCtx) pCtx, pData, 90, pMac2);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCMP(pMac, pMac2, macLen, &compare);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(keySize, compare, 0);
    }

    /* reset pMac2 and delete the context and key so we can re-use them */
    status = DIGI_MEMSET(pMac2, 0x00, macLen);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacDelete(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* Now perform the mac again with the deserialized key */
    if(testKeyCreds)
    {
        /* password should not be needed in the tapArgs */
        tapArgs.pKeyCredentials = NULL; 

        status = CRYPTO_INTERFACE_TAP_deserializeSymKeyWithCreds(&pSymWrapper, pSerKey, serLen, pPassword, passwordLen, pTapArgs);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, pTapArgs);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_TAP_getHmacCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacSingle(MOC_SYM(gpHwAccelCtx) pCtx, pData, 90, pMac2);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pMac, pMac2, macLen, &compare);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

exit:

    status = CRYPTO_INTERFACE_HmacDelete(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);

    if (NULL != pSymWrapper)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_FREE((void **) &pSerKey);
    }

    if(testKeyCreds && NULL != pCredList)
    {   
        (void) TAP_UTILS_clearCredentialList(pCredList);    
        /* Free outer shell */
        (void) DIGI_FREE((void** ) &pCredList);
    }

    return retVal;
}

static int tapTestEx(ubyte4 keySize, TAP_HASH_ALG hashAlg, intBoolean testDeferredUnload)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    HMAC_CTX *pCtx = NULL;
    HMAC_CTX *pCtx2 = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    /* Pointers for a special free on ctx1 */
    MocSymCtx pMocSymCtx = NULL;
    MTapKeyData *pTapData = NULL;

    ubyte pData[90] = {0};
    ubyte pMac[64] = {0}; /* big enough for any sha */
    ubyte pMac2[64] = {0};
    ubyte4 macLen = 20;  /* sha1 by default */

    MSymTapKeyGenArgs tapArgs = {0};
    void *pTapArgs = (void *) &tapArgs;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    tapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    tapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    tapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    tapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
    tapArgs.hashAlg = hashAlg;

    switch (hashAlg)
    {
        /* macLen is 20 for SHA1 by default */
        case TAP_HASH_ALG_SHA224:
            macLen = 28;
            break;

        case TAP_HASH_ALG_SHA256:
            macLen = 32;
            break;

        case TAP_HASH_ALG_SHA384:
            macLen = 48;
            break;

        case TAP_HASH_ALG_SHA512:
            macLen = 64;
            break;
    }

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pData); ++i)
    {
        pData[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, keySize * 8, pTapArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable HMAC context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getHmacCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx, pData, 5);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx, pData + 5, 16);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx, pData + 21, 42);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx, pData + 63, 27);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacFinal(MOC_SYM(gpHwAccelCtx) pCtx, pMac);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* reset and mac again */
    status = CRYPTO_INTERFACE_HmacReset(MOC_SYM(gpHwAccelCtx) pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx, pData, 90);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacFinal(MOC_SYM(gpHwAccelCtx) pCtx, pMac2);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pMac, pMac2, macLen, &compare);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

    /* reset pMac2 and delete the context and key so we can re-use them */
    status = DIGI_MEMSET(pMac2, 0x00, macLen);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* reset */
    status = CRYPTO_INTERFACE_HmacReset(MOC_SYM(gpHwAccelCtx) pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* Now perform the mac again with the deserialized key */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, pTapArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_getHmacCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx2);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_HmacDeferKeyUnload(pCtx2, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx2, pData, 89);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx2, pData + 89, 1);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacFinal(MOC_SYM(gpHwAccelCtx) pCtx2, pMac2);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_HmacGetKeyInfo (pCtx2, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = DIGI_MEMCMP(pMac, pMac2, macLen, &compare);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

exit:

    status = CRYPTO_INTERFACE_HmacDelete(MOC_SYM(gpHwAccelCtx) &pCtx2);
    retVal += UNITTEST_STATUS(keySize, status);

    if (NULL != pCtx)
    {
        pMocSymCtx = pCtx->pMocSymCtx;
        if (NULL != pMocSymCtx)
        {
            pTapData = (MTapKeyData *) pMocSymCtx->pLocalData;
            if (NULL != pTapData)
            {
                if (NULL != pTapData->pKey)
                {
#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
                    TAP_freeKeyEx(&(pTapData->pKey));
#else
                    TAP_freeKey(&(pTapData->pKey));
#endif
                }

                DIGI_FREE((void **)&pTapData);
            }

            DIGI_FREE((void **)&pMocSymCtx);
        }

        DIGI_FREE((void **)&pCtx);
    }

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(1), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(1), tokenHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (NULL != pSymWrapper)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_FREE((void **) &pSerKey);
    }

    return retVal;
}

static int tapTest(ubyte4 keySize, TAP_HASH_ALG hashAlg, intBoolean testDeferredUnload)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    HMAC_CTX *pCtx = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    ubyte pData[90] = {0};
    ubyte pMac[64] = {0}; /* big enough for any sha */
    ubyte pMac2[64] = {0};
    ubyte4 macLen = 20;  /* sha1 by default */

    MSymTapKeyGenArgs tapArgs = {0};
    void *pTapArgs = (void *) &tapArgs;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    tapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    tapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    tapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    tapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
    tapArgs.hashAlg = hashAlg;

    switch (hashAlg)
    {
        /* macLen is 20 for SHA1 by default */
        case TAP_HASH_ALG_SHA224:
            macLen = 28;
            break;

        case TAP_HASH_ALG_SHA256:
            macLen = 32;
            break;

        case TAP_HASH_ALG_SHA384:
            macLen = 48;
            break;

        case TAP_HASH_ALG_SHA512:
            macLen = 64;
            break;
    }

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pData); ++i)
    {
        pData[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, keySize * 8, pTapArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable HMAC context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getHmacCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx, pData, 5);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx, pData + 5, 16);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx, pData + 21, 42);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx, pData + 63, 27);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacFinal(MOC_SYM(gpHwAccelCtx) pCtx, pMac);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* reset and mac again */
    status = CRYPTO_INTERFACE_HmacReset(MOC_SYM(gpHwAccelCtx) pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx, pData, 90);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacFinal(MOC_SYM(gpHwAccelCtx) pCtx, pMac2);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pMac, pMac2, macLen, &compare);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

    /* reset pMac2 and delete the context and key so we can re-use them */
    status = DIGI_MEMSET(pMac2, 0x00, macLen);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacDelete(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* Now perform the mac again with the deserialized key */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, pTapArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_getHmacCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_HmacDeferKeyUnload(pCtx, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx, pData, 89);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacUpdate(MOC_SYM(gpHwAccelCtx) pCtx, pData + 89, 1);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacFinal(MOC_SYM(gpHwAccelCtx) pCtx, pMac2);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_HmacGetKeyInfo (pCtx, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = DIGI_MEMCMP(pMac, pMac2, macLen, &compare);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

exit:

    status = CRYPTO_INTERFACE_HmacDelete(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(1), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(1), tokenHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (NULL != pSymWrapper)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_FREE((void **) &pSerKey);
    }

    return retVal;
}


static int tapTestSingle(ubyte4 keySize, TAP_HASH_ALG hashAlg, intBoolean testDeferredUnload)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    HMAC_CTX *pCtx = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    ubyte pData[90] = {0};
    ubyte pMac[64] = {0}; /* big enough for any sha */
    ubyte pMac2[64] = {0};
    ubyte4 macLen = 20;  /* sha1 by default */

    MSymTapKeyGenArgs tapArgs = {0};
    void *pTapArgs = (void *) &tapArgs;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    tapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    tapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    tapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    tapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
    tapArgs.hashAlg = hashAlg;

    switch (hashAlg)
    {
        /* macLen is 20 for SHA1 by default */
        case TAP_HASH_ALG_SHA224:
            macLen = 28;
            break;

        case TAP_HASH_ALG_SHA256:
            macLen = 32;
            break;

        case TAP_HASH_ALG_SHA384:
            macLen = 48;
            break;

        case TAP_HASH_ALG_SHA512:
            macLen = 64;
            break;
    }

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pData); ++i)
    {
        pData[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, keySize * 8, pTapArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable HMAC context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getHmacCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacSingle(MOC_SYM(gpHwAccelCtx) pCtx, pData, 90, pMac);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* reset and mac again */
    status = CRYPTO_INTERFACE_HmacReset(MOC_SYM(gpHwAccelCtx) pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacSingle(MOC_SYM(gpHwAccelCtx) pCtx, pData, 90, pMac2);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pMac, pMac2, macLen, &compare);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

    /* reset pMac2 and delete the context and key so we can re-use them */
    status = DIGI_MEMSET(pMac2, 0x00, macLen);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_HmacDelete(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* Now perform the mac again with the deserialized key */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, pTapArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_getHmacCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_HmacDeferKeyUnload(pCtx, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_HmacSingle(MOC_SYM(gpHwAccelCtx) pCtx, pData, 90, pMac2);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_HmacGetKeyInfo (pCtx, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = DIGI_MEMCMP(pMac, pMac2, macLen, &compare);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

exit:

    status = CRYPTO_INTERFACE_HmacDelete(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(1), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(1), tokenHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (NULL != pSymWrapper)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_FREE((void **) &pSerKey);
    }

    return retVal;
}
#endif /* __ENABLE_DIGICERT_TAP__ */

/*----------------------------------------------------------------------------*/

int crypto_interface_hmac_test_init()
{

    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;
    ubyte4 modNum = 1;

    InitMocanaSetupInfo setupInfo = { 0 };
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) &&     \
        defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC__))
    errorCount = (errorCount + testCryptoInterface());
#endif

    errorCount = (errorCount + negativeTests());
    errorCount = (errorCount + validEdgeCases());
    errorCount = (errorCount + runMd5Tests());
    errorCount = (errorCount + runMd5TestsQuick());

    errorCount = (errorCount + runHmacSha1Tests());
    errorCount = (errorCount + testHmacSha1Quick());
    errorCount = (errorCount + testHmacSha1Ex());
    errorCount = (errorCount + runHmacSha256Tests());
    errorCount = (errorCount + runHmacSha512Tests());

    /* uses update + final, and reset, and clone */
    errorCount = (errorCount + runHmacTests());
    /* Quick */
    errorCount = (errorCount + runHmacTests2());
    /* QuickEx */
    errorCount = (errorCount + runHmacTests3());
    /* Quicker */
    errorCount = (errorCount + runHmacTests4());
    /* QuickerEx */
    errorCount = (errorCount + runHmacTests5());
    /* QuickerInline */
    errorCount = (errorCount + runHmacTests6());
    /* QuickerInlineEx */
    errorCount = (errorCount + runHmacTests7());
    /* QuickerEx with NULL/0 key */
    errorCount = (errorCount + runHmacTests8());

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)

    status = TAP_EXAMPLE_init(&modNum, 1);
    if (OK != status)
    {
        errorCount += 1;
        goto exit;
    }

#ifndef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
    errorCount += tapKATExtended(32, TAP_HASH_ALG_SHA256, TRUE);
    errorCount += tapKATExtended(32, TAP_HASH_ALG_SHA256, FALSE);

/*    errorCount += tapKATExtended(48, TAP_HASH_ALG_SHA384);
    errorCount += tapKATExtended(64, TAP_HASH_ALG_SHA512); */
    errorCount += tapTestSingle(32, TAP_HASH_ALG_SHA256, FALSE);

/*    errorCount += tapTestSingle(48, TAP_HASH_ALG_SHA384, FALSE);
    errorCount += tapTestSingle(64, TAP_HASH_ALG_SHA512, FALSE); */
    errorCount += tapTestSingle(32, TAP_HASH_ALG_SHA256, TRUE);
/*    errorCount += tapTestSingle(48, TAP_HASH_ALG_SHA384, TRUE);
    errorCount += tapTestSingle(64, TAP_HASH_ALG_SHA512, TRUE);*/
#endif

#ifndef __ENABLE_DIGICERT_TPM2__
#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
    errorCount = (errorCount + tapTestEx(20, TAP_HASH_ALG_SHA1, FALSE));
    errorCount = (errorCount + tapTestEx(32, TAP_HASH_ALG_SHA1, FALSE));
    /* smaller keys than the hashLen do not seem to be supported */
    /* errorCount = (errorCount + tapTest(13, TAP_HASH_ALG_SHA1, FALSE)); */

    errorCount = (errorCount + tapTestEx(32, TAP_HASH_ALG_SHA256, FALSE));
    errorCount = (errorCount + tapTestEx(48, TAP_HASH_ALG_SHA256, FALSE));
    /* errorCount = (errorCount + tapTest(20, TAP_HASH_ALG_SHA256, FALSE)); */

    errorCount = (errorCount + tapTestEx(28, TAP_HASH_ALG_SHA224, FALSE));
    errorCount = (errorCount + tapTestEx(64, TAP_HASH_ALG_SHA224, FALSE));

    errorCount = (errorCount + tapTestEx(48, TAP_HASH_ALG_SHA384, FALSE));

    errorCount = (errorCount + tapTestEx(64, TAP_HASH_ALG_SHA512, FALSE));

    errorCount = (errorCount + tapTestEx(20, TAP_HASH_ALG_SHA1, TRUE));

    errorCount = (errorCount + tapTestEx(32, TAP_HASH_ALG_SHA256, TRUE));

    errorCount += tapKAT(20, TAP_HASH_ALG_SHA1);
    errorCount += tapKAT(32, TAP_HASH_ALG_SHA224); /* 32 on purpose */
    errorCount += tapKAT(32, TAP_HASH_ALG_SHA256);
    errorCount += tapKAT(48, TAP_HASH_ALG_SHA384);
    errorCount += tapKAT(64, TAP_HASH_ALG_SHA512);

    /* oversized keys */
    errorCount += tapKAT(1024, TAP_HASH_ALG_SHA224);
    errorCount += tapKAT(256, TAP_HASH_ALG_SHA256);
    errorCount += tapKAT(2048, TAP_HASH_ALG_SHA384);
#else
    errorCount = (errorCount + tapTest(20, TAP_HASH_ALG_SHA1, FALSE));
    errorCount = (errorCount + tapTest(32, TAP_HASH_ALG_SHA1, FALSE));
    /* smaller keys than the hashLen do not seem to be supported */
    /* errorCount = (errorCount + tapTest(13, TAP_HASH_ALG_SHA1, FALSE)); */

    errorCount = (errorCount + tapTest(32, TAP_HASH_ALG_SHA256, FALSE));
    errorCount = (errorCount + tapTest(48, TAP_HASH_ALG_SHA256, FALSE));
    /* errorCount = (errorCount + tapTest(20, TAP_HASH_ALG_SHA256, FALSE)); */

    errorCount = (errorCount + tapTest(28, TAP_HASH_ALG_SHA224, FALSE));
    errorCount = (errorCount + tapTest(64, TAP_HASH_ALG_SHA224, FALSE));
    errorCount = (errorCount + tapTest(48, TAP_HASH_ALG_SHA384, FALSE));
    errorCount = (errorCount + tapTest(64, TAP_HASH_ALG_SHA512, FALSE));
    errorCount = (errorCount + tapTest(20, TAP_HASH_ALG_SHA1, TRUE));
    errorCount = (errorCount + tapTest(32, TAP_HASH_ALG_SHA256, TRUE));

    errorCount = (errorCount + tapTestSingle(20, TAP_HASH_ALG_SHA1, FALSE));
    errorCount = (errorCount + tapTestSingle(32, TAP_HASH_ALG_SHA1, FALSE));

    errorCount = (errorCount + tapTestSingle(32, TAP_HASH_ALG_SHA256, FALSE));
    errorCount = (errorCount + tapTestSingle(48, TAP_HASH_ALG_SHA256, FALSE));

    errorCount = (errorCount + tapTestSingle(28, TAP_HASH_ALG_SHA224, FALSE));
    errorCount = (errorCount + tapTestSingle(64, TAP_HASH_ALG_SHA224, FALSE));
    errorCount = (errorCount + tapTestSingle(48, TAP_HASH_ALG_SHA384, FALSE));
    errorCount = (errorCount + tapTestSingle(64, TAP_HASH_ALG_SHA512, FALSE));
    errorCount = (errorCount + tapTestSingle(20, TAP_HASH_ALG_SHA1, TRUE));
    errorCount = (errorCount + tapTestSingle(32, TAP_HASH_ALG_SHA256, TRUE));

    errorCount += tapKAT(20, TAP_HASH_ALG_SHA1);
    errorCount += tapKAT(32, TAP_HASH_ALG_SHA224); /* 32 on purpose */
    errorCount += tapKAT(32, TAP_HASH_ALG_SHA256);
    errorCount += tapKAT(48, TAP_HASH_ALG_SHA384);
    errorCount += tapKAT(64, TAP_HASH_ALG_SHA512);

    /* oversized keys */
    errorCount += tapKAT(4096, TAP_HASH_ALG_SHA1);
    errorCount += tapKAT(1024, TAP_HASH_ALG_SHA224);
    errorCount += tapKAT(256, TAP_HASH_ALG_SHA256);
    errorCount += tapKAT(2048, TAP_HASH_ALG_SHA384);
    errorCount += tapKAT(4096, TAP_HASH_ALG_SHA512);
#endif
#endif

#endif /* __ENABLE_DIGICERT_TAP__ */
exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
    TAP_EXAMPLE_clean();
#endif

    DIGICERT_free(&gpMocCtx);
    return errorCount;
}
