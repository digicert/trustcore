/*
 * crypto_interface_tdes_test.c
 *
 * test file for TDES
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
#include "../../crypto/mocasym.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_tdes.h"

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
#include "crypto_interface_tap_example.h"
#include "../../crypto/mocsymalgs/tap/symtap.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_sym_tap.h"
#include "../../crypto_interface/crypto_interface_tdes_tap.h"
#endif
#endif

/*
 * Plain text and cipher text buffers are
 * the size of the largest test passed
 */
typedef struct kvt_tdescbc{
    ubyte   pKey[24];
    ubyte4  keyLen;
    ubyte   pIv[8];
    ubyte4  ivLen;
    ubyte   pPlainText[200];
    ubyte4  plainTextLen;
    ubyte   pCipherText[200];
    ubyte4  cipherTextLen;
} kvt_tdescbc;


/* prototype for runAllKnownTests */
static MSTATUS runKnownTest(kvt_tdescbc test, int updateMode);
static MSTATUS runKnownTestReset3DES(kvt_tdescbc test);
static int test3DESClone(kvt_tdescbc test);

/*----------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) &&     \
        defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_TDES__))
static int testCryptoInterface()
{
    MSTATUS status = OK;

    DES3Ctx *pCtx = NULL;
    MocSymCtx pMocCtx = NULL;

    ubyte pKey[24] = { 0 };
    ubyte4 keyLen = 24;


#ifdef __ENABLE_DIGICERT_TDES_MBED__

    /* create context for encryption step, TRUE for encryption */
    pCtx = Create3DESCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, TRUE);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

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
        Delete3DESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pCtx);

    if(OK != status)
        return 1;
    return 0;
}
#endif


/*----------------------------------------------------------------------------*/

static int runAllKnownTests()
{
    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;

    ubyte pKey[] = {
        0x32, 0x3b, 0xf2, 0x4f, 0xe0, 0xad, 0x70, 0x94,
        0x3e, 0x70, 0xbf, 0x1c, 0x5d, 0xf4, 0xd5, 0x31,
        0xdc, 0x0d, 0x92, 0x6e, 0x83, 0x80, 0x4c, 0x4a
    };
    ubyte4 keyLen = 24;

    ubyte pIv[] = {
        0x29, 0x85, 0x58, 0xd9, 0x55, 0x17, 0xa0, 0x45
    };
    ubyte4 ivLen = 8;

    ubyte pPlainText[] = {
        0x26, 0xe4, 0x4a, 0xa7, 0x8f, 0xcc, 0x69, 0x06, 0x87, 0xe7, 0x4c, 0xfd,
        0xfc, 0xbd, 0x6e, 0xf3, 0x46, 0x96, 0x01, 0x1e, 0x5a, 0xe1, 0xcb, 0xfe,
        0x40, 0xd6, 0x33, 0x2b, 0xc7, 0x5b, 0x9c, 0x51, 0x77, 0x24, 0xf1, 0x79,
        0xc7, 0x1f, 0x81, 0x8a, 0x90, 0x0f, 0x0e, 0x0f, 0xc2, 0x76, 0x20, 0x3a
    };
    ubyte4 plainTextLen = 48;

    ubyte pExpectedCipherText[] = {
        0xd0, 0x9b, 0x95, 0x68, 0x87, 0x77, 0x69, 0x78, 0x0f, 0xda, 0x99, 0x11,
        0xc2, 0x9b, 0x30, 0x3b, 0x27, 0xe1, 0x5b, 0x5f, 0x29, 0xb2, 0xdd, 0xf8,
        0x9c, 0x3b, 0x7e, 0xdc, 0xc0, 0x4d, 0xee, 0x78, 0xb7, 0x51, 0xd4, 0x59,
        0xa5, 0x0d, 0xf3, 0xae, 0x57, 0xbf, 0xfd, 0x4b, 0x4c, 0xa4, 0x1f, 0xc4
    };
    ubyte4 expectedCipherTextLen = 48;

    /* struct used to pass vectors to runKnownTest() */
    kvt_tdescbc test;


    DIGI_MEMCPY(test.pKey, pKey, keyLen);
    test.keyLen = keyLen;

    DIGI_MEMCPY(test.pIv, pIv, ivLen);
    test.ivLen = ivLen;

    DIGI_MEMCPY(test.pPlainText, pPlainText, plainTextLen);
    test.plainTextLen = plainTextLen;

    DIGI_MEMCPY(test.pCipherText, pExpectedCipherText, expectedCipherTextLen);
    test.cipherTextLen = expectedCipherTextLen;

    /* run test, if failed, increment error count by 1 */
    status = runKnownTest(test, 0);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        errorCount = (errorCount + 1);

    /* run again with update mode 1 */
    status = runKnownTest(test, 1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        errorCount = (errorCount + 1);

    /* test cloning a context */
    status = test3DESClone(test);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        errorCount = (errorCount + 1);

    /* memset all values to prepare for next test */
    DIGI_MEMSET(test.pKey, 0, 24);
    DIGI_MEMSET(test.pIv, 0, 8);
    DIGI_MEMSET(test.pPlainText, 0, 200);
    DIGI_MEMSET(test.pCipherText, 0, 200);

    ubyte pKey2[24] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

    ubyte4 keyLen2 = 24;

    ubyte pIv2[8] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};

    ubyte4 ivLen2 = 8;

    ubyte pPlainText2[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ubyte4 plainTextLen2 = 8;

    ubyte pExpectedCipherText2[8] = {0xf7, 0x55, 0x2a, 0xb6, 0xcb, 0x21, 0xe2,
        0xbc};
    ubyte4 expectedCipherTextLen2 = 8;

    /* copy values for next test */
    DIGI_MEMCPY(test.pKey, pKey2, keyLen2);
    test.keyLen = keyLen;
    DIGI_MEMCPY(test.pIv, pIv2, ivLen2);
    test.ivLen = ivLen2;

    DIGI_MEMCPY(test.pPlainText, pPlainText2, plainTextLen2);
    test.plainTextLen = plainTextLen2;

    DIGI_MEMCPY(test.pCipherText, pExpectedCipherText2, expectedCipherTextLen2);
    test.cipherTextLen = expectedCipherTextLen2;

    /* run test */
    status = runKnownTest(test, 0);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        errorCount = (errorCount + 1);

    DIGI_MEMSET(test.pKey, 0, 24);
    DIGI_MEMSET(test.pIv, 0, 8);
    DIGI_MEMSET(test.pPlainText, 0, 200);
    DIGI_MEMSET(test.pCipherText, 0, 200);

    return errorCount;
}

/*----------------------------------------------------------------------------*/

static int test3DESClone(kvt_tdescbc test)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = 667;

    /* all iv values are 8 bytes */
    ubyte pIvCopy[8] = { 0 };
    ubyte ivCopyLen = 8;

    /* buffer used for operations */
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;

    DES3Ctx *pEncryptCtx = NULL;
    DES3Ctx *pCloneCtx = NULL;

    /* allocate memory for buffer used in operations. */
    DIGI_MALLOC((void**)&pData, test.plainTextLen);
    dataLen = test.plainTextLen;

    /* make copy of of plaintext to pass to Do3DES,
     * operations happen in place, need copy of plain
     * text so original isn't altered */
    DIGI_MEMCPY(pData, test.pPlainText, dataLen);

    /* iv buffer is used for intermediary values, so
     * we need to use a copy of original so it isn't
     * altered. */
    DIGI_MEMCPY(pIvCopy, test.pIv, ivCopyLen);

    /* create context for encryption step, TRUE for encryption */
    pEncryptCtx = Create3DESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
    if (NULL == pEncryptCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Process the first 8 bytes of data */
    status = Do3DES(MOC_SYM(gpHwAccelCtx) pEncryptCtx, pData, 8, TRUE, pIvCopy);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Clone the context */
    status = Clone3DESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx)pEncryptCtx, (BulkCtx *)&pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Process the rest of the data with the cloned contxt */
    status = Do3DES(MOC_SYM(gpHwAccelCtx) pEncryptCtx, pData + 8, dataLen - 8, TRUE, pIvCopy);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare cipher text in pData with expected cipher text */
    status = DIGI_MEMCMP(pData, test.pCipherText, test.cipherTextLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* test result of comparison */
    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    if (NULL != pEncryptCtx)
        Delete3DESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *) &pEncryptCtx);

    if (NULL != pCloneCtx)
        Delete3DESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *) &pCloneCtx);

    if(NULL != pData)
        DIGI_FREE((void**)&pData);

    return status;

}

/*----------------------------------------------------------------------------*/

static int runAllKnownTestsReset3DES()
{
    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;

    ubyte pKey[] = {
        0x32, 0x3b, 0xf2, 0x4f, 0xe0, 0xad, 0x70, 0x94,
        0x3e, 0x70, 0xbf, 0x1c, 0x5d, 0xf4, 0xd5, 0x31,
        0xdc, 0x0d, 0x92, 0x6e, 0x83, 0x80, 0x4c, 0x4a
    };
    ubyte4 keyLen = 24;

    ubyte pIv[] = {
        0x29, 0x85, 0x58, 0xd9, 0x55, 0x17, 0xa0, 0x45
    };
    ubyte4 ivLen = 8;


    ubyte pPlainText[] = {
        0x26, 0xe4, 0x4a, 0xa7, 0x8f, 0xcc, 0x69, 0x06, 0x87, 0xe7, 0x4c, 0xfd,
        0xfc, 0xbd, 0x6e, 0xf3, 0x46, 0x96, 0x01, 0x1e, 0x5a, 0xe1, 0xcb, 0xfe,
        0x40, 0xd6, 0x33, 0x2b, 0xc7, 0x5b, 0x9c, 0x51, 0x77, 0x24, 0xf1, 0x79,
        0xc7, 0x1f, 0x81, 0x8a, 0x90, 0x0f, 0x0e, 0x0f, 0xc2, 0x76, 0x20, 0x3a
    };
    ubyte4 plainTextLen = 48;

    ubyte pExpectedCipherText[] = {
        0xd0, 0x9b, 0x95, 0x68, 0x87, 0x77, 0x69, 0x78, 0x0f, 0xda, 0x99, 0x11,
        0xc2, 0x9b, 0x30, 0x3b, 0x27, 0xe1, 0x5b, 0x5f, 0x29, 0xb2, 0xdd, 0xf8,
        0x9c, 0x3b, 0x7e, 0xdc, 0xc0, 0x4d, 0xee, 0x78, 0xb7, 0x51, 0xd4, 0x59,
        0xa5, 0x0d, 0xf3, 0xae, 0x57, 0xbf, 0xfd, 0x4b, 0x4c, 0xa4, 0x1f, 0xc4
    };
    ubyte4 expectedCipherTextLen = 48;

    /* struct used to pass vectors to runKnownTest() */
    kvt_tdescbc test;


    DIGI_MEMCPY(test.pKey, pKey, keyLen);
    test.keyLen = keyLen;

    DIGI_MEMCPY(test.pIv, pIv, ivLen);
    test.ivLen = ivLen;

    DIGI_MEMCPY(test.pPlainText, pPlainText, plainTextLen);
    test.plainTextLen = plainTextLen;

    DIGI_MEMCPY(test.pCipherText, pExpectedCipherText, expectedCipherTextLen);
    test.cipherTextLen = expectedCipherTextLen;

    /* run test, if failed, increment error count by 1 */
    status = runKnownTest(test, 0);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        errorCount = (errorCount + 1);

    /* run again with update mode 1 */
    status = runKnownTest(test, 1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        errorCount = (errorCount + 1);

    /* memset all values to prepare for next test */
    DIGI_MEMSET(test.pKey, 0, 24);
    DIGI_MEMSET(test.pIv, 0, 8);
    DIGI_MEMSET(test.pPlainText, 0, 200);
    DIGI_MEMSET(test.pCipherText, 0, 200);

    ubyte pKey2[24] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

    ubyte4 keyLen2 = 24;

    ubyte pIv2[8] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};

    ubyte4 ivLen2 = 8;

    ubyte pPlainText2[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ubyte4 plainTextLen2 = 8;

    ubyte pExpectedCipherText2[8] = {0xf7, 0x55, 0x2a, 0xb6, 0xcb, 0x21, 0xe2,
        0xbc};
    ubyte4 expectedCipherTextLen2 = 8;

    /* copy values for next test */
    DIGI_MEMCPY(test.pKey, pKey2, keyLen2);
    test.keyLen = keyLen;
    DIGI_MEMCPY(test.pIv, pIv2, ivLen2);
    test.ivLen = ivLen2;

    DIGI_MEMCPY(test.pPlainText, pPlainText2, plainTextLen2);
    test.plainTextLen = plainTextLen2;

    DIGI_MEMCPY(test.pCipherText, pExpectedCipherText2, expectedCipherTextLen2);
    test.cipherTextLen = expectedCipherTextLen2;

    /* run test */
    status = runKnownTestReset3DES(test);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        errorCount = (errorCount + 1);

    DIGI_MEMSET(test.pKey, 0, 24);
    DIGI_MEMSET(test.pIv, 0, 8);
    DIGI_MEMSET(test.pPlainText, 0, 200);
    DIGI_MEMSET(test.pCipherText, 0, 200);

    return errorCount;
}

/*----------------------------------------------------------------------------*/

static MSTATUS runKnownTest(kvt_tdescbc test, int updateMode)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = 667;

    /* all iv values are 8 bytes */
    ubyte pIvCopy[8] = { 0 };
    ubyte ivCopyLen = 8;

    /* buffer used for operations */
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;

    DES3Ctx *pEncryptCtx = NULL;
    DES3Ctx *pDecryptCtx = NULL;

    /* allocate memory for buffer used in operations. */
    DIGI_MALLOC((void**)&pData, test.plainTextLen);
    dataLen = test.plainTextLen;

    /* make copy of of plaintext to pass to Do3DES,
     * operations happen in place, need copy of plain
     * text so original isn't altered */
    DIGI_MEMCPY(pData, test.pPlainText, dataLen);

    /* iv buffer is used for intermediary values, so
     * we need to use a copy of original so it isn't
     * altered. */
    DIGI_MEMCPY(pIvCopy, test.pIv, ivCopyLen);

    /* create context for encryption step, TRUE for encryption */
    pEncryptCtx = Create3DESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
    if (NULL == pEncryptCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* do the encryption, note that cipher text will be written to data
     * buffer */
    if (updateMode && dataLen >= 32)
    {
        /* Our operator allows for non-block size buffering but our high level Do3DES is inplace and doesn't */
        status = Do3DES(MOC_SYM(gpHwAccelCtx) pEncryptCtx, pData, 8, TRUE, pIvCopy);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        status = Do3DES(MOC_SYM(gpHwAccelCtx) pEncryptCtx, pData + 8, 16, TRUE, pIvCopy);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        status = Do3DES(MOC_SYM(gpHwAccelCtx) pEncryptCtx, pData + 24, dataLen - 24, TRUE, pIvCopy);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
    }
    else
    {
        status = Do3DES(MOC_SYM(gpHwAccelCtx) pEncryptCtx, pData, dataLen, TRUE, pIvCopy);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
    }
    /* compare cipher text in pData with expected cipher text */
    status = DIGI_MEMCMP(pData, test.pCipherText, test.cipherTextLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* test result of comparison */
    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* make another copy of IV for decryption operation. */
    DIGI_MEMCPY(pIvCopy, test.pIv, ivCopyLen);

    /* create context for decryption step, FALSE for decryption */
    pDecryptCtx = Create3DESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if (updateMode && dataLen >= 32)
    {
        /* Our operator allows for non-block size buffering but our high level Do3DES is inplace and doesn't */
        status = Do3DES(MOC_SYM(gpHwAccelCtx) pDecryptCtx, pData, 8, FALSE, pIvCopy);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        status = Do3DES(MOC_SYM(gpHwAccelCtx) pDecryptCtx, pData + 8, 16, FALSE, pIvCopy);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        status = Do3DES(MOC_SYM(gpHwAccelCtx) pDecryptCtx, pData + 24, dataLen - 24, FALSE, pIvCopy);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
    }
    else
    {
        status = Do3DES(MOC_SYM(gpHwAccelCtx) pDecryptCtx, pData, dataLen, FALSE, pIvCopy);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
    }

    cmpRes = 667;
    /* compare cipher text in pData with expected cipher text */
    status = DIGI_MEMCMP(pData, test.pPlainText, test.plainTextLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* test result of comparison */
    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    if (NULL != pEncryptCtx)
        Delete3DESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *) &pEncryptCtx);

    if (NULL != pDecryptCtx)
        Delete3DESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *) &pDecryptCtx);

    if(NULL != pData)
        DIGI_FREE((void**)&pData);

    return status;
}


/*----------------------------------------------------------------------------*/

static MSTATUS runKnownTestReset3DES(kvt_tdescbc test)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = 667;

    /* all iv values are 8 bytes */
    ubyte pIvCopy[8] = { 0 };
    ubyte ivCopyLen = 8;

    /* buffer used for operations */
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;

    DES3Ctx *pEncryptCtx = NULL;
    DES3Ctx *pDecryptCtx = NULL;

    /* allocate memory for buffer used in operations. */
    DIGI_MALLOC((void**)&pData, test.plainTextLen);
    dataLen = test.plainTextLen;

    /* make copy of of plaintext to pass to Do3DES,
     * operations happen in place, need copy of plain
     * text so original isn't altered */
    DIGI_MEMCPY(pData, test.pPlainText, dataLen);

    /* iv buffer is used for intermediary values, so
     * we need to use a copy of original so it isn't
     * altered. */
    DIGI_MEMCPY(pIvCopy, test.pIv, ivCopyLen);

    /* create context for encryption step, TRUE for encryption */
    pEncryptCtx = Create3DESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
    if (NULL == pEncryptCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* do the encryption, note that cipher text will be written to data
     * buffer */
    status = Do3DES(MOC_SYM(gpHwAccelCtx) pEncryptCtx, pData, dataLen, TRUE, pIvCopy);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Now reset the context, then make the above call again */

    status = Reset3DESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pEncryptCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* compare cipher text in pData with expected cipher text */
    status = DIGI_MEMCMP(pData, test.pCipherText, test.cipherTextLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* test result of comparison */
    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* make another copy of IV for decryption operation. */
    DIGI_MEMCPY(pIvCopy, test.pIv, ivCopyLen);

    /* create context for decryption step, FALSE for decryption */
    pDecryptCtx = Create3DESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
    if (NULL == pDecryptCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* the plain text will be written to data buffer */
    status = Do3DES(MOC_SYM(gpHwAccelCtx) pDecryptCtx, pData, dataLen, FALSE, pIvCopy);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Now reset the context, then make the above call again */

    status = Reset3DESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pDecryptCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    cmpRes = 667;
    /* compare cipher text in pData with expected cipher text */
    status = DIGI_MEMCMP(pData, test.pPlainText, test.plainTextLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* test result of comparison */
    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    if (NULL != pEncryptCtx)
        Delete3DESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *) &pEncryptCtx);

    if (NULL != pDecryptCtx)
        Delete3DESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *) &pDecryptCtx);

    if(NULL != pData)
        DIGI_FREE((void**)&pData);

    return status;
}


/*----------------------------------------------------------------------------*/


/* Test THREE_DES_initKey, THREE_DES_encipher, THREE_DES_decipher,
 * THREE_DES_clearKey from src/crypto/three_des.h
 */
static int testThreeDesInternals()
{
    MSTATUS status = ERR_NULL_POINTER;
    ctx3des des3Context;

    ubyte pKey[24] = {
        0xe6, 0x52, 0x1f, 0x3d, 0x4f, 0x01, 0xa1, 0x51,
        0xe6, 0x8a, 0x02, 0x25, 0x16, 0x6d, 0x51, 0xa7,
        0x43, 0x29, 0xe0, 0x2a, 0xdc, 0x4c, 0xdc, 0x43
    };
    ubyte4 keyLen = 24;

    ubyte pText[32] = {
        0xb5, 0x9d, 0xbe, 0xfb, 0xd8, 0x35, 0x2e, 0x48, 0x5f, 0x99, 0x5a, 0xfb,
        0xdb, 0xa3, 0x04, 0xe2, 0xb4, 0xa8, 0x7e, 0x16, 0x70, 0xab, 0x10, 0xd1,
        0x32, 0xd1, 0x9a, 0x7f, 0x81, 0x15, 0x7a, 0x18
    };
    ubyte4 textLen = 32;

    ubyte pExpected[32] = {
        0xfb, 0x9b, 0x94, 0x75, 0x47, 0xd4, 0xd9, 0x50, 0x34, 0xd5, 0x64, 0x55,
        0x56, 0x58, 0x47, 0xd3, 0x0d, 0x41, 0x53, 0xc9, 0xf5, 0x86, 0x9a, 0xf8,
        0x3d, 0x63, 0x2e, 0x21, 0xf7, 0xab, 0xf7, 0xab
    };

    ubyte4 expectedLen = 32;

    ubyte pData[32];
    ubyte4 dataLen = 32;
    sbyte4 cmpRes;

    status = THREE_DES_initKey(&des3Context, pKey, keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = THREE_DES_encipher(&des3Context, pText, pData, textLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    cmpRes = -1;
    status = DIGI_MEMCMP(pExpected, pData, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = THREE_DES_decipher(&des3Context, pExpected, pData, expectedLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    cmpRes = -1;
    status = DIGI_MEMCMP(pText, pData, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = THREE_DES_clearKey(&des3Context);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

exit:
    if(OK != status)
        return 1;
    return 0;
}

#ifndef __DISABLE_3DES_TWO_KEY_CIPHER__
static int testTwoKeyTDes()
{
    int retVal = 0;
    MSTATUS status = OK;
    BulkCtx ctx = NULL;
    sbyte4 cmp;

    ubyte pKey[16] = {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    ubyte pText[8] = {0};
    ubyte pTextCopy[8] = {0};
    ubyte pIv[8] = {0};
    ubyte pIvCopy[8] = {0};
    ubyte pCipher[8] = {0xFA,0xFD,0x50,0x84,0x37,0x4F,0xCE,0x34};

    /* encrypt */
    ctx = Create2Key3DESCtx(MOC_SYM(gpHwAccelCtx) pKey, sizeof(pKey), TRUE);
    if (NULL == ctx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    /* inplace encrypt */
    status = Do3DES(MOC_SYM(gpHwAccelCtx) ctx, pText, sizeof(pText), TRUE, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = Delete3DESCtx(MOC_SYM(gpHwAccelCtx) &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pText, pCipher, 8, &cmp);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmp)
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);

    /* now decrypt */
    ctx = Create2Key3DESCtx(MOC_SYM(gpHwAccelCtx) pKey, sizeof(pKey), FALSE);
    if (NULL == ctx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    /* use pIvCopy as pIv may have been mangled, ok to mangle pCipher now inplace */
    status = Do3DES(MOC_SYM(gpHwAccelCtx) ctx, pCipher, sizeof(pCipher), FALSE, pIvCopy);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = Delete3DESCtx(MOC_SYM(gpHwAccelCtx) &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pCipher, pTextCopy, 8, &cmp);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmp)
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);

exit:

    if (NULL != ctx)
        Delete3DESCtx(MOC_SYM(gpHwAccelCtx) &ctx); /* ok to ignore return code */

    return retVal;
}

#endif /* __DISABLE_3DES_TWO_KEY_CIPHER__ */

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
/* known answer test by comparing TAP (Hw) results with Sw results */
static int tapKATCbc(byteBoolean isEnc)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    sbyte4 retLen = 0;
    int i;

    BulkCtx pCtxHw = NULL;
    BulkCtx pCtxSw = NULL;

    SymmetricKey *pSymWrapper = NULL;

    ubyte pInput[64];
    ubyte pInputCopy[64];
    ubyte pIv[8] = {0xff, 0xee, 0xee, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd};

    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;

    TAP_KeyInfo keyInfo = {0};
    MSymTapCreateArgs createArgs = {0};
    ubyte pKey[24] = {0}; 

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_TDES;

    /* make a pseduo random looking plaintext of 8 blocks */
    for (i = 0; i < sizeof(pInput); ++i)
    {
        pInput[i] = pInputCopy[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    for (i = 0; i < 24; ++i)
    {
        pKey[i] = (ubyte) (i+1);
    }

    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_TDES;
    keyInfo.keyUsage = TAP_KEY_USAGE_DECRYPT;
    keyInfo.algKeyInfo.desInfo.symMode = TAP_SYM_KEY_MODE_UNDEFINED;
    createArgs.pKeyInfo = &keyInfo;
    createArgs.pKeyData = (ubyte *)pKey;
    createArgs.keyDataLen = 24;
    createArgs.token = FALSE;

    status = CRYPTO_INTERFACE_TAP_SymImportExternalKey(&pSymWrapper, pAesTapArgs, (void *)&createArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_getTDesCbcCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtxHw, isEnc ? MOCANA_SYM_TAP_ENCRYPT : MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pCtxSw = CRYPTO_INTERFACE_Create3DESCtx (MOC_SYM(gpHwAccelCtx) pKey, 24, isEnc ? 1 : 0);
    if (NULL == pCtxSw)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    status = CRYPTO_INTERFACE_Do3DES (MOC_SYM(gpHwAccelCtx) pCtxHw, pInput, 8, isEnc ? 1 : 0, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_Do3DES (MOC_SYM(gpHwAccelCtx) pCtxHw, pInput + 8, 16, isEnc ? 1 : 0, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_Do3DES (MOC_SYM(gpHwAccelCtx) pCtxHw, pInput + 24, 40, isEnc ? 1 : 0, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_Do3DES (MOC_SYM(gpHwAccelCtx) pCtxSw, pInputCopy, 16, isEnc ? 1 : 0, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_Do3DES (MOC_SYM(gpHwAccelCtx) pCtxSw, pInputCopy + 16, 40, isEnc ? 1 : 0, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_Do3DES (MOC_SYM(gpHwAccelCtx) pCtxSw, pInputCopy + 56, 8, isEnc ? 1 : 0, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pInput, pInputCopy, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pCtxSw)
    {
        (void) CRYPTO_INTERFACE_Delete3DESCtx (MOC_SYM(gpHwAccelCtx) &pCtxSw);
    }
    if (NULL != pCtxHw)
    {
        (void) CRYPTO_INTERFACE_Delete3DESCtx (MOC_SYM(gpHwAccelCtx) &pCtxHw);
    }

    if (NULL != pSymWrapper)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }

    return retVal;
}

static int tapKATEcb(byteBoolean isEnc)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    sbyte4 retLen = 0;
    int i;

    ctx3des ctxHw = {0};
    ctx3des ctxSw = {0};

    SymmetricKey *pSymWrapper = NULL;

    ubyte pInput[64];
    ubyte pOutputHw[64];
    ubyte pOutputSw[64];

    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;

    TAP_KeyInfo keyInfo = {0};
    MSymTapCreateArgs createArgs = {0};
    ubyte pKey[24] = {0}; 

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_TDES;

    /* make a pseduo random looking plaintext of 8 blocks */
    for (i = 0; i < sizeof(pInput); ++i)
    {
        pInput[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    for (i = 0; i < 24; ++i)
    {
        pKey[i] = (ubyte) (i+1);
    }

    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_TDES;
    keyInfo.keyUsage = TAP_KEY_USAGE_DECRYPT;
    keyInfo.algKeyInfo.desInfo.symMode = TAP_SYM_KEY_MODE_UNDEFINED;
    createArgs.pKeyInfo = &keyInfo;
    createArgs.pKeyData = (ubyte *)pKey;
    createArgs.keyDataLen = 24;
    createArgs.token = FALSE;

    status = CRYPTO_INTERFACE_TAP_SymImportExternalKey(&pSymWrapper, pAesTapArgs, (void *)&createArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_initTDesEcbCtxFromSymmetricKey (
        pSymWrapper, &ctxHw);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_THREE_DES_initKey(&ctxSw, pKey, 24);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (isEnc)
    {
        status = CRYPTO_INTERFACE_THREE_DES_encipher (&ctxHw, pInput, pOutputHw, 64); 
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_THREE_DES_encipher (&ctxSw, pInput, pOutputSw, 64); 
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = CRYPTO_INTERFACE_THREE_DES_decipher (&ctxHw, pInput, pOutputHw, 64); 
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_THREE_DES_decipher (&ctxSw, pInput, pOutputSw, 64); 
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    status = DIGI_MEMCMP(pOutputSw, pOutputHw, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    status = CRYPTO_INTERFACE_THREE_DES_clearKey (MOC_SYM(gpHwAccelCtx) &ctxSw);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    status = CRYPTO_INTERFACE_THREE_DES_clearKey (MOC_SYM(gpHwAccelCtx) &ctxHw);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    if (NULL != pSymWrapper)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }

    return retVal;
}

static int tapTestCbc(intBoolean testDeferredUnload)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    BulkCtx pCtx = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    ubyte pIv[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    ubyte pIvCopy[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    ubyte pPlain[64];
    ubyte pData[64];

    MSymTapKeyGenArgs tapArgs = {0};
    void *pTapArgs = (void *) &tapArgs;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    tapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    tapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    tapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    tapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_TDES;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pPlain); ++i)
    {
        pPlain[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    /* Make a copy so we can test the recovered plaintext */
    status = DIGI_MEMCPY(pData, pPlain, sizeof(pPlain));
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, 24 * 8 /* in bits */, pTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable TDES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getTDesCbcCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx, TRUE);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_TDesCbcDeferKeyUnload(pCtx, TRUE);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_Do3DES (MOC_SYM(gpHwAccelCtx) pCtx, pData, 8, TRUE, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;   

    status = CRYPTO_INTERFACE_Do3DES (MOC_SYM(gpHwAccelCtx) pCtx, pData + 8, 16, TRUE, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_Do3DES (MOC_SYM(gpHwAccelCtx) pCtx, pData + 24, 40, TRUE, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;   

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_TDesCbcGetKeyInfo (pCtx, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_Delete3DESCtx(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* deserialize into a SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, (void *) pTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable TDES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getTDesCbcCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx, FALSE);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_TDesCbcDeferKeyUnload(pCtx, TRUE);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_Do3DES (MOC_SYM(gpHwAccelCtx) pCtx, pData, 48, FALSE, pIvCopy);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;   

    status = CRYPTO_INTERFACE_Do3DES (MOC_SYM(gpHwAccelCtx) pCtx, pData + 48, 16, FALSE, pIvCopy);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, pPlain, sizeof(pPlain), &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pCtx)
    {
        status = CRYPTO_INTERFACE_Delete3DESCtx(MOC_SYM(gpHwAccelCtx) &pCtx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pSymWrapper)
    {
        status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_FREE((void **) &pSerKey);
    }

    return retVal;
}

static int tapTestEcb(intBoolean testDeferredUnload)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    ctx3des ctx = {0};
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    ubyte pPlain[64];
    ubyte pCipher[64] = {0};
    ubyte pRecPlain[64] = {0};

    MSymTapKeyGenArgs tapArgs = {0};
    void *pTapArgs = (void *) &tapArgs;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    tapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    tapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    tapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    tapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_TDES;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pPlain); ++i)
    {
        pPlain[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, 24 * 8 /* in bits */, pTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_SymKeyDeferUnload(pSymWrapper, TRUE);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable TDES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_initTDesEcbCtxFromSymmetricKey (pSymWrapper, &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_THREE_DES_encipher(&ctx, pPlain, pCipher, 8);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_THREE_DES_encipher(&ctx, pPlain + 8, pCipher + 8, 16);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_THREE_DES_encipher(&ctx, pPlain + 24, pCipher + 24, 40);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_TDesEcbGetKeyInfo (&ctx, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    /* clear the context */
    status = CRYPTO_INTERFACE_THREE_DES_clearKey (&ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* deserialize into a SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, (void *) pTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable TDES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_initTDesEcbCtxFromSymmetricKey (pSymWrapper, &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_TDesEcbDeferKeyUnload(&ctx, TRUE);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_THREE_DES_decipher(&ctx, pCipher, pRecPlain, 48);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_THREE_DES_decipher(&ctx, pCipher + 48, pRecPlain + 48, 16);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
 
    status = DIGI_MEMCMP(pRecPlain, pPlain, sizeof(pPlain), &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    status = CRYPTO_INTERFACE_THREE_DES_clearKey(&ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    if (NULL != pSymWrapper)
    {
        status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_FREE((void **) &pSerKey);
    }

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(1), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(1), tokenHandle);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}
#endif

/*----------------------------------------------------------------------------*/

int crypto_interface_tdes_test_init()
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
        UNITTEST_STATUS(__MOC_LINE__, status);
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
        defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_TDES__))

    errorCount = (errorCount + testCryptoInterface());
#endif

    /* CALL TEST FUNCTIONS HERE */
    errorCount = (errorCount + runAllKnownTests());
    errorCount = (errorCount + runAllKnownTestsReset3DES());
    errorCount = (errorCount + testThreeDesInternals());

#ifndef __DISABLE_3DES_TWO_KEY_CIPHER__
    errorCount = (errorCount + testTwoKeyTDes());
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
    status = TAP_EXAMPLE_init(&modNum, 1);
    if (OK != status)
    {
        errorCount += 1;
        goto exit;
    }

    errorCount = (errorCount + tapTestCbc(FALSE));
    errorCount = (errorCount + tapTestEcb(FALSE));
     
    errorCount = (errorCount + tapTestCbc(TRUE));
    errorCount = (errorCount + tapTestEcb(TRUE));
       
    errorCount += tapKATCbc(TRUE);
    errorCount += tapKATCbc(FALSE);

    errorCount += tapKATEcb(TRUE);
    errorCount += tapKATEcb(FALSE);

#endif /* __ENABLE_DIGICERT_TAP__ */

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
    TAP_EXAMPLE_clean();
#endif

    DIGICERT_free(&gpMocCtx);
    return errorCount;
}
