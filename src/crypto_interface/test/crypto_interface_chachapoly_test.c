/*
 * crypto_interface_chachapoly_test.c
 *
 * test cases for crypto interface API for chacha.h
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
#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/chacha20.h"

#include "../../common/mstdlib.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include "../../crypto_interface/crypto_interface_priv.h"

void CHACHA20_block(ChaCha20Ctx* ctx);

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static ubyte4 gCurrentVector = 0;

typedef struct TestVector
{
    char *pKey;
    char *pNonce;
    char *pAad;
    char *pData;
    char *pResult;

} TestVector;

#if defined( __ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)
#include "chachapoly_data_inc.h"

static int knownAnswerTest(TestVector *pTestVector)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 resCmp;
    BulkCtx ctx = NULL;

    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;
    ubyte *pNonce = NULL;
    ubyte4 nonceLen = 0;
    ubyte *pAad = NULL;
    ubyte4 aadLen = 0;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    ubyte *pResult = NULL;
    ubyte4 resultLen = 0;

    ubyte *pDataCopy = NULL;

    /* set the vectors from the test vector */
    if (pTestVector->pKey != NULL)
    {
        keyLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pKey, &pKey);
    }
    if (pTestVector->pNonce != NULL)
    {
        nonceLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pNonce, &pNonce);
    }
    if (pTestVector->pAad != NULL)
    {
        aadLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pAad, &pAad);
    }
    if (pTestVector->pData != NULL)
    {
        dataLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pData, &pData);
    }
    if (pTestVector->pResult != NULL)
    {
        resultLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pResult, &pResult);
    }

    /* copy the data and add room for the 16 byte tag at the end */
    status = DIGI_MALLOC((void **) &pDataCopy, dataLen + 16);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    if (dataLen)
    {
        status = DIGI_MEMCPY(pDataCopy, pData, dataLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
    }

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, 1);
    retVal += UNITTEST_VALIDPTR(gCurrentVector, ctx);
    if (retVal)
        goto exit;

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, nonceLen, pAad, aadLen, pDataCopy, dataLen, 16, 1);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    /* verify cipher text and tag */
    status = DIGI_MEMCMP(pDataCopy, pResult, resultLen, &resCmp);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, resCmp, 0);

    /* delete the context and re-create */
    status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &ctx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, 0);
    retVal += UNITTEST_VALIDPTR(0, ctx);
    if (retVal) goto exit;

    /* now decrypt and verify */
    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, nonceLen, pAad, aadLen, pDataCopy, dataLen, 16, 0);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    /* verify we get back the original data */
    if (dataLen)
    {
        status = DIGI_MEMCMP(pDataCopy, pData, dataLen, &resCmp);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(gCurrentVector, resCmp, 0);
    }

exit:

    if (NULL != ctx)
    {
        status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &ctx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pDataCopy)
    {
        status = DIGI_FREE((void **) &pDataCopy);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pKey)
    {
        status = DIGI_FREE((void **) &pKey);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pNonce)
    {
        status = DIGI_FREE((void **) &pNonce);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pAad)
    {
        status = DIGI_FREE((void **) &pAad);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pData)
    {
        status = DIGI_FREE((void **) &pData);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pResult)
    {
        status = DIGI_FREE((void **) &pResult);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    return retVal;
}

static int cloneTest(TestVector *pTestVector)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 resCmp;
    BulkCtx ctx = NULL;
    BulkCtx pCloneCtx = NULL;

    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;
    ubyte *pNonce = NULL;
    ubyte4 nonceLen = 0;
    ubyte *pAad = NULL;
    ubyte4 aadLen = 0;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    ubyte *pResult = NULL;
    ubyte4 resultLen = 0;

    ubyte *pDataCopy = NULL;

    /* set the vectors from the test vector */
    if (pTestVector->pKey != NULL)
    {
        keyLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pKey, &pKey);
    }
    if (pTestVector->pNonce != NULL)
    {
        nonceLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pNonce, &pNonce);
    }
    if (pTestVector->pAad != NULL)
    {
        aadLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pAad, &pAad);
    }
    if (pTestVector->pData != NULL)
    {
        dataLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pData, &pData);
    }
    if (pTestVector->pResult != NULL)
    {
        resultLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pResult, &pResult);
    }

    /* copy the data and add room for the 16 byte tag at the end */
    status = DIGI_MALLOC((void **) &pDataCopy, dataLen + 16);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    if (dataLen)
    {
        status = DIGI_MEMCPY(pDataCopy, pData, dataLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
    }

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, 1);
    retVal += UNITTEST_VALIDPTR(gCurrentVector, ctx);
    if (retVal)
        goto exit;

    status = ChaCha20Poly1305_cloneCtx(MOC_SYM(gpHwAccelCtx) ctx, &pCloneCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) pCloneCtx, pNonce, nonceLen, pAad, aadLen, pDataCopy, dataLen, 16, 1);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    /* verify cipher text and tag */
    status = DIGI_MEMCMP(pDataCopy, pResult, resultLen, &resCmp);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, resCmp, 0);

    /* delete the context and re-create */
    status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &ctx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &pCloneCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, 0);
    retVal += UNITTEST_VALIDPTR(0, ctx);
    if (retVal) goto exit;

    status = ChaCha20Poly1305_cloneCtx(MOC_SYM(gpHwAccelCtx) ctx, &pCloneCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    /* now decrypt and verify */
    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) pCloneCtx, pNonce, nonceLen, pAad, aadLen, pDataCopy, dataLen, 16, 0);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    /* verify we get back the original data */
    if (dataLen)
    {
        status = DIGI_MEMCMP(pDataCopy, pData, dataLen, &resCmp);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(gCurrentVector, resCmp, 0);
    }

exit:

    if (NULL != ctx)
    {
        status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &ctx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pCloneCtx)
    {
        status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &pCloneCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pDataCopy)
    {
        status = DIGI_FREE((void **) &pDataCopy);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pKey)
    {
        status = DIGI_FREE((void **) &pKey);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pNonce)
    {
        status = DIGI_FREE((void **) &pNonce);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pAad)
    {
        status = DIGI_FREE((void **) &pAad);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pData)
    {
        status = DIGI_FREE((void **) &pData);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pResult)
    {
        status = DIGI_FREE((void **) &pResult);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    return retVal;
}


/* Test decrypting a corrupted ciphertext of corrupted tag */
static int testAeadFailCase(TestVector *pTestVector)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 resCmp;
    BulkCtx ctx = NULL;

    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;
    ubyte *pNonce = NULL;
    ubyte4 nonceLen = 0;
    ubyte *pAad = NULL;
    ubyte4 aadLen = 0;
    ubyte *pResult = NULL;
    ubyte4 resultLen = 0;

    ubyte temp;

    /* set the vectors from the test vector */
    if (pTestVector->pKey != NULL)
    {
        keyLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pKey, &pKey);
    }
    if (pTestVector->pNonce != NULL)
    {
        nonceLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pNonce, &pNonce);
    }
    if (pTestVector->pAad != NULL)
    {
        aadLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pAad, &pAad);
    }
    if (pTestVector->pResult != NULL)
    {
        resultLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pResult, &pResult);
    }

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, 0);
    retVal += UNITTEST_VALIDPTR(__MOC_LINE__, ctx);
    if (retVal)
        goto exit;

    /* change one byte of the data portion of pResult */
    temp = pResult[0];
    pResult[0] = 0x00;

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, nonceLen, pAad, aadLen, pResult, resultLen - 16, 16, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CRYPTO_AEAD_FAIL);

    /* reset the context */
    status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, 0);
    retVal += UNITTEST_VALIDPTR(__MOC_LINE__, ctx);
    if (retVal)
        goto exit;

    /* change it back and change one byte of the tag portion */
    pResult[0] = temp;
    pResult[resultLen - 1] = 0x00;

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, nonceLen, pAad, aadLen, pResult, resultLen - 16, 16, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CRYPTO_AEAD_FAIL);

exit:

    if (NULL != ctx)
    {
        status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &ctx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pKey)
    {
        status = DIGI_FREE((void **) &pKey);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pNonce)
    {
        status = DIGI_FREE((void **) &pNonce);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pAad)
    {
        status = DIGI_FREE((void **) &pAad);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pResult)
    {
        status = DIGI_FREE((void **) &pResult);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

static int testErrorCases()
{
    int retVal = 0;
    BulkCtx ctx = NULL;
    MSTATUS status;

    ubyte pKey[32] = {0};
    ubyte pNonce[12] = {0};
    ubyte pAad[8] = {0};
    ubyte pData[32] = {0};

    /******* ChaCha20Poly1305_createCtx *******/

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) NULL, sizeof(pKey), 0);
    if (NULL != ctx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
        goto exit;
    }

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, 0, 0);
    if (NULL != ctx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
        goto exit;
    }

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, 31, 0);
    if (NULL != ctx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
        goto exit;
    }

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, 33, 0);
    if (NULL != ctx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
        goto exit;
    }

    /* correctly create a ctx for further tests */
    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, 32, 0);
    if (NULL == ctx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
        goto exit;
    }

    /******* ChaCha20Poly1305_cipher *******/

    /* null params */
    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) NULL, pNonce, sizeof(pNonce), pAad, sizeof(pAad), pData, sizeof(pData), 16, 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, NULL, sizeof(pNonce), pAad, sizeof(pAad), pData, sizeof(pData), 16, 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, sizeof(pNonce), NULL, sizeof(pAad), pData, sizeof(pData), 16, 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, sizeof(pNonce), pAad, sizeof(pAad), NULL, sizeof(pData), 16, 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) NULL, pNonce, sizeof(pNonce), pAad, sizeof(pAad), pData, sizeof(pData), 16, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, NULL, sizeof(pNonce), pAad, sizeof(pAad), pData, sizeof(pData), 16, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, sizeof(pNonce), NULL, sizeof(pAad), pData, sizeof(pData), 16, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, sizeof(pNonce), pAad, sizeof(pAad), NULL, sizeof(pData), 16, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invalid nonceLen */
    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, 0, pAad, sizeof(pAad), pData, sizeof(pData), 16, 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CHACHA20_BAD_NONCE_LENGTH);

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, 11, pAad, sizeof(pAad), pData, sizeof(pData), 16, 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CHACHA20_BAD_NONCE_LENGTH);

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, 13, pAad, sizeof(pAad), pData, sizeof(pData), 16, 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CHACHA20_BAD_NONCE_LENGTH);

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, 0, pAad, sizeof(pAad), pData, sizeof(pData), 16, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CHACHA20_BAD_NONCE_LENGTH);

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, 11, pAad, sizeof(pAad), pData, sizeof(pData), 16, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CHACHA20_BAD_NONCE_LENGTH);

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, 13, pAad, sizeof(pAad), pData, sizeof(pData), 16, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CHACHA20_BAD_NONCE_LENGTH);

    /* invalid verifyLen, re-create a ctx each further test */

    status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, 32, 1);
    if (NULL == ctx)
    {
      retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
      goto exit;
    }

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, sizeof(pNonce), pAad, sizeof(pAad), pData, sizeof(pData), 0, 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CHACHA20_BAD_TAG_LENGTH);

    status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, 32, 1);
    if (NULL == ctx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
        goto exit;
    }

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, sizeof(pNonce), pAad, sizeof(pAad), pData, sizeof(pData), 15, 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CHACHA20_BAD_TAG_LENGTH);

    status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, 32, 1);
    if (NULL == ctx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
        goto exit;
    }

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, sizeof(pNonce), pAad, sizeof(pAad), pData, sizeof(pData), 17, 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CHACHA20_BAD_TAG_LENGTH);

    status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, 32, 0);
    if (NULL == ctx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
        goto exit;
    }

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, sizeof(pNonce), pAad, sizeof(pAad), pData, sizeof(pData), 0, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CHACHA20_BAD_TAG_LENGTH);

    status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, 32, 0);
    if (NULL == ctx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
        goto exit;
    }

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, sizeof(pNonce), pAad, sizeof(pAad), pData, sizeof(pData), 15, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CHACHA20_BAD_TAG_LENGTH);

    status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    ctx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, 32, 0);
    if (NULL == ctx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
        goto exit;
    }

    status = ChaCha20Poly1305_cipher(MOC_SYM(gpHwAccelCtx) ctx, pNonce, sizeof(pNonce), pAad, sizeof(pAad), pData, sizeof(pData), 17, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CHACHA20_BAD_TAG_LENGTH);

    /******* ChaCha20Poly1305_deleteCtx *******/

    status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* deleting already deleted ctx is on OK no-op */

exit:

    if (NULL != ctx)
    {
        status = ChaCha20Poly1305_deleteCtx(MOC_SYM(gpHwAccelCtx) &ctx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

#if 0 /* tempory removed until we have a way to not call internal method CHACHA20_block directly */
/* Test vectors are from https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
 */
static int chachaPolySetNonceForSSH()
{
    int i, retVal = 0;
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ChaCha20Ctx *pCtx = NULL;
    ubyte pKey[32] = { 0 };
    ubyte pNonce[8] = { 0 };

    DIGI_MEMSET(pKey, 0x00, 32);

    ubyte pExpectedKeyStream[64] = {
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5,
        0x53, 0x86, 0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
        0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c,
        0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
        0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69,
        0xb2, 0xee, 0x65, 0x86
    };

    ubyte pExpectedKeyStream2[64] = {
        0x45, 0x40, 0xf0, 0x5a, 0x9f, 0x1f, 0xb2, 0x96, 0xd7, 0x73, 0x6e, 0x7b,
        0x20, 0x8e, 0x3c, 0x96, 0xeb, 0x4f, 0xe1, 0x83, 0x46, 0x88, 0xd2, 0x60,
        0x4f, 0x45, 0x09, 0x52, 0xed, 0x43, 0x2d, 0x41, 0xbb, 0xe2, 0xa0, 0xb6,
        0xea, 0x75, 0x66, 0xd2, 0xa5, 0xd1, 0xe7, 0xe2, 0x0d, 0x42, 0xaf, 0x2c,
        0x53, 0xd7, 0x92, 0xb1, 0xc4, 0x3f, 0xea, 0x81, 0x7e, 0x9a, 0xd2, 0x75,
        0xae, 0x54, 0x69, 0x63
    };

    ubyte pExpectedKeyStream3[60] = {
        0xde, 0x9c, 0xba, 0x7b, 0xf3, 0xd6, 0x9e, 0xf5, 0xe7, 0x86, 0xdc, 0x63,
        0x97, 0x3f, 0x65, 0x3a, 0x0b, 0x49, 0xe0, 0x15, 0xad, 0xbf, 0xf7, 0x13,
        0x4f, 0xcb, 0x7d, 0xf1, 0x37, 0x82, 0x10, 0x31, 0xe8, 0x5a, 0x05, 0x02,
        0x78, 0xa7, 0x08, 0x45, 0x27, 0x21, 0x4f, 0x73, 0xef, 0xc7, 0xfa, 0x5b,
        0x52, 0x77, 0x06, 0x2e, 0xb7, 0xa0, 0x43, 0x3e, 0x44, 0x5f, 0x41, 0xe3
    };

    /* Test 1 */
    pCtx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, 32, 0);
    if (NULL == pCtx)
    {
        return 1;
    }

    CHACHA20_block(pCtx);

    for (i = 0; i < 64; i ++)
    {
        retVal += UNITTEST_TRUE(i, pExpectedKeyStream[i] == pCtx->keystream[i]);
    }

    DeleteChaCha20Ctx((BulkCtx*)&pCtx);

    DIGI_MEMSET(pKey, 0x00, 32);
    pKey[31] = 1;
    pCtx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, 32, 0);
    if (NULL == pCtx)
    {
        retVal += 1;
        return retVal;
    }

    CHACHA20_block(pCtx);

    for (i = 0; i < 64; i ++)
    {
        retVal += UNITTEST_TRUE(i, pExpectedKeyStream2[i] == pCtx->keystream[i]);
    }

    DeleteChaCha20Ctx((BulkCtx*)&pCtx);

    /* Test 3 */
    DIGI_MEMSET(pKey, 0x00, 32);
    DIGI_MEMSET(pNonce, 0x00, 8);
    pNonce[7] = 1;
    pCtx = ChaCha20Poly1305_createCtx(MOC_SYM(gpHwAccelCtx) pKey, 32, 0);
    if (NULL == pCtx)
    {
        retVal += 1;
        return retVal;
    }

    if(OK > CHACHA20_setNonceAndCounterSSH(MOC_SYM(gpHwAccelCtx) (BulkCtx)pCtx, pNonce, 8, NULL, 0))
    {
        retVal +=1;
        return retVal;
    }

    CHACHA20_block(pCtx);

    for (i = 0; i < 60; i ++)
    {
        retVal += UNITTEST_TRUE(i, pExpectedKeyStream3[i] == pCtx->keystream[i]);
    }

    DeleteChaCha20Ctx((BulkCtx*)&pCtx);

#endif
    return retVal;
}
#endif /* 0 */
#endif /* defined( __ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__) */

int crypto_interface_chachapoly_test_init()
{
    int retVal = 0;

#if defined( __ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)
    MSTATUS status;
    int i;

    InitMocanaSetupInfo setupInfo = {0};
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    gCurrentVector = 0;
    for (i = 0; i < COUNTOF(gTestVector); ++i)
    {
        retVal += knownAnswerTest(gTestVector + i);
        retVal += cloneTest(gTestVector + i);
        gCurrentVector++;
    }

    retVal += testAeadFailCase(&gFailVector);
    retVal += testErrorCases();
#if 0
    retVal += chachaPolySetNonceForSSH();
#endif
exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

#endif

    return retVal;
}
