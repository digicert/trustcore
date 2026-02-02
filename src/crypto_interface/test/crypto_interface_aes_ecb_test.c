/*
* crypto_interface_aes_ecb_test.c
*
* test file for AES in ECB mode
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
#include "../../crypto/aes.h"
#include "../../crypto/aes_ecb.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include "../../crypto_interface/test/ecb128Tests.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_aes.h"

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
#include "crypto_interface_tap_example.h"
#include "../../crypto/mocsymalgs/tap/symtap.h"
#include "../../crypto_interface/crypto_interface_sym_tap.h"
#include "../../crypto_interface/crypto_interface_aes_tap.h"
#endif
#endif

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
MSTATUS TAP_freeKeyEx(TAP_Key **ppKey);
#endif

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__

#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <stdio.h>

#define ENCRYPT_ITERATIONS 10000000
#define DECRYPT_ITERATIONS 10000000

#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES__))
/*----------------------------------------------------------------------------*/
static int testCryptoInterface(aesTest test)
{
    MSTATUS status = OK;

    ubyte *pKey = NULL;
    sbyte4 keyLen = 0;

    keyLen = UNITTEST_UTILS_str_to_byteStr((const sbyte*)test.pKey, &pKey);

    aesCipherContext *pAesCtx = NULL;;
    MocSymCtx pTest = NULL;
    ubyte enabled ='\0';

#if (defined(__ENABLE_DIGICERT_MBED_SYM_OPERATORS__) && \
    (defined(__ENABLE_DIGICERT_AES_ECB_MBED__)))
    pAesCtx = (aesCipherContext*)CreateAESECBCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, TRUE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    pTest = pAesCtx->pMocSymCtx;
    enabled = pAesCtx->enabled;
    if(NULL == pTest)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if(FALSE == enabled)
    {
        status = ERR_INVALID_ARG;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

#endif

exit:
    if (NULL != pAesCtx)
    {
        DeleteAESECBCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pAesCtx);
    }

    if (NULL != pKey)
    {
        (void) DIGI_FREE((void **) &pKey);
    }

    if(OK != status)
        return 1;
    return 0;
}
#endif


/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__

static int speedTestAes(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;

    /* use multi block test for 32 byte key length */
    ubyte pData[16] = {0};
    sbyte4 dataLen = 16;

    ubyte *pPlain = NULL;
    sbyte4 plainLen = 0;

    ubyte *pCipher = NULL;
    sbyte4 cipherLen = 0;

    ubyte *pKey = NULL;
    sbyte4 keyLen = 0;

    keyLen = UNITTEST_UTILS_str_to_byteStr((const sbyte*)test.pKey, &pKey);
    plainLen = UNITTEST_UTILS_str_to_byteStr((const sbyte*)test.pPlain, &pPlain);
    cipherLen = UNITTEST_UTILS_str_to_byteStr((const sbyte*)test.pCipher, &pCipher);

    status = DIGI_MEMCPY(pData, pPlain, 16);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    sbyte4 cmpRes = -1;
    aesCipherContext *pAesCtx;

    struct tms tstart;
    struct tms tend;
    double diffTime = 0.0;

    ubyte *pOutputFormat = "%-25s: %g seconds\n";
    FILE *pFile = NULL;

    if(NULL == (pFile = fopen(
        "../../../projects/cryptointerface_unittest/speed_test.txt", "a")))
    {
        printf("failed to open file\n");
        goto exit;
    }

    pAesCtx = (aesCipherContext*)CreateAESECBCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, TRUE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for(int i = 0;i < ENCRYPT_ITERATIONS; i++)
    {
        status =  DIGI_MEMCPY(pData, pPlain, dataLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        times(&tstart);
        status = DoAESECB(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, dataLen, TRUE);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
        times(&tend);

        status = DIGI_MEMCMP(pData, pCipher, dataLen, &cmpRes);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        if(0 != cmpRes)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
        diffTime += tend.tms_utime - tstart.tms_utime;
    }
    fprintf(pFile, pOutputFormat, "aes-ecb encrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "aes-ecb encrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));

    status = DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* do decryption step */
    pAesCtx = (aesCipherContext*) CreateAESECBCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, FALSE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* reset variable for decrypt step */
    diffTime = 0.0;
    for(int i = 0;i < DECRYPT_ITERATIONS; i++)
    {
        status =  DIGI_MEMCPY(pData, pCipher, dataLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        times(&tstart);
        status = DoAESECB(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, dataLen, FALSE);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
        times(&tend);

        status = DIGI_MEMCMP(pData, pPlain, dataLen, &cmpRes);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        if(0 != cmpRes)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
        diffTime += tend.tms_utime - tstart.tms_utime;
    }
    fprintf(pFile, pOutputFormat, "aes-ecb decrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "aes-ecb decrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));

exit:

    if (NULL != pAesCtx)
    {
        DeleteAESECBCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pAesCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}
#endif /* ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__ */


/*----------------------------------------------------------------------------*/

static int runSingleBlockTest(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = -1;
    aesCipherContext *pAesCtx = NULL;

    /* buffer used to DoAESECB operations */
    ubyte pData[32] = {0};
    sbyte4 dataLen = 32;

    ubyte *pPlain = NULL;
    sbyte4 plainLen = 0;

    ubyte *pCipher = NULL;
    sbyte4 cipherLen = 0;

    ubyte *pKey = NULL;
    sbyte4 keyLen = 0;

    keyLen = UNITTEST_UTILS_str_to_byteStr((const sbyte*)test.pKey, &pKey);
    plainLen = UNITTEST_UTILS_str_to_byteStr((const sbyte*)test.pPlain, &pPlain);
    cipherLen = UNITTEST_UTILS_str_to_byteStr((const sbyte*)test.pCipher, &pCipher);
    dataLen = plainLen;

    status = DIGI_MEMCPY(pData, pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    pAesCtx = (aesCipherContext*)CreateAESECBCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, TRUE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DoAESECB(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, dataLen, TRUE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, pCipher, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DeleteAESECBCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* do decryption step */
    pAesCtx = (aesCipherContext*)CreateAESECBCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, FALSE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DoAESECB(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, dataLen, FALSE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, pPlain, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    if(NULL != pAesCtx)
    {
        DeleteAESECBCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    }
    if (NULL != pKey)
    {
        DIGI_FREE((void **)&pKey);
    }
    if (NULL != pPlain)
    {
        DIGI_FREE((void **)&pPlain);
    }
    if (NULL != pCipher)
    {
        DIGI_FREE((void **)&pCipher);
    }

    if(OK != status)
        return 1;
    return 0;
}


/*----------------------------------------------------------------------------*/

static int runCloneTest(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = -1;
    aesCipherContext *pAesCtx = NULL;
    aesCipherContext *pCloneCtx = NULL;

    /* buffer used to DoAESECB operations */
    ubyte pData[32] = {0};
    sbyte4 dataLen = 32;

    ubyte *pPlain = NULL;
    sbyte4 plainLen = 0;

    ubyte *pCipher = NULL;
    sbyte4 cipherLen = 0;

    ubyte *pKey = NULL;
    sbyte4 keyLen = 0;

    keyLen = UNITTEST_UTILS_str_to_byteStr((const sbyte*)test.pKey, &pKey);
    plainLen = UNITTEST_UTILS_str_to_byteStr((const sbyte*)test.pPlain, &pPlain);
    cipherLen = UNITTEST_UTILS_str_to_byteStr((const sbyte*)test.pCipher, &pCipher);
    dataLen = plainLen;

    status = DIGI_MEMCPY(pData, pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    pAesCtx = (aesCipherContext*)CreateAESECBCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, TRUE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = CloneAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, (BulkCtx *)&pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAESECB(MOC_SYM(gpHwAccelCtx) (BulkCtx)pCloneCtx, pData, dataLen, TRUE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, pCipher, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DeleteAESECBCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DeleteAESECBCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* do decryption step */
    pAesCtx = (aesCipherContext*)CreateAESECBCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, FALSE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = CloneAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, (BulkCtx *)&pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAESECB(MOC_SYM(gpHwAccelCtx) (BulkCtx)pCloneCtx, pData, dataLen, FALSE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, pPlain, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    if(NULL != pAesCtx)
    {
        DeleteAESECBCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    }
    if(NULL != pCloneCtx)
    {
        DeleteAESECBCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pCloneCtx);
    }
    if (NULL != pKey)
    {
        DIGI_FREE((void **)&pKey);
    }
    if (NULL != pPlain)
    {
        DIGI_FREE((void **)&pPlain);
    }
    if (NULL != pCipher)
    {
        DIGI_FREE((void **)&pCipher);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int runTests()
{
    int errorCount = 0;
    int i = 0;

    for(; i < 128; i++)
    {
        errorCount = (errorCount + runSingleBlockTest(gpEcb128Tests[i]));
        errorCount = (errorCount + runCloneTest(gpEcb128Tests[i]));
    }

    return errorCount;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
/* known answer test by comparing TAP (Hw) results with Sw results */
static int tapKAT(ubyte4 keySize, byteBoolean isEnc)
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
    ubyte pOutputHw[64] = {0};
    ubyte pOutputSw[64] = {0};

    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pInput); ++i)
    {
        pInput[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    TAP_KeyInfo keyInfo = {0};
    MSymTapCreateArgs createArgs = {0};
    ubyte pKey[32] = {0}; /* big enough for all tests */
    for (i = 0; i < keySize/8; ++i)
    {
        pKey[i] = (ubyte) (i+1);
    }

    switch(keySize)
    {
        case 128:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_128;
            break;

        case 192:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_192;
            break;

        case 256:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_256;
            break;

        default:
            goto exit;
    }

    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_AES;
    keyInfo.keyUsage = TAP_KEY_USAGE_DECRYPT;
    keyInfo.algKeyInfo.aesInfo.symMode = TAP_SYM_KEY_MODE_UNDEFINED;
    createArgs.pKeyInfo = &keyInfo;
    createArgs.pKeyData = (ubyte *)pKey;
    createArgs.keyDataLen = keySize/8;
    createArgs.token = FALSE;

    status = CRYPTO_INTERFACE_TAP_SymImportExternalKey(&pSymWrapper, pAesTapArgs, (void *)&createArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtxHw, MODE_ECB, isEnc ? MOCANA_SYM_TAP_ENCRYPT : MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pCtxSw = CRYPTO_INTERFACE_CreateAESECBCtx (MOC_SYM(gpHwAccelCtx) pKey, keySize/8, isEnc ? 1 : 0);
    if (NULL == pCtxSw)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    if (isEnc)
    {
        status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtxHw, NULL, pInput, 64 * 8, pOutputHw, &retLen);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(__MOC_LINE__, retLen, 64 * 8);

        status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtxSw, NULL, pInput, 64 * 8, pOutputSw, &retLen);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(__MOC_LINE__, retLen, 64 * 8);

    }
    else
    {
        status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtxHw, NULL, pInput, 64 * 8, pOutputHw, &retLen);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(__MOC_LINE__, retLen, 64 * 8);

        status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtxSw, NULL, pInput, 64 * 8, pOutputSw, &retLen);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(__MOC_LINE__, retLen, 64 * 8);
    }

    status = DIGI_MEMCMP(pOutputSw, pOutputHw, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pCtxSw)
    {
        (void *)CRYPTO_INTERFACE_DeleteAESCtx (MOC_SYM(gpHwAccelCtx) &pCtxSw);
    }
    if (NULL != pCtxHw)
    {
        (void *)CRYPTO_INTERFACE_DeleteAESCtx (MOC_SYM(gpHwAccelCtx) &pCtxHw);
    }

    if (NULL != pSymWrapper)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }

    return retVal;
}

static int genKeyTestEx(ubyte4 keySize)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    BulkCtx pCtx = NULL;
    BulkCtx pCtx2 = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    /* Pointers for a special free on ctx1 */
    aesCipherContext *pAesCtx = NULL;
    MocSymCtx pMocSymCtx = NULL;
    MTapKeyData *pTapData = NULL;

    ubyte pPlain[64];
    ubyte pCipher[64] = {0};
    ubyte pRecPlain[64] = {0};
    sbyte4 retLen = 0;

    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pPlain); ++i)
    {
        pPlain[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, keySize, pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx, MODE_ECB, MOCANA_SYM_TAP_ENCRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, NULL, pPlain, 16 * 8, pCipher, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, NULL, pPlain + 16, 32 * 8, pCipher + 16, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 32 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, NULL, pPlain + 48, 16 * 8, pCipher + 48, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    /* test Reset context and decrypt again */
    status = CRYPTO_INTERFACE_ResetAESCtx(&pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* deserialize into a SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, (void *) pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx2, MODE_ECB, MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, NULL, pCipher, 16 * 8, pRecPlain, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, NULL, pCipher + 16, 32 * 8, pRecPlain + 16, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 32 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, NULL, pCipher + 48, 16 * 8, pRecPlain + 48, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = DIGI_MEMCMP(pPlain, pRecPlain, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

    /* test Reset context and decrypt again */
    status = CRYPTO_INTERFACE_ResetAESCtx(&pCtx2);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, NULL, pCipher, 16 * 8, pRecPlain, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, NULL, pCipher + 16, 32 * 8, pRecPlain + 16, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 32 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, NULL, pCipher + 48, 16 * 8, pRecPlain + 48, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = DIGI_MEMCMP(pPlain, pRecPlain, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    status = CRYPTO_INTERFACE_DeleteAESCtx(MOC_SYM(gpHwAccelCtx) &pCtx2);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    /* Special free code since we have two aes ctxs with two TAP keys each pointing to the same
     * underlying SMP resource, the above deletion deletes the actual object that this ctx also
     * points to, so to avoid errors manually free all the containers */
    if (NULL != pCtx)
    {
        pAesCtx = (aesCipherContext *)pCtx;
        pMocSymCtx = pAesCtx->pMocSymCtx;
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

static int genKeyTest(ubyte4 keySize)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    BulkCtx pCtx = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    ubyte pPlain[64];
    ubyte pCipher[64] = {0};
    ubyte pRecPlain[64] = {0};
    sbyte4 retLen = 0;

    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pPlain); ++i)
    {
        pPlain[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, keySize, pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx, MODE_ECB, MOCANA_SYM_TAP_ENCRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, NULL, pPlain, 16 * 8, pCipher, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, NULL, pPlain + 16, 32 * 8, pCipher + 16, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 32 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, NULL, pPlain + 48, 16 * 8, pCipher + 48, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    /* delete the context */
    status = CRYPTO_INTERFACE_DeleteAESCtx (MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* deserialize into a SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, (void *) pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx, MODE_ECB, MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx, NULL, pCipher, 16 * 8, pRecPlain, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx, NULL, pCipher + 16, 32 * 8, pRecPlain + 16, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 32 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx, NULL, pCipher + 48, 16 * 8, pRecPlain + 48, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = DIGI_MEMCMP(pPlain, pRecPlain, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

    /* test Reset context and decrypt again */
    status = CRYPTO_INTERFACE_ResetAESCtx(&pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx, NULL, pCipher, 16 * 8, pRecPlain, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx, NULL, pCipher + 16, 32 * 8, pRecPlain + 16, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 32 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx, NULL, pCipher + 48, 16 * 8, pRecPlain + 48, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = DIGI_MEMCMP(pPlain, pRecPlain, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    status = CRYPTO_INTERFACE_DeleteAESCtx(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

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
#endif

/*----------------------------------------------------------------------------*/

int crypto_interface_aes_ecb_test_init()
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

    /* TESTS GO HERE */

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES__))

    errorCount = (errorCount + testCryptoInterface(gpEcb128Tests[0]));
#endif

    errorCount = (errorCount + runTests());

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
    status = TAP_EXAMPLE_init(&modNum, 1);
    if (OK != status)
    {
        errorCount += 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
    errorCount = (errorCount + genKeyTestEx(128));
    errorCount = (errorCount + genKeyTestEx(192));
    errorCount = (errorCount + genKeyTestEx(256));
#else
    errorCount = (errorCount + genKeyTest(128));
    errorCount = (errorCount + genKeyTest(192));
    errorCount = (errorCount + genKeyTest(256));
#endif

    errorCount += tapKAT(128, TRUE);
    errorCount += tapKAT(192, TRUE);
    errorCount += tapKAT(256, TRUE);

    errorCount += tapKAT(128, FALSE);
    errorCount += tapKAT(192, FALSE);
    errorCount += tapKAT(256, FALSE);

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
