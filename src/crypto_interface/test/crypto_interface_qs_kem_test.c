/*
 * crypto_interface_qs_kem_test.c
 *
 * test cases for crypto interface API crypto_interface_qs_kem.c
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
#include "../../common/random.h"
#include "../../crypto_interface/crypto_interface_qs_kem.h"
#include "../../crypto_interface/crypto_interface_priv.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#ifdef __ENABLE_DIGICERT_PQC_KEM__

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static MocCtx gpMocCtx = NULL;

static int testKem(ubyte4 cipher)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare = -1;
    int hint = cipher;

    QS_CTX *pCtx1 = NULL;
    QS_CTX *pCtx2 = NULL;

    QS_CTX *pClone1 = NULL;
    QS_CTX *pClone2 = NULL;

    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;

    ubyte *pCipher = NULL;
    ubyte4 cipherLen = 0;

    ubyte *pSS1 = NULL;
    ubyte4 ss1Len = 0;

    ubyte *pSS2 = NULL;
    ubyte4 ss2Len = 0;

    /* Party 1 Begins */
    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(gpHwAccelCtx) &pCtx1, cipher);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_generateKeyPair(MOC_HASH(gpHwAccelCtx) pCtx1, RANDOM_rngFun, g_pRandomContext);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPublicKeyAlloc(pCtx1, &pPub, &pubLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* Public key gets sent to party 2 */
    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(gpHwAccelCtx) &pCtx2, cipher);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_setPublicKey(pCtx2, pPub, pubLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* Make clones for testing clones */
    status = CRYPTO_INTERFACE_QS_cloneCtx(&pClone1, pCtx1);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_cloneCtx(&pClone2, pCtx2);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* Party 2 generates the secret and ciphertext */
    status = CRYPTO_INTERFACE_QS_KEM_encapsulateAlloc(MOC_HASH(gpHwAccelCtx) pCtx2, RANDOM_rngFun, g_pRandomContext, &pCipher, &cipherLen, &pSS2, &ss2Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* Party 1 can decrypt the ciphertext and generate their copy of the SS */
    status = CRYPTO_INTERFACE_QS_KEM_decapsulateAlloc(MOC_HASH(gpHwAccelCtx) pCtx1, pCipher, cipherLen, &pSS1, &ss1Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* Validate the shared secrets match */
    if (ss1Len != ss2Len)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    status = DIGI_MEMCMP(pSS1, pSS2, ss1Len, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    /* Reset pSS1 and Test again with the clone */
    status = DIGI_MEMSET_FREE(&pSS1, ss1Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_KEM_decapsulateAlloc(MOC_HASH(gpHwAccelCtx) pClone1, pCipher, cipherLen, &pSS1, &ss1Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* Validate the shared secrets match */
    if (ss1Len != ss2Len)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    status = DIGI_MEMCMP(pSS1, pSS2, ss1Len, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    /* Reset pSS1, pSS2 and pCipher and test again with the clone */
    status = DIGI_MEMSET_FREE(&pSS1, ss2Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET_FREE(&pSS2, ss2Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET_FREE(&pCipher, cipherLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* Party 2 generates the secret and ciphertext */
    status = CRYPTO_INTERFACE_QS_KEM_encapsulateAlloc(MOC_HASH(gpHwAccelCtx) pClone2, RANDOM_rngFun, g_pRandomContext, &pCipher, &cipherLen, &pSS2, &ss2Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* Party 1 can decrypt the ciphertext and generate their copy of the SS */
    status = CRYPTO_INTERFACE_QS_KEM_decapsulateAlloc(MOC_HASH(gpHwAccelCtx) pCtx1, pCipher, cipherLen, &pSS1, &ss1Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* Validate the shared secrets match */
    if (ss1Len != ss2Len)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    status = DIGI_MEMCMP(pSS1, pSS2, ss1Len, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    /* Reset pSS1 and Test again with the clone */
    status = DIGI_MEMSET_FREE(&pSS1, ss1Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_KEM_decapsulateAlloc(MOC_HASH(gpHwAccelCtx) pClone1, pCipher, cipherLen, &pSS1, &ss1Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* Validate the shared secrets match */
    if (ss1Len != ss2Len)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    status = DIGI_MEMCMP(pSS1, pSS2, ss1Len, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (compare)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

exit:

    status = CRYPTO_INTERFACE_QS_deleteCtx(&pCtx1);
    retVal += UNITTEST_STATUS(hint, status);

    status = CRYPTO_INTERFACE_QS_deleteCtx(&pCtx2);
    retVal += UNITTEST_STATUS(hint, status);

    status = CRYPTO_INTERFACE_QS_deleteCtx(&pClone1);
    retVal += UNITTEST_STATUS(hint, status);

    status = CRYPTO_INTERFACE_QS_deleteCtx(&pClone2);
    retVal += UNITTEST_STATUS(hint, status);

    if (NULL != pPub)
    {
        status = DIGI_FREE((void **)&pPub);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pCipher)
    {
        status = DIGI_FREE((void **)&pCipher);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pSS1)
    {
        status = DIGI_FREE((void **)&pSS1);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pSS2)
    {
        status = DIGI_FREE((void **)&pSS2);
        retVal += UNITTEST_STATUS(hint, status);
    }

    return retVal;
}

#endif

/*----------------------------------------------------------------------------*/

int crypto_interface_qs_kem_test_init()
{
    int retVal = 0;

#ifdef __ENABLE_DIGICERT_PQC_KEM__
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

/* no MLKEM yet for oqs */
#ifndef __ENABLE_DIGICERT_KEM_OQS_KYBER__
    retVal += testKem(cid_PQC_MLKEM_512);
    retVal += testKem(cid_PQC_MLKEM_768);
    retVal += testKem(cid_PQC_MLKEM_1024);
#endif

exit:

    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

#endif /* __ENABLE_DIGICERT_PQC_KEM__ */

    return retVal;
}
