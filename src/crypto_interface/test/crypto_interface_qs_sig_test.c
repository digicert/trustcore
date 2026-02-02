/*
 * crypto_interface_qs_sig_test.c
 *
 * test cases for crypto interface API crypto_interface_qs_sig.c
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
#include "../../crypto/ecc_edwards_keys.h"
#include "../../crypto/pqc/pqc_ser.h"
#include "../../crypto_interface/crypto_interface_priv.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_qs_sig.h"
#include "../../crypto_interface/crypto_interface_ecc.h"
#include "../../crypto_interface/crypto_interface_qs_composite.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

/* can remove the sig_oqs flag once our own implementations exist */
#if defined(__ENABLE_DIGICERT_PQC_SIG__)

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
static int signVerifyComposite(int hint, AsymmetricKey *pSignKey, AsymmetricKey *pVerKey, ubyte *pDomain, ubyte4 domainLen, byteBoolean lenPrefixing)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 vStatus = 1;

    ubyte *pSig = NULL;
    ubyte4 sigLen = 0;

    ubyte pData[500];
    ubyte4 dataLen = 500;

    ubyte pTempDomain[4] = {0x01, 0x02, 0x03, 0x04};

    sbyte4 i = 0;
    /* set the data to random looking data */
    for (i = 0; i < dataLen; i++)
        pData[i] = (ubyte) (47 * (i + 1 + 2*hint)) & 0xff;

    status = CRYPTO_INTERFACE_QS_compositeGetSigLen(MOC_ASYM(gpHwAccelCtx) pSignKey, lenPrefixing, &sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pSig, sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
       goto exit;
    
    status = CRYPTO_INTERFACE_QS_compositeSign(MOC_ASYM(gpHwAccelCtx) pSignKey, lenPrefixing, RANDOM_rngFun, g_pRandomContext, pDomain, domainLen, pData, dataLen,
                                               pSig, sigLen, &sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
       goto exit;

    /* EdDSA requires key to be marked public for verify, for testing purposes make sure it is */
    if (pVerKey->clAlg == cid_EC_Ed25519 || pVerKey->clAlg == cid_EC_Ed448)
    {
        ((edECCKey *) (pVerKey->key.pECC->pEdECCKey))->isPrivate = 0;
    }

    status = CRYPTO_INTERFACE_QS_compositeVerify(MOC_ASYM(gpHwAccelCtx) pVerKey, lenPrefixing, pDomain, domainLen, pData, dataLen, pSig, sigLen, &vStatus);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
       goto exit;

    if (vStatus)
    {
        retVal += UNITTEST_STATUS(hint, -1);
        goto exit;
    }

    /* Negative test, change len prefixing */
    status = CRYPTO_INTERFACE_QS_compositeVerify(MOC_ASYM(gpHwAccelCtx) pVerKey, !lenPrefixing, pDomain, domainLen, pData, dataLen, pSig, sigLen, &vStatus);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
       goto exit; 

    if (!vStatus)
    {
        retVal += UNITTEST_STATUS(hint, -1);
        goto exit;
    }

    /* Negative test, change the domain */
    status = CRYPTO_INTERFACE_QS_compositeVerify(MOC_ASYM(gpHwAccelCtx) pVerKey, lenPrefixing, pDomain ? NULL : pTempDomain, domainLen ? 0 : 4, pData, dataLen, pSig, sigLen, &vStatus);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
       goto exit; 

    if (!vStatus)
    {
        retVal += UNITTEST_STATUS(hint, -1);
        goto exit;
    }

    /* Negative test, change pData */
    pData[0]++;
    status = CRYPTO_INTERFACE_QS_compositeVerify(MOC_ASYM(gpHwAccelCtx) pVerKey, lenPrefixing, pDomain, domainLen, pData, dataLen, pSig, sigLen, &vStatus);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
       goto exit; 

    if (!vStatus)
    {
        retVal += UNITTEST_STATUS(hint, -1);
        goto exit;
    }
    pData[0]--;

    /* Negative test, change length byte of pSig */
    pSig[0]++;
    status = CRYPTO_INTERFACE_QS_compositeVerify(MOC_ASYM(gpHwAccelCtx) pVerKey, lenPrefixing, pDomain, domainLen, pData, dataLen, pSig, sigLen, &vStatus);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
       goto exit; 

    if (!vStatus)
    {
        retVal += UNITTEST_STATUS(hint, -1);
        goto exit;
    }
    pSig[0]--;

    /* Negative test, change a qs byte of the sig  */
    pSig[5]++;
    status = CRYPTO_INTERFACE_QS_compositeVerify(MOC_ASYM(gpHwAccelCtx) pVerKey, lenPrefixing, pDomain, domainLen, pData, dataLen, pSig, sigLen, &vStatus);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit; 

    if (!vStatus)
    {
        retVal += UNITTEST_STATUS(hint, -1);
        goto exit;
    }
    pSig[5]--;

    /* Negative test, change clasical byte of pSig */
    pSig[sigLen - 1]++;
    status = CRYPTO_INTERFACE_QS_compositeVerify(MOC_ASYM(gpHwAccelCtx) pVerKey, lenPrefixing, pDomain, domainLen, pData, dataLen, pSig, sigLen, &vStatus);
    if (OK == status && !vStatus) /* RSA may return error and non-zero vStatus, so check both at same time */
    {
        retVal += UNITTEST_STATUS(hint, -1);
        goto exit;
    }

exit:

    /* set the pVerKey back to private for eddsa (just in case cleanup needs it to be correct) */
    if (pVerKey->clAlg == cid_EC_Ed25519 || pVerKey->clAlg == cid_EC_Ed448)
    {
        ((edECCKey *) (pVerKey->key.pECC->pEdECCKey))->isPrivate = 1;
    }

    if (NULL != pSig)
    {
        status = DIGI_FREE((void **)&pSig);
        retVal += UNITTEST_STATUS(hint, status);
    }

    return retVal;
}

/*---------------------------------------------------------------------------*/

static int hybridSerializationTest(int hint, char *pKeyFile)
{
    MSTATUS status;

    int retVal = 0;
    ubyte4 res = 1;
    AsymmetricKey key1;
    AsymmetricKey key2;

    ubyte *pSerializedKey1 = NULL;
    ubyte4 serializedKey1Len;

    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen;

    status = CRYPTO_initAsymmetricKey(&key1);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&key2);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = DIGICERT_readFile(pKeyFile, &pKeyBlob, &keyBlobLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pKeyBlob, keyBlobLen, NULL, &key1);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &key1, privateKeyInfoDer, &pSerializedKey1, &serializedKey1Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pSerializedKey1, serializedKey1Len, NULL, &key2);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* now test rountrips with the key combinations */
    retVal += signVerifyComposite(hint, &key1, &key1, NULL, 0, FALSE);
    retVal += signVerifyComposite(hint, &key2, &key1, NULL, 0, FALSE);
    retVal += signVerifyComposite(hint, &key2, &key2, NULL, 0, FALSE);
    retVal += signVerifyComposite(hint, &key1, &key2, NULL, 0, FALSE);

exit:

    CRYPTO_uninitAsymmetricKey(&key1, NULL);
    CRYPTO_uninitAsymmetricKey(&key2, NULL);

    if (NULL != pSerializedKey1)
        DIGI_FREE((void **) &pSerializedKey1);

    if (NULL != pKeyBlob)
        DIGI_FREE((void **) &pKeyBlob);

    return retVal;
}
#endif

/* TODO uncomment and fix (ie add RSA) once pubkeys are supported */
#if 0
static int hybridPubKeySerializationTest(int hint, char *pKeyFile)
{
    MSTATUS status;

    int retVal = 0;
    ubyte4 res = 1;
    AsymmetricKey key1;
    AsymmetricKey key2;

    ubyte *pSerializedKey1 = NULL;
    ubyte4 serializedKey1Len;

    MEccKeyTemplate template1 = {0};
    MEccKeyTemplate template2 = {0};
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen;

    status = CRYPTO_initAsymmetricKey(&key1);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&key2);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = DIGICERT_readFile(pKeyFile, &pKeyBlob, &keyBlobLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pKeyBlob, keyBlobLen, NULL, &key1);
    if (OK != status)
        goto exit;

    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &key1, publicKeyInfoDer, &pSerializedKey1, &serializedKey1Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pSerializedKey1, serializedKey1Len, NULL, &key2);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_getKeyParametersAllocAux(MOC_ECC(gpHwAccelCtx)
        key1.key.pECC, &template1, MOC_GET_PUBLIC_KEY_DATA);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_getKeyParametersAllocAux(MOC_ECC(gpHwAccelCtx)
        key2.key.pECC, &template2, MOC_GET_PUBLIC_KEY_DATA);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    res = -1;
    status = DIGI_MEMCMP(template1.pPublicKey, template2.pPublicKey, template2.publicKeyLen, &res);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (0 != res)
    {
        status = ERR_CMP;
        retVal += UNITTEST_STATUS(hint, status);
        goto exit;
    }

    retVal += compareTwoKeys(&key1, &key2, hint);
    retVal += negativeTestEcc(&key1, &key2, hint);
    retVal += negativeTestQs(&key1, &key2, hint);
exit:
    CRYPTO_INTERFACE_EC_freeKeyTemplateAux(NULL, &template1);
    CRYPTO_INTERFACE_EC_freeKeyTemplateAux(NULL, &template2);
    CRYPTO_uninitAsymmetricKey(&key1, NULL);
    CRYPTO_uninitAsymmetricKey(&key2, NULL);

    if (NULL != pSerializedKey1)
        DIGI_FREE((void **) &pSerializedKey1);

    if (NULL != pKeyBlob)
        DIGI_FREE((void **) &pKeyBlob);

    return retVal;
}
#endif

static int testGetSetPrivKey(ubyte4 cipher)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 vStatus = 1;
    int hint = cipher;

    QS_CTX *pCtx1 = NULL;
    QS_CTX *pCtx2 = NULL;
    
    ubyte *pPri = NULL;
    ubyte4 priLen = 0;

    ubyte *pSig = NULL;
    ubyte4 sigLen = 0;

    ubyte pData[100];
    ubyte4 dataLen = 100;

    sbyte4 i = 0;

    /* set the data to random looking data */
    for (i = 0; i < dataLen; i++)
        pData[i] = (ubyte) (47 * (i + 1 + 2*hint)) & 0xff;

    /* Party 1 Begins */
    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(gpHwAccelCtx) &pCtx1, cipher);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_generateKeyPair(MOC_HASH(gpHwAccelCtx) pCtx1, RANDOM_rngFun, g_pRandomContext);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* We get and set the private key in another context and then roundtrip */
    status = CRYPTO_INTERFACE_QS_getPrivateKeyAlloc(pCtx1, &pPri, &priLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(gpHwAccelCtx) &pCtx2, cipher);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_setPrivateKey(pCtx2, pPri, priLen);    
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* party 2 signs the message */
    status = CRYPTO_INTERFACE_QS_SIG_signAlloc(MOC_HASH(gpHwAccelCtx) pCtx2, RANDOM_rngFun, g_pRandomContext, pData, dataLen, &pSig, &sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* party 1 verifies the message, use original ctx */
    status = CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(gpHwAccelCtx) pCtx1, pData, dataLen, pSig, sigLen, &vStatus);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (vStatus)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

exit:

    status = CRYPTO_INTERFACE_QS_deleteCtx(&pCtx1);
    retVal += UNITTEST_STATUS(hint, status);

    status = CRYPTO_INTERFACE_QS_deleteCtx(&pCtx2);
    retVal += UNITTEST_STATUS(hint, status);

    if (NULL != pPri)
    {
        status = DIGI_FREE((void **)&pPri);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pSig)
    {
        status = DIGI_FREE((void **)&pSig);
        retVal += UNITTEST_STATUS(hint, status);
    }

    return retVal;
}

static int testSig(ubyte4 cipher, ubyte *pContextStr, ubyte4 contextStrLen, byteBoolean stream)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 vStatus = 1;
    int hint = cipher;

    QS_CTX *pCtx1 = NULL;
    QS_CTX *pCtx2 = NULL;

    QS_CTX *pClone1 = NULL;
    QS_CTX *pClone2 = NULL;

    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;

    ubyte *pSig = NULL;
    ubyte4 sigLen = 0;

    ubyte pData[500];
    ubyte4 dataLen = 500;

    sbyte4 i = 0;

    /* set the data to random looking data */
    for (i = 0; i < dataLen; i++)
        pData[i] = (ubyte) (47 * (i + 1 + 2*hint)) & 0xff;

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

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
    if (stream)
    {
        status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pCtx1, &sigLen);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;        

        status = DIGI_MALLOC((void **) &pSig, sigLen);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_SIG_streamingInit(pCtx1, TRUE, 0, pContextStr, contextStrLen);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_SIG_streamingUpdate(pCtx1, pData, 200);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_SIG_streamingUpdate(pCtx1, pData + 200, 200);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_SIG_streamingUpdate(pCtx1, pData + 400, dataLen - 400);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_SIG_streamingSignFinal(pCtx1, RANDOM_rngFun, g_pRandomContext, pSig, sigLen, &sigLen);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_SIG_streamingInit(pCtx2, TRUE, 0, pContextStr, contextStrLen);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;
    
        status = CRYPTO_INTERFACE_QS_SIG_streamingUpdate(pCtx2, pData, 200);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_SIG_streamingUpdate(pCtx2, pData + 200, 200);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_SIG_streamingUpdate(pCtx2, pData + 400, dataLen - 400);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_SIG_streamingVerifyFinal(pCtx2, pSig, sigLen, &vStatus);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;
    }
    else
#endif
    {
        /* party 1 signs the message */
        status = CRYPTO_INTERFACE_QS_SIG_signAlloc(MOC_HASH(gpHwAccelCtx) pCtx1, RANDOM_rngFun, g_pRandomContext, pData, dataLen, &pSig, &sigLen);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        /* party 2 verifies the message, use original ctx */
        status = CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(gpHwAccelCtx) pCtx2, pData, dataLen, pSig, sigLen, &vStatus);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;
    }

    if (vStatus)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

    if (0 == contextStrLen)
    {
        /* party 2 verifies the message, use clone ctx */
        status = CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(gpHwAccelCtx) pClone2, pData, dataLen, pSig, sigLen, &vStatus);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        if (vStatus)
        {
            retVal += UNITTEST_STATUS(hint, -1); /* force error */
            goto exit;
        }

        /* reset signature and now use pClone1 */
        status = DIGI_MEMSET_FREE(&pSig, sigLen);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        /* party 1 signs the message */
        status = CRYPTO_INTERFACE_QS_SIG_signAlloc(MOC_HASH(gpHwAccelCtx) pClone1, RANDOM_rngFun, g_pRandomContext, pData, dataLen, &pSig, &sigLen);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        /* party 2 verifies the message, use original ctx */
        status = CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(gpHwAccelCtx) pCtx2, pData, dataLen, pSig, sigLen, &vStatus);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        if (vStatus)
        {
            retVal += UNITTEST_STATUS(hint, -1); /* force error */
            goto exit;
        }

        /* party 2 verifies the message, use clone ctx */
        status = CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(gpHwAccelCtx) pClone2, pData, dataLen, pSig, sigLen, &vStatus);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        if (vStatus)
        {
            retVal += UNITTEST_STATUS(hint, -1); /* force error */
            goto exit;
        }

        /* Negative test, change the message */

        pData[0] ^= 0xff;

        status = CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(gpHwAccelCtx) pCtx2, pData, dataLen, pSig, sigLen, &vStatus);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        if (!vStatus)
        {
            retVal += UNITTEST_STATUS(hint, -1); /* force error */
            goto exit;
        }

        /* Negative test, put the message back, change the signature */

        pData[0] ^= 0xff;
        pSig[0] ^= 0xff;

        status = CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(gpHwAccelCtx) pCtx2, pData, dataLen, pSig, sigLen, &vStatus);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        if (!vStatus)
        {
            retVal += UNITTEST_STATUS(hint, -1); /* force error */
            goto exit;
        }
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

    if (NULL != pSig)
    {
        status = DIGI_FREE((void **)&pSig);
        retVal += UNITTEST_STATUS(hint, status);
    }

    return retVal;
}

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
static int testSigPreHashMode(ubyte4 cipher, ubyte digestId, ubyte *pContextStr, ubyte4 contextStrLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 vStatus = 1;
    int hint = cipher;

    QS_CTX *pCtx1 = NULL;
    QS_CTX *pCtx2 = NULL;

    ubyte *pSig = NULL;
    ubyte4 sigLen = 0;

    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;

    ubyte pData[64];
    ubyte4 dataLen = 32;

    sbyte4 i = 0;

    if (ht_sha512 == digestId || ht_shake256 == digestId)
        dataLen = 64;

    /* set the data to random looking data */
    for (i = 0; i < dataLen; i++)
        pData[i] = (ubyte) (47 * (i + 1 + 2*hint)) & 0xff;

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

    /* party 1 signs the message, get sigLen and alloc buffer first */
    status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pCtx1, &sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;   

    status = DIGI_MALLOC((void **) &pSig, sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;    

    status = CRYPTO_INTERFACE_QS_SIG_signDigest(MOC_HASH(gpHwAccelCtx) pCtx1, RANDOM_rngFun, g_pRandomContext, digestId, pData, dataLen, pSig, sigLen, &sigLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* party 2 verifies the message, use original ctx */
    status = CRYPTO_INTERFACE_QS_SIG_verifyDigest(MOC_HASH(gpHwAccelCtx) pCtx2, digestId, pData, dataLen, pSig, sigLen, &vStatus);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (vStatus)
    {
        retVal += UNITTEST_STATUS(hint, -1); /* force error */
        goto exit;
    }

exit:
    status = CRYPTO_INTERFACE_QS_deleteCtx(&pCtx1);
    retVal += UNITTEST_STATUS(hint, status);

    status = CRYPTO_INTERFACE_QS_deleteCtx(&pCtx2);
    retVal += UNITTEST_STATUS(hint, status);

    if (NULL != pPub)
    {
        status = DIGI_FREE((void **)&pPub);
        retVal += UNITTEST_STATUS(hint, status);
    }

    if (NULL != pSig)
    {
        status = DIGI_FREE((void **)&pSig);
        retVal += UNITTEST_STATUS(hint, status);
    }

    return retVal;
}

static int testCompositeSig(ubyte4 compositeAlgByte, ubyte4 qsAlg, ubyte4 clAlg, ubyte *pDomain, ubyte4 domainLen, byteBoolean lenPrefixing)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 vStatus = 1;
    int hint = compositeAlgByte;

    AsymmetricKey key = {0};
    QS_CTX *pCtx = NULL;

    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(gpHwAccelCtx) &pCtx, qsAlg);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_generateKeyPair(MOC_HASH(gpHwAccelCtx) pCtx, RANDOM_rngFun, g_pRandomContext);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (clAlg < cid_RSA_2048_PKCS15) /* ECC */
    {
        status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(MOC_ECC(gpHwAccelCtx) clAlg, (void **) &key.key.pECC, RANDOM_rngFun, g_pRandomContext, akt_ecc, NULL);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        ubyte4 keySize = 2048;

        if (clAlg == cid_RSA_3072_PKCS15 || clAlg == cid_RSA_3072_PSS)
            keySize = 3072;
        else if (clAlg == cid_RSA_4096_PKCS15 || clAlg == cid_RSA_4096_PSS)
            keySize = 4096;

        status = CRYPTO_createRSAKey(&key, NULL);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_RSA_generateKey (MOC_RSA(gpHwAccelCtx) g_pRandomContext, key.key.pRSA, keySize, NULL);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;
    }

    /* change key type */
    key.type = akt_hybrid;
    key.clAlg = clAlg;
    key.pQsCtx = pCtx; pCtx = NULL;
 
    retVal += signVerifyComposite(hint, &key, &key, pDomain, domainLen, lenPrefixing);

exit:

    status = CRYPTO_uninitAsymmetricKey(&key, NULL);
    retVal += UNITTEST_STATUS(hint, status);

    if (NULL != pCtx)
    {
        status = CRYPTO_INTERFACE_QS_deleteCtx(&pCtx);
        retVal += UNITTEST_STATUS(hint, status);
    }

    return retVal;
}
#endif /* __ENABLE_DIGICERT_PQC_SIG_STREAMING__ */
#endif /* __ENABLE_DIGICERT_PQC_SIG__ */

/*----------------------------------------------------------------------------*/

int crypto_interface_qs_sig_test_init()
{
    int retVal = 0;

#if defined(__ENABLE_DIGICERT_PQC_SIG__)
    MSTATUS status;
    int i;
    ubyte pLongCtx[255] = {0xff, 0xfe, 0xfd, 0xfc, /* rest 0x00 ok */ };
    ubyte domain[4] = {0xaa, 0xbb, 0xcc, 0xdd};

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

    /* for oqs this tests rountrip of dilithium,
       not ml-dsa, and pre-hash and context will be ignored */
    retVal += testSig(cid_PQC_MLDSA_44, NULL, 0, FALSE);
    retVal += testSig(cid_PQC_MLDSA_65, NULL, 0, FALSE);
    retVal += testSig(cid_PQC_MLDSA_87, NULL, 0, FALSE);

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
    retVal += testSig(cid_PQC_MLDSA_44, NULL, 0, TRUE);
    retVal += testSig(cid_PQC_MLDSA_65, NULL, 0, TRUE);
    retVal += testSig(cid_PQC_MLDSA_87, NULL, 0, TRUE);
    retVal += testSig(cid_PQC_MLDSA_44, pLongCtx, 255, TRUE);
    retVal += testSig(cid_PQC_MLDSA_65, (ubyte *) "My Signer", 9, TRUE);
    retVal += testSig(cid_PQC_MLDSA_87, (ubyte *) "A", 1, TRUE);
#endif

    retVal += testGetSetPrivKey(cid_PQC_MLDSA_44);
    retVal += testGetSetPrivKey(cid_PQC_MLDSA_65);
    retVal += testGetSetPrivKey(cid_PQC_MLDSA_87);

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
    retVal += testSigPreHashMode(cid_PQC_MLDSA_44, ht_sha256, NULL, 0);
    retVal += testSigPreHashMode(cid_PQC_MLDSA_44, ht_sha512, pLongCtx, 255);
    retVal += testSigPreHashMode(cid_PQC_MLDSA_44, ht_shake128, (ubyte *) "My Signer", 9);

    /* For 65 and 87 digest needs to be at least 384 or 512 bit outputs, sha512 is only option */
    retVal += testSigPreHashMode(cid_PQC_MLDSA_65, ht_sha512, pLongCtx, 1);
    retVal += testSigPreHashMode(cid_PQC_MLDSA_87, ht_sha512, NULL, 0);
#endif

#ifdef __ENABLE_DIGICERT_SIG_OQS_FALCON__
    retVal += testSig(cid_PQC_FNDSA_512, NULL, 0, FALSE);
    retVal += testSig(cid_PQC_FNDSA_1024, NULL, 0, FALSE);
#endif

    retVal += testSig(cid_PQC_SLHDSA_SHA2_128F, NULL, 0, FALSE);
    retVal += testSig(cid_PQC_SLHDSA_SHAKE_128F, NULL, 0, FALSE);
#ifndef __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__
    retVal += testSig(cid_PQC_SLHDSA_SHA2_128S, NULL, 0, FALSE);
    retVal += testSig(cid_PQC_SLHDSA_SHAKE_128S, NULL, 0, FALSE);
    retVal += testSig(cid_PQC_SLHDSA_SHA2_192S, NULL, 0, FALSE);
    retVal += testSig(cid_PQC_SLHDSA_SHA2_192F, NULL, 0, FALSE);
    retVal += testSig(cid_PQC_SLHDSA_SHAKE_192S, NULL, 0, FALSE);
    retVal += testSig(cid_PQC_SLHDSA_SHAKE_192F, NULL, 0, FALSE);
    retVal += testSig(cid_PQC_SLHDSA_SHA2_256S, NULL, 0, FALSE);
    retVal += testSig(cid_PQC_SLHDSA_SHA2_256F, NULL, 0, FALSE);
    retVal += testSig(cid_PQC_SLHDSA_SHAKE_256S, NULL, 0, FALSE);
    retVal += testSig(cid_PQC_SLHDSA_SHAKE_256F, NULL, 0, FALSE);
#endif

/* TODO can be uncommented once the proper pre hash mode APIs are added to SLHDSA
    retVal += testSigPreHashMode(cid_PQC_SLHDSA_SHA2_128S, ht_shake128, "My Signer", 9);
    retVal += testSigPreHashMode(cid_PQC_SLHDSA_SHA2_128F, ht_sha256, NULL, 0);
    retVal += testSigPreHashMode(cid_PQC_SLHDSA_SHAKE_128S, ht_sha512, pLongCtx, 255);
    retVal += testSigPreHashMode(cid_PQC_SLHDSA_SHAKE_128F, ht_shake256, "My Signer", 9);

    /* for 192 and 256 bit security strengths we can only use 512 bit hash outputs 
    retVal += testSigPreHashMode(cid_PQC_SLHDSA_SHA2_192S, ht_sha512, pLongCtx, 255);
    retVal += testSigPreHashMode(cid_PQC_SLHDSA_SHA2_192F, ht_shake256, "1", 1);
    retVal += testSigPreHashMode(cid_PQC_SLHDSA_SHAKE_192S, ht_sha512, NULL, 0);
    retVal += testSigPreHashMode(cid_PQC_SLHDSA_SHAKE_192F, ht_shake256, "My Signer", 9);

    retVal += testSigPreHashMode(cid_PQC_SLHDSA_SHA2_256S, ht_shake256, pLongCtx, 255);
    retVal += testSigPreHashMode(cid_PQC_SLHDSA_SHA2_256F, ht_sha512, "1", 1);
    retVal += testSigPreHashMode(cid_PQC_SLHDSA_SHAKE_256S, ht_shake256, NULL, 0);
    retVal += testSigPreHashMode(cid_PQC_SLHDSA_SHAKE_256F, ht_sha512, pLongCtx, 255); */

    /* once we checkout oqs with mldsa we can remove this ifndef */
#ifndef __ENABLE_DIGICERT_SIG_OQS_DILITHIUM__
#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
    retVal += testCompositeSig(60, cid_PQC_MLDSA_44, cid_RSA_2048_PSS, NULL, 0, FALSE);
    retVal += testCompositeSig(60, cid_PQC_MLDSA_44, cid_RSA_2048_PSS, NULL, 0, TRUE);
    retVal += testCompositeSig(60, cid_PQC_MLDSA_44, cid_RSA_2048_PSS, domain, 4, FALSE);
    retVal += testCompositeSig(60, cid_PQC_MLDSA_44, cid_RSA_2048_PSS, domain, 4, TRUE);

    retVal += testCompositeSig(61, cid_PQC_MLDSA_44, cid_RSA_2048_PKCS15, NULL, 0, FALSE);
    retVal += testCompositeSig(62, cid_PQC_MLDSA_44, cid_EC_Ed25519, NULL, 0, FALSE);

    retVal += testCompositeSig(63, cid_PQC_MLDSA_44, cid_EC_P256, NULL, 0, FALSE);
    retVal += testCompositeSig(63, cid_PQC_MLDSA_44, cid_EC_P256, NULL, 0, TRUE);
    retVal += testCompositeSig(63, cid_PQC_MLDSA_44, cid_EC_P256, domain, 4, FALSE);
    retVal += testCompositeSig(63, cid_PQC_MLDSA_44, cid_EC_P256, domain, 4, TRUE);

#ifndef __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__
    retVal += testCompositeSig(64, cid_PQC_MLDSA_65, cid_RSA_3072_PSS, NULL, 0, FALSE);
    retVal += testCompositeSig(65, cid_PQC_MLDSA_65, cid_RSA_3072_PKCS15, NULL, 0, FALSE);
    retVal += testCompositeSig(66, cid_PQC_MLDSA_65, cid_RSA_4096_PSS, NULL, 0, FALSE);
    retVal += testCompositeSig(67, cid_PQC_MLDSA_65, cid_RSA_4096_PKCS15, NULL, 0, FALSE);
#endif
    retVal += testCompositeSig(68, cid_PQC_MLDSA_65, cid_EC_P256, NULL, 0, FALSE);
    retVal += testCompositeSig(69, cid_PQC_MLDSA_65, cid_EC_P384, NULL, 0, FALSE);
    retVal += testCompositeSig(71, cid_PQC_MLDSA_65, cid_EC_Ed25519, NULL, 0, FALSE);
    retVal += testCompositeSig(72, cid_PQC_MLDSA_87, cid_EC_P384, NULL, 0, FALSE);

    retVal += testCompositeSig(74, cid_PQC_MLDSA_87, cid_EC_Ed448, NULL, 0, TRUE);
    retVal += testCompositeSig(74, cid_PQC_MLDSA_87, cid_EC_Ed448, NULL, 0, FALSE);
    retVal += testCompositeSig(74, cid_PQC_MLDSA_87, cid_EC_Ed448, domain, 4, TRUE);
    retVal += testCompositeSig(74, cid_PQC_MLDSA_87, cid_EC_Ed448, domain, 4, FALSE);
#ifndef __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__
    retVal += testCompositeSig(75, cid_PQC_MLDSA_87, cid_RSA_4096_PSS, NULL, 0, FALSE);
#endif
    retVal += hybridSerializationTest(60, "mldsa44_rsa2048_pss.der");
    retVal += hybridSerializationTest(61, "mldsa44_rsa2048_pkcs15.der");
    retVal += hybridSerializationTest(62, "mldsa44_ed25519.der");
    retVal += hybridSerializationTest(63, "mldsa44_p256.der");
    retVal += hybridSerializationTest(64, "mldsa65_rsa3072_pss.der");
    retVal += hybridSerializationTest(65, "mldsa65_rsa3072_pkcs15.der");
    retVal += hybridSerializationTest(66, "mldsa65_rsa4096_pss.der");
    retVal += hybridSerializationTest(67, "mldsa65_rsa4096_pkcs15.der");
    retVal += hybridSerializationTest(68, "mldsa65_p256.der");
    retVal += hybridSerializationTest(69, "mldsa65_p384.der");
    retVal += hybridSerializationTest(71, "mldsa65_ed25519.der");
    retVal += hybridSerializationTest(72, "mldsa87_p384.der");
    retVal += hybridSerializationTest(74, "mldsa87_ed448.der");
    retVal += hybridSerializationTest(75, "mldsa87_rsa4096_pss.der");
#endif
 /* retVal += hybridPubKeySerializationTest(255, "mldsa65_256.der"); */
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
