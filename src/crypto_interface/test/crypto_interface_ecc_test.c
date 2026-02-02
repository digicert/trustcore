/*
 * crypto_interface_ecc_test.c
 *
 * Unit test for ECC.
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
#include "../../crypto/ecc.h"

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__
/* speed test headers */
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <stdio.h>

#define SIGN_ITERATIONS         1000
#define VERIFY_ITERATIONS       10000
#define SERIALIZE_ITERATIONS    1000000
#define DESERIALIZE_ITERATIONS  1000000

#endif

static MocCtx gpMocCtx = NULL;
static ubyte *gpKValue = NULL;
static ubyte4 gKValueLen = 0;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

/*----------------------------------------------------------------------------*/

/* custom random function that isn't random, it provides buffer
 * with the correct K value for known vector tests. */
sbyte4 RANDOM_testRngFun(void *rngFunArg, ubyte4 length, ubyte *buffer)
{

    sbyte4 copied = 0;
    int kLength = gKValueLen;
    int i = 0;

    if (length < kLength)
    {
        return ERR_RAND;
    }
    for (; i < length; ++i)
    {
#if defined(__ENABLE_DIGICERT_ECC_P256_MBED__)
        buffer[i] = gpKValue[i];
#else
        buffer[length - i - 1] = gpKValue[i];
#endif
        copied++;
    }

    return OK;
}


/*------------------------------------------------------------------*/

MSTATUS getEccPubsFromPris (
    ECCKey *pKey1,
    ECCKey *pKey2,
    ECCKey **ppNewPubKey1,
    ECCKey **ppNewPubKey2
)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pPubData1 = NULL;
    ubyte *pPubData2 = NULL;
    ECCKey *pNewPubKey1 = NULL;
    ECCKey *pNewPubKey2 = NULL;
    sbyte4 cmp = 667;
    ubyte4 curveId = 0, pLen = 0;

    /* Get the curve id */
    status = EC_getCurveIdFromKey(pKey1, &curveId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Get the public key length */
    status = EC_getPointByteStringLenEx(pKey1, &pLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&pPubData1, pLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Write just the public data to a buffer */
    status = EC_writePublicKeyToBuffer(MOC_ECC(gpHwAccelCtx) pKey1, pPubData1, pLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Now get the public data from key2 */
    status = DIGI_MALLOC((void **)&pPubData2, pLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Write just the public data to a buffer */
    status = EC_writePublicKeyToBuffer(MOC_ECC(gpHwAccelCtx) pKey2, pPubData2, pLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pPubData1, pPubData2, pLen, &cmp);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmp)
    {
        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Now make keys from the public data */
    status = EC_newPublicKeyFromByteString(MOC_ECC(gpHwAccelCtx) curveId, &pNewPubKey1, pPubData1, pLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_newPublicKeyFromByteString(MOC_ECC(gpHwAccelCtx) curveId, &pNewPubKey2, pPubData2, pLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    *ppNewPubKey1 = pNewPubKey1;
    *ppNewPubKey2 = pNewPubKey2;

exit:

    if (NULL != pPubData1)
    {
        DIGI_FREE((void **)&pPubData1);
    }
    if (NULL != pPubData2)
    {
        DIGI_FREE((void **)&pPubData2);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS testEccSignVerifyDigest (
    ECCKey *pSignKey,
    ECCKey *pVerifyKey,
    ubyte *pHash,
    ubyte4 hashLen,
    ubyte *pSig,
    ubyte4 eLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 sLen = 0, vfy = 1;

    /* get length of an element for calculating signature length */
    status = EC_getElementByteStringLen(pSignKey, &sLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(eLen != sLen)
    {
        /* This error status can be improved */
        status = ERR_INVALID_ARG;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* signature is 2x the size of an element */
    sLen = 2*sLen;

    status = ECDSA_signDigest (MOC_ECC(gpHwAccelCtx)
        pSignKey, RANDOM_rngFun, g_pRandomContext, pHash, hashLen, pSig, sLen, &sLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = ECDSA_verifySignatureDigest (MOC_ECC(gpHwAccelCtx)
        pVerifyKey, pHash, hashLen, pSig, eLen, pSig + eLen, eLen, &vfy);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if (0 != vfy)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* alter the value of the first byte of the S value of signature for a negative test */
    pSig[eLen] = (1 + pSig[eLen]);

    status = ECDSA_verifySignatureDigest (MOC_ECC(gpHwAccelCtx)
        pVerifyKey, pHash, hashLen, pSig, eLen, pSig + eLen, eLen, &vfy);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if (0 == vfy)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    /* zero buffer, this might want to be in other function */
    if(NULL != pSig)
    {
        DIGI_MEMSET(pSig, 0, (2 * eLen));
    }
    return status;
}

/*------------------------------------------------------------------*/

MSTATUS testEccSignVerify (
    ECCKey *pSignKey,
    ECCKey *pVerifyKey,
    ubyte *pHash,
    ubyte4 hashLen,
    ubyte *pSig,
    ubyte4 eLen
    )
{
    MSTATUS status;

    status = testEccSignVerifyDigest (
        pSignKey, pVerifyKey, pHash, hashLen, pSig, eLen);
    if (OK != status)
        goto exit;

exit:
    return status;
}

/*------------------------------------------------------------------*/

MSTATUS testTwoSignVerify (
    ECCKey *pKey1,
    ECCKey *pKey2,
    ubyte *pHash,
    ubyte4 hashLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 eLen = 0, sLen = 0;
    ubyte *pSig = NULL;
    ECCKey *pPubKey1 = NULL;
    ECCKey *pPubKey2 = NULL;


    /* Get element length to calculate signature length with */
    status = EC_getElementByteStringLen(pKey1, &eLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Allocate enough space for the DER encoded signature */
    sLen = (eLen * 2) + 9;
    status = DIGI_MALLOC((void **)&pSig, sLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Sign with key1, verify with key2 */
    status = testEccSignVerify(pKey1, pKey2, pHash, hashLen, pSig, eLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Now the other way around */
    status = testEccSignVerify(pKey2, pKey1, pHash, hashLen, pSig, eLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = getEccPubsFromPris(pKey1, pKey2, &pPubKey1, &pPubKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Sign private key1, verify public key1 */
    status = testEccSignVerify(pKey1, pPubKey1, pHash, hashLen, pSig, eLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Sign private key2, verify public key2 */
    status = testEccSignVerify(pKey2, pPubKey2, pHash, hashLen, pSig, eLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Sign private key1, verify public key2 */
    status = testEccSignVerify(pKey1, pPubKey2, pHash, hashLen, pSig, eLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Sign private key2, verify public key1 */
    status = testEccSignVerify(pKey2, pPubKey1, pHash, hashLen, pSig, eLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

exit:

    if (NULL != pPubKey1)
    {
        EC_deleteKeyEx(&pPubKey1);
    }
    if (NULL != pPubKey2)
    {
        EC_deleteKeyEx(&pPubKey2);
    }
    if (NULL != pSig)
    {
        DIGI_FREE((void **)&pSig);
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS testTwoEcdh (
    ECCKey *pKey1,
    ECCKey *pKey2
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmp = 1;
    ubyte4 sLen1 = 0, sLen2 = 0;
    ECCKey *pPubKey1 = NULL;
    ECCKey *pPubKey2 = NULL;
    ubyte *pOrigSecret = NULL;
    ubyte *pSecret1 = NULL;
    ubyte *pSecret2 = NULL;

    /* ECDH using original keys */
    status = ECDH_generateSharedSecretFromKeys ( MOC_ECC(gpHwAccelCtx)
        pKey1, pKey2, &pSecret1, &sLen1, 1, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = ECDH_generateSharedSecretFromKeys ( MOC_ECC(gpHwAccelCtx)
        pKey2, pKey1, &pSecret2, &sLen2, 1, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if (sLen1 != sLen2)
    {
        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    cmp = 1;
    status = DIGI_MEMCMP(pSecret1, pSecret2, sLen1, &cmp);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if (0 != cmp)
    {
        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Allocate buffer for original secret  */
    status = DIGI_MALLOC((void **)&pOrigSecret, sLen1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* copy the secret over to buffer we created */
    status = DIGI_MEMCPY(pOrigSecret, pSecret1, sLen1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* zero buffers so we can reuse them */
    status = DIGI_MEMSET(pSecret1, 0, sLen1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status =DIGI_MEMSET(pSecret2, 0, sLen2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_FREE((void **) &pSecret1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_FREE((void **) &pSecret2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = getEccPubsFromPris(pKey1, pKey2, &pPubKey1, &pPubKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* ECDH using separate public keys */
    status = ECDH_generateSharedSecretFromKeys ( MOC_ECC(gpHwAccelCtx)
        pKey1, pPubKey2, &pSecret1, &sLen1, 1, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = ECDH_generateSharedSecretFromKeys ( MOC_ECC(gpHwAccelCtx)
        pKey2, pPubKey1, &pSecret2, &sLen2, 1, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if (sLen1 != sLen2)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* compare the secret1 and secret2 are still the same */
    cmp = 1;
    status = DIGI_MEMCMP(pSecret1, pSecret2, sLen1, &cmp);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if (0 != cmp)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* This should match the original secret */
    cmp = 1;
    status = DIGI_MEMCMP(pSecret1, pOrigSecret, sLen1, &cmp);
    if (OK != status)
      goto exit;

    if (0 != cmp)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }


exit:

    if (NULL != pPubKey1)
    {
        EC_deleteKeyEx(&pPubKey1);
    }
    if (NULL != pPubKey2)
    {
        EC_deleteKeyEx(&pPubKey2);
    }
    if (NULL != pSecret1)
    {
        DIGI_MEMSET(pSecret1, 0, sLen1);
        DIGI_FREE((void **)&pSecret1);
    }
    if (NULL != pSecret2)
    {
        DIGI_MEMSET(pSecret2, 0, sLen2);
        DIGI_FREE((void **)&pSecret2);
    }
    if (NULL != pOrigSecret)
    {
        DIGI_MEMSET(pOrigSecret, 0, sLen1);
        DIGI_FREE((void **)&pOrigSecret);
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS testTwoEqual (
    ECCKey *pKey1,
    ECCKey *pKey2,
    ubyte4 otherCurveId
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    byteBoolean res = FALSE;
    sbyte4 cmp = 1;
    ubyte4 curveId = 0;
    MEccKeyTemplate template1;
    MEccKeyTemplate template2;
    ECCKey *pNewKey1 = NULL;
    ECCKey *pNewKey2 = NULL;

    /* These keys should be equal */
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey1, pKey2, &res);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if (FALSE == res)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = EC_cloneKeyEx(MOC_ECC(gpHwAccelCtx) &pNewKey1, pKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = EC_cloneKeyEx(MOC_ECC(gpHwAccelCtx) &pNewKey2, pKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* All of these keys should be equal */
    res = FALSE;
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey1, pNewKey1, &res);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if (FALSE == res)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    res = FALSE;
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey2, pNewKey2, &res);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;


    if (FALSE == res)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    res = FALSE;
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey1, pNewKey2, &res);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if (FALSE == res)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
    res = FALSE;
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey2, pNewKey1, &res);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if (FALSE == res)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    res = FALSE;
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pNewKey1, pNewKey2, &res);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (FALSE == res)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }


    status = EC_deleteKeyEx(&pNewKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* make sure EC_delete set pointer to null */
    if(NULL != pNewKey1)
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = EC_deleteKeyEx(&pNewKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* make sure EC_delete set pointer to null */
    if(NULL != pNewKey2)
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Get the curve id */
    status = EC_getCurveIdFromKey(pKey1, &curveId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if(curveId != otherCurveId)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Get the key data out */
    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) pKey1, &template1, MOC_GET_PRIVATE_KEY_DATA);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Get data from key2 */
    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) pKey2, &template2, MOC_GET_PRIVATE_KEY_DATA);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Ensure lengths match */
    if (template1.publicKeyLen != template2.publicKeyLen)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (template1.privateKeyLen != template2.privateKeyLen)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Ensure values match */
    cmp = 1;
    status = DIGI_MEMCMP(template1.pPublicKey, template2.pPublicKey, template1.publicKeyLen, &cmp);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if (0 != cmp)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    cmp = 1;
    status = DIGI_MEMCMP(template1.pPrivateKey, template2.pPrivateKey, template1.privateKeyLen, &cmp);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if (0 != cmp)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Allocate memory for key1 */
    status = EC_newKeyEx(curveId, &pNewKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Set key values for key1 using template1 */
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx)
        pNewKey1, template1.pPublicKey, template1.publicKeyLen,
        template1.pPrivateKey, template1.privateKeyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Allocate memory for key 2 */
    status = EC_newKeyEx(curveId, &pNewKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Set key values for key2 using template2 */
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx)
        pNewKey2, template2.pPublicKey, template2.publicKeyLen,
        template2.pPrivateKey, template2.privateKeyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* All of these keys should be equal */
    res = FALSE;
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey1, pNewKey1, &res);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    if (FALSE == res)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    res = FALSE;
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey2, pNewKey2, &res);
    if (OK != status)
      goto exit;

    if (FALSE == res)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    res = FALSE;
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey1, pNewKey2, &res);
    if (OK != status)
      goto exit;

    if (FALSE == res)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    res = FALSE;
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey2, pNewKey1, &res);
    if (OK != status)
      goto exit;

    if (FALSE == res)
    {

        status = ERR_EC;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pNewKey1)
    {

        EC_deleteKeyEx(&pNewKey1);
    }
    if (NULL != pNewKey2)
    {
        EC_deleteKeyEx(&pNewKey2);
    }

    if((NULL != pKey1))
    {
        EC_freeKeyTemplate(pKey1, &template1);
    }

    if((NULL != pKey2))
    {
        EC_freeKeyTemplate(pKey2, &template2);
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS testTwoEcc (
    ECCKey *pKey1,
    ECCKey *pKey2,
    ubyte4 curveId,
    ubyte *pDigest,
    ubyte4 digestLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    /*  not using UNITTEST_STATUS here because all three of these functions
        a print the line that caused the bad status */
    status = testTwoEqual(pKey1, pKey2, curveId);
    if (OK != status)
      goto exit;

    status = testTwoSignVerify(pKey1, pKey2, pDigest, digestLen);
    if (OK != status)
      goto exit;

    status = testTwoEcdh(pKey1, pKey2);

exit:
    return status;
}

MSTATUS eccFunctionalTests(ubyte4 curveId, ubyte* pDigest, ubyte4 digestLen)
{
    MSTATUS status = ERR_NULL_POINTER, fstatus;
    ubyte4 eLen = 0, serialLen = 0;
    AsymmetricKey asymKey1;
    AsymmetricKey asymKey2;
    ubyte *pSerialData = NULL;
    ECCKey *pKey1 = NULL;
    ECCKey *pKey2 = NULL;
    MEccKeyTemplate template1;
    MKeySerialize pSupported[1] = {
        KeySerializeEcc
    };

    /* Create an empty key */
    status = EC_newKeyEx(curveId, &pKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = EC_getElementByteStringLen(pKey1, &eLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Generate a new keypair */
    status = EC_generateKeyPairEx(MOC_ECC(gpHwAccelCtx) pKey1, RANDOM_rngFun, g_pRandomContext);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Clone this key */
    status = EC_cloneKeyEx(MOC_ECC(gpHwAccelCtx) &pKey2, pKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Test the cloned key */
    status = testTwoEcc(pKey1, pKey2, curveId, pDigest, digestLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = EC_deleteKeyEx(&pKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Get the key data out */
    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) pKey1, &template1, MOC_GET_PRIVATE_KEY_DATA);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Create another key shell on the same curve */
    status = EC_newKeyEx(curveId, &pKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Make a copy of key1 into key2 */
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx)
        pKey2, template1.pPublicKey, template1.publicKeyLen,
        template1.pPrivateKey, template1.privateKeyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Test the copied key */
    status = testTwoEcc(pKey1, pKey2, curveId, pDigest, digestLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = EC_deleteKeyEx(&pKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_initAsymmetricKey(&asymKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_initAsymmetricKey(&asymKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_loadAsymmetricKey(&asymKey1, akt_ecc, (void **)&pKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = EC_cloneKeyEx(MOC_ECC(gpHwAccelCtx) &pKey1, asymKey1.key.pECC);
    if (OK != status)
      goto exit;

    status = CRYPTO_serializeKey ( MOC_ASYM(gpHwAccelCtx)
        &asymKey1, pSupported, 1, privateKeyInfoDer, &pSerialData, &serialLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_deserializeKey ( MOC_ASYM(gpHwAccelCtx)
        pSerialData, serialLen, pSupported, 1, &asymKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Test the deserialized key */
    status = testTwoEcc(asymKey1.key.pECC, asymKey2.key.pECC, curveId, pDigest, digestLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = DIGI_FREE((void **)&pSerialData);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_initAsymmetricKey(&asymKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_serializeKey ( MOC_ASYM(gpHwAccelCtx)
        &asymKey1, pSupported, 1, mocanaBlobVersion2, &pSerialData, &serialLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_deserializeKey ( MOC_ASYM(gpHwAccelCtx)
        pSerialData, serialLen, pSupported, 1, &asymKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Test the deserialized key */
    status = testTwoEcc(asymKey1.key.pECC, asymKey2.key.pECC, curveId, pDigest, digestLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = DIGI_FREE((void **)&pSerialData);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

exit:

    fstatus = EC_freeKeyTemplate(pKey1, &template1);
    if (OK == status)
        status = fstatus;

    fstatus = CRYPTO_uninitAsymmetricKey(&asymKey1, NULL);
    if (OK == status)
        status = fstatus;

    if (NULL != pKey1)
    {
        fstatus = EC_deleteKeyEx(&pKey1);
        if (OK == status)
            status = fstatus;
    }
    if (NULL != pKey2)
    {
        fstatus = EC_deleteKeyEx(&pKey2);
        if (OK == status)
            status = fstatus;
    }



    /* If status is not OK, this test failed, return 1 to add to errorCount */
    if(OK != status)
        return 1;
    return 0;
}


/*----------------------------------------------------------------------------*/

int eccTest(ubyte4 curveId)
{
    MSTATUS status = ERR_NULL_POINTER;

    unsigned char pK[] = {
        0xa6, 0xe3, 0xc5, 0x7d, 0xd0, 0x1a, 0xbe, 0x90, 0x08, 0x65, 0x38, 0x39,
        0x83, 0x55, 0xdd, 0x4c, 0x3b, 0x17, 0xaa, 0x87, 0x33, 0x82, 0xb0, 0xf2,
        0x4d, 0x61, 0x29, 0x49, 0x3d, 0x8a, 0xad, 0x60
    };
    unsigned int kLen = 32;

    unsigned char pP[] = {
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57,
        0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
        0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21
    };
    unsigned int pLen = 32;
    unsigned int rLen = 32;
    unsigned int sLen = 32;

    /* first byte is the compression byte, followed by X value, then Y value
     * of the public key */
    ubyte pPoint[] = {
        0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb,
        0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa,
        0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe,
        0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc,
        0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2,
        0x94, 0xd4, 0x46, 0x22, 0x99
    };
    ubyte4 pointLen = 65;

    /* sha256 hash value of the unicode octet string "sample" without quotes */
    unsigned char pHash[] = {
        0xaf, 0x2b, 0xdb, 0xe1, 0xaa, 0x9b, 0x6e, 0xc1, 0xe2, 0xad, 0xe1, 0xd6,
        0x94, 0xf4, 0x1f, 0xc7, 0x1a, 0x83, 0x1d, 0x02, 0x68, 0xe9, 0x89, 0x15,
        0x62, 0x11, 0x3d, 0x8a, 0x62, 0xad, 0xd1, 0xbf
    };
    unsigned int hashLen = 32;
    ubyte4 vfy = 1;

    /* set k values */
    gKValueLen = kLen;
    gpKValue = pK;
    ECCKey *pKey = NULL;
    /* message that will hashed for signature */

    /* variables used for computing and comparing signatures */
    ubyte pSignature[64] = { 0 };
    ubyte4 signatureLen = 64;

    status = EC_newKeyEx(curveId, &pKey);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen, pP, pLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }
    status = ECDSA_signDigest(MOC_ECC(gpHwAccelCtx) pKey, RANDOM_testRngFun, g_pRandomContext, pHash,
                              hashLen, pSignature, signatureLen, &signatureLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* we don't seed the RNG here so we don't do comparison of expected r and s values */

    status = ECDSA_verifySignatureDigest(MOC_ECC(gpHwAccelCtx) pKey, pHash, hashLen, pSignature, rLen, pSignature+rLen, sLen, &vfy);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if(0 != vfy)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
exit:
    if(NULL != pKey)
    {
        EC_deleteKeyEx(&pKey);
    }
    if (OK > status)
        return 1;
    return 0;
}


/*------------------------------------------------------------------*/

int testEccLengthByCurveId(ubyte4 curveId)
{
    MSTATUS status;
    ECCKey *pKey = NULL;
    ubyte4 curveId2 = 0, length = 0, length2 = 0;

    status = EC_getPointByteStringLenByCurveId (curveId, &length);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = EC_newKeyEx(curveId, &pKey);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = EC_getCurveIdFromKey(pKey, &curveId2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if (curveId != curveId2)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
    status = EC_getPointByteStringLenEx(pKey, &length2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if (length != length2)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    if(NULL != pKey)
    {
        EC_deleteKeyEx(&pKey);
    }
    if (OK > status)
        return 1;
    return 0;
}

int testEccLengthByCurveIdAll()
{
    ubyte4 errorCount = 0;
    
#ifdef __ENABLE_DIGICERT_ECC_P192__
    errorCount = testEccLengthByCurveId(cid_EC_P192);
#endif

#ifndef __DISABLE_DIGICERT_ECC_P224__
    errorCount += testEccLengthByCurveId(cid_EC_P224);
#endif

#ifndef __DISABLE_DIGICERT_ECC_P256__
    errorCount += testEccLengthByCurveId(cid_EC_P256);
#endif

#ifndef __DISABLE_DIGICERT_ECC_P384__
    errorCount += testEccLengthByCurveId(cid_EC_P384);
#endif

#ifndef __DISABLE_DIGICERT_ECC_P521__
    errorCount += testEccLengthByCurveId(cid_EC_P521);
#endif

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    errorCount += testEccLengthByCurveId(cid_EC_X25519);
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
    errorCount += testEccLengthByCurveId(cid_EC_Ed25519);
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    errorCount += testEccLengthByCurveId(cid_EC_X448);
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
    errorCount += testEccLengthByCurveId(cid_EC_Ed448);
#endif
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ */

    return errorCount;
}


/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__

int testEccSpeed(ubyte4 curveId)
{

    MSTATUS status = ERR_NULL_POINTER;
    ECCKey *pKey1 = NULL;
    ubyte4 eLen = 0;

    unsigned char pHash[] = {
        0xaf, 0x2b, 0xdb, 0xe1, 0xaa, 0x9b, 0x6e, 0xc1, 0xe2, 0xad, 0xe1, 0xd6,
        0x94, 0xf4, 0x1f, 0xc7, 0x1a, 0x83, 0x1d, 0x02, 0x68, 0xe9, 0x89, 0x15,
        0x62, 0x11, 0x3d, 0x8a, 0x62, 0xad, 0xd1, 0xbf
    };
    unsigned int hashLen = 32;
    ubyte *pSig = NULL;
    ubyte *pSerialData = NULL;
    ubyte4 sigLen = 0, serialLen = 0;
    sbyte4 vfy = -1;

    int i;
    struct tms tstart;
    struct tms tend;
    double diffTime;

    ubyte *pOutputFormat = "%-25s: %5g seconds\n";
    FILE *fp = NULL;
    AsymmetricKey asymKey1;
    AsymmetricKey asymKey2;

    MKeySerialize pSupported[1] = {
        KeySerializeEcc
    };

    /* file to save times in */
    if(NULL == (fp = fopen(
        "../../../projects/cryptointerface_unittest/speed_test.txt", "a")))
        goto exit;

    /* Create an empty key */
    status = EC_newKeyEx(curveId, &pKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = EC_getElementByteStringLen(pKey1, &eLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = DIGI_MALLOC((void**)&pSig, 2*eLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    sigLen = 2*eLen;

    /* Generate a new keypair */
    status = EC_generateKeyPairEx(MOC_ECC(gpHwAccelCtx) pKey1, RANDOM_rngFun, g_pRandomContext);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    times(&tstart);
    for(i = 0;i < SIGN_ITERATIONS; i++){
        status = ECDSA_signDigest (MOC_ECC(gpHwAccelCtx)
            pKey1, RANDOM_rngFun, g_pRandomContext, pHash, hashLen, pSig,
            sigLen, &sigLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
        goto exit;
    }
    times(&tend);
    diffTime = tend.tms_utime - tstart.tms_utime;
    fprintf(fp, pOutputFormat, "ecc sign speed", 
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "ecc sign speed", 
        diffTime / sysconf(_SC_CLK_TCK));

    times(&tstart);
    for(i = 0;i < VERIFY_ITERATIONS; i++){
        status = ECDSA_verifySignatureDigest (MOC_ECC(gpHwAccelCtx)
            pKey1, pHash, hashLen, pSig, eLen, pSig + eLen, eLen, &vfy);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
          goto exit;
    }
    times(&tend);
    diffTime = tend.tms_utime - tstart.tms_utime;
    fprintf(fp, pOutputFormat, "ecc verify speed", 
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "ecc verify speed", 
        diffTime / sysconf(_SC_CLK_TCK));

    status = CRYPTO_initAsymmetricKey(&asymKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_initAsymmetricKey(&asymKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;


    status = CRYPTO_loadAsymmetricKey(&asymKey1, akt_ecc, (void **)&pKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    times(&tstart);
    for(i = 0;i < SERIALIZE_ITERATIONS; i++){
        status = CRYPTO_serializeKey ( MOC_ASYM(gpHwAccelCtx)
            &asymKey1, pSupported, 1, privateKeyInfoDer, &pSerialData, 
            &serialLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
          goto exit;
    }
    times(&tend);
    diffTime = tend.tms_utime - tstart.tms_utime;
    fprintf(fp, pOutputFormat, "ecc serialize speed", 
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "ecc serialize speed", 
            diffTime / sysconf(_SC_CLK_TCK));

    times(&tstart);
    for(i = 0;i < DESERIALIZE_ITERATIONS; i++){
        status = CRYPTO_deserializeKey ( MOC_ASYM(gpHwAccelCtx)
            pSerialData, serialLen, pSupported, 1, &asymKey2);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
          goto exit;
    }
    times(&tend);
    diffTime = tend.tms_utime - tstart.tms_utime;
    fprintf(fp, pOutputFormat, "ecc deserialize speed", 
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "ecc deserialize speed", 
            diffTime / sysconf(_SC_CLK_TCK));

exit:
    if(NULL != fp)
        fclose(fp);
    if(OK != status)
        return 1;
    return 0;
}
#endif


/*------------------------------------------------------------------*/

int crypto_interface_ecc_test_init()
{

    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;

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

    /* Do not use a buffer of all zero as the hash value, there appears to be a
     * bug in mbedtls for that particular case */
    ubyte pSha1Digest[20] = {1};
    ubyte pSha224Digest[28] = {1};
    ubyte pSha256Digest[32] = {1};
    ubyte pSha384Digest[48] = {1};
    ubyte pSha512Digest[64] = {1};

    errorCount += testEccLengthByCurveIdAll();

#if ( defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && defined(__ENABLE_DIGICERT_ECC_P192_MBED__) ) \
 || ( !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && defined(__ENABLE_DIGICERT_ECC_P192__) )
    
    /* Test P192 */
#ifdef __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__
    errorCount += eccFunctionalTests(cid_EC_P192, pSha1Digest, 20);
#else
    errorCount += eccFunctionalTests(cid_EC_P192, pSha1Digest, 20);
    errorCount += eccFunctionalTests(cid_EC_P192, pSha224Digest, 28);
    errorCount += eccFunctionalTests(cid_EC_P192, pSha256Digest, 32);
    errorCount += eccFunctionalTests(cid_EC_P192, pSha384Digest, 48);
    errorCount += eccFunctionalTests(cid_EC_P192, pSha512Digest, 64);
    
#endif /* __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__ */
#endif /* Test P192 */
    
#if ( defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && defined(__ENABLE_DIGICERT_ECC_P224_MBED__) ) \
 || ( !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__DISABLE_DIGICERT_ECC_P224__) )
    
    /* Test P224 */
#ifdef __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__
    errorCount += eccFunctionalTests(cid_EC_P224, pSha224Digest, 28);
#else
    errorCount += eccFunctionalTests(cid_EC_P224, pSha1Digest, 20);
    errorCount += eccFunctionalTests(cid_EC_P224, pSha224Digest, 28);
    errorCount += eccFunctionalTests(cid_EC_P224, pSha256Digest, 32);
    errorCount += eccFunctionalTests(cid_EC_P224, pSha384Digest, 48);
    errorCount += eccFunctionalTests(cid_EC_P224, pSha512Digest, 64);
    
#endif /* __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__ */
#endif /* Test P224 */
    
#if ( defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && defined(__ENABLE_DIGICERT_ECC_P256_MBED__) ) \
 || ( !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__DISABLE_DIGICERT_ECC_P256__) ) \
 || defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)

/* Test P256 */
    
#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__
    errorCount = (errorCount + testEccSpeed(cid_EC_P256));
#else
    /* if speed test flag isn't defined, run tests as normal */
    errorCount = (errorCount + eccTest(cid_EC_P256));

#ifdef __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__
    
    errorCount += eccFunctionalTests(cid_EC_P256, pSha256Digest, 32);
    
#else
    
    errorCount += eccFunctionalTests(cid_EC_P256, pSha1Digest, 20);
    errorCount += eccFunctionalTests(cid_EC_P256, pSha224Digest, 28);
    errorCount += eccFunctionalTests(cid_EC_P256, pSha256Digest, 32);
    errorCount += eccFunctionalTests(cid_EC_P256, pSha384Digest, 48);
    errorCount += eccFunctionalTests(cid_EC_P256, pSha512Digest, 64);
    
#endif /* __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__ */
#endif /* __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__ */
#endif /* Test P256 */
   
#if ( defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && defined(__ENABLE_DIGICERT_ECC_P384_MBED__) ) \
 || ( !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__DISABLE_DIGICERT_ECC_P384__) )
    
    /* Test P384 */
#ifdef __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__
    errorCount += eccFunctionalTests(cid_EC_P384, pSha384Digest, 48);
#else
    errorCount += eccFunctionalTests(cid_EC_P384, pSha1Digest, 20);
    errorCount += eccFunctionalTests(cid_EC_P384, pSha224Digest, 28);
    errorCount += eccFunctionalTests(cid_EC_P384, pSha256Digest, 32);
    errorCount += eccFunctionalTests(cid_EC_P384, pSha384Digest, 48);
    errorCount += eccFunctionalTests(cid_EC_P384, pSha512Digest, 64);
    
#endif /* __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__ */
#endif /* Test P384 */
    
#if ( defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && defined(__ENABLE_DIGICERT_ECC_P521_MBED__) ) \
 || ( !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__DISABLE_DIGICERT_ECC_P521__) )
    
    /* Test P521 */
#ifdef __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__
    errorCount += eccFunctionalTests(cid_EC_P521, pSha512Digest, 64);
#else
    errorCount += eccFunctionalTests(cid_EC_P521, pSha1Digest, 20);
    errorCount += eccFunctionalTests(cid_EC_P521, pSha224Digest, 28);
    errorCount += eccFunctionalTests(cid_EC_P521, pSha256Digest, 32);
    errorCount += eccFunctionalTests(cid_EC_P521, pSha384Digest, 48);
    errorCount += eccFunctionalTests(cid_EC_P521, pSha512Digest, 64);
    
#endif /* __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__ */
#endif /* Test P521 */
    
exit:
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif
    
    DIGICERT_free(&gpMocCtx);
    return errorCount;
}
