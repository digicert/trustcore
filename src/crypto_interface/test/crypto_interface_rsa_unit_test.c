/*
 * crypto_interface_rsa_unit_test.c
 *
 * expanded test cases for crypto interface API in rsa.h
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
#include "../../crypto/rsa.h"

#include "../../common/mstdlib.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include "../../crypto_interface/crypto_interface_priv.h"
#include "../../crypto/test/nonrandop.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "crypto_interface_tap_example.h"
#include "../cryptointerface.h"
#include "../../crypto/mocasymkeys/tap/rsatap.h"
#include "../../crypto_interface/crypto_interface_rsa_tap.h"
#include "../../crypto_interface/crypto_interface_tap.h"
#endif

#include "../../asn1/parseasn1.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static int gCurrentVector = 0;
static int gCurrentVectorVerify = 0;

typedef enum VectorType
{
    encDec,
    signVerify

} VectorType;

typedef struct TestVector
{
    char *pModulus;
    char *pP;
    char *pQ;
    char *pPublicExponent;
    char *pDigestOrPlain;
    char *pSigOrCipher;
    char *pNonce;
    VectorType type;

} TestVector;

typedef struct TestVectorVerify
{
    char *pModulus;
    char *pPublicExponent;
    char *pDigest;
    char *pSignature;
    sbyte4 verifyStatus;

} TestVectorVerify;

typedef struct TestVectorVerifyData
{
    /* Assume e=0x10001 */
    char *pModulus;
    char *pMessage;
    ubyte hashId;
    char *pSignature;
    byteBoolean isValid;

} TestVectorVerifyData;

#define MOC_RSA_MAX_MOD_BYTE_LEN 384
#include "rsa_data_inc.h"

/* Global variables so the "fake RNG" callback method will have access as what to return */
static ubyte gpNonce[MOC_RSA_MAX_MOD_BYTE_LEN] = {0};
static ubyte4 gNonceLen = 0;
static ubyte4 gNoncePos = 0;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
static MSTATUS getDeterministicRngCtx (randomContext **ppRandCtx)
{
    MSTATUS status;
    randomContext *pRandCtx = NULL;

    status = ERR_NULL_POINTER;
    if (NULL == ppRandCtx)
        goto exit;

    status = CRYPTO_createMocSymRandom (NonRandomOperator, (void *)g_pRandomContext, NULL, &pRandCtx);
    if (OK != status)
        goto exit;

    *ppRandCtx = pRandCtx;
    pRandCtx = NULL;

exit:

    if (NULL != pRandCtx)
    {
        CRYPTO_freeMocSymRandom(&pRandCtx);
    }

    return status;
}
#endif /* defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__) */

/*
 A fake random number generator callBack method. It just write to the buffer
 the value of the global variable gpNonce. gpNonce is big enough for all curves,
 but we need to take into account the Endianness of the platforms pf_unit type.
 */
static sbyte4 rngCallback(void *rngFunArg, ubyte4 length, ubyte *pBuffer)
{
    MSTATUS status = OK;

    (void) rngFunArg;

    if ((gNoncePos + length) > gNonceLen) /* uh oh, error */
    {
        return -1;
    }

    status = DIGI_MEMCPY(pBuffer, gpNonce + gNoncePos, length);
    UNITTEST_STATUS(gCurrentVector, status);
    gNoncePos += length;

    return (sbyte4) status;
}


static int testSignVerify(ubyte *pModulus, ubyte4 modulusLen, ubyte *pP, ubyte4 pLen,
                          ubyte *pQ, ubyte4 qLen, ubyte *pPub, ubyte4 pubLen,
                          ubyte *pDigest, ubyte4 digestLen, ubyte *pSig, ubyte4 sigLen)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    intBoolean isValid = FALSE;

    RSAKey *pKey = NULL;
    ubyte pGeneratedSig[MOC_RSA_MAX_MOD_BYTE_LEN] = {0};
    ubyte pGeneratedVerify[MOC_RSA_MAX_MOD_BYTE_LEN] = {0};
    sbyte4 sigSize;
    ubyte4 verifySize;

    status = RSA_createKey(&pKey);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    /* set values of key for the known vector test */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pKey, pPub, pubLen, pModulus,
                               modulusLen, pP, pLen, pQ,
                               qLen, NULL);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = RSA_getCipherTextLength(MOC_RSA(gpHwAccelCtx) pKey, &sigSize);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, sigSize, sigLen);

    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pKey, pDigest, digestLen, pGeneratedSig, NULL);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pGeneratedSig, pSig, sigLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

    /* verify first with the boolean setting API */
    status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pKey, pDigest, digestLen, pSig, sigLen, &isValid, NULL);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, isValid, TRUE);

    /* verify again for the raw API */
    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pKey, pSig, pGeneratedVerify, &verifySize, NULL);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, verifySize, digestLen);

    status = DIGI_MEMCMP(pGeneratedVerify, pDigest, digestLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

exit:

    if (NULL != pKey)
    {
        status = RSA_freeKey(&pKey, NULL);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    return retVal;
}

#ifdef __ENABLE_DIGICERT_TAP__
static int testSignVerifyTapPkcs15(ubyte4 modNum,
    TAP_SIG_SCHEME sigScheme, TAP_ENC_SCHEME encScheme, TAP_KEY_USAGE keyUsage,
    ubyte4 keySize, byteBoolean testDeferredUnload)
{
    AsymmetricKey key = {0};
    RSAKey *pNewKey = NULL, *pPubKey = NULL;
    MRsaTapKeyGenArgs rsaTapArgs = {0};
    int retVal = 0;
    intBoolean isValid = FALSE;
    MSTATUS status = 0;

    ubyte pDigest[32] = {0};
    ubyte4 digestLen = sizeof(pDigest);
    ubyte *pDigestInfo = NULL;
    ubyte4 digestInfoLen = 0;
    ubyte pSig[512] = {0}; /* big enough for any key size */
    ubyte4 sigLen = keySize/8;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    status = CRYPTO_initAsymmetricKey(&key);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = sigScheme; /* estc_tapSignScheme; 1-6 */
    rsaTapArgs.algKeyInfo.rsaInfo.encScheme = encScheme;
    rsaTapArgs.keyUsage = keyUsage; /* estc_tapKeyUsage */
    rsaTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(modNum);
    rsaTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(modNum);
    rsaTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(modNum);

    status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(MOC_RSA(gpHwAccelCtx) NULL, (void **) &pNewKey, keySize, NULL, akt_tap_rsa, &rsaTapArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_RsaDeferKeyUnload (pNewKey, MOC_ASYM_KEY_TYPE_PRIVATE, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    /* Construct digest info to sign. */
    status = ASN1_buildDigestInfoAlloc(
        pDigest, digestLen, ht_sha256, &pDigestInfo, &digestInfoLen);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_RSA_signMessage(MOC_RSA(gpHwAccelCtx) pNewKey, pDigestInfo, digestInfoLen,
        pSig, NULL, akt_tap_rsa);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {   /* Sign again with the same key just to test*/
        status = CRYPTO_INTERFACE_RSA_signMessage (MOC_ECC(gpHwAccelCtx) pNewKey, pDigestInfo, digestInfoLen,
            pSig, NULL, akt_tap_rsa);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_TAP_RsaGetKeyInfo(pNewKey, MOC_ASYM_KEY_TYPE_PRIVATE, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    /* verify with the boolean setting API */
    status = CRYPTO_INTERFACE_RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pNewKey, pDigestInfo, digestInfoLen, pSig, sigLen, &isValid, NULL);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, isValid, TRUE);

    status = CRYPTO_loadAsymmetricKey(&key, akt_tap_rsa, (void **) &pNewKey);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_getRSAPublicKey(&key, &pPubKey);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* Verify with public key portion */
    isValid = FALSE;
    status = CRYPTO_INTERFACE_RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pPubKey, pDigestInfo, digestInfoLen, pSig, sigLen, &isValid, NULL);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, isValid, TRUE);

exit:

    (void) CRYPTO_uninitAsymmetricKey(&key, NULL);

    if (NULL != pNewKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(&pNewKey, NULL);
    }

    if (NULL != pPubKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(&pPubKey, NULL);
    }

    if (NULL != pDigestInfo)
    {
        (void) DIGI_FREE((void **) &pDigestInfo);
    }

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(modNum), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(modNum), tokenHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    return retVal;
}

static int testSignVerifyTapPss(ubyte4 modNum,
    TAP_SIG_SCHEME sigScheme, TAP_ENC_SCHEME encScheme, TAP_KEY_USAGE keyUsage,
    ubyte4 keySize, ubyte hashAlgo, ubyte4 saltLen, byteBoolean testDeferredUnload)
{
    RSAKey *pNewKey = NULL, *pPubKey = NULL;
    MRsaTapKeyGenArgs rsaTapArgs = {0};
    int retVal = 0;
    ubyte4 isValid = 1;
    MSTATUS status = 0;

    ubyte pData[512] = { 0 };
    ubyte *pSig = NULL;
    ubyte4 sigLen = 0;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    switch (hashAlgo)
    {
        /* estc_tapSignScheme; 1-6 */
        case ht_sha1:
            rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PSS_SHA1;
            break;

        case ht_sha256:
            rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PSS_SHA256;
            break;

        default:
            status = ERR_RSA_INVALID_HASH_ALGO;
            retVal += UNITTEST_STATUS(keySize, status);
            goto exit;
    }

    rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = sigScheme;
    rsaTapArgs.algKeyInfo.rsaInfo.encScheme = encScheme;
    rsaTapArgs.keyUsage = keyUsage; /* estc_tapKeyUsage; TAP_KEY_USAGE_SIGNING */
    rsaTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(modNum);
    rsaTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(modNum);
    rsaTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(modNum);

    status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(MOC_RSA(gpHwAccelCtx) NULL, (void **) &pNewKey, keySize, NULL, akt_tap_rsa, &rsaTapArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_RsaDeferKeyUnload (pNewKey, MOC_ASYM_KEY_TYPE_PRIVATE, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    /* RSA-PSS algorithm takes the entire buffer */
    status = CRYPTO_INTERFACE_PKCS1_rsaPssSignExt (MOC_RSA(gpHwAccelCtx) NULL, pNewKey, hashAlgo, MOC_PKCS1_ALG_MGF1, hashAlgo, pData, sizeof(pData),
                                                   saltLen, &pSig, &sigLen, NULL);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, sigLen, keySize/8);

    if (testDeferredUnload)
    {
        /* Sign again with the same key just to test*/
        status = DIGI_FREE((void **) &pSig);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_PKCS1_rsaPssSignExt (NULL, pNewKey, hashAlgo, MOC_PKCS1_ALG_MGF1, hashAlgo, pData, sizeof(pData),
                                                   saltLen, &pSig, &sigLen, NULL);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_TAP_RsaGetKeyInfo(pNewKey, MOC_ASYM_KEY_TYPE_PRIVATE, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    /* Verify with software */
    status = CRYPTO_INTERFACE_getRsaSwPubFromTapKey(pNewKey, &pPubKey);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_PKCS1_rsaPssVerifyExt (MOC_RSA(gpHwAccelCtx) pPubKey, hashAlgo, MOC_PKCS1_ALG_MGF1, hashAlgo, pData, sizeof(pData), pSig, 
      sigLen, saltLen, &isValid, NULL); 
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, isValid, 0);

    /* verify with hardware
    isValid = 1;
    status = CRYPTO_INTERFACE_PKCS1_rsaPssVerify (MOC_RSA(gpHwAccelCtx) pNewKey, hashAlgo, MOC_PKCS1_ALG_MGF1, hashAlgo,
                                                  pDigestInfo, digestInfoLen, pSig, sigLen, saltLen, &isValid);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, isValid, 0);*/

exit:

    if (NULL != pNewKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(MOC_RSA(gpHwAccelCtx) &pNewKey, NULL);
    }

    if (NULL != pPubKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(MOC_RSA(gpHwAccelCtx) &pPubKey, NULL);
    }

    if (NULL != pSig)
    {
        (void) DIGI_FREE((void **) &pSig);
    }

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(modNum), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(modNum), tokenHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    return retVal;
}

static int testEncryptDecryptTapPkcs15(ubyte4 modNum,
    TAP_SIG_SCHEME sigScheme, TAP_ENC_SCHEME encScheme, TAP_KEY_USAGE keyUsage,
    ubyte4 keySize, byteBoolean testDeferredUnload)
{
    RSAKey *pNewKey = NULL;
    MRsaTapKeyGenArgs rsaTapArgs = {0};
    int retVal = 0;
    intBoolean isValid = FALSE;
    MSTATUS status = 0;
    sbyte4 compare = -1;

    ubyte pPlainText[32] = {0};
    ubyte4 plainTextLen = sizeof(pPlainText);
    ubyte pEnc[512] = {0}; /* big enough for any key size */
    ubyte pDec[32];
    ubyte4 decLen;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = sigScheme; /* estc_tapSignScheme; 1-6 */
    rsaTapArgs.algKeyInfo.rsaInfo.encScheme = encScheme; /* estc_tapEncScheme; 1-5 */
    rsaTapArgs.keyUsage = keyUsage; /* estc_tapKeyUsage */
    rsaTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(modNum);
    rsaTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(modNum);
    rsaTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(modNum);

    status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(MOC_RSA(gpHwAccelCtx) NULL, (void **) &pNewKey, keySize, NULL, akt_tap_rsa, &rsaTapArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_RsaDeferKeyUnload (pNewKey, MOC_ASYM_KEY_TYPE_PRIVATE, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_RSA_encrypt(
        MOC_RSA(gpHwAccelCtx) pNewKey, pPlainText, plainTextLen, pEnc, NULL, NULL, NULL, akt_tap_rsa);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {   /* Encrypt again with the same key just to test*/
        status = CRYPTO_INTERFACE_RSA_encrypt (
            MOC_RSA(gpHwAccelCtx) pNewKey, pPlainText, plainTextLen, pEnc, NULL, NULL, NULL, akt_tap_rsa);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_TAP_RsaGetKeyInfo(pNewKey, MOC_ASYM_KEY_TYPE_PRIVATE, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    /* verify with the boolean setting API */
    DIGI_MEMSET(pDec, 0xAB, sizeof(pDec));
    status = CRYPTO_INTERFACE_RSA_decrypt(
        MOC_RSA(gpHwAccelCtx) pNewKey, pEnc, pDec, &decLen, NULL, NULL, NULL, akt_tap_rsa);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, decLen, sizeof(pPlainText));

    status = DIGI_MEMCMP(pDec, pPlainText, plainTextLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

exit:

    if (NULL != pNewKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(MOC_RSA(gpHwAccelCtx) &pNewKey, NULL);
    }

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(modNum), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(modNum), tokenHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    return retVal;
}

static int testEncryptDecryptTapOaep(ubyte4 modNum,
    TAP_SIG_SCHEME sigScheme, TAP_ENC_SCHEME encScheme, TAP_KEY_USAGE keyUsage,
    ubyte4 keySize, ubyte *pLabel, ubyte4 labelLen, byteBoolean testDeferredUnload)
{
    RSAKey *pNewKey = NULL;
    MRsaTapKeyGenArgs rsaTapArgs = {0};
    int retVal = 0;
    intBoolean isValid = FALSE;
    MSTATUS status = 0;
    sbyte4 compare = -1;

    ubyte pPlainText[32] = {0xFF, 0xEE, 0xDD};
    ubyte4 plainTextLen = sizeof(pPlainText);
    ubyte *pEnc = NULL;
    ubyte4 encLen = 0;

    ubyte *pDec = NULL;
    ubyte4 decLen = 0;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = sigScheme; /* estc_tapSignScheme; 1-6 */
    rsaTapArgs.algKeyInfo.rsaInfo.encScheme = encScheme; /* estc_tapEncScheme; 1-5 */
    rsaTapArgs.keyUsage = keyUsage; /* estc_tapKeyUsage */
    rsaTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(modNum);
    rsaTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(modNum);
    rsaTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(modNum);

    status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(MOC_RSA(gpHwAccelCtx) NULL, (void **) &pNewKey, keySize, NULL, akt_tap_rsa, &rsaTapArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_RsaDeferKeyUnload (pNewKey, MOC_ASYM_KEY_TYPE_PRIVATE, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) NULL, pNewKey, ht_sha1, 0, ht_sha1, pPlainText,
                                                   plainTextLen, pLabel, labelLen, &pEnc, &encLen);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, encLen, keySize/8);

    if (testDeferredUnload)
    {   /* Encrypt again with the same key just to test*/

        status = DIGI_FREE((void **) &pEnc);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_PKCS1_rsaOaepEncrypt (MOC_RSA(gpHwAccelCtx) NULL, pNewKey, ht_sha1, 0, ht_sha1, pPlainText,
                                                        plainTextLen, pLabel, labelLen, &pEnc, &encLen);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_TAP_RsaGetKeyInfo(pNewKey, MOC_ASYM_KEY_TYPE_PRIVATE, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pNewKey, ht_sha1, 0, ht_sha1, pEnc, encLen, pLabel,
                                                   labelLen, &pDec, &decLen);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, decLen, sizeof(pPlainText));

    status = DIGI_MEMCMP(pDec, pPlainText, plainTextLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

exit:

    if (NULL != pNewKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(MOC_RSA(gpHwAccelCtx) &pNewKey, NULL);
    }

    if (NULL != pEnc)
    {
        (void) DIGI_FREE((void **) &pEnc);
    }

    if (NULL != pDec)
    {
        (void) DIGI_FREE((void **) &pDec);
    }

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(modNum), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(modNum), tokenHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    return retVal;
}
#endif /* __ENABLE_DIGICERT_TAP__ */

static int testEncDec(ubyte *pModulus, ubyte4 modulusLen, ubyte *pP, ubyte4 pLen,
                      ubyte *pQ, ubyte4 qLen, ubyte *pPub, ubyte4 pubLen,
                      ubyte *pPlain, ubyte4 plainLen, ubyte *pCipher, ubyte4 cipherLen)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;

    RSAKey *pKey = NULL;
    ubyte pGenCipher[MOC_RSA_MAX_MOD_BYTE_LEN] = {0};
    ubyte pRecoveredPlain[MOC_RSA_MAX_MOD_BYTE_LEN] = {0};
    sbyte4 cipherSize;
    ubyte4 plainSize;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    randomContext *pRndCtx = NULL;
#endif

    status = RSA_createKey(&pKey);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        /* Get a deterministc RNG */
        status = getDeterministicRngCtx(&pRndCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;

        /* Set up the RNG to produce the nonce that was copied to gpNonce */
        status = CRYPTO_seedRandomContext(pRndCtx, NULL, gpNonce, gNonceLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
    }
#endif

    /* set values of key for the known vector test */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pKey, pPub, pubLen, pModulus,
                               modulusLen, pP, pLen, pQ,
                               qLen, NULL);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = RSA_getCipherTextLength(MOC_RSA(gpHwAccelCtx) pKey, &cipherSize);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, cipherSize, cipherLen);

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pKey, pPlain, plainLen, pGenCipher, RANDOM_rngFun, pRndCtx, NULL);
    else
#endif
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pKey, pPlain, plainLen, pGenCipher, rngCallback, NULL, NULL);

    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pGenCipher, pCipher, cipherLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pKey, pCipher, pRecoveredPlain, &plainSize, NULL, NULL, NULL);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, plainSize, plainLen);

    status = DIGI_MEMCMP(pRecoveredPlain, pPlain, plainLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

exit:

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (NULL != pRndCtx && pKey != NULL && CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = CRYPTO_freeMocSymRandom(&pRndCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
#endif

    if (NULL != pKey)
    {
        status = RSA_freeKey(&pKey, NULL);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    return retVal;
}


static int testVerify(ubyte *pModulus, ubyte4 modulusLen, ubyte *pPub, ubyte4 pubLen,
                      ubyte *pDigest, ubyte4 digestLen, ubyte *pSig, ubyte4 sigLen, sbyte4 expectedStatus)
{
    MSTATUS status = OK, fstatus = OK;
    int retVal = 0;
    sbyte4 compare;
    intBoolean isValid = FALSE;

    RSAKey *pKey = NULL;
    ubyte pGeneratedVerify[MOC_RSA_MAX_MOD_BYTE_LEN] = {0};
    ubyte4 verifySize;

    status = RSA_createKey(&pKey);
    retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    if (OK != status)
        goto exit;

    /* set values of key for the known vector test */
    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pKey, pPub, pubLen, pModulus, modulusLen, NULL);
    if (ERR_RSA_UNSUPPORTED_KEY_LENGTH == expectedStatus)
        retVal += UNITTEST_INT(gCurrentVectorVerify, status, expectedStatus);
    else
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    if (OK != status)
        goto exit;

    /* verify first with the boolean setting API */
    fstatus = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pKey, pDigest, digestLen, pSig, sigLen, &isValid, NULL);

    /* verify again for the raw API */
    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pKey, pSig, pGeneratedVerify, &verifySize, NULL);

    if (expectedStatus)
    {
        /* first API just check that we didn't get something valid */
        if (OK == fstatus && isValid)
        {
            /* force error */
           retVal += UNITTEST_INT(gCurrentVectorVerify, 0, -1);
        }

        /* For second API we may have status = ERR_RSA_DECRYPTION
            or status OK with a non-matching digest (for expectedStatus -1).
        */
        if (-1 == expectedStatus)  /* something should be wrong with the digest */
        {
            if (verifySize != digestLen)
            {
                goto exit; /* no test failure */
            }
            else
            {
                status = DIGI_MEMCMP(pGeneratedVerify, pDigest, digestLen, &compare);
                retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
                if (OK != status)
                    goto exit;

                if (!compare)
                {
                /* force error */
                    retVal += UNITTEST_INT(gCurrentVectorVerify, 0, -1);
                }
            }
        }
        else  /* we should have status == expectedStatus */
        {
            retVal += UNITTEST_INT(gCurrentVectorVerify, (int) status, (int) expectedStatus);
        }
    }
    else  /* is a valid sig */
    {
        /* check first API */
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, fstatus);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(gCurrentVectorVerify, isValid, TRUE);

        /* check second API */
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(gCurrentVectorVerify, verifySize, digestLen);

        status = DIGI_MEMCMP(pGeneratedVerify, pDigest, digestLen, &compare);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(gCurrentVectorVerify, compare, 0);
    }

exit:

    if (NULL != pKey)
    {
        status = RSA_freeKey(&pKey, NULL);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }

    return retVal;
}


static int knownAnswerTest(TestVector *pTestVector)
{
    MSTATUS status;
    int retVal = 0;

    ubyte *pModulus = NULL;
    ubyte4 modulusLen = 0;

    ubyte *pP = NULL;
    ubyte4 pLen = 0;

    ubyte *pQ = NULL;
    ubyte4 qLen = 0;

    ubyte *pPublicExponent = NULL;
    ubyte4 publicExponentLen = 0;

    ubyte *pDigestOrPlain = NULL;
    ubyte4 digestOrPlainLen = 0;

    ubyte *pSigOrCipher = NULL;
    ubyte4 sigOrCipherLen = 0;

    ubyte *pNonce = NULL;

    if (NULL != pTestVector->pModulus)
        modulusLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pModulus, &pModulus);

    if (NULL != pTestVector->pP)
        pLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pP, &pP);

    if (NULL != pTestVector->pQ)
        qLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pQ, &pQ);

    if (NULL != pTestVector->pPublicExponent)
        publicExponentLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPublicExponent, &pPublicExponent);

    if (NULL != pTestVector->pDigestOrPlain)
        digestOrPlainLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pDigestOrPlain, &pDigestOrPlain);

    if (NULL != pTestVector->pSigOrCipher)
        sigOrCipherLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSigOrCipher, &pSigOrCipher);

    /* copy nonce to the global variable for use in the rngCallback method */
    if (NULL != pTestVector->pNonce)
    {
        gNonceLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pNonce, &pNonce);
        status = DIGI_MEMCPY(gpNonce, pNonce, gNonceLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;

        gNoncePos = 0;
    }

    if (signVerify == pTestVector->type)
        retVal += testSignVerify(pModulus, modulusLen, pP, pLen, pQ, qLen, pPublicExponent, publicExponentLen,
                                 pDigestOrPlain, digestOrPlainLen, pSigOrCipher, sigOrCipherLen);
    else
        retVal += testEncDec(pModulus, modulusLen, pP, pLen, pQ, qLen, pPublicExponent, publicExponentLen,
                             pDigestOrPlain, digestOrPlainLen, pSigOrCipher, sigOrCipherLen);
exit:

    if (NULL != pModulus)
    {
        status = DIGI_FREE((void **) &pModulus);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pP)
    {
        status = DIGI_FREE((void **) &pP);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pQ)
    {
        status = DIGI_FREE((void **) &pQ);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pPublicExponent)
    {
        status = DIGI_FREE((void **) &pPublicExponent);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pDigestOrPlain)
    {
        status = DIGI_FREE((void **) &pDigestOrPlain);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pSigOrCipher)
    {
        status = DIGI_FREE((void **) &pSigOrCipher);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pNonce)
    {
        status = DIGI_FREE((void **) &pNonce);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    return retVal;
}

static int knownAnswerTestVerify(TestVectorVerify *pTestVector)
{
    MSTATUS status;
    int retVal = 0;

    ubyte *pModulus = NULL;
    ubyte4 modulusLen = 0;

    ubyte *pPublicExponent = NULL;
    ubyte4 publicExponentLen = 0;

    ubyte *pDigest = NULL;
    ubyte4 digestLen = 0;

    ubyte *pSignature = NULL;
    ubyte4 sigLen = 0;

    if (NULL != pTestVector->pModulus)
        modulusLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pModulus, &pModulus);

    if (NULL != pTestVector->pPublicExponent)
        publicExponentLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPublicExponent, &pPublicExponent);

    if (NULL != pTestVector->pDigest)
        digestLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pDigest, &pDigest);

    if (NULL != pTestVector->pSignature)
        sigLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSignature, &pSignature);

    retVal += testVerify(pModulus, modulusLen, pPublicExponent, publicExponentLen,
                         pDigest, digestLen, pSignature, sigLen, pTestVector->verifyStatus);
exit:

    if (NULL != pModulus)
    {
        status = DIGI_FREE((void **) &pModulus);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }
    if (NULL != pPublicExponent)
    {
        status = DIGI_FREE((void **) &pPublicExponent);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }
    if (NULL != pDigest)
    {
        status = DIGI_FREE((void **) &pDigest);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }
    if (NULL != pSignature)
    {
        status = DIGI_FREE((void **) &pSignature);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }

    return retVal;
}

#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_RSA_SIGN_DATA__)
static int knownAnswerTestVerifyMessage(TestVectorVerifyData *pTestVector)
{
    MSTATUS status;
    int retVal = 0;

    ubyte *pModulus = NULL;
    ubyte4 modulusLen = 0;

    ubyte *pMessage = NULL;
    ubyte4 messageLen = 0;

    ubyte *pSignature = NULL;
    ubyte4 sigLen = 0;

    ubyte pPub[3] = {0x01, 0x00, 0x01};

    intBoolean isValid = FALSE;
    RSAKey *pKey = NULL;

    if (NULL != pTestVector->pModulus)
        modulusLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pModulus, &pModulus);

    if (NULL != pTestVector->pMessage)
        messageLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pMessage, &pMessage);

    if (NULL != pTestVector->pSignature)
        sigLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSignature, &pSignature);

    status = RSA_createKey(&pKey);
    retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    if (OK != status)
        goto exit;

    /* set values of key for the known vector test */
    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pKey, pPub, 3, pModulus, modulusLen, NULL);
    retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    if (OK != status)
        goto exit;

    status = RSA_verifyData(MOC_RSA(gpHwAccelCtx) pKey, pMessage, messageLen, pTestVector->hashId, 
                            pSignature, sigLen, &isValid, NULL);
    if (pTestVector->isValid == TRUE)
    {
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
        if (OK != status)
            goto exit;

        if (isValid != TRUE)
        {
            retVal += UNITTEST_STATUS(gCurrentVectorVerify, -1);
            goto exit; 
        }
    }
    else
    {
        if (OK == status && isValid == TRUE)
        {
            retVal += UNITTEST_STATUS(gCurrentVectorVerify, -1);
            goto exit; 
        }
    }
    
exit:

    if (NULL != pModulus)
    {
        status = DIGI_FREE((void **) &pModulus);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }
    if (NULL != pMessage)
    {
        status = DIGI_FREE((void **) &pMessage);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }
    if (NULL != pSignature)
    {
        status = DIGI_FREE((void **) &pSignature);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }
    if (NULL != pKey)
    {
        status = RSA_freeKey(&pKey, NULL);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }

    return retVal;
}

static int testSignFull(RSAKey *pPrivKey, ubyte hashId, ubyte *pExpDigest, ubyte4 expDigestLen)
{
    /* We roundrip test the signFull API vs then parsing the digest info and using another verify API */
    int retVal = 0;
    MSTATUS status = OK;

    ubyte msg[12] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c};
    ubyte sig[256] = {0};
    ubyte recPlain[256] = {0};
    ubyte4 recPlainLen = 0;

    ubyte *pOid = NULL;
    ubyte4 oidLen = 0;
    ubyte *pDigest = NULL;
    ubyte4 digestLen = 0;
    ubyte4 recHashId = 0;
    sbyte4 cmp = -1;

    status = RSA_signData(MOC_RSA(gpHwAccelCtx) pPrivKey, msg, sizeof(msg), hashId, sig, NULL);
    retVal += UNITTEST_STATUS(hashId, status);
    if (OK != status)
        goto exit;

    /* now verify using the non-Full API and parse the digest info using asn1 code */
    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pPrivKey, sig, recPlain, &recPlainLen, NULL);
    retVal += UNITTEST_STATUS(hashId, status);
    if (OK != status)
        goto exit;

    status = ASN1_parseDigestInfo (recPlain, recPlainLen, &pOid, &oidLen, &pDigest, &digestLen, &recHashId);
    retVal += UNITTEST_STATUS(hashId, status);
    if (OK != status)
        goto exit;

    if ((ubyte4) hashId != recHashId)
    {
        retVal += UNITTEST_STATUS(hashId, -1);
        goto exit;
    }

    if (digestLen != expDigestLen)
    {
        retVal += UNITTEST_STATUS(hashId, -1);
        goto exit;        
    }

    status = DIGI_MEMCMP(pDigest, pExpDigest, digestLen, &cmp);
    retVal += UNITTEST_STATUS(hashId, status);
    if (OK != status)
        goto exit;

    if (cmp)
    {
        retVal += UNITTEST_STATUS(hashId, -1);
        goto exit;         
    }

    /* TO DO compare OID */

exit:

    return retVal;
}

static int testVerifyFull(RSAKey *pPrivKey, ubyte hashId, ubyte *pDigest, ubyte4 digestLen)
{
    int retVal = 0;
    MSTATUS status = OK;

    ubyte msg[12] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c};
    ubyte sig[256] = {0};

    ubyte *pDigestInfo = NULL;
    ubyte4 digestInfoLen = 0;

    intBoolean isValid = FALSE;

    status = ASN1_buildDigestInfoAlloc (pDigest, digestLen, (ubyte4) hashId, &pDigestInfo, &digestInfoLen);
    retVal += UNITTEST_STATUS(hashId, status);
    if (OK != status)
        goto exit;

    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pPrivKey, pDigestInfo, digestInfoLen, sig, NULL);
    retVal += UNITTEST_STATUS(hashId, status);
    if (OK != status)
        goto exit;

    status = RSA_verifyData(MOC_RSA(gpHwAccelCtx) pPrivKey, msg, sizeof(msg), hashId, sig, sizeof(sig), &isValid, NULL);
    retVal += UNITTEST_STATUS(hashId, status);
    if (OK != status)
        goto exit;

    if (isValid != TRUE)
    {
        retVal += UNITTEST_STATUS(hashId, -1);
        goto exit; 
    }

exit:

    if (NULL != pDigestInfo)
    {
        status = DIGI_FREE((void **) &pDigestInfo);
        retVal += UNITTEST_STATUS(hashId, status);
    }
    return retVal;
}

static int testVerifyFullNegative(RSAKey *pPrivKey, ubyte hashId, ubyte *pDigest, ubyte4 digestLen)
{
    int retVal = 0;
    MSTATUS status = OK;

    ubyte msg[12] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c};
    ubyte sig[256] = {0};

    ubyte *pDigestInfo = NULL;
    ubyte4 digestInfoLen = 0;

    intBoolean isValid = FALSE;

    status = ASN1_buildDigestInfoAlloc (pDigest, digestLen, (ubyte4) hashId, &pDigestInfo, &digestInfoLen);
    retVal += UNITTEST_STATUS(hashId, status);
    if (OK != status)
        goto exit;

    /* change the last byte of the oid but leave the digest part alone */
    if (ht_md5 == hashId)
        pDigestInfo[digestInfoLen - digestLen - 3] = 0x04; /* turn md5 oid into md4*/
    if (ht_sha256 == hashId)
        pDigestInfo[digestInfoLen - digestLen - 3] = 0x02; /* turn sha256 oid into sha512 */

    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pPrivKey, pDigestInfo, digestInfoLen, sig, NULL);
    retVal += UNITTEST_STATUS(hashId, status);
    if (OK != status)
        goto exit;

    status = RSA_verifyData(MOC_RSA(gpHwAccelCtx) pPrivKey, msg, sizeof(msg), hashId, sig, sizeof(sig), &isValid, NULL);
    retVal += UNITTEST_STATUS(hashId, status);
    if (OK != status)
        goto exit;

    if (isValid != FALSE)
    {
        retVal += UNITTEST_STATUS(hashId, -1);
        goto exit; 
    }

    /* test again this time with different digest */
    /* change the last byte of the oid but leave the digest part alone */
    if (ht_md5 == hashId)
        pDigestInfo[digestInfoLen - digestLen - 3] = 0x05; /* set back to md5 */
    if (ht_sha256 == hashId)
        pDigestInfo[digestInfoLen - digestLen - 3] = 0x01; /* set back to sha256 */

    /* change the last byte of the hash */
    pDigestInfo[digestInfoLen - 1]++;

    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pPrivKey, pDigestInfo, digestInfoLen, sig, NULL);
    retVal += UNITTEST_STATUS(hashId, status);
    if (OK != status)
        goto exit;

    status = RSA_verifyData(MOC_RSA(gpHwAccelCtx) pPrivKey, msg, sizeof(msg), hashId, sig, sizeof(sig), &isValid, NULL);
    retVal += UNITTEST_STATUS(hashId, status);
    if (OK != status)
        goto exit;

    if (isValid != FALSE)
    {
        retVal += UNITTEST_STATUS(hashId, -1);
        goto exit; 
    }

exit:

    if (NULL != pDigestInfo)
    {
        status = DIGI_FREE((void **) &pDigestInfo);
        retVal += UNITTEST_STATUS(hashId, status);
    }
    return retVal;
}

static int testSignVerifyFull()
{
    int retVal = 0;
    MSTATUS status = OK;
    RSAKey *pPrivKey = NULL;

    /* Digest of ABCDEFGHIJKL, ie {0x40, 0x41 ... } */
#ifdef __ENABLE_DIGICERT_MD2__
    ubyte expectedMd2[16] = {0x06,0x01,0xf1,0x0f,0x72,0x1e,0x7f,0x3e,0xab,0x63,0xb8,0x78,0xf1,0x27,0x7d,0xb3};
#endif
#ifdef __ENABLE_DIGICERT_MD4__
    ubyte expectedMd4[16] = {0x83,0xeb,0xbd,0x2b,0x44,0x41,0xe2,0xa2,0x9d,0xfb,0x08,0x55,0x88,0x89,0x19,0xbf};
#endif
    ubyte expectedMd5[16] = {0x2b,0x0d,0xc5,0x68,0xe5,0x88,0xe4,0x6a,0x5a,0x7c,0xd5,0x6d,0xce,0xc3,0x48,0xaf};
    ubyte expectedSha1[20] = {0x2a,0xa3,0x6a,0x11,0x11,0x05,0x9c,0x0b,0xbd,0x7a,0xd0,0xc6,0xbb,0xa1,0x08,0xf5,
                              0x0d,0xf8,0xe8,0x67};
    ubyte expectedSha224[28] = {0x43,0x7e,0x46,0x92,0x8a,0x3c,0xcb,0xe2,0x95,0x33,0x1d,0x17,0x4d,0x98,0x3b,0x0e,
                                0xba,0x64,0x54,0x5e,0x11,0xf9,0x69,0xf1,0x52,0xd1,0xa2,0x2e};
    ubyte expectedSha256[32] = {0x92,0x24,0x29,0xcc,0xdb,0x70,0x45,0xd1,0x11,0x43,0xe2,0xe3,0x98,0x2a,0x11,0xaf,
                                0xc1,0x1b,0x53,0x7b,0xf2,0x59,0xd8,0x8d,0x24,0x25,0xfa,0x88,0x06,0xe8,0x6e,0x78};
    ubyte expectedSha384[48] = {0x45,0xa5,0x82,0x8e,0x8d,0x88,0x64,0xab,0x3e,0x87,0x24,0x26,0x07,0xeb,0x17,0x31,
                                0x95,0x88,0xb8,0x12,0xff,0xd8,0x68,0x4f,0xbd,0x3e,0xa5,0xbd,0xb0,0xb0,0x1c,0x6c,
                                0x18,0x81,0x36,0xa5,0x8a,0xd1,0x4f,0x14,0x5c,0xc0,0x3a,0x52,0xff,0x09,0x80,0xde};
    ubyte expectedSha512[64] = {0x5d,0x8b,0x76,0x6d,0x3b,0x37,0xce,0x8a,0xa6,0x8d,0xd3,0x54,0xa5,0x0a,0xf9,0xc9,
                                0x42,0x01,0x28,0x6d,0x79,0x93,0xd4,0x2e,0x20,0xbb,0x7a,0x93,0xc0,0xcc,0x98,0x97,
                                0xfd,0x27,0x14,0xa2,0x86,0x0e,0xc8,0xc4,0xd7,0x99,0x12,0x37,0x6c,0x82,0x34,0xdf,
                                0xb5,0x2e,0x84,0x1e,0xff,0x0e,0xb9,0x60,0x37,0x0a,0x84,0xea,0x57,0x35,0xe8,0xb3};
#ifdef __ENABLE_DIGICERT_SHA3__
    ubyte expectedSha3_224[28] = {0x51,0xea,0xb6,0xe9,0x8d,0x6b,0x39,0xae,0xc6,0xfe,0x69,0xa5,0xf5,0x37,0xee,0x57,
                                  0xc9,0x49,0x3e,0x80,0x67,0x8f,0x19,0x7a,0x01,0x66,0xc2,0xdf};
    ubyte expectedSha3_256[32] = {0xd9,0x94,0x28,0x76,0x4c,0xc4,0x3a,0x2f,0xf5,0xc1,0xac,0x4d,0xb1,0xe5,0xda,0x82,
                                  0x6a,0x97,0xda,0xe5,0x53,0x0e,0x26,0x86,0x50,0x31,0x8a,0xdb,0x2e,0x2e,0x24,0x6f};
    ubyte expectedSha3_384[48] = {0x88,0x12,0xb7,0xa3,0x65,0x73,0x33,0xe9,0x8d,0xdd,0xb7,0x8d,0x81,0xe0,0x7c,0x4f,
                                  0xd6,0x9d,0x9a,0x5f,0x10,0xcc,0x1b,0x23,0x1c,0xce,0x6a,0x08,0xeb,0x00,0x8d,0x70,
                                  0xfa,0xc1,0xcd,0x3d,0x2f,0xf2,0x28,0x87,0x83,0x9d,0xd5,0x3f,0x76,0xec,0x6f,0x0b};
    ubyte expectedSha3_512[64] = {0x64,0x4f,0x89,0x50,0x45,0x74,0x97,0xa7,0xad,0x3b,0x89,0xff,0x1b,0xae,0x0d,0x51,
                                  0x04,0x60,0x4d,0xfe,0x71,0x91,0xb9,0x5f,0xed,0x47,0x50,0xa5,0x51,0xbb,0x07,0x05,
                                  0x17,0x3f,0xba,0x66,0xcb,0x71,0xba,0xc5,0xe8,0x9d,0xbe,0xf4,0x18,0x09,0x6a,0x76,
                                  0xf7,0x4d,0xb0,0x60,0x29,0x8c,0x3e,0x2a,0xb5,0x4a,0x35,0x13,0xfe,0x50,0xb9,0xea};
    ubyte expectedShake128[32] = {0x75,0xc1,0x37,0x2a,0x2b,0x69,0x21,0x83,0x21,0x8a,0xc7,0x6e,0x17,0xf6,0x91,0xc3,
                                  0xda,0x84,0x98,0x34,0x15,0xf0,0x98,0xec,0xbd,0x97,0x02,0x1c,0x90,0x90,0xca,0x40};
    ubyte expectedShake256[64] = {0x05,0xe5,0xa1,0x90,0xdb,0xe2,0x73,0x87,0x24,0x7f,0x71,0xd2,0x82,0xd6,0x7b,0xc4,
                                  0xb8,0x43,0x1d,0x9a,0x32,0xbc,0x05,0x5d,0x47,0x4c,0xd8,0xda,0x66,0x2c,0x07,0xc2,
                                  0x50,0xfb,0x04,0x8a,0x94,0x64,0x92,0xfe,0xa1,0x19,0x5e,0x06,0xe2,0xe2,0x49,0x85,
                                  0xc6,0x7c,0xa6,0x98,0x3c,0x34,0x92,0xc0,0xd0,0x0b,0x1f,0xa5,0xec,0x53,0x06,0x2b};
#endif

    status = RSA_createKey(&pPrivKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_generateKey(MOC_RSA(gpHwAccelCtx) g_pRandomContext, pPrivKey, (int) 2048, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_MD2__
    retVal += testSignFull(pPrivKey, ht_md2, expectedMd2, sizeof(expectedMd2));
#endif
#ifdef __ENABLE_DIGICERT_MD5__
    retVal += testSignFull(pPrivKey, ht_md4, expectedMd4, sizeof(expectedMd4));
#endif
    retVal += testSignFull(pPrivKey, ht_md5, expectedMd5, sizeof(expectedMd5));
    retVal += testSignFull(pPrivKey, ht_sha1, expectedSha1, sizeof(expectedSha1));
    retVal += testSignFull(pPrivKey, ht_sha224, expectedSha224, sizeof(expectedSha224));
    retVal += testSignFull(pPrivKey, ht_sha256, expectedSha256, sizeof(expectedSha256));
    retVal += testSignFull(pPrivKey, ht_sha384, expectedSha384, sizeof(expectedSha384));
    retVal += testSignFull(pPrivKey, ht_sha512, expectedSha512, sizeof(expectedSha512));

#ifdef __ENABLE_DIGICERT_SHA3__
    retVal += testSignFull(pPrivKey, ht_sha3_224, expectedSha3_224, sizeof(expectedSha3_224));
    retVal += testSignFull(pPrivKey, ht_sha3_256, expectedSha3_256, sizeof(expectedSha3_256));
    retVal += testSignFull(pPrivKey, ht_sha3_384, expectedSha3_384, sizeof(expectedSha3_384));
    retVal += testSignFull(pPrivKey, ht_sha3_512, expectedSha3_512, sizeof(expectedSha3_512));
    retVal += testSignFull(pPrivKey, ht_shake128, expectedShake128, sizeof(expectedShake128));
    retVal += testSignFull(pPrivKey, ht_shake256, expectedShake256, sizeof(expectedShake256));
#endif

#ifdef __ENABLE_DIGICERT_MD2__
    retVal += testVerifyFull(pPrivKey, ht_md2, expectedMd2, sizeof(expectedMd2));
#endif
#ifdef __ENABLE_DIGICERT_MD4__
    retVal += testVerifyFull(pPrivKey, ht_md4, expectedMd4, sizeof(expectedMd4));
#endif
    retVal += testVerifyFull(pPrivKey, ht_md5, expectedMd5, sizeof(expectedMd5));
    retVal += testVerifyFull(pPrivKey, ht_sha1, expectedSha1, sizeof(expectedSha1));
    retVal += testVerifyFull(pPrivKey, ht_sha224, expectedSha224, sizeof(expectedSha224));
    retVal += testVerifyFull(pPrivKey, ht_sha256, expectedSha256, sizeof(expectedSha256));
    retVal += testVerifyFull(pPrivKey, ht_sha384, expectedSha384, sizeof(expectedSha384));
    retVal += testVerifyFull(pPrivKey, ht_sha512, expectedSha512, sizeof(expectedSha512));

#ifdef __ENABLE_DIGICERT_SHA3__
    retVal += testVerifyFull(pPrivKey, ht_sha3_224, expectedSha3_224, sizeof(expectedSha3_224));
    retVal += testVerifyFull(pPrivKey, ht_sha3_256, expectedSha3_256, sizeof(expectedSha3_256));
    retVal += testVerifyFull(pPrivKey, ht_sha3_384, expectedSha3_384, sizeof(expectedSha3_384));
    retVal += testVerifyFull(pPrivKey, ht_sha3_512, expectedSha3_512, sizeof(expectedSha3_512));
    retVal += testVerifyFull(pPrivKey, ht_shake128, expectedShake128, sizeof(expectedShake128));
    retVal += testVerifyFull(pPrivKey, ht_shake256, expectedShake256, sizeof(expectedShake256));
#endif

    retVal += testVerifyFullNegative(pPrivKey, ht_md5, expectedMd5, sizeof(expectedMd5));
    retVal += testVerifyFullNegative(pPrivKey, ht_sha256, expectedSha256, sizeof(expectedSha256));

exit:

    if (NULL != pPrivKey)
    {
        status = RSA_freeKey(&pPrivKey, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}
#endif /* #if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_RSA_SIGN_DATA__) */

/* This method includes tests of init and delete method error cases too */
static int testErrorCases()
{
    int retVal = 0;
    MSTATUS status = OK;
    intBoolean isValid;

    RSAKey *pPrivKey = NULL;
    RSAKey *pPubKey = NULL;

    /* space to test too large a modulus */
#ifdef __ENABLE_DIGICERT_64_BIT__
    ubyte pModulus[512*8+1] =
#else
    ubyte pModulus[512*4+1] =
#endif
    {
        0xb0,0x30,0xe1,0x64,0x9b,0xe0,0x5f,0x85,0xdf,0xc2,0x5d,0xbf,0x3d,0xc7,0x1f,0xc7,
        0x87,0x85,0xa7,0x31,0x50,0x50,0x10,0x3d,0x47,0x05,0xe5,0x3a,0x9e,0xe5,0xdb,0x78,
        0x25,0xe5,0x31,0x65,0x70,0x73,0x0c,0xf8,0xcb,0xc9,0xf7,0xb8,0x49,0xfa,0x26,0x1c,
        0xc6,0x5c,0x8e,0xba,0x30,0x0e,0x77,0xcd,0x08,0xc5,0x26,0xed,0x94,0xb1,0x86,0xa5,
        0xbf,0x46,0xc5,0x10,0xf3,0x44,0xaf,0xc5,0xfc,0x5b,0xf3,0x82,0x06,0xbd,0x45,0xdc,
        0xe6,0x47,0xd5,0x51,0xe3,0x0d,0x8b,0xae,0x86,0xd7,0xd1,0xcc,0x4c,0xcd,0x4c,0x0c,
        0xa6,0xdf,0x54,0xc9,0xeb,0x7a,0x42,0xf5,0xe4,0x1c,0x1c,0xf4,0x5a,0xd7,0x17,0xcd,
        0xe8,0x5a,0xbc,0x99,0x2d,0xf7,0x56,0x34,0xdb,0x62,0xc1,0x36,0xbe,0xd8,0xd1,0x2b
    };

    ubyte4 modulusLen = 128;

    ubyte pP[64] =
    {
        0xdf,0xa5,0x76,0xd0,0x5c,0x2f,0x46,0x8b,0x04,0x30,0xa8,0x46,0x7e,0xcd,0x0b,0x4d,
        0xb4,0x92,0xac,0xb0,0x33,0x07,0x42,0x65,0xef,0x29,0xc1,0x44,0x3e,0xcc,0xa3,0xcc,
        0xc6,0x9d,0xd4,0x30,0xfa,0xc0,0xf3,0x5b,0x8b,0x98,0xde,0x0c,0xd0,0x8a,0xae,0x4f,
        0xd9,0xfe,0xfc,0xfe,0xb3,0x3e,0x64,0x1c,0xbb,0xa3,0xa5,0x44,0x93,0xc2,0x99,0x3d
    };
    ubyte pQ[64] =
    {
        0xc9,0xad,0xf2,0xff,0x9c,0x4f,0xe9,0x8d,0x24,0xa1,0x72,0xcf,0x33,0x18,0x83,0x94,
        0x29,0x8f,0xb0,0x22,0xc0,0x58,0x27,0x70,0x89,0xc9,0x40,0x5e,0x5b,0x74,0x85,0x14,
        0x13,0x40,0xe3,0xdd,0x89,0x9f,0xa9,0xca,0x2e,0x8f,0x61,0x1f,0xce,0x56,0x26,0x81,
        0x10,0x59,0x6c,0x9a,0x7f,0x2b,0xcb,0x11,0x20,0xef,0xd7,0x19,0x63,0xce,0x2a,0x87
    };

    /* space to test too large a pubKey */
    ubyte pPub[9] = {0x01, 0x00, 0x01};
    ubyte4 pubLen = 3;

    ubyte pDigest[118] = {0}; /* big renough to test too big */
    ubyte4 digestLen = 32;
    ubyte pSig[128] = {0};
    sbyte4 sigSize = 128;

    ubyte pVerify[128] = {0};
    ubyte4 verifySize = 0;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    randomContext *pRndCtx = NULL;
#endif

    /******* RSA_createKey *******/

    status = RSA_createKey(NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* properly create keys for further tests */
    status = RSA_createKey(&pPrivKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_createKey(&pPubKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {
        /* Get a deterministc RNG */
        status = getDeterministicRngCtx(&pRndCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;

        /* Set up the RNG to produce the nonce that was copied to gpNonce */
        status = CRYPTO_seedRandomContext(pRndCtx, NULL, gpNonce, gNonceLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;

        /* mbed will check that the modulus is not even lol! */
        pModulus[sizeof(pModulus) - 1] = 0x01;
    }
#endif

    /******* RSA_setPublicKeyData *******/

    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) NULL, pPub, pubLen, pModulus, modulusLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, NULL, pubLen, pModulus, modulusLen, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, pubLen, NULL, modulusLen, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* bad exponent */
    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, 0, pModulus, modulusLen, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);

    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub + 1, 1, pModulus, modulusLen, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);

    /* mbed allows an exponent of 1 */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPubKey->enabled)
#endif
    {
        status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, 1, pModulus, modulusLen, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);
    }

    /******* RSA_setPublicKeyParameters *******/

    status = RSA_setPublicKeyParameters(MOC_RSA(gpHwAccelCtx) NULL, 65537, pModulus, modulusLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setPublicKeyParameters(MOC_RSA(gpHwAccelCtx) pPubKey, 65537, NULL, modulusLen, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setPublicKeyParameters(MOC_RSA(gpHwAccelCtx) pPubKey, 0, pModulus, modulusLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);

    /* mbed allows an exponent of 1 */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPubKey->enabled)
#endif
    {
        status = RSA_setPublicKeyParameters(MOC_RSA(gpHwAccelCtx) pPubKey, 1, pModulus, modulusLen, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);
    }

    /* properly set the public key params for further tests */
    status = RSA_setPublicKeyParameters(MOC_RSA(gpHwAccelCtx) pPubKey, 65537, pModulus, modulusLen, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /******* RSA_setAllKeyData ********/

    /* Null params */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) NULL, pPub, pubLen, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, NULL, pubLen, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* mbed will get the modulus from p and q */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPrivKey->enabled)
#endif
    {
        status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, pubLen, NULL, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);
    }

    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, pubLen, pModulus, modulusLen, NULL, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, pubLen, pModulus, modulusLen, pP, sizeof(pP),
                               NULL, sizeof(pQ), NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* bad public exponent */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, 0, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);

    /* mbed allows an exponent of 1 */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPrivKey->enabled)
#endif
    {
        status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, 1, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);
    }

    /******* RSA_setAllKeyParameters *******/

    /* Null params */
    status = RSA_setAllKeyParameters(MOC_RSA(gpHwAccelCtx) NULL, 65537, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* mbed will get the modulus from p and q */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPrivKey->enabled)
#endif
    {
        status = RSA_setAllKeyParameters(MOC_RSA(gpHwAccelCtx) pPrivKey, 65537, NULL, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);
    }

    status = RSA_setAllKeyParameters(MOC_RSA(gpHwAccelCtx) pPrivKey, 65537, pModulus, modulusLen, NULL, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setAllKeyParameters(MOC_RSA(gpHwAccelCtx) pPrivKey, 65537, pModulus, modulusLen, pP, sizeof(pP),
                               NULL, sizeof(pQ), NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* bad public exponent */
    status = RSA_setAllKeyParameters(MOC_RSA(gpHwAccelCtx) pPrivKey, 0, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);

    status = RSA_setAllKeyParameters(MOC_RSA(gpHwAccelCtx) pPrivKey, 1, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);

    /* properly set the params for further tests */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, pubLen, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /******* RSA_getCipherTextLength *******/

    status = RSA_getCipherTextLength(MOC_RSA(gpHwAccelCtx) NULL, &sigSize);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_getCipherTextLength(MOC_RSA(gpHwAccelCtx) pPrivKey, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /******* RSA_encrypt *******/

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) NULL, pDigest, digestLen, pVerify, RANDOM_rngFun, pRndCtx, NULL);
    else
#endif
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) NULL, pDigest, digestLen, pVerify, rngCallback, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, NULL, digestLen, pVerify, RANDOM_rngFun, pRndCtx, NULL);
    else
#endif
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, NULL, digestLen, pVerify, rngCallback, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* For operators NULL output buffer will set the length to what's needed (so not a true error case) */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, NULL, RANDOM_rngFun, pRndCtx, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BUFFER_TOO_SMALL);

        /* but for RSA there is no output length param to be set and checked */
    }
    else
#endif
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, NULL, rngCallback, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);
    }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pVerify, NULL, pRndCtx, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    }
    else
#endif
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pVerify, NULL, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);
    }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pVerify, RANDOM_rngFun, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    }
#endif

    /* invalid plainLen */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, 118, pVerify, RANDOM_rngFun, pRndCtx, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    }
    else
#endif
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, 118, pVerify, rngCallback, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_INVALID_KEY);
    }

    /* invalid rng */
    gNoncePos = gNonceLen;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {   /* mbed is supposed to use the RANDOM_rngFun and pRndCtx */
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pVerify, rngCallback, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    }
    else
#endif
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pVerify, rngCallback, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_RNG_FAILURE);
    }

    /******* RSA_decrypt *******/

    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) NULL, pVerify, pDigest, (ubyte4*) &sigSize, NULL, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, NULL, pDigest, (ubyte4*) &sigSize, NULL, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* For operators NULL output buffer will set the length to what's needed (so not a true error case) */
    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, pVerify, NULL, (ubyte4*) &sigSize, NULL, NULL, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
    {
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BUFFER_TOO_SMALL);

        /* we set the plainSize (ie sigSize) to the modulusLen even though it might be less */
        retVal += UNITTEST_INT(__MOC_LINE__, sigSize, modulusLen);
    }
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, pVerify, pDigest, NULL, NULL, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* use a public key */
    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pVerify, pDigest, (ubyte4*) &sigSize, NULL, NULL, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_KEY_NOT_READY);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_INVALID_KEY);

    /* ciphertext of 0 */
    status = DIGI_MEMSET(pVerify, 0x00, sizeof(pVerify));
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, pVerify, pDigest, (ubyte4*) &sigSize, NULL, NULL, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_OUT_OF_RANGE);

    /******* RSA_signMessage *******/

    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) NULL, pDigest, digestLen, pSig, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pPrivKey, NULL, digestLen, pSig, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pPrivKey, pDigest, digestLen, NULL, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BUFFER_TOO_SMALL);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* digest too large, mbed does not distinguish this error case */
    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pPrivKey, pDigest, 118, pSig, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_BAD_SIGNATURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_INVALID_KEY);

    /* sign with a public key */
    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pSig, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_KEY_NOT_READY);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_INVALID_KEY);

    /******* RSA_verifySignature *******/

    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) NULL, pSig, pVerify, &verifySize, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pPubKey, NULL, pVerify, &verifySize, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pPubKey, pSig, NULL, &verifySize, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BUFFER_TOO_SMALL);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pPubKey, pSig, pVerify, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* properly set a public key too large for our verify */
    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, 9, pModulus, modulusLen, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* mbed is fine with the public key, just we don't get a valid decryption */
    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pPubKey, pSig, pVerify, &verifySize, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_DECRYPTION);

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPubKey->enabled)
#endif
    {
        /* properly set a modulus too large for our verify */
#ifdef __ENABLE_DIGICERT_64_BIT__
        pModulus[512*8] = 0x01;
        status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, pubLen, pModulus, 512*8+1, NULL);
#else
        pModulus[512*4] = 0x01;
        status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, pubLen, pModulus, 512*4+1, NULL);
#endif
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pPubKey, pSig, pVerify, &verifySize, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_INVALID_MODULUS);
    }
    /* ERR_RSA_DECRYPTION is tested in the test vectors */

    /****** RSA_verifyDigest *******/

    status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) NULL, pDigest, digestLen, pSig, sigSize, &isValid, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pPubKey, NULL, digestLen, pSig, sigSize, &isValid, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pSig, sigSize, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPubKey->enabled)
#endif
    {
        status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pSig, sigSize, &isValid, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_BAD_SIGNATURE);

        status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pSig, 127, &isValid, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_BAD_SIGNATURE);

        status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pSig, 129, &isValid, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_BAD_SIGNATURE);
    }

    /****** RSA_freeKey *******/

    status = RSA_freeKey(NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* properly free pPrivKey */
    status = RSA_freeKey(&pPrivKey, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* free an already freed key */
    status = RSA_freeKey(&pPrivKey, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

exit:

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (NULL != pRndCtx && NULL != pPubKey && CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {
        status = CRYPTO_freeMocSymRandom(&pRndCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
#endif

    if (NULL != pPrivKey)
    {
        status = RSA_freeKey(&pPrivKey, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pPubKey)
    {
        status = RSA_freeKey(&pPubKey, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

#ifdef __ENABLE_DIGICERT_TAP__

typedef struct
{
    TAP_SIG_SCHEME sigScheme;
    TAP_ENC_SCHEME encScheme;
    TAP_KEY_USAGE keyUsage;
    ubyte4 keySize;
} TAP_GEN_TestVector;

static TAP_GEN_TestVector gpTapKeyGen[] = {
    {
        TAP_SIG_SCHEME_NONE,
        TAP_ENC_SCHEME_NONE,
        TAP_KEY_USAGE_GENERAL,
        2048,
    },
    {
        TAP_SIG_SCHEME_PKCS1_5,
        TAP_ENC_SCHEME_NONE,
        TAP_KEY_USAGE_GENERAL,
        2048,
    },
    {
        TAP_SIG_SCHEME_PSS_SHA1,
        TAP_ENC_SCHEME_NONE,
        TAP_KEY_USAGE_GENERAL,
        2048,
    },
    {
        TAP_SIG_SCHEME_PSS_SHA256,
        TAP_ENC_SCHEME_NONE,
        TAP_KEY_USAGE_GENERAL,
        2048,
    },
    {
        TAP_SIG_SCHEME_PKCS1_5_SHA1,
        TAP_ENC_SCHEME_NONE,
        TAP_KEY_USAGE_GENERAL,
        2048,
    },
    {
        TAP_SIG_SCHEME_PKCS1_5_SHA256,
        TAP_ENC_SCHEME_NONE,
        TAP_KEY_USAGE_GENERAL,
        2048,
    },
    {
        TAP_SIG_SCHEME_PSS_SHA384,
        TAP_ENC_SCHEME_NONE,
        TAP_KEY_USAGE_GENERAL,
        2048,
    },
    {
        TAP_SIG_SCHEME_PKCS1_5_SHA384,
        TAP_ENC_SCHEME_NONE,
        TAP_KEY_USAGE_GENERAL,
        2048,
    }
};

typedef struct
{
    TAP_SignatureInfo sigInfo;
} TAP_SIG_TestVector;

static TAP_SIG_TestVector gpTapSigInfo[] = {
    {
        TAP_SIG_SCHEME_NONE
    },
    {
        TAP_SIG_SCHEME_PKCS1_5
    },
    {
        TAP_SIG_SCHEME_PSS_SHA256,
        {
            .rsaPss = {
                TAP_HASH_ALG_SHA256,
                32,
                {
                    TAP_MGF1,
                    {
                        .mgf1 = {
                            TAP_HASH_ALG_SHA256
                        }
                    }
                }
            }
        }
    },
    {
        TAP_SIG_SCHEME_PKCS1_5_SHA1
    },
    {
        TAP_SIG_SCHEME_PKCS1_5_SHA256
    },
    {
        TAP_SIG_SCHEME_PSS_SHA384,
        {
            .rsaPss = {
                TAP_HASH_ALG_SHA384,
                48,
                {
                    TAP_MGF1,
                    {
                        .mgf1 = {
                            TAP_HASH_ALG_SHA384
                        }
                    }
                }
            }
        }
    },
    {
        TAP_SIG_SCHEME_PKCS1_5_SHA384
    },
    {
        TAP_SIG_SCHEME_PSS,
        {
            .rsaPss = {
                TAP_HASH_ALG_SHA1,
                20,
                {
                    TAP_MGF1,
                    {
                        .mgf1 = {
                            TAP_HASH_ALG_SHA1
                        }
                    }
                }
            }
        }
    },
    {
        TAP_SIG_SCHEME_PSS,
        {
            .rsaPss = {
                TAP_HASH_ALG_SHA256,
                32,
                {
                    TAP_MGF1,
                    {
                        .mgf1 = {
                            TAP_HASH_ALG_SHA256
                        }
                    }
                }
            }
        }
    },
    {
        TAP_SIG_SCHEME_PSS,
        {
            .rsaPss = {
                TAP_HASH_ALG_SHA384,
                48,
                {
                    TAP_MGF1,
                    {
                        .mgf1 = {
                            TAP_HASH_ALG_SHA384
                        }
                    }
                }
            }
        }
    },
    {
        TAP_SIG_SCHEME_PSS,
        {
            .rsaPss = {
                TAP_HASH_ALG_SHA512,
                64,
                {
                    TAP_MGF1,
                    {
                        .mgf1 = {
                            TAP_HASH_ALG_SHA512
                        }
                    }
                }
            }
        }
    },
    {
        TAP_SIG_SCHEME_PSS,
        {
            .rsaPss = {
                TAP_HASH_ALG_SHA256,
                1,
                {
                    TAP_MGF1,
                    {
                        .mgf1 = {
                            TAP_HASH_ALG_SHA256
                        }
                    }
                }
            }
        }
    },
    {
        TAP_SIG_SCHEME_PSS,
        {
            .rsaPss = {
                TAP_HASH_ALG_SHA256,
                15,
                {
                    TAP_MGF1,
                    {
                        .mgf1 = {
                            TAP_HASH_ALG_SHA256
                        }
                    }
                }
            }
        }
    }
};

static int testTapKeyGen(ubyte4 modNum, TAP_GEN_TestVector *pTest, int testIndex, AsymmetricKey **ppRetKey)
{
    int retVal = 0;
    MSTATUS status;
    MRsaTapKeyGenArgs rsaTapArgs = {0};
    RSAKey *pNewKey = NULL;

    rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = pTest->sigScheme;
    rsaTapArgs.algKeyInfo.rsaInfo.encScheme = pTest->encScheme;
    rsaTapArgs.keyUsage = pTest->keyUsage;
    rsaTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(modNum);
    rsaTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(modNum);
    rsaTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(modNum);

    status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(MOC_RSA(gpHwAccelCtx) NULL, (void **) &pNewKey, pTest->keySize, NULL, akt_tap_rsa, &rsaTapArgs);
    retVal += UNITTEST_STATUS(testIndex, status);
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **) ppRetKey, 1, sizeof(AsymmetricKey));
    retVal += UNITTEST_STATUS(testIndex, status);
    if (OK != status)
        goto exit;
        
    CRYPTO_initAsymmetricKey(*ppRetKey);
    status = CRYPTO_loadAsymmetricKey(*ppRetKey, akt_tap_rsa, (void **) &pNewKey);
    retVal += UNITTEST_STATUS(testIndex, status);
    if (OK != status)
        goto exit;

exit:

    return status;
}

static int testTapKeySign(ubyte4 modNum, TAP_SIG_TestVector *pTest, int testIndex, AsymmetricKey *pKey)
{
    int retVal = 0;
    MSTATUS status;
    ubyte *pData = NULL, *pBuffer = NULL;
    ubyte4 dataLen = 0, bufferLen = 0;
    ubyte *pSignature = NULL;
    ubyte4 signatureLen = 0;
    RSAKey *pPubKey = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_Signature tapSignature1 = { 0 };
    TAP_Signature tapSignature2 = { 0 };
    TAP_Buffer tapData = { 0 };
    TAP_Buffer tapDecrypt = { 0 };
    TAP_ErrorContext errContext = { 0 };
    TAP_ErrorContext *pErrContext = &errContext;
    sbyte4 compare;
    intBoolean pssInfoSet = FALSE;

    status = CRYPTO_INTERFACE_getRSAPublicKey(pKey, &pPubKey);
    retVal += UNITTEST_STATUS(testIndex, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_getTapKey(pKey, &pTapKey);
    retVal += UNITTEST_STATUS(testIndex, status);
    if (OK != status)
        goto exit;

    switch (pTest->sigInfo.sigScheme)
    {
        case TAP_SIG_SCHEME_NONE:
            {
                status = RSA_getCipherTextLength(
                    MOC_RSA(gpHwAccelCtx) pKey->key.pRSA, &dataLen);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                status = DIGI_MALLOC((void **) &pData, dataLen);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                DIGI_MEMSET(pData, 0x70, dataLen);

                tapData.pBuffer = pData;
                tapData.bufferLen = dataLen;

                status = TAP_asymDecrypt(
                    pTapKey, TAP_EXAMPLE_getEntityCredentialList(modNum),
                    NULL, TAP_ENC_SCHEME_NONE, &tapData, &tapDecrypt,
                    pErrContext);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                pSignature = tapDecrypt.pBuffer;
                signatureLen = tapDecrypt.bufferLen;

                status = CRYPTO_INTERFACE_RSA_applyPublicKey(
                    MOC_RSA(gpHwAccelCtx) pPubKey, pSignature, signatureLen,
                    &pBuffer, NULL, akt_rsa);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCMP(pBuffer, pData, dataLen, &compare);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                retVal += UNITTEST_INT(testIndex, compare, 0);
                DIGI_FREE((void **) &pBuffer);

                status = TAP_asymSignEx(
                    pTapKey, TAP_EXAMPLE_getEntityCredentialList(modNum),
                    NULL, &(pTest->sigInfo), &tapData, &tapSignature2, pErrContext);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                pSignature = tapSignature2.signature.rsaSignature.pSignature;
                signatureLen = tapSignature2.signature.rsaSignature.signatureLen;

                status = CRYPTO_INTERFACE_RSA_applyPublicKey(
                    MOC_RSA(gpHwAccelCtx) pPubKey, pSignature, signatureLen,
                    &pBuffer, NULL, akt_rsa);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCMP(pBuffer, pData, dataLen, &compare);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                retVal += UNITTEST_INT(testIndex, compare, 0);
            }
            break;

        case TAP_SIG_SCHEME_PKCS1_5:
        case TAP_SIG_SCHEME_PKCS1_5_SHA1:
        case TAP_SIG_SCHEME_PKCS1_5_SHA256:
        case TAP_SIG_SCHEME_PKCS1_5_SHA384:
            {
                intBoolean isValid = FALSE;
                ubyte hashAlg = ht_sha256;
                BulkHashAlgo *pBulkHashAlgo = NULL;

                if (TAP_SIG_SCHEME_PKCS1_5_SHA1 == pTest->sigInfo.sigScheme)
                {
                    hashAlg = ht_sha1;
                }
                else if (TAP_SIG_SCHEME_PKCS1_5_SHA384 == pTest->sigInfo.sigScheme)
                {
                    hashAlg = ht_sha384;
                }

                status = CRYPTO_getRSAHashAlgo(hashAlg, (const BulkHashAlgo **) &pBulkHashAlgo);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                dataLen = pBulkHashAlgo->digestSize;

                status = DIGI_MALLOC((void **) &pData, dataLen);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                DIGI_MEMSET(pData, 0x72, dataLen);

                status = ASN1_buildDigestInfoAlloc(
                    pData, dataLen, hashAlg, &pBuffer, &bufferLen);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                tapData.pBuffer = pData;
                tapData.bufferLen = dataLen;

                status = TAP_asymSign(
                    pTapKey, TAP_EXAMPLE_getEntityCredentialList(modNum),
                    NULL, pTest->sigInfo.sigScheme, FALSE, &tapData, &tapSignature1,
                    pErrContext);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                pSignature = tapSignature1.signature.rsaSignature.pSignature;
                signatureLen = tapSignature1.signature.rsaSignature.signatureLen;

                status = CRYPTO_INTERFACE_RSA_verifyDigest(
                    MOC_RSA(gpHwAccelCtx) pPubKey, pBuffer, bufferLen,
                    pSignature, signatureLen, &isValid, NULL);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                retVal += UNITTEST_INT(testIndex, isValid, TRUE);

                status = TAP_asymSignEx(
                    pTapKey, TAP_EXAMPLE_getEntityCredentialList(modNum),
                    NULL, &(pTest->sigInfo), &tapData, &tapSignature2, pErrContext);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                pSignature = tapSignature2.signature.rsaSignature.pSignature;
                signatureLen = tapSignature2.signature.rsaSignature.signatureLen;

                isValid = FALSE;
                status = CRYPTO_INTERFACE_RSA_verifyDigest(
                    MOC_RSA(gpHwAccelCtx) pPubKey, pBuffer, bufferLen,
                    pSignature, signatureLen, &isValid, NULL);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                retVal += UNITTEST_INT(testIndex, isValid, TRUE);
            }
            break;

        case TAP_SIG_SCHEME_PSS:
        case TAP_SIG_SCHEME_PSS_SHA256:
        case TAP_SIG_SCHEME_PSS_SHA384:
            {
                ubyte4 verify = 1;
                ubyte hashAlg, mfgHashAlg;

                status = TAP_UTILS_getHashIdFromTapHashAlg(
                    pTest->sigInfo.sigInfo.rsaPss.hashAlgo, &hashAlg);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                status = TAP_UTILS_getHashIdFromTapHashAlg(
                    pTest->sigInfo.sigInfo.rsaPss.mgf.mgfInfo.mgf1.hashAlgo,
                    &mfgHashAlg);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                dataLen = 987;
                status = DIGI_MALLOC((void **) &pData, dataLen);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                DIGI_MEMSET(pData, 0x72, dataLen);

                tapData.pBuffer = pData;
                tapData.bufferLen = dataLen;

                if (TAP_SIG_SCHEME_PSS != pTest->sigInfo.sigScheme)
                {
                    status = TAP_asymSign(
                        pTapKey, TAP_EXAMPLE_getEntityCredentialList(modNum),
                        NULL, pTest->sigInfo.sigScheme, TRUE, &tapData,
                        &tapSignature1, pErrContext);
                    retVal += UNITTEST_STATUS(testIndex, status);
                    if (OK != status)
                        goto exit;

                    pSignature = tapSignature1.signature.rsaSignature.pSignature;
                    signatureLen = tapSignature1.signature.rsaSignature.signatureLen;

                    status = CRYPTO_INTERFACE_PKCS1_rsaPssVerifyExt(
                        MOC_RSA(gpHwAccelCtx) pPubKey, hashAlg,
                        MOC_PKCS1_ALG_MGF1, mfgHashAlg, pData, dataLen, pSignature,
                        signatureLen, pTest->sigInfo.sigInfo.rsaPss.saltLen, &verify,
                        NULL);
                    retVal += UNITTEST_STATUS(testIndex, status);
                    if (OK != status)
                        goto exit;

                    retVal += UNITTEST_INT(testIndex, verify, 0);
                }

                status = TAP_asymSignEx(
                    pTapKey, TAP_EXAMPLE_getEntityCredentialList(modNum),
                    NULL, &(pTest->sigInfo), &tapData, &tapSignature2, pErrContext);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                pSignature = tapSignature2.signature.rsaSignature.pSignature;
                signatureLen = tapSignature2.signature.rsaSignature.signatureLen;

                verify = 1;
                status = CRYPTO_INTERFACE_PKCS1_rsaPssVerifyExt(
                    MOC_RSA(gpHwAccelCtx) pPubKey, hashAlg,
                    MOC_PKCS1_ALG_MGF1, mfgHashAlg, pData, dataLen, pSignature,
                    signatureLen, pTest->sigInfo.sigInfo.rsaPss.saltLen, &verify,
                    NULL);
                retVal += UNITTEST_STATUS(testIndex, status);
                if (OK != status)
                    goto exit;

                retVal += UNITTEST_INT(testIndex, verify, 0);
            }
            break;

        default:
            status = ERR_TAP_INVALID_SCHEME;
            retVal += UNITTEST_STATUS(testIndex, status);
            goto exit;
    }

exit:

    if (NULL != pPubKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(&pPubKey, NULL);
    }

    TAP_freeSignature(&tapSignature1);
    TAP_freeSignature(&tapSignature2);

    if (NULL != tapDecrypt.pBuffer)
    {
        TAP_UTILS_freeBuffer(&tapDecrypt);
    }

    if (NULL != pBuffer)
    {
        DIGI_FREE((void **) &pBuffer);
    }

    if (NULL != pData)
    {
        DIGI_FREE((void **) &pData);
    }

    return retVal;
}

#ifdef __ENABLE_DIGICERT_GET_KEY_BY_ID_TESTS__
static int testGetKeyById(ubyte4 modNum, ubyte4 keySize, ubyte4 keySigScheme, ubyte4 sigScheme, ubyte *pId, ubyte4 idLen)
{
    AsymmetricKey key = {0};
    RSAKey *pPubKey = NULL;
    int retVal = 0;
    MSTATUS status = 0;
    ubyte4 i = 0;

    ubyte hashAlg = ht_sha256;
    ubyte4 saltLen = 32;
    ubyte pDigest[64] = {0};
    ubyte4 digestLen = 32;
    ubyte *pDigestInfo = NULL;
    ubyte4 digestInfoLen = 0;
    ubyte pSig[512] = {0}; /* big enough for any key size */
    ubyte *pSigPss = NULL;
    ubyte4 sigLen = keySize/8;
    ubyte4 retSigLen = 0;
    intBoolean isValid = FALSE;

    TAP_KeyInfo keyInfo = {0};
    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
    keyInfo.algKeyInfo.rsaInfo.sigScheme = keySigScheme;

    ubyte *pSerializedKey = NULL;
    ubyte4 serializedKeyLen = 0;

    switch (sigScheme)
    {
        case TAP_SIG_SCHEME_PKCS1_5_SHA1:
        case TAP_SIG_SCHEME_PSS_SHA1:
            hashAlg = ht_sha1;
            digestLen = 20;
            saltLen = 20;
            break;

        case TAP_SIG_SCHEME_PKCS1_5_SHA224:
            hashAlg = ht_sha224;
            digestLen = 28;
            break;

        case TAP_SIG_SCHEME_PKCS1_5_SHA256:
        case TAP_SIG_SCHEME_PSS_SHA256:
            /* already at defaults */
            break;

        case TAP_SIG_SCHEME_PKCS1_5_SHA384:
        case TAP_SIG_SCHEME_PSS_SHA384:
            hashAlg = ht_sha384;
            digestLen = 48;
            break;

        case TAP_SIG_SCHEME_PKCS1_5_SHA512:
        case TAP_SIG_SCHEME_PSS_SHA512:
            hashAlg = ht_sha512;
            digestLen = 64;
            break;
    }
    for (i = 0; i < digestLen; ++i)
    {
        pDigest[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_initAsymmetricKey(&key);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_serializeKeyById(TAP_EXAMPLE_getTapContext(modNum), TAP_EXAMPLE_getEntityCredentialList(modNum), TAP_EXAMPLE_getCredentialList(modNum),
                                                   &keyInfo, (ubyte *) pId, idLen, mocanaBlobVersion2, &pSerializedKey, &serializedKeyLen);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pSerializedKey, serializedKeyLen, NULL, &key);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;
    
    if (TAP_SIG_SCHEME_PSS_SHA1 == sigScheme || TAP_SIG_SCHEME_PSS_SHA256 == sigScheme)
    {
        /* RSA-PSS algorithm takes the entire buffer */
        status = CRYPTO_INTERFACE_PKCS1_rsaPssSignExt (MOC_RSA(gpHwAccelCtx) NULL, key.key.pRSA, hashAlg, MOC_PKCS1_ALG_MGF1, hashAlg, pDigest, digestLen,
                                                    saltLen, &pSigPss, &retSigLen, NULL);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(keySize, sigLen, retSigLen);


        status = CRYPTO_INTERFACE_getRSAPublicKey(&key, &pPubKey);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_PKCS1_rsaPssVerifyExt (MOC_RSA(gpHwAccelCtx) pPubKey, hashAlg, MOC_PKCS1_ALG_MGF1, hashAlg, pDigest, digestLen, pSigPss, 
                                                         sigLen, saltLen, &isValid, NULL); 
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        /* pss API sets the output param to 0 for valid signatures */
        retVal += UNITTEST_INT(keySize, isValid, 0);
    } 
    else
    {
        /* Construct digest info to sign. */
        status = ASN1_buildDigestInfoAlloc(pDigest, digestLen, hashAlg, &pDigestInfo, &digestInfoLen);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_RSA_signMessage(MOC_RSA(gpHwAccelCtx) key.key.pRSA, pDigestInfo, digestInfoLen,
            pSig, NULL, akt_tap_rsa);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_getRSAPublicKey(&key, &pPubKey);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        /* Verify with public key portion */
        status = CRYPTO_INTERFACE_RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pPubKey, pDigestInfo, digestInfoLen, pSig, sigLen, &isValid, NULL);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(keySize, isValid, TRUE);
    }

exit:
   
    if (NULL != pSerializedKey)
    {
        (void) DIGI_FREE((void** ) &pSerializedKey);
    }

    (void) CRYPTO_uninitAsymmetricKey(&key, NULL);

    if (NULL != pPubKey)
    {
        (void) RSA_freeKey(&pPubKey, NULL);
    }
    
    if (NULL != pSigPss)
    {
        (void) DIGI_FREE((void **) &pSigPss);
    }

    if (NULL != pDigestInfo)
    {
        (void) DIGI_FREE((void **) &pDigestInfo);
    }

    return retVal;
}
#endif /* __ENABLE_DIGICERT_GET_KEY_BY_ID_TESTS__ */

static int testTap()
{
    int retVal = 0;
    int i, j;

    /* For all of these cases the only one that works consistently is for RSA
     * 2048 with SHA-256 with for PKCS 1.5 and raw signing. The other cases
     * do not work either due to key size or different parameters based on TPM2
     * version (such as RSA-PSS salt length).
     */

#if !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)

    /* PKCS 1.5 padding with no signature scheme */
#if !defined(__ENABLE_DIGICERT_CLOUDHSM_TEST_SET__)
    retVal += testSignVerifyTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 1024, FALSE);
#endif
    retVal += testSignVerifyTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, FALSE);
    retVal += testSignVerifyTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 3072, FALSE);
    retVal += testSignVerifyTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 4096, FALSE);

    /* PKCS 1.5 padding with explicit PKCS 1.5 signature scheme */
#ifndef __ENABLE_DIGICERT_CLOUDHSM_TEST_SET__
    retVal += testSignVerifyTapPkcs15(1, TAP_SIG_SCHEME_PKCS1_5, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 1024, FALSE);
#endif
    retVal += testSignVerifyTapPkcs15(1, TAP_SIG_SCHEME_PKCS1_5, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, FALSE);
    retVal += testSignVerifyTapPkcs15(1, TAP_SIG_SCHEME_PKCS1_5, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 3072, FALSE);
    retVal += testSignVerifyTapPkcs15(1, TAP_SIG_SCHEME_PKCS1_5, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 4096, FALSE);

    /* test deferred unload */
    retVal += testSignVerifyTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, TRUE);
    retVal += testSignVerifyTapPkcs15(1, TAP_SIG_SCHEME_PKCS1_5, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 3072, TRUE);

    /* PSS SHA-1 padding with no signature scheme */
#ifndef __ENABLE_DIGICERT_CLOUDHSM_TEST_SET__
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 1024, ht_sha1, 20, FALSE);
#endif
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha1, 20, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 3072, ht_sha1, 20, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 4096, ht_sha1, 20, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha1, 0, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha1, 16, FALSE);
#ifndef __ENABLE_DIGICERT_CLOUDHSM_TEST_SET__
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha1, 32, FALSE);
#endif

    /* PSS SHA-256 padding with no signature scheme */
#ifndef __ENABLE_DIGICERT_CLOUDHSM_TEST_SET__
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 1024, ht_sha256, 32, FALSE);
#endif
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha256, 32, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 3072, ht_sha256, 32, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 4096, ht_sha256, 32, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha256, 0, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha256, 16, FALSE);

    /* PSS SHA-1 padding with explicit PSS SHA-1 signature scheme */
#ifndef __ENABLE_DIGICERT_CLOUDHSM_TEST_SET__
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA1, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 1024, ht_sha1, 20, FALSE);
#endif
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA1, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha1, 20, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA1, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 3072, ht_sha1, 20, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA1, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 4096, ht_sha1, 20, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA1, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha1, 0, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA1, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha1, 16, FALSE);
#ifndef __ENABLE_DIGICERT_CLOUDHSM_TEST_SET__
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA1, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha1, 32, FALSE);
#endif

    /* PSS SHA-256 padding with explicit PSS SHA-256 signature scheme */
#ifndef __ENABLE_DIGICERT_CLOUDHSM_TEST_SET__
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA256, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 1024, ht_sha256, 32, FALSE);
#endif
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA256, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha256, 32, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA256, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 3072, ht_sha256, 32, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA256, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 4096, ht_sha256, 32, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA256, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha256, 0, FALSE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA256, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha256, 16, FALSE);

    /* Test with deferred unload */
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha1, 20, TRUE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 3072, ht_sha256, 32, TRUE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA1, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha1, 16, TRUE);
    retVal += testSignVerifyTapPss(1, TAP_SIG_SCHEME_PSS_SHA256, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_SIGNING, 2048, ht_sha256, 32, TRUE);

    /* PKCS 1.5 padding with no encryption scheme */
#ifndef __ENABLE_DIGICERT_CLOUDHSM_TEST_SET__
    retVal += testEncryptDecryptTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_DECRYPT, 1024, FALSE);
#endif
    retVal += testEncryptDecryptTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_DECRYPT, 2048, FALSE);
    retVal += testEncryptDecryptTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_DECRYPT, 3072, FALSE);
    retVal += testEncryptDecryptTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_DECRYPT, 4096, FALSE);

    /* PKCS 1.5 padding with explicit PKCS 1.5 encryption scheme */
#ifndef __ENABLE_DIGICERT_CLOUDHSM_TEST_SET__
    retVal += testEncryptDecryptTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_PKCS1_5, TAP_KEY_USAGE_DECRYPT, 1024, FALSE);
#endif
    retVal += testEncryptDecryptTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_PKCS1_5, TAP_KEY_USAGE_DECRYPT, 2048, FALSE);
    retVal += testEncryptDecryptTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_PKCS1_5, TAP_KEY_USAGE_DECRYPT, 3072, FALSE);
    retVal += testEncryptDecryptTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_PKCS1_5, TAP_KEY_USAGE_DECRYPT, 4096, FALSE);

    /* Test deffered unload */
#ifndef __ENABLE_DIGICERT_CLOUDHSM_TEST_SET__
    retVal += testEncryptDecryptTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_DECRYPT, 1024, TRUE);
#endif
    retVal += testEncryptDecryptTapPkcs15(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_PKCS1_5, TAP_KEY_USAGE_DECRYPT, 2048, TRUE);

    /* OAEP SHA-1 padding with no encryption scheme */
#ifndef __ENABLE_DIGICERT_CLOUDHSM_TEST_SET__
    retVal += testEncryptDecryptTapOaep(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_DECRYPT, 1024, NULL, 0, FALSE);
#endif
    retVal += testEncryptDecryptTapOaep(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_DECRYPT, 2048, NULL, 0, FALSE);
    retVal += testEncryptDecryptTapOaep(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_DECRYPT, 3072, NULL, 0, FALSE);
    retVal += testEncryptDecryptTapOaep(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_DECRYPT, 4096, NULL, 0, FALSE);

    /* OAEP SHA-1 padding with explicit OAEP SHA-1 encryption scheme */
#ifndef __ENABLE_DIGICERT_CLOUDHSM_TEST_SET__
    retVal += testEncryptDecryptTapOaep(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_OAEP_SHA1, TAP_KEY_USAGE_DECRYPT, 1024, NULL, 0, FALSE);
#endif
    retVal += testEncryptDecryptTapOaep(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_OAEP_SHA1, TAP_KEY_USAGE_DECRYPT, 2048, NULL, 0, FALSE);
    retVal += testEncryptDecryptTapOaep(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_OAEP_SHA1, TAP_KEY_USAGE_DECRYPT, 3072, NULL, 0, FALSE);
    retVal += testEncryptDecryptTapOaep(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_OAEP_SHA1, TAP_KEY_USAGE_DECRYPT, 4096, NULL, 0, FALSE);

    /* Test deffered unload */
    retVal += testEncryptDecryptTapOaep(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_NONE, TAP_KEY_USAGE_DECRYPT, 2048, NULL, 0, TRUE);
    retVal += testEncryptDecryptTapOaep(1, TAP_SIG_SCHEME_NONE, TAP_ENC_SCHEME_OAEP_SHA1, TAP_KEY_USAGE_DECRYPT, 4096, NULL, 0, TRUE);
#endif

/* Cloudhsm does not support raw RSA signing */
#if !defined(__ENABLE_DIGICERT_CLOUDHSM_TEST_SET__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
    for (i = 0; i < COUNTOF(gpTapKeyGen); i++)
    {
        AsymmetricKey *pKey = NULL;

        retVal += testTapKeyGen(1, gpTapKeyGen + i, i, &pKey);

        if (NULL != pKey)
        {
#ifdef __ENABLE_DIGICERT_TPM2__
            TAP_Key *pTapKey = NULL;

            /* we just test the pkcs1.5 sha-256 vectors */
            retVal += testTapKeySign(1, gpTapSigInfo, 0, pKey);
            retVal += testTapKeySign(1, gpTapSigInfo + 1, 1, pKey);
            retVal += testTapKeySign(1, gpTapSigInfo + 4, 4, pKey);

            CRYPTO_INTERFACE_getTapKey(pKey, &pTapKey);
            TAP_unloadKey(pTapKey, NULL);
#else
            for (j = 0; j < COUNTOF(gpTapSigInfo); j++)
            {
                retVal += testTapKeySign(1, gpTapSigInfo + j, j, pKey);
            }
#endif
            CRYPTO_uninitAsymmetricKey(pKey, NULL);
            DIGI_FREE((void **) &pKey);
        }
    }
#endif

#ifdef __ENABLE_DIGICERT_GET_KEY_BY_ID_TESTS__
#ifdef __ENABLE_DIGICERT_SOFTHSM_TEST_SET__
    { 
        /* To enable these tests, define the above flags, and keys need to be generated with appropriate IDs. For example
           using the OpenSC pkcs11-tool, run...

pkcs11-tool --module=/usr/local/lib/softhsm/libsofthsm2.so --token-label myToken --login --pin 0000 --keypairgen --mechanism RSA-PKCS-KEY-PAIR-GEN --key-type RSA:1024 --usage-sign --label mykey --id 1024aabbccddeeff
pkcs11-tool --module=/usr/local/lib/softhsm/libsofthsm2.so --token-label myToken --login --pin 0000 --keypairgen --mechanism RSA-PKCS-KEY-PAIR-GEN --key-type RSA:2048 --usage-sign --label mykey --id 2048
pkcs11-tool --module=/usr/local/lib/softhsm/libsofthsm2.so --token-label myToken --login --pin 0000 --keypairgen --mechanism RSA-PKCS-KEY-PAIR-GEN --key-type RSA:3072 --usage-sign --label mykey --id 30
pkcs11-tool --module=/usr/local/lib/softhsm/libsofthsm2.so --token-label myToken --login --pin 0000 --keypairgen --mechanism RSA-PKCS-KEY-PAIR-GEN --key-type RSA:4096 --usage-sign --label mykey --id 4096aabbccddeeff1234

        */

        ubyte pId_1024[8] = {0x10, 0x24, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
        ubyte pId_2048[2] = {0x20, 0x48};
        ubyte pId_3072[1] = {0x30};
        ubyte pId_4096[10] = {0x40, 0x96, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x12, 0x34};

        retVal += testGetKeyById(1, 1024, TAP_SIG_SCHEME_NONE, TAP_SIG_SCHEME_NONE, pId_1024, sizeof(pId_1024));
        retVal += testGetKeyById(1, 2048, TAP_SIG_SCHEME_NONE, TAP_SIG_SCHEME_NONE, pId_2048, sizeof(pId_2048));
        retVal += testGetKeyById(1, 3072, TAP_SIG_SCHEME_NONE, TAP_SIG_SCHEME_NONE, pId_3072, sizeof(pId_3072));
        retVal += testGetKeyById(1, 4096, TAP_SIG_SCHEME_NONE, TAP_SIG_SCHEME_NONE, pId_4096, sizeof(pId_4096));

        retVal += testGetKeyById(1, 1024, TAP_SIG_SCHEME_PKCS1_5_SHA1, TAP_SIG_SCHEME_PKCS1_5_SHA1, pId_1024, sizeof(pId_1024));
        retVal += testGetKeyById(1, 2048, TAP_SIG_SCHEME_PKCS1_5_SHA256, TAP_SIG_SCHEME_PKCS1_5_SHA256, pId_2048, sizeof(pId_2048));
        retVal += testGetKeyById(1, 3072, TAP_SIG_SCHEME_PKCS1_5_SHA384, TAP_SIG_SCHEME_PKCS1_5_SHA384, pId_3072, sizeof(pId_3072));
        retVal += testGetKeyById(1, 4096, TAP_SIG_SCHEME_PKCS1_5_SHA384, TAP_SIG_SCHEME_PKCS1_5_SHA384, pId_4096, sizeof(pId_4096));
        
        retVal += testGetKeyById(1, 1024, TAP_SIG_SCHEME_PSS_SHA1, TAP_SIG_SCHEME_PSS_SHA1, pId_1024, sizeof(pId_1024));
        retVal += testGetKeyById(1, 2048, TAP_SIG_SCHEME_PSS_SHA256, TAP_SIG_SCHEME_PSS_SHA256, pId_2048, sizeof(pId_2048));
        retVal += testGetKeyById(1, 3072, TAP_SIG_SCHEME_PSS_SHA256, TAP_SIG_SCHEME_PSS_SHA256, pId_3072, sizeof(pId_3072));
        retVal += testGetKeyById(1, 4096, TAP_SIG_SCHEME_PSS_SHA256, TAP_SIG_SCHEME_PSS_SHA256, pId_4096, sizeof(pId_4096));
    }
#endif
#ifdef __ENABLE_DIGICERT_DIGICERT_SSM__
    {
        /* To enable these tests, define the above flags, and make sure there exists key pairs with the following IDs */
        MSTATUS status = OK;

        ubyte pIdD_2048[37] = "ab15ffba-39d0-4b3f-82be-1a3406f56619";
        ubyte pIdD_2048_2[37] = "5bab78eb-a7da-4d61-b83f-91a546124c17";
        ubyte pIdD_3072[37] = "7f7132f5-510d-4d47-b8f6-c4fd6b9cb191";
        ubyte pIdD_3072_2[37] = "1fff83a8-9a67-47ba-a606-e96e1d496ae4";
        ubyte pIdD_4096[37] = "fa90664c-a5f8-4793-a114-7230c2e20650";
        ubyte pIdD_4096_2[37] = "571f284c-feff-4a89-b4f3-720d730bcc6c";

        status = CRYPTO_INTERFACE_registerTapCtxCallback(TAP_EXAMPLE_getCtx2);
        retVal += UNITTEST_STATUS(0, status);
        if (OK != status)
            goto exit;
             
        retVal += testGetKeyById(2, 2048, TAP_SIG_SCHEME_NONE, pIdD_2048, 36);
        retVal += testGetKeyById(2, 2048, TAP_SIG_SCHEME_NONE, TAP_SIG_SCHEME_NONE, pIdD_2048_2, 36);
        retVal += testGetKeyById(2, 3072, TAP_SIG_SCHEME_NONE, TAP_SIG_SCHEME_NONE, pIdD_3072, 36);
        retVal += testGetKeyById(2, 3072, TAP_SIG_SCHEME_NONE, TAP_SIG_SCHEME_NONE, pIdD_3072_2, 36);
        retVal += testGetKeyById(2, 4096, TAP_SIG_SCHEME_NONE, TAP_SIG_SCHEME_NONE, pIdD_4096, 36);

        retVal += testGetKeyById(2, 2048, TAP_SIG_SCHEME_PKCS1_5_SHA256, TAP_SIG_SCHEME_PKCS1_5_SHA256, pIdD_2048, 36);
        retVal += testGetKeyById(2, 2048, TAP_SIG_SCHEME_PKCS1_5_SHA256, TAP_SIG_SCHEME_PKCS1_5_SHA256, pIdD_2048_2, 36);
        retVal += testGetKeyById(2, 3072, TAP_SIG_SCHEME_PKCS1_5_SHA384, TAP_SIG_SCHEME_PKCS1_5_SHA384, pIdD_3072, 36);
        retVal += testGetKeyById(2, 3072, TAP_SIG_SCHEME_PKCS1_5_SHA384, TAP_SIG_SCHEME_PKCS1_5_SHA384, pIdD_3072_2, 36);
        retVal += testGetKeyById(2, 4096, TAP_SIG_SCHEME_PKCS1_5_SHA384, TAP_SIG_SCHEME_PKCS1_5_SHA384, pIdD_4096, 36);

        retVal += testGetKeyById(2, 4096, TAP_SIG_SCHEME_PKCS1_5_SHA512, TAP_SIG_SCHEME_PKCS1_5_SHA512, pIdD_4096_2, 36);
        retVal += testGetKeyById(2, 4096, TAP_SIG_SCHEME_PKCS1_5_SHA256, TAP_SIG_SCHEME_PKCS1_5_SHA256, pIdD_4096_2, 36);

        /* reverse the sigScheme from the keySigScheme */
        retVal += testGetKeyById(2, 4096, TAP_SIG_SCHEME_PKCS1_5_SHA512, TAP_SIG_SCHEME_PKCS1_5_SHA256, pIdD_4096_2, 36);
        retVal += testGetKeyById(2, 4096, TAP_SIG_SCHEME_PKCS1_5_SHA256, TAP_SIG_SCHEME_PKCS1_5_SHA512, pIdD_4096_2, 36);
exit:
        /* retVal += testGetKeyById(2050, TAP_SIG_SCHEME_PSS_SHA256, pId_2048, 36); not suppoted yet */
    }
#endif
#endif /* __ENABLE_DIGICERT_GET_KEY_BY_ID_TESTS__ */

/*  retVal += testEncryptDecryptTapOaep(1024, (ubyte *) "J", 1);
    retVal += testEncryptDecryptTapOaep(2048, (ubyte *) "JH", 2);
    retVal += testEncryptDecryptTapOaep(3072, (ubyte *) "a longer test label", 19);
    retVal += testEncryptDecryptTapOaep(4096, (ubyte *) "and finally a label bigger than 32 chars", 40);*/

    return retVal;
}

#endif

int crypto_interface_rsa_unit_test_init()
{
    MSTATUS status;
    int retVal = 0;
    int i;

    InitMocanaSetupInfo setupInfo = {0};
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

/* Config files like pkcs_smp.conf have to match the module numbers given in the list below */
#if defined(__ENABLE_DIGICERT_GET_KEY_BY_ID_TESTS__) && defined(__ENABLE_DIGICERT_DIGICERT_SSM__) && defined(__ENABLE_DIGICERT_SOFTHSM_TEST_SET__)
    ubyte4 pModNums[2] = {1, 2};
    ubyte4 numMods = 2;
#else
    ubyte4 pModNums[1] = {1};
    ubyte4 numMods = 1;
#endif

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
    for (i = 0; i < sizeof(gTestVector)/sizeof(gTestVector[0]); ++i)
    {
        retVal += knownAnswerTest(gTestVector+i);
        gCurrentVector++;
    }

    gCurrentVectorVerify = 0;
    for (i = 0; i < sizeof(gTestVectorVerify)/sizeof(gTestVectorVerify[0]); ++i)
    {
        retVal += knownAnswerTestVerify(gTestVectorVerify+i);
        gCurrentVectorVerify++;
    }

#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_RSA_SIGN_DATA__)
    gCurrentVectorVerify = 0;
    for (i = 0; i < sizeof(gTestVectorVerifyData)/sizeof(gTestVectorVerifyData[0]); ++i)
    {
        retVal += knownAnswerTestVerifyMessage(gTestVectorVerifyData+i);
        gCurrentVectorVerify++;
    }

    retVal += testSignVerifyFull();
#endif
    retVal += testErrorCases();

#ifdef __ENABLE_DIGICERT_TAP__
    status = TAP_EXAMPLE_init(pModNums, numMods);
    if (OK != status)
    {
        retVal += 1;
        goto exit;
    }

    retVal += testTap();

#endif

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

#ifdef __ENABLE_DIGICERT_TAP__
    TAP_EXAMPLE_clean();
#endif

    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);

    return retVal;
}
