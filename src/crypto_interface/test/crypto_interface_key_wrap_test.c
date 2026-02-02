/*
 * crypto_interface_key_wrap_test.c
 *
 * test cases for crypto interface keywrap API
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

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__

#include "../../crypto_interface/crypto_interface_priv.h"
#include "../../crypto/test/nonrandop.h"
#include "../../crypto/aes.h"
#include "../../crypto/aes_ctr.h"
#include "../../crypto_interface/crypto_interface_aes.h"

#include "../../crypto_interface/example/crypto_interface_tap_example.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto/mocasymkeys/tap/rsatap.h"
#include "../../crypto_interface/crypto_interface_rsa_tap.h"
#include "../../crypto/mocsymalgs/tap/symtap.h"
#include "../../crypto_interface/crypto_interface_sym_tap.h"
#include "../../crypto_interface/crypto_interface_aes_tap.h"

static MocCtx gpMocCtx = NULL;

static int keyWrapOAEPTest()
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 i;
    TAP_KEY_CMK extractTrue = TAP_KEY_CMK_ENABLE;
    sbyte4 cmp = 1;
    RSAKey *pNewKey = NULL;
    RSAKey *pPubKey = NULL;
    AsymmetricKey asymWrapper;
    SymmetricKey *pSymWrapper = NULL;
    SymmetricKey *pNewSymKey = NULL;
    TAP_KeyInfo unwrapKeyInfo = {0};
    TAP_AttributeList createAttributes = {0};
    MRsaTapKeyGenArgs rsaTapArgs = {0};
    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;
    ubyte *pWrapped = NULL;
    ubyte4 wrapLen = 0;
    ubyte *pSymId = NULL;
    ubyte4 symIdLen = 0;
    ubyte *pAsymId = NULL;
    ubyte4 asymIdLen = 0;
    char *pLabel = "testlabel";
    ubyte4 labelLen = DIGI_STRLEN(pLabel);
    
    BulkCtx pCtx = NULL;
    BulkCtx pCtx2 = NULL;
    ubyte pIv[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x00};
    ubyte pPlain[64];
    ubyte pCipher[64] = {0};
    ubyte pRecPlain[64] = {0};
    sbyte4 retLen = 0;

    DIGI_MEMSET(pCipher, 0, 64);
    DIGI_MEMSET(pRecPlain, 0, 64);

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pPlain); ++i)
    {
        pPlain[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    /* Prepare arguments to generate RSA keypair */
    rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_NONE; /* estc_tapSignScheme; 1-6 */
    rsaTapArgs.algKeyInfo.rsaInfo.encScheme = TAP_ENC_SCHEME_NONE;
    rsaTapArgs.keyUsage = TAP_KEY_USAGE_SIGNING; /* estc_tapKeyUsage */
    rsaTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    rsaTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    rsaTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);

    /* Prepare the attributes for creating exportable AES key */
    status = DIGI_MALLOC((void **) &createAttributes.pAttributeList, sizeof(TAP_Attribute));
    if (OK != status)
        goto exit;

    createAttributes.pAttributeList[0].type = TAP_ATTR_KEY_CMK;
    createAttributes.pAttributeList[0].length = sizeof(TAP_KEY_CMK);
    createAttributes.pAttributeList[0].pStructOfType = (void *) &extractTrue;
    createAttributes.listLen = 1;

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.pKeyAttributes = &createAttributes;
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    /* Generate RSA TAP keypair */
    status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(NULL, (void **) &pNewKey, 4096, NULL, akt_tap_rsa, &rsaTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Generate extractable AES key on token */
    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, 128, pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* Get a pure SW RSA public key from the keypair */
    status = CRYPTO_INTERFACE_getRsaSwPubFromTapKey(pNewKey, &pPubKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* Load key into AsymmetricKey so we can get ID */
    status = CRYPTO_loadAsymmetricKey(&asymWrapper, akt_tap_rsa, (void **) &pNewKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Get ID, will be used later as wrapping key ID */
    status = CRYPTO_INTERFACE_TAP_asymGetTapObjectId(&asymWrapper, &pAsymId, &asymIdLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Get ID, will be used later as key to be wrapped ID */
    status = CRYPTO_INTERFACE_TAP_symGetTapObjectId(pSymWrapper, &pSymId, &symIdLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Just for testing, encrypt some data with the generated AES key */
    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx, MODE_CBC, MOCANA_SYM_TAP_ENCRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, pIv, pPlain, 64 * 8, pCipher, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* We must delete the AES context, otherwise we have a pending cipher operation
     * on the token */
    status = CRYPTO_INTERFACE_DeleteAESCtx (&pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Wrap the AES key with the RSA public key */
    status = CRYPTO_INTERFACE_TAP_RSA_wrapSymKey (
        TAP_EXAMPLE_getTapContext(1), TAP_EXAMPLE_getEntityCredentialList(1), TAP_EXAMPLE_getCredentialList(1), 
        pPubKey, pSymId, symIdLen, TRUE, ht_sha1, NULL, 0, &pWrapped, &wrapLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* We must specify the key type for unwrap */
    unwrapKeyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    /* Unwrap the wrapped key onto the token */
    status = CRYPTO_INTERFACE_TAP_RSA_unwrapSymKey (
        TAP_EXAMPLE_getTapContext(1), TAP_EXAMPLE_getEntityCredentialList(1), TAP_EXAMPLE_getCredentialList(1), 
        &unwrapKeyInfo, pAsymId, asymIdLen, TRUE, ht_sha1, NULL, 0, pWrapped, wrapLen, &pNewSymKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Verification test, decrypt the previously encrypted data using the unwrapped key */
    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pNewSymKey, &pCtx2, MODE_CBC, MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher, 64 * 8, pRecPlain, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pPlain, pRecPlain, 16, &cmp);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, cmp, 0);

exit:

    CRYPTO_uninitAsymmetricKey(&asymWrapper, NULL);
    if (NULL != pNewKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(&pNewKey, NULL);
    }
    if (NULL != pPubKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(&pPubKey, NULL);
    }
    if (NULL != pSymWrapper)
    {
        CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }
    if (NULL != pNewSymKey)
    {
        CRYPTO_INTERFACE_TAP_deleteSymKey(&pNewSymKey);
    }
    if (NULL != pCtx)
    {
        CRYPTO_INTERFACE_DeleteAESCtx(&pCtx);
    }
    if (NULL != pCtx2)
    {
        CRYPTO_INTERFACE_DeleteAESCtx(&pCtx2);
    }
    if (NULL != pSymId)
    {
        DIGI_FREE((void **)&pSymId);
    }
    if (NULL != pAsymId)
    {
        DIGI_FREE((void **)&pAsymId);
    }
    if (NULL != pWrapped)
    {
        DIGI_FREE((void **)&pWrapped);
    }
    if (NULL != createAttributes.pAttributeList)
    {
        DIGI_FREE((void **)&createAttributes.pAttributeList);
    }

    return retVal;
}

static int keyWrapTest()
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 i;
    TAP_KEY_CMK extractTrue = TAP_KEY_CMK_ENABLE;
    sbyte4 cmp = 1;
    RSAKey *pNewKey = NULL;
    RSAKey *pPubKey = NULL;
    AsymmetricKey asymWrapper;
    SymmetricKey *pSymWrapper = NULL;
    SymmetricKey *pNewSymKey = NULL;
    TAP_KeyInfo unwrapKeyInfo = {0};
    TAP_AttributeList createAttributes = {0};
    MRsaTapKeyGenArgs rsaTapArgs = {0};
    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;
    ubyte *pWrapped = NULL;
    ubyte4 wrapLen = 0;
    ubyte *pSymId = NULL;
    ubyte4 symIdLen = 0;
    ubyte *pAsymId = NULL;
    ubyte4 asymIdLen = 0;
    
    BulkCtx pCtx = NULL;
    BulkCtx pCtx2 = NULL;
    ubyte pIv[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x00};
    ubyte pPlain[64];
    ubyte pCipher[64] = {0};
    ubyte pRecPlain[64] = {0};
    sbyte4 retLen = 0;

    DIGI_MEMSET(pCipher, 0, 64);
    DIGI_MEMSET(pRecPlain, 0, 64);

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pPlain); ++i)
    {
        pPlain[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    /* Prepare arguments to generate RSA keypair */
    rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_NONE; /* estc_tapSignScheme; 1-6 */
    rsaTapArgs.algKeyInfo.rsaInfo.encScheme = TAP_ENC_SCHEME_NONE;
    rsaTapArgs.keyUsage = TAP_KEY_USAGE_SIGNING; /* estc_tapKeyUsage */
    rsaTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    rsaTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    rsaTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);

    /* Prepare the attributes for creating exportable AES key */
    status = DIGI_MALLOC((void **) &createAttributes.pAttributeList, sizeof(TAP_Attribute));
    if (OK != status)
        goto exit;

    createAttributes.pAttributeList[0].type = TAP_ATTR_KEY_CMK;
    createAttributes.pAttributeList[0].length = sizeof(TAP_KEY_CMK);
    createAttributes.pAttributeList[0].pStructOfType = (void *) &extractTrue;
    createAttributes.listLen = 1;

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.pKeyAttributes = &createAttributes;
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    /* Generate RSA TAP keypair */
    status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(NULL, (void **) &pNewKey, 4096, NULL, akt_tap_rsa, &rsaTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Generate extractable AES key on token */
    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, 128, pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* Get a pure SW RSA public key from the keypair */
    status = CRYPTO_INTERFACE_getRsaSwPubFromTapKey(pNewKey, &pPubKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* Load key into AsymmetricKey so we can get ID */
    status = CRYPTO_loadAsymmetricKey(&asymWrapper, akt_tap_rsa, (void **) &pNewKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Get ID, will be used later as wrapping key ID */
    status = CRYPTO_INTERFACE_TAP_asymGetTapObjectId(&asymWrapper, &pAsymId, &asymIdLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Get ID, will be used later as key to be wrapped ID */
    status = CRYPTO_INTERFACE_TAP_symGetTapObjectId(pSymWrapper, &pSymId, &symIdLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Just for testing, encrypt some data with the generated AES key */
    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx, MODE_CBC, MOCANA_SYM_TAP_ENCRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, pIv, pPlain, 64 * 8, pCipher, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* We must delete the AES context, otherwise we have a pending cipher operation
     * on the token */
    status = CRYPTO_INTERFACE_DeleteAESCtx (&pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Wrap the AES key with the RSA public key */
    status = CRYPTO_INTERFACE_TAP_RSA_wrapSymKey (
        TAP_EXAMPLE_getTapContext(1), TAP_EXAMPLE_getEntityCredentialList(1), TAP_EXAMPLE_getCredentialList(1), 
        pPubKey, pSymId, symIdLen, FALSE, 0, NULL, 0, &pWrapped, &wrapLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* We must specify the key type for unwrap */
    unwrapKeyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    /* Unwrap the wrapped key onto the token */
    status = CRYPTO_INTERFACE_TAP_RSA_unwrapSymKey (
        TAP_EXAMPLE_getTapContext(1), TAP_EXAMPLE_getEntityCredentialList(1), TAP_EXAMPLE_getCredentialList(1), 
        &unwrapKeyInfo, pAsymId, asymIdLen, FALSE, 0, NULL, 0, pWrapped, wrapLen, &pNewSymKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Verification test, decrypt the previously encrypted data using the unwrapped key */
    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pNewSymKey, &pCtx2, MODE_CBC, MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher, 64 * 8, pRecPlain, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pPlain, pRecPlain, 16, &cmp);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, cmp, 0);

exit:

    CRYPTO_uninitAsymmetricKey(&asymWrapper, NULL);
    if (NULL != pNewKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(&pNewKey, NULL);
    }
    if (NULL != pPubKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(&pPubKey, NULL);
    }
    if (NULL != pSymWrapper)
    {
        CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }
    if (NULL != pNewSymKey)
    {
        CRYPTO_INTERFACE_TAP_deleteSymKey(&pNewSymKey);
    }
    if (NULL != pCtx)
    {
        CRYPTO_INTERFACE_DeleteAESCtx(&pCtx);
    }
    if (NULL != pCtx2)
    {
        CRYPTO_INTERFACE_DeleteAESCtx(&pCtx2);
    }
    if (NULL != pSymId)
    {
        DIGI_FREE((void **)&pSymId);
    }
    if (NULL != pAsymId)
    {
        DIGI_FREE((void **)&pAsymId);
    }
    if (NULL != pWrapped)
    {
        DIGI_FREE((void **)&pWrapped);
    }
    if (NULL != createAttributes.pAttributeList)
    {
        DIGI_FREE((void **)&createAttributes.pAttributeList);
    }

    return retVal;
}
#endif /* __ENABLE_DIGICERT_SMP_PKCS11__ */

int crypto_interface_key_wrap_test_init()
{
#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
    MSTATUS status;
    int retVal = 0;
    int i;
    ubyte4 modNum = 1;

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

    status = TAP_EXAMPLE_init(&modNum, 1);
    if (OK != status)
    {
        retVal += 1;
        goto exit;
    }

    retVal += keyWrapTest();
    retVal += keyWrapOAEPTest();

exit:

    TAP_EXAMPLE_clean();

    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);

    return retVal;
#else
    return 0;
#endif
}
