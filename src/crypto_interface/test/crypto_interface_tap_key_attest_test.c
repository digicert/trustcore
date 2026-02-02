/*
 * crypto_interface_tap_key_attest_test.c
 *
 * test cases for TAP key attestation
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

#include "../../common/mstdlib.h"
#include "../../crypto/pkcs10.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include "../../crypto_interface/crypto_interface_priv.h"
#include "../../crypto/test/nonrandop.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "crypto_interface_tap_example.h"
#include "../cryptointerface.h"
#include "../../crypto/mocasymkeys/tap/rsatap.h"
#include "../../crypto/mocasymkeys/tap/ecctap.h"
#endif

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

#ifdef __ENABLE_DIGICERT_TAP__

static int generateTapAttestKey(AsymmetricKey *pKey, ubyte4 keyType)
{
    MSTATUS status;
    MRsaTapKeyGenArgs rsaTapArgs = { 0 };
    MEccTapKeyGenArgs eccTapArgs = { 0 };
    void *pNewKey = NULL;

    CRYPTO_uninitAsymmetricKey(pKey, NULL);
    CRYPTO_initAsymmetricKey(pKey);

    switch(keyType)
    {
        case akt_tap_rsa:
            rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
            rsaTapArgs.algKeyInfo.rsaInfo.encScheme = TAP_ENC_SCHEME_NONE;
            rsaTapArgs.keyUsage = TAP_KEY_USAGE_ATTESTATION;
            rsaTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
            rsaTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
            rsaTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);

            status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(
                MOC_RSA(gpHwAccelCtx) NULL, (void **) &pNewKey, 2048, NULL,
                keyType, &rsaTapArgs);
            if (OK != status)
                goto exit;

            break;

        case akt_tap_ecc:
            eccTapArgs.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_NONE;
            eccTapArgs.keyUsage = TAP_KEY_USAGE_ATTESTATION;
            eccTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
            eccTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
            eccTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);

            status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(
                MOC_ECC(gpHwAccelCtx) cid_EC_P256, (void **) &pNewKey,
                RANDOM_rngFun, g_pRandomContext, keyType, &eccTapArgs);
            if (OK != status)
                goto exit;

            break;

        default:
            status = ERR_BAD_KEY_TYPE;
            goto exit;
    }

    status = CRYPTO_loadAsymmetricKey(pKey, keyType, (void **) &pNewKey);
    if (OK != status)
        goto exit;

exit:

    return status;
}

static int testTapAttestAsn1Cert()
{
    int retVal = 0;
    MSTATUS status;
    AsymmetricKey tapKey = { 0 };
    nameAttr pNames1[] =
    {
        {countryName_OID, 0, (ubyte*)"US", 2}
    };
    nameAttr pNames2[] =
    {
        {stateOrProvinceName_OID, 0, (ubyte*)"California", 10}
    };
    nameAttr pNames3[] =
    {
        {localityName_OID, 0, (ubyte*)"Menlo Park", 10}
    };
    nameAttr pNames4[] =
    {
        {organizationName_OID, 0, (ubyte*)"Mocana Corporation", 18}
    };
    nameAttr pNames5[] =
    {
        {organizationalUnitName_OID, 0, (ubyte*)"Engineering", 11}
    };
    nameAttr pNames6[] =
    {
        {commonName_OID, 0, (ubyte*)"tapattest", 10}
    };
    nameAttr pNames7[] =
    {
        {pkcs9_emailAddress_OID, 0, (ubyte*)"info@mocana.com", 15}
    };
    relativeDN pRDNs[] = {
        {pNames1, 1},
        {pNames2, 1},
        {pNames3, 1},
        {pNames4, 1},
        {pNames5, 1},
        {pNames6, 1},
        {pNames7, 1}
    };
    certDistinguishedName CDN = {
        pRDNs,
        7,
        "030526000126Z",
        "330524230126Z"
    };
    ubyte *pReq = NULL;
    ubyte4 reqLen = 0;

    status = generateTapAttestKey(&tapKey, akt_tap_rsa);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = PKCS10_GenerateCertReqFromDNEx(
        &tapKey, ht_sha256, &CDN, NULL, &pReq, &reqLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

exit:

    DIGI_FREE((void **) &pReq);
    CRYPTO_uninitAsymmetricKey(&tapKey, NULL);

    return retVal;
}

static int testTapAttest()
{
    int retVal = 0;

    retVal += testTapAttestAsn1Cert();

    return retVal;
}

#endif /* __ENABLE_DIGICERT_TAP__ */

int crypto_interface_tap_key_attest_test_init()
{
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

#ifdef __ENABLE_DIGICERT_TAP__
    status = TAP_EXAMPLE_init(&modNum, 1);
    if (OK != status)
    {
        retVal += 1;
        goto exit;
    }

    retVal += testTapAttest();

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
