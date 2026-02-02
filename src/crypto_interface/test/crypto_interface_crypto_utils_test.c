/*
 * crypto_interface_crypto_utils_test.c
 *
 * test cases for crypto utils API in crypto_utils.h
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

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "crypto_interface_tap_example.h"
#include "../cryptointerface.h"
#include "../../crypto/mocasymkeys/tap/rsatap.h"
#include "../tap/tap.h"
#endif

#include "../../crypto/cert_store.h"
#include "../../crypto/crypto_utils.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static int gettype_and_bitlength_test(
    ubyte *pKeyData, ubyte4 keyDataLen, ubyte *pPassword, ubyte4 passwordLen,
    ubyte4 expectedKeyType, ubyte4 expectedBitLen, ubyte2 expectedProvider)
{
    int retVal = 0;
    MSTATUS status;
    ubyte4 keyType, keyBitLength;
    ubyte2 provider;
    ubyte4 moduleId;

    status = CRYPTO_UTILS_getAsymmetricKeyInfo(MOC_ASYM(gpHwAccelCtx)
        pKeyData, keyDataLen, pPassword, passwordLen, &keyType, &keyBitLength,
        &provider, &moduleId);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    retVal += UNITTEST_INT(__MOC_LINE__, keyType, expectedKeyType);
    retVal += UNITTEST_INT(__MOC_LINE__, keyBitLength, expectedBitLen);
    retVal += UNITTEST_INT(__MOC_LINE__, provider, expectedProvider);
    /* Ensure module ID is non-zero */
    if (0 == moduleId)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, moduleId);
    }

exit:

    return retVal;
}

static int gettype_and_bitlength_by_file_test(
    sbyte *pKey, ubyte *pPassword, ubyte4 passwordLen, ubyte4 expectedKeyType,
    ubyte4 expectedBitLen, ubyte2 expectedProvider)
{
    int retVal = 0;
    MSTATUS status;
    ubyte *pKeyData = NULL;
    ubyte4 keyDataLen = 0;

    status = DIGICERT_readFile(pKey, &pKeyData, &keyDataLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    retVal += gettype_and_bitlength_test(
        pKeyData, keyDataLen, pPassword, passwordLen, expectedKeyType,
        expectedBitLen, expectedProvider);

exit:
    DIGI_FREE((void **) &pKeyData);
    return retVal;
}

#if defined(__ENABLE_DIGICERT_TAP__)

static int gettype_and_bitlength_tap_key_test(
    ubyte4 expectedKeyType, ubyte4 expectedBitLen,
    ubyte2 expectedProvider)
{
    int retVal = 0;
    MSTATUS status;
    MRsaTapKeyGenArgs rsaTapArgs = {0};
    RSAKey *pNewKey = NULL;
    AsymmetricKey genKey = {0};
    ubyte *pSerializedKey = NULL;
    ubyte4 serializedKeyLen = 0;

    switch (expectedKeyType)
    {
        case akt_tap_rsa:
            rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_NONE;
            rsaTapArgs.algKeyInfo.rsaInfo.encScheme = TAP_ENC_SCHEME_NONE;
            rsaTapArgs.keyUsage = TAP_KEY_USAGE_GENERAL;
            rsaTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
            rsaTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
            rsaTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);

            status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(
                NULL, (void **) &pNewKey, expectedBitLen, NULL, expectedKeyType,
                &rsaTapArgs);
            if (OK != status)
            {
                retVal += UNITTEST_STATUS(__MOC_LINE__, status);
                goto exit;
            }

            genKey.type = expectedKeyType;
            genKey.key.pRSA = pNewKey;
            break;

        default:
            retVal += UNITTEST_STATUS(__MOC_LINE__, ERR_BAD_KEY_TYPE);
            goto exit;
    }

    status = CRYPTO_serializeAsymKey(
        &genKey, mocanaBlobVersion2, &pSerializedKey, &serializedKeyLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += gettype_and_bitlength_test(
        pSerializedKey, serializedKeyLen, NULL, 0, expectedKeyType,
        expectedBitLen, expectedProvider);

exit:
    CRYPTO_uninitAsymmetricKey(&genKey, NULL);
    DIGI_FREE((void **) &pSerializedKey);
    return retVal;
}
#endif

int crypto_interface_crypto_utils_test_init()
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

    retVal += gettype_and_bitlength_by_file_test(
        (sbyte *) "testRsaJsonKey.pem", NULL, 0, akt_rsa, 2048, 0);
    retVal += gettype_and_bitlength_by_file_test(
        (sbyte *) "testEccJsonKey.pem", NULL, 0, akt_ecc, 384, 0);
#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) || !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
    retVal += gettype_and_bitlength_by_file_test(
        (sbyte *) "dsakey.pem", NULL, 0, akt_dsa, 1024, 0);
#endif

#ifdef __ENABLE_DIGICERT_TAP__
    status = TAP_EXAMPLE_init(&modNum, 1);
    if (OK != status)
    {
        retVal += 1;
        goto exit;
    }

    retVal += gettype_and_bitlength_tap_key_test(
        akt_tap_rsa, 2048, (ubyte2) TAP_EXAMPLE_getProvider());

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
