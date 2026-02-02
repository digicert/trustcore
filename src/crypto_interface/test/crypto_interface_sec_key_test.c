/*
 * crypto_interface_sec_key_test.c
 *
 * SEC Key Test
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
#include "../../crypto/sec_key.c"

#include "../../../unit_tests/unittest.h"
#include "../../common/initmocana.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static const sbyte* gSecFiles[] = 
{
    /* private key file,          public key file */
    (const sbyte*) FILE_PATH("seckey521_1.der"), (const sbyte*) FILE_PATH("pubseckey521_1.der"),
    (const sbyte*) FILE_PATH("seckey521_2.der"), (const sbyte*) FILE_PATH("pubseckey521_2.der"),
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)
    (const sbyte*) FILE_PATH("seckey25519.der"), (const sbyte*) FILE_PATH("pubseckey25519.der"),
#endif
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
    (const sbyte*) FILE_PATH("seckey448.der"), (const sbyte*) FILE_PATH("pubseckey448.der"),
#endif
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)
    (const sbyte*) FILE_PATH("seckey25519a.der"), (const sbyte*) FILE_PATH("pubseckey25519.der"),
#endif
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
    (const sbyte*) FILE_PATH("seckey448a.der"), (const sbyte*) FILE_PATH("pubseckey448.der"),
#endif
};

/*--------------------------------------------------------------------------*/

static int ReadSECKey( int hint, const sbyte* fileName, AsymmetricKey* pKey, ubyte4 expectedKeyType, byteBoolean doWriteTest)
{
    int retVal;
    ubyte* newBuffer = 0;
    ubyte4 newBufferLen;
    ubyte* writeBuffer = 0;
    ubyte4 writeBufferLen;
    sbyte4 res;
    intBoolean isPriv = FALSE;
    byteBoolean vfy = FALSE;

    retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( (const char *) fileName, &newBuffer, &newBufferLen));
    if ( retVal)  goto exit;

    retVal = UNITTEST_STATUS(hint, SEC_getKey(MOC_ECC(gpHwAccelCtx) newBuffer, newBufferLen, pKey));
    if ( retVal)  goto exit;

    retVal = UNITTEST_TRUE(hint, expectedKeyType == pKey->type);
    if ( retVal)  goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    retVal = UNITTEST_STATUS(hint, CRYPTO_INTERFACE_EC_isKeyPrivate(pKey->key.pECC, &isPriv));
#else
    retVal = UNITTEST_STATUS(hint, EC_isKeyPrivate(pKey->key.pECC, &isPriv));
#endif
    if ( retVal) goto exit;

    if (isPriv)
    {
        ECCKey* pECCKey = pKey->key.pECC;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        retVal += UNITTEST_STATUS( hint, CRYPTO_INTERFACE_EC_verifyKeyPairAux( MOC_ECC(gpHwAccelCtx) pKey->key.pECC, pKey->key.pECC, &vfy));
#else
        retVal += UNITTEST_STATUS( hint, EC_verifyKeyPairEx( MOC_ECC(gpHwAccelCtx) pKey->key.pECC, pKey->key.pECC, &vfy));
#endif
    }
    else
    {
        ECCKey* pECCKey = pKey->key.pECC;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        retVal += UNITTEST_STATUS( hint, CRYPTO_INTERFACE_EC_verifyPublicKeyAux( MOC_ECC(gpHwAccelCtx) pKey->key.pECC, &vfy));
#else
        retVal += UNITTEST_STATUS( hint, EC_verifyPublicKeyEx( MOC_ECC(gpHwAccelCtx) pKey->key.pECC, &vfy));
#endif
    }
    if ( retVal)  goto exit;

    retVal += UNITTEST_STATUS( hint, TRUE == vfy);
    if ( retVal)  goto exit;
    
    if (doWriteTest)
    {
        /* write test */
        retVal += UNITTEST_STATUS( hint, SEC_setKey(MOC_ASYM(gpHwAccelCtx) pKey, &writeBuffer, &writeBufferLen));
        if ( retVal)  goto exit;
        
        retVal += UNITTEST_TRUE(hint, writeBufferLen == newBufferLen);
        
        DIGI_MEMCMP( writeBuffer, newBuffer, writeBufferLen, &res);
        retVal += UNITTEST_TRUE(hint, 0 == res);
    }
    
exit:
    
    if (newBuffer)
    {
        FREE(newBuffer);
    }
    if (writeBuffer)
    {
        FREE(writeBuffer);
    }

    return retVal;
}

/*--------------------------------------------------------------------------*/

static int no_pub_sec_key_test(void)
{
    AsymmetricKey asymKey;
    int retVal = 0;
    MSTATUS status;
    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;
	
    CRYPTO_initAsymmetricKey(&asymKey);

    status = DIGICERT_readFile("sec_key_no_pub.der", &pKey, &keyLen);
    retVal += UNITTEST_STATUS( __MOC_LINE__, status);

    status = SEC_getKey(MOC_ECC(gpHwAccelCtx) pKey, keyLen, &asymKey);
    retVal += UNITTEST_STATUS( __MOC_LINE__, status);
    
exit:

    DIGI_FREE((void **) &pKey);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    return retVal;
}

/*--------------------------------------------------------------------------*/

int crypto_interface_sec_key_test_all()
{
    MSTATUS status;
    int i, retVal = 0;
    AsymmetricKey pubKey;
    AsymmetricKey privateKey;
    ubyte4 keyType = akt_ecc;
    byteBoolean doWriteTest = TRUE;

    InitMocanaSetupInfo setupInfo = { 0 };
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;
    
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        retVal = 1;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
    
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

    CRYPTO_initAsymmetricKey(&pubKey);
    CRYPTO_initAsymmetricKey(&privateKey);

    for (i = 0; i < COUNTOF(gSecFiles); ++i)
    {
        /* key files after the first 4 are Edward's curves */
        if (i == 4)
        {
            keyType = akt_ecc_ed;
#ifndef __ENABLE_DIGICERT_EDDSA_PRIV_W_PUB_SER__
            doWriteTest = FALSE;  /* public key will be added so rewriting key won't match */
#endif
        }
        /* last 2 private key files have extra params that won't be regenerated */
        if (i == 8)
            doWriteTest = FALSE;

        if (i & 1) /* public key file */
        {
            retVal += ReadSECKey( i, gSecFiles[i], &pubKey, keyType, TRUE);
            /* verify public matches private */
            
            /* last 2 private key files are different from the public keys */
            if (i < 8)
            {
                retVal += UNITTEST_STATUS( 99, CRYPTO_matchPublicKey( &privateKey, &pubKey));
            }
        }
        else  /* private key file */
        {
            retVal += ReadSECKey( i, gSecFiles[i], &privateKey, keyType, doWriteTest);
        }
    }

    CRYPTO_uninitAsymmetricKey( &pubKey, 0);
    CRYPTO_uninitAsymmetricKey( &privateKey, 0);

    retVal += no_pub_sec_key_test();

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);
    
    return retVal;
}
