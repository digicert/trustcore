/*
 * sec_key_test.c
 *
 * SEC Key  Test
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

#include "../sec_key.c"

#include "../../../unit_tests/unittest.h"


static const sbyte* gSecFiles[] = 
{
    /* private key file,          public key file */
    FILE_PATH("seckey521_1.der"), FILE_PATH("pubseckey521_1.der"),
    FILE_PATH("seckey521_2.der"), FILE_PATH("pubseckey521_2.der"), 
};

/*--------------------------------------------------------------------------*/

static int ReadSECKey( int hint, const sbyte* fileName, AsymmetricKey* pKey)
{
    int retVal;
    ubyte* newBuffer = 0;
    ubyte4 newBufferLen;
    ubyte* writeBuffer = 0;
    ubyte4 writeBufferLen;
    sbyte4 res;

    if (retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( fileName,  
                                                     &newBuffer,
                                                     &newBufferLen)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(hint, SEC_getKey(newBuffer, newBufferLen,
                                               pKey)))
    {
        goto exit;
    }

    if ( retVal = UNITTEST_TRUE(hint, pKey->type == akt_ecc))
    {
        goto exit;
    }

    if ( pKey->key.pECC->privateKey)
    {
        ECCKey* pECCKey = pKey->key.pECC;
        retVal += UNITTEST_STATUS( hint, EC_verifyKeyPair( pECCKey->pCurve, pECCKey->k, pECCKey->Qx, pECCKey->Qy));
    }
    else
    {
        ECCKey* pECCKey = pKey->key.pECC;
        retVal += UNITTEST_STATUS( hint, EC_verifyPublicKey( pECCKey->pCurve, pECCKey->Qx, pECCKey->Qy));
    }
    if ( retVal)  goto exit;

    /* write test */
    retVal += UNITTEST_STATUS( hint, SEC_setKey( pKey, &writeBuffer, &writeBufferLen));
    if ( retVal)  goto exit;

    retVal += UNITTEST_TRUE(hint, writeBufferLen == newBufferLen);

    DIGI_MEMCMP( writeBuffer, newBuffer, writeBufferLen, &res);
    retVal += UNITTEST_TRUE(hint, 0 == res);

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

int sec_key_test_all()
{
    int i, retVal = 0;
    hwAccelDescr hwAccelCtx;
    AsymmetricKey pubKey;
    AsymmetricKey privateKey;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    CRYPTO_initAsymmetricKey(&pubKey);
    CRYPTO_initAsymmetricKey(&privateKey);

    for (i = 0; i < COUNTOF(gSecFiles); ++i)
    {
        if (i & 1) /* public key file */
        {

            retVal += ReadSECKey( i, gSecFiles[i], &pubKey);
            /* verify public matches private */
            retVal += CRYPTO_matchPublicKey( &privateKey, &pubKey);

        }
        else  /* private key file */
        {
            retVal += ReadSECKey( i, gSecFiles[i], &privateKey);
        }

    }

    CRYPTO_uninitAsymmetricKey( &pubKey, 0);
    CRYPTO_uninitAsymmetricKey( &privateKey, 0);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}

int sec_key_test_no_publickey()
{
    AsymmetricKey asymKey;
    int retVal = 0;
    MSTATUS status;
    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;

    CRYPTO_initAsymmetricKey(&asymKey);
	
    status = DIGICERT_readFile("sec_key_no_pub.der", &pKey, &keyLen);
    if (OK != status)
    {
        retVal++;
        goto exit;
    }

    status = SEC_getKey(pKey, keyLen, &asymKey);
    if (OK != status)
    {
        retVal++;
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pKey);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    return retVal;
}
