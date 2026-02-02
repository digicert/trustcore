/*
 * pubcrypto_test.c
 *
 * Pubcrypto Test
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

#include "../../common/moptions.h"

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/tree.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../common/initmocana.h"
#include "../../crypto/crypto.h"
#include "../../crypto/rsa.h"
#include "../../crypto/dsa.h"
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/keyblob.h"
#include "../../crypto/ca_mgmt.h"

#include "../../../unit_tests/unittest.h"

int pubcrypto_sw_serializeOutRSA(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext* rc)
{
    MSTATUS status;
    int retVal = 0;
    AsymmetricKey key, outKey;
    ubyte* buffer = 0;
    ubyte4 bufferLen;

    /* Generate RSA key to serializeOut */
    if (OK > ( status = CRYPTO_initAsymmetricKey(&key)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    if (OK > ( status = CRYPTO_initAsymmetricKey(&outKey)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    if (OK > (status = CRYPTO_createRSAKey(&key, NULL)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    if (OK > (status = RSA_generateKey(MOC_RSA(hwAccelCtx)
                                       rc, key.key.pRSA, 2048, NULL)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    /* testing for KEYBLOB_makeKeyBlobEx */
    if(OK > (status = KEYBLOB_makeKeyBlobEx(&key, &buffer, &bufferLen)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    if(OK > (status = KEYBLOB_extractKeyBlobEx(buffer, bufferLen, &outKey)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    retVal += UNITTEST_STATUS( 0, CRYPTO_matchPublicKey(&key, &outKey));

exit:
    FREE(buffer);
    CRYPTO_uninitAsymmetricKey( &key, NULL );
    CRYPTO_uninitAsymmetricKey( &outKey, NULL );
    return retVal;
}

int pubcrypto_sw_serializeOutDSA(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* rc)
{
    MSTATUS status;
    vlong* pVlongQueue = 0;
    int retVal = 0;
    AsymmetricKey key, outKey;
    ubyte* buffer = 0;
    ubyte4 bufferLen;

    /* Generate RSA key to serializeOut */
    if (OK > ( status = CRYPTO_initAsymmetricKey(&key)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    if (OK > ( status = CRYPTO_initAsymmetricKey(&outKey)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    if (OK > (status = CRYPTO_createDSAKey(&key, &pVlongQueue)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    if(OK > (status = DSA_generateKey(MOC_DSA(hwAccelCtx) rc, key.key.pDSA, 2048, NULL, NULL, NULL, &pVlongQueue)))
    {
        retVal += UNITTEST_STATUS( 0 , status);
        goto exit;
    }

    /* testing for KEYBLOB_makeKeyBlobEx */
    if(OK > (status = KEYBLOB_makeKeyBlobEx(&key, &buffer, &bufferLen)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    if(OK > (status = KEYBLOB_extractKeyBlobEx(buffer, bufferLen, &outKey)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    retVal += UNITTEST_STATUS( 0, CRYPTO_matchPublicKey(&key, &outKey));

exit:
    FREE(buffer);
    CRYPTO_uninitAsymmetricKey( &key, 0 );
    CRYPTO_uninitAsymmetricKey( &outKey, 0 );
    VLONG_freeVlongQueue( &pVlongQueue );

    return retVal;
}

int pubcrypto_sw_serializeOutECC(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext* rc)
{
    MSTATUS status;
    int retVal = 0;
    AsymmetricKey key, outKey;
    ubyte* buffer = 0;
    ubyte4 bufferLen;

    /* Generate ECC key to serializeOut */
    if (OK > ( status = CRYPTO_initAsymmetricKey(&key)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    if (OK > ( status = CRYPTO_initAsymmetricKey(&outKey)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    if (OK > (status = CRYPTO_createECCKey(&key, EC_P256)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    if(OK > (status = EC_generateKeyPair(EC_P256, RANDOM_rngFun, rc, key.key.pECC->k, key.key.pECC->Qx, key.key.pECC->Qy)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }
    key.key.pECC->privateKey = TRUE;

    /* testing for KEYBLOB_makeKeyBlobEx */
    if(OK > (status = KEYBLOB_makeKeyBlobEx(&key, &buffer, &bufferLen)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    if(OK > (status = KEYBLOB_extractKeyBlobEx(buffer, bufferLen, &outKey)))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    retVal += UNITTEST_STATUS( 0, CRYPTO_matchPublicKey(&key, &outKey));

exit:
    FREE( buffer);
    CRYPTO_uninitAsymmetricKey( &key, NULL );
    CRYPTO_uninitAsymmetricKey( &outKey, NULL );

    return retVal;
}

/*--------------------------------------------------------------------------*/
int pubcrypto_test_all()
{
    
    int retVal = 0;
    hwAccelDescr hwAccelCtx;

    InitMocanaSetupInfo setupInfo = {
        .MocSymRandOperator = NULL,
        .pOperatorInfo = NULL,
        /**********************************************************
         *************** DO NOT USE MOC_NO_AUTOSEED ***************
         ***************** in any production code. ****************
         **********************************************************/
        .flags = MOC_NO_AUTOSEED,
        .pStaticMem = NULL,
        .staticMemSize = 0,
        .pDigestOperators = NULL,
        .digestOperatorCount = 0,
        .pSymOperators = NULL,
        .symOperatorCount = 0,
        .pKeyOperators = NULL,
        .keyOperatorCount = 0
    };
    
    retVal += UNITTEST_STATUS(0, DIGICERT_initialize(&setupInfo, NULL));
    if (retVal) return retVal;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        goto exit;

    retVal += pubcrypto_sw_serializeOutRSA(MOC_RSA(hwAccelCtx) g_pRandomContext);
    retVal += pubcrypto_sw_serializeOutDSA(MOC_DSA(hwAccelCtx) g_pRandomContext);
    retVal += pubcrypto_sw_serializeOutECC(MOC_RSA(hwAccelCtx) g_pRandomContext);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

exit:

    DIGICERT_freeDigicert();

    return retVal;
}
