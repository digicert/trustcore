/*
 * pubcrypto_test.c
 *
 * Pubcrypto Test
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
#include "../../crypto/mocasym.h"
#include "../../crypto/keyblob.h"
#include "../../crypto/ca_mgmt.h"

#include "../../../unit_tests/unittest.h"

#if defined(__ENABLE_DIGICERT_ID_CALLBACK__) && defined(__ENABLE_DIGICERT_ASYM_KEY__) && \
    defined(__ENABLE_DIGICERT_SERIALIZE__)
static int pubcrypto_testFailStoreId(
    ubyte *pInId, ubyte4 inIdLen, ubyte *pKeyBuffer, ubyte4 keyBufferLen,
    ubyte *pOutId, ubyte4 *pOutIdLen)
{
    return ERR_NOT_IMPLEMENTED;
}

static ubyte *pTestStoredKey = NULL;
static ubyte4 testStoredKeyLen = 0;
static int testSerializeError = 0;
static int testDeserializeError = 0;
static int testDeserializeCalls = 0;
static ubyte testOutputId[] = {4, 5, 6, 7};

static int pubcrypto_testStoreId(
    ubyte *pInId, ubyte4 inIdLen, ubyte *pKeyBuffer, ubyte4 keyBufferLen,
    ubyte *pOutId, ubyte4 *pOutIdLen)
{
    MSTATUS status;
    if (3 != inIdLen || 1 != pInId[0] || 2 != pInId[1] || 3 != pInId[2])
        return ERR_INVALID_INPUT;
    if (NULL == pOutId || *pOutIdLen < sizeof(testOutputId))
    {
        *pOutIdLen = sizeof(testOutputId);
        return ERR_BUFFER_TOO_SMALL;
    }
    if (1 == testSerializeError)
        return ERR_NOT_IMPLEMENTED;
    if (2 == testSerializeError)
    {
        *pOutIdLen += 1;
        return OK;
    }
    if (NULL != pTestStoredKey)
        return ERR_INVALID_INPUT;
    status = DIGI_MALLOC_MEMCPY((void **) &pTestStoredKey, keyBufferLen,
                                pKeyBuffer, keyBufferLen);
    if (OK != status)
        return status;
    testStoredKeyLen = keyBufferLen;
    status = DIGI_MEMCPY(pOutId, testOutputId, sizeof(testOutputId));
    *pOutIdLen = sizeof(testOutputId);
    return status;
}

static int pubcrypto_testIdCallback(
    ubyte *pId, ubyte4 idLen, ubyte *pKeyBufferOut, ubyte4 *pKeyBufferOutLen)
{
    sbyte4 cmp = 0;
    ++testDeserializeCalls;
    if (1 == testDeserializeError || (2 == testDeserializeError && NULL != pKeyBufferOut))
        return ERR_NOT_IMPLEMENTED;
    if (idLen != sizeof(testOutputId) || NULL == pTestStoredKey)
        return ERR_INVALID_INPUT;
    if (OK != DIGI_MEMCMP(pId, testOutputId, idLen, &cmp) || 0 != cmp)
        return ERR_INVALID_INPUT;
    if (NULL == pKeyBufferOut || *pKeyBufferOutLen < testStoredKeyLen)
    {
        *pKeyBufferOutLen = testStoredKeyLen;
        return ERR_BUFFER_TOO_SMALL;
    }
    if (3 == testDeserializeError)
    {
        *pKeyBufferOutLen += 1;
        return OK;
    }
    *pKeyBufferOutLen = testStoredKeyLen;
    return DIGI_MEMCPY(pKeyBufferOut, pTestStoredKey, testStoredKeyLen);
}
#endif

int pubcrypto_sw_serializeOutRSA(hwAccelDescr hwAccelCtx, randomContext* rc)
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

#if defined(__ENABLE_DIGICERT_ID_CALLBACK__) && defined(__ENABLE_DIGICERT_ASYM_KEY__) && \
    defined(__ENABLE_DIGICERT_SERIALIZE__)
    {
        IdSerializationCallback oldCallback = CRYPTO_getIdSerializationCallback();
        IdDeserializationCallback oldDeserializationCallback = CRYPTO_getIdDeserializationCallback();
        serializedKeyFormat formats[] = {privateKeyInfoDer, privateKeyPem};
        ubyte id[] = {1, 2, 3};
        ubyte *pStoredKey = NULL;
        ubyte4 storedKeyLen = 0;
        ubyte *pRecoveredKey = NULL;
        ubyte4 recoveredKeyLen = 0;
        int previousCalls;
        sbyte4 cmp;
        ubyte4 i;

        CRYPTO_setIdSerializationCallback(pubcrypto_testFailStoreId);
        retVal += UNITTEST_TRUE(0, CRYPTO_getIdSerializationCallback() == pubcrypto_testFailStoreId);
        status = CRYPTO_serializeAsymKeyToStorage(MOC_ASYM(hwAccelCtx)
            &key, privateKeyInfoDer, id, sizeof(id), 0, &pStoredKey, &storedKeyLen);
        retVal += UNITTEST_INT(0, status, ERR_NOT_IMPLEMENTED);
        if (NULL != pStoredKey)
            DIGI_MEMSET_FREE(&pStoredKey, storedKeyLen);
        CRYPTO_setIdSerializationCallback(NULL);
        retVal += UNITTEST_TRUE(0, NULL == CRYPTO_getIdSerializationCallback());

        CRYPTO_setIdSerializationCallback(pubcrypto_testStoreId);
        CRYPTO_setIdDeserializationCallback(pubcrypto_testIdCallback);
        retVal += UNITTEST_TRUE(0, CRYPTO_getIdDeserializationCallback() == pubcrypto_testIdCallback);
        testSerializeError = 1;
        status = CRYPTO_serializeAsymKeyToStorage(MOC_ASYM(hwAccelCtx)
            &key, privateKeyInfoDer, id, sizeof(id), 0, &pStoredKey, &storedKeyLen);
        retVal += UNITTEST_INT(0, status, ERR_NOT_IMPLEMENTED);
        testSerializeError = 2;
        status = CRYPTO_serializeAsymKeyToStorage(MOC_ASYM(hwAccelCtx)
            &key, privateKeyInfoDer, id, sizeof(id), 0, &pStoredKey, &storedKeyLen);
        retVal += UNITTEST_INT(0, status, ERR_INVALID_INPUT);
        testSerializeError = 0;

        for (i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i)
        {
            status = CRYPTO_serializeAsymKeyToStorage(MOC_ASYM(hwAccelCtx)
                &key, formats[i], id, sizeof(id), 0, &pStoredKey, &storedKeyLen);
            retVal += UNITTEST_INT(0, status, OK);
            if (OK == status)
            {
                if (privateKeyInfoDer == formats[i])
                {
                    MKeyOperatorData idInput = {0};
                    MKeyOperatorData wrongInput = {0};
                    MKeyOperatorDataReturn wrongOutput = {0};
                    MKeyObjectInfo idInfo = {0};
                    ubyte *pWrongKey = NULL;
                    ubyte4 wrongKeyLen = 0;
                    int previousCalls = testDeserializeCalls;
                    idInput.pData = pStoredKey;
                    idInput.length = storedKeyLen;
                    status = KeyOperatorId(NULL, NULL, MOC_ASYM_OP_GET_PARAMS,
                                           &idInput, &idInfo, NULL);
                    retVal += UNITTEST_INT(0, status, OK);
                    if (OK == status)
                        retVal += UNITTEST_TRUE(0, idInfo.provider == ID_CALLBACK_PROVIDER);

                    idInfo.provider = ID_CALLBACK_PROVIDER ^ 1;
                    wrongInput.pData = testOutputId;
                    wrongInput.length = sizeof(testOutputId);
                    wrongInput.pAdditionalOpInfo = &idInfo;
                    wrongOutput.ppData = &pWrongKey;
                    wrongOutput.pLength = &wrongKeyLen;
                    status = KeyOperatorId(NULL, NULL, MOC_ASYM_OP_SERIALIZE,
                                           &wrongInput, &wrongOutput, NULL);
                    retVal += UNITTEST_INT(0, status, OK);
                    if (OK == status)
                    {
                        status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx)
                            pWrongKey, wrongKeyLen, NULL, &outKey);
                        retVal += UNITTEST_INT(0, status, ERR_INVALID_INPUT);
                        retVal += UNITTEST_INT(0, testDeserializeCalls, previousCalls);
                    }
                    if (NULL != pWrongKey)
                        DIGI_MEMSET_FREE(&pWrongKey, wrongKeyLen);
                }
                testDeserializeError = 1;
                status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx)
                    pStoredKey, storedKeyLen, NULL, &outKey);
                retVal += UNITTEST_INT(0, status, ERR_NOT_IMPLEMENTED);
                testDeserializeError = 2;
                status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx)
                    pStoredKey, storedKeyLen, NULL, &outKey);
                retVal += UNITTEST_INT(0, status, ERR_NOT_IMPLEMENTED);
                testDeserializeError = 3;
                status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx)
                    pStoredKey, storedKeyLen, NULL, &outKey);
                retVal += UNITTEST_INT(0, status, ERR_INVALID_INPUT);
                testDeserializeError = 0;
                previousCalls = testDeserializeCalls;
                status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx)
                    pStoredKey, storedKeyLen, NULL, &outKey);
                retVal += UNITTEST_INT(0, status, OK);
                retVal += UNITTEST_INT(0, testDeserializeCalls, previousCalls + 2);
                if (OK == status)
                {
                    retVal += UNITTEST_STATUS(0, CRYPTO_matchPublicKey(&key, &outKey));
                    status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx)
                        &outKey, privateKeyInfoDer, &pRecoveredKey, &recoveredKeyLen);
                    retVal += UNITTEST_INT(0, status, OK);
                    if (OK == status)
                    {
                        retVal += UNITTEST_INT(0, recoveredKeyLen, testStoredKeyLen);
                        if (recoveredKeyLen == testStoredKeyLen)
                        {
                            status = DIGI_MEMCMP(
                                pRecoveredKey, pTestStoredKey, recoveredKeyLen, &cmp);
                            retVal += UNITTEST_STATUS(0, status);
                            if (OK == status)
                                retVal += UNITTEST_INT(0, cmp, 0);
                        }
                    }
                    if (NULL != pRecoveredKey)
                        DIGI_MEMSET_FREE(&pRecoveredKey, recoveredKeyLen);
                }
                CRYPTO_uninitAsymmetricKey(&outKey, NULL);
                CRYPTO_initAsymmetricKey(&outKey);
                previousCalls = testDeserializeCalls;
                status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx)
                    pTestStoredKey, testStoredKeyLen, NULL, &outKey);
                retVal += UNITTEST_INT(0, status, OK);
                retVal += UNITTEST_INT(0, testDeserializeCalls, previousCalls);
                if (OK == status)
                    retVal += UNITTEST_STATUS(0, CRYPTO_matchPublicKey(&key, &outKey));
                CRYPTO_uninitAsymmetricKey(&outKey, NULL);
                CRYPTO_initAsymmetricKey(&outKey);
            }
            if (NULL != pStoredKey)
                DIGI_MEMSET_FREE(&pStoredKey, storedKeyLen);
            if (NULL != pTestStoredKey)
                DIGI_MEMSET_FREE(&pTestStoredKey, testStoredKeyLen);
            testStoredKeyLen = 0;
        }
        CRYPTO_setIdDeserializationCallback(NULL);
        retVal += UNITTEST_TRUE(0, NULL == CRYPTO_getIdDeserializationCallback());
        CRYPTO_setIdDeserializationCallback(oldDeserializationCallback);
        CRYPTO_setIdSerializationCallback(oldCallback);
    }
#endif

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

    retVal += pubcrypto_sw_serializeOutRSA(hwAccelCtx, g_pRandomContext);
    retVal += pubcrypto_sw_serializeOutDSA(MOC_DSA(hwAccelCtx) g_pRandomContext);
    retVal += pubcrypto_sw_serializeOutECC(MOC_RSA(hwAccelCtx) g_pRandomContext);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

exit:

    DIGICERT_freeDigicert();

    return retVal;
}
