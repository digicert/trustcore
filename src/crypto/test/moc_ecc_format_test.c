/*
 * moc_ecc_format_test.c
 *
 * test cases for ECC key format methods.
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
#include "../../crypto/primeec.h"

#include <stdio.h>

/*
 * THIS IS ONLY FOR WORKING FOR CLION! SWITCH BACK FOR MERGE REQUEST.
 * THIS IS SO THE TWO TESTS CAN BE INCLUDED IN SAME main.c
 *
 * DO NOT FORGET TO CHANGE THIS BACK
 */
static MocCtx gpMocCtx = NULL;
static void *gOpInfo = NULL;
//extern MocCtx gpMocCtx = NULL;
//extern *gOpInfo = NULL;

/* generates a key with. All that is needed is curve id and random
 * data returns status. */

MSTATUS EccKeyCloneTest(ubyte4 curveId)
{
    MSTATUS status = ERR_NULL_POINTER;

    /* TEST DATA VARIABLES DECLARED HERE */
    /* for EC_getCurveId */
    ubyte4 keyCurveId = 0, cloneKeyCurveId = 1;

    /* for EC_getElemByteStringLen */
    sbyte4 elemLen = 0, cloneElemLen = 1;

    /* for EC_getPointByteStringLen */
    sbyte4 pointLen = 0, clonePointLen = 1;

    /* for EC_writePublicKeyToBuffer */
    ubyte pubKeyBuffer[133] = {};
    ubyte clonePubKeyBuffer[133] = {};

    sbyte4 writeBufCmp = 1;

    /* for EC_PublicKeyToBufferAlloc */
    ubyte *pPubKey = NULL;
    ubyte4 pubKeyLen = 0;

    ubyte *pClonePubKey = NULL;
    ubyte4 clonePubKeyLen = 1;

    sbyte4 writePubCmp = 1;

    /* for EC_getKeyParametersAlloc */
    MEccKeyTemplate pTemplate[1];
    MEccKeyTemplate pCloneTemplate[1];

    sbyte4 templateCmp = 1;

    /* for EC_newPublicKeyFromByteString */
    ECCKey *pEccPubKey = NULL;
    ECCKey *pCloneEccPubKey = NULL;

    byteBoolean eccPubCmp = 1;

    /* KEYS USED FOR TEST */
    ECCKey *pKey = NULL;
    ECCKey *pCloneKey = NULL;

    /* for EC_equalKey */
    byteBoolean equalBool = 0;

    /* create ECCKey object */
    status = EC_generateKeyPairAlloc(curveId, &pKey, RANDOM_rngFun,
                                       g_pRandomContext);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* clone the key */
    status = EC_cloneKey(&pCloneKey, pKey);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* test if they are equal. */
    status = EC_equalKey(pKey, pCloneKey, &equalBool);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if (TRUE != equalBool)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* get curveIds */
    status = EC_getCurveIdFromKey(pKey, &keyCurveId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = EC_getCurveIdFromKey(pCloneKey, &cloneKeyCurveId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* compare results */
    if (keyCurveId != cloneKeyCurveId)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* get length of elements */
    status = EC_getElementByteStringLen(pKey, &elemLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }


    status = EC_getElementByteStringLen(pCloneKey, &cloneElemLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* compare results */
    if (elemLen != cloneElemLen)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* get length of point */
    status = EC_getPointByteStringLenEx(pKey, &pointLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = EC_getPointByteStringLenEx(pCloneKey, &clonePointLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* compare results */
    if (pointLen != clonePointLen)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* write public keys to buffers */
    status = EC_writePublicKeyToBuffer(pKey, pubKeyBuffer, (ubyte4) pointLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = EC_writePublicKeyToBuffer(pCloneKey, clonePubKeyBuffer,
                                       (ubyte4) clonePointLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* compare buffers */
    status = DIGI_MEMCMP(pubKeyBuffer, clonePubKeyBuffer, (usize) pointLen,
                        &writeBufCmp);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if (0 != writeBufCmp)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;

    }

    /* allocate and test buffers */
    status = EC_writePublicKeyToBufferAlloc(pKey, &pPubKey, &pubKeyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = EC_writePublicKeyToBufferAlloc(pCloneKey, &pClonePubKey,
                                            &clonePubKeyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* check if buffers are different lengths */
    if (pubKeyLen != clonePubKeyLen)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;

    }

    status = DIGI_MEMCMP(pPubKey, pClonePubKey, (usize) pubKeyLen,
                        &writePubCmp);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }


    /* check that values of buffer are equal */
    if (0 != writePubCmp)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* test that template are created the same */
    status = EC_getKeyParametersAlloc(pKey, pTemplate,
                                      MOC_GET_PRIVATE_KEY_DATA);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = EC_getKeyParametersAlloc(pCloneKey, pCloneTemplate,
                                      MOC_GET_PRIVATE_KEY_DATA);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* how to compare template? */

    /* make public keys */
    status = EC_newPublicKeyFromByteString(keyCurveId, &pEccPubKey, pPubKey,
                                           pubKeyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = EC_newPublicKeyFromByteString(cloneKeyCurveId, &pCloneEccPubKey,
                                           pClonePubKey, clonePubKeyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* compare public keys */
    status = EC_equalKey(pEccPubKey, pCloneEccPubKey, &eccPubCmp);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK > status){
        goto exit;
    }

    if(TRUE != eccPubCmp)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    /* clean up memory */
    (void) EC_freeKeyTemplate (pKey, pTemplate);
    (void) EC_freeKeyTemplate (pCloneKey, pCloneTemplate);
    (void) DIGI_FREE((void **) &pPubKey);
    (void) DIGI_FREE((void **) &pClonePubKey);
    (void) EC_deleteKeyEx(&pKey);
    (void) EC_deleteKeyEx(&pCloneKey);
    (void) EC_deleteKeyEx(&pEccPubKey);
    (void) EC_deleteKeyEx(&pCloneEccPubKey);

    return status;
}


/*----------------------------------------------------------------------------*/

int moc_ecc_format_test_init()
{

    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;


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

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }

    errorCount = EccKeyCloneTest(cid_EC_P192);
    errorCount = (errorCount + EccKeyCloneTest(cid_EC_P224));
    errorCount = (errorCount + EccKeyCloneTest(cid_EC_P256));
    errorCount = (errorCount + EccKeyCloneTest(cid_EC_P384));
    errorCount = (errorCount + EccKeyCloneTest(cid_EC_P521));

exit:
    DIGICERT_free(&gpMocCtx);
    return errorCount;
}
