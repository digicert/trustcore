/*
 * dsa_test.c
 *
 * unit test for dsa.c
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

#include "../dsa.c"
#include "../../common/initmocana.h"
#include "../../../unit_tests/unittest.h"
#include "../sha512.h"
#include "../dsa2.h"

#ifdef __RTOS_WIN32__
#include <stdio.h>
#include <string.h>
#endif

/*------------------------------------------------------------------*/

static const ubyte m_dsaKeyBlob[] =
{
    0x00, 0x00, 0x00, 0x41, 0x00, 0x99, 0x6e, 0xf0, 0xeb, 0x5a, 0xd3, 0x39, 0x0b, 0x7b, 0x1b, 0xd6,
    0xb3, 0xe3, 0x5f, 0xe2, 0x54, 0x74, 0x30, 0xb0, 0x11, 0x52, 0xf3, 0xc3, 0x92, 0xcc, 0x45, 0x95,
    0x1e, 0x02, 0xca, 0x26, 0x71, 0x87, 0x2a, 0x66, 0xb6, 0x74, 0x6d, 0x1b, 0x88, 0xb6, 0x32, 0xb0,
    0x47, 0xc0, 0xeb, 0x82, 0xcc, 0xb2, 0x20, 0x36, 0x13, 0xbc, 0xaa, 0xbf, 0x0e, 0x9b, 0x8f, 0xef,
    0x34, 0x37, 0x32, 0x2c, 0x25, 0x00, 0x00, 0x00, 0x15, 0x00, 0xe2, 0x1c, 0xe1, 0x57, 0x83, 0x92,
    0xd3, 0xaa, 0xdf, 0xb8, 0x86, 0x52, 0x29, 0x6d, 0xee, 0xcc, 0xa8, 0xa5, 0xb2, 0x51, 0x00, 0x00,
    0x00, 0x40, 0x59, 0xba, 0x81, 0xdd, 0xa8, 0x29, 0x52, 0x3b, 0x12, 0x80, 0x0b, 0xfd, 0x53, 0x20,
    0x47, 0xe2, 0x75, 0x74, 0x26, 0x37, 0x68, 0x4a, 0x13, 0x32, 0x86, 0x94, 0x98, 0x7f, 0x25, 0x23,
    0xc8, 0x9a, 0xfb, 0x88, 0x0a, 0x4a, 0xa1, 0x2f, 0xc9, 0xa2, 0x44, 0x12, 0xfa, 0x33, 0x92, 0x00,
    0x83, 0xb4, 0xd2, 0x5e, 0xf9, 0x01, 0x8c, 0xd3, 0x1f, 0x62, 0x6c, 0xc9, 0x12, 0x1e, 0x26, 0x63,
    0xd1, 0x88, 0x00, 0x00, 0x00, 0x41, 0x00, 0x85, 0x67, 0x2d, 0xf6, 0xf6, 0xa0, 0xd4, 0xaa, 0x31,
    0x00, 0xa4, 0x37, 0x9b, 0x41, 0x1b, 0x75, 0x4c, 0x2f, 0x98, 0xd5, 0x85, 0xbf, 0x75, 0x7c, 0x36,
    0x10, 0x76, 0xd1, 0x8f, 0x19, 0xc3, 0xc5, 0xd9, 0x84, 0xc4, 0x49, 0xdc, 0x4a, 0x76, 0x40, 0x38,
    0x19, 0x88, 0xc4, 0x49, 0x77, 0xf3, 0xfb, 0xd4, 0x6a, 0x80, 0x96, 0x28, 0x28, 0x4c, 0x2d, 0x3d,
    0xf5, 0x02, 0xe0, 0x07, 0x12, 0x17, 0xc7, 0x00, 0x00, 0x00, 0x15, 0x00, 0x93, 0xd0, 0xb5, 0xe5,
    0x6f, 0x5a, 0x38, 0x5c, 0x7a, 0x8c, 0xa0, 0xab, 0xef, 0xdf, 0x90, 0x4b, 0x05, 0xb2, 0xd9, 0xe6
};


/*------------------------------------------------------------------*/

static int
FIPS_DSA_DoPCT(MOC_DSA(hwAccelDescr hwAccelCtx)
                int hint,
                DSAKey* pDSAKey,
                randomContext*  pRandomContext,
                ubyte4 addR, ubyte4 addS,
                vlong **ppVlongQueue)
{
    char*           pMsg            = "Attack at dawn";
    vlong*          pBuff           = NULL;
    vlong*          pR              = NULL;
    vlong*          pS              = NULL;
    intBoolean      isGoodSig       = FALSE;
    int             retVal          = 0;

    /* Converting the message string to VLONG */
    UNITTEST_STATUS_GOTO(hint,
                        VLONG_vlongFromByteString(pMsg, (sbyte4) DIGI_STRLEN(pMsg), &pBuff, ppVlongQueue),
                        retVal, exit);

    /* Compute the Signature */
    UNITTEST_STATUS_GOTO(hint,
                        DSA_computeSignature(MOC_DSA(hwAccelCtx) pRandomContext,
                                            pDSAKey, pBuff,
                                            &isGoodSig, &pR, &pS, ppVlongQueue),
                        retVal, exit);

    retVal += UNITTEST_TRUE(hint, isGoodSig);

    UNITTEST_STATUS_GOTO(hint, VLONG_addImmediate(pR, addR, ppVlongQueue),
                        retVal, exit);
    UNITTEST_STATUS_GOTO(hint, VLONG_addImmediate(pS, addS, ppVlongQueue),
                        retVal, exit);

    /* Verify the signature */
    UNITTEST_STATUS_GOTO(hint, DSA_verifySignature(MOC_DSA(hwAccelCtx) pDSAKey,
                                           pBuff, pR, pS, &isGoodSig, ppVlongQueue),
                            retVal, exit);

    if (addR || addS)
    {
        retVal += UNITTEST_TRUE( hint, 0 == isGoodSig);
    }
    else
    {
        retVal += UNITTEST_TRUE(hint, isGoodSig);
    }

exit:
    VLONG_freeVlong(&pR, ppVlongQueue);
    VLONG_freeVlong(&pS, ppVlongQueue);
    VLONG_freeVlong(&pBuff, ppVlongQueue);

    return retVal;

} /* FIPS_DSA_DoPCT */


/*------------------------------------------------------------------*/

static int test_dsa2( MOC_DSA(hwAccelDescr hwAccelCtx)
                int hint,
                DSAKey* pDSAKey,
                randomContext*  pRandomContext,
                ubyte4 addR, ubyte4 addS,
                vlong **ppVlongQueue)
{
    char*           pMsg            = "Attack at dawn";
    vlong*          pR              = NULL;
    vlong*          pS              = NULL;
    intBoolean      isGoodSig       = FALSE;
    int             retVal          = 0;
    ubyte           hash[SHA512_RESULT_SIZE];


    /* no test vectors found for this yet (08-2010) -- smoke test */

    /* Converting the message string to VLONG */
    UNITTEST_STATUS_GOTO(hint,
                        SHA512_completeDigest(MOC_HASH(hwAccelCtx) pMsg, (ubyte4) DIGI_STRLEN(pMsg), hash),
                        retVal, exit);

    /* Compute the Signature */
    UNITTEST_STATUS_GOTO(hint,
                        DSA_computeSignature2(MOC_DSA(hwAccelCtx) RANDOM_rngFun, pRandomContext,
                                            pDSAKey, hash, SHA512_RESULT_SIZE,
                                            &pR, &pS, ppVlongQueue),
                        retVal, exit);

    UNITTEST_STATUS_GOTO(hint, VLONG_addImmediate(pR, addR, ppVlongQueue),
                        retVal, exit);
    UNITTEST_STATUS_GOTO(hint, VLONG_addImmediate(pS, addS, ppVlongQueue),
                        retVal, exit);

    /* Verify the signature */
    UNITTEST_STATUS_GOTO(hint, DSA_verifySignature2(MOC_DSA(hwAccelCtx) pDSAKey,
                                           hash, SHA512_RESULT_SIZE, pR, pS, &isGoodSig, ppVlongQueue),
                            retVal, exit);

    if (addR || addS)
    {
        retVal += UNITTEST_TRUE( hint, 0 == isGoodSig);
    }
    else
    {
        retVal += UNITTEST_TRUE(hint, isGoodSig);
    }

exit:
    VLONG_freeVlong(&pR, ppVlongQueue);
    VLONG_freeVlong(&pS, ppVlongQueue);

    return retVal;
}


/*------------------------------------------------------------------*/

static int test_dsa3( MOC_DSA(hwAccelDescr hwAccelCtx)
                int hint,
                randomContext*  pRandomContext,
                ubyte4 L, ubyte4 N, DSAHashType hashSize,
                vlong **ppVlongQueue)
{
    DSAKey*         pDSAKey = NULL;
    int             retVal          = 0;
    ubyte           seed[64] = {0};
    ubyte4          C = 0;
    char*			pBuff = "Attack at dawn";
    vlong*			pMesg = NULL;
    intBoolean      isGoodSig;
    intBoolean      isGoodKey;
    vlong*          pH  = NULL;
    vlong*          pR = NULL;
    vlong*          pS = NULL;

    /* Create a DSA Key */
    UNITTEST_STATUS_GOTO(hint,
						DSA_createKey(&pDSAKey),
						retVal, exit);


    /* Generate DSA Key */
    UNITTEST_STATUS_GOTO(hint,
						DSA_generateKeyEx(MOC_DSA(hwAccelCtx) pRandomContext, pDSAKey, L, N, hashSize, &C, seed, &pH, ppVlongQueue),
						retVal, exit);

    /* Verify the DSA Keys */
    UNITTEST_STATUS_GOTO(hint,
						DSA_verifyKeysEx(MOC_DSA(hwAccelCtx) pRandomContext, seed, N/8, pDSAKey, hashSize, DSA_186_4, C, pH, &isGoodKey, ppVlongQueue),
						retVal, exit);

    retVal += UNITTEST_TRUE(hint, isGoodKey);

    /* Converting the message string to VLONG */
    UNITTEST_STATUS_GOTO(hint,
						VLONG_vlongFromByteString(pBuff, (sbyte4)DIGI_STRLEN(pBuff), &pMesg, NULL),
						retVal, exit);

    /* Compute the Signature */
    UNITTEST_STATUS_GOTO(hint,
						DSA_computeSignature(MOC_DSA(hwAccelCtx) pRandomContext, pDSAKey, pMesg, &isGoodSig, &pR, &pS, ppVlongQueue),
						retVal, exit);

    retVal += UNITTEST_TRUE(hint, isGoodSig);

    /* Verify the signature */
    UNITTEST_STATUS_GOTO(hint,
						DSA_verifySignature(MOC_DSA(hwAccelCtx) pDSAKey, pMesg, pR, pS, &isGoodSig, ppVlongQueue),
						retVal, exit);

    retVal += UNITTEST_TRUE(hint, isGoodSig);

exit:
    DSA_freeKey(&pDSAKey, NULL);
    VLONG_freeVlong(&pMesg, NULL);
    VLONG_freeVlong(&pH, NULL);
    VLONG_freeVlong(&pR, NULL);
    VLONG_freeVlong(&pS, NULL);

	return retVal;

}

/*------------------------------------------------------------------*/

int dsa_test_all()
{
    hwAccelDescr    hwAccelCtx;
    int             retVal = 0;
    vlong*          pVlongQueue = NULL;
    randomContext*  pRandomContext  = NULL;
    DSAKey*         pDSAKey = 0;

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
    
    if (OK > (MSTATUS)(retVal = DIGICERT_initialize(&setupInfo, NULL)))
        return retVal;

    UNITTEST_STATUS_GOTO(0, HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx), retVal, exit);
    UNITTEST_STATUS_GOTO(0, 
                        DSA_extractKeyBlob(&pDSAKey, m_dsaKeyBlob, sizeof(m_dsaKeyBlob)),
                        retVal, exit);

    retVal += FIPS_DSA_DoPCT(MOC_DSA(hwAccelCtx) 1, pDSAKey, g_pRandomContext, 0, 0, &pVlongQueue); 
    retVal += FIPS_DSA_DoPCT(MOC_DSA(hwAccelCtx) 2, pDSAKey, g_pRandomContext, 5, 0, &pVlongQueue); 
    retVal += FIPS_DSA_DoPCT(MOC_DSA(hwAccelCtx) 3, pDSAKey, g_pRandomContext, 0, 5, &pVlongQueue); 

    retVal += test_dsa2(MOC_DSA(hwAccelCtx) 1, pDSAKey, g_pRandomContext, 0, 0, &pVlongQueue); 
    retVal += test_dsa2(MOC_DSA(hwAccelCtx) 2, pDSAKey, g_pRandomContext, 5, 0, &pVlongQueue); 
    retVal += test_dsa2(MOC_DSA(hwAccelCtx) 3, pDSAKey, g_pRandomContext, 0, 5, &pVlongQueue);

#ifdef __ENABLE_DIGICERT_DSA_ALL_KEYSIZE__
	retVal += test_dsa3(MOC_DSA(hwAccelCtx) 1, g_pRandomContext, 1024, 160, DSA_sha1, &pVlongQueue);
	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 2, g_pRandomContext, 1024, 160, DSA_sha224, &pVlongQueue);
	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 3, g_pRandomContext, 1024, 160, DSA_sha256, &pVlongQueue);
	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 4, g_pRandomContext, 1024, 160, DSA_sha384, &pVlongQueue);
	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 5, g_pRandomContext, 1024, 160, DSA_sha512, &pVlongQueue);
#endif

	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 6, g_pRandomContext, 2048, 224, DSA_sha224, &pVlongQueue);
	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 7, g_pRandomContext, 2048, 224, DSA_sha256, &pVlongQueue);
	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 8, g_pRandomContext, 2048, 224, DSA_sha384, &pVlongQueue);
	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 9, g_pRandomContext, 2048, 224, DSA_sha512, &pVlongQueue);

	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 10, g_pRandomContext, 2048, 256, DSA_sha256, &pVlongQueue);
	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 11, g_pRandomContext, 2048, 256, DSA_sha384, &pVlongQueue);
	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 12, g_pRandomContext, 2048, 256, DSA_sha512, &pVlongQueue);

	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 13, g_pRandomContext, 3072, 256, DSA_sha256, &pVlongQueue);
	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 14, g_pRandomContext, 3072, 256, DSA_sha384, &pVlongQueue);
	// retVal += test_dsa3(MOC_DSA(hwAccelCtx) 15, g_pRandomContext, 3072, 256, DSA_sha512, &pVlongQueue);

exit:

    DSA_freeKey(&pDSAKey, 0);
    VLONG_freeVlongQueue(&pVlongQueue);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    DIGICERT_freeDigicert();

    return retVal;
}
