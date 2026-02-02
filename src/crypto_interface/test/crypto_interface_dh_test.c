/*
 * crypto_interface_dh_test.c
 *
 * test cases for crypto interface API in dh.h
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
#include "../../common/vlong.h"
#include "../../crypto/dh.h"
#include "../../crypto_interface/crypto_interface_priv.h"
#include "../../crypto_interface/crypto_interface_dh.h"
#include "../../crypto/test/nonrandop.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#ifndef __DISABLE_DIGICERT_DIFFIE_HELLMAN__

#if !defined(__DISABLE_DIGICERT_DH_BLINDING__) || \
  ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__) && defined(__ENABLE_DIGICERT_DH_MBED__) )
#define __TEST_BLINDING__
#endif

typedef struct TestVector
{
    ubyte4 groupNum;
    char *pG;
    char *pP;
    char *pQ;
    char *pY;
    char *pF;
    char *pE;
    char *pK;
  
} TestVector;

#include "dh_data_inc.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static int gCurrentVector = 0;

typedef struct
{
    ubyte4 group;
    ubyte4 defaultKeyLength;
    intBoolean fipsApproved;
} TestDhGroup;

static TestDhGroup gpDhGroups[] = {
    { DH_GROUP_1,          32, FALSE },
    { DH_GROUP_2,          32, FALSE },
    { DH_GROUP_5,          32, FALSE },
    { DH_GROUP_14,         28, TRUE  },
    { DH_GROUP_15,         32, TRUE  },
    { DH_GROUP_16,         38, TRUE  },
    { DH_GROUP_17,         44, TRUE  },
    { DH_GROUP_18,         50, TRUE  },
    { DH_GROUP_24,         32, FALSE },
    { DH_GROUP_FFDHE2048,  28, TRUE  },
    { DH_GROUP_FFDHE3072,  32, TRUE  },
    { DH_GROUP_FFDHE4096,  38, TRUE  },
    { DH_GROUP_FFDHE6144,  44, TRUE  },
    { DH_GROUP_FFDHE8192,  50, TRUE  }
};

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

static MSTATUS seedDeterministicRng(randomContext *pRandom, void *pSeedInfo, ubyte *pEntropyBytes, ubyte4 entropyLen)
{
    MSTATUS status = OK;
    
#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__) || !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
    ubyte *pTemp = NULL;
    ubyte4 i = 0;

    /* make a mutable copy of pEntropyBytes */
    status = DIGI_MALLOC((void **) &pTemp, entropyLen);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCPY(pTemp, pEntropyBytes, entropyLen);
    if (OK != status)
        goto exit;
    
    /* subtract one from the last byte */
    i = entropyLen - 1;
    pTemp[i]--;
    
    /* keep borrowing if needbe */
    while (0xFF == pTemp[i] && i > 0)
    {
        i--;
        pTemp[i]--;
    }
    
    pEntropyBytes = pTemp; /* ok to change passed by value ptr */
    
#endif

    status = CRYPTO_seedRandomContext(pRandom, pSeedInfo, pEntropyBytes, entropyLen);
    
#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__) || !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
exit:
    
    if (NULL != pTemp)
    {
        DIGI_FREE((void **) &pTemp);
    }
#endif
    
    return status;
}

static int testGroup(TestDhGroup *pGroup, byteBoolean blinding)
{
    MSTATUS status;
    int retVal = 0;

    diffieHellmanContext *pLocal = NULL;
    diffieHellmanContext *pPeer = NULL;
    randomContext *pBlindingCtx = NULL;

    ubyte *pLocalPub = NULL, *pLocalSS = NULL;
    ubyte4 localPubLen = 0, localSSLen = 0;
    ubyte *pPeerPub = NULL, *pPeerSS = NULL;
    ubyte4 peerPubLen = 0, peerSSLen = 0;
    sbyte4 compare;
    
    MDhKeyTemplate keyTemplate = {0};

    if (blinding)
    {
        pBlindingCtx = g_pRandomContext;
    }

    status = DH_allocate(&pLocal);
    retVal += UNITTEST_STATUS(pGroup->group, status);
    if (OK != status)
        goto exit;

    status = DH_allocate(&pPeer);
    retVal += UNITTEST_STATUS(pGroup->group, status);
    if (OK != status)
        goto exit;

    keyTemplate.groupNum = pGroup->group;
    status = DH_setKeyParameters(MOC_DH(gpHwAccelCtx) pLocal, &keyTemplate);
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if (FALSE == pGroup->fipsApproved)
    {
        retVal += UNITTEST_TRUE(pGroup->group, OK != status);
        goto exit; /* Not a valid fips group */
    }
    else
#endif
    {
        retVal += UNITTEST_STATUS(pGroup->group, status);
        if (OK != status)
            goto exit;
    }

    status = DH_setKeyParameters(MOC_DH(gpHwAccelCtx) pPeer, &keyTemplate);
    retVal += UNITTEST_STATUS(pGroup->group, status);
    if (OK != status)
        goto exit;

    status = DH_generateKeyPair(
        MOC_DH(gpHwAccelCtx) pLocal, g_pRandomContext, pGroup->defaultKeyLength);
    retVal += UNITTEST_STATUS(pGroup->group, status);
    if (OK != status)
        goto exit;

    status = DH_generateKeyPair(
        MOC_DH(gpHwAccelCtx) pPeer, g_pRandomContext, pGroup->defaultKeyLength);
    retVal += UNITTEST_STATUS(pGroup->group, status);
    if (OK != status)
        goto exit;

    status = DH_getPublicKey(MOC_DH(gpHwAccelCtx) pLocal, &pLocalPub, &localPubLen);
    retVal += UNITTEST_STATUS(pGroup->group, status);
    if (OK != status)
        goto exit;
        
    status = DH_getPublicKey(MOC_DH(gpHwAccelCtx) pPeer, &pPeerPub, &peerPubLen);
    retVal += UNITTEST_STATUS(pGroup->group, status);
    if (OK != status)
        goto exit;

    status = DH_computeKeyExchangeEx(
        MOC_DH(gpHwAccelCtx) pLocal, pBlindingCtx, pPeerPub, peerPubLen, &pLocalSS, &localSSLen);
    retVal += UNITTEST_STATUS(pGroup->group, status);
    if (OK != status)
        goto exit;

    status = DH_computeKeyExchangeEx(
        MOC_DH(gpHwAccelCtx) pPeer, pBlindingCtx, pLocalPub, localPubLen, &pPeerSS, &peerSSLen);
    retVal += UNITTEST_STATUS(pGroup->group, status);
    if (OK != status)
        goto exit;

    /* verify it is correct */
    retVal += UNITTEST_INT(pGroup->group, localSSLen, peerSSLen);
    
    status = DIGI_MEMCMP(pLocalSS, pPeerSS, localSSLen, &compare);
    retVal += UNITTEST_STATUS(pGroup->group, status);
    
    retVal += UNITTEST_INT(pGroup->group, compare, 0);

#ifdef __TEST_BLINDING__
    if (blinding)
    {
        /* Test two more calls with the same data, reset pSS */
        DIGI_FREE((void **) &pLocalSS);
        
        status = DH_computeKeyExchangeEx(
            MOC_DH(gpHwAccelCtx) pLocal, pBlindingCtx, pPeerPub, peerPubLen, &pLocalSS, &localSSLen);
        retVal += UNITTEST_STATUS(pGroup->group, status);
        if (OK != status)
            goto exit;
        
        /* verify it is correct */
        retVal += UNITTEST_INT(pGroup->group, localSSLen, peerSSLen);
        
        status = DIGI_MEMCMP(pLocalSS, pPeerSS, localSSLen, &compare);
        retVal += UNITTEST_STATUS(pGroup->group, status);
        
        retVal += UNITTEST_INT(pGroup->group, compare, 0);
        
        /* Test again */
        DIGI_FREE((void **) &pLocalSS);
        
        status = DH_computeKeyExchangeEx(
            MOC_DH(gpHwAccelCtx) pLocal, pBlindingCtx, pPeerPub, peerPubLen, &pLocalSS, &localSSLen);
        retVal += UNITTEST_STATUS(pGroup->group, status);
        if (OK != status)
            goto exit;
        
        /* verify it is correct */
        retVal += UNITTEST_INT(pGroup->group, localSSLen, peerSSLen);
        
        status = DIGI_MEMCMP(pLocalSS, pPeerSS, localSSLen, &compare);
        retVal += UNITTEST_STATUS(pGroup->group, status);
        
        retVal += UNITTEST_INT(pGroup->group, compare, 0);

        /* Test two more calls with the same data, reset pSS */
        DIGI_FREE((void **) &pPeerSS);
        
        status = DH_computeKeyExchangeEx(
            MOC_DH(gpHwAccelCtx) pPeer, pBlindingCtx, pLocalPub, localPubLen, &pPeerSS, &peerSSLen);
        retVal += UNITTEST_STATUS(pGroup->group, status);
        if (OK != status)
            goto exit;
        
        /* verify it is correct */
        retVal += UNITTEST_INT(pGroup->group, localSSLen, peerSSLen);
        
        status = DIGI_MEMCMP(pLocalSS, pPeerSS, localSSLen, &compare);
        retVal += UNITTEST_STATUS(pGroup->group, status);
        
        retVal += UNITTEST_INT(pGroup->group, compare, 0);
        
        /* Test again */
        DIGI_FREE((void **) &pPeerSS);
        
        status = DH_computeKeyExchangeEx(
            MOC_DH(gpHwAccelCtx) pPeer, pBlindingCtx, pLocalPub, localPubLen, &pPeerSS, &peerSSLen);
        retVal += UNITTEST_STATUS(pGroup->group, status);
        if (OK != status)
            goto exit;
        
        /* verify it is correct */
        retVal += UNITTEST_INT(pGroup->group, localSSLen, peerSSLen);
        
        status = DIGI_MEMCMP(pLocalSS, pPeerSS, localSSLen, &compare);
        retVal += UNITTEST_STATUS(pGroup->group, status);
        
        retVal += UNITTEST_INT(pGroup->group, compare, 0);
    }
#endif

exit:

    if (NULL != pLocal)
    {
        status = DH_freeDhContext(&pLocal, NULL);
        retVal += UNITTEST_STATUS(pGroup->group, status);
    }
    if (NULL != pPeer)
    {
        status = DH_freeDhContext(&pPeer, NULL);
        retVal += UNITTEST_STATUS(pGroup->group, status);
    }
    if (NULL != pLocalPub)
    {
        DIGI_FREE((void **) &pLocalPub);
    }
    if (NULL != pPeerPub)
    {
        DIGI_FREE((void **) &pPeerPub);
    }
    if (NULL != pLocalSS)
    {
        DIGI_FREE((void **) &pLocalSS);
    }
    if (NULL != pPeerSS)
    {
        DIGI_FREE((void **) &pPeerSS);
    }

    return retVal;
}

static int testFunctionalCases()
{
    int retVal = 0, i;

    for (i = 0; i < COUNTOF(gpDhGroups); i++)
    {
        retVal += testGroup(gpDhGroups + i, FALSE);
#ifdef __TEST_BLINDING__
        retVal += testGroup(gpDhGroups + i, TRUE);
#endif
    }

    return retVal;
}

static int testStandardGroup(ubyte4 groupNum, ubyte *pY, ubyte4 yLen, ubyte *pF, ubyte4 fLen, ubyte *pE, ubyte4 eLen, ubyte *pK, ubyte4 kLen, byteBoolean blinding)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    
    diffieHellmanContext *pCtx = NULL;
    randomContext *pRndCtx = NULL;
    randomContext *pBlindingCtx = NULL;
    
    ubyte *pPublicKey = NULL;
    ubyte4 pubKeyLen = 0;
    
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    
    MDhKeyTemplate keyTemplate = {0};
    
    /* Get a deterministc RNG */
    status = getDeterministicRngCtx(&pRndCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    /* Set up the RNG to produce desired y value */
    status = seedDeterministicRng(pRndCtx, NULL, pY, yLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    if (blinding)
    {
        pBlindingCtx = pRndCtx;
    }
    
    /* Test using setKeyParameters */
    status = DH_allocate(&pCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    keyTemplate.groupNum = groupNum;
    status = DH_setKeyParameters(MOC_DH(gpHwAccelCtx) pCtx, &keyTemplate);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    status = DH_generateKeyPair(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, yLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* get the public key */
    status = DH_getPublicKey(MOC_DH(gpHwAccelCtx) pCtx, &pPublicKey, &pubKeyLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, pubKeyLen, fLen);
    
    status = DIGI_MEMCMP(pPublicKey, pF, fLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

    /* Now compute the shared secret */
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pBlindingCtx, pE, eLen, &pSS, &ssLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
    
    status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

#ifdef __TEST_BLINDING__
    if (blinding)
    {
        /* Test two more calls with the same data, reset pSS */
        DIGI_FREE((void **) &pSS);
        
        status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pBlindingCtx, pE, eLen, &pSS, &ssLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
        
        /* verify it is correct */
        retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
        
        status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        
        retVal += UNITTEST_INT(gCurrentVector, compare, 0);
        
        /* Test again */
        DIGI_FREE((void **) &pSS);
        
        status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pBlindingCtx, pE, eLen, &pSS, &ssLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
        
        /* verify it is correct */
        retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
        
        status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        
        retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    }
#endif
    
exit:
    
    if (NULL != pCtx)
    {
        status = DH_freeDhContext(&pCtx, NULL);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pRndCtx)
    {
        status = CRYPTO_freeMocSymRandom(&pRndCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pPublicKey)
    {
        DIGI_FREE((void **) &pPublicKey);
    }
    if (NULL != pSS)
    {
        DIGI_FREE((void **) &pSS);
    }
    
    return retVal;
}

static int testStandardGroupServer(ubyte4 groupNum, ubyte *pY, ubyte4 yLen, ubyte *pF, ubyte4 fLen, ubyte *pE, ubyte4 eLen, ubyte *pK, ubyte4 kLen, byteBoolean blinding)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    
    diffieHellmanContext *pCtx = NULL;
    randomContext *pRndCtx = NULL;
    randomContext *pBlindingCtx = NULL;
    
    ubyte *pPublicKey = NULL;
    ubyte4 pubKeyLen = 0;
    
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    
    /* Get a deterministc RNG */
    status = getDeterministicRngCtx(&pRndCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* Set up the RNG to produce desired y value */
    status = seedDeterministicRng(pRndCtx, NULL, pY, yLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    if (blinding)
    {
        pBlindingCtx = pRndCtx;
    }
    
    /* test server */
    status = DH_allocateServer(MOC_DH(gpHwAccelCtx) pRndCtx, &pCtx, groupNum);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* get the public key */
    status = DH_getPublicKey(MOC_DH(gpHwAccelCtx) pCtx, &pPublicKey, &pubKeyLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, pubKeyLen, fLen);
    
    status = DIGI_MEMCMP(pPublicKey, pF, fLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    
    /* compute the shared secret */
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pBlindingCtx, pE, eLen, &pSS, &ssLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
    
    status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

#ifdef __TEST_BLINDING__
    if (blinding)
    {
        /* Test two more calls with the same data, reset pSS */
        DIGI_FREE((void **) &pSS);
        
        status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pBlindingCtx, pE, eLen, &pSS, &ssLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
        
        /* verify it is correct */
        retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
        
        status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        
        retVal += UNITTEST_INT(gCurrentVector, compare, 0);
        
        /* Test again */
        DIGI_FREE((void **) &pSS);
        
        status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pBlindingCtx, pE, eLen, &pSS, &ssLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
        
        /* verify it is correct */
        retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
        
        status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        
        retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    }
#endif
    
exit:
    
    if (NULL != pCtx)
    {
        status = DH_freeDhContext(&pCtx, NULL);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pRndCtx)
    {
        status = CRYPTO_freeMocSymRandom(&pRndCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pPublicKey)
    {
        DIGI_FREE((void **) &pPublicKey);
    }
    if (NULL != pSS)
    {
        DIGI_FREE((void **) &pSS);
    }
    
    return retVal;
}


static int testStandardGroupClient(ubyte4 groupNum, ubyte *pY, ubyte4 yLen, ubyte *pF, ubyte4 fLen, ubyte *pE, ubyte4 eLen, ubyte *pK, ubyte4 kLen, byteBoolean blinding)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    
    diffieHellmanContext *pCtx = NULL;
    randomContext *pRndCtx = NULL;
    randomContext *pBlindingCtx = NULL;
    
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    
    /* Get a deterministc RNG */
    status = getDeterministicRngCtx(&pRndCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* Set up the RNG to produce desired y value */
    status = seedDeterministicRng(pRndCtx, NULL, pY, yLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    if (blinding)
    {
        pBlindingCtx = pRndCtx;
    }
    
    /* test client */
    status = DH_allocateClientAux(MOC_DH(gpHwAccelCtx) pRndCtx, &pCtx, groupNum);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* client's public key not computed by the above call, only the private key */
    
    /* compute the shared secret */
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pBlindingCtx, pE, eLen, &pSS, &ssLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
    
    status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

#ifdef __TEST_BLINDING__
    if (blinding)
    {
        /* Test two more calls with the same data, reset pSS */
        DIGI_FREE((void **) &pSS);
        
        status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pBlindingCtx, pE, eLen, &pSS, &ssLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
        
        /* verify it is correct */
        retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
        
        status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        
        retVal += UNITTEST_INT(gCurrentVector, compare, 0);
        
        /* Test again */
        DIGI_FREE((void **) &pSS);
        
        status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pBlindingCtx, pE, eLen, &pSS, &ssLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
        
        /* verify it is correct */
        retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
        
        status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        
        retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    }
#endif
    
exit:
    
    if (NULL != pCtx)
    {
        status = DH_freeDhContext(&pCtx, NULL);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pRndCtx)
    {
        status = CRYPTO_freeMocSymRandom(&pRndCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pSS)
    {
        DIGI_FREE((void **) &pSS);
    }
    
    return retVal;
}


static int testCustomGroup(ubyte *pG, ubyte4 gLen, ubyte *pP, ubyte4 pLen, ubyte *pQ, ubyte4 qLen, ubyte *pY, ubyte4 yLen,
                           ubyte *pF, ubyte4 fLen, ubyte *pE, ubyte4 eLen, ubyte *pK, ubyte4 kLen, byteBoolean blinding)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    
    diffieHellmanContext *pCtx = NULL;
    randomContext *pRndCtx = NULL;
    randomContext *pBlindingCtx = NULL;
    
    MDhKeyTemplate inputTemplate = {0};
    MDhKeyTemplate outputTemplate = {0};
    
    ubyte *pPublicKey = NULL;
    ubyte4 pubKeyLen = 0;
    
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    
    inputTemplate.pG = pG;
    inputTemplate.gLen = gLen;
    inputTemplate.pP = pP;
    inputTemplate.pLen = pLen;
    inputTemplate.pQ = pQ;
    inputTemplate.qLen = qLen;
    
    /* Get a deterministc RNG */
    status = getDeterministicRngCtx(&pRndCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* Set up the RNG to produce desired y value */
    status = seedDeterministicRng(pRndCtx, NULL, pY, yLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    if (blinding)
    {
        pBlindingCtx = pRndCtx;
    }
    
    status = DH_allocate(&pCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = DH_setKeyParameters(MOC_DH(gpHwAccelCtx) pCtx, &inputTemplate);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = DH_generateKeyPair(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, yLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    /* get the public key */
    status = DH_getPublicKey(MOC_DH(gpHwAccelCtx) pCtx, &pPublicKey, &pubKeyLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, pubKeyLen, fLen);
    
    status = DIGI_MEMCMP(pPublicKey, pF, fLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    
    /* test DH_getKeyParametersAlloc for a private key before
     computingKeyExchange (since the latter destroys Y) */
    
    retVal += DH_getKeyParametersAlloc(MOC_DH(gpHwAccelCtx) &outputTemplate, pCtx, MOC_GET_PRIVATE_KEY_DATA);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    retVal += UNITTEST_INT(gCurrentVector, outputTemplate.pLen, pLen);
    retVal += UNITTEST_INT(gCurrentVector, outputTemplate.gLen, gLen);
    
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pCtx->enabled)
#endif
        retVal += UNITTEST_INT(gCurrentVector, outputTemplate.qLen, qLen);

    
    retVal += UNITTEST_INT(gCurrentVector, outputTemplate.yLen, yLen);
    retVal += UNITTEST_INT(gCurrentVector, outputTemplate.fLen, fLen);
    
    status = DIGI_MEMCMP(outputTemplate.pP, pP, pLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    
    status = DIGI_MEMCMP(outputTemplate.pG, pG, gLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    if (NULL != pQ && CRYPTO_INTERFACE_ALGO_ENABLED != pCtx->enabled)
#else
    if (NULL != pQ)
#endif
    {
        status = DIGI_MEMCMP(outputTemplate.pQ, pQ, qLen, &compare);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        
        retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    }
    
    status = DIGI_MEMCMP(outputTemplate.pY, pY, yLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    
    status = DIGI_MEMCMP(outputTemplate.pF, pF, fLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    
    /* Now compute the shared secret */
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pBlindingCtx, pE, eLen, &pSS, &ssLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
    
    status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

    /* reset and test DH_getKeyParametersAlloc for a public key */
    status = DH_freeKeyTemplate(pCtx, &outputTemplate);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += DH_getKeyParametersAlloc(MOC_DH(gpHwAccelCtx) &outputTemplate, pCtx, MOC_GET_PUBLIC_KEY_DATA);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    retVal += UNITTEST_INT(gCurrentVector, outputTemplate.pLen, pLen);
    retVal += UNITTEST_INT(gCurrentVector, outputTemplate.gLen, gLen);
    
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pCtx->enabled)
#endif
        retVal += UNITTEST_INT(gCurrentVector, outputTemplate.qLen, qLen);
    
    retVal += UNITTEST_INT(gCurrentVector, outputTemplate.fLen, fLen);
    
    status = DIGI_MEMCMP(outputTemplate.pP, pP, pLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    
    status = DIGI_MEMCMP(outputTemplate.pG, pG, gLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    if (NULL != pQ && CRYPTO_INTERFACE_ALGO_ENABLED != pCtx->enabled)
#else
    if (NULL != pQ)
#endif
    {
        status = DIGI_MEMCMP(outputTemplate.pQ, pQ, qLen, &compare);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        
        retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    }
    
    status = DIGI_MEMCMP(outputTemplate.pF, pF, fLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

#ifdef __TEST_BLINDING__
    if (blinding)
    {
        /* Test two more calls with the same data, reset pSS */
        DIGI_FREE((void **) &pSS);
        
        status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pBlindingCtx, pE, eLen, &pSS, &ssLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
        
        /* verify it is correct */
        retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
        
        status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        
        retVal += UNITTEST_INT(gCurrentVector, compare, 0);
        
        /* Test again */
        DIGI_FREE((void **) &pSS);
        
        status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pBlindingCtx, pE, eLen, &pSS, &ssLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
        
        /* verify it is correct */
        retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
        
        status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        
        retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    }
#endif
    
exit:
    
    if (NULL != pCtx)
    {
        status = DH_freeDhContext(&pCtx, NULL);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    
    if (NULL != pRndCtx)
    {
        status = CRYPTO_freeMocSymRandom(&pRndCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    
    status = DH_freeKeyTemplate(pCtx, &outputTemplate);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    /* inputTemplate not allocated */
    
    if (NULL != pPublicKey)
    {
        DIGI_FREE((void **) &pPublicKey);
    }
    if (NULL != pSS)
    {
        DIGI_FREE((void **) &pSS);
    }
    
    return retVal;
}

#ifdef __TEST_BLINDING__
static int testExtraBlinding(ubyte *pG, ubyte4 gLen, ubyte *pP, ubyte4 pLen, ubyte *pY, ubyte4 yLen,
                             ubyte *pE, ubyte4 eLen, ubyte *pK, ubyte4 kLen)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    
    diffieHellmanContext *pCtx = NULL;
    randomContext *pRndCtx = NULL;
    
    MDhKeyTemplate inputTemplate = {0};
    
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    
    inputTemplate.pG = pG;
    inputTemplate.gLen = gLen;
    inputTemplate.pP = pP;
    inputTemplate.pLen = pLen;
    
    /* Get a deterministc RNG */
    status = getDeterministicRngCtx(&pRndCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* Set up the RNG to produce desired y value */
    status = seedDeterministicRng(pRndCtx, NULL, pY, yLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    status = DH_allocate(&pCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    status = DH_setKeyParameters(MOC_DH(gpHwAccelCtx) pCtx, &inputTemplate);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    status = DH_generateKeyPair(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, yLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* Compute the shared secret 4 times, time 1 */
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, pE, eLen, &pSS, &ssLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
    
    status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    
    /* reset pSS, time 2 */
    DIGI_FREE((void **) &pSS);
    
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, pE, eLen, &pSS, &ssLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
    
    status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    
    /* time 3 */
    DIGI_FREE((void **) &pSS);
    
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, pE, eLen, &pSS, &ssLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
    
    status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

    /* time 4 */
    DIGI_FREE((void **) &pSS);
    
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, pE, eLen, &pSS, &ssLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, ssLen, kLen);
    
    status = DIGI_MEMCMP(pSS, pK, kLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    
    /* change y and compute the SS 3 more times */
    
    DIGI_FREE((void **) &pSS);
    
    /* Set up the RNG to produce desired y value */
    status = seedDeterministicRng(pRndCtx, NULL, gpVector0_newY, sizeof(gpVector0_newY));
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    /* DH_generateKeyPair does not free the key, free here */    
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    (void) VLONG_freeVlong(&COMPUTED_VLONG_Y(pCtx), NULL);
    (void) VLONG_freeVlong(&COMPUTED_VLONG_F(pCtx), NULL);
#endif

    status = DH_generateKeyPair(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, sizeof(gpVector0_newY));
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, pE, eLen, &pSS, &ssLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, ssLen, sizeof(gpVector0_newSS));
    
    status = DIGI_MEMCMP(pSS, gpVector0_newSS, ssLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

    /* time 2 */
    
    DIGI_FREE((void **) &pSS);
    
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, pE, eLen, &pSS, &ssLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, ssLen, sizeof(gpVector0_newSS));
    
    status = DIGI_MEMCMP(pSS, gpVector0_newSS, ssLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);
    
    /* time 3 */
    
    DIGI_FREE((void **) &pSS);
    
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, pE, eLen, &pSS, &ssLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /* verify it is correct */
    retVal += UNITTEST_INT(gCurrentVector, ssLen, sizeof(gpVector0_newSS));
    
    status = DIGI_MEMCMP(pSS, gpVector0_newSS, ssLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    
    retVal += UNITTEST_INT(gCurrentVector, compare, 0);
 
exit:
    
    if (NULL != pCtx)
    {
        status = DH_freeDhContext(&pCtx, NULL);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    
    if (NULL != pRndCtx)
    {
        status = CRYPTO_freeMocSymRandom(&pRndCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    /* inputTemplate not allocated */
    
    if (NULL != pSS)
    {
        DIGI_FREE((void **) &pSS);
    }
    
    return retVal;
}
#endif

static int knownAnswerTest(TestVector *pTestVector)
{
    int retVal = 0;

    ubyte *pG = NULL;
    ubyte4 gLen = 0;
    ubyte *pP = NULL;
    ubyte4 pLen = 0;
    ubyte *pQ = NULL;
    ubyte4 qLen = 0;
    ubyte *pY = NULL;
    ubyte4 yLen = 0;
    ubyte *pF = NULL;
    ubyte4 fLen = 0;
    ubyte *pE = NULL;
    ubyte4 eLen = 0;
    ubyte *pK = NULL;
    ubyte4 kLen = 0;
    
    /* set the vectors from the test vector */
    if (pTestVector->pG != NULL)
    {
        gLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pG, &pG);
    }
    if (pTestVector->pP != NULL)
    {
        pLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pP, &pP);
    }
    if (pTestVector->pQ != NULL)
    {
        qLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pQ, &pQ);
    }
    if (pTestVector->pY != NULL)
    {
        yLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pY, &pY);
    }
    if (pTestVector->pF != NULL)
    {
        fLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pF, &pF);
    }
    if (pTestVector->pE != NULL)
    {
        eLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pE, &pE);
    }
    if (pTestVector->pK != NULL)
    {
        kLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pK, &pK);
    }

    if (DH_GROUP_TBD != pTestVector->groupNum)
    {
        retVal += testStandardGroup(pTestVector->groupNum, pY, yLen, pF, fLen, pE, eLen, pK, kLen, FALSE);
        retVal += testStandardGroupServer(pTestVector->groupNum, pY, yLen, pF, fLen, pE, eLen, pK, kLen, FALSE);
        retVal += testStandardGroupClient(pTestVector->groupNum, pY, yLen, pF, fLen, pE, eLen, pK, kLen, FALSE);
#ifdef __TEST_BLINDING__
        retVal += testStandardGroup(pTestVector->groupNum, pY, yLen, pF, fLen, pE, eLen, pK, kLen, TRUE);
        retVal += testStandardGroupServer(pTestVector->groupNum, pY, yLen, pF, fLen, pE, eLen, pK, kLen, TRUE);
        retVal += testStandardGroupClient(pTestVector->groupNum, pY, yLen, pF, fLen, pE, eLen, pK, kLen, TRUE);
#endif
    }
    else
    {
        retVal += testCustomGroup(pG, gLen, pP, pLen, pQ, qLen, pY, yLen, pF, fLen, pE, eLen, pK, kLen, FALSE);
#ifdef __TEST_BLINDING__
        retVal += testCustomGroup(pG, gLen, pP, pLen, pQ, qLen, pY, yLen, pF, fLen, pE, eLen, pK, kLen, TRUE);
        
        if (pTestVector == gTestVector) /* pointer comparison */
        {
            /* Use the first test vector for testing blinding after changing the exponent */
            retVal += testExtraBlinding(pG, gLen, pP, pLen, pY, yLen, pE, eLen, pK, kLen);
        }
#endif
    }
    
exit:
    
    if (NULL != pG)
    {
        DIGI_FREE((void **)&pG);
    }
    if (NULL != pP)
    {
        DIGI_FREE((void **)&pP);
    }
    if (NULL != pQ)
    {
        DIGI_FREE((void **)&pQ);
    }
    if (NULL != pY)
    {
        DIGI_FREE((void **)&pY);
    }
    if (NULL != pF)
    {
        DIGI_FREE((void **)&pF);
    }
    if (NULL != pE)
    {
        DIGI_FREE((void **)&pE);
    }
    if (NULL != pK)
    {
        DIGI_FREE((void **)&pK);
    }
    
    return retVal;
}

static int testErrorCases()
{
    MSTATUS status;
    int retVal = 0;
    
    diffieHellmanContext *pCtx = NULL;
    randomContext *pRndCtx = NULL;
    randomContext *pEmptyRndCtx = NULL;
    MDhKeyTemplate template = {0};
    
    ubyte *pPublicKey = NULL;
    ubyte4 pubKeyLen = 0;
    
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    
    ubyte pP[256] = {0x80};
    ubyte4 pLen = 256;
    
    ubyte pG[128] = {0x01};
    ubyte4 gLen = 128;
    
    ubyte pE[128] = {0x01};
    ubyte4 eLen = 128;
    
    ubyte pY[32] = {0x01};
    ubyte4 yLen = 32;
    
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    ubyte4 algoStatus, index;
    
    /* Determine if we have an DH implementation */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(moc_alg_dh, &algoStatus, &index);
    if (OK != status)
        goto exit;
#endif
    
    /* Properly get some RNG for testing */
    status = getDeterministicRngCtx(&pRndCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* Properly get some RNG for testing */
    status = getDeterministicRngCtx(&pEmptyRndCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* only seed the first one */
    status = seedDeterministicRng(pRndCtx, NULL, pY, yLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /******* DH_allocate *******/
    
    status = DH_allocate(NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* DH_allocateServer *******/

    /* NULL params */
    status = DH_allocateServer(MOC_DH(gpHwAccelCtx) NULL, &pCtx, 14);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = DH_allocateServer(MOC_DH(gpHwAccelCtx) pRndCtx, NULL, 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invalid group */
    status = DH_allocateServer(MOC_DH(gpHwAccelCtx) pRndCtx, &pCtx, 0);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_DH_GROUP_PARAMS_NOT_SET);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CRYPTO_DH_UNSUPPORTED_GROUP);
    
    status = DH_allocateServer(MOC_DH(gpHwAccelCtx) pRndCtx, &pCtx, 25);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_DH_UNSUPPORTED_GROUP);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CRYPTO_DH_UNSUPPORTED_GROUP);
    
    /* properly allocated a context for further tests */
    status = DH_allocate(&pCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    /******* DH_generateKeyPair *******/
    
    /* NULL params */
    status = DH_generateKeyPair(MOC_DH(gpHwAccelCtx) NULL, pRndCtx, yLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DH_generateKeyPair(MOC_DH(gpHwAccelCtx) pCtx, NULL, yLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* p and g not set yet */
    status = DH_generateKeyPair(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, yLen);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
        /* pKeyData inside the public key is still NULL so we never get to a more descriptive error code */
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_KEY_EXCHANGE);
    
    /* we'll test below with only g and not p */
    
    /******* DH_getPublicKey *******/
    
    status = DH_getPublicKey(MOC_DH(gpHwAccelCtx) NULL, &pPublicKey, &pubKeyLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DH_getPublicKey(MOC_DH(gpHwAccelCtx) pCtx, NULL, &pubKeyLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DH_getPublicKey(MOC_DH(gpHwAccelCtx) pCtx, &pPublicKey, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* public key was never set or generated */
    status = DH_getPublicKey(MOC_DH(gpHwAccelCtx) pCtx, &pPublicKey, &pubKeyLen);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
        /* pKeyData inside the public key is still NULL so we never get to a more descriptive error code */
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_KEY_EXCHANGE);

    /******* DH_computeKeyExchangeEx *******/
    
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) NULL, pRndCtx, pE, eLen, &pSS, &ssLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, NULL, eLen, &pSS, &ssLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, pE, eLen, NULL, &ssLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, pE, eLen, &pSS, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* eLen is 0 */
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, NULL, pE, 0, &pSS, &ssLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BAD_CLIENT_E);

    /* p and g were never set */
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, pE, eLen, &pSS, &ssLen);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
        /* pKeyData inside the public key is still NULL so we never get to a more descriptive error code */
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_KEY_EXCHANGE);
    
    /* properly set just g for future tests */
    template.pG = pG;
    template.gLen = gLen;
    status = DH_setKeyParameters(MOC_DH(gpHwAccelCtx) pCtx, &template);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* p still not set  */
    status = DH_computeKeyExchangeEx(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, pE, eLen, &pSS, &ssLen);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
        /* pKeyData inside the private key is still NULL so we never get to a more descriptive error code */
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_KEY_EXCHANGE);
    
    /* test DH_generateKeyPair again too */
    status = DH_generateKeyPair(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, yLen);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
        /* pKeyData is set now but only has g, not p */
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_DH_GROUP_PARAMS_NOT_SET);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_KEY_EXCHANGE);
    
    /* reset context, set P and G for one more test */
    status = DH_freeDhContext(&pCtx, NULL);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = DH_allocate(&pCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    template.pP = pP;
    template.pLen = pLen;
    template.pG = pG;
    template.gLen = gLen;
    status = DH_setKeyParameters(MOC_DH(gpHwAccelCtx) pCtx, &template);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* invalid key len */
    status = DH_generateKeyPair(MOC_DH(gpHwAccelCtx) pCtx, pRndCtx, 0);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DH_INVALID_KEYLENGTH);

    /******* DH_getKeyParametersAlloc *******/
    
    status = DH_getKeyParametersAlloc(MOC_DH(gpHwAccelCtx) NULL, pCtx, MOC_GET_PUBLIC_KEY_DATA);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DH_getKeyParametersAlloc(MOC_DH(gpHwAccelCtx) &template, NULL, MOC_GET_PUBLIC_KEY_DATA);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DH_getKeyParametersAlloc(MOC_DH(gpHwAccelCtx) &template, pCtx, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    
    /******* DH_setKeyParameters *******/
    
    status = DH_setKeyParameters(MOC_DH(gpHwAccelCtx) NULL, &template);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = DH_setKeyParameters(MOC_DH(gpHwAccelCtx) pCtx, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* DH_freeKeyTemplate *******/
    
    /* ok (no-op) for params to be NULL */
    status = DH_freeKeyTemplate(pCtx, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    /* reset template.pG as it wasn't allocated */
    template.pG = NULL;
    template.gLen = 0;
    template.pP = NULL;
    template.pLen = 0;
    template.pY = NULL;
    template.yLen = 0;
    status = DH_freeKeyTemplate(NULL, &template);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    /******* DH_freeDhContext *******/

    status = DH_freeDhContext(NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* properly free for one last test */
    status = DH_freeDhContext(&pCtx, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* already freed context */
    status = DH_freeDhContext(&pCtx, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
exit:
    
    template.pP = NULL;
    template.pG = NULL;
    status = DH_freeKeyTemplate(pCtx, &template);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    if (NULL != pRndCtx)
    {
        status = CRYPTO_freeMocSymRandom(&pRndCtx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    if (NULL != pEmptyRndCtx)
    {
        status = CRYPTO_freeMocSymRandom(&pEmptyRndCtx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    if (NULL != pCtx)
    {
        status = DH_freeDhContext(&pCtx, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
        
    return retVal;
}

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static int testParamAndKeyGen(ubyte4 pSize, ubyte4 qSize, FFCHashType hashType)
{
    int retVal = 0;
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    MSTATUS status = OK;
    diffieHellmanContext *pCtx = NULL;
    intBoolean isValid = FALSE;

    status = CRYPTO_INTERFACE_DH_allocateExt(&pCtx, NULL);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DH_generateDomainParams(MOC_FFC(gpHwAccelCtx) pCtx, g_pRandomContext,
                                                      pSize, qSize, hashType, NULL);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DH_generateKeyPair(MOC_DH(gpHwAccelCtx) pCtx, g_pRandomContext, qSize/8);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DH_verifyPrivateKey(MOC_DH(gpHwAccelCtx) pCtx, &isValid, NULL);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    if (FALSE == isValid)
    {
        retVal += UNITTEST_STATUS(qSize, -1);
    }
    isValid = FALSE;

    status = CRYPTO_INTERFACE_DH_verifyPublicKey(MOC_DH(gpHwAccelCtx) pCtx, &isValid, NULL);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    if (FALSE == isValid)
    {
        retVal += UNITTEST_STATUS(qSize, -1);
    }
    isValid = FALSE;
    
    status = CRYPTO_INTERFACE_DH_verifyKeyPair(MOC_DH(gpHwAccelCtx) pCtx, &isValid, NULL);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    if (FALSE == isValid)
    {
        retVal += UNITTEST_STATUS(qSize, -1);
    }
    
    /* simple neg test, further tests are more complex, maybe can be added later or covered by openssl */
    isValid = TRUE;

    status = VLONG_increment(COMPUTED_VLONG_Y(pCtx), NULL);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DH_verifyKeyPair(MOC_DH(gpHwAccelCtx) pCtx, &isValid, NULL);
    retVal += UNITTEST_STATUS(qSize, status);
    if (OK != status)
        goto exit;

    if (TRUE == isValid)
    {
        retVal += UNITTEST_STATUS(qSize, -1);
    }

exit:

    status = CRYPTO_INTERFACE_DH_freeDhContext(&pCtx, NULL);
    retVal += UNITTEST_STATUS(qSize, status);

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ */

    return retVal;
}

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

/*----------------------------------------------------------------------------*/

int crypto_interface_dh_test_init()
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
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
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

    /* FIPS does not allow RNG operator to be plugged in */
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
    gCurrentVector = 0;

    for (i = 0; i < COUNTOF(gTestVector); ++i)
    {
        retVal += knownAnswerTest(gTestVector+i);
        gCurrentVector++;
    }
#endif
    
    retVal += testFunctionalCases();
    retVal += testErrorCases();
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    retVal += testParamAndKeyGen(1024, 160, FFC_sha1);
    retVal += testParamAndKeyGen(2048, 224, FFC_sha224);
    retVal += testParamAndKeyGen(2048, 256, FFC_sha256);
#endif

exit:
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    return retVal;
}
#endif /* __DISABLE_DIGICERT_DIFFIE_HELLMAN__ */
