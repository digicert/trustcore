/**
 * @file hw_sim_dh.c
 *
 * @brief DH test for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_DH__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define DH_allocateServer         HW_DH_allocateServer
#define DH_allocateClient         HW_DH_allocateClient
#define DH_allocateClientAux      HW_DH_allocateClientAux
#define DH_setPG                  HW_DH_setPG
#define DH_setPGQ                 HW_DH_setPGQ
#define DH_computeKeyExchange     HW_DH_computeKeyExchange
#define DH_setKeyParameters       HW_DH_setKeyParameters
#define DH_getKeyParametersAlloc  HW_DH_getKeyParametersAlloc
#define DH_generateKeyPair        HW_DH_generateKeyPair
#define DH_getPublicKey           HW_DH_getPublicKey
#define DH_computeKeyExchangeEx   HW_DH_computeKeyExchangeEx
#define DH_validateDomainParams   HW_DH_validateDomainParams
#define DH_verifyPQ_FIPS1864      HW_DH_verifyPQ_FIPS1864
#define DH_verifyG                HW_DH_verifyG

#include "../../dh.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef DH_allocateServer
#undef DH_allocateClient
#undef DH_allocateClientAux
#undef DH_setPG
#undef DH_setPGQ
#undef DH_computeKeyExchange
#undef DH_setKeyParameters
#undef DH_getKeyParametersAlloc
#undef DH_generateKeyPair
#undef DH_getPublicKey
#undef DH_computeKeyExchangeEx
#undef DH_validateDomainParams
#undef DH_verifyPQ_FIPS1864
#undef DH_verifyG

extern MSTATUS DH_allocateServer(hwAccelDescr hwAccelCtx, randomContext *pRandomContext, diffieHellmanContext **pp_dhContext, ubyte4 groupNum)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_allocateServer");
    if (OK != status)
        return status;
    
    return HW_DH_allocateServer(hwAccelCtx, pRandomContext, pp_dhContext, groupNum);
}

extern MSTATUS DH_allocateClient(hwAccelDescr hwAccelCtx, randomContext *pRandomContext, diffieHellmanContext **pp_dhContext, ubyte4 groupNum)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_allocateClient");
    if (OK != status)
        return status;
    
    return HW_DH_allocateClient(hwAccelCtx, pRandomContext, pp_dhContext, groupNum);
}

extern MSTATUS DH_allocateClientAux(hwAccelDescr hwAccelCtx, randomContext *pRandomContext, diffieHellmanContext **pp_dhContext, ubyte4 groupNum)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_allocateClientAux");
    if (OK != status)
        return status;
    
    return HW_DH_allocateClientAux(hwAccelCtx, pRandomContext, pp_dhContext, groupNum);
}

extern MSTATUS DH_setPG(hwAccelDescr hwAccelCtx, randomContext *pRandomContext, ubyte4 lengthY, diffieHellmanContext *p_dhContext, const vlong *P, const vlong *G)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_setPG");
    if (OK != status)
        return status;
    
    return HW_DH_setPG(hwAccelCtx, pRandomContext, lengthY, p_dhContext, P, G);
}

extern MSTATUS DH_setPGQ(hwAccelDescr hwAccelCtx, randomContext *pRandomContext, ubyte4 lengthY, diffieHellmanContext *p_dhContext, const vlong *P, const vlong *G, const vlong *Q)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_setPGQ");
    if (OK != status)
        return status;
    
    return HW_DH_setPGQ(hwAccelCtx, pRandomContext, lengthY, p_dhContext, P, G, Q);
}

extern MSTATUS DH_computeKeyExchange(hwAccelDescr hwAccelCtx, diffieHellmanContext *p_dhContext, vlong** ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_computeKeyExchange");
    if (OK != status)
        return status;
    
    return HW_DH_computeKeyExchange(hwAccelCtx, p_dhContext, ppVlongQueue);
}

extern MSTATUS DH_setKeyParameters(hwAccelDescr hwAccelCtx, diffieHellmanContext *pTargetCtx, MDhKeyTemplate *pSrcTemplate)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_setKeyParameters");
    if (OK != status)
        return status;
    
    return HW_DH_setKeyParameters(hwAccelCtx, pTargetCtx, pSrcTemplate);
}

extern MSTATUS DH_getKeyParametersAlloc(hwAccelDescr hwAccelCtx, MDhKeyTemplate *pTargetTemplate, diffieHellmanContext *pSrcCtx, ubyte keyType)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_getKeyParametersAlloc");
    if (OK != status)
        return status;
    
    return HW_DH_getKeyParametersAlloc(hwAccelCtx, pTargetTemplate, pSrcCtx, keyType);
}

extern MSTATUS DH_generateKeyPair(hwAccelDescr hwAccelCtx, diffieHellmanContext *pCtx, randomContext *pRandomContext, ubyte4 numBytes)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_generateKeyPair");
    if (OK != status)
        return status;
    
    return HW_DH_generateKeyPair(hwAccelCtx, pCtx, pRandomContext, numBytes);
}

extern MSTATUS DH_getPublicKey(hwAccelDescr hwAccelCtx, diffieHellmanContext *pCtx, ubyte **ppPublicKey, ubyte4 *pPublicKeyLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_getPublicKey");
    if (OK != status)
        return status;
    
    return HW_DH_getPublicKey(hwAccelCtx, pCtx, ppPublicKey, pPublicKeyLen);
}

extern MSTATUS DH_computeKeyExchangeEx(hwAccelDescr hwAccelCtx, diffieHellmanContext *pCtx, randomContext *pRandomContext, ubyte *pOtherPartysPublicKey, ubyte4 publicKeyLen,
                                           ubyte **ppSharedSecret, ubyte4 *pSharedSecretLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_computeKeyExchangeEx");
    if (OK != status)
        return status;
    
    return HW_DH_computeKeyExchangeEx(hwAccelCtx, pCtx, pRandomContext, pOtherPartysPublicKey, publicKeyLen, ppSharedSecret, pSharedSecretLen);
}

extern MSTATUS DH_validateDomainParams(hwAccelDescr hwAccelCtx, randomContext* pFipsRngCtx,
                                           diffieHellmanContext *pCtx, FFCHashType hashType, ubyte4 C,
                                           ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsValid, ubyte4 *pPriKeyLen, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_validateDomainParams");
    if (OK != status)
        return status;
    
    return HW_DH_validateDomainParams(hwAccelCtx, pFipsRngCtx, pCtx, hashType, C, pSeed, seedSize, pIsValid, pPriKeyLen, ppVlongQueue);
}

extern MSTATUS DH_verifyPQ_FIPS1864(hwAccelDescr hwAccelCtx, randomContext* pFipsRngCtx,
                                        diffieHellmanContext *pCtx, FFCHashType hashType, ubyte4 C,
                                        ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsValid, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_verifyPQ_FIPS1864");
    if (OK != status)
        return status;
    
    return HW_DH_verifyPQ_FIPS1864(hwAccelCtx, pFipsRngCtx, pCtx, hashType, C, pSeed, seedSize, pIsValid, ppVlongQueue);
}

extern MSTATUS DH_verifyG(hwAccelDescr hwAccelCtx, diffieHellmanContext *pCtx, intBoolean *pIsValid, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DH_verifyG");
    if (OK != status)
        return status;
    
    return HW_DH_verifyG(hwAccelCtx, pCtx, pIsValid, ppVlongQueue);
}
#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_DH__) */
