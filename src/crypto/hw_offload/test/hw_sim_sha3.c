/**
 * @file hw_sim_sha3.c
 *
 * @brief SHA3 - Secure Hash Algorithm 3 Header for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_SHA3__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define SHA3_allocDigest    HW_SHA3_allocDigest
#define SHA3_initDigest     HW_SHA3_initDigest
#define SHA3_updateDigest   HW_SHA3_updateDigest
#define SHA3_finalDigest    HW_SHA3_finalDigest
#define SHA3_freeDigest     HW_SHA3_freeDigest
#define SHA3_completeDigest HW_SHA3_completeDigest
#define SHA3_cloneCtx       HW_SHA3_cloneCtx
#define SHA3_additionalXOF  HW_SHA3_additionalXOF

#include "../../sha3.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef SHA3_allocDigest
#undef SHA3_initDigest
#undef SHA3_updateDigest
#undef SHA3_finalDigest
#undef SHA3_freeDigest
#undef SHA3_completeDigest
#undef SHA3_cloneCtx
#undef SHA3_additionalXOF

extern MSTATUS SHA3_allocDigest(hwAccelDescr hwAccelCtx, BulkCtx *pp_shaContext)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA3_allocDigest");
    if (OK != status)
        return status;
    
    return HW_SHA3_allocDigest(hwAccelCtx, pp_shaContext);
}

extern MSTATUS SHA3_freeDigest(hwAccelDescr hwAccelCtx, BulkCtx *pp_shaContext)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA3_freeDigest");
    if (OK != status)
        return status;
    
    return HW_SHA3_freeDigest(hwAccelCtx, pp_shaContext);
}

extern MSTATUS SHA3_initDigest(hwAccelDescr hwAccelCtx, SHA3_CTX *pCtx, ubyte4 mode)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA3_initDigest");
    if (OK != status)
        return status;
    
    return HW_SHA3_initDigest(hwAccelCtx, pCtx, mode);
}

extern MSTATUS SHA3_updateDigest(hwAccelDescr hwAccelCtx, SHA3_CTX *pCtx, ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA3_updateDigest");
    if (OK != status)
        return status;
    
    return HW_SHA3_updateDigest(hwAccelCtx, pCtx, pData, dataLen);
}

extern MSTATUS SHA3_finalDigest(hwAccelDescr hwAccelCtx, SHA3_CTX *pCtx, ubyte *pOutput, ubyte4 desiredOutputLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA3_finalDigest");
    if (OK != status)
        return status;
    
    return HW_SHA3_finalDigest(hwAccelCtx, pCtx, pOutput, desiredOutputLen);
}

extern MSTATUS SHA3_completeDigest(hwAccelDescr hwAccelCtx, ubyte4 mode, ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput, ubyte4 desiredOutputLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA3_completeDigest");
    if (OK != status)
        return status;
    
    return HW_SHA3_completeDigest(hwAccelCtx, mode, pData, dataLen, pShaOutput, desiredOutputLen);
}

extern MSTATUS SHA3_cloneCtx(hwAccelDescr hwAccelCtx, SHA3_CTX *pDest, SHA3_CTX *pSrc)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA3_cloneCtx");
    if (OK != status)
        return status;
    
    return HW_SHA3_cloneCtx(hwAccelCtx, pDest, pSrc);
}

extern MSTATUS SHA3_additionalXOF(hwAccelDescr hwAccelCtx, SHA3_CTX *pSha3_ctx, ubyte *pResult, ubyte4 desiredResultLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA3_additionalXOF");
    if (OK != status)
        return status;
    
    return HW_SHA3_additionalXOF(hwAccelCtx, pSha3_ctx, pResult, desiredResultLen);
}
#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_SHA3__) */
