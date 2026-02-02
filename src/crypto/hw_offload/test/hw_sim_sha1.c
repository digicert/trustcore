/**
 * @file hw_sim_sha1.c
 *
 * @brief SHA - Secure Hash Algorithm Header for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_SHA1__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define SHA1_allocDigest    HW_SHA1_allocDigest
#define SHA1_initDigest     HW_SHA1_initDigest
#define SHA1_updateDigest   HW_SHA1_updateDigest
#define SHA1_finalDigest    HW_SHA1_finalDigest
#define SHA1_freeDigest     HW_SHA1_freeDigest
#define SHA1_completeDigest HW_SHA1_completeDigest
#define SHA1_cloneCtx       HW_SHA1_cloneCtx

#include "../../sha1.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef SHA1_allocDigest
#undef SHA1_initDigest
#undef SHA1_updateDigest
#undef SHA1_finalDigest
#undef SHA1_freeDigest
#undef SHA1_completeDigest
#undef SHA1_cloneCtx

extern MSTATUS SHA1_allocDigest(hwAccelDescr hwAccelCtx, BulkCtx *pp_shaContext)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA1_allocDigest");
    if (OK != status)
        return status;
    
    return HW_SHA1_allocDigest(hwAccelCtx, pp_shaContext);
}

extern MSTATUS SHA1_freeDigest(hwAccelDescr hwAccelCtx, BulkCtx *pp_shaContext)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA1_freeDigest");
    if (OK != status)
        return status;
    
    return HW_SHA1_freeDigest(hwAccelCtx, pp_shaContext);
}

extern MSTATUS SHA1_initDigest(hwAccelDescr hwAccelCtx, shaDescr *pCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA1_initDigest");
    if (OK != status)
        return status;
    
    return HW_SHA1_initDigest(hwAccelCtx, pCtx);
}

extern MSTATUS SHA1_updateDigest(hwAccelDescr hwAccelCtx, shaDescr *pCtx, const ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA1_updateDigest");
    if (OK != status)
        return status;
    
    return HW_SHA1_updateDigest(hwAccelCtx, pCtx, pData, dataLen);
}

extern MSTATUS SHA1_finalDigest(hwAccelDescr hwAccelCtx, shaDescr *pCtx, ubyte *pOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA1_finalDigest");
    if (OK != status)
        return status;
    
    return HW_SHA1_finalDigest(hwAccelCtx, pCtx, pOutput);
}

extern MSTATUS SHA1_completeDigest(hwAccelDescr hwAccelCtx, const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA1_completeDigest");
    if (OK != status)
        return status;
    
    return HW_SHA1_completeDigest(hwAccelCtx, pData, dataLen, pShaOutput);
}

extern MSTATUS SHA1_cloneCtx(hwAccelDescr hwAccelCtx, shaDescr *pDest, shaDescr *pSrc)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA1_cloneCtx");
    if (OK != status)
        return status;
    
    return HW_SHA1_cloneCtx(hwAccelCtx, pDest, pSrc);
}
#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_SHA1__) */
