/**
 * @file hw_sim_sha512.c
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_SHA512__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define SHA512_allocDigest    HW_SHA512_allocDigest
#define SHA512_initDigest     HW_SHA512_initDigest
#define SHA512_updateDigest   HW_SHA512_updateDigest
#define SHA512_finalDigest    HW_SHA512_finalDigest
#define SHA512_freeDigest     HW_SHA512_freeDigest
#define SHA512_completeDigest HW_SHA512_completeDigest
#define SHA512_cloneCtx       HW_SHA512_cloneCtx
#define SHA384_initDigest     HW_SHA384_initDigest
#define SHA384_finalDigest    HW_SHA384_finalDigest
#define SHA384_completeDigest HW_SHA384_completeDigest
#define SHA384_cloneCtx       HW_SHA384_cloneCtx

#include "../../sha512.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef SHA512_allocDigest
#undef SHA512_initDigest
#undef SHA512_updateDigest
#undef SHA512_finalDigest
#undef SHA512_freeDigest
#undef SHA512_completeDigest
#undef SHA512_cloneCtx
#undef SHA384_initDigest
#undef SHA384_finalDigest
#undef SHA384_completeDigest
#undef SHA384_cloneCtx

extern MSTATUS SHA512_allocDigest(hwAccelDescr hwAccelCtx, BulkCtx *pp_shaContext)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA512_allocDigest");
    if (OK != status)
        return status;
    
    return HW_SHA512_allocDigest(hwAccelCtx, pp_shaContext);
}

extern MSTATUS SHA512_freeDigest(hwAccelDescr hwAccelCtx, BulkCtx *pp_shaContext)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA512_freeDigest");
    if (OK != status)
        return status;
    
    return HW_SHA512_freeDigest(hwAccelCtx, pp_shaContext);
}

extern MSTATUS SHA512_initDigest(hwAccelDescr hwAccelCtx, sha512Descr *pCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA512_initDigest");
    if (OK != status)
        return status;
    
    return HW_SHA512_initDigest(hwAccelCtx, pCtx);
}

extern MSTATUS SHA512_updateDigest(hwAccelDescr hwAccelCtx, sha512Descr *pCtx, const ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA512_updateDigest");
    if (OK != status)
        return status;
    
    return HW_SHA512_updateDigest(hwAccelCtx, pCtx, pData, dataLen);
}

extern MSTATUS SHA512_finalDigest(hwAccelDescr hwAccelCtx, sha512Descr *pCtx, ubyte *pOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA512_finalDigest");
    if (OK != status)
        return status;
    
    return HW_SHA512_finalDigest(hwAccelCtx, pCtx, pOutput);
}

extern MSTATUS SHA512_completeDigest(hwAccelDescr hwAccelCtx, const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA512_completeDigest");
    if (OK != status)
        return status;
    
    return HW_SHA512_completeDigest(hwAccelCtx, pData, dataLen, pShaOutput);
}

extern MSTATUS SHA512_cloneCtx(hwAccelDescr hwAccelCtx, sha512Descr *pDest, sha512Descr *pSrc)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA512_cloneCtx");
    if (OK != status)
        return status;
    
    return HW_SHA512_cloneCtx(hwAccelCtx, pDest, pSrc);
}

extern MSTATUS SHA384_initDigest(hwAccelDescr hwAccelCtx, sha512Descr *pCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA384_initDigest");
    if (OK != status)
        return status;
    
    return HW_SHA384_initDigest(hwAccelCtx, pCtx);
}

extern MSTATUS SHA384_finalDigest(hwAccelDescr hwAccelCtx, sha512Descr *pCtx, ubyte *pOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA384_finalDigest");
    if (OK != status)
        return status;
    
    return HW_SHA384_finalDigest(hwAccelCtx, pCtx, pOutput);
}

extern MSTATUS SHA384_completeDigest(hwAccelDescr hwAccelCtx, const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA384_completeDigest");
    if (OK != status)
        return status;
    
    return HW_SHA384_completeDigest(hwAccelCtx, pData, dataLen, pShaOutput);
}

extern MSTATUS SHA384_cloneCtx(hwAccelDescr hwAccelCtx, sha512Descr *pDest, sha512Descr *pSrc)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA384_cloneCtx");
    if (OK != status)
        return status;
    
    return HW_SHA384_cloneCtx(hwAccelCtx, pDest, pSrc);
}
#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_SHA512__) */
