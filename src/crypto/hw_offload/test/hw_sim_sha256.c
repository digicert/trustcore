/**
 * @file hw_sim_sha256.c
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_SHA256__)

/* redefine existing methods to simulate that they are using a hw implementation */

#ifndef __DISABLE_DIGICERT_SHA256__
#define SHA256_allocDigest    HW_SHA256_allocDigest
#define SHA256_initDigest     HW_SHA256_initDigest
#define SHA256_updateDigest   HW_SHA256_updateDigest
#define SHA256_finalDigest    HW_SHA256_finalDigest
#define SHA256_freeDigest     HW_SHA256_freeDigest
#define SHA256_completeDigest HW_SHA256_completeDigest
#define SHA256_cloneCtx       HW_SHA256_cloneCtx
#endif

#ifndef __DISABLE_DIGICERT_SHA224__
#define SHA224_initDigest     HW_SHA224_initDigest
#define SHA224_finalDigest    HW_SHA224_finalDigest
#define SHA224_completeDigest HW_SHA224_completeDigest
#define SHA224_cloneCtx       HW_SHA224_cloneCtx
#endif

#include "../../sha256.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#ifndef __DISABLE_DIGICERT_SHA256__
#undef SHA256_allocDigest
#undef SHA256_initDigest
#undef SHA256_updateDigest
#undef SHA256_finalDigest
#undef SHA256_freeDigest
#undef SHA256_completeDigest
#undef SHA256_cloneCtx
#endif

#ifndef __DISABLE_DIGICERT_SHA224__
#undef SHA224_initDigest
#undef SHA224_finalDigest
#undef SHA224_completeDigest
#undef SHA224_cloneCtx
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
extern MSTATUS SHA256_allocDigest(hwAccelDescr hwAccelCtx, BulkCtx *pp_shaContext)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA256_allocDigest");
    if (OK != status)
        return status;
    
    return HW_SHA256_allocDigest(hwAccelCtx, pp_shaContext);
}

extern MSTATUS SHA256_freeDigest(hwAccelDescr hwAccelCtx, BulkCtx *pp_shaContext)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA256_freeDigest");
    if (OK != status)
        return status;
    
    return HW_SHA256_freeDigest(hwAccelCtx, pp_shaContext);
}

extern MSTATUS SHA256_initDigest(hwAccelDescr hwAccelCtx, sha256Descr *pCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA256_initDigest");
    if (OK != status)
        return status;
    
    return HW_SHA256_initDigest(hwAccelCtx, pCtx);
}

extern MSTATUS SHA256_updateDigest(hwAccelDescr hwAccelCtx, sha256Descr *pCtx, const ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA256_updateDigest");
    if (OK != status)
        return status;
    
    return HW_SHA256_updateDigest(hwAccelCtx, pCtx, pData, dataLen);
}

extern MSTATUS SHA256_finalDigest(hwAccelDescr hwAccelCtx, sha256Descr *pCtx, ubyte *pOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA256_finalDigest");
    if (OK != status)
        return status;
    
    return HW_SHA256_finalDigest(hwAccelCtx, pCtx, pOutput);
}

extern MSTATUS SHA256_completeDigest(hwAccelDescr hwAccelCtx, const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA256_completeDigest");
    if (OK != status)
        return status;
    
    return HW_SHA256_completeDigest(hwAccelCtx, pData, dataLen, pShaOutput);
}

extern MSTATUS SHA256_cloneCtx(hwAccelDescr hwAccelCtx, sha256Descr *pDest, sha256Descr *pSrc)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA256_cloneCtx");
    if (OK != status)
        return status;
    
    return HW_SHA256_cloneCtx(hwAccelCtx, pDest, pSrc);
}
#endif /*  __DISABLE_DIGICERT_SHA256__*/

#ifndef __DISABLE_DIGICERT_SHA224__
extern MSTATUS SHA224_initDigest(hwAccelDescr hwAccelCtx, sha256Descr *pCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA224_initDigest");
    if (OK != status)
        return status;
    
    return HW_SHA224_initDigest(hwAccelCtx, pCtx);
}

extern MSTATUS SHA224_finalDigest(hwAccelDescr hwAccelCtx, sha256Descr *pCtx, ubyte *pOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA224_finalDigest");
    if (OK != status)
        return status;
    
    return HW_SHA224_finalDigest(hwAccelCtx, pCtx, pOutput);
}

extern MSTATUS SHA224_completeDigest(hwAccelDescr hwAccelCtx, const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA224_completeDigest");
    if (OK != status)
        return status;
    
    return HW_SHA224_completeDigest(hwAccelCtx, pData, dataLen, pShaOutput);
}

extern MSTATUS SHA224_cloneCtx(hwAccelDescr hwAccelCtx, sha256Descr *pDest, sha256Descr *pSrc)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "SHA224_cloneCtx");
    if (OK != status)
        return status;
    
    return HW_SHA224_cloneCtx(hwAccelCtx, pDest, pSrc);
}
#endif /* __DISABLE_DIGICERT_SHA224__ */

#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_SHA256__) */
