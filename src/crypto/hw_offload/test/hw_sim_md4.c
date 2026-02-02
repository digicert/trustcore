/**
 * @file hw_sim_md4.c
 *
 * @brief MD4 - Hash Algorithm Header for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_MD4__) \
    && defined(__ENABLE_DIGICERT_MD4__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define MD4Alloc           HW_MD4Alloc
#define MD4Free            HW_MD4Free
#define MD4Init            HW_MD4Init
#define MD4Update          HW_MD4Update
#define MD4Final           HW_MD4Final
#define MD4_completeDigest HW_MD4_completeDigest
#define MD4_cloneCtx       HW_MD4_cloneCtx
#define MD45_PADDING       HW4_MD45_PADDING
#define MD45_encode        HW4_MD45_encode
#define MD45_decode        HW4_MD45_decode

#include "../../md45.c"
#include "../../md4.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef MD4Alloc
#undef MD4Free
#undef MD4Init
#undef MD4Update
#undef MD4Final
#undef MD4_completeDigest
#undef MD4_cloneCtx
#undef MD45_PADDING
#undef MD45_encode
#undef MD45_decode

extern MSTATUS MD4Alloc(hwAccelDescr hwAccelCtx, BulkCtx *pp_context)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD4Alloc");
    if (OK != status)
        return status;
    
    return HW_MD4Alloc(hwAccelCtx, pp_context);
}

extern MSTATUS MD4Free(hwAccelDescr hwAccelCtx, BulkCtx *pp_context)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD4Free");
    if (OK != status)
        return status;
    
    return HW_MD4Free(hwAccelCtx, pp_context);
}

extern MSTATUS MD4Init(hwAccelDescr hwAccelCtx, MD4_CTX *pCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD4Init");
    if (OK != status)
        return status;
    
    return HW_MD4Init(hwAccelCtx, pCtx);
}

extern MSTATUS MD4Update(hwAccelDescr hwAccelCtx, MD4_CTX *pCtx, const ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD4Update");
    if (OK != status)
        return status;
    
    return HW_MD4Update(hwAccelCtx, pCtx, pData, dataLen);
}

extern MSTATUS MD4Final(hwAccelDescr hwAccelCtx, MD4_CTX *pCtx, ubyte *pOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD4Final");
    if (OK != status)
        return status;
    
    return HW_MD4Final(hwAccelCtx, pCtx, pOutput);
}

extern MSTATUS MD4_completeDigest(hwAccelDescr hwAccelCtx, const ubyte *pData, ubyte4 dataLen, ubyte *pOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD4_completeDigest");
    if (OK != status)
        return status;
    
    return HW_MD4_completeDigest(hwAccelCtx, pData, dataLen, pOutput);
}

extern MSTATUS MD4_cloneCtx(hwAccelDescr hwAccelCtx, MD4_CTX *pDest, MD4_CTX *pSrc)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD4_cloneCtx");
    if (OK != status)
        return status;
    
    return HW_MD4_cloneCtx(hwAccelCtx, pDest, pSrc);
}
#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_MD4__) 
          && defined(__ENABLE_DIGICERT_MD4__)) */
