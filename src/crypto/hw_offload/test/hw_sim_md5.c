/**
 * @file hw_sim_md5.c
 *
 * @brief MD5 - Hash Algorithm Header for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_MD5__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define MD5Alloc_m         HW_MD5Alloc_m
#define MD5Init_m          HW_MD5Init_m
#define MD5Update_m        HW_MD5Update_m
#define MD5Final_m         HW_MD5Final_m
#define MD5Free_m          HW_MD5Free_m
#define MD5_completeDigest HW_MD5_completeDigest
#define MD5_cloneCtx       HW_MD5_cloneCtx
#define MD45_PADDING       HW5_MD45_PADDING
#define MD45_encode        HW5_MD45_encode
#define MD45_decode        HW5_MD45_decode

#include "../../md45.c"
#include "../../md5.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef MD5Alloc_m
#undef MD5Init_m
#undef MD5Update_m
#undef MD5Final_m
#undef MD5Free_m
#undef MD5_completeDigest
#undef MD5_cloneCtx
#undef MD45_PADDING
#undef MD45_encode
#undef MD45_decode

extern MSTATUS MD5Alloc_m(hwAccelDescr hwAccelCtx, BulkCtx *pp_context)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD5Alloc_m");
    if (OK != status)
        return status;
    
    return HW_MD5Alloc_m(hwAccelCtx, pp_context);
}

extern MSTATUS MD5Free_m(hwAccelDescr hwAccelCtx, BulkCtx *pp_context)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD5Free_m");
    if (OK != status)
        return status;
    
    return HW_MD5Free_m(hwAccelCtx, pp_context);
}

extern MSTATUS MD5Init_m(hwAccelDescr hwAccelCtx, MD5_CTX *pCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD5Init_m");
    if (OK != status)
        return status;
    
    return HW_MD5Init_m(hwAccelCtx, pCtx);
}

extern MSTATUS MD5Update_m(hwAccelDescr hwAccelCtx, MD5_CTX *pCtx, const ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD5Update_m");
    if (OK != status)
        return status;
    
    return HW_MD5Update_m(hwAccelCtx, pCtx, pData, dataLen);
}

extern MSTATUS MD5Final_m(hwAccelDescr hwAccelCtx, MD5_CTX *pCtx, ubyte *pOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD5Final_m");
    if (OK != status)
        return status;
    
    return HW_MD5Final_m(hwAccelCtx, pCtx, pOutput);
}

extern MSTATUS MD5_completeDigest(hwAccelDescr hwAccelCtx, const ubyte *pData, ubyte4 dataLen, ubyte *pOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD5_completeDigest");
    if (OK != status)
        return status;
    
    return HW_MD5_completeDigest(hwAccelCtx, pData, dataLen, pOutput);
}

extern MSTATUS MD5_cloneCtx(hwAccelDescr hwAccelCtx, MD5_CTX *pDest, MD5_CTX *pSrc)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "MD5_cloneCtx");
    if (OK != status)
        return status;
    
    return HW_MD5_cloneCtx(hwAccelCtx, pDest, pSrc);
}
#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_MD5__) */
