/**
 * @file hw_sim_blake2.c
 *
 * @brief BLAKE2 - Header for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_BLAKE2__)

/* redefine existing methods to simulate that they are using a hw implementation */

#ifdef __ENABLE_DIGICERT_BLAKE_2B__
#define BLAKE2B_alloc    HW_BLAKE2B_alloc
#define BLAKE2B_init     HW_BLAKE2B_init
#define BLAKE2B_update   HW_BLAKE2B_update
#define BLAKE2B_final    HW_BLAKE2B_final
#define BLAKE2B_delete   HW_BLAKE2B_delete
#define BLAKE2B_complete HW_BLAKE2B_complete
#define BLAKE2B_cloneCtx HW_BLAKE2B_cloneCtx
#endif

#ifdef __ENABLE_DIGICERT_BLAKE_2S__
#define BLAKE2S_alloc    HW_BLAKE2S_alloc
#define BLAKE2S_init     HW_BLAKE2S_init
#define BLAKE2S_update   HW_BLAKE2S_update
#define BLAKE2S_final    HW_BLAKE2S_final
#define BLAKE2S_delete   HW_BLAKE2S_delete
#define BLAKE2S_complete HW_BLAKE2S_complete
#define BLAKE2S_cloneCtx HW_BLAKE2S_cloneCtx
#endif

#include "../../blake2.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#ifdef __ENABLE_DIGICERT_BLAKE_2B__
#undef BLAKE2B_alloc
#undef BLAKE2B_init
#undef BLAKE2B_update
#undef BLAKE2B_final
#undef BLAKE2B_delete
#undef BLAKE2B_complete
#undef BLAKE2B_cloneCtx
#endif

#ifdef __ENABLE_DIGICERT_BLAKE_2S__
#undef BLAKE2S_alloc
#undef BLAKE2S_init
#undef BLAKE2S_update
#undef BLAKE2S_final
#undef BLAKE2S_delete
#undef BLAKE2S_complete
#undef BLAKE2S_cloneCtx
#endif

#ifdef __ENABLE_DIGICERT_BLAKE_2B__
extern MSTATUS BLAKE2B_alloc(hwAccelDescr hwAccelCtx, BulkCtx *ppCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2B_alloc");
    if (OK != status)
        return status;
    
    return HW_BLAKE2B_alloc(hwAccelCtx, ppCtx);
}

extern MSTATUS BLAKE2B_init(hwAccelDescr hwAccelCtx, BulkCtx pCtx, ubyte4 outLen, ubyte *pKey, ubyte4 keyLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2B_init");
    if (OK != status)
        return status;
    
    return HW_BLAKE2B_init(hwAccelCtx, pCtx, outLen, pKey, keyLen);
}

extern MSTATUS BLAKE2B_update(hwAccelDescr hwAccelCtx, BulkCtx pCtx, ubyte *pData, ubyte4 dataLen )
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2B_update");
    if (OK != status)
        return status;
    
    return HW_BLAKE2B_update(hwAccelCtx, pCtx, pData, dataLen);
}

extern MSTATUS BLAKE2B_final(hwAccelDescr hwAccelCtx, BulkCtx pCtx, ubyte *pOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2B_final");
    if (OK != status)
        return status;
    
    return HW_BLAKE2B_final(hwAccelCtx, pCtx, pOutput);
}

extern MSTATUS BLAKE2B_delete(hwAccelDescr hwAccelCtx, BulkCtx *ppCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2B_delete");
    if (OK != status)
        return status;
    
    return HW_BLAKE2B_delete(hwAccelCtx, ppCtx);
}

extern MSTATUS BLAKE2B_complete(hwAccelDescr hwAccelCtx, ubyte *pKey, ubyte4 keyLen, ubyte *pData,
                                ubyte4 dataLen, ubyte *pOutput, ubyte4 outLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2B_complete");
    if (OK != status)
        return status;
    
    return HW_BLAKE2B_complete(hwAccelCtx, pKey, keyLen, pData, dataLen, pOutput, outLen);
}

extern MSTATUS BLAKE2B_cloneCtx(hwAccelDescr hwAccelCtx, BLAKE2B_CTX *pDest, BLAKE2B_CTX *pSrc)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2B_cloneCtx");
    if (OK != status)
        return status;
    
    return HW_BLAKE2B_cloneCtx(hwAccelCtx, pDest, pSrc);
}
#endif /* __ENABLE_DIGICERT_BLAKE_2B__ */

#ifdef __ENABLE_DIGICERT_BLAKE_2S__
extern MSTATUS BLAKE2S_alloc(hwAccelDescr hwAccelCtx, BulkCtx *ppCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2S_alloc");
    if (OK != status)
        return status;
    
    return HW_BLAKE2S_alloc(hwAccelCtx, ppCtx);
}

extern MSTATUS BLAKE2S_init(hwAccelDescr hwAccelCtx, BulkCtx pCtx, ubyte4 outLen, ubyte *pKey, ubyte4 keyLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2S_init");
    if (OK != status)
        return status;
    
    return HW_BLAKE2S_init(hwAccelCtx, pCtx, outLen, pKey, keyLen);
}

extern MSTATUS BLAKE2S_update(hwAccelDescr hwAccelCtx, BulkCtx pCtx, ubyte *pData, ubyte4 dataLen )
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2S_update");
    if (OK != status)
        return status;
    
    return HW_BLAKE2S_update(hwAccelCtx, pCtx, pData, dataLen);
}

extern MSTATUS BLAKE2S_final(hwAccelDescr hwAccelCtx, BulkCtx pCtx, ubyte *pOutput)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2S_final");
    if (OK != status)
        return status;
    
    return HW_BLAKE2S_final(hwAccelCtx, pCtx, pOutput);
}

extern MSTATUS BLAKE2S_delete(hwAccelDescr hwAccelCtx, BulkCtx *ppCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2S_delete");
    if (OK != status)
        return status;
    
    return HW_BLAKE2S_delete(hwAccelCtx, ppCtx);
}

extern MSTATUS BLAKE2S_complete(hwAccelDescr hwAccelCtx, ubyte *pKey, ubyte4 keyLen, ubyte *pData,
                                ubyte4 dataLen, ubyte *pOutput, ubyte4 outLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2S_complete");
    if (OK != status)
        return status;
    
    return HW_BLAKE2S_complete(hwAccelCtx, pKey, keyLen, pData, dataLen, pOutput, outLen);
}

extern MSTATUS BLAKE2S_cloneCtx(hwAccelDescr hwAccelCtx, BLAKE2S_CTX *pDest, BLAKE2S_CTX *pSrc)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "BLAKE2S_cloneCtx");
    if (OK != status)
        return status;
    
    return HW_BLAKE2S_cloneCtx(hwAccelCtx, pDest, pSrc);
}
#endif /* __ENABLE_DIGICERT_BLAKE_2S__ */

#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_BLAKE2__) */
