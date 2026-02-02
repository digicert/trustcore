/**
 * @file hw_sim_rc.c
 *
 * @brief RC (RC4) Header for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_RC__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define CreateRC4Ctx   HW_CreateRC4Ctx
#define DeleteRC4Ctx   HW_DeleteRC4Ctx
#define DoRC4          HW_DoRC4
#define CloneRC4Ctx    HW_CloneRC4Ctx

#include "../../rc4algo.c"
#include "../../arc4.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef CreateRC4Ctx
#undef DeleteRC4Ctx
#undef DoRC4
#undef CloneRC4Ctx

extern BulkCtx CreateRC4Ctx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CreateRC4Ctx");
    if (OK != status)
        return NULL;
    
    return HW_CreateRC4Ctx(hwAccelCtx, keyMaterial, keyLength, encrypt);
}

extern MSTATUS DeleteRC4Ctx(hwAccelDescr hwAccelCtx, BulkCtx *ctx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DeleteRC4Ctx");
    if (OK != status)
        return status;
    
    return HW_DeleteRC4Ctx(hwAccelCtx, ctx);
}

extern MSTATUS DoRC4(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DoRC4");
    if (OK != status)
        return status;
    
    return HW_DoRC4(hwAccelCtx, ctx, data, dataLength, encrypt, iv);
}

extern MSTATUS CloneRC4Ctx(hwAccelDescr hwAccelCtx, BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CloneRC4Ctx");
    if (OK != status)
        return status;
    
    return HW_CloneRC4Ctx(hwAccelCtx, pCtx, ppNewCtx);
}

#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_RC__) */
