/**
 * @file hw_sim_blowfish.c
 *
 * @brief Blowfish Header for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_BLOWFISH__) \
    && defined(__ENABLE_BLOWFISH_CIPHERS__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define CreateBlowfishCtx     HW_CreateBlowfishCtx
#define DeleteBlowfishCtx   HW_DeleteBlowfishCtx
#define DoBlowfish   HW_DoBlowfish

#include "../../blowfish.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef CreateBlowfishCtx
#undef DeleteBlowfishCtx
#undef DoBlowfish

extern BulkCtx CreateBlowfishCtx(hwAccelDescr hwAccelCtx, ubyte* pKeyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CreateBlowfishCtx");
    if (OK != status)
        return NULL;
    
    return HW_CreateBlowfishCtx(hwAccelCtx, pKeyMaterial, keyLength, encrypt);
}

extern MSTATUS DeleteBlowfishCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DeleteBlowfishCtx");
    if (OK != status)
        return status;
    
    return HW_DeleteBlowfishCtx(hwAccelCtx, ctx);
}

extern MSTATUS DoBlowfish(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DoBlowfish");
    if (OK != status)
        return status;
    
    return HW_DoBlowfish(hwAccelCtx, ctx, data, dataLength, encrypt, iv);
}

#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_BLOWFISH__) 
          && defined(__ENABLE_BLOWFISH_CIPHERS__) */
