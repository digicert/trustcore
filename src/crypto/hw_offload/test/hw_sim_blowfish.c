/**
 * @file hw_sim_blowfish.c
 *
 * @brief Blowfish Header for hw simulator
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
