/**
 * @file hw_sim_aes.c
 *
 * @brief AES Header for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_AES__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define AESALGO_makeAesKeyEx     HW_AESALGO_makeAesKeyEx
#define AESALGO_blockEncryptEx   HW_AESALGO_blockEncryptEx
#define AESALGO_blockDecryptEx   HW_AESALGO_blockDecryptEx
#define CreateAESCtx             HW_CreateAESCtx
#define DeleteAESCtx             HW_DeleteAESCtx
#define ResetAESCtx              HW_ResetAESCtx
#define DoAES                    HW_DoAES
#define CreateAESCFBCtx          HW_CreateAESCFBCtx
#define CreateAESCFB1Ctx         HW_CreateAESCFB1Ctx
#define CreateAESOFBCtx          HW_CreateAESOFBCtx
#define CloneAESCtx              HW_CloneAESCtx
#define CreateAESECBCtx          HW_CreateAESECBCtx
#define DeleteAESECBCtx          HW_DeleteAESECBCtx
#define DoAESECB                 HW_DoAESECB

#include "../../aes.c"
#include "../../aes_ecb.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef AESALGO_makeAesKeyEx
#undef AESALGO_blockEncryptEx
#undef AESALGO_blockDecryptEx
#undef CreateAESCtx
#undef DeleteAESCtx
#undef ResetAESCtx
#undef DoAES
#undef CreateAESCFBCtx
#undef CreateAESCFB1Ctx
#undef CreateAESOFBCtx
#undef CloneAESCtx
#undef CreateAESECBCtx
#undef DeleteAESECBCtx
#undef DoAESECB

extern MSTATUS AESALGO_makeAesKeyEx(hwAccelDescr hwAccelCtx, aesCipherContext *pAesContext, sbyte4 keyLen, const ubyte *keyMaterial,
                                    sbyte4 encrypt, sbyte4 mode)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "AESALGO_makeAesKeyEx");
    if (OK != status)
        return status;
    
    return HW_AESALGO_makeAesKeyEx(hwAccelCtx, pAesContext, keyLen, keyMaterial, encrypt, mode);
}

extern MSTATUS AESALGO_blockEncryptEx (hwAccelDescr hwAccelCtx, aesCipherContext *pAesContext, ubyte* iv, ubyte *input, sbyte4 inputLen,
                                       ubyte *outBuffer, sbyte4 *pRetLength)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "AESALGO_blockEncryptEx");
    if (OK != status)
        return status;
    
    return HW_AESALGO_blockEncryptEx(hwAccelCtx, pAesContext, iv, input, inputLen, outBuffer, pRetLength);
}

extern MSTATUS AESALGO_blockDecryptEx (hwAccelDescr hwAccelCtx, aesCipherContext *pAesContext, ubyte* iv, ubyte *input, sbyte4 inputLen,
                                       ubyte *outBuffer, sbyte4 *pRetLength)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "AESALGO_blockDecryptEx");
    if (OK != status)
        return status;
    
    return HW_AESALGO_blockDecryptEx(hwAccelCtx, pAesContext, iv, input, inputLen, outBuffer, pRetLength);
}

extern BulkCtx CreateAESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CreateAESCtx");
    if (OK != status)
        return NULL;
    
    return HW_CreateAESCtx(hwAccelCtx, keyMaterial, keyLength, encrypt);
}

extern BulkCtx CreateAESCFBCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CreateAESCFBCtx");
    if (OK != status)
        return NULL;
    
    return HW_CreateAESCFBCtx(hwAccelCtx, keyMaterial, keyLength, encrypt);
}

extern BulkCtx CreateAESCFB1Ctx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CreateAESCFB1Ctx");
    if (OK != status)
        return NULL;
    
    return HW_CreateAESCFB1Ctx(hwAccelCtx, keyMaterial, keyLength, encrypt);
}

extern BulkCtx CreateAESOFBCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CreateAESOFBCtx");
    if (OK != status)
        return NULL;
    
    return HW_CreateAESOFBCtx(hwAccelCtx, keyMaterial, keyLength, encrypt);
}

extern MSTATUS DeleteAESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DeleteAESCtx");
    if (OK != status)
        return status;
    
    return HW_DeleteAESCtx(hwAccelCtx, ctx);
}

extern MSTATUS DoAES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DoAES");
    if (OK != status)
        return status;
    
    return HW_DoAES(hwAccelCtx, ctx, data, dataLength, encrypt, iv);
}

extern MSTATUS CloneAESCtx(hwAccelDescr hwAccelCtx, BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CloneAESCtx");
    if (OK != status)
        return status;
    
    return HW_CloneAESCtx(hwAccelCtx, pCtx, ppNewCtx);
}

extern MSTATUS ResetAESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ResetAESCtx");
    if (OK != status)
        return status;
    
    return HW_ResetAESCtx(hwAccelCtx, ctx);
}

extern BulkCtx CreateAESECBCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CreateAESECBCtx");
    if (OK != status)
        return NULL;
    
    return HW_CreateAESECBCtx(hwAccelCtx, keyMaterial, keyLength, encrypt);
}

extern MSTATUS DeleteAESECBCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DeleteAESECBCtx");
    if (OK != status)
        return status;
    
    return HW_DeleteAESECBCtx(hwAccelCtx, ctx);
}

extern MSTATUS DoAESECB(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DoAESECB");
    if (OK != status)
        return status;
 
    return HW_DoAESECB(hwAccelCtx, ctx, data, dataLength, encrypt);
}
#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_AES__) */
