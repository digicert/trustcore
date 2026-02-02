/**
 * @file hw_sim_des.c
 *
 * @brief DES Header for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_DES__) \
    && (defined(__ENABLE_DES_CIPHER__) || !defined(__DISABLE_3DES_CIPHERS__))

/* redefine existing methods to simulate that they are using a hw implementation */

#ifdef __ENABLE_DES_CIPHER__
#define CreateDESCtx          HW_CreateDESCtx
#define DeleteDESCtx          HW_DeleteDESCtx
#define CloneDESCtx           HW_CloneDESCtx
#define DoDES                 HW_DoDES
#endif

#ifndef __DISABLE_3DES_CIPHERS__
#define Create3DESCtx         HW_Create3DESCtx
#define Delete3DESCtx         HW_Delete3DESCtx
#define Reset3DESCtx          HW_Reset3DESCtx
#define Do3DesCbcWithPkcs5Pad HW_Do3DesCbcWithPkcs5Pad
#define Do3DES                HW_Do3DES
#define Clone3DESCtx          HW_Clone3DESCtx
#define Create2Key3DESCtx     HW_Create2Key3DESCtx
#endif

#include "../../des.c"
#include "../../three_des.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#ifdef __ENABLE_DES_CIPHER__
#undef CreateDESCtx
#undef DeleteDESCtx
#undef CloneDESCtx
#undef DoDES
#endif

#ifndef __DISABLE_3DES_CIPHERS__
#undef Create3DESCtx
#undef Delete3DESCtx
#undef Reset3DESCtx
#undef Do3DesCbcWithPkcs5Pad
#undef Do3DES
#undef Clone3DESCtx
#undef Create2Key3DESCtx
#endif

#ifdef __ENABLE_DES_CIPHER__
extern BulkCtx CreateDESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CreateDESCtx");
    if (OK != status)
        return NULL;
    
    return HW_CreateDESCtx(hwAccelCtx, keyMaterial, keyLength, encrypt);
}

extern MSTATUS DeleteDESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DeleteDESCtx");
    if (OK != status)
        return status;
    
    return HW_DeleteDESCtx(hwAccelCtx, ctx);
}

extern MSTATUS CloneDESCtx(hwAccelDescr hwAccelCtx, BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CloneDESCtx");
    if (OK != status)
        return status;
    
    return HW_CloneDESCtx(hwAccelCtx, pCtx, ppNewCtx);
}

extern MSTATUS DoDES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DoDES");
    if (OK != status)
        return status;
    
    return HW_DoDES(hwAccelCtx, ctx, data, dataLength, encrypt, iv);
}
#endif /* __ENABLE_DES_CIPHER__ */

#ifndef __DISABLE_3DES_CIPHERS__
extern BulkCtx Create3DESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "Create3DESCtx");
    if (OK != status)
        return NULL;
    
    return HW_Create3DESCtx(hwAccelCtx, keyMaterial, keyLength, encrypt);
}

extern MSTATUS Delete3DESCtx(hwAccelDescr hwAccelCtx, BulkCtx *ctx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "Delete3DESCtx");
    if (OK != status)
        return status;
    
    return HW_Delete3DESCtx(hwAccelCtx, ctx);
}

extern MSTATUS Reset3DESCtx(hwAccelDescr hwAccelCtx, BulkCtx *ctx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "Reset3DESCtx");
    if (OK != status)
        return status;
    
    return HW_Reset3DESCtx(hwAccelCtx, ctx);
}

extern MSTATUS Do3DesCbcWithPkcs5Pad (hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte *pDataToProcess,
                                      ubyte4 dataLength, ubyte *pProcessedData, ubyte4 bufferSize,
                                      ubyte4 *pProcessedDataLen, sbyte4 encryptFlag, ubyte *pInitVector)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "Do3DesCbcWithPkcs5Pad");
    if (OK != status)
        return status;
    
    return HW_Do3DesCbcWithPkcs5Pad(hwAccelCtx, ctx, pDataToProcess, dataLength, pProcessedData, bufferSize,
                                      pProcessedDataLen, encryptFlag, pInitVector);
}

extern MSTATUS Do3DES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "Do3DES");
    if (OK != status)
        return status;
    
    return HW_Do3DES(hwAccelCtx, ctx, data, dataLength, encrypt, iv);
}

extern MSTATUS Clone3DESCtx(hwAccelDescr hwAccelCtx, BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "Clone3DESCtx");
    if (OK != status)
        return status;
    
    return HW_Clone3DESCtx(hwAccelCtx, pCtx, ppNewCtx);
}

extern BulkCtx Create2Key3DESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "Create2Key3DESCtx");
    if (OK != status)
        return NULL;
    
    return HW_Create2Key3DESCtx(hwAccelCtx, keyMaterial, keyLength, encrypt);
}
#endif /* __DISABLE_3DES_CIPHERS__ */

#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_DES__) 
          && (defined(__ENABLE_DES_CIPHER__) || !defined(__DISABLE_3DES_CIPHERS__)) */
