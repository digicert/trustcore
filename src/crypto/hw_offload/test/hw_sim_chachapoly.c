/**
 * @file hw_sim_chachapoly.c
 *
 * @brief ChaChaPoly Header for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_CHACHAPOLY__) \
    && defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define Poly1305Update                 HW_Poly1305Update
#define Poly1305_completeDigest        HW_Poly1305_completeDigest
#define Poly1305Init                   HW_Poly1305Init
#define Poly1305Final                  HW_Poly1305Final
#define CreateChaCha20Ctx              HW_CreateChaCha20Ctx
#define DeleteChaCha20Ctx              HW_DeleteChaCha20Ctx
#define DoChaCha20                     HW_DoChaCha20
#define CHACHA20_setNonceAndCounterSSH HW_CHACHA20_setNonceAndCounterSSH
#define ChaCha20Poly1305_cipher        HW_ChaCha20Poly1305_cipher
#define ChaCha20Poly1305_cipherSSH     HW_ChaCha20Poly1305_cipherSSH
#define CloneChaCha20Ctx               HW_CloneChaCha20Ctx
#define ChaCha20Poly1305_createCtx     HW_ChaCha20Poly1305_createCtx
#define ChaCha20Poly1305_deleteCtx     HW_ChaCha20Poly1305_deleteCtx
#define ChaCha20Poly1305_update_nonce  HW_ChaCha20Poly1305_update_nonce
#define ChaCha20Poly1305_update_aad    HW_ChaCha20Poly1305_update_aad
#define ChaCha20Poly1305_update_data   HW_ChaCha20Poly1305_update_data
#define ChaCha20Poly1305_final         HW_ChaCha20Poly1305_final
#define ChaCha20Poly1305_cloneCtx      HW_ChaCha20Poly1305_cloneCtx

#include "../../poly1305.c"
#include "../../chacha20.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef Poly1305Update
#undef Poly1305_completeDigest
#undef Poly1305Init
#undef Poly1305Final
#undef CreateChaCha20Ctx
#undef DeleteChaCha20Ctx
#undef DoChaCha20
#undef CHACHA20_setNonceAndCounterSSH
#undef ChaCha20Poly1305_cipher
#undef ChaCha20Poly1305_cipherSSH
#undef CloneChaCha20Ctx
#undef ChaCha20Poly1305_createCtx
#undef ChaCha20Poly1305_deleteCtx
#undef ChaCha20Poly1305_update_nonce
#undef ChaCha20Poly1305_update_aad
#undef ChaCha20Poly1305_update_data
#undef ChaCha20Poly1305_final
#undef ChaCha20Poly1305_cloneCtx

extern MSTATUS Poly1305Update(hwAccelDescr hwAccelCtx, Poly1305Ctx *ctx, const ubyte *m, ubyte4 bytes)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "Poly1305Update");
    if (OK != status)
        return status;
    
    return HW_Poly1305Update(hwAccelCtx, ctx, m, bytes);
}

extern MSTATUS Poly1305_completeDigest(hwAccelDescr hwAccelCtx, ubyte mac[16], const ubyte *m, ubyte4 bytes,
                        const ubyte key[32])
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "Poly1305_completeDigest");
    if (OK != status)
        return status;
    
    return HW_Poly1305_completeDigest(hwAccelCtx, mac, m, bytes, key);
}

extern MSTATUS Poly1305Init(hwAccelDescr hwAccelCtx, Poly1305Ctx *ctx, const ubyte key[32])
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "Poly1305Init");
    if (OK != status)
        return status;
    
    return HW_Poly1305Init(hwAccelCtx, ctx, key);
}

extern MSTATUS Poly1305Final(hwAccelDescr hwAccelCtx, Poly1305Ctx *ctx, ubyte mac[16])
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "Poly1305Final");
    if (OK != status)
        return status;

    return HW_Poly1305Final(hwAccelCtx, ctx, mac);
}

extern BulkCtx CreateChaCha20Ctx(hwAccelDescr hwAccelCtx, const ubyte *pKeyMaterial, sbyte4 keyLength, 
                                 sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CreateChaCha20Ctx");
    if (OK != status)
        return NULL;
    
    return HW_CreateChaCha20Ctx(hwAccelCtx, pKeyMaterial, keyLength, encrypt);
}

extern MSTATUS DeleteChaCha20Ctx(hwAccelDescr hwAccelCtx, BulkCtx *pCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DeleteChaCha20Ctx");
    if (OK != status)
        return status;
    
    return HW_DeleteChaCha20Ctx(hwAccelCtx, pCtx);
}

extern MSTATUS DoChaCha20(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte *pData, sbyte4 dataLength,
                          sbyte4 encrypt, ubyte *pIv)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DoChaCha20");
    if (OK != status)
        return status;
    
    return HW_DoChaCha20(hwAccelCtx, ctx, pData, dataLength, encrypt, pIv);
}

extern MSTATUS CHACHA20_setNonceAndCounterSSH(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte *pNonce, ubyte4 nonceLength,
                                              ubyte *pCounter, ubyte counterLength)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CHACHA20_setNonceAndCounterSSH");
    if (OK != status)
        return status;
    
    return HW_CHACHA20_setNonceAndCounterSSH(hwAccelCtx, ctx, pNonce, nonceLength, pCounter, counterLength);
}

extern MSTATUS CloneChaCha20Ctx(hwAccelDescr hwAccelCtx, BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "CloneChaCha20Ctx");
    if (OK != status)
        return status;
    
    return HW_CloneChaCha20Ctx(hwAccelCtx, pCtx, ppNewCtx);
}

extern BulkCtx ChaCha20Poly1305_createCtx(hwAccelDescr hwAccelCtx, ubyte *pKey, sbyte4 keyLen, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ChaCha20Poly1305_createCtx");
    if (OK != status)
        return NULL;
    
    return HW_ChaCha20Poly1305_createCtx(hwAccelCtx, pKey, keyLen, encrypt);
}

extern MSTATUS ChaCha20Poly1305_deleteCtx(hwAccelDescr hwAccelCtx, BulkCtx *pCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ChaCha20Poly1305_deleteCtx");
    if (OK != status)
        return status;
    
    return HW_ChaCha20Poly1305_deleteCtx(hwAccelCtx, pCtx);
}

extern MSTATUS ChaCha20Poly1305_cipherSSH(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte *pNonce, ubyte4 nlen,
                                          ubyte *pAdata, ubyte4 alen, ubyte *pData, ubyte4 dlen, 
                                          ubyte4 verifyLen, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ChaCha20Poly1305_cipherSSH");
    if (OK != status)
        return status;
    
    return HW_ChaCha20Poly1305_cipherSSH(hwAccelCtx, ctx, pNonce, nlen, pAdata, alen, pData, dlen, verifyLen, encrypt);
}

extern MSTATUS ChaCha20Poly1305_cipher(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte *pNonce, ubyte4 nlen,
                                       ubyte *pAdata, ubyte4 alen, ubyte *pData, ubyte4 dlen,
                                       ubyte4 verifyLen, sbyte4 encrypt)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ChaCha20Poly1305_cipher");
    if (OK != status)
        return status;
 
    return HW_ChaCha20Poly1305_cipher(hwAccelCtx, ctx, pNonce, nlen, pAdata, alen, pData, dlen, verifyLen, encrypt);
}

extern MSTATUS ChaCha20Poly1305_update_nonce(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte *pNonce, ubyte4 nonceLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ChaCha20Poly1305_update_nonce");
    if (OK != status)
        return status;
    
    return HW_ChaCha20Poly1305_update_nonce(hwAccelCtx, ctx, pNonce, nonceLen);
}

extern MSTATUS ChaCha20Poly1305_update_aad(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte *pAadData, ubyte4 aadDataLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ChaCha20Poly1305_update_aad");
    if (OK != status)
        return status;

    return HW_ChaCha20Poly1305_update_aad(hwAccelCtx, ctx, pAadData, aadDataLen);
}

extern MSTATUS ChaCha20Poly1305_update_data(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ChaCha20Poly1305_update_data");
    if (OK != status)
        return status;

    return HW_ChaCha20Poly1305_update_data(hwAccelCtx, ctx, pData, dataLen);
}                                             

extern MSTATUS ChaCha20Poly1305_final(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte *pTag, ubyte4 tagLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ChaCha20Poly1305_final");
    if (OK != status)
        return status;
    
    return HW_ChaCha20Poly1305_final(hwAccelCtx, ctx, pTag, tagLen);
}

extern MSTATUS ChaCha20Poly1305_cloneCtx(hwAccelDescr hwAccelCtx, BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ChaCha20Poly1305_cloneCtx");
    if (OK != status)
        return status;

    return HW_ChaCha20Poly1305_cloneCtx(hwAccelCtx, pCtx, ppNewCtx);
}                      
#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_CHACHAPOLY__)
          && defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__) */
