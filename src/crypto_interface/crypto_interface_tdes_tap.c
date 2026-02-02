/*
 * crypto_interface_tdes_tap.c
 *
 * Cryptographic Interface specification for TDES TAP.
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

#include "../crypto/mocsym.h"
#include "../common/debug_console.h"
#include "../crypto_interface/crypto_interface_sym_tap.h"
#include "../crypto_interface/crypto_interface_des_tap.h"
#include "../crypto_interface/crypto_interface_tdes_tap.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../tap/tap_smp.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../asn1/mocasn1.h"
#include "../crypto/mocsymalgs/tap/symtap.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/cryptointerface.h"
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_getTDesCbcCtxFromSymmetricKeyAlloc(
    SymmetricKey *pSymKey,
    BulkCtx *ppNewCtx,
    sbyte4 encrypt
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    DES3Ctx *pNewCtx = NULL;
    MocSymCtx pSymCtx = NULL;
    MTapKeyData *pTapData = NULL;

    if ( (NULL == pSymKey) || (NULL == pSymKey->pKeyData) || (NULL == ppNewCtx) )
    {
        goto exit;
    }

    pSymCtx = (MocSymCtx)pSymKey->pKeyData;
    pTapData = (MTapKeyData *)pSymCtx->pLocalData;

    if (NULL == pTapData)
        goto exit;

    /* This method is defined for use with only for CBC mode! */
    pTapData->symMode = TAP_SYM_KEY_MODE_CBC;

    /* Override the internal TAP structure sym mode too */
    pTapData->pKey->keyData.algKeyInfo.desInfo.symMode = TAP_SYM_KEY_MODE_CBC;

    /* Set the direction */
    pTapData->direction = encrypt ? MOCANA_SYM_TAP_ENCRYPT : MOCANA_SYM_TAP_DECRYPT;

    /* Allocate the new wrapper */
    status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(DES3Ctx));
    if (OK != status)
        goto exit;

    /* Transfer control of the underlying MocSymCtx to the wrapper */
    pNewCtx->pMocSymCtx = pSymCtx; pSymCtx = NULL;
    pSymKey->pKeyData = NULL;

    /* Mark this object as crypto interface enabled */
    pNewCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    *ppNewCtx = (BulkCtx) pNewCtx; pNewCtx = NULL;

exit:

    /* Allocation is last thing to fail, no cleanup needed on it */

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_initTDesEcbCtxFromSymmetricKey (
    SymmetricKey *pSymKey,
    ctx3des *pCtx
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    MocSymCtx pSymCtx = NULL;
    MTapKeyData *pTapData = NULL;

    if ( (NULL == pSymKey) || (NULL == pSymKey->pKeyData) || (NULL == pCtx) )
    {
        goto exit;
    }

    pSymCtx = (MocSymCtx)pSymKey->pKeyData;
    pTapData = (MTapKeyData *)pSymCtx->pLocalData;

    if (NULL == pTapData)
        goto exit;

    /* clear any existing key */
    status = CRYPTO_INTERFACE_THREE_DES_clearKey(pCtx);
    if (OK != status)
        goto exit;

    /* This method is defined for use with only for EBC mode! */
    pTapData->symMode = TAP_SYM_KEY_MODE_ECB;

    /* Override the internal TAP structure sym mode too */
    pTapData->pKey->keyData.algKeyInfo.desInfo.symMode = TAP_SYM_KEY_MODE_ECB;

    /* Transfer control of the underlying MocSymCtx to the wrapper */
    pCtx->pMocSymCtx = pSymCtx; pSymCtx = NULL;
    pSymKey->pKeyData = NULL;

    /* Mark this object as crypto interface enabled */
    pCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

exit:

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_TDesEcbDeferKeyUnload (
    BulkCtx pCtx,
    byteBoolean deferredTokenUnload
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    ctx3des *pTDesCtx = (ctx3des *) pCtx;

    if (NULL == pCtx)
        return ERR_NULL_POINTER;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pTDesCtx->enabled)
        return ERR_TAP_INVALID_KEY_TYPE;

    return CRYPTO_INTERFACE_TAP_SymDeferUnload(pTDesCtx->pMocSymCtx, deferredTokenUnload); 
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_TDesCbcDeferKeyUnload (
    BulkCtx pCtx,
    byteBoolean deferredTokenUnload
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    DES3Ctx *pTDesCtx = (DES3Ctx *) pCtx;

    if (NULL == pCtx)
        return ERR_NULL_POINTER;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pTDesCtx->enabled)
        return ERR_TAP_INVALID_KEY_TYPE;

    return CRYPTO_INTERFACE_TAP_SymDeferUnload(pTDesCtx->pMocSymCtx, deferredTokenUnload); 
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_TDesEcbGetKeyInfo (
    BulkCtx pCtx,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    )
{
    ctx3des *pTDesCtx = (ctx3des *) pCtx;

    if (NULL == pTDesCtx)
        return ERR_NULL_POINTER;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pTDesCtx->enabled)
        return ERR_TAP_INVALID_KEY_TYPE;

    return CRYPTO_INTERFACE_TAP_SymGetKeyInfo(pTDesCtx->pMocSymCtx, pTokenHandle, pKeyHandle); 
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_TDesCbcGetKeyInfo (
    BulkCtx pCtx,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    )
{
    DES3Ctx *pTDesCtx = (DES3Ctx *) pCtx;

    if (NULL == pTDesCtx)
        return ERR_NULL_POINTER;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pTDesCtx->enabled)
        return ERR_TAP_INVALID_KEY_TYPE;

    return CRYPTO_INTERFACE_TAP_SymGetKeyInfo(pTDesCtx->pMocSymCtx, pTokenHandle, pKeyHandle); 
}
#endif /* __ENABLE_DIGICERT_TAP__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_Do3DES (
    MocSymCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pIv
    )
{
    return CRYPTO_INTERFACE_TAP_DES_CBC(pCtx, pData, dataLen, encrypt, pIv, TRUE);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_THREE_DES_encipher (
    MocSymCtx pCtx,
    ubyte *pSrc,
    ubyte *pDest,
    ubyte4 numBytes
    )
{
    return CRYPTO_INTERFACE_TAP_DES_ECB(pCtx, pSrc, pDest, numBytes, TRUE, TRUE);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_THREE_DES_decipher (
    MocSymCtx pCtx,
    ubyte *pSrc,
    ubyte *pDest,
    ubyte4 numBytes
    )
{
    return CRYPTO_INTERFACE_TAP_DES_ECB(pCtx, pSrc, pDest, numBytes, FALSE, TRUE);
}
