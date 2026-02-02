/*
 * crypto_interface_hmac_kdf.c
 *
 * Cryptographic Interface specification for HMAC-KDF.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC_KDF_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/hmac_kdf.h"
#include "../crypto_interface/crypto_interface_hmac_kdf.h"
#include "../crypto_interface/crypto_interface_hmac_common.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC_KDF__

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_HMAC__))
#define MOC_HMAC_KDF_EXTRACT(_status, _pDigest, _pSalt, _saltLen, _pInKey, _inKeyLen, _pOut, _outLen, _pExtCtx) \
_status = HmacKdfExtractExt(MOC_HASH(hwAccelCtx) _pDigest, _pSalt, _saltLen, _pInKey, _inKeyLen, _pOut, _outLen, _pExtCtx)
#else
#define MOC_HMAC_KDF_EXTRACT(_status, _pDigest, _pSalt, _saltLen, _pInKey, _inKeyLen, _pOut, _outLen, _pExtCtx) \
_status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_HMAC__))
#define MOC_HMAC_KDF_EXPAND(_status, _pDigest, _pRandKey, _randKeyLen, _pCtx, _ctxLen, _pIv, _ivLen, _pOut, _keyLen, _pExtCtx) \
_status = HmacKdfExpandExt(MOC_HASH(hwAccelCtx) _pDigest, _pRandKey, _randKeyLen, _pCtx, _ctxLen,  _pIv, _ivLen, _pOut, _keyLen, _pExtCtx)
#else
#define MOC_HMAC_KDF_EXPAND(_status, _pDigest, _pRandKey, _randKeyLen, _pCtx, _ctxLen,  _pIv, _ivLen, _pOut, _keyLen, _pExtCtx) \
_status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_HmacKdfCommon(
    const BulkHashAlgo *pDigest,
    ubyte4 index,
    MHmacKdfOperatorData *pOpData,
    ubyte *pOutput,
    ubyte4 outputLen
    )
{
    MSTATUS status, fstatus;
    MocSymCtx pNewSymCtx = NULL;
    MocCtx pMocCtx = NULL;
    MSymOperator pOperator = NULL;
    ubyte hashAlgo;
    ubyte4 derivedOutLen;
    
    status = CRYPTO_INTERFACE_HmacGetHashAlgoFlag (pDigest, &hashAlgo);
    if (OK != status)
        goto exit;
    
    /* Get a reference to the MocCtx within the Crypto Interface Core */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
        goto exit;
    
    /* get the operator */
    status = CRYPTO_getSymOperatorAndInfoFromIndex(index, pMocCtx, &pOperator, NULL);
    if (OK != status)
        goto exit;
    
    /* create a new sym ctx */
    status = CRYPTO_createMocSymCtx (pOperator, (void *) &hashAlgo, pMocCtx, &pNewSymCtx);
    if (OK != status)
        goto exit;
    
    status = CRYPTO_deriveKey (pNewSymCtx, (void *) pOpData, pOutput, outputLen, &derivedOutLen);

exit:
    
    if (NULL != pNewSymCtx)
    {
        fstatus = CRYPTO_freeMocSymCtx (&pNewSymCtx);
        if (OK == status)
            status = fstatus;
    }
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacKdfExtract(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest,
    ubyte *pSalt,
    ubyte4 saltLen,
    ubyte *pInputKeyMaterial,
    ubyte4 inputKeyMaterialLen,
    ubyte *pOutput,
    ubyte4 outputLen
    )
{
    return CRYPTO_INTERFACE_HmacKdfExtractExt(MOC_HASH(hwAccelCtx) pDigest, pSalt, saltLen, pInputKeyMaterial,
                                              inputKeyMaterialLen, pOutput, outputLen, NULL);
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacKdfExtractExt(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest,
    ubyte *pSalt,
    ubyte4 saltLen, 
    ubyte *pInputKeyMaterial,
    ubyte4 inputKeyMaterialLen,
    ubyte *pOutput,
    ubyte4 outputLen,
    void *pExtCtx
    )
{
    MSTATUS status;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_hmac_kdf, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        MHmacKdfOperatorData hmacData = {0};

        hmacData.flag = MOC_SYM_HMAC_KDF_EXTRACT;
        hmacData.pSalt = pSalt;
        hmacData.saltLen = saltLen;
        hmacData.pInputKeyMaterial = pInputKeyMaterial;
        hmacData.inputKeyMaterialLen = inputKeyMaterialLen;
        
        status = CRYPTO_INTERFACE_HmacKdfCommon(pDigest, index, &hmacData, pOutput, outputLen);
    }
    else
    {
        MOC_HMAC_KDF_EXTRACT(status, pDigest, pSalt, saltLen, pInputKeyMaterial, inputKeyMaterialLen, pOutput, outputLen, pExtCtx);
    }
    
exit:
        
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacKdfExpand(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest,
    ubyte *pPseudoRandomKey,
    ubyte4 pseudoRandomKeyLen,
    ubyte *pContext,
    ubyte4 contextLen,
    ubyte *pIv,
    ubyte4 ivLen,
    ubyte *pOutput,
    ubyte4 keyLength
    )
{
    return CRYPTO_INTERFACE_HmacKdfExpandExt(MOC_HASH(hwAccelCtx)
        pDigest, pPseudoRandomKey, pseudoRandomKeyLen, pContext, contextLen,
        pIv, ivLen, pOutput, keyLength, NULL);
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacKdfExpandExt(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest,
    ubyte *pPseudoRandomKey,
    ubyte4 pseudoRandomKeyLen,
    ubyte *pContext,
    ubyte4 contextLen,
    ubyte *pIv,
    ubyte4 ivLen,
    ubyte *pOutput,
    ubyte4 keyLength,
    void *pExtCtx
    )
{
    MSTATUS status;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_hmac_kdf, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        MHmacKdfOperatorData hmacData = {0};

        hmacData.flag = MOC_SYM_HMAC_KDF_EXPAND;
        hmacData.pPseudoRandomKey = pPseudoRandomKey;
        hmacData.pseudoRandomKeyLen = pseudoRandomKeyLen;
        hmacData.pContext = pContext;
        hmacData.contextLen = contextLen;
        hmacData.pIv = pIv;
        hmacData.ivLen = ivLen;

        status = CRYPTO_INTERFACE_HmacKdfCommon(pDigest, index, &hmacData, pOutput, keyLength);
    }
    else
    {
        MOC_HMAC_KDF_EXPAND(status, pDigest, pPseudoRandomKey, pseudoRandomKeyLen, pContext, contextLen, pIv, ivLen, pOutput, keyLength, pExtCtx);
    }
    
exit:
    
    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC_KDF__ */
