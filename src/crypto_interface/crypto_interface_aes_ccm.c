/*
 * crypto_interface_aes_ccm.c
 *
 * Cryptographic Interface specification for AES-CCM mode.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CCM_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ccm.h"
#include "../crypto_interface/crypto_interface_aes_ccm.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CCM__

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CCM__))
#define MOC_AES_CCM_CREATE_CTX(_pCtx, _pKey, _keyLen, _encrypt)    \
    _pCtx = AESCCM_createCtx(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _encrypt);            \
    if (NULL != _pCtx)                                             \
    {                                                              \
        _pCtx->pMocSymCtx = NULL;                                  \
        _pCtx->enabled = CRYPTO_INTERFACE_ALGO_DISABLED;           \
    }
#else
#define MOC_AES_CCM_CREATE_CTX(_pCtx, _pKey, _keyLen, _encrypt)    \
    _pCtx = NULL
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) &&  \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CCM__))
#define MOC_AES_CCM_DELETE_CTX(_status, _pCtx)                \
    _status = AESCCM_deleteCtx(MOC_SYM(hwAccelCtx) _pCtx)
#else
#define MOC_AES_CCM_DELETE_CTX(_status, _pCtx)       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CCM__))
#define MOC_AES_CCM_CIPHER(_status, _pCtx, _pNonce, _nLen, _pAuthData, _authDataLength, _pData, _dataLength, _verifyLen, _encrypt)  \
    _status = AESCCM_cipher(MOC_SYM(hwAccelCtx) _pCtx, _pNonce, _nLen, _pAuthData, _authDataLength, _pData, _dataLength, _verifyLen, _encrypt)
#else
#define MOC_AES_CCM_CIPHER(_status, _pCtx, _pNonce, _nLen, _pAuthData, _authDataLength, _pData, _dataLength, _verifyLen, _encrypt)  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CCM__))
#define MOC_AES_AESCCMEncrypt(_status, _M, _L, _pKeyMaterial, _keyLength, _pNonce, _pEncData, _encDataLength, _pAuthData, _authDataLength, _U)      \
    _status = AESCCM_encrypt(MOC_SYM(hwAccelCtx) _M, _L, _pKeyMaterial, _keyLength, _pNonce, _pEncData, _encDataLength, _pAuthData, _authDataLength, _U)
#else
#define MOC_AES_AESCCMEncrypt(_status, _M, _L, _pKeyMaterial, _keyLength, _pNonce, _pEncData, _encDataLength, _pAuthData, _authDataLength, _U)      \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CCM__))
#define MOC_AES_AESCCMDecrypt(_status, _M, _L, _pKeyMaterial, _keyLength, _pNonce, _pEncData, _encDataLength, _pAuthData, _authDataLength, _U)      \
    _status = AESCCM_decrypt(MOC_SYM(hwAccelCtx) _M, _L, _pKeyMaterial, _keyLength, _pNonce, _pEncData, _encDataLength, _pAuthData, _authDataLength, _U)
#else
#define MOC_AES_AESCCMDecrypt(_status, _M, _L, _pKeyMaterial, _keyLength, _pNonce, _pEncData, _encDataLength, _pAuthData, _authDataLength, _U)      \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CCM__))
#define MOC_AES_AESCCMClone(_status, _pSrc, _ppDest)         \
    _status = AESCCM_clone(MOC_SYM(hwAccelCtx) _pSrc, _ppDest)
#else
#define MOC_AES_AESCCMClone(_status, _pSrc, _ppDest)         \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

extern BulkCtx CRYPTO_INTERFACE_AES_CCM_createCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
    sbyte4 keyLength,
    sbyte4 encrypt
    )
{
    MSTATUS status;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    aesCipherContext *pCtx = NULL;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_ccm, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_CCM_CREATE_CTX(pCtx, pKeyMaterial, keyLength, encrypt);
    }

exit:

    return pCtx;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_AES_CCM_deleteCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ppCtx)
{
    MSTATUS status = ERR_NULL_POINTER;

    MOC_AES_CCM_DELETE_CTX(status, ppCtx);
    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS  CRYPTO_INTERFACE_AES_CCM_encrypt(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte M, ubyte L, ubyte* pKeyMaterial,
    sbyte4 keyLength, const ubyte* pNonce, ubyte* pEncData, ubyte4 encDataLength,
    const ubyte* pAuthData, ubyte4 authDataLength, ubyte U[/*M*/])
{
    MSTATUS status = ERR_NULL_POINTER;

    MOC_AES_AESCCMEncrypt(status, M, L, pKeyMaterial, keyLength, pNonce, pEncData, encDataLength, pAuthData, authDataLength, U);
    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS  CRYPTO_INTERFACE_AES_CCM_decrypt(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte M, ubyte L, ubyte* pKeyMaterial,
    sbyte4 keyLength, const ubyte* pNonce, ubyte* pEncData, ubyte4 encDataLength,
    const ubyte* pAuthData, ubyte4 authDataLength, const ubyte U[/*M*/])
{
    MSTATUS status = ERR_NULL_POINTER;

    MOC_AES_AESCCMDecrypt(status, M, L, pKeyMaterial, keyLength, pNonce, pEncData, encDataLength, pAuthData, authDataLength, U);
    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_AES_CCM_cipher(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte* pNonce, ubyte4 nLen,
    ubyte* pAuthData, ubyte4 authDataLength, ubyte* pData, ubyte4 dataLength,
    ubyte4 verifyLen, sbyte4 encrypt)
{
    MSTATUS status = ERR_NULL_POINTER;
    MOC_AES_CCM_CIPHER(status, pCtx, pNonce, nLen, pAuthData, authDataLength, pData, dataLength, verifyLen, encrypt);
    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_AES_CCM_clone(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    MOC_AES_AESCCMClone(status, pCtx, ppNewCtx);
    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CCM__ */
