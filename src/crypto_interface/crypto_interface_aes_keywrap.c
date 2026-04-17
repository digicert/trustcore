/*
 * crypto_interface_aes_keywrap.c
 *
 * Cryptographic Interface specification for AES-KEYWRAP.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_KEYWRAP_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/aes.h"
#include "../crypto/aes_keywrap.h"
#include "../crypto_interface/crypto_interface_aes_keywrap.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_KEYWRAP__

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_KEYWRAP_ENC3394(_status, _pKey, keyLen, _pData, _dataLen, _pOut, _bufSize, _outLen, _transform) \
    _status = AESKWRAP_encrypt3394Ex(MOC_SYM(hwAccelCtx) _pKey, keyLen, _pData, _dataLen, _pOut, _bufSize, _outLen, _transform)
#else
#define MOC_AES_KEYWRAP_ENC3394(_status, _pKey, keyLen, _pData, _dataLen, _pOut, _bufSize, _outLen, _transform) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_KEYWRAP_DEC3394(_status, _pKey, keyLen, _pData, _dataLen, _pOut, _bufSize, _outLen, _transform) \
    _status = AESKWRAP_decrypt3394Ex(MOC_SYM(hwAccelCtx) _pKey, keyLen, _pData, _dataLen, _pOut, _bufSize, _outLen, _transform)
#else
#define MOC_AES_KEYWRAP_DEC3394(_status, _pKey, keyLen, _pData, _dataLen, _pOut, _bufSize, _outLen, _transform) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_KEYWRAP_ENC5649(_status, _pKey, keyLen, _pData, _dataLen, _pOut, _bufSize, _outLen, _transform) \
    _status = AESKWRAP_encrypt5649Ex(MOC_SYM(hwAccelCtx) _pKey, keyLen, _pData, _dataLen, _pOut, _bufSize, _outLen, _transform)
#else
#define MOC_AES_KEYWRAP_ENC5649(_status, _pKey, keyLen, _pData, _dataLen, _pOut, _bufSize, _outLen, _transform) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_KEYWRAP_DEC5649(_status, _pKey, keyLen, _pData, _dataLen, _pOut, _bufSize, _outLen, _transform) \
    _status = AESKWRAP_decrypt5649Ex(MOC_SYM(hwAccelCtx) _pKey, keyLen, _pData, _dataLen, _pOut, _bufSize, _outLen, _transform)
#else
#define MOC_AES_KEYWRAP_DEC5649(_status, _pKey, keyLen, _pData, _dataLen, _pOut, _bufSize, _outLen, _transform) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESKWRAP_encrypt3394Ex (
    MOC_SYM (hwAccelDescr hwAccelCtx)
    ubyte *pKeyMaterial,
    sbyte4 keyLength,
    ubyte *pDataToEncrypt,
    ubyte4 dataToEncryptLen,
    ubyte *pEncryptedData,
    ubyte4 bufferSize,
    ubyte4 *pEncryptedDataLen,
    ubyte transform
    )
{
    MSTATUS status;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_kw, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_KEYWRAP_ENC3394(status, pKeyMaterial, keyLength, pDataToEncrypt, dataToEncryptLen, pEncryptedData, bufferSize, pEncryptedDataLen, transform);
    }

exit:

    return status;   
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESKWRAP_decrypt3394Ex (
    MOC_SYM (hwAccelDescr hwAccelCtx)
    ubyte *pKeyMaterial,
    sbyte4 keyLength,
    ubyte *pEncryptedData,
    ubyte4 encryptedDataLen,
    ubyte *pDecryptedData,
    ubyte4 bufferSize,
    ubyte4 *pDecryptedDataLen,
    ubyte transform
    )
{
    MSTATUS status;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_kw, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_KEYWRAP_DEC3394(status, pKeyMaterial, keyLength, pEncryptedData, encryptedDataLen, pDecryptedData, bufferSize, pDecryptedDataLen, transform);
    }

exit:

    return status; 
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESKWRAP_encrypt5649Ex (
    MOC_SYM (hwAccelDescr hwAccelCtx)
    ubyte *pKeyMaterial,
    sbyte4 keyLength,
    ubyte *pDataToEncrypt,
    ubyte4 dataToEncryptLen,
    ubyte *pEncryptedData,
    ubyte4 bufferSize,
    ubyte4 *pEncryptedDataLen,
    ubyte transform
    )
{
    MSTATUS status;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_kw, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_KEYWRAP_ENC5649(status, pKeyMaterial, keyLength, pDataToEncrypt, dataToEncryptLen, pEncryptedData, bufferSize, pEncryptedDataLen, transform);
    }

exit:

    return status; 
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESKWRAP_decrypt5649Ex (
    MOC_SYM (hwAccelDescr hwAccelCtx)
    ubyte *pKeyMaterial,
    sbyte4 keyLength,
    ubyte *pEncryptedData,
    ubyte4 encryptedDataLen,
    ubyte *pDecryptedData,
    ubyte4 bufferSize,
    ubyte4 *pDecryptedDataLen,
    ubyte transform
    )
{
    MSTATUS status;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_kw, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_KEYWRAP_DEC5649(status, pKeyMaterial, keyLength, pEncryptedData, encryptedDataLen, pDecryptedData, bufferSize, pDecryptedDataLen, transform);
    }

exit:

    return status; 
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_KEYWRAP__ */
