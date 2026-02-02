/*
 * crypto_interface_aes_keywrap.c
 *
 * Cryptographic Interface specification for AES-KEYWRAP.
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
