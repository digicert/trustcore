/*
 * crypto_interface_aes_eax.c
 *
 * Cryptographic Interface specification for AES-EAX mode.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_EAX_INTERNAL__

#include "../crypto/mocsym.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/aes_cmac.h"
#include "../crypto/aes_eax.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_aes_eax.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_EAX__

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_EAX_INIT(_status, _keyMaterial, _keyLength, _nonce, _nonceLen, _pCtx) \
    _status = AES_EAX_init(MOC_SYM(hwAccelCtx) _keyMaterial, _keyLength, _nonce, _nonceLen, _pCtx)
#else
#define MOC_AES_EAX_INIT(_status, _keyMaterial, _keyLength, _nonce, _nonceLen, _pCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_EAX_UPDATE_HEADER(_status, _headerData, _dataLength, _pCtx);  \
    _status = AES_EAX_updateHeader(MOC_SYM(hwAccelCtx) _headerData, _dataLength, _pCtx)
#else
#define MOC_AES_EAX_UPDATE_HEADER(_status, _headerData, _dataLength, _pCtx);  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_EAX_ENC_MSG(_status, _msgData, _msgLen, _pCtx)                \
    _status = AES_EAX_encryptMessage(MOC_SYM(hwAccelCtx) _msgData, _msgLen, _pCtx)
#else
#define MOC_AES_EAX_ENC_MSG(_status, _msgData, _msgLen, _pCtx)                \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_EAX_DEC_MSG(_status, _msgData, _msgLen, _pCtx)                \
    _status = AES_EAX_decryptMessage(MOC_SYM(hwAccelCtx) _msgData, _msgLen, _pCtx)
#else
#define MOC_AES_EAX_DEC_MSG(_status, _msgData, _msgLen, _pCtx)                \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_EAX_FINAL(_status, _tag, _tagLen, _pCtx)                      \
    _status = AES_EAX_final(MOC_SYM(hwAccelCtx) _tag, _tagLen, _pCtx)
#else
#define MOC_AES_EAX_FINAL(_status, _tag, _tagLen, _pCtx)                      \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_EAX_GEN_TAG(_status, _cipherText, _cipherLen, _header, _headerLen, _tag, _tagLen, _pCtx) \
    _status = AES_EAX_generateTag(MOC_SYM(hwAccelCtx) _cipherText, _cipherLen, _header, _headerLen, _tag, _tagLen, _pCtx)
#else
#define MOC_AES_EAX_GEN_TAG(_status, _cipherText, _cipherLen, _header, _headerLen, _tag, _tagLen, _pCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_EAX_GET_PLAIN(_status, _cipherText, _cipherLen, _pCtx)        \
    _status = AES_EAX_getPlainText(MOC_SYM(hwAccelCtx) _cipherText, _cipherLen, _pCtx)
#else
#define MOC_AES_EAX_GET_PLAIN(_status, _cipherText, _cipherLen, _pCtx)        \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_EAX_CLEAR(_status, _pCtx)                                     \
    _status = AES_EAX_clear(MOC_SYM(hwAccelCtx) _pCtx)
#else
#define MOC_AES_EAX_CLEAR(_status, _pCtx)                                     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_EAX_init(
    MOC_SYM(hwAccelDescr hwAccelCtx) 
    const ubyte* keyMaterial,
    ubyte4 keyLength, 
    const ubyte* nonce, 
    ubyte4 nonceLength, 
    AES_EAX_Ctx* pCtx)
{
    MSTATUS status = OK;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_eax, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_EAX_INIT(status, keyMaterial, keyLength, nonce, nonceLength, pCtx);
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_EAX_updateHeader(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    const ubyte* headerData,
    sbyte4 dataLength,
    AES_EAX_Ctx* pCtx)
{
    MSTATUS status = OK;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_eax, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_EAX_UPDATE_HEADER(status, headerData, dataLength, pCtx);
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_EAX_encryptMessage(
    MOC_SYM(hwAccelDescr hwAccelCtx) 
    ubyte* msgData,
    sbyte4 msgLen,
    AES_EAX_Ctx* pCtx)
{
    MSTATUS status = OK;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_eax, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_EAX_ENC_MSG(status, msgData, msgLen, pCtx);
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_EAX_decryptMessage(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte* msgData,
    sbyte4 msgLen,
    AES_EAX_Ctx* pCtx)
{
    MSTATUS status = OK;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_eax, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_EAX_DEC_MSG(status, msgData, msgLen, pCtx);
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_EAX_final(
    MOC_SYM(hwAccelDescr hwAccelCtx) 
    ubyte tag[/*tagLen*/],
    sbyte4 tagLen,
    AES_EAX_Ctx* pCtx)
{
    MSTATUS status = OK;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_eax, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_EAX_FINAL(status, tag, tagLen, pCtx);
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_EAX_generateTag(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    const ubyte* cipherText, 
    sbyte4 cipherLen,
    const ubyte* header,
    sbyte4 headerLen,
    ubyte tag[/*tagLen*/],
    sbyte4 tagLen,
    AES_EAX_Ctx* pCtx)
{
    MSTATUS status = OK;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_eax, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_EAX_GEN_TAG(status, cipherText, cipherLen, header, headerLen, tag, tagLen, pCtx);
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_EAX_getPlainText(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte* cipherText,
    sbyte4 cipherLen,
    AES_EAX_Ctx* pCtx)
{
    MSTATUS status = OK;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_eax, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_EAX_GET_PLAIN(status, cipherText, cipherLen, pCtx);
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_EAX_clear(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    AES_EAX_Ctx* pCtx)
{
    MSTATUS status = OK;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_eax, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_EAX_CLEAR(status, pCtx);
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_EAX__ */
