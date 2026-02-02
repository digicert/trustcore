/*
 * crypto_interface_aes_xcbc_mac_96.c
 *
 * Cryptographic Interface specification for AES-XCBC core modes.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_XCBC_INTERNAL__

#include "../crypto/mocsym.h"
#include "../crypto/aes.h"
#include "../crypto/aes_xcbc_mac_96.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_XCBC__))

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES_XCBC_MAC_96__))
#define MOC_AES_XCBC_MAC_96_INIT(_status, _pKey, _pCtx)                      \
    _status = AES_XCBC_MAC_96_init(MOC_SYM(hwAccelCtx) _pKey, _pCtx)
#else
#define MOC_AES_XCBC_MAC_96_INIT(_status, _pKey, _pCtx)                      \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES_XCBC_MAC_96__))
#define MOC_AES_XCBC_MAC_96_UPDATE(_status, _pData, _dataLen, _pCtx)         \
    _status = AES_XCBC_MAC_96_update(MOC_SYM(hwAccelCtx) _pData, _dataLen, _pCtx)
#else
#define MOC_AES_XCBC_MAC_96_UPDATE(_status, _pData, _dataLen, _pCtx)         \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES_XCBC_MAC_96__))
#define MOC_AES_XCBC_MAC_96_FINAL(_status, _pCmac, _pCtx)                    \
    _status = AES_XCBC_MAC_96_final(MOC_SYM(hwAccelCtx) _pCmac, _pCtx)
#else
#define MOC_AES_XCBC_MAC_96_FINAL(_status, _pCmac, _pCtx)                    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES_XCBC_MAC_96__))
#define MOC_AES_XCBC_MAC_96_RESET(_status, _pCtx)                            \
    _status = AES_XCBC_MAC_96_reset(MOC_SYM(hwAccelCtx) _pCtx)
#else
#define MOC_AES_XCBC_MAC_96_RESET(_status, _pCtx)                            \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES_XCBC_MAC_96__))
#define MOC_AES_XCBC_PRF_128_INIT(_status, _pKey, _keyLen, _pCtx)            \
    _status = AES_XCBC_PRF_128_init(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _pCtx)
#else
#define MOC_AES_XCBC_PRF_128_INIT(_status, _pKey, _keyLen, _pCtx)            \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES_XCBC_MAC_96__))
#define MOC_AES_XCBC_PRF_128_FINAL(_status, _pCmac, _pCtx)                   \
    _status = AES_XCBC_PRF_128_final(MOC_SYM(hwAccelCtx) _pCmac, _pCtx)
#else
#define MOC_AES_XCBC_PRF_128_FINAL(_status, _pCmac, _pCtx)                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES_XCBC_MAC_96__))
#define MOC_AES_XCBC_CLEAR(_status, _pCtx)                                   \
    _status = AES_XCBC_clear(MOC_SYM(hwAccelCtx) _pCtx)
#else
#define MOC_AES_XCBC_CLEAR(_status, _pCtx)                                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_MAC_96_init(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    const ubyte pKeyMaterial[16],
    AES_XCBC_MAC_96_Ctx *pCtx
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_xcbc, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_XCBC_MAC_96_INIT(status, pKeyMaterial, pCtx);
    }

exit:

    return status;
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_MAC_96_update(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    const ubyte *pData,
    sbyte4 dataLength,
    AES_XCBC_MAC_96_Ctx *pCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_XCBC_MAC_96_UPDATE(status, pData, dataLength, pCtx);
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_MAC_96_final(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte pCmac[12],
    AES_XCBC_MAC_96_Ctx *pCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_XCBC_MAC_96_FINAL(status, pCmac, pCtx);
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_MAC_96_reset(
   MOC_SYM(hwAccelDescr hwAccelCtx)
   AES_XCBC_MAC_96_Ctx *pCtx
   )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_XCBC_MAC_96_RESET(status, pCtx);
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_PRF_128_init(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    const ubyte pKeyMaterial[/*keyLength*/],
    sbyte4 keyLength,
    AES_XCBC_PRF_128_Ctx *pCtx
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_xcbc, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_XCBC_PRF_128_INIT(status, pKeyMaterial, keyLength, pCtx);
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_PRF_128_final(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte pCmac[16],
    AES_XCBC_PRF_128_Ctx *pCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_XCBC_PRF_128_FINAL(status, pCmac, pCtx);
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_clear (
    MOC_SYM(hwAccelDescr hwAccelCtx)
    AES_XCBC_MAC_96_Ctx *pCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_XCBC_CLEAR(status, pCtx);
    }

exit:

    return status;
}
#endif /* defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_XCBC__) */
