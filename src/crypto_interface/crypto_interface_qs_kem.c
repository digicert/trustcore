/*
 * crypto_interface_qs_kem.c
 *
 * Cryptographic Interface specification for Key Encapsulation Mechanism methods.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_KEM_INTERNAL__

#include "../crypto/mocasym.h"
#include "../crypto/pqc/mlkem.h"
#include "../common/initmocana.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_qs_kem.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_KEM__

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_KEM__))
#define QS_KEM_CIPHER_LEN(_status, _pCtx, _pCipherLen) \
    _status = QS_KEM_getCipherTextLen(_pCtx, _pCipherLen)
#else
#define QS_KEM_CIPHER_LEN(_status, _pCtx, _pCipherLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_KEM__))
#define QS_KEM_SS_LEN(_status, _pCtx, _pSharedSecretLen) \
    _status = QS_KEM_getSharedSecretLen(_pCtx, _pSharedSecretLen)
#else
#define QS_KEM_SS_LEN(_status, _pCtx, _pSharedSecretLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_KEM__))
#define QS_KEM_ENCAPS(_status, _pCtx, _rngFun, _pRngFunArg, _pCipherText, _cipherTextLen, _pSharedSecret, _sharedSecretLen) \
    _status = QS_KEM_encapsulate(MOC_HASH(hwAccelCtx) _pCtx, _rngFun, _pRngFunArg, _pCipherText, _cipherTextLen, _pSharedSecret, _sharedSecretLen)
#else
#define QS_KEM_ENCAPS(_status, _pCtx, _rngFun, _pRngFunArg, _pCipherText, _cipherTextLen, _pSharedSecret, _sharedSecretLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_KEM__))
#define QS_KEM_DECAPS(_status, _pCtx, _pCipherText, _cipherTextLen, _pSharedSecret, _sharedSecretLen) \
    _status = QS_KEM_decapsulate(MOC_HASH(hwAccelCtx) _pCtx, _pCipherText, _cipherTextLen, _pSharedSecret, _sharedSecretLen)
#else
#define QS_KEM_DECAPS(_status, _pCtx, _pCipherText, _cipherTextLen, _pSharedSecret, _sharedSecretLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_KEM__))

static MSTATUS QS_KEM_getCipherTextLen(QS_CTX *pCtx, ubyte4 *pCipherLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:
        {
            size_t len = 0;
            status = MLKEM_getCipherTextLen((MLKEMCtx *) pCtx->pKey, &len);
            if (OK != status)
                goto exit;
            *pCipherLen = len;
            break;
        }
        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}

/* ------------------------------------------------------------------- */

static MSTATUS QS_KEM_getSharedSecretLen(QS_CTX *pCtx, ubyte4 *pSharedSecretLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:
        {
            size_t len = 0;
            status = MLKEM_getSharedSecretLen((MLKEMCtx *) pCtx->pKey, &len);
            if (OK != status)
                goto exit;
            *pSharedSecretLen = len;
            break;
        }
        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}

/* ------------------------------------------------------------------- */

static MSTATUS QS_KEM_encapsulate(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg, ubyte *pCipherText, ubyte4 cipherTextLen, ubyte *pSharedSecret, ubyte4 sharedSecretLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            status = MLKEM_encapsulate((MLKEMCtx *) pCtx->pKey, rngFun, pRngFunArg, pCipherText, cipherTextLen, pSharedSecret, sharedSecretLen);
            if (OK != status)
                goto exit;

            break;

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}

/* ------------------------------------------------------------------- */

static MSTATUS QS_KEM_decapsulate(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, ubyte *pCipherText, ubyte4 cipherTextLen, ubyte *pSharedSecret, ubyte4 sharedSecretLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx || NULL == pCtx->pSecretKey)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            status = MLKEM_decapsulate((MLKEMCtx *) pCtx->pKey, pCipherText, cipherTextLen, pSharedSecret, sharedSecretLen);
            if (OK != status)
                goto exit;

            break;

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}
#endif /* #if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
               (defined(__ENABLE_DIGICERT_PQC_KEM__)) */

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_KEM_getCipherTextLenFromAlgo(ubyte4 algo, ubyte4 *pCipherLen)
{
    MSTATUS status = OK;
    QS_CTX *pCtx = NULL;

    /* Input validity is handled by the below calls */
    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(NULL) &pCtx, algo);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_KEM_getCipherTextLen(pCtx, pCipherLen);

exit:

    if (NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pCtx);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_KEM_getCipherTextLen(QS_CTX *pCtx, ubyte4 *pCipherLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    status = ERR_WRONG_CTX_TYPE;
    if (MOC_QS_KEM != pCtx->type)
        goto exit;

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* pPublicKey and pCipherLen will be validated by the this call */
        status = CRYPTO_getDomainParam ((MocAsymKey) pCtx->pPublicKey, MOC_ASYM_KEY_PARAM_CIPHERTEXT_LEN, pCipherLen);
    }
    else
    {
        QS_KEM_CIPHER_LEN(status, pCtx, pCipherLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_KEM_getSharedSecretLen(QS_CTX *pCtx, ubyte4 *pSharedSecretLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    status = ERR_WRONG_CTX_TYPE;
    if (MOC_QS_KEM != pCtx->type)
        goto exit;

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* pSharedSecretLen and pPublicKey will be validated by the this call */
        /* Note we use the public key since that should be set for both encapsulate and decapsulate flows */
        status = CRYPTO_getDomainParam ((MocAsymKey) pCtx->pPublicKey, MOC_ASYM_KEY_PARAM_SHAREDSECRET_LEN, pSharedSecretLen);
    }
    else
    {
        QS_KEM_SS_LEN(status, pCtx, pSharedSecretLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_KEM_encapsulate(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx,
                                                   RNGFun rngFun, void *pRngFunArg,
                                                   ubyte *pCipherText, ubyte4 cipherTextLen,
                                                   ubyte *pSharedSecret, ubyte4 sharedSecretLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    status = ERR_WRONG_CTX_TYPE;
    if (MOC_QS_KEM != pCtx->type)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* Encapsulate */
        status = CRYPTO_keyEncapsulate((MocAsymKey) pCtx->pPublicKey, rngFun, pRngFunArg, pCipherText, cipherTextLen, pSharedSecret, sharedSecretLen);
    }
    else
    {
        QS_KEM_ENCAPS(status, pCtx, rngFun, pRngFunArg, pCipherText, cipherTextLen, pSharedSecret, sharedSecretLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_KEM_encapsulateAlloc(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg, ubyte **ppCipherText, ubyte4* pCipherTextLen,
                                                        ubyte **ppSharedSecret, ubyte4 *pSharedSecretLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pCipher = NULL;
    ubyte4 cipherLen = 0;
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;

    if (NULL == pCtx || NULL == ppCipherText || NULL == pCipherTextLen || NULL == ppSharedSecret || NULL == pSharedSecretLen)
        goto exit;

    status = CRYPTO_INTERFACE_QS_KEM_getCipherTextLen(pCtx, &cipherLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_KEM_getSharedSecretLen(pCtx, &ssLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pCipher, cipherLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pSS, ssLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_KEM_encapsulate(MOC_HASH(hwAccelCtx) pCtx, rngFun, pRngFunArg, pCipher, cipherLen, pSS, ssLen);
    if (OK != status)
        goto exit;

    *ppCipherText = pCipher; pCipher = NULL;
    *pCipherTextLen = cipherLen;

    *ppSharedSecret = pSS; pSS = NULL;
    *pSharedSecretLen = ssLen;

exit:

    if (NULL != pCipher)
    {
        DIGI_MEMSET_FREE(&pCipher, cipherLen);
    }

    if (NULL != pSS)
    {
        DIGI_MEMSET_FREE(&pSS, ssLen);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_KEM_decapsulate(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, ubyte *pCipherText, ubyte4 cipherTextLen, ubyte *pSharedSecret, ubyte4 sharedSecretLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    status = ERR_WRONG_CTX_TYPE;
    if (MOC_QS_KEM != pCtx->type)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* Encapsulate */
        status = CRYPTO_keyDecapsulate((MocAsymKey) pCtx->pSecretKey, pCipherText, cipherTextLen, pSharedSecret, sharedSecretLen);
    }
    else
    {
        QS_KEM_DECAPS(status, pCtx, pCipherText, cipherTextLen, pSharedSecret, sharedSecretLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_KEM_decapsulateAlloc(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, ubyte *pCipherText, ubyte4 cipherTextLen, ubyte **ppSharedSecret, ubyte4 *pSharedSecretLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;

    if (NULL == pCtx)
        goto exit;

    status = CRYPTO_INTERFACE_QS_KEM_getSharedSecretLen(pCtx, &ssLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pSS, ssLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_KEM_decapsulate(MOC_HASH(hwAccelCtx) pCtx, pCipherText, cipherTextLen, pSS, ssLen);
    if (OK != status)
        goto exit;

    *ppSharedSecret = pSS; pSS = NULL;
    *pSharedSecretLen = ssLen;

exit:

    if (NULL != pSS)
    {
        DIGI_MEMSET_FREE(&pSS, ssLen);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_KEM__ */
