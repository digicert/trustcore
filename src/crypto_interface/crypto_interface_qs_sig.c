/*
 * crypto_interface_qs_sig.c
 *
 * Cryptographic Interface specification for Signature Authentication methods.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_SIG_INTERNAL__

#include "../crypto/mocasym.h"
#include "../crypto/pqc/mldsa.h"
#include "../crypto/pqc/slhdsa.h"
#include "../common/initmocana.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_qs_sig.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_SIG__

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_SIG__))
#define QS_SIG_LEN(_status, _pCtx, _pSigLen) \
    _status = QS_SIG_getSignatureLen(_pCtx, _pSigLen)
#else
#define QS_SIG_LEN(_status, _pCtx, _pSigLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_SIG__))
#define QS_SIG_PREHASH_AND_CONTEXT(_status, _pCtx, _preHashMode, _pContext, _contextLen) \
    _status = QS_SIG_setPrehashAndContext(_pCtx, _preHashMode, _pContext, _contextLen)
#else
#define QS_SIG_PREHASH_AND_CONTEXT(_status, _pCtx, _preHashMode, _pContext, _contextLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_SIG__))
#define QS_SIG_SIGN(_status, _pCtx, _rngFun, _pRngFunArg, _pData, _dataLen, _pSignature, _sigBufferLen, _pActualSigLen) \
    _status = QS_SIG_sign(MOC_HASH(hwAccelCtx) _pCtx, _rngFun, _pRngFunArg, _pData, _dataLen, _pSignature, _sigBufferLen, _pActualSigLen)
#else
#define QS_SIG_SIGN(_status, _pCtx, _rngFun, _pRngFunArg, _pData, _dataLen, _pSignature, _sigBufferLen, _pActualSigLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_SIG__))
#define QS_SIG_SIGN_DIGEST(_status, _pCtx, _rngFun, _pRngFunArg, _digestId, _pData, _dataLen, _pSignature, _sigBufferLen, _pActualSigLen) \
    _status = QS_SIG_signDigest(MOC_HASH(hwAccelCtx) _pCtx, _rngFun, _pRngFunArg, _digestId, _pData, _dataLen, _pSignature, _sigBufferLen, _pActualSigLen)
#else
#define QS_SIG_SIGN_DIGEST(_status, _pCtx, _rngFun, _pRngFunArg, _digestId, _pData, _dataLen, _pSignature, _sigBufferLen, _pActualSigLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_SIG__))
#define QS_SIG_VERIFY(_status, _pCtx, _pData, _dataLen, _pSignature, _signatureLen, _pVerifyStatus) \
    _status = QS_SIG_verify(MOC_HASH(hwAccelCtx) _pCtx, _pData, _dataLen, _pSignature, _signatureLen, _pVerifyStatus)
#else
#define QS_SIG_VERIFY(_status, _pCtx, _pData, _dataLen, _pSignature, _signatureLen, _pVerifyStatus) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_SIG__))
#define QS_SIG_VERIFY_DIGEST(_status, _pCtx, _digestId, _pData, _dataLen, _pSignature, _signatureLen, _pVerifyStatus) \
    _status = QS_SIG_verifyDigest(MOC_HASH(hwAccelCtx) _pCtx, _digestId, _pData, _dataLen, _pSignature, _signatureLen, _pVerifyStatus)
#else
#define QS_SIG_VERIFY_DIGEST(_status, _pCtx, _digestId, _pData, _dataLen, _pSignature, _signatureLen, _pVerifyStatus) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif
#endif

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_SIG__))
#define QS_SIG_STREAM_INIT(_status, _pCtx, _isExtMu, _digestId, _pCtxStr, _ctxStrLen) \
    _status = QS_SIG_streamingInit(_pCtx, _isExtMu, _digestId, _pCtxStr, _ctxStrLen)
#else
#define QS_SIG_STREAM_INIT(_status, _pCtx, _isExtMu, _digestId, _pCtxStr, _ctxStrLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_SIG__))
#define QS_SIG_STREAM_UPDATE(_status, _pCtx, _pData, _dataLen) \
    _status = QS_SIG_streamingUpdate(_pCtx, _pData, _dataLen)
#else
#define QS_SIG_STREAM_UPDATE(_status, _pCtx, _pData, _dataLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_SIG__))
#define QS_SIG_STREAM_SIGN(_status, _pCtx, _rngFun, _rngArg, _pSig, _sigLen, _pActSigLen) \
    _status = QS_SIG_streamingSignFinal(_pCtx, _rngFun, _rngArg, _pSig, _sigLen, _pActSigLen)
#else
#define QS_SIG_STREAM_SIGN(_status, _pCtx, _rngFun, _rngArg, _pSig, _sigLen, _pActSigLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_SIG__))
#define QS_SIG_STREAM_VERIFY(_status, _pCtx, _pSig, _sigLen, _pVStat) \
    _status = QS_SIG_streamingVerifyFinal(_pCtx, _pSig, _sigLen, _pVStat)
#else
#define QS_SIG_STREAM_VERIFY(_status, _pCtx, _pSig, _sigLen, _pVStat) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

#endif /* __ENABLE_DIGICERT_PQC_SIG_STREAMING__ */

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC_SIG__))

static MSTATUS QS_SIG_convertDigestType(ubyte digestId, MLDSADigestType *pDigestType)
{
    /* internal method, NULL checks not necc */
    switch(digestId)
    {
        case ht_sha256:
            *pDigestType = MLDSA_DIGEST_TYPE_SHA256;
            break;
        case ht_sha512:
            *pDigestType = MLDSA_DIGEST_TYPE_SHA512;
            break;
        case ht_shake128:
            *pDigestType = MLDSA_DIGEST_TYPE_SHAKE128;
            break;
        case ht_shake256: /* TODO once we know SLHDSADigestTypes */
        default:
            return ERR_INVALID_INPUT;
    }

    return OK;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_SIG_getSignatureLen(QS_CTX *pCtx, ubyte4 *pSigLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    size_t len = 0;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_getSignatureLen((MLDSACtx *) pCtx->pKey, &len);
            if (OK != status)
                goto exit;
            *pSigLen = len;

            break;

        case cid_PQC_SLHDSA_SHA2_128S:
        case cid_PQC_SLHDSA_SHA2_128F:
        case cid_PQC_SLHDSA_SHAKE_128S:
        case cid_PQC_SLHDSA_SHAKE_128F:
        case cid_PQC_SLHDSA_SHA2_192S:
        case cid_PQC_SLHDSA_SHA2_192F:
        case cid_PQC_SLHDSA_SHAKE_192S:
        case cid_PQC_SLHDSA_SHAKE_192F:
        case cid_PQC_SLHDSA_SHA2_256S:
        case cid_PQC_SLHDSA_SHA2_256F:
        case cid_PQC_SLHDSA_SHAKE_256S:
        case cid_PQC_SLHDSA_SHAKE_256F:

            status = SLHDSA_getSignatureLen((SLHDSACtx *) pCtx->pKey, &len);
            if (OK != status)
                goto exit;
            *pSigLen = len;

            break;

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_SIG_sign(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg, ubyte *pData, ubyte4 dataLen,
                           ubyte *pSignature, ubyte4 sigBufferLen, ubyte4 *pActualSigLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    size_t len = 0;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:
        {
            status = MLDSA_getSignatureLen((MLDSACtx *) pCtx->pKey, &len);
            if (OK != status)
                goto exit;

            if (sigBufferLen > len) {
                sigBufferLen = len;
            }
            status = MLDSA_signMessage((MLDSACtx *) pCtx->pKey, pData, dataLen, rngFun, pRngFunArg, pSignature, sigBufferLen);
            if (OK != status)
                goto exit;

            *pActualSigLen = len;

            break;
        }
        case cid_PQC_SLHDSA_SHA2_128S:
        case cid_PQC_SLHDSA_SHA2_128F:
        case cid_PQC_SLHDSA_SHAKE_128S:
        case cid_PQC_SLHDSA_SHAKE_128F:
        case cid_PQC_SLHDSA_SHA2_192S:
        case cid_PQC_SLHDSA_SHA2_192F:
        case cid_PQC_SLHDSA_SHAKE_192S:
        case cid_PQC_SLHDSA_SHAKE_192F:
        case cid_PQC_SLHDSA_SHA2_256S:
        case cid_PQC_SLHDSA_SHA2_256F:
        case cid_PQC_SLHDSA_SHAKE_256S:
        case cid_PQC_SLHDSA_SHAKE_256F:

            status = SLHDSA_getSignatureLen((SLHDSACtx *) pCtx->pKey, &len);
            if (OK != status)
                goto exit;

            if (sigBufferLen > len) {
                sigBufferLen = len;
            }
            status = SLHDSA_signMessage((SLHDSACtx *) pCtx->pKey, pData, dataLen, rngFun, pRngFunArg, pSignature, sigBufferLen);
            if (OK != status)
                goto exit;

            *pActualSigLen = len;

            break;

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
static MSTATUS QS_SIG_signDigest(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg, ubyte digestId, 
                                 ubyte *pData, ubyte4 dataLen, ubyte *pSignature, ubyte4 sigBufferLen, ubyte4 *pActualSigLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    MLDSADigestType digestType = 0;

    if (NULL == pCtx)
        goto exit;
    
    status = QS_SIG_convertDigestType(digestId, &digestType);
    if (OK != status)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:
        {
            size_t len = 0;
            status = MLDSA_getSignatureLen((MLDSACtx *) pCtx->pKey, &len);
            if (OK != status)
                goto exit;

            if (sigBufferLen > len) 
            {
                sigBufferLen = len;
            }
            status = MLDSA_signDigest((MLDSACtx *) pCtx->pKey, pData, dataLen, digestType, rngFun, pRngFunArg, pSignature, sigBufferLen);
            if (OK != status)
                goto exit;

            *pActualSigLen = len;

            break;
        }
        case cid_PQC_SLHDSA_SHA2_128S:
        case cid_PQC_SLHDSA_SHA2_128F:
        case cid_PQC_SLHDSA_SHAKE_128S:
        case cid_PQC_SLHDSA_SHAKE_128F:
        case cid_PQC_SLHDSA_SHA2_192S:
        case cid_PQC_SLHDSA_SHA2_192F:
        case cid_PQC_SLHDSA_SHAKE_192S:
        case cid_PQC_SLHDSA_SHAKE_192F:
        case cid_PQC_SLHDSA_SHA2_256S:
        case cid_PQC_SLHDSA_SHA2_256F:
        case cid_PQC_SLHDSA_SHAKE_256S:
        case cid_PQC_SLHDSA_SHAKE_256F:

            /*  TODO: uncomment once SLHDSA has this API. may need digestType to be an SLHDSADigestType.
            status = SLHDSA_signDigest(MOC_HASH(hwAccelCtx) (SlhdsaKey *) pCtx->pKey, rngFun, pRngFunArg, digestType, pData, dataLen,
                                 pSignature, sigBufferLen, pActualSigLen);
            if (OK != status)
                goto exit;

            break; */

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}
#endif

/*----------------------------------------------------------------------------*/

static MSTATUS QS_SIG_verify(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, ubyte *pData, ubyte4 dataLen,
                             ubyte *pSignature, ubyte4 signatureLen, ubyte4 *pVerifyStatus)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_verifyMessage((MLDSACtx *) pCtx->pKey, pData, dataLen, pSignature, signatureLen);

            *pVerifyStatus = status;
            /* Signature verification failure is not considered a failure for the crypto interface */
            if (status == ERR_CRYPTO_FAILURE) {
                status = OK;
            }

            if (OK != status)
                goto exit;

            break;

        case cid_PQC_SLHDSA_SHA2_128S:
        case cid_PQC_SLHDSA_SHA2_128F:
        case cid_PQC_SLHDSA_SHAKE_128S:
        case cid_PQC_SLHDSA_SHAKE_128F:
        case cid_PQC_SLHDSA_SHA2_192S:
        case cid_PQC_SLHDSA_SHA2_192F:
        case cid_PQC_SLHDSA_SHAKE_192S:
        case cid_PQC_SLHDSA_SHAKE_192F:
        case cid_PQC_SLHDSA_SHA2_256S:
        case cid_PQC_SLHDSA_SHA2_256F:
        case cid_PQC_SLHDSA_SHAKE_256S:
        case cid_PQC_SLHDSA_SHAKE_256F:

            status = SLHDSA_verifyMessage((SLHDSACtx *) pCtx->pKey, pData, dataLen, pSignature, signatureLen);

            *pVerifyStatus = status;
            /* Signature verification failure is not considered a failure for the crypto interface */
            if (status == ERR_CRYPTO_FAILURE) {
                status = OK;
            }

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

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
static MSTATUS QS_SIG_verifyDigest(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, ubyte digestId, ubyte *pData, ubyte4 dataLen,
                                   ubyte *pSignature, ubyte4 signatureLen, ubyte4 *pVerifyStatus)
{
    MSTATUS status = ERR_NULL_POINTER;
    MLDSADigestType digestType = 0;

    if (NULL == pCtx)
        goto exit;
    
    status = QS_SIG_convertDigestType(digestId, &digestType);
    if (OK != status)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_verifyDigest((MLDSACtx *) pCtx->pKey, pData, dataLen, digestType, pSignature, signatureLen);

            *pVerifyStatus = status;
            /* Signature verification failure is not considered a failure for the crypto interface */
            if (status == ERR_CRYPTO_FAILURE) {
                status = OK;
            }

            if (OK != status)
                goto exit;

            break;

        case cid_PQC_SLHDSA_SHA2_128S:
        case cid_PQC_SLHDSA_SHA2_128F:
        case cid_PQC_SLHDSA_SHAKE_128S:
        case cid_PQC_SLHDSA_SHAKE_128F:
        case cid_PQC_SLHDSA_SHA2_192S:
        case cid_PQC_SLHDSA_SHA2_192F:
        case cid_PQC_SLHDSA_SHAKE_192S:
        case cid_PQC_SLHDSA_SHAKE_192F:
        case cid_PQC_SLHDSA_SHA2_256S:
        case cid_PQC_SLHDSA_SHA2_256F:
        case cid_PQC_SLHDSA_SHAKE_256S:
        case cid_PQC_SLHDSA_SHAKE_256F:
            
            /* TODO: Once SLHDSA has this API we can uncomment, may need to make digest type SLHDSADigestType
            status = SLHDSA_verifyDigest(MOC_HASH(hwAccelCtx) (SlhdsaKey *) pCtx->pKey, pData, dataLen, digestType,
                                        pSignature, signatureLen, pVerifyStatus);
            if (OK != status)
                goto exit; 
                
            break; */

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_SIG_streamingInit(QS_CTX *pCtx, byteBoolean isExternalMu, ubyte digestId, ubyte *pContextStr, ubyte4 ctxStrLen)
{
    MSTATUS status;

    /* pCtx already checked for non-null */
    switch(pCtx->alg)
    {
        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_streamingInit((MLDSACtx *) pCtx->pKey, isExternalMu, digestId, pContextStr, ctxStrLen);
            break;

        case cid_PQC_SLHDSA_SHA2_128S:
        case cid_PQC_SLHDSA_SHA2_128F:
        case cid_PQC_SLHDSA_SHAKE_128S:
        case cid_PQC_SLHDSA_SHAKE_128F:
        case cid_PQC_SLHDSA_SHA2_192S:
        case cid_PQC_SLHDSA_SHA2_192F:
        case cid_PQC_SLHDSA_SHAKE_192S:
        case cid_PQC_SLHDSA_SHAKE_192F:
        case cid_PQC_SLHDSA_SHA2_256S:
        case cid_PQC_SLHDSA_SHA2_256F:
        case cid_PQC_SLHDSA_SHAKE_256S:
        case cid_PQC_SLHDSA_SHAKE_256F:
        default:

            status = ERR_NOT_IMPLEMENTED; /* NEXT TODO */
            break;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_SIG_streamingUpdate(QS_CTX *pCtx, ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status;

    /* pCtx already checked for non-null */
    switch(pCtx->alg)
    {
        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_streamingUpdate((MLDSACtx *) pCtx->pKey, pData, dataLen);
            break;

        case cid_PQC_SLHDSA_SHA2_128S:
        case cid_PQC_SLHDSA_SHA2_128F:
        case cid_PQC_SLHDSA_SHAKE_128S:
        case cid_PQC_SLHDSA_SHAKE_128F:
        case cid_PQC_SLHDSA_SHA2_192S:
        case cid_PQC_SLHDSA_SHA2_192F:
        case cid_PQC_SLHDSA_SHAKE_192S:
        case cid_PQC_SLHDSA_SHAKE_192F:
        case cid_PQC_SLHDSA_SHA2_256S:
        case cid_PQC_SLHDSA_SHA2_256F:
        case cid_PQC_SLHDSA_SHAKE_256S:
        case cid_PQC_SLHDSA_SHAKE_256F:
        default:

            status = ERR_NOT_IMPLEMENTED; /* NEXT TODO */
            break;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_SIG_streamingSignFinal(QS_CTX *pCtx, RNGFun rngFun, void *pRngArg,
                                         ubyte *pSignature, ubyte4 sigBufferLen, ubyte4 *pActualSigLen)
{
    MSTATUS status;

    /* pCtx already checked for non-null */
    switch(pCtx->alg)
    {
        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_streamingSignFinal((MLDSACtx *) pCtx->pKey, rngFun, pRngArg, pSignature, sigBufferLen, pActualSigLen);
            break;

        case cid_PQC_SLHDSA_SHA2_128S:
        case cid_PQC_SLHDSA_SHA2_128F:
        case cid_PQC_SLHDSA_SHAKE_128S:
        case cid_PQC_SLHDSA_SHAKE_128F:
        case cid_PQC_SLHDSA_SHA2_192S:
        case cid_PQC_SLHDSA_SHA2_192F:
        case cid_PQC_SLHDSA_SHAKE_192S:
        case cid_PQC_SLHDSA_SHAKE_192F:
        case cid_PQC_SLHDSA_SHA2_256S:
        case cid_PQC_SLHDSA_SHA2_256F:
        case cid_PQC_SLHDSA_SHAKE_256S:
        case cid_PQC_SLHDSA_SHAKE_256F:
        default:

            status = ERR_NOT_IMPLEMENTED; /* NEXT TODO */
            break;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_SIG_streamingVerifyFinal(QS_CTX *pCtx, ubyte *pSignature, ubyte4 signatureLen, ubyte4 *pVerifyStatus)
{
    MSTATUS status;

     /* pCtx already checked for non-null */
     switch(pCtx->alg)
     {
         case cid_PQC_MLDSA_44:
         case cid_PQC_MLDSA_65:
         case cid_PQC_MLDSA_87:
 
             status = MLDSA_streamingVerifyFinal((MLDSACtx *) pCtx->pKey, pSignature, signatureLen, pVerifyStatus);
             break;
 
         case cid_PQC_SLHDSA_SHA2_128S:
         case cid_PQC_SLHDSA_SHA2_128F:
         case cid_PQC_SLHDSA_SHAKE_128S:
         case cid_PQC_SLHDSA_SHAKE_128F:
         case cid_PQC_SLHDSA_SHA2_192S:
         case cid_PQC_SLHDSA_SHA2_192F:
         case cid_PQC_SLHDSA_SHAKE_192S:
         case cid_PQC_SLHDSA_SHAKE_192F:
         case cid_PQC_SLHDSA_SHA2_256S:
         case cid_PQC_SLHDSA_SHA2_256F:
         case cid_PQC_SLHDSA_SHAKE_256S:
         case cid_PQC_SLHDSA_SHAKE_256F:
         default:
         
             status = ERR_NOT_IMPLEMENTED; /* NEXT TODO */
             break;
     }
 
     return status;   
}
#endif /* __ENABLE_DIGICERT_PQC_SIG_STREAMING__ */

#endif /* (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
           (defined(__ENABLE_DIGICERT_PQC_SIG__)) */

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_SIG_getSignatureLen(QS_CTX *pCtx, ubyte4 *pSigLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    status = ERR_WRONG_CTX_TYPE;
    if (MOC_QS_SIG != pCtx->type)
        goto exit;

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* pSigLen and pSecretKey will be validated by the this call */
        status = CRYPTO_getDomainParam ((MocAsymKey) pCtx->pSecretKey, MOC_ASYM_KEY_PARAM_SIGNATURE_LEN, pSigLen);
    }
    else
    {
        QS_SIG_LEN(status, pCtx, pSigLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_SIG_sign(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg, ubyte *pData, ubyte4 dataLen,
                                            ubyte *pSignature, ubyte4 sigBufferLen, ubyte4 *pActualSigLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx) /* Other params checked in the calls below */
        goto exit;

    status = ERR_WRONG_CTX_TYPE;
    if (MOC_QS_SIG != pCtx->type)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = CRYPTO_asymSignMessage((MocAsymKey) pCtx->pSecretKey, NULL, 0, 0, NULL, rngFun, pRngFunArg, pData, dataLen,
                                        pSignature, sigBufferLen, pActualSigLen, NULL);

    }
    else
    {
        QS_SIG_SIGN(status, pCtx, rngFun, pRngFunArg, pData, dataLen, pSignature, sigBufferLen, pActualSigLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
extern MSTATUS CRYPTO_INTERFACE_QS_SIG_signDigest(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg, ubyte digestId, 
                                                  ubyte *pData, ubyte4 dataLen, ubyte *pSignature, ubyte4 sigBufferLen, ubyte4 *pActualSigLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx) /* Other params checked in the calls below */
        goto exit;

    status = ERR_WRONG_CTX_TYPE;
    if (MOC_QS_SIG != pCtx->type)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* For now we use the algorithmDetails argument to pass in the digestId. We may want to just pass in
           the oid in pAlgId. This depends on how other impls such as OQS define their APIs */
        status = CRYPTO_asymSignDigest((MocAsymKey) pCtx->pSecretKey, NULL, 0, (ubyte4) digestId, NULL, rngFun, pRngFunArg, pData, dataLen,
                                        pSignature, sigBufferLen, pActualSigLen, NULL);
    }
    else
    {
        QS_SIG_SIGN_DIGEST(status, pCtx, rngFun, pRngFunArg, digestId, pData, dataLen, pSignature, sigBufferLen, pActualSigLen);
    }

exit:

    return status;
}
#endif

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_SIG_signAlloc(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg, ubyte *pData, ubyte4 dataLen,
                                                 ubyte **ppSignature, ubyte4 *pSignatureLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pSig = NULL;
    ubyte4 maxSigLen = 0;
    ubyte4 sigLen = 0;

    if (NULL == pCtx || NULL == ppSignature || NULL == pSignatureLen) /* Other params checked in the calls below */
        goto exit;

    status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pCtx, &maxSigLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pSig, maxSigLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_SIG_sign(MOC_HASH(hwAccelCtx) pCtx, rngFun, pRngFunArg, pData, dataLen, pSig, maxSigLen, &sigLen);
    if (OK != status)
        goto exit;

    *ppSignature = pSig; pSig = NULL;

    /* we'll just set the actual signature length. It's ok for the caller to DIGI_MEMSET_FREE
       this length since after it will be garbage anyway */
    *pSignatureLen = sigLen;

exit:

    if (NULL != pSig)
    {
        DIGI_MEMSET_FREE(&pSig, maxSigLen);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, ubyte *pData, ubyte4 dataLen,
                                              ubyte *pSignature, ubyte4 signatureLen, ubyte4 *pVerifyStatus)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)  /* other params checked for NULL in the call to CRYPTO_asymVerifyMessage */
        goto exit;

    status = ERR_WRONG_CTX_TYPE;
    if (MOC_QS_SIG != pCtx->type)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* Once pre-hash mode is supported by OQS we may want to call CRYPTO_asymVerifyDigest in that case */
        status = CRYPTO_asymVerifyMessage((MocAsymKey) pCtx->pPublicKey, NULL, 0, 0, NULL, NULL, NULL, pData, dataLen,
                                          pSignature, signatureLen, pVerifyStatus, NULL);
    }
    else
    {
        QS_SIG_VERIFY(status, pCtx, pData, dataLen, pSignature, signatureLen, pVerifyStatus);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
extern MSTATUS CRYPTO_INTERFACE_QS_SIG_verifyDigest(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, ubyte digestId, ubyte *pData, ubyte4 dataLen,
                                                    ubyte *pSignature, ubyte4 signatureLen, ubyte4 *pVerifyStatus)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)  /* other params checked for NULL in the call to CRYPTO_asymVerifyMessage */
        goto exit;

    status = ERR_WRONG_CTX_TYPE;
    if (MOC_QS_SIG != pCtx->type)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* For now we use the algorithmDetails argument to pass in the digestId. We may want to just pass in
           the oid in pAlgId. This depends on how other impls such as OQS define their APIs */
        status = CRYPTO_asymVerifyDigest((MocAsymKey) pCtx->pPublicKey, NULL, 0, (ubyte4) digestId, NULL, NULL, NULL, pData, dataLen,
                                          pSignature, signatureLen, pVerifyStatus, NULL);
    }
    else
    {
        QS_SIG_VERIFY_DIGEST(status, pCtx, digestId, pData, dataLen, pSignature, signatureLen, pVerifyStatus);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/   

extern MSTATUS CRYPTO_INTERFACE_QS_SIG_streamingInit(QS_CTX *pCtx, byteBoolean isExternalMu, ubyte digestId,
                                                     ubyte *pContextStr, ubyte4 ctxStrLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    status = ERR_WRONG_CTX_TYPE;
    if (MOC_QS_SIG != pCtx->type)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        QS_SIG_STREAM_INIT(status, pCtx, isExternalMu, digestId, pContextStr, ctxStrLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/    

extern MSTATUS CRYPTO_INTERFACE_QS_SIG_streamingUpdate(QS_CTX *pCtx, ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    status = ERR_WRONG_CTX_TYPE;
    if (MOC_QS_SIG != pCtx->type)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        QS_SIG_STREAM_UPDATE(status, pCtx, pData, dataLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_SIG_streamingSignFinal(QS_CTX *pCtx, RNGFun rngFun, void *pRngArg,
                                                          ubyte *pSignature, ubyte4 sigBufferLen, ubyte4 *pActualSigLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    status = ERR_WRONG_CTX_TYPE;
    if (MOC_QS_SIG != pCtx->type)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        QS_SIG_STREAM_SIGN(status, pCtx, rngFun, pRngArg, pSignature, sigBufferLen, pActualSigLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_SIG_streamingVerifyFinal(QS_CTX *pCtx, ubyte *pSignature, ubyte4 signatureLen, ubyte4 *pVerifyStatus)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    status = ERR_WRONG_CTX_TYPE;
    if (MOC_QS_SIG != pCtx->type)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        QS_SIG_STREAM_VERIFY(status, pCtx, pSignature, signatureLen, pVerifyStatus);
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_PQC_SIG_STREAMING__ */
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_SIG__ */
