/*
 * crypto_interface_qs.c
 *
 * Cryptographic Interface specification for common quantum safe methods.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_INTERNAL__

#include "../crypto/mocasym.h"
#include "../common/initmocana.h"
#include "../common/mtypes.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/pqc/mlkem.h"
#include "../crypto/pqc/mldsa.h"
#include "../crypto/pqc/slhdsa.h"
#include "../crypto/pqc/pqc_ser.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_qs.h"

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_KEM__) || defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_SIG__)

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))
#define QS_NEW_CTX(_status, _ppNewCtx, _algo, hw) \
    _status = QS_newCtx(_ppNewCtx, hw, _algo)
#else
#define QS_NEW_CTX(_status, _ppNewCtx, _algo, hw) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))
#define QS_CLONE_CTX(_status, _ppNewCtx, _pCtx) \
    _status = QS_cloneCtx(_ppNewCtx, _pCtx)
#else
#define QS_CLONE_CTX(_status, _ppNewCtx, _pCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))
#define QS_GEN_KEY(_status, _pCtx, _rngFun, _pRngFunArg) \
    _status = QS_generateKeyPair(MOC_HASH(hwAccelCtx) _pCtx, _rngFun, _pRngFunArg)
#else
#define QS_GEN_KEY(_status, _pCtx, _rngFun, _pRngFunArg) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))
#define QS_GET_PUB_LEN(_status, _pCtx, _pPubLen) \
    _status = QS_getPublicKeyLen(_pCtx, _pPubLen)
#else
#define QS_GET_PUB_LEN(_status, _pCtx, _pPubLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))
#define QS_GET_PUB(_status, _pCtx, _pPublicKey, _pubLen) \
    _status = QS_getPublicKey(_pCtx, _pPublicKey, _pubLen)
#else
#define QS_GET_PUB(_status, _pCtx, _pPublicKey, _pubLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))
#define QS_SET_PUB(_status, _pCtx, _pPublicKey, _pubLen) \
    _status = QS_setPublicKey(_pCtx, _pPublicKey, _pubLen)
#else
#define QS_SET_PUB(_status, _pCtx, _pPublicKey, _pubLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))
#define QS_GET_PRI_LEN(_status, _pCtx, _pPriLen) \
    _status = QS_getPrivateKeyLen(_pCtx, _pPriLen)
#else
#define QS_GET_PRI_LEN(_status, _pCtx, _pPriLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))
#define QS_GET_PRI(_status, _pCtx, _pPrivateKey, _priLen) \
    _status = QS_getPrivateKey(_pCtx, _pPrivateKey, _priLen)
#else
#define QS_GET_PRI(_status, _pCtx, _pPrivateKey, _priLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))
#define QS_SET_PRI(_status, _pCtx, _pPrivateKey, _priLen) \
    _status = QS_setPrivateKey(_pCtx, _pPrivateKey, _priLen)
#else
#define QS_SET_PRI(_status, _pCtx, _pPrivateKey, _priLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))
#define QS_PUB_PRI_MATCH(_status, _pCtx, _rng, _rngArg, _pIsValid) \
    _status = QS_validateKeyPair(_pCtx, _rng, _rngArg, _pIsValid)
#else
#define QS_PUB_PRI_MATCH(_status, _pCtx, _rng, _rngArg, _pIsValid) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))
#define QS_SER_KEY(_status, _pCtx, _keyType, _ppSerKey, _pSerKeyLen) \
    _status = QS_serializeKeyAlloc(_pCtx, _keyType, _ppSerKey, _pSerKeyLen)
#else
#define QS_SER_KEY(_status, _pCtx, _keyType, _ppSerKey, _pSerKeyLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))
#define QS_DESER_KEY(_status, _pCtx, _keyType, _pSerKey, _serKeyLen) \
    _status = QS_deserializeKey(_pCtx, _keyType, _pSerKey, _serKeyLen)
#else
#define QS_DESER_KEY(_status, _pCtx, _keyType, _pSerKey, _serKeyLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))
#define QS_DEL_CTX(_status, _ppCtx) \
    _status = QS_deleteCtx(_ppCtx)
#else
#define QS_DEL_CTX(_status, _ppCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__))

static MLKEMType algToMLKEMType(ubyte4 alg)
{
        if (alg == cid_PQC_MLKEM_512)
            return MLKEM_TYPE_512;
        else if (alg == cid_PQC_MLKEM_768)
            return MLKEM_TYPE_768;
        else if (alg == cid_PQC_MLKEM_1024)
            return MLKEM_TYPE_1024;

        return MLKEM_TYPE_ERR;
}

static MLDSAType algToMLDSAType(ubyte4 alg)
{
        if (alg == cid_PQC_MLDSA_44)
            return MLDSA_TYPE_44;
        else if (alg == cid_PQC_MLDSA_65)
            return MLDSA_TYPE_65;
        else if (alg == cid_PQC_MLDSA_87)
            return MLDSA_TYPE_87;

        return MLDSA_TYPE_ERR;
}

static SLHDSAType algToSLHDSAType(ubyte4 alg)
{
    switch (alg) {
        case cid_PQC_SLHDSA_SHA2_128S:
            return SLHDSA_TYPE_SHA2_128S;
        case cid_PQC_SLHDSA_SHA2_128F:
            return SLHDSA_TYPE_SHA2_128F;
        case cid_PQC_SLHDSA_SHAKE_128S:
            return SLHDSA_TYPE_SHAKE_128S;
        case cid_PQC_SLHDSA_SHAKE_128F:
            return SLHDSA_TYPE_SHAKE_128F;
        case cid_PQC_SLHDSA_SHA2_192S:
            return SLHDSA_TYPE_SHA2_192S;
        case cid_PQC_SLHDSA_SHA2_192F:
            return SLHDSA_TYPE_SHA2_192F;
        case cid_PQC_SLHDSA_SHAKE_192S:
            return SLHDSA_TYPE_SHAKE_192S;
        case cid_PQC_SLHDSA_SHAKE_192F:
            return SLHDSA_TYPE_SHAKE_192F;
        case cid_PQC_SLHDSA_SHA2_256S:
            return SLHDSA_TYPE_SHA2_256S;
        case cid_PQC_SLHDSA_SHA2_256F:
            return SLHDSA_TYPE_SHA2_256F;
        case cid_PQC_SLHDSA_SHAKE_256S:
            return SLHDSA_TYPE_SHAKE_256S;
        case cid_PQC_SLHDSA_SHAKE_256F:
            return SLHDSA_TYPE_SHAKE_256F;
        default:
            return SLHDSA_TYPE_ERR;
    }
}

static MSTATUS QS_deleteCtx(QS_CTX **ppCtx)
{
    MSTATUS status = OK;

    if (NULL == ppCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == *ppCtx)
        goto exit; /* ok no-op */

    switch((*ppCtx)->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            status = MLKEM_destroyCtx((MLKEMCtx *) (*ppCtx)->pKey);
            (void) DIGI_MEMSET_FREE((ubyte **)&(*ppCtx)->pKey, sizeof(MLKEMCtx));
            break;

        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_destroyCtx((MLDSACtx *) (*ppCtx)->pKey);
            (void) DIGI_MEMSET_FREE((ubyte **) &(*ppCtx)->pKey, sizeof(MLDSACtx));
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

            status = SLHDSA_destroyCtx((SLHDSACtx *) (*ppCtx)->pKey);
            DIGI_MEMSET_FREE((ubyte**)&(*ppCtx)->pKey, sizeof(SLHDSACtx));
            break;

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

    (void) DIGI_MEMSET_FREE((ubyte **) ppCtx, sizeof(QS_CTX));

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_newCtx(QS_CTX **ppNewCtx, hwAccelDescr hwAccelCtx, ubyte4 alg)
{
    MSTATUS status = ERR_NULL_POINTER;
    QS_CTX *pNewCtx = NULL;
    MLDSACtx *pMldsaCtx = NULL;
    MLKEMCtx *pMlkemCtx = NULL;
    SLHDSACtx *pSlhCtx = NULL;

    if (NULL == ppNewCtx)
        goto exit;

    /* Allocate the QS context */
    status = DIGI_CALLOC((void **)&pNewCtx, 1, sizeof(QS_CTX));
    if (OK != status)
        goto exit;

    /* Set the alg right away so if we error we cleanup properly */
    pNewCtx->alg = alg;

    switch(alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:
        {
            status = DIGI_CALLOC((void **)&pMlkemCtx, 1, sizeof(MLKEMCtx));
            if (OK != status)
                goto exit;

            status = MLKEM_createCtx(algToMLKEMType(alg), hwAccelCtx, pMlkemCtx);
            if (OK != status)
                goto exit;

            pNewCtx->pKey = pMlkemCtx; pMlkemCtx = NULL;
            pNewCtx->type = MOC_QS_KEM;
            break;
        }
        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:
        {
            status = DIGI_CALLOC((void **)&pMldsaCtx, 1, sizeof(MLDSACtx));
            if (OK != status)
                goto exit;

            status = MLDSA_createCtx(algToMLDSAType(alg), hwAccelCtx, pMldsaCtx);
            if (OK != status)
                goto exit;

            pNewCtx->pKey = pMldsaCtx; pMldsaCtx = NULL;
            pNewCtx->type = MOC_QS_SIG;
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
        {
            status = DIGI_CALLOC((void **)&pSlhCtx, 1, sizeof(SLHDSACtx));
            if (status != OK)
                goto exit;

            status = SLHDSA_createCtx(algToSLHDSAType(alg), hwAccelCtx, pSlhCtx);
            if (OK != status)
                goto exit;

            pNewCtx->pKey = pSlhCtx; pSlhCtx = NULL;
            pNewCtx->type = MOC_QS_SIG;
            break;
        }
        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

    /* Set the callers pointer */
    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;

exit:

    if (NULL != pMlkemCtx)
    {
        (void) DIGI_FREE((void **) &pMlkemCtx);
    }
    if (NULL != pMldsaCtx)
    {
        (void) DIGI_FREE((void **) &pMldsaCtx);
    }
    if (NULL != pSlhCtx)
    {
        (void) DIGI_FREE((void **) &pSlhCtx);
    }
    if (NULL != pNewCtx)
    {
        (void) QS_deleteCtx(&pNewCtx);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_cloneCtx(QS_CTX **ppNewCtx, QS_CTX *pCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    QS_CTX *pNewCtx = NULL;
    MLDSACtx *pMldsaCtx = NULL;
    MLKEMCtx *pMlkemCtx = NULL;
    SLHDSACtx *pSlhCtx = NULL;

    if (NULL == ppNewCtx || NULL == pCtx)
        goto exit;

    /* Allocate the QS context */
    status = DIGI_CALLOC((void **)&pNewCtx, 1, sizeof(QS_CTX));
    if (OK != status)
        goto exit;

    pNewCtx->enabled = pCtx->enabled;
    pNewCtx->isPrivate = pCtx->isPrivate;
    pNewCtx->type = pCtx->type;
    pNewCtx->alg = pCtx->alg;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            if (NULL != pCtx->pKey)
            {
                status = DIGI_CALLOC((void **) &pMlkemCtx, 1, sizeof(MLKEMCtx));
                if (OK != status)
                    goto exit;

                status = MLKEM_cloneCtx((MLKEMCtx *) pCtx->pKey, pMlkemCtx);
                if (OK != status)
                    goto exit;

                pNewCtx->pKey = pMlkemCtx; pMlkemCtx = NULL;
            }
            break;

        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            if (NULL != pCtx->pKey)
            {
                status = DIGI_CALLOC((void **) &pMldsaCtx, 1, sizeof(MLDSACtx));
                if (OK != status)
                    goto exit;

                status = MLDSA_cloneCtx((MLDSACtx *) pCtx->pKey, pMldsaCtx);
                if (OK != status)
                    goto exit;

                pNewCtx->pKey = pMldsaCtx; pMldsaCtx = NULL;
            }
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

            if (NULL != pCtx->pKey)
            {
                status = DIGI_CALLOC((void **)&pSlhCtx, 1, sizeof(SLHDSACtx));
                if (status != OK)
                    goto exit;
                status = SLHDSA_cloneCtx((SLHDSACtx *) pCtx->pKey, pSlhCtx);
                if (OK != status)
                    goto exit;

                pNewCtx->pKey = pSlhCtx; pSlhCtx = NULL;

            }
            break;

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

    *ppNewCtx = pNewCtx; pNewCtx = NULL;

exit:

    if (NULL != pMlkemCtx)
    {
        (void) DIGI_FREE((void **) &pMlkemCtx);
    }
    if (NULL != pMldsaCtx)
    {
        (void) DIGI_FREE((void **) &pMldsaCtx);
    }
    if (NULL != pSlhCtx)
    {
        (void) DIGI_FREE((void **) &pSlhCtx);
    }
    if (NULL != pNewCtx)
    {
        (void) QS_deleteCtx(&pNewCtx);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_generateKeyPair(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            status = MLKEM_generateKeyPair(rngFun, pRngFunArg, (MLKEMCtx *) pCtx->pKey);
            if (OK != status)
                goto exit;

            break;

        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

           status = MLDSA_generateKeyPair(rngFun, pRngFunArg, (MLDSACtx *) pCtx->pKey);
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

           status = SLHDSA_generateKeyPair(rngFun, pRngFunArg, (SLHDSACtx *) pCtx->pKey);
            if (OK != status)
                goto exit;

            break;

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

    pCtx->isPrivate = TRUE;

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_getPublicKeyLen(QS_CTX *pCtx, ubyte4 *pPubLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    size_t len = 0;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            status = MLKEM_getPublicKeyLen((MLKEMCtx *) pCtx->pKey, &len);
            if (OK != status)
                goto exit;
            *pPubLen = len;

            break;

        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_getPublicKeyLen((MLDSACtx *) pCtx->pKey, &len);
            if (OK != status)
                goto exit;
            *pPubLen = len;

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

            status = SLHDSA_getPublicKeyLen((SLHDSACtx *) pCtx->pKey, &len);
            if (OK != status)
                goto exit;
            *pPubLen = len;

            break;

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_getPublicKey(QS_CTX *pCtx, ubyte *pPublicKey, ubyte4 pubLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            status = MLKEM_getPublicKey((MLKEMCtx *) pCtx->pKey, pPublicKey, pubLen);
            if (OK != status)
                goto exit;

            break;

        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_getPublicKey((MLDSACtx *) pCtx->pKey, pPublicKey, pubLen);
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

            status = SLHDSA_getPublicKey((SLHDSACtx *) pCtx->pKey, pPublicKey, pubLen);
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

static MSTATUS QS_setPublicKey(QS_CTX *pCtx, ubyte *pPublicKey, ubyte4 pubLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            status = MLKEM_setPublicKey(pPublicKey, pubLen, (MLKEMCtx *) pCtx->pKey);
            if (OK != status)
                goto exit;

            break;

        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_setPublicKey(pPublicKey, pubLen, (MLDSACtx *) pCtx->pKey);
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

            status = SLHDSA_setPublicKey(pPublicKey, pubLen, (SLHDSACtx *) pCtx->pKey);
            if (OK != status)
                goto exit;

            break;

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

    pCtx->isPrivate = FALSE;

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_getPrivateKeyLen(QS_CTX *pCtx, ubyte4 *pPriLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    size_t len = 0;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            status = MLKEM_getPrivateKeyLen((MLKEMCtx *) pCtx->pKey, &len);
            if (OK != status)
                goto exit;
            *pPriLen = len;

            break;

        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_getPrivateKeyLen((MLDSACtx *) pCtx->pKey, &len);
            if (OK != status)
                goto exit;
            *pPriLen = len;

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

            /* fallthrough for now */

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_getPrivateKey(QS_CTX *pCtx, ubyte *pPrivateKey, ubyte4 priLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            status = MLKEM_getPrivateKey((MLKEMCtx *) pCtx->pKey, pPrivateKey, priLen);
            if (OK != status)
                goto exit;

            break;

        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_getPrivateKey((MLDSACtx *) pCtx->pKey, pPrivateKey, priLen);
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

            /* fallthrough for now */

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_setPrivateKey(QS_CTX *pCtx, ubyte *pPrivateKey, ubyte4 priLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            status = MLKEM_setPrivateKey(pPrivateKey, priLen, (MLKEMCtx *) pCtx->pKey);
            if (OK != status)
                goto exit;

            break;

        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_setPrivateKey(pPrivateKey, priLen, (MLDSACtx *) pCtx->pKey);
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

            /* fallthrough for now */

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

    pCtx->isPrivate = TRUE;

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_validateKeyPair(QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg, byteBoolean *pIsValid)
{
    MSTATUS status = ERR_NULL_POINTER;
    bool valid = false;

    if (NULL == pCtx || NULL == pIsValid)
        goto exit;

    *pIsValid = FALSE;

    status = ERR_KEY_IS_NOT_PRIVATE;
    if (!pCtx->isPrivate)
    {
        goto exit;
    }

    status = OK;
    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            valid = MLKEM_verifyKeyPair((MLKEMCtx *) pCtx->pKey, rngFun, pRngFunArg);
            if (valid)
            {
               *pIsValid = TRUE;
            }

            break;
            
        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            valid = MLDSA_verifyKeyPair((MLDSACtx *) pCtx->pKey);
            if (valid)
            {
               *pIsValid = TRUE;
            }

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

            valid = SLHDSA_verifyKeyPair((SLHDSACtx *) pCtx->pKey);
            if (valid)
            {
               *pIsValid = TRUE;
            }

            break;

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_serializeKeyAlloc(QS_CTX *pCtx, ubyte4 keyType, ubyte **ppSerKey, ubyte4 *pSerKeyLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    size_t len = 0;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            status = MLKEM_serializeKeyAlloc((MLKEMCtx *) pCtx->pKey, MOC_ASYM_KEY_TYPE_PUBLIC == keyType ? TRUE : FALSE,
                                             ppSerKey, &len);
            *pSerKeyLen = len;
            break;

        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_serializeKeyAlloc((MLDSACtx *) pCtx->pKey, MOC_ASYM_KEY_TYPE_PUBLIC == keyType ? TRUE : FALSE,
                                                  ppSerKey, &len);
            *pSerKeyLen = len;
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

            status = SLHDSA_serializeKeyAlloc((SLHDSACtx *) pCtx->pKey, MOC_ASYM_KEY_TYPE_PUBLIC == keyType ? TRUE : FALSE,
                                                  ppSerKey, &len);
            *pSerKeyLen = len;
            break;

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS QS_deserializeKey(QS_CTX *pCtx, ubyte4 keyType, ubyte *pSerKey, ubyte4 serKeyLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    switch(pCtx->alg)
    {
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:

            status = MLKEM_deserializeKey((MLKEMCtx *) pCtx->pKey, MOC_ASYM_KEY_TYPE_PUBLIC == keyType ? TRUE : FALSE,
                                           pSerKey, serKeyLen);
            if (OK != status)
                goto exit;

            if (NULL != ((MLKEMCtx *) pCtx->pKey)->decKey && ((MLKEMCtx *) pCtx->pKey)->decKeyLen)
            {
                pCtx->isPrivate = TRUE;
            }
            break;

        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:

            status = MLDSA_deserializeKey((MLDSACtx *) pCtx->pKey, MOC_ASYM_KEY_TYPE_PUBLIC == keyType ? TRUE : FALSE,
                                               pSerKey, serKeyLen);
            if (OK != status)
                goto exit;

            if (NULL != ((MLDSACtx *) pCtx->pKey)->privKey && ((MLDSACtx *) pCtx->pKey)->privKeyLen)
            {
                pCtx->isPrivate = TRUE;
            }
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

            status = SLHDSA_deserializeKey((SLHDSACtx *) pCtx->pKey, MOC_ASYM_KEY_TYPE_PUBLIC == keyType ? TRUE : FALSE,
                                               pSerKey, serKeyLen);
            if (OK != status)
                goto exit;

            if (NULL != ((SLHDSACtx *) pCtx->pKey)->privKey && ((SLHDSACtx *) pCtx->pKey)->privKeyLen)
            {
                pCtx->isPrivate = TRUE;
            }
            break;

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    return status;
}
#endif /* #if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_PQC__)) */

/*----------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_QS_convertToKeyAlgo(ubyte4 algo, ubyte4 *pKeyAlgo, ubyte4 *pType)
{
    switch(algo)
    {
        /* mlKem not implemented via operators but have to return a key algo for now */
        case cid_PQC_MLKEM_512:
        case cid_PQC_MLKEM_768:
        case cid_PQC_MLKEM_1024:
            *pKeyAlgo = moc_alg_qs_kem_mlkem;
            *pType = MOC_QS_KEM;
            break;

        case cid_PQC_MLDSA_44:
        case cid_PQC_MLDSA_65:
        case cid_PQC_MLDSA_87:
            *pKeyAlgo = moc_alg_qs_sig_mldsa;
            *pType = MOC_QS_SIG;
            break;

        case cid_PQC_FNDSA_512:
        case cid_PQC_FNDSA_1024:
            *pKeyAlgo = moc_alg_qs_sig_fndsa;
            *pType = MOC_QS_SIG;
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
            *pKeyAlgo = moc_alg_qs_sig_slhdsa;
            *pType = MOC_QS_SIG;
            break;

        default:
            return ERR_INVALID_INPUT;
    }

    return OK;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_getAlg(QS_CTX *pCtx, ubyte4 *pAlg)
{
    if (NULL == pCtx || NULL == pAlg)
        return ERR_NULL_POINTER;

    *pAlg = pCtx->alg;

    return OK;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX **ppNewCtx, ubyte4 algo)
{
    MSTATUS status = ERR_NULL_POINTER;
    MocCtx pMocCtx = NULL;
    MocAsymKey pNewSecretKey = NULL;
    MocAsymKey pNewPubKey = NULL;
    QS_CTX *pNewCtx = NULL;
    ubyte4 algoStatus = 0, index = 0;
    ubyte4 type, keyAlg = 0;

    if (NULL == ppNewCtx)
        goto exit;

    status = CRYPTO_INTERFACE_QS_convertToKeyAlgo(algo, &keyAlg, &type);
    if (OK != status)
        goto exit;

    status = ERR_INVALID_ARG;
    if (MOC_QS_SIG != type && MOC_QS_KEM != type)  /* only two options at the moment */
        goto exit;

    /* Determine if we have an implementation */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(keyAlg, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        /* Get a reference to the MocCtx registered with the crypto interface */
        status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
        if (OK != status)
            goto exit;

        /* Get an empty secret key from the MocCtx */
        status = CRYPTO_getAsymObjectFromIndex (index, pMocCtx, (void *) &algo, MOC_ASYM_KEY_TYPE_PRIVATE, &pNewSecretKey);
        if (OK != status)
            goto exit;

        /* Get an empty public key from the MocCtx */
        status = CRYPTO_getAsymObjectFromIndex (index, pMocCtx, (void *) &algo, MOC_ASYM_KEY_TYPE_PUBLIC, &pNewPubKey);
        if (OK != status)
            goto exit;

        /* Allocate the QS context */
        status = DIGI_CALLOC((void **)&pNewCtx, 1, sizeof(QS_CTX));
        if (OK != status)
            goto exit;

        /* Set the newly created keys inside the ctx */
        pNewCtx->pSecretKey = (void *) pNewSecretKey;
        pNewSecretKey = NULL;

        pNewCtx->pPublicKey = (void *) pNewPubKey;
        pNewPubKey = NULL;

        /* Mark this object to indicate that there is an implementation through the crypto interface */
        pNewCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

        /* No private key value is set yet so mark it public for now */
        pNewCtx->isPrivate = FALSE;

        /* Set the type */
        pNewCtx->type = type;

        /* Set the algorithm */
        pNewCtx->alg = algo;

        /* Set the callers pointer */
        *ppNewCtx = pNewCtx;
        pNewCtx = NULL;
    }
    else
    {
        hwAccelDescr tmp = (hwAccelDescr)0;
        /* I'm using the comma operator in ways I'm not proud of but this effectively sets the hw acceleration to either NULL or the
         * optionally passed in hwAccelCtx. Profound apologies.
         */
        {
            hwAccelDescr hw = MOC_HASH(hwAccelCtx) tmp;
            QS_NEW_CTX(status, ppNewCtx, algo, hw);
        }
    }

exit:

    if (NULL != pNewSecretKey)
    {
        CRYPTO_freeMocAsymKey(&pNewSecretKey, NULL);
    }
    if (NULL != pNewPubKey)
    {
        CRYPTO_freeMocAsymKey(&pNewPubKey, NULL);
    }
    if (NULL != pNewCtx)
    {
        DIGI_FREE((void **)&pNewCtx);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_cloneCtx(QS_CTX **ppNewCtx, QS_CTX *pCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    QS_CTX *pNewCtx = NULL;

    if (NULL == pCtx || NULL == ppNewCtx)
        goto exit;

    /* Is this a crypto interface ctx? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* Allocate the QS context */
        status = DIGI_CALLOC((void **)&pNewCtx, 1, sizeof(QS_CTX));
        if (OK != status)
            goto exit;

        /* Clone the underlying secret key */
        status = CRYPTO_cloneMocAsymKey((MocAsymKey) pCtx->pSecretKey, (MocAsymKey *) &pNewCtx->pSecretKey, NULL);
        if (OK != status)
            goto exit;

        /* Clone the underlying public key */
        status = CRYPTO_cloneMocAsymKey((MocAsymKey) pCtx->pPublicKey, (MocAsymKey *) &pNewCtx->pPublicKey, NULL);
        if (OK != status)
            goto exit;

        pNewCtx->enabled = pCtx->enabled;
        pNewCtx->isPrivate = pCtx->isPrivate;
        pNewCtx->type = pCtx->type;
        pNewCtx->alg = pCtx->alg;

        *ppNewCtx = pNewCtx; pNewCtx = NULL;
    }
    else
    {
        QS_CLONE_CTX(status, ppNewCtx, pCtx);
    }

exit:

    if (NULL != pNewCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pNewCtx); /* only here on error, ignore return */
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_generateKeyPair(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 algoStatus, index;
    MocCtx pMocCtx = NULL;
    MKeyOperator keyOperator = NULL;
    ubyte4 keyAlg = 0;
    ubyte4 type = 0;

    if (NULL == pCtx)
        goto exit;

    status = ERR_UNINITIALIZED_CONTEXT;
    if (MOC_QS_SIG != pCtx->type && MOC_QS_KEM != pCtx->type)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* Get a reference to the MocCtx registered with the crypto interface */
        status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_convertToKeyAlgo(pCtx->alg, &keyAlg, &type);
        if (OK != status)
            goto exit;

        /* get the index of the operator */
        status = CRYPTO_INTERFACE_checkAsymAlgoStatus(keyAlg, &algoStatus, &index);
        if (OK != status)
            goto exit;

        /* get the operator */
        status = CRYPTO_getAsymOperatorAndInfoFromIndex(index, pMocCtx, &keyOperator, NULL);
        if (OK != status)
            goto exit;

        /* Generate the new secret and public keys (destroying any old ones) */
        status = CRYPTO_generateKeyPair(keyOperator, (void *) (&pCtx->alg), pMocCtx, rngFun, pRngFunArg, (MocAsymKey *) &(pCtx->pPublicKey), (MocAsymKey *) &(pCtx->pSecretKey), NULL);
        if (OK != status)
            goto exit;

        /* we have both public and private keys now */
        pCtx->isPrivate = TRUE;
    }
    else
    {
        QS_GEN_KEY(status, pCtx, rngFun, pRngFunArg);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_getPublicKeyLenFromAlgo(ubyte4 algo, ubyte4 *pPubLen)
{
    MSTATUS status = OK;
    QS_CTX *pCtx = NULL;

    /* Input validity is handled by the below calls */
    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(0) &pCtx, algo);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pCtx, pPubLen);

exit:

    if (NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pCtx);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_getPublicKeyLen(QS_CTX *pCtx, ubyte4 *pPubLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* pubLen and publicKey will be validated by the this call */
        status = CRYPTO_getDomainParam ((MocAsymKey) pCtx->pPublicKey, MOC_ASYM_KEY_PARAM_PUBKEY_LEN, pPubLen);
    }
    else
    {
        QS_GET_PUB_LEN(status, pCtx, pPubLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_getPublicKey(QS_CTX *pCtx, ubyte *pPublicKey, ubyte4 pubLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        MPqcKeyTemplate template = {0};

        if (NULL == pPublicKey)
            goto exit;

        template.pPublicKey = pPublicKey;
        template.publicKeyLen = pubLen;

        /* Get the public key data from the operator, this doesn't actually allocate any buffers in our case */
        status = CRYPTO_getKeyDataAlloc ((MocAsymKey) pCtx->pPublicKey, (void *)&template, MOC_GET_PUBLIC_KEY_DATA);
        if (OK != status)
        {
            /* If we didn't find it then this might be a secret key, get the public key from the secret key */
            status = CRYPTO_getKeyDataAlloc((MocAsymKey) pCtx->pSecretKey, (void *)&template, MOC_GET_PUBLIC_KEY_DATA);
        }
    }
    else
    {
        QS_GET_PUB(status, pCtx, pPublicKey, pubLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_getPrivateKeyLen(QS_CTX *pCtx, ubyte4 *pPriLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* pubLen and publicKey will be validated by the this call */
        status = CRYPTO_getDomainParam ((MocAsymKey) pCtx->pSecretKey, MOC_ASYM_KEY_PARAM_PRIKEY_LEN, pPriLen);
    }
    else
    {
        QS_GET_PRI_LEN(status, pCtx, pPriLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_getPrivateKey(QS_CTX *pCtx, ubyte *pPrivateKey, ubyte4 priLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        MPqcKeyTemplate template = {0};

        if (NULL == pPrivateKey)
            goto exit;

        template.pSecretKey = pPrivateKey;
        template.secretKeyLen = priLen;

        /* Get the public key data from the operator, this doesn't actually allocate any buffers in our case */
        status = CRYPTO_getKeyDataAlloc ((MocAsymKey) pCtx->pSecretKey, (void *)&template, MOC_GET_PRIVATE_KEY_DATA);
    }
    else
    {
        QS_GET_PRI(status, pCtx, pPrivateKey, priLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_getPublicKeyAlloc(QS_CTX *pCtx, ubyte **ppPublicKey, ubyte4 *pPubLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pPublicKey = NULL;
    ubyte4 pubLen = 0;

    if (NULL == pCtx || NULL == ppPublicKey || NULL == pPubLen)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pCtx, &pubLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pPublicKey, pubLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPublicKey(pCtx, pPublicKey, pubLen);
    if (OK != status)
        goto exit;

    *ppPublicKey = pPublicKey; pPublicKey = NULL;
    *pPubLen = pubLen;

exit:

    if (NULL != pPublicKey)
    {
        DIGI_MEMSET_FREE(&pPublicKey, pubLen);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_getPrivateKeyAlloc(QS_CTX *pCtx, ubyte **ppPrivateKey, ubyte4 *pPriLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pPrivateKey = NULL;
    ubyte4 priLen = 0;

    if (NULL == pCtx || NULL == ppPrivateKey || NULL == pPriLen)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPrivateKeyLen(pCtx, &priLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pPrivateKey, priLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPrivateKey(pCtx, pPrivateKey, priLen);
    if (OK != status)
        goto exit;

    *ppPrivateKey = pPrivateKey; pPrivateKey = NULL;
    *pPriLen = priLen;

exit:

    if (NULL != pPrivateKey)
    {
        DIGI_MEMSET_FREE(&pPrivateKey, priLen);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_validateKeyPair(QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg, byteBoolean *pIsValid)
{
    MSTATUS status = OK;
    MocAsymKey pPubKeyToUse = NULL;
    
    if (NULL == pCtx || NULL == pIsValid)
        return status;

    *pIsValid = FALSE; /* default in case of other errors */

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* Does the QS Ctx have a public key to check against? */
        if (NULL != pCtx->pPublicKey)
        {
            pPubKeyToUse = (MocAsymKey) pCtx->pPublicKey;
        }
        else
        {
            /* If none was provided, see if we can validate the public key as part of the private key pair */
            pPubKeyToUse = (MocAsymKey) pCtx->pSecretKey;
        }

       status = CRYPTO_validatePubPriMatch ((MocAsymKey) pCtx->pSecretKey, pPubKeyToUse, pIsValid);
    }
    else
    {
        QS_PUB_PRI_MATCH(status, pCtx, rngFun, pRngFunArg, pIsValid);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_equalKey(QS_CTX *pCtx1, QS_CTX *pCtx2, ubyte4 keyType, byteBoolean *pRes)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pKey1 = NULL;
    ubyte4 key1Len;
    ubyte *pKey2 = NULL;
    ubyte4 key2Len;
    sbyte4 cmpRes = -1;

    if (NULL == pCtx1 || NULL == pCtx2 || NULL == pRes)
        goto exit;

    *pRes = FALSE; /* default */
    
    if (MOC_ASYM_KEY_TYPE_PRIVATE == keyType)
    {
        status = CRYPTO_INTERFACE_QS_getPrivateKeyAlloc(pCtx1, &pKey1, &key1Len);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_getPrivateKeyAlloc(pCtx2, &pKey2, &key2Len);
        if (OK != status)
            goto exit;

        if (key1Len != key2Len)
            goto exit;

        status = DIGI_MEMCMP(pKey1, pKey2, key1Len, &cmpRes);
        if (OK != status)
            goto exit;

        if (0 != cmpRes)
            goto exit;

        (void) DIGI_MEMSET_FREE(&pKey1, key1Len);
        (void) DIGI_MEMSET_FREE(&pKey2, key2Len);
    }

    /* compare public keys no matter what */
    status = CRYPTO_INTERFACE_QS_getPublicKeyAlloc(pCtx1, &pKey1, &key1Len);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPublicKeyAlloc(pCtx2, &pKey2, &key2Len);
    if (OK != status)
        goto exit;

    if (key1Len != key2Len)
        goto exit;

    status = DIGI_MEMCMP(pKey1, pKey2, key1Len, &cmpRes);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
        goto exit;

    *pRes = TRUE;

exit:

    if (NULL != pKey1)
    {
        (void) DIGI_MEMSET_FREE(&pKey1, key1Len);
    }

    if (NULL != pKey2)
    {
        (void) DIGI_MEMSET_FREE(&pKey2, key2Len);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_setPublicKey(QS_CTX *pCtx, ubyte *pPublicKey, ubyte4 pubLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        MPqcKeyTemplate template = {0};

        template.pPublicKey = pPublicKey;
        template.publicKeyLen = pubLen;

        /* Set the secret key operator data */
        status = CRYPTO_setKeyData((MocAsymKey) pCtx->pPublicKey, (void *) &template);
    }
    else
    {
        QS_SET_PUB(status, pCtx, pPublicKey, pubLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_setPrivateKey(QS_CTX *pCtx, ubyte *pPrivateKey, ubyte4 priLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        MPqcKeyTemplate template = {0};

        template.pSecretKey = pPrivateKey;
        template.secretKeyLen = priLen;

        /* Set the secret key operator data */
        status = CRYPTO_setKeyData((MocAsymKey) pCtx->pSecretKey, (void *) &template);
    }
    else
    {
        QS_SET_PRI(status, pCtx, pPrivateKey, priLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_serializeKeyAlloc(QS_CTX *pCtx, ubyte4 keyType, ubyte **ppSerKey, ubyte4 *pSerKeyLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        if (MOC_ASYM_KEY_TYPE_PRIVATE == keyType && NULL != pCtx->pSecretKey)
        {
            status = CRYPTO_serializeMocAsymKeyAlloc ((MocAsymKey) pCtx->pSecretKey, mocanaBlobVersion2, ppSerKey, pSerKeyLen);
        }
        else if (MOC_ASYM_KEY_TYPE_PUBLIC == keyType && NULL != pCtx->pPublicKey)
        {
            status = CRYPTO_serializeMocAsymKeyAlloc ((MocAsymKey) pCtx->pPublicKey, mocanaBlobVersion2, ppSerKey, pSerKeyLen);
        }
        else
        {
            status = ERR_INVALID_INPUT;
        }
    }
    else
    {
        QS_SER_KEY(status, pCtx, keyType, ppSerKey, pSerKeyLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_deserializeKey(QS_CTX *pCtx, ubyte4 keyType, ubyte *pSerKey, ubyte4 serKeyLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled) {
        /* Cap's deserilize API allocates the MocAsymKey for you, but we already create it upon context init */
        /* instead of using CAP we just reach in to the operator directly */
        MKeyOperatorData qsBlob = {0};
        qsBlob.pData = pSerKey;
        qsBlob.length = serKeyLen;

        /* This works because there is an issue with what constitues a public and private key. The QS context has public and secret
         * keys that need to be filled in but the underlying QS algos have their own separate definition of what a public and
         * private key is. As well the mocana version 2 serial/deserial format has a built in public and private key. There ends up
         * being a bunch of combinations of what a public/private/secret key is. Ffilling in both QS key types addresses the issue
         * and removes the need for users to call deserialize twice.
         */
        MocAsymKey secretKey = (MocAsymKey)pCtx->pSecretKey;
        MocAsymKey publicKey = (MocAsymKey)pCtx->pPublicKey;
        if ( secretKey == NULL || secretKey->KeyOperator == NULL || publicKey == NULL || publicKey->KeyOperator == NULL) {
            goto exit;
        }

        status = secretKey->KeyOperator (secretKey, NULL, MOC_ASYM_OP_DESERIALIZE, (void *)&qsBlob, NULL, NULL);
        if (status != OK) {
            goto exit;
        }
        status = publicKey->KeyOperator (publicKey, NULL, MOC_ASYM_OP_DESERIALIZE, (void *)&qsBlob, NULL, NULL);
    }
    else {
        QS_DESER_KEY(status, pCtx, keyType, pSerKey, serKeyLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_QS_deleteCtx(QS_CTX **ppCtx)
{
    MSTATUS status = ERR_NULL_POINTER, fstatus = OK;

    if (NULL == ppCtx)
        goto exit;

    status = OK;
    if (NULL == *ppCtx)
        goto exit;  /* ok no-op */

    /* Is this enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == (*ppCtx)->enabled)
    {
        status = CRYPTO_freeMocAsymKey((MocAsymKey *) &((*ppCtx)->pSecretKey), NULL);

        fstatus = CRYPTO_freeMocAsymKey((MocAsymKey *) &((*ppCtx)->pPublicKey), NULL);
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_MEMSET_FREE((ubyte **) ppCtx, sizeof(QS_CTX));
        if (OK == status)
            status = fstatus;
    }
    else
    {
        QS_DEL_CTX(status, ppCtx);
    }

exit:

    return status;
}
#endif /* defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_KEM__) || defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_SIG__) */
