/*
 * ecc.c
 *
 * Elliptic Curve Cryptography
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC_INTERNAL__

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_ECC__

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/primefld.h"
#include "../crypto/primefld_priv.h"
#include "../crypto/primeec_priv.h"
#include "../crypto/ecc.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/crypto.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/crypto_hash_fips.h"
#endif

#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__

#include "../crypto/ecc_edwards.h"

/* for simplicity defined some flags for different combinations of curves/algorithms */
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
#include "../crypto/ecc_edwards_dsa.h"
#endif /* __ENABLE_DIGICERT_ECC_EDDSA__ */

#ifdef __ENABLE_DIGICERT_ECC_EDDH__
#include "../crypto/ecc_edwards_dh.h"
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) && defined(__DISABLE_DIGICERT_SHA512__)
#error Must undefine __DISABLE_DIGICERT_SHA512__ if __ENABLE_DIGICERT_ECC_EDDSA_25519__ is defined.
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) && !defined(__ENABLE_DIGICERT_SHA3__)
#error Must define __ENABLE_DIGICERT_SHA3__ if __ENABLE_DIGICERT_ECC_EDDSA_448__ is defined.
#endif
#endif /* __ENABLE_DIGICERT_ECC_ED_COMMON__ */


MSTATUS EC_cloneKeyEx(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey **ppNew, ECCKey *pSrc)
{
    MSTATUS status = ERR_NULL_POINTER;
    
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    ECCKey *pNew = NULL;
    edECCKey *pEdECCKey = NULL;
#endif
    
    if (NULL == pSrc)
        goto exit;
    
    if (NULL != pSrc->pCurve)
        return EC_cloneKey(ppNew, pSrc);
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
        /* do our own allocation of the outer key shell */
        status = DIGI_CALLOC((void **) &pNew, sizeof(ECCKey), 1);
        if (OK != status)
            goto exit;
        
        status = edECC_cloneKey(&pEdECCKey, (edECCKey *)(pSrc->pEdECCKey), NULL);
        if (OK != status)
            goto exit;
        
        pNew->curveId = pSrc->curveId;
        pNew->pEdECCKey = (void *) pEdECCKey; pEdECCKey = NULL;
        *ppNew = pNew; pNew = NULL;
    }
#endif /* #else status is still ERR_NULL_POINTER */
    
exit:
    
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    if (NULL != pEdECCKey)
    {   /* don't change status, ignore return */
        edECC_deleteKey(&pEdECCKey, NULL);
    }
    if (NULL != pNew)
    {   /* don't change status, ignore return */
        pNew->pEdECCKey = NULL; /* rest of key is already zero */
        DIGI_FREE((void **) &pNew);
    }
#endif
    
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EC_isKeyPrivate(ECCKey *pKey, intBoolean *pResult)
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pKey || NULL == pResult)
        goto exit;
    
    if (NULL != pKey->pCurve)
    {
        *pResult = pKey->privateKey;
        status = OK;
    }
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else if (NULL != pKey->pEdECCKey)
    {
        *pResult = ((edECCKey *) pKey->pEdECCKey)->isPrivate;
        status = OK;
    }
    
    /* else status is still ERR_NULL_POINTER */
#endif

exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EC_deleteKeyEx(ECCKey **ppKey)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == ppKey || NULL == *ppKey)
        goto exit;
    
    if (NULL != (*ppKey)->pCurve)
        status = EC_deleteKey(ppKey);
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
        if (NULL != (*ppKey)->pEdECCKey)
        {   /* don't change status, ignore return */
            status = edECC_deleteKey((edECCKey **) &((*ppKey)->pEdECCKey), NULL);
            if (OK != status)
                goto exit;
            /*
             the above method will set (*ppKey)->pEdECCKey to NULL,
             and the rest of key is already zero
             */
        }
    
        status = DIGI_FREE((void **) ppKey);
    }
    
    /* else status is still ERR_NULL_POINTER */
#endif
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/


MSTATUS EC_equalKeyEx(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pKey1, ECCKey *pKey2, byteBoolean *pRes)
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pKey1)
        goto exit;
    
    if (NULL != pKey1->pCurve)
        return EC_equalKey(pKey1, pKey2, pRes); /* will handle other validation */
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
        if (NULL == pKey2 || NULL == pRes)
            goto exit;  /* status still ERR_NULL_POINTER */
        
        /* check outer key's curveId */
        if (pKey1->curveId != pKey2->curveId)
        {
            *pRes = FALSE;
            status = OK;
            goto exit;
        }
        
        status = edECC_equalKey((edECCKey *) pKey1->pEdECCKey, (edECCKey *) pKey2->pEdECCKey, pRes, NULL);
    }
#endif  /* #else status is still ERR_NULL_POINTER */
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

/* sets ppCurve if curveId indicates a NIST curve, or sets pEdCurve if curveId indicates an Edward's curve */
static MSTATUS CRYPTO_getEllipticCurveFromCurveId( ubyte4 curveId, PEllipticCurvePtr *ppCurve, ubyte *pEdCurve)
{
    MSTATUS status = OK;
    
    /* internal method, NULL checks not necessary, make sure *ppCurve is NULL in case of Edward's curve */
    *ppCurve = NULL;
    
    switch (curveId)      /* curveId is also the oid suffix */
    {
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case cid_EC_P192:
            *ppCurve = EC_P192;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
        case cid_EC_P224:
            *ppCurve = EC_P224;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
        case cid_EC_P256:
            *ppCurve = EC_P256;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
        case cid_EC_P384:
            *ppCurve = EC_P384;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
        case cid_EC_P521:
            *ppCurve = EC_P521;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
        case cid_EC_X25519:
            *pEdCurve = (ubyte) curveX25519;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
        case cid_EC_X448:
            *pEdCurve = (ubyte) curveX448;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
        case cid_EC_Ed25519:
            *pEdCurve = (ubyte) curveEd25519;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
        case cid_EC_Ed448:
            *pEdCurve = (ubyte) curveEd448;
            break;
#endif
        default:
            status = ERR_EC_UNSUPPORTED_CURVE;
            break;
    }

    return status;
}


/*---------------------------------------------------------------------------*/

/* Create a new key from a curve identifier */
MSTATUS EC_newKeyEx (
    ubyte4 curveId,
    ECCKey** ppNewKey
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ECCKey* pNew = NULL;
    PEllipticCurvePtr pCurve = NULL;
    ubyte edCurve = 0;
    
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    edECCKey *pEdECCKey = NULL;
#endif
    
    if (NULL == ppNewKey)
        goto exit;
    
    status = CRYPTO_getEllipticCurveFromCurveId(curveId, &pCurve, &edCurve);
    if (OK != status)
        goto exit;
    
    if (NULL != pCurve)
    {
        status = EC_newKey(pCurve, &pNew);
    }
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else /* OK status and pCurve is NULL so must be an edwards curve */
    {
        /* do our own allocation of the outer key shell */
        status = DIGI_CALLOC((void **) &pNew, sizeof(ECCKey), 1);
        if (OK != status)
            goto exit;
        
        /* allocate the edward's key */
        status = edECC_newKey(&pEdECCKey, (edECCCurve) edCurve, NULL);
        if (OK != status)
            goto exit;
        
        pNew->pEdECCKey = (void *) pEdECCKey; pEdECCKey = NULL;
        pNew->curveId = curveId;
        
        /* rest of pNew is empty */
    }
#endif

    *ppNewKey = pNew; pNew = NULL;
    
exit:
    
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    if (NULL != pEdECCKey)
    {   /* don't change status, ignore return */
        edECC_deleteKey(&pEdECCKey, NULL);
    }
    if (NULL != pNew)
    {   /* don't change status, ignore return */
        pNew->pEdECCKey = NULL; /* rest of key is already zero */
        DIGI_FREE((void **) &pNew);
    }
#else
    if (NULL != pNew)
    {   /* don't change status, ignore return */
        EC_deleteKey(&pNew);
    }
#endif

    return status;
}

/*---------------------------------------------------------------------------*/

/* Retrieve the curve identifier from a key */
MSTATUS EC_getCurveIdFromKey (
    ECCKey *pKey,
    ubyte4 *pCurveId
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pKey || NULL == pCurveId)
        goto exit;

    if (NULL != pKey->pCurve)
    {
        *pCurveId = pKey->pCurve->pPF->curveId;
        status = OK;
    }
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
        /* need to make sure there's at least an Edward's context */
        status = ERR_EC_UNALLOCATED_KEY;
        if (NULL == pKey->pEdECCKey)
            goto exit;

        *pCurveId = pKey->curveId;
        status = OK;
    }
#endif /* #else status is still ERR_NULL_POINTER */
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

/* Get the length of an individual prime field element when represented as a bytestring */
MSTATUS EC_getElementByteStringLen (
    ECCKey *pKey,
    ubyte4 *pLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 len = 0;
    
    if (NULL == pLen || NULL == pKey)
        goto exit;

    if (NULL != pKey->pCurve)
        status = PRIMEFIELD_getElementByteStringLen(pKey->pCurve->pPF, (sbyte4 *) &len);
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
        status = edECC_getKeyLen((edECCKey *) (pKey->pEdECCKey), &len, NULL);
#endif  /* #else status is still ERR_NULL_POINTER */
    
    if (OK == status)
        *pLen = len;
exit:
    
    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS EC_getPointByteStringLenByCurveId (
    ubyte4 curveId,
    ubyte4 *pLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 len = 0;

    if (NULL == pLen)
        return status;

    status = ERR_INVALID_ARG;
    switch (curveId)
    {
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case cid_EC_P192:
            status = EC_getPointByteStringLen(EC_P192, (sbyte4*) &len);
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
        case cid_EC_P224:
            status = EC_getPointByteStringLen(EC_P224, (sbyte4*) &len);
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
        case cid_EC_P256:
            status = EC_getPointByteStringLen(EC_P256, (sbyte4*) &len);
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
        case cid_EC_P384:
            status = EC_getPointByteStringLen(EC_P384, (sbyte4*) &len);
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
        case cid_EC_P521:
            status = EC_getPointByteStringLen(EC_P521, (sbyte4*) &len);
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
        case cid_EC_X25519:
            len = MOC_CURVE25519_BYTE_SIZE;
            status = OK;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
        case cid_EC_Ed25519:
            len = MOC_CURVE25519_ENCODING_SIZE;
            status = OK;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
        case cid_EC_X448:
            len = MOC_CURVE448_BYTE_SIZE;
            status = OK;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
        case cid_EC_Ed448:
            len = MOC_CURVE448_ENCODING_SIZE;
            status = OK;
            break;
#endif
    };

    if (OK == status)
        *pLen = len;

    return status;
}

/*---------------------------------------------------------------------------*/

/*
 Get the length of a point, ie a pair of field elements, when represented
 as a bytestring. For NIST curves this is twice the element length + 1 (accounting
 for the uncompressed 0x04 leading byte). For Edwards curves points are in
 a compressed form, whose size is also that of a single element.
 */
MSTATUS EC_getPointByteStringLenEx (
    ECCKey *pKey,
    ubyte4 *pLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 len = 0;
    
    if (NULL == pLen || NULL == pKey)
        goto exit;
    
    if (NULL != pKey->pCurve)
        status = EC_getPointByteStringLen(pKey->pCurve, (sbyte4 *) &len);
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
        status = edECC_getKeyLen((edECCKey *) (pKey->pEdECCKey), &len, NULL);
#endif  /* #else status is still ERR_NULL_POINTER */
    
    if (OK == status)
        *pLen = len;
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

#ifndef __ECC_HARDWARE_ACCELERATOR__

MSTATUS EC_setKeyParametersEx( MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pKey, ubyte *pPoint, ubyte4 pointLen,
                               ubyte *pScalar, ubyte4 scalarLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pKey)
        goto exit;
    
    if (NULL != pKey->pCurve)
        status = EC_setKeyParameters(pKey, pPoint, pointLen, pScalar, scalarLen);
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
        BulkHashAlgo *pShaSuite = NULL;
        
        if (NULL == pPoint && NULL != pScalar)
        {
            switch (pKey->curveId)
            {
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
                case cid_EC_Ed25519:
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
                    status = CRYPTO_FIPS_getECCHashAlgo(ht_sha512, &pShaSuite);
#else
                    status = CRYPTO_getECCHashAlgo(ht_sha512, &pShaSuite);
#endif
                    if (OK != status)
                        goto exit;
                    
                    break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
                case cid_EC_Ed448:
                    
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
                    status = CRYPTO_FIPS_getECCHashAlgo(ht_shake256, &pShaSuite);
#else
                    status = CRYPTO_getECCHashAlgo(ht_shake256, &pShaSuite);
#endif
                    if (OK != status)
                        goto exit;
                    
                    break;
#endif
                default:  /* EDDH, keep pShaSUite NULL */
                    break;
            }
        }
        
        status = edECC_setKeyParameters( MOC_ECC(hwAccelCtx) (edECCKey *) pKey->pEdECCKey, pPoint, pointLen, pScalar, scalarLen, pShaSuite, NULL);
    }
#endif
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EC_setPrivateKeyEx( MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pKey, ubyte *pScalar, ubyte4 scalarLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pKey)
        goto exit;
    
    if (NULL != pKey->pCurve)
        status = EC_setPrivateKey(pKey, pScalar, scalarLen);
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
        /* method not supported for EdDSA, only EdDH, we use a dummy public key */
        status = ERR_EC_UNSUPPORTED_CURVE;
#ifdef __ENABLE_DIGICERT_ECC_EDDH__

        ubyte pDummyPoint[MOC_CURVE448_BYTE_SIZE] = {0};
        ubyte4 pointLen = 0;

        if (cid_EC_X25519 == pKey->curveId || cid_EC_X448 == pKey->curveId)
        {
            status = EC_getPointByteStringLenByCurveId(pKey->curveId, &pointLen);
            if (OK != status)
                goto exit;

            status = edECC_setKeyParameters(MOC_ECC(hwAccelCtx) (edECCKey *) pKey->pEdECCKey, pDummyPoint, pointLen, pScalar, scalarLen, NULL, NULL); 
        }
#endif
    }
#endif
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EC_verifyKeyPairEx (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pPrivateKey,
    ECCKey *pPublicKey,
    byteBoolean *pVfy
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    
    /* The private key must be provided */
    if ( NULL == pPrivateKey || NULL == pVfy )
        goto exit;

    *pVfy = FALSE;

    /* validate the private key consists of a valid key pair */
    if (NULL != pPrivateKey->pCurve)
        status = EC_verifyKeyPair(pPrivateKey->pCurve, pPrivateKey->k, pPrivateKey->Qx, pPrivateKey->Qy);
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
        BulkHashAlgo *pShaSuite = NULL;
        
        switch (pPrivateKey->curveId)
        {
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
            case cid_EC_Ed25519:
                
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
                status = CRYPTO_FIPS_getECCHashAlgo(ht_sha512, &pShaSuite);
#else
                status = CRYPTO_getECCHashAlgo(ht_sha512, &pShaSuite);
#endif
                if (OK != status)
                    goto exit;
                
                break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
            case cid_EC_Ed448:
                
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
                status = CRYPTO_FIPS_getECCHashAlgo(ht_shake256, &pShaSuite);
#else
                status = CRYPTO_getECCHashAlgo(ht_shake256, &pShaSuite);
#endif
                if (OK != status)
                    goto exit;
                
                break;
#endif
            default:  /* EDDH, keep pShaSUite NULL */
                break;
        }
        
        status = edECC_validateKey(MOC_ECC(hwAccelCtx) (edECCKey *) pPrivateKey->pEdECCKey, pShaSuite, NULL);
    }
#endif /* #else status is still ERR_NULL_POINTER */
    
    if (ERR_FALSE == status)
    {
        status = OK;
        goto exit;  /* pVfy is FALSE still */
    }
    else if (OK != status)
        goto exit;
    
    /* for any curve form, if a public key was passed in, also validate it is the same */
    if (NULL != pPublicKey)
    {
        byteBoolean match;
        
        status = EC_equalKeyEx(MOC_ECC(hwAccelCtx) pPrivateKey, pPublicKey, &match);
        if (OK != status || (OK == status && !match) )  /* pVfy is FALSE still */
            goto exit;
    }

    *pVfy = TRUE;
    
exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EC_verifyPublicKeyEx (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pPubKey,
    byteBoolean *pIsValid
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if ( NULL == pPubKey || NULL == pIsValid )
        goto exit;

    /* Default to false */
    *pIsValid = FALSE;

    if (NULL != pPubKey->pCurve)
        status = EC_verifyPublicKey(pPubKey->pCurve, pPubKey->Qx, pPubKey->Qy);
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else  /* no hash aglo needed for (edDSA) public key validation */
        status = edECC_validateKey(MOC_ECC(hwAccelCtx) (edECCKey *) pPubKey->pEdECCKey, NULL, NULL);
#endif /* #else status is still ERR_NULL_POINTER */
    
    if (ERR_FALSE == status)
    {
        status = OK;
        goto exit;  /* pIsValid is FALSE still */
    }
    else if (OK != status)
        goto exit;
    
    *pIsValid = TRUE;
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

/* Generate a key pair previously allocated with EC_newKeyEx */
MSTATUS EC_generateKeyPairEx (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pKey,
    RNGFun rngFun,
    void* rngArg
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        goto exit;
    
    if (NULL != pKey->pCurve)
    {
        /* rest of validation handled by the call below. */
        status = EC_generateKeyPair (pKey->pCurve, rngFun, rngArg, pKey->k, pKey->Qx, pKey->Qy);
        if (OK == status)
        {
            pKey->privateKey = TRUE;
        }
    }
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
        BulkHashAlgo *pShaSuite = NULL;
        
        switch (pKey->curveId)
        {
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
            case cid_EC_Ed25519:
                
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
                status = CRYPTO_FIPS_getECCHashAlgo(ht_sha512, &pShaSuite);
#else
                status = CRYPTO_getECCHashAlgo(ht_sha512, &pShaSuite);
#endif
                if (OK != status)
                    goto exit;
                
                break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
            case cid_EC_Ed448:
                
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
                status = CRYPTO_FIPS_getECCHashAlgo(ht_shake256, &pShaSuite);
#else
                status = CRYPTO_getECCHashAlgo(ht_shake256, &pShaSuite);
#endif
                if (OK != status)
                    goto exit;
                
                break; /* EDDH, keep pShaSUite NULL */
#endif
            default:
                break;
        }

        status = edECC_generateKeyPair(MOC_ECC(hwAccelCtx) (edECCKey *) pKey->pEdECCKey, rngFun, rngArg, pShaSuite, NULL);
    }
#endif /* #else status is still ERR_NULL_POINTER */

exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

/* Generate a key pair on the curve specified from the curve id */
MSTATUS EC_generateKeyPairAlloc (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ubyte4 curveId,
    ECCKey **ppNewKey,
    RNGFun rngFun,
    void* rngArg
    )
{
    MSTATUS status;
    
    /* Input validatation covered by the two called methods below */
    status = EC_newKeyEx(curveId, ppNewKey);
    if (OK != status)
        return status;

    status = EC_generateKeyPairEx(MOC_ECC(hwAccelCtx) *ppNewKey, rngFun, rngArg);
    if (OK != status && NULL != *ppNewKey)
    {
        EC_deleteKeyEx(ppNewKey);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

/* Write the public points to a buffer, analogous to EC_writePointToBuffer */
MSTATUS EC_writePublicKeyToBuffer (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pKey,
    ubyte *pBuffer,
    ubyte4 bufferSize
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pKey)
        goto exit;
    
    if (NULL != pKey->pCurve)
        /* rest of validation handled by the following call */
        status = EC_writePointToBuffer(pKey->pCurve, pKey->Qx, pKey->Qy, pBuffer, bufferSize);
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
        status = edECC_getPublicKey(MOC_ECC(hwAccelCtx) (edECCKey *) pKey->pEdECCKey, pBuffer, bufferSize, NULL);
#endif  /* #else status is still ERR_NULL_POINTER */
    
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

/* Same as EC_writePublicKeyToBuffer except it allocated the buffer for you */
MSTATUS EC_writePublicKeyToBufferAlloc (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pKey,
    ubyte **ppBuffer,
    ubyte4 *pBufferSize
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 len;
    ubyte *pBuffer = NULL;
    
    if (NULL == ppBuffer || NULL == pBufferSize) /* pKey validate in next call */
        goto exit;
    
    status = EC_getPointByteStringLenEx(pKey, &len);
    if (OK != status)
        goto exit;
    
    /* allocate a buffer for the point byte string */
    status = DIGI_MALLOC((void **) &pBuffer, len);
    if (OK != status)
        goto exit;

    status = EC_writePublicKeyToBuffer(MOC_ECC(hwAccelCtx) pKey, pBuffer, len);
    if (OK != status)
        goto exit;
    
    *ppBuffer = pBuffer; pBuffer = NULL;
    *pBufferSize = len;

exit:

    if (NULL != pBuffer)
    {   /* don't change status, ignore return code */
        DIGI_FREE((void **)&pBuffer);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

/* Create a new ECC public key from a raw bytestring of points x and y */
MSTATUS EC_newPublicKeyFromByteString (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ubyte4 curveId,
    ECCKey **ppNewKey,
    ubyte *pByteString,
    ubyte4 byteStringLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ECCKey *pNew = NULL;
    
    if (NULL == ppNewKey)
        goto exit;
    
    /* Rest of input validation done by the calls below */
    status = EC_newKeyEx(curveId, &pNew);
    if (OK != status)
        goto exit;

    status = EC_setKeyParametersEx(MOC_ECC(hwAccelCtx) pNew, pByteString, byteStringLen, NULL, 0);
    if (OK != status)
        goto exit;
    
    *ppNewKey = pNew; pNew = NULL;
    
exit:
    
    if( NULL != pNew)
    {
        /* don't change status, ok to ignore return */
        EC_deleteKeyEx(&pNew);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

/* Allocates and sets the appropriate keys parameters of pTemplate with
 * that from the passed in pKey. reqType should be one of
 * MOC_GET_PUBLIC_KEY_DATA or MOC_GET_PRIVATE_KEY_DATA. The latter option
 * will set both the private and public key parameters. */
MSTATUS EC_getKeyParametersAlloc (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pKey,
    MEccKeyTemplate *pTemplate,
    ubyte reqType
    )
{
    MSTATUS status = ERR_INVALID_ARG;

    ubyte *pPrivBytes = NULL;
    ubyte4 privLen = 0;

    ubyte *pPubBytes = NULL;
    ubyte4 pubLen = 0;

    /* Must have the proper key type flag defined */
    if ( (MOC_GET_PUBLIC_KEY_DATA  != reqType) &&
        (MOC_GET_PRIVATE_KEY_DATA != reqType) )
        goto exit;
    
    status = ERR_NULL_POINTER;
    if (NULL == pKey || NULL == pTemplate)
        goto exit;

    if (NULL != pKey->pCurve)
    {
        if (MOC_GET_PRIVATE_KEY_DATA == reqType)
        {
            status = PRIMEFIELD_getAsByteString(pKey->pCurve->pPF, pKey->k, &pPrivBytes, (sbyte4 *) &privLen);
            if (OK != status)
                goto exit;
        }
        
        status = EC_pointToByteString (pKey->pCurve, pKey->Qx, pKey->Qy, &pPubBytes, (sbyte4 *) &pubLen);
    }
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
        if (MOC_GET_PRIVATE_KEY_DATA == reqType)
            status = edECC_getKeyParametersAlloc(MOC_ECC(hwAccelCtx) (edECCKey *) pKey->pEdECCKey, &pPubBytes, &pubLen, &pPrivBytes, &privLen, NULL);
        else
            status = edECC_getKeyParametersAlloc(MOC_ECC(hwAccelCtx) (edECCKey *) pKey->pEdECCKey, &pPubBytes, &pubLen, NULL, NULL, NULL);
    }
#endif /* #else status is still ERR_NULL_POINTER */
    if (OK != status)
        goto exit;
    
    /* no errors, set all template paramters (even if pPrivBytes is NULL) */
    pTemplate->pPrivateKey = pPrivBytes;
    pTemplate->privateKeyLen = privLen;
    pPrivBytes = NULL;
    
    pTemplate->pPublicKey = pPubBytes;
    pTemplate->publicKeyLen = pubLen;
    pPubBytes = NULL;
    
exit:

    /* Only on error will any of these not be NULL. Don't change status */
    if (NULL != pPrivBytes)
    {
        DIGI_MEMSET(pPrivBytes, 0x00, privLen);
        DIGI_FREE((void **) &pPrivBytes);
    }

    if (NULL != pPubBytes)
    {
        DIGI_MEMSET(pPubBytes, 0x00, pubLen);
        DIGI_FREE((void **) &pPubBytes);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EdDSA_signInput (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pKey,
    ubyte *pInput,
    ubyte4 inputLen,
    byteBoolean isPreHash,
    ubyte *pCtx,
    ubyte4 ctxLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen,
    void *pExtCtx
)
{
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    MSTATUS status = ERR_NULL_POINTER;
    BulkHashAlgo *pShaSuite = NULL;

    if (NULL == pKey || NULL == pKey->pEdECCKey)
        goto exit;
        
    if (cid_EC_Ed25519 == pKey->curveId)
    {
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
        status = CRYPTO_FIPS_getECCHashAlgo(ht_sha512, &pShaSuite);
#else
        status = CRYPTO_getECCHashAlgo(ht_sha512, &pShaSuite);
#endif
    }
    else if (cid_EC_Ed448 == pKey->curveId)
    {
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
        status = CRYPTO_FIPS_getECCHashAlgo(ht_shake256, &pShaSuite);
#else
        status = CRYPTO_getECCHashAlgo(ht_shake256, &pShaSuite);
#endif
    }
    else
    {
        status = ERR_EC_UNSUPPORTED_CURVE;
    }
    if (OK != status)
        goto exit;
        
    status = edDSA_Sign(MOC_ECC(hwAccelCtx) (edECCKey *) pKey->pEdECCKey, pInput, inputLen, pSignature, bufferSize, pSignatureLen, pShaSuite, isPreHash, pCtx, ctxLen, pExtCtx);

exit:
    
    return status;
#else
    return ERR_NOT_IMPLEMENTED;
#endif
}

/*---------------------------------------------------------------------------*/

MSTATUS EdDSA_verifyInput (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pKey,
    ubyte *pInput,
    ubyte4 inputLen,
    byteBoolean isPreHash,
    ubyte *pCtx,
    ubyte4 ctxLen,
    ubyte *pSignature,
    ubyte4 signatureLen,
    ubyte4 *pVerifyFailures,
    void *pExtCtx
    )
{
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    MSTATUS status = ERR_NULL_POINTER;
    BulkHashAlgo *pShaSuite = NULL;

    if (NULL == pKey || NULL == pInput || NULL == pSignature || NULL == pKey->pEdECCKey)
        goto exit;

    if (cid_EC_Ed25519 == pKey->curveId)
    {
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
        status = CRYPTO_FIPS_getECCHashAlgo(ht_sha512, &pShaSuite);
#else
        status = CRYPTO_getECCHashAlgo(ht_sha512, &pShaSuite);
#endif
    }
    else if (cid_EC_Ed448 == pKey->curveId)
    {
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
        status = CRYPTO_FIPS_getECCHashAlgo(ht_shake256, &pShaSuite);
#else
        status = CRYPTO_getECCHashAlgo(ht_shake256, &pShaSuite);
#endif
    }
    else
    {
        status = ERR_EC_UNSUPPORTED_CURVE;
    }
    if (OK != status)
        goto exit;

    status = edDSA_VerifySignature(MOC_ECC(hwAccelCtx) pKey->pEdECCKey, pInput, inputLen,
                                   pSignature, signatureLen, pVerifyFailures, pShaSuite,
                                   isPreHash, pCtx, ctxLen, pExtCtx);

exit:
    
    return status;
#else
    return ERR_NOT_IMPLEMENTED;
#endif
}

/*---------------------------------------------------------------------------*/

/* Produces concatenation of r and s as big endian bytestrings, zero padded
 * if necessary to ensure each bytestring is exactly element length. */
MSTATUS ECDSA_signDigest (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pKey,
    RNGFun rngFun,
    void* rngArg,
    ubyte *pHash,
    ubyte4 hashLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen
    )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;

    PFEPtr r = NULL;
    PFEPtr s = NULL;
    sbyte4 elementLen;

    if (NULL == pKey || NULL == rngFun || NULL == pHash ||
        NULL == pSignatureLen)
    {
        return ERR_NULL_POINTER;
    }

#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    if (NULL != pKey->pEdECCKey && NULL == pKey->pCurve)
        return ERR_NOT_IMPLEMENTED;
#endif
    
    if (NULL == pKey->pCurve || NULL == pKey->k)
        return ERR_NULL_POINTER;
    
    if (!(pKey->privateKey))
        return ERR_EC_INVALID_KEY_TYPE;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECDSA,0);

    /* get the element byte length, OK to ignore return code */
    PRIMEFIELD_getElementByteStringLen(pKey->pCurve->pPF, &elementLen);

    /* Ensure the output buffer is large enough, if it is not large enough
     * then write the output length and return an error indicating that
     * the buffer was too small */
    if (bufferSize < (ubyte4)(elementLen * 2) || NULL == pSignature)
    {
        *pSignatureLen = (elementLen * 2);
        return ERR_BUFFER_TOO_SMALL;
    }

    /* Reset in case of error */
    *pSignatureLen = 0;

    status = PRIMEFIELD_newElement(pKey->pCurve->pPF, &r);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pKey->pCurve->pPF, &s);
    if (OK != status)
        goto exit;

    status = ECDSA_signDigestAux (
        pKey->pCurve, pKey->k, rngFun, rngArg, pHash, hashLen, r, s);
    if (OK != status)
        goto exit;

    /* write r and s in Big Endian. Ok to ignore return codes */
    PRIMEFIELD_writeByteString (pKey->pCurve->pPF, r, pSignature, elementLen);
    PRIMEFIELD_writeByteString (
        pKey->pCurve->pPF, s, pSignature + elementLen, elementLen);

    *pSignatureLen = (elementLen * 2);

exit:

    if (NULL != r)
    {
        PRIMEFIELD_deleteElement(pKey->pCurve->pPF, &r);
    }
    if (NULL != s)
    {
        PRIMEFIELD_deleteElement(pKey->pCurve->pPF, &s);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_ECDSA,0);
    return status;
}

/*---------------------------------------------------------------------------*/

/* Verify signature in raw form, which is simply the signature values r and s
 * as individual big endian bytestrings */
MSTATUS ECDSA_verifySignatureDigest (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pPublicKey,
    ubyte *pHash,
    ubyte4 hashLen,
    ubyte *pR,
    ubyte4 rLen,
    ubyte *pS,
    ubyte4 sLen,
    ubyte4 *pVerifyFailures
    )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    PFEPtr r = NULL;
    PFEPtr s = NULL;

    sbyte4 elementLen;

    if (NULL == pPublicKey || NULL == pHash || NULL == pR || NULL == pS ||
        NULL == pVerifyFailures)
    {
        return ERR_NULL_POINTER;
    }

#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    if (NULL != pPublicKey->pEdECCKey && NULL == pPublicKey->pCurve)
        return ERR_NOT_IMPLEMENTED;
#endif
    
    if (NULL == pPublicKey->pCurve || NULL == pPublicKey->Qx || NULL == pPublicKey->Qy)
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECDSA,0);

    *pVerifyFailures = 1; /* set to false by default */

    /* get the element byte length, OK to ignore return code */
    PRIMEFIELD_getElementByteStringLen(pPublicKey->pCurve->pPF, &elementLen);

    status = PRIMEFIELD_newElement(pPublicKey->pCurve->pPF, &r);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pPublicKey->pCurve->pPF, &s);
    if (OK != status)
        goto exit;

    /* create the primefield element representation of r */
    status = PRIMEFIELD_setToByteString (
        pPublicKey->pCurve->pPF, r, pR, rLen);
    if (OK != status)
    {
        /* treat ERR_FF_DIFFERENT_FIELDS as a verify failure */
        if (ERR_FF_DIFFERENT_FIELDS == status)
            status = OK;

        goto exit;
    }

    /* create the primefield element representation of s */
    status = PRIMEFIELD_setToByteString (
        pPublicKey->pCurve->pPF, s, pS, sLen);
    if (OK != status)
    {
        /* treat ERR_FF_DIFFERENT_FIELDS as a verify failure */
        if (ERR_FF_DIFFERENT_FIELDS == status)
            status = OK;

        goto exit;
    }

    status = ECDSA_verifySignature (
        pPublicKey->pCurve, pPublicKey->Qx, pPublicKey->Qy, pHash, hashLen, r, s);
    if (OK == status)
        *pVerifyFailures = 0;
    else if (status == ERR_FALSE)
        status = OK; /* but *pVerifyFailures is still 1 */

exit:

    if (NULL != r)
    {
        PRIMEFIELD_deleteElement(pPublicKey->pCurve->pPF, &r);
    }
    if (NULL != s)
    {
        PRIMEFIELD_deleteElement(pPublicKey->pCurve->pPF, &s);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_ECDSA,0);
    return status;
}

/*---------------------------------------------------------------------------*/

/* Generate an ECDH shared secret from a public and private key. */
MSTATUS ECDH_generateSharedSecretFromKeys (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pPrivateKey,
    ECCKey *pPublicKey,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen,
    sbyte4 flag,
    void *pKdfInfo
    )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pRawSSBuffer = NULL;
    ubyte4 rawSSlen = 0;
    MOC_UNUSED(pKdfInfo);

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECDH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECDH,0);

    if (NULL == pPrivateKey || NULL == pPublicKey || NULL == ppSharedSecret || NULL == pSharedSecretLen)
        goto exit;
    
    if (NULL != pPrivateKey->pCurve)
    {
        if (NULL == pPublicKey->pCurve || NULL == pPublicKey->Qx || NULL == pPublicKey->Qy || NULL == pPrivateKey->k)
            goto exit;
        
        status = ERR_EC_INVALID_KEY_TYPE;
        if (!(pPrivateKey->privateKey))
            goto exit;
        
        status = ERR_EC_DIFFERENT_CURVE;
        if (pPrivateKey->pCurve != pPublicKey->pCurve)
            goto exit;
        
        status = ECDH_generateSharedSecretAux (pPublicKey->pCurve, pPublicKey->Qx, pPublicKey->Qy, pPrivateKey->k,
                                               &pRawSSBuffer, (sbyte4 *) &rawSSlen, flag);
        if (OK != status)
            goto exit;
    }
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
#ifdef __ENABLE_DIGICERT_ECC_EDDH__
        ubyte4 pubLen;
        
        if (NULL == pPrivateKey->pEdECCKey || NULL == pPublicKey->pEdECCKey)
            goto exit;  /* status still ERR_NULL_POINTER */
        
        status = ERR_EC_UNSUPPORTED_CURVE;  /* must be an edDH curve */
        if (cid_EC_X448 != pPrivateKey->curveId && cid_EC_X25519 != pPrivateKey->curveId)
            goto exit;
        
        status = ERR_EC_DIFFERENT_CURVE;   /* must be the same curve */
        if (pPrivateKey->curveId != pPublicKey->curveId)
            goto exit;
 
        /*
         For efficiency we'll reach inside pPublicKey to validate and then use
         the public key, rather than calling get public key methods to copy it over
         */
        status = ERR_EC_INVALID_KEY_TYPE;
        if (((edECCKey *) pPublicKey->pEdECCKey)->isPrivate)
            goto exit;
        
        status = EC_getElementByteStringLen(pPublicKey, &pubLen);
        if (OK != status)
            goto exit;

        status = edDH_GenerateSharedSecret(MOC_ECC(hwAccelCtx) (edECCKey *) pPrivateKey->pEdECCKey, ((edECCKey *) pPublicKey->pEdECCKey)->pPubKey, pubLen,
                                           &pRawSSBuffer, &rawSSlen, NULL);
        if (OK != status)
            goto exit;
#else
        status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDH__ */
        
    }
#endif /* __ENABLE_DIGICERT_ECC_ED_COMMON__ #else status still ERR_NULL_POINTER */
    
    *ppSharedSecret = pRawSSBuffer; pRawSSBuffer = NULL;
    *pSharedSecretLen = rawSSlen;

exit:
    
    if (NULL != pRawSSBuffer)
    {
        DIGI_MEMSET(pRawSSBuffer, 0x00, rawSSlen);
        DIGI_FREE((void **)&pRawSSBuffer);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_ECDH,0);
    return status;
}

/*---------------------------------------------------------------------------*/

/* Generate an ECDH shared secret from private key and bytestring
   representation of the public point.
 */
MSTATUS ECDH_generateSharedSecretFromPublicByteString (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pPrivateKey,
    ubyte *pPublicPointByteString,
    ubyte4 pointByteStringLen,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen,
    sbyte4 flag,
    void *pKdfInfo
    )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status, fstatus;
    ubyte4 curveId;

    ECCKey *pPubKey = NULL;

    /* All input parameter validation is handled by the below called methods */
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECDH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECDH,curveId);

    status = EC_getCurveIdFromKey(pPrivateKey, &curveId);
    if (OK != status)
        goto exit;

    status = EC_newPublicKeyFromByteString ( MOC_ECC(hwAccelCtx)
        curveId, &pPubKey, pPublicPointByteString, pointByteStringLen);
    if (OK != status)
        goto exit;

    status = ECDH_generateSharedSecretFromKeys ( MOC_ECC(hwAccelCtx)
        pPrivateKey, pPubKey, ppSharedSecret, pSharedSecretLen, flag, pKdfInfo);

exit:

    if (NULL != pPubKey)
    {
        fstatus = EC_deleteKeyEx(&pPubKey);
        if (OK == status)
            status = fstatus;
    }
    
    FIPS_LOG_END_ALG(FIPS_ALGO_ECDH,curveId);
    return status;
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECDH_MODES__
MSTATUS ECDH_keyAgreementScheme(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ubyte4 mode, 
    ECCKey *pStatic, 
    ECCKey *pEphemeral, 
    ubyte *pOtherPartysStatic, 
    ubyte4 otherStaticLen,
    ubyte *pOtherPartysEphemeral,
    ubyte4 otherEphemeralLen,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen)
{
    /* not available for Edward's curves */
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    if ( (NULL != pStatic && NULL != pStatic->pEdECCKey && NULL == pStatic->pCurve) || 
         (NULL != pEphemeral && NULL != pEphemeral->pEdECCKey && NULL == pEphemeral->pCurve) )
        return ERR_NOT_IMPLEMENTED;
#endif

    return ECDH_keyAgreementSchemePrimeCurve(mode, pStatic, pEphemeral, pOtherPartysStatic, otherStaticLen, 
                                             pOtherPartysEphemeral, otherEphemeralLen, ppSharedSecret, pSharedSecretLen);
}
#endif

/*---------------------------------------------------------------------------*/

MSTATUS ECDSA_signMessage (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pPrivateKey,
    RNGFun rngFun,
    void *pRngArg,
    ubyte hashAlgo,
    ubyte *pMessage,
    ubyte4 messageLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen,
    void *pExtCtx
    )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    MSTATUS fstatus = OK;
    ubyte *pDigest = NULL;
    ubyte4 digestLen = 0;
    BulkHashAlgo *pShaSuite = NULL;
    BulkCtx pShaCtx = NULL; /* used in the prime curve flow only */
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECDSA,0);

    if (NULL == pPrivateKey)
        goto exit;
    
    if (NULL != pPrivateKey->pCurve)
    {
        if (NULL == pMessage && messageLen)
            goto exit;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
        status = CRYPTO_FIPS_getECCHashAlgo(hashAlgo, &pShaSuite);
#else
        status = CRYPTO_getECCHashAlgo(hashAlgo, &pShaSuite);
#endif
        if (OK != status)
            goto exit;
        
        /*
         another special case, for ht_none message will just be copied
         up to the max digest size stored in pShaSuite->digestSize
         */
        if (ht_none != hashAlgo)
            digestLen = pShaSuite->digestSize;
        else
            digestLen = messageLen < pShaSuite->digestSize ? messageLen : pShaSuite->digestSize;
            
        /* allocate memory for the resulting digest */
        
        status = DIGI_MALLOC((void **) &pDigest, digestLen);
        if (OK != status)
            goto exit;
        
        status = pShaSuite->allocFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
        if (OK != status)
            goto exit;
        
        status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
        if (OK != status)
            goto exit;
        
        if (messageLen)
        {
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pMessage, messageLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->finalFunc(MOC_HASH(hwAccelCtx) pShaCtx, pDigest);
        if (OK != status)
            goto exit;
        
        status = ECDSA_signDigest(MOC_ECC(hwAccelCtx) pPrivateKey, rngFun, pRngArg, pDigest, digestLen, pSignature, bufferSize, pSignatureLen);
    }
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
        
        if (NULL == pPrivateKey->pEdECCKey)
            goto exit;  /* status still ERR_NULL_POINTER */

        /* Ignore the hashAlgo passed in. edDSA hashes are fixed to the curve */
        
        if (cid_EC_Ed25519 == pPrivateKey->curveId)
        {
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
            status = CRYPTO_FIPS_getECCHashAlgo(ht_sha512, &pShaSuite);
#else
            status = CRYPTO_getECCHashAlgo(ht_sha512, &pShaSuite);
#endif
        }
        else if (cid_EC_Ed448 == pPrivateKey->curveId)
        {
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
            status = CRYPTO_FIPS_getECCHashAlgo(ht_shake256, &pShaSuite);
#else
            status = CRYPTO_getECCHashAlgo(ht_shake256, &pShaSuite);
#endif
        }
        else
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
        }
        if (OK != status)
            goto exit;
        
        status = edDSA_Sign(MOC_ECC(hwAccelCtx) (edECCKey *) pPrivateKey->pEdECCKey, pMessage, messageLen, pSignature, bufferSize, pSignatureLen, pShaSuite, FALSE, NULL, 0, pExtCtx);
#else
        status = ERR_NOT_IMPLEMENTED;
#endif
    }
#endif /* __ENABLE_DIGICERT_ECC_ED_COMMON__ #else status still ERR_NULL_POINTER */
    
exit:
    
    if (NULL != pShaCtx && NULL != pShaSuite)
    {
        /* we will check status of sha sha free function */
        fstatus = pShaSuite->freeFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
        if (OK == status)
            status = fstatus;
    }
    
    if (NULL != pDigest)
    {   /* don't change status, no need to check return codes */
        DIGI_MEMSET(pDigest, 0x00, digestLen);
        DIGI_FREE((void **) &pDigest);
    }
    
    FIPS_LOG_END_ALG(FIPS_ALGO_ECDSA,0);
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS ECDSA_verifyMessage (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pPublicKey,
    ubyte hashAlgo,
    ubyte *pMessage,
    ubyte4 messageLen,
    ubyte *pSignature,
    ubyte4 signatureLen,
    ubyte4 *pVerifyFailures,
    void *pExtCtx
    )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    MSTATUS fstatus = OK;
    ECDSA_CTX dsaCtx = {0};
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECDSA,0);

    /* below methods will handle input validation */
    status = ECDSA_initVerify(MOC_ECC(hwAccelCtx) &dsaCtx, pPublicKey, hashAlgo, pSignature, signatureLen, pExtCtx);
    if (OK != status)
        goto exit;
    
    status = ECDSA_updateVerify(MOC_ECC(hwAccelCtx) &dsaCtx, pMessage, messageLen, pExtCtx);

exit:
    
    /* whether error or not, EC_finalVerify will free memory allocated on init */
    fstatus = ECDSA_finalVerify(MOC_ECC(hwAccelCtx) &dsaCtx, pVerifyFailures, pExtCtx);
    if (OK == status)
        status = fstatus;
    
    FIPS_LOG_END_ALG(FIPS_ALGO_ECDSA,0);
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS ECDSA_initVerify (
   MOC_ECC(hwAccelDescr hwAccelCtx)
   ECDSA_CTX *pCtx,
   ECCKey *pPublicKey,
   ubyte hashAlgo,
   ubyte *pSignature,
   ubyte4 signatureLen,
   void *pExtCtx
   )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    ECCKey *pNewKey = NULL;
    BulkHashAlgo *pShaSuite = NULL;
    BulkCtx pShaCtx = NULL; /* used in the prime curve flow only */
    ubyte *pSigCopy = NULL; /* used in the prime curve flow only */

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECDSA,0);

    if (NULL == pCtx || NULL == pPublicKey || NULL == pSignature)
        goto exit;

    status = ERR_ECDSA_INVALID_SIGNATURE_SIZE;
    if (!signatureLen || signatureLen & 0x01)  /* quick sanity check on the signature, must be even */
        goto exit;

    /* Make a copy of the key for the ECDSA_CTX */
    status = EC_cloneKeyEx(MOC_ECC(hwAccelCtx) &pNewKey, pPublicKey);
    if (OK != status)
        goto exit;

    if (NULL != pNewKey->pCurve)
    {
        status = ERR_ECDSA_ALREADY_INITIALIZED_CTX;
        if (pCtx->ecDSA_CTX.initialized)
            goto exit;
        
        /* Get the hash algorithm, alloc and init */
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
        status = CRYPTO_FIPS_getECCHashAlgo(hashAlgo, &pShaSuite);
#else
        status = CRYPTO_getECCHashAlgo(hashAlgo, &pShaSuite);
#endif
        if (OK != status)
            goto exit;
        
        status = pShaSuite->allocFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
        if (OK != status)
            goto exit;
        
        status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
        if (OK != status)
            goto exit;
        
        /* also copy in the signature to the ecDSA_CTX */
        status = DIGI_MALLOC((void **) &pSigCopy, signatureLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_MEMCPY(pSigCopy, pSignature, signatureLen);
        if (OK != status)
            goto exit;
    
        /* No errors, set ecDSA ctx */
        pCtx->ecDSA_CTX.pSignature = pSigCopy; pSigCopy = NULL;
        pCtx->ecDSA_CTX.signatureLen = signatureLen;
        pCtx->ecDSA_CTX.pShaCtx = pShaCtx;     pShaCtx = NULL;
        pCtx->ecDSA_CTX.pShaSuite = pShaSuite;
        pCtx->ecDSA_CTX.initialized = TRUE;
        pCtx->ecDSA_CTX.isNoHash = (ht_none == hashAlgo) ? TRUE : FALSE;
        pCtx->ecDSA_CTX.messageLen = 0;
    }
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
        
        /* Ignore the hashAlgo passed in. edDSA hashes are fixed to the curve */
        if (cid_EC_Ed25519 == pNewKey->curveId)
        {
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
            status = CRYPTO_FIPS_getECCHashAlgo(ht_sha512, &pShaSuite);
#else
            status = CRYPTO_getECCHashAlgo(ht_sha512, &pShaSuite);
#endif
        }
        else if (cid_EC_Ed448 == pNewKey->curveId)
        {
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
            status = CRYPTO_FIPS_getECCHashAlgo(ht_shake256, &pShaSuite);
#else
            status = CRYPTO_getECCHashAlgo(ht_shake256, &pShaSuite);
#endif
        }
        else
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
        }
        if (OK != status)
            goto exit;

        status = edDSA_initVerify(MOC_ECC(hwAccelCtx) &(pCtx->edDSA_CTX), (edECCKey *) pNewKey->pEdECCKey, pSignature, signatureLen, pShaSuite, FALSE, NULL, 0, pExtCtx);
#else
        status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA__ */
    }
#else
    else
        status = ERR_NULL_POINTER;
#endif /* __ENABLE_DIGICERT_ECC_ED_COMMON__ */

    if (OK == status)
    {
        pCtx->pKey = pNewKey;
        pNewKey = NULL;
    }
    
exit:
    
    if (NULL != pNewKey)
    {   /* don't change status, ok to ignore return */
        EC_deleteKeyEx(&pNewKey);
    }
    
    if (NULL != pSigCopy)
    {   /* don't change status, ok to ignore return */
        DIGI_MEMSET(pSigCopy, 0x00, signatureLen);
        DIGI_FREE((void **) &pSigCopy);
    }
    
    if (NULL != pShaCtx && NULL != pShaSuite)
    {
        /* we will check status of sha sha free function */
        (void) pShaSuite->freeFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
    }
    
    FIPS_LOG_END_ALG(FIPS_ALGO_ECDSA,0);
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS ECDSA_updateVerify (
   MOC_ECC(hwAccelDescr hwAccelCtx)
   ECDSA_CTX *pCtx,
   ubyte *pMessage,
   ubyte4 messageLen,
   void *pExtCtx
   )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECDSA,0);

    if (NULL == pCtx || NULL == pCtx->pKey)
        goto exit;
    
    if (NULL != pCtx->pKey->pCurve)
    {
        if (NULL == pMessage && messageLen)
            goto exit;
        
        status = ERR_ECDSA_UNINITIALIZED_CTX;
        if (!pCtx->ecDSA_CTX.initialized || NULL == pCtx->ecDSA_CTX.pShaSuite) /* sanity check */
            goto exit;
        
        if ( messageLen )
            status = pCtx->ecDSA_CTX.pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pCtx->ecDSA_CTX.pShaCtx, pMessage, messageLen);
        else
            status = OK;
        
        if( OK == status && pCtx->ecDSA_CTX.isNoHash )
            pCtx->ecDSA_CTX.messageLen += messageLen;
    }
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
        status = edDSA_update(MOC_ECC(hwAccelCtx) &(pCtx->edDSA_CTX), pMessage, messageLen, pExtCtx);
#else
        status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA__ */
    }
#endif /* __ENABLE_DIGICERT_ECC_ED_COMMON__ #else status still ERR_NULL_POINTER */
    
exit:
    
    FIPS_LOG_END_ALG(FIPS_ALGO_ECDSA,0);
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS ECDSA_finalVerify (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECDSA_CTX *pCtx,
    ubyte4 *pVerifyFailures,
    void *pExtCtx
    )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_ECDSA_UNINITIALIZED_CTX;
    MSTATUS fstatus = OK;
    ubyte *pDigest = NULL;
    ubyte4 digestLen = 0;
    ubyte4 rsLen = 0;
    
    /* return now on these firt errors, so exit block can assume these are not NULL */
    if (NULL == pCtx || NULL == pCtx->pKey)
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_ECDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_ECDSA,0);

    if (NULL != pCtx->pKey->pCurve)
    {
        if (!pCtx->ecDSA_CTX.initialized || NULL == pCtx->ecDSA_CTX.pShaSuite) /* sanity check */
            goto exit;
        
        /* special case, for ht_none message was copied and we kept track of its length */
        if (pCtx->ecDSA_CTX.isNoHash)
            digestLen = pCtx->ecDSA_CTX.messageLen;
        else
            digestLen = pCtx->ecDSA_CTX.pShaSuite->digestSize;
        
        rsLen = (pCtx->ecDSA_CTX.signatureLen >> 1);  /* signatureLen checked to be even on init call */
        
        /* allocate memory for the resulting digest */
        
        status = DIGI_MALLOC((void **) &pDigest, digestLen);
        if (OK != status)
            goto exit;
        
        status = pCtx->ecDSA_CTX.pShaSuite->finalFunc(MOC_HASH(hwAccelCtx) pCtx->ecDSA_CTX.pShaCtx, pDigest);
        if (OK != status)
            goto exit;
        
        status = ECDSA_verifySignatureDigest(MOC_ECC(hwAccelCtx) pCtx->pKey, pDigest, digestLen, pCtx->ecDSA_CTX.pSignature, rsLen, pCtx->ecDSA_CTX.pSignature + rsLen, rsLen, pVerifyFailures);
    }
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
    else
    {
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
        status = edDSA_finalVerify(MOC_ECC(hwAccelCtx) &(pCtx->edDSA_CTX), pVerifyFailures, pExtCtx);
#else
        status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA__ */
    }
#endif /* __ENABLE_DIGICERT_ECC_ED_COMMON__ #else status still ERR_NULL_POINTER */

exit:

    /* whether error or not, if using an ecDSA_CTX we need to clean it up */
    if (NULL != pCtx->pKey->pCurve)
    {
        if (NULL != pCtx->ecDSA_CTX.pSignature)
        {   /* ok to ignore return codes here and not change status */
            DIGI_MEMSET(pCtx->ecDSA_CTX.pSignature, 0x00, pCtx->ecDSA_CTX.signatureLen);
            DIGI_FREE((void **) &pCtx->ecDSA_CTX.pSignature);
        }

        if (NULL != pCtx->ecDSA_CTX.pShaSuite && NULL != pCtx->ecDSA_CTX.pShaCtx)
        {   /* we do check the return of the freeFunc */
            fstatus = pCtx->ecDSA_CTX.pShaSuite->freeFunc(MOC_HASH(hwAccelCtx) &(pCtx->ecDSA_CTX.pShaCtx));
            if (OK == status)
                status = fstatus;
        }

        if (NULL != pDigest) /* ok to be within this if statement, only ever allocated in the prime curve case */
        {
            DIGI_MEMSET(pDigest, 0x00, digestLen);
            DIGI_FREE((void **) &pDigest);
        }
    }

    /* and final cleanup is to delete our copy of the key */
    fstatus = EC_deleteKeyEx(&pCtx->pKey);
    if (OK == status)
        fstatus = status;

    /* ok to ignore return code, pCtx is not NULL, this will set initialized flags to FALSE  */
    DIGI_MEMSET((ubyte *) pCtx, 0x00, sizeof(ECDSA_CTX));

    FIPS_LOG_END_ALG(FIPS_ALGO_ECDSA,0);
    return status;
}

#endif /* __ECC_HARDWARE_ACCELERATOR__ */

/*---------------------------------------------------------------------------*/

/* Frees the key parameters of the passed in pTemplate */
MSTATUS EC_freeKeyTemplate (
    ECCKey *pKey,
    MEccKeyTemplate *pTemplate
    )
{
    MSTATUS status = OK;
    
    /* We still need the key parameter for the crypto interface */
    MOC_UNUSED(pKey);
    
    if (NULL == pTemplate)
        goto exit;  /* Like RSA we'll allow NULL to be an OK no-op */
    
    if (NULL != pTemplate->pPrivateKey)
    {
        status = DIGI_MEMSET(pTemplate->pPrivateKey, 0x00, pTemplate->privateKeyLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_FREE((void **) &pTemplate->pPrivateKey);
        if (OK != status)
            goto exit;
        
        pTemplate->privateKeyLen = 0;
    }
    
    if (NULL != pTemplate->pPublicKey)
    {
        status = DIGI_MEMSET(pTemplate->pPublicKey, 0x00, pTemplate->publicKeyLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_FREE((void **) &pTemplate->pPublicKey);
        if (OK != status)
            goto exit;
        
        pTemplate->publicKeyLen = 0;
    }
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS EC_createCombMutexes()
{
    MSTATUS status = OK;
    
#if !defined(__DISABLE_DIGICERT_SIGNED_ODD_COMB__) && defined(__ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__)
    status = EC_createPrimeCurveMutexes();
    if (OK != status)
        return status;
#endif

#ifndef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
    
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
    status = CURVE25519_createCombMutex();
    if (OK != status)
        return status;
#endif
    
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
    status = CURVE448_createCombMutex();
#endif
    
#endif /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */
    
    return status;
}

MOC_EXTERN MSTATUS EC_deleteAllCombsAndMutexes()
{
    MSTATUS status = OK;
    
#if !defined(__DISABLE_DIGICERT_SIGNED_ODD_COMB__) && defined(__ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__)
    status = EC_deletePrimeCurveCombsAndMutexes();
#endif
    
#ifndef __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__
    
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
    {
        MSTATUS fstatus = CURVE25519_deleteCombAndMutex();
        if (OK == status)
            status = fstatus;
    }
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
    {
        MSTATUS fstatus = CURVE448_deleteCombAndMutex();
        if (OK == status)
            status = fstatus;
    }
#endif
    
#endif /* __ENABLE_DIGICERT_EDWARDS_GLOBAL_CONSTANTS__ */
    
    return status;
}
#endif /* __ENABLE_DIGICERT_ECC__ */
