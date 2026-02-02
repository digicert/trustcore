/*
 * ecc_edwards_keys.c
 *
 * Methods related to Edward's form ECC keys.
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

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_ECC__

#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include "../crypto/ecc_edwards.h"
#include "../crypto/ecc_edwards_keys.h"
#include "../crypto/ecc_edwards_dsa.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

#define CURVE25519_GENERATOR 9
#define CURVE448_GENERATOR 5

#endif /* __ENABLE_DIGICERT_ECC_ED_COMMON__ */

/******************************************************************************************/

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
static int eddsa_fail = 0;

FIPS_TESTLOG_IMPORT;
#endif

/*
 Validates whether the sha suite has the appropriate EVP methods or one shot methods for
 the curve given
 */
static MSTATUS edDSA_validateShaSuite(BulkHashAlgo *pShaSuite, edECCCurve curve, byteBoolean *pIsShaEvp)
{
    if (NULL == pShaSuite || NULL == pIsShaEvp)
        return ERR_NULL_POINTER;
    
    *pIsShaEvp = TRUE;
    
    /* Check for a valid sha suite */
    if (NULL == pShaSuite->allocFunc || NULL == pShaSuite->initFunc || NULL == pShaSuite->updateFunc || NULL == pShaSuite->freeFunc ||
        (NULL == pShaSuite->finalFunc && curveEd25519 == curve) || (NULL == pShaSuite->finalXOFFunc && curveEd448 == curve))
    {
        /* sha evp methods are not available. Check to see if we can do a one shot digest mode */
        if ( (NULL == pShaSuite->digestFunc && curveEd25519 == curve) || (NULL == pShaSuite->digestXOFFunc && curveEd448 == curve))
            return ERR_EC_INVALID_HASH_ALGO;
        else
            *pIsShaEvp = FALSE;
    }
    
    return OK;
}
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__

/*
 Hashes the private value pPriv and does the elliptic curve scalar-point
 multiply to calculate the public key pResultPub. pPriv must be 32 bytes in
 length and pResultPub must have room for 32 bytes.
 */
static MSTATUS edDSA_curve25519_calculatePubFromPriv(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte *pResultPub, ubyte *pPrivKey, BulkHashAlgo *pShaSuite, byteBoolean isShaEvp)
{
    MSTATUS status;
    
    /* sha ctx if isShaEvp is true */
    void *pShaCtx = NULL;
    
    ubyte pHash[MOC_EDDSA_SHA512_LEN] = {0};
    
    projPoint25519 *pPoint = NULL;
    
    /* internal method, NULL checks already done */
    
    /* Allocate space for a projPoint25519 */
    status = DIGI_CALLOC((void **)&pPoint, 1, sizeof(projPoint25519));
    if (OK != status)
        return status;
    
    /* Section 5.1.5 Step 1 */
    if (isShaEvp)
    {
        status = pShaSuite->allocFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
        if (OK != status)
            goto exit;
        
        status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
        if (OK != status)
            goto exit;
        
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pPrivKey, MOC_CURVE25519_ENCODING_SIZE);
        if (OK != status)
            goto exit;
        
        status = pShaSuite->finalFunc(MOC_HASH(hwAccelCtx) pShaCtx, pHash);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = pShaSuite->digestFunc(MOC_HASH(hwAccelCtx) pPrivKey, MOC_CURVE25519_ENCODING_SIZE, pHash);
        if (OK != status)
            goto exit;
    }
    
    /* 5.1.5 Step 2, prune the buffer  */
    pHash[0] &= 0xf8;  /* set the lowest 3 bits to 0 */
    pHash[MOC_CURVE25519_ENCODING_SIZE-1] &= 0x7f; /* set the highest bit to 0 */
    pHash[MOC_CURVE25519_ENCODING_SIZE-1] |= 0x40; /* second highest bit (2^254) to one */
    
    /* 5.1.5 Step 3, pass in NULL to indicate multiplication by the cyclic group generator B */
    status = CURVE25519_multiplyPoint(MOC_ECC(hwAccelCtx) pPoint, pHash, NULL);
    if (OK != status)
        goto exit;
    
    /* 5.1.5 Step 4 */
    status = CURVE25519_convertProjectiveToEncoded(pResultPub, pPoint);
    
exit:
    
    /* Don't change status on below calls */
    DIGI_MEMSET(pHash, 0x00, MOC_EDDSA_SHA512_LEN);
    
    if (NULL != pShaCtx)
    {
        pShaSuite->freeFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
    }
    
    if (NULL != pPoint)
    {
        DIGI_MEMSET( (ubyte *) pPoint, 0x00, sizeof(projPoint25519));
        DIGI_FREE((void **) &pPoint);
    }
    
    return status;
}


#endif /* __ENABLE_DIGICERT_ECC_EDDSA_25519__ */

/******************************************************************************************/

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__

/*
 Hashes the private value pPriv and does the elliptic curve scalar-point
 multiply to calculate the public key pResultPub. pPriv must be 57 bytes in
 length and pResultPub must have room for 57 bytes.
 */
static MSTATUS edDSA_curve448_calculatePubFromPriv(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte *pResultPub, ubyte *pPrivKey, BulkHashAlgo *pShaSuite, byteBoolean isShaEvp)
{
    MSTATUS status;
    
    /* sha ctx if isShaEvp is true */
    void *pShaCtx = NULL;

    ubyte pHash[MOC_EDDSA_SHAKE256_LEN] = {0};
    
    projPoint448 *pPoint = NULL;
    
    /* internal method, NULL checks already done */
    
    /* Allocate space for a projPoint448 */
    status = DIGI_CALLOC((void **)&pPoint, 1, sizeof(projPoint448));
    if (OK != status)
        return status;
    
    /* Section 5.2.5 Step 1 */
    if (isShaEvp)
    {
        status = pShaSuite->allocFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
        if (OK != status)
            goto exit;
        
        status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
        if (OK != status)
            goto exit;
        
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pPrivKey, MOC_CURVE448_ENCODING_SIZE);
        if (OK != status)
            goto exit;
        
        status = pShaSuite->finalXOFFunc(MOC_HASH(hwAccelCtx) pShaCtx, pHash, MOC_EDDSA_SHAKE256_LEN);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = pShaSuite->digestXOFFunc(MOC_HASH(hwAccelCtx) pPrivKey, MOC_CURVE448_ENCODING_SIZE, pHash, MOC_EDDSA_SHAKE256_LEN);
        if (OK != status)
            goto exit;
    }
    
    /* 5.2.5 Step 2, prune the buffer  */
    pHash[0] &= 0xfc;  /* set the lowest 2 bits to 0 */
    pHash[MOC_CURVE448_ENCODING_SIZE-1] = 0x00; /* set the highest byte to 0 */
    pHash[MOC_CURVE448_ENCODING_SIZE-2] |= 0x80; /* second highest bit (2^447) to one */
    
    /* 5.2.5 Step 3, pHasH has 57th byte 0x00 so proper padding for the comb multiply is used */
    status = CURVE448_multiplyPoint(MOC_ECC(hwAccelCtx) pPoint, pHash, NULL);
    if (OK != status)
        goto exit;
    
    /* 5.2.5 Step 4 */
    status = CURVE448_convertProjectiveToEncoded(pResultPub, pPoint);
    
exit:
    
    /* Don't change status on below calls */
    DIGI_MEMSET(pHash, 0x00, MOC_EDDSA_SHAKE256_LEN);
    
    if (NULL != pShaCtx)
    {
        pShaSuite->freeFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
    }
    
    if (NULL != pPoint)
    {
        DIGI_MEMSET( (ubyte *) pPoint, 0x00, sizeof(projPoint448));
        DIGI_FREE((void **) &pPoint);
    }
    
    return status;
}

#endif /* __ENABLE_DIGICERT_ECC_EDDSA_448__ */

/******************************************************************************************/

#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__

/* internal helper function for getting the keyLength from the curve */
static MSTATUS edECC_curveToKeyLen(edECCCurve curve, ubyte4 *pKeyLen)
{
    MSTATUS status = OK;
    
    /* internal method, NULL check not necessary */
    
    switch(curve)
    {
        case curveX25519:
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
            *pKeyLen = MOC_CURVE25519_BYTE_SIZE;     /* 32 */
#else
            status = ERR_NOT_IMPLEMENTED;
#endif
            break;
            
        case curveEd25519:
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
            *pKeyLen = MOC_CURVE25519_ENCODING_SIZE; /* 32 */
#else
            status = ERR_NOT_IMPLEMENTED;
#endif
            break;
            
        case curveX448:
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
            *pKeyLen = MOC_CURVE448_BYTE_SIZE;       /* 56 */
#else
            status = ERR_NOT_IMPLEMENTED;
#endif
            break;
            
        case curveEd448:
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
            *pKeyLen = MOC_CURVE448_ENCODING_SIZE;   /* 57 */
#else
            status = ERR_NOT_IMPLEMENTED;
#endif
            break;
            
        default:
            status = ERR_EC_UNSUPPORTED_CURVE;
            break;
    }

    return status;
}


/*
 Allocates memory for a new key. The buffers for the fields pPrivKey and pPubKey
 are allocated at the end of the key struct (analogous to primeec's newKey method).
 */
MSTATUS edECC_newKey(edECCKey **ppKey, edECCCurve curve, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte4 keyLen;
    
    edECCKey *pNew = NULL;
  
    MOC_UNUSED(pExtCtx);

    if (NULL == ppKey)
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,curve);

    status = edECC_curveToKeyLen(curve, &keyLen);
    if (OK != status)
        goto exit;
    
    /* allocate all the storage in one block */
    status = DIGI_CALLOC( (void **) &pNew, sizeof(edECCKey) + 2 * keyLen, 1);
    if (OK != status)
        goto exit;
    
    pNew->pPrivKey = ((ubyte *) pNew) + sizeof(edECCKey);
    pNew->pPubKey = ((ubyte *) pNew) + sizeof(edECCKey) + keyLen;
    pNew->isPrivate = FALSE; /* Default to FALSE */
    pNew->curve = curve;
    
exit:
    /* set the key, even if NULL on error */
    *ppKey = pNew;
    
    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,curve);
    return status;
}


/*
 Computes the key length in bytes of the key given.
 Note public and private keys are the same length for Edwards curves.
 */
MSTATUS edECC_getKeyLen(edECCKey *pKey, ubyte4 *pKeyLen, void *pExtCtx)
{
    if (NULL == pKey || NULL == pKeyLen)
        return ERR_NULL_POINTER;

    MOC_UNUSED(pExtCtx);

    return edECC_curveToKeyLen(pKey->curve, pKeyLen);
}


/* compares the public key only to see if the keys match */
MSTATUS edECC_equalKey(edECCKey *pKey1, edECCKey *pKey2, byteBoolean *pMatch, void *pExtCtx)
{
    MSTATUS status = OK;
    ubyte4 keyLen;
    sbyte4 compare;
    
    if (NULL == pKey1 || NULL == pKey2 || NULL == pMatch)
        return ERR_NULL_POINTER;
    
    *pMatch = FALSE; /* default */
    
    if (pKey1->curve != pKey2->curve)
        goto exit;  /* status OK but pMatch is FALSE */

    status = edECC_getKeyLen(pKey1, &keyLen, pExtCtx);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCMP(pKey1->pPubKey, pKey2->pPubKey, keyLen, &compare);
    if (OK != status)
        goto exit;
    
    if (!compare)
        *pMatch = TRUE;
    
exit:
    
    return status;
}


/* compares the public key only to see if the keys match */
MSTATUS edECC_cloneKey(edECCKey **ppNew, edECCKey *pSrc, void *pExtCtx)
{
    MSTATUS status = OK;
    ubyte4 keyLen;
    edECCKey *pNew = NULL;
    
    if (NULL == ppNew || NULL == pSrc)
        return ERR_NULL_POINTER;

    status = edECC_getKeyLen(pSrc, &keyLen, pExtCtx);
    if (OK != status)
        goto exit;
    
    status = edECC_newKey(&pNew, pSrc->curve, pExtCtx);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCPY(pNew->pPubKey, pSrc->pPubKey, keyLen);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCPY(pNew->pPrivKey, pSrc->pPrivKey, keyLen);
    if (OK != status)
        goto exit;
    
    pNew->isPrivate = pSrc->isPrivate;
    
    *ppNew = pNew; pNew = NULL;
    
exit:
    
    if (NULL != pNew)
    {
        /* don't alter status, ok to not check return code */
        edECC_deleteKey(&pNew, pExtCtx);
    }
    
    return status;
}


/*
 Internal helper method to calculate the public key from the private key for any curve.
 It is up to the caller to make sure pPub and pPriv must be the correct length in
 bytes for the curve passed in.
 
 IMPORTANT: pPub must be initially zero'd out (for edDH at least).
 */
MSTATUS edECC_calculatePubFromPriv(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte *pPub, ubyte *pPriv, edECCCurve curve, BulkHashAlgo *pShaSuite, byteBoolean isShaEvp)
{
    MSTATUS status;
    
    /* internal method, NULL checks not necc */
    
#if !defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) && !defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
    MOC_UNUSED(pShaSuite);
    MOC_UNUSED(isShaEvp);
#endif
    
    switch (curve)
    {
        case curveX25519:
            
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
            /* set the public key to the u-coord of the curve generator, ie 9 */
            pPub[0] = CURVE25519_GENERATOR;
            
            /* call X25519, inplace op is ok */
            status = CURVE25519_X25519(MOC_ECC(hwAccelCtx) pPub, pPriv, pPub);
#else
            status = ERR_NOT_IMPLEMENTED;
#endif
            break;
            
        case curveEd25519:
            
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
            status = edDSA_curve25519_calculatePubFromPriv(MOC_ECC(hwAccelCtx) pPub, pPriv, pShaSuite, isShaEvp);
#else
            status = ERR_NOT_IMPLEMENTED;
#endif
            break;
            
        case curveX448:
            
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
            /* set the public key to the u-coord of the curve generator, ie 9 */
            pPub[0] = CURVE448_GENERATOR;
            
            /* call X25519, inplace op is ok */
            status = CURVE448_X448(MOC_ECC(hwAccelCtx) pPub, pPriv, pPub);
#else
            status = ERR_NOT_IMPLEMENTED;
#endif
            break;
            
        case curveEd448:
            
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
            status = edDSA_curve448_calculatePubFromPriv(MOC_ECC(hwAccelCtx) pPub, pPriv, pShaSuite, isShaEvp);
#else
            status = ERR_NOT_IMPLEMENTED;
#endif
            break;
            
        default:
            
            status = ERR_EC_UNSUPPORTED_CURVE;
            
    }
    
    return status;
}

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#ifdef __ENABLE_DIGICERT_FIPS_EDDSA__
extern MSTATUS
edECC_generateKey_FIPS_consistency_test(edECCKey *pKey, BulkHashAlgo *pShaSuite)
{
    sbyte4  msgLen = 15;
    ubyte   msg[] = {
        'C', 'L', 'E', 'A', 'R', '_', 'T', 'E', 'X', 'T', '_', 'L', 'I', 'N', 'E'
    };
    ubyte pSignature[57*2] = {0};
    ubyte4 signatureLen;
    MSTATUS status = OK;
    ubyte4 verifyStatus  = 0;

    if(OK > (status = edDSA_Sign(pKey, msg, msgLen, pSignature,
        sizeof(pSignature), &signatureLen, pShaSuite, FALSE, NULL, 0, NULL)))
    {
        goto exit;
    }

    if ( 1 == eddsa_fail )
    {
        pSignature[0] ^= 0x783F;
    }
    eddsa_fail = 0;

    pKey->isPrivate = FALSE;
    status = edDSA_VerifySignature(pKey, msg, msgLen, pSignature,
        signatureLen, &verifyStatus, pShaSuite, FALSE, NULL, 0, NULL);
    if (OK != status)
    {
        goto exit;
    }

    if (0 == verifyStatus)
        FIPS_TESTLOG(1020, "edECC_generateKey_FIPS_consistancy_test: GOOD Signature Verify!" );

exit:
    if (0 != verifyStatus)
    {
        status = ERR_FIPS_EDDSA_SIGN_VERIFY_FAIL;
        setFIPS_Status(FIPS_ALGO_EDDSA,status);
    }

    pKey->isPrivate = TRUE;
    return status;

} /* edECC_generateKey_FIPS_consistency_test */
#endif /* __ENABLE_DIGICERT_FIPS_EDDSA__ */
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/*
 For edDSA generates a key pair as per the specs in Section 5.1.5 for curve25519 or 5.2.5 for curve448.
 For edDH generates a key pair as per the specs in Section 5 of RFC 7748. The private key is just random
 data, which is hashed for edDSA only, and then it is pruned before doing a point multiply to get the public key.
 pShaSuite is unused and should be NULL for edDH. pKey must have already been allocated.
 */
MSTATUS edECC_generateKeyPair(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, RNGFun rngFun, void *pRngArg, BulkHashAlgo *pShaSuite, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    byteBoolean isShaEvp = TRUE;
    ubyte4 keyLen;
    
    if (NULL == pKey || NULL == rngFun)
        return ERR_NULL_POINTER;

    if (NULL == pKey->pPrivKey || NULL == pKey->pPubKey)
        return ERR_EC_UNALLOCATED_KEY;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,pKey->curve);

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    /* if edDSA validate the pShaSuite */
    if (curveEd448 == pKey->curve || curveEd25519 == pKey->curve)
    {
        status = edDSA_validateShaSuite(pShaSuite, pKey->curve, &isShaEvp);
        if (OK != status)
            goto exit;
    }
#endif
    
    /* we get the length now but ignore the return since edECC_newKey will also validate the curve */
    status = edECC_getKeyLen(pKey, &keyLen, pExtCtx);
    if (OK != status)
        goto exit;

    /* generate a random private key */
    status = (MSTATUS) rngFun(pRngArg, keyLen, pKey->pPrivKey);
    if (OK != status)
        goto exit;
    
    status = edECC_calculatePubFromPriv(MOC_ECC(hwAccelCtx) pKey->pPubKey, pKey->pPrivKey, pKey->curve, pShaSuite, isShaEvp);
    if (OK != status)
        goto exit;

    pKey->isPrivate = TRUE;

exit:
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#ifdef __ENABLE_DIGICERT_FIPS_EDDSA__

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    if (curveEd448 == pKey->curve || curveEd25519 == pKey->curve)
    {
        status = edECC_generateKey_FIPS_consistency_test(pKey, pShaSuite);
    }
#endif
#endif /* __ENABLE_DIGICERT_FIPS_EDDSA__ */
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,pKey->curve);
    return status;
}


/*
 Sets the public key and/or the private key in an already allocated edECCKey.
 NULL may be passed in for the private key or the public key. If the public key
 is NULL for a private key then the public key will be calculated.
 
 For DSA the input buffers represent the keys in an Edward's encoded form, ie a
 Little Endian bytewise value for the private key, and a Little Endian bytewise
 coordinate y for the public key with a single high bit on the end representing x.
 
 For DH the input buffer pPrivKey represents a pruned scaler in Little Endian form.
 (see section 5 of RFC 7748 for what pruned means for each curve (same defn as RFC 8032)).
 The input buffer pPubKey represents a u-coordinate of the Montgomery form curve
 in Little Endian.
 
 This method does not validate the key pair if both a private key and public key are passed in.
 */
MSTATUS edECC_setKeyParameters(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, ubyte *pPubKey, ubyte4 pubKeyLen, ubyte *pPrivKey, ubyte4 privKeyLen, BulkHashAlgo *pShaSuite, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte4 keyLen;
    byteBoolean isShaEvp = TRUE;

    if (NULL == pKey || (NULL == pPubKey && NULL == pPrivKey) || (NULL == pPubKey && pubKeyLen) || (NULL == pPrivKey && privKeyLen) )
        return ERR_NULL_POINTER;

    if (NULL == pKey->pPrivKey || NULL == pKey->pPubKey)
        return ERR_EC_UNALLOCATED_KEY;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,pKey->curve);
    
    status = edECC_getKeyLen(pKey, &keyLen, pExtCtx);
    if (OK != status)
        goto exit;
    
    if ((NULL != pPubKey && keyLen != pubKeyLen) || (NULL != pPrivKey && keyLen != privKeyLen) )
        return ERR_EDECC_INVALID_KEY_LENGTH;
    
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    /* if edDSA and no public key then we need the pShaSuite */
    if ( NULL == pPubKey && (curveEd448 == pKey->curve || curveEd25519 == pKey->curve) )
    {
        status = edDSA_validateShaSuite(pShaSuite, pKey->curve, &isShaEvp);
        if (OK != status)
            goto exit;
    }
#endif

    if (NULL != pPrivKey)
    {
        pKey->isPrivate = TRUE;
        DIGI_MEMCPY(pKey->pPrivKey, pPrivKey, keyLen); /* ok to ignore return status */
    }
    else
    {
        pKey->isPrivate = FALSE;
        DIGI_MEMSET(pKey->pPrivKey, 0x00, keyLen); /* ok to ignore return status */
    }
    
    /* Set the public key or generate it! */
    if (NULL != pPubKey)
    {
        status = DIGI_MEMCPY(pKey->pPubKey, pPubKey, keyLen);
    }
    else
    {
        status = edECC_calculatePubFromPriv(MOC_ECC(hwAccelCtx) pKey->pPubKey, pKey->pPrivKey, pKey->curve, pShaSuite, isShaEvp);
    }

exit:
    
    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,pKey->curve);
    return status;
}


/*
 Allocates a buffer for the public key and fills it with the key in the encoded form.
 If pKey is a private key and ppPrivKey is also not NULL, then that will also be allocated
 and filled in the private key (in standard Big Endian form).
 */
MSTATUS edECC_getKeyParametersAlloc(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, ubyte **ppPubKey, ubyte4 *pPubLen, ubyte **ppPrivKey, ubyte4 *pPrivLen, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte4 keyLen;
    ubyte *pPubBytes = NULL;
    ubyte *pPrivBytes = NULL;

    if (NULL == pKey || NULL == ppPubKey || NULL == pPubLen)
        return ERR_NULL_POINTER;

    if (NULL == pKey->pPubKey)
        return ERR_EC_UNALLOCATED_KEY;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,pKey->curve);
    
    status = edECC_getKeyLen(pKey, &keyLen, pExtCtx);
    if (OK != status)
        goto exit;
    
    status = DIGI_MALLOC((void **) &pPubBytes, keyLen);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCPY(pPubBytes, pKey->pPubKey, keyLen);
    if (OK != status)
        goto exit;
    
    if (pKey->isPrivate && NULL != ppPrivKey)
    {
        status = ERR_NULL_POINTER;
        if (NULL == pPrivLen)
            goto exit;
        
        /* sanity check for the private key too */
        status = ERR_EC_UNALLOCATED_KEY;
        if (NULL == pKey->pPrivKey)
            goto exit;
        
        status = DIGI_MALLOC((void **) &pPrivBytes, keyLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_MEMCPY(pPrivBytes, pKey->pPrivKey, keyLen);
        if (OK != status)
            goto exit;
        
        *ppPrivKey = pPrivBytes; pPrivBytes = NULL;
        *pPrivLen = keyLen;
    }
    
    *ppPubKey = pPubBytes; pPubBytes = NULL;
    *pPubLen = keyLen;

exit:
    
    if (NULL != pPubBytes)
    {   /* don't change status, ok to ignore return codes */
        DIGI_MEMSET(pPubBytes, 0x00, keyLen);
        DIGI_FREE((void **) &pPubBytes);
    }
    if (NULL != pPrivBytes)
    {
        DIGI_MEMSET(pPrivBytes, 0x00, keyLen);
        DIGI_FREE((void **) &pPrivBytes);
    }
    
    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,pKey->curve);
    return status;
}


/*
 For a private key we validate the the public key is the correct value with respect to the
 private key. For an edDSA public key we validate that it consists of a properly encoded
 point on the curve. For an edDH public key any value is valid so we always return OK.
 */
MSTATUS edECC_validateKey(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, BulkHashAlgo *pShaSuite, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    if (NULL == pKey)
        return ERR_NULL_POINTER;

    if ( NULL == pKey->pPubKey || (pKey->isPrivate && NULL == pKey->pPrivKey) )
        return ERR_EC_UNALLOCATED_KEY;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,pKey->curve);
    
    if (pKey->isPrivate)
    {
        byteBoolean isShaEvp = TRUE;
        ubyte4 keyLen;
        ubyte pPubCompare[MOC_CURVE448_ENCODING_SIZE] = {0}; /* 57, big enough for all forms of public keys */
        sbyte4 compare;
        
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
        /* if edDSA validate the pShaSuite */
        if (curveEd448 == pKey->curve || curveEd25519 == pKey->curve)
        {
            status = edDSA_validateShaSuite(pShaSuite, pKey->curve, &isShaEvp);
            if (OK != status)
                goto exit;
        }
#endif
        status = edECC_getKeyLen(pKey, &keyLen, pExtCtx);
        if (OK != status)
            goto exit;
        
        status = edECC_calculatePubFromPriv(MOC_ECC(hwAccelCtx) pPubCompare, pKey->pPrivKey, pKey->curve, pShaSuite, isShaEvp);
        if (OK != status)
            goto exit;
        
        status = DIGI_MEMCMP(pPubCompare, pKey->pPubKey, keyLen, &compare);
        if (OK != status)
            goto exit;
        
        if (compare)
            status = ERR_FALSE;
        
        /* zero memory, don't change status, ok to not check return code */
        DIGI_MEMSET(pPubCompare, 0x00, keyLen);
    }
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
    else if (curveEd25519 == pKey->curve)
    {
        projPoint25519 *pPoint = NULL;
        
        /* Allocate space for a projPoint25519 */
        status = DIGI_CALLOC((void **)&pPoint, 1, sizeof(projPoint25519));
        if (OK != status)
            goto exit;
        
        status = CURVE25519_convertEncodedToProjective(pPoint, pKey->pPubKey);
        if (ERR_NOT_FOUND == status)
        {
            status = ERR_FALSE;
        }
        
        /* Don't change status on clearing memory */
        DIGI_MEMSET((ubyte *) pPoint, 0x00, sizeof(projPoint25519));
        DIGI_FREE((void **) &pPoint);
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
    else if (curveEd448 == pKey->curve)
    {
        projPoint448 *pPoint = NULL;
        
        /* Allocate space for a projPoint25519 */
        status = DIGI_CALLOC((void **)&pPoint, 1, sizeof(projPoint448));
        if (OK != status)
            goto exit;
        
         status = CURVE448_convertEncodedToProjective(pPoint, pKey->pPubKey);
        if (ERR_NOT_FOUND == status)
        {
            status = ERR_FALSE;
        }
        
        /* Don't change status on clearing memory */
        DIGI_MEMSET((ubyte *) pPoint, 0x00, sizeof(projPoint448));
        DIGI_FREE((void **) &pPoint);
    }
#endif
    
exit:
    
    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,pKey->curve);
    return status;
}


/* Fills a buffer with the public key as a Little Endian byte array. */
MSTATUS edECC_getPublicKey(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, ubyte *pOutBuffer, ubyte4 bufferLen, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte4 keyLen;

    if (NULL == pKey || NULL == pOutBuffer)
        return ERR_NULL_POINTER;

    if (NULL == pKey->pPubKey)
        return ERR_EC_UNALLOCATED_KEY;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,pKey->curve);
    
    status = edECC_getKeyLen(pKey, &keyLen, pExtCtx);
    if (OK != status)
        goto exit;
    
    if (keyLen > bufferLen)
        return ERR_BUFFER_OVERFLOW;
    
    status = DIGI_MEMCPY(pOutBuffer, pKey->pPubKey, keyLen);

exit:
    
    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,pKey->curve);
    return status;
}


/* zeros and frees memory associated with an edECCKey */
MSTATUS edECC_deleteKey(edECCKey **ppKey, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte4 keyLen = 0;
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif

    if (NULL == ppKey)
        return ERR_NULL_POINTER;

    if (NULL == *ppKey)
        return ERR_EC_UNALLOCATED_KEY;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,0);
  
    status = edECC_getKeyLen(*ppKey, &keyLen, pExtCtx);
    if (OK != status)
        goto exit;
    
#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nedECC - Before Zeroization\n");
        for( counter = 0; counter < (sizeof(edECCKey) + 2*keyLen); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ppKey+counter));
        }
        FIPS_PRINT("\n");
#endif

    /* zero out the entire key and buffer for pPrivKey and pPubKey */
    status = DIGI_MEMSET((ubyte *) *ppKey, 0x00, sizeof(edECCKey) + 2*keyLen);
    if (OK != status)
        goto exit;
    
#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nedECC - After Zeroization\n");
        for( counter = 0; counter < (sizeof(edECCKey) + 2*keyLen); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ppKey+counter));
        }
        FIPS_PRINT("\n");
#endif

    status = DIGI_FREE((void **) ppKey);
    
exit:
    
    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,0);
    return status;
}

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/ecc_edwards_keys_priv.h"

static void EDDSA_triggerFail(void)
{
    eddsa_fail = 1;
}

static FIPS_entry_fct eddsa_table[] = {
    { EDDSA_TRIGGER_FAIL_F_ID,     (s_fct*)EDDSA_triggerFail},
    { -1, NULL } /* End of array */
};

MOC_EXTERN const FIPS_entry_fct* EDDSA_getPrivileged()
{
    if (OK == FIPS_isTestMode())
        return eddsa_table;

    return NULL;
}

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */
#endif /* __ENABLE_DIGICERT_ECC_EDDSA__ */

#endif /* __ENABLE_DIGICERT_ECC_ED_COMMON__ */
#endif /* __ENABLE_DIGICERT_ECC__ */
