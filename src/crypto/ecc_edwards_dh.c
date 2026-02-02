/*
 * ecc_edwards_dh.c
 *
 * Methods to do Edward's Form Diffie-Hellman.
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

#if defined(__ENABLE_DIGICERT_ECC__) && ( defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__) )

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"

#include "../crypto/ecc_edwards.h"
#include "../crypto/ecc_edwards_dh.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

/*
 Allocates a buffer and generates a shared secret from our private key and another party's public key.
 The contents of pSharedSecretLen will be the length of the buffer allocated, and the contents of ppSharedSecret
 will be the buffer. This will be the raw shared secret (ie a Little Endian u-coordinate on the Montgomery form
 curve) as specified in RFC 7748.
 */
MSTATUS edDH_GenerateSharedSecret(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pPrivateKey, ubyte *pOtherPartysPublicKey, ubyte4 publicKeyLen,
                                  ubyte **ppSharedSecret, ubyte4 *pSharedSecretLen, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    ubyte *pSS = NULL;
    ubyte4 keyAndSSLen = 0;
    ubyte4 i;
  
    MOC_UNUSED(pExtCtx);

    if (NULL == pPrivateKey || NULL == pOtherPartysPublicKey || NULL == ppSharedSecret || NULL == pSharedSecretLen)
        return ERR_NULL_POINTER;
    
    if (!pPrivateKey->isPrivate)
        return ERR_EC_INVALID_KEY_TYPE;

    if (NULL == pPrivateKey->pPrivKey)
        return ERR_EC_UNALLOCATED_KEY;

    switch (pPrivateKey->curve)
    {
        case curveX25519:
            keyAndSSLen = MOC_CURVE25519_BYTE_SIZE;
            break;
            
        case curveX448:
            keyAndSSLen = MOC_CURVE448_BYTE_SIZE;
            break;
            
        default:
            status = ERR_EDECC_INVALID_CURVE_ID_FOR_ALG;
            goto exit;
    }
    
    if (publicKeyLen != keyAndSSLen)
        return ERR_EDECC_INVALID_KEY_LENGTH;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDH,pPrivateKey->curve);
    
    /* set to NULL in case we error */
    *ppSharedSecret = NULL;
    *pSharedSecretLen = 0;

    /* Allocate space for the shared secret */
    status = DIGI_CALLOC((void **)&pSS, keyAndSSLen, 1);
    if (OK != status)
        goto exit;
    
    switch(pPrivateKey->curve)
    {
        case curveX25519:
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
            status = CURVE25519_X25519(MOC_ECC(hwAccelCtx) pSS, pPrivateKey->pPrivKey, pOtherPartysPublicKey);
#else
            status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDH_25519__ */
            break;
            
        case curveX448:
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
            status = CURVE448_X448(MOC_ECC(hwAccelCtx) pSS, pPrivateKey->pPrivKey, pOtherPartysPublicKey);
#else
            status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDH_448__ */
            break;
            
        default:
            status = ERR_EDECC_INVALID_CURVE_ID_FOR_ALG;
    }
    
exit:

    if (OK == status)
    {
        ubyte temp = 0x00;
        
        /* Test for an all zero shared secret by OR-ing all bytes of pSS */
        for (i = 0; i < keyAndSSLen; ++i)
        {
            temp |= pSS[i];
        }
        if (!temp)
        {
            status = ERR_EDDH_ZERO_SECRET;
        }
        else
        {
            *ppSharedSecret = pSS;
            *pSharedSecretLen = keyAndSSLen;
        }
    }
    
    if (OK != status && NULL != pSS)
    {
        DIGI_MEMSET(pSS, 0x00, keyAndSSLen);
        DIGI_FREE((void **)&pSS);
    }
    
    FIPS_LOG_END_ALG(FIPS_ALGO_EDDH,pPrivateKey->curve);
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_ECC__) && ( defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__) ) */
