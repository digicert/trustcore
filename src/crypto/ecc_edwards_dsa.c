/*
 * ecc_edwards_dsa.c
 *
 * Methods to do Edward's Form Digital Signature Algorithm.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_EDDSA_INTERNAL__

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_ECC__

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"

#include "../crypto/ecc_edwards.h"
#include "../crypto/ecc_edwards_dsa.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__

/*
 Big Endian bytewise large cyclic group order L
 This constant is not accessed within a large iteration loop so ok to just keep global version.
 */
static const ubyte gpLbytes25519[MOC_CURVE25519_BYTE_SIZE] =
{
    0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x14,0xDE,0xF9,0xDE,0xA2,0xF7,0x9C,0xD6,0x58,0x12,0x63,0x1A,0x5C,0xF5,0xD3,0xED
};

/*
 dom2(F,C) as in section 2, ASCII for "SigEd25519 no Ed25519 collisions" followed by F as an octet,
 OLEN(C) as an octet, and then C. */
static const ubyte pSigEd25519[32] =
{
    0x53,0x69,0x67,0x45,0x64,0x32,0x35,0x35,0x31,0x39,0x20,0x6e,0x6f,0x20,0x45,0x64,
    0x32,0x35,0x35,0x31,0x39,0x20,0x63,0x6f,0x6c,0x6c,0x69,0x73,0x69,0x6f,0x6e,0x73
};

/*
 Reduces in place a Little Endian buffer mod L (the curve's large cyclic group order).
 pBuffer should be 64 bytes in length. ppL can be NULL and will be allocated with the
 value L, or it can be passed in already as L. ppResult will be allocated and set to
 the correct answer. Also, the first 32 bytes of pBuffer will be overwritten with the
 Little Endian byte form of ppResult. We don't use Barrett reduction since the value
 in pBuffer is likely bigger than L^2.
 
 Please be sure to freeVlong on ppL and ppResult.
 */
static MSTATUS reduceByteBufferByL25519(ubyte *pBuffer, vlong **ppResult, vlong **ppL)
{
    MSTATUS status;
    int i;
    
    vlong *pBufferValue = NULL;
    vlong *pUnusedQuotient = NULL;
    
    sbyte4 retBufLen = MOC_CURVE25519_BYTE_SIZE;
    
    /* set to NULL in case we error */
    *ppResult = NULL;
    
    /* Put pBuffer in Big Endian */
    for(i = 0; i < MOC_EDDSA_SHA512_LEN/2; ++i)
    {
        /* swap using xor */
        pBuffer[i] = pBuffer[i] ^ pBuffer[MOC_EDDSA_SHA512_LEN - 1 - i];
        pBuffer[MOC_EDDSA_SHA512_LEN - 1 - i] = pBuffer[MOC_EDDSA_SHA512_LEN - 1 - i] ^ pBuffer[i];
        pBuffer[i] = pBuffer[i] ^ pBuffer[MOC_EDDSA_SHA512_LEN - 1 - i];
    }
    
    /* Make it a vlong */
    status = VLONG_vlongFromByteString (pBuffer, MOC_EDDSA_SHA512_LEN, &pBufferValue, NULL);
    if (OK != status)
        goto exit;
    
    /* if not already defined, make L a vlong */
    if (NULL == *ppL)
    {
        status = VLONG_vlongFromByteString (gpLbytes25519, MOC_CURVE25519_BYTE_SIZE, ppL, NULL);
        if (OK != status)
            goto exit;
    }
    
    /* allocate space for an unused quotient, and remainder of pBuffer divided by L */
    status = VLONG_allocVlong(&pUnusedQuotient, NULL);
    if (OK != status)
        goto exit;
    
    status = VLONG_allocVlong(ppResult, NULL);
    if (OK != status)
        goto exit;
    
#ifdef __ENABLE_DIGICERT_64_BIT__
    status = VLONG_reallocVlong (pUnusedQuotient, (MOC_CURVE25519_BYTE_SIZE/8) + 1);
    if (OK != status)
        goto exit;
    
    status = VLONG_reallocVlong (*ppResult, (MOC_CURVE25519_BYTE_SIZE/8));
    if (OK != status)
        goto exit;
#else
    status = VLONG_reallocVlong (pUnusedQuotient, (MOC_CURVE25519_BYTE_SIZE/4) + 1);
    if (OK != status)
        goto exit;
    
    status = VLONG_reallocVlong (*ppResult, (MOC_CURVE25519_BYTE_SIZE/4));
    if (OK != status)
        goto exit;
#endif
    
    /* compute pResult = pBufferValue mod L, the quotient is not needed */
    status = VLONG_unsignedDivide (pUnusedQuotient, pBufferValue, *ppL, *ppResult, NULL);
    if (OK != status)
        goto exit;
    
    /* now get pResult back as a byte string, re-use the first 32 bytes of pBuffer*/
    status = VLONG_byteStringFromVlong (*ppResult, pBuffer, &retBufLen);
    if (OK != status)
        goto exit;
    
    /* convert to Little Endian */
    for(i = 0; i < MOC_CURVE25519_BYTE_SIZE/2; ++i)
    {
        pBuffer[i] = pBuffer[i] ^ pBuffer[MOC_CURVE25519_BYTE_SIZE - 1 - i];
        pBuffer[MOC_CURVE25519_BYTE_SIZE - 1 - i] = pBuffer[MOC_CURVE25519_BYTE_SIZE - 1 - i] ^ pBuffer[i];
        pBuffer[i] = pBuffer[i] ^ pBuffer[MOC_CURVE25519_BYTE_SIZE - 1 - i];
    }
    
exit:
    
    if (OK != status)
    {
        /* Free pResult and pL on error */
        if (NULL != *ppResult)
        {
            VLONG_freeVlong(ppResult, NULL);
        }
        if (NULL != *ppL)
        {
            VLONG_freeVlong(ppL, NULL);
        }
    }
    
    if (NULL != pBufferValue)
    {
        VLONG_freeVlong(&pBufferValue, NULL);
    }
    if (NULL != pUnusedQuotient)
    {
        VLONG_freeVlong(&pUnusedQuotient, NULL);
    }
    
    return status;
}



/*
 Internal sign method for edDSA on curve25519.
 
 pPrivKey, pPubKey must be MOC_CURVE25519_ENCODING_SIZE bytes long (ie 32)
 pSignature must have already been allocated to 2*MOC_CURVE25519_ENCODING_SIZE bytes (ie 64).
 */
static MSTATUS edDSA_curve25519_sign(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte *pPrivKey, ubyte *pPubKey, ubyte *pMessage, ubyte4 messageLen,
                                     ubyte *pSignature, BulkHashAlgo *pShaSuite, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, byteBoolean isShaEvp)
{
    MSTATUS status;
    int i;
    
    /* sha ctx if isShaEvp is true */
    void *pShaCtx = NULL;
    /* Buffer for complete sha input if isShaEvp is false */
    ubyte *pShaInput = NULL;
    
    ubyte pHash[MOC_EDDSA_SHA512_LEN] = {0};
    ubyte pHash2[MOC_EDDSA_SHA512_LEN] = {0};
    ubyte ps[MOC_CURVE25519_ENCODING_SIZE] = {0};

    ubyte pPreHash[MOC_EDDSA_SHA512_LEN] = {0};
    ubyte pFlags[2] = {0};
    ubyte4 domLen = 0;

    vlong *pVlong_r = NULL;
    vlong *pVlong_s = NULL;
    vlong *pVlong_k = NULL;
    vlong *pVlong_S = NULL;
    vlong *pVlong_L = NULL;
    sbyte4 Slen = MOC_CURVE25519_ENCODING_SIZE;
    
    projPoint25519 *pR = NULL;

    /* internal method, NULL checks already done */

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__
    ubyte pPubKeyCalc[MOC_CURVE25519_ENCODING_SIZE];

    MOC_UNUSED(pPubKey);

    status = edECC_calculatePubFromPriv(MOC_ECC(hwAccelCtx) pPubKeyCalc, pPrivKey, curveEd25519, pShaSuite, isShaEvp);
    if (OK != status)
        goto exit;
#endif

    if (isShaEvp)
    {
        status = pShaSuite->allocFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
        if (OK != status)
            goto exit;
    }

    if (preHash)
    {
        /* compute PH(M) */
        if (isShaEvp)
        {
            status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
            if (OK != status)
                goto exit;
            
            if (NULL != pMessage && messageLen)
            {
                status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pMessage, messageLen);
                if (OK != status)
                    goto exit;
            }

            status = pShaSuite->finalFunc(MOC_HASH(hwAccelCtx) pShaCtx, pPreHash);
            if (OK != status)
                goto exit;
        }
        else
        {
            status = pShaSuite->digestFunc(MOC_HASH(hwAccelCtx) pMessage, messageLen, pPreHash);
            if (OK != status)
                goto exit;
        }

        /* ok to change pMessage and msgLen to now be PH(M) */
        pMessage = (ubyte *) pPreHash;
        messageLen = MOC_EDDSA_SHA512_LEN;

        /* pre-Hash flag */
        pFlags[0] = 0x01;
    }
    
    /* followed by the context length */
    pFlags[1] = (ubyte) ctxLen;

    /* Allocate space for a projPoint25519 */
    status = DIGI_CALLOC((void **)&pR, 1, sizeof(projPoint25519));
    if (OK != status)
        return status;

    /* Section 5.1.6 Step 1 */
    if (isShaEvp)
    {
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
    
    /* copy the scalar s out of the first 32 bytes of pHash, considered as a (bytewise) Little Endian integer */
    status = DIGI_MEMCPY(ps, pHash, MOC_CURVE25519_ENCODING_SIZE);
    if (OK != status)
        goto exit;
    
    ps[0] &= 0xf8;  /* set the lowest 3 bits to 0 */
    ps[MOC_CURVE25519_ENCODING_SIZE-1] &= 0x7f; /* set the highest bit to 0 */
    ps[MOC_CURVE25519_ENCODING_SIZE-1] |= 0x40; /* second highest bit (2^254) to one */
    
    /* Section 5.1.6 Step 2, use the rest of the pHash as a salt to the message */
    if (isShaEvp)
    {
        status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
        if (OK != status)
            goto exit;
        
        /* dom2(F,C) */
        if (preHash || ctxLen)
        {     
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pSigEd25519, sizeof(pSigEd25519));
            if (OK != status)
                goto exit;
            
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pFlags, 2);
            if (OK != status)
                goto exit;

            if (ctxLen)
            {
                status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pCtx, ctxLen);
                if (OK != status)
                    goto exit;
            }        
        }

        /* prefix */
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pHash + MOC_CURVE25519_ENCODING_SIZE, MOC_CURVE25519_ENCODING_SIZE);
        if (OK != status)
            goto exit;
        
        /* M or PH(M) */
        if (NULL != pMessage && messageLen)
        {
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pMessage, messageLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->finalFunc(MOC_HASH(hwAccelCtx) pShaCtx, pHash2);  /* pHash2 is now the scalar r */
        if (OK != status)
            goto exit;
    }
    else
    {
        /*
         Allocate space for the largest input string we will ever need to input to sha.
         That happens to be the third sha invocation with dom2(F,C) || ENC(R) || ENC(A) || PH(M)
         This is the second invocation.
         */
        if (preHash || ctxLen)
        {     
            domLen = sizeof(pSigEd25519) + 2 + ctxLen;
        }
        /* else it's still zero */

        status = DIGI_MALLOC((void **)&pShaInput, domLen + 2*MOC_CURVE25519_ENCODING_SIZE + messageLen);
        if (OK != status)
            goto exit;
        
        if (preHash || ctxLen)
        {     
            /* dom2(F,C) */
            status = DIGI_MEMCPY(pShaInput, pSigEd25519, sizeof(pSigEd25519));
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pShaInput + sizeof(pSigEd25519), pFlags, 2);
            if (OK != status)
                goto exit;
            
            if (ctxLen)
            {
                status = DIGI_MEMCPY(pShaInput + sizeof(pSigEd25519) + 2, pCtx, ctxLen);
                if (OK != status)
                    goto exit;
            }
        }

        /* prefix */
        status = DIGI_MEMCPY(pShaInput + domLen, pHash + MOC_CURVE25519_ENCODING_SIZE, MOC_CURVE25519_ENCODING_SIZE);
        if (OK != status)
            goto exit;

        /* M or PH(M) */
        if (NULL != pMessage && messageLen)
        {
            status = DIGI_MEMCPY(pShaInput + domLen + MOC_CURVE25519_ENCODING_SIZE, pMessage, messageLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->digestFunc(MOC_HASH(hwAccelCtx) pShaInput, domLen + MOC_CURVE25519_ENCODING_SIZE + messageLen, pHash2);
        if (OK != status)
            goto exit;
    }
    
    /*
     reduce r mod L. Note this method will return the result back in pHash
     in Little Endian as well as in pVlong_r.
     */
    status = reduceByteBufferByL25519(pHash2, &pVlong_r, &pVlong_L);
    if (OK != status)
        goto exit;
    
    /* Section 5.1.6 Step 3, compute the scalar produce R = r * B */
    status = CURVE25519_multiplyPoint(MOC_ECC(hwAccelCtx) pR, pHash2, NULL);
    if (OK != status)
        goto exit;
    
    /* Encode the point R for the first half of the signature */
    status = CURVE25519_convertProjectiveToEncoded(pSignature, pR);
    if (OK != status)
        goto exit;
    
    /* Section 5.1.6 Step 4, compute k */
    if (isShaEvp)
    {
        status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
        if (OK != status)
            goto exit;
        
        /* dom2(F,C) */
        if (preHash || ctxLen)
        {     
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pSigEd25519, sizeof(pSigEd25519));
            if (OK != status)
                goto exit;
            
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pFlags, 2);
            if (OK != status)
                goto exit;

            if (ctxLen)
            {
                status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pCtx, ctxLen);
                if (OK != status)
                    goto exit;
            }        
        }

        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pSignature, MOC_CURVE25519_ENCODING_SIZE);
        if (OK != status)
            goto exit;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pPubKeyCalc, MOC_CURVE25519_ENCODING_SIZE);
#else
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pPubKey, MOC_CURVE25519_ENCODING_SIZE);
#endif
        if (OK != status)
            goto exit;
        
        if (NULL != pMessage && messageLen)
        {
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pMessage, messageLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->finalFunc(MOC_HASH(hwAccelCtx) pShaCtx, pHash); /* pHash is now k */
        if (OK != status)
            goto exit;
    }
    else
    {
        /* re-use pShaInput which is already allocated and already begins with dom2(F,C) */
        status = DIGI_MEMCPY(pShaInput + domLen, pSignature, MOC_CURVE25519_ENCODING_SIZE);
        if (OK != status)
            goto exit;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__        
        status = DIGI_MEMCPY(pShaInput + domLen + MOC_CURVE25519_ENCODING_SIZE, pPubKeyCalc, MOC_CURVE25519_ENCODING_SIZE);
#else
        status = DIGI_MEMCPY(pShaInput + domLen + MOC_CURVE25519_ENCODING_SIZE, pPubKey, MOC_CURVE25519_ENCODING_SIZE);
#endif
        if (OK != status)
            goto exit;
        
        if (NULL != pMessage && messageLen)
        {
            status = DIGI_MEMCPY(pShaInput + domLen + 2*MOC_CURVE25519_ENCODING_SIZE, pMessage, messageLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->digestFunc(MOC_HASH(hwAccelCtx) pShaInput, domLen + 2*MOC_CURVE25519_ENCODING_SIZE + messageLen, pHash);
        if (OK != status)
            goto exit;
    }
    
    /* reduce k mod L */
    status = reduceByteBufferByL25519(pHash, &pVlong_k, &pVlong_L);
    if (OK != status)
        goto exit;
    
    /* Section 5.1.6 Step 5, compute S = (r + k * s) mod L */
    status = VLONG_allocVlong(&pVlong_S, NULL);
    if (OK != status)
        goto exit;
    
#ifdef __ENABLE_DIGICERT_64_BIT__
    status = VLONG_reallocVlong (pVlong_S, (MOC_CURVE25519_BYTE_SIZE/4)+1);
    if (OK != status)
        goto exit;
#else
    status = VLONG_reallocVlong (pVlong_S, (MOC_CURVE25519_BYTE_SIZE/2)+1);
    if (OK != status)
        goto exit;
#endif
    
    /* Convert s to Big Endian for vlong-ification */
    for (i = 0; i < (MOC_CURVE25519_ENCODING_SIZE/2); ++i)
    { /* swap with xor */
        ps[i] = ps[i] ^  ps[MOC_CURVE25519_ENCODING_SIZE - 1 - i];
        ps[MOC_CURVE25519_ENCODING_SIZE - 1 - i] = ps[MOC_CURVE25519_ENCODING_SIZE - 1 - i] ^ ps[i];
        ps[i] = ps[i] ^  ps[MOC_CURVE25519_ENCODING_SIZE - 1 - i];
    }
    
    status = VLONG_vlongFromByteString (ps, MOC_CURVE25519_BYTE_SIZE, &pVlong_s, NULL);
    if (OK != status)
        goto exit;
    
    status = VLONG_unsignedMultiply(pVlong_S, pVlong_k, pVlong_s);
    if (OK != status)
        goto exit;
    
    status = addUnsignedVlongs (pVlong_S, pVlong_r);
    if (OK != status)
        goto exit;
    
    /* re-use pVlong_s for S mod L */
    status = VLONG_unsignedDivide (pVlong_k, pVlong_S,  pVlong_L, pVlong_s, NULL);
    if (OK != status)
        goto exit;
    
    status = VLONG_byteStringFromVlong (pVlong_s, pSignature + MOC_CURVE25519_ENCODING_SIZE, &Slen);
    if (OK != status)
        goto exit;
    
    /* Convert S to Little Endian */
    for (i = MOC_CURVE25519_ENCODING_SIZE; i < 48; ++i) /* 48 is halfway point */
    {
        pSignature[i] = pSignature[i] ^ pSignature[95 - i]; /* starts at 63, 62, 61 ... */
        pSignature[95 - i] = pSignature[95 - i] ^ pSignature[i];
        pSignature[i] = pSignature[i] ^ pSignature[95 - i];
    }
    
exit:
    
    /* Don't change status on below calls */
    if (OK != status)
    {
        DIGI_MEMSET(pSignature, 0x00, 2*MOC_CURVE25519_ENCODING_SIZE);
    }
    
    DIGI_MEMSET(pHash, 0x00, MOC_EDDSA_SHA512_LEN);
    DIGI_MEMSET(pHash2, 0x00, MOC_EDDSA_SHA512_LEN);
    DIGI_MEMSET(ps, 0x00, MOC_CURVE25519_ENCODING_SIZE);
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__  
    DIGI_MEMSET(pPubKeyCalc, 0x00, MOC_CURVE25519_ENCODING_SIZE);
#endif

    if (preHash)
    {
        DIGI_MEMSET(pPreHash, 0x00, MOC_EDDSA_SHA512_LEN);
    }
    DIGI_MEMSET(pFlags, 0x00, 2);

    if (NULL != pShaCtx)
    {
        pShaSuite->freeFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
    }
    if (NULL != pShaInput)
    {
        DIGI_MEMSET( (ubyte *) pShaInput, 0x00, domLen + 2*MOC_CURVE25519_ENCODING_SIZE + messageLen);
        DIGI_FREE((void **) &pShaInput);
    }
    
    if (NULL != pR)
    {
        DIGI_MEMSET( (ubyte *) pR, 0x00, sizeof(projPoint25519));
        DIGI_FREE((void **) &pR);
    }
    
    if (NULL != pVlong_k)
    {
        VLONG_freeVlong(&pVlong_k, NULL);
    }
    if (NULL != pVlong_s)
    {
        VLONG_freeVlong(&pVlong_s, NULL);
    }
    if (NULL != pVlong_r)
    {
        VLONG_freeVlong(&pVlong_r, NULL);
    }
    if (NULL != pVlong_S)
    {
        VLONG_freeVlong(&pVlong_S, NULL);
    }
    if (NULL != pVlong_L)
    {
        VLONG_freeVlong(&pVlong_L, NULL);
    }
    
    return status;
}


/* Internal one shot verifySignature method for edDSA on curve25519 */
static MSTATUS edDSA_curve25519_VerifySignature(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte *pPubKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature,
                                                ubyte4 *pVerifyStatus, BulkHashAlgo *pShaSuite, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, byteBoolean isShaEvp)
{
    MSTATUS status;
    int i;
    
    sbyte4 compare = -1; /* false default */
    
    ubyte pBuffer[MOC_EDDSA_SHA512_LEN] = {0};
    ubyte pPreHash[MOC_EDDSA_SHA512_LEN] = {0};
    ubyte pFlags[2] = {0};

    vlong *pK = NULL;
    vlong *pL = NULL;
    
    projPoint25519 *pA = NULL;
    
    /* sha ctx if isShaEvp is true */
    void *pShaCtx = NULL;
    /* Buffer for complete sha input if isShaEvp is false */
    ubyte *pShaInput = NULL;

    ubyte4 domLen = 0;
    
    /* internal method, NULL checks already done */
    
    /* We will validate S (the second half of pSignature) before continuing */
    
    /* make sure S is not 0, if loop gets to 64 == i then it is */
    i = MOC_CURVE25519_ENCODING_SIZE;
    while ( i < 2*MOC_CURVE25519_ENCODING_SIZE && ( !(pSignature[i]) ) )
    {
        i++;
    }
    if ( (2*MOC_CURVE25519_ENCODING_SIZE) == i)
    {
        *pVerifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
    }
    
    /* make sure S is not larger than or equal to L, S is Little Endian, L is Big Endian */
    i = 0;
    while (i < MOC_CURVE25519_ENCODING_SIZE)
    {
        if ( pSignature[2*MOC_CURVE25519_ENCODING_SIZE - 1 - i] > gpLbytes25519[i] )
        {
            *pVerifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
            break;
        }
        else if ( pSignature[2*MOC_CURVE25519_ENCODING_SIZE - 1 - i] < gpLbytes25519[i] )
        {
            break;
        }
        i++;
    }
    if (MOC_CURVE25519_ENCODING_SIZE == i)   /*   S = L in this case  */
    {
        *pVerifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
    }

    if (isShaEvp)
    {
        status = pShaSuite->allocFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
        if (OK != status)
            goto exit;
    }

    if (preHash)
    {
        /* compute PH(M) */
        if (isShaEvp)
        {
            status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
            if (OK != status)
                goto exit;
            
            if (NULL != pMessage && messageLen)
            {
                status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pMessage, messageLen);
                if (OK != status)
                    goto exit;
            }

            status = pShaSuite->finalFunc(MOC_HASH(hwAccelCtx) pShaCtx, pPreHash);
            if (OK != status)
                goto exit;
        }
        else
        {
            status = pShaSuite->digestFunc(MOC_HASH(hwAccelCtx) pMessage, messageLen, pPreHash);
            if (OK != status)
                goto exit;
        }

        /* ok to change pMessage and msgLen to now be PH(M) */
        pMessage = (ubyte *) pPreHash;
        messageLen = MOC_EDDSA_SHA512_LEN;

        /* pre-Hash flag */
        pFlags[0] = 0x01;
    }
    
    /* followed by the context length */
    pFlags[1] = (ubyte) ctxLen;
    
    /* Allocate space for four projPoint25519 in a single shot, recall each point is 4 coords */
    status = DIGI_CALLOC((void **)&pA, 1, 16 * MOC_NUM_25519_ELEM_BYTES);
    if (OK != status)
        return status;
    
    /* Validate and convert the encoded public key and encoded R first */
    status = CURVE25519_convertEncodedToProjective(pA, pPubKey);        /* A */
    if (ERR_NOT_FOUND == status)
        *pVerifyStatus |= MOCANA_EDDSA_VERIFY_PUB_KEY_INVALID;
    else if (OK != status)
        goto exit;
    
    status = CURVE25519_convertEncodedToProjective(&pA[1], pSignature); /* R */
    if (ERR_NOT_FOUND == status)
        *pVerifyStatus |= MOCANA_EDDSA_VERIFY_R_INVALID;
    else if (OK != status)
        goto exit;
    
    
    /* Section 5.1.7 Step 2, compute sha-512 of dom2(F,C) || ENC(R) || ENC(A) || PH(M) */
    if (isShaEvp)
    {
        status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
        if (OK != status)
            goto exit;

        /* dom2(F,C) */
        if (preHash || ctxLen)
        {     
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pSigEd25519, sizeof(pSigEd25519));
            if (OK != status)
                goto exit;
            
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pFlags, 2);
            if (OK != status)
                goto exit;

            if (ctxLen)
            {
                status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pCtx, ctxLen);
                if (OK != status)
                    goto exit;
            }        
        }
                
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pSignature, MOC_CURVE25519_ENCODING_SIZE);
        if (OK != status)
            goto exit;
        
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pPubKey, MOC_CURVE25519_ENCODING_SIZE);
        if (OK != status)
            goto exit;
        
        if (NULL != pMessage && messageLen)
        {
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pMessage, messageLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->finalFunc(MOC_HASH(hwAccelCtx) pShaCtx, pBuffer);
        if (OK != status)
            goto exit;
    }
    else
    {
        if (preHash || ctxLen)
        {     
            domLen = sizeof(pSigEd25519) + 2 + ctxLen;
        }
        /* else it's still zero */

        /* Allocate space for dom2(F,C) || ENC(R) || ENC(A) || PH(M) */
        status = DIGI_MALLOC((void **)&pShaInput, domLen + 2*MOC_CURVE25519_ENCODING_SIZE + messageLen);
        if (OK != status)
            goto exit;
        
        if (preHash || ctxLen)
        {     
            /* dom2(F,C) */
            status = DIGI_MEMCPY(pShaInput, pSigEd25519, sizeof(pSigEd25519));
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pShaInput + sizeof(pSigEd25519), pFlags, 2);
            if (OK != status)
                goto exit;
            
            if (ctxLen)
            {
                status = DIGI_MEMCPY(pShaInput + sizeof(pSigEd25519) + 2, pCtx, ctxLen);
                if (OK != status)
                    goto exit;
            }
        }

        status = DIGI_MEMCPY(pShaInput + domLen, pSignature, MOC_CURVE25519_ENCODING_SIZE);
        if (OK != status)
            goto exit;
        
        status = DIGI_MEMCPY(pShaInput + domLen + MOC_CURVE25519_ENCODING_SIZE, pPubKey, MOC_CURVE25519_ENCODING_SIZE);
        if (OK != status)
            goto exit;
        
        if (NULL != pMessage && messageLen)
        {
            status = DIGI_MEMCPY(pShaInput + domLen + 2*MOC_CURVE25519_ENCODING_SIZE, pMessage, messageLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->digestFunc(MOC_HASH(hwAccelCtx) pShaInput, domLen + 2*MOC_CURVE25519_ENCODING_SIZE + messageLen, pBuffer);
        if (OK != status)
            goto exit;
    }
    
    /*
     5.1.7 Step 3, compute k = H mod L, ie we need to reduce mod L
     this method places the result back in pBuffer
     */
    status = reduceByteBufferByL25519(pBuffer, &pK, &pL);
    if (OK != status)
        goto exit;
    
    /* compute R + k * A on the curve, re-use pA to store the result */
    status = CURVE25519_multiplyPoint(MOC_ECC(hwAccelCtx) &pA[2], pBuffer, pA);
    if (OK != status)
        goto exit;
    
    CURVE25519_addPoints(pA, &pA[2], &pA[1], (sbyte4 *) &pA[3]); /* re-use pA */
    
    /* Compute S * B on the curve, recall S is the second half of pSignature, NULL indicates we're multiplying by B */
    status = CURVE25519_multiplyPoint(MOC_ECC(hwAccelCtx) &pA[2], pSignature + MOC_CURVE25519_ENCODING_SIZE, NULL);
    if (OK != status)
        goto exit;
    
    /* Compare pA and pTemp, so convert each to encoded form, re-use pBuffer */
    status = CURVE25519_convertProjectiveToEncoded(pBuffer, pA);
    if (OK != status)
        goto exit;
    
    status = CURVE25519_convertProjectiveToEncoded(pBuffer + MOC_CURVE25519_ENCODING_SIZE, &pA[2]);
    if (OK != status)
        goto exit;
    
    /* Compare */
    status = DIGI_MEMCMP(pBuffer, pBuffer+MOC_CURVE25519_ENCODING_SIZE, MOC_CURVE25519_ENCODING_SIZE, &compare);
    if (OK != status)
        goto exit;
    
    if (compare)
        *pVerifyStatus |= MOCANA_EDDSA_VERIFY_FAIL;
    
exit:
    
    if (NULL != pShaCtx)
    {
        pShaSuite->freeFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
    }
    if (NULL != pShaInput)
    {
        DIGI_MEMSET( (ubyte *) pShaInput, 0x00, domLen + 2*MOC_CURVE25519_ENCODING_SIZE + messageLen);
        DIGI_FREE((void **) &pShaInput);
    }
    
    if (NULL != pA)
    {
        /* Don't change status */
        DIGI_MEMSET((ubyte *) pA, 0x00, 16 * MOC_NUM_25519_ELEM_BYTES);
        DIGI_FREE((void **) &pA);
    }
    
    DIGI_MEMSET(pBuffer, 0x00, MOC_EDDSA_SHA512_LEN);
    if (preHash)
    {
        DIGI_MEMSET(pPreHash, 0x00, MOC_EDDSA_SHA512_LEN);
    }
    DIGI_MEMSET(pFlags, 0x00, 2);
    
    if (NULL != pK)
    {
        VLONG_freeVlong(&pK, NULL);
    }
    if (NULL != pL)
    {
        VLONG_freeVlong(&pL, NULL);
    }
    
    return status;
}


/*
 Internal initVerify method for edDSA on curve25519. pSignature, pPubKey,
 and pShaSuite must have already been copied to the pEdDSA_ctx.
 */
static MSTATUS edDSA_curve25519_initVerify(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx)
{
    MSTATUS status;
    int i;
    
    /* internal method, NULL checks already done */
    
    /* We will validate S (the second half of pSignature) before continuing */
    
    /* make sure S is not 0, if loop gets to 64 == i then it is */
    i = MOC_CURVE25519_ENCODING_SIZE;
    while ( i < 2*MOC_CURVE25519_ENCODING_SIZE && ( !(pEdDSA_ctx->pSignature[i]) ) )
    {
        i++;
    }
    if ( (2*MOC_CURVE25519_ENCODING_SIZE) == i)
    {
        pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
    }
    
    /* make sure S is not larger than or equal to L, S is Little Endian, L is Big Endian */
    i = 0;
    while (i < MOC_CURVE25519_ENCODING_SIZE)
    {
        if ( pEdDSA_ctx->pSignature[2*MOC_CURVE25519_ENCODING_SIZE - 1 - i] > gpLbytes25519[i] )
        {
            pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
            break;
        }
        else if ( pEdDSA_ctx->pSignature[2*MOC_CURVE25519_ENCODING_SIZE - 1 - i] < gpLbytes25519[i] )
        {
            break;
        }
        i++;
    }
    if (MOC_CURVE25519_ENCODING_SIZE == i)   /*   S = L in this case  */
    {
        pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
    }

    status = pEdDSA_ctx->shaSuite.initFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx);
    if (OK != status)
        goto exit;

    if (!pEdDSA_ctx->preHash)
    {
        /* dom2(F,C) */
        if (pEdDSA_ctx->ctxLen)
        {     
            ubyte pFlags[2] = {0};

            status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pSigEd25519, sizeof(pSigEd25519));
            if (OK != status)
                goto exit;
            
            pFlags[1] = (ubyte) pEdDSA_ctx->ctxLen;
            status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pFlags, 2);
            if (OK != status)
                goto exit;

            status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pCtx, pEdDSA_ctx->ctxLen);
            if (OK != status)
                goto exit;
        }

        /*
            Validation of R will be postponed until finalVerify in order
            to save memory of storing a decoded R in the ctx
        */
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pSignature, MOC_CURVE25519_ENCODING_SIZE);
        if (OK != status)
            goto exit;
            
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pPubKey, MOC_CURVE25519_ENCODING_SIZE);
        if (OK != status)
            goto exit;

        /* ready for the message next */
    }
    /* else we are ready to hash the message on update */

exit:

    return status;
}


/* Internal finalVerify method for edDSA on curve25519 */
static MSTATUS edDSA_curve25519_finalVerify(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx)
{
    MSTATUS status;
    sbyte4 compare = -1; /* false default */
    
    ubyte pBuffer[MOC_EDDSA_SHA512_LEN] = {0};
    ubyte pPreHash[MOC_EDDSA_SHA512_LEN] = {0};
    
    vlong *pK = NULL;
    vlong *pL = NULL;
    
    projPoint25519 *pA = NULL;
    
    /* internal method, NULL checks already done */
    
    /* Allocate space for four projPoint25519 in a single shot, recall each point is 4 coords */
    status = DIGI_CALLOC((void **)&pA, 1, 16 * MOC_NUM_25519_ELEM_BYTES);
    if (OK != status)
        return status;
    
    /* Validate and convert the encoded public key and encoded R first */
    status = CURVE25519_convertEncodedToProjective(pA, pEdDSA_ctx->pPubKey); /* A */
    if (ERR_NOT_FOUND == status)
        pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_PUB_KEY_INVALID;
    else if (OK != status)
        goto exit;
    
    status = CURVE25519_convertEncodedToProjective(&pA[1], pEdDSA_ctx->pSignature); /* R */
    if (ERR_NOT_FOUND == status)
        pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_R_INVALID;
    else if (OK != status)
        goto exit;
    
    if (pEdDSA_ctx->preHash)
    {
        ubyte pFlags[2] = {0x01, 0x00};
        pFlags[1] = (ubyte) pEdDSA_ctx->ctxLen;

        status = pEdDSA_ctx->shaSuite.finalFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pPreHash);
        if (OK != status)
            goto exit;

        /* re init for the rest of the steps */
        status = pEdDSA_ctx->shaSuite.initFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx);
        if (OK != status)
            goto exit;

        /* dom2(F,C) */
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pSigEd25519, sizeof(pSigEd25519));
        if (OK != status)
            goto exit;
              
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pFlags, 2);
        if (OK != status)
            goto exit;

        if (pEdDSA_ctx->ctxLen)
        {    
            status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pCtx, pEdDSA_ctx->ctxLen);
            if (OK != status)
                goto exit;
        }
    
        /*
            Validation of R will be postponed until finalVerify in order
            to save memory of storing a decoded R in the ctx
        */
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pSignature, MOC_CURVE25519_ENCODING_SIZE);
        if (OK != status)
            goto exit;
            
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pPubKey, MOC_CURVE25519_ENCODING_SIZE);
        if (OK != status)
            goto exit;

        /* now ready for the hash of the message */
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pPreHash, MOC_EDDSA_SHA512_LEN);
        if (OK != status)
            goto exit;
    }

    /* Finalize the Hash, Section 5.1.7 Step 2 */
    status = pEdDSA_ctx->shaSuite.finalFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pBuffer);
    if (OK != status)
        goto exit;
    
    /* 5.1.7 Step 3, compute k = H mod L, ie we need to reduce mod L
     this method places the result back in pBuffer
     */
    status = reduceByteBufferByL25519(pBuffer, &pK, &pL);
    if (OK != status)
        goto exit;
    
    /* compute R + k * A on the curve, re-use pA to store the result */
    status = CURVE25519_multiplyPoint(MOC_ECC(hwAccelCtx) &pA[2], pBuffer, pA);
    if (OK != status)
        goto exit;
    
    CURVE25519_addPoints(pA, &pA[2], &pA[1], (sbyte4 *) &pA[3]); /* re-use pA */
    
    /* Compute S * B on the curve, recall S is the second half of pSignature, NULL indicates we're multiplying B */
    status = CURVE25519_multiplyPoint(MOC_ECC(hwAccelCtx) &pA[2], pEdDSA_ctx->pSignature + MOC_CURVE25519_ENCODING_SIZE, NULL);
    if (OK != status)
        goto exit;
    
    /* Compare pA and pTemp, so convert each to encoded form, re-use pBuffer */
    status = CURVE25519_convertProjectiveToEncoded(pBuffer, pA);
    if (OK != status)
        goto exit;
    
    status = CURVE25519_convertProjectiveToEncoded(pBuffer + MOC_CURVE25519_ENCODING_SIZE, &pA[2]);
    if (OK != status)
        goto exit;
    
    /* Compare */
    status = DIGI_MEMCMP(pBuffer, pBuffer+MOC_CURVE25519_ENCODING_SIZE, MOC_CURVE25519_ENCODING_SIZE, &compare);
    if (OK != status)
        goto exit;
    
    if (compare)
        pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_FAIL;
    
exit:
    
    if (NULL != pA)
    {
        /* Don't change status */
        DIGI_MEMSET((ubyte *) pA, 0x00, 16 * MOC_NUM_25519_ELEM_BYTES);
        DIGI_FREE((void **) &pA);
    }
    
    DIGI_MEMSET(pBuffer, 0x00, MOC_EDDSA_SHA512_LEN);

    if (pEdDSA_ctx->preHash)
    {
        DIGI_MEMSET(pPreHash, 0x00, MOC_EDDSA_SHA512_LEN);
    }
    if (NULL != pK)
    {
        VLONG_freeVlong(&pK, NULL);
    }
    if (NULL != pL)
    {
        VLONG_freeVlong(&pL, NULL);
    }
    
    return status;
}

static MSTATUS edDSA_curve25519_finalSign(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte *pSignature)
{
    MSTATUS status;
    int i;
        
    ubyte pHash[MOC_EDDSA_SHA512_LEN] = {0};
    ubyte pHash2[MOC_EDDSA_SHA512_LEN] = {0};
    ubyte ps[MOC_CURVE25519_ENCODING_SIZE] = {0};

    ubyte pPreHash[MOC_EDDSA_SHA512_LEN] = {0};
    ubyte pFlags[2] = {0x01, 0x00};

    vlong *pVlong_r = NULL;
    vlong *pVlong_s = NULL;
    vlong *pVlong_k = NULL;
    vlong *pVlong_S = NULL;
    vlong *pVlong_L = NULL;
    sbyte4 Slen = MOC_CURVE25519_ENCODING_SIZE;
    
    projPoint25519 *pR = NULL;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__
    ubyte pPubKeyCalc[MOC_CURVE25519_ENCODING_SIZE];

    status = edECC_calculatePubFromPriv(MOC_ECC(hwAccelCtx) pPubKeyCalc, pEdDSA_ctx->pPrivKey, curveEd25519, &pEdDSA_ctx->shaSuite, TRUE);
    if (OK != status)
        goto exit;
#endif

    /* internal method, NULL checks already done */
    
    pFlags[1] = (ubyte) pEdDSA_ctx->ctxLen;

    /* finish the pre hash */
    status = pEdDSA_ctx->shaSuite.finalFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pPreHash);
    if (OK != status)
        goto exit;
  
    /* Allocate space for a projPoint25519 */
    status = DIGI_CALLOC((void **)&pR, 1, sizeof(projPoint25519));
    if (OK != status)
        goto exit;

    status = pEdDSA_ctx->shaSuite.initFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx);
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pPrivKey, MOC_CURVE25519_ENCODING_SIZE);
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.finalFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pHash);
    if (OK != status)
        goto exit;

    /* copy the scalar s out of the first 32 bytes of pHash, considered as a (bytewise) Little Endian integer */
    status = DIGI_MEMCPY(ps, pHash, MOC_CURVE25519_ENCODING_SIZE);
    if (OK != status)
        goto exit;
    
    ps[0] &= 0xf8;  /* set the lowest 3 bits to 0 */
    ps[MOC_CURVE25519_ENCODING_SIZE-1] &= 0x7f; /* set the highest bit to 0 */
    ps[MOC_CURVE25519_ENCODING_SIZE-1] |= 0x40; /* second highest bit (2^254) to one */
    
    /* Section 5.1.6 Step 2, use the rest of the pHash as a salt to the message */
    status = pEdDSA_ctx->shaSuite.initFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx);
    if (OK != status)
        goto exit;
    
    /* dom2(F,C) */
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pSigEd25519, sizeof(pSigEd25519));
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pFlags, 2);
    if (OK != status)
        goto exit;

    if (pEdDSA_ctx->ctxLen)
    {
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pCtx, pEdDSA_ctx->ctxLen);
        if (OK != status)
            goto exit;
    }        
    
    /* prefix */
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pHash + MOC_CURVE25519_ENCODING_SIZE, MOC_CURVE25519_ENCODING_SIZE);
    if (OK != status)
        goto exit;
    
    /* PH(M) */
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pPreHash, MOC_EDDSA_SHA512_LEN);
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.finalFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pHash2);  /* pHash2 is now the scalar r */
    if (OK != status)
        goto exit;
    
    /*
     reduce r mod L. Note this method will return the result back in pHash
     in Little Endian as well as in pVlong_r.
     */
    status = reduceByteBufferByL25519(pHash2, &pVlong_r, &pVlong_L);
    if (OK != status)
        goto exit;
    
    /* Section 5.1.6 Step 3, compute the scalar produce R = r * B */
    status = CURVE25519_multiplyPoint(MOC_ECC(hwAccelCtx) pR, pHash2, NULL);
    if (OK != status)
        goto exit;
    
    /* Encode the point R for the first half of the signature */
    status = CURVE25519_convertProjectiveToEncoded(pSignature, pR);
    if (OK != status)
        goto exit;
    
    /* Section 5.1.6 Step 4, compute k */
    status = pEdDSA_ctx->shaSuite.initFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx);
    if (OK != status)
        goto exit;
    
    /* dom2(F,C) */
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pSigEd25519, sizeof(pSigEd25519));
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pFlags, 2);
    if (OK != status)
        goto exit;

    if (pEdDSA_ctx->ctxLen)
    {
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pCtx, pEdDSA_ctx->ctxLen);
        if (OK != status)
            goto exit;
    }

    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pSignature, MOC_CURVE25519_ENCODING_SIZE);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__   
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pPubKeyCalc, MOC_CURVE25519_ENCODING_SIZE);
#else
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pPubKey, MOC_CURVE25519_ENCODING_SIZE);
#endif
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pPreHash, MOC_EDDSA_SHA512_LEN);
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.finalFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pHash); /* pHash is now k */
    if (OK != status)
        goto exit;
    
    /* reduce k mod L */
    status = reduceByteBufferByL25519(pHash, &pVlong_k, &pVlong_L);
    if (OK != status)
        goto exit;
    
    /* Section 5.1.6 Step 5, compute S = (r + k * s) mod L */
    status = VLONG_allocVlong(&pVlong_S, NULL);
    if (OK != status)
        goto exit;
    
#ifdef __ENABLE_DIGICERT_64_BIT__
    status = VLONG_reallocVlong (pVlong_S, (MOC_CURVE25519_BYTE_SIZE/4)+1);
    if (OK != status)
        goto exit;
#else
    status = VLONG_reallocVlong (pVlong_S, (MOC_CURVE25519_BYTE_SIZE/2)+1);
    if (OK != status)
        goto exit;
#endif
    
    /* Convert s to Big Endian for vlong-ification */
    for (i = 0; i < (MOC_CURVE25519_ENCODING_SIZE/2); ++i)
    { /* swap with xor */
        ps[i] = ps[i] ^  ps[MOC_CURVE25519_ENCODING_SIZE - 1 - i];
        ps[MOC_CURVE25519_ENCODING_SIZE - 1 - i] = ps[MOC_CURVE25519_ENCODING_SIZE - 1 - i] ^ ps[i];
        ps[i] = ps[i] ^  ps[MOC_CURVE25519_ENCODING_SIZE - 1 - i];
    }
    
    status = VLONG_vlongFromByteString (ps, MOC_CURVE25519_BYTE_SIZE, &pVlong_s, NULL);
    if (OK != status)
        goto exit;
    
    status = VLONG_unsignedMultiply(pVlong_S, pVlong_k, pVlong_s);
    if (OK != status)
        goto exit;
    
    status = addUnsignedVlongs (pVlong_S, pVlong_r);
    if (OK != status)
        goto exit;
    
    /* re-use pVlong_s for S mod L */
    status = VLONG_unsignedDivide (pVlong_k, pVlong_S,  pVlong_L, pVlong_s, NULL);
    if (OK != status)
        goto exit;
    
    status = VLONG_byteStringFromVlong (pVlong_s, pSignature + MOC_CURVE25519_ENCODING_SIZE, &Slen);
    if (OK != status)
        goto exit;
    
    /* Convert S to Little Endian */
    for (i = MOC_CURVE25519_ENCODING_SIZE; i < 48; ++i) /* 48 is halfway point */
    {
        pSignature[i] = pSignature[i] ^ pSignature[95 - i]; /* starts at 63, 62, 61 ... */
        pSignature[95 - i] = pSignature[95 - i] ^ pSignature[i];
        pSignature[i] = pSignature[i] ^ pSignature[95 - i];
    }
    
exit:
    
    /* Don't change status on below calls */
    if (OK != status)
    {
        DIGI_MEMSET(pSignature, 0x00, 2*MOC_CURVE25519_ENCODING_SIZE);
    }
    
    DIGI_MEMSET(pHash, 0x00, MOC_EDDSA_SHA512_LEN);
    DIGI_MEMSET(pHash2, 0x00, MOC_EDDSA_SHA512_LEN);
    DIGI_MEMSET(ps, 0x00, MOC_CURVE25519_ENCODING_SIZE);
    DIGI_MEMSET(pPreHash, 0x00, MOC_EDDSA_SHA512_LEN);
    DIGI_MEMSET(pFlags, 0x00, 2);
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__  
    DIGI_MEMSET(pPubKeyCalc, 0x00, MOC_CURVE25519_ENCODING_SIZE);
#endif

    if (NULL != pR)
    {
        DIGI_MEMSET( (ubyte *) pR, 0x00, sizeof(projPoint25519));
        DIGI_FREE((void **) &pR);
    }
    
    if (NULL != pVlong_k)
    {
        VLONG_freeVlong(&pVlong_k, NULL);
    }
    if (NULL != pVlong_s)
    {
        VLONG_freeVlong(&pVlong_s, NULL);
    }
    if (NULL != pVlong_r)
    {
        VLONG_freeVlong(&pVlong_r, NULL);
    }
    if (NULL != pVlong_S)
    {
        VLONG_freeVlong(&pVlong_S, NULL);
    }
    if (NULL != pVlong_L)
    {
        VLONG_freeVlong(&pVlong_L, NULL);
    }
    
    return status;
}

#endif /* __ENABLE_DIGICERT_ECC_EDDSA_25519__ */


/***************************************************************************************/


#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__

/*
 Big Endian bytewise large cyclic group order L
 These constants are not accessed within a large iteration loop so ok to just keep global version.
 */
static const ubyte gpLbytes448[MOC_CURVE448_BYTE_SIZE] =
{
    0x3F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7C,0xCA,0x23,0xE9,
    0xC4,0x4E,0xDB,0x49,0xAE,0xD6,0x36,0x90,0x21,0x6C,0xC2,0x72,0x8D,0xC5,0x8F,0x55,
    0x23,0x78,0xC2,0x92,0xAB,0x58,0x44,0xF3
};

/*
 dom4(F,C) as in section 2, ASCII for "SigEd448". Will be followed by F as an octet,
 and OLEN(C) as an octet and the context C */
static const ubyte pSigEd448[8] =
{
    0x53,0x69,0x67,0x45,0x64,0x34,0x34,0x38
};


/*
 Reduces in place a Little Endian buffer mod L (the curve's large cyclic group order).
 pBuffer should be 64 bytes in length. ppL can be NULL and will be allocated with the
 value L, or it can be passed in already as L. ppResult will be allocated and set to
 the correct answer. Also, the first 56 bytes of pBuffer will be overwritten with the
 Little Endian byte form of ppResult. We don't use Barrett reduction since the value
 in pBuffer is likely bigger than L^2.
 
 NOTE: This method will pad pBuffer with another 0x00 byte on the most significant byte.
 This padding byte is needed for the comb point-multiply routines.
 
 Please be sure to freeVlong on ppL and ppResult.
 */
static MSTATUS reduceByteBufferByL448(ubyte *pBuffer, vlong **ppResult, vlong **ppL)
{
    MSTATUS status;
    int i;
    
    vlong *pBufferValue = NULL;
    vlong *pUnusedQuotient = NULL;
    
    sbyte4 retBufLen = MOC_CURVE448_BYTE_SIZE;
    
    /* set to NULL in case we error */
    *ppResult = NULL;
    
    /* Put pBuffer in Big Endian */
    for(i = 0; i < MOC_EDDSA_SHAKE256_LEN/2; ++i)
    {
        /* swap using xor */
        pBuffer[i] = pBuffer[i] ^ pBuffer[MOC_EDDSA_SHAKE256_LEN - 1 - i];
        pBuffer[MOC_EDDSA_SHAKE256_LEN - 1 - i] = pBuffer[MOC_EDDSA_SHAKE256_LEN - 1 - i] ^ pBuffer[i];
        pBuffer[i] = pBuffer[i] ^ pBuffer[MOC_EDDSA_SHAKE256_LEN - 1 - i];
    }
    
    /* Make it a vlong */
    status = VLONG_vlongFromByteString (pBuffer, MOC_EDDSA_SHAKE256_LEN, &pBufferValue, NULL);
    if (OK != status)
        goto exit;
    
    /* if not already defined, make L a vlong */
    if (NULL == *ppL)
    {
        status = VLONG_vlongFromByteString (gpLbytes448, MOC_CURVE448_BYTE_SIZE, ppL, NULL);
        if (OK != status)
            goto exit;
    }
    
    /* allocate space for an unused quotient, and remainder of pBuffer divided by L */
    status = VLONG_allocVlong(&pUnusedQuotient, NULL);
    if (OK != status)
        goto exit;
    
    status = VLONG_allocVlong(ppResult, NULL);
    if (OK != status)
        goto exit;
    
#ifdef __ENABLE_DIGICERT_64_BIT__
    status = VLONG_reallocVlong (pUnusedQuotient, (MOC_CURVE448_BYTE_SIZE/8) + 1);
    if (OK != status)
        goto exit;
    
    status = VLONG_reallocVlong (*ppResult, (MOC_CURVE448_BYTE_SIZE/8));
    if (OK != status)
        goto exit;
#else
    status = VLONG_reallocVlong (pUnusedQuotient, (MOC_CURVE448_BYTE_SIZE/4) + 1);
    if (OK != status)
        goto exit;
    
    status = VLONG_reallocVlong (*ppResult, (MOC_CURVE448_BYTE_SIZE/4));
    if (OK != status)
        goto exit;
#endif
    
    /* compute pResult = pBufferValue mod L, the quotient is not needed */
    status = VLONG_unsignedDivide (pUnusedQuotient, pBufferValue, *ppL, *ppResult, NULL);
    if (OK != status)
        goto exit;
    
    /* now get pResult back as a byte string, re-use the first 56 bytes of pBuffer*/
    status = VLONG_byteStringFromVlong (*ppResult, pBuffer, &retBufLen);
    if (OK != status)
        goto exit;
    
    /* convert to Little Endian */
    for(i = 0; i < MOC_CURVE448_BYTE_SIZE/2; ++i)
    {
        pBuffer[i] = pBuffer[i] ^ pBuffer[MOC_CURVE448_BYTE_SIZE - 1 - i];
        pBuffer[MOC_CURVE448_BYTE_SIZE - 1 - i] = pBuffer[MOC_CURVE448_BYTE_SIZE - 1 - i] ^ pBuffer[i];
        pBuffer[i] = pBuffer[i] ^ pBuffer[MOC_CURVE448_BYTE_SIZE - 1 - i];
    }
    
    pBuffer[MOC_CURVE448_BYTE_SIZE] = 0x00;
    
exit:
    
    if (OK != status)
    {
        /* Free pResult and pL on error */
        if (NULL != *ppResult)
        {
            VLONG_freeVlong(ppResult, NULL);
        }
        if (NULL != *ppL)
        {
            VLONG_freeVlong(ppL, NULL);
        }
    }
    
    if (NULL != pBufferValue)
    {
        VLONG_freeVlong(&pBufferValue, NULL);
    }
    if (NULL != pUnusedQuotient)
    {
        VLONG_freeVlong(&pUnusedQuotient, NULL);
    }
    
    return status;
}

/* Pre-hash output length is 64 bytes using SHAKE rather than the 114 length used elsewhere */
#define MOC_CURVE448_PREHASH_LEN 64

/*
 Internal sign method for edDSA on curve448.
 
 pPrivKey, pPubKey must be MOC_CURVE448_ENCODING_SIZE bytes long (ie 57)
 pSignature must have already been allocated to 2*MOC_CURVE448_ENCODING_SIZE bytes (ie 114).
 */
static MSTATUS edDSA_curve448_sign(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte *pPrivKey, ubyte *pPubKey, ubyte *pMessage, ubyte4 messageLen,
                                   ubyte *pSignature, BulkHashAlgo *pShaSuite, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, byteBoolean isShaEvp)
{
    MSTATUS status;
    int i;
    
    /* sha ctx if isShaEvp is true */
    void *pShaCtx = NULL;
    /* Buffer for complete sha input if isShaEvp is false */
    ubyte *pShaInput = NULL;
    
    ubyte pHash[MOC_EDDSA_SHAKE256_LEN] = {0};
    ubyte pHash2[MOC_EDDSA_SHAKE256_LEN] = {0};
    ubyte ps[MOC_CURVE448_ENCODING_SIZE] = {0};
    
    ubyte pPreHash[MOC_CURVE448_PREHASH_LEN] = {0};
    ubyte pFlags[2] = {0};    
    ubyte4 domLen = 0;

    vlong *pVlong_r = NULL;
    vlong *pVlong_s = NULL;
    vlong *pVlong_k = NULL;
    vlong *pVlong_S = NULL;
    vlong *pVlong_L = NULL;
    sbyte4 Slen = MOC_CURVE448_BYTE_SIZE;
    
    projPoint448 *pR = NULL;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__
    ubyte pPubKeyCalc[MOC_CURVE448_ENCODING_SIZE];

    MOC_UNUSED(pPubKey);

    status = edECC_calculatePubFromPriv(MOC_ECC(hwAccelCtx) pPubKeyCalc, pPrivKey, curveEd448, pShaSuite, isShaEvp);
    if (OK != status)
        goto exit;
#endif

    /* internal method, NULL checks already done */
    
    if (isShaEvp)
    {
        status = pShaSuite->allocFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
        if (OK != status)
            goto exit;
    }

    if (preHash)
    {
        /* compute PH(M) */
        if (isShaEvp)
        {
            status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
            if (OK != status)
                goto exit;
            
            if (NULL != pMessage && messageLen)
            {
                status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pMessage, messageLen);
                if (OK != status)
                    goto exit;
            }

            status = pShaSuite->finalXOFFunc(MOC_HASH(hwAccelCtx) pShaCtx, pPreHash, MOC_CURVE448_PREHASH_LEN);
            if (OK != status)
                goto exit;
        }
        else
        {
            status = pShaSuite->digestXOFFunc(MOC_HASH(hwAccelCtx) pMessage, messageLen, pPreHash, MOC_CURVE448_PREHASH_LEN);
            if (OK != status)
                goto exit;
        }

        /* ok to change pMessage and msgLen to now be PH(M) */
        pMessage = (ubyte *) pPreHash;
        messageLen = MOC_CURVE448_PREHASH_LEN;

        /* pre-Hash flag */
        pFlags[0] = 0x01;
    }
    
    /* followed by the context length */
    pFlags[1] = (ubyte) ctxLen;

    /* Allocate space for a projPoint448 */
    status = DIGI_CALLOC((void **)&pR, 1, sizeof(projPoint448));
    if (OK != status)
        return status;
    
    /* Section 5.2.6 Step 1 */
    if (isShaEvp)
    {
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
    
    /* copy the scalar s out of the first 57 bytes of pHash, considered as a (bytewise) Little Endian integer */
    status = DIGI_MEMCPY(ps, pHash, MOC_CURVE448_ENCODING_SIZE);
    if (OK != status)
        goto exit;
    
    ps[0] &= 0xfc;  /* set the lowest 2 bits to 0 */
    ps[MOC_CURVE448_ENCODING_SIZE-1] = 0x00;  /* set the highest byte to 0 */
    ps[MOC_CURVE448_ENCODING_SIZE-2] |= 0x80; /* second highest bit (2^447) to one */
    
    /* Section 5.2.6 Step 2, use the rest of the pHash as a salt to the message */
    if (isShaEvp)
    {
        status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
        if (OK != status)
            goto exit;
        
        /* Unlike 25519 we always include dom4(F,C) whether its prehash or context or not! */
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, (ubyte *) pSigEd448, sizeof(pSigEd448));
        if (OK != status)
            goto exit;
        
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pFlags, 2);
        if (OK != status)
            goto exit;
        
        if (ctxLen)
        {
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pCtx, ctxLen);
            if (OK != status)
                goto exit;
        }

        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pHash + MOC_CURVE448_ENCODING_SIZE, MOC_CURVE448_ENCODING_SIZE);
        if (OK != status)
            goto exit;
        
        if (NULL != pMessage && messageLen)
        {
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pMessage, messageLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->finalXOFFunc(MOC_HASH(hwAccelCtx) pShaCtx, pHash2, MOC_EDDSA_SHAKE256_LEN);  /* pHash2 is now the scalar r */
        if (OK != status)
            goto exit;
    }
    else
    {
        domLen = sizeof(pSigEd448) + 2 + ctxLen;
        /*
         Allocate space for the largest input string we will ever need to input to sha.
         That happens to be the third sha invocation with dom4(F,C) || ENC(R) || ENC(A) || PH(M).
         This is the second invocation.
         */
        status = DIGI_MALLOC((void **)&pShaInput, domLen + 2*MOC_CURVE448_ENCODING_SIZE + messageLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_MEMCPY(pShaInput, pSigEd448, sizeof(pSigEd448));
        if (OK != status)
            goto exit;
        
        status = DIGI_MEMCPY(pShaInput + sizeof(pSigEd448), pFlags, 2);
        if (OK != status)
            goto exit;

        if (ctxLen)
        {
            status = DIGI_MEMCPY(pShaInput + sizeof(pSigEd448) + 2, pCtx, ctxLen);
            if (OK != status)
                goto exit;
        }

        status = DIGI_MEMCPY(pShaInput + domLen, pHash + MOC_CURVE448_ENCODING_SIZE, MOC_CURVE448_ENCODING_SIZE);
        if (OK != status)
            goto exit;
        
        if (NULL != pMessage && messageLen)
        {
            status = DIGI_MEMCPY(pShaInput + domLen + MOC_CURVE448_ENCODING_SIZE, pMessage, messageLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->digestXOFFunc(MOC_HASH(hwAccelCtx) pShaInput, domLen + MOC_CURVE448_ENCODING_SIZE + messageLen, pHash2, MOC_EDDSA_SHAKE256_LEN);
        if (OK != status)
            goto exit;
    }
    
    /*
     reduce r mod L. Note this method will return the result back in pHash
     in Little Endian as well as in pVlong_r. pHash2 will be properly padded with an extra 0x00 byte for CURVE448_multiplyPoint.
     */
    status = reduceByteBufferByL448(pHash2, &pVlong_r, &pVlong_L);
    if (OK != status)
        goto exit;
    
    /* Section 5.2.6 Step 3, compute the scalar produce R = r * B, NULL indicates to multiply by B */
    status = CURVE448_multiplyPoint(MOC_ECC(hwAccelCtx) pR, pHash2, NULL);
    if (OK != status)
        goto exit;
    
    /* Encode the point R for the first half of the signature */
    status = CURVE448_convertProjectiveToEncoded(pSignature, pR);
    if (OK != status)
        goto exit;
    
    /* Section 5.2.6 Step 4, compute k */
    if (isShaEvp)
    {
        status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
        if (OK != status)
            goto exit;
    
        /* Unlike 25519 we always include dom4(F,C) whether its prehash or context or not! */
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, (ubyte *) pSigEd448, sizeof(pSigEd448));
        if (OK != status)
            goto exit;
        
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pFlags, 2);
        if (OK != status)
            goto exit;
        
        if (ctxLen)
        {
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pCtx, ctxLen);
            if (OK != status)
                goto exit;
        }

        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pSignature, MOC_CURVE448_ENCODING_SIZE);
        if (OK != status)
            goto exit;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__          
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pPubKeyCalc, MOC_CURVE448_ENCODING_SIZE);
#else
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pPubKey, MOC_CURVE448_ENCODING_SIZE);
#endif
        if (OK != status)
            goto exit;
        
        if (NULL != pMessage && messageLen)
        {
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pMessage, messageLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->finalXOFFunc(MOC_HASH(hwAccelCtx) pShaCtx, pHash, MOC_EDDSA_SHAKE256_LEN) ; /* pHash is now k */
        if (OK != status)
            goto exit;
    }
    else
    {
        /* re-use pShaInput which is already allocated and already begins with dom4(F,C) */
        status = DIGI_MEMCPY(pShaInput + domLen, pSignature, MOC_CURVE448_ENCODING_SIZE);
        if (OK != status)
            goto exit;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__         
        status = DIGI_MEMCPY(pShaInput + domLen + MOC_CURVE448_ENCODING_SIZE, pPubKeyCalc, MOC_CURVE448_ENCODING_SIZE);
#else
        status = DIGI_MEMCPY(pShaInput + domLen + MOC_CURVE448_ENCODING_SIZE, pPubKey, MOC_CURVE448_ENCODING_SIZE);
#endif
        if (OK != status)
            goto exit;
        
        if (NULL != pMessage && messageLen)
        {
            status = DIGI_MEMCPY(pShaInput + domLen + 2*MOC_CURVE448_ENCODING_SIZE, pMessage, messageLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->digestXOFFunc(MOC_HASH(hwAccelCtx) pShaInput, domLen + 2*MOC_CURVE448_ENCODING_SIZE + messageLen, pHash, MOC_EDDSA_SHAKE256_LEN);
        if (OK != status)
            goto exit;
    }
    
    /* reduce k mod L */
    status = reduceByteBufferByL448(pHash, &pVlong_k, &pVlong_L);
    if (OK != status)
        goto exit;
    
    /* Section 5.2.6 Step 5, compute S = (r + k * s) mod L */
    status = VLONG_allocVlong(&pVlong_S, NULL);
    if (OK != status)
        goto exit;
    
#ifdef __ENABLE_DIGICERT_64_BIT__
    status = VLONG_reallocVlong (pVlong_S, (MOC_CURVE448_BYTE_SIZE/4)+1);
    if (OK != status)
        goto exit;
#else
    status = VLONG_reallocVlong (pVlong_S, (MOC_CURVE448_BYTE_SIZE/2)+1);
    if (OK != status)
        goto exit;
#endif
    
    /* Convert s to Big Endian for vlong-ification */
    for (i = 0; i < (MOC_CURVE448_BYTE_SIZE/2); ++i)
    { /* swap with xor */
        ps[i] = ps[i] ^  ps[MOC_CURVE448_BYTE_SIZE - 1 - i];
        ps[MOC_CURVE448_BYTE_SIZE - 1 - i] = ps[MOC_CURVE448_BYTE_SIZE - 1 - i] ^ ps[i];
        ps[i] = ps[i] ^  ps[MOC_CURVE448_BYTE_SIZE - 1 - i];
    }
    
    status = VLONG_vlongFromByteString (ps, MOC_CURVE448_BYTE_SIZE, &pVlong_s, NULL);
    if (OK != status)
        goto exit;
    
    status = VLONG_unsignedMultiply(pVlong_S, pVlong_k, pVlong_s);
    if (OK != status)
        goto exit;
    
    status = addUnsignedVlongs (pVlong_S, pVlong_r);
    if (OK != status)
        goto exit;
    
    /* re-use pVlong_s for S mod L */
    status = VLONG_unsignedDivide (pVlong_k, pVlong_S,  pVlong_L, pVlong_s, NULL);
    if (OK != status)
        goto exit;
    
    status = VLONG_byteStringFromVlong (pVlong_s, pSignature + MOC_CURVE448_ENCODING_SIZE, &Slen);
    if (OK != status)
        goto exit;
    
    /* S is Big Endian in bytes 57 to 112 of pSignature. Convert to Little Endian. */
    for (i = MOC_CURVE448_ENCODING_SIZE; i < 85; ++i)   /* 85 is halfway point */
    {
        pSignature[i] = pSignature[i] ^ pSignature[169 - i]; /* starts at 112, 111, 110 ... */
        pSignature[169 - i] = pSignature[169 - i] ^ pSignature[i];
        pSignature[i] = pSignature[i] ^ pSignature[169 - i];
    }
    /* last byte of an encoded S is zero */
    pSignature[2*MOC_CURVE448_ENCODING_SIZE - 1] = 0x00;
    
exit:
    
    /* Don't change status on below calls */
    if (OK != status)
    {
        DIGI_MEMSET(pSignature, 0x00, 2*MOC_CURVE448_ENCODING_SIZE);
    }
    
    DIGI_MEMSET(pHash, 0x00, MOC_EDDSA_SHAKE256_LEN);
    DIGI_MEMSET(pHash2, 0x00, MOC_EDDSA_SHAKE256_LEN);
    DIGI_MEMSET(ps, 0x00, MOC_CURVE448_ENCODING_SIZE);
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__  
    DIGI_MEMSET(pPubKeyCalc, 0x00, MOC_CURVE448_ENCODING_SIZE);
#endif

    if (preHash)
    {
        DIGI_MEMSET(pPreHash, 0x00, MOC_CURVE448_PREHASH_LEN);
    }
    DIGI_MEMSET(pFlags, 0x00, 2);

    if (NULL != pShaCtx)
    {
        pShaSuite->freeFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
    }
    if (NULL != pShaInput)
    {
        DIGI_MEMSET( (ubyte *) pShaInput, 0x00, domLen + 2*MOC_CURVE448_ENCODING_SIZE + messageLen);
        DIGI_FREE((void **) &pShaInput);
    }
    
    if (NULL != pR)
    {
        DIGI_MEMSET( (ubyte *) pR, 0x00, sizeof(projPoint448));
        DIGI_FREE((void **) &pR);
    }
    
    if (NULL != pVlong_k)
    {
        VLONG_freeVlong(&pVlong_k, NULL);
    }
    if (NULL != pVlong_s)
    {
        VLONG_freeVlong(&pVlong_s, NULL);
    }
    if (NULL != pVlong_r)
    {
        VLONG_freeVlong(&pVlong_r, NULL);
    }
    if (NULL != pVlong_S)
    {
        VLONG_freeVlong(&pVlong_S, NULL);
    }
    if (NULL != pVlong_L)
    {
        VLONG_freeVlong(&pVlong_L, NULL);
    }
    
    return status;
}


/* Internal one shot verifySignature method for edDSA on curve448 */
static MSTATUS edDSA_curve448_VerifySignature(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte *pPubKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature,
                                              ubyte4 *pVerifyStatus, BulkHashAlgo *pShaSuite, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, byteBoolean isShaEvp)
{
    MSTATUS status;
    int i;
    
    sbyte4 compare = -1; /* false default */
    
    ubyte pBuffer[MOC_EDDSA_SHAKE256_LEN] = {0};
    
    ubyte pPreHash[MOC_CURVE448_PREHASH_LEN] = {0};
    ubyte pFlags[2] = {0};    
    ubyte4 domLen = 0;

    vlong *pK = NULL;
    vlong *pL = NULL;
    
    projPoint448 *pA = NULL;
    
    /* sha ctx if isShaEvp is true */
    void *pShaCtx = NULL;
    /* Buffer for complete sha input if isShaEvp is false */
    ubyte *pShaInput = NULL;
    
    /* internal method, NULL checks already done */
    
    /* We will validate S (the second half of pSignature) before continuing */
    
    /* Last byte of S should be 0x00 */
    if (0x00 != pSignature[2*MOC_CURVE448_ENCODING_SIZE - 1])
    {
        *pVerifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
        /* add MOCANA_EDDSA_VERIFY_FAIL too since we ignore this byte in calculating the point multiply S * B  */
        *pVerifyStatus |= MOCANA_EDDSA_VERIFY_FAIL;
    }
    
    /* make sure rest of S is not 0, if loop gets to 113 == i then it is */
    i = MOC_CURVE448_ENCODING_SIZE;
    while ( i < (2*MOC_CURVE448_ENCODING_SIZE - 1) && ( !(pSignature[i]) ) )
    {
        i++;
    }
    if ( (2*MOC_CURVE448_ENCODING_SIZE - 1) == i)
    {
        *pVerifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
    }
    
    /*
     make sure S is not larger than or equal to L, S is Little Endian, L is Big Endian
     S's most significant byte is in byte 112 (ie 2*MOC_CURVE448_BYTE_SIZE ).
     */
    i = 0;
    while (i < MOC_CURVE448_BYTE_SIZE)
    {
        if ( pSignature[2*MOC_CURVE448_BYTE_SIZE - i] > gpLbytes448[i] )
        {
            *pVerifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
            break;
        }
        else if ( pSignature[2*MOC_CURVE448_BYTE_SIZE - i] < gpLbytes448[i] )
        {
            break;
        }
        i++;
    }
    if (MOC_CURVE448_BYTE_SIZE == i)   /*   S = L in this case  */
    {
        *pVerifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
    }
    
    if (isShaEvp)
    {
        status = pShaSuite->allocFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
        if (OK != status)
            goto exit;
    }

    if (preHash)
    {
        /* compute PH(M) */
        if (isShaEvp)
        {
            status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
            if (OK != status)
                goto exit;
            
            if (NULL != pMessage && messageLen)
            {
                status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pMessage, messageLen);
                if (OK != status)
                    goto exit;
            }

            status = pShaSuite->finalXOFFunc(MOC_HASH(hwAccelCtx) pShaCtx, pPreHash, MOC_CURVE448_PREHASH_LEN);
            if (OK != status)
                goto exit;
        }
        else
        {
            status = pShaSuite->digestXOFFunc(MOC_HASH(hwAccelCtx) pMessage, messageLen, pPreHash, MOC_CURVE448_PREHASH_LEN);
            if (OK != status)
                goto exit;
        }

        /* ok to change pMessage and msgLen to now be PH(M) */
        pMessage = (ubyte *) pPreHash;
        messageLen = MOC_CURVE448_PREHASH_LEN;

        /* pre-Hash flag */
        pFlags[0] = 0x01;
    }
    
    /* followed by the context length */
    pFlags[1] = (ubyte) ctxLen;

    /*
     Allocate space for three projPoint448 (recall each point has 3 coords),
     and 7 more elements, so 16 elements total, in a single shot
     */
    status = DIGI_CALLOC((void **)&pA, 16 * MOC_CURVE448_NUM_UNITS, sizeof(pf_unit));
    if (OK != status)
        return status;
    
    /* Validate and convert the encoded public key and encoded R first */
    status = CURVE448_convertEncodedToProjective(pA, pPubKey);         /* A */
    if (ERR_NOT_FOUND == status)
        *pVerifyStatus |= MOCANA_EDDSA_VERIFY_PUB_KEY_INVALID;
    else if (OK != status)
        goto exit;
    
    status = CURVE448_convertEncodedToProjective(&pA[1], pSignature);  /* R */
    if (ERR_NOT_FOUND == status)
        *pVerifyStatus |= MOCANA_EDDSA_VERIFY_R_INVALID;
    else if (OK != status)
        goto exit;
    
    /* Section 5.2.7 Step 2, Perform the required shake digest with of ENC(R) || ENC(A) */
    if (isShaEvp)
    {        
        status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
        if (OK != status)
            goto exit;
        
        /* Unlike 25519 we always include dom4(F,C) whether its prehash or context or not! */
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, (ubyte *) pSigEd448, sizeof(pSigEd448));
        if (OK != status)
            goto exit;
        
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pFlags, 2);
        if (OK != status)
            goto exit;
        
        if (ctxLen)
        {
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pCtx, ctxLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pSignature, MOC_CURVE448_ENCODING_SIZE);
        if (OK != status)
            goto exit;

        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pPubKey, MOC_CURVE448_ENCODING_SIZE);
        if (OK != status)
            goto exit;
        
        if (NULL != pMessage && messageLen)
        {
            status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pMessage, messageLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->finalXOFFunc(MOC_HASH(hwAccelCtx) pShaCtx, pBuffer, MOC_EDDSA_SHAKE256_LEN);
        if (OK != status)
            goto exit;
    }
    else
    {
        domLen = sizeof(pSigEd448) + 2 + ctxLen;

        /* Allocate space for dom4(F,C) || ENC(R) || ENC(A) || PH(M) */
        status = DIGI_MALLOC((void **)&pShaInput, domLen + 2*MOC_CURVE448_ENCODING_SIZE + messageLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_MEMCPY(pShaInput, pSigEd448, sizeof(pSigEd448));
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pShaInput + sizeof(pSigEd448), pFlags, 2);
        if (OK != status)
            goto exit;

        if (ctxLen)
        {
            status = DIGI_MEMCPY(pShaInput + sizeof(pSigEd448) + 2, pCtx, ctxLen);
            if (OK != status)
                goto exit;
        }

        status = DIGI_MEMCPY(pShaInput + domLen, pSignature, MOC_CURVE448_ENCODING_SIZE);
        if (OK != status)
            goto exit;
        
        status = DIGI_MEMCPY(pShaInput + domLen + MOC_CURVE448_ENCODING_SIZE, pPubKey, MOC_CURVE448_ENCODING_SIZE);
        if (OK != status)
            goto exit;
        
        if (NULL != pMessage && messageLen)
        {
            status = DIGI_MEMCPY(pShaInput + domLen + 2*MOC_CURVE448_ENCODING_SIZE, pMessage, messageLen);
            if (OK != status)
                goto exit;
        }
        
        status = pShaSuite->digestXOFFunc(MOC_HASH(hwAccelCtx) pShaInput, domLen + 2*MOC_CURVE448_ENCODING_SIZE + messageLen, pBuffer, MOC_EDDSA_SHAKE256_LEN);
        if (OK != status)
            goto exit;
    }
    
    /*
     5.2.7 Step 3, compute k = H mod L, ie we need to reduce mod L
     this method places the result back in pBuffer, pBuffer will be properly padded with an extra 0x00 byte for CURVE448_multiplyPoint.
     */
    status = reduceByteBufferByL448(pBuffer, &pK, &pL);
    if (OK != status)
        goto exit;
    
    /* compute R + k * A on the curve, re-use pA to store the result */
    status = CURVE448_multiplyPoint(MOC_ECC(hwAccelCtx) &pA[2], pBuffer, pA);
    if (OK != status)
        goto exit;
    
    CURVE448_addPoints(pA, &pA[2], &pA[1], (pf_unit *) &pA[3]);       /* re-use pA */
    
    /*
     Compute S * B on the curve, recall S is the second half of pSignature
     and the last byte is 0x00, so ok to input to the comb multiply routine
     */
    status = CURVE448_multiplyPoint(MOC_ECC(hwAccelCtx) &pA[2], pSignature + MOC_CURVE448_ENCODING_SIZE, NULL);
    if (OK != status)
        goto exit;
    
    /* Compare pA and pTemp, so convert each to encoded form, re-use pBuffer */
    status = CURVE448_convertProjectiveToEncoded(pBuffer, pA);
    if (OK != status)
        goto exit;
    
    status = CURVE448_convertProjectiveToEncoded(pBuffer + MOC_CURVE448_ENCODING_SIZE, &pA[2]);
    if (OK != status)
        goto exit;
    
    /* Compare */
    status = DIGI_MEMCMP(pBuffer, pBuffer+MOC_CURVE448_ENCODING_SIZE, MOC_CURVE448_ENCODING_SIZE, &compare);
    if (OK != status)
        goto exit;
    
    if (compare)
        *pVerifyStatus |= MOCANA_EDDSA_VERIFY_FAIL;
    
exit:
    
    /* Don't change status on below calls */
    DIGI_MEMSET(pBuffer, 0x00, MOC_EDDSA_SHAKE256_LEN);
    if (preHash)
    {
        DIGI_MEMSET(pPreHash, 0x00, MOC_CURVE448_PREHASH_LEN);
    }
    DIGI_MEMSET(pFlags, 0x00, 2);
    
    if (NULL != pShaCtx)
    {
        pShaSuite->freeFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
    }
    if (NULL != pShaInput)
    {
        DIGI_MEMSET( (ubyte *) pShaInput, 0x00, domLen + 2*MOC_CURVE448_ENCODING_SIZE + messageLen);
        DIGI_FREE((void **) &pShaInput);
    }
    
    if (NULL != pA)
    {
        DIGI_MEMSET( (ubyte *) pA, 0x00, 16 * MOC_CURVE448_NUM_UNITS * sizeof(pf_unit));
        DIGI_FREE((void **) &pA);
    }
    
    if (NULL != pK)
    {
        VLONG_freeVlong(&pK, NULL);
    }
    if (NULL != pL)
    {
        VLONG_freeVlong(&pL, NULL);
    }
    
    return status;
}


/*
 Internal initVerify method for edDSA on curve448. pSignature, pPubKey,
 and pShaSuite must have already been copied to the pEdDSA_ctx.
 */
static MSTATUS edDSA_curve448_initVerify(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx)
{
    MSTATUS status;
    int i;
    
    /* internal method, NULL checks already done */
    
    /* We will validate S (the second half of pSignature) before continuing */
    
    /* Last byte of S should be 0x00 */
    if (0x00 != pEdDSA_ctx->pSignature[2*MOC_CURVE448_ENCODING_SIZE - 1])
    {
        pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
        /* add MOCANA_EDDSA_VERIFY_FAIL too since we ignore this byte in calculating the point multiply S * B  */
        pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_FAIL;
    }
    
    /* make sure rest of S is not 0, if loop gets to 113 == i then it is */
    i = MOC_CURVE448_ENCODING_SIZE;
    while ( i < (2*MOC_CURVE448_ENCODING_SIZE - 1) && ( !(pEdDSA_ctx->pSignature[i]) ) )
    {
        i++;
    }
    if ( (2*MOC_CURVE448_ENCODING_SIZE - 1) == i)
    {
        pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
    }
    
    /*
     make sure S is not larger than or equal to L, S is Little Endian, L is Big Endian
     S's most significant byte is in byte 112 (ie 2*MOC_CURVE448_BYTE_SIZE ).
     */
    i = 0;
    while (i < MOC_CURVE448_BYTE_SIZE)
    {
        if ( pEdDSA_ctx->pSignature[2*MOC_CURVE448_BYTE_SIZE - i] > gpLbytes448[i] )
        {
            pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
            break;
        }
        else if ( pEdDSA_ctx->pSignature[2*MOC_CURVE448_BYTE_SIZE - i] < gpLbytes448[i] )
        {
            break;
        }
        i++;
    }
    if (MOC_CURVE448_BYTE_SIZE == i)   /*   S = L in this case  */
    {
        pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_S_INVALID;
    }
    
    status = pEdDSA_ctx->shaSuite.initFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx);
    if (OK != status)
        goto exit;
    
    if (!pEdDSA_ctx->preHash)
    {
        /* no support for context or pre-hash in init/update/final */
        ubyte pFlags[2] = {0};
        pFlags[1] = (ubyte) pEdDSA_ctx->ctxLen;

        /* unlike 25519 we always include dom4(F,C) */
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, (ubyte *) pSigEd448, sizeof(pSigEd448));
        if (OK != status)
            goto exit;

        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, (ubyte *) pFlags, 2);
        if (OK != status)
            goto exit;

        if (pEdDSA_ctx->ctxLen)
        {     
            status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pCtx, pEdDSA_ctx->ctxLen);
            if (OK != status)
                goto exit;
        }

        /*
            Validation of R will be postponed until finalVerify in order
            to save memory of storing a decoded R in the ctx
        */
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pSignature, MOC_CURVE448_ENCODING_SIZE);
        if (OK != status)
            goto exit;
            
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pPubKey, MOC_CURVE448_ENCODING_SIZE);
        if (OK != status)
            goto exit;

        /* ready for the message next */
    }
    /* else we are ready to hash the message on update */

exit:

    return status;
}


/* Internal finalVerify method for edDSA on curve448 */
static MSTATUS edDSA_curve448_finalVerify(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx)
{
    MSTATUS status;
    sbyte4 compare = -1; /* false default */
    
    ubyte pBuffer[MOC_EDDSA_SHAKE256_LEN] = {0};
    ubyte pPreHash[MOC_CURVE448_PREHASH_LEN] = {0};
    
    vlong *pK = NULL;
    vlong *pL = NULL;
    
    projPoint448 *pA = NULL;
    
    /* internal method, NULL checks already done */
    
    /*
     Allocate space for three projPoint448 (recall each point has 3 coords),
     and 7 more elements, so 16 elements total, in a single shot
     */
    status = DIGI_CALLOC((void **)&pA, 16 * MOC_CURVE448_NUM_UNITS, sizeof(pf_unit));
    if (OK != status)
        return status;
    
    /* Validate and convert the encoded public key and encoded R first */
    status = CURVE448_convertEncodedToProjective(pA, pEdDSA_ctx->pPubKey);
    if (ERR_NOT_FOUND == status)
        pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_PUB_KEY_INVALID;
    else if (OK != status)
        goto exit;
    
    status = CURVE448_convertEncodedToProjective(&pA[1], pEdDSA_ctx->pSignature);  /* R */
    if (ERR_NOT_FOUND == status)
        pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_R_INVALID;
    else if (OK != status)
        goto exit;
    
    if (pEdDSA_ctx->preHash)
    {
        ubyte pFlags[2] = {0x01, 0x00};
        pFlags[1] = (ubyte) pEdDSA_ctx->ctxLen;

        status = pEdDSA_ctx->shaSuite.finalXOFFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pPreHash, MOC_CURVE448_PREHASH_LEN);
        if (OK != status)
            goto exit;

        /* re init for the rest of the steps */
        status = pEdDSA_ctx->shaSuite.initFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx);
        if (OK != status)
            goto exit;

        /* dom2(F,C) */
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pSigEd448, sizeof(pSigEd448));
        if (OK != status)
            goto exit;
              
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pFlags, 2);
        if (OK != status)
            goto exit;

        if (pEdDSA_ctx->ctxLen)
        {    
            status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pCtx, pEdDSA_ctx->ctxLen);
            if (OK != status)
                goto exit;
        }
    
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pSignature, MOC_CURVE448_ENCODING_SIZE);
        if (OK != status)
            goto exit;
            
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pPubKey, MOC_CURVE448_ENCODING_SIZE);
        if (OK != status)
            goto exit;

        /* now ready for the hash of the message */
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pPreHash, MOC_CURVE448_PREHASH_LEN);
        if (OK != status)
            goto exit;
    }

    /* Finalize the Hash, Section 5.2.7 Step 2 */
    status = pEdDSA_ctx->shaSuite.finalXOFFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pBuffer, MOC_EDDSA_SHAKE256_LEN);
    if (OK != status)
        goto exit;
    
    /*
     5.2.7 Step 3, compute k = H mod L, ie we need to reduce mod L
     this method places the result back in pBuffer, pBuffer will be properly padded with an extra 0x00 byte for CURVE448_multiplyPoint.
     */
    status = reduceByteBufferByL448(pBuffer, &pK, &pL);
    if (OK != status)
        goto exit;
    
    /* compute R + k * A on the curve, re-use pA to store the result */
    status = CURVE448_multiplyPoint(MOC_ECC(hwAccelCtx) &pA[2], pBuffer, pA);
    if (OK != status)
        goto exit;
    
    CURVE448_addPoints(pA, &pA[2], &pA[1], (pf_unit *) &pA[3]);       /* re-use pA */
    
    /*
     Compute S * B on the curve, recall S is the second half of pSignature
     and the last byte is 0x00, so ok to enter into the comb multiply routine.
     */
    status = CURVE448_multiplyPoint(MOC_ECC(hwAccelCtx) &pA[2], pEdDSA_ctx->pSignature + MOC_CURVE448_ENCODING_SIZE, NULL);
    if (OK != status)
        goto exit;
    
    /* Compare pA and pTemp, so convert each to encoded form, re-use pBuffer */
    status = CURVE448_convertProjectiveToEncoded(pBuffer, pA);
    if (OK != status)
        goto exit;
    
    status = CURVE448_convertProjectiveToEncoded(pBuffer + MOC_CURVE448_ENCODING_SIZE, &pA[2]);
    if (OK != status)
        goto exit;
    
    /* Compare */
    status = DIGI_MEMCMP(pBuffer, pBuffer+MOC_CURVE448_ENCODING_SIZE, MOC_CURVE448_ENCODING_SIZE, &compare);
    if (OK != status)
        goto exit;
    
    if (compare)
        pEdDSA_ctx->verifyStatus |= MOCANA_EDDSA_VERIFY_FAIL;
    
exit:
    
    /* Don't change status on below calls */
    DIGI_MEMSET( pBuffer, 0x00, MOC_EDDSA_SHAKE256_LEN);
    if (pEdDSA_ctx->preHash)
    {
        DIGI_MEMSET(pPreHash, 0x00, MOC_CURVE448_PREHASH_LEN);
    }

    if (NULL != pA)
    {
        DIGI_MEMSET( (ubyte *) pA, 0x00, 16 * MOC_CURVE448_NUM_UNITS * sizeof(pf_unit));
        DIGI_FREE((void **) &pA);
    }
    
    if (NULL != pK)
    {
        VLONG_freeVlong(&pK, NULL);
    }
    if (NULL != pL)
    {
        VLONG_freeVlong(&pL, NULL);
    }
    
    return status;
}

static MSTATUS edDSA_curve448_finalSign(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte *pSignature)
{
    MSTATUS status;
    int i;
        
    ubyte pHash[MOC_EDDSA_SHAKE256_LEN] = {0};
    ubyte pHash2[MOC_EDDSA_SHAKE256_LEN] = {0};
    ubyte ps[MOC_CURVE448_ENCODING_SIZE] = {0};

    ubyte pPreHash[MOC_CURVE448_PREHASH_LEN] = {0};
    ubyte pFlags[2] = {0x01, 0x00};

    vlong *pVlong_r = NULL;
    vlong *pVlong_s = NULL;
    vlong *pVlong_k = NULL;
    vlong *pVlong_S = NULL;
    vlong *pVlong_L = NULL;
    sbyte4 Slen = MOC_CURVE448_BYTE_SIZE;
    
    projPoint448 *pR = NULL;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__
    ubyte pPubKeyCalc[MOC_CURVE448_ENCODING_SIZE];

    status = edECC_calculatePubFromPriv(MOC_ECC(hwAccelCtx) pPubKeyCalc, pEdDSA_ctx->pPrivKey, curveEd448, &pEdDSA_ctx->shaSuite, TRUE);
    if (OK != status)
        goto exit;
#endif

    /* internal method, NULL checks already done */
    
    pFlags[1] = (ubyte) pEdDSA_ctx->ctxLen;

    /* finish the pre hash */
    status = pEdDSA_ctx->shaSuite.finalXOFFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pPreHash, MOC_CURVE448_PREHASH_LEN);
    if (OK != status)
        goto exit;
  
    /* Allocate space for a projPoint448 */
    status = DIGI_CALLOC((void **)&pR, 1, sizeof(projPoint448));
    if (OK != status)
        goto exit;

    status = pEdDSA_ctx->shaSuite.initFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx);
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pPrivKey, MOC_CURVE448_ENCODING_SIZE);
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.finalXOFFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pHash, MOC_EDDSA_SHAKE256_LEN);
    if (OK != status)
        goto exit;

    /* copy the scalar s out of the first 32 bytes of pHash, considered as a (bytewise) Little Endian integer */
    status = DIGI_MEMCPY(ps, pHash, MOC_CURVE448_ENCODING_SIZE);
    if (OK != status)
        goto exit;
    
    ps[0] &= 0xfc;  /* set the lowest 2 bits to 0 */
    ps[MOC_CURVE448_ENCODING_SIZE-1] = 0x00;  /* set the highest byte to 0 */
    ps[MOC_CURVE448_ENCODING_SIZE-2] |= 0x80; /* second highest bit (2^447) to one */
    
    /* Section 5.2.6 Step 2, use the rest of the pHash as a salt to the message */
    status = pEdDSA_ctx->shaSuite.initFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx);
    if (OK != status)
        goto exit;
    
    /* dom2(F,C) */
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pSigEd448, sizeof(pSigEd448));
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pFlags, 2);
    if (OK != status)
        goto exit;

    if (pEdDSA_ctx->ctxLen)
    {
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pCtx, pEdDSA_ctx->ctxLen);
        if (OK != status)
            goto exit;
    }        
    
    /* prefix */
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pHash + MOC_CURVE448_ENCODING_SIZE, MOC_CURVE448_ENCODING_SIZE);
    if (OK != status)
        goto exit;
    
    /* PH(M) */
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pPreHash, MOC_CURVE448_PREHASH_LEN);
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.finalXOFFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pHash2, MOC_EDDSA_SHAKE256_LEN);  /* pHash2 is now the scalar r */
    if (OK != status)
        goto exit;
    
    /*
     reduce r mod L. Note this method will return the result back in pHash
     in Little Endian as well as in pVlong_r. pHash2 will be properly padded with an extra 0x00 byte for CURVE448_multiplyPoint.
     */
    status = reduceByteBufferByL448(pHash2, &pVlong_r, &pVlong_L);
    if (OK != status)
        goto exit;
    
    /* Section 5.2.6 Step 3, compute the scalar produce R = r * B, NULL indicates to multiply by B */
    status = CURVE448_multiplyPoint(MOC_ECC(hwAccelCtx) pR, pHash2, NULL);
    if (OK != status)
        goto exit;
    
    /* Encode the point R for the first half of the signature */
    status = CURVE448_convertProjectiveToEncoded(pSignature, pR);
    if (OK != status)
        goto exit;
    
    /* Section 5.2.6 Step 4, compute k */
    status = pEdDSA_ctx->shaSuite.initFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx);
    if (OK != status)
        goto exit;
    
    /* dom4(F,C) */
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pSigEd448, sizeof(pSigEd448));
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pFlags, 2);
    if (OK != status)
        goto exit;

    if (pEdDSA_ctx->ctxLen)
    {
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pCtx, pEdDSA_ctx->ctxLen);
        if (OK != status)
            goto exit;
    }

    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pSignature, MOC_CURVE448_ENCODING_SIZE);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__     
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pPubKeyCalc, MOC_CURVE448_ENCODING_SIZE);
#else
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pEdDSA_ctx->pPubKey, MOC_CURVE448_ENCODING_SIZE);
#endif
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pPreHash, MOC_CURVE448_PREHASH_LEN);
    if (OK != status)
        goto exit;
    
    status = pEdDSA_ctx->shaSuite.finalXOFFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pHash, MOC_EDDSA_SHAKE256_LEN); /* pHash is now k */
    if (OK != status)
        goto exit;
    
    /* reduce k mod L */
    status = reduceByteBufferByL448(pHash, &pVlong_k, &pVlong_L);
    if (OK != status)
        goto exit;

    /* Section 5.2.6 Step 5, compute S = (r + k * s) mod L */
    status = VLONG_allocVlong(&pVlong_S, NULL);
    if (OK != status)
        goto exit;
    
#ifdef __ENABLE_DIGICERT_64_BIT__
    status = VLONG_reallocVlong (pVlong_S, (MOC_CURVE448_BYTE_SIZE/4)+1);
    if (OK != status)
        goto exit;
#else
    status = VLONG_reallocVlong (pVlong_S, (MOC_CURVE448_BYTE_SIZE/2)+1);
    if (OK != status)
        goto exit;
#endif
    
    /* Convert s to Big Endian for vlong-ification */
    for (i = 0; i < (MOC_CURVE448_BYTE_SIZE/2); ++i)
    { /* swap with xor */
        ps[i] = ps[i] ^  ps[MOC_CURVE448_BYTE_SIZE - 1 - i];
        ps[MOC_CURVE448_BYTE_SIZE - 1 - i] = ps[MOC_CURVE448_BYTE_SIZE - 1 - i] ^ ps[i];
        ps[i] = ps[i] ^  ps[MOC_CURVE448_BYTE_SIZE - 1 - i];
    }
    
    status = VLONG_vlongFromByteString (ps, MOC_CURVE448_BYTE_SIZE, &pVlong_s, NULL);
    if (OK != status)
        goto exit;
    
    status = VLONG_unsignedMultiply(pVlong_S, pVlong_k, pVlong_s);
    if (OK != status)
        goto exit;
    
    status = addUnsignedVlongs (pVlong_S, pVlong_r);
    if (OK != status)
        goto exit;
    
    /* re-use pVlong_s for S mod L */
    status = VLONG_unsignedDivide (pVlong_k, pVlong_S,  pVlong_L, pVlong_s, NULL);
    if (OK != status)
        goto exit;
    
    status = VLONG_byteStringFromVlong (pVlong_s, pSignature + MOC_CURVE448_ENCODING_SIZE, &Slen);
    if (OK != status)
        goto exit;
    
    /* S is Big Endian in bytes 57 to 112 of pSignature. Convert to Little Endian. */
    for (i = MOC_CURVE448_ENCODING_SIZE; i < 85; ++i)   /* 85 is halfway point */
    {
        pSignature[i] = pSignature[i] ^ pSignature[169 - i]; /* starts at 112, 111, 110 ... */
        pSignature[169 - i] = pSignature[169 - i] ^ pSignature[i];
        pSignature[i] = pSignature[i] ^ pSignature[169 - i];
    }
    /* last byte of an encoded S is zero */
    pSignature[2*MOC_CURVE448_ENCODING_SIZE - 1] = 0x00;
    
exit:
    
    /* Don't change status on below calls */
    if (OK != status)
    {
        DIGI_MEMSET(pSignature, 0x00, 2*MOC_CURVE448_ENCODING_SIZE);
    }
    
    DIGI_MEMSET(pHash, 0x00, MOC_EDDSA_SHAKE256_LEN);
    DIGI_MEMSET(pHash2, 0x00, MOC_EDDSA_SHAKE256_LEN);
    DIGI_MEMSET(ps, 0x00, MOC_CURVE448_ENCODING_SIZE);
    DIGI_MEMSET(pPreHash, 0x00, MOC_CURVE448_PREHASH_LEN);
    DIGI_MEMSET(pFlags, 0x00, 2);
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__  
    DIGI_MEMSET(pPubKeyCalc, 0x00, MOC_CURVE448_ENCODING_SIZE);
#endif

    if (NULL != pR)
    {
        DIGI_MEMSET( (ubyte *) pR, 0x00, sizeof(projPoint448));
        DIGI_FREE((void **) &pR);
    }
    
    if (NULL != pVlong_k)
    {
        VLONG_freeVlong(&pVlong_k, NULL);
    }
    if (NULL != pVlong_s)
    {
        VLONG_freeVlong(&pVlong_s, NULL);
    }
    if (NULL != pVlong_r)
    {
        VLONG_freeVlong(&pVlong_r, NULL);
    }
    if (NULL != pVlong_S)
    {
        VLONG_freeVlong(&pVlong_S, NULL);
    }
    if (NULL != pVlong_L)
    {
        VLONG_freeVlong(&pVlong_L, NULL);
    }
    
    return status;
}
#endif /* __ENABLE_DIGICERT_ECC_EDDSA_448__ */


/***************************************************************************************************************/


#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)

/*
 edDSA sign. pKey must be a private key.
 pSignatureLen will hold its length in bytes (twice the curve's encoding size of course).
 */
MSTATUS edDSA_Sign(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature,
                   ubyte4 bufferSize, ubyte4 *pSignatureLen, BulkHashAlgo *pShaSuite, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    byteBoolean isShaEvp = TRUE;
    ubyte4 sigLen = 0;
  
    MOC_UNUSED(pExtCtx);

    /* Allow pMessage NULL if we have zero messageLen */
    if ( NULL == pKey || (NULL == pMessage && messageLen) || NULL == pSignatureLen || NULL == pShaSuite || (NULL == pCtx && ctxLen) )
        return ERR_NULL_POINTER;

    if (ctxLen > 255) /* rfc 8032 requirement for ctx mode */
        return ERR_INVALID_ARG;
    
    /* Check for a valid sha suite */
    if (NULL == pShaSuite->allocFunc || NULL == pShaSuite->initFunc || NULL == pShaSuite->updateFunc || NULL == pShaSuite->freeFunc ||
        (NULL == pShaSuite->finalFunc && curveEd25519 == pKey->curve) || (NULL == pShaSuite->finalXOFFunc && curveEd448 == pKey->curve))
    {
        /* sha evp methods are not available. Check to see if we can do a one shot digest mode */
        if ( (NULL == pShaSuite->digestFunc && curveEd25519 == pKey->curve) || (NULL == pShaSuite->digestXOFFunc && curveEd448 == pKey->curve))
            return ERR_EC_INVALID_HASH_ALGO;
        else
            isShaEvp = FALSE;
    }
    
    if (!pKey->isPrivate)
        return ERR_EC_INVALID_KEY_TYPE;
    
    if (NULL == pKey->pPrivKey)
        return ERR_EC_UNALLOCATED_KEY;

#ifndef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__
    if (NULL == pKey->pPubKey)
        return ERR_EC_UNALLOCATED_KEY;
#endif

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,pKey->curve);

    switch(pKey->curve)
    {
        case curveEd25519:
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
            
            sigLen = 2*MOC_CURVE25519_ENCODING_SIZE;
            
            if (NULL == pSignature || bufferSize < sigLen)
            {
                *pSignatureLen = sigLen;
                status = ERR_BUFFER_TOO_SMALL;
                goto exit;
            }
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__
            status = edDSA_curve25519_sign(MOC_ECC(hwAccelCtx) pKey->pPrivKey, NULL, pMessage, messageLen, pSignature, pShaSuite, preHash, pCtx, ctxLen, isShaEvp);
#else
            status = edDSA_curve25519_sign(MOC_ECC(hwAccelCtx) pKey->pPrivKey, pKey->pPubKey, pMessage, messageLen, pSignature, pShaSuite, preHash, pCtx, ctxLen, isShaEvp);
#endif
#else
            status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA_25519__ */
            break;
            
        case curveEd448:
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
            
            sigLen = 2*MOC_CURVE448_ENCODING_SIZE;
            
            if (NULL == pSignature || bufferSize < sigLen)
            {
                *pSignatureLen = sigLen;
                status = ERR_BUFFER_TOO_SMALL;
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__
            status = edDSA_curve448_sign(MOC_ECC(hwAccelCtx) pKey->pPrivKey, NULL, pMessage, messageLen, pSignature, pShaSuite, preHash, pCtx, ctxLen, isShaEvp);
#else
            status = edDSA_curve448_sign(MOC_ECC(hwAccelCtx) pKey->pPrivKey, pKey->pPubKey, pMessage, messageLen, pSignature, pShaSuite, preHash, pCtx, ctxLen, isShaEvp);
#endif
#else
            status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA_448__ */
            break;
        
        default:
            status = ERR_EDECC_INVALID_CURVE_ID_FOR_ALG;
    }

    if (OK == status)
        *pSignatureLen = sigLen;
    
exit:
    
    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,pKey->curve);
    return status;

}


/*
 A context free one shot edDSA verify API. We still use the sha evp methods if available by
 default. pKey must be a public key.
 */
MSTATUS edDSA_VerifySignature(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature,
                              ubyte4 signatureLen, ubyte4 *pVerifyStatus, BulkHashAlgo *pShaSuite, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    byteBoolean isShaEvp = TRUE;
    
    MOC_UNUSED(pExtCtx);
    
    /* Allow pMessage NULL if we have zero messageLen */
    if ( NULL == pKey || (NULL == pMessage && messageLen) || NULL == pSignature || NULL == pVerifyStatus || NULL == pShaSuite || (NULL == pCtx && ctxLen) )
        return ERR_NULL_POINTER;
    
    if (ctxLen > 255) /* rfc 8032 requirement for ctx mode */
        return ERR_INVALID_ARG;

    /* Check for a valid sha suite */
    if (NULL == pShaSuite->allocFunc || NULL == pShaSuite->initFunc || NULL == pShaSuite->updateFunc || NULL == pShaSuite->freeFunc ||
        (NULL == pShaSuite->finalFunc && curveEd25519 == pKey->curve) || (NULL == pShaSuite->finalXOFFunc && curveEd448 == pKey->curve))
    {
        /* sha evp methods are not available. Check to see if we can do a one shot digest mode */
        if ( (NULL == pShaSuite->digestFunc && curveEd25519 == pKey->curve) || (NULL == pShaSuite->digestXOFFunc && curveEd448 == pKey->curve))
            return ERR_EC_INVALID_HASH_ALGO;
        else
            isShaEvp = FALSE;
    }
    
    if (pKey->isPrivate)
        return ERR_EC_INVALID_KEY_TYPE;
    
    if (NULL == pKey->pPubKey)
        return ERR_EC_UNALLOCATED_KEY;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,pKey->curve);

    *pVerifyStatus = 0x80000000; /* non-zero default, we'll un-set the first bit at the end  */
    
    switch(pKey->curve)
    {
        case curveEd25519:
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
            
            /* Quick check of signature Size */
            if (2*MOC_CURVE25519_ENCODING_SIZE != signatureLen)
            {
                status = ERR_ECDSA_INVALID_SIGNATURE_SIZE;
                goto exit;
            }
            
            status = edDSA_curve25519_VerifySignature(MOC_ECC(hwAccelCtx) pKey->pPubKey, pMessage, messageLen, pSignature, pVerifyStatus, pShaSuite, preHash, pCtx, ctxLen, isShaEvp);
#else
            status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA_25519__ */
            break;
            
        case curveEd448:
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
            
            /* Quick check of signature Size. Postpone other checks until finalVerify  */
            if (2*MOC_CURVE448_ENCODING_SIZE != signatureLen)
            {
                status = ERR_ECDSA_INVALID_SIGNATURE_SIZE;
                goto exit;
            }
            
            status = edDSA_curve448_VerifySignature(MOC_ECC(hwAccelCtx) pKey->pPubKey, pMessage, messageLen, pSignature, pVerifyStatus, pShaSuite, preHash, pCtx, ctxLen, isShaEvp);
#else
            status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA_448__ */
            break;
            
        default:
            status = ERR_EDECC_INVALID_CURVE_ID_FOR_ALG;
    }
    
exit:
    
    if (OK == status)  /* un-set the first bit in pVerifyStatus */
        *pVerifyStatus &= 0x7fffffff;
    
    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,pKey->curve);
    return status;
}

/* only pre hash mode available */
MSTATUS edDSA_initSignPreHash(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, edECCKey *pKey, BulkHashAlgo *pShaSuite, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    ubyte4 encodingSize = 0;
    
    MOC_UNUSED(pExtCtx);
    
    if (NULL == pEdDSA_ctx || NULL == pKey || NULL == pShaSuite || (NULL == pCtx && ctxLen) )
        return ERR_NULL_POINTER;
    
    if (pEdDSA_ctx->initialized)
        return ERR_ECDSA_ALREADY_INITIALIZED_CTX;
    
    /* We must have EVP style methods in the pShaSuite */
    if (NULL == pShaSuite->allocFunc || NULL == pShaSuite->initFunc || NULL == pShaSuite->updateFunc || NULL == pShaSuite->freeFunc ||
        (NULL == pShaSuite->finalFunc && curveEd25519 == pKey->curve) || (NULL == pShaSuite->finalXOFFunc && curveEd448 == pKey->curve))
        return ERR_EC_INVALID_HASH_ALGO;
    
    if (!pKey->isPrivate)
        return ERR_EC_INVALID_KEY_TYPE;
        
    if (NULL == pKey->pPrivKey)
        return ERR_EC_UNALLOCATED_KEY;

#ifndef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__
    if (NULL == pKey->pPubKey)
        return ERR_EC_UNALLOCATED_KEY;
#endif

    /* validate the curve and get the encoding size */
    switch (pKey->curve)
    {
        case curveEd25519:
            encodingSize = MOC_CURVE25519_ENCODING_SIZE;
            break;
            
        case curveEd448:
            encodingSize = MOC_CURVE448_ENCODING_SIZE;
            break;
            
        default:
            status = ERR_EDECC_INVALID_CURVE_ID_FOR_ALG;
            return status;
    }

    if (ctxLen > 255)
        return ERR_INVALID_ARG;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,pKey->curve);

    /* set to NULL in case we error */
    pEdDSA_ctx->pShaCtx = NULL;
    pEdDSA_ctx->pPubKey = NULL;
    pEdDSA_ctx->pPrivKey = NULL;
    pEdDSA_ctx->pCtx = NULL;

    pEdDSA_ctx->curve = pKey->curve;
    pEdDSA_ctx->ctxLen = ctxLen;
    pEdDSA_ctx->preHash = 1; /* not used but set anyway */

    /* allocate and copy the public keys and ctx */
#ifndef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__
    status = DIGI_MALLOC((void **) &pEdDSA_ctx->pPubKey, encodingSize);
    if (OK != status)
        goto exit;
#endif

    status = DIGI_MALLOC((void **) &pEdDSA_ctx->pPrivKey, encodingSize);
    if (OK != status)
        goto exit;

    /* and the context if it is there */
    if (ctxLen)
    {
        status = DIGI_MALLOC((void **) &pEdDSA_ctx->pCtx, ctxLen);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pEdDSA_ctx->pCtx, pCtx, ctxLen);
        if (OK != status)
            goto exit;
    }

    /* Copy the public key and signature to the ctx */
#ifndef __ENABLE_DIGICERT_ECC_EDDSA_SIGN_GEN_PUB__
    status = DIGI_MEMCPY(pEdDSA_ctx->pPubKey, pKey->pPubKey, encodingSize);
    if (OK != status)
        goto exit;
#endif

    status = DIGI_MEMCPY(pEdDSA_ctx->pPrivKey, pKey->pPrivKey, encodingSize);
    if (OK != status)
        goto exit;

    /* Copy the pShaSuite to the edDSA_CTX */
    status = DIGI_MEMCPY((void *) &pEdDSA_ctx->shaSuite, (void *) pShaSuite, sizeof(BulkHashAlgo));
    if (OK != status)
        goto exit;
    
    /* Allocate the pShaCtx in the pEdDSA_ctx */
    status = pShaSuite->allocFunc(MOC_HASH(hwAccelCtx) &pEdDSA_ctx->pShaCtx);
    if (OK != status)
        goto exit;

    status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx);
    /* must be pre-hash mode, ready for message */
    
exit:

    if (OK != status)
    {
        /* Leave status unchanged */
        if (NULL != pEdDSA_ctx->pShaCtx)
            pShaSuite->freeFunc(MOC_HASH(hwAccelCtx) &pEdDSA_ctx->pShaCtx);
        
        if (NULL != pEdDSA_ctx->pPubKey)
        {
            DIGI_MEMSET(pEdDSA_ctx->pPubKey, 0x00, encodingSize);
            DIGI_FREE((void **) &pEdDSA_ctx->pPubKey);
        }
        if (NULL != pEdDSA_ctx->pPrivKey)
        {
            DIGI_MEMSET(pEdDSA_ctx->pPrivKey, 0x00, encodingSize);
            DIGI_FREE((void **) &pEdDSA_ctx->pPrivKey);
        }
        if (NULL != pEdDSA_ctx->pCtx)
        {
            DIGI_MEMSET(pEdDSA_ctx->pCtx, 0x00, ctxLen);
            DIGI_FREE((void **) &pEdDSA_ctx->pCtx);
        }
        
        DIGI_MEMSET((ubyte *) pEdDSA_ctx, 0x00, sizeof(edDSA_CTX));
    }
    else
    {
        pEdDSA_ctx->initialized = TRUE;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,pKey->curve);
    return status;
}

/*
 Initializes the edDSA_verify operation. The public key and signature
 are copied to the pEdDSA_ctx. The signature component S is validated
 and the hashing process is started.
 
 pShaSuite's must have EVP methods defined. We cannot do our own message
 chunk concatenation at this point since we don't know the full length of
 the message.
 */
MSTATUS edDSA_initVerify(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, edECCKey *pKey, ubyte *pSignature, ubyte4 signatureLen, BulkHashAlgo *pShaSuite, 
                         byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    ubyte4 encodingSize = 0;
    
    MOC_UNUSED(pExtCtx);
    
    if (NULL == pEdDSA_ctx || NULL == pKey || NULL == pSignature || NULL == pShaSuite || (NULL == pCtx && ctxLen) )
        return ERR_NULL_POINTER;
    
    if (pEdDSA_ctx->initialized)
        return ERR_ECDSA_ALREADY_INITIALIZED_CTX;
    
    /* We must have EVP style methods in the pShaSuite */
    if (NULL == pShaSuite->allocFunc || NULL == pShaSuite->initFunc || NULL == pShaSuite->updateFunc || NULL == pShaSuite->freeFunc ||
        (NULL == pShaSuite->finalFunc && curveEd25519 == pKey->curve) || (NULL == pShaSuite->finalXOFFunc && curveEd448 == pKey->curve))
        return ERR_EC_INVALID_HASH_ALGO;
    
    if (pKey->isPrivate)
        return ERR_EC_INVALID_KEY_TYPE;
    
    if (NULL == pKey->pPubKey)
        return ERR_EC_UNALLOCATED_KEY;
    
    /* validate the curve and get the encoding size */
    switch (pKey->curve)
    {
        case curveEd25519:
            encodingSize = MOC_CURVE25519_ENCODING_SIZE;
            break;
            
        case curveEd448:
            encodingSize = MOC_CURVE448_ENCODING_SIZE;
            break;
            
        default:
            status = ERR_EDECC_INVALID_CURVE_ID_FOR_ALG;
            return status;
    }
    
    /* Check of signature Size */
    if (signatureLen != 2*encodingSize)
        return ERR_ECDSA_INVALID_SIGNATURE_SIZE;

    if (ctxLen > 255)
        return ERR_INVALID_ARG;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,pKey->curve);

    /* set to NULL in case we error */
    pEdDSA_ctx->pShaCtx = NULL;
    pEdDSA_ctx->pPubKey = NULL;
    pEdDSA_ctx->pSignature = NULL;
    pEdDSA_ctx->pCtx = NULL;
    
    pEdDSA_ctx->curve = pKey->curve;
    pEdDSA_ctx->verifyStatus = 0; /* ok to have 0 default since this is internal */
    pEdDSA_ctx->preHash = preHash;
    pEdDSA_ctx->ctxLen = ctxLen;

    /* allocate and copy the public key and signature */
    status = DIGI_MALLOC((void **) &pEdDSA_ctx->pPubKey, encodingSize);
    if (OK != status)
        goto exit;
    
    status = DIGI_MALLOC((void **) &pEdDSA_ctx->pSignature, signatureLen);
    if (OK != status)
        goto exit;

    /* and the context if it is there */
    if (ctxLen)
    {
        status = DIGI_MALLOC((void **) &pEdDSA_ctx->pCtx, ctxLen);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pEdDSA_ctx->pCtx, pCtx, ctxLen);
        if (OK != status)
            goto exit;
    }

    /* Copy the public key and signature to the ctx */
    status = DIGI_MEMCPY(pEdDSA_ctx->pPubKey, pKey->pPubKey, encodingSize);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCPY(pEdDSA_ctx->pSignature, pSignature, signatureLen);
    if (OK != status)
        goto exit;

    /* Copy the pShaSuite to the edDSA_CTX */
    status = DIGI_MEMCPY((void *) &pEdDSA_ctx->shaSuite, (void *) pShaSuite, sizeof(BulkHashAlgo));
    if (OK != status)
        goto exit;
    
    /* Allocate the pShaCtx in the pEdDSA_ctx */
    status = pShaSuite->allocFunc(MOC_HASH(hwAccelCtx) &pEdDSA_ctx->pShaCtx);
    if (OK != status)
        goto exit;
    
    switch(pEdDSA_ctx->curve)
    {
        case curveEd25519:
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
            status = edDSA_curve25519_initVerify(MOC_ECC(hwAccelCtx) pEdDSA_ctx);
#else
            status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA_25519__ */
            break;
            
        case curveEd448:
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
            status = edDSA_curve448_initVerify(MOC_ECC(hwAccelCtx) pEdDSA_ctx);
#else
            status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA_448__ */
            break;
            
        default:
            status = ERR_EDECC_INVALID_CURVE_ID_FOR_ALG;
    }
    
exit:
    
    if (OK != status)
    {
        /* Leave status unchanged */
        if (NULL != pEdDSA_ctx->pShaCtx)
            pShaSuite->freeFunc(MOC_HASH(hwAccelCtx) &pEdDSA_ctx->pShaCtx);
        
        if (NULL != pEdDSA_ctx->pPubKey)
        {
            DIGI_MEMSET(pEdDSA_ctx->pPubKey, 0x00, encodingSize);
            DIGI_FREE((void **) &pEdDSA_ctx->pPubKey);
        }
        if (NULL != pEdDSA_ctx->pSignature)
        {
            DIGI_MEMSET(pEdDSA_ctx->pSignature, 0x00, signatureLen);
            DIGI_FREE((void **) &pEdDSA_ctx->pSignature);
        }
        if (NULL != pEdDSA_ctx->pCtx)
        {
            DIGI_MEMSET(pEdDSA_ctx->pCtx, 0x00, ctxLen);
            DIGI_FREE((void **) &pEdDSA_ctx->pCtx);
        }
        
        DIGI_MEMSET((ubyte *) pEdDSA_ctx, 0x00, sizeof(edDSA_CTX));
    }
    else
    {
        pEdDSA_ctx->initialized = TRUE;
    }
    
    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,pKey->curve);
    return status;
}


/* Updates the digest calculation in pEdDSA_ctx with the message or portion of the message */
MSTATUS edDSA_update(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte *pMessage, ubyte4 messageLen, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    MOC_UNUSED(pExtCtx);
    
    /* Allow NULL message if messageLen is 0 */
    if (NULL == pEdDSA_ctx || (NULL == pMessage && messageLen) )
        return ERR_NULL_POINTER;
    
    if ( !(pEdDSA_ctx->initialized) )
        return ERR_ECDSA_UNINITIALIZED_CTX;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,pEdDSA_ctx->curve);

    if (NULL != pMessage && messageLen)
    {
        status = pEdDSA_ctx->shaSuite.updateFunc(MOC_HASH(hwAccelCtx) pEdDSA_ctx->pShaCtx, pMessage, messageLen);
    }
    
    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,0);
    return status;
}

/*
 Finalizes the EdDSA sign operation. Returns OK on successful completion of the method.
 */
MSTATUS edDSA_finalSign(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte *pSignature, ubyte4 bufferSize, ubyte4 *pSignatureLen, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    ubyte4 sigLen = 0;
    
    MOC_UNUSED(pExtCtx);
    
    if (NULL == pEdDSA_ctx || NULL == pSignatureLen)
        return ERR_NULL_POINTER;
    
    if ( !(pEdDSA_ctx->initialized) )
        return ERR_ECDSA_UNINITIALIZED_CTX;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,pEdDSA_ctx->curve);

    switch(pEdDSA_ctx->curve)
    {
        case curveEd25519:
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
            
            sigLen = 2*MOC_CURVE25519_ENCODING_SIZE;
            
            if (NULL == pSignature || bufferSize < sigLen)
            {
                *pSignatureLen = sigLen;
                status = ERR_BUFFER_TOO_SMALL;
                goto exit;
            }
            
            status = edDSA_curve25519_finalSign(MOC_ECC(hwAccelCtx) pEdDSA_ctx, pSignature);
#else
            status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA_25519__ */
            break;
            
        case curveEd448:
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
            
            sigLen = 2*MOC_CURVE448_ENCODING_SIZE;
            
            if (NULL == pSignature || bufferSize < sigLen)
            {
                *pSignatureLen = sigLen;
                status = ERR_BUFFER_TOO_SMALL;
                goto exit;
            }

            status = edDSA_curve448_finalSign(MOC_ECC(hwAccelCtx) pEdDSA_ctx, pSignature);
#else
            status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA_448__ */
            break;
        
        default:
            status = ERR_EDECC_INVALID_CURVE_ID_FOR_ALG;
            goto exit;
    }

    if (OK == status)
        *pSignatureLen = sigLen;
    
exit:
    
    if (OK == status)
    {        
        /* cleanup, make sure the freeFunc succeeds first */
        if (NULL != pEdDSA_ctx->pShaCtx)
        {
            status = pEdDSA_ctx->shaSuite.freeFunc(MOC_HASH(hwAccelCtx) &pEdDSA_ctx->pShaCtx);
        }
        
        if (OK == status)
        {
            /* Now ok to ignore status return codes */
            if (NULL != pEdDSA_ctx->pPubKey)
            {
                DIGI_MEMSET(pEdDSA_ctx->pPubKey, 0x00, sigLen/2);
                DIGI_FREE((void **) &pEdDSA_ctx->pPubKey);
            }
            
            if (NULL != pEdDSA_ctx->pPrivKey)
            {
                DIGI_MEMSET(pEdDSA_ctx->pPrivKey, 0x00, sigLen/2);
                DIGI_FREE((void **) &pEdDSA_ctx->pPrivKey);
            }

            if (NULL != pEdDSA_ctx->pCtx)
            {
                DIGI_MEMSET(pEdDSA_ctx->pCtx, 0x00, pEdDSA_ctx->ctxLen);
                DIGI_FREE((void **) &pEdDSA_ctx->pCtx);
            }
            
            /* This will set initialized flag back to FALSE too */
            DIGI_MEMSET((ubyte *) pEdDSA_ctx, 0x00, sizeof(edDSA_CTX));
        }
    }
    
    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,0);
    return status;
}

/*
 Finalizes the edDSA_verify operation. Returns OK on successful completion of the
 method. Sets pVerifyStatus to zero if the signature is valid and non-zero otherwise.
 */
MSTATUS edDSA_finalVerify(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte4 *pVerifyStatus, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    ubyte4 encodingSize = 0;
    
    MOC_UNUSED(pExtCtx);
    
    if (NULL == pEdDSA_ctx || NULL == pVerifyStatus)
        return ERR_NULL_POINTER;
    
    if ( !(pEdDSA_ctx->initialized) )
        return ERR_ECDSA_UNINITIALIZED_CTX;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_EDDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_EDDSA,pEdDSA_ctx->curve);

    *pVerifyStatus = 0x80000000; /* set to non-zero default */
    
    switch(pEdDSA_ctx->curve)
    {
        case curveEd25519:
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
            
            status = edDSA_curve25519_finalVerify(MOC_ECC(hwAccelCtx) pEdDSA_ctx);
            encodingSize = MOC_CURVE25519_ENCODING_SIZE;
#else
            status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA_25519__ */
            break;
            
        case curveEd448:
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
            status = edDSA_curve448_finalVerify(MOC_ECC(hwAccelCtx) pEdDSA_ctx);
            encodingSize = MOC_CURVE448_ENCODING_SIZE;
#else
            status = ERR_NOT_IMPLEMENTED;
#endif /* __ENABLE_DIGICERT_ECC_EDDSA_448__ */
            break;
            
        default:
            status = ERR_EDECC_INVALID_CURVE_ID_FOR_ALG;
            goto exit;
    }
    
    *pVerifyStatus |= pEdDSA_ctx->verifyStatus;

exit:
    
    if (OK == status)
    {
        /* remove the leading set bit on success */
        *pVerifyStatus &= 0x7fffffff;
        
        /* cleanup, make sure the freeFunc succeeds first */
        if (NULL != pEdDSA_ctx->pShaCtx)
        {
            status = pEdDSA_ctx->shaSuite.freeFunc(MOC_HASH(hwAccelCtx) &pEdDSA_ctx->pShaCtx);
        }
        
        if (OK == status)
        {
            /* Now ok to ignore status return codes */
            if (NULL != pEdDSA_ctx->pPubKey)
            {
                DIGI_MEMSET(pEdDSA_ctx->pPubKey, 0x00, encodingSize);
                DIGI_FREE((void **) &pEdDSA_ctx->pPubKey);
            }
            
            if (NULL != pEdDSA_ctx->pSignature)
            {
                DIGI_MEMSET(pEdDSA_ctx->pSignature, 0x00, 2*encodingSize);
                DIGI_FREE((void **) &pEdDSA_ctx->pSignature);
            }

            if (NULL != pEdDSA_ctx->pCtx)
            {
                DIGI_MEMSET(pEdDSA_ctx->pCtx, 0x00, pEdDSA_ctx->ctxLen);
                DIGI_FREE((void **) &pEdDSA_ctx->pCtx);
            }
            
            /* This will set initialized flag back to FALSE too */
            DIGI_MEMSET((ubyte *) pEdDSA_ctx, 0x00, sizeof(edDSA_CTX));
        }
    }
    
    FIPS_LOG_END_ALG(FIPS_ALGO_EDDSA,pEdDSA_ctx->curve);
    return status;
}

#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) */
#endif /* __ENABLE_DIGICERT_ECC__ */
