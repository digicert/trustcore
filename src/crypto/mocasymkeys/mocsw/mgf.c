/*
 * mgf1.c
 *
 * Perform Mask Generating FUnction 1 (MGF1) used in OAEP and PSS.
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

#include "../../../crypto/mocasym.h"
#include "../../../harness/harness.h"

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_PKCS1__))

MOC_EXTERN MSTATUS MaskGenFunction1(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const ubyte *mgfSeed,
    ubyte4 mgfSeedLen,
    ubyte4 maskLen,
    BulkHashAlgo *H,
    ubyte **ppRetMask
    )
{
    /* RFC 3447, section B.2.1: MGF1 is a Mask Generation Function based on a hash function */
    BulkCtx hashCtx = NULL;
    ubyte*  T    = NULL;
    ubyte*  C    = NULL;
    ubyte*  mask = NULL;
    ubyte4  Tlen;
    ubyte4  TbufLen = 0;
    MSTATUS status;

    if ((NULL == mgfSeed) || (NULL == H) || (NULL == ppRetMask))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* maskLen and mgfSeedLen are ubyte4 types so < 2^32 by defition.
       Therefore maskLen < 2^32 * hashLen and mgfSeedLen < max_hash_inputLen (which is typically 2^64-1).
       SP 800-56B Rev 2 compliance is therefore satisfied, no need for these checks */
    
    TbufLen = maskLen + H->digestSize;

    if (NULL == (T = MALLOC(TbufLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL == (mask = MALLOC(maskLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, 4, TRUE, &C)))
        goto exit;

    DEBUG_RELABEL_MEMORY(C);

    /* C = 0 */
    C[0] = C[1] = C[2] = C[3] = 0;

    /* setup hash context */
    if (OK > (status = H->allocFunc(MOC_HASH(hwAccelCtx) &hashCtx)))
        goto exit;

    for (Tlen = 0; Tlen < maskLen; Tlen += H->digestSize)
    {
        /* T = T || Hash(mgfSeed || C) */
        if (OK > (status = H->initFunc(MOC_HASH(hwAccelCtx) hashCtx)))
            goto exit;

        if (OK > (status = H->updateFunc(MOC_HASH(hwAccelCtx) hashCtx, mgfSeed, mgfSeedLen)))
            goto exit;

        if (OK > (status = H->updateFunc(MOC_HASH(hwAccelCtx) hashCtx, C, 4)))
            goto exit;

        if (OK > (status = H->finalFunc(MOC_HASH(hwAccelCtx) hashCtx, Tlen + T)))
            goto exit;

        /* increment string counter */
        if (0 == ++C[3])
            if (0 == ++C[2])
                if (0 == ++C[1])
                    ++C[0];
    }

    /* copy out result */
    if (OK > (status = DIGI_MEMCPY(mask, T, maskLen)))
        goto exit;

    *ppRetMask = mask;
    mask = NULL;

exit:
    if ((NULL != H) && (NULL != hashCtx))
        H->freeFunc(MOC_HASH(hwAccelCtx) &hashCtx);

    if (NULL != C)
    {
        (void) DIGI_MEMSET(C, 0x00, 4);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &C);
    }

    if (NULL != mask)
    {
        /* zeroize buffer, before releasing */
        (void) DIGI_MEMSET(mask, 0x00, maskLen);
        (void) DIGI_FREE((void **) &mask);
    }

    if (NULL != T)
    {
        /* zeroize buffer, before releasing */
        (void) DIGI_MEMSET(T, 0x00, TbufLen);
        (void) DIGI_FREE((void **) &T);
    }

    return status;
}

MOC_EXTERN MSTATUS MaskGenFunctionShake(
  MOC_HASH(hwAccelDescr hwAccelCtx)
  const ubyte *mgfSeed,
  ubyte4 mgfSeedLen,
  ubyte4 maskLen,
  BulkHashAlgo *H,
  ubyte **ppRetMask
  )
{
    BulkCtx hashCtx = NULL;
    MSTATUS status = OK;
    ubyte *pMask = NULL;

    if (OK > (status = DIGI_MALLOC((void **) &pMask, maskLen)))
        goto exit;

    if (OK > (status = H->allocFunc(MOC_HASH(hwAccelCtx) &hashCtx)))
        goto exit;

    if (OK > (status = H->initFunc(MOC_HASH(hwAccelCtx) hashCtx)))
        goto exit;

    if (OK > (status = H->updateFunc(MOC_HASH(hwAccelCtx) hashCtx, mgfSeed, mgfSeedLen)))
        goto exit;

    if (OK > (status = H->finalXOFFunc(MOC_HASH(hwAccelCtx) hashCtx, pMask, maskLen)))
        goto exit;

    *ppRetMask = pMask; pMask = NULL;

exit:

    if ((NULL != H) && (NULL != hashCtx))
        H->freeFunc(MOC_HASH(hwAccelCtx) &hashCtx);

    if (NULL != pMask)
    {
        (void) DIGI_FREE((void **) &pMask); /* no need to zero since mask is only set on last step */
    }

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_PKCS1__)) */
