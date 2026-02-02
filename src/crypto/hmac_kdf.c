/*
 * hmac_kdf.c
 * 
 * Implementes Hmac KDF (HKDF) as per RFC 5869
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC_KDF_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mdefs.h"
#include "../common/mstdlib.h"
#include "../common/mocana.h"

#include "../crypto/hw_accel.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#ifndef __DISABLE_DIGICERT_SHA256__
#include "../crypto/sha256.h"
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
#include "../crypto/sha512.h"
#endif

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

#include "../crypto/hmac.h"
#include "../crypto/hmac_kdf.h"

MOC_EXTERN MSTATUS HmacKdfExtract(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest,
    ubyte *pSalt,
    ubyte4 saltLen,
    ubyte *pInputKeyMaterial,
    ubyte4 inputKeyMaterialLen,
    ubyte *pOutput,
    ubyte4 outputLen
    )
{
    return HmacKdfExtractExt(MOC_HASH(hwAccelCtx) pDigest, pSalt, saltLen, pInputKeyMaterial,
                             inputKeyMaterialLen, pOutput, outputLen, NULL);
}

/* HMAC-KDF extract as per RFC 5869 section 2.2.
 *
 * Generate a pseudorandom key (PRK) from a salt value and input key material
 * (IKM) value. The salt value will default to a buffer of all zeroes of digest
 * length is one is not provided. The PRK will be digest length in bytes based
 * off of the hash suite passed in.
 */
MOC_EXTERN MSTATUS HmacKdfExtractExt(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest,
    ubyte *pSalt,
    ubyte4 saltLen,
    ubyte *pInputKeyMaterial,
    ubyte4 inputKeyMaterialLen,
    ubyte *pOutput,
    ubyte4 outputLen,
    void *pExtCtx
    )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte *pZeroes = NULL;

    MOC_UNUSED(pExtCtx);
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC_KDF); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_HMAC_KDF,0);

    /* Caller must provide digest suite and output buffer.
     */
    status = ERR_NULL_POINTER;
    if ( (NULL == pDigest) || (NULL == pOutput) )
        goto exit;

    /* Return an error if a NULL salt length was specified with a valid length.
     */
    if ( (NULL == pSalt) && (0 != saltLen) )
        goto exit;

    /* The output of the extract will be of digest length. Ensure the output
     * buffer is large enough.
     */
    status = ERR_BAD_LENGTH;
    if (outputLen < pDigest->digestSize)
        goto exit;

    /* If no salt was provided then default to a salt of all zeroes of digest
     * length.
     */
    if (NULL == pSalt)
    {
        status = DIGI_CALLOC((void **) &pZeroes, 1, pDigest->digestSize);
        if (OK != status)
            goto exit;
        
        pSalt = pZeroes;
        saltLen = pDigest->digestSize;
    }

    /* Generate the pseudo random key.
     */
    status = HmacQuick(MOC_HASH(hwAccelCtx)
        pSalt, saltLen, pInputKeyMaterial, inputKeyMaterialLen, pOutput,
        pDigest);

exit:

    if (NULL != pZeroes)
    {
        DIGI_FREE((void **) &pZeroes);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_HMAC_KDF,0);
    return status;
}



MOC_EXTERN MSTATUS HmacKdfExpand(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest,
    ubyte *pPseudoRandomKey,
    ubyte4 pseudoRandomKeyLen,
    ubyte *pContext,
    ubyte4 contextLen,
    ubyte *pIv,
    ubyte4 ivLen,
    ubyte *pOutput,
    ubyte4 keyLength
    )
{
    return HmacKdfExpandExt(MOC_HASH(hwAccelCtx) pDigest, pPseudoRandomKey, pseudoRandomKeyLen, pContext,
                            contextLen, pIv, ivLen, pOutput, keyLength, NULL);
}

/* HMAC-KDF expand as per RFC 5869 section 2.3.
 *
 * This will generate key material based on the psuedorandom key and the
 * context. The pseudorandom key must be digest length in bytes (based off the
 * hash suite passed into the function). The context is optional. The caller
 * must specify the amount of key material they want in bytes.
 */
MOC_EXTERN MSTATUS HmacKdfExpandExt(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest,
    ubyte *pPseudoRandomKey,
    ubyte4 pseudoRandomKeyLen,
    ubyte *pContext,
    ubyte4 contextLen,
    ubyte *pIv,
    ubyte4 ivLen,
    ubyte *pOutput,
    ubyte4 keyLength,
    void *pExtCtx
    )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte count;
    ubyte4 outputLen;
    HMAC_CTX *pHmacCtx = NULL;
    ubyte *pTemp = NULL;

    MOC_UNUSED(pExtCtx);
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC_KDF); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_HMAC_KDF,0);

    /* Caller must provide a digest suite, psuedorandom key, and an output
     * buffer.
     */
    status = ERR_NULL_POINTER;
    if ( (NULL == pDigest) || (NULL == pPseudoRandomKey) || (NULL == pOutput) )
        goto exit;

    /* The extract method cannot generate more then 255 * digest length in key
     * bytes so ensure that the caller does not request too many key bytes.
     */
    status = ERR_BAD_LENGTH;
    if (keyLength > (255 * pDigest->digestSize))
        goto exit;

    status = HmacCreate(MOC_HASH(hwAccelCtx) &pHmacCtx, pDigest);
    if (OK != status)
        goto exit;
    
    status = HmacKey(MOC_HASH(hwAccelCtx) pHmacCtx, pPseudoRandomKey, pseudoRandomKeyLen);
    if (OK != status)
        goto exit;

    /* Check if IV should be used */
    if (0 < ivLen)
    {
        status = HmacUpdate(
            MOC_HASH(hwAccelCtx) pHmacCtx, pIv, ivLen);
        if (OK != status)
            goto exit;
    }

    /* Process all the blocks of digest length data, where the Hmac operation
     * will be performed on the previous Hmac concatenated with the context
     * concatenated with the count.
     */
    count = 1;
    outputLen = 0;
    while (keyLength > pDigest->digestSize)
    {
        status = HmacUpdate(MOC_HASH(hwAccelCtx) pHmacCtx, pOutput - outputLen, outputLen);
        if (OK != status)
            goto exit;

        if (NULL != pContext)
        {
            status = HmacUpdate(MOC_HASH(hwAccelCtx) pHmacCtx, pContext, contextLen);
            if (OK != status)
                goto exit;
        }

        status = HmacUpdate(MOC_HASH(hwAccelCtx) pHmacCtx, &count, 1);
        if (OK != status)
            goto exit;

        status = HmacFinal(MOC_HASH(hwAccelCtx) pHmacCtx, pOutput);
        if (OK != status)
            goto exit;

        status = HmacReset(MOC_HASH(hwAccelCtx) pHmacCtx);
        if (OK != status)
            goto exit;

        pOutput += pDigest->digestSize;
        keyLength -= pDigest->digestSize;
        outputLen = pDigest->digestSize;
        count++;
    }

    /* Operate on the last few bytes that will not be of digest size (Temporary
     * buffer will be used to store data and copied to the output buffer).
     */
    if (0 != keyLength)
    {
        status = DIGI_MALLOC((void **) &pTemp, pDigest->digestSize);
        if (OK != status)
            goto exit;

        status = HmacUpdate(MOC_HASH(hwAccelCtx) pHmacCtx, pOutput - outputLen, outputLen);
        if (OK != status)
            goto exit;

        if (NULL != pContext)
        {
            status = HmacUpdate(MOC_HASH(hwAccelCtx) pHmacCtx, pContext, contextLen);
            if (OK != status)
                goto exit;
        }

        status = HmacUpdate(MOC_HASH(hwAccelCtx) pHmacCtx, &count, 1);
        if (OK != status)
            goto exit;

        status = HmacFinal(MOC_HASH(hwAccelCtx) pHmacCtx, pTemp);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pOutput, pTemp, keyLength);
        if (OK != status)
            goto exit;
    }

exit:

    if (NULL != pTemp)
    {
        DIGI_MEMSET(pTemp, 0x00, pDigest->digestSize);
        DIGI_FREE((void **) &pTemp);
    }

    if (NULL != pHmacCtx)
        HmacDelete(MOC_HASH(hwAccelCtx) &pHmacCtx);

    FIPS_LOG_END_ALG(FIPS_ALGO_HMAC_KDF,0);
    return status;
}
