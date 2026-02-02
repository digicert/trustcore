/*
 * nist_drbg_hash.c
 *
 * RNG described in NIST SP800 90
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_DRBG_HASH_INTERNAL__

#include "../common/moptions_custom.h"

#ifdef __ENABLE_DIGICERT_NIST_DRBG_HASH__

#include "../crypto/nist_drbg_hash.h"
#include "../common/mstdlib.h"

/*------------------------------------------------------------------*/

/* The largest hash algorithm this operator supports is SHA512 */
#define HASH_DRBG_MAX_HASH_OUTPUT_LEN_BYTES 64

/* We only use two seedLens, MOCANA_HASH_DRBG_MAX_SEED_LEN_BYTES and HASH_DRBG_MIN_SEED_LEN_BITS */
#define HASH_DRBG_MIN_SEED_LEN_BITS 440
#define HASH_DRBG_MIN_SEED_LEN_BYTES (HASH_DRBG_MIN_SEED_LEN_BITS/8) /* 55 */

#define NIST_HASHDRBG_SHA1_OUTLEN 20
#define NIST_HASHDRBG_SHA224_OUTLEN 28
#define NIST_HASHDRBG_SHA256_OUTLEN 32
#define NIST_HASHDRBG_SHA384_OUTLEN 48
#define NIST_HASHDRBG_SHA512_OUTLEN 64

/* We do not allow an input security strength, we just set it based on the hash method */
#define NIST_HASHDRBG_SHA1_MIN_SECURITY_STRENGTH 16
#define NIST_HASHDRBG_SHA224_MIN_SECURITY_STRENGTH 24
#define NIST_HASHDRBG_SHA256_MIN_SECURITY_STRENGTH 32

#ifdef __ENABLE_DIGICERT_64_BIT__

#define bi_unit ubyte8

#define MOC_BSWAP(val) \
( (((val) >> 56) & 0x00000000000000FF) | (((val) >> 40) & 0x000000000000FF00) | \
  (((val) >> 24) & 0x0000000000FF0000) | (((val) >>  8) & 0x00000000FF000000) | \
  (((val) <<  8) & 0x000000FF00000000) | (((val) << 24) & 0x0000FF0000000000) | \
  (((val) << 40) & 0x00FF000000000000) | (((val) << 56) & 0xFF00000000000000) )

#else

#define bi_unit ubyte4

#define MOC_BSWAP(val) \
( (((val) >> 24) & 0x000000FF) | (((val) >>  8) & 0x0000FF00) | \
  (((val) <<  8) & 0x00FF0000) | (((val) << 24) & 0xFF000000) )

#endif

#ifdef MOC_LITTLE_ENDIAN
#define MOC_BSWAP_IF_LENDIAN(val) \
val = MOC_BSWAP(val);
#else
#define MOC_BSWAP_IF_LENDIAN(val)
#endif


static void NIST_HASHDRBG_addToV(ubyte *pV, ubyte4 vLen, ubyte *pAddend, ubyte4 addendBufLen)
{
    sbyte4 i, j;
    bi_unit u = 0;
    bi_unit ux = 0;
    bi_unit carry = 0;

    /* Both inputs must be a multiple of word size for this to work properly.
     * This function should only ever be called internally from this file, so
     * we do not check to guarantee that these are of word size.
     * (ie we know vLen == 56 or 112 which is divisible by 8).
     */
    ubyte4 numWordsInV =  vLen / sizeof(bi_unit);
    ubyte4 numWordsInAddend = addendBufLen / sizeof(bi_unit);

    /* Treat the input buffers as word arrays */
    bi_unit *pOne = (bi_unit *)pV;
    bi_unit *pTwo = (bi_unit *)pAddend;

    /* Perform the addition word by word starting with the last word in each
     * array. Only add as many words as are in the added buffer */
    for (i = numWordsInV - 1, j = numWordsInAddend - 1; i >= 0 && j >= 0; i--, j--)
    {
        /* Get the ith word from V */
        u = pOne[i];

        /* The math for the carry only works if the word is big endian, if this
         * platform is little endian, swap the bytes in the word to big endian */
        MOC_BSWAP_IF_LENDIAN(u);

        /* Add the ith word of V with the carry. The carry will be zero on the
         * first iteration, but may be nonzero for subsequent iterations */
        u = u + carry;

        /* Technically that last addition could have overflowed u, account for
         * that case now by checking for a carry */
        carry = (u < carry) ? 1 : 0;

        /* Get the jth word of the value we are adding to V */
        ux = pTwo[j];

        /* Byte swap if necessary */
        MOC_BSWAP_IF_LENDIAN(ux);

        /* Perform the word addition */
        u = u + ux;

        /* Compute the carry, notice it is a += on the offchance that adding
         * the first carry overflowed word u */
        carry += ((u < ux) ? 1 : 0);

        /* If little endian platform, byte swap it back before placing it
         * back into the buffer */
        MOC_BSWAP_IF_LENDIAN(u);
        pOne[i] = u;
    }

    /* Process the carry, the worst case is that every word is all 1 bits causing
     * an overflow in every word. In this case the last carry wont be processed
     * because the result of this addition is modded by 2^440 anyways so the
     * caller of this function will trim off the leading extra byte anyways. */
    while (0 != carry && i >= 0)
    {
        u = pOne[i];
        MOC_BSWAP_IF_LENDIAN(u);
        u = u + carry;
        carry = (u < carry) ? 1 : 0;
        MOC_BSWAP_IF_LENDIAN(u);
        pOne[i] = u;
        i--;
    }

    /* Just to be extra careful, dont even let these two words
     * float out onto the stack */
    u = 0;
    ux = 0;

}


static MSTATUS NIST_HASHDRBG_processAdd(MOC_SYM(hwAccelDescr hwAccelCtx) NIST_HASH_DRBG_Ctx *pContext,
                                        ubyte *pAdditionalInput, ubyte4 additionalInputLen)
{
    MSTATUS status;
    ubyte pHashBuffer[HASH_DRBG_MAX_HASH_OUTPUT_LEN_BYTES] = {0};
    ubyte *pIter = NULL;
    ubyte *pBuf = NULL;
    ubyte4 bufLen = 0;

    /* We must have some additional data to process */
    status = ERR_INVALID_INPUT;
    if (!additionalInputLen)
        goto exit;

    /* Per NIST SP800-90A 10.1.1.4 Step 2.1,
     * We need enough space for 0x02 || V || additional_input */
    bufLen = 1 + pContext->seedLenBytes + additionalInputLen;
    status = DIGI_MALLOC((void **)&pBuf, bufLen);
    if (OK != status)
        goto exit;

    pBuf[0] = 2;

    /* Use a temporary iterator so we dont lose the original address */
    pIter = pBuf + 1;

    /* Remember extra prepended byte in the V buffer */
    status = DIGI_MEMCPY (pIter, pContext->pV + 1, pContext->seedLenBytes);
    if (OK != status)
        goto exit;

    pIter += pContext->seedLenBytes;

    /* Copy in the additional input */
    status = DIGI_MEMCPY (pIter, pAdditionalInput, additionalInputLen);
    if (OK != status)
        goto exit;

    /* Step 2.1, w = Hash(0x02 || V || additional_input). Compute the hash w and
     * place it at the end of the hash buffer. If the hash algorithm is SHA256
     * then this will completely fill the buffer, if it is SHA1 or SHA224 then
     * it will partially fill the buffer and be prepended with zeros. Either way
     * we end up with the hash value in a buffer that is a multiple of word size,
     * prepended with zeros if necessary so it can be treated as a big endian
     * number. In this way we can perform the addition in constant space and
     * near constant time */
    status = pContext->hashMethod(pBuf, bufLen, &pHashBuffer[HASH_DRBG_MAX_HASH_OUTPUT_LEN_BYTES - pContext->hashOutLen]);
    if (OK != status)
        goto exit;

    if (MOCANA_HASH_DRBG_MAX_SEED_LEN_BYTES == pContext->seedLenBytes)
    {
        bufLen = 0;
    }
    else /* HASH_DRBG_MIN_SEED_LEN_BYTES == pContext->seedLenBytes */
    {
        bufLen = HASH_DRBG_MAX_HASH_OUTPUT_LEN_BYTES/2; /* 32 */
    }

    /* Compute V = V + w. We always pass the max buffer size so we can guarantee
     * the input is of word length. If this is using SHA1 then the hash output
     * would be 20 bytes. While that is of word length on a 32 bit system it is
     * not a multiple of word length for a 64 bit system. The same is true for
     * SHA224 with an output length of 28 bytes. The math for the addition wont
     * work properly if the input is not a multiple of word size, so we always
     * pass the max. */
    NIST_HASHDRBG_addToV(pContext->pV, pContext->seedLenBytes + 1, pHashBuffer + bufLen, HASH_DRBG_MAX_HASH_OUTPUT_LEN_BYTES - bufLen);

    /* No need to mod 2^seedLenBits now (ie no need to 0 the first byte of pContext->pV).
     * The calling method quickly resets it to the 0x03 that it needs. */
exit:

    /* Wipe and clear constructed buffer */
    if (NULL != pBuf)
    {
        DIGI_MEMSET_FREE(&pBuf, bufLen);
    }

    /* Wipe temporary values from the stack */
    DIGI_MEMSET(pHashBuffer, 0, HASH_DRBG_MAX_HASH_OUTPUT_LEN_BYTES);

    return status;
}


static MSTATUS NIST_HASHDRBG_hashGen(MOC_SYM(hwAccelDescr hwAccelCtx) NIST_HASH_DRBG_Ctx *pContext,
                                     ubyte4 outLen, ubyte *pOutput)
{
    MSTATUS status;
    sbyte4 j;
    ubyte4 i, numBlocks;
    ubyte pData[MOCANA_HASH_DRBG_MAX_SEED_LEN_BYTES];
    ubyte pHashOutput[HASH_DRBG_MAX_HASH_OUTPUT_LEN_BYTES];

    /* Step 1, m = ceiling(num_bytes_requested/outlen_bytes) */
    numBlocks = (outLen + pContext->hashOutLen - 1) / pContext->hashOutLen;

    /* Step 2, data = V. Remember in the NIST notation the equals operator
     * treats all things as arbitrary objects so this is not setting a pointer
     * but instead indicates a full buffer copy. Remember the pV buffer has space
     * for an extra prepended byte so dont include it in the copy */
    status = DIGI_MEMCPY (pData, pContext->pV + 1, pContext->seedLenBytes);
    if (OK != status)
        goto exit;

    /* Step 4, for 1 to m */
    for (i = 0; i < numBlocks; i++)
    {
        /* Step 4.1, w = Hash(data) */
        status = pContext->hashMethod(pData, pContext->seedLenBytes, pHashOutput);
        if (OK != status)
            goto exit;

        /* Step 4.3, data = data + 1. Again note this does not modify the actual
         * V value, only the local copy in data */
        for (j = (sbyte4)pContext->seedLenBytes - 1; j >= 0; j--)
        {
            if ( ++(pData[j]) )
                break;
        }

        /* Copy data to output buffer */
        if (outLen >= pContext->hashOutLen)
        {
            status = DIGI_MEMCPY(pOutput, pHashOutput, pContext->hashOutLen);
            if (OK != status)
                goto exit;

            outLen -= pContext->hashOutLen;
            pOutput += pContext->hashOutLen;
        }
        else if (outLen != 0)
        {
            status = DIGI_MEMCPY(pOutput, pHashOutput, outLen);
            if (OK != status)
                goto exit;

            outLen = 0;
        }
    }

exit:

    /* Wipe stack buffers */
    DIGI_MEMSET(pData, 0, sizeof(pData));
    DIGI_MEMSET(pHashOutput, 0, sizeof(pHashOutput));

    return status;
}


static MSTATUS NIST_HASHDRBG_df(MOC_SYM(hwAccelDescr hwAccelCtx) NIST_HASH_DRBG_Ctx *pContext,
                                ubyte *pInput, ubyte4 inLen, ubyte4 outLen, ubyte *pOutput)
{
    MSTATUS status;
    ubyte4 i, totalInputLen, numBlocks;
    ubyte *pTotalInput = NULL;
    ubyte pHashOutput[HASH_DRBG_MAX_HASH_OUTPUT_LEN_BYTES];

    /* Per NIST SP800-90A 10.3.1 Step 4.1,
     * Total input is ( counter || no_bits_to_return || input_string ) */
    totalInputLen = 1 + 4 + inLen;
    status = DIGI_MALLOC((void **)&pTotalInput, totalInputLen);
    if (OK != status)
        goto exit;

    /* Step 2 */
    numBlocks = (outLen + pContext->hashOutLen - 1) / pContext->hashOutLen;

    /* Step 3 */
    pTotalInput[0] = 1;

    /* Set the number of bits to return */
    BIGEND32(&pTotalInput[1], (outLen * 8));

    /* Copy in the input string */
    status = DIGI_MEMCPY((void *)(&pTotalInput[5]), (void *)pInput, inLen);
    if (OK != status)
        goto exit;

    /* Step 4 with logic from step 5, loop from 0 to numBlocks but only so
     * long as there are more bytes to return */
    for (i = 0; i < numBlocks && outLen != 0; i++)
    {
        /* Step 4.1, Hash(counter || no_bits_to_return || input_string) */
        status = pContext->hashMethod(pTotalInput, totalInputLen, pHashOutput);
        if (OK != status)
            goto exit;

        /* Step 4.2 */
        pTotalInput[0]++;

        /* Copy hash output to output buffer */
        if (outLen >= pContext->hashOutLen)
        {
            status = DIGI_MEMCPY((void *)pOutput, (void *)pHashOutput, pContext->hashOutLen);
            if (OK != status)
                goto exit;

            outLen -= pContext->hashOutLen;
            pOutput += pContext->hashOutLen;
        }
        else
        {
            status = DIGI_MEMCPY((void *)pOutput, (void *)pHashOutput, outLen);
            if (OK != status)
                goto exit;

            outLen = 0;
        }
    }

exit:

    /* Wipe and free the total input buffer */
    if (NULL != pTotalInput)
    {
        DIGI_MEMSET_FREE(&pTotalInput, totalInputLen);
    }

    /* Wipe the hash output buffer */
    DIGI_MEMSET(pHashOutput, 0, pContext->hashOutLen);

    return status;

}


static MSTATUS NIST_HASHDRBG_seed(MOC_SYM(hwAccelDescr hwAccelCtx) NIST_HASH_DRBG_Ctx *pContext,
                                  ubyte *pSeedMaterial, ubyte4 seedMaterialLen)
{
    MSTATUS status;
    ubyte pSeed[MOCANA_HASH_DRBG_MAX_SEED_LEN_BYTES + 1] = {0};
    ubyte pConstant[MOCANA_HASH_DRBG_MAX_SEED_LEN_BYTES] = {0};

    /* 10.1.1.2/10.1.1.3 Step 2, we pass pSeed + 1 because we will reuse the
     * same buffer in Step 4 when we need to prepend a 0x00 byte */
    status = NIST_HASHDRBG_df(pContext, pSeedMaterial, seedMaterialLen,
                              pContext->seedLenBytes, pSeed + 1);
    if (OK != status)
        goto exit;

    /* Step 4 */
    status = NIST_HASHDRBG_df(pContext, pSeed, pContext->seedLenBytes + 1,
                              pContext->seedLenBytes, pConstant);
    if (OK != status)
        goto exit;

    /* Copy the values to the internal data structure, pV and pC buffers have
     * space for an extra prepended byte */
    status = DIGI_MEMCPY (pContext->pV + 1, pSeed + 1, pContext->seedLenBytes);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY (pContext->pC + 1, pConstant, pContext->seedLenBytes);
    if (OK != status)
        goto exit;

    /* Step 5, initialize the reseed counter to one */
    status = DIGI_MEMSET(pContext->pReseedCtr, 0, 8);
    if (OK != status)
        goto exit;

    pContext->pReseedCtr[7] = 1;

exit:

    /* Wipe the internal buffers from the stack */
    DIGI_MEMSET(pSeed, 0, pContext->seedLenBytes + 1);
    DIGI_MEMSET(pConstant, 0, pContext->seedLenBytes);

    return status;
}


MSTATUS NIST_HASHDRBG_newSeededContext(MOC_SYM(hwAccelDescr hwAccelCtx) NIST_HASH_DRBG_Ctx **ppNewContext,
                                       ubyte *pEntropyInput, ubyte4 entropyInputLen, ubyte *pNonce,
                                       ubyte4 nonceLen, ubyte *pPersonalization, ubyte4 personalizationLen,
                                       DrbgHashMethod hashMethod, ubyte4 hashOutLenBytes)
{
    MSTATUS status;
    ubyte *pSeedMaterial = NULL;
    ubyte *pIter = NULL;
    ubyte4 seedMaterialLen = 0;
    NIST_HASH_DRBG_Ctx *pNewCtx = NULL;

    status = ERR_NULL_POINTER;
    if (NULL == ppNewContext || NULL == hashMethod || NULL == pEntropyInput)
        goto exit;

    /* Allocate the new ctx */
    status = DIGI_CALLOC((void **)&pNewCtx, 1, sizeof(NIST_HASH_DRBG_Ctx));
    if (OK != status)
        goto exit;

    /* Check that hashOutLenBytes makes sense. We only allow the valid Sha methods, Table 2 in Sec 10.1, plus sha3 */
    status = ERR_NIST_RNG_HASH_DF_BAD_OUTPUT_LEN;
    if (NIST_HASHDRBG_SHA1_OUTLEN == hashOutLenBytes) /* Sha1 */
    {
        pNewCtx->securityStrengthBytes = NIST_HASHDRBG_SHA1_MIN_SECURITY_STRENGTH;
        pNewCtx->seedLenBytes = HASH_DRBG_MIN_SEED_LEN_BYTES;
    }
    else if (NIST_HASHDRBG_SHA224_OUTLEN == hashOutLenBytes) /* Sha-224, Sha-512/224, Sha3-224 */
    {
        pNewCtx->securityStrengthBytes = NIST_HASHDRBG_SHA224_MIN_SECURITY_STRENGTH;
        pNewCtx->seedLenBytes = HASH_DRBG_MIN_SEED_LEN_BYTES;
    }
    else if (NIST_HASHDRBG_SHA256_OUTLEN == hashOutLenBytes) /* Sha-256, Sha-512/256, Sha3-256 */
    {
        pNewCtx->securityStrengthBytes = NIST_HASHDRBG_SHA256_MIN_SECURITY_STRENGTH;
        pNewCtx->seedLenBytes = HASH_DRBG_MIN_SEED_LEN_BYTES;
    }
    else if (NIST_HASHDRBG_SHA384_OUTLEN == hashOutLenBytes) /* Sha-384, Sha3-384 */
    {
        pNewCtx->securityStrengthBytes = NIST_HASHDRBG_SHA256_MIN_SECURITY_STRENGTH;
        pNewCtx->seedLenBytes = MOCANA_HASH_DRBG_MAX_SEED_LEN_BYTES;
    }
    else if (NIST_HASHDRBG_SHA512_OUTLEN == hashOutLenBytes) /* Sha-512, Sha3-512 */
    {
        pNewCtx->securityStrengthBytes = NIST_HASHDRBG_SHA256_MIN_SECURITY_STRENGTH;
        pNewCtx->seedLenBytes = MOCANA_HASH_DRBG_MAX_SEED_LEN_BYTES;
    }
    else
    {
        goto exit;
    }

    /* Per NIST SP800-90A 10.1 Table 2, minimum entropy input is the security
     * strength of the underlying hash algorithm */
    status = ERR_NIST_RNG_HASH_BAD_ENTROPY_INPUT_LEN;
    if (entropyInputLen < pNewCtx->securityStrengthBytes)
        goto exit;

    pNewCtx->hashOutLen = hashOutLenBytes;
    pNewCtx->hashMethod = hashMethod;

    /* NIST SP800-90A 10.1.1.2,
     * Step 1, seed_material = entropy_input || nonce || personalizationstr */
    seedMaterialLen = entropyInputLen + nonceLen + personalizationLen;
    status = DIGI_MALLOC((void **)&pSeedMaterial, seedMaterialLen);
    if (OK != status)
        goto exit;

    /* Copy the entropy input into the buffer */
    status = DIGI_MEMCPY(pSeedMaterial, pEntropyInput, entropyInputLen);
    if (OK != status)
        goto exit;

    /* Use a temporary iterator */
    pIter = pSeedMaterial + entropyInputLen;

    /* Copy the nonce if available */
    if (NULL != pNonce && nonceLen)
    {
        /* Per NIST SP800-90A 8.6.7, nonce must be at least security_strength/2 */
        status = ERR_NIST_RNG_HASH_BAD_NONCE_INPUT_LEN;
        if ( nonceLen < (pNewCtx->securityStrengthBytes / 2) )
            goto exit;

        status = DIGI_MEMCPY(pIter, pNonce, nonceLen);
        if (OK != status)
            goto exit;

        pIter += nonceLen;
    }

    /* Copy the personalization string if available */
    if (NULL != pPersonalization && personalizationLen)
    {
        status = DIGI_MEMCPY(pIter, pPersonalization, personalizationLen);
        if (OK != status)
            goto exit;

        /* done with pIter, no need to increment */
    }

    status = NIST_HASHDRBG_seed(pNewCtx, pSeedMaterial, seedMaterialLen);
    if (OK != status)
        goto exit;

    /* Create the mutex */
    status = RTOS_mutexCreate(&(pNewCtx->pMutex), 0, 0);
    if (OK != status)
        goto exit;

    *ppNewContext = pNewCtx;
    pNewCtx = NULL;

exit:

    /* don't change status */
    if (NULL != pSeedMaterial)
    {
        DIGI_MEMSET_FREE(&pSeedMaterial, seedMaterialLen);
    }

    if (NULL != pNewCtx)
    {
        /* If this is not NULL, we had some error during creation. Depending
         * on where it failed some things might be allocated in the internal
         * structure. We dont want to deal with all those combinations of
         * possible allocations in the internal structure */
        NIST_HASHDRBG_deleteContext(&pNewCtx);
    }

    return status;
}


MSTATUS NIST_HASHDRBG_deleteContext( MOC_SYM(hwAccelDescr hwAccelCtx) NIST_HASH_DRBG_Ctx **ppContext)
{
    MSTATUS status, fStatus;

    status = ERR_NULL_POINTER;
    if (NULL == ppContext)
        goto exit;

    /* If there is nothing to free, just return */
    status = OK;
    if (NULL == *ppContext)
        goto exit;

    /* Free the mutex */
    if (NULL != (*ppContext)->pMutex)
    {
        fStatus = RTOS_mutexFree(&(*ppContext)->pMutex);
        if (OK == status)
            status = fStatus;
    }

    /* Wipe and free the ppContext itself */
    fStatus = DIGI_MEMSET_FREE ((ubyte **) ppContext, sizeof(NIST_HASH_DRBG_Ctx));
    if (OK == status)
        status = fStatus;

exit:
    return status;
}


MSTATUS NIST_HASHDRBG_reSeed(MOC_SYM(hwAccelDescr hwAccelCtx) NIST_HASH_DRBG_Ctx *pContext, ubyte *pEntropyInput,
                             ubyte4 entropyInputLen, ubyte *pAdditionalInput, ubyte4 additionalInputLen)
{

    MSTATUS status;
    ubyte pZeroCtr[8] = {0};
    ubyte *pSeedMaterial = NULL;
    ubyte *pIter = NULL;
    ubyte4 seedMaterialLen = 0;
    sbyte4 cmpRes = 0;

    status = ERR_NULL_POINTER;
    if (NULL == pContext || NULL == pEntropyInput || (NULL == pAdditionalInput && additionalInputLen))
        goto exit;

    /* If the reseed counter is zero then the drbg was never instantiated */
    status = DIGI_MEMCMP(pZeroCtr, pContext->pReseedCtr, 8, &cmpRes);
    if (OK != status)
        goto exit;

    status = ERR_NIST_RNG_HASH_UNINITIALIZED_CTX;
    if (0 == cmpRes)
        goto exit;

    /* Per NIST SP800-90A 10.1 Table 2, minimum entropy input is the security
     * strength of the underlying hash algorithm */
    status = ERR_NIST_RNG_HASH_BAD_ENTROPY_INPUT_LEN;
    if (entropyInputLen < pContext->securityStrengthBytes)
        goto exit;

    /* Reseed counter is not zero, this is a reseed operation. Per NIST
     * SP800-90A 10.1.1.3 Step 1,
     * seed_material = 0x01 || V || entropy_input || additional_input */
    seedMaterialLen = 1 + pContext->seedLenBytes + entropyInputLen + additionalInputLen;
    status = DIGI_MALLOC((void **)&pSeedMaterial, seedMaterialLen);
    if (OK != status)
        goto exit;

    pSeedMaterial[0] = 1;

    /* Use a temporary iterator, we copy V in last as to minimize time this thread has access to
       the mutable parts of the state of pContext. Start pIter after V. */
    pIter = pSeedMaterial + 1 + pContext->seedLenBytes;

    /* Copy the entropy input into the buffer */
    status = DIGI_MEMCPY(pIter, pEntropyInput, entropyInputLen);
    if (OK != status)
        goto exit;

    pIter += entropyInputLen;

    /* Copy the additional input (if availbable) into the buffer */
    if (NULL != pAdditionalInput && additionalInputLen)
    {
        status = DIGI_MEMCPY(pIter, pAdditionalInput, additionalInputLen);
        if (OK != status)
            goto exit;
    }

    /* put pIter back to where V should go */
    pIter = pSeedMaterial + 1;

    /* Time to get V from the ctx, only one consumer at a time */
    status = RTOS_mutexWait(pContext->pMutex);
    if (OK != status)
        goto exit;

    /* Copy V into the buffer, again dont include the prepended byte */
    status = DIGI_MEMCPY (pIter, pContext->pV + 1, pContext->seedLenBytes);
    if (OK != status)
        goto exit;

    status = NIST_HASHDRBG_seed(pContext, pSeedMaterial, seedMaterialLen);

exit:

    /* Release the mutex */
    if (NULL != pContext)
    {
        RTOS_mutexRelease(pContext->pMutex);
    }

    /* Wipe and free the seed material */
    if (NULL != pSeedMaterial)
    {
        DIGI_MEMSET_FREE(&pSeedMaterial, seedMaterialLen);
    }

    return status;
}


MSTATUS NIST_HASHDRBG_generate(MOC_SYM(hwAccelDescr hwAccelCtx) NIST_HASH_DRBG_Ctx *pContext, ubyte *pAdditionalInput,
                               ubyte4 additionalInputLen, ubyte *pOutput, ubyte4 outputLenBytes)
{
    MSTATUS status;
    sbyte4 i, cmpRes;
    ubyte pHashBuffer[HASH_DRBG_MAX_HASH_OUTPUT_LEN_BYTES] = {0};
    ubyte pZeroCtr[8] = {0};
    ubyte4 hashOffset = 0;

    status = ERR_NULL_POINTER;
    if (NULL == pContext || (NULL == pOutput && outputLenBytes))
        goto exit;

    /* If the reseed counter is zero, we never got a seed */
    status = DIGI_MEMCMP(pZeroCtr, pContext->pReseedCtr, 8, &cmpRes);
    if (OK != status)
        goto exit;

    status = ERR_NIST_RNG_HASH_UNINITIALIZED_CTX;
    if (0 == cmpRes)
        goto exit;

    /* Only one consumer at a time */
    status = RTOS_mutexWait(pContext->pMutex);
    if (OK != status)
        goto exit;

    /* Per NIST SP800-90A 10.1 table 2, this DRBG must be reseeded
     * after 2^48 requests. The counter is a manually managed 8 byte
     * buffer representing a 64-bit big endian counter. The lowest order
     * bit in pReseedCtr[1] is the 48th bit, so just check if any bits in
     * that byte are set. */
    status = ERR_NIST_RNG_DBRG_RESEED_NEEDED;
    if (0 != pContext->pReseedCtr[1])
        goto exit;

    /* NIST SP800-90A 10.1.1.4 Step 2, Process additional data if available */
    if (NULL != pAdditionalInput && additionalInputLen)
    {
        status = NIST_HASHDRBG_processAdd(pContext, pAdditionalInput, additionalInputLen);
        if (OK != status)
            goto exit;
    }

    /* Step 3, Generate the actual output random bytes for this call */
    status = NIST_HASHDRBG_hashGen(pContext, outputLenBytes, pOutput);
    if (OK != status)
        goto exit;

    /* Now we update the internal state for the next generate, begin with
     * Step 4, H = Hash(0x03 || V). This is one of the places where we use
     * that extra byte in the pV buffer. */
    pContext->pV[0] = 3;

    /* Compute the hash H and place it at the end of the hash buffer. If the hash
     * algorithm is SHA256 then this will completely fill the buffer, if it is
     * SHA1 or SHA224 then it will partially fill the buffer and be prepended
     * with zeros. Either way we end up with the hash value in a buffer that is
     * a multiple of word size, prepended with zeros if necessary so it can be
     * treated as a big endian number. In this way we can perform the addition
     * in constant space and near constant time */
    status = pContext->hashMethod(pContext->pV, pContext->seedLenBytes + 1,
                                  &pHashBuffer[HASH_DRBG_MAX_HASH_OUTPUT_LEN_BYTES - pContext->hashOutLen]);
    if (OK != status)
        goto exit;

    /* We are now going to compute V = (V + H + C + reseedCtr) mod 2^440.
     * Just to be safe, make sure the extra prepended bytes are set to zero */
    pContext->pV[0] = 0;
    pContext->pC[0] = 0;

    if( HASH_DRBG_MIN_SEED_LEN_BYTES == pContext->seedLenBytes )
    {
        hashOffset = HASH_DRBG_MAX_HASH_OUTPUT_LEN_BYTES/2;  /* 32 */
    }
    /* Compute V = V + C. Both the pV and pC buffers have an extra prepended byte
     * so they are guaranteed to be a multiple of word size */
    NIST_HASHDRBG_addToV(pContext->pV, pContext->seedLenBytes + 1, pContext->pC, pContext->seedLenBytes + 1);

    /* Compute V = V + H. We always pass the max buffer size so we can guarantee
     * the input is of word length. If this is using SHA1 then the hash output
     * would be 20 bytes. While that is of word length on a 32 bit system it is
     * not a multiple of word length for a 64 bit system. The same is true for
     * SHA224 with an output length of 28 bytes. The math for the addition wont
     * work properly if the input is not a multiple of word size, so we always
     * pass the max. */
    NIST_HASHDRBG_addToV(pContext->pV, pContext->seedLenBytes + 1, pHashBuffer + hashOffset, HASH_DRBG_MAX_HASH_OUTPUT_LEN_BYTES - hashOffset);

    /* Compute V = V + reseedCtr. The reseed counter is implemented as a manually
     * managed 8 byte big endian counter. Even though the high order 2 bytes should
     * never be set (it would require a reseed before that), again we always pass
     * the entire buffer size to ensure the input is a multiple of word size
     * on all architectures */
    NIST_HASHDRBG_addToV(pContext->pV, pContext->seedLenBytes + 1, pContext->pReseedCtr, 8);

    /* No need to mod 2^seedLenBits now (ie no need to 0 the first byte of pContext->pV).
     * The next call to generate will reset that byte for us, and reseed doesn't touch that byte */

    /* Increment the reseed counter. The reseed counter is managed manually
     * so it is in a format that is easier to work with for addition. Perform
     * the incrementing now, we dont need to worry about overflowing the buffer
     * since the DRBG will reject generate requests after 2^48 requests */
    for (i = 7; i >= 0; i--)
    {
        if (++(pContext->pReseedCtr[i]))
            break;
    }

exit:

    /* Release the mutex */
    if (NULL != pContext)
    {
        RTOS_mutexRelease(pContext->pMutex);
    }

    /* Wipe stack buffer */
    DIGI_MEMSET(pHashBuffer, 0, HASH_DRBG_MAX_HASH_OUTPUT_LEN_BYTES);

    return status;
}


MSTATUS NIST_HASHDRBG_numberGenerator(MOC_SYM(hwAccelDescr hwAccelCtx) NIST_HASH_DRBG_Ctx *pRandomContext,
                                      ubyte *pBuffer, sbyte4 bufferLen)
{
    return NIST_HASHDRBG_generate(MOC_SYM(hwAccelCtx) pRandomContext, NULL, 0, pBuffer, bufferLen);
}


sbyte4 NIST_HASHDRBG_rngFun(MOC_SYM(hwAccelDescr hwAccelCtx) void *pRngFunArg, ubyte4 length, ubyte *pBuffer)
{
    return NIST_HASHDRBG_generate(MOC_SYM(hwAccelCtx) pRngFunArg, NULL, 0, pBuffer, length);
}

#endif /* __ENABLE_DIGICERT_NIST_DRBG_HASH__ */
