/*
 * pkcs1.c
 *
 * PKCS#1 Version 2.1 Utilities
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

/**
@file       pkcs1.c
@brief      C source code for the Mocana SoTP PKCS&nbsp;\#1 convenience API.
@details    This file contains the Mocana SoTP convenience functions that
            support PKCS&nbsp;\#1, version 2.1, as defined by RFC&nbsp;3447.


@flags
To enable the SoT Platform PKCS&nbsp;\#1 convenience API functions, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS1__

@filedoc    pkcs1.c
*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_PKCS1_INTERNAL__

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_PKCS1__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#ifndef __RSA_PKCS1_HARDWARE_ACCELERATOR__

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/memory_debug.h"
#include "../common/debug_console.h"
#include "../asn1/oiddefs.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif
#include "../crypto/crypto.h"
#include "../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/pkcs1.h"
#include "../harness/harness.h"

/*--------------------------------------------------------------------------*/

/**
@brief      Convert an octet string to a non-negative integer.

@details    This function converts an octet string to a non-negative integer, as
            defined in RFC&nbsp;3447.

@sa         PKCS1_I2OSP()

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined:
+ \c \__ENABLE_DIGICERT_PKCS1__

@inc_file pkcs1.h

@param  pMessage    Octet string to convert.
@param  mesgLen     Number of bytes in the octet string, \p pMessage.
@param  ppRetM      On return, pointer to the resultant non-negative integer.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs1.c
*/
extern MSTATUS
PKCS1_OS2IP(const ubyte *pMessage, ubyte4 mesgLen, vlong **ppRetM)
{
    MSTATUS status;

    if (OK > (status = VLONG_vlongFromByteString(pMessage, (sbyte4)mesgLen, ppRetM, NULL)))
        goto exit;

    DEBUG_RELABEL_MEMORY(*ppRetM);

exit:
    return status;
}


/*--------------------------------------------------------------------------*/

/**
@brief      Convert a non-negative integer to an octet string.

@details    This function converts a non-negative integer to an octet string of
            a given length, as defined in RFC&nbsp;3447.

@sa         PKCS1_OS2IP()

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined:
+ \c \__ENABLE_DIGICERT_PKCS1__

@inc_file pkcs1.h

@param  pValue      Non-negative integer to convert.
@param  fixedLength Length of the resultant octet string.
@param  ppRetString On return, pointer to resultant octet string.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs1.c
*/
extern MSTATUS
PKCS1_I2OSP(vlong *pValue, ubyte4 fixedLength, ubyte **ppRetString)
{
    ubyte*  pString = NULL;
    MSTATUS status = ERR_MEM_ALLOC_FAIL;

    if (NULL != (pString = MALLOC(fixedLength)))
    {
        if (OK > (status = VLONG_fixedByteStringFromVlong(pValue, pString, (sbyte4)fixedLength)))
            goto exit;

        /* set results */
        *ppRetString = pString;
        pString = NULL;
    }

exit:
    if (NULL != pString)
        FREE(pString);

    return status;
}


/*--------------------------------------------------------------------------*/

/**
@brief      Generate an MGF1 mask based on a given hash function, as defined in
            RFC&nbsp;3447.

@details    This function generates an MGF1 mask mask of a given length, based
            a given hash function, as defined in RFC&nbsp;3447.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined:
+ \c \__ENABLE_DIGICERT_PKCS1__

@inc_file pkcs1.h

@param  hwAccelCtx  Hardware acceleration context.
@param  mgfSeed     Seed generated from a pRandomContext.
@param  mgfSeedLen  Number of bytes in the MGF seed, \p mgfSeed.
@param  maskLen     Number of bytes in the returned mask, \p ppRetMask.
@param  H           Hash function.
@param  ppRetMask   On return, pointer to address of generated mask.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs1.c
*/
extern MSTATUS
PKCS1_MGF1_FUNC(MOC_RSA(hwAccelDescr hwAccelCtx) const ubyte *mgfSeed, ubyte4 mgfSeedLen, ubyte4 maskLen, BulkHashAlgo *H, ubyte **ppRetMask)
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

/*--------------------------------------------------------------------------*/

extern MSTATUS
PKCS1_MGF_SHAKE_FUNC(MOC_RSA(hwAccelDescr hwAccelCtx) const ubyte *mgfSeed, ubyte4 mgfSeedLen, ubyte4 maskLen, BulkHashAlgo *H, ubyte **ppRetMask)
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

/*--------------------------------------------------------------------------*/

static MSTATUS
emeOaepEncode(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
              ubyte4 k, BulkHashAlgo *H, ubyte4 hLen, BulkHashAlgo *mgfH,
              mgfFunc MGF, const ubyte *M, ubyte4 mLen, const ubyte *L, ubyte4 lLen,
              ubyte** ppRetEM)
{
    BulkCtx         hashCtx = NULL;
    ubyte*          EM = NULL;
    ubyte*          DB = NULL;
    ubyte*          seed = NULL;
    ubyte*          seedMask = NULL;
    ubyte*          maskedSeed = NULL;
    ubyte*          dbMask = NULL;
    ubyte*          maskedDB = NULL;
    ubyte4          i;
    MSTATUS         status;

    /* allocate memory for DB */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, k - hLen - 1, TRUE, &DB)))
        goto exit;

    DEBUG_RELABEL_MEMORY(DB);

    /* setup hash context */
    if (OK > (status = H->allocFunc(MOC_HASH(hwAccelCtx) &hashCtx)))
        goto exit;

    if (OK > (status = H->initFunc(MOC_HASH(hwAccelCtx) hashCtx)))
        goto exit;

    if ((0 != lLen) && (NULL != L))
    {
        /* make sure there is something to hash */
        if (OK > (status = H->updateFunc(MOC_HASH(hwAccelCtx) hashCtx, L, lLen)))
            goto exit;
    }

    /* DB = lHash = HASH(L) */
    /* lHash || PS || 0x01 || M */
    if (OK > (status = H->finalFunc(MOC_HASH(hwAccelCtx) hashCtx, DB)))
        goto exit;

    /* || PS */
    DIGI_MEMSET(DB + hLen, 0x00, k - mLen - (2 * hLen) - 2);

    /* || 0x01 */
    DB[hLen + (k - mLen - (2 * hLen) - 2)] = 0x01;

    /* || M */
    DIGI_MEMCPY(DB + hLen + (k - mLen - (2 * hLen) - 2) + 1, M, mLen);

    /* allocate memory for seed */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, hLen, TRUE, &seed)))
        goto exit;

    DEBUG_RELABEL_MEMORY(seed);

    /* generate a random octet string seed of length hLen */
    if (OK > (status = RANDOM_numberGenerator(pRandomContext, seed, hLen)))
        goto exit;

    /* dbMask = MGF(seed, k - hLen - 1) */
    if (OK > (status = MGF(MOC_RSA(hwAccelCtx) seed, hLen, k - hLen -1, mgfH, &dbMask)))
        goto exit;

    /* allocate EM == 0x00 || maskedSeed || maskedDB */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, k, TRUE, &EM)))
        goto exit;

    DEBUG_RELABEL_MEMORY(EM);

    /* set maskedDB */
    maskedDB = EM + 1 + hLen;

    /* maskedDB = DB xor dbMask */
    for (i = 0; i < k - hLen - 1; i++)
        maskedDB[i] = DB[i] ^ dbMask[i];

    /* seedMask = MGF(maskedDB, hLen) */
    if (OK > (status = MGF(MOC_RSA(hwAccelCtx) maskedDB, k - hLen - 1, hLen, mgfH, &seedMask)))
        goto exit;

    /* set maskedSeed */
    maskedSeed = EM + 1;

    /* maskedSeed = seed xor seedMask */
    for (i = 0; i < hLen; i++)
        maskedSeed[i] = seed[i] ^ seedMask[i];

    /* EM = 0x00 || maskedSeed || maskedDB */
    EM[0] = 0x00;

    /* return EM */
    *ppRetEM = EM;
    EM = NULL;

exit:

    if (NULL != seedMask)
    {
        (void) DIGI_MEMSET(seedMask, 0x00, hLen);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &seedMask);
    }

    if (NULL != EM)
    {
        (void) DIGI_MEMSET(EM, 0x00, k);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &EM);
    }

    if (NULL != dbMask)
    {
        (void) DIGI_MEMSET(dbMask, 0x00, k - hLen - 1);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &dbMask);
    }

    if (NULL != seed)
    {
        (void) DIGI_MEMSET(seed, 0x00, hLen);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &seed);
    }

    if (NULL != DB)
    {    
        (void) DIGI_MEMSET(DB, 0x00, k - hLen - 1);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &DB);
    }

    if (NULL != H && NULL != hashCtx)
    {
        (void) H->freeFunc(MOC_HASH(hwAccelCtx) &hashCtx);
    }

    return status;

} /* emeOaepEncode */


/*--------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
static MSTATUS
PKCS1_rsaEncryption(MOC_RSA(hwAccelDescr hwAccelCtx)
                    const RSAKey *pRSAKey, ubyte4 k, ubyte *EM,
                    ubyte **ppRetC)
{
    vlong*  m = NULL;
    vlong*  c = NULL;
    vlong*  n_minus_one = NULL;
    ubyte*  C = NULL;
    vlong*  pVlongQueue = NULL;
    MSTATUS status;

    /* RFC 3447, section 4.2 */
    if (OK > (status = PKCS1_OS2IP(EM, k, &m)))
        goto exit;

    /* As Per SP 800-56B R2 we check that 1 < m < n-1 */
    if (OK > (status = VLONG_makeVlongFromVlong (RSA_N(pRSAKey), &n_minus_one, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_decrement (n_minus_one, &pVlongQueue)))
        goto exit;    

    status = ERR_RSA_OUT_OF_RANGE;
    if (VLONG_compareUnsigned (m, (vlong_unit) 1 ) <= 0 || VLONG_compareSignedVlongs (m, n_minus_one) >= 0)
        goto exit;
        
    if (OK > (status = RSA_RSAEP(MOC_RSA(hwAccelCtx) pRSAKey, m, &c, &pVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(c);

    /* RFC 3447, section 4.1 */
    if (OK > (status = PKCS1_I2OSP(c, k, &C)))
        goto exit;

    DEBUG_RELABEL_MEMORY(C);

    /* set results */
    *ppRetC = C;
    C = NULL;

exit:

    if (NULL != C)
    {
        (void) DIGI_MEMSET(C, 0x00, k);
        (void) DIGI_FREE((void **) &C);
    }

    (void) VLONG_freeVlong(&c, &pVlongQueue);
    (void) VLONG_freeVlong(&m, &pVlongQueue);
    (void) VLONG_freeVlong(&n_minus_one, &pVlongQueue);
    (void) VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* PKCS1_rsaEncryption */
#endif

#ifndef __DISABLE_DIGICERT_RSA__
/*--------------------------------------------------------------------------*/

/**
@brief      Encode and encrypt a plaintext message using RSA-OAEP encryption as
            defined in RFC&nbsp;3447.

@details    This function encodes and encrypts a plain text message using the
            RSAES-OAEP encryption scheme defined in RFC&nbsp;3447. This scheme
            employs the RSAEP encryption primitive and the EME-OAEP (Optimal
            Asymmetric Encryption Padding) encoding method.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined:
+ \c \__ENABLE_DIGICERT_PKCS1__

@inc_file pkcs1.h

@param hwAccelCtx       Hardware acceleration context.
@param pRandomContext   Random number context.
@param pRSAKey          Recipient's RSA public key.
@param H                BulkHashAlgo struct used to perform hash operations.
@param MGF              Mask generation function (RFC&nbsp;\#3447 defines MFG1).
@param M                Plain text message to be encrypted, of length
                          mLen <= k - 2hlen -2, where k is the length in octets of the RSA modulus n.
@param mLen             Length in octets of the message.
@param L                (Optional) Label to use in the OAEP encoding.
@param lLen             Lenth of label, \p L, in octets.
@param ppRetEncrypt     On return, pointer to ciphertext: an octet string of
                          length k, where k is the length in octets of the RSA
                          modulus n.
@param pRetEncryptLen   On return, pointer to length in octets of the resultant
                          cyphertext message, \p ppRetEncrypt.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs1.c
*/
MOC_EXTERN MSTATUS
PKCS1_INT_rsaesOaepEncrypt(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
                       const RSAKey *pRSAKey, BulkHashAlgo *H, BulkHashAlgo *mgfH,
                       mgfFunc MGF, const ubyte *M, ubyte4 mLen, const ubyte *L, ubyte4 lLen,
                       ubyte **ppRetEncrypt, ubyte4 *pRetEncryptLen)
{
    ubyte*          EM = NULL;
    ubyte4          hLen;
    ubyte4          k = 0, temp;
    MSTATUS         status;

    if (NULL == pRSAKey || NULL == MGF || NULL == H || (mLen && NULL == M) || (lLen && NULL == L) || NULL == ppRetEncrypt || NULL == pRetEncryptLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* check that the key has at least N, rest of key will be checked later */
    if (!RSA_N(pRSAKey))
        return ERR_RSA_KEY_NOT_READY;

    hLen = H->digestSize;
    k = (7 + VLONG_bitLength(RSA_N(pRSAKey))) / 8;

    /* Check to see if there is enough space. We need space for at least at least
     * 2 digest blocks, 2 bytes, and the message.
     * It's possible 2 * hLen is == k (1024-bit key, SHA-512).
     * So we have to be careful in how we compute the difference.
     */
    temp = (2 * hLen) + 2;
    if ( (temp > k) || ((k - temp) < mLen) )
    {
        /* message too long */
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (OK > (status = emeOaepEncode(MOC_RSA(hwAccelCtx) pRandomContext, k, H, hLen, mgfH, MGF, M, mLen, (ubyte *) L, lLen, &EM)))
        goto exit;

    if (OK > (status = PKCS1_rsaEncryption(MOC_RSA(hwAccelCtx) pRSAKey, k, EM, ppRetEncrypt)))
        goto exit;

    DEBUG_RELABEL_MEMORY(*ppRetEncrypt);
    *pRetEncryptLen = k;

exit:

    if (NULL != EM)
    {
        (void) DIGI_MEMSET(EM, 0x00, k);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &EM);
    }

    return status;

} /* PKCS1_rsaesOaepEncrypt */

#endif /* !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__) */

/*--------------------------------------------------------------------------*/

static MSTATUS
emeOaepDecode(MOC_RSA(hwAccelDescr hwAccelCtx) ubyte4 k, BulkHashAlgo *H, ubyte4 hLen,
              BulkHashAlgo *mgfH, mgfFunc MGF, ubyte *EM, const ubyte *L, ubyte4 lLen,
              ubyte** ppRetM, ubyte4 *pRetMlen)
{
    BulkCtx         hashCtx = NULL;
    ubyte*          lHash = NULL;
    ubyte*          DB = NULL;
    ubyte*          seed = NULL;
    ubyte*          seedMask = NULL;
    ubyte*          maskedSeed = NULL;
    ubyte*          dbMask = NULL;
    ubyte*          maskedDB = NULL;
    ubyte*          M = NULL;
    sbyte4          mLen = 0, cmpResult;
    ubyte4          i;
    ubyte           Y;
    MSTATUS         status;
    byteBoolean     paddingErrorFlag = FALSE;

    /* allocate memory for lHash */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, hLen, TRUE, &lHash)))
        goto exit;

    DEBUG_RELABEL_MEMORY(lHash);

    /* setup hash context */
    if (OK > (status = H->allocFunc(MOC_HASH(hwAccelCtx) &hashCtx)))
        goto exit;

    if (OK > (status = H->initFunc(MOC_HASH(hwAccelCtx) hashCtx)))
        goto exit;

    if ((0 != lLen) && (NULL != L))
    {
        /* make sure there is something to hash */
        if (OK > (status = H->updateFunc(MOC_HASH(hwAccelCtx) hashCtx, L, lLen)))
            goto exit;
    }

    /* lHash = HASH(L) */
    if (OK > (status = H->finalFunc(MOC_HASH(hwAccelCtx) hashCtx, lHash)))
        goto exit;

    /* separate EM == Y || maskedSeed || maskedDB */
    Y = *EM;

    /* set maskedSeed */
    maskedSeed = EM + 1;

    /* set maskedDB */
    maskedDB = EM + 1 + hLen;

    /* seedMask = MGF(maskedDB, hLen) */
    if (OK > (status = MGF(MOC_RSA(hwAccelCtx) maskedDB, k - hLen - 1, hLen, mgfH, &seedMask)))
        goto exit;

    /* allocate memory for seed */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, hLen, TRUE, &seed)))
        goto exit;

    DEBUG_RELABEL_MEMORY(seed);

    /* maskedSeed = seed xor seedMask */
    for (i = 0; i < hLen; i++)
        seed[i] = maskedSeed[i] ^ seedMask[i];

    /* dbMask = MGF(seed, k - hLen - 1) */
    if (OK > (status = MGF(MOC_RSA(hwAccelCtx) seed, hLen, k - hLen -1, mgfH, &dbMask)))
        goto exit;

    /* allocate DB = lHash' || PS || 0x01 || M */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, k - hLen - 1, TRUE, &DB)))
        goto exit;

    DEBUG_RELABEL_MEMORY(DB);

    /* maskedDB = DB xor dbMask */
    for (i = 0; i < k - hLen - 1; i++)
        DB[i] = maskedDB[i] ^ dbMask[i];

    i = hLen;
    while ((i < k - hLen - 1) && (0x01 != DB[i]))
    {
        /* It should be all 0x00 padding until we get to the 0x01 byte */
        if (DB[i])
        {
            paddingErrorFlag = TRUE;
        }

        i++;
    }

    mLen = ((k - hLen - 1) - i) - 1;

    if ((0 < mLen) && (NULL == (M = MALLOC(mLen))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* copy out M */
    if (0 < mLen)
    {
        DIGI_MEMCPY(M, DB + i + 1, mLen);
    }

    /* now do tests to make sure cipher text is correct in form
     * Start with lHash, make sure the value we computed here is the same value
     * in the decrypted data
     */
    status = DIGI_MEMCMP (
      (void *)lHash, (void *)DB, hLen, &cmpResult);
    if (OK != status)
      goto exit;

    if ((0 != Y) || (0 >= mLen) || (0 != cmpResult) || paddingErrorFlag)
    {
        status = ERR_CRYPTO_FAILURE;
        goto exit;
    }

    /* return M */
    *ppRetM = M;
    M = NULL;

    /* and length */
    *pRetMlen = mLen;

exit:

   if (NULL != seedMask)
    {
        (void) DIGI_MEMSET(seedMask, 0x00, hLen);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &seedMask);
    }

    if (NULL != dbMask)
    {
        (void) DIGI_MEMSET(dbMask, 0x00, k - hLen - 1);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &dbMask);
    }

    if (NULL != seed)
    {
        (void) DIGI_MEMSET(seed, 0x00, hLen);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &seed);
    }

    if (NULL != DB)
    {    
        (void) DIGI_MEMSET(DB, 0x00, k - hLen - 1);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &DB);
    }

    if (NULL != lHash)
    {    
        (void) DIGI_MEMSET(lHash, 0x00, hLen);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &lHash);
    }

    if (NULL != M)
    {
        (void) DIGI_MEMSET(M, 0x00, mLen);
        (void) DIGI_FREE((void **) &M);
    }

    if (NULL != H && NULL != hashCtx)
    {
        (void) H->freeFunc(MOC_HASH(hwAccelCtx) &hashCtx);
    }

    return status;

} /* emeOaepDecode */


/*--------------------------------------------------------------------------*/

#if !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)
static MSTATUS
PKCS1_rsaDecryption(MOC_RSA(hwAccelDescr hwAccelCtx)
                    const RSAKey *pRSAKey, ubyte4 k, const ubyte *C,
                    ubyte **ppRetEM)
{
    ubyte*  EM = NULL;
    vlong*  m  = NULL;
    vlong*  c  = NULL;
    vlong*  n_minus_one = NULL;
    vlong*  pVlongQueue = NULL;
    MSTATUS status;

    /* RFC 3447, section 4.2 */
    if (OK > (status = PKCS1_OS2IP(C, k, &c)))
        goto exit;

    /* As Per SP 800-56B R2 we check that 1 < c < n-1, this is more stringent than the check in RSA_RSADP */
    if (OK > (status = VLONG_makeVlongFromVlong (RSA_N(pRSAKey), &n_minus_one, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_decrement (n_minus_one, &pVlongQueue)))
        goto exit;    

    status = ERR_RSA_OUT_OF_RANGE;
    if (VLONG_compareUnsigned (c, (vlong_unit) 1 ) <= 0 || VLONG_compareSignedVlongs (c, n_minus_one) >= 0)
        goto exit;

    if (OK > (status = RSA_RSADP(MOC_RSA(hwAccelCtx) pRSAKey, c, &m, &pVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(m);

    /* RFC 3447, section 4.1 */
    if (OK > (status = PKCS1_I2OSP(m, k, &EM)))
        goto exit;

    DEBUG_RELABEL_MEMORY(EM);

    /* set results */
    *ppRetEM = EM;
    EM = NULL;

exit:

    if (NULL != EM)
    {
        (void) DIGI_MEMSET(EM, 0x00, k);
        (void) DIGI_FREE((void **) &EM);
    }

    (void) VLONG_freeVlong(&n_minus_one, &pVlongQueue);
    (void) VLONG_freeVlong(&m, &pVlongQueue);
    (void) VLONG_freeVlong(&c, &pVlongQueue);
    (void) VLONG_freeVlongQueue(&pVlongQueue);

    return status;
}
#endif


/*--------------------------------------------------------------------------*/

#if !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)
/**
@brief      Decrypt and decode an RSAES-OAEP message as defined in RFC&nbsp;3447.

@details    This function decrypts and decodes an RSAES-OAEP encrypted message
            using the RSAES-OAEP decryption scheme defined in RFC&nbsp;3447. It
            employs the RSADP decryption primitive and the EME-OAEP (Optimal
            Asymmetric Encryption Padding) decoding method.

@todo_version (interior typecast change, explicit free on exit)

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined:
+ \c \__ENABLE_DIGICERT_PKCS1__

And the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_RSA_DECRYPTION__

@inc_file pkcs1.h

@param hwAccelCtx           Hardware acceleration context.
@param pRSAKey              Recipient's RSA private key.
@param H                    BulkHashAlgo struct used to perform hash operations.
@param MGF                  Mask generation function (RFC&nbsp;\#3447 defines MFG1).
@param C                    Ciphertext to be decrypted, an octet string of
                              length k, where k = 2hLen + 2, and where hLen
                              is the length in octets of the hash function output.
@param cLen                 Length of ciphertext, \p C, in octets.
@param L                    (Optional) Label whose association with the message
                              is to be verified.
@param lLen                 Lenth of label, in octets.
@param ppRetDecrypt         On return, pointer to message: an octet string of
                              length mLen, where mLen <= k - 2hLen - 2.
@param pRetDecryptLength    On return, pointer to lenth of message, \p
                              ppRetDecrypt, in octets.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs1.c
*/
MOC_EXTERN MSTATUS
PKCS1_INT_rsaesOaepDecrypt(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKey, BulkHashAlgo *H,
                       BulkHashAlgo *mgfH, mgfFunc MGF, const ubyte *C, ubyte4 cLen, const ubyte *L, ubyte4 lLen,
                       ubyte **ppRetDecrypt, ubyte4 *pRetDecryptLength)
{
    ubyte*          EM = NULL;
    ubyte4          hLen;
    ubyte4          k = 0;
    MSTATUS         status;

    if (NULL == pRSAKey || NULL == MGF || NULL == H || (cLen && NULL == C) || (lLen && NULL == L) || NULL == ppRetDecrypt || NULL == pRetDecryptLength)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* check that the key has at least N, rest of key will be checked later */
    if (!RSA_N(pRSAKey))
        return ERR_RSA_KEY_NOT_READY;

    hLen = H->digestSize;
    k = (7 + VLONG_bitLength(RSA_N(pRSAKey))) / 8;

    if ((k != cLen) || (k < ((2 * hLen) + 2)))
    {
        /* message should be equal to key length */
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (OK > (status = PKCS1_rsaDecryption(MOC_RSA(hwAccelCtx) pRSAKey, k, C, &EM)))
        goto exit;

    if (OK > (status = emeOaepDecode(MOC_RSA(hwAccelCtx) k, H, hLen, mgfH, MGF, EM, L, lLen, ppRetDecrypt, pRetDecryptLength)))
        goto exit;

    DEBUG_RELABEL_MEMORY(*ppRetDecrypt);

exit:

    if (NULL != EM)
    {
        (void) DIGI_MEMSET(EM, 0x00, k);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &EM);
    }

    return status;

} /* PKCS1_rsaesOaepDecrypt */

#endif /* !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__) */


/*--------------------------------------------------------------------------*/

static MSTATUS
emsaPssEncode(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
              const ubyte *M, ubyte4 mLen, ubyte4 emBits, ubyte4 sLen,
              BulkHashAlgo *Halgo, ubyte4 hLen, BulkHashAlgo *mgfHalgo,
              mgfFunc MGF, ubyte** ppRetEM)
{
    ubyte4  emLen = ((emBits + 7) / 8);
    BulkCtx hashCtx = NULL;
    ubyte*  EM = NULL;
    ubyte*  Mprime = NULL;
    ubyte*  DB = NULL;
    ubyte*  salt = NULL;
    ubyte*  H = NULL;
    ubyte*  dbMask = NULL;
    ubyte*  maskedDB = NULL;
    ubyte4  i, leftBits;
    MSTATUS status;

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
    DEBUG_PRINTNL(DEBUG_CRYPTO, "emsaPssEncode: got here.");
#endif

    *ppRetEM = NULL;

    if ((emLen < (hLen + sLen + 2)) ||
        (emBits < ((8 * hLen) + (8 * sLen) + 9)))
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* allocate memory for M' (Mprime) */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, 8 + hLen + sLen, TRUE, &Mprime)))
        goto exit;

    DEBUG_RELABEL_MEMORY(Mprime);

    /* setup hash context */
    if (OK > (status = Halgo->allocFunc(MOC_HASH(hwAccelCtx) &hashCtx)))
        goto exit;

    if (OK > (status = Halgo->initFunc(MOC_HASH(hwAccelCtx) hashCtx)))
        goto exit;

    if ((0 != mLen) && (NULL != M))
    {
        /* make sure there is something to hash */
        if (OK > (status = Halgo->updateFunc(MOC_HASH(hwAccelCtx) hashCtx, M, mLen)))
            goto exit;
    }

    /* M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
    /* set first 8 octets to zero */
    DIGI_MEMSET(Mprime, 0x00, 8);

    /* append mHash */
    if (OK > (status = Halgo->finalFunc(MOC_HASH(hwAccelCtx) hashCtx, 8 + Mprime)))
        goto exit;

    /* append random octet string salt of length sLen */
    salt = 8 + hLen + Mprime;

    if (0 < sLen)
    {
        if (OK > (status = RANDOM_numberGenerator(pRandomContext, salt, sLen)))
            goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
    DEBUG_PRINTNL(DEBUG_CRYPTO, "M'=");
    DEBUG_HEXDUMP(DEBUG_CRYPTO, Mprime, 8 + hLen + sLen);
#endif

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
    DEBUG_PRINTNL(DEBUG_CRYPTO, "salt=");
    DEBUG_HEXDUMP(DEBUG_CRYPTO, salt, sLen);
#endif

    /* allocate memory for H */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, hLen, TRUE, &H)))
        goto exit;

    DEBUG_RELABEL_MEMORY(H);

    /* H = Hash(M') */
    if (OK > (status = Halgo->initFunc(MOC_HASH(hwAccelCtx) hashCtx)))
        goto exit;

    if (OK > (status = Halgo->updateFunc(MOC_HASH(hwAccelCtx) hashCtx, Mprime, 8 + hLen + sLen)))
        goto exit;

    if (OK > (status = Halgo->finalFunc(MOC_HASH(hwAccelCtx) hashCtx, H)))
        goto exit;

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
    DEBUG_PRINTNL(DEBUG_CRYPTO, "H=");
    DEBUG_HEXDUMP(DEBUG_CRYPTO, H, hLen);
#endif

    /* allocate memory for DB */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, emLen - hLen - 1, TRUE, &DB)))
        goto exit;

    DEBUG_RELABEL_MEMORY(DB);

    /* DB = PS || 0x01 || salt */
    /* clear first PS octets */
    if (emLen - sLen - hLen - 2)
        DIGI_MEMSET(DB, 0x00, emLen - sLen - hLen - 2);

    *(DB + emLen - sLen - hLen - 2) = 0x01;

    DIGI_MEMCPY(DB + emLen - sLen - hLen - 1, salt, sLen);

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
    DEBUG_PRINTNL(DEBUG_CRYPTO, "DB=");
    DEBUG_HEXDUMP(DEBUG_CRYPTO, DB, emLen - hLen - 1);
#endif

    /* dbMask = MGF(H, emLen - hLen - 1) */
    if (OK > (status = MGF(MOC_RSA(hwAccelCtx) H, hLen, emLen - hLen - 1, mgfHalgo, &dbMask)))
        goto exit;

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
    DEBUG_PRINTNL(DEBUG_CRYPTO, "dbMask=");
    DEBUG_HEXDUMP(DEBUG_CRYPTO, dbMask, emLen - hLen - 1);
#endif

    /* allocate EM == maskedDB || H || 0xbc */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, emLen, TRUE, &EM)))
        goto exit;

    DEBUG_RELABEL_MEMORY(EM);

    /* set maskedDB */
    maskedDB = EM;

    /* EM == maskedDB || H || 0xbc */
    /* maskedDB = DB xor dbMask */
    for (i = 0; i < emLen - hLen - 1; i++)
        maskedDB[i] = DB[i] ^ dbMask[i];

    /* clear leftmost maskedDB bits ((8 * emLen) - emBits) */
    if (0 < (leftBits = ((8 * emLen) - emBits)))
    {
        ubyte mask = 0xff >> leftBits;

        *maskedDB = ((*maskedDB) & mask);
    }

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
    DEBUG_PRINTNL(DEBUG_CRYPTO, "maskedDB=");
    DEBUG_HEXDUMP(DEBUG_CRYPTO, maskedDB, emLen - hLen - 1);
#endif

    /* append H to EM */
    DIGI_MEMCPY(EM + emLen - hLen - 1, H, hLen);

    /* append 0xbc*/
    *(EM + emLen - 1) = 0xbc;

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
    DEBUG_PRINTNL(DEBUG_CRYPTO, "EM=");
    DEBUG_HEXDUMP(DEBUG_CRYPTO, EM, emLen);
#endif

    /* return EM */
    *ppRetEM = EM;
    EM = NULL;

exit:

    if (NULL != EM)
    {
        (void) DIGI_MEMSET(EM, 0x00, emLen);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &EM);
    }

    if (NULL != dbMask)
    {
        (void) DIGI_MEMSET(dbMask, 0x00, emLen - hLen - 1);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &dbMask);
    }

    if (NULL != DB)
    {
        (void) DIGI_MEMSET(DB, 0x00, emLen - hLen - 1);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &DB);
    }

    if (NULL != Mprime)
    {
        (void) DIGI_MEMSET(Mprime, 0x00, 8 + hLen + sLen);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &Mprime);
    }

    if (NULL != H)
    {
        (void) DIGI_MEMSET(H, 0x00, hLen);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &H);
    }

    if (NULL != Halgo && NULL != hashCtx)
    {
        (void) Halgo->freeFunc(MOC_HASH(hwAccelCtx) &hashCtx);
    }

    return status;

} /* emsaPssEncode */


/*--------------------------------------------------------------------------*/

static MSTATUS
emsaPssVerify(MOC_RSA(hwAccelDescr hwAccelCtx) const ubyte * const M, ubyte4 mLen,
              ubyte *EM, ubyte4 emBits, sbyte4 sLen,
              BulkHashAlgo *Halgo, ubyte4 hLen, BulkHashAlgo *mgfHalgo,
              mgfFunc MGF, intBoolean *pIsConsistent)
{
  ubyte4  emLen = ((emBits + 7) / 8);
  BulkCtx hashCtx = NULL;
  ubyte*  maskedDB;
  ubyte*  H;
  ubyte*  DB = NULL;
  ubyte*  salt = NULL;
  ubyte*  dbMask = NULL;
  ubyte*  Mprime = NULL;
  ubyte*  Hprime = NULL;
  ubyte4  i, leftBits;
  sbyte4  result;
  ubyte4  vfyResult;
  MSTATUS status = OK;

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
  DEBUG_PRINTNL(DEBUG_CRYPTO, "emsaPssVerify: got here.");
#endif

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
  DEBUG_PRINTNL(DEBUG_CRYPTO, "EM=");
  DEBUG_HEXDUMP(DEBUG_CRYPTO, EM, emLen);
#endif

  /* Set vfyResult to 0, meaning there have been no errors in verifying the
   * signature.
   * Each time we encounter an error, add to vfyResult. At the end, if
   * vfyResult is not 0, then set status to ERR_RSA_DECRYPTION.
   * We want to make all checks and not stop as soon as we hit an error.
   */
  vfyResult = 0;

  /* default to result being inconsistent */
  *pIsConsistent = FALSE;

  /* test lengths
   * If the block is not big enough, we can't perform the operation at all.
   */
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__    
  if (sLen < -1 || sLen > (sbyte4) hLen)
#else
  if (sLen < -1)
#endif
  {
    status = ERR_INVALID_ARG;
    goto exit;
  }
  else if (-1 == sLen)
  {
    if ((emLen < (hLen + 2)) ||
        (emBits < ((8 * hLen) + 9)))
      goto exit;
  }
  else
  {
    if ((emLen < (hLen + (ubyte4) sLen + 2)) ||
        (emBits < ((8 * hLen) + (8 * (ubyte4) sLen) + 9)))
      goto exit;
  }

  if (0xbc != EM[emLen - 1])
    vfyResult++;

  /* set pointers */
  maskedDB = EM;
  H = EM + emLen - hLen - 1;

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
  DEBUG_PRINTNL(DEBUG_CRYPTO, "maskedDB=");
  DEBUG_HEXDUMP(DEBUG_CRYPTO, maskedDB, emLen - hLen - 1);
#endif

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
  DEBUG_PRINTNL(DEBUG_CRYPTO, "H=");
  DEBUG_HEXDUMP(DEBUG_CRYPTO, H, hLen);
#endif

  /* test left most bits for zero */
  if (0 < (leftBits = ((8 * emLen) - emBits)))
  {
    ubyte mask = 0xff >> leftBits;

    if (0x00 != ((*maskedDB) & (0xff ^ mask)))
      vfyResult++;
  }

  /* dbMask = MGF(H, emLen - hLen - 1 */
  if (OK > (status = MGF(MOC_RSA(hwAccelCtx) H, hLen, emLen - hLen - 1, mgfHalgo, &dbMask)))
    goto exit;

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
  DEBUG_PRINTNL(DEBUG_CRYPTO, "dbMask=");
  DEBUG_HEXDUMP(DEBUG_CRYPTO, dbMask, emLen - hLen - 1);
#endif

  /* allocate memory for DB */
  if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, emLen - hLen - 1, TRUE, &DB)))
    goto exit;

  DEBUG_RELABEL_MEMORY(DB);

  /* DB = maskedDB xor dbMask */
  for (i = 0; i < emLen - hLen - 1; i++)
    DB[i] = maskedDB[i] ^ dbMask[i];

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
  DEBUG_PRINTNL(DEBUG_CRYPTO, "DB=");
  DEBUG_HEXDUMP(DEBUG_CRYPTO, DB, emLen - hLen - 1);
#endif

  /* clear leftmost DB bits ((8 * emLen) - emBits) */
  if (0 < (leftBits = ((8 * emLen) - emBits)))
  {
    ubyte mask = 0xff >> leftBits;

    *DB = ((*DB) & mask);
  }

  if (-1 != sLen)
  {
    /* make sure the leftmost emLen - hLen - sLen - 2 octets are zero */
    for (i = 0; i < (emLen - hLen - (ubyte4) sLen - 2); i++)
    {
      if (0x00 != DB[i])
        vfyResult++;
    }

    if (0x01 != DB[i])
      vfyResult++;
  }
  else
  {
    i = 0;

    /* we don't know the saltLen so just count the leftmost 0x00 octets */
    while( i < (emLen - hLen - 1) && 0x00 == DB[i] )
    {
      i++;
    }
    if (i == emLen - hLen - 1)  /* got to the end, no 0x01 byte */
    {
      vfyResult++;
    }
    else
    {
      /* next byte must be 0x01 */
      if (0x01 != DB[i])
        vfyResult++;
    }

    /* now we know the salt length, ok to overwrite passed by value sLen */
    sLen = (sbyte4) (emLen - hLen - 2 - i);

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__    
    /* Validate the salt len is in the proper range */
    if (sLen < 0 || sLen > (sbyte4) hLen)
      vfyResult++;
#endif
  }

  /* allocate memory for M' (Mprime) */
  if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, 8 + hLen + (ubyte4) sLen, TRUE, &Mprime)))
    goto exit;

  DEBUG_RELABEL_MEMORY(DB);

  /* setup hash context */
  if (OK > (status = Halgo->allocFunc(MOC_HASH(hwAccelCtx) &hashCtx)))
    goto exit;

  if (OK > (status = Halgo->initFunc(MOC_HASH(hwAccelCtx) hashCtx)))
    goto exit;

  if ((0 != mLen) && (NULL != M))
  {
    /* make sure there is something to hash */
    if (OK > (status = Halgo->updateFunc(MOC_HASH(hwAccelCtx) hashCtx, M, mLen)))
      goto exit;
  }

  /* M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
  /* set first 8 octets to zero */
  DIGI_MEMSET(Mprime, 0x00, 8);

  /* mHash = HASH(M) */
  if (OK > (status = Halgo->finalFunc(MOC_HASH(hwAccelCtx) hashCtx, 8 + Mprime)))
    goto exit;

  /* append random octet string salt of length sLen */
  salt = emLen - (ubyte4) sLen - hLen - 1 + DB;

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
  DEBUG_PRINTNL(DEBUG_CRYPTO, "salt=");
  DEBUG_HEXDUMP(DEBUG_CRYPTO, salt, (ubyte4) sLen);
#endif

  if (OK > (status = DIGI_MEMCPY(8 + hLen + Mprime, salt, (ubyte4) sLen)))
    goto exit;

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
  DEBUG_PRINTNL(DEBUG_CRYPTO, "M'=");
  DEBUG_HEXDUMP(DEBUG_CRYPTO, Mprime, 8 + hLen + (ubyte4) sLen);
#endif

  /* allocate memory for H' (Hprime) */
  if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, hLen, TRUE, &Hprime)))
    goto exit;

  DEBUG_RELABEL_MEMORY(Hprime);

  /* setup hash context */
  if (OK > (status = Halgo->initFunc(MOC_HASH(hwAccelCtx) hashCtx)))
    goto exit;

  if (OK > (status = Halgo->updateFunc(MOC_HASH(hwAccelCtx) hashCtx, Mprime, 8 + hLen + (ubyte4) sLen)))
    goto exit;

  if (OK > (status = Halgo->finalFunc(MOC_HASH(hwAccelCtx) hashCtx, Hprime)))
    goto exit;

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
  DEBUG_PRINTNL(DEBUG_CRYPTO, "H'=");
  DEBUG_HEXDUMP(DEBUG_CRYPTO, Hprime, hLen);
#endif

  if (OK > (status = DIGI_CTIME_MATCH(H, Hprime, hLen, &result)))
    goto exit;

  if (0 != result)
    vfyResult++;

  /* If none of the tests failed, vfyResult will be 0.
   * If so, set the return to TRUE.
   */
  if (0 == vfyResult)
    *pIsConsistent = TRUE;

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
  DEBUG_PRINTNL(DEBUG_CRYPTO, "emsaPssVerify: exit.");
#endif

exit:

    if (NULL != Hprime)
    {
        (void) DIGI_MEMSET(Hprime, 0x00, hLen);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &Hprime);
    }

    if (NULL != dbMask)
    {
        (void) DIGI_MEMSET(dbMask, 0x00, emLen - hLen - 1);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &dbMask);
    }

    if (NULL != DB)
    {
        (void) DIGI_MEMSET(DB, 0x00, emLen - hLen - 1);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &DB);
    }

    if (NULL != Mprime)
    {
        (void) DIGI_MEMSET(Mprime, 0x00, 8 + hLen + (ubyte4) sLen);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &Mprime);
    }

    if (NULL != Halgo && NULL != hashCtx)
    {
        (void) Halgo->freeFunc(MOC_HASH(hwAccelCtx) &hashCtx);
    }

    return status;

} /* emsaPssVerify */


/*--------------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_RSA_DECRYPTION__))

/**
@brief      Generate a signature using the RSASSA_PSS signature scheme defined
            in RFC&nbsp;3447.

@details    This function generates a signature using the RSASSA_PSS signature
            scheme defined in RFC&nbsp;3447. It employs the RSASP1 signature primitive with the EMSA-PSS encoding method.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined:
+ \c \__ENABLE_DIGICERT_PKCS1__

@inc_file pkcs1.h

@param  hwAccelCtx          Hardware acceleration context.
@param  pRandomContext      Random number context.
@param  pRSAKey             Recipient's RSA private key.
@param  Halgo               BulkHashAlgo struct used to perform hash operations.
@param  MGF                 Mask generation function (RFC&nbsp;\#3447 defines
                              MFG1).
@param  pMessage            Message to be signed, an octet string.
@param  mesgLen             Length in octets of message (pMessage).
@param  saltLen             Length of salt to be used by EMSA-PSS encoding
                              method for random number generation.
@param  ppRetSignature      On return, pointer to resultant signature&mdash;an
                              octet string.
@param  pRetSignatureLen    On return, pointer to length of signature, in
                              octets.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs1.c
*/
MOC_EXTERN MSTATUS
PKCS1_INT_rsassaPssSign(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
                    const RSAKey *pRSAKey, BulkHashAlgo *Halgo, BulkHashAlgo *mgfHalgo, mgfFunc MGF,
                    const ubyte *pMessage, ubyte4 mesgLen, ubyte4 saltLen,
                    ubyte **ppRetSignature, ubyte4 *pRetSignatureLen)
{
    FIPS_LOG_DECL_SESSION;
    vlong*          s = NULL;
    vlong*          m = NULL;
    vlong*          n_minus_one = NULL;
    ubyte*          pEM = NULL;
    ubyte4          emBits;
    ubyte4          k;
    vlong*          pVlongQueue = NULL;
    MSTATUS         status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */

    if (NULL == pRSAKey || NULL == Halgo || (mesgLen && NULL == pMessage) || NULL == ppRetSignature || NULL == pRetSignatureLen)
        return ERR_NULL_POINTER;

    /* check that the key has at least N, rest of key will be checked later */
    if (!RSA_N(pRSAKey))
        return ERR_RSA_KEY_NOT_READY;

    FIPS_LOG_START_ALG(FIPS_ALGO_RSA_PSS,0);

    emBits = VLONG_bitLength(RSA_N(pRSAKey)) - 1;
    k = (emBits + 7)/8;

    if (OK > (status = emsaPssEncode(MOC_RSA(hwAccelCtx) pRandomContext,
                                     pMessage, mesgLen, emBits, saltLen,
                                     Halgo, Halgo->digestSize, mgfHalgo, MGF, &pEM)))
    {
        goto exit;
    }

    if (OK > (status = PKCS1_OS2IP(pEM, k, &m)))
        goto exit;

    /* As Per SP 800-56B R2 we check that 1 < m < n-1 */
    if (OK > (status = VLONG_makeVlongFromVlong (RSA_N(pRSAKey), &n_minus_one, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_decrement (n_minus_one, &pVlongQueue)))
        goto exit;    

    status = ERR_RSA_OUT_OF_RANGE;
    if (VLONG_compareUnsigned (m, (vlong_unit) 1 ) <= 0 || VLONG_compareSignedVlongs (m, n_minus_one) >= 0)
        goto exit;

    if (OK > (status = RSA_RSASP1(MOC_RSA(hwAccelCtx) pRSAKey, m, NULL, NULL, &s, &pVlongQueue)))
        goto exit;

    if (OK > (status = PKCS1_I2OSP(s, k, ppRetSignature)))
        goto exit;

    DEBUG_RELABEL_MEMORY(*ppRetSignature);

    *pRetSignatureLen = k;

exit:

    (void) VLONG_freeVlong(&s, &pVlongQueue);
    (void) VLONG_freeVlong(&m, &pVlongQueue);
    (void) VLONG_freeVlong(&n_minus_one, &pVlongQueue);
    (void) VLONG_freeVlongQueue(&pVlongQueue);

    if (NULL != pEM)
    {
        (void) DIGI_MEMSET(pEM, 0x00, k);
        (void) CRYPTO_FREE(hwAccelCtx, TRUE, &pEM);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA_PSS,0);
    return status;

} /* PKCS1_rsassaPssSign */

#endif /* if (!defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)) */


/*--------------------------------------------------------------------------*/

/**
@brief      Free signature memory.

@details    This function frees memory allocated for a signature generated by
            the RSASSA_PSS signature scheme.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined:
+ \c \__ENABLE_DIGICERT_PKCS1__

@inc_file pkcs1.h

@param  hwAccelCtx  For future use.
@param  ppSignature Pointer to signature generated by RSASSA_PSS signature
                      scheme.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs1.c
*/
MOC_EXTERN MSTATUS
PKCS1_INT_rsassaFreePssSign(MOC_RSA(hwAccelDescr hwAccelCtx) ubyte **ppSignature)
{
    return CRYPTO_FREE(hwAccelCtx, TRUE, ppSignature);
}


/*--------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
/**
@brief      Verify a RSASSA-PSS signature.

@details    This function verifies a signature generated by the RSASSA_PSS
            signature scheme defined in RFC&nbsp;3447. It employs the RSAVP1
            primitive with the EMSA-PSS decoding method.

@ingroup    pkcs_functions

@flags
There are no flag dependencies to enable this function.

@inc_file pkcs1.h

@param  hwAccelCtx          Hardware acceleration context.
@param  pRSAKey             Signer's RSA public key.
@param  Halgo               BulkHashAlgo struct used to perform hash operations.
@param  MGF                 Mask generation function (RFC \#3447 defines MFG1).
@param  pMessage            Message whose signature is to be verified, an octet
                              string.
@param  mesgLen             Length of message in octets.
@param  pSignature          Signature to be verified, an octet string.
@param  signatureLen        Length.
@param  saltLen             Length of salt to be used by EMSA-PSS decoding
                              method for random number generation. Use -1
                              to get the salt length from the signature.
@param  pRetIsSignatureValid    On return, pointer to \c TRUE if signature is
                                  valid; otherwise pointer to \c FALSE.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs1.c
*/
MOC_EXTERN MSTATUS
PKCS1_INT_rsassaPssVerify(MOC_RSA(hwAccelDescr hwAccelCtx)
                      const RSAKey *pRSAKey, BulkHashAlgo *Halgo, BulkHashAlgo *mgfHalgo, mgfFunc MGF,
                      const ubyte * const pMessage, ubyte4 mesgLen,
                      const ubyte *pSignature, ubyte4 signatureLen, sbyte4 saltLen,
                      intBoolean *pRetIsSignatureValid)
{
    FIPS_LOG_DECL_SESSION;
    vlong*          s = NULL;
    vlong*          m = NULL;
    ubyte*          pEM = NULL;
    vlong*          n_minus_one = NULL;
    ubyte4          emBits;
    ubyte4          k;
    ubyte4          offset = 0;
    vlong*          pVlongQueue = NULL;
    MSTATUS         status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */

    if (NULL == pRSAKey || NULL == Halgo || (mesgLen && NULL == pMessage) || (signatureLen && NULL == pSignature) || NULL == pRetIsSignatureValid)
        return ERR_NULL_POINTER;

    /* default */
    *pRetIsSignatureValid = FALSE;

    /* check that the key has at least N, rest of key will be checked later */
    if (!RSA_N(pRSAKey))
        return ERR_RSA_KEY_NOT_READY;

    FIPS_LOG_START_ALG(FIPS_ALGO_RSA_PSS,0);

    emBits = VLONG_bitLength(RSA_N(pRSAKey));
    k = (emBits + 7)/8; /* we keep k the modLen in bytes */
    emBits--;

    if (OK > (status = PKCS1_OS2IP(pSignature, signatureLen, &s)))
        goto exit;

    /* As Per SP 800-56B R2 we check that 1 < s < n-1 */
    if (OK > (status = VLONG_makeVlongFromVlong (RSA_N(pRSAKey), &n_minus_one, &pVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_decrement (n_minus_one, &pVlongQueue)))
        goto exit;    

    status = ERR_RSA_OUT_OF_RANGE;
    if (VLONG_compareUnsigned (s, (vlong_unit) 1 ) <= 0 || VLONG_compareSignedVlongs (s, n_minus_one) >= 0)
        goto exit;

    if (OK > (status = RSA_RSAVP1(MOC_RSA(hwAccelCtx) pRSAKey, s, &m, &pVlongQueue)))
        goto exit;

    /* !!!! PKCS#1 v2.1: pg 29: add bit test here! */

    if (OK > (status = PKCS1_I2OSP(m, k, &pEM)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pEM);

    /* for emBits divisible by 8 first byte has to be zero and em begins with next byte */
    if (0 == (emBits & 0x07))
    {
        if (0x00 != pEM[0])
        {
            status = ERR_RSA_BAD_SIGNATURE;
            goto exit;
        }
        else
        {
            offset = 1;
        }
    }

    if (OK > (status = emsaPssVerify(MOC_RSA(hwAccelCtx) pMessage, mesgLen,
                                     pEM + offset, emBits, saltLen,
                                     Halgo, Halgo->digestSize, mgfHalgo,
                                     MGF, pRetIsSignatureValid)))
    {
        goto exit;
    }

    /* return an error with flag --- double notify, if signature check fails */
    if (TRUE != *pRetIsSignatureValid)
        status = ERR_RSA_BAD_SIGNATURE;

exit:

    if (NULL != pEM)
    {
        (void) DIGI_MEMSET(pEM, 0x00, k);
        (void) DIGI_FREE((void **) &pEM);
    }

    (void) VLONG_freeVlong(&m, &pVlongQueue);
    (void) VLONG_freeVlong(&s, &pVlongQueue);
    (void) VLONG_freeVlong(&n_minus_one, &pVlongQueue);
    (void) VLONG_freeVlongQueue(&pVlongQueue);

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA_PSS,0);
    return status;

} /* PKCS1_rsassaPssVerify */


#endif /* __DISABLE_DIGICERT_RSA__ */
#endif /* __RSA_PKCS1_HARDWARE_ACCELERATOR__ */
#endif /* __ENABLE_DIGICERT_PKCS1__ */
