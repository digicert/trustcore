/*
 * psspad.c
 *
 * Pad and unpad following PKCS 1 version 2.0 PSS.
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
#include "../../../crypto/mocasymkeys/mocsw/commonasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonrsa.h"
#include "../../../harness/harness.h"
#include "../../../crypto/pkcs1.h"

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_PKCS1__))

MOC_EXTERN MSTATUS RsaPadPss(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    RNGFun rngFun,
    void *rngFunArg,
    const ubyte *M,
    ubyte4 mLen,
    ubyte4 emBits,
    ubyte4 sLen,
    BulkHashAlgo *Halgo,
    BulkHashAlgo *mgfHalgo,
    ubyte4 hLen,
    ubyte MGF,
    ubyte** ppRetEM
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte pDigest[64] = {0}; /* big enough for sha512, largest digest */
    BulkCtx pHashCtx = NULL;

    if (NULL == Halgo)
        goto exit;

    /* rest of input validation will be done by RsaPssPadDigest */

    /* setup hash context */
    if (OK > (status = Halgo->allocFunc(MOC_HASH(hwAccelCtx) &pHashCtx)))
        goto exit;

    if (OK > (status = Halgo->initFunc(MOC_HASH(hwAccelCtx) pHashCtx)))
        goto exit;

    /* make sure there is something to hash */
    if ((0 != mLen) && (NULL != M))
    {
        if (OK > (status = Halgo->updateFunc(MOC_HASH(hwAccelCtx) pHashCtx, M, mLen)))
            goto exit;
    }

    if (OK > (status = Halgo->finalFunc(MOC_HASH(hwAccelCtx) pHashCtx, pDigest)))
        goto exit;

    status = RsaPadPssDigest(MOC_HASH(hwAccelCtx) rngFun, rngFunArg, pDigest, hLen, emBits, sLen,
                             Halgo, mgfHalgo, MGF, ppRetEM);
exit:

    if (NULL != Halgo && NULL != pHashCtx)
    {
        (void) Halgo->freeFunc(MOC_HASH(hwAccelCtx) &pHashCtx);
    }
    
    return status;
}

MOC_EXTERN MSTATUS RsaPadPssDigest(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    RNGFun rngFun,
    void *rngFunArg,
    const ubyte *pDigest,
    ubyte4 hLen,
    ubyte4 emBits,
    ubyte4 sLen,
    BulkHashAlgo *Halgo,
    BulkHashAlgo *mgfHalgo,
    ubyte MGF,
    ubyte **ppRetEM
    )
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
    mgfFunc mgf = 0;
    MSTATUS status;

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
    DEBUG_PRINTNL(DEBUG_CRYPTO, "emsaPssEncode: got here.");
#endif

    if (NULL == ppRetEM || NULL == mgfHalgo || NULL == Halgo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetEM = NULL;

    if (MOC_PKCS1_ALG_MGF1 == MGF)
    {
        mgf = MaskGenFunction1;
    }
    else if (MOC_PKCS1_ALG_SHAKE == MGF)
    {
        mgf = MaskGenFunctionShake;
    }
    else
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

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
 
    /* M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
    (void) DIGI_MEMSET(Mprime, 0x00, 8);
    (void) DIGI_MEMCPY(Mprime + 8, pDigest, hLen);

    /* append random octet string salt of length sLen */
    salt = Mprime + 8 + hLen;

    if (0 < sLen)
    {
        if (OK > (status = rngFun(rngFunArg, sLen, salt)))
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

    /* setup hash context */
    if (OK > (status = Halgo->allocFunc(MOC_HASH(hwAccelCtx) &hashCtx)))
        goto exit;

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

    /* dbMask = mgf(H, emLen - hLen - 1) */
    if (OK > (status = mgf(MOC_HASH(hwAccelCtx) H, hLen, emLen - hLen - 1, mgfHalgo, &dbMask)))
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

}

MOC_EXTERN MSTATUS RsaPadPssVerifyDigest(
    MOC_HASH(hwAccelDescr hwAccelCtx) 
    const ubyte *pDigest,
    ubyte4 hLen,
    ubyte *EM,
    ubyte4 emBits,
    sbyte4 sLen,
    BulkHashAlgo *Halgo,
    BulkHashAlgo *mgfHalgo,
    ubyte MGF,
    intBoolean *pIsConsistent)
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
    mgfFunc mgf = 0;
    MSTATUS status = OK;

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
    DEBUG_PRINTNL(DEBUG_CRYPTO, "emsaPssVerify: got here.");
#endif

#ifdef __ENABLE_DIGICERT_PKCS1_DEBUG__
    DEBUG_PRINTNL(DEBUG_CRYPTO, "EM=");
    DEBUG_HEXDUMP(DEBUG_CRYPTO, EM, emLen);
#endif

    if (NULL == mgfHalgo || NULL == Halgo || NULL == pIsConsistent)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (MOC_PKCS1_ALG_MGF1 == MGF)
    {
        mgf = MaskGenFunction1;
    }
    else if (MOC_PKCS1_ALG_SHAKE == MGF)
    {
        mgf = MaskGenFunctionShake;
    }
    else
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

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
    if (OK > (status = mgf(MOC_HASH(hwAccelCtx) H, hLen, emLen - hLen - 1, mgfHalgo, &dbMask)))
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

    /* M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
    /* set first 8 octets to zero */
    (void) DIGI_MEMSET(Mprime, 0x00, 8);
    (void) DIGI_MEMCPY(Mprime + 8, pDigest, hLen);

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
    if (OK > (status = Halgo->allocFunc(MOC_HASH(hwAccelCtx) &hashCtx)))
        goto exit;

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
}
#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_PKCS1__)) */
