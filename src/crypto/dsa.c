/*
 * dsa.c
 *
 * DSA Factory
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA_INTERNAL__

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_DSA__))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/debug_console.h"
#include "../common/memory_debug.h"
#include "../common/prime.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../asn1/parseasn1.h"
#include "../asn1/derencoder.h"
#include "../asn1/oiddefs.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/rsa.h"
#include "../crypto/dsa.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/keyblob.h"
#include "../crypto/ca_mgmt.h"
#include "../harness/harness.h"

/*------------------------------------------------------------------*/

#define SIZEOF_DSA_Q            (SHA_HASH_RESULT_SIZE * 8)
#define MAX_DSA_ITERATIONS      4096


#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
static int dsa_fail = 0;

FIPS_TESTLOG_IMPORT;

/*------------------------------------------------------------------*/

/* prototype */
extern MSTATUS
DSA_generateKey_FIPS_consistancy_test(MOC_DSA(sbyte4 hwAccelCtx) randomContext* pFipsRngCtx, DSAKey* p_dsaDescr);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/*------------------------------------------------------------------*/

extern MSTATUS
DSA_createKey(DSAKey **pp_retDsaDescr)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DSA,0);

    if (NULL == pp_retDsaDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (*pp_retDsaDescr = MALLOC(sizeof(DSAKey))))
        status = ERR_MEM_ALLOC_FAIL;
    else
        DIGI_MEMSET((ubyte *)(*pp_retDsaDescr), 0x00, sizeof(DSAKey));

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_DSA,0);
    return status;
}


/*--------------------------------------------------------------------------*/


extern MSTATUS
DSA_cloneKey(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey** ppNew, const DSAKey* pSrc)
{
    DSAKey* pNew = NULL;
    MSTATUS status = OK;

    if ((NULL == ppNew) || (NULL == pSrc))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > ( status = DSA_createKey(&pNew)))
        goto exit;

    if (OK > ( status = VLONG_makeVlongFromVlong(DSA_P(pSrc), &DSA_P(pNew), NULL)))
        goto exit;

    if (OK > ( status = VLONG_makeVlongFromVlong(DSA_Q(pSrc), &DSA_Q(pNew), NULL)))
        goto exit;

    if (OK > ( status = VLONG_makeVlongFromVlong(DSA_G(pSrc), &DSA_G(pNew), NULL)))
        goto exit;

    if (OK > ( status = VLONG_makeVlongFromVlong(DSA_Y(pSrc), &DSA_Y(pNew), NULL)))
        goto exit;

    if (DSA_X(pSrc))
        if ( OK > ( status = VLONG_makeVlongFromVlong(DSA_X(pSrc), &DSA_X(pNew), NULL)))
            goto exit;

    /* OK */
    *ppNew = pNew;
    pNew = NULL;

exit:
    if (NULL != pNew)
        DSA_freeKey(&pNew, NULL);

    return status;
}


/*------------------------------------------------------------------*/


extern MSTATUS
DSA_freeKey(DSAKey **ppFreeDSAKey, vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DSA,0);

    if ((NULL == ppFreeDSAKey) || (NULL == *ppFreeDSAKey))
    {
        status = ERR_NULL_POINTER;
    }
    else
    {
        sbyte4 i;

        for (i = 0; i < NUM_DSA_VLONG; i++)
            VLONG_freeVlong(&((*ppFreeDSAKey)->dsaVlong[i]), ppVlongQueue);

        FREE(*ppFreeDSAKey);
        *ppFreeDSAKey = NULL;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_DSA,0);
    return status;
}


/*------------------------------------------------------------------*/

static void
DSA_clearKey(DSAKey *pDSAKey, vlong **ppVlongQueue)
{
    sbyte4 i;

    if (NULL == pDSAKey)
        return; /* nothing to clear */

    for (i = 0; i < NUM_DSA_VLONG; i++)
        VLONG_freeVlong(&(pDSAKey->dsaVlong[i]), ppVlongQueue);
}


/*------------------------------------------------------------------*/


extern MSTATUS
DSA_equalKey(MOC_DSA(hwAccelDescr hwAccelCtx) const DSAKey *pKey1, const DSAKey *pKey2, byteBoolean* pResult)
{
    MSTATUS status = OK;

    if ((NULL == pKey1) || (NULL == pKey2) || (NULL == pResult))
        status = ERR_NULL_POINTER;
    else
    {
        /* only compare the public part */
        *pResult = FALSE;

        if ((0 == VLONG_compareSignedVlongs(DSA_P(pKey1), DSA_P(pKey2))) &&
            (0 == VLONG_compareSignedVlongs(DSA_Q(pKey1), DSA_Q(pKey2))) &&
            (0 == VLONG_compareSignedVlongs(DSA_G(pKey1), DSA_G(pKey2))) &&
            (0 == VLONG_compareSignedVlongs(DSA_Y(pKey1), DSA_Y(pKey2))) )
        {
            *pResult = TRUE;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/


#if !defined(__DSA_HARDWARE_ACCELERATOR_VERIFY__) && !defined(__DSA_HARDWARE_ACCELERATOR__)

extern MSTATUS
DSA_verifySignature(MOC_DSA(hwAccelDescr hwAccelCtx) const DSAKey *p_dsaDescr,
                    vlong *m, vlong *pR, vlong *pS,
                    intBoolean *isGoodSignature, vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    vlong*  w  = NULL;
    vlong*  u1 = NULL;
    vlong*  u2 = NULL;
    vlong*  v  = NULL;
    vlong*  v1 = NULL;
    vlong*  v2 = NULL;
    vlong*  v3 = NULL;
    vlong*  t  = NULL;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DSA,0);

    *isGoodSignature = FALSE;

    /* From FIPS-186-2: To verify the signature, the verifier first checks to see
                        that 0 < r < q and 0 < s < q; if either condition is
                        violated the signature shall be rejected. */

    /* verify r and s are greater than zero */
    if ((pR->negative) || (pS->negative) ||
        (VLONG_isVlongZero(pR)) || (VLONG_isVlongZero(pS)) )
    {
        status = ERR_CRYPTO_DSA_SIGN_VERIFY_RS_TEST;
        goto exit;
    }

    /* r and s must be less than q */
    if ((VLONG_compareSignedVlongs(DSA_Q(p_dsaDescr), pR) <= 0) ||
        (VLONG_compareSignedVlongs(DSA_Q(p_dsaDescr), pS) <= 0) )
    {
        status = ERR_CRYPTO_DSA_SIGN_VERIFY_RS_TEST;
        goto exit;
    }

    if (OK > (status = VLONG_allocVlong(&t, ppVlongQueue)))
        goto exit;

    /* w = s^-1 mod q */
    if (OK > (status = VLONG_modularInverse(MOC_MOD(hwAccelCtx) pS, DSA_Q(p_dsaDescr), &w, ppVlongQueue)))
        goto exit;

    /* t = m * w */
    if (OK > (status = VLONG_vlongSignedMultiply(t, m, w)))
        goto exit;

    /* u1 = (m * w) mod q */
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) t, DSA_Q(p_dsaDescr), &u1, ppVlongQueue)))
        goto exit;

    /* t = r * w */
    if (OK > (status = VLONG_vlongSignedMultiply(t, pR, w)))
        goto exit;

    /* u2 = (r * w) mod q */
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) t, DSA_Q(p_dsaDescr), &u2, ppVlongQueue)))
        goto exit;

    /* v1 = g^u1 mod p */
    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) DSA_G(p_dsaDescr), u1, DSA_P(p_dsaDescr), &v1, ppVlongQueue)))
        goto exit;

    /* v2 = y^u2 mod p */
    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) DSA_Y(p_dsaDescr), u2, DSA_P(p_dsaDescr), &v2, ppVlongQueue)))
        goto exit;

    /* t = (g^u1 mod p) * (y^u2 mod p) */
    if (OK > (status = VLONG_vlongSignedMultiply(t, v1, v2)))
        goto exit;

    /* v3 = (g^u1 * y^u2) mod p */
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) t, DSA_P(p_dsaDescr), &v3, ppVlongQueue)))
        goto exit;

    /* v = ((g^u1 * y^u2) mod p) mod q */
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) v3, DSA_Q(p_dsaDescr), &v, ppVlongQueue)))
        goto exit;

    if (0 == VLONG_compareSignedVlongs(v, pR))
        *isGoodSignature = TRUE;

exit:
    VLONG_freeVlong(&w, ppVlongQueue);
    VLONG_freeVlong(&u1, ppVlongQueue);
    VLONG_freeVlong(&u2, ppVlongQueue);
    VLONG_freeVlong(&v, ppVlongQueue);
    VLONG_freeVlong(&v1, ppVlongQueue);
    VLONG_freeVlong(&v2, ppVlongQueue);
    VLONG_freeVlong(&v3, ppVlongQueue);
    VLONG_freeVlong(&t, ppVlongQueue);

    FIPS_LOG_END_ALG(FIPS_ALGO_DSA,0);
    return status;

} /* DSA_verifySignature */

#endif /* !defined(__DSA_HARDWARE_ACCELERATOR_VERIFY__) && !defined(__DSA_HARDWARE_ACCELERATOR__) */

/*------------------------------------------------------------------*/

extern MSTATUS
DSA_computeSignature(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
                     const DSAKey *p_dsaDescr, vlong* m, intBoolean *pVerifySignature,
                     vlong **ppR, vlong **ppS, vlong **ppVlongQueue)
{
  return (DSA_computeSignatureEx (
    MOC_DSA (hwAccelCtx) RANDOM_rngFun, (void *)pFipsRngCtx, p_dsaDescr, m,
    pVerifySignature, ppR, ppS, ppVlongQueue));
} /* DSA_computeSignature */


/*------------------------------------------------------------------*/

#if !defined(__DSA_HARDWARE_ACCELERATOR_SIGN__) && !defined(__DSA_HARDWARE_ACCELERATOR__)

extern MSTATUS
DSA_computeSignatureEx(MOC_DSA(hwAccelDescr hwAccelCtx)
                       RNGFun rngfun, void* rngarg,
                       const DSAKey *p_dsaDescr, vlong* m,
                       intBoolean *pVerifySignature,
                       vlong **ppR, vlong **ppS, vlong **ppVlongQueue)
{
    /* p, q, g, private, public are all provided by key file */
    /* k is random */
    /* x = private key */
    /* y = public key */
    /* m = digested data */
    /* transmit p,q,g,y(public) */
    FIPS_LOG_DECL_SESSION;
    ubyte4      privateKeySize = VLONG_bitLength(DSA_X(p_dsaDescr)) / 8;
    ubyte*      p_kBuf    = NULL;
    vlong*      ksrc      = NULL;
    vlong*      k         = NULL;
    vlong*      kinv      = NULL;
    vlong*      x         = NULL;
    vlong*      tmp       = NULL;
    vlong*      tmp1      = NULL;
    MSTATUS     status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DSA,0);

    if (OK != (status = DIGI_MALLOC((void **)&p_kBuf, 2*privateKeySize)))
        goto exit;

    /* compute a random k, less than q using FIPS 186-2 */
    if (OK > (status = rngfun(rngarg, 2 * privateKeySize, p_kBuf)))
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(p_kBuf, 2*privateKeySize,
                                                 &ksrc, ppVlongQueue)))
    {
        goto exit;
    }

    if ( OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx)  ksrc, DSA_Q(p_dsaDescr),
                                                       &k, ppVlongQueue)))
    {
        goto exit;
    }

    /* Compute r = (g^k mod p) mod q */
    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) DSA_G(p_dsaDescr), k,
                                    DSA_P(p_dsaDescr), &tmp, ppVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) tmp,
                                                     DSA_Q(p_dsaDescr), ppR, ppVlongQueue)))
    {
        goto exit;
    }

    /* Compute s = inv(k) (m + xr) mod q */
    /* tmp = xr */
    if (OK > (status = VLONG_vlongSignedMultiply(tmp, DSA_X(p_dsaDescr), *ppR)))
        goto exit;

    /* tmp = (m + xr) */
    if (OK > (status = VLONG_addSignedVlongs(tmp, m, ppVlongQueue)))
      goto exit;

    /* tmp1 = (m + xr) mod q */
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) tmp, DSA_Q(p_dsaDescr), &tmp1, ppVlongQueue)))
        goto exit;

    /* kinv = inv(k) mod q */
    if (OK > (status = VLONG_modularInverse(MOC_MOD(hwAccelCtx) k, DSA_Q(p_dsaDescr), &kinv, ppVlongQueue)))
        goto exit;

    /* tmp = ((m + xr) mod q) * (inv(k) mod q) */
    if (OK > (status = VLONG_vlongSignedMultiply(tmp, tmp1, kinv)))
        goto exit;

    /* s = inv(k) (m + xr) mod q */
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) tmp, DSA_Q(p_dsaDescr), ppS, ppVlongQueue)))
        goto exit;

    if (NULL != pVerifySignature)
    {
        DSA_verifySignature(MOC_DSA(hwAccelCtx) p_dsaDescr, m, *ppR, *ppS, pVerifySignature, ppVlongQueue);
    }

exit:
    VLONG_freeVlong(&ksrc, ppVlongQueue);
    VLONG_freeVlong(&k, ppVlongQueue);
    VLONG_freeVlong(&kinv, ppVlongQueue);
    VLONG_freeVlong(&x, ppVlongQueue);
    VLONG_freeVlong(&tmp, ppVlongQueue);
    VLONG_freeVlong(&tmp1, ppVlongQueue);
    DIGI_FREE((void **)&p_kBuf);

    FIPS_LOG_END_ALG(FIPS_ALGO_DSA,0);
    return status;

} /* DSA_computeSignatureEx */

#endif /* !defined(__DSA_HARDWARE_ACCELERATOR_SIGN__) && !defined(__DSA_HARDWARE_ACCELERATOR__) */

/*------------------------------------------------------------------*/

#ifndef __DSA_HARDWARE_ACCELERATOR__

extern MSTATUS
generatePQ(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 L, ubyte4 Nin, DSAHashType hashType, ubyte4 *pRetC, ubyte *pRetSeed, vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    /* this is the FIPS version! */
    ubyte*          S     = NULL;
    ubyte*          U     = NULL;
    ubyte*          U_tmp = NULL;
    ubyte*          U_hash  = NULL;
    vlong*          U_vlong = NULL;
    vlong*          U_vlongtmp = NULL;
    vlong*          bBit    = NULL;
    vlong*          q     = NULL;
    vlong*          W     = NULL;
    vlong*          Vk    = NULL;
    vlong*          X     = NULL;
    vlong*          p     = NULL;
    vlong*          swap; /* placeholder for swap */
    ubyte4          n, k, C, N, carry, b;
    sbyte4          index;
    intBoolean      isPrimeQ, isPrimeP;
    MSTATUS         status = OK;
    ubyte4          shaSize;
    ubyte4          shaBytes;
    ubyte4          iterations = (4 * L) - 1;
    ubyte4          seedSize = Nin/8;
#ifdef __ENABLE_DIGICERT_64_BIT__
    ubyte4          unitSize = 64;
#else
    ubyte4          unitSize = 32;
#endif

    if(NULL == pFipsRngCtx || NULL == p_dsaDescr)
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DSA,L);

    isPrimeP = FALSE;

    if( OK > (status = FFC_getHashLen((FFCHashType) hashType, &shaSize)))
        goto exit;

    shaBytes = shaSize / 8;

    /* KRB:: Possible Doc issue:
     * Size of memory pointed to by seed param must be at least seedSize = Nin/8, or we will write off past the end of the array.
     * We really should add a parameter this the function call to specify the seedSize, then we can verify it is valid, or force it to Nin/8.
     * */

    /* FIPS 186-4 only allows the following (L,N) pairs: (1024, 160), (2048, 224), (2048, 256), or (3072, 256) */
    if(!(
#ifdef __ENABLE_DIGICERT_DSA_ALL_KEYSIZE__
#ifdef __ENABLE_DIGICERT_DSA_768__
    ((L == 768)) && (Nin >= 128 && Nin <= 256) ||
#endif
    ((L == 1024) && (Nin == 160)) ||
#endif
    ((L == 2048) && (Nin == 224)) || ((L == 2048) && (Nin == 256)) || ((L == 3072) && (Nin == 256))))
    {
        status = ERR_DSA_INVALID_KEYLENGTH;
        goto exit;
    }

    /* The shaSize must be greater than N.  The only allowed SHA algorithms are SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 */
    if(shaSize < Nin)
    {
        status = ERR_DSA_HASH_TOO_SMALL;
        goto exit;
    }

    if ( OK > (status = CRYPTO_ALLOC ( hwAccelCtx, seedSize, TRUE, &S ) ) )
        goto exit;

    if ( OK > (status = CRYPTO_ALLOC ( hwAccelCtx, shaBytes , TRUE, &U ) ) )
        goto exit;

    if ( OK > (status = CRYPTO_ALLOC ( hwAccelCtx, seedSize , TRUE, &U_tmp ) ) )
        goto exit;

    if ( OK > (status = CRYPTO_ALLOC ( hwAccelCtx, shaBytes , TRUE, &U_hash ) ) )
        goto exit;

    if (OK > (status = VLONG_allocVlong(&W, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_allocVlong(&X, ppVlongQueue)))
        goto exit;

    n = (L-1) / shaSize;
    b = (L-1) - (n*shaSize);

    do
    {
        isPrimeQ = FALSE;

        do
        {
            /* make random number S */
            if (OK > (status = RANDOM_numberGenerator(pFipsRngCtx, S, seedSize)))
                goto exit;

            /* U = HASH(S) mod 2^(N-1) */
            if (OK > (status = FFC_getHashValue(MOC_FFC(hwAccelCtx) (FFCHashType) hashType, S, seedSize, U)))
                goto exit;

            VLONG_freeVlong(&U_vlong, ppVlongQueue);
            if (OK > (status = VLONG_vlongFromByteString(U, shaBytes, &U_vlong, ppVlongQueue)))
                goto exit;

            VLONG_freeVlong(&U_vlongtmp, ppVlongQueue);
            if (OK > (status = VLONG_allocVlong(&U_vlongtmp, ppVlongQueue)))
                goto exit;

            if (OK > (status = VLONG_setVlongBit(U_vlongtmp, Nin - 1)))
                goto exit;

            if(OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) U_vlong, U_vlongtmp, &swap, ppVlongQueue)))
                goto exit;
            VLONG_freeVlong(&U_vlong, ppVlongQueue);
            U_vlong = swap; swap = 0;


            /* q = 2^(N-1) + U + 1 - (U mod 2) */
            VLONG_freeVlong(&q, ppVlongQueue);
            if (OK > (status = VLONG_allocVlong(&q, ppVlongQueue)))
                goto exit;

            if (OK > (status = VLONG_setVlongBit(q, Nin - 1)))
                goto exit;

            /* if U is odd then U + 1 - (U mod 2) = U  */
            /* if U is even then U + 1 - (U mod 2) = U + 1 */
            if(!(U[shaBytes-1] & 0x01))
            {
                if (OK > (status = VLONG_increment(U_vlong, ppVlongQueue)))
                    goto exit;
            }

            if (OK > (status = VLONG_addSignedVlongs(q, U_vlong, ppVlongQueue)))
                goto exit;

            if (OK > (status = PRIME_doPrimeTestsEx(MOC_MOD(hwAccelCtx) pFipsRngCtx, q, prime_DSA, &isPrimeQ, ppVlongQueue)))
                goto exit;
        }
        while (FALSE == isPrimeQ);

        /* Let C = 0 and N = 1 */
        C = 0;
        N = 1;

        do
        {
            /* Vk = HASH((S + N + k) mod 2^g) */
            VLONG_clearVlong(W);    /* W = 0 */
            for (k = 0; k <= n; k++)
            {
                DIGI_MEMCPY(U_tmp, S, seedSize);

                carry = N + k;

                for (index = seedSize-1; 0 <= index; index--)
                {
                    carry += U_tmp[index];

                    U_tmp[index] = (ubyte)(carry & 0xff);

                    carry >>= 8;

                    if (0 == carry)
                        break;
                }

                /* Vk = HASH[(Seed + offset + k)] */
                if (OK > (status = FFC_getHashValue(MOC_FFC(hwAccelCtx) (FFCHashType) hashType, U_tmp, seedSize, U_hash)))
                    goto exit;

                /* W += Vk; W = V0 + (V1 << shaSize) + ... + (Vk << (k * shaSize) */
                VLONG_freeVlong(&Vk, ppVlongQueue);
                if (OK > (status = VLONG_vlongFromByteString(U_hash, shaBytes, &Vk, ppVlongQueue)))
                    goto exit;

                if (k == n)
                {
                    ubyte4 i;

                    for (i = shaSize/unitSize; i > (b / unitSize); i--)
                        if (OK > (status = VLONG_setVlongUnit(Vk, i, 0)))
                            goto exit;

                    /* clear highest bit */
                    VLONG_freeVlong(&bBit, ppVlongQueue);
                    if (OK > (status = VLONG_allocVlong(&bBit, ppVlongQueue)))
                        goto exit;

                    if (OK > (status = VLONG_setVlongBit(bBit, b)))
                        goto exit;

                    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) Vk, bBit, &swap, ppVlongQueue)))
                        goto exit;

                    VLONG_freeVlong(&Vk, ppVlongQueue);
                    Vk = swap; swap = 0;


                }

                if (OK > (status = VLONG_shlXvlong(Vk, k * shaSize)))
                    goto exit;

                if (OK > (status = VLONG_addSignedVlongs(W, Vk, ppVlongQueue)))
                    goto exit;
            }

            /* X = W + (2^(L-1)) */
            VLONG_clearVlong(X);

            if (OK > (status = VLONG_setVlongBit(X, L - 1)))
                goto exit;

            if (OK > (status = VLONG_addSignedVlongs(X, W, ppVlongQueue)))
                goto exit;

            /* p = X - ((X mod 2q) - 1) */
            if (OK > (status = VLONG_shlVlong(q)))
                goto exit;

            VLONG_freeVlong(&p, ppVlongQueue);
            if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) X, q, &p, ppVlongQueue)))
                goto exit;

            if (OK > (status = VLONG_shrVlong(q)))
                goto exit;

            if (OK > (status = VLONG_decrement(p, ppVlongQueue)))
                goto exit;

            /* negate it */
            p->negative ^= TRUE;

            if (OK > (status = VLONG_addSignedVlongs(p, X, ppVlongQueue)))
                goto exit;

            /* if p < (2^(L-1)), we need to try p again */
            if ((0 != (p->pUnits[0] & 1)) && (!p->negative) && (VLONG_bitLength(p) >= L))
            {
                if (OK > (status = PRIME_doPrimeTestsEx(MOC_MOD(hwAccelCtx) pFipsRngCtx, p, prime_DSA, &isPrimeP, ppVlongQueue)))
                    goto exit;

                /* if p is prime, we got our prime pair */
                if (isPrimeP)
                    break;
            }

            /* C = C + 1 and N = N + n + 1 */
            C++;
            N += n + 1;
        }
        while ((iterations > C) && (FALSE == isPrimeP));
    }
    while (FALSE == isPrimeP);

    /* copy values to DSA structure */
    DSA_P(p_dsaDescr) = p; p = NULL;
    DSA_Q(p_dsaDescr) = q; q = NULL;

    if (NULL != pRetC)
        *pRetC = C;

    if (NULL != pRetSeed)
        DIGI_MEMCPY(pRetSeed, S, seedSize);

exit:

    CRYPTO_FREE ( hwAccelCtx, TRUE, &S );
    CRYPTO_FREE ( hwAccelCtx, TRUE, &U );
    CRYPTO_FREE ( hwAccelCtx, TRUE, &U_tmp );
    CRYPTO_FREE ( hwAccelCtx, TRUE, &U_hash);

    VLONG_freeVlong(&U_vlong, ppVlongQueue);
    VLONG_freeVlong(&U_vlongtmp, ppVlongQueue);
    VLONG_freeVlong(&bBit, ppVlongQueue);
    VLONG_freeVlong(&q, ppVlongQueue);
    VLONG_freeVlong(&W, ppVlongQueue);
    VLONG_freeVlong(&Vk, ppVlongQueue);
    VLONG_freeVlong(&X, ppVlongQueue);
    VLONG_freeVlong(&p, ppVlongQueue);

    FIPS_LOG_END_ALG(FIPS_ALGO_DSA,L);
    return status;
} /* generatePQ */

/*------------------------------------------------------------------*/

/* This is similar to generateG except this will generate a random h value first,
 * then find g = h ^ ((p-1)/q) mod p.
 * <p>When computing DSA params (p, q, and g), find p and q first (q divides
 * p-1). Then find a g that has a large order. The order of g is the number of
 * values it generates. a number is generated by g if there exists an integer n
 * such that g^n mod p = that number. There will be a number m such that g^m mod
 * p is 1, but we want that number to be very large. If we follow the formula
 * above, then the order of g will be q. That means we can select any number < q
 * as our x or k, and we'll have a result within the very large field.
 * <p>There's actually one more check. If h^ ((p-1)/q) is 1, then that is a bad
 * g. That can happen, but it is rare if you use a random h. But if it does
 * happen, just choose another h.
 * <p>Some implementatations choose a fixed h and compute g. The function
 * generateG chooses p-2 as the h (and p-3 if p-2 does not work). That means
 * there is one and only one g for each p, q combination. This function will
 * generate a random h, then compute g.
 * <p>Using this function, you can generate many different g values for each p, q
 * combination. Some applications use the same DSA parameters for many keys. Some
 * of those applications would like to share only p and q, they want to generate
 * a new g every time they generate a new key pair. This means that many keys
 * will have the same p and q, but different g values.
 * <p>For FIPS purposes, the function will return the h value (the random number
 * used to build the g) if you want. If you pass NULL for the ppRetH arg, the
 * function will not return it.
 * <p>The caller passes in a DSAKey with p and q set, but no other elements. The
 * function will set the g inside the DSAKey with the new random g. That g will
 * be freed during the call to DSA_freeKey.
 */
extern MSTATUS DSA_generateRandomG (
  MOC_DSA(hwAccelDescr hwAccelCtx)
  DSAKey *p_dsaDescr,
  randomContext *pRandomContext,
  vlong **ppRetH,
  vlong **ppVlongQueue
  )
{
  FIPS_LOG_DECL_SESSION;
  MSTATUS status;
  ubyte4 bitLenP, bitLenG, byteLen;
  ubyte *pBuffer = NULL;
  vlong *pExpo = NULL;
  vlong *pGVal = NULL;
  vlong *pHVal = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == p_dsaDescr) || (NULL == pRandomContext) )
    goto exit;

  /* For this function, we need a p and q in the DSAKey, but nothing else.
   */
  status = ERR_INVALID_INPUT;
  if ( (NULL == (DSA_P (p_dsaDescr))) || (NULL == (DSA_Q (p_dsaDescr))) ||
       (NULL != (DSA_Y (p_dsaDescr))) || (NULL != (DSA_X (p_dsaDescr))) )
    goto exit;

  bitLenP = VLONG_bitLength (DSA_P (p_dsaDescr));

  FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */
  FIPS_LOG_START_ALG(FIPS_ALGO_DSA,0);

  if (
#ifdef __ENABLE_DIGICERT_DSA_ALL_KEYSIZE__
    (1024 != bitLenP) &&
#ifdef __ENABLE_DIGICERT_DSA_768__
    (768 != bitLenP) &&
#endif
#endif
     (2048 != bitLenP) && (3072 != bitLenP) )
    goto exit;

  byteLen = bitLenP / 8;

  /* Compute (p-1)/q
   * Use the pHVal as a temp variable.
   */
  status = VLONG_makeVlongFromVlong (DSA_P (p_dsaDescr), &pHVal, ppVlongQueue);
  if (OK != status)
    goto exit;

  status = VLONG_decrement (pHVal, ppVlongQueue);
  if (OK != status)
    goto exit;

  status = VLONG_operatorDivideSignedVlongs (
    pHVal, DSA_Q (p_dsaDescr), &pExpo, ppVlongQueue);
  if (OK != status)
    goto exit;

  /* We're going to generate a random number about the same size as p, but less
   * than p.
   * First, a buffer to hold the random bytes.
   */
  status = DIGI_MALLOC ((void **)&pBuffer, byteLen);
  if (OK != status)
    goto exit;

  /* Generate an h, compute g = h ^ ((p-1)/q) mod p.
   * If g is not 1, we're good to go.
   * However, if g is the same byte length as p, some things down the road are
   * easier.
   */
  bitLenG = 1;
  do
  {
    status = RANDOM_numberGenerator (pRandomContext, pBuffer, byteLen);
    if (OK != status)
      goto exit;

    /* Set the msBit to 0 to guarantee the number is < p.
     */
    pBuffer[0] &= 0x7f;

    status = VLONG_freeVlong (&pHVal, ppVlongQueue);
    if (OK != status)
      goto exit;

    if (NULL != pGVal)
    {
      status = VLONG_freeVlong (&pGVal, ppVlongQueue);
      if (OK != status)
        goto exit;
    }

    status = VLONG_vlongFromByteString (
      pBuffer, (sbyte4)byteLen, &pHVal, NULL);
    if (OK != status)
      goto exit;

    /* Now find g = h ^ expo
     */
    status = VLONG_modexp (
      MOC_MOD (hwAccelCtx) pHVal, pExpo, DSA_P (p_dsaDescr),
      &pGVal, ppVlongQueue);
    if (OK != status)
      goto exit;

    bitLenG = VLONG_bitLength (pGVal);

  } while (bitLenG < (bitLenP - 8));

  /* We have a g, put it into the DSAKey.
   */
  DSA_G (p_dsaDescr) = pGVal;
  pGVal = NULL;

  /* If the caller requested we return H, return it.
   */
  if (NULL != ppRetH)
  {
    *ppRetH = pHVal;
    pHVal = NULL;
  }

exit:

  if (NULL != pGVal)
  {
    VLONG_freeVlong (&pGVal, ppVlongQueue);
  }
  if (NULL != pHVal)
  {
    VLONG_freeVlong (&pHVal, ppVlongQueue);
  }
  if (NULL != pExpo)
  {
    VLONG_freeVlong (&pExpo, ppVlongQueue);
  }
  if (NULL != pBuffer)
  {
    DIGI_FREE ((void **)&pBuffer);
  }

  FIPS_LOG_END_ALG(FIPS_ALGO_DSA,0);
  return (status);
}

/*------------------------------------------------------------------*/

extern MSTATUS DSA_generateRandomGAux(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *p_dsaDescr, randomContext *pRandomContext, ubyte **ppH, ubyte4 *pHLen, vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    vlong *pH = NULL;
    ubyte *pNewH = NULL;
    sbyte4 newHLen = 0;

    if (NULL != ppH)
    {
        if (NULL == pHLen) /* rest of params validated in below call */
            goto exit;
        
        status = DSA_generateRandomG(MOC_DSA(hwAccelCtx) p_dsaDescr, pRandomContext, &pH, ppVlongQueue);
        if (OK != status)
            goto exit;
        
        status = VLONG_byteStringFromVlong (pH, NULL, &newHLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_MALLOC((void **) &pNewH, (ubyte4) newHLen);
        if (OK != status)
            goto exit;
        
        status = VLONG_byteStringFromVlong (pH, pNewH, &newHLen);
        if (OK != status)
            goto exit;
        
        *ppH = pNewH; pNewH = NULL;
        *pHLen = (ubyte4) newHLen;
    }
    else
    {
        status = DSA_generateRandomG(MOC_DSA(hwAccelCtx) p_dsaDescr, pRandomContext, NULL, ppVlongQueue);
    }
    
exit:
    
    if (NULL != pNewH)
    {
        (void) DIGI_MEMSET_FREE(&pNewH, (ubyte4) newHLen);
    }
    
    if (NULL != pH)
    {
        (void) VLONG_freeVlong (&pH, ppVlongQueue);
    }
    
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
generateG(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *p_dsaDescr, vlong **ppRetH, vlong **ppVlongQueue)
{
    vlong*  h         = NULL;
    vlong*  p_1       = NULL;
    vlong*  p_1_div_q = NULL;
    MSTATUS status = OK;

    /* p_1 = p-1 */
    if (OK > (status = VLONG_makeVlongFromVlong(DSA_P(p_dsaDescr), &p_1, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_decrement(p_1, ppVlongQueue)))
        goto exit;

    /* h must be less than (p-1) */
    if (OK > (status = VLONG_makeVlongFromVlong(p_1, &h, ppVlongQueue)))
        goto exit;

    /* compute (p-1)/q) */
    if (OK > (status = VLONG_operatorDivideSignedVlongs(p_1, DSA_Q(p_dsaDescr), &p_1_div_q, ppVlongQueue)))
        goto exit;

    /* g = (h^((p-1)/q)) mod p */
    do
    {
        VLONG_freeVlong(&DSA_G(p_dsaDescr), ppVlongQueue);

        if (OK > (status = VLONG_decrement(h, ppVlongQueue)))
            goto exit;

        if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) h, p_1_div_q, DSA_P(p_dsaDescr), &DSA_G(p_dsaDescr), ppVlongQueue)))
            goto exit;
    }
    while (1 >= VLONG_bitLength(DSA_G(p_dsaDescr)));

    if (NULL != ppRetH)
    {
        *ppRetH = h;
        h = NULL;
    }

exit:
    VLONG_freeVlong(&h, ppVlongQueue);
    VLONG_freeVlong(&p_1, ppVlongQueue);
    VLONG_freeVlong(&p_1_div_q, ppVlongQueue);

    return status;

} /* generateG */

/*------------------------------------------------------------------*/

extern MSTATUS
DSA_verifyG(MOC_DSA(hwAccelDescr hwAccelCtx) vlong *pP, vlong *pQ, vlong *pG, intBoolean *isValid, vlong **ppVlongQueue)
{
    return FFC_verifyG(MOC_FFC(hwAccelCtx) pP, pQ, pG, isValid, ppVlongQueue);
}

/*------------------------------------------------------------------*/

extern MSTATUS
DSA_computeKeyPairEx(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, DSAKey *p_dsaDescr,  ubyte4 Lin, ubyte4 Nin, vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    ubyte       privKeySrc[64+8];  /* Largest N (512 bits = 64 bytes) + (64 bits = 8 bytes) */
    MSTATUS     status    = OK;
    vlong*      pKeySrc   = NULL;
    vlong*      q_1       = NULL;
    ubyte4      rngsize = 0;
    MOC_UNUSED(Lin);

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DSA,0);

    if ((NULL == pFipsRngCtx) || (NULL == p_dsaDescr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* For FIPS "KeyPair" testing */
    VLONG_freeVlong(&DSA_X(p_dsaDescr), ppVlongQueue);
    VLONG_freeVlong(&DSA_Y(p_dsaDescr), ppVlongQueue);

    rngsize = (Nin + 64) / 8;

    /* compute a random private key(x), less than q -- using the FIPS 186-4 algorithm */
    if (OK > (status = RANDOM_numberGenerator(pFipsRngCtx, privKeySrc, rngsize)))
        goto exit;

    if (OK > ( status = VLONG_vlongFromByteString( privKeySrc, rngsize,
                                                   &pKeySrc, ppVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_makeVlongFromVlong(DSA_Q(p_dsaDescr), &q_1, ppVlongQueue)))
        goto exit;

    /* q_1 = q-1 */
    if (OK > (status = VLONG_decrement(q_1, ppVlongQueue)))
        goto exit;

    /* x = C mod (q-1) */
    if ( OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx)  pKeySrc, q_1,
                                                       &DSA_X(p_dsaDescr), ppVlongQueue)))
        goto exit;

    /* x = C mod (q-1) + 1 */
    if (OK > (status = VLONG_increment(DSA_X(p_dsaDescr), ppVlongQueue)))
        goto exit;

    /* compute a public key(y): y = ((g^x) mod p) */
    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) DSA_G(p_dsaDescr), DSA_X(p_dsaDescr),
                                    DSA_P(p_dsaDescr), &DSA_Y(p_dsaDescr), ppVlongQueue)))
    {
        goto exit;
    }

exit:
    if (OK > status)
    {
        VLONG_freeVlong(&DSA_Y(p_dsaDescr), ppVlongQueue);
        VLONG_freeVlong(&DSA_X(p_dsaDescr), ppVlongQueue);
    }
    VLONG_freeVlong(&pKeySrc, ppVlongQueue);
    VLONG_freeVlong(&q_1, ppVlongQueue);

    FIPS_LOG_END_ALG(FIPS_ALGO_DSA,0);
    return status;

} /* DSA_computeKeyPairEx */

/*------------------------------------------------------------------*/

extern MSTATUS
DSA_computeKeyPair(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, vlong **ppVlongQueue)
{
	ubyte4      Lin, Nin = 0;

	/* get the length of P */
	Lin = (VLONG_bitLength( DSA_P( p_dsaDescr)) + 7) / 8;
	/* get the length of Q */
	Nin = (VLONG_bitLength( DSA_Q( p_dsaDescr)) + 7) / 8;

	return DSA_computeKeyPairEx(MOC_DSA(hwAccelCtx) pFipsRngCtx, p_dsaDescr, Lin, Nin, ppVlongQueue);

} /* DSA_computeKeyPair */


/*------------------------------------------------------------------*/


extern MSTATUS
DSA_generateKeyEx(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 keySize, ubyte4 qSize, DSAHashType hashType, ubyte4 *pRetC, ubyte *pRetSeed, vlong **ppRetH, vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DSA,keySize);

#ifdef __VERIFY_DSA_KEY_GENERATION__
    intBoolean dsaKeyGood;
    vlong*     pM = NULL;
    vlong*     pR = NULL;
    vlong*     pS = NULL;
    ubyte     *buf = NULL;
    ubyte4     privatekeySize = 0;

    /* At the moment, the max qSize is the max digest size. So the maximum qSize
     * can ever be is 512 bits, the largest digest size we support (SHA-512).
     */
    status = ERR_INVALID_INPUT;
    if ( (0 == qSize) || (qSize > 512) )
      goto exit;

    privatekeySize = (qSize + 7) / 8;

    status = DIGI_MALLOC ((void **)&buf, privatekeySize);
    if (OK != status)
      goto exit;

    /* KRB:: Possible Doc issue:
     * Size of DSAHashType can't be smaller than qSize (aka Nin).
     * It is enforced in generatePQ, but we should prob doc it.
     */

#endif

    if (NULL != ppRetH)
        *ppRetH = NULL;

#ifdef __VERIFY_DSA_KEY_GENERATION__
    do
    {
        dsaKeyGood = TRUE;

        if (NULL != ppRetH)
            VLONG_freeVlong(ppRetH, ppVlongQueue);
#endif

        /* compute the two big primes p & q */
        if (OK > (status = generatePQ(MOC_DSA(hwAccelCtx) pFipsRngCtx, p_dsaDescr, keySize, qSize, hashType, pRetC, pRetSeed, ppVlongQueue)))
            goto exit;

        /* compute g based on p & q */
        if (OK > (status = generateG(MOC_DSA(hwAccelCtx) p_dsaDescr, ppRetH, ppVlongQueue)))
            goto exit;

        /* compute public and private keys */
        if (OK > (status = DSA_computeKeyPairEx(MOC_DSA(hwAccelCtx) pFipsRngCtx, p_dsaDescr, keySize, qSize, ppVlongQueue)))
            goto exit;

#ifdef __VERIFY_DSA_KEY_GENERATION__
        if (OK > (status = RANDOM_numberGenerator(pFipsRngCtx, buf, privatekeySize)))
            goto exit;

        if (OK > (status = VLONG_vlongFromByteString(buf, privatekeySize, &pM, ppVlongQueue)))
            goto exit;

        if (OK > (status = DSA_computeSignature(MOC_DSA(hwAccelCtx) pFipsRngCtx, p_dsaDescr, pM, &dsaKeyGood, &pR, &pS, ppVlongQueue)))
            goto exit;

        VLONG_freeVlong(&pM, ppVlongQueue);
        VLONG_freeVlong(&pR, ppVlongQueue);
        VLONG_freeVlong(&pS, ppVlongQueue);

        if (FALSE == dsaKeyGood)
        {
            DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *)"DSA_generateKey: key verification failed.");
            DSA_clearKey(p_dsaDescr, ppVlongQueue);
        }
    }
    while (FALSE == dsaKeyGood);
#endif

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK > (status = DSA_generateKey_FIPS_consistancy_test(MOC_DSA(sbyte4 hwAccelCtx) pFipsRngCtx, p_dsaDescr)))
        goto exit;
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    goto nocleanup;

exit:
#ifdef __VERIFY_DSA_KEY_GENERATION__
    VLONG_freeVlong(&pM, ppVlongQueue);
    VLONG_freeVlong(&pR, ppVlongQueue);
    VLONG_freeVlong(&pS, ppVlongQueue);
#endif

    if (OK > status)
        DSA_clearKey(p_dsaDescr, ppVlongQueue);

nocleanup:
#ifdef __VERIFY_DSA_KEY_GENERATION__
    if (NULL != buf)
    {
      DIGI_MEMSET ((void *)buf, 0, privatekeySize);
      DIGI_FREE ((void **)&buf);
    }
#endif
    FIPS_LOG_END_ALG(FIPS_ALGO_DSA,keySize);
    return status;

}

/*------------------------------------------------------------------*/

extern MSTATUS
DSA_generateKey(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 keySize, ubyte4 *pRetC, ubyte *pRetSeed, vlong **ppRetH, vlong **ppVlongQueue)
{
    ubyte4 nInput = 0;
    DSAHashType hashType;

    /* FIPS 186-4 only allows the following (L,N) pairs: (1024, 160), (2048, 224), (2048, 256), or (3072, 256) */
    switch(keySize)
    {
#ifdef  __ENABLE_DIGICERT_DSA_ALL_KEYSIZE__
#ifdef __ENABLE_DIGICERT_DSA_768__
        case 768:
#endif
        case 1024:
        {
            nInput = 160;
            hashType = DSA_sha1;
            break;
        }
#endif
        /* KRB:: Note: (L,N,Sha) (2048, 224) is also legal.
         * Application really should call DSA_generateKeyEx() to be able to specify (L,N,SHA).
         */
        case 2048:
        {
            nInput = 256;
            hashType = DSA_sha256;
            break;
        }
        case 3072:
        {
            nInput = 256;
            hashType = DSA_sha256;
            break;
        }
        default:
        {
            return ERR_DSA_INVALID_KEYLENGTH;
        }
    }
    return DSA_generateKeyEx(MOC_DSA(hwAccelCtx) pFipsRngCtx, p_dsaDescr, keySize, nInput, hashType, pRetC, pRetSeed, ppRetH, ppVlongQueue);

} /* DSA_generateKey */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__

extern MSTATUS
DSA_generateKey_FIPS_consistancy_test(MOC_DSA(sbyte4 hwAccelCtx) randomContext* pFipsRngCtx, DSAKey* p_dsaDescr)
{
    MSTATUS status = OK;

    sbyte4 msgLen = 15;
    ubyte msg[] = {
        'C', 'L', 'E', 'A', 'R', '_', 'T', 'E', 'X', 'T', '_', 'L', 'I', 'N', 'E'
    };
    intBoolean verifySignature = FALSE;
    intBoolean isGoodSignature = FALSE;
    vlong* msgVL = NULL;
    vlong* pR = NULL;
    vlong* pS = NULL;


    if (OK > (status = VLONG_vlongFromByteString( msg, msgLen, &msgVL, NULL )))
        goto exit;

    if (OK > (status = DSA_computeSignature( MOC_DSA(sbyte4 hwAccelCtx) pFipsRngCtx, p_dsaDescr, msgVL, &verifySignature, &pR, &pS, NULL )))
        goto exit;

    if ( 1 == dsa_fail )
    {
        *(pR->pUnits) = 0xA6D3;
    }
    dsa_fail = 0;

    if (OK > (status = DSA_verifySignature( MOC_DSA(sbyte4 hwAccelCtx) p_dsaDescr, msgVL, pR, pS, &isGoodSignature, NULL )))
        goto exit;

    if (!isGoodSignature)
    {
        status = ERR_FIPS_DSA_SIGN_VERIFY_FAIL;
        setFIPS_Status(FIPS_ALGO_DSA,status);
        goto exit;
    }

    FIPS_TESTLOG(1001, "DSA_generateKey_FIPS_consistancy_test: GOOD Signature Verify!");

exit:
    VLONG_freeVlong(&msgVL, NULL);
    VLONG_freeVlong(&pR, NULL);
    VLONG_freeVlong(&pS, NULL);

    return status;
}
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/*------------------------------------------------------------------*/

extern MSTATUS
DSA_makeKeyBlob(MOC_DSA(hwAccelDescr hwAccelCtx) const DSAKey *p_dsaDescr, ubyte *pKeyBlob, ubyte4 *pRetKeyBlobLength)
{
    FIPS_LOG_DECL_SESSION;
    ubyte*  pMpintStringP   = NULL;
    ubyte*  pMpintStringQ   = NULL;
    ubyte*  pMpintStringG   = NULL;
    ubyte*  pMpintStringX   = NULL;
    ubyte*  pMpintStringY   = NULL;
    sbyte4  mpintByteSizeP  = 0;
    sbyte4  mpintByteSizeQ  = 0;
    sbyte4  mpintByteSizeG  = 0;
    sbyte4  mpintByteSizeX  = 0;
    sbyte4  mpintByteSizeY  = 0;
    ubyte4  keySize;
    ubyte4  index;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DSA,0);

    if (NULL == p_dsaDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* p */
    if (OK > (status = VLONG_mpintByteStringFromVlong(DSA_P(p_dsaDescr), &pMpintStringP, &mpintByteSizeP)))
        goto exit;

    /* q */
    if (OK > (status = VLONG_mpintByteStringFromVlong(DSA_Q(p_dsaDescr), &pMpintStringQ, &mpintByteSizeQ)))
        goto exit;

    /* g */
    if (OK > (status = VLONG_mpintByteStringFromVlong(DSA_G(p_dsaDescr), &pMpintStringG, &mpintByteSizeG)))
        goto exit;

    /* y */
    if (OK > (status = VLONG_mpintByteStringFromVlong(DSA_Y(p_dsaDescr), &pMpintStringY, &mpintByteSizeY)))
        goto exit;

    /* x */
    if (DSA_X(p_dsaDescr))
        if (OK > (status = VLONG_mpintByteStringFromVlong(DSA_X(p_dsaDescr), &pMpintStringX, &mpintByteSizeX)))
            goto exit;

    keySize = mpintByteSizeP + mpintByteSizeQ + mpintByteSizeG + mpintByteSizeY + mpintByteSizeX;

    if (NULL != pKeyBlob)
    {
        /* p */
        if (OK > (status = DIGI_MEMCPY(pKeyBlob, pMpintStringP, mpintByteSizeP)))
            goto exit;
        index = mpintByteSizeP;

        /* q */
        if (OK > (status = DIGI_MEMCPY(index + pKeyBlob, pMpintStringQ, mpintByteSizeQ)))
            goto exit;
        index += mpintByteSizeQ;

        /* g */
        if (OK > (status = DIGI_MEMCPY(index + pKeyBlob, pMpintStringG, mpintByteSizeG)))
            goto exit;
        index += mpintByteSizeG;

        /* y */
        if (OK > (status = DIGI_MEMCPY(index + pKeyBlob, pMpintStringY, mpintByteSizeY)))
            goto exit;
        index += mpintByteSizeY;

        /* x */
        if (DSA_X(p_dsaDescr))
            if (OK > (status = DIGI_MEMCPY(index + pKeyBlob, pMpintStringX, mpintByteSizeX)))
                goto exit;
    }

    *pRetKeyBlobLength = keySize;

exit:
    if (NULL != pMpintStringP)
        FREE(pMpintStringP);

    if (NULL != pMpintStringQ)
        FREE(pMpintStringQ);

    if (NULL != pMpintStringG)
        FREE(pMpintStringG);

    if (NULL != pMpintStringX)
        FREE(pMpintStringX);

    if (NULL != pMpintStringY)
        FREE(pMpintStringY);

    FIPS_LOG_END_ALG(FIPS_ALGO_DSA,0);
    return status;

} /* DSA_makeKeyBlob */


/*------------------------------------------------------------------*/


extern MSTATUS
DSA_extractKeyBlob(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey **pp_RetNewDsaDescr, const ubyte *pKeyBlob, ubyte4 keyBlobLength)
{
    ubyte4  index;
    MSTATUS status = OK;

    FIPS_LOG_DECL_SESSION;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DSA,0);

    if (0 == keyBlobLength)
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    if (OK > (status = DSA_createKey(pp_RetNewDsaDescr)))
        goto exit;

    /* p */
    index = 0;
    if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &(DSA_P(*pp_RetNewDsaDescr)), &index, NULL)))
        goto exit;

    pKeyBlob += index;
    if (0 >= (sbyte4)(keyBlobLength = (keyBlobLength - index)))
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* q */
    if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &(DSA_Q(*pp_RetNewDsaDescr)), &index, NULL)))
        goto exit;

    pKeyBlob += index;
    if (0 >= (sbyte4)(keyBlobLength = (keyBlobLength - index)))
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* g */
    if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &(DSA_G(*pp_RetNewDsaDescr)), &index, NULL)))
        goto exit;

    pKeyBlob += index;
    if (0 >= (sbyte4)(keyBlobLength = (keyBlobLength - index)))
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* y */
    if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &(DSA_Y(*pp_RetNewDsaDescr)), &index, NULL)))
        goto exit;

    /* !!! no private key, just exit */
    if (0 == (keyBlobLength - index))
        goto exit;

    pKeyBlob += index;
    if (0 >= (sbyte4)(keyBlobLength = (keyBlobLength - index)))
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* x */
    if (OK > (status = VLONG_newFromMpintBytes(pKeyBlob, keyBlobLength, &(DSA_X(*pp_RetNewDsaDescr)), &index, NULL)))
        goto exit;

    if (0 != keyBlobLength - index)
        status = ERR_BAD_KEY_BLOB;

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_DSA,0);
    return status;

} /* DSA_extractKeyBlob */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_FIPS_DSA_PQGVER_TEST__

static MSTATUS
verifyPQ1864(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
         DSAKey *p_dsaDescr, ubyte4 L, ubyte4 Nin, DSAHashType hashType, ubyte4 *pRetC,
         ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsPrimePQ, vlong **ppVlongQueue)
{
    if(!(((L == 1024) && (Nin == 160)) || ((L == 2048) && (Nin == 224)) || ((L == 2048) && (Nin == 256)) || ((L == 3072) && (Nin == 256))))
    {
        return ERR_DSA_INVALID_KEYLENGTH;
    }

    return FFC_computePQ_FIPS_1864(MOC_FFC(hwAccelCtx) pFipsRngCtx,
                                   &DSA_P(p_dsaDescr), &DSA_Q(p_dsaDescr), L, Nin, (FFCHashType) hashType, pRetC,
                                   pSeed, seedSize, pIsPrimePQ, ppVlongQueue);
} /* verifyPQ1864 */

/*------------------------------------------------------------------*/

static MSTATUS
verifyPQ1862(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
         DSAKey *p_dsaDescr, ubyte4 L, ubyte4 Nin, ubyte4 *pRetC,
         ubyte *pSeed, intBoolean *pIsPrimePQ, vlong **ppVlongQueue)
{
    ubyte*          S     = NULL;
    ubyte*          U     = NULL;
    ubyte*          U_tmp = NULL;
    vlong*          q     = NULL;
    vlong*          W     = NULL;
    vlong*          Vk    = NULL;
    vlong*          X     = NULL;
    vlong*          p     = NULL;
    vlong*          bBit  = NULL;
    ubyte4          n, k, C, N, carry, b;
    sbyte4          index;
    intBoolean      isPrimeQ, isPrimeP;
    MSTATUS         status = OK;
#ifdef __ENABLE_DIGICERT_64_BIT__
    ubyte4          unitSize = 64;
#else
    ubyte4          unitSize = 32;
#endif

    isPrimeP = FALSE;
    *pIsPrimePQ = FALSE;
    /* An implementation of Appendix A.1.1.1 of NIST FIPS 186-4 */
    /* FIPS 186-4 only allows for keys of the (L,N) pair (1024, 160)  (Appendix A.1.1.1) */
    if ((L != 1024) | (Nin != 160))
    {
        status = ERR_DSA_INVALID_KEYLENGTH;
        goto exit;
    }

    /* allocate buffers */
    if (NULL == (S = MALLOC(SHA_HASH_RESULT_SIZE)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL == (U = MALLOC(SHA_HASH_RESULT_SIZE)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL == (U_tmp = MALLOC(SHA_HASH_RESULT_SIZE)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = VLONG_allocVlong(&W, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_allocVlong(&X, ppVlongQueue)))
        goto exit;

    n = (L-1) / 160;
    b = (L-1) - (n*160);

    isPrimeQ = FALSE;

    /* use the provided seed as S */
    if (OK > (status = DIGI_MEMCPY(S, pSeed, SHA_HASH_RESULT_SIZE)))
        goto exit;

    /* U = SHA(S) */
    if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) S, SHA_HASH_RESULT_SIZE, U)))
        goto exit;

    /* make temp copy of S */
    DIGI_MEMCPY(U_tmp, S, SHA_HASH_RESULT_SIZE);

    /* compute S+1, we don't need to do anything to compute ((S+1) mod 2^g) */
    for (index = SHA_HASH_RESULT_SIZE - 1; 0 <= index; index--)
        if (++U_tmp[index])
            break;

    /* hash U_tmp on top of itself */
    if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) U_tmp, SHA_HASH_RESULT_SIZE, U_tmp)))
        goto exit;

    for (index = SHA_HASH_RESULT_SIZE - 1; 0 <= index; index--)
        U[index] = (ubyte)(U[index] ^ U_tmp[index]);

    /* set the most and least significant bits */
    U[0] |= 0x80;
    U[SHA_HASH_RESULT_SIZE - 1] |= 0x01;

    /* q = U */
    VLONG_freeVlong(&q, ppVlongQueue);
    if (OK > (status = VLONG_vlongFromByteString(U, SHA_HASH_RESULT_SIZE, &q, ppVlongQueue)))
        goto exit;

    if (OK > (status = PRIME_doPrimeTestsEx(MOC_MOD(hwAccelCtx) pFipsRngCtx, q, prime_DSA, &isPrimeQ, ppVlongQueue)))
        goto exit;

    /* Q should have been prime with the provided seed */
    if (FALSE == isPrimeQ)
        goto exit;

    /* Let C = 0 and N = 2 */
    C = 0;
    N = 2;

    do
    {
        /* Vk = SHA((S + N + k) mod 2^g) */
        VLONG_clearVlong(W);    /* W = 0 */

        for (k = 0; k <= n; k++)
        {
            DIGI_MEMCPY(U_tmp, S, SHA_HASH_RESULT_SIZE);

            carry = N + k;

            for (index = SHA_HASH_RESULT_SIZE-1; 0 <= index; index--)
            {
                carry += U_tmp[index];

                U_tmp[index] = (ubyte)(carry & 0xff);

                carry >>= 8;

                if (0 == carry)
                    break;
            }

            /* Vk = SHA-1[(Seed + offset + k)] */
            if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) U_tmp, SHA_HASH_RESULT_SIZE, U_tmp)))
                goto exit;

            /* W += Vk; W = V0 + (V1 << 160) + ... + (Vk << (k * 160) */
            VLONG_freeVlong(&Vk, ppVlongQueue);

            if (OK > (status = VLONG_vlongFromByteString(U_tmp, SHA_HASH_RESULT_SIZE, &Vk, ppVlongQueue)))
                goto exit;

            if (k == n)
            {
                ubyte4 i;
                vlong* tmp;

                for (i = 5; i > (b / unitSize); i--)
                    if (OK > (status = VLONG_setVlongUnit(Vk, i, 0)))
                        goto exit;

                /* clear highest bit */
                VLONG_freeVlong(&bBit, ppVlongQueue);
                if (OK > (status = VLONG_allocVlong(&bBit, ppVlongQueue)))
                    goto exit;

                if (OK > (status = VLONG_setVlongBit(bBit, b)))
                    goto exit;

                if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) Vk, bBit, &tmp, ppVlongQueue)))
                    goto exit;

                VLONG_freeVlong(&Vk, ppVlongQueue);
                Vk = tmp; tmp = 0;

            }

            if (OK > (status = VLONG_shlXvlong(Vk, k * SIZEOF_DSA_Q)))
                goto exit;

            if (OK > (status = VLONG_addSignedVlongs(W, Vk, ppVlongQueue)))
                goto exit;
        }

        /* X = W + (2^(L-1)) */
        VLONG_clearVlong(X);

        if (OK > (status = VLONG_setVlongBit(X, L - 1)))
            goto exit;

        if (OK > (status = VLONG_addSignedVlongs(X, W, ppVlongQueue)))
            goto exit;

        /* p = X - ((X mod 2q) - 1) */
        if (OK > (status = VLONG_shlVlong(q)))
            goto exit;

        VLONG_freeVlong(&p, ppVlongQueue);
        if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) X, q, &p, ppVlongQueue)))
            goto exit;

        if (OK > (status = VLONG_shrVlong(q)))
            goto exit;

        if (OK > (status = VLONG_decrement(p, ppVlongQueue)))
            goto exit;

        /* negate it */
        p->negative ^= TRUE;

        if (OK > (status = VLONG_addSignedVlongs(p, X, ppVlongQueue)))
            goto exit;

        /* if p < (2^(L-1)), we need to try p again */
        if ((0 != (p->pUnits[0] & 1)) && (!p->negative) && (VLONG_bitLength(p) >= L))
        {
            if (OK > (status = PRIME_doPrimeTestsEx(MOC_MOD(hwAccelCtx) pFipsRngCtx, p, prime_DSA, &isPrimeP, ppVlongQueue)))
                goto exit;

            /* if p is prime, we got our prime pair */
            if (isPrimeP)
                break;
        }

        /* C = C + 1 and N = N + n + 1 */
        C++;
        N += n + 1;
    }
    while ((MAX_DSA_ITERATIONS > C) && (FALSE == isPrimeP));

    /* p should have been prime from q, based on the seed */
    if (FALSE == isPrimeP)
        goto exit;

    /* PQ are both prime */
    *pIsPrimePQ = TRUE;

    /* copy values to DSA structure */
    DSA_P(p_dsaDescr) = p; p = NULL;
    DSA_Q(p_dsaDescr) = q; q = NULL;

    if (NULL != pRetC)
        *pRetC = C;

exit:
    FREE(S);
    FREE(U);
    FREE(U_tmp);
    VLONG_freeVlong(&q, ppVlongQueue);
    VLONG_freeVlong(&W, ppVlongQueue);
    VLONG_freeVlong(&Vk, ppVlongQueue);
    VLONG_freeVlong(&X, ppVlongQueue);
    VLONG_freeVlong(&p, ppVlongQueue);
    VLONG_freeVlong(&bBit, ppVlongQueue);

    return status;

} /* verifyPQ */

/*------------------------------------------------------------------*/

static MSTATUS
verifyPQ(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
         DSAKey *p_dsaDescr, ubyte4 L, ubyte4 Nin, DSAHashType hashType, DSAKeyType keyType, ubyte4 *pRetC,
         ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsPrimePQ, vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_LOG_START_ALG(FIPS_ALGO_DSA,L);

    if(keyType == DSA_186_4)
    {
        status = verifyPQ1864(MOC_DSA(hwAccelCtx) pFipsRngCtx,
                            p_dsaDescr, L, Nin, hashType,  pRetC,
                            pSeed, seedSize, pIsPrimePQ, ppVlongQueue);
    }
    else
    {
        status = verifyPQ1862(MOC_DSA(hwAccelCtx) pFipsRngCtx,
                             p_dsaDescr, L, Nin, pRetC,
                             pSeed, pIsPrimePQ, ppVlongQueue);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_DSA,L);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DSA_verifyPQ(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
            DSAKey *p_dsaDescr, ubyte4 L, ubyte4 Nin, DSAHashType hashType, DSAKeyType keyType, ubyte4 C,
            ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsPrimePQ, vlong **ppVlongQueue)
{
    ubyte4          newC = 0;
    DSAKey*         pDsa = NULL;
    intBoolean      isNewPrimePQ = FALSE;
    MSTATUS         status = OK;

    if (NULL == p_dsaDescr || NULL == DSA_P(p_dsaDescr) || NULL == DSA_Q(p_dsaDescr))
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */

    *pIsPrimePQ = FALSE;

    if (OK > (status = DSA_createKey(&pDsa)))
        goto exit;

    if(OK > (status =  verifyPQ(MOC_DSA(hwAccelCtx) pFipsRngCtx, pDsa, L, Nin, hashType, keyType, &newC, pSeed, seedSize, &isNewPrimePQ, ppVlongQueue)))
        goto exit;

    if ((FALSE == isNewPrimePQ) || (newC != C) || (0 != VLONG_compareSignedVlongs(DSA_P(p_dsaDescr), DSA_P(pDsa)))  || (0 != VLONG_compareSignedVlongs(DSA_Q(p_dsaDescr), DSA_Q(pDsa))))
        goto exit;

    *pIsPrimePQ = TRUE;
exit:
    DSA_freeKey(&pDsa, ppVlongQueue);

    return status;
}

#endif /* __DISABLE_DIGICERT_FIPS_DSA_PQGVER_TEST__ */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_FIPS_DSA_PQGVER_TEST__

extern MSTATUS
DSA_verifyKeysEx(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, ubyte *pSeed, ubyte4 seedSize, const DSAKey *p_dsaDescr, DSAHashType hashType, DSAKeyType keyType, ubyte4 C, vlong *pH, intBoolean *isGoodKeys, vlong **ppVlongQueue)
{
    ubyte4          newC = 0;
    vlong*          p_1       = NULL;
    vlong*          p_1_div_q = NULL;
    DSAKey*         pDsa = NULL;
    intBoolean      isPrimePQ = FALSE;
    intBoolean      isValidG = FALSE;
    MSTATUS         status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */

    if ((NULL == pSeed) || (NULL == p_dsaDescr) || (NULL == pH) || (NULL == isGoodKeys) || (NULL == DSA_P(p_dsaDescr)) || (NULL == DSA_Q(p_dsaDescr)))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *isGoodKeys = FALSE;

    /* we first verify p&q are good */
    if (OK > (status = DSA_createKey(&pDsa)))
        goto exit;

    if (OK > (status = verifyPQ(MOC_DSA(hwAccelCtx) pFipsRngCtx, pDsa, VLONG_bitLength(DSA_P(p_dsaDescr)), VLONG_bitLength(DSA_Q(p_dsaDescr)), hashType, keyType, &newC, pSeed, seedSize, &isPrimePQ, ppVlongQueue)))
        goto exit;

    if ((FALSE == isPrimePQ) || (newC != C) || (0 != VLONG_compareSignedVlongs(DSA_P(p_dsaDescr), DSA_P(pDsa)))  || (0 != VLONG_compareSignedVlongs(DSA_Q(p_dsaDescr), DSA_Q(pDsa))))
        goto exit;

    if(OK > (status =  FFC_verifyG(MOC_FFC(hwAccelCtx) DSA_P(p_dsaDescr), DSA_Q(p_dsaDescr), DSA_G(p_dsaDescr), &isValidG, ppVlongQueue)))
        goto exit;

    if(isValidG)
        *isGoodKeys = TRUE;

exit:
    VLONG_freeVlong(&p_1_div_q, ppVlongQueue);
    VLONG_freeVlong(&p_1, ppVlongQueue);
    DSA_freeKey(&pDsa, ppVlongQueue);

    return status;

}

/*------------------------------------------------------------------*/

extern MSTATUS
DSA_verifyKeys(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, ubyte *pSeed, const DSAKey *p_dsaDescr, ubyte4 C, vlong *pH, intBoolean *isGoodKeys, vlong **ppVlongQueue)
{
    /* Default to (SHA-1) */
    return DSA_verifyKeysEx(MOC_DSA(hwAccelCtx) pFipsRngCtx, pSeed, 20, p_dsaDescr, DSA_sha1, DSA_186_4, C, pH, isGoodKeys, ppVlongQueue);
} /* DSA_verifyKeys */
#endif /* __DISABLE_DIGICERT_FIPS_DSA_PQGVER_TEST__ */


/*------------------------------------------------------------------*/

extern MSTATUS
DSA_setKeyParameters( MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey,
                     const ubyte* p, ubyte4 pLen,
                     const ubyte* q, ubyte4 qLen,
                     const ubyte* g, ubyte4 gLen,
                     vlong **ppVlongQueue)
{
    MSTATUS status;

    DSA_clearKey( pKey, ppVlongQueue);

    status = ERR_NULL_POINTER;
    if ( (NULL == p) || (NULL == q) )
        goto exit;

    if (OK > (status = VLONG_vlongFromByteString(p, pLen, &DSA_P(pKey),
                                                 ppVlongQueue)))
    {
        goto exit;
    }
    DEBUG_RELABEL_MEMORY(DSA_P(pKey));

    if (OK > (status = VLONG_vlongFromByteString(q, qLen, &DSA_Q(pKey),
                                                 ppVlongQueue)))
    {
        goto exit;
    }
    DEBUG_RELABEL_MEMORY(DSA_Q(pKey));

    /* We accept a NULL g.
     */
    if ( (NULL == g) || (0 == gLen) )
      goto exit;

    if (OK > (status = VLONG_vlongFromByteString(g, gLen, &DSA_G(pKey),
                                                 ppVlongQueue)))
    {
        goto exit;
    }
    DEBUG_RELABEL_MEMORY(DSA_G(pKey));

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DSA_setAllKeyParameters(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey,
                        const ubyte* p, ubyte4 pLen,
                        const ubyte* q, ubyte4 qLen,
                        const ubyte* g, ubyte4 gLen,
                        const ubyte* x, ubyte4 xLen,
                        vlong **ppVlongQueue)
{
    /* use this to set the parameters of a private key */
    MSTATUS status = OK;
    FIPS_LOG_DECL_SESSION;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DSA,0);

    if (!pKey || !p || !q || !g  || !x)   /* y is not used */
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( OK > (status = DSA_setKeyParameters(MOC_DSA(hwAccelCtx) pKey, p, pLen, q, qLen,
                                                g, gLen, ppVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_vlongFromByteString(x, xLen,
                                                 &DSA_X(pKey), ppVlongQueue)))
    {
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(DSA_X(pKey));

    /* recompute Y */
    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) DSA_G(pKey), DSA_X(pKey),
                                    DSA_P(pKey), &DSA_Y(pKey), ppVlongQueue)))
    {
        goto exit;
    }

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_DSA,0);
    return status;
}


/*------------------------------------------------------------------*/


extern MSTATUS
DSA_setPublicKeyParameters(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey, const ubyte* p, ubyte4 pLen,
                            const ubyte* q, ubyte4 qLen,
                            const ubyte* g, ubyte4 gLen,
                            const ubyte* y, ubyte4 yLen,
                            vlong **ppVlongQueue)
{
    /* use this to set the parameters of a public key */
    MSTATUS status = OK;
    FIPS_LOG_DECL_SESSION;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DSA,0);

    if (!pKey || !p || !q || !g  || !y)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DSA_clearKey( pKey, ppVlongQueue);

    if (OK > (status = VLONG_vlongFromByteString(p, pLen, &DSA_P(pKey),
                                                 ppVlongQueue)))
    {
        goto exit;
    }
    DEBUG_RELABEL_MEMORY(DSA_P(pKey));

    if (OK > (status = VLONG_vlongFromByteString(q, qLen, &DSA_Q(pKey),
                                                 ppVlongQueue)))
    {
        goto exit;
    }
    DEBUG_RELABEL_MEMORY(DSA_Q(pKey));

    if (OK > (status = VLONG_vlongFromByteString(g, gLen, &DSA_G(pKey),
                                                 ppVlongQueue)))
    {
        goto exit;
    }
    DEBUG_RELABEL_MEMORY(DSA_G(pKey));

    if (OK > (status = VLONG_vlongFromByteString(y, yLen, &DSA_Y(pKey),
                                                 ppVlongQueue)))
    {
        goto exit;
    }
    DEBUG_RELABEL_MEMORY(DSA_Y(pKey));

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_DSA,0);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS DSA_generateKeyAux(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 keySize, vlong **ppVlongQueue)
{
    return DSA_generateKey(MOC_DSA(hwAccelCtx) pFipsRngCtx, p_dsaDescr, keySize, NULL, NULL, NULL, ppVlongQueue);
}

/*------------------------------------------------------------------*/

extern MSTATUS DSA_generateKeyAux2(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 keySize,
                                       ubyte4 qSize, DSAHashType hashType, vlong **ppVlongQueue)
{
    return DSA_generateKeyEx(MOC_DSA(hwAccelCtx) pFipsRngCtx, p_dsaDescr, keySize, qSize, hashType, NULL, NULL, NULL, ppVlongQueue);
}

/*------------------------------------------------------------------*/

extern MSTATUS DSA_computeSignatureAux(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext *pRngCtx, DSAKey *pKey, ubyte *pM, ubyte4 mLen, intBoolean *pVerify,
                                       ubyte **ppR, ubyte4 *pRLen, ubyte **ppS, ubyte4 *pSLen, vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    vlong *pRvlong = NULL;
    vlong *pSvlong = NULL;
    vlong *pMvlong = NULL;

    ubyte *pR = NULL;
    ubyte *pS = NULL;
    sbyte4 rsLen = 0;
    
    if (NULL == pKey || NULL == DSA_Q(pKey) || NULL == pRngCtx || NULL == ppR || NULL == pRLen || NULL == ppS || NULL == pSLen || NULL == pM)
        goto exit;
    
    status = VLONG_vlongFromByteString(pM, mLen, &pMvlong, ppVlongQueue);
    if (OK != status)
        goto exit;
    
    status = DSA_computeSignature(MOC_DSA(hwAccelCtx) pRngCtx, pKey, pMvlong, pVerify, &pRvlong, &pSvlong, ppVlongQueue);
    if (OK != status)
        goto exit;
    
    rsLen = (ubyte4) (VLONG_bitLength(DSA_Q(pKey)) + 7) / 8;
    
    status = DIGI_MALLOC((void **) &pR, (ubyte4) rsLen);
    if (OK != status)
        goto exit;
    
    status = DIGI_MALLOC((void **) &pS, (ubyte4) rsLen);
    if (OK != status)
        goto exit;
    
    status = VLONG_byteStringFromVlong (pRvlong, pR, &rsLen);  /* This will zero pad to the correct length if needbe */
    if (OK != status)
        goto exit;

    status = VLONG_byteStringFromVlong (pSvlong, pS, &rsLen);
    if (OK != status)
        goto exit;
    
    /* all is good, set the output params */
    
    *ppR = pR; pR = NULL;
    *ppS = pS; pS = NULL;
    *pRLen = (ubyte4) rsLen;
    *pSLen = (ubyte4) rsLen;
    
exit:
    
    /* no need to chceck return values */
    (void) VLONG_freeVlong(&pRvlong, ppVlongQueue);
    (void) VLONG_freeVlong(&pSvlong, ppVlongQueue);
    (void) VLONG_freeVlong(&pMvlong, ppVlongQueue);
    
    if (NULL != pR)
    {
        (void) DIGI_MEMSET_FREE(&pR, rsLen);
    }
    
    if (NULL != pS)
    {
        (void) DIGI_MEMSET_FREE(&pS, rsLen);
    }
    
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS DSA_verifySignatureAux(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey, ubyte *pM, ubyte4 mLen, ubyte *pR, ubyte4 rLen,
                                      ubyte *pS, ubyte4 sLen, intBoolean *pIsGoodSignature, vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    vlong *pRvlong = NULL;
    vlong *pSvlong = NULL;
    vlong *pMvlong = NULL;
    
    if (NULL == pKey || NULL == pM || NULL == pR || NULL == pS || NULL == pIsGoodSignature)
        goto exit;
    
    status = VLONG_vlongFromByteString(pM, mLen, &pMvlong, ppVlongQueue);
    if (OK != status)
        goto exit;
    
    status = VLONG_vlongFromByteString(pR, rLen, &pRvlong, ppVlongQueue);
    if (OK != status)
        goto exit;
    
    status = VLONG_vlongFromByteString(pS, sLen, &pSvlong, ppVlongQueue);
    if (OK != status)
        goto exit;
    
    status = DSA_verifySignature(MOC_DSA(hwAccelCtx) pKey, pMvlong, pRvlong, pSvlong, pIsGoodSignature, ppVlongQueue);

exit:
    
    /* no need to chceck return values */
    (void) VLONG_freeVlong(&pRvlong, ppVlongQueue);
    (void) VLONG_freeVlong(&pSvlong, ppVlongQueue);
    (void) VLONG_freeVlong(&pMvlong, ppVlongQueue);
    
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS DSA_setKeyParametersAux(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey, MDsaKeyTemplatePtr pTemplate)
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pKey || NULL == pTemplate)
        goto exit;
    
    if (NULL != pTemplate->pX && pTemplate->xLen)
    {
        status = DSA_setAllKeyParameters(MOC_DSA(hwAccelCtx)pKey, pTemplate->pP, pTemplate->pLen, pTemplate->pQ, pTemplate->qLen,
                                         pTemplate->pG, pTemplate->gLen, pTemplate->pX, pTemplate->xLen, NULL);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DSA_setKeyParameters(MOC_DSA(hwAccelCtx) pKey, pTemplate->pP, pTemplate->pLen, pTemplate->pQ, pTemplate->qLen,
                                      pTemplate->pG, pTemplate->gLen, NULL);
        if (OK != status)
            goto exit;
    }
    
    if (NULL != pTemplate->pY && pTemplate->yLen)
    {
        status = VLONG_vlongFromByteString(pTemplate->pY, pTemplate->yLen, &DSA_Y(pKey), NULL);
        if (OK != status)
            goto exit;
    }
    
exit:
    
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS DSA_getKeyParametersAlloc(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey, MDsaKeyTemplatePtr pTemplate, ubyte keyType)
{
    MSTATUS status = ERR_NULL_POINTER;
    
    ubyte *pP = NULL;
    ubyte *pQ = NULL;
    ubyte *pG = NULL;
    ubyte *pX = NULL;
    ubyte *pY = NULL;
    
    sbyte4 pLen = 0;
    sbyte4 qLen = 0;
    sbyte4 gLen = 0;
    sbyte4 xLen = 0;
    sbyte4 yLen = 0;
    
    if (NULL == pKey || NULL == pTemplate)
        goto exit;
   
    /* require a private key if that is the type requested */
    status = ERR_DSA_INVALID_PARAM;
    if (MOC_GET_PRIVATE_KEY_DATA == keyType && NULL == DSA_X(pKey))
        goto exit;
    
    /* Otherwise we just return what the key has, no other validation */
    if (NULL != DSA_P(pKey))
    {
        status = VLONG_byteStringFromVlong (DSA_P(pKey), NULL, &pLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_MALLOC((void **) &pP, (ubyte4) pLen);
        if (OK != status)
            goto exit;
        
        status = VLONG_byteStringFromVlong (DSA_P(pKey), pP, &pLen);
        if (OK != status)
            goto exit;
    }
    
    if (NULL != DSA_Q(pKey))
    {
        status = VLONG_byteStringFromVlong (DSA_Q(pKey), NULL, &qLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_MALLOC((void **) &pQ, (ubyte4) qLen);
        if (OK != status)
            goto exit;
        
        status = VLONG_byteStringFromVlong (DSA_Q(pKey), pQ, &qLen);
        if (OK != status)
            goto exit;
    }
    
    if (NULL != DSA_G(pKey))
    {
        status = VLONG_byteStringFromVlong (DSA_G(pKey), NULL, &gLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_MALLOC((void **) &pG, (ubyte4) gLen);
        if (OK != status)
            goto exit;
        
        status = VLONG_byteStringFromVlong (DSA_G(pKey), pG, &gLen);
        if (OK != status)
            goto exit;
    }
    
    if (NULL != DSA_Y(pKey))
    {
        status = VLONG_byteStringFromVlong (DSA_Y(pKey), NULL, &yLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_MALLOC((void **) &pY, (ubyte4) yLen);
        if (OK != status)
            goto exit;
        
        status = VLONG_byteStringFromVlong (DSA_Y(pKey), pY, &yLen);
        if (OK != status)
            goto exit;
    }
    
    if (MOC_GET_PRIVATE_KEY_DATA == keyType) /* already checked non-null DSA_X(pKey) */
    {
        status = VLONG_byteStringFromVlong (DSA_X(pKey), NULL, &xLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_MALLOC((void **) &pX, (ubyte4) xLen);
        if (OK != status)
            goto exit;
        
        status = VLONG_byteStringFromVlong (DSA_X(pKey), pX, &xLen);
        if (OK != status)
            goto exit;
    }
    
    /* all is good, now free any existing values */
    status = DSA_freeKeyTemplate(pKey, pTemplate); /* always returns OK */
    
    /* and set the new values */
    pTemplate->pP = pP; pP = NULL;
    pTemplate->pLen  = (ubyte4) pLen;
    
    pTemplate->pQ = pQ; pQ = NULL;
    pTemplate->qLen  = (ubyte4) qLen;
    
    pTemplate->pG = pG; pG = NULL;
    pTemplate->gLen  = (ubyte4) gLen;
    
    pTemplate->pY = pY; pY = NULL;
    pTemplate->yLen  = (ubyte4) yLen;
    
    pTemplate->pX = pX; pX = NULL;
    pTemplate->xLen  = (ubyte4) xLen;
    
exit:
    
    if (NULL != pP)
        (void) DIGI_MEMSET_FREE(&pP, (ubyte4) pLen); /* ok to ignore return */
    
    if (NULL != pQ)
        (void) DIGI_MEMSET_FREE(&pQ, (ubyte4) qLen); /* ok to ignore return */
    
    if (NULL != pG)
        (void) DIGI_MEMSET_FREE(&pG, (ubyte4) gLen); /* ok to ignore return */
    
    if (NULL != pY)
        (void) DIGI_MEMSET_FREE(&pY, (ubyte4) yLen); /* ok to ignore return */
    
    if (NULL != pX)
        (void) DIGI_MEMSET_FREE(&pX, (ubyte4) xLen); /* ok to ignore return */
    
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS DSA_getCipherTextLength(MOC_DSA(hwAccelDescr hwAccelCtx) const DSAKey *pKey, sbyte4* cipherTextLen)
{
    if ((NULL == pKey) || (NULL == cipherTextLen) || (NULL == DSA_P(pKey)))
    {
        return ERR_NULL_POINTER;
    }
    
    return VLONG_byteStringFromVlong( DSA_P(pKey), NULL, cipherTextLen);
}

/*------------------------------------------------------------------*/

extern MSTATUS DSA_getSignatureLength (MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey, ubyte4 *pSigLen)
{
    if ((NULL == pKey) || (NULL == pSigLen) || (NULL == DSA_Q(pKey)))
    {
        return ERR_NULL_POINTER;
    }
    
    return VLONG_byteStringFromVlong( DSA_Q(pKey), NULL, (sbyte4 *) pSigLen);
}
#endif /* __DSA_HARDWARE_ACCELERATOR__ */

/*------------------------------------------------------------------*/

extern MSTATUS DSA_freeKeyTemplate(DSAKey *pKey, MDsaKeyTemplatePtr pTemplate)
{
    MOC_UNUSED(pKey); /* not needed, only here for crypto interface reasons */
    
    if (NULL == pTemplate) /* ok no-op */
        return OK;
    
    if (NULL != pTemplate->pP)
    {
        (void) DIGI_MEMSET_FREE(&pTemplate->pP, pTemplate->pLen); /* ok to ignore return codes */
    }
    
    if (NULL != pTemplate->pQ)
    {
        (void) DIGI_MEMSET_FREE(&pTemplate->pQ, pTemplate->qLen); /* ok to ignore return codes */
    }
    
    if (NULL != pTemplate->pG)
    {
        (void) DIGI_MEMSET_FREE(&pTemplate->pG, pTemplate->gLen); /* ok to ignore return codes */
    }
    
    if (NULL != pTemplate->pY)
    {
        (void) DIGI_MEMSET_FREE(&pTemplate->pY, pTemplate->yLen); /* ok to ignore return codes */
    }
    
    if (NULL != pTemplate->pX)
    {
        (void) DIGI_MEMSET_FREE(&pTemplate->pX, pTemplate->xLen); /* ok to ignore return codes */
    }
    
    return OK;
}

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/dsa_priv.h"

static void DSA_triggerFail()
{
    dsa_fail = 1;
}

static FIPS_entry_fct dsa_table[] = {
    { DSA_TRIGGER_FAIL_F_ID,     (s_fct*)DSA_triggerFail},
    { -1, NULL } /* End of array */
};

MOC_EXTERN const FIPS_entry_fct* DSA_getPrivileged()
{
    if (OK == FIPS_isTestMode())
        return dsa_table;

    return NULL;
}
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

#endif /* (defined(__ENABLE_DIGICERT_DSA__)) */
