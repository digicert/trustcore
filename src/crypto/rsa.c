/*
 * file rsa.c
 *
 * brief     C source code file for the Nanocrypto RSA API.
 * details   RSA public key encryption
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

/*------------------------------------------------------------------*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#ifndef __DISABLE_DIGICERT_RSA__
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#ifndef __RSA_HARDWARE_ACCELERATOR__

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__
#include "../common/vlong_const.h"
#endif
#include "../common/random.h"
#include "../common/prime.h"
#include "../common/debug_console.h"
#include "../common/memory_debug.h"
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
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/sha3.h"
#include "../crypto/keyblob.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/crypto.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/crypto_hash_fips.h"
#endif
#ifdef __ENABLE_DIGICERT_PKCS11_CRYPTO__
#include "../crypto/pkcs11.h"
#include "../crypto/hw_offload/pkcs11_rsa.h"
#endif

#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
#include "../crypto/secmod.h"
#include "../smp/smp_tpm12/tpm12_lib/hsmrsainfo.h"
#endif

/*------------------------------------------------------------------*/

#define PREDEFINED_E        (65537)

#ifndef MOCANA_MAX_MODULUS_SIZE
#define MOCANA_MAX_MODULUS_SIZE     (512)
#endif

#ifndef MOCANA_MAX_BLIND_FACTOR_REUSE
#define MOCANA_MAX_BLIND_FACTOR_REUSE (32)
#endif

#define RSA_BLOB_VERSION    (2)


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__
/* use fixed point arithmic: multiply by sqrRootOf2factor and then divide by sqrRootOf2divisor */
/* sqrRootOf2divisor = 100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000.0 */
/* 10 * sqrt(2)     ~= 141421356237309504880168872420969807856967187537694807317667973799073247846210703885038753432764157273501384623091229702492483605585073721264412149709993.0 */
static const ubyte sqrRootOf2factor[]  = { 0x00, 0x00, 0x00, 0x40,
                                           0x02, 0xb3, 0x40, 0xd1, 0x0f, 0x2d, 0xdc, 0x52, 0xfb, 0x4b, 0x66, 0x08, 0x5a, 0x90, 0xb1, 0x88,
                                           0x67, 0xb7, 0x15, 0x53, 0xf8, 0x5e, 0x78, 0x62, 0x59, 0x66, 0xd8, 0x84, 0x86, 0x43, 0xb6, 0x75,
                                           0xc8, 0x54, 0x1c, 0x0d, 0x7b, 0x14, 0x6d, 0x50, 0x1b, 0xb0, 0x1f, 0xfc, 0x2d, 0x00, 0xb2, 0x83,
                                           0x26, 0x56, 0xb9, 0x60, 0x85, 0x92, 0x96, 0x47, 0x60, 0xbb, 0xad, 0x7b, 0xff, 0x74, 0x7c, 0xa9 };
/* sqrRootOf2divisor = 100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000.0 */
static const ubyte sqrRootOf2divisor[] = { 0x00, 0x00, 0x00, 0x40,
                                           0x01, 0xe8, 0xca, 0x31, 0x85, 0xde, 0xb7, 0x19, 0xa2, 0xfd, 0x64, 0xb0, 0xcc, 0xbf, 0x84, 0xba,
                                           0xd2, 0xd8, 0xaf, 0x57, 0xd5, 0xd9, 0x29, 0xcb, 0x5f, 0x1e, 0x32, 0xbf, 0xfb, 0xdc, 0x5d, 0x1c,
                                           0x3e, 0x21, 0xf7, 0x95, 0x4f, 0xe4, 0xa7, 0x41, 0xd3, 0xad, 0x0e, 0xeb, 0xa1, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
#endif


/*------------------------------------------------------------------*/
/* prototype */

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
static int rsa_fail = 0;
FIPS_TESTLOG_IMPORT;
#endif

#if (defined(__RSAINT_HARDWARE__) && defined(__ENABLE_DIGICERT_PKCS11_CRYPTO__))
extern MSTATUS
RSAINT_decrypt(CK_SESSION_HANDLE hSession,
               CK_MECHANISM_PTR pMechanism,
               CK_OBJECT_HANDLE hKey,
               CK_BYTE_PTR pEngcryptedData,
               CK_ULONG ulEncryptedDataLen,
               CK_BYTE_PTR pData,
               CK_ULONG_PTR pulDataLen);

extern MSTATUS
RSA_signMessage(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
                const ubyte* plainText, ubyte4 plainTextLen,
                ubyte* cipherText, vlong **ppVlongQueue);

#elif (defined(__RSAINT_HARDWARE__))
extern MSTATUS
RSAINT_decrypt(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKeyInt,
               const vlong *pCipher, RNGFun rngFun, void* rngFunArg,
               vlong **ppRetDecrypt, vlong **ppVlongQueue);

#endif   /* __RSAINT_HARDWARE__ */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
/* prototype */
extern MSTATUS
RSA_generateKey_FIPS_consistancy_test(MOC_RSA(sbyte4 hwAccelCtx) RSAKey *p_rsaKey);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/*------------------------------------------------------------------*/

static MSTATUS
RSAINT_encrypt(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKeyInt,
               const vlong *pPlain, vlong **ppRetEncrypt, vlong **ppVlongQueue)
{
    if (!RSA_N(pRSAKeyInt) || !RSA_E(pRSAKeyInt))
        return ERR_RSA_KEY_NOT_READY;
    
    return VLONG_modexp(MOC_MOD(hwAccelCtx) pPlain, RSA_E(pRSAKeyInt),
                        RSA_N(pRSAKeyInt), ppRetEncrypt, ppVlongQueue);
}


/*------------------------------------------------------------------*/

#if !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)
MOC_EXTERN MSTATUS
RSAINT_decryptAux(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKey,
                  const vlong *c, vlong **ppRetDecrypt, vlong **ppVlongQueue)
{
#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__
    vlong_unit *pM1 = NULL;
    vlong_unit *pTemp;
    vlong_unit mask;
    ubyte4 primeLen;
    ubyte4 modLen;
    ubyte4 i;
#endif
    vlong*  m1  = NULL;
    vlong*  m2  = NULL;
    vlong*  tmp = NULL;
    vlong*  h   = NULL;
    sbyte4 cmpResult;
    MSTATUS status;

    if (!RSA_DP(pRSAKey) || !RSA_DQ(pRSAKey) || !RSA_QINV(pRSAKey) ||
        !RSA_MODEXP_P(pRSAKey) || !RSA_MODEXP_Q(pRSAKey) )
    {
        /* must call the correct routines to set up the key */
        return ERR_RSA_KEY_NOT_READY;
    }

    /* Verify that 0 < c < n
     * where c is the ciphertext and n is the modulus.
     */
    status = ERR_RSA_OUT_OF_RANGE;
    cmpResult = VLONG_compareUnsigned (c, (vlong_unit)0);
    if (0 == cmpResult)
      goto exit;

    /* Compare left to right. If left < right, cmpResult < 0.
     */
    cmpResult = VLONG_compareSignedVlongs (c, RSA_N (pRSAKey));
    if (cmpResult >= 0)
      goto exit;

#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__
    primeLen = RSA_P(pRSAKey)->numUnitsUsed;

    /* We can only do const time algo if length of primes match */
    if (primeLen == RSA_Q(pRSAKey)->numUnitsUsed)
    {
        modLen = primeLen << 1;

        /* m2 will contain the final output so must be a real vlong and not just vlong_units */
        if (OK > ( status = VLONG_allocVlongZero (&m2, modLen, ppVlongQueue)))
        {
            goto exit;
        }

        /* allocate space for m1 and temp together, each gets extra word, temp gets double space */
        if (OK > ( status = DIGI_MALLOC((void **) &pM1, (3 * primeLen + 2) * sizeof(vlong_unit))))
        {
            goto exit;
        }

        pTemp = pM1 + primeLen + 1;

        if (OK > ( status = VLONG_constTimeMontExp (MOC_MOD(hwAccelCtx) RSA_MODEXP_P(pRSAKey), (vlong *) c,
                                                    RSA_DP(pRSAKey), pM1)))
        {
            goto exit;
        }

        if (OK > ( status = VLONG_constTimeMontExp (MOC_MOD(hwAccelCtx) RSA_MODEXP_Q(pRSAKey), (vlong *) c,
                                                    RSA_DQ(pRSAKey), m2->pUnits)))
        {
            goto exit;
        }

        /* h = qInv * (m1 - m2) mod p */

        /* if m1 < m2 we add P (which is > Q) to m1 ensuring new m1 > m2  */
        mask = VLONG_constTimeCmp( pM1, m2->pUnits, primeLen);
        
        mask = ZERO_UNIT - mask;

        for (i = 0; i < primeLen; i++)
        {
            pTemp[i] = (RSA_P(pRSAKey)->pUnits[i]) & mask;
        }
        /* pad both with extra byte in case of overflow */
        pTemp[i] = ZERO_UNIT;
        pM1[i] = ZERO_UNIT;

        /* we now know there will be no overflow, m2 also has extra zero pad unit */
        (void) VLONG_constTimeAdd(pM1, pM1, pTemp, primeLen + 1);
        (void) VLONG_constTimeSubtract(pM1, pM1, m2->pUnits, primeLen + 1);

        VLONG_constTimeMultiply(pTemp, primeLen + 1 + RSA_QINV(pRSAKey)->numUnitsUsed, 
                                pM1, primeLen + 1, RSA_QINV(pRSAKey)->pUnits, RSA_QINV(pRSAKey)->numUnitsUsed);

        /* Re-use pM1 var as H */
        if (OK > (status = VLONG_constTimeDiv(NULL, pM1, pTemp, primeLen + 1 + RSA_QINV(pRSAKey)->numUnitsUsed, 
                                              RSA_P(pRSAKey)->pUnits, primeLen)))
        {
            goto exit;
        }

        VLONG_constTimeMultiply(pTemp, modLen, pM1, primeLen, RSA_Q(pRSAKey)->pUnits, primeLen);

        /* result m2 is known to be < modulus so no carry possible */
        (void) VLONG_constTimeAdd(m2->pUnits, m2->pUnits, pTemp, modLen);

        m2->numUnitsUsed = modLen;
    }
    else
#endif
    {
        if (OK > ( status = VLONG_modExp(MOC_MOD(hwAccelCtx) RSA_MODEXP_P(pRSAKey), c,
                                        RSA_DP(pRSAKey), &m1, ppVlongQueue)))
        {
            goto exit;
        }

        if (OK > ( status = VLONG_modExp(MOC_MOD(hwAccelCtx) RSA_MODEXP_Q(pRSAKey), c,
                                        RSA_DQ(pRSAKey), &m2, ppVlongQueue)))
        {
            goto exit;
        }

        /* h = qInv * (m1 - m2) mod p */
        if ( VLONG_compareSignedVlongs( m1, m2) <  0 )
        {
            if ( OK > ( status = VLONG_addSignedVlongs(m1, RSA_P(pRSAKey),
                                                    ppVlongQueue)))
            {
                goto exit;
            }
        }

        /* m1 -= m2 */
        if (OK > ( status = VLONG_subtractSignedVlongs(m1, m2, ppVlongQueue)))
            goto exit;

        /* temporary = qInv * m1 */
        if (OK > ( status = VLONG_allocVlong(&tmp, ppVlongQueue)))
            goto exit;

        DEBUG_RELABEL_MEMORY(tmp);

        if (OK > ( status = VLONG_unsignedMultiply(tmp, m1, RSA_QINV(pRSAKey))))
            goto exit;

        /* h = pm mod p */
        if (OK > ( status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) tmp,
                                                        RSA_P(pRSAKey), &h,
                                                        ppVlongQueue)))
        {
            goto exit;
        }

        /* m = m2 + hq */
        if (OK > ( status = VLONG_unsignedMultiply( tmp, h, RSA_Q(pRSAKey))))
            goto exit;

        /* m2 += m1 */
        if (OK > ( status = VLONG_addSignedVlongs(m2, tmp, ppVlongQueue)))
            goto exit;
    }

    *ppRetDecrypt = m2;
    m2 = 0;

exit:

#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__
    if (NULL != pM1)
    {
        (void) DIGI_MEMSET_FREE((ubyte **) &pM1, (3 * primeLen + 2) * sizeof(vlong_unit));
    }
#endif

    VLONG_freeVlong(&m1, ppVlongQueue);
    VLONG_freeVlong(&m2, ppVlongQueue);
    VLONG_freeVlong(&h, ppVlongQueue);
    VLONG_freeVlong(&tmp, ppVlongQueue);

    return status;

} /* RSAINT_decryptAux */

#endif


#ifdef __ENABLE_DIGICERT_VERIFY_RSA_SIGNATURE__

/*------------------------------------------------------------------*/

static MSTATUS
RSAINT_decryptLong(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKey,
               const vlong *c, vlong **ppRetDecrypt, vlong **ppVlongQueue)
{
    vlong*  pm      = NULL;
    vlong*  qm      = NULL;
    vlong*  d       = NULL;
    vlong*  tmp     = NULL;
    MSTATUS status;

    if (OK > (status = VLONG_allocVlong(&tmp, ppVlongQueue)))
        goto exit;

    /* pm = p - 1 */
    if (OK > (status = VLONG_makeVlongFromVlong(RSA_P(pRSAKey), &pm,
                                                ppVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_decrement(pm, ppVlongQueue)))
        goto exit;

    /* qm = q - 1 */
    if (OK > (status = VLONG_makeVlongFromVlong(RSA_Q(pRSAKey), &qm,
                                                ppVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_decrement(qm, ppVlongQueue)))
        goto exit;

    /* d = e^-1 mod ((p-1)*(q-1)) */
    if (OK > (status = VLONG_vlongSignedMultiply(tmp, pm, qm)))
        goto exit;

    if (OK > (status = VLONG_modularInverse(MOC_MOD(hwAccelCtx) RSA_E(pRSAKey),
                                            tmp, &d, ppVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) c, d, RSA_N(pRSAKey),
                                    ppRetDecrypt, ppVlongQueue)))
   {
       goto exit;
   }

exit:
    VLONG_freeVlong(&pm, ppVlongQueue);
    VLONG_freeVlong(&qm, ppVlongQueue);
    VLONG_freeVlong(&d, ppVlongQueue);
    VLONG_freeVlong(&tmp, ppVlongQueue);

    return status;

} /* RSAINT_decryptLong */
#endif  /* __ENABLE_DIGICERT_VERIFY_RSA_SIGNATURE__ */


/*--------------------------------------------------------------------------*/

#if !defined( __RSAINT_HARDWARE__) && !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)
static MSTATUS
RSAINT_initBlindingFactors(MOC_MOD(hwAccelDescr hwAccelCtx) const RSAKey* pRSAKey,
                           vlong** ppRE, vlong** ppR1,
                           RNGFun rngFun, void* rngFunArg,
                           vlong **ppVlongQueue)
{
    MSTATUS status;
    vlong*  pR = 0;
    ubyte4 rSize = RSA_N(pRSAKey)->numUnitsUsed-1;

    /* generate a random number < RSA_N(pRSAKey)  */
    if (OK > (status = VLONG_allocVlong( &pR, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pR);

    if (OK > (status = VLONG_reallocVlong( pR, rSize)))
    {
        goto exit;
    }

#ifdef __DIGICERT_BLIND_FACTOR_SIZE__
    if ( __DIGICERT_BLIND_FACTOR_SIZE__ &&
         __DIGICERT_BLIND_FACTOR_SIZE__ <=  rSize)
    {
        rSize = __DIGICERT_BLIND_FACTOR_SIZE__;
    }
#endif

    pR->numUnitsUsed = rSize;
    status = (MSTATUS) rngFun( rngFunArg,  rSize * sizeof(vlong_unit), (ubyte*) pR->pUnits);
    if (OK != status)
    {
        status = ERR_RSA_RNG_FAILURE;
        goto exit;
    }
    
    /* RE modular E exponent of R */
    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) pR, RSA_E(pRSAKey),
                                    RSA_N(pRSAKey), ppRE, ppVlongQueue)))
    {
        goto exit;
    }

    /* R1 = modular inverse of r */
    if (OK > (status = VLONG_modularInverse(MOC_MOD(hwAccelCtx) pR,
                                            RSA_N(pRSAKey), ppR1,
                                            ppVlongQueue)))
    {
        goto exit;
    }

exit:

    VLONG_freeVlong( &pR, ppVlongQueue);
    return status;
}
#endif /* __RSAINT_HARDWARE__ */


/*--------------------------------------------------------------------------*/

#if !defined( __RSAINT_HARDWARE__) && !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)
static MSTATUS
RSAINT_decrypt(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKeyInt,
               const vlong *pCipher, RNGFun rngFun, void* rngFunArg,
               vlong **ppRetDecrypt, vlong **ppVlongQueue)
{
#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__
    ubyte4 modLen;
    ubyte4 prodLen;
    ubyte4 r1Len;
#endif
    vlong*  product = NULL;
    vlong*  blinded = NULL;
    vlong*  savedR1 = NULL;
#ifndef __PSOS_RTOS__
    BlindingHelper* pBH;
#endif
    MSTATUS status;

    if ( 0 == rngFun ) /* no blinding */
    {
        return RSAINT_decryptAux( MOC_RSA(hwAccelCtx) pRSAKeyInt,
               pCipher, ppRetDecrypt, ppVlongQueue);
    }

    /* support for custom blinding implementation */
#if defined( CUSTOM_RSA_BLIND_FUNC)
    return CUSTOM_RSA_BLIND_FUNC( MOC_RSA(hwAccelCtx) pRSAKeyInt,
                                pCipher, rngFun, rngFunArg,
                                RSAINT_decryptAux, ppRetDecrypt,
                                ppVlongQueue);

#else

#if !defined(__PSOS_RTOS__)

    /* to defeat constness warnings */
    pBH = (BlindingHelper*) &pRSAKeyInt->blinding;

    /* acquire the lock on the blinding factors */
    if (OK > (status = RTOS_mutexWait( pBH->blindingMutex)))
        goto exit;

    if ( pBH->counter >= MOCANA_MAX_BLIND_FACTOR_REUSE)
    {
        VLONG_freeVlong( &pBH->pR1, ppVlongQueue);
        VLONG_freeVlong( &pBH->pRE, ppVlongQueue);
    }

    if ( !pBH->pR1 || !pBH->pRE)
    {
        if (OK > ( status = RSAINT_initBlindingFactors( MOC_MOD(hwAccelCtx)
                                                    pRSAKeyInt,
                                                    &pBH->pRE, &pBH->pR1,
                                                    rngFun, rngFunArg,
                                                    ppVlongQueue)))
        {
            goto release_mutex;
        }
        /* reset the counter */
        pBH->counter = 0;
    }
    else
    {
        ++(pBH->counter); /* increment the counter */
    }

#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__

    modLen = RSA_N(pRSAKeyInt)->numUnitsUsed;
    prodLen = pBH->pRE->numUnitsUsed + pCipher->numUnitsUsed;
    r1Len = pBH->pR1->numUnitsUsed;

    /* make real vlongs for this flow */
    if (OK > (status = VLONG_allocVlongZero (&blinded, modLen, ppVlongQueue)))
        goto release_mutex;

    /* for product */
    if (OK > (status = VLONG_allocVlongZero (&product, prodLen, ppVlongQueue)))
        goto release_mutex;

    /* for savedR1 */
    if (OK > (status = VLONG_allocVlongZero (&savedR1, r1Len, ppVlongQueue)))
        goto release_mutex;

    VLONG_constTimeMultiply(product->pUnits, prodLen, pBH->pRE->pUnits, pBH->pRE->numUnitsUsed, pCipher->pUnits, pCipher->numUnitsUsed);

    if (OK > (status = VLONG_constTimeDiv(NULL, blinded->pUnits, product->pUnits, prodLen, RSA_N(pRSAKeyInt)->pUnits, modLen)))
        goto release_mutex;

    if (OK > (status = DIGI_MEMCPY((ubyte *) (savedR1->pUnits), (ubyte *) (pBH->pR1->pUnits), r1Len * sizeof(vlong_unit))))
        goto release_mutex;

#else

    if (OK > (status = VLONG_allocVlong(&product, ppVlongQueue)))
        goto release_mutex;

    DEBUG_RELABEL_MEMORY(product);

    if (OK > (status = VLONG_vlongSignedMultiply( product, pBH->pRE, pCipher)))
        goto release_mutex;

    /* blinded is the blinded cipher text */
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx)
                                                     product,
                                                     RSA_N(pRSAKeyInt),
                                                     &blinded,
                                                     ppVlongQueue)))
    {
        goto release_mutex;
    }
    /* savedR1 is a copy of the blinding inverse os we can release the mutex early */
    if (OK > (status = VLONG_makeVlongFromVlong( pBH->pR1, &savedR1, ppVlongQueue)))
        goto release_mutex;

#endif /* __ENABLE_DIGICERT_VLONG_CONST_TIME__ */

    /* square both blinding factors -- note that if it fails in the middle, the blinding
    factors will be out of sync and all decryption will fail after that !!! */
    if (OK > ( VLONG_vlongSignedSquare( product, pBH->pRE)))
    {
        goto release_mutex;
    }

    VLONG_freeVlong(&pBH->pRE, ppVlongQueue);
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) product,
                                                     RSA_N(pRSAKeyInt),
                                                     &pBH->pRE,
                                                     ppVlongQueue)))
    {
        goto release_mutex;
    }

    if (OK > ( VLONG_vlongSignedSquare( product, pBH->pR1)))
    {
        goto release_mutex;
    }

    VLONG_freeVlong(&pBH->pR1, ppVlongQueue);
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx)
                                                     product,
                                                     RSA_N(pRSAKeyInt),
                                                     &pBH->pR1,
                                                     ppVlongQueue)))
    {
        goto release_mutex;
    }

release_mutex:
    RTOS_mutexRelease( pBH->blindingMutex);
    if (OK > status) /* there was an error i.e. we jumped to release_mutex */
    {
        goto exit;
    }

#else  /* __PSOS_RTOS__ -> no mutex */

    if (OK > ( status = RSAINT_initBlindingFactors( MOC_MOD(hwAccelCtx)
                                                pRSAKeyInt,
                                                &blinded, &savedR1,
                                                rngFun, rngFunArg,
                                                ppVlongQueue)))
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__

    modLen = RSA_N(pRSAKeyInt)->numUnitsUsed;
    prodLen = blinded->numUnitsUsed + pCipher->numUnitsUsed;
    r1Len = savedR1->numUnitsUsed;

    VLONG_constTimeMultiply(product->pUnits, prodLen, blinded->pUnits, blinded->numUnitsUsed, pCipher->pUnits, pCipher->numUnitsUsed);

    /* re-use blinded, it needs to be freed and re-allocated to the correct length */
    VLONG_freeVlong(&blinded, ppVlongQueue);

    if (OK > (status = VLONG_allocVlongZero (&blinded, modLen, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_constTimeDiv(NULL, blinded->pUnits, product->pUnits, prodLen, RSA_N(pRSAKeyInt)->pUnits, modLen)))
        goto exit;

#else

    if (OK > (status = VLONG_allocVlong(&product, ppVlongQueue)))
        goto exit;

    if (OK > ( status = VLONG_vlongSignedMultiply( product, blinded, pCipher)))
        goto exit;

    VLONG_freeVlong(&blinded, ppVlongQueue);
    /* blinded is now the blinded cipher text */
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx)
                                                     product,
                                                     RSA_N(pRSAKeyInt),
                                                     &blinded,
                                                     ppVlongQueue)))
    {
        goto exit;
    }

    /* product -> allocated, can be disposed of
        blinded is blinded cipher text
        savedR1 is inverse blinding factor */

#endif /* __ENABLE_DIGICERT_VLONG_CONST_TIME__ */
#endif /* __PSOS_RTOS__ -> no mutex */

    VLONG_freeVlong( &product, ppVlongQueue);
    /* call the normal routine */
    if (OK > (status = RSAINT_decryptAux( MOC_RSA(hwAccelCtx) pRSAKeyInt,
                                          blinded, &product, ppVlongQueue)))
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__

    /* re-use blinded, it needs to be freed and re-allocated to the correct length */
    VLONG_freeVlong(&blinded, ppVlongQueue);

    if (OK > (status = VLONG_allocVlongZero (&blinded, modLen + r1Len, ppVlongQueue)))
        goto exit;

    VLONG_constTimeMultiply(blinded->pUnits, blinded->numUnitsUsed, product->pUnits, modLen, savedR1->pUnits, r1Len);

    /* and now re-use product */
    VLONG_freeVlong(&product, ppVlongQueue);

    if (OK > (status = VLONG_allocVlongZero (&product, modLen, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_constTimeDiv(NULL, product->pUnits, blinded->pUnits, blinded->numUnitsUsed, RSA_N(pRSAKeyInt)->pUnits, modLen)))
        goto exit;

    *ppRetDecrypt = product; product = NULL;

#else

    /* unblind with savedR1 */
    if (OK > ( status = VLONG_vlongSignedMultiply( blinded, product, savedR1)))
        goto exit;

    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx)
                                                     blinded,
                                                     RSA_N(pRSAKeyInt),
                                                     ppRetDecrypt,
                                                     ppVlongQueue)))
    {
        goto exit;
    }
#endif

exit:
    VLONG_freeVlong(&product, ppVlongQueue);
    VLONG_freeVlong(&blinded, ppVlongQueue);
    VLONG_freeVlong(&savedR1, ppVlongQueue);

    return status;
#endif  /* __CUSTOM_RSA_BLINDING__ */
} /* RSAINT_decrypt */
#endif /* __RSAINT_HARDWARE__ */


/*------------------------------------------------------------------*/


MOC_EXTERN MSTATUS
RSA_createKey(RSAKey **pp_RetRSAKey)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    RSAKey* pNewKey = 0;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

    if (NULL == pp_RetRSAKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pNewKey = (RSAKey*) MALLOC(sizeof(RSAKey))))
        status = ERR_MEM_ALLOC_FAIL;
    else
        status = DIGI_MEMSET((ubyte *)(pNewKey), 0x00, sizeof(RSAKey));

#if !defined( __PSOS_RTOS__) && !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)
    if (OK > status)
    {
        goto exit;
    }

    if (OK > ( status = RTOS_mutexCreate( &(pNewKey->blinding.blindingMutex),
                                          (enum mutexTypes) 0,0)))
    {
        goto exit;
    }
#endif

    *pp_RetRSAKey = pNewKey;
    pNewKey = 0;

exit:

    if ( pNewKey)
    {
        FREE( pNewKey);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
    return status;
}


/*------------------------------------------------------------------*/

static void
RSA_clearKey( RSAKey* pRSAKey, vlong **ppVlongQueue)
{
    sbyte4 i;

    for (i = 0; i < NUM_RSA_VLONG; ++i)
    {
        VLONG_freeVlong(&(pRSAKey->v[i]), ppVlongQueue);
    }
    for (i = 0; i < NUM_RSA_MODEXP; ++i)
    {
        VLONG_deleteModExpHelper( &pRSAKey->modExp[i], ppVlongQueue);
    }

#if !defined( __PSOS_RTOS__) && !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)
    /* free the blinding factors */
    VLONG_freeVlong( &pRSAKey->blinding.pR1, ppVlongQueue);
    VLONG_freeVlong( &pRSAKey->blinding.pRE, ppVlongQueue);
#endif

}


/*--------------------------------------------------------------------------*/


extern MSTATUS
RSA_cloneKey(MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey** ppNew, const RSAKey* pSrc, vlong **ppVlongQueue)
{
    MSTATUS status = OK;
    RSAKey* pNew = 0;


    if (!ppNew || !pSrc)
    {
        return ERR_NULL_POINTER;
    }

    if (OK > ( status = RSA_createKey( &pNew)))
    {
        return status;
    }

    pNew->privateKey = pSrc->privateKey;
    if ( OK > ( status = VLONG_makeVlongFromVlong( RSA_N(pSrc), &RSA_N(pNew), ppVlongQueue)))
    {
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(RSA_N(pNew));

    if ( OK > ( status = VLONG_makeVlongFromVlong( RSA_E(pSrc), &RSA_E(pNew), ppVlongQueue)))
    {
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(RSA_E(pNew));

#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
    if(!(pSrc->hsmInfo))
    {
#endif
    if (pSrc->privateKey)
    {
        sbyte4 i;

        if (!RSA_DP(pSrc) || !RSA_DQ(pSrc) || !RSA_QINV(pSrc) ||
            !RSA_MODEXP_P(pSrc) || !RSA_MODEXP_Q(pSrc))
        {
            status = ERR_RSA_KEY_NOT_READY;
            goto exit;
        }

        for (i = 2; i < NUM_RSA_VLONG; ++i)
        {
            if ( OK > ( status = VLONG_makeVlongFromVlong( pSrc->v[i], &pNew->v[i], ppVlongQueue)))
            {
                goto exit;
            }

            DEBUG_RELABEL_MEMORY(pNew->v[i]);
        }

        for (i = 0; i < NUM_RSA_MODEXP; ++i)
        {
            if ( OK > ( status = VLONG_makeModExpHelperFromModExpHelper(
                        pSrc->modExp[i], &pNew->modExp[i], ppVlongQueue)))
            {
                goto exit;
            }
        }
    }

#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
    }
#endif

#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
    if(pSrc->hsmInfo)
    {
        if(OK > (status = HSMRSAINFO_copyHSMRSAInfo(&(pNew->hsmInfo), pSrc->hsmInfo)))
            goto exit;
    }
#endif

    /* OK */
    *ppNew = pNew;
    pNew = 0;

exit:

    if (pNew)
    {
        RSA_freeKey( &pNew, NULL);
    }

    return status;
}


/*------------------------------------------------------------------*/


MOC_EXTERN MSTATUS
RSA_freeKey(RSAKey **ppFreeRSAKey, vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

    if ((NULL == ppFreeRSAKey) || (NULL == *ppFreeRSAKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    RSA_clearKey( *ppFreeRSAKey, ppVlongQueue);

#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
    if((*ppFreeRSAKey)->hsmInfo)
    {
        status = HSMRSAINFO_freeHSMRSAInfo(&((*ppFreeRSAKey)->hsmInfo));
    }
#endif

#if !defined( __PSOS_RTOS__) && !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)
    RTOS_mutexFree(&((**ppFreeRSAKey).blinding.blindingMutex));
#endif

    FREE(*ppFreeRSAKey);
    *ppFreeRSAKey = NULL;

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
    return status;
}


/*------------------------------------------------------------------*/

#ifndef __DISABLE_RSA_KEY_EQUALITY_TEST__


extern MSTATUS
RSA_equalKey(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey1, const RSAKey *pKey2, byteBoolean* pResult)
{
    MSTATUS status = OK;

    if ((NULL == pKey1) || (NULL == pKey2) || (NULL == pResult))
        status = ERR_NULL_POINTER;
    else
    {
        /* only compare the public part */
        *pResult = FALSE;

        if ((0 == VLONG_compareSignedVlongs(RSA_E(pKey1), RSA_E(pKey2))) &&
            (0 == VLONG_compareSignedVlongs(RSA_N(pKey1), RSA_N(pKey2))))
        {
            *pResult = TRUE;
        }
    }

    return status;
}

#endif /* __DISABLE_RSA_KEY_EQUALITY_TEST__ */


/*------------------------------------------------------------------*/


MOC_EXTERN MSTATUS RSA_setPublicKeyParameters (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte4 exponent,
  const ubyte *pModulus,
  ubyte4 modulusLen,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ubyte pPubExpo[4];

  /* Null checks done in the call to RSA_setPublicKeyData */
    
  status = ERR_BAD_EXPONENT;
  if (2 > exponent)
    goto exit;

  pPubExpo[0] = (ubyte)(exponent >> 24);
  pPubExpo[1] = (ubyte)(exponent >> 16);
  pPubExpo[2] = (ubyte)(exponent >>  8);
  pPubExpo[3] = (ubyte)(exponent);

  status = RSA_setPublicKeyData ( MOC_RSA(hwAccelCtx)
    pKey, pPubExpo, 4, pModulus, modulusLen, ppVlongQueue);

exit:

  return (status);
}

extern MSTATUS RSA_setPublicKeyData (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pPubExpo,
  ubyte4 pubExpoLen,
  const ubyte *pModulus,
  ubyte4 modulusLen,
  vlong **ppVlongQueue
  )
{
  FIPS_LOG_DECL_SESSION;
  MSTATUS status = OK;

  FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
  FIPS_LOG_START_ALG(FIPS_ALGO_RSA,modulusLen);

  status = ERR_NULL_POINTER;
  if (NULL == pKey || NULL == pPubExpo || NULL == pModulus)
    goto exit;

  status = ERR_BAD_EXPONENT;
  if (1 > pubExpoLen)
    goto exit;

  if ( (1 == pubExpoLen) && (2 > pPubExpo[0]) )
    goto exit;

  RSA_clearKey (pKey, ppVlongQueue);

  status = VLONG_vlongFromByteString (
    pPubExpo, pubExpoLen, &RSA_E(pKey), ppVlongQueue);
  if (OK != status)
    goto exit;

  status = VLONG_vlongFromByteString (
    pModulus, modulusLen, &RSA_N(pKey), ppVlongQueue);
  if (OK != status)
    goto exit;

  DEBUG_RELABEL_MEMORY(RSA_N(pKey));

  pKey->privateKey = FALSE;

exit:

  FIPS_LOG_END_ALG(FIPS_ALGO_RSA,modulusLen);
  return (status);
}

/*------------------------------------------------------------------*/

extern MSTATUS
RSA_prepareKey(MOC_RSA(hwAccelDescr hwAccelCtx)
               RSAKey *pRSAKey, vlong** ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    /* This precomputes some values used for the decrypt operation */
    MSTATUS status = OK;
    vlong* pm = 0;
    vlong* qm = 0;

    if (!pRSAKey)
        return ERR_NULL_POINTER;

    if (!pRSAKey->privateKey)
        return OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

    /* make sure  p > q */
    if ( VLONG_compareSignedVlongs( RSA_P(pRSAKey), RSA_Q(pRSAKey) ) < 0)
    {
        vlong* tmp;
        tmp = RSA_P(pRSAKey);
        RSA_P(pRSAKey) = RSA_Q(pRSAKey);
        RSA_Q(pRSAKey) = tmp;
        VLONG_freeVlong(&RSA_DP(pRSAKey), ppVlongQueue);
        VLONG_freeVlong(&RSA_DQ(pRSAKey), ppVlongQueue);
        VLONG_freeVlong(&RSA_QINV(pRSAKey), ppVlongQueue);
        VLONG_deleteModExpHelper( &RSA_MODEXP_P(pRSAKey), ppVlongQueue);
        VLONG_deleteModExpHelper( &RSA_MODEXP_Q(pRSAKey), ppVlongQueue);
    }

    if ( !RSA_DP(pRSAKey))
    {
        /* pm = p - 1; */
        if (OK > (status = VLONG_makeVlongFromVlong(RSA_P(pRSAKey), &pm,
                                                    ppVlongQueue)))
        {
            goto exit;
        }

        DEBUG_RELABEL_MEMORY(pm);

        if (OK > (status = VLONG_decrement(pm, ppVlongQueue)))
            goto exit;

        /* dP = e^-1 mod pm */
        if (OK > ( status = VLONG_modularInverse( MOC_MOD( hwAccelCtx)
                                                  RSA_E(pRSAKey), pm,
                                                  &RSA_DP(pRSAKey), ppVlongQueue)))
        {
            goto exit;
        }
    }

    if (!RSA_DQ(pRSAKey))
    {
        /* qm = q - vlong(1); */
        if (OK > (status = VLONG_makeVlongFromVlong(RSA_Q(pRSAKey), &qm,
                                                    ppVlongQueue)))
        {
            goto exit;
        }

        DEBUG_RELABEL_MEMORY(qm);

        if (OK > (status = VLONG_decrement(qm, ppVlongQueue)))
            goto exit;

        /* dQ = e^-1 mod qm */
        if (OK > ( status = VLONG_modularInverse( MOC_MOD(hwAccelCtx)
                                                  RSA_E(pRSAKey), qm,
                                                  &RSA_DQ(pRSAKey), ppVlongQueue)))
        {
            goto exit;
        }
    }

    if (!RSA_QINV(pRSAKey))
    {
        /* qInv = q^ -1 mod p */
        if ( OK > ( status = VLONG_modularInverse( MOC_MOD( hwAccelCtx)
                                                   RSA_Q(pRSAKey), RSA_P(pRSAKey),
                                                   &RSA_QINV(pRSAKey),
                                                   ppVlongQueue)))
        {
            goto exit;
        }
    }

    if (!RSA_MODEXP_P(pRSAKey) )
    {
        if (OK > ( status = VLONG_newModExpHelper(MOC_MOD(hwAccelCtx) &RSA_MODEXP_P(pRSAKey),
                                                   RSA_P(pRSAKey), ppVlongQueue)))
        {
            goto exit;
        }
    }

    if (!RSA_MODEXP_Q(pRSAKey) )
    {
        if (OK > ( status = VLONG_newModExpHelper(MOC_MOD(hwAccelCtx)
                                        &RSA_MODEXP_Q(pRSAKey),
                                        RSA_Q(pRSAKey), ppVlongQueue)))
        {
            goto exit;
        }
    }

exit:
    VLONG_freeVlong(&pm, ppVlongQueue);
    VLONG_freeVlong(&qm, ppVlongQueue);

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
    return status;
}


/*------------------------------------------------------------------*/

#if defined( __ENABLE_ALL_TESTS__) || !defined(__DISABLE_PKCS1_KEY_READ__)

MSTATUS RSA_setAllKeyParameters (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte4 exponent,
  const ubyte *modulus,
  ubyte4 modulusLen,
  const ubyte *prime1,
  ubyte4 prime1Len,
  const ubyte *prime2,
  ubyte4 prime2Len,
  vlong **ppVlongQueue)
{
  MSTATUS status;
  ubyte pPubExpo[4];

  /* Null checks done in the call to RSA_setAllKeyData */
    
  status = ERR_BAD_EXPONENT;
  if (2 > exponent)
    goto exit;

  pPubExpo[0] = (ubyte)(exponent >> 24);
  pPubExpo[1] = (ubyte)(exponent >> 16);
  pPubExpo[2] = (ubyte)(exponent >>  8);
  pPubExpo[3] = (ubyte)(exponent);

  status = RSA_setAllKeyData (
    MOC_RSA (hwAccelCtx) pKey, pPubExpo, 4, modulus, modulusLen,
    prime1, prime1Len, prime2, prime2Len, ppVlongQueue);

exit:

  return (status);
}

MOC_EXTERN MSTATUS RSA_setAllKeyData (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pPubExpo,
  ubyte4 pubExpoLen,
  const ubyte *pModulus,
  ubyte4 modulusLen,
  const ubyte *pPrime1,
  ubyte4 prime1Len,
  const ubyte *pPrime2,
  ubyte4 prime2Len,
  vlong **ppVlongQueue
  )
{
  FIPS_LOG_DECL_SESSION;
  MSTATUS status = ERR_NULL_POINTER;

  FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
  FIPS_LOG_START_ALG(FIPS_ALGO_RSA,modulusLen);

  /* The key and public key params checked for NULL below in RSA_setPublicKeyData */
  if (NULL == pPrime1 || NULL == pPrime2)
    goto exit;
    
  status = RSA_setPublicKeyData ( MOC_RSA(hwAccelCtx)
    pKey, pPubExpo, pubExpoLen, pModulus, modulusLen, ppVlongQueue);
  if (OK != status)
    goto exit;

  status = VLONG_vlongFromByteString (
    pPrime1, prime1Len, &RSA_P(pKey), ppVlongQueue);
  if (OK != status)
    goto exit;

  DEBUG_RELABEL_MEMORY(RSA_P(pKey));

  status = VLONG_vlongFromByteString (
    pPrime2, prime2Len, &RSA_Q(pKey), ppVlongQueue);
  if (OK != status)
    goto exit;

  DEBUG_RELABEL_MEMORY(RSA_Q(pKey));

  pKey->privateKey = TRUE;

  status = RSA_prepareKey (MOC_MOD(hwAccelCtx) pKey, ppVlongQueue);

exit:

  FIPS_LOG_END_ALG(FIPS_ALGO_RSA,modulusLen);
  return (status);
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS RSA_getKeyParametersAlloc (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    RSAKey *pKey,
    MRsaKeyTemplate *pTemplate,
    ubyte keyType
    )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    ubyte *pRetPubExpo = NULL, *pRetModulus = NULL, *pRetPrimeP = NULL,
          *pRetPrimeQ  = NULL;
    ubyte4 retPubExpoLen = 0, retModulusLen = 0, retPrimePLen = 0,
           retPrimeQLen  = 0;
    ubyte *pRetD = NULL, *pRetDp = NULL, *pRetDq = NULL, *pQinv = NULL;
    ubyte4 retDLen = 0, retDpLen = 0, retDqLen = 0, retQinvLen = 0;
    vlong *pTempD = NULL;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

    status = ERR_NULL_POINTER;
    if ( (NULL == pTemplate) || (NULL == pKey) )
        goto exit;

    /* Must have the proper key type flag defined */
    status = ERR_INVALID_ARG;
    if ( (MOC_GET_PUBLIC_KEY_DATA  != keyType) &&
         (MOC_GET_PRIVATE_KEY_DATA != keyType) )
        goto exit;

    /* Get the public exponent */
    if (NULL != RSA_E (pKey))
    {
        /* Get the length required for the output buffer */
        status = VLONG_byteStringFromVlong (
            RSA_E (pKey), NULL, (sbyte4 *) &retPubExpoLen);
        if (OK != status)
            goto exit;

        /* Allocate the public exponent buffer */
        status = DIGI_MALLOC ((void **)&pRetPubExpo, retPubExpoLen);
        if (OK != status)
            goto exit;

        /* Now actually get the byte string buffer */
        status = VLONG_byteStringFromVlong (
            RSA_E (pKey), pRetPubExpo, (sbyte4 *) &retPubExpoLen);
        if (OK != status)
            goto exit;
    }

    /* Get the modulus */
    if (NULL != RSA_N (pKey))
    {
        /* Get the length required for the output buffer */
        status = VLONG_byteStringFromVlong (
            RSA_N (pKey), NULL, (sbyte4 *) &retModulusLen);
        if (OK != status)
            goto exit;

        /* Allocate the modulus buffer */
        status = DIGI_MALLOC ((void **)&pRetModulus, retModulusLen);
        if (OK != status)
            goto exit;

        /* Now actually get the modulus buffer */
        status = VLONG_byteStringFromVlong (
            RSA_N (pKey), pRetModulus, (sbyte4 *) &retModulusLen);
        if (OK != status)
            goto exit;
    }

    if (MOC_GET_PRIVATE_KEY_DATA == keyType)
    {
        /* We need at least P and Q if this is a private key */
        status = ERR_NULL_POINTER;
        if ( (NULL == RSA_P(pKey)) || (NULL == RSA_Q(pKey)) )
        {
            goto exit;
        }

        /* Private:  Get the Prime P */
        if (NULL != RSA_P(pKey))
        {
            /* Get the length required for the output buffer */
            status = VLONG_byteStringFromVlong (
                RSA_P(pKey), NULL, (sbyte4 *) &retPrimePLen);
            if (OK != status)
                goto exit;

            /* Allocate the Prime P buffer */
            status = DIGI_MALLOC ((void **)&pRetPrimeP, retPrimePLen);
            if (OK != status)
                goto exit;

            /* Now actually get the prime P buffer */
            status = VLONG_byteStringFromVlong (
                RSA_P(pKey), pRetPrimeP, (sbyte4 *) &retPrimePLen);
            if (OK != status)
                goto exit;
        }

        /* Private:  Get the Prime Q */
        if (NULL != RSA_Q(pKey))
        {
            /* Get the length required for the output buffer */
            status = VLONG_byteStringFromVlong (
                RSA_Q(pKey), NULL, (sbyte4 *) &retPrimeQLen);
            if (OK != status)
                goto exit;

            /* Allocate the Prime P buffer */
            status = DIGI_MALLOC ((void **)&pRetPrimeQ, retPrimeQLen);
            if (OK != status)
                goto exit;

            /* Now actually get the prime P buffer */
            status = VLONG_byteStringFromVlong (
                RSA_Q(pKey), pRetPrimeQ, (sbyte4 *) &retPrimeQLen);
            if (OK != status)
                goto exit;
        }

        /* Private:  Get Dp */
        if (NULL != RSA_DP(pKey))
        {
            /* Get the length required for the output buffer */
            status = VLONG_byteStringFromVlong (
                RSA_DP(pKey), NULL, (sbyte4 *) &retDpLen);
            if (OK != status)
                goto exit;

            /* Allocate the Dp buffer */
            status = DIGI_MALLOC ((void **)&pRetDp, retDpLen);
            if (OK != status)
                goto exit;

            /* Now actually get the Dp buffer */
            status = VLONG_byteStringFromVlong (
                RSA_DP(pKey), pRetDp, (sbyte4 *) &retDpLen);
            if (OK != status)
                goto exit;
        }

        /* Private:  Get Dq */
        if (NULL != RSA_DQ(pKey))
        {
            /* Get the length required for the output buffer */
            status = VLONG_byteStringFromVlong (
                RSA_DQ(pKey), NULL, (sbyte4 *) &retDqLen);
            if (OK != status)
                goto exit;

            /* Allocate the Dq buffer */
            status = DIGI_MALLOC ((void **)&pRetDq, retDqLen);
            if (OK != status)
                goto exit;

            /* Now actually get the Dq buffer */
            status = VLONG_byteStringFromVlong (
                RSA_DQ(pKey), pRetDq, (sbyte4 *) &retDqLen);
            if (OK != status)
                goto exit;
        }

        /* Private:  Get Qinv */
        if (NULL != RSA_QINV(pKey))
        {
            /* Get the length required for the output buffer */
            status = VLONG_byteStringFromVlong (
                RSA_QINV(pKey), NULL, (sbyte4 *) &retQinvLen);
            if (OK != status)
                goto exit;

            /* Allocate the Qinv buffer */
            status = DIGI_MALLOC ((void **)&pQinv, retQinvLen);
            if (OK != status)
                goto exit;

            /* Now actually get the Qinv buffer */
            status = VLONG_byteStringFromVlong (
                RSA_QINV(pKey), pQinv, (sbyte4 *) &retQinvLen);
            if (OK != status)
                goto exit;
        }

        /* Private: get the calculated private exponent D */
        status = RSA_getPrivateExponent(MOC_RSA(hwAccelCtx) pKey, &pTempD, NULL);
        if (OK != status)
            goto exit;

        /* Get the length required for the output buffer */
        status = VLONG_byteStringFromVlong (
            pTempD, NULL, (sbyte4 *) &retDLen);
        if (OK != status)
            goto exit;

        /* Allocate the D buffer */
        status = DIGI_MALLOC ((void **)&pRetD, retDLen);
        if (OK != status)
            goto exit;

        /* Write the value into the newly allocated buffer */
        status = VLONG_byteStringFromVlong (
            pTempD, pRetD, (sbyte4 *) &retDLen);
        if (OK != status)
            goto exit;
    }

    /* Now that all our cases have passed without error, move the buffer pointers
     * into the pTemplate */
    pTemplate->eLen = retPubExpoLen;
    pTemplate->pE = pRetPubExpo;
    pRetPubExpo = NULL;

    pTemplate->nLen = retModulusLen;
    pTemplate->pN = pRetModulus;
    pRetModulus = NULL;

    pTemplate->pLen = retPrimePLen;
    pTemplate->pP = pRetPrimeP;
    pRetPrimeP = NULL;

    pTemplate->qLen = retPrimeQLen;
    pTemplate->pQ = pRetPrimeQ;
    pRetPrimeQ = NULL;

    pTemplate->dLen = retDLen;
    pTemplate->pD = pRetD;
    pRetD = NULL;

    pTemplate->dpLen = retDpLen;
    pTemplate->pDp = pRetDp;
    pRetDp = NULL;

    pTemplate->dqLen = retDqLen;
    pTemplate->pDq = pRetDq;
    pRetDq = NULL;

    pTemplate->qInvLen = retQinvLen;
    pTemplate->pQinv = pQinv;
    pQinv = NULL;


exit:

    if (NULL != pTempD)
    {
        VLONG_freeVlong (&pTempD, NULL);
    }

    if (NULL != pRetPubExpo)
    {
        DIGI_MEMSET(pRetPubExpo, 0x00, retPubExpoLen);
        DIGI_FREE ((void **) &pRetPubExpo);
    }

    if (NULL != pRetModulus)
    {
        DIGI_MEMSET(pRetModulus, 0x00, retModulusLen);
        DIGI_FREE ((void **) &pRetModulus);
    }

    if (NULL != pRetPrimeP)
    {
        DIGI_MEMSET(pRetPrimeP, 0x00, retPrimePLen);
        DIGI_FREE ((void **) &pRetPrimeP);
    }

    if (NULL != pRetPrimeQ)
    {
        DIGI_MEMSET(pRetPrimeQ, 0x00, retPrimeQLen);
        DIGI_FREE ((void **) &pRetPrimeQ);
    }

    if (NULL != pRetD)
    {
        DIGI_MEMSET(pRetD, 0x00, retDLen);
        DIGI_FREE ((void **) &pRetD);
    }

    if (NULL != pRetDp)
    {
        DIGI_MEMSET(pRetDp, 0x00, retDpLen);
        DIGI_FREE ((void **) &pRetDp);
    }

    if (NULL != pRetDq)
    {
        DIGI_MEMSET(pRetDq, 0x00, retDqLen);
        DIGI_FREE ((void **) &pRetDq);
    }

    if (NULL != pQinv)
    {
        DIGI_MEMSET(pQinv, 0x00, retQinvLen);
        DIGI_FREE ((void **) &pQinv);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
    return (status);
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS RSA_freeKeyTemplate (
    RSAKey *pKey,
    MRsaKeyTemplate *pTemplate
    )
{
    MSTATUS status = OK;
    MOC_UNUSED(pKey);

    /* If the pointer is already NULL, we're done here */
    if (NULL == pTemplate)
        goto exit;

    if (NULL != pTemplate->pE)
    {
        status = DIGI_MEMSET(pTemplate->pE, 0x00, pTemplate->eLen);
        if (OK != status)
            goto exit;

        status = DIGI_FREE ((void **) &pTemplate->pE);
        if (OK != status)
            goto exit;

        pTemplate->eLen = 0;

    }

    if (NULL != pTemplate->pN)
    {
        status = DIGI_MEMSET(pTemplate->pN, 0x00, pTemplate->nLen);
        if (OK != status)
            goto exit;

        status = DIGI_FREE ((void **) &pTemplate->pN);
        if (OK != status)
            goto exit;

        pTemplate->nLen = 0;
    }

    if (NULL != pTemplate->pP)
    {
        status = DIGI_MEMSET(pTemplate->pP, 0x00, pTemplate->pLen);
        if (OK != status)
            goto exit;

        status = DIGI_FREE ((void **) &pTemplate->pP);
        if (OK != status)
            goto exit;

        pTemplate->pLen = 0;
    }

    if (NULL != pTemplate->pQ)
    {
        status = DIGI_MEMSET(pTemplate->pQ, 0x00, pTemplate->qLen);
        if (OK != status)
            goto exit;

        status = DIGI_FREE ((void **) &pTemplate->pQ);
        if (OK != status)
            goto exit;

        pTemplate->qLen = 0;
    }

    if (NULL != pTemplate->pD)
    {
        status = DIGI_MEMSET(pTemplate->pD, 0x00, pTemplate->dLen);
        if (OK != status)
            goto exit;

        status = DIGI_FREE ((void **) &pTemplate->pD);
        if (OK != status)
            goto exit;

        pTemplate->dLen = 0;
    }

    if (NULL != pTemplate->pDp)
    {
        status = DIGI_MEMSET(pTemplate->pDp, 0x00, pTemplate->dpLen);
        if (OK != status)
            goto exit;

        status = DIGI_FREE ((void **) &pTemplate->pDp);
        if (OK != status)
            goto exit;

        pTemplate->dpLen = 0;
    }

    if (NULL != pTemplate->pDq)
    {
        status = DIGI_MEMSET(pTemplate->pDq, 0x00, pTemplate->dqLen);
        if (OK != status)
            goto exit;

        status = DIGI_FREE ((void **) &pTemplate->pDq);
        if (OK != status)
            goto exit;

        pTemplate->dqLen = 0;
    }

    if (NULL != pTemplate->pQinv)
    {
        status = DIGI_MEMSET(pTemplate->pQinv, 0x00, pTemplate->qInvLen);
        if (OK != status)
            goto exit;

        status = DIGI_FREE ((void **) &pTemplate->pQinv);
        if (OK != status)
            goto exit;

        pTemplate->qInvLen = 0;
    }

exit:

    return (status);
}


/*----------------------------------------------------------------------------*/

#endif /* __ENABLE_ALL_TESTS__ || !__DISABLE_PKCS1_KEY_READ__ */


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
RSA_getCipherTextLength(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey, sbyte4 *pCipherTextLen)
{

    if ((NULL == pKey) || (NULL == pCipherTextLen) || (NULL == RSA_N(pKey)))
    {
        return ERR_NULL_POINTER;
    }

    return VLONG_byteStringFromVlong( RSA_N(pKey), NULL, pCipherTextLen);
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_ALL_TESTS__) || (!defined(__DISABLE_DIGICERT_RSA_CLIENT_CODE__)))

MOC_EXTERN MSTATUS
RSA_encrypt(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
            const ubyte* plainText, ubyte4 plainTextLen, ubyte* cipherText,
            RNGFun rngFun, void* rngFunArg, vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    /* encrypt the plainText using PKCS#1 scheme */
    sbyte4  keyLen;
    sbyte4  i;
    vlong*  pPkcs1       = NULL;
    vlong*  pEncrypted   = NULL;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

    if ( 0 == pKey || 0 == plainText || 0 == cipherText || 0 == rngFun)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = VLONG_byteStringFromVlong(RSA_N(pKey), NULL, &keyLen)))
        goto exit;

    if (keyLen < (sbyte4) (plainTextLen+3+8)) /* padding must be at least 8 chars long */
    {
        status = ERR_RSA_INVALID_KEY;
        goto exit;
    }

    cipherText[0] = 0;
    cipherText[1] = 2;

    status = (*rngFun)(rngFunArg, (keyLen - 3) - plainTextLen, cipherText + 2);
    if (OK != status)
    {
        status = ERR_RSA_RNG_FAILURE;
        goto exit;
    }
    
    for(i = 2; i < (sbyte4) (keyLen - plainTextLen) - 1; ++i)
    {
        if (0 == cipherText[i])
        {
            cipherText[i] = 1;
        }
    }

    cipherText[(keyLen - plainTextLen) - 1] = 0;

    DIGI_MEMCPY((cipherText + keyLen) - plainTextLen, plainText, plainTextLen);

    if (OK > (status = VLONG_vlongFromByteString(cipherText, keyLen, &pPkcs1,
                                                 ppVlongQueue)))
    {
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pPkcs1);

    if (OK > (status = RSAINT_encrypt(MOC_RSA(hwAccelCtx) pKey, pPkcs1,
                                      &pEncrypted, ppVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_byteStringFromVlong(pEncrypted, cipherText,
                                                 &keyLen)))
    {
        goto exit;
    }

exit:
    VLONG_freeVlong(&pEncrypted, ppVlongQueue);
    VLONG_freeVlong(&pPkcs1, ppVlongQueue);

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
    return status;

} /* RSA_encrypt */

#endif /* (defined(__ENABLE_ALL_TESTS__) || (!defined(__DISABLE_DIGICERT_RSA_CLIENT_CODE__))) */


/*------------------------------------------------------------------*/
#if !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)

extern MSTATUS
RSA_decrypt(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
            const ubyte* cipherText, ubyte* plainText, ubyte4* plainTextLen,
            RNGFun rngFun, void* rngFunArg, vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    sbyte4  keyLen = 0, decryptedLen = 0;
    sbyte4  i;
    vlong*  pPkcs1     = NULL;
    vlong*  pEncrypted = NULL;
    sbyte4  realLen    = 0;
    ubyte4  padResult;
    MSTATUS status = OK;
#if (defined(__ENABLE_DIGICERT_PKCS11_CRYPTO__) || defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__))
  sbyte4  cipherTextLen = 0;
#endif

  FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
  FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

  if ((NULL == pKey) || (NULL == plainText) || (NULL == cipherText) || (NULL == plainTextLen))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  if (FALSE == pKey->privateKey)
  {
    status = ERR_RSA_INVALID_KEY;
    goto exit;
  }

#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
  if(pKey->hsmInfo)
  {
    ubyte* pDecrypted = NULL;
    ubyte4 decryptedLen;

    /*We will get the cipher text length from modulus*/
    if (OK > (status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pKey, &cipherTextLen)))
    {
      goto exit;
    }

    if (OK > (status = HSMRSAINFO_decryptMessage(pKey, cipherText, cipherTextLen, &pDecrypted, &decryptedLen)))
    {
      goto exit;
    }

    if (NULL != pDecrypted)
    {
      DIGI_MEMCPY(plainText, pDecrypted, decryptedLen);
      *plainTextLen = decryptedLen;
      HSMRSAINFO_freeData(&pDecrypted);
    }

    /* note: signedLen should equal keyLen, or something went wrong */

    goto exit;
  }
#endif

#ifdef __ENABLE_DIGICERT_PKCS11_CRYPTO__

  if (OK > (status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pKey, &cipherTextLen)))
  {
    goto exit;

  }

  /* C_Decrypt is for single part decryption, meaning no loop is required
   * pMechanism is fixed to NULL upon BAI's request
   *
   */
  if (OK != (status = RSAINT_decrypt((CK_SESSION_HANDLE)hwAccelCtx,
    NULL,
    (CK_OBJECT_HANDLE)pKey,
    (CK_BYTE_PTR)cipherText,
    (CK_ULONG)cipherTextLen,
    (CK_BYTE_PTR)plainText,
    (CK_ULONG_PTR)&decryptedLen)))
  {
    goto exit;
  }

#else    /* regular case */

  if (OK > (status = VLONG_byteStringFromVlong(RSA_N(pKey), NULL, &keyLen)))
    goto exit;

  if (OK > (status = VLONG_vlongFromByteString(cipherText, keyLen, &pEncrypted, ppVlongQueue)))
    goto exit;

  DEBUG_RELABEL_MEMORY(pEncrypted);

  if (OK > (status = RSAINT_decrypt(MOC_RSA(hwAccelCtx) pKey, pEncrypted, rngFun, rngFunArg,
    &pPkcs1, ppVlongQueue)))
  {
    goto exit;
  }

  decryptedLen = keyLen;

#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__
  /* If constant time code calculated pPkcs1 then it will have numUnitsUsed the full length */
  if (( (ubyte4) decryptedLen + sizeof(vlong_unit) - 1)/sizeof(vlong_unit) <= pPkcs1->numUnitsUsed)
  {
    /* VLONG_fixedByteStringFromVlong is constant time when numUnitsUsed is the full length */
    if (OK > (status = VLONG_fixedByteStringFromVlong (pPkcs1, plainText, decryptedLen)))
        goto exit;
  }
  else
#endif
  {
    if (OK > (status = VLONG_byteStringFromVlong(pPkcs1, plainText, &decryptedLen)))
     goto exit;
  }

    /* Set padResult to 0, meaning there have been no errors in unpadding.
     * Each time we encounter an error, add to padResult. At the end, if
     * padResult is not 0, then set status to ERR_RSA_DECRYPTION.
     * We want to make all checks and not stop as soon as we hit an error.
     */
  padResult = 0;
    /* plaintext contains actually the whole pkcs1 */
    /* some verifications */
  i = 2;

  /*
   Note the call to VLONG_byteStringFromVlong did not change decryptedLen and
   will always 0x00 pad, so we're expecting the first two bytes to be something specific.
   */
  if ((plainText[0] != 0) || (plainText[1] != 2))
  {
    padResult++;
  }

  /* scan until the first 0 byte */
  for (; i < decryptedLen; ++i)
  {
    if (0 == plainText[i])
    {
      break;
    }
  }

  /*    0    1    2    3    4    5    6    7    8    9    10 */
  /*    0    2    1    2    3    4    5    6    7    8    0 */
  if ( i < 10) /* padding must be at least 8 non-zero bytes after the first two bytes */
    padResult++;

  for ( ++i; i < decryptedLen; ++i, ++realLen)
  {
    plainText[realLen] = plainText[i];
  }

  /* This happens if no 00 byte was found.
   */
  if (0 == realLen)
    padResult++;

  *plainTextLen = realLen;

  status = ERR_RSA_DECRYPTION;
  if (0 == padResult)
    status = OK;

#endif    /* __ENABLE_DIGICERT_PKCS11_CRYPTO__ */

exit:
#ifndef __ENABLE_DIGICERT_PKCS11_CRYPTO__
  VLONG_freeVlong(&pPkcs1, ppVlongQueue);
  VLONG_freeVlong(&pEncrypted, ppVlongQueue);
#endif

  FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
  return status;
} /* RSA_decrypt */
#endif /* !__DISABLE_DIGICERT_RSA_DECRYPTION__ */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA_VERIFY__

extern MSTATUS
RSA_verifySignature(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey, const ubyte* cipherText,
                    ubyte* plainText, ubyte4* plainTextLen, vlong **ppVlongQueue)
{
  /* decrypt the cipherText using PKCS#1 scheme */
  FIPS_LOG_DECL_SESSION;
  sbyte4  keyLen;
  sbyte4  i;
  vlong*  pPkcs1     = NULL;
  vlong*  pEncrypted = NULL;
  sbyte4  realLen     = 0;
  ubyte4  vfyResult;
  MSTATUS status = OK;

  FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
  FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

  if ((NULL == pKey) || (NULL == plainText) || (NULL == cipherText) || (NULL == plainTextLen))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  if (OK > (status = VLONG_byteStringFromVlong(RSA_N(pKey), NULL, &keyLen)))
    goto exit;

  if (MOCANA_MAX_MODULUS_SIZE < keyLen)
  {
    status = ERR_RSA_INVALID_MODULUS;
    goto exit;
  }

  if (!RSA_E(pKey))
  {
    status = ERR_RSA_INVALID_EXPONENT;
    goto exit;
  }

  if (OK > (status = VLONG_vlongFromByteString(cipherText, keyLen, &pEncrypted, ppVlongQueue)))
    goto exit;

  if (OK > (status = RSAINT_encrypt(MOC_RSA(hwAccelCtx) pKey, pEncrypted, &pPkcs1, ppVlongQueue)))
    goto exit;

  if (OK > (status = VLONG_byteStringFromVlong(pPkcs1, plainText, &keyLen)))
    goto exit;

  /* Set vfyResult to 0, meaning there have been no errors in verifying the
   * signature.
   * Each time we encounter an error, add to vfyResult. At the end, if
   * vfyResult is not 0, then set status to ERR_RSA_DECRYPTION.
   * We want to make all checks and not stop as soon as we hit an error.
   */
  vfyResult = 0;

  /* plaintext contains actually the whole pkcs1 */

  /* note VLONG_byteStringFromVlong did not alter keyLen so
     plainText should start 0x00 0x01 ...
   */
  if ((plainText[0] != 0) || (plainText[1] != 1))
    vfyResult++;

  /* scan until the first 0 byte
   * In addition, check to make sure all the pad bytes are 0xFF. */
  for (i = 2; i < keyLen; ++i)
  {
    if (0 == plainText[i])
      break;

    if (0xff != plainText[i])
      vfyResult++;
  }

  /* There must be at least 11 bytes of pad. That includes the leading 00 01
   * bytes and the 00 byte indicating end of pad.
   * Hence, the index of the 00 byte must be at least 10.
   */
  /*    0    1    2    3    4    5    6    7    8    9    10 */
  /*    0    1    1    2    3    4    5    6    7    8    0 */
  if (10 > i)
    vfyResult++;

  /* There must have been a 0x00 byte after the 0xff padding */
  if (keyLen == i)
    vfyResult++;
    
  /* Move the data after the pad bytes to the front of the buffer as the return.
   */
  for (++i; i < keyLen; ++i, ++realLen)
  {
    plainText[realLen] = plainText[i];
  }

  *plainTextLen = realLen;

  status = ERR_RSA_DECRYPTION;
  if (0 == vfyResult)
    status = OK;

exit:
  VLONG_freeVlong(&pPkcs1, ppVlongQueue);
  VLONG_freeVlong(&pEncrypted, ppVlongQueue);

  FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
  return status;
} /* RSA_verifySignature */

#endif /* __DISABLE_DIGICERT_RSA_VERIFY_CERTIFICATE__ */


/*------------------------------------------------------------------*/
/* added __RSAINT_HARDWARE__ */
#if !defined( __DISABLE_DIGICERT_RSA_SIGN__) && !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__) && !defined(__ENABLE_DIGICERT_PKCS11_CRYPTO__)

extern MSTATUS
RSA_signMessage(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
                const ubyte* plainText, ubyte4 plainTextLen,
                ubyte* cipherText, vlong **ppVlongQueue)
{
    /* encrypt the plainText using PKCS#1 scheme */
    FIPS_LOG_DECL_SESSION;
    vlong*  pPkcs1      = NULL;
    vlong*  pEncrypted  = NULL;
    vlong*  pVerify     = NULL;
    sbyte4  keyLen;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

    if ((NULL == pKey) || (NULL == plainText) || (NULL == cipherText))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    
    if (FALSE == pKey->privateKey)
    {
        status = ERR_RSA_INVALID_KEY;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
    /* If the RSA key is generated by a security module, we will find the key length in
       the RSA key's signCallback */
    if(pKey->hsmInfo)
    {
        ubyte* pSignature = NULL;
        ubyte4 signedLen;

        if(OK > (status = HSMRSAINFO_signMessage(pKey, plainText, plainTextLen, &pSignature, &signedLen)))
        {
            goto exit;
        }

        if(NULL != pSignature)
        {
            DIGI_MEMCPY(cipherText, pSignature, signedLen);
            HSMRSAINFO_freeData(&pSignature);
        }

        /* note: signedLen should equal keyLen, or something went wrong */

        goto exit;
    }
#endif

    if (OK > (status = VLONG_byteStringFromVlong(RSA_N(pKey), NULL, &keyLen)))
        goto exit;


#ifndef __ENABLE_DIGICERT_RSA_ALL_KEYSIZE__
    /* if the key is not 2048 or 3072 bits long, fail */
    if((256 != keyLen) && (384 != keyLen))
    {
        status = ERR_RSA_UNSUPPORTED_KEY_LENGTH;
        goto exit;
    }
#endif

    if (keyLen < (sbyte4) (plainTextLen+3+8)) /* padding must be at least 8 chars long */
    {
        status = ERR_RSA_INVALID_KEY;
        goto exit;
    }

    cipherText[0] = 0;
    cipherText[1] = 1;

    DIGI_MEMSET(cipherText + 2, 0xff, (keyLen - 3) - plainTextLen);

    cipherText[(keyLen - plainTextLen) - 1] = 0;

    DIGI_MEMCPY((cipherText + keyLen) - plainTextLen, plainText, plainTextLen);



    if (OK > (status = VLONG_vlongFromByteString(cipherText, keyLen, &pPkcs1, ppVlongQueue)))
        goto exit;

    if (OK > (status = RSAINT_decrypt(MOC_RSA(hwAccelCtx) pKey, pPkcs1, NULL, NULL, &pEncrypted, ppVlongQueue)))
        goto exit;

#ifdef __ENABLE_DIGICERT_VERIFY_RSA_SIGNATURE__
    /* verify the signature -- note that this will significantly decrease the performance (about 25 %) */
    if ( OK > ( status = RSAINT_encrypt( MOC_RSA(hwAccelCtx) pKey, pEncrypted, &pVerify, ppVlongQueue)))
        goto exit;

    if ( VLONG_compareSignedVlongs( pPkcs1, pVerify) )
    {
        VLONG_freeVlong(&pEncrypted, ppVlongQueue);
        /* RSA-CRT failed because of a random or hardware error --- don't send back wrong result since it
            allows to recover the private key cf. http://theory.stanford.edu/~dabo/papers/faults.ps.gz */
        if ( OK > ( status = RSAINT_decryptLong( MOC_MOD(hwAccelCtx) pKey, pPkcs1, &pEncrypted, ppVlongQueue)))
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__
    /* If constant time code calculated pEncrypted then it will have numUnitsUsed the full length */
    if (((ubyte4) keyLen + sizeof(vlong_unit) - 1)/sizeof(vlong_unit) <= pEncrypted->numUnitsUsed)
    {
        /* VLONG_fixedByteStringFromVlong is constant time when numUnitsUsed is the full length */
        if (OK > (status = VLONG_fixedByteStringFromVlong (pEncrypted, cipherText, keyLen)))
            goto exit;
    }
    else
#endif
    {
        if (OK > (status = VLONG_byteStringFromVlong(pEncrypted, cipherText, &keyLen)))
            goto exit;
    }

exit:

    VLONG_freeVlong(&pEncrypted, ppVlongQueue);
    VLONG_freeVlong(&pPkcs1, ppVlongQueue);
    VLONG_freeVlong(&pVerify, ppVlongQueue);

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
    return status;

} /* RSA_signMessage */

#endif /* __DISABLE_DIGICERT_RSA_SIGN__  __DISABLE_DIGICERT_RSA_DECRYPTION__ */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_RSA_SIGN_DATA__

#define SEQ_FIRST_BYTE 0x30
#define OID_FIRST_BYTE 0x06
#define OCTSTR_FIRST_BYTE 0x04

#define MD2_LAST_BYTE 0x02
#define MD4_LAST_BYTE 0x04
#define MD5_LAST_BYTE 0x05
#define SHA224_LAST_BYTE 0x04
#define SHA256_LAST_BYTE 0x01
#define SHA384_LAST_BYTE 0x02
#define SHA512_LAST_BYTE 0x03
#define SHA3_224_LAST_BYTE 0x07
#define SHA3_256_LAST_BYTE 0x08
#define SHA3_384_LAST_BYTE 0x09
#define SHA3_512_LAST_BYTE 0x0a
#define SHAKE128_LAST_BYTE 0x0b
#define SHAKE256_LAST_BYTE 0x0c
#define ALG_ID_PENULT 0x05
#define ALG_ID_ULT 0x00

/* Encode this
*   0x30 len
*      0x30 0x06 len oid 0x05 0x00
*      0x04 len
*         < digest >
*  or 0x30 <len> 0x30 <len> 0x06 <len> <md_oid> 0x05 0x00 0x04 <len> <md>
*  which has to level length (ie the length after the first 0x30)
*/
#define MD_TOTAL_LEN 34
#define SHA1_TOTAL_LEN 35
#define SHA224_TOTAL_LEN 47
#define SHA256_TOTAL_LEN 51
#define SHA384_TOTAL_LEN 67
#define SHA512_TOTAL_LEN 83
/* sha3 oid same length as sha2, so total lengths match based on output length */
#define SHA3_224_TOTAL_LEN SHA224_TOTAL_LEN
#define SHA3_256_TOTAL_LEN SHA256_TOTAL_LEN
#define SHA3_384_TOTAL_LEN SHA384_TOTAL_LEN
#define SHA3_512_TOTAL_LEN SHA512_TOTAL_LEN
#define SHAKE128_TOTAL_LEN SHA256_TOTAL_LEN
#define SHAKE256_TOTAL_LEN SHA512_TOTAL_LEN

/* from parse asn1, common sections of the OIDs that we'll use, first byte is total oid len */
static ubyte gpMdOidMain[8] = {0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02};
static ubyte gpSha1Oid[6] = {0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A};
static ubyte gpSha2OidMain[9] = {0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02};

/*------------------------------------------------------------------*/

static MSTATUS RSA_getDigestInfoLens(ubyte hashId, ubyte4 *pTotalLen, ubyte4 *pDigestLen)
{
    /* internal method, NULL checks not necc */
    switch(hashId)
    {
#ifdef __ENABLE_DIGICERT_MD2__
        case md2withRSAEncryption:
#endif
#ifdef __ENABLE_DIGICERT_MD4__
        case md4withRSAEncryption:
#endif
        case md5withRSAEncryption:
            *pDigestLen = MD5_RESULT_SIZE; /* 16, same for all MDs */
            *pTotalLen = MD_TOTAL_LEN;
            break;

        case sha1withRSAEncryption:
            *pDigestLen = SHA1_RESULT_SIZE;
            *pTotalLen = SHA1_TOTAL_LEN;
            break;

#ifndef __DISABLE_DIGICERT_SHA256__
        case sha256withRSAEncryption:
            *pDigestLen = SHA256_RESULT_SIZE;
            *pTotalLen = SHA256_TOTAL_LEN;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
        case sha384withRSAEncryption:
            *pDigestLen = SHA384_RESULT_SIZE;
            *pTotalLen = SHA384_TOTAL_LEN;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case sha512withRSAEncryption:
            *pDigestLen = SHA512_RESULT_SIZE;
            *pTotalLen = SHA512_TOTAL_LEN;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA224__
        case sha224withRSAEncryption:
            *pDigestLen = SHA224_RESULT_SIZE;
            *pTotalLen = SHA224_TOTAL_LEN;
            break;
#endif

#ifdef __ENABLE_DIGICERT_SHA3__
        case ht_sha3_224:
            *pDigestLen = SHA3_224_RESULT_SIZE;
            *pTotalLen = SHA3_224_TOTAL_LEN;
            break;

        case ht_sha3_256:
            *pDigestLen = SHA3_256_RESULT_SIZE;
            *pTotalLen = SHA3_256_TOTAL_LEN;
            break;

        case ht_sha3_384:
            *pDigestLen = SHA3_384_RESULT_SIZE;
            *pTotalLen = SHA3_384_TOTAL_LEN;
            break;

        case ht_sha3_512:
            *pDigestLen = SHA3_512_RESULT_SIZE;
            *pTotalLen = SHA3_512_TOTAL_LEN;
            break;

        case ht_shake128:
            *pDigestLen = SHAKE128_RESULT_SIZE;
            *pTotalLen = SHAKE128_TOTAL_LEN;
            break;

        case ht_shake256:
            *pDigestLen = SHAKE256_RESULT_SIZE;
            *pTotalLen = SHAKE256_TOTAL_LEN;
            break;
#endif
        
        default:
            return ERR_INVALID_INPUT;
    }

    return OK;
}

/*------------------------------------------------------------------*/

static MSTATUS RSA_makeDigestInfo(
    ubyte hashId,
    ubyte **ppDigestInfo,
    ubyte4 *pDigestInfoLen, 
    ubyte **ppDigestStart)
{
    MSTATUS status = OK;

    ubyte *pDigestInfo = NULL;
    ubyte *pDigestInfoPtr = NULL;
    ubyte4 digestLen = 0;
    ubyte4 totalLen = 0;

    status = RSA_getDigestInfoLens(hashId, &totalLen, &digestLen);
    if (OK != status)
        goto exit;

    /* allocate, leave room for the first 0x30 and first length byte */
    status = DIGI_MALLOC((void **) &pDigestInfo, totalLen);
    if (OK != status)
        goto exit;

    pDigestInfo[0] = SEQ_FIRST_BYTE;
    pDigestInfo[1] = (ubyte) (totalLen - 2); /* 85 at most (< 128) so single byte is sufficient */
    pDigestInfo[2] = SEQ_FIRST_BYTE;
    /* pDigestInfo[3] oid length plus extra 0x00 0x05 bytes filled in later */
    pDigestInfo[4] = OID_FIRST_BYTE;

    pDigestInfoPtr = pDigestInfo + 5;

    switch(hashId)
    {
#ifdef __ENABLE_DIGICERT_MD2__
        case md2withRSAEncryption:
#endif
#ifdef __ENABLE_DIGICERT_MD4__
        case md4withRSAEncryption:
#endif
        case md5withRSAEncryption:
            pDigestInfo[3] = (ubyte) (gpMdOidMain[0] + 4);
            status = DIGI_MEMCPY(pDigestInfoPtr, gpMdOidMain, sizeof(gpMdOidMain));
            if (OK != status)
                goto exit;

            pDigestInfoPtr += sizeof(gpMdOidMain);
#ifdef __ENABLE_DIGICERT_MD2__
            if (md2withRSAEncryption == hashId)
                *pDigestInfoPtr = MD2_LAST_BYTE;
#endif
#ifdef __ENABLE_DIGICERT_MD4__
            if (md4withRSAEncryption == hashId)
                *pDigestInfoPtr = MD4_LAST_BYTE;
#endif
            if (md5withRSAEncryption == hashId)
                *pDigestInfoPtr = MD5_LAST_BYTE;
                
            pDigestInfoPtr++;
            break;

        case sha1withRSAEncryption:
            pDigestInfo[3] = (ubyte) (gpSha1Oid[0] + 4);
            status = DIGI_MEMCPY(pDigestInfoPtr, gpSha1Oid, sizeof(gpSha1Oid));
            if (OK != status)
                goto exit;

            pDigestInfoPtr += sizeof(gpSha1Oid);
            break;

#ifndef __DISABLE_DIGICERT_SHA256__
        case sha256withRSAEncryption:
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
        case sha384withRSAEncryption:
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
        case sha512withRSAEncryption:
#endif
#ifndef __DISABLE_DIGICERT_SHA224__
        case sha224withRSAEncryption:
#endif
#ifdef __ENABLE_DIGICERT_SHA3__
        case ht_sha3_224:
        case ht_sha3_256:
        case ht_sha3_384:
        case ht_sha3_512:
        case ht_shake128:
        case ht_shake256:
#endif
            pDigestInfo[3] = (ubyte) (gpSha2OidMain[0] + 4);
            status = DIGI_MEMCPY(pDigestInfoPtr, gpSha2OidMain, sizeof(gpSha2OidMain));
            if (OK != status)
                goto exit;

            pDigestInfoPtr += sizeof(gpSha2OidMain);
#ifndef __DISABLE_DIGICERT_SHA256__
            if (sha256withRSAEncryption == hashId)
                *pDigestInfoPtr = SHA256_LAST_BYTE;
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
            if (sha384withRSAEncryption == hashId)
                *pDigestInfoPtr = SHA384_LAST_BYTE;
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
            if (sha512withRSAEncryption == hashId)
                *pDigestInfoPtr = SHA512_LAST_BYTE;
#endif
#ifndef __DISABLE_DIGICERT_SHA224__
            if (sha224withRSAEncryption == hashId)
                *pDigestInfoPtr = SHA224_LAST_BYTE;
#endif
#ifdef __ENABLE_DIGICERT_SHA3__
            if (ht_sha3_224 == hashId)
                *pDigestInfoPtr = SHA3_224_LAST_BYTE;
            if (ht_sha3_256 == hashId)
                *pDigestInfoPtr = SHA3_256_LAST_BYTE;
            if (ht_sha3_384 == hashId)
                *pDigestInfoPtr = SHA3_384_LAST_BYTE;
            if (ht_sha3_512 == hashId)
                *pDigestInfoPtr = SHA3_512_LAST_BYTE;
            if (ht_shake128 == hashId)
                *pDigestInfoPtr = SHAKE128_LAST_BYTE;
            if (ht_shake256 == hashId)
                *pDigestInfoPtr = SHAKE256_LAST_BYTE;
#endif
            pDigestInfoPtr++;
            break;

        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }

    *pDigestInfoPtr = ALG_ID_PENULT;
    pDigestInfoPtr++;
    *pDigestInfoPtr = ALG_ID_ULT;
    pDigestInfoPtr++;
    *pDigestInfoPtr = OCTSTR_FIRST_BYTE;
    pDigestInfoPtr++;
    *pDigestInfoPtr = (ubyte) digestLen;

    *ppDigestInfo = pDigestInfo; pDigestInfo = NULL;
    *pDigestInfoLen = totalLen;
    
    /* we leave empty space for the digest to be placed, and return where it starts */
    *ppDigestStart = pDigestInfoPtr + 1;
 
exit:

    if (NULL != pDigestInfo)
    {
        (void) DIGI_MEMSET_FREE(&pDigestInfo, totalLen);
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS RSA_validateDigestInfo(
    ubyte hashId,
    ubyte *pDigestInfo,
    ubyte4 digestInfoLen,
    ubyte **ppDigestStart,
    ubyte4 *pDigestLen)
{
    MSTATUS status = OK;
    ubyte4 totalLen = 0;
    sbyte4 cmp = -1;
    ubyte oidLen = 0;

    /* internal method, null checks no necc */

    /* validate the lengths first */
    status = RSA_getDigestInfoLens(hashId, &totalLen, pDigestLen);
    if (OK != status)
        goto exit;

    /* Check the form of the digestInfo. Make sure nothing is after it by checking its len.
       FIPS 186-5 Sec S.4 ...
       "Only if the extracted DigestInfo has the appropriate form shall the signature 
       verification process continue." */
    status = ERR_FALSE;
    if (digestInfoLen != totalLen)
        goto exit;

    /* keep constant time, last bit means invalid, first means valid */
    if (SEQ_FIRST_BYTE != pDigestInfo[0])
        goto exit;
   
    if ((ubyte) (totalLen - 2) != pDigestInfo[1])
        goto exit;

    if (SEQ_FIRST_BYTE != pDigestInfo[2])
        goto exit;

    /* pDigestInfo[3] checked later, save it */
    oidLen = pDigestInfo[3]; 
    
    if (OID_FIRST_BYTE != pDigestInfo[4])
        goto exit;

    /* ok to move passed by value ptr */
    pDigestInfo += 5;

    switch(hashId)
    {
#ifdef __ENABLE_DIGICERT_MD2__
        case md2withRSAEncryption:
#endif
#ifdef __ENABLE_DIGICERT_MD4__
        case md4withRSAEncryption:
#endif
        case md5withRSAEncryption:
            if ((ubyte) (gpMdOidMain[0] + 4) != oidLen)
                goto exit;

            (void) DIGI_CTIME_MATCH(pDigestInfo, gpMdOidMain, sizeof(gpMdOidMain), &cmp);
            if (cmp)
                goto exit;

            pDigestInfo += sizeof(gpMdOidMain);
#ifdef __ENABLE_DIGICERT_MD2__
            if (md2withRSAEncryption == hashId && MD2_LAST_BYTE != *pDigestInfo)
                goto exit;
#endif
#ifdef __ENABLE_DIGICERT_MD4__
            if (md4withRSAEncryption == hashId && MD4_LAST_BYTE != *pDigestInfo)
                goto exit;
#endif
            if (md5withRSAEncryption == hashId && MD5_LAST_BYTE != *pDigestInfo)
                goto exit;
              
            pDigestInfo++;
            break;

        case sha1withRSAEncryption:
            if ((ubyte) (gpSha1Oid[0] + 4) != oidLen)
                goto exit;

            (void) DIGI_CTIME_MATCH(pDigestInfo, gpSha1Oid, sizeof(gpSha1Oid), &cmp);
            if (cmp)
                goto exit;

            pDigestInfo += sizeof(gpSha1Oid);
            break;

#ifndef __DISABLE_DIGICERT_SHA256__
        case sha256withRSAEncryption:
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
        case sha384withRSAEncryption:
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
        case sha512withRSAEncryption:
#endif
#ifndef __DISABLE_DIGICERT_SHA224__
        case sha224withRSAEncryption:
#endif
#ifdef __ENABLE_DIGICERT_SHA3__
        case ht_sha3_224:
        case ht_sha3_256:
        case ht_sha3_384:
        case ht_sha3_512:
        case ht_shake128:
        case ht_shake256:
#endif
            if ((ubyte) (gpSha2OidMain[0] + 4) != oidLen)
                goto exit;

            (void) DIGI_CTIME_MATCH(pDigestInfo, gpSha2OidMain, sizeof(gpSha2OidMain), &cmp);
            if (cmp)
                goto exit;

            pDigestInfo += sizeof(gpSha2OidMain);
#ifndef __DISABLE_DIGICERT_SHA256__
            if (sha256withRSAEncryption == hashId && SHA256_LAST_BYTE != *pDigestInfo)
                goto exit;
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
            if (sha384withRSAEncryption == hashId && SHA384_LAST_BYTE != *pDigestInfo)
                goto exit;
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
            if (sha512withRSAEncryption == hashId && SHA512_LAST_BYTE != *pDigestInfo)
                goto exit;
#endif
#ifndef __DISABLE_DIGICERT_SHA224__
            if (sha224withRSAEncryption == hashId && SHA224_LAST_BYTE != *pDigestInfo)
                goto exit;
#endif
#ifdef __ENABLE_DIGICERT_SHA3__
            if (ht_sha3_224 == hashId && SHA3_224_LAST_BYTE != *pDigestInfo)
                goto exit;
            if (ht_sha3_256 == hashId && SHA3_256_LAST_BYTE != *pDigestInfo)
                goto exit;
            if (ht_sha3_384 == hashId && SHA3_384_LAST_BYTE != *pDigestInfo)
                goto exit;
            if (ht_sha3_512 == hashId && SHA3_512_LAST_BYTE != *pDigestInfo)
                goto exit;
            if (ht_shake128 == hashId && SHAKE128_LAST_BYTE != *pDigestInfo)
                goto exit;
            if (ht_shake256 == hashId && SHAKE256_LAST_BYTE != *pDigestInfo)
                goto exit;
#endif
            pDigestInfo++;
            break;

        default:
            goto exit; /* status still ERR_FALSE */
    }

    if (ALG_ID_PENULT != *pDigestInfo)
        goto exit;
    
    pDigestInfo++;

    if (ALG_ID_ULT != *pDigestInfo)
        goto exit;

    pDigestInfo++;
    
    if (OCTSTR_FIRST_BYTE != *pDigestInfo)
        goto exit;

    pDigestInfo++;
    
    if ((ubyte)(*pDigestLen) != *pDigestInfo)
        goto exit;

    status = OK;
    *ppDigestStart = pDigestInfo + 1;
    /* pDigestLen already is set */

exit:
   
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS RSA_digestMessage(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    ubyte *pData,
    ubyte4 dataLen,
    ubyte hashId,
    ubyte *pDigest)
{
    MSTATUS status = ERR_NULL_POINTER;
    BulkHashAlgo *pShaSuite = NULL;
    BulkCtx pShaCtx = NULL;

    if (NULL == pData && dataLen)
        goto exit;

    if (ht_none == hashId)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    status = CRYPTO_FIPS_getRSAHashAlgo(hashId, (const BulkHashAlgo **) &pShaSuite);
#else
    status = CRYPTO_getRSAHashAlgo(hashId, (const BulkHashAlgo **) &pShaSuite);
#endif
    if (OK != status)
        goto exit;
    
    status = pShaSuite->allocFunc(MOC_HASH(hwAccelCtx) &pShaCtx);
    if (OK != status)
        goto exit;
    
    status = pShaSuite->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
    if (OK != status)
        goto exit;
    
    if (dataLen)
    {
        status = pShaSuite->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pData, dataLen);
        if (OK != status)
            goto exit;
    }
    
    status = pShaSuite->finalFunc(MOC_HASH(hwAccelCtx) pShaCtx, pDigest);

exit:

    if (NULL != pShaSuite && NULL != pShaCtx)
    {
        (void) pShaSuite->freeFunc(MOC_HASH(hwAccelCtx) &pShaCtx); 
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS RSA_signData(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    RSAKey *pKey,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte hashId,
    ubyte *pSignature,
    vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pDigestInfo = NULL;
    ubyte *pDigestStart = NULL;
    ubyte4 digestInfoLen = 0;

    if (NULL == pKey || NULL == pSignature)
        goto exit;

    status = RSA_makeDigestInfo(hashId, &pDigestInfo, &digestInfoLen, &pDigestStart);
    if (OK != status)
        goto exit;

    status = RSA_digestMessage(MOC_HASH(hwAccelCtx) pData, dataLen, hashId, pDigestStart);
    if (OK != status)
        goto exit;

    status = RSA_signMessage(MOC_RSA(hwAccelCtx) pKey, pDigestInfo, digestInfoLen,
                             pSignature, ppVlongQueue);
 
exit:

    if (NULL != pDigestInfo)
    {
        (void) DIGI_MEMSET_FREE(&pDigestInfo, digestInfoLen);
    }  

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS RSA_verifyData(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    RSAKey *pKey,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte hashId,
    ubyte *pSignature,
    ubyte4 signatureLen,
    intBoolean *pIsValid,
    vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pPlainText = NULL;
    ubyte4 plainTextLen = 0;
    ubyte *pDigestStart = NULL;
    ubyte4 digestLen = 0;
    ubyte *pOurDigest = NULL;
    sbyte4 cmp = -1;

    /* rest of input validation done by the below calls */
    if (NULL == pIsValid)
        goto exit;

    /* get the max length of the decrypted signature */
    status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pKey, (sbyte4 *) &plainTextLen);
    if (OK != status)
        goto exit;

    if (signatureLen != plainTextLen)
    {
        *pIsValid = FALSE;
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pPlainText, plainTextLen);
    if (OK != status)
        goto exit;

    status = RSA_verifySignature(MOC_RSA(hwAccelCtx) pKey, pSignature, 
                                 pPlainText, &plainTextLen, ppVlongQueue);
    if (OK != status)
        goto exit;

    /* valid comes out as 0x80 for valid digest infos */
    status = RSA_validateDigestInfo(hashId, pPlainText, plainTextLen, &pDigestStart, &digestLen);
    if (ERR_FALSE == status)
    {
        /* ERR_FALSE is a verification error, not a software error */
        *pIsValid = FALSE;
        status = OK;
        goto exit;
    }
    else if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pOurDigest, digestLen);
    if (OK != status)
        goto exit;

    status = RSA_digestMessage(MOC_HASH(hwAccelCtx) pData, dataLen, hashId, pOurDigest); 
    if (OK != status)
        goto exit;

    status = DIGI_CTIME_MATCH(pOurDigest, pDigestStart, digestLen, &cmp);
    if (OK != status)
        goto exit;

    if (cmp)
    {
        *pIsValid = FALSE;
    }
    else
    {
        *pIsValid = TRUE;
    }

exit:

    /* Free and zero the part of the plaintext we wrote to */
    if (NULL != pPlainText)
    {
        (void) DIGI_MEMSET_FREE(&pPlainText, plainTextLen);
    }

    if (NULL != pOurDigest)
    {
        (void) DIGI_MEMSET_FREE(&pOurDigest, digestLen);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_RSA_SIGN_DATA__ */

/*------------------------------------------------------------------*/

extern MSTATUS
RSA_keyFromByteString(MOC_RSA(hwAccelDescr hwAccelCtx)
                      RSAKey **ppKey, const ubyte* byteString, ubyte4 len,
                      vlong** ppVlongQueue)
{
    /* format is version + {length (4 bytes big-endian) - bytes} for each
      e, n, p, q, dP, dQ, qInv */
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    sbyte4 numVlong;
    ubyte4 partLen;
    sbyte4 i;
    RSAKey* pNewKey = 0;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

    if (!byteString || !ppKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( len < 2 )
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* support version 1 (with MontgomeryCtx) and 2 (without MontgomeryCtx) */
    if (*byteString++ > RSA_BLOB_VERSION)
    {
        status = ERR_BAD_KEY_BLOB_VERSION;
        goto exit;
    }
    len--;

    if (OK > (status = RSA_createKey( &pNewKey)))
    {
        goto exit;
    }

    pNewKey->privateKey = (*byteString++) ? TRUE : FALSE;
    len--;

    if (pNewKey->privateKey)
    {
        numVlong = NUM_RSA_VLONG;
    }
    else
    {
        numVlong = 2;
    }

    /* read each v */
    for ( i = 0; i < numVlong; ++i)
    {
        if (len < sizeof(ubyte4))
        {
            status = ERR_BAD_KEY_BLOB;
            goto exit;
        }

        partLen = ((ubyte4)byteString[0] << 24) +
            ((ubyte4)byteString[1] << 16) +
            ((ubyte4)byteString[2] << 8) +
            ((ubyte4)byteString[3]);
        byteString += 4;
        len -= 4;
        if (len < partLen)
        {
            status = ERR_BAD_KEY_BLOB;
            goto exit;
        }

        if (OK > ( status = VLONG_vlongFromByteString( byteString, partLen,
                                    pNewKey->v+i, ppVlongQueue)))
        {
            goto exit;
        }
        byteString += partLen;
        len -= partLen;
    }

    if (pNewKey->privateKey)
    {
        if (OK > (status = RSA_prepareKey(MOC_RSA(hwAccelCtx)
               pNewKey, ppVlongQueue)))
        {
            goto exit;
        }
    }

    *ppKey = pNewKey;
    pNewKey = 0;
    status = OK;

exit:

    if (pNewKey)
    {
        RSA_freeKey( &pNewKey, ppVlongQueue);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
RSA_byteStringFromKey(MOC_RSA(hwAccelDescr hwAccelCtx)
                      const RSAKey *pKey, ubyte *pBuffer, ubyte4 *pRetLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    sbyte4  i, numVlong;
    ubyte4  vlongLen[NUM_RSA_VLONG];
    ubyte4  requiredLen;

    if (!pKey || !pRetLen)
    {
        return ERR_NULL_POINTER;
    }

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

    if (OK > (status = RSA_prepareKey(MOC_MOD(hwAccelCtx) (RSAKey*) pKey, 0)))
    {
        goto exit;
    }

    if (pKey->privateKey)
    {
        numVlong = NUM_RSA_VLONG;
    }
    else
    {
        numVlong = 2;
    }

    requiredLen = 2 + (numVlong ) * sizeof(ubyte4);

    for ( i = 0; i < numVlong; ++i)
    {
        if (OK > ( status = VLONG_byteStringFromVlong(pKey->v[i], NULL, (sbyte4 *)vlongLen+i)))
        {
            goto exit;
        }
        requiredLen += vlongLen[i];
    }

    if (pBuffer)
    {
        if ( *pRetLen >= requiredLen)
        {
            *pBuffer++ = RSA_BLOB_VERSION;
            *pBuffer++ = (pKey->privateKey) ? 1 : 0;

            for ( i = 0; i < numVlong; ++i)
            {
                BIGEND32( pBuffer, vlongLen[i]);
                pBuffer += sizeof(ubyte4);

                if (OK > ( status = VLONG_byteStringFromVlong(pKey->v[i], pBuffer, (sbyte4 *)vlongLen + i)))
                {
                    goto exit;
                }
                pBuffer += vlongLen[i];
            }
        }
        else
        {
            status = ERR_BUFFER_OVERFLOW;
        }
    }
    *pRetLen = requiredLen;

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
    return status;
}

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__
static MSTATUS
increment(ubyte *pBuffer, ubyte4 bufLength)
{
    intBoolean  carry;
    MSTATUS     status = OK;

    if (NULL == pBuffer)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    do
    {
        carry = (++pBuffer[bufLength - 1]) ? FALSE : TRUE;
        bufLength--;
    }
    while ((TRUE == carry) && (bufLength));

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__
static MSTATUS
smallPrimeCycle(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte4 length,
                ubyte *pPrimeSeed, ubyte4 primeSeedLength,
                ubyte *pHashResult1,
                vlong **ppRetPrime, intBoolean *pRetFail,
                MSTATUS (*completeDigest)(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pDigestOutput),
                ubyte4 hashResultSize,
                vlong **ppVlongQueue)
{
    ubyte*      pHashResult2 = NULL;
    ubyte4      primeCandidate;
    ubyte4      primeGenCounter = 0;
    intBoolean  isPrime;
    MSTATUS     status;

    *pRetFail = TRUE;

    if (OK != (status = DIGI_MALLOC((void **)&pHashResult2, hashResultSize)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pHashResult2);

    do
    {
        if (OK > (status = completeDigest(MOC_HASH(hwAccelCtx) pPrimeSeed, primeSeedLength, pHashResult1)))
            goto exit;

        increment(pPrimeSeed, primeSeedLength);

        if (OK > (status = completeDigest(MOC_HASH(hwAccelCtx) pPrimeSeed, primeSeedLength, pHashResult2)))
            goto exit;

        increment(pPrimeSeed, primeSeedLength);
        primeGenCounter++;

        /* Hash(prime_seed) XOR Hash(prime_seed + 1) */
        primeCandidate  = pHashResult1[hashResultSize-4] ^ pHashResult2[hashResultSize-4]; primeCandidate <<= 8;
        primeCandidate |= pHashResult1[hashResultSize-3] ^ pHashResult2[hashResultSize-3]; primeCandidate <<= 8;
        primeCandidate |= pHashResult1[hashResultSize-2] ^ pHashResult2[hashResultSize-2]; primeCandidate <<= 8;
        primeCandidate |= pHashResult1[hashResultSize-1] ^ pHashResult2[hashResultSize-1];

        /* c = (2^(length-1) + (c mod 2^(length-1)) */
        primeCandidate = (1 << (length-1)) + (primeCandidate % (1 << (length-1)));

        /* set the odd low/odd bit */
        primeCandidate |= 1;

        if (OK > (status = PRIME_simpleSmallPrimeTest(primeCandidate, &isPrime)))
            goto exit;

        if (TRUE == isPrime)
        {
            if (OK > (status = VLONG_makeVlongFromUnsignedValue(primeCandidate, ppRetPrime, ppVlongQueue)))
                goto exit;

            *pRetFail = FALSE;
            goto exit;
        }
    }
    while ((4 * length) > primeGenCounter);

exit:
    DIGI_FREE((void**) &pHashResult2);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__
static MSTATUS
bigPrimeCycle(MOC_RSA(hwAccelDescr hwAccelCtx)
              ubyte4 length, ubyte *pPrimeSeed,
              const ubyte4 primeSeedLength, const ubyte4 iterations,
              vlong *C0, vlong *t,
              ubyte *pHashResult1,
              vlong **ppRetPrime, intBoolean *pRetFail,
              MSTATUS (*completeDigest)(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pDigestOutput),
              ubyte4 hashResultSize,
              vlong **ppVlongQueue)
{
    vlong*      a               = NULL;
    vlong*      a_tmp           = NULL;
    vlong*      C               = NULL;
    vlong*      C_tmp           = NULL;
    vlong*      t_tmp           = NULL;
    vlong*      _2powN          = NULL;
    vlong*      pRemainder      = NULL;
    vlong*      z               = NULL;
    vlong*      z_1             = NULL;
    vlong*      pGcd            = NULL;
    ubyte4      primeGenCounter = 0;    /* no need for an old counter */
    ubyte4      i;
    MSTATUS     status;

    *pRetFail = TRUE;

    if (OK > (status = VLONG_allocVlong(&a, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(a);

    if (OK > (status = VLONG_allocVlong(&C, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(C);

    if (OK > (status = VLONG_allocVlong(&_2powN, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(_2powN);

    if (OK > (status = VLONG_allocVlong(&pRemainder, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pRemainder);

    if (OK > (status = VLONG_allocVlong(&C_tmp, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(C_tmp);

    do
    {
        /* step 23. if (((2 * t * C0) + 1) > 2^length), then t = ceiling(2^(length-1)/ (2 * C0)) */
        /* c = (2 * t * C0) + 1 */
        if (OK > (status = VLONG_vlongSignedMultiply(C, t, C0)))
            goto exit;

        /* C = (2 * t * C0) */
        if (OK > (status = VLONG_shlVlong(C)))
            goto exit;

        /* C = (2 * t * C0) + 1 */
        if (OK > (status = VLONG_increment(C, ppVlongQueue)))
            goto exit;

        if (OK > (status = VLONG_clearVlong(_2powN)))
            goto exit;

        /*  > 2^length */
        if (OK > (status = VLONG_setVlongBit(_2powN, (length))))
            goto exit;

        /* if (((2 * t * C0) + 1) > 2^length) */
        if (VLONG_compareSignedVlongs(C, _2powN) > 0)
        {
            /* then t = ceiling(2^(length-1)/ (2 * C0)) */
            if (OK > (status = VLONG_copySignedValue(C_tmp, C0)))
                goto exit;

            /* C_tmp = 2 * C0*/
            if (OK > (status = VLONG_shlVlong(C_tmp)))
                goto exit;

            if (OK > (status = VLONG_clearVlong(_2powN)))
                goto exit;

            /* 2^(length-1) */
            if (OK > (status = VLONG_setVlongBit(_2powN, (length-1))))
                goto exit;

            /* t = 2^(length-1)/ (2 * C0) */
            if (OK > (status = VLONG_unsignedDivide(t, _2powN, C_tmp, pRemainder, ppVlongQueue)))
                goto exit;

            /* ceiling() */
            if (FALSE == VLONG_isVlongZero(pRemainder))
                if (OK > (status = VLONG_increment(t, ppVlongQueue)))
                    goto exit;

            if (OK > (status = VLONG_vlongSignedMultiply(C, t, C0)))
                goto exit;

            if (OK > (status = VLONG_shlVlong(C)))
                goto exit;

            if (OK > (status = VLONG_increment(C, ppVlongQueue)))
                goto exit;
        }

        /* prime_gen_counter++ */
        primeGenCounter++;

        /* a = 0 */
        if (OK > (status = VLONG_clearVlong(a)))
            goto exit;

        /* for i = 0 to iterations do (MUST BE <=, so we ensure one minimum iteration) */
        for (i = 0; i <= iterations; i++)
        {
            /* a = a + (Hash(prime_seed + i) * 2^(i*outlen) */
            if (OK > (status = completeDigest(MOC_HASH(hwAccelCtx) pPrimeSeed, primeSeedLength, pHashResult1)))
                goto exit;

            increment(pPrimeSeed, primeSeedLength);

            VLONG_freeVlong(&a_tmp, ppVlongQueue);
            if (OK > (status = VLONG_vlongFromByteString(pHashResult1, hashResultSize, &a_tmp, ppVlongQueue)))
                goto exit;

            DEBUG_RELABEL_MEMORY(a_tmp);

            if (OK > (status = VLONG_shlXvlong(a_tmp, (i * 8 * hashResultSize))))
                goto exit;

            if (OK > (status = VLONG_addSignedVlongs(a, a_tmp, ppVlongQueue)))
                goto exit;
        }

        /* a = 2 + (a mod (c-3)) */
        if (OK > (status = VLONG_copySignedValue(a_tmp, a)))
            goto exit;

        if (OK > (status = VLONG_copySignedValue(C_tmp, C)))
            goto exit;

        if (OK > (status = VLONG_subtractImmediate(C_tmp, 3, ppVlongQueue)))
            goto exit;

        VLONG_freeVlong(&a, ppVlongQueue);
        if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) a_tmp, C_tmp, &a, ppVlongQueue)))
            goto exit;

        DEBUG_RELABEL_MEMORY(a);

        if (OK > (status = VLONG_addImmediate(a, 2, ppVlongQueue)))
            goto exit;

        /* z = a^(2 * t) mod c */
        VLONG_freeVlong(&t_tmp, ppVlongQueue);
        if (OK > (status = VLONG_makeVlongFromVlong(t, &t_tmp, ppVlongQueue)))
            goto exit;

        DEBUG_RELABEL_MEMORY(t_tmp);

        if (OK > (status = VLONG_shlVlong(t_tmp)))
            goto exit;

        VLONG_freeVlong(&z, ppVlongQueue);
        if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) a, t_tmp, C, &z, ppVlongQueue)))
            goto exit;

        DEBUG_RELABEL_MEMORY(z);

        VLONG_freeVlong(&z_1, ppVlongQueue);
        if (OK > (status = VLONG_makeVlongFromVlong(z, &z_1, ppVlongQueue)))
            goto exit;

        DEBUG_RELABEL_MEMORY(z_1);

        /* z-1 */
        if (OK > (status = VLONG_decrement(z_1, ppVlongQueue)))
            goto exit;

        /* if ((1 == gcd(z-1,c)) and (1 == z^C0 mod c)), then prime = c, return SUCCESS */
        /* gcd(z-1,c) */
        VLONG_freeVlong(&pGcd, ppVlongQueue);
        if (OK > (status = VLONG_greatestCommonDenominator(MOC_MOD(hwAccelCtx) z_1, C, &pGcd, ppVlongQueue)))
            goto exit;

        DEBUG_RELABEL_MEMORY(pGcd);

        if (0 == VLONG_compareUnsigned(pGcd, 1) )
        {
            /* z^C0 mod c*/
            VLONG_freeVlong(&pRemainder, ppVlongQueue);
            if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) z, C0, C, &pRemainder, ppVlongQueue)))
                goto exit;

            DEBUG_RELABEL_MEMORY(pRemainder);

            /* if ((1 == gcd(z-1,c)) and (1 == z^C0 mod c)), then prime = c, return SUCCESS */
            if (0 == VLONG_compareUnsigned(pRemainder, 1))
            {
                /* C is prime! */
                *ppRetPrime = C;
                C = NULL;
                *pRetFail = FALSE;
                goto exit;
            }
        }

        /* t++ */
        if (OK > (status = VLONG_increment(t, ppVlongQueue)))
            goto exit;

        /* goto to step 23 */
    }
    while ((4 * length) > primeGenCounter);

    *pRetFail = TRUE;

exit:
    VLONG_freeVlong(&a, ppVlongQueue);
    VLONG_freeVlong(&a_tmp, ppVlongQueue);
    VLONG_freeVlong(&C, ppVlongQueue);
    VLONG_freeVlong(&C_tmp, ppVlongQueue);
    VLONG_freeVlong(&t_tmp, ppVlongQueue);
    VLONG_freeVlong(&_2powN, ppVlongQueue);
    VLONG_freeVlong(&pRemainder, ppVlongQueue);
    VLONG_freeVlong(&z, ppVlongQueue);
    VLONG_freeVlong(&z_1, ppVlongQueue);
    VLONG_freeVlong(&pGcd, ppVlongQueue);

    return status;

} /* bigPrimeCycle */
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__
static MSTATUS
shaweTaylor(MOC_RSA(hwAccelDescr hwAccelCtx) ubyte4 length,
            ubyte *pInputSeed, const ubyte4 inputSeedLength,
            intBoolean *pRetFail, vlong **ppRetPrime, ubyte *pRetSeed,
            MSTATUS (*completeDigest)(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pDigestOutput),
            ubyte4 hashResultSize,
            vlong **ppVlongQueue)
{
    ubyte*      pPrimeSeed   = NULL;
    ubyte*      pHashResult1 = NULL;
    vlong*      C0           = NULL;
    vlong*      C_tmp        = NULL;
    vlong*      x            = NULL;
    vlong*      x_tmp        = NULL;
    vlong*      t            = NULL;
    vlong*      pRemainder   = NULL;
    ubyte4      iterations;
    ubyte4      i;
    MSTATUS     status;

    if (2 > length)
    {
        status = ERR_RSA_KEY_LENGTH_TOO_SMALL;
        goto exit;
    }

    if (OK != (status = DIGI_MALLOC((void **)&pPrimeSeed, inputSeedLength)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pPrimeSeed);

    if (OK > (status = DIGI_MEMCPY(pPrimeSeed, pInputSeed, inputSeedLength)))
        goto exit;

    if (OK != (status = DIGI_MALLOC((void **)&pHashResult1, hashResultSize)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pHashResult1);

    if (33 > length)
    {
        if (OK > (status = smallPrimeCycle(MOC_HASH(hwAccelCtx) length,
                                           pPrimeSeed, inputSeedLength, pHashResult1,
                                           ppRetPrime, pRetFail, completeDigest,
                                           hashResultSize, ppVlongQueue)))
        {
            goto exit;
        }

        status = DIGI_MEMCPY(pRetSeed, pPrimeSeed, inputSeedLength);

        /* under all circumstances we are going to exit */
        goto exit;
    }

    if (OK > (status = shaweTaylor(MOC_RSA(hwAccelCtx) (1 + (length&1) + (length/2)),
                                   pInputSeed, inputSeedLength, pRetFail, &C0,
                                   pPrimeSeed, completeDigest, hashResultSize, ppVlongQueue)))
    {
        goto exit;
    }

    /* not an error, but need to try new input seed */
    if (TRUE == *pRetFail)
        goto exit;

    if (OK > (status = VLONG_makeVlongFromUnsignedValue(0, &x, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(x);

    if (OK > (status = VLONG_allocVlong(&C_tmp, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(C_tmp);

    if (OK > (status = VLONG_allocVlong(&pRemainder, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pRemainder);

    if (OK > (status = VLONG_allocVlong(&t, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(t);

    /* iterations roundup(length/hashsize) - 1 */
    iterations  = (length % (8 * hashResultSize)) ? 1 : 0;
    iterations += (length / (8 * hashResultSize));
    iterations -= 1;

    /* x = 0 */
    if (OK > (status = VLONG_clearVlong(x)))
        goto exit;

    /* for i = 0 to iterations do (MUST BE <=, so we ensure one minimum iteration) */
    for (i = 0; i <= iterations; i++)
    {
        /* x = x + (Hash(prime_seed + i) * 2^(i*outlen) */
        if (OK > (status = completeDigest(MOC_HASH(hwAccelCtx) pPrimeSeed, inputSeedLength, pHashResult1)))
            goto exit;

        increment(pPrimeSeed, inputSeedLength);

        VLONG_freeVlong(&x_tmp, ppVlongQueue);
        if (OK > (status = VLONG_vlongFromByteString(pHashResult1, hashResultSize, &x_tmp, ppVlongQueue)))
            goto exit;

        DEBUG_RELABEL_MEMORY(x_tmp);

        if (OK > (status = VLONG_shlXvlong(x_tmp, (i * 8 * hashResultSize))))
            goto exit;

        if (OK > (status = VLONG_addSignedVlongs(x, x_tmp, ppVlongQueue)))
            goto exit;
    }

    /* x = 2^(length-1) + (x mod 2^(length-1)) */
    if (OK > (status = VLONG_N_mod_2powX(x, length-1)))
        goto exit;

    if (OK > (status = VLONG_setVlongBit(x, length-1)))
        goto exit;

    /* t = ceiling(x / (2 * C0)) */
    if (OK > (status = VLONG_copySignedValue(C_tmp, C0)))
        goto exit;

    /* C_tmp = (2 * C0) */
    if (OK > (status = VLONG_shlVlong(C_tmp)))
        goto exit;

    if (OK > (status = VLONG_unsignedDivide(t, x, C_tmp, pRemainder, ppVlongQueue)))
        goto exit;

    /* ceiling() */
    if (FALSE == VLONG_isVlongZero(pRemainder))
    {
        if (OK > (status = VLONG_increment(t, ppVlongQueue)))
            goto exit;
    }
    
    if (OK > (status = bigPrimeCycle(MOC_RSA(hwAccelCtx) length,
                                     pPrimeSeed, inputSeedLength, iterations,
                                     C0, t, pHashResult1, ppRetPrime, pRetFail,
                                     completeDigest, hashResultSize, ppVlongQueue)))
    {
        goto exit;
    }

    status = DIGI_MEMCPY(pRetSeed, pPrimeSeed, inputSeedLength);

exit:
    VLONG_freeVlong(&C0, ppVlongQueue);
    VLONG_freeVlong(&C_tmp, ppVlongQueue);
    VLONG_freeVlong(&x, ppVlongQueue);
    VLONG_freeVlong(&x_tmp, ppVlongQueue);
    VLONG_freeVlong(&t, ppVlongQueue);
    VLONG_freeVlong(&pRemainder, ppVlongQueue);
    DIGI_FREE((void**) &pHashResult1);
    DIGI_FREE((void**) &pPrimeSeed);

    return status;

} /* shaweTaylor */
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__
static MSTATUS
make2PowNSqrt2(ubyte4 nLen, vlong **pRet2PowNSqrt2, vlong **ppVlongQueue)
{
    /* returns (2^N) * sqrt(2) */
    vlong*  pTwoPowN  = NULL;
    vlong*  pXTwoPowN = NULL;
    vlong*  pFactor   = NULL;
    vlong*  pDivisor  = NULL;
    ubyte4  bytesConsumed;
    MSTATUS status;

    if (OK > (status = VLONG_newFromMpintBytes(sqrRootOf2factor, sizeof(sqrRootOf2factor), &pFactor, &bytesConsumed, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_newFromMpintBytes(sqrRootOf2divisor, sizeof(sqrRootOf2divisor), &pDivisor, &bytesConsumed, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_allocVlong(&pXTwoPowN, ppVlongQueue)))
        goto exit;

    /* make 2^n */
    if (OK > (status = VLONG_allocVlong(&pTwoPowN, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_setVlongBit(pTwoPowN, nLen)))
        goto exit;

    /* 2^n * fixedpoint sqrt(2) */
    if (OK > (status = VLONG_vlongSignedMultiply(pXTwoPowN, pTwoPowN, pFactor)))
        goto exit;

    /* 2^n * fixedpoint sqrt(2) / adjust fixedpoint */
    if (OK > (status = VLONG_operatorDivideSignedVlongs(pXTwoPowN, pDivisor, pRet2PowNSqrt2, ppVlongQueue)))
        goto exit;

exit:
    VLONG_freeVlong(&pTwoPowN, ppVlongQueue);
    VLONG_freeVlong(&pXTwoPowN, ppVlongQueue);
    VLONG_freeVlong(&pDivisor, ppVlongQueue);
    VLONG_freeVlong(&pFactor, ppVlongQueue);

    return status;

} /* make2PowNSqrt2 */
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__
static MSTATUS
compute_XY(MOC_MOD(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
           const vlong *R, const vlong *r1, const vlong *r2, const vlong *_2r1,
           ubyte4 nLen, const vlong *_2PowNSqrt2, const vlong *pDebugX,
           vlong **ppRetX, vlong **ppRetY, vlong **ppVlongQueue)
{
    vlong*      X           = NULL;
    vlong*      Y           = NULL;
    vlong*      R_X         = NULL;     /* R-X */
    vlong*      _2r1r2      = NULL;     /* 2r1r2 */
    intBoolean  isStrongEnough;
    MSTATUS     status;
    MOC_UNUSED(r1);

    do
    {
        /* step 3 */
        isStrongEnough = FALSE;

        do
        {
            VLONG_freeVlong(&X, ppVlongQueue);

            if (NULL == pDebugX)
            {
                /* generate a random X */
                if (OK > (status = VLONG_makeRandomVlong(pRandomContext, &X, nLen/2, ppVlongQueue)))
                    goto exit;
            }
            else
            {
                /* hardwired X */
                if (OK > (status = VLONG_makeVlongFromVlong(pDebugX, &X, ppVlongQueue)))
                    goto exit;
            }

            DEBUG_RELABEL_MEMORY(X);

            /* X must be greater than (2^n * sqrt(2)) */
            if (1 == VLONG_compareSignedVlongs(X, _2PowNSqrt2))
                isStrongEnough = TRUE;
        }
        while (FALSE == isStrongEnough);

        /* Compute: Y = X + ((R - X) mod 2r1r2) */
        if (OK > (status = VLONG_allocVlong(&_2r1r2, ppVlongQueue)))
            goto exit;

        DEBUG_RELABEL_MEMORY(_2r1r2);

        /* 2r1r2 */
        if (OK > (status = VLONG_vlongSignedMultiply(_2r1r2, _2r1, r2)))
            goto exit;

        /* R_X = R */
        VLONG_freeVlong(&R_X, ppVlongQueue);
        if (OK > (status = VLONG_makeVlongFromVlong(R, &R_X, ppVlongQueue)))
            goto exit;

        DEBUG_RELABEL_MEMORY(R_X);

        /* R_X = R-X */
        if (OK > (status = VLONG_subtractSignedVlongs(R_X, X, ppVlongQueue)))
            goto exit;

        /* (R-X) mod 2r1r2 */
        VLONG_freeVlong(&Y, ppVlongQueue);
        if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) R_X, _2r1r2, &Y, ppVlongQueue)))
            goto exit;

        DEBUG_RELABEL_MEMORY(Y);

        /* Y = X + ((R-X) mod 2r1r2) */
        if (OK > (status = VLONG_addSignedVlongs(Y, X, ppVlongQueue)))
            goto exit;
    }
    while (VLONG_bitLength(Y) >= (1 + (nLen/2)));

    *ppRetY = Y;
    Y = NULL;
    *ppRetX = X;
    X = NULL;

exit:
    VLONG_freeVlong(&X, ppVlongQueue);
    VLONG_freeVlong(&Y, ppVlongQueue);
    VLONG_freeVlong(&R_X, ppVlongQueue);
    VLONG_freeVlong(&_2r1r2, ppVlongQueue);

    return status;

} /* compute_XY */
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__
static MSTATUS
primeSearch(MOC_MOD(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
            const vlong *X, vlong *Y, ubyte4 nLen, const vlong *e, const vlong *_2r1r2,
            intBoolean *pIsPrime, intBoolean *pBad_r1r2, vlong **ppVlongQueue)
{
    vlong*      pGcd        = NULL;
    vlong*      Y_1         = NULL;
    ubyte4      i;
    MSTATUS     status;

    *pIsPrime  = FALSE;
    *pBad_r1r2 = FALSE;
    i = 0;

    if (OK > (status = VLONG_allocVlong(&Y_1, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(Y_1);

    while (!(VLONG_bitLength(Y) >= (1 + (nLen/2))))
    {
        /* only primes greater than X should be considered */
        if (VLONG_compareSignedVlongs(Y, X) >= 0)
        {
            VLONG_freeVlong(&pGcd, ppVlongQueue);

            /* Y_1 = Y - 1*/
            if (OK > (status = VLONG_copySignedValue(Y_1, Y)))
                goto exit;

            if (OK > (status = VLONG_decrement(Y_1, ppVlongQueue)))
                goto exit;

            /* calculate GCD */
            if (OK > (status = VLONG_greatestCommonDenominator(MOC_MOD(hwAccelCtx) e, Y_1, &pGcd, ppVlongQueue)))
                goto exit;

            DEBUG_RELABEL_MEMORY(pGcd);

            /* if GCD(Y-1, e) is 1 */
            if (0 == VLONG_compareUnsigned(pGcd, 1))
            {
                if (OK > (status = PRIME_doPrimeTestsEx(MOC_MOD(hwAccelCtx) pRandomContext, Y, prime_RSA, pIsPrime, ppVlongQueue)))
                    goto exit;

                /* we found our prime! */
                if (TRUE == *pIsPrime)
                    break;
            }
        }

        i = i + 1;

        if ((5 * (nLen/2)) <= i)
        {
            /* no error, we need to recalculate r1 and r2 */
            *pBad_r1r2 = TRUE;
            goto exit;
        }

        /* Y = Y + (2r1r2) */
        if (OK > (status = VLONG_addSignedVlongs(Y, _2r1r2, ppVlongQueue)))
            goto exit;
    }

exit:
    VLONG_freeVlong(&pGcd, ppVlongQueue);
    VLONG_freeVlong(&Y_1, ppVlongQueue);

    return status;

} /* primeSearch */
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__
static MSTATUS
probablePrime(MOC_MOD(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
              const vlong *r1, const vlong *r2, ubyte4 nLen, const vlong *e, const vlong *pDebugX,
              intBoolean *pBad_r1r2, vlong **ppY, vlong **ppX, vlong **ppVlongQueue)
{
    vlong*      X           = NULL;
    vlong*      _2r1        = NULL;     /* 2*r1 */
    vlong*      pGcd        = NULL;     /* GCD(2r1, r2) */
    vlong*      Y           = NULL;
    vlong*      R           = NULL;     /* R = (((r2)^-1 mod 2r1) * r2) - (((2r1)^-1 mod r2)*2r1) */
    vlong*      Ry          = NULL;
    vlong*      pT1         = NULL;
    vlong*      _2r1r2      = NULL;     /* 2r1r2 */
    vlong*      _2PowNSqrt2 = NULL;
    intBoolean  isPrime     = FALSE;
    MSTATUS     status;

    /* (default) we may need to rewind */
    *pBad_r1r2 = FALSE;

    /* _2r1 r1 */
    if (OK > (status = VLONG_makeVlongFromVlong(r1, &_2r1, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(_2r1);

    /* multiply by 2 */
    if (OK > (status = VLONG_shlVlong(_2r1)))
        goto exit;

    /* calculate GCD */
    if (OK > (status = VLONG_greatestCommonDenominator(MOC_MOD(hwAccelCtx) _2r1, r2, &pGcd, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pGcd);

    /* step 1. make sure GCD(2r1,r2) is 1 */
    if (0 != VLONG_compareUnsigned(pGcd, 1))
    {
        /* no error, we need to recalculate r1 and r2 */
        *pBad_r1r2 = TRUE;
        goto exit;
    }

    /* step 2 */
    if (OK > (status = VLONG_allocVlong(&R, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(R);

    /* Compute: R = (((r2)^-1 mod 2r1) * r2) - (((2r1)^-1 mod r2)*2r1) */
    /* r2^-1 mod 2r1 */
    VLONG_freeVlong(&pT1, ppVlongQueue);
    if (OK > (status = VLONG_modularInverse(MOC_MOD(hwAccelCtx) r2, _2r1, &pT1, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pT1);

    /* R = (r2^-1 mod 2r1) * r2 */
    if (OK > (status = VLONG_vlongSignedMultiply(R, pT1, r2)))
        goto exit;

    /* free temp */
    VLONG_freeVlong(&pT1, ppVlongQueue);

    /* (2r1)^-1 mod r2 */
    if (OK > (status = VLONG_modularInverse(MOC_MOD(hwAccelCtx) _2r1, r2, &pT1, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pT1);

    if (OK > (status = VLONG_allocVlong(&Ry, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(Ry);

    /* Ry = (((2r1)^-1 mod r2)*2r1) */
    if (OK > (status = VLONG_vlongSignedMultiply(Ry, pT1, _2r1)))
        goto exit;

    /* free temp */
    VLONG_freeVlong(&pT1, ppVlongQueue);

    /* Final result: R = (p2^-1 mod p1)p2 - (p1^-1 mod p2)p1 */
    if (OK > (status = VLONG_subtractSignedVlongs(R, Ry, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_allocVlong(&_2r1r2, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(_2r1r2);

    if (OK > (status = VLONG_vlongSignedMultiply(_2r1r2, _2r1, r2)))
        goto exit;

    /* 2^n * sqrt(2) */
    if (OK > (status = make2PowNSqrt2(((nLen/2)-1), &_2PowNSqrt2, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(_2PowNSqrt2);

    while (1)
    {
        VLONG_freeVlong(&Y, ppVlongQueue);
        VLONG_freeVlong(&X, ppVlongQueue);

        if (OK > (status = compute_XY(MOC_MOD(hwAccelCtx) pRandomContext, R, r1, r2, _2r1, nLen, _2PowNSqrt2, pDebugX, &X, &Y, ppVlongQueue)))
            goto exit;

        DEBUG_RELABEL_MEMORY(X);
        DEBUG_RELABEL_MEMORY(Y);

        /* incrementally search for primes */
        if (OK > (status = primeSearch(MOC_MOD(hwAccelCtx) pRandomContext, X, Y, nLen, e, _2r1r2, &isPrime, pBad_r1r2, ppVlongQueue)))
            goto exit;

        if (TRUE == *pBad_r1r2)
        {
            /* no error, we need to recalculate r1 and r2 */
            goto exit;
        }

        if (TRUE == isPrime)
            break;
    }

    /* return Yp0 / Yq0 */
    *ppY = Y;
    Y = NULL;
    *ppX = X;
    X = NULL;

    /* we made it to the end, r1 and r2 are good */
    *pBad_r1r2 = FALSE;

exit:
    VLONG_freeVlong(&X, ppVlongQueue);
    VLONG_freeVlong(&Y, ppVlongQueue);
    VLONG_freeVlong(&_2r1, ppVlongQueue);
    VLONG_freeVlong(&pGcd, ppVlongQueue);
    VLONG_freeVlong(&_2r1r2, ppVlongQueue);
    VLONG_freeVlong(&_2PowNSqrt2, ppVlongQueue);
    VLONG_freeVlong(&Ry, ppVlongQueue);
    VLONG_freeVlong(&pT1, ppVlongQueue);
    VLONG_freeVlong(&R, ppVlongQueue);

    return status;

} /* probablePrime */

#endif /* __DISABLE_DIGICERT_KEY_GENERATION__ */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__

extern MSTATUS
RSA_generateKeyFipsSteps(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
                         ubyte4 nLen, vlong *e, const vlong *pDebugX, ubyte4 length1, ubyte4 length2,
                         vlong **ppRetP1, vlong **ppRetP2, vlong **ppRetXp, vlong **ppRetPrime,
                         ubyte *pInputSeed, ubyte4 inputSeedLength,
                         ubyte *pRetPrimeSeed1, ubyte *pRetPrimeSeed2,
                         intBoolean *pRetFail,
                         MSTATUS (*completeDigest)(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pDigestOutput),
                         ubyte4 hashResultSize,
                         vlong **ppVlongQueue)
{
    MSTATUS     status;

    *pRetFail = TRUE;

    VLONG_freeVlong(ppRetPrime, ppVlongQueue);
    VLONG_freeVlong(ppRetP2, ppVlongQueue);
    VLONG_freeVlong(ppRetP1, ppVlongQueue);
    VLONG_freeVlong(ppRetXp, ppVlongQueue);

    if (NULL != pRetPrimeSeed1)
    {
        if (OK > (status = DIGI_MEMCPY(pRetPrimeSeed1, pInputSeed, inputSeedLength)))
            goto exit;
    }

    if (OK > (status = shaweTaylor(MOC_RSA(hwAccelCtx) length1, pInputSeed, inputSeedLength, pRetFail, ppRetP1, pInputSeed, completeDigest, hashResultSize, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(*ppRetP1);

    if (TRUE == *pRetFail)
        goto exit;

    *pRetFail = TRUE;

    if (NULL != pRetPrimeSeed2)
    {
        if (OK > (status = DIGI_MEMCPY(pRetPrimeSeed2, pInputSeed, inputSeedLength)))
            goto exit;
    }

    if (OK > (status = shaweTaylor(MOC_RSA(hwAccelCtx) length2, pInputSeed, inputSeedLength, pRetFail, ppRetP2, pInputSeed, completeDigest, hashResultSize, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(*ppRetP2);

    if (TRUE == *pRetFail)
        goto exit;

    *pRetFail = TRUE;

    if (OK > (status = probablePrime(MOC_MOD(hwAccelCtx) pRandomContext, *ppRetP1, *ppRetP2, nLen, e, pDebugX, pRetFail, ppRetPrime, ppRetXp, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(*ppRetXp);
    DEBUG_RELABEL_MEMORY(*ppRetPrime);

exit:
    return status;

} /* RSA_generateKeyFipsSteps */

#endif /* __DISABLE_DIGICERT_KEY_GENERATION__ */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__
static MSTATUS
genr1r2Length(MOC_HASH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
              ubyte4 nlen, ubyte4 *pRetR1Len, ubyte4 *pRetR2Len,
              MSTATUS (*completeDigest)(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pDigestOutput),
              ubyte4 hashResultSize)
{
    ubyte*  pRngBuf = NULL;
    ubyte4  minLen;
    ubyte4  maxLen;
    ubyte4  r1Len = 0;
    ubyte4  r2Len = 0;
    MSTATUS status;

    if (OK != (status = DIGI_MALLOC((void **)&pRngBuf, hashResultSize)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pRngBuf);

    /* Updated to FIPS 186-5 table A.1 */
    if (4096 <= nlen)
    {
        minLen = 200;
        maxLen = 2030;
    }
    else if (3072 <= nlen)
    {
        minLen = 170;
        maxLen = 1518;
    }
    else if (2048 <= nlen)
    {
        minLen = 140;
        maxLen = 1007;
    }
    /* Left to support FIPS 186-4 (table B.1)*/
    else if (1024 <= nlen)
    {
        minLen = 100;
        maxLen = 496;
    }
    else
    {
        status = ERR_RSA_KEY_LENGTH_TOO_SMALL;
        goto exit;
    }

    /* generate random len */
    do
    {
        if (OK > (status = RANDOM_numberGenerator(pRandomContext, pRngBuf, hashResultSize)))
            goto exit;

        if (OK > (status = completeDigest(MOC_HASH(hwAccelCtx) pRngBuf, hashResultSize, pRngBuf)))
            goto exit;

        r1Len  = pRngBuf[0] ^ pRngBuf[hashResultSize - 1]; r1Len <<= 8;
        r1Len |= pRngBuf[1] ^ pRngBuf[hashResultSize - 2]; r1Len <<= 8;
        r1Len |= pRngBuf[2] ^ pRngBuf[hashResultSize - 3]; r1Len <<= 8;
        r1Len |= pRngBuf[3] ^ pRngBuf[hashResultSize - 4];

        r2Len  = pRngBuf[4] ^ pRngBuf[0]; r2Len <<= 8;
        r2Len |= pRngBuf[5] ^ pRngBuf[1]; r2Len <<= 8;
        r2Len |= pRngBuf[6] ^ pRngBuf[2]; r2Len <<= 8;
        r2Len |= pRngBuf[7] ^ pRngBuf[3];

        r1Len %= (maxLen - minLen + pRngBuf[8]);
        r2Len %= (maxLen - pRngBuf[9]);
    }
    while ((maxLen <= (r1Len + r2Len)) || (minLen >= r1Len) || (minLen >= r2Len));

    if (OK > (status = DIGI_MEMSET(pRngBuf, 0x00, hashResultSize)))
        goto exit;

    *pRetR1Len = r1Len;
    *pRetR2Len = r2Len;

exit:
    DIGI_FREE((void**) &pRngBuf);

    return status;
}
#endif /* __DISABLE_DIGICERT_KEY_GENERATION__ */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__
extern MSTATUS
RSA_generateKeyEx2(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
                  ubyte4 keySize, vlong *e,
                  vlong **p, vlong **q,
                  vlong **Xp, vlong **Xp1, vlong **Xp2,
                  vlong **Xq, vlong **Xq1, vlong **Xq2,
                  ubyte4 inputSeedLength,
                  ubyte *pRetPrimeSeedP1, ubyte *pRetPrimeSeedP2,
                  ubyte *pRetPrimeSeedQ1, ubyte *pRetPrimeSeedQ2,
                  vlong **ppVlongQueue)
{
    /* FIPS 186-4 B.3.5 */
    FIPS_LOG_DECL_SESSION;
    ubyte*      pInputSeed = NULL;
    vlong*      delta = NULL;
    intBoolean  isFail = TRUE;
    ubyte4      r1Len = 0;
    ubyte4      r2Len = 0;
    MSTATUS     status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,keySize);

    if (OK > (status = genr1r2Length(MOC_HASH(hwAccelCtx) pRandomContext, keySize, &r1Len, &r2Len, SHA1_completeDigest, SHA1_RESULT_SIZE)))
        goto exit;

    if (OK != (status = DIGI_MALLOC((void **)&pInputSeed, inputSeedLength)))
        goto exit;

    do
    {
        if (OK > (status = RANDOM_numberGenerator(pRandomContext, pInputSeed, inputSeedLength)))
            goto exit;

        VLONG_freeVlong(p, ppVlongQueue);
        VLONG_freeVlong(Xp2, ppVlongQueue);
        VLONG_freeVlong(Xp1, ppVlongQueue);
        VLONG_freeVlong(Xp, ppVlongQueue);

        /* do p */
        if (OK > (status = RSA_generateKeyFipsSteps(MOC_RSA(hwAccelCtx) pRandomContext,
                                                    keySize, e, NULL, r1Len, r2Len, Xp1, Xp2, Xp, p,
                                                    pInputSeed, inputSeedLength, pRetPrimeSeedP1, pRetPrimeSeedP2,
                                                    &isFail, SHA1_completeDigest, SHA1_RESULT_SIZE, ppVlongQueue)))
        {
            goto exit;
        }

        DEBUG_RELABEL_MEMORY(*p);
        DEBUG_RELABEL_MEMORY(*Xp);
        DEBUG_RELABEL_MEMORY(*Xp1);
        DEBUG_RELABEL_MEMORY(*Xp2);
    }
    while (TRUE == isFail);

    while (1)
    {
        do
        {
            if (OK > (status = genr1r2Length(MOC_HASH(hwAccelCtx) pRandomContext, keySize, &r1Len, &r2Len, SHA1_completeDigest, SHA1_RESULT_SIZE)))
                goto exit;

            /* to prevent memory leaks... */
            VLONG_freeVlong(q, ppVlongQueue);
            VLONG_freeVlong(Xq2, ppVlongQueue);
            VLONG_freeVlong(Xq1, ppVlongQueue);
            VLONG_freeVlong(Xq, ppVlongQueue);

            /* do q */
            if (OK > (status = RSA_generateKeyFipsSteps(MOC_RSA(hwAccelCtx) pRandomContext, keySize, e, NULL, r1Len, r2Len, Xq1, Xq2, Xq, q, pInputSeed, inputSeedLength, pRetPrimeSeedQ1, pRetPrimeSeedQ2, &isFail, SHA1_completeDigest, SHA1_RESULT_SIZE, ppVlongQueue)))
                goto exit;

            /* Ensure values set by the previous function have been set properly */
            if ( (NULL == q) || (NULL == Xq) || (NULL == Xq1) || (NULL == Xq2) )
            {
              status = ERR_NULL_POINTER;
              goto exit;
            }

            DEBUG_RELABEL_MEMORY(*q);
            DEBUG_RELABEL_MEMORY(*Xq);
            DEBUG_RELABEL_MEMORY(*Xq1);
            DEBUG_RELABEL_MEMORY(*Xq2);
        }
        while (TRUE == isFail);

        /* |p-q| */
        VLONG_freeVlong(&delta, ppVlongQueue);
        if (OK > (status = VLONG_makeVlongFromVlong(*p, &delta, ppVlongQueue)))
            goto exit;

        DEBUG_RELABEL_MEMORY(delta);

        if (OK > (status = VLONG_subtractSignedVlongs(delta, *q, ppVlongQueue)))
            goto exit;

        /* |p-q| <= 2^((nLen/2)-100) */
        if (!(((keySize/2)-100) <= VLONG_bitLength(delta)))
        {
            /* need to try again, delta to small to prevent Fermat style factoring attacks */
            continue;
        }

        /* |Xp-Xq| */
        if (OK > (status = VLONG_copySignedValue(delta, *Xp)))
            goto exit;

        if (OK > (status = VLONG_subtractSignedVlongs(delta, *Xq, ppVlongQueue)))
            goto exit;

        /* |Xp-Xq| <= 2^((nLen/2)-100) */
        if (!(((keySize/2)-100) <= VLONG_bitLength(delta)))
        {
            /* need to try again, delta to small to prevent Fermat style factoring attacks */
            continue;
        }

        break;
    }

exit:
    VLONG_freeVlong(&delta, ppVlongQueue);
    DIGI_FREE((void**) &pInputSeed);

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,keySize);
    return status;

} /* RSA_generateKeyEx2 */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__
static MSTATUS
RSA_generateKeyEx(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
                  RSAKey *p_rsaKey, ubyte4 keySize,
                  vlong **Xp, vlong **Xp1, vlong **Xp2,
                  vlong **Xq, vlong **Xq1, vlong **Xq2, vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    ubyte4      inputSeedLength = 64; /*in bytes*/ /* 28 */
    vlong*      n   = NULL;
    vlong*      e   = NULL;
    vlong*      delta = NULL;
    vlong*      p   = NULL;
    vlong*      q   = NULL;
    MSTATUS     status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,keySize);

    if (NULL == p_rsaKey)
    {
        status = ERR_RSA_INVALID_KEY;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_RSA_ALL_KEYSIZE__
    
    /* require key bit size to be a multiple of 128 */
    if (keySize & 0x7fUL)
    {
        status = ERR_RSA_UNSUPPORTED_KEY_LENGTH;
        goto exit;
    }

    if (1024 > keySize)
    {
        status = ERR_RSA_KEY_LENGTH_TOO_SMALL;
        goto exit;
    }
#else
    /* key size must be 2048, or 3072 */
    if ((2048 != keySize) && (3072 != keySize))
    {
        status = ERR_RSA_UNSUPPORTED_KEY_LENGTH;
        goto exit;
    }
#endif

    /* e is predefined and meets the constraints */
    if (OK > (status = VLONG_makeVlongFromUnsignedValue(PREDEFINED_E, &e, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(e);

    if (OK > (status = RSA_generateKeyEx2(MOC_RSA(hwAccelCtx) pRandomContext, keySize, e,
                                          &p, &q, Xp, Xp1, Xp2, Xq, Xq1, Xq2,
                                          inputSeedLength, NULL, NULL, NULL, NULL, ppVlongQueue)))
    {
        goto exit;
    }

    if ( (NULL == p) || (NULL == q) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* small optimization later on when using private keys */
    if (VLONG_compareSignedVlongs(p, q) < 0)
    {
        vlong *swap = p;
        p = q;
        q = swap;
    }

    DEBUG_RELABEL_MEMORY(p);
    DEBUG_RELABEL_MEMORY(q);

    /* compute n */
    if (OK > (status = VLONG_allocVlong(&n, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(n);

    if (OK > (status = VLONG_vlongSignedMultiply(n, p, q)))
        goto exit;

    /* store results */
    p_rsaKey->privateKey  = TRUE;
    RSA_N(p_rsaKey) = n;    n = NULL;
    RSA_E(p_rsaKey) = e;    e = NULL;
    RSA_P(p_rsaKey) = p;    p = NULL;
    RSA_Q(p_rsaKey) = q;    q = NULL;

    status = RSA_prepareKey(MOC_MOD(hwAccelCtx) p_rsaKey, ppVlongQueue);

exit:
    VLONG_freeVlong(&n, ppVlongQueue);
    VLONG_freeVlong(&q, ppVlongQueue);
    VLONG_freeVlong(&p, ppVlongQueue);
    VLONG_freeVlong(&delta, ppVlongQueue);
    VLONG_freeVlong(&e, ppVlongQueue);

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,keySize);
    return status;

} /* RSA_generateKeyEx */
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
RSA_generateKeyFIPS(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
                RSAKey *p_rsaKey, ubyte4 keySize, vlong **Xp, vlong **Xp1, vlong **Xp2,
                vlong **Xq, vlong **Xq1, vlong **Xq2, vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    intBoolean  isFirstTime = TRUE;
    MSTATUS     status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,keySize);

    /* to ensure we produce keys of the correct bit length */
    do
    {
        if (FALSE == isFirstTime)
        {
            RSA_clearKey(p_rsaKey, ppVlongQueue);

            VLONG_freeVlong(Xq2, ppVlongQueue);
            VLONG_freeVlong(Xq1, ppVlongQueue);
            VLONG_freeVlong(Xp2, ppVlongQueue);
            VLONG_freeVlong(Xp1, ppVlongQueue);
            VLONG_freeVlong(Xq, ppVlongQueue);
            VLONG_freeVlong(Xp, ppVlongQueue);
        }

        if (OK > (status = RSA_generateKeyEx(MOC_RSA(hwAccelCtx) pRandomContext,
                                             p_rsaKey, keySize,
                                             Xp, Xp1, Xp2, Xq, Xq1, Xq2, ppVlongQueue)))
        {
            goto exit;
        }

        isFirstTime = FALSE;
    }
    while (keySize != VLONG_bitLength(RSA_N(p_rsaKey)));

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK > (status = RSA_generateKey_FIPS_consistancy_test(MOC_RSA(hwAccelCtx) p_rsaKey)))
        goto exit;
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,keySize);
    return status;

}

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__

extern MSTATUS
RSA_generateKey(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
                RSAKey *p_rsaKey, ubyte4 keySize, vlong **ppVlongQueue)
{
    vlong*      Xp = NULL;
    vlong*      Xp1 = NULL;
    vlong*      Xp2 = NULL;
    vlong*      Xq = NULL;
    vlong*      Xq1 = NULL;
    vlong*      Xq2 = NULL;
    MSTATUS     status = OK;

#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
    if(p_rsaKey->hsmInfo)
    {
        return HSMRSAINFO_generateKey(p_rsaKey, keySize);
    }
#endif

    status = RSA_generateKeyFIPS(MOC_RSA(hwAccelCtx) pRandomContext,
                p_rsaKey, keySize, &Xp, &Xp1, &Xp2, &Xq, &Xq1, &Xq2, ppVlongQueue);

    VLONG_freeVlong(&Xq2, ppVlongQueue);
    VLONG_freeVlong(&Xq1, ppVlongQueue);
    VLONG_freeVlong(&Xp2, ppVlongQueue);
    VLONG_freeVlong(&Xp1, ppVlongQueue);
    VLONG_freeVlong(&Xq, ppVlongQueue);
    VLONG_freeVlong(&Xp, ppVlongQueue);

    return status;

} /* RSA_generateKey */
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
extern MSTATUS
RSA_generateKey_FIPS_consistancy_test(MOC_RSA(sbyte4 hwAccelCtx) RSAKey* p_rsaKey)
{
    sbyte4  msgLen = 15;
    ubyte   msg[] = {
        'C', 'L', 'E', 'A', 'R', '_', 'T', 'E', 'X', 'T', '_', 'L', 'I', 'N', 'E'
    };
    ubyte*  pPlainText = NULL;
    ubyte*  pCipherText = NULL;
    sbyte4  cipherTextLen = 0;
    sbyte4  msgLenRet = 0;
    sbyte4  cmpRes = 0;
    MSTATUS status = OK;

    /* Get the cipher text length */
    if (OK > (status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) p_rsaKey, &cipherTextLen )))
        goto exit;

    /* Allocate memory for Cipher Text */
    pCipherText = MALLOC(cipherTextLen);

    if (NULL == pCipherText)
        goto exit;

    /* Allocate memory for plaintext */
    pPlainText = MALLOC(cipherTextLen);
    if (NULL == pPlainText)
        goto exit;

    if (OK > (status = RSA_signMessage(MOC_RSA(hwAccelCtx) p_rsaKey, msg, msgLen, pCipherText, NULL)))
        goto exit;

    if ( 1 == rsa_fail )
    {
        pCipherText[0] ^= 0x78;
        pCipherText[1] ^= 0x3F;
    }
    rsa_fail = 0;

    if (OK > (status = RSA_verifySignature(MOC_RSA(hwAccelCtx) p_rsaKey, pCipherText, pPlainText, (ubyte4*)&msgLenRet, NULL)))
    {
        status = ERR_FIPS_RSA_SIGN_VERIFY_FAIL;
        setFIPS_Status(FIPS_ALGO_RSA,status);
        goto exit;
    }

    if (msgLen != msgLenRet)
    {
        status = ERR_FIPS_RSA_SIGN_VERIFY_FAIL;
        setFIPS_Status(FIPS_ALGO_RSA,status);
        goto exit;
    }

    if (OK != DIGI_CTIME_MATCH(msg, pPlainText, msgLen, &cmpRes))
    {
        status = ERR_FIPS_RSA_SIGN_VERIFY_FAIL;
        setFIPS_Status(FIPS_ALGO_RSA,status);
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_FIPS_RSA_SIGN_VERIFY_FAIL;
        setFIPS_Status(FIPS_ALGO_RSA,status);
        goto exit;
    }

    FIPS_TESTLOG(1060, "RSA_generateKey_FIPS_consistancy_test: GOOD Signature Verify!" );

exit:
    if (NULL != pPlainText)
        FREE( pPlainText);

    if (NULL != pCipherText)
        FREE( pCipherText);

    return status;

} /* RSA_generateKey_FIPS_consistancy_test */

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

#endif /* __DISABLE_DIGICERT_KEY_GENERATION__ */


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_RSA_DECRYPTION__) && !defined(__RSAINT_HARDWARE__) && !defined(__ENABLE_DIGICERT_PKCS11_CRYPTO__))
extern MSTATUS
RSA_RSASP1(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKey,
           const vlong *pMessage, RNGFun rngFun, void* rngFunArg, vlong **ppRetSignature, vlong **ppVlongQueue)
{
    return RSAINT_decrypt(MOC_RSA(hwAccelCtx) pRSAKey, pMessage, rngFun, rngFunArg, ppRetSignature, ppVlongQueue);
}
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
RSA_RSAVP1(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pPublicRSAKey,
           const vlong *pSignature, vlong **ppRetMessage, vlong **ppVlongQueue)
{
    return RSAINT_encrypt(MOC_RSA(hwAccelCtx) pPublicRSAKey, pSignature, ppRetMessage, ppVlongQueue);
}


/*------------------------------------------------------------------*/

#if !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)
extern MSTATUS
RSA_RSADP(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKey,
          const vlong *pCipherText, vlong **ppMessage, vlong **ppVlongQueue)
{
    return RSAINT_decryptAux(MOC_RSA(hwAccelCtx) pRSAKey, pCipherText, ppMessage, ppVlongQueue);
}
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
RSA_RSAEP(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pPublicRSAKey,
          const vlong *pMessage, vlong **ppRetCipherText, vlong **ppVlongQueue)
{
    return RSAINT_encrypt(MOC_RSA(hwAccelCtx) pPublicRSAKey, pMessage, ppRetCipherText, ppVlongQueue);
}

/*------------------------------------------------------------------*/

extern MSTATUS
RSA_getPrivateExponent (
    MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey *pRSAKey,
    vlong **ppRetD,
    vlong **ppVlongQueue
    )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_MEM_ALLOC_FAIL;
    vlong* po = NULL;
    vlong* qo = NULL;
    vlong* pq = NULL;
    vlong* rem = NULL;
    vlong* gcd = NULL;
    vlong* lamda = NULL;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

    if ( (OK > VLONG_allocVlong(&pq, ppVlongQueue)) ||
         (OK > VLONG_allocVlong(&lamda, ppVlongQueue)) ||
         (OK > VLONG_allocVlong(&rem, ppVlongQueue)) )
    {
        goto exit;
    }

    /* po = p - 1; */
    if (OK > (status = VLONG_makeVlongFromVlong(RSA_P(pRSAKey), &po,
                                                ppVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_decrement(po, ppVlongQueue)))
        goto exit;

    /* qo = q - 1; */
    if (OK > (status = VLONG_makeVlongFromVlong(RSA_Q(pRSAKey), &qo,
                                                ppVlongQueue)))
    {
        goto exit;
    }

    if (OK > (status = VLONG_decrement(qo, ppVlongQueue)))
        goto exit;

    /* pq = (p - 1)(q - 1) */
    if (OK > (status = VLONG_unsignedMultiply(pq, po, qo)))
        goto exit;

#if 1
    /* gcd = GCD(po, qo) */
    if (OK > (status = VLONG_greatestCommonDenominator(MOC_MOD(hwAccelCtx) po, qo, &gcd, ppVlongQueue)))
        goto exit;

    /* lamda = pq/gcd */
    if (OK > (status = VLONG_unsignedDivide(lamda, pq, gcd, rem, ppVlongQueue)))
        goto exit;

    /* check if rem is 0 */
    if (!VLONG_isVlongZero(rem))
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    /* lamda = LCM(p-1, q-1) = (p-1)*(q-1)/GCD(p-1, q-1) */
    status = VLONG_modularInverse(MOC_MOD(hwAccelCtx) RSA_E(pRSAKey), lamda, ppRetD, ppVlongQueue);
#else

    status = VLONG_modularInverse(MOC_MOD(hwAccelCtx) RSA_E(pRSAKey), pq, ppRetD, ppVlongQueue);

#endif

exit:
    VLONG_freeVlong(&po, ppVlongQueue);
    VLONG_freeVlong(&qo, ppVlongQueue);
    VLONG_freeVlong(&pq, ppVlongQueue);
    VLONG_freeVlong(&rem, ppVlongQueue);
    VLONG_freeVlong(&gcd, ppVlongQueue);
    VLONG_freeVlong(&lamda, ppVlongQueue);

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
RSA_applyPublicKey (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    RSAKey *pPublicKey,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte **ppOutput,
    vlong **ppVlongQueue
    )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte4 outputLen = 0;
    sbyte4 modulusLen = 0;
    ubyte *pOutput = NULL;
    vlong *pInputVlong = NULL;
    vlong *pOutputVlong = NULL;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

    status = ERR_NULL_POINTER;
    if ( (NULL == pPublicKey) || (NULL == pInput) || (NULL == ppOutput) )
        goto exit;

    status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pPublicKey, &modulusLen);
    if (OK != status)
        goto exit;

    status = VLONG_vlongFromByteString (
        pInput, inputLen, &pInputVlong, ppVlongQueue);
    if (OK != status)
        goto exit;

    status = RSAINT_encrypt ( MOC_RSA(hwAccelCtx)
        (const RSAKey *)pPublicKey, pInputVlong, &pOutputVlong, ppVlongQueue);
    if (OK != status)
        goto exit;

    outputLen = (ubyte4)modulusLen;

    status = DIGI_CALLOC((void **)&pOutput, 1, outputLen);
    if (OK != status)
        goto exit;

    status = VLONG_byteStringFromVlong(pOutputVlong, pOutput, (sbyte4*)&outputLen);
    if (OK != status)
        goto exit;

    *ppOutput = pOutput;
    pOutput = NULL;

exit:

    if (NULL != pOutput)
    {
        DIGI_FREE((void **)&pOutput);
    }
    if (NULL != pInputVlong)
    {
        VLONG_freeVlong(&pInputVlong, ppVlongQueue);
    }
    if (NULL != pOutputVlong)
    {
        VLONG_freeVlong(&pOutputVlong, ppVlongQueue);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
RSA_applyPrivateKey (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    RSAKey *pPrivateKey,
    RNGFun rngFun,
    void *rngFunArg,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte **ppOutput,
    vlong **ppVlongQueue
    )
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte4 outputLen = 0;
    sbyte4 modulusLen = 0;
    ubyte *pOutput = NULL;
    vlong *pInputVlong = NULL;
    vlong *pOutputVlong = NULL;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

    status = ERR_NULL_POINTER;
    if ( (NULL == pPrivateKey) || (NULL == pInput) || (NULL == ppOutput) )
        goto exit;

    status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pPrivateKey, &modulusLen);
    if (OK != status)
        goto exit;

    status = VLONG_vlongFromByteString (
        pInput, inputLen, &pInputVlong, ppVlongQueue);
    if (OK != status)
        goto exit;

    status = RSAINT_decrypt ( MOC_RSA(hwAccelCtx)
        (const RSAKey *)pPrivateKey, pInputVlong, rngFun, rngFunArg,
        &pOutputVlong, ppVlongQueue);
    if (OK != status)
        goto exit;

    outputLen = (ubyte4)modulusLen;

    status = DIGI_CALLOC((void **)&pOutput, 1, outputLen);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__
    /* If constant time code calculated pOutputVlong then it will have numUnitsUsed the full length */
    if ((outputLen + sizeof(vlong_unit) - 1)/sizeof(vlong_unit) <= pOutputVlong->numUnitsUsed)
    {
        /* VLONG_fixedByteStringFromVlong is constant time when numUnitsUsed is the full length */
        status = VLONG_fixedByteStringFromVlong (pOutputVlong, pOutput, (sbyte4) outputLen);
        if (OK != status)
            goto exit;
    }
    else
#endif
    {
        status = VLONG_byteStringFromVlong(pOutputVlong, pOutput, (sbyte4*)&outputLen);
        if (OK != status)
            goto exit;
    }

    *ppOutput = pOutput;
    pOutput = NULL;

exit:

    if (NULL != pOutput)
    {
        DIGI_FREE((void **)&pOutput);
    }
    if (NULL != pInputVlong)
    {
        VLONG_freeVlong(&pInputVlong, ppVlongQueue);
    }
    if (NULL != pOutputVlong)
    {
        VLONG_freeVlong(&pOutputVlong, ppVlongQueue);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
    return status;
}

extern MSTATUS RSA_verifyDigest(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    RSAKey *pKey,
    ubyte *pMsgDigest,
    ubyte4 digestLen,
    ubyte* pSignature,
    ubyte4 sigLen,
    intBoolean *pIsValid,
    vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 cipherLen = 0;
    ubyte *pDecrypted = NULL;
    ubyte4 decLen = 0;
    ubyte4 checkLen = 0;
    sbyte4 localValid = FALSE;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_RSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_RSA,0);

    if (NULL == pIsValid || NULL == pMsgDigest) /* rest of params validated in below calls */
        goto exit;

    /* set to false just in case we error early */
    *pIsValid = FALSE;

    /* Fips powerup status is also called by RSA_getCipherTextLength if needbe */
    status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pKey, (sbyte4 *) &cipherLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pDecrypted, cipherLen);
    if (OK != status)
        goto exit;

    status = ERR_RSA_BAD_SIGNATURE;
    if (cipherLen != sigLen)
        goto exit;

    status = RSA_verifySignature(MOC_RSA(hwAccelCtx) pKey, pSignature, pDecrypted, &decLen, ppVlongQueue);
    if (OK != status)
        goto exit;

    checkLen = (decLen < digestLen) ? decLen : digestLen;

    status = DIGI_CTIME_MATCH(pDecrypted, pMsgDigest, checkLen, &localValid);
    if (OK != status)
        goto exit;

    localValid |= (decLen - digestLen);

    if (localValid)
    {
        *pIsValid = FALSE;
    }
    else
    {
        *pIsValid = TRUE; 
    }

exit:

    if (NULL != pDecrypted)
    {
        DIGI_MEMSET_FREE(&pDecrypted, cipherLen);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_RSA,0);
    return status;
}

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/rsa_priv.h"

extern void RSA_triggerFail(void)
{
    rsa_fail = 1;
}

static FIPS_entry_fct rsa_table[] = {
    { RSA_TRIGGER_FAIL_F_ID,     (s_fct*)RSA_triggerFail},
    { -1, NULL } /* End of array */
};

MOC_EXTERN const FIPS_entry_fct* RSA_getPrivileged()
{
    if (OK == FIPS_isTestMode())
        return rsa_table;

    return NULL;
}
#endif

#endif /* __RSA_HARDWARE_ACCELERATOR__ */
#endif /* __DISABLE_DIGICERT_RSA__ */
