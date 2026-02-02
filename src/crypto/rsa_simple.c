/*
 * rsa_simple.c
 *
 * RSA decryption for minimal environments
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
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../crypto/primefld.h"
#include "../crypto/primefld_priv.h"
#include "../crypto/rsa_simple.h"

#if (defined(__ENABLE_DIGICERT_RSA_SIMPLE__) && defined(__ENABLE_DIGICERT_ECC__))

/*--------------------------------------------------------------------------*/

static MSTATUS
RSA_SIMPLE_writeToByteString( sbyte4 n, const pf_unit* a,
                             ubyte* b, sbyte4 bLen)
{
    sbyte4 i;

    if (bLen < (sbyte4) (n * sizeof(pf_unit)))
        return ERR_BUFFER_OVERFLOW;

    for (i = 0; i < n; ++i, a++)
    {
        pf_unit u = *a;
        b[--bLen] = (ubyte) ((u));
        b[--bLen] = (ubyte) ((u) >> 8);
        b[--bLen] = (ubyte) ((u) >> 16);
        b[--bLen] = (ubyte) ((u) >> 24);
#ifdef __ENABLE_DIGICERT_64_BIT__
        b[--bLen] = (ubyte) ((u) >> 32);
        b[--bLen] = (ubyte) ((u) >> 40);
        b[--bLen] = (ubyte) ((u) >> 48);
        b[--bLen] = (ubyte) ((u) >> 56);
#endif
    }
    while (bLen > 0)
    {
        b[--bLen] = 0;
    }

    return OK;
}


/*--------------------------------------------------------------------------*/

MSTATUS
RSA_SIMPLE_verifySignature(sbyte4 k,
                           const pf_unit modulus[/*k+1*/],
                           const pf_unit mu[/*k+1*/],
                           sbyte4 modulusLen,
                           ubyte4 e,
                           const ubyte cipherText[/*modulusLen*/],
                           const ubyte* plainText,
                           ubyte4 plainTextLen)
{
  /* !!! modulus and mu must be k + 1 pf_units long !!! */
  MSTATUS status = OK;
  pf_unit* pt = 0;
  pf_unit* ct = 0;
  ubyte*   pkcs1;
  sbyte4 i, realLen;
  ubyte4 vfyResult;

  /* test the pointers */
  if (!modulus || !mu || !cipherText || !plainText)
    return ERR_NULL_POINTER;

  /* allocate a single buffer for everything */
  pt = (pf_unit*) MALLOC( (2 * k ) * sizeof(pf_unit));
  if (!pt)
  {
    status = ERR_MEM_ALLOC_FAIL;
    goto exit;
  }

  ct = pt + k;

  /* transfer the bytes to the buffer */
  BI_setUnitsToByteString( k, pt, cipherText, modulusLen);

  /* do the modular exponentiation */
  if (OK > (status = BI_modExp( k, ct, pt, e, modulus, mu)))
    goto exit;

  /* back to byte string -- reuse pt as byte string */
  pkcs1 = (ubyte*) pt;
  if (OK > (status = RSA_SIMPLE_writeToByteString( k, ct, pkcs1, modulusLen)))
    goto exit;

  /* Set vfyResult to 0, meaning there have been no errors in verifying the
   * signature.
   * Each time we encounter an error, add to vfyResult. At the end, if
   * vfyResult is not 0, then set status to ERR_RSA_DECRYPTION.
   * We want to make all checks and not stop as soon as we hit an error.
   */
  vfyResult = 0;

  /* some verifications */
  if (((pkcs1[0] != 0) || (pkcs1[1] != 1)) && (pkcs1[0] != 1))
    vfyResult++;

  /* scan until the first 0 byte */
  for (i = 2; i < modulusLen; ++i)
  {
    if (0 == pkcs1[i])
      break;

    if (0xff != pkcs1[i])
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

  /* compare the expected result */
  /* If everything is correct except the result does not compare correctly,
   * return ERR_FALSE.
   * If there is some other problem, return ERR_RSA_DECRYPTION.
   * Hence, if the "memcmp" does not show equal, don't update vfyResult, just
   * make sure status is set to ERR_FALSE.
   */
  realLen = 0;
  status = OK;
  for (++i; i < modulusLen; ++i, ++realLen)
  {
    if (plainText[realLen] != pkcs1[i])
      status = ERR_FALSE;
  }

  if (plainTextLen != realLen)
    status = ERR_FALSE;

  /* If there were some error other than a memcmp failure, then return this
   * DECRYPTION. The memcmp probably also failed, but this type of error takes
   * precedence.
   */
  if (0 != vfyResult)
    status = ERR_RSA_DECRYPTION;

exit:

  if (pt)
  {
    FREE(pt);
  }

  return status;
}


/*--------------------------------------------------------------------------*/

MSTATUS
RSA_SIMPLE_decryptAux(sbyte4 n,  pf_unit pt[/*n*/], const pf_unit ct[/*n*/],
                      const pf_unit p[/*n/2+1*/],
                      const pf_unit mu_p[/*n/2+1*/],
                      const pf_unit dp[/*n/2*/],
                      const pf_unit q[/*n/2+1*/],
                      const pf_unit mu_q[/*n/2+1*/],
                      const pf_unit dq[/*n/2*/],
                      const pf_unit qinv[/*n/2*/])
{
    MSTATUS status;
    pf_unit *mulBuffer = 0;
    pf_unit* m1;
    sbyte4 i;

    mulBuffer = (pf_unit*) MALLOC( (5 * (n/2) + 2) * sizeof(pf_unit));
    if (!mulBuffer)
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    m1 = mulBuffer + 2 * n + 2; /* m1 size = n / 2 */
    /* CRT */
    /* m1 = c^dP mod p */
    /* m2 = c^dQ mod q */
    /* h = qInv(m1 - m2) mod p */
    /* m = m2 + hq */

    /* m1 = c^dP mod p */
    if (OK > ( status = BI_modExpEx(n/2, m1, ct, n/2, dp, p, mu_p)))
    {
        goto exit;
    }

    /* pt = m2 = c^dQ mod q */
    if (OK > ( status = BI_modExpEx(n/2, pt, ct, n/2, dq, q, mu_q)))
    {
        goto exit;
    }

    /* h = qInv * (m1 - m2) mod p */
    if ( BI_cmp(n/2, m1, pt) < 0 )
    {
        BI_add(n/2, m1, p);
    }

    /* m1 -= m2 */
    BI_sub(n/2, m1, pt);

    /* tmp = qInv * m1 */    /* mulBuffer size = n */
    BI_mul( n/2, mulBuffer, qinv, m1, n);

    /* barrett reduction mod p -> h is placed in m1 */
    status = BI_barrettReduction( n/2, mulBuffer, m1, mulBuffer + n, mu_p, p);
    if (OK != status)
        goto exit;
    
    /* tmp = hq */
    BI_mul(n/2, mulBuffer, m1, q, n);

    /* m2 += m1 */
    /* IMPORTANT to zero the upper half of the pt buffer */
    for (i = n/2; i < n; ++i)
    {
        pt[i] = ZERO_UNIT;
    }
    BI_add(n, pt, mulBuffer);

exit:
    FREE(mulBuffer);

    return status;

} /* RSAINT_decryptAux */


/*--------------------------------------------------------------------------*/

MSTATUS
RSA_SIMPLE_blindDecryptAux(sbyte4 n,  pf_unit pt[/*n*/],
                           const pf_unit ct[/*n*/],
                           const pf_unit p[/*n/2+1*/],
                           const pf_unit mu_p[/*n/2+1*/],
                           const pf_unit dp[/*n/2*/],
                           const pf_unit q[/*n/2+1*/],
                           const pf_unit mu_q[/*n/2+1*/],
                           const pf_unit dq[/*n/2*/],
                           const pf_unit qinv[/*n/2*/],
                           const pf_unit modulus[/*n+1*/],
                           const pf_unit mu_modulus[/*n+1*/],
                           pf_unit re[/*n*/],
                           pf_unit r1[/*n*/])
{
    /* blinding version: re and r1 are the blinding factors and they
        are updated by squaring in this routine */

    MSTATUS status;
    pf_unit *mulBuffer = 0;
    pf_unit* m1;
    sbyte4 i;

    mulBuffer = (pf_unit*) MALLOC( (5 * n + 2) * sizeof(pf_unit));
    if (!mulBuffer)
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    /* blind the cipher text */
    BI_mul( n, mulBuffer, ct, re, 2 * n);
    /* modulo modulus -> blinded cipher text is at (mulBuffer + 2 n) */
    status = BI_barrettReduction( n, mulBuffer, mulBuffer + 2 * n, mulBuffer + 3 * n, mu_modulus, modulus);
    if (OK != status)
        goto exit;

    ct = mulBuffer + 2 * n;
    m1 = mulBuffer + 3 * n; /* m1 size = n / 2 */
    /* CRT */
    /* m1 = c^dP mod p */
    /* m2 = c^dQ mod q */
    /* h = qInv(m1 - m2) mod p */
    /* m = m2 + hq */

    /* m1 = c^dP mod p */
    if (OK > ( status = BI_modExpEx(n/2, m1, ct, n/2, dp, p, mu_p)))
    {
        goto exit;
    }

    /* pt = m2 = c^dQ mod q */
    if (OK > ( status = BI_modExpEx(n/2, pt, ct, n/2, dq, q, mu_q)))
    {
        goto exit;
    }

    /* h = qInv * (m1 - m2) mod p */
    if ( BI_cmp(n/2, m1, pt) < 0 )
    {
        BI_add(n/2, m1, p);
    }

    /* m1 -= m2 */
    BI_sub(n/2, m1, pt);

    /* tmp = qInv * m1 */    /* mulBuffer size = n */
    BI_mul( n/2, mulBuffer, qinv, m1, n);

    /* barrett reduction mod p -> h is placed in m1 */
    status = BI_barrettReduction( n/2, mulBuffer, m1, mulBuffer + n, mu_p, p);
    if (OK != status)
        goto exit;

    /* tmp = hq */
    BI_mul(n/2, mulBuffer, m1, q, n);

    /* m2 += m1 */
    /* IMPORTANT to zero the upper half of the pt buffer */
    for (i = n/2; i < n; ++i)
    {
        pt[i] = ZERO_UNIT;
    }
    BI_add(n, pt, mulBuffer);

    /* unblind */
    /* multiply pt by r1 to unblind */
    BI_mul(n, mulBuffer, pt, r1, 2 * n);

    /* modulo modulus */
    status = BI_barrettReduction( n, mulBuffer, pt, mulBuffer + 3 * n, mu_modulus, modulus);
    if (OK != status)
        goto exit;
    
    /* square the factors */
    /* re */
    BI_mul( n, mulBuffer, re, re, 2 * n);
    /* modulo modulus */
    status = BI_barrettReduction( n, mulBuffer, re, mulBuffer + 3 * n, mu_modulus, modulus);
    if (OK != status)
        goto exit;
    
    /* r1 */
    BI_mul( n, mulBuffer, r1, r1, 2 * n);
    /* modulo modulus */
    status = BI_barrettReduction( n, mulBuffer, r1, mulBuffer + 3 * n, mu_modulus, modulus);

exit:
    FREE(mulBuffer);

    return status;

} /* RSAINT_blindDecryptAux */


/*--------------------------------------------------------------------------*/

MSTATUS
RSA_SIMPLE_sign(sbyte4 n,  ubyte s[/*n*sizeof(pf_unit)*/],
            const ubyte* msg, ubyte4 msgLen,
            const pf_unit p[/*n/2+1*/],
            const pf_unit mu_p[/*n/2+1*/],
            const pf_unit dp[/*n/2*/],
            const pf_unit q[/*n/2+1*/],
            const pf_unit mu_q[/*n/2+1*/],
            const pf_unit dq[/*n/2*/],
            const pf_unit qinv[/*n/2*/])
{
    MSTATUS status;
    pf_unit* pt = 0;
    ubyte* tmp;
    sbyte4 i;

    if (msgLen + 3 + 8 > n * sizeof(pf_unit))
        return ERR_INVALID_ARG;

    pt = (pf_unit*) MALLOC(  2 * n * sizeof(pf_unit));

    if (!pt )
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    tmp = s;
    *tmp++ = 0;
    *tmp++ = 1;
    for (i = 0; i < (n * sizeof(pf_unit)) - msgLen - 3; ++i)
    {
        *tmp++ = 0xFF;
    }
    *tmp++ = 0;
    for (i = 0; i < msgLen; ++i)
    {
        *tmp++ = *msg++;
    }
    /* transfer the bytes to the buffer */
    BI_setUnitsToByteString( n, pt+n, s, n * sizeof(pf_unit));

    status = RSA_SIMPLE_decryptAux( n, pt, pt + n,
                                    p, mu_p, dp,
                                    q, mu_q, dq,
                                    qinv);

    /* transfer back to s */
    for (i = n-1; i >= 0; --i)
    {
        pf_unit u = pt[i];

#ifdef __ENABLE_DIGICERT_64_BIT__
        *s++ = (ubyte) ((u) >> 56);
        *s++ = (ubyte) ((u) >> 48);
        *s++ = (ubyte) ((u) >> 40);
        *s++ = (ubyte) ((u) >> 32);
#endif
        *s++ = (ubyte) ((u) >> 24);
        *s++ = (ubyte) ((u) >> 16);
        *s++ = (ubyte) ((u) >> 8);
        *s++ = (ubyte) ((u));
    }

exit:

    if (pt)
        FREE(pt);

    return status;
}



/*--------------------------------------------------------------------------*/

MSTATUS
RSA_SIMPLE_sign_blind(sbyte4 n,  ubyte s[/*n*sizeof(pf_unit)*/],
            const ubyte* msg, ubyte4 msgLen,
            const pf_unit p[/*n/2+1*/],
            const pf_unit mu_p[/*n/2+1*/],
            const pf_unit dp[/*n/2*/],
            const pf_unit q[/*n/2+1*/],
            const pf_unit mu_q[/*n/2+1*/],
            const pf_unit dq[/*n/2*/],
            const pf_unit qinv[/*n/2*/],
            const pf_unit modulus[/*n+1*/],
            const pf_unit mu_modulus[/*n+1*/],
            pf_unit re[/*n*/],
            pf_unit r1[/*n*/])
{
    MSTATUS status;
    pf_unit* pt = 0;
    ubyte* tmp;
    sbyte4 i;

    if (msgLen + 3 + 8 > n * sizeof(pf_unit))
        return ERR_INVALID_ARG;

    pt = (pf_unit*) MALLOC(  2 * n * sizeof(pf_unit));

    if (!pt )
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    tmp = s;
    *tmp++ = 0;
    *tmp++ = 1;
    for (i = 0; i < (n * sizeof(pf_unit)) - msgLen - 3; ++i)
    {
        *tmp++ = 0xFF;
    }
    *tmp++ = 0;
    for (i = 0; i < msgLen; ++i)
    {
        *tmp++ = *msg++;
    }
    /* transfer the bytes to the buffer */
    BI_setUnitsToByteString( n, pt+n, s, n * sizeof(pf_unit));

    status = RSA_SIMPLE_blindDecryptAux( n, pt, pt + n,
                                    p, mu_p, dp,
                                    q, mu_q, dq,
                                    qinv, modulus, mu_modulus,
                                    re, r1);
    /* transfer back to s */
    for (i = n-1; i >= 0; --i)
    {
        pf_unit u = pt[i];

#ifdef __ENABLE_DIGICERT_64_BIT__
        *s++ = (ubyte) ((u) >> 56);
        *s++ = (ubyte) ((u) >> 48);
        *s++ = (ubyte) ((u) >> 40);
        *s++ = (ubyte) ((u) >> 32);
#endif
        *s++ = (ubyte) ((u) >> 24);
        *s++ = (ubyte) ((u) >> 16);
        *s++ = (ubyte) ((u) >> 8);
        *s++ = (ubyte) ((u));
    }

exit:

    if (pt)
        FREE(pt);

    return status;
}

#endif /* __ENABLE_DIGICERT_RSA_SIMPLE__ */
