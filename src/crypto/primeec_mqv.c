/*
 * primeec_mqv.c
 *
 * Prime MQV Elliptic Curve Cryptography
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
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/random.h"
#if (defined(__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__))
#include "../common/vlong.h"
#endif
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/primeec_mqv.h"

#include "../crypto/primefld_priv.h"
#include "../crypto/primeec_priv.h"

#if (defined(__ENABLE_DIGICERT_ECC__) && !defined(__DISABLE_DIGICERT_ECC_MQV__))


/*--------------------------------------------------------------------------*/

static MSTATUS ECMQV_bar( PrimeFieldPtr pPF,
                         const ECCKey* pQ, PFEPtr * ppQBar)
{
    MSTATUS status;
    PFEPtr pQBar = 0;
    ubyte4 i, bpu, bits;

    /* "calculate" (Qu bar) */
    if (OK > ( status = PRIMEFIELD_newElement( pPF, &pQBar)))
        goto exit;

    /* IMPORTANT ASSUMPTION: for NIST P curves, the order of the point has
    the same bit length as the order of the field so we can shortcut the
    computation of the bitlength of the order of the curve */
    bits = (pPF->numBits / 2) + (pPF->numBits & 1);
    bpu = sizeof(pf_unit)*8;

    /* copy half of the words */
    for (i = 0; bits >= bpu; ++i)
    {
        pQBar->units[i] = pQ->Qx->units[i];
        bits -= bpu;
    }

    /* more bits to copy ? */
    if (bits)
    {
        /* 0 < bits < bpu */
        pf_unit mask;
        mask = (FULL_MASK >> (bpu - bits));
        pQBar->units[i] = (pQ->Qx->units[i] & mask) |
                            ((pf_unit) 1 << bits);
    }
    else
    {
        pQBar->units[i] = (pf_unit) 1;
    }

    *ppQBar = pQBar;
    pQBar = 0;

exit:

    PRIMEFIELD_deleteElement( pPF, &pQBar);
    return status;
}
/*--------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS ECMQV_generateSharedSecret(const ECCKey* pQ1U,
                                              const ECCKey* pQ2U,
                                              const ECCKey* pQ1V,
                                              const ECCKey* pQ2V,
                                              PFEPtr* pSharedSecret)
{
    /* we are using the naming used in SEC1 */
    MSTATUS status;
    PrimeFieldPtr pPF;
    PFEPtr pU = 0;
    PFEPtr pS = 0;
    PFEPtr pX = 0;
    PFEPtr pY = 0;
    PFEPtr pV = 0;

    if (!pQ1U || !pQ2U || !pQ1V || !pQ2V ||
        !pSharedSecret)
    {
        return ERR_NULL_POINTER;
    }

    if (pQ1U->pCurve != pQ2U->pCurve ||
        pQ1U->pCurve != pQ1V->pCurve ||
        pQ1U->pCurve != pQ2V->pCurve)
    {
        return ERR_EC_DIFFERENT_CURVE;
    }

    if (!pQ1U->privateKey ||
        !pQ2U->privateKey )
    {
        return ERR_EC_PUBLIC_KEY;
    }

    pPF = EC_getUnderlyingField( pQ1U->pCurve);

    /* "compute" Q2UBar - > U */
    if (OK > ( status = ECMQV_bar( pPF, pQ2U, &pU)))
        goto exit;

    if (OK > ( status = PRIMEFIELD_newElement( pPF, &pS) ) ||
        OK > ( status = PRIMEFIELD_newElement( pPF, &pX) ) ||
        OK > ( status = PRIMEFIELD_newElement( pPF, &pY) ) )
    {
        goto exit;
    }

    /* compute s  = d2u + Q2UBar * d1u mod n*/
    /* S = pQ2UBar * d1U mod n */
    if (OK > ( status  = PRIMEFIELD_barrettMultiply( pPF, pS, pU, pQ1U->k,
                                                     pQ1U->pCurve->n,
                                                     pQ1U->pCurve->mu)))
    {
        goto exit;
    }

    /* better be safe */
    if (OK > ( status = EC_modOrder(pQ1U->pCurve, pQ2U->k)))
        goto exit;

    /* S += du2  mod n*/
    if (OK > ( status = PRIMEFIELD_addAux( pPF, pS, pQ2U->k, pQ1U->pCurve->n)))
        goto exit;

    /* "compute" Q2VBar -> V */
    if (OK > ( status = ECMQV_bar( pPF, pQ2V, &pV)))
        goto exit;

    /* compute the point Q2V + Q2VBar * Q1V */
    if ( OK > ( status = EC_addMultiplyPoint( pPF, pX, pY, pQ2V->Qx, pQ2V->Qy,
                                                pV, pQ1V->Qx, pQ1V->Qy)))
    {
        goto exit;
    }

    /* and now multiply it by S ; cofactor is 1 for NIST curves */
    if (OK > ( status = EC_multiplyPoint( pPF, pU, pV, pS, pX, pY)))
    {
        goto exit;
    }

    /* verify point is not at infinity */
    if (  0 == PRIMEFIELD_cmpToUnsigned( pPF, pU, 0) &&
          0 == PRIMEFIELD_cmpToUnsigned( pPF, pV, 0) )
    {
        status = ERR_EC_INFINITE_RESULT;
        goto exit;
    }

    *pSharedSecret = pU;
    pU = 0;

exit:

    PRIMEFIELD_deleteElement( pPF, &pV);
    PRIMEFIELD_deleteElement( pPF, &pY);
    PRIMEFIELD_deleteElement( pPF, &pX);
    PRIMEFIELD_deleteElement( pPF, &pS);
    PRIMEFIELD_deleteElement( pPF, &pU);

    return status;
}



#endif /* __ENABLE_DIGICERT_ECC__ */
