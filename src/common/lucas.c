/*
 * lucas.c
 *
 * Lucas Prime Test
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
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
#include "../common/vlong.h"
#include "../common/jacobi.h"
#include "../common/lucas.h"
#include "../common/memory_debug.h"
#include "../common/random.h"
#include "../crypto/rsa.h"

#if (!defined(__DISABLE_DIGICERT_COMMON_LUCAS_PRIME__))

/*------------------------------------------------------------------*/

static MSTATUS
LUCAS_findD(MOC_MOD(hwAccelDescr hwAccelCtx) vlong *p, vlong **D, vlong **ppVlongQueue)
{
    sbyte4  jacobiResult = 0;
    vlong*  a = NULL;
    MSTATUS status;

    if (OK > (status = VLONG_makeVlongFromUnsignedValue(5, &a, ppVlongQueue)))
        goto exit;

    while (1)
    {
        if (OK > (status = JACOBI_jacobiSymbol(MOC_MOD(hwAccelCtx) a, p, &jacobiResult, ppVlongQueue)))
            goto exit;

        if (-1 == jacobiResult)
        {
            /* if jacobi result equals -1 */
            *D = a;
            a = NULL;

            break;
        }

        /* sequence: { 5, -7, 9, -11, 13, -15, 17, ... } */
        if (TRUE == a->negative)
        {
            a->negative = FALSE;

            if (OK > (status = VLONG_addImmediate(a, 2, ppVlongQueue)))
                goto exit;
        }
        else
        {
            if (OK > (status = VLONG_addImmediate(a, 2, ppVlongQueue)))
                goto exit;

            a->negative = TRUE;
        }
    }

exit:
    VLONG_freeVlong(&a, ppVlongQueue);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
LUCAS_defaultSet(MOC_MOD(hwAccelDescr hwAccelCtx) vlong *D, vlong *U, vlong *V, vlong *p,
                 vlong **Uk, vlong **Vk, vlong** ppVlongQueue)
{
    vlong*  pTemp1 = NULL;
    vlong*  pTemp2 = NULL;
    MSTATUS status;

    if (OK > (status = VLONG_allocVlong(&pTemp1, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pTemp1);

    if (OK > (status = VLONG_allocVlong(&pTemp2, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pTemp2);

    /* Set (U,V) = (UV mod p, (V^2 + DU^2 / 2) mod p */
    /* UV */
    if (OK > (status = VLONG_vlongSignedMultiply(pTemp1, U, V)))
        goto exit;

    /* (U, V) = UV mod p */
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) pTemp1, p, Uk, ppVlongQueue)))
        goto exit;

    /* Vk = ((V^2 + D(U^2)) / 2) mod p */
    /* U^2 */
    if (OK > (status = VLONG_vlongSignedMultiply(pTemp1, U, U)))
        goto exit;

    /* D(U^2) */
    if (OK > (status = VLONG_vlongSignedMultiply(pTemp2, D, pTemp1)))
        goto exit;

    /* V^2 */
    if (OK > (status = VLONG_vlongSignedMultiply(pTemp1, V, V)))
        goto exit;

    /* V^2 + D(U^2) */
    if (OK > (status = VLONG_addSignedVlongs(pTemp1, pTemp2, ppVlongQueue)))
        goto exit;

    /* SPECIAL NOTE: if pTemp is odd, we add p to prevent rounding error */
    if (1 & VLONG_getVlongUnit(pTemp1, 0))
        if (OK > (status = VLONG_addSignedVlongs(pTemp1, p, ppVlongQueue)))
            goto exit;

    /* ((V^2 + D(U^2)) / 2) */
    if (OK > (status = VLONG_shrVlong(pTemp1)))
        goto exit;

    /* Vk = ((V^2 + D(U^2)) / 2) mod p */
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) pTemp1, p, Vk, ppVlongQueue)))
        goto exit;

exit:
    VLONG_freeVlong(&pTemp2, ppVlongQueue);
    VLONG_freeVlong(&pTemp1, ppVlongQueue);

    return status;

} /* LUCAS_defaultSet */


/*------------------------------------------------------------------*/

static MSTATUS
LUCAS_extraSet(MOC_MOD(hwAccelDescr hwAccelCtx) vlong *D, vlong *P, vlong *U, vlong *V, vlong *p,
               vlong **Uk, vlong **Vk, vlong** ppVlongQueue)
{
    vlong*  pTemp1 = NULL;
    vlong*  pTemp2 = NULL;
    MSTATUS status;

    if (OK > (status = VLONG_allocVlong(&pTemp1, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pTemp1);

    if (OK > (status = VLONG_allocVlong(&pTemp2, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pTemp2);

    /* ANSI X9.80-2005: Uk = ((PU + V) / 2) mod p */
    /* PU */
    if (OK > (status = VLONG_vlongSignedMultiply(pTemp1, P, U)))
        goto exit;

    /* PU + V */
    if (OK > (status = VLONG_addSignedVlongs(pTemp1, V, ppVlongQueue)))
        goto exit;

    /* SPECIAL NOTE: if pTemp is odd, we add p to prevent rounding error */
    if (1 & VLONG_getVlongUnit(pTemp1, 0))
        if (OK > (status = VLONG_addSignedVlongs(pTemp1, p, ppVlongQueue)))
            goto exit;

    /* ((PU + V) / 2) */
    if (OK > (status = VLONG_shrVlong(pTemp1)))
        goto exit;

    /* Uk = ((PU + V) / 2) mod p */
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) pTemp1, p, Uk, ppVlongQueue)))
        goto exit;

    /* ANSI X9.80-2005: Vk = ((PV + DU) / 2) mod p */
    /* PV */
    if (OK > (status = VLONG_vlongSignedMultiply(pTemp1, P, V)))
        goto exit;

    /* DU */
    if (OK > (status = VLONG_vlongSignedMultiply(pTemp2, D, U)))
        goto exit;

    /* PV + DU */
    if (OK > (status = VLONG_addSignedVlongs(pTemp1, pTemp2, ppVlongQueue)))
        goto exit;

    /* SPECIAL NOTE: if pTemp is odd, we add p to prevent rounding error */
    if (1 & VLONG_getVlongUnit(pTemp1, 0))
        if (OK > (status = VLONG_addSignedVlongs(pTemp1, p, ppVlongQueue)))
            goto exit;

    /* ((PV + DU) / 2) */
    if (OK > (status = VLONG_shrVlong(pTemp1)))
        goto exit;

    /* Vk = ((PV + DU) / 2) mod p */
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) pTemp1, p, Vk, ppVlongQueue)))
        goto exit;

exit:
    VLONG_freeVlong(&pTemp2, ppVlongQueue);
    VLONG_freeVlong(&pTemp1, ppVlongQueue);

    return status;

} /* LUCAS_extraSet */


/*------------------------------------------------------------------*/

static MSTATUS
LUCAS_primeTestEx(MOC_MOD(hwAccelDescr hwAccelCtx) vlong *p, intBoolean *pIsPrime, vlong** ppVlongQueue)
{
    vlong*  D = NULL;
    vlong*  K = NULL;
    vlong*  P = NULL;
    vlong*  U = NULL;
    vlong*  V = NULL;
    vlong*  Uk = NULL;
    vlong*  Vk = NULL;
    vlong*  U_mod_p = NULL;
    sbyte4  i;
    ubyte4  r;
    MSTATUS status;

    *pIsPrime = FALSE;

    /* ANSI X9.80-2005: D in sequence { 5, -7, 9, -11, 13, -15, 17, ... } for Jacobi Symbol */
    if (OK > (status = LUCAS_findD(MOC_MOD(hwAccelCtx) p, &D, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(D);

    /* P = 1, K = p + 1 */
    if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &P, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(P);

    /* K = 1 + p */
    if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &K, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(K);

    if (OK > (status = VLONG_addSignedVlongs(K, p, ppVlongQueue)))
        goto exit;

    /* r = highest bit of K (Kr) */
    r = VLONG_bitLength(K) - 1;

    /* step 3 */
    if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &U, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(U);

    if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &V, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(V);

    /* for i = r-1 to 0 */
    for (i = r-1; i >= 0; i--)
    {
        if (OK > (status = LUCAS_defaultSet(MOC_MOD(hwAccelCtx) D, U, V, p, &Uk, &Vk, ppVlongQueue)))
            goto exit;

        DEBUG_RELABEL_MEMORY(Uk);
        DEBUG_RELABEL_MEMORY(Vk);

        /* swap in the results */
        VLONG_freeVlong(&V, ppVlongQueue);
        VLONG_freeVlong(&U, ppVlongQueue);

        U = Uk;
        Uk = NULL;
        V = Vk;
        Vk = NULL;

        if (VLONG_isVlongBitSet(K, i))
        {
            if (OK > (status = LUCAS_extraSet(MOC_MOD(hwAccelCtx) D, P, U, V, p, &Uk, &Vk, ppVlongQueue)))
                goto exit;

            DEBUG_RELABEL_MEMORY(Uk);
            DEBUG_RELABEL_MEMORY(Vk);

            /* swap in the results */
            VLONG_freeVlong(&V, ppVlongQueue);
            VLONG_freeVlong(&U, ppVlongQueue);

            U = Uk;
            Uk = NULL;
            V = Vk;
            Vk = NULL;
        }
    }

    /* Last step, verify U is divisible by p */
    if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) U, p, &U_mod_p, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(U_mod_p);

    /* if U = 0 mod p, then p is probably prime */
    *pIsPrime = VLONG_isVlongZero(U_mod_p);

exit:
    VLONG_freeVlong(&U_mod_p, ppVlongQueue);
    VLONG_freeVlong(&Vk, ppVlongQueue);
    VLONG_freeVlong(&Uk, ppVlongQueue);
    VLONG_freeVlong(&V, ppVlongQueue);
    VLONG_freeVlong(&U, ppVlongQueue);
    VLONG_freeVlong(&K, ppVlongQueue);
    VLONG_freeVlong(&P, ppVlongQueue);
    VLONG_freeVlong(&D, ppVlongQueue);

    return status;

} /* LUCAS_primeTestEx */


/*------------------------------------------------------------------*/

extern MSTATUS
LUCAS_primeTest(MOC_MOD(hwAccelDescr hwAccelCtx) vlong *pTestPrime, intBoolean *pIsPrime, vlong** ppVlongQueue)
{
    MSTATUS status;

    if ((NULL == pTestPrime) || (NULL == pIsPrime))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pIsPrime = FALSE;

    if ((TRUE == VLONG_isVlongZero(pTestPrime)) ||
        (FALSE == VLONG_isVlongBitSet(pTestPrime, 0)) )
    {
        status = ERR_EVEN_NUMBER;
        goto exit;
    }

    status = LUCAS_primeTestEx(MOC_MOD(hwAccelCtx) pTestPrime, pIsPrime, ppVlongQueue);

exit:
    return status;
}
#endif /* __DISABLE_DIGICERT_COMMON_LUCAS_PRIME__ */
