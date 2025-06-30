/*
 * jacobi.c
 *
 * Jacobi Symbol
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

#if (!defined(__DISABLE_MOCANA_COMMON_JACOBI__))

/*------------------------------------------------------------------*/

extern MSTATUS
JACOBI_jacobiSymbol(MOC_MOD(hwAccelDescr hwAccelCtx)
                    const vlong *a, const vlong *p,
                    sbyte4 *pRetJacobiResult,
                    vlong **ppVlongQueue)
{
    vlong*      a1  = NULL;
    vlong*      p1  = NULL;
    vlong*      u   = NULL;
    vlong*      z   = NULL;
    sbyte4      jacobi;
    vlong_unit  m;
    vlong_unit  i2;
    vlong_unit  n8;
    vlong_unit  u4;
    MSTATUS     status;

    jacobi = 0;

    if (OK > (status = VLONG_makeVlongFromVlong(a, &a1, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_makeVlongFromVlong(p, &p1, ppVlongQueue)))
        goto exit;

    p1->negative = FALSE;

    m = 0;

    n8 = VLONG_getVlongUnit(p1, 0) % 8;

    if ((n8 + 1) & 1)
        goto exit;

    if (a1->negative)
    {
        a1->negative = FALSE;

        if ((3 == n8) || (7 == n8))
        {
            m = m + 1;
        }
    }

    do
    {
        if (TRUE == VLONG_isVlongZero(a1))
            goto exit;

        i2 = 0;

        VLONG_freeVlong(&u, ppVlongQueue);

        if (OK > (status = VLONG_makeVlongFromVlong(a1, &u, ppVlongQueue)))
            goto exit;

        if (OK > (status = VLONG_shrVlong(u)))
            goto exit;

        while (0 == (VLONG_getVlongUnit(a1, 0) & 1))
        {
            i2 = i2 + 1;

            if (OK > (status = VLONG_shrVlong(a1)))
                goto exit;

            if (OK > (status = VLONG_shrVlong(u)))
                goto exit;
        }

        if (1 & (i2))
            m = m + (n8*n8-1) / 8;

        u4 = VLONG_getVlongUnit(a1, 0) % 4;
        m  = m + (n8-1)*(u4-1) / 4;

        if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) p1, a1, &z, ppVlongQueue)))
            goto exit;

        VLONG_freeVlong(&p1, ppVlongQueue);
        p1 = a1;

        a1 = z;
        z = NULL;   /* to prevent dangling pointer */

        n8 = VLONG_getVlongUnit(p1, 0) % 8;
    }
    while (VLONG_compareUnsigned(p1, 1) > 0);

    m = m % 2;

    if (0 == m)
        jacobi = 1;
    else
        jacobi = -1;

exit:
    *pRetJacobiResult = jacobi;

    VLONG_freeVlong(&z, ppVlongQueue);
    VLONG_freeVlong(&u, ppVlongQueue);
    VLONG_freeVlong(&p1, ppVlongQueue);
    VLONG_freeVlong(&a1, ppVlongQueue);

    return status;

} /* JACOBI_jacobiSymbol */

#endif /* __DISABLE_MOCANA_COMMON_JACOBI__ */
