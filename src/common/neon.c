/*
 * neon.c
 *
 * Routines using the ARM NEON instructions.
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

#if  __ARM_NEON__

#include "../common/moptions.h"
#include "../common/mtypes.h"

#include "../common/neon.h"


/*---------------------------------------------------------------------------*/

static void
NEON_mult( ubyte4* pResult, ubyte4* pFactorA, ubyte4* pFactorB,
           ubyte4 i_limit, ubyte4 j_limit, ubyte4 x_limit)
{
    ubyte4 x,i,j,j_upper;

    NEON_INIT();

    for (x = 0; x < x_limit; x++)
    {
        i = (x <= i_limit) ? x : i_limit;
        j = x - i;

        j_upper = ((x <= j_limit) ? x : j_limit);

        while (j <= j_upper)
        {
            NEON_MULT(pFactorA + (i*2), pFactorB + (j*2));
            i--; j++;
        }
        NEON_FINAL(pResult);
        pResult += 2;
    }
}


/*---------------------------------------------------------------------------*/

static void
NEON_sqr( ubyte4* pResult, ubyte4* pFactorA,
           ubyte4 i_limit, ubyte4 x_limit)
{

    ubyte4 x,i,j;

    NEON_INIT();

    for (x = 0; x < x_limit; x++)
    {
        NEON_INIT2();

        i = (x <= i_limit) ? x : i_limit;
        j = x - i;

        while (j < i)
        {
            NEON_MULT2(pFactorA + (i*2), pFactorA + (j*2));
            i--; j++;
        }

        NEON_ADD_DOUBLE();

        /* add odd-even case */
        if (i == j)
        {
            NEON_MULT( pFactorA + (i*2),
                       pFactorA + (i*2));
        }
        NEON_FINAL( pResult);
        pResult += 2;
    }
}


/*---------------------------------------------------------------------------*/

extern void
NEON_multiply( ubyte4* pResult, ubyte4* pFactorA, ubyte4* pFactorB,
                  ubyte4 i_limit, ubyte4 j_limit, ubyte4 x_limit)
{
    if (0 == (i_limit & 1) )
    {
        pFactorA[i_limit+1] = 0;
    }
    if (0 == (j_limit & 1) )
    {
        pFactorB[j_limit+1] = 0;
    }

    NEON_mult( pResult,
               pFactorA,
               pFactorB,
               (i_limit)/2,
               (j_limit)/2,
               (x_limit+1)/2);
}



/*---------------------------------------------------------------------------*/

extern void
NEON_square( ubyte4* pResult, ubyte4* pFactorA, ubyte4 i_limit,
             ubyte4 x_limit)
{
    if (0 == (i_limit & 1) )
    {
        pFactorA[i_limit+1] = 0;
    }

    NEON_sqr( pResult,
               pFactorA,
               (i_limit)/2,
               (x_limit+1)/2);
}


#endif /* __ARM_NEON__ */


