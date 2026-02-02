/*
 * sse2.c
 *
 * Routines using the Intel SSE2 instructions.
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

#if  __SSE2__

#include "../common/moptions.h"
#include "../common/mtypes.h"

#include "../common/sse2.h"


/*------------------------------------------------------------------------------*/

static void
SSE2_mult( ubyte4* pResult, ubyte4* pFactorA, ubyte4* pFactorB,
           ubyte4 i_limit, ubyte4 j_limit, ubyte4 x_limit)
{
    ubyte4 r[8] __attribute__((aligned(16))) = { 0};

    ubyte4 x,i,j,j_upper;


    for (x = 0; x < x_limit; x++)
    {
        i = (x <= i_limit) ? x : i_limit;
        j = x - i;

        j_upper = ((x <= j_limit) ? x : j_limit);

        /* note: based on x being odd or even and j + i = x
           we could do a single test on x and not do any
           test on j (only i) in the loop. But that does
           degrade performance (-O3) */
        while (j <= j_upper)
        {
            if ( i & 1)
            {
                if (j & 1)
                {
                    SSE2_multiply_11( pFactorA + (i*2),
                                      pFactorB + (j*2), r);
                }
                else
                {
                    SSE2_multiply_10( pFactorA + (i*2),
                                      pFactorB + (j*2), r);
                }
            }
            else
            {
                if (j & 1)
                {
                    SSE2_multiply_01( pFactorA + (i*2),
                                      pFactorB + (j*2), r);
                }
                else
                {
                    SSE2_multiply_00( pFactorA + (i*2),
                                      pFactorB + (j*2), r);
                }
            }

            i--; j++;
        }

        /* because of SSE2, the arrangements of the results in the
           r array is a bit strange */
        SSE2_ADD_64( r, pResult);
        pResult += 2;
    }
}


/*------------------------------------------------------------------------------*/

static void
SSE2_sqr( ubyte4* pResult, ubyte4* pFactorA,
           ubyte4 i_limit, ubyte4 x_limit)
{
    ubyte4 r[8] __attribute__((aligned(16))) = { 0};
    ubyte4 h[8] __attribute__((aligned(16))) = { 0};

    ubyte4 x,i,j;

    for (x = 0; x < x_limit; x++)
    {
        h[0] = h[1] = h[2] = h[3] = h[4] = h[5] = h[6] = h[7] = 0;

        i = (x <= i_limit) ? x : i_limit;
        j = x - i;

        while (j < i)
        {
            if ( i & 1)
            {
                if (j & 1)
                {
                    SSE2_multiply_11( pFactorA + (i*2),
                                      pFactorA + (j*2), h);
                }
                else
                {
                    SSE2_multiply_10( pFactorA + (i*2),
                                      pFactorA + (j*2), h);
                }
            }
            else
            {
                if (j & 1)
                {
                    SSE2_multiply_01( pFactorA + (i*2),
                                      pFactorA + (j*2), h);
                }
                else
                {
                    SSE2_multiply_00( pFactorA + (i*2),
                                      pFactorA + (j*2), h);
                }
            }
            i--; j++;
        }

        SSE2_ADD_DOUBLE( h, r);

        /* add odd-even case */
        if (i == j)
        {
            if ( i & 1)
            {
                SSE2_multiply_11( pFactorA + (i*2),
                                  pFactorA + (i*2), r);
            }
            else
            {
                SSE2_multiply_00( pFactorA + (i*2),
                                  pFactorA + (i*2), r);
            }
        }
        /* because of SSE2, the arrangements of the results in the
           r array is a bit strange */
        SSE2_ADD_64( r, pResult);
        pResult += 2;
    }
}


/*---------------------------------------------------------------------------*/

extern void
SSE2_multiply( ubyte4* pResult, ubyte4* pFactorA, ubyte4* pFactorB,
                  ubyte4 i_limit, ubyte4 j_limit, ubyte4 x_limit)
{
    if (0 == (i_limit & 1) )
    {
        pFactorA[i_limit+1] = 0;
    }
    if (0 == (j_limit& 1) )
    {
        pFactorB[j_limit+1] = 0;
    }

    SSE2_mult( pResult,
               pFactorA,
               pFactorB,
               (i_limit)/2,
               (j_limit)/2,
               (x_limit+1)/2);
}



/*---------------------------------------------------------------------------*/

extern void
SSE2_square( ubyte4* pResult, ubyte4* pFactorA, ubyte4 i_limit,
             ubyte4 x_limit)
{
    if (0 == (i_limit & 1) )
    {
        pFactorA[i_limit+1] = 0;
    }


    SSE2_sqr( pResult,
               pFactorA,
               (i_limit)/2,
               (x_limit+1)/2);
}


#endif


