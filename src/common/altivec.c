/*
 * altivec.c
 *
 * Very Long Integer Library
 *
 * Support for Altivec optimizations
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

#ifdef __ALTIVEC__
#include <altivec.h>


/*---------------------------------------------------------------------------*/

static MSTATUS
ALTIVEC_mult(vector unsigned int *pVec1, ubyte4 len1,
             vector unsigned int *pVec2, ubyte4 len2,
             vector unsigned int *pResult, ubyte4 lenR)
{

    ubyte4 columnIndex;
    ubyte4 maxColumn;
    vector unsigned int *pLongSrc, *pShortSrc;
    ubyte4 shortcount, longcount;
    vector unsigned int sumlo = {0,0,0,0};
    vector unsigned int sumhi = {0,0,0,0};
    vector unsigned int zero = {0,0,0,0};
    vector unsigned char switchByteSelectorLo;
    vector unsigned char switchByteSelectorHi;
    vector unsigned char staggeredSumPermuterEven;
    vector unsigned char staggeredSumPermuterOdd;
    vector unsigned char unitsTransposer;
    vector unsigned int *pIncrementer;
    vector unsigned int *pDecrementer;
    vector unsigned int *pLongBound;
    vector unsigned int *pShortBound;
    ubyte4 productCount;

    if (len1 > len2)
    {
        pLongSrc    = pVec1;
        pShortSrc   = pVec2;
        longcount   = len1;
        shortcount  = len2;
    }
    else
    {
        pLongSrc    = pVec2;
        pShortSrc   = pVec1;
        longcount   = len2;
        shortcount  = len1;
    }

    if (longcount > 16384)
    {
        return ERR_BAD_LENGTH; /*vector multiply overflow*/
    }

    pLongBound =    pLongSrc;
    pShortBound =   pShortSrc;

    productCount =  1;

    for (columnIndex = 0; columnIndex < lenR; columnIndex++)
    {
        pResult[columnIndex] = (vector unsigned int) {0,0,0,0};
    }



    switchByteSelectorLo =  (vector unsigned char)
       ((vector unsigned int){0x001f001d, 0x001f001d, 0x001f001d, 0x001f001d});
    switchByteSelectorHi =  (vector unsigned char)
       ((vector unsigned int){0x001e001c, 0x001e001c, 0x001e001c, 0x001e001c});

    staggeredSumPermuterEven =  (vector unsigned char)
       ((vector unsigned int){0x04050607, 0x0c0d0e0f, 0x14151617, 0x1c1d1e1f});
    staggeredSumPermuterOdd =   (vector unsigned char)
       ((vector unsigned int){0x00010203, 0x08090a0b, 0x10111213, 0x18191a1b});

#ifdef __ENABLE_DIGICERT_64_BIT__
    unitsTransposer = ( vector unsigned char)
       ((vector unsigned int){0x08090A0B, 0x0C0D0E0F, 0x00010203, 0x04050607});
#else
   unitsTransposer = ( vector unsigned char)
       ((vector unsigned int){0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203});
#endif


    maxColumn = ( lenR + 1 < len1+len2)? lenR+1: len1+len2;
    for (columnIndex = 1; columnIndex < maxColumn; columnIndex++)
    {
        vector unsigned int currentLoSumHiOddBytes;
        vector unsigned int currentLoSumHiEvenBytes;
        vector unsigned int currentLoSumLoOddBytes;
        vector unsigned int currentLoSumLoEvenBytes;
        vector unsigned int currentHiSumHiOddBytes;
        vector unsigned int currentHiSumHiEvenBytes;
        vector unsigned int currentHiSumLoOddBytes;
        vector unsigned int currentHiSumLoEvenBytes;

        vector unsigned int tempsumhi, tempsumlo;

        vector unsigned int carrytemphi, carrytemplo;

        vector unsigned int carryhi, carrylo;

        vector unsigned int carrynext={0, 0, 0, 0};

        vector unsigned int p1, p2;

        int innerLoop, outerLoop;

        pIncrementer = pShortBound;
        pDecrementer = pLongBound;

        carryhi =(vector unsigned int) {0,0,0,0};
        carrylo =(vector unsigned int) {0,0,0,0};

        currentLoSumHiOddBytes =(vector unsigned int) {0,0,0,0};
        currentLoSumHiEvenBytes = (vector unsigned int){0,0,0,0};

        currentLoSumLoOddBytes =(vector unsigned int) {0,0,0,0};

        currentLoSumLoEvenBytes =(vector unsigned int) {0,0,0,0};

        currentHiSumHiOddBytes = (vector unsigned int) {0,0,0,0};
        currentHiSumHiEvenBytes = (vector unsigned int) {0,0,0,0};

        currentHiSumLoOddBytes = (vector unsigned int) {0,0,0,0};
        currentHiSumLoEvenBytes = (vector unsigned int) {0,0,0,0};

        for (outerLoop = 1; outerLoop <= productCount; outerLoop++)
        {

            vector unsigned short candVectorLoBytes;
            vector unsigned short candVectorHiBytes;

            vector unsigned short candHiVectorHorizontalHi;
            vector unsigned short candHiVectorHorizontalLo;
            vector unsigned short candLoVectorHorizontalHi;
            vector unsigned short candLoVectorHorizontalLo;

            /* combining the vec_perm with the other ops so that
               there is only 4 perms to generate the 4 vectors A3,
               A2, A1, and A0 does not improve performance */
            p1 = vec_perm( *pIncrementer++, zero, unitsTransposer);
            p2 = vec_perm( *pDecrementer--, zero, unitsTransposer);

            candLoVectorHorizontalHi = (vector unsigned short)
                vec_mergeh((vector unsigned short)p1,
                           (vector unsigned short)p1);
            candLoVectorHorizontalLo = (vector unsigned short)
                vec_mergel((vector unsigned short)p1,
                           (vector unsigned short)p1);

            candHiVectorHorizontalHi = (vector unsigned short) {0,0,0,0};

            candHiVectorHorizontalLo = vec_sld((vector unsigned short)zero,
                                               candLoVectorHorizontalHi, 2);
            candLoVectorHorizontalHi = vec_sld(candLoVectorHorizontalHi,
                                               candLoVectorHorizontalLo, 2);
            candLoVectorHorizontalLo = vec_sld(candLoVectorHorizontalLo,
                                               (vector unsigned short)zero, 2);
            /* cf article A3,A2,A1,A0
               candHiVectorHorizontalHi = (0, 0, 0, 0, 0, 0, 0, 0)
               candHiVectorHorizontalLo = (0, 0, 0, 0, 0, 0, 0, A)
               candLoVectorHorizontalHi = (A, B, B, C, C, D, D, E)
               candLoVectorHorizontalLo = (E, F, F, G, G, H, H, 0)
            */

            for (innerLoop = 0; innerLoop < 2; innerLoop++)
            {
                candVectorLoBytes = vec_perm((vector unsigned short)zero,
                                             (vector unsigned short)p2,
                                             switchByteSelectorLo);
                candVectorHiBytes = vec_perm((vector unsigned short)zero,
                                             (vector unsigned short)p2,
                                             switchByteSelectorHi);


                currentHiSumLoOddBytes = vec_msum(candHiVectorHorizontalLo,
                                                  candVectorHiBytes,
                                                  currentHiSumLoOddBytes);
                currentHiSumLoEvenBytes = vec_msum(candHiVectorHorizontalLo,
                                                     candVectorLoBytes,
                                                     currentHiSumLoEvenBytes);
                candHiVectorHorizontalHi = vec_sld(candHiVectorHorizontalHi,
                                                    candHiVectorHorizontalLo,
                                                    8);
                candHiVectorHorizontalLo = vec_sld(candHiVectorHorizontalLo,
                                                    candLoVectorHorizontalHi,
                                                    8);

                currentLoSumHiOddBytes = vec_msum(candLoVectorHorizontalHi,
                                                     candVectorHiBytes,
                                                     currentLoSumHiOddBytes);
                currentLoSumHiEvenBytes = vec_msum(candLoVectorHorizontalHi,
                                                     candVectorLoBytes,
                                                     currentLoSumHiEvenBytes);

                currentLoSumLoOddBytes = vec_msum(candLoVectorHorizontalLo,
                                                     candVectorHiBytes,
                                                  currentLoSumLoOddBytes);
                currentLoSumLoEvenBytes = vec_msum(candLoVectorHorizontalLo,
                                                   candVectorLoBytes,
                                                   currentLoSumLoEvenBytes);

                candLoVectorHorizontalHi = vec_sld(candLoVectorHorizontalHi,
                                                   candLoVectorHorizontalLo,
                                                   8);
                candLoVectorHorizontalLo = vec_sld(candLoVectorHorizontalLo,
                                                   (vector unsigned short)zero,
                                                   8);
                p2 = vec_sld(zero, p2, 12);
            }

            /*
             Perform a loop similar to the one above, except we do not do
             the partial products for the low half of the low vector, since
             we know that it will be zero.  The partial products of these
             msums will be added to the results of the previous loop.
            */
            for (innerLoop = 0; innerLoop < 2; innerLoop++)
            {
                candVectorLoBytes = vec_perm((vector unsigned short)zero,
                                             (vector unsigned short)p2,
                                             switchByteSelectorLo);
                candVectorHiBytes = vec_perm((vector unsigned short)zero,
                                             (vector unsigned short)p2,
                                             switchByteSelectorHi);


                currentHiSumHiOddBytes = vec_msum(candHiVectorHorizontalHi,
                                                  candVectorHiBytes,
                                                  currentHiSumHiOddBytes);
                currentHiSumHiEvenBytes = vec_msum(candHiVectorHorizontalHi,
                                                   candVectorLoBytes,
                                                   currentHiSumHiEvenBytes);

                currentHiSumLoOddBytes = vec_msum(candHiVectorHorizontalLo,
                                                  candVectorHiBytes,
                                                  currentHiSumLoOddBytes);
                currentHiSumLoEvenBytes = vec_msum(candHiVectorHorizontalLo,
                                                   candVectorLoBytes,
                                                   currentHiSumLoEvenBytes);

                candHiVectorHorizontalHi = vec_sld(candHiVectorHorizontalHi,
                                                   candHiVectorHorizontalLo,
                                                   8);
                candHiVectorHorizontalLo = vec_sld(candHiVectorHorizontalLo,
                                                   candLoVectorHorizontalHi,
                                                   8);

                currentLoSumHiOddBytes = vec_msum(candLoVectorHorizontalHi,
                                                  candVectorHiBytes,
                                                  currentLoSumHiOddBytes);
                currentLoSumHiEvenBytes = vec_msum(candLoVectorHorizontalHi,
                                                   candVectorLoBytes,
                                                   currentLoSumHiEvenBytes);

                candLoVectorHorizontalHi = vec_sld(candLoVectorHorizontalHi,
                                                    candLoVectorHorizontalLo,
                                                   8);

                p2 = vec_sld(zero, p2, 12);
            }

            if ( (!(outerLoop & 0x3f)) || outerLoop == productCount)
            {
                tempsumhi = vec_perm(currentHiSumHiEvenBytes,
                                     currentHiSumLoEvenBytes,
                                     staggeredSumPermuterEven);
                tempsumlo = vec_perm(currentLoSumHiEvenBytes,
                                     currentLoSumLoEvenBytes,
                                     staggeredSumPermuterEven);

                carrytemphi = vec_addc(tempsumhi, sumhi);
                carrytemplo = vec_addc(tempsumlo, sumlo);

                carryhi = vec_add(carryhi, carrytemphi);
                carrylo = vec_add(carrylo, carrytemplo);

                /* add to sum */
                sumhi = vec_add(tempsumhi, sumhi);
                sumlo = vec_add(tempsumlo, sumlo);

                tempsumhi = vec_perm(currentHiSumHiOddBytes,
                                     currentHiSumLoOddBytes,
                                     staggeredSumPermuterEven);
                tempsumlo = vec_perm(currentLoSumHiOddBytes,
                                     currentLoSumLoOddBytes,
                                     staggeredSumPermuterEven);

                carrytemphi = vec_sld(zero, tempsumhi, 1);
                carrynext = vec_add(carrynext, carrytemphi);

                /* shift elements */
                tempsumhi = vec_sld(tempsumhi, tempsumlo, 1);
                tempsumlo = vec_sld(tempsumlo, zero, 1);

                /* figure out carry */
                carrytemphi = vec_addc(tempsumhi, sumhi);
                carrytemplo = vec_addc(tempsumlo, sumlo);

                /* add carry to existing carries */
                carryhi = vec_add(carryhi, carrytemphi);
                carrylo = vec_add(carrylo, carrytemplo);

                /* add to sum */
                sumhi = vec_add(tempsumhi, sumhi);
                sumlo = vec_add(tempsumlo, sumlo);

                tempsumhi = vec_perm(currentHiSumHiEvenBytes,
                                     currentHiSumLoEvenBytes,
                                     staggeredSumPermuterOdd);
                tempsumlo = vec_perm(currentLoSumHiEvenBytes,
                                     currentLoSumLoEvenBytes,
                                     staggeredSumPermuterOdd);

                carrytemphi = vec_sld(zero, tempsumhi, 2);
                carrynext = vec_add(carrynext, carrytemphi);

                /* shift elements */
                tempsumhi = vec_sld(tempsumhi, tempsumlo, 2);
                tempsumlo = vec_sld(tempsumlo, zero, 2);

                /* figure out carry */
                carrytemphi = vec_addc(tempsumhi, sumhi);
                carrytemplo = vec_addc(tempsumlo, sumlo);

                /* add carry to previous carry */
                carryhi = vec_add(carryhi, carrytemphi);
                carrylo = vec_add(carrylo, carrytemplo);

                /* add to sum */
                sumhi = vec_add(tempsumhi, sumhi);
                sumlo = vec_add(tempsumlo, sumlo);

                /* select out elements */
                tempsumhi = vec_perm(currentHiSumHiOddBytes,
                                     currentHiSumLoOddBytes,
                                     staggeredSumPermuterOdd);
                tempsumlo = vec_perm(currentLoSumHiOddBytes,
                                     currentLoSumLoOddBytes,
                                     staggeredSumPermuterOdd);

                /* figure out how much shifts out of the vector, and add it to the carry */
                carrytemphi = vec_sld(zero, tempsumhi, 3);
                carrynext = vec_add(carrynext, carrytemphi);

                /* shift elements */
                tempsumhi = vec_sld(tempsumhi, tempsumlo, 3);
                tempsumlo = vec_sld(tempsumlo, zero, 3);

                /* figure out carry */
                carrytemphi = vec_addc(tempsumhi, sumhi);
                carrytemplo = vec_addc(tempsumlo, sumlo);

                /* add carry to previous carry */
                carryhi = vec_add(carryhi, carrytemphi);
                carrylo = vec_add(carrylo, carrytemplo);

                /* add to sum */
                sumhi = vec_add(tempsumhi, sumhi);
                sumlo = vec_add(tempsumlo, sumlo);

                if (outerLoop != productCount) {
                    currentLoSumHiOddBytes =    (vector unsigned int){0,0,0,0};
                    currentLoSumHiEvenBytes =   (vector unsigned int){0,0,0,0};

                    currentLoSumLoOddBytes =    (vector unsigned int){0,0,0,0};
                    currentLoSumLoEvenBytes =   (vector unsigned int){0,0,0,0};

                    currentHiSumHiOddBytes =    (vector unsigned int){0,0,0,0};
                    currentHiSumHiEvenBytes =   (vector unsigned int){0,0,0,0};

                    currentHiSumLoOddBytes =    (vector unsigned int){0,0,0,0};
                    currentHiSumLoEvenBytes =   (vector unsigned int){0,0,0,0};
                }

            }

        }

        /*
         * We have finished adding all partial products together, so now
         * we need to reconcile all carries. We repeatedly shift the
         * carries left by 32 bits, add them, and figure out the new
         * resulting carry.
         */

        do
        {
            /* add any overflow to carry for next column */
            carrynext = vec_add(carrynext, vec_sld(zero, carryhi, 4));

            /* shift carries left 32 bits */
            carryhi = vec_sld(carryhi, carrylo, 4);
            carrylo = vec_sld(carrylo, zero, 4);

            /* figure out new high carry */
            carrytemphi = vec_addc(carryhi, sumhi);

            /* add carry to sum */
            sumhi = vec_add(carryhi, sumhi);

            /* save new carry */
            carryhi = carrytemphi;

            /* figure out new low carry */
            carrytemplo = vec_addc(carrylo, sumlo);

            /* add carry to sum */
            sumlo = vec_add(carrylo, sumlo);

            /* save new carry */
            carrylo = carrytemplo;
        } while (!vec_all_eq(zero, vec_or(carryhi, carrylo)));


        /*
         * save this result, and increment pointer for storage of
         * next result.
         */
        *pResult++ = vec_perm(sumlo, zero, unitsTransposer);

        /*
         * This column's high result is added in as part of next column's
         * low result, and our carry goes in to the next columns high
         * result.
         */
        sumlo = sumhi;
        sumhi = carrynext;

        /*
         * move bounds pointers to point to new bounds of 128-bit
         * multiplicand elements.
         */
        if (columnIndex < shortcount)
        {
            pLongBound++;
            productCount++;
        }
        else if (columnIndex < longcount)
        {
            pLongBound++;
        }
        else
        {
            productCount--;
            pShortBound++;
        }
    }

    /*
     * save the final column's result
     */
    if ( columnIndex <= lenR)
    {
        *pResult = vec_perm(sumlo, zero, unitsTransposer);
    }

    return OK;
}


static MSTATUS
ALTIVEC_sqr( vector unsigned int *pVec1, ubyte4 len1,
                vector unsigned int *pResult, ubyte4 lenR)
{
    ubyte4                     columnIndex;
    ubyte4                     maxColumn;
    vector unsigned int        sumlo       = (vector unsigned int){0,0,0,0};
    vector unsigned int        sumhi       = (vector unsigned int){0,0,0,0};
    vector unsigned int        zero        = (vector unsigned int){0,0,0,0};
    vector unsigned char        switchByteSelectorLo;
    vector unsigned char        switchByteSelectorHi;
    vector unsigned char        staggeredSumPermuterEven;
    vector unsigned char        staggeredSumPermuterOdd;
    vector unsigned char       unitsTransposer;
    vector unsigned int        *pIncrementer;
    vector unsigned int        *pDecrementer;
    vector unsigned int        *pTopBound;
    vector unsigned int        *pBottomBound;
    ubyte4                      productCount;
    sbyte4                      singleadd;
    sbyte4                      singlenext;
    sbyte4                      lastproduct;
    sbyte4                      outerloopcount=0;

    if (len1 > 16384)
    {
        return ERR_BAD_LENGTH;
    }

    pTopBound = pVec1;
    pBottomBound = pVec1;

    productCount = 1;

    for (columnIndex = 0; columnIndex < lenR; columnIndex++)
    {
        pResult[columnIndex] = (vector unsigned int){0,0,0,0};
    }

    switchByteSelectorLo = (vector unsigned char)
       ((vector unsigned int) {0x001f001d, 0x001f001d, 0x001f001d, 0x001f001d});
    switchByteSelectorHi = (vector unsigned char)
       ((vector unsigned int){0x001e001c, 0x001e001c, 0x001e001c, 0x001e001c});

    staggeredSumPermuterEven = (vector unsigned char)
       ((vector unsigned int){0x04050607, 0x0c0d0e0f, 0x14151617, 0x1c1d1e1f});
    staggeredSumPermuterOdd = (vector unsigned char)
       ((vector unsigned int){0x00010203, 0x08090a0b, 0x10111213, 0x18191a1b});

#ifdef __ENABLE_DIGICERT_64_BIT__
    unitsTransposer = ( vector unsigned char)
       ((vector unsigned int){0x08090A0B, 0x0C0D0E0F, 0x00010203, 0x04050607});
#else
    unitsTransposer = ( vector unsigned char)
       ((vector unsigned int){0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203});
#endif

    maxColumn = (lenR + 1 < 2 * len1)? lenR+1 : 2 * len1;
    for (columnIndex = 1; columnIndex < maxColumn; columnIndex++)
    {
        vector unsigned int currentLoSumHiOddBytes;
        vector unsigned int currentLoSumHiEvenBytes;
        vector unsigned int currentLoSumLoOddBytes;
        vector unsigned int currentLoSumLoEvenBytes;
        vector unsigned int currentHiSumHiOddBytes;
        vector unsigned int currentHiSumHiEvenBytes;
        vector unsigned int currentHiSumLoOddBytes;
        vector unsigned int currentHiSumLoEvenBytes;

        vector unsigned int tempsumhi, tempsumlo;

        vector unsigned int carrytemphi, carrytemplo;

        vector unsigned int carryhi, carrylo;

        vector unsigned int carrynext=(vector unsigned int){0,0,0,0};

        vector unsigned int p1, p2;

        int                     innerLoop;

        pIncrementer = pBottomBound;
        pDecrementer = pTopBound;

        carryhi = (vector unsigned int){0,0,0,0};
        carrylo = (vector unsigned int){0,0,0,0};

        currentLoSumHiOddBytes=(vector unsigned int){0,0,0,0};
        currentLoSumHiEvenBytes=(vector unsigned int){0,0,0,0};

        currentLoSumLoOddBytes=(vector unsigned int){0,0,0,0};
        currentLoSumLoEvenBytes=(vector unsigned int){0,0,0,0};

        currentHiSumHiOddBytes=(vector unsigned int){0,0,0,0};
        currentHiSumHiEvenBytes=(vector unsigned int){0,0,0,0};

        currentHiSumLoOddBytes=(vector unsigned int){0,0,0,0};
        currentHiSumLoEvenBytes=(vector unsigned int){0,0,0,0};

        do
        {

            vector unsigned short candVectorLoBytes;
            vector unsigned short candVectorHiBytes;

            vector unsigned short candHiVectorHorizontalHi;
            vector unsigned short candHiVectorHorizontalLo;
            vector unsigned short candLoVectorHorizontalHi;
            vector unsigned short candLoVectorHorizontalLo;

            p1 = vec_perm(*pIncrementer, zero, unitsTransposer);
            p2 = vec_perm(*pDecrementer, zero, unitsTransposer);

            candLoVectorHorizontalHi = (vector unsigned short)
                vec_mergeh((vector unsigned short)p1,
                           (vector unsigned short)p1);
            candLoVectorHorizontalLo = (vector unsigned short)
                vec_mergel((vector unsigned short)p1,
                           (vector unsigned short)p1);

            candHiVectorHorizontalHi = (vector unsigned short){0,0,0,0};
            candHiVectorHorizontalLo = vec_sld((vector unsigned short)zero,
                                               candLoVectorHorizontalHi, 2);
            candLoVectorHorizontalHi = vec_sld(candLoVectorHorizontalHi,
                                               candLoVectorHorizontalLo, 2);
            candLoVectorHorizontalLo = vec_sld(candLoVectorHorizontalLo,
                                               (vector unsigned short)zero, 2);


            /*
              We now have these four partial multiplicand vectors:

              candHiVectorHorizontalHi = (0, 0, 0, 0, 0, 0, 0, 0)
              candHiVectorHorizontalLo = (0, 0, 0, 0, 0, 0, 0, A)
              candLoVectorHorizontalHi = (A, B, B, C, C, D, D, E)
              candLoVectorHorizontalLo = (E, F, F, G, G, H, H, 0)
            */


            for (innerLoop = 0; innerLoop < 2; innerLoop++)
            {

                candVectorLoBytes = vec_perm((vector unsigned short)zero,
                                             (vector unsigned short)p2,
                                             switchByteSelectorLo);
                candVectorHiBytes = vec_perm((vector unsigned short)zero,
                                             (vector unsigned short)p2,
                                             switchByteSelectorHi);

                currentHiSumLoOddBytes = vec_msum(candHiVectorHorizontalLo,
                                                  candVectorHiBytes,
                                                  currentHiSumLoOddBytes);
                currentHiSumLoEvenBytes = vec_msum(candHiVectorHorizontalLo,
                                                   candVectorLoBytes,
                                                   currentHiSumLoEvenBytes);

                candHiVectorHorizontalHi = vec_sld(candHiVectorHorizontalHi,
                                                   candHiVectorHorizontalLo,
                                                   8);
                candHiVectorHorizontalLo = vec_sld(candHiVectorHorizontalLo,
                                                   candLoVectorHorizontalHi,
                                                   8);


                currentLoSumHiOddBytes = vec_msum(candLoVectorHorizontalHi,
                                                  candVectorHiBytes,
                                                  currentLoSumHiOddBytes);
                currentLoSumHiEvenBytes = vec_msum(candLoVectorHorizontalHi,
                                                   candVectorLoBytes,
                                                   currentLoSumHiEvenBytes);

                currentLoSumLoOddBytes = vec_msum(candLoVectorHorizontalLo,
                                                  candVectorHiBytes,
                                                  currentLoSumLoOddBytes);
                currentLoSumLoEvenBytes = vec_msum(candLoVectorHorizontalLo,
                                                   candVectorLoBytes,
                                                   currentLoSumLoEvenBytes);

                candLoVectorHorizontalHi = vec_sld(candLoVectorHorizontalHi,
                                                   candLoVectorHorizontalLo,
                                                   8);
                candLoVectorHorizontalLo = vec_sld(candLoVectorHorizontalLo,
                                                   (vector unsigned short)zero,
                                                   8);

                p2 = vec_sld(zero, p2, 12);
            }

            for (innerLoop = 0; innerLoop < 2; innerLoop++)
            {
                candVectorLoBytes = vec_perm((vector unsigned short)zero,
                                             (vector unsigned short)p2,
                                             switchByteSelectorLo);
                candVectorHiBytes = vec_perm((vector unsigned short)zero,
                                             (vector unsigned short)p2,
                                             switchByteSelectorHi);
                currentHiSumHiOddBytes = vec_msum(candHiVectorHorizontalHi,
                                                  candVectorHiBytes,
                                                  currentHiSumHiOddBytes);
                currentHiSumHiEvenBytes = vec_msum(candHiVectorHorizontalHi,
                                                   candVectorLoBytes,
                                                   currentHiSumHiEvenBytes);

                currentHiSumLoOddBytes = vec_msum(candHiVectorHorizontalLo,
                                                  candVectorHiBytes,
                                                  currentHiSumLoOddBytes);
                currentHiSumLoEvenBytes = vec_msum(candHiVectorHorizontalLo,
                                                   candVectorLoBytes,
                                                   currentHiSumLoEvenBytes);

                candHiVectorHorizontalHi = vec_sld(candHiVectorHorizontalHi,
                                                   candHiVectorHorizontalLo,
                                                   8);
                candHiVectorHorizontalLo = vec_sld(candHiVectorHorizontalLo,
                                                   candLoVectorHorizontalHi,
                                                   8);

                currentLoSumHiOddBytes = vec_msum(candLoVectorHorizontalHi,
                                                  candVectorHiBytes,
                                                  currentLoSumHiOddBytes);
                currentLoSumHiEvenBytes = vec_msum(candLoVectorHorizontalHi,
                                                   candVectorLoBytes,
                                                   currentLoSumHiEvenBytes);

                candLoVectorHorizontalHi = vec_sld(candLoVectorHorizontalHi,
                                                   candLoVectorHorizontalLo,
                                                   8);

                p2 = vec_sld(zero, p2, 12);
            }


            singleadd = (pIncrementer++ == pDecrementer--);

            singlenext = (pIncrementer == pDecrementer);

            lastproduct = pDecrementer < pIncrementer;

            if ( (!(++outerloopcount & 0x1f)) || (singlenext | lastproduct))
            {
                if (!singleadd)
                {
                    currentLoSumHiOddBytes = vec_add(currentLoSumHiOddBytes,
                                                     currentLoSumHiOddBytes);
                    currentHiSumHiOddBytes = vec_add(currentHiSumHiOddBytes,
                                                     currentHiSumHiOddBytes);
                    currentLoSumLoOddBytes = vec_add(currentLoSumLoOddBytes,
                                                     currentLoSumLoOddBytes);
                    currentHiSumLoOddBytes = vec_add(currentHiSumLoOddBytes,
                                                     currentHiSumLoOddBytes);
                    currentLoSumHiEvenBytes = vec_add(currentLoSumHiEvenBytes,
                                                      currentLoSumHiEvenBytes);
                    currentHiSumHiEvenBytes = vec_add(currentHiSumHiEvenBytes,
                                                      currentHiSumHiEvenBytes);
                    currentLoSumLoEvenBytes = vec_add(currentLoSumLoEvenBytes,
                                                      currentLoSumLoEvenBytes);
                    currentHiSumLoEvenBytes = vec_add(currentHiSumLoEvenBytes,
                                                      currentHiSumLoEvenBytes);
                }

                /* select out elements */
                tempsumhi = vec_perm(currentHiSumHiEvenBytes,
                                     currentHiSumLoEvenBytes,
                                     staggeredSumPermuterEven);
                tempsumlo = vec_perm(currentLoSumHiEvenBytes,
                                     currentLoSumLoEvenBytes,
                                     staggeredSumPermuterEven);

                /* figure out carry from adding to sum */
                carrytemphi = vec_addc(tempsumhi, sumhi);
                carrytemplo = vec_addc(tempsumlo, sumlo);

                /* add in carry to existing carries */
                carryhi = vec_add(carryhi, carrytemphi);
                carrylo = vec_add(carrylo, carrytemplo);

                /* add to sum */
                sumhi = vec_add(tempsumhi, sumhi);
                sumlo = vec_add(tempsumlo, sumlo);


                /* select out elements */
                tempsumhi = vec_perm(currentHiSumHiOddBytes,
                                     currentHiSumLoOddBytes,
                                     staggeredSumPermuterEven);
                tempsumlo = vec_perm(currentLoSumHiOddBytes,
                                     currentLoSumLoOddBytes,
                                     staggeredSumPermuterEven);

                carrytemphi = vec_sld(zero, tempsumhi, 1);
                carrynext = vec_add(carrynext, carrytemphi);

                /* shift elements */
                tempsumhi = vec_sld(tempsumhi, tempsumlo, 1);
                tempsumlo = vec_sld(tempsumlo, zero, 1);

                /* figure out carry */
                carrytemphi = vec_addc(tempsumhi, sumhi);
                carrytemplo = vec_addc(tempsumlo, sumlo);

                /* add carry to existing carries */
                carryhi = vec_add(carryhi, carrytemphi);
                carrylo = vec_add(carrylo, carrytemplo);

                /* add to sum */
                sumhi = vec_add(tempsumhi, sumhi);
                sumlo = vec_add(tempsumlo, sumlo);

                /* select out elements */
                tempsumhi = vec_perm(currentHiSumHiEvenBytes,
                                     currentHiSumLoEvenBytes,
                                     staggeredSumPermuterOdd);
                tempsumlo = vec_perm(currentLoSumHiEvenBytes,
                                     currentLoSumLoEvenBytes,
                                     staggeredSumPermuterOdd);

                carrytemphi = vec_sld(zero, tempsumhi, 2);
                carrynext = vec_add(carrynext, carrytemphi);

                /* shift elements */
                tempsumhi = vec_sld(tempsumhi, tempsumlo, 2);
                tempsumlo = vec_sld(tempsumlo, zero, 2);

                /* figure out carry */
                carrytemphi = vec_addc(tempsumhi, sumhi);
                carrytemplo = vec_addc(tempsumlo, sumlo);

                /* add carry to previous carry */
                carryhi = vec_add(carryhi, carrytemphi);
                carrylo = vec_add(carrylo, carrytemplo);

                /* add to sum */
                sumhi = vec_add(tempsumhi, sumhi);
                sumlo = vec_add(tempsumlo, sumlo);

                /* select out elements */
                tempsumhi = vec_perm(currentHiSumHiOddBytes,
                                     currentHiSumLoOddBytes,
                                     staggeredSumPermuterOdd);
                tempsumlo = vec_perm(currentLoSumHiOddBytes,
                                     currentLoSumLoOddBytes,
                                     staggeredSumPermuterOdd);

                /* figure out how much shifts out of the vector, */
                /* and add it to the carry */
                carrytemphi = vec_sld(zero, tempsumhi, 3);
                carrynext = vec_add(carrynext, carrytemphi);

                /* shift elements */
                tempsumhi = vec_sld(tempsumhi, tempsumlo, 3);
                tempsumlo = vec_sld(tempsumlo, zero, 3);

                /* figure out carry */
                carrytemphi = vec_addc(tempsumhi, sumhi);
                carrytemplo = vec_addc(tempsumlo, sumlo);

                /* add carry to previous carry */
                carryhi = vec_add(carryhi, carrytemphi);
                carrylo = vec_add(carrylo, carrytemplo);

                /* add to sum */
                sumhi = vec_add(tempsumhi, sumhi);
                sumlo = vec_add(tempsumlo, sumlo);

                if (!lastproduct) {
                    currentLoSumHiOddBytes =    (vector unsigned int){0,0,0,0};
                    currentLoSumHiEvenBytes =   (vector unsigned int){0,0,0,0};

                    currentLoSumLoOddBytes =    (vector unsigned int){0,0,0,0};
                    currentLoSumLoEvenBytes =   (vector unsigned int){0,0,0,0};

                    currentHiSumHiOddBytes =    (vector unsigned int){0,0,0,0};
                    currentHiSumHiEvenBytes =   (vector unsigned int){0,0,0,0};

                    currentHiSumLoOddBytes =    (vector unsigned int){0,0,0,0};
                    currentHiSumLoEvenBytes =   (vector unsigned int){0,0,0,0};
                }
            }
        } while (!lastproduct);

        do
        {
            /* add any overflow to carry for next column */
            carrynext = vec_add(carrynext, vec_sld(zero, carryhi, 4));

            /* shift carries left 32 bits */
            carryhi = vec_sld(carryhi, carrylo, 4);
            carrylo = vec_sld(carrylo, zero, 4);

            /* figure out new high carry */
            carrytemphi = vec_addc(carryhi, sumhi);

            /* add carry to sum */
            sumhi = vec_add(carryhi, sumhi);

            /* save new carry */
            carryhi = carrytemphi;

            /* figure out new low carry */
            carrytemplo = vec_addc(carrylo, sumlo);

            /* add carry to sum */
            sumlo = vec_add(carrylo, sumlo);

            /* save new carry */
            carrylo = carrytemplo;
        } while (!vec_all_eq(zero, vec_or(carryhi, carrylo)));

        *pResult++ = vec_perm(sumlo, zero, unitsTransposer);


        /* This column's high result is added in as part of next column's
         * low result, and our carry goes in to the next columns high
         * result.
         */
        sumlo = sumhi;
        sumhi = carrynext;


        /* move bounds pointers to point to new bounds of 128-bit
           multiplicand elements.*/

        if (columnIndex < len1)
        {
            pTopBound++;
            productCount++;
        } else {
            productCount--;
            pBottomBound++;
        }
    }

    /* save the final column's result */
    if (columnIndex <= lenR)
    {
        *pResult = vec_perm(sumlo, zero, unitsTransposer);
    }
    return OK;
}


#ifdef __ENABLE_DIGICERT_64_BIT__
/* Note that you should probably not used Altivec on 64 bit CPU environment
   since tests show it's slower */

/*---------------------------------------------------------------------------*/

extern MSTATUS
ALTIVEC_multiply( ubyte8* pResult, ubyte8* pFactorA, ubyte8* pFactorB,
                  ubyte4 numUnitsA, ubyte4 numUnitsB, ubyte4 numUnitsR)
{
   ++numUnitsA;
   while (numUnitsA & 1)
   {
       if (pFactorA[numUnitsA])
       {
           pFactorA[numUnitsA] = 0;
       }
       ++numUnitsA;
   }

   ++numUnitsB;
   while (numUnitsB & 1)
   {
       if (pFactorB[numUnitsB])
       {
           pFactorB[numUnitsB] = 0;
       }
       ++numUnitsB;
   }

   return ALTIVEC_mult( (vector unsigned int*) pFactorA,
                         numUnitsA/2,
                         ( vector unsigned int*) pFactorB,
                         numUnitsB/2,
                         (vector unsigned int*) pResult,
                        (numUnitsR+1)/2);
}



/*---------------------------------------------------------------------------*/

extern MSTATUS
ALTIVEC_square( ubyte8* pResult, ubyte8* pFactorA, ubyte4 numUnitsA,
             ubyte4 numUnitsR)
{
   ++numUnitsA;
   while (numUnitsA & 1)
   {
       if (pFactorA[numUnitsA])
       {
           pFactorA[numUnitsA] = 0;
       }
       ++numUnitsA;
   }

   return ALTIVEC_sqr( (vector unsigned int*) pFactorA,
                         numUnitsA/2,
                         (vector unsigned int*) pResult,
                        (numUnitsR+1)/2);
}

#else

/*---------------------------------------------------------------------------*/

extern MSTATUS
ALTIVEC_multiply( ubyte4* pResult, ubyte4* pFactorA, ubyte4* pFactorB,
                  ubyte4 numUnitsA, ubyte4 numUnitsB, ubyte4 numUnitsR)
{
   ++numUnitsA;
   while (numUnitsA & 3)
   {
       if (pFactorA[numUnitsA])
       {
           pFactorA[numUnitsA] = 0;
       }
       ++numUnitsA;
   }

   ++numUnitsB;
   while (numUnitsB & 3)
   {
       if (pFactorB[numUnitsB])
       {
           pFactorB[numUnitsB] = 0;
       }
       ++numUnitsB;
   }

   return ALTIVEC_mult( (vector unsigned int*) pFactorA,
                         numUnitsA/4,
                         ( vector unsigned int*) pFactorB,
                         numUnitsB/4,
                         (vector unsigned int*) pResult,
                        (numUnitsR+3)/4);
}



/*---------------------------------------------------------------------------*/

extern MSTATUS
ALTIVEC_square( ubyte4* pResult, ubyte4* pFactorA, ubyte4 numUnitsA,
             ubyte4 numUnitsR)
{
   ++numUnitsA;
   while (numUnitsA & 3)
   {
       if (pFactorA[numUnitsA])
       {
           pFactorA[numUnitsA] = 0;
       }
       ++numUnitsA;
   }

   return ALTIVEC_sqr( (vector unsigned int*) pFactorA,
                         numUnitsA/4,
                         (vector unsigned int*) pResult,
                        (numUnitsR+3)/4);
}

#endif

#endif
/* __ALTIVEC__ */
