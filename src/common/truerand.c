/*
 * truerand.c
 *
 * Implementation of AT&T Bell Labs 'truerand' Algorithm
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
#include "../common/mrtos.h"
#include "../common/mstdlib.h"


/*------------------------------------------------------------------*/

#ifndef TRUERAND_DEPOT_SIZE_IN_BYTES
#define TRUERAND_DEPOT_SIZE_IN_BYTES        (32)
#endif


/*------------------------------------------------------------------*/

static ubyte4          m_coin;
static intBoolean      m_secondCoinToss;
static volatile ubyte4 m_counter;
static volatile ubyte4 m_bitPosition = 0;
static volatile ubyte4 m_numBitsRequired = 0;
static volatile ubyte  m_bitDepot[TRUERAND_DEPOT_SIZE_IN_BYTES];


/*------------------------------------------------------------------*/

extern intBoolean
TRUERAND_irqHandler(void)
{
    /* on return, if entropy generation has completed (isDone?) this function will return true */
    intBoolean isDone = FALSE;

    if (m_bitPosition >= m_numBitsRequired)
    {
        isDone = TRUE;
        goto exit;
    }

    /* Von Nuemann unbiasing coin toss algorithm */
    if (FALSE == m_secondCoinToss)
    {
        /* use the least significant bit as our coin toss */
        m_coin = (m_counter & 1);
    }
    else
    {
        /* remove the bias! */
        if (m_coin != (m_counter & 1))
        {
            if (m_coin)
            {
                /* coin was heads, set the bit */
                m_bitDepot[m_bitPosition / 8] |=  (1 << (m_bitPosition % 8));
            }
            else
            {
                /* coin was tails, clear the bit */
                m_bitDepot[m_bitPosition / 8] &= ~(1 << (m_bitPosition % 8));
            }

            /* setup for next bit */
            m_bitPosition++;

            /* did we collect enough bits? */
            if (m_bitPosition >= m_numBitsRequired)
                isDone = TRUE;
        }
    }

    /* oscillate between first and second coin toss */
    m_secondCoinToss = (TRUE == m_secondCoinToss) ? FALSE : TRUE;

exit:
    return isDone;
}


/*------------------------------------------------------------------*/

extern MSTATUS
TRUERAND_entropyCollector(ubyte *pRetEntopy, ubyte4 numBitsRequired,
                          void(*setTrueRandIrqHandler)(void))
{
    /* IMPORTANT: this code is not reentrant! it's intended use is for rng seed */
    ubyte4  tmpBitsRequired;
    ubyte4  tmpBytesRequired;
    ubyte4  numBitsCollected = 0;
    ubyte4  numBytesCollected = 0;
    MSTATUS status = OK;

    /* verify input is good */
    if (NULL == pRetEntopy)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* setup irq handler coin toss context */
    m_secondCoinToss = FALSE;

    do
    {
        /* set number of bits/bytes we can collect in one iteration */
        if ((TRUERAND_DEPOT_SIZE_IN_BYTES * 8) < (numBitsRequired - numBitsCollected))
        {
            tmpBitsRequired = (TRUERAND_DEPOT_SIZE_IN_BYTES * 8);
            tmpBytesRequired = TRUERAND_DEPOT_SIZE_IN_BYTES;
        }
        else
        {
            tmpBitsRequired = (numBitsRequired - numBitsCollected);
            tmpBytesRequired = ((numBitsRequired - numBitsCollected) + 7) / 8;
        }

        /* set bit collector counters */
        m_bitPosition = 0;
        m_numBitsRequired = tmpBitsRequired;

        /* enable irq handler for truerand, TRUERAND_irqHandler() should be invoked by timer interupt handler */
        setTrueRandIrqHandler();

        /* start tossing the coin continuously */
        while (m_bitPosition < tmpBitsRequired)
            m_counter++;

        /* copy over the entropy bits/bytes, yes this will round up the last byte */
        DIGI_MEMCPY(numBytesCollected + pRetEntopy, (ubyte *)m_bitDepot, tmpBytesRequired);

        /* jic - deal with collecting over partitions */
        numBitsCollected  += tmpBitsRequired;
        numBytesCollected += tmpBytesRequired;
    }
    while (numBitsCollected < numBitsRequired);

exit:
    return status;

} /* TRUERAND_entropyCollector */



