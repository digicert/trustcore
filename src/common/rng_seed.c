/**
 * @file  rng_seed.c
 * @brief A random number generator seed
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
#include "../common/rng_seed.h"
#include "../crypto/sha1.h"
#include "../harness/harness.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_sha1.h"
#endif

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

#ifdef __ENABLE_DIGICERT_DEV_URANDOM__
#ifndef __ENABLE_DIGICERT_VALGRIND_SUPPORT__
#define __ENABLE_DIGICERT_VALGRIND_SUPPORT__
#endif
#endif

#ifdef __ENABLE_DIGICERT_VALGRIND_SUPPORT__
#include <stdio.h>
#endif


#ifndef __DISABLE_DIGICERT_RNG__
/*------------------------------------------------------------------*/
#define MOCANA_RAND_ENTROPY3_KILLWAIT_TIME   700
#define MOCANA_RAND_ENTROPY2_KILLWAIT_TIME   300
#define MOCANA_RAND_ENTROPY1_KILLWAIT_TIME   100

#if (!defined(RNG_SEED_BUFFER_SIZE))
#define RNG_SEED_BUFFER_SIZE        (64)
#endif

#if (!defined(RNG_SEED_ROUNDS))
#define RNG_SEED_ROUNDS             (8)
#endif

#define RNG_SEED_NUM_SHA1_ROUNDS    ((RNG_SEED_BUFFER_SIZE + (SHA1_RESULT_SIZE - 1)) / SHA1_RESULT_SIZE)


#if defined(__ENABLE_DIGICERT_RNG_SEED_STATE_DEBUG__) || defined(__ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__)

#ifdef __KERNEL__
#define PRINTDBG printk
#else
#include <stdio.h>
#define PRINTDBG printf
#endif

#endif

/*------------------------------------------------------------------*/

typedef enum
{
    kEntropyInit = 0,
    kEntropyStart,
    kEntropyWorking,
    kEntropyDone,
    kEntropyIdle,
    kEntropyDead

} entropyThreadState;


/*------------------------------------------------------------------*/

#if (defined(_DEBUG))
/* when in debug mode we disable this to prevent normally helpful debugger warnings */
#define RNG_SEED_DEBUG_RESET(X)     X = 0
#else
#define RNG_SEED_DEBUG_RESET(X)     X = X
#endif

/* Our collection of entropy - must be volatile to prevent */
/* compiler optimizations that may reduce our entropy collecting */
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
static volatile ubyte               m_entropyByteDepotHistory[RNG_SEED_BUFFER_SIZE + SHA1_RESULT_SIZE];
#endif

static volatile ubyte               m_entropyByteDepot[RNG_SEED_BUFFER_SIZE + SHA1_RESULT_SIZE];
static volatile ubyte               m_entropyScratch[RNG_SEED_BUFFER_SIZE + SHA1_RESULT_SIZE];
static volatile ubyte4              m_indexEntropyByteDepot = 0;
static volatile ubyte4              m_indexEntropyBitIn = 0;

#define BITINMODVAL (8 * RNG_SEED_BUFFER_SIZE)

/* for entropy thread ipc mechanism */
static volatile entropyThreadState mEntropyThreadState1;
static volatile entropyThreadState mEntropyThreadState2;
static volatile entropyThreadState mEntropyThreadState3;
static volatile entropyThreadState mEntropyThreadsState;

static volatile intBoolean          mShouldEntropyThreadsDie  = FALSE;

static intBoolean                   mIsRngSeedInit            = FALSE;
static intBoolean                   mIsRngSeedThreadInit      = FALSE;
static RTOS_MUTEX                   mRngSeedMutex;
static RTOS_MUTEX                   mRngSeedThreadMutex;


/*------------------------------------------------------------------*/

static RTOS_THREAD ethread01 = NULL;
static RTOS_THREAD ethread02 = NULL;
static RTOS_THREAD ethread03 = NULL;

static MSTATUS RNG_SEED_createInitialState(void);
/*------------------------------------------------------------------*/

static void
RNG_SEED_scramble(void)
{
    sbyte4  i, j, k, l;

    for (i = 0; i < RNG_SEED_NUM_SHA1_ROUNDS; ++i)
    {
        ubyte* w = (ubyte *)&(m_entropyScratch[i * SHA1_RESULT_SIZE]);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_SHA1_G((ubyte *)m_entropyScratch, w);
#else
        SHA1_G((ubyte *)m_entropyScratch, w);
#endif

        k = RNG_SEED_NUM_SHA1_ROUNDS;
        j = (k - (i + 1));
        l = j * SHA1_RESULT_SIZE;
    }
    (void)l;   /* variable is set but not used */
}


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__

/**
 * @brief    Wait until all three sibling threads are ready to start working.
 * @details  This function will wait until all three sibling threads are in the
 *           kEntropyStart state before setting them all off working
 *           simultaneously. Each thread will continously scramble the buffer
 *           until all threads are ready to start work.
 *
 * @param threadCount  Calling thread number, only used for debug output.
 * @param value        Value to keep xor'ing with buffer while waiting.
 *
 * @return  \c OK (0) when all threads are ready to start.
 *
 * @note  This function has no timeout, if for some reason one of the sibling
 *        threads fails to initialize properly the other threads will wait
 *        for it indefinitely.
 *
 * @par Flags
 * To enable this function the following flags must \n not be defined:
 *   + \c \__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
 *   .
 */
static MSTATUS
RNG_SEED_entropyThreadWaitForStart(ubyte4 threadCount,
                                   ubyte value)
{
    ubyte4      RNG_SEED_DEBUG_RESET(index);      /* don't initialize var */
    intBoolean  isMutexSet = FALSE;
    MSTATUS     status = OK;

    do
    {
        if (FALSE != mShouldEntropyThreadsDie)
        {
            status = ERR_RAND_TERMINATE_THREADS;
            goto exit;
        }

        /* while we are waiting for everyone to be ready, let's keep scrambling the scratch buffer */
        /* use of unitialized 'index' OK */
        /* coverity[uninit_use] */
        index = ((1 + index) % RNG_SEED_BUFFER_SIZE);
        m_entropyScratch[index] ^= value;
        RNG_SEED_scramble();

        RTOS_sleepMS(50);

        /* make sure everyone is sync'd up to ready state before moving to next state */
        MRTOS_mutexWait(mRngSeedThreadMutex, &isMutexSet);


#ifdef __ENABLE_DIGICERT_RNG_SEED_STATE_DEBUG__
        PRINTDBG("RNG_SEED_entropyThreadWaitForStart [%d]: %d, %d, %d, %d\n", threadCount, mEntropyThreadState1, mEntropyThreadState2, mEntropyThreadState3, mEntropyThreadsState);
#endif

        if ((kEntropyWorking != mEntropyThreadsState) &&
            (kEntropyStart   == mEntropyThreadState1)  &&
            (kEntropyStart   == mEntropyThreadState2)  &&
            (kEntropyStart   == mEntropyThreadState3))
        {
            mEntropyThreadsState = kEntropyWorking;
        }

        MRTOS_mutexRelease(mRngSeedThreadMutex, &isMutexSet);
    }
    while (kEntropyWorking != mEntropyThreadsState);

exit:
    if (TRUE == isMutexSet)
        MRTOS_mutexRelease(mRngSeedThreadMutex, &isMutexSet);

    return status;
}
#endif /* __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__ */


/*------------------------------------------------------------------*/

static void RNG_SEED_entropyMoveScratchToDepot(void)
{
    /* xor copy out the newly generated scratch data into the depot */
    DIGI_XORCPY((void *)m_entropyByteDepot, (void *)m_entropyScratch, RNG_SEED_BUFFER_SIZE);

    /* scramble previous seed to prevent eaves droppers */
    RNG_SEED_scramble();

    /* indicate number of bytes available in the depot */
    m_indexEntropyByteDepot = 0;

}

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__

/**
 * @brief    Wait until all three sibling threads are done working.
 * @details  This function will wait until all three sibling threads are in the
 *           kEntropyDone state before copying the result from the scratch
 *           buffer to the actual entropy deopt.  Each thread will continously
 *           scramble the buffer until all threads are done.
 *
 * @param threadCount  Calling thread number, only used for debug output.
 * @param value        Value to keep xor'ing with buffer while waiting.
 *
 * @return  \c OK (0) when all threads are ready to start.
 *
 * @note  This function has no timeout, if for some reason one of the sibling
 *        threads fails to complete properly the other threads will wait
 *        for it indefinitely.
 *
 * @par Flags
 * To enable this function the following flags must \n not be defined:
 *   + \c \__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
 *   .
 */
static MSTATUS
RNG_SEED_entropyThreadWaitForDone(ubyte4 threadCount,
                                  ubyte value)
{
    ubyte4      RNG_SEED_DEBUG_RESET(index);      /* don't initialize var */
    intBoolean  isMutexSet = FALSE;
    MSTATUS     status = OK;

    do
    {
        if (FALSE != mShouldEntropyThreadsDie)
        {
            status = ERR_RAND_TERMINATE_THREADS;
            goto exit;
        }

        /* while we are waiting for everyone to be done, let's keep scrambling the scratch buffer */
        /* use of unitialized 'index' OK */
        /* coverity[uninit_use] */
        index = ((1 + index) % RNG_SEED_BUFFER_SIZE);
        m_entropyScratch[index] ^= value;
        RNG_SEED_scramble();

        RTOS_sleepMS(50);

        MRTOS_mutexWait(mRngSeedThreadMutex, &isMutexSet);

#ifdef __ENABLE_DIGICERT_RNG_SEED_STATE_DEBUG__
        PRINTDBG("RNG_SEED_entropyThreadWaitForDone [%d]: %d, %d, %d, %d\n", threadCount, mEntropyThreadState1, mEntropyThreadState2, mEntropyThreadState3, mEntropyThreadsState);
#endif

        if ((kEntropyIdle != mEntropyThreadsState) &&
            (kEntropyDone == mEntropyThreadState1) &&
            (kEntropyDone == mEntropyThreadState2) &&
            (kEntropyDone == mEntropyThreadState3))
        {
            RNG_SEED_entropyMoveScratchToDepot();

            mEntropyThreadsState = kEntropyIdle;
        }

        MRTOS_mutexRelease(mRngSeedThreadMutex, &isMutexSet);
    }
    while (kEntropyIdle != mEntropyThreadsState);

exit:
    MRTOS_mutexRelease(mRngSeedThreadMutex, &isMutexSet);

    return status;
}
#endif /* __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__ */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__

/**
 * @brief    First thread specific interactions for entropy generation.
 * @details  This function will interact with the common buffer in a
 *           unique way to generate entropy.  After all threads are synched to
 *           begin working this thread performs its operation in rounds, each
 *           round consists of a loop from zero until the end of the buffer.
 *           For each iteration of the loop, the 5th bit of the octet is flipped
 *           before sleeping for 13-15 miliseconds. Performing the
 *           bit flip is non-blocking, so it is possible that the bit flip is
 *           lost or another threads change is lost thus generating entropy.
 *
 * @par Flags
 * To enable this function, the following flags must \b not be defined:
 *   + \c \__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
 *   .
 */
static void
RNG_SEED_entropyThread1(void* context)
{
    do
    {
        moctime_t       startTime;
        sbyte4          i;
        sbyte4          j;

        mEntropyThreadState1 = kEntropyStart;

        if (OK > (RNG_SEED_entropyThreadWaitForStart(1, 0x11)))
            goto exit;

        mEntropyThreadState1 = kEntropyWorking;

        for (i = 0; i < RNG_SEED_ROUNDS; i++)
        {
            RTOS_deltaMS(NULL, &startTime);

            for (j = 0; j < RNG_SEED_BUFFER_SIZE; j++)
            {
                if (FALSE != mShouldEntropyThreadsDie)
                    goto exit;

                m_entropyScratch[j] ^= 0x10;
                RTOS_sleepMS(((RTOS_deltaMS(&startTime, NULL) >> 1) & 0x3) + 13);
            }
        }

        mEntropyThreadState1 = kEntropyDone;

        RTOS_deltaMS(NULL, &startTime);

        /* keep running until thread 3 is done */
        while (kEntropyDone != mEntropyThreadState3)
        {
            if (FALSE != mShouldEntropyThreadsDie)
                goto exit;

            for (i = 0; ((RNG_SEED_BUFFER_SIZE > i) && (kEntropyDone != mEntropyThreadState3)); i++)
            {
                if (FALSE != mShouldEntropyThreadsDie)
                    goto exit;
                m_entropyScratch[i] ^= 0x10;
                RTOS_sleepMS(((RTOS_deltaMS(&startTime, NULL) >> 1) & 0x3) + 13);
            }
        }

        if (OK > (RNG_SEED_entropyThreadWaitForDone(1, 0x90)))
            goto exit;

        mEntropyThreadState1 = kEntropyIdle;

        while ((FALSE == mShouldEntropyThreadsDie) && (kEntropyIdle == mEntropyThreadState1))
            RTOS_sleepMS(MOCANA_RAND_ENTROPY1_KILLWAIT_TIME);
    }
    while (FALSE == mShouldEntropyThreadsDie);

exit:
    mShouldEntropyThreadsDie = TRUE;
    mEntropyThreadState1 = kEntropyDead;

    return;

} /* RNG_SEED_entropyThread1 */
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__

/**
 * @brief    Second thread specific interactions for entropy generation.
 * @details  This function will interact with the common buffer in a
 *           unique way to generate entropy.  After all threads are synched to
 *           begin working this thread performs its operation in rounds, each
 *           round consists of a loop from the end of the buffer to zero (note
 *           that this loops in reverse of thread 1, thread 1 loops low to high
 *           while thread 2 loops high to low).  Each iteration of the loop
 *           modifies the octet in a decreasing manner then sleeps for 7-9
 *           milliseconds. Interrupts and context switches in the system will
 *           generate entropy.
 *
 * @par Flags
 * To enable this function, the following flags must \b not be defined:
 *   + \c \__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
 *   .
 */
static void
RNG_SEED_entropyThread2(void* context)
{
    do
    {
        moctime_t       startTime;
        sbyte4          i;
        sbyte4          j;

        mEntropyThreadState2 = kEntropyStart;

        if (OK > (RNG_SEED_entropyThreadWaitForStart(2, 0x22)))
            goto exit;

        mEntropyThreadState2 = kEntropyWorking;

        for (i = 0; i < RNG_SEED_ROUNDS; i++)
        {
            RTOS_deltaMS(NULL, &startTime);

            for (j = RNG_SEED_BUFFER_SIZE - 1; j >= 0; j--)
            {
                ubyte4 newval;

                if (FALSE != mShouldEntropyThreadsDie)
                    goto exit;

                newval = m_entropyScratch[j];
                newval = (newval ^ (newval >> 2) ^ (newval >> 5) ^ (newval * 13) ^ (newval * 37) ^ (newval * 57)) & 0xff;
                m_entropyScratch[j] = (ubyte)newval;

                RTOS_sleepMS(((RTOS_deltaMS(&startTime, NULL) >> 1) & 0x3) + 7);
            }
        }

        mEntropyThreadState2 = kEntropyDone;

        RTOS_deltaMS(NULL, &startTime);

        /* keep running until thread 3 is done */
        while (kEntropyDone != mEntropyThreadState3)
        {
            for (i = RNG_SEED_BUFFER_SIZE - 1; ((i >= 0) && (kEntropyDone != mEntropyThreadState3)); i--)
            {
                ubyte4 newval;

                if (FALSE != mShouldEntropyThreadsDie)
                    goto exit;

                newval = m_entropyScratch[i];
                newval = (newval ^ (newval >> 2) ^ (newval >> 5) ^ (newval * 13) ^ (newval * 37) ^ (newval * 57)) & 0xff;
                m_entropyScratch[i] = (ubyte)newval;

                RTOS_sleepMS(((RTOS_deltaMS(&startTime, NULL) >> 1) & 0x3) + 7);
            }
        }

        if (OK > (RNG_SEED_entropyThreadWaitForDone(2, 0xa2)))
            goto exit;

        mEntropyThreadState2 = kEntropyIdle;

        while ((FALSE == mShouldEntropyThreadsDie) && (kEntropyIdle == mEntropyThreadState2))
            RTOS_sleepMS(MOCANA_RAND_ENTROPY2_KILLWAIT_TIME);
    }
    while (FALSE == mShouldEntropyThreadsDie);

exit:
    mShouldEntropyThreadsDie = TRUE;
    mEntropyThreadState2 = kEntropyDead;

    return;
}
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__

/**
 * @brief    Third thread specific interactions for entropy generation.
 * @details  This function will interact with the common buffer in a
 *           unique way to generate entropy.  After all threads are synched to
 *           begin working this thread performs its operation in rounds, each
 *           round consists of a loop that executes 6 times.  Each iteration of
 *           the loop scrambles the buffer for (loop counter)*7 milliseconds
 *           before sleeping for 3-5 milliseconds.  This is nearly always the
 *           last of the three sibling threads to complete.
 *
 * @par Flags
 * To enable this function, the following flags must \b not be defined:
 *   + \c \__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
 *   .
 */
static void
RNG_SEED_entropyThread3(void* context)
{
    do
    {
        ubyte4          i;
        ubyte4          j;
        moctime_t       startTime;

        mEntropyThreadState3 = kEntropyStart;

        if (OK > (RNG_SEED_entropyThreadWaitForStart(3, 0x33)))
            goto exit;

        mEntropyThreadState3 = kEntropyWorking;

        for (i = 0; i < RNG_SEED_ROUNDS; i++)
        {
            for (j = 0; j < RNG_SEED_BUFFER_SIZE; j += 11)
            {
                if (FALSE != mShouldEntropyThreadsDie)
                    goto exit;

                RTOS_deltaMS(NULL, &startTime);

                while (RTOS_deltaMS(&startTime, NULL) < ((j + 1) * 7))
                    RNG_SEED_scramble();

                RTOS_sleepMS(((RTOS_deltaMS(&startTime, NULL) >> 1) & 0x3) + 3);
            }
        }

        mEntropyThreadState3 = kEntropyDone;

        if (OK > (RNG_SEED_entropyThreadWaitForDone(3, 0x3b)))
            goto exit;

        mEntropyThreadState3 = kEntropyIdle;

        while ((FALSE == mShouldEntropyThreadsDie) && (kEntropyIdle == mEntropyThreadState3))
            RTOS_sleepMS(MOCANA_RAND_ENTROPY3_KILLWAIT_TIME);
    }
    while (FALSE == mShouldEntropyThreadsDie);

exit:
    mShouldEntropyThreadsDie = TRUE;
    mEntropyThreadState3 = kEntropyDead;

    return;
}
#endif


/*------------------------------------------------------------------*/

#pragma GCC diagnostic ignored "-Wuninitialized"
static void
RNG_SEED_simpleSeedInit(void)
{
    ubyte4                  upTime = 0, i = 0;

    TimeDate                timeSeed = {0};

#ifdef __ENABLE_DIGICERT_FREESTANDING__
    upTime = EZFIPS_random();
#else
    upTime = RTOS_getUpTimeInMS();
#endif

    for (i = 0; i < sizeof(upTime); i++)
        m_entropyScratch[i] ^= ((ubyte *)(&upTime))[i];

#ifdef __ENABLE_DIGICERT_FREESTANDING__
    i = 0;
    for (;;)
    {
        ubyte* dest = (ubyte*) &timeSeed;
        ubyte4 tmp = EZFIPS_random();
        while (tmp && i < sizeof(timeSeed))
        {
            dest[i++] = (tmp & 0xFF);
            tmp >>= 8;
        }
        if (i >= sizeof(timeSeed))
        {
            break;
        }
    }
#else
    RTOS_timeGMT(&timeSeed);
#endif
    for (i = 1; i < (1 + sizeof(timeSeed)); i++)
        m_entropyScratch[RNG_SEED_BUFFER_SIZE - i] ^= ((ubyte *)(&timeSeed))[i - 1];

    for (i = 0; i < RNG_SEED_BUFFER_SIZE; i++)
        m_entropyScratch[(i + sizeof(upTime)) % RNG_SEED_BUFFER_SIZE] ^= (ubyte)(0x67 + i);

    RNG_SEED_scramble();
}

/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__)) && (!defined(__DISABLE_DIGICERT_RAND_SEED__)))
static MSTATUS
RNG_SEED_entropyThreadLauncher(void)
{
    moctime_t   startTime;
    MSTATUS     status = OK;

    RTOS_deltaMS(NULL, &startTime);

    /* leverages preemptive RTOS */
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("*** creating entropy threads 00\n");
#endif

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("*** creating entropy thread 01\n");
#endif

    if (OK > (status = RTOS_createThread(RNG_SEED_entropyThread1, (void *)NULL, (sbyte4)ENTROPY_THREAD, &ethread01)))
        goto exit;

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("*** creating entropy thread 02\n");
#endif

    if (OK > (status = RTOS_createThread(RNG_SEED_entropyThread2, (void *)NULL, (sbyte4)ENTROPY_THREAD, &ethread02)))
        goto exit;

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("*** creating entropy thread 03\n");
#endif

    if (OK > (status = RTOS_createThread(RNG_SEED_entropyThread3, (void *)NULL, (sbyte4)ENTROPY_THREAD, &ethread03)))
        goto exit;

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("*** entropy threads created \n");
#endif

    while ((kEntropyDone <= mEntropyThreadState1) || (kEntropyDone <= mEntropyThreadState2) || (kEntropyDone <= mEntropyThreadState3))
    {
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
        PRINTDBG("*** ethreads running\n");
#endif
        RNG_SEED_scramble();
        RTOS_sleepMS(((RTOS_deltaMS(&startTime, NULL) >> 1) & 0xFF) + 1);
    }

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("*** entropy threads init done\n");
#endif

exit:
    return status;

} /* RNG_SEED_entropyThreadLauncher */

#endif /* #if ((!defined(__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__)) && (!defined(__DISABLE_DIGICERT_RAND_SEED__))) */

/*------------------------------------------------------------------*/
#ifdef __FIPS_OPS_TEST__
static int seed_fail = 0;

MOC_EXTERN void triggerSeedFail(void)
{
    seed_fail = 1;
}
MOC_EXTERN void resetSeedFail(void)
{
    seed_fail = 0;
}
#endif


#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
static
MSTATUS RNG_SEED_fipsConditionalTest(ubyte *pGeneratedBytes, ubyte4 numEntropyBytes)
{
    MSTATUS status = OK;
    sbyte4 cmp = 0;

    if ( numEntropyBytes > sizeof(m_entropyByteDepotHistory) )
    {
        status = ERR_FIPS_RNG_FAIL;
        goto exit;
    }

#ifdef __FIPS_OPS_TEST__
    if ( 1 == seed_fail )
    {
        DIGI_MEMCPY((void *)m_entropyByteDepotHistory, (void *)pGeneratedBytes, numEntropyBytes);
    }
#endif

    /* New Seed must not be the same compare to the previous one -- FIPS */
    status =  DIGI_CTIME_MATCH((const ubyte *)m_entropyByteDepotHistory, (const ubyte *)pGeneratedBytes, numEntropyBytes, &cmp);

    if ( ( OK > status ) || ( 0 == cmp )  )
    {
        status = ERR_FIPS_RNG_FAIL;
    }
    else
    {
        /* Copy the current Seed output to history for future comparision */
        DIGI_MEMCPY((void *)m_entropyByteDepotHistory, (void *)pGeneratedBytes, numEntropyBytes);
    }

exit:
    return status;
}

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/*------------------------------------------------------------------*/

extern MSTATUS
RNG_SEED_extractInitialDepotBits(ubyte *pDstCloneEntropyBytes, ubyte4 numEntropyBytes)
{
    intBoolean      isExtractMutexSet = FALSE;
    ubyte4          numBytesToClone;
    ubyte4          index;
    MSTATUS         status;
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    ubyte4 			numEntropyBytesRequested = numEntropyBytes;
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */
    ubyte 			*pTempDestCloneEntropyBytes = pDstCloneEntropyBytes;

    if (FALSE == mIsRngSeedInit)
    {
        if (OK > (status = RNG_SEED_createInitialState()))
            return status;
    }

    /* only allow one consumer at a time... */
    if (OK > (status = MRTOS_mutexWait(mRngSeedMutex, &isExtractMutexSet)))
        goto exit;

    RNG_SEED_simpleSeedInit();
    RNG_SEED_entropyMoveScratchToDepot();
    RNG_SEED_scramble();

    do
    {
        /* calculate number bytes available to clone */
        index = m_indexEntropyByteDepot;
        numBytesToClone = ((RNG_SEED_BUFFER_SIZE - index) > numEntropyBytes) ? numEntropyBytes : (RNG_SEED_BUFFER_SIZE - index);

        /* if no bytes are available for cloning... */
        if (0 == numBytesToClone)
        {
#ifndef __DISABLE_DIGICERT_RAND_SEED__
            RNG_SEED_simpleSeedInit(); /* Do it again. */
            RNG_SEED_entropyMoveScratchToDepot();
#else /* ifndef __DISABLE_DIGICERT_RAND_SEED__ */
            /* only useful for benchmarking / optimizing key generation */
            m_indexEntropyByteDepot = 0; /* It must be full again */
#endif /* ifndef __DISABLE_DIGICERT_RAND_SEED__ */
            /* do over... */
            continue;
        }

        /* copy entropy bits out */
        DIGI_MEMCPY(pTempDestCloneEntropyBytes, (void *)(index + m_entropyByteDepot), numBytesToClone);
        pTempDestCloneEntropyBytes += numBytesToClone;

        /* zeroize remove seed bytes */
        DIGI_MEMSET((ubyte*) (index + m_entropyByteDepot), 0x00, numBytesToClone);

        /* just in case we straddle buffers, etc */
        numEntropyBytes -= numBytesToClone;
        m_indexEntropyByteDepot += numBytesToClone;
    }
    while (0 != numEntropyBytes);

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if ( OK > ( status = RNG_SEED_fipsConditionalTest(pDstCloneEntropyBytes, numEntropyBytesRequested) ) )
    {
    	setFIPS_Status(FIPS_ALGO_DRBG_CTR,status);
    	goto exit;
    }
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    status = OK;

exit:
	MRTOS_mutexRelease(mRngSeedMutex, &isExtractMutexSet);

	return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
RNG_SEED_extractDepotBits(ubyte *pDstCloneEntropyBytes, ubyte4 numEntropyBytes)
{
    intBoolean      isFirstTime = FALSE;
#if ((!defined(__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__)) && (!defined(__DISABLE_DIGICERT_RAND_SEED__)))
    intBoolean      isExtractMutexSet = FALSE;
    ubyte4          numBytesToClone;
    ubyte4          index;
    moctime_t       startTime;
#endif
    MSTATUS         status;
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    ubyte4 			numEntropyBytesRequested = numEntropyBytes;
#endif
#if ((!defined(__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__)) && (!defined(__DISABLE_DIGICERT_RAND_SEED__)))
    ubyte 			*pTempDestCloneEntropyBytes = pDstCloneEntropyBytes;

    RTOS_deltaMS(NULL, &startTime);
#endif

    if (TRUE == mShouldEntropyThreadsDie)
    {
        return ERR_RAND_TERMINATE_THREADS;
    }

    if (FALSE == mIsRngSeedInit)
    {
        if (OK > (status = RNG_SEED_createInitialState()))
            return status;
        else
            isFirstTime = TRUE; /* This really is the first time */
    }

    if (FALSE == mIsRngSeedThreadInit)
    {
        mEntropyThreadState1 = kEntropyInit;
        mEntropyThreadState2 = kEntropyInit;
        mEntropyThreadState3 = kEntropyInit;
        mEntropyThreadsState = kEntropyInit;

        isFirstTime = TRUE; /* Consider this the first time too */

    }

#if ((!defined(__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__)) && (!defined(__DISABLE_DIGICERT_RAND_SEED__)))

    /* only allow one consumer at a time... */
    if (OK > (status = MRTOS_mutexWait(mRngSeedMutex, &isExtractMutexSet)))
        goto exit;

    /* the first time we are called, we need to spawn the entropy threads */
    if (TRUE == isFirstTime)
    {
        mEntropyThreadsState = kEntropyStart;

        if (OK > (status = RNG_SEED_entropyThreadLauncher()))
            goto exit;
        mIsRngSeedThreadInit = TRUE;

    }

    do
    {
        if (TRUE == mShouldEntropyThreadsDie)
        {
            status = ERR_RAND_TERMINATE_THREADS;
            goto exit;
        }

        /* calculate number bytes available to clone */
        index = m_indexEntropyByteDepot;
        numBytesToClone = ((RNG_SEED_BUFFER_SIZE - index) > numEntropyBytes) ? numEntropyBytes : (RNG_SEED_BUFFER_SIZE - index);

        /* if no bytes are available for cloning... */
        if (0 == numBytesToClone)
        {
            /* if the threads are not already working on new bits...  */
            if ((kEntropyIdle == mEntropyThreadsState) &&
                (kEntropyIdle == mEntropyThreadState1) &&
                (kEntropyIdle == mEntropyThreadState2) &&
                (kEntropyIdle == mEntropyThreadState3))
            {
                /* have them run! */
                mEntropyThreadsState = kEntropyStart;
                mEntropyThreadState1 = kEntropyStart;
                mEntropyThreadState2 = kEntropyStart;
                mEntropyThreadState3 = kEntropyStart;
            }
            else if (kEntropyIdle != mEntropyThreadsState)
            {
                /* otherwise, scramble while we wait until a new batch is available */
                RNG_SEED_scramble();
                RTOS_sleepMS(((RTOS_deltaMS(&startTime, NULL) >> 1) & 0xFF) + 1);
            }

            /* do over... */
            continue;
        }

        /* copy entropy bits out */
        DIGI_MEMCPY(pTempDestCloneEntropyBytes, (void *)(index + m_entropyByteDepot), numBytesToClone);
        pTempDestCloneEntropyBytes += numBytesToClone;

        /* zeroize remove seed bytes */
        DIGI_MEMSET((ubyte *)(index + m_entropyByteDepot), 0x00, numBytesToClone);

        /* just in case we straddle buffers, etc */
        numEntropyBytes -= numBytesToClone;
        m_indexEntropyByteDepot += numBytesToClone;
    }
    while (0 != numEntropyBytes);

    /* kick off threads again, if they are idle */
    if ((kEntropyIdle == mEntropyThreadsState) &&
        (kEntropyIdle == mEntropyThreadState1) &&
        (kEntropyIdle == mEntropyThreadState2) &&
        (kEntropyIdle == mEntropyThreadState3))
    {
        /* have them run! */
        mEntropyThreadsState = kEntropyStart;
        mEntropyThreadState1 = kEntropyStart;
        mEntropyThreadState2 = kEntropyStart;
        mEntropyThreadState3 = kEntropyStart;
    }

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if ( OK > ( status = RNG_SEED_fipsConditionalTest(pDstCloneEntropyBytes, numEntropyBytesRequested) ) )
    {
    	setFIPS_Status(FIPS_ALGO_DRBG_CTR,status);
    	goto exit;
    }
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    status = OK;

exit:
    MRTOS_mutexRelease(mRngSeedMutex, &isExtractMutexSet);

    return status;

#else /* #if ((!defined(__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__)) && (!defined(__DISABLE_DIGICERT_RAND_SEED__))) */
    /* the first time we are called, we need to do a simple seed */
    if (TRUE == isFirstTime)
    {
        /* Needed so that next time we don't think it's still the first time */
        mIsRngSeedThreadInit = TRUE; /* Even though there really are no threads */
    }

    status = RNG_SEED_extractInitialDepotBits(pDstCloneEntropyBytes, numEntropyBytes);

	return status;

#endif /* #if ((!defined(__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__)) && (!defined(__DISABLE_DIGICERT_RAND_SEED__))) */

}

/*------------------------------------------------------------------*/

extern MSTATUS RNG_SEED_extractInitialDepotBitsEx (
    void *pCtx,
    ubyte *pDstCloneEntropyBytes,
    ubyte4 numEntropyBytes
    )
{
    return RNG_SEED_extractInitialDepotBits(pDstCloneEntropyBytes, numEntropyBytes);
}

extern MSTATUS RNG_SEED_extractDepotBitsEx (
    void *pCtx,
    ubyte *pDstCloneEntropyBytes,
    ubyte4 numEntropyBytes
    )
{
    return RNG_SEED_extractDepotBits(pDstCloneEntropyBytes, numEntropyBytes);
}

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ADD_ENTROPY__

#define BITMODVAL (8 * RNG_SEED_BUFFER_SIZE);

extern MSTATUS RNG_SEED_addEntropyBit(ubyte entropyBit)
{
    intBoolean      isExtractMutexSet = FALSE;
    ubyte4          bitPos;
    MSTATUS         status;

    if (TRUE == mShouldEntropyThreadsDie)
    {
        return ERR_RAND_TERMINATE_THREADS;
    }

    if (FALSE == mIsRngSeedInit)
    {
        if (OK > (status = RNG_SEED_createInitialState()))
            return status;
    }

    /* only allow one consumer at a time... */
    /* Note that this is same mutex used by ExtractDepotBits */
    if (OK > (status = MRTOS_mutexWait(mRngSeedMutex, &isExtractMutexSet)))
        goto exit;

    bitPos = m_indexEntropyBitIn = ((m_indexEntropyBitIn + 1) % BITINMODVAL);

    if (entropyBit & 1)
    {
        ubyte4  index       = ((bitPos >> 3) % RNG_SEED_BUFFER_SIZE);
        ubyte4  bitIndex    = (bitPos & 7);
        ubyte   byteXorMask = (ubyte) (1 << bitIndex);

        m_entropyScratch[index] = m_entropyScratch[index] ^ byteXorMask;
    }

    status = OK;

exit:
    MRTOS_mutexRelease(mRngSeedMutex, &isExtractMutexSet);

    return status;
}

#endif /* #ifndef __DISABLE_DIGICERT_ADD_ENTROPY__ */

/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__

MOC_EXTERN MSTATUS
RNG_SEED_zeroizeDepotBits(void)
{
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif

#ifdef __ZEROIZE_TEST__
    FIPS_PRINT("\nRNG_SEED::indexEntropyByteDepot- Before Zeroization: %d", m_indexEntropyByteDepot);
    FIPS_PRINT("\nRNG_SEED::indexEntropyBitIn- Before Zeroization: %d", m_indexEntropyBitIn);

    FIPS_PRINT("\nRNG_SEED::EntropyDepotHistory - Before Zeroization\n");
    for( counter = 0; counter < (RNG_SEED_BUFFER_SIZE + SHA1_RESULT_SIZE); counter++)
    {
        FIPS_PRINT("%02x",*((ubyte*)m_entropyByteDepotHistory+counter));
    }
    FIPS_PRINT("\n");

    FIPS_PRINT("\nRNG_SEED::EntropyByteDepot - Before Zeroization\n");
    for( counter = 0; counter < (RNG_SEED_BUFFER_SIZE + SHA1_RESULT_SIZE); counter++)
    {
        FIPS_PRINT("%02x",*((ubyte*)m_entropyByteDepot+counter));
    }
    FIPS_PRINT("\n");

    FIPS_PRINT("\nRNG_SEED::EntropyDepotScratch - Before Zeroization\n");
    for( counter = 0; counter < (RNG_SEED_BUFFER_SIZE + SHA1_RESULT_SIZE); counter++)
    {
        FIPS_PRINT("%02x",*((ubyte*)m_entropyScratch+counter));
    }
    FIPS_PRINT("\n");
#endif

    m_indexEntropyByteDepot = 0;
    m_indexEntropyBitIn = 0;
    DIGI_MEMSET((ubyte *)&m_entropyByteDepotHistory, 0, RNG_SEED_BUFFER_SIZE + SHA1_RESULT_SIZE);
    DIGI_MEMSET((ubyte *)&m_entropyByteDepot, 0, RNG_SEED_BUFFER_SIZE + SHA1_RESULT_SIZE);
    DIGI_MEMSET((ubyte *)&m_entropyScratch, 0, RNG_SEED_BUFFER_SIZE + SHA1_RESULT_SIZE);

#ifdef __ZEROIZE_TEST__
    FIPS_PRINT("\nRNG_SEED::indexEntropyByteDepot- After Zeroization: %d", m_indexEntropyByteDepot);
    FIPS_PRINT("\nRNG_SEED::indexEntropyBitIn- After Zeroization: %d", m_indexEntropyBitIn);

    FIPS_PRINT("\nRNG_SEED::EntropyDepotHistory - After Zeroization\n");
    for( counter = 0; counter < (RNG_SEED_BUFFER_SIZE + SHA1_RESULT_SIZE); counter++)
    {
        FIPS_PRINT("%02x",*((ubyte*)m_entropyByteDepotHistory+counter));
    }
    FIPS_PRINT("\n");

    FIPS_PRINT("\nRNG_SEED::EntropyByteDepot - After Zeroization\n");
    for( counter = 0; counter < (RNG_SEED_BUFFER_SIZE + SHA1_RESULT_SIZE); counter++)
    {
        FIPS_PRINT("%02x",*((ubyte*)m_entropyByteDepot+counter));
    }
    FIPS_PRINT("\n");

    FIPS_PRINT("\nRNG_SEED::EntropyDepotScratch - After Zeroization\n");
    for( counter = 0; counter < (RNG_SEED_BUFFER_SIZE + SHA1_RESULT_SIZE); counter++)
    {
        FIPS_PRINT("%02x",*((ubyte*)m_entropyScratch+counter));
    }
    FIPS_PRINT("\n");
#endif

    return OK;
}

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/*------------------------------------------------------------------*/

extern MSTATUS
RNG_SEED_entropyThreadIds(RTOS_THREAD **ppRetTid1, RTOS_THREAD **ppRetTid2, RTOS_THREAD **ppRetTid3)
{
    /* has the entropy threads been initialized? if not, error out. */
    if (FALSE == mIsRngSeedInit)
        return ERR_FALSE;

    /* return back reference */
    *ppRetTid1 = &ethread01;
    *ppRetTid2 = &ethread02;
    *ppRetTid3 = &ethread03;

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
RNG_SEED_killEntropyThreads(void)
{
    mShouldEntropyThreadsDie = TRUE;

    return OK;
}

extern MSTATUS
RNG_SEED_DestroyEntropyThreads(void)
{
    ubyte4 waitCount = 0;
    mShouldEntropyThreadsDie = TRUE;
    if (ethread01 != NULL)
        RTOS_destroyThread(ethread01);
    if (ethread02 != NULL)
        RTOS_destroyThread(ethread02);
    if (ethread03 != NULL)
        RTOS_destroyThread(ethread03);

    /* Wait for all threads to die */
    while ( (mEntropyThreadState1 != kEntropyDead) ||
            (mEntropyThreadState2 != kEntropyDead) ||
            (mEntropyThreadState3 != kEntropyDead) )
    {
        RTOS_sleepMS(50);
        waitCount++;
        if (20 < waitCount)
        {
            return ERR_RAND_TERMINATE_THREADS;
        }
    }

    return OK;
}

/*------------------------------------------------------------------*/

static MSTATUS
RNG_SEED_resetState(void)
{
    /* clears local/module variables, if want to restart entropy threads */
    /* up to caller to make sure any previous threads are dead before calling this API */
	if (mRngSeedThreadMutex != NULL)
		RTOS_mutexFree(&mRngSeedThreadMutex);
	if (mRngSeedMutex != NULL)
		RTOS_mutexFree(&mRngSeedMutex);

	mShouldEntropyThreadsDie = FALSE;
    mIsRngSeedInit = FALSE;
    mIsRngSeedThreadInit = FALSE;
    return OK;
}


/*------------------------------------------------------------------*/

static  MSTATUS
RNG_SEED_createInitialState(void)
{
    MSTATUS         status = OK;

    if (FALSE == mIsRngSeedInit)
    {
        /* we don't have a master mutex, so we need to */
        /* assume that there is no contention for the very first call */
        /* this should be thread safe, since we generally only have */
        /* have a single entropy context --- seed generation is too */
        /* expensive to have multiple contextes */
        if (OK > (status = RTOS_mutexCreate(&mRngSeedMutex, (enum mutexTypes) 0, 0)))
            goto exit;

        if (OK > (status = RTOS_mutexCreate(&mRngSeedThreadMutex, (enum mutexTypes) 0, 0)))
            goto exit;

        m_indexEntropyByteDepot = RNG_SEED_BUFFER_SIZE;     /* no bytes available */
        m_indexEntropyBitIn = 0;

        mIsRngSeedInit = TRUE;
        mShouldEntropyThreadsDie = FALSE;
    }
    else
    {
        status = ERR_FALSE;
    }

exit:
    return status;

}

/*------------------------------------------------------------------*/

extern MSTATUS RNG_SEED_initDepotState(void)
{
	return RNG_SEED_createInitialState();
}

extern MSTATUS RNG_SEED_freeDepotState(void)
{
    return RNG_SEED_resetState();
}

#endif	/* #ifndef __DISABLE_DIGICERT_RNG__ */
