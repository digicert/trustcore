/**
 * @file  rng_seed.h
 * @brief A random number generator seed header
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

#ifndef __RNG_SEED_HEADER__
#define __RNG_SEED_HEADER__

/* Allocate and initializes Internal entropy bit depot. */
MOC_EXTERN MSTATUS RNG_SEED_initDepotState(void);
/* Free resources related to the bit depot. */
MOC_EXTERN MSTATUS RNG_SEED_freeDepotState(void);

/* Zeroize the bit depot, This is required to meet FIPS 140-3 requirements. */
/* Internally called from fips.c interface function. */
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
MOC_EXTERN MSTATUS RNG_SEED_zeroizeDepotBits(void);
#endif

/**
 * @brief    Collect and return the requested number of entropy bytes.
 * @details  This function will use a simple algorithm to collect
 *           entropy bytes to be used as seed material. Note this seed material
 *           is not cryptographically random, nor is it FIPS approved.  Use at
 *           your own risk.
 *
 * @param pDstCloneEntropyBytes  Pointer to a caller allocated buffer that will
 *                               recieve the entropy bytes after generation.
 * @param numEntropyBytes        Number of entropy bytes to collect.
 *
 * @return            \c OK (0) if successful; otherwise a negative number error
 *                    code definition from merrors.h. To retrieve a string
 *                    containing an English text error identifier corresponding
 *                    to the function's returned error status, use the
 *                    \c DISPLAY_ERROR macro.
 *
 * @par Flags
 * To enable this function, the following flags must \b not be defined:
 *  + \c \__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
 *  + \c \__DISABLE_DIGICERT_RAND_SEED__
 *  .
 */
MOC_EXTERN MSTATUS RNG_SEED_extractInitialDepotBits(ubyte *pDstCloneEntropyBytes, ubyte4 numEntropyBytes);

/**
 * @brief    Collect and return the requested number of entropy bytes.
 * @details  This function will use a custom FIPS approved algorithm to collect
 *           entropy bytes to be used as seed material.  The entropy is created
 *           by a race condition between competing threads, interrupts, and
 *           other threads of execution within the device.  There will be a
 *           random number of context switches during the execution of the
 *           entropy seed generation, it is expected that this number will
 *           exceed 100 per second.
 *           <p>Upon the first call, this function will spawn three additional
 *           threads to execute simultaneously, each thread will interact
 *           differently with a common buffer(m_entropyScratch) to generate the
 *           seed value. The master thread will loop for the duration of the
 *           seed generation, continously calling RNG_SEED_scramble() then
 *           sleeping for t milliseconds : 0 < t < 256.
 *           <p>The three sibling threads all folow the same basic pattern of
 *           execution:
 *             1. Wait for all siblings to be ready for seed generation, each
 *                thread scrambles the buffer while waiting.
 *             2. Once all threads are ready, begin thread specific interaction
 *                with the entropy buffer (see documentation on each thread
 *                for more information).
 *             3. Each thread then completes its operation, marks itself as
 *                done, then continues its thread specific interaction until
 *                all of the other sibling threads are complete.
 *           Once all threads are done, the data is copied from the entropy
 *           scratch buffer into the entropy depot, then bytes are taken from
 *           entropy depot and placed into the input buffer.
 *
 * @param pDstCloneEntropyBytes  Pointer to a caller allocated buffer that will
 *                               recieve the entropy bytes after generation.
 * @param numEntropyBytes        Number of entropy bytes to collect.
 *
 * @return            \c OK (0) if successful; otherwise a negative number error
 *                    code definition from merrors.h. To retrieve a string
 *                    containing an English text error identifier corresponding
 *                    to the function's returned error status, use the
 *                    \c DISPLAY_ERROR macro.
 *
 * @par Flags
 * To enable this function, the following flags must \b not be defined:
 *  + \c \__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
 *  + \c \__DISABLE_DIGICERT_RAND_SEED__
 *  .
 *
 * @note  If the \c \__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__ flag is defined,
 *        this function acts as a wrapper to RNG_SEED_extractInitialDepotBits.
 */
MOC_EXTERN MSTATUS RNG_SEED_extractDepotBits(ubyte *pDstCloneEntropyBytes, ubyte4 numEntropyBytes);

/* Wrapper functions */
MOC_EXTERN MSTATUS RNG_SEED_extractInitialDepotBitsEx (
    void *pCtx,
    ubyte *pDstCloneEntropyBytes,
    ubyte4 numEntropyBytes
    );

MOC_EXTERN MSTATUS RNG_SEED_extractDepotBitsEx (
  void *pCtx,
  ubyte *pDstCloneEntropyBytes,
  ubyte4 numEntropyBytes
  );

MOC_EXTERN MSTATUS RNG_SEED_addEntropyBit(ubyte entropyBit);

/* If you must kill and then later restart entropy threads, do this: */
/* 1. Get the thread ids */
/* 2. Kill the threads */
/* 3. Wait and verify the threads are indeed dead --- may take a little while for them to get the message */
/* 4. Release mutexes, reset state */
/* Now you can safely spin up threads at a future point. */

MOC_EXTERN MSTATUS RNG_SEED_entropyThreadIds(RTOS_THREAD **ppRetTid1, RTOS_THREAD **ppRetTid2, RTOS_THREAD **ppRetTid3);
MOC_EXTERN MSTATUS RNG_SEED_killEntropyThreads(void);
MOC_EXTERN MSTATUS RNG_SEED_DestroyEntropyThreads(void);

#ifdef __FIPS_OPS_TEST__
MOC_EXTERN void triggerSeedFail(void);
MOC_EXTERN void resetSeedFail(void);
#endif

/* seed producing function used for EZFIPS
this needs to be defined by the host executable */
MOC_EXTERN ubyte4 EZFIPS_random(void);

#endif /* __RNG_SEED_HEADER__ */
