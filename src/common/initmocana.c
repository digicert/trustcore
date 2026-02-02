/**
 * @file   initmocana.c
 * @brief  Mocana Initialization Routines
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

#include "../common/initmocana.h"
#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/mtcp.h"
#include "../common/utils.h"
#include "../common/mocana.h"
#include "../common/random.h"
#include "../common/rng_seed.h"
#include "../common/debug_console.h"
#include "../common/mem_part.h"
#include "../crypto/hw_accel.h"
#include "../harness/harness.h"
#include "../common/mudp.h"
#include "../common/external_rand_thread.h"
#include "../crypto/crypto.h"
#include "../crypto/crypto_init.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_random.h"
#endif

#ifdef __ENABLE_DIGICERT_MEM_PROFILE__
#include "../common/mem_profiler.h"
#endif

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__

#include "../data_protection/file_protect.h"
#include "../data_protection/tools/fp_example_seed_callback.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap_api.h"

#undef MOC_FP_SEED_CB
#define MOC_FP_SEED_CB             TAP_DP_seedCallback

#undef MOC_FP_FINGERPRINT_CB
#define MOC_FP_FINGERPRINT_CB      TAP_DP_fingerprintCallback

#undef MOC_FP_FREE_FINGERPRINT_CB
#define MOC_FP_FREE_FINGERPRINT_CB TAP_DP_freeFingerprintCallback

#endif /* __ENABLE_DIGICERT_TAP__ */
#endif /* __ENABLE_DIGICERT_DATA_PROTECTION__ */

MOC_EXTERN_DATA_DEF moctime_t gStartTime;

#ifndef __DISABLE_DIGICERT_INIT__

#ifdef __DISABLE_DIGICERT_STARTUP_GUARD__
#define MOC_REF_CHECK(_status)
#define MOC_INIT_CHECK(_status, _pSetupInfo)
#define MOC_INIT_CLEANUP(_status, _pSetupInfo)
#define DIGI_FREE_CHECK(_status)
#define DIGI_FREE_CLEANUP(_status, _pSetupInfo)

#define MOC_INIT_CRYPTO_INTERFACE_CORE(_status, _isMultiThreaded)
#define MOC_UNINIT_CRYPTO_INTERFACE_CORE(_status, _dStatus)

#else
/**
 * @var initMutex  Global mutex to ensure multiple nested calls to
 *                 DIGICERT_initialize are thread safe
 */
static RTOS_MUTEX initMutex = NULL;
/**
 * @var refCount   Reference count to ensure multiple nested calls to
 *                 DIGICERT_initialize are thread safe
 */
static sbyte4 refCount = 0;

#ifdef __RTOS_WIN32__
MOC_EXTERN_MOCANA_H ShutdownHandler g_sslShutdownHandler = NULL;
#else
ShutdownHandler g_sslShutdownHandler = NULL;
#endif

#ifdef __ENABLE_DIGICERT_CUSTOM_ENTROPY_INJECT__
MOC_EXTERN sbyte4 DIGICERT_addCustomEntropyInjection(void);
#endif

/*----------------------------------------------------------------------------*/

/* If the Crypto Interface is enabled, initialize the core */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#define MOC_INIT_CRYPTO_INTERFACE_CORE(_status, _isMultiThreaded)              \
    _status = CRYPTO_INTERFACE_initializeCore(_isMultiThreaded);               \
    if (OK != _status)                                                         \
      goto exit;
#else
#define MOC_INIT_CRYPTO_INTERFACE_CORE(_status, _isMultiThreaded)
#endif

/*----------------------------------------------------------------------------*/

/* If the Crypto Interface is enabled, uninitialize the core */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#define MOC_UNINIT_CRYPTO_INTERFACE_CORE(_status, _dStatus)                    \
    _dStatus = CRYPTO_INTERFACE_uninitializeCore();                            \
    if (OK == _status)                                                         \
      _status = _dStatus;
#else
#define MOC_UNINIT_CRYPTO_INTERFACE_CORE(_status, _dStatus)
#endif

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
#define MOC_INIT_FP_CALLBACKS(_status)                                         \
    _status = FP_registerSeedCallback(MOC_FP_SEED_CB, NULL);                   \
    if (OK != _status)                                                         \
      goto exit;                                                               \
                                                                               \
    _status = FP_registerFingerprintCallback (                                 \
      MOC_FP_FINGERPRINT_CB, MOC_FP_FREE_FINGERPRINT_CB, NULL);                \
    if (OK != _status)                                                         \
      goto exit;                                                               \
                                                                               \
    DPM_initialize();
#else
#define MOC_INIT_FP_CALLBACKS(_status)
#endif

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
#define DIGI_FREE_FP_CALLBACKS(_status, _dStatus)                               \
    _dStatus = FP_shutdown();                                                  \
    if (OK == _status)                                                         \
      _status = _dStatus;
#else
#define DIGI_FREE_FP_CALLBACKS(_status, _dStatus)
#endif

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#define MOC_INIT_TAP_EXTERN(_status)                                           \
    _status = CRYPTO_INTERFACE_initializeTAPExtern();                          \
    if (OK != _status)                                                         \
      goto exit;
#else
#define MOC_INIT_TAP_EXTERN(_status)
#endif

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#define DIGI_FREE_TAP_EXTERN(_status, _dStatus)                                 \
    _dStatus = CRYPTO_INTERFACE_freeTAPExtern();                               \
    if (OK == _status)                                                         \
      _status = _dStatus;
#else
#define DIGI_FREE_TAP_EXTERN(_status, _dStatus)
#endif

/*----------------------------------------------------------------------------*/

#define MOC_REF_CHECK(_status)                                                 \
    if (0 == refCount)                                                         \
    {                                                                          \
        _status = ERR_MOCANA_NOT_INITIALIZED;                                   \
        goto exit;                                                             \
    }                                                                          \
    refCount--;

/**
 * @def      MOC_INIT_CHECK(_status, _pSetupInfo)
 * @details  The first invocation is not thread safe as there is a race
 *           condition to create the global mutex.  All calls after the first
 *           are thread safe. The calling thread waits until it can acquire the
 *           global mutex, after which it will execute the initialization
 *           sequence if this is the first call.  If it is not the first call
 *           simply increment the reference count and return \c OK.
 *           <p>Because creation of these mutexes may involve memory allocation,
 *           special attention must be given to RTOS implementations that
 *           provide their own memory management as the MOC_INIT_CHECK is called
 *           before MOC_RTOS_INIT.
 *
 * @param _status      The \ref MSTATUS value for return from the calling function.
 * @param _pSetupInfo  A pointer to an InitMocanaSetupInfo structure.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_DIGICERT_STARTUP_GUARD__
 *   .
 * @sa MOC_INIT_CLEANUP
 */
#define MOC_INIT_CHECK(_status, _pSetupInfo)                                   \
    if (0 == refCount)                                                         \
    {                                                                          \
      _status = RTOS_mutexCreate(&initMutex, 0, 0);                            \
      if (OK != _status)                                                       \
        goto exit;                                                             \
    }                                                                          \
    _status = RTOS_mutexWait(initMutex);                                       \
    if (OK != _status)                                                         \
      goto exit;                                                               \
    if (1 == refCount)                                                         \
    {                                                                          \
      if (NULL != _pSetupInfo)                                                 \
      {                                                                        \
        if (NULL != _pSetupInfo->MocSymRandOperator)                           \
          _status = ERR_RAND_CTX_ALREADY_INITIALIZED;                          \
        else if (NULL != _pSetupInfo->pStaticMem)                              \
          _status = ERR_MEM_PART_ALREADY_INITIALIZED;                          \
      }                                                                        \
      goto exit;                                                               \
    }                                                                          \
    else                                                                       \
    {                                                                          \
        refCount++;                                                            \
    }

/**
 * @def      MOC_INIT_CLEANUP(_status, _dStatus)
 * @details  This macro will release the global mutex used for managing
 *           reference counting.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 * @param _dStatus  The temporary placeholder for checking return status during
 *                  cleanup. This is necessary because unlike the initialization
 *                  code, an error does not result in a return. Instead the rest
 *                  of the cleanup code executes, and since we do not want to
 *                  overwrite the value of status with the results of the
 *                  subsequent calls we store it in dStatus unless its an error.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_DIGICERT_STARTUP_GUARD__
 *   .
 * @sa MOC_INIT_CHECK
 */
#define MOC_INIT_CLEANUP(_status, _dStatus)                                    \
    if (NULL != initMutex)                                                     \
    {                                                                          \
      _dStatus = RTOS_mutexRelease(initMutex);                                 \
      if (OK != dStatus)                                                       \
        _status = _dStatus;                                                    \
    }
/**
 * @def      DIGI_FREE_CHECK(_status)
 * @details  This macro will wait if necessary to get a handle on the global
 *           mutex, then decrement the reference count. If the count is zero
 *           then the uninitialization code is executed, else return \c OK.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_DIGICERT_STARTUP_GUARD__
 *   .
 * @sa DIGI_FREE_CLEANUP
 */
#define DIGI_FREE_CHECK(_status)                                                \
    if (NULL == initMutex)                                                     \
      goto exit;                                                               \
    status = RTOS_mutexWait(initMutex);                                        \
    if (OK != status)                                                          \
      goto exit;                                                               \
    if (0 != refCount)                                                         \
      goto exit;

/**
 * @def      DIGI_FREE_CLEANUP(_status, _dStatus)
 * @details  This macro will free the global mutex if the reference count is
 *           zero, otherwise it will release the mutex and return \c OK.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 * @param _dStatus  The temporary placeholder status used to check return values.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_DIGICERT_STARTUP_GUARD__
 *   .
 * @sa DIGI_FREE_CHECK
 */
#define DIGI_FREE_CLEANUP(_status, _dStatus)                                    \
    if (NULL != initMutex)                                                     \
    {                                                                          \
      _dStatus = RTOS_mutexFree(&initMutex);                                   \
      if (OK == _status)                                                       \
        _status = _dStatus;                                                    \
    }

#endif /* defined (__DISABLE_DIGICERT_STARTUP_GUARD__) */

/*----------------------------------------------------------------------------*/

extern MSTATUS
DIGICERT_initialize(
  InitMocanaSetupInfo *pSetupInfo,
  MocCtx *ppCtx
  )
{
  MSTATUS status = OK;
  MSTATUS dStatus = OK;
  InitMocanaSetupInfo setupInfo = {0};
  intBoolean isMultiThreaded = TRUE;
  MocCtx pMocCtx = NULL;
  MocSubCtx *pOpListCtx = NULL;

  /* Build-dependent variable initializations */
  MOC_MEM_PART_DECL(pPartition, staticMemLoadFlag)

  if (NULL != ppCtx)
    *ppCtx = NULL;


#ifdef __ENABLE_DIGICERT_MEM_PROFILE__
  if (OK > (status = MEM_PROFILER_init()))
    goto exit;
#endif

  /*
   * Each of the following macros will expand to the associated initialization
   * code if the corresponding build flags are set
   */

  /* Initialize memory partitions, if the caller has specified that a static
   * memory partition is to be used then set up and initialize the partition */
  MOC_MEM_PART_INIT(status, pSetupInfo, pPartition, staticMemLoadFlag)

  /* Initialize platform specific information */
  MOC_RTOS_INIT(status)

  /* Manage threads using safe reference counting */
  MOC_INIT_CHECK(status, pSetupInfo)

  /* set the value of gStartTime*/
  RTOS_deltaMS(NULL, &gStartTime);

  /* Initialize any hardware accelerators */
  MOC_HARDWARE_ACCEL_INIT(status)

  /* Initialize TCP internals */
  MOC_CHECK_TCP_INIT(status)

  /* Initialize UDP internals */
  MOC_UDP_INIT(status)

  /* Initialize debug console */
  MOC_DEBUG_CONSOLE_INIT(status)
  MOC_DEBUG_CONSOLE_START(status, MOCANA_DEBUG_CONSOLE_PORT)

  if ( (NULL != pSetupInfo) &&
         (0 != (MOC_INIT_FLAG_SINGLE_THREAD & pSetupInfo->flags)) )
  {
    isMultiThreaded = FALSE;
  }

  /* If the caller wants an AlgCtx, build one, even if there are no Operators.
   */
  if (NULL != ppCtx)
  {
    if (NULL == pSetupInfo)
    {
      pSetupInfo = &setupInfo;
    }

    status = CreateMocCtx (isMultiThreaded, &pMocCtx);
    if (OK != status)
      goto exit;

    /* Build the first SubCtx, one that contains the Operator lists.
     */
    status = MBuildOpListCtx (
      pSetupInfo->pDigestOperators, pSetupInfo->digestOperatorCount,
      pSetupInfo->pSymOperators, pSetupInfo->symOperatorCount,
      pSetupInfo->pKeyOperators, pSetupInfo->keyOperatorCount,
      &pOpListCtx);
    if (OK != status)
      goto exit;

    status = MocLoadNewSubCtx (pMocCtx, &pOpListCtx);
    if (OK != status)
      goto exit;
  }

  /* Initialize the Crypto Interface Core */
  MOC_INIT_CRYPTO_INTERFACE_CORE(status, isMultiThreaded)

  status = CRYPTO_DIGI_init();
  if (OK != status)
    goto exit;

  MOC_INIT_FP_CALLBACKS(status)
  /* Initialize global random number generator */
  {
  MOC_GRNG_INIT(status, pSetupInfo, pMocCtx)
  }

  /* Set flag for successful initialization */
  MOC_MEM_PART_SET_DONE_FLAG(staticMemLoadFlag)

  if (NULL != ppCtx)
  {
    *ppCtx = pMocCtx;
    pMocCtx = NULL;
  }

  MOC_INIT_TAP_EXTERN(status)

exit:

  if (NULL != pOpListCtx)
  {
    MSubCtxOpListFree ((struct MocSubCtx **)&pOpListCtx);
  }
  if (NULL != pMocCtx)
  {
    FreeMocCtx (&pMocCtx);
  }

  /* Check to see if we need to clean up static memory partitions on error */
  MOC_MEM_PART_INIT_CLEANUP(pSetupInfo, pPartition, staticMemLoadFlag)

  /* Manage threads using safe reference counting */
  MOC_INIT_CLEANUP(status, dStatus)

  return (MSTATUS)status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS DIGICERT_free(
  MocCtx *ppCtx
  )
{
  MSTATUS status = ERR_MOCANA_NOT_INITIALIZED;
  MSTATUS dStatus = OK;

  MOC_REF_CHECK(status)

  if (NULL != ppCtx)
  {
    if (NULL != *ppCtx)
    {
      FreeMocCtx (ppCtx);
    }
  }

  /*
   * Each of the following macros will expand to the associated cleanup
   * code if the corresponding build flags are set
   */

  /* Manage threads using safe reference counting */
  DIGI_FREE_CHECK(status)

  DIGI_FREE_TAP_EXTERN(status, dStatus)

  /* Free global random number generator */
  {
  MOC_GRNG_FREE(status, dStatus)
  }

  DIGI_FREE_FP_CALLBACKS(status, dStatus)

  dStatus = CRYPTO_DIGI_free();
  if (OK == status)
    status = dStatus;

  /* Uninitialize the Crypto Interface Core */
  MOC_UNINIT_CRYPTO_INTERFACE_CORE(status, dStatus)

  if (NULL != g_sslShutdownHandler)
  {
    g_sslShutdownHandler();
  }
  RTOS_sleepMS(100);

#ifndef __DISABLE_DIGICERT_RNG__
#if ((!defined(__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__)) && (!defined(__DISABLE_DIGICERT_RAND_SEED__)))
  if (ENTROPY_SRC_EXTERNAL != RANDOM_getEntropySource())
  {
    RNG_SEED_DestroyEntropyThreads();
    RNG_SEED_freeDepotState();
  }
#endif
#endif

  /* Shutdown debug console */
  MOC_DEBUG_CONSOLE_STOP(status, dStatus)

  /* Shutdown UDP internals */
  MOC_UDP_SHUTDOWN(status, dStatus)

  /* Shutdown TCP internals */
  MOC_CHECK_TCP_SHUTDOWN(status, dStatus)

  /* Shutdown platform specific information */
  MOC_RTOS_SHUTDOWN(status, dStatus)

  /* Shutdown any hardware accelerators */
  MOC_HARDWARE_ACCEL_UNINIT(status, dStatus)

exit:
#if (defined(__KERNEL__))
  MOC_INIT_CLEANUP(status, dStatus);
#endif

  /* Manage threads using safe reference counting */
  DIGI_FREE_CLEANUP(status, dStatus)

  /* Free memory partitions, including static ones set up during initialization */
  MOC_MEM_PART_UNINIT(status, dStatus)

#ifdef __ENABLE_DIGICERT_MEM_PROFILE__
  dStatus = MEM_PROFILER_done();
  if (OK == status)
    status = dStatus;
#endif

  return (sbyte4)status;
}

#endif /* __DISABLE_DIGICERT_INIT__ */
