/*
 * fips.c
 *
 * FIPS 140-3 Self Test Compliance
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

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/mversion.h"
#include "../common/int64.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/rng_seed.h"
#include "../common/debug_console.h"
#include "../common/memory_debug.h"
#include "../crypto/crypto.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ecb.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/aes_ccm.h"
#include "../crypto/aes_cmac.h"
#include "../crypto/aes_xts.h"

#if (defined(__ENABLE_DIGICERT_AES_NI__) || defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
#include "../crypto/aesalgo_intel_ni.h"
#endif

#include "../crypto/gcm.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/sha3.h"
#include "../crypto/hmac.h"
#include "../crypto/hmac_kdf.h"
#include "../crypto/dh.h"
#include "../crypto/rsa.h"
#include "../crypto/dsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primefld_priv.h"
#include "../crypto/primeec.h"
#include "../crypto/ecc.h"
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
#include "../crypto/ecc_edwards.h"
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */
#include "../crypto/crypto_init.h"
#include "../crypto/nist_rng_types.h"
#include "../crypto/nist_rng.h"
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#include "../harness/harness.h"


#if defined(__RTOS_LINUX__) || defined(__RTOS_ANDROID__)
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
#include <stdio.h>
#define __DIGICERT_LINUX_SHARED_LIBRARY__
#else
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#endif
#endif

#ifdef __RTOS_VXWORKS__
#include <stdio.h>
#endif

#ifdef __RTOS_WIN32__
#include <stdio.h>
/* Conflicts w/ def in WinNT.h */
#ifdef CR
#undef CR
#endif
#include <Windows.h>
#include <string.h>
#include <tchar.h>
#define DLL_NAME _T("mss_fips")
#define SIGNATURE_FILE (DLL_NAME _T(".sig"))
#endif

#ifdef __RTOS_WINCE__
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <tchar.h>
#define DLL_NAME _T("mss_ce_dll")
#define SIGNATURE_FILE (DLL_NAME _T(".sig"))
#endif

/* Extern for Linux/Win32 Crypto Module FILE Read */
#ifdef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
MOC_EXTERN sbyte4 DIGI_CRYPTO_fipsSelfTestInit(ubyte* filename);
MOC_EXTERN sbyte4 DIGI_CRYPTO_fipsSelfTestUpdate(sbyte4 fd, ubyte* buf, ubyte4 bufLen);
MOC_EXTERN sbyte4 DIGI_CRYPTO_fipsSelfTestFinal(sbyte4 fd);
MOC_EXTERN int DIGI_CRYPTO_getKernelTaskId(void);
#endif

MOC_EXTERN FIPS_debugPrint sDebugPrintFunction;

static intBoolean sTestMode = FALSE;

FIPSRuntimeConfig sCurrRuntimeConfig; /* What are we configured to run */

FIPS_AlgoTestConfig sCurrAlgoTestConfig;
FIPS_InternalPowerupTestConfig sInternalCurrPowerupTestConfig;

volatile FIPSStartupStatus sCurrStatus; /* What has passed (or not). */

#ifdef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
static struct semaphore* gFipsMutexLock = NULL;
static int gFipsMutexOwner = 0;
#else
static RTOS_MUTEX gFipsMutexLock = NULL;
#endif

static randomContext*    gpFIPSTestRandomContext = NULL;

static MSTATUS (*FIPS_SinglePowerupTest[NUM_FIPS_ALGONAME_VALUES])(hwAccelDescr);

#define ALGOID_INRANGE(MINID,MAXID,PASSID) ( ((PASSID >= MINID) && (PASSID <= MAXID)) )

/*---------------------------------------------------------------------------*/

MOC_EXTERN int FIPS_SHA3AlgoFromMode(ubyte4 sha3_mode)
{
    int algoid = MOCANA_SHA3_MODE_SHA3_256;
    switch (sha3_mode)
    {
        case MOCANA_SHA3_MODE_SHA3_224:
            algoid = FIPS_ALGO_SHA3_224;
            break;
        case MOCANA_SHA3_MODE_SHA3_256:
            algoid = FIPS_ALGO_SHA3_256;
            break;
        case MOCANA_SHA3_MODE_SHA3_384:
            algoid = FIPS_ALGO_SHA3_384;
            break;
        case MOCANA_SHA3_MODE_SHA3_512:
            algoid = FIPS_ALGO_SHA3_512;
            break;
        case MOCANA_SHA3_MODE_SHAKE128:
            algoid = FIPS_ALGO_SHA3_SHAKE128;
            break;
        case MOCANA_SHA3_MODE_SHAKE256:
            algoid = FIPS_ALGO_SHA3_SHAKE256;
            break;
        default:
            break;
    }

    return algoid;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN int FIPS_AESAlgoFromMode(ubyte4 aes_mode)
{
    int algoid = FIPS_ALGO_AES_CBC;
    switch (aes_mode)
    {
        case MODE_ECB:
            algoid = FIPS_ALGO_AES_ECB;
            break;
        case MODE_CBC:
            algoid = FIPS_ALGO_AES_CBC;
            break;
        case MODE_CFB1:
            algoid = FIPS_ALGO_AES_CFB;
            break;
        case MODE_CFB128:
            algoid = FIPS_ALGO_AES_CFB;
            break;
        case MODE_OFB:
            algoid = FIPS_ALGO_AES_OFB;
            break;
        case MODE_CTR:
            algoid = FIPS_ALGO_AES_CTR;
            break;
        default:
            break;
    }

    return algoid;
}

/*---------------------------------------------------------------------------*/

static MSTATUS FIPS_InitializePowerupTestConfig(void)
{
    int i = 0;
    MSTATUS status = OK;

    for (i = 0; i < FIPS_MAX_TEST_COUNT; i++)
    {
        sInternalCurrPowerupTestConfig.test[i].action = FIPS_SKIP;
        sInternalCurrPowerupTestConfig.test[i].enc_dec_pattern = FALSE;
        sInternalCurrPowerupTestConfig.test[i].failurePowerup = FALSE;
        sInternalCurrPowerupTestConfig.test[i].enc_failurePowerup = FALSE;
        sInternalCurrPowerupTestConfig.test[i].dec_failurePowerup = FALSE;
    }

    for (i = FIRST_FIPS_ALGO; i <= LAST_FIPS_ALGO; i++)
    {
        sCurrAlgoTestConfig.test[i].action = FIPS_SKIP;
    }

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS FIPS_fillInternalPowerupTestConfig(
    FIPS_InternalPowerupTestConfig* testConfig)
{
    int i = 0;
    MSTATUS status = OK;

    for (i = FIRST_KAT_TEST; i <= LAST_KAT_TEST; i++)
    {
        if( (testConfig->test[i].failurePowerup) ||
                (testConfig->test[i].enc_failurePowerup) ||
                (testConfig->test[i].dec_failurePowerup) )
        {
            FIPS_TESTLOG_FMT(120, "FIPS_fillInternalPowerupTestConfig: Should fail KAT test: %d", i);
        }
        sInternalCurrPowerupTestConfig.test[i].action = testConfig->test[i].action;
        sInternalCurrPowerupTestConfig.test[i].enc_dec_pattern = testConfig->test[i].enc_dec_pattern;
        sInternalCurrPowerupTestConfig.test[i].failurePowerup = testConfig->test[i].failurePowerup;
        sInternalCurrPowerupTestConfig.test[i].enc_failurePowerup = testConfig->test[i].enc_failurePowerup;
        sInternalCurrPowerupTestConfig.test[i].dec_failurePowerup = testConfig->test[i].dec_failurePowerup;
    }
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS FIPS_fillAlgoTestConfig(
        FIPS_AlgoTestConfig* testConfig)
{
    int i = 0;
    MSTATUS status = OK;

    for (i = FIRST_FIPS_ALGO; i <= LAST_FIPS_ALGO; i++)
    {
        sCurrAlgoTestConfig.test[i].action = testConfig->test[i].action;
    }
    return status;
}

/*---------------------------------------------------------------------------*/
MOC_EXTERN MSTATUS FIPS_printAlgoTestConfig(char* title,
                                            FIPS_AlgoTestConfig* testConfig)
{
    int i = 0;
    MSTATUS status = OK;

    FIPS_TESTLOG_FMT(130, "==================================  %s  ==================================\n",
                     title);
    for (i = FIRST_FIPS_ALGO; i <= LAST_FIPS_ALGO; i++)
    {
        FIPS_TESTLOG_FMT(131, "--------------------->> testConfig->test[%d].action: %d",
                         i, testConfig->test[i].action);
    }
    FIPS_TESTLOG(132, "=========================================================================\n");

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_InitializeBeforeIntegrityChk(void)
{
    MSTATUS status = OK;

    FIPS_TESTLOG(104, "FIPS_InitializeBeforeIntegrityChk.");

#ifdef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__

    gFipsMutexOwner = 0;
    status = RTOS_mutexCreate((RTOS_MUTEX*)&gFipsMutexLock, FIPS_STATUS_MUTEX, 0);
    if (OK != status)
       goto exit;

    FIPS_TESTLOG(105, "FIPS_Initialize_Mutex_Created.");
#else /* __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__ */

    status = RTOS_recursiveMutexCreate(&gFipsMutexLock, FIPS_STATUS_MUTEX, 0);
    if (OK != status)
       goto exit;

    FIPS_TESTLOG(106, "FIPS_Initialize_Mutex_Created.");
#endif /* __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__ */

    status = FIPS_InitializePowerupTestConfig();
    if (OK != status)
    {
        goto exit;
    }

    FIPS_SinglePowerupTest[FIPS_ALGO_SHA1] = FIPS_sha1Kat;
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA256] = FIPS_sha224_256Kat;
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA512] = FIPS_sha384_512Kat;

#if (defined(__ENABLE_DIGICERT_SHA3__))
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA3_224] = FIPS_sha3_224Kat;
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA3_256] = FIPS_sha3_256Kat;
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA3_384] = FIPS_sha3_384Kat;
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA3_512] = FIPS_sha3_512Kat;
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA3_SHAKE128] = FIPS_sha3_shake128Kat;
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA3_SHAKE256] = FIPS_sha3_shake256Kat;
#else
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA3_224] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA3_256] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA3_384] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA3_512] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA3_SHAKE128] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_SHA3_SHAKE256] = NULL;
#endif

    FIPS_SinglePowerupTest[FIPS_ALGO_HMAC] = FIPS_hmacShaAllKat;

    FIPS_SinglePowerupTest[FIPS_ALGO_3DES] = FIPS_tdesCbcKat;
    FIPS_SinglePowerupTest[FIPS_ALGO_AES_CBC] = FIPS_aes256CbcKat;
    FIPS_SinglePowerupTest[FIPS_ALGO_AES_CCM] = FIPS_aesCcmKat;
    FIPS_SinglePowerupTest[FIPS_ALGO_AES_CFB] = FIPS_aesCfbKat;
    FIPS_SinglePowerupTest[FIPS_ALGO_AES_CMAC] = FIPS_aesCmacKat;
    FIPS_SinglePowerupTest[FIPS_ALGO_AES_CTR] = FIPS_aes256CtrKat;
    FIPS_SinglePowerupTest[FIPS_ALGO_AES_ECB] = FIPS_aes256EcbKat;
#if defined(__ENABLE_DIGICERT_GCM__)
    FIPS_SinglePowerupTest[FIPS_ALGO_AES_GCM] = FIPS_aesGcmKat;
#endif
    FIPS_SinglePowerupTest[FIPS_ALGO_AES_OFB] = FIPS_aesOfbKat;
    FIPS_SinglePowerupTest[FIPS_ALGO_AES_XTS] = FIPS_aesXtsKat;

#if (!defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__))
#ifdef __ENABLE_DIGICERT_FIPS_RSA__
    FIPS_SinglePowerupTest[FIPS_ALGO_RSA] = FIPS_rsaKat;
#endif
    /* Todo: May want to break into separate HMAC KDF tests in the future. */
    FIPS_SinglePowerupTest[FIPS_ALGO_HMAC_KDF] = FIPS_hmacKdfAll_Kat;
    FIPS_SinglePowerupTest[FIPS_ALGO_DH] = FIPS_dhKat;

#if (defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_FIPS_ECDH__))
    FIPS_SinglePowerupTest[FIPS_ALGO_ECC] = FIPS_ecdhKat;
    FIPS_SinglePowerupTest[FIPS_ALGO_EDDH] = FIPS_eddhKat;
#endif

#if (defined(__ENABLE_DIGICERT_DSA__))
   FIPS_SinglePowerupTest[FIPS_ALGO_DSA] = FIPS_dsaKat;
#endif

#if (defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_FIPS_ECDSA__))
    FIPS_SinglePowerupTest[FIPS_ALGO_ECDSA] = FIPS_ecdsaKat;
#endif
#if (defined(__ENABLE_DIGICERT_ECC_EDDSA__))
    FIPS_SinglePowerupTest[FIPS_ALGO_EDDSA] = FIPS_eddsaKat;
#endif

#if (defined(__ENABLE_DIGICERT_PQC_KEM__))
#if defined(__ENABLE_DIGICERT_FIPS_MLKEM__)
    FIPS_SinglePowerupTest[FIPS_ALGO_MLKEM] = FIPS_mlkemKat;
#endif
#endif
#if (defined(__ENABLE_DIGICERT_PQC_SIG__))
#if defined(__ENABLE_DIGICERT_FIPS_MLDSA__)
    FIPS_SinglePowerupTest[FIPS_ALGO_MLDSA] = FIPS_mldsaKat;
#endif
#if defined(__ENABLE_DIGICERT_FIPS_SLHDSA__)
    FIPS_SinglePowerupTest[FIPS_ALGO_SLHDSA] = FIPS_slhdsaKat;
#endif
#endif

#else /* ifdef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__ */
    FIPS_SinglePowerupTest[FIPS_ALGO_RSA] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_HMAC_KDF] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_DH] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_ECC] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_EDDH] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_ECDSA] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_EDDSA] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_MLKEM] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_MLDSA] = NULL;
    FIPS_SinglePowerupTest[FIPS_ALGO_SLHDSA] = NULL;

#endif /* !defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__) */

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

/* Default implementation for test log */
#ifdef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
__weak FIPS_debugPrint
#else
FIPS_debugPrint __attribute__((weak))
#endif
FIPS_getDebugPrintImplementation()
{
    return NULL;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_InitializeAfterIntegrityChk(void)
{
    MSTATUS status = OK;

    if (sDebugPrintFunction)
	sCurrRuntimeConfig.fipsDebugPrint = sDebugPrintFunction;

    FIPS_TESTLOG(102, "FIPS_InitializeAfterIntegrityChk.");

    sCurrRuntimeConfig.fipsEventLog = NULL;
    sCurrRuntimeConfig.fipsEventLogId = 0;
    sCurrRuntimeConfig.fipsEventSessionId = 0;
    sCurrRuntimeConfig.fipsEventDepth = NULL;
    sCurrRuntimeConfig.fipsEventTID = NULL;
    sCurrRuntimeConfig.fipsMutexLock = NULL;
    status = RTOS_mutexCreate((RTOS_MUTEX*)&sCurrRuntimeConfig.fipsMutexLock,
                              FIPS_CONFIG_MUTEX, 0);

    return status;
}

/*---------------------------------------------------------------------------*/
MOC_EXTERN MSTATUS FIPS_Finalize(void)
{
    MSTATUS status = OK;

    FIPS_TESTLOG(109, "FIPS_Finalize.");

#ifdef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
    if (NULL != gFipsMutexLock)
    {
        RTOS_mutexFree((RTOS_MUTEX*)&gFipsMutexLock);
        if (OK != status)
            goto exit;
        gFipsMutexLock = NULL;

        FIPS_TESTLOG(111, "FIPS_Initialize_Mutex_Destroyed.");
    }
#else
    if (NULL != gFipsMutexLock)
    {
        status = RTOS_recursiveMutexFree(&gFipsMutexLock);
        if (OK != status)
            goto exit;
        gFipsMutexLock = NULL;
        FIPS_TESTLOG(112, "FIPS_Initialize_Mutex_Destroyed.");
    }
#endif
    if (NULL != sCurrRuntimeConfig.fipsMutexLock)
    {
        status = RTOS_mutexFree(&sCurrRuntimeConfig.fipsMutexLock);
        if (OK != status)
            goto exit;

        sCurrRuntimeConfig.fipsMutexLock = NULL;
        FIPS_TESTLOG(113, "FIPS_Event_Depth_Mutex_Destroyed.");
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
/*---------------------------------------------------*/
/* This is the .so version here. */
static MSTATUS FIPS_AcquireLock(intBoolean *isLock)
{
    MSTATUS status = OK;
    if(NULL != gFipsMutexLock)
    {
        status = RTOS_recursiveMutexWait(gFipsMutexLock);
        if (OK != status)
        {
            goto exit;
        }
        *isLock = TRUE;
    }
    else
    {
        status = ERR_NULL_POINTER;
    }
exit:
    return status;
}
/*---------------------------------------------------*/
#else /* __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__ */
/* This is the LKM version here. */
static MSTATUS FIPS_AcquireLock(intBoolean *isLock)
{
    MSTATUS status = OK;
    int meTID;

    if(NULL != gFipsMutexLock)
    {
        meTID = DIGI_CRYPTO_getKernelTaskId();
        if( gFipsMutexOwner != meTID)
        {
            status = RTOS_mutexWait(gFipsMutexLock); /* block */
            if (OK != status)
            {
                gFipsMutexOwner = -42; /* No one owns it */
                goto exit;
            }
            gFipsMutexOwner = meTID; /* Set owner to me after getting the lock */
            *isLock = TRUE;
        }
        else
        {
            status = OK;
            *isLock = FALSE;
        }
    }
    else
    {
        status = ERR_NULL_POINTER;
    }
exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__ */
/*----------------------------------------------------*/

/*---------------------------------------------------------------------------*/

/*---------------------------------------------------*/
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
/*---------------------------------------------------*/
/* This is the .so version here. */
static MSTATUS FIPS_ReleaseLock(intBoolean *isLock)
{
    MSTATUS status = OK;

    if(NULL != gFipsMutexLock)
    {
        status = RTOS_recursiveMutexRelease(gFipsMutexLock);
        if (OK != status)
        {
            goto exit;
        }
        *isLock = FALSE;
    }
    else
    {
        status = ERR_NULL_POINTER;
    }

exit:
    return status;
}

/*---------------------------------------------------*/
#else /* __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__ */
/* This is the LKM version here. */
static MSTATUS FIPS_ReleaseLock(intBoolean *isLock)
{
    MSTATUS status = OK;
    int meTID = DIGI_CRYPTO_getKernelTaskId();

    if(NULL != gFipsMutexLock)
    {
        if(*isLock == TRUE)
        {
            if(gFipsMutexOwner == meTID)
            {
                gFipsMutexOwner = 0; /* reset owner before releasing the lock */
                status = RTOS_mutexRelease(gFipsMutexLock);
                if (OK != status)
                {
                    gFipsMutexOwner = -42; /* No one owns it */
                    goto exit;
                }
                *isLock = FALSE;
            }
        }
        else
        {
            status = OK;
        }
    }
    else
    {
        status = ERR_NULL_POINTER;
    }

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__ */
/*----------------------------------------------------*/

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_Zeroize(void)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_LOG_START_SVC(FIPS_ZEROIZE_SVC,0);

    if (gpFIPSTestRandomContext != NULL)
    {
        RANDOM_releaseContext((randomContext**)&gpFIPSTestRandomContext);
        gpFIPSTestRandomContext = NULL;
    }

    status = RNG_SEED_zeroizeDepotBits();
    if (OK != status)
    {
       goto exit;
    }

exit:
    FIPS_LOG_END_SVC(FIPS_ZEROIZE_SVC,0);
    return status;
}

/*---------------------------------------------------------------------------*/

static void FIPS_ZeroStartupStatus(FIPSRuntimeConfig *pfips_config)
{
    int i = 0;

    sCurrStatus.integrityTestStatus = ERR_FIPS_SELF_TEST_INCOMPLETE;
    sCurrStatus.globalFIPS_powerupStatus = ERR_FIPS_SELF_TEST_INCOMPLETE;
    sCurrStatus.startupState = FIPS_SS_INIT;

    for (i = FIRST_FIPS_ALGO; i <= LAST_FIPS_ALGO; i++)
    {
        sCurrStatus.algoEnabled[i] = pfips_config->algoEnabled[i];

        if (sCurrStatus.algoEnabled[i])
        {
            sCurrStatus.algoStatus[i] = ERR_FIPS_SELF_TEST_INCOMPLETE;
        }
        else
        {
            sCurrStatus.algoStatus[i] = ERR_RTOS;
        }
    }

    if (sCurrRuntimeConfig.fipsEventMaxThreads > 0)
    {
        DIGI_FREE((void**)&sCurrRuntimeConfig.fipsEventDepth);
        DIGI_FREE((void**)&sCurrRuntimeConfig.fipsEventTID);
        sCurrRuntimeConfig.fipsEventMaxThreads = 0;
    }

    sCurrRuntimeConfig.fipsEventDepthLimit = 0;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_isTestMode(void)
{
    return (sTestMode)?OK:ERR_FIPS;
}

/* Placeholder for actual challenge value */
static const ubyte sChallenge[SHA256_RESULT_SIZE] = {
    'M', 'O', 'C', '_', 'C', 'H', 'A', 'B' ,'!',
    0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
    'M', 'O', 'C', '_', 'C', 'H', 'A', 'E' ,'!'
};

MOC_EXTERN MSTATUS FIPS_setTestMode(ubyte *pToken, ubyte4 tokenLen)
{
    MSTATUS status;
    ubyte   versionBuff[256] = {0};
    ubyte   result[SHA256_RESULT_SIZE];
    sbyte4  optLen = tokenLen - SHA256_RESULT_SIZE;
    sbyte4  cmpRes = 0;

    status = DIGICERT_readVersion(VT_BUILD|VT_TIMESTAMP, versionBuff, sizeof(versionBuff));
    if (OK != status)
	goto exit;

    status = HMAC_SHA256(pToken, SHA256_RESULT_SIZE,
			 versionBuff, DIGI_STRLEN(versionBuff),
			 pToken + SHA256_RESULT_SIZE, optLen,
			 result);
    if (OK != status)
	goto exit;

    if (OK != DIGI_CTIME_MATCH(sChallenge, result,
			      sizeof(sChallenge), &cmpRes))
    {
	status = ERR_CRYPTO;
	goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_CRYPTO;
        goto exit;
    }

    sTestMode = TRUE;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_getDefaultConfig(FIPSRuntimeConfig *pfips_config)
{
    MSTATUS status = OK;

    if (pfips_config == NULL)
        return ERR_INVALID_ARG;

    DIGI_MEMSET((void *)pfips_config, 0x00, sizeof(FIPSRuntimeConfig));

    /************************************************/
    /* Set default Random # algorithm               */
    /************************************************/
    pfips_config->randomDefaultAlgo = FIPS_ALGO_DRBG_CTR;

    /************************************************/
    /* Set default Random # Entropy source flag     */
    /************************************************/
#ifdef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
    pfips_config->useInternalEntropy = FALSE;
#else
    pfips_config->useInternalEntropy = TRUE;
#endif

    /************************************************/
    /* Set default lib & sig Path to null           */
    /************************************************/
    pfips_config->libPath = NULL; /* default to compile time path */
    pfips_config->sigPath = NULL; /* default to compile time path */

    /****************************************************************/
    /* Set list of startup tests to run based on compile time flags */
    /****************************************************************/
#ifdef __ENABLE_DIGICERT_RNG_DRBG_CTR__
    pfips_config->algoEnabled[FIPS_ALGO_DRBG_CTR] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_DRBG_CTR] = FALSE;
#endif

    pfips_config->algoEnabled[FIPS_ALGO_SHA1] = TRUE;

#ifdef __ENABLE_DIGICERT_FIPS_SHA256__
    pfips_config->algoEnabled[FIPS_ALGO_SHA256] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_SHA256] = FALSE;
#endif

#ifdef __ENABLE_DIGICERT_FIPS_SHA512__
    pfips_config->algoEnabled[FIPS_ALGO_SHA512] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_SHA512] = FALSE;
#endif

#ifdef __ENABLE_DIGICERT_FIPS_SHA3__
    pfips_config->algoEnabled[FIPS_ALGO_SHA3_224] = TRUE;
    pfips_config->algoEnabled[FIPS_ALGO_SHA3_256] = TRUE;
    pfips_config->algoEnabled[FIPS_ALGO_SHA3_384] = TRUE;
    pfips_config->algoEnabled[FIPS_ALGO_SHA3_512] = TRUE;
    pfips_config->algoEnabled[FIPS_ALGO_SHA3_SHAKE128] = TRUE;
    pfips_config->algoEnabled[FIPS_ALGO_SHA3_SHAKE256] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_SHA3_224] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_SHA3_256] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_SHA3_384] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_SHA3_512] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_SHA3_SHAKE128] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_SHA3_SHAKE256] = FALSE;
#endif

    pfips_config->algoEnabled[FIPS_ALGO_HMAC] = TRUE;

#ifdef __ENABLE_DIGICERT_FIPS_3DES__
    pfips_config->algoEnabled[FIPS_ALGO_3DES] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_3DES] = FALSE;
#endif

#ifdef __ENABLE_DIGICERT_FIPS_AES__
    pfips_config->algoEnabled[FIPS_ALGO_AES] = TRUE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_ECB] = TRUE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_CBC] = TRUE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_CFB] = TRUE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_OFB] = TRUE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_CCM] = TRUE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_CTR] = TRUE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_CMAC] = TRUE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_XTS] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_AES] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_ECB] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_CBC] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_CFB] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_OFB] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_CCM] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_CTR] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_CMAC] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_AES_XTS] = FALSE;
#endif

#ifdef __ENABLE_DIGICERT_GCM__
    pfips_config->algoEnabled[FIPS_ALGO_AES_GCM] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_AES_GCM] = FALSE;
#endif

#ifdef __ENABLE_DIGICERT_ECC__
    pfips_config->algoEnabled[FIPS_ALGO_ECC] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_ECC] = FALSE;
#endif

#if (!defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__))

#ifdef __ENABLE_DIGICERT_FIPS_ECDH__
    pfips_config->algoEnabled[FIPS_ALGO_ECDH] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_ECDH] = FALSE;
#endif

#ifdef __ENABLE_DIGICERT_FIPS_EDDH__
    pfips_config->algoEnabled[FIPS_ALGO_EDDH] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_EDDH] = FALSE;
#endif

#ifdef __ENABLE_DIGICERT_FIPS_ECDSA__
    pfips_config->algoEnabled[FIPS_ALGO_ECDSA] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_ECDSA] = FALSE;
#endif

#ifdef __ENABLE_DIGICERT_FIPS_EDDSA__
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    pfips_config->algoEnabled[FIPS_ALGO_EDDSA] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_EDDSA] = FALSE;
#endif
#endif

    pfips_config->algoEnabled[FIPS_ALGO_DH] = TRUE;

#ifdef __ENABLE_DIGICERT_FIPS_MLDSA__
#if (defined(__ENABLE_DIGICERT_PQC__)&&defined(__ENABLE_DIGICERT_PQC_SIG__))
    pfips_config->algoEnabled[FIPS_ALGO_MLDSA] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_MLDSA] = FALSE;
#endif
#endif /* __ENABLE_DIGICERT_FIPS_MLDSA__ */

#ifdef __ENABLE_DIGICERT_FIPS_SLHDSA__
#if (defined(__ENABLE_DIGICERT_PQC__)&&defined(__ENABLE_DIGICERT_PQC_SIG__))
    pfips_config->algoEnabled[FIPS_ALGO_SLHDSA] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_SLHDSA] = FALSE;
#endif
#endif /* __ENABLE_DIGICERT_FIPS_SLHDSA__ */

#ifdef __ENABLE_DIGICERT_FIPS_MLKEM__
#if (defined(__ENABLE_DIGICERT_PQC__)&&defined(__ENABLE_DIGICERT_PQC_KEM__))
    pfips_config->algoEnabled[FIPS_ALGO_MLKEM] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_MLKEM] = FALSE;
#endif
#endif /* __ENABLE_DIGICERT_FIPS_MLKEM__ */

#ifdef __ENABLE_DIGICERT_FIPS_RSA__
    pfips_config->algoEnabled[FIPS_ALGO_RSA] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_RSA] = FALSE;
#endif

#ifdef __ENABLE_DIGICERT_FIPS_DSA__
    pfips_config->algoEnabled[FIPS_ALGO_DSA] = TRUE;
#else
    pfips_config->algoEnabled[FIPS_ALGO_DSA] = FALSE;
#endif

    pfips_config->algoEnabled[FIPS_ALGO_HMAC_KDF] = TRUE;

#else /* (!defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__)) */
    pfips_config->algoEnabled[FIPS_ALGO_SLHDSA]  = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_MLDSA]  = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_MLKEM]  = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_ECDH]  = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_ECDSA] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_EDDSA] = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_DH]    = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_RSA]   = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_DSA]   = FALSE;
    pfips_config->algoEnabled[FIPS_ALGO_HMAC_KDF] = FALSE;
#endif /* (!defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__)) */

    /*****************************************
     * Fix ECC inter-related parameters
     * */
    if ( (pfips_config->algoEnabled[FIPS_ALGO_ECDH] != TRUE) &&
            (pfips_config->algoEnabled[FIPS_ALGO_ECDSA] != TRUE) )
    {
        /* If all of these ECC-based tests are FALSE, then ECC must be FALSE. */
        pfips_config->algoEnabled[FIPS_ALGO_ECC] = FALSE;
    }

    pfips_config->algoEnabled[FIPS_ALGO_ALL] = FALSE;  /* Unused 0 entry */
    /*****************************************/


    /*****************************************
     * If libPath and sigPath are NULL, then we will use the compile time paths.
     *
     */
    pfips_config->libPath = NULL;
    pfips_config->sigPath = NULL;

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS CopyRuntimeConfigToCurrent(FIPSRuntimeConfig *pfips_config)
{
    if (pfips_config == NULL)
        return ERR_INVALID_ARG;

    /* First shallow copy everything. */
    DIGI_MEMCPY((ubyte*)&sCurrRuntimeConfig, (ubyte*)pfips_config, sizeof(FIPSRuntimeConfig));

    /* Now deep copy path pointers. */
    if (pfips_config->libPath != NULL)
    {
        int liblen = DIGI_STRLEN((const sbyte *)pfips_config->libPath);
        if (liblen != 0)
        {
            sCurrRuntimeConfig.libPath = MALLOC(liblen+1);
            if (sCurrRuntimeConfig.libPath)
            {
                DIGI_STRCBCPY( (sbyte*) sCurrRuntimeConfig.libPath, liblen+1, (const sbyte*)pfips_config->libPath);
            }
        }
    }

    if (pfips_config->sigPath != NULL)
    {
        int siglen = DIGI_STRLEN((const sbyte *)pfips_config->sigPath);
        if (siglen != 0)
        {
            sCurrRuntimeConfig.sigPath = MALLOC(siglen+1);
            if (sCurrRuntimeConfig.sigPath)
            {
                DIGI_STRCBCPY( (sbyte*) sCurrRuntimeConfig.sigPath, siglen+1, (const sbyte*)pfips_config->sigPath);
            }
        }
    }

    return OK;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN void FIPS_DumpStartupStatusData(void)
{
    int i = 0;

    FIPS_TESTLOG(140, "===================================================================");

    FIPS_TESTLOG_FMT(141, "sCurrStatus.startupState: %d", sCurrStatus.startupState);

    FIPS_TESTLOG_FMT(142, "sCurrStatus.globalFIPS_powerupStatus: %d",
                     sCurrStatus.globalFIPS_powerupStatus);

    FIPS_TESTLOG_FMT(143, "sCurrStatus.integrityTestStatus: %d",
                     sCurrStatus.integrityTestStatus);

    FIPS_TESTLOG_FMT(144, "sCurrStatus.startupShouldFail: %d",
                     sCurrStatus.startupShouldFail);

    FIPS_TESTLOG_FMT(145, "sCurrStatus.startupFailTestNumber: %d",
                     sCurrStatus.startupFailTestNumber);

    FIPS_TESTLOG(146, "---------------------------------------------------------");

    for (i = FIRST_FIPS_ALGO; i <= LAST_FIPS_ALGO; i++)
    {
        FIPS_TESTLOG_FMT(147, "sCurrStatus.algo[%d] Enabled=%s  :  Status=%d",
                         i, ((sCurrStatus.algoEnabled[i])?"TRUE ":"FALSE"), sCurrStatus.algoStatus[i]);
    }

    FIPS_TESTLOG(148, "===================================================================");
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_InternalCopyStartupStatus(FIPSStartupStatus *pCopyOfStatus)
{
    if (pCopyOfStatus == NULL)
        return ERR_NULL_POINTER;

    DIGI_MEMCPY((ubyte*)pCopyOfStatus, (ubyte*)&sCurrStatus, sizeof(FIPSStartupStatus));

    return OK;
}

/*---------------------------------------------------------------------------*/

static MSTATUS runFIPS_powerupTest(int fips_algoid)
{
    MSTATUS status = OK;
    hwAccelDescr hwAccelCtx;
    intBoolean isLock = FALSE;

#ifdef __DBG_VERBOSE_DEBUG_LOCKS__
    if (isLock)
       DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "runFIPS:Calling FIPS_AcquireLock(TRUE)");
    else
       DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "runFIPS:Calling FIPS_AcquireLock(FALSE)");
#endif /* __DBG_VERBOSE_DEBUG_LOCKS__ */
    status = FIPS_AcquireLock(&isLock);
    if (OK != status)
        goto exit;

    sCurrStatus.algoStatus[fips_algoid] = ERR_FIPS_FIRST_USE;

    if (OK > (MSTATUS)(status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
    {
        FIPS_TESTLOG(114, "runFIPS_powerupTest: HARDWARE_ACCEL_OPEN_CHANNEL() failed.");
        goto exit;
    }

#if (!defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__))
    if ( FIPS_ALGO_DSA == fips_algoid || FIPS_ALGO_ECDSA == fips_algoid || FIPS_ALGO_EDDSA == fips_algoid)
    {
        if (gpFIPSTestRandomContext == NULL)
        {
            FIPS_TESTLOG(115, "runFIPS_powerupTest: gpFIPSTestRandomContext == NULL.");
            status = ERR_NULL_POINTER;
            goto exit;
        }
    }
#endif /* !defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__) */

    if(NULL != FIPS_SinglePowerupTest[fips_algoid])
    {
        status = FIPS_SinglePowerupTest[fips_algoid](hwAccelCtx);
        if (OK != status)
            goto exit;
    }
    else
    {
        switch (fips_algoid)
        {
        case FIPS_ALGO_AES:
            sCurrStatus.algoStatus[FIPS_ALGO_AES] = OK;
            break;
#if (!defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__))
#if (defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_FIPS_ECDH__))
        case FIPS_ALGO_ECDH:
            if (OK > (status = FIPS_ecdhKat(hwAccelCtx)))
                goto exit;
            break;
        case FIPS_ALGO_ECC:
            if (OK > (status = FIPS_ecdhKat(hwAccelCtx)))
                goto exit;
            break;
#endif /* (defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_FIPS_ECDH__)) */
#ifdef __ENABLE_DIGICERT_FIPS_EDDH__

        case FIPS_ALGO_EDDH:
            if (OK > (status = FIPS_eddhKat(hwAccelCtx)))
                goto exit;
            break;
#endif /* defined(__ENABLE_DIGICERT_FIPS_EDDH__) */
#if (defined(__ENABLE_DIGICERT_DSA__))
        case FIPS_ALGO_DSA:
            if (OK > (status = FIPS_dsaKat(hwAccelCtx)))
                goto exit;
            break;
#endif /* (defined(__ENABLE_DIGICERT_DSA__)) */
#if (defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_FIPS_ECDSA__))
        case FIPS_ALGO_ECDSA:
            if (OK > (status = FIPS_ecdsaKat(hwAccelCtx)))
                goto exit;
            break;
#endif /* (defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_FIPS_ECDSA__)) */
#if (defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_FIPS_EDDSA__))
        case FIPS_ALGO_EDDSA:
            if (OK > (status = FIPS_eddsaKat(hwAccelCtx)))
                goto exit;
            break;
#endif /* (defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_FIPS_EDDSA__)) */
#endif /* !defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__) */
        default:
            FIPS_TESTLOG(150, "getFIPS_powerupStatus: SinglePowerupTest not defined.");
            break;
        }
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

#ifdef __DBG_VERBOSE_DEBUG_LOCKS__
    if (isLock)
       DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "runFIPS:Calling FIPS_ReleaseLock(TRUE)");
    else
       DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "runFIPS:Calling FIPS_ReleaseLock(FALSE)");
#endif /* __DBG_VERBOSE_DEBUG_LOCKS__ */
    {
        MSTATUS fstatus = FIPS_ReleaseLock(&isLock);
        if (OK == status)
            status = fstatus;
    }
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS getFIPS_powerupStatus(int fips_algoid)
{
    MSTATUS status = OK;
    int i, children_enabled;
    int firstchild, lastchild;
    intBoolean checkchildren;
    intBoolean isLock = FALSE;

    if ((fips_algoid < FIPS_ALGO_ALL) || (fips_algoid > LAST_FIPS_ALGO))
        return ERR_FIPS;

    /* First check the global. If it is an err, then we are done. */
    if (OK != (status = sCurrStatus.globalFIPS_powerupStatus))
        goto exit;


    if (sCurrStatus.startupState != FIPS_SS_INPROCESS)
    {
        if((ERR_FIPS_SELF_TEST_INCOMPLETE == sCurrStatus.algoStatus[fips_algoid]) ||
                (ERR_FIPS_FIRST_USE == sCurrStatus.algoStatus[fips_algoid]))
        {
            if(ERR_FIPS_SELF_TEST_INCOMPLETE == sCurrStatus.algoStatus[fips_algoid])
            {
                runFIPS_powerupTest(fips_algoid);
                status = sCurrStatus.algoStatus[fips_algoid];
                goto exit;
            }

            if(ERR_FIPS_FIRST_USE == sCurrStatus.algoStatus[fips_algoid])
            {
#ifdef __DBG_VERBOSE_DEBUG_LOCKS__
                if (isLock)
                   DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "getFIPS:Calling FIPS_AcquireLock(TRUE)");
                else
                    DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "getFIPS:Calling FIPS_AcquireLock(FALSE)");
#endif /* __DBG_VERBOSE_DEBUG_LOCKS__ */
                status = FIPS_AcquireLock(&isLock);
                if (OK != status)
                   goto exit;
                sCurrStatus.algoStatus[fips_algoid] = OK;
#ifdef __DBG_VERBOSE_DEBUG_LOCKS__
                if (isLock)
                   DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "getFIPS:Calling FIPS_ReleaseLock(TRUE)");
                else
                    DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "getFIPS:Calling FIPS_ReleaseLock(FALSE)");
#endif /* __DBG_VERBOSE_DEBUG_LOCKS__ */
                status = FIPS_ReleaseLock(&isLock);
                if (OK != status)
                   goto exit;
            }
            status = sCurrStatus.algoStatus[fips_algoid];
            goto exit;
        }

        /* During Startup Selftest, we don't check individual algos, since we haven't
         * initialized them yet...
         */
        checkchildren = FALSE;
        switch (fips_algoid)
        {
        case FIPS_ALGO_AES:
            /* Check the parent first */
            if (OK != (status = sCurrStatus.algoStatus[fips_algoid]))
                break;

            checkchildren = TRUE;
            firstchild = FIPS_ALGO_AES_ECB;
            lastchild = FIPS_ALGO_AES_XTS;

            break;

        case FIPS_ALGO_ALL:
            /* Check all enabled algos */
            for (i = FIRST_FIPS_ALGO; i <= LAST_FIPS_ALGO; i++)
            {
                if (sCurrStatus.algoEnabled[fips_algoid] == TRUE)
                {
                    if (OK != (status = sCurrStatus.algoStatus[fips_algoid]))
                        break;
                }
            }
            break;

        default:
            /* General case: all other algos: Just return the status of that algo
             * which will be ERR_FIPS_SELF_TEST_INCOMPLETE if its startup test wasn't run.
             */
            status = sCurrStatus.algoStatus[fips_algoid];
            break;

        }

        if (checkchildren == TRUE)
        {
            /* Check the children */
            children_enabled = 0;
            for (i = firstchild; i <= lastchild; i++)
            {
                if (sCurrStatus.algoEnabled[i] == TRUE)
                {
                    children_enabled++;
                    if (OK != (status = sCurrStatus.algoStatus[fips_algoid]))
                        break;
                }
            }
            if (children_enabled == 0)
                status = ERR_FIPS_SELF_TEST_INCOMPLETE;
        }

    } /* endif not in FIPS_SS_INPROCESS state */

exit:

    if (status != OK)
    {
        FIPS_TESTLOG_FMT(160, "getFIPS_powerupStatus(%d) returning %d\n",
                         fips_algoid, status);
    }

    return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_SelftestIntegrity(void)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_LOG_START_SVC(FIPS_FORCE_INTEGTEST_SVC,0);

#ifdef __ENABLE_DIGICERT_FIPS_INTEG_TEST__
    status = FIPS_INTEG_TEST();

    if (status != OK)
    {
        FIPS_TESTLOG_FMT(161, "FIPS_IntegTest Status=%d\n", status);
    }
    else
    {
        FIPS_TESTLOG(162, "FIPS_StartupSelftestIntegrity: FIPS_IntegTest Successful...");
    }
#endif /* __ENABLE_DIGICERT_FIPS_INTEG_TEST__ */

    FIPS_LOG_END_SVC(FIPS_FORCE_INTEGTEST_SVC,0);

    return status;
}

/*---------------------------------------------------------------------------*/

#define __DIGICERT_PERSIST_USE_FILE__

MOC_EXTERN MSTATUS FIPS_getFileLocations(sbyte** ppSharedLibPath,
    sbyte** ppSigPath, sbyte** ppPersistStatusPath)
{
    MSTATUS status = OK;

    if((NULL == ppSharedLibPath) || (NULL == ppSigPath) ||
       (NULL == ppPersistStatusPath))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC((void **)ppSharedLibPath, 1,
        DIGI_STRLEN((const sbyte*)FIPS_INTEG_TEST_BINARY_FILENAME) + 1);
    if (OK != status)
    {
        goto exit;
    }

    DIGI_MEMCPY(*ppSharedLibPath,
        (const char*)FIPS_INTEG_TEST_BINARY_FILENAME,
        DIGI_STRLEN((const sbyte*)FIPS_INTEG_TEST_BINARY_FILENAME));
    (*ppSharedLibPath)[DIGI_STRLEN((const sbyte*)FIPS_INTEG_TEST_BINARY_FILENAME)] = '\0';

    status = DIGI_CALLOC((void **)ppSigPath, 1,
        DIGI_STRLEN((const sbyte*)FIPS_INTEG_TEST_HASH_FILENAME) + 1);
    if (OK != status)
    {
        goto exit;
    }

    DIGI_MEMCPY(*ppSigPath,
        (const char*)FIPS_INTEG_TEST_HASH_FILENAME,
        DIGI_STRLEN((const sbyte*)FIPS_INTEG_TEST_HASH_FILENAME));
    (*ppSigPath)[DIGI_STRLEN((const sbyte*)FIPS_INTEG_TEST_HASH_FILENAME)] = '\0';

#ifdef __DIGICERT_PERSIST_FILEPATH__
    status = DIGI_CALLOC((void **)ppPersistStatusPath, 1,
        DIGI_STRLEN((const sbyte*)__DIGICERT_PERSIST_FILEPATH__) + 1);
    if (OK != status)
    {
        goto exit;
    }

    DIGI_MEMCPY(*ppPersistStatusPath,
        (const char*)__DIGICERT_PERSIST_FILEPATH__,
        DIGI_STRLEN((const sbyte*)__DIGICERT_PERSIST_FILEPATH__));
    (*ppPersistStatusPath)[DIGI_STRLEN((const sbyte*)__DIGICERT_PERSIST_FILEPATH__)] = '\0';

#endif

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN void setFIPS_Status(int fips_algoid, MSTATUS statusValue)
{
	if ((fips_algoid < FIRST_FIPS_ALGO) || (fips_algoid > LAST_FIPS_ALGO))
		return;

    FIPS_TESTLOG_FMT(180, "setFIPS_Status(%d) setting %d", fips_algoid, statusValue);

    sCurrStatus.algoStatus[fips_algoid] = statusValue;
    if (statusValue != OK)
    {
        /* If anything breaks, break them all */
        sCurrStatus.globalFIPS_powerupStatus = statusValue;
    }
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN void setFIPS_Status_Once(int fips_algoid, MSTATUS statusValue)
{
    if ((fips_algoid < FIRST_FIPS_ALGO) || (fips_algoid >LAST_FIPS_ALGO))
        return;

    if (statusValue == OK)
    {
        if ((sCurrStatus.algoStatus[fips_algoid] == ERR_FIPS_SELF_TEST_INCOMPLETE) ||
           (sCurrStatus.algoStatus[fips_algoid] == ERR_FIPS_FIRST_USE))
        {
            setFIPS_Status(fips_algoid, statusValue);
        }
    }
    else
    {
        setFIPS_Status(fips_algoid, statusValue);
    }
}

/*--------------------------------------------------------*/

static void FIPS_StartupTests_SaveResults(MSTATUS status)
{
    int i;
    if (status == OK)
    {
        for (i = FIRST_FIPS_ALGO; i <= LAST_FIPS_ALGO; i++)
        {
            if (sCurrStatus.algoEnabled[i])
            {
                if ((sCurrStatus.algoStatus[i] != OK) &&
                   (sCurrStatus.algoStatus[i] != ERR_FIPS_SELF_TEST_INCOMPLETE))
                {
                    status = sCurrStatus.algoStatus[i]; /* Not OK. */
                    FIPS_TESTLOG_FMT(181, "FIPS_StartupTests_SaveResults: Test %d FAILED with %d",
                                     i, sCurrStatus.algoStatus[i]);
                }
            }
            else
            {   /* If it is disabled, mark it as incomplete too. */
                sCurrStatus.algoStatus[i] = ERR_FIPS_SELF_TEST_INCOMPLETE;
            }
        }
    }

#ifdef __ENABLE_DIGICERT_FIPS_INTEG_TEST__
    if (sCurrStatus.integrityTestStatus != OK)
    {
        status = sCurrStatus.integrityTestStatus;
    }
#endif

    /*******************************/
    /* This is the important part. */
    /*******************************/
    sCurrStatus.globalFIPS_powerupStatus = status;
    sCurrStatus.startupState = FIPS_SS_DONE;

    if (status == OK)
    {
        FIPS_TESTLOG(182, "FIPS_StartupTests_SaveResults: status = OK");
    }
    else
    {
        FIPS_TESTLOG(183, "FIPS_StartupTests_SaveResults: status = FAILED");
    }
}

/*------------------------------------------------------------------*/
/* FIPS force failure tests */
/*------------------------------------------------------------------*/

/*------------------------------------------------------------------*/

static MSTATUS FIPS_InternalResetInitialAlgoStatus(int fips_algoid)
{
    MSTATUS status = OK;
    int i = 0;

    for(i = 0; i < FIPS_APPROVED_ALGO_END; i++)
    {
        if((FIPS_ALGO_DRBG_CTR == i) || (FIPS_ALGO_SHA256 == i) || (FIPS_ALGO_AES == i))
        {
            sCurrStatus.algoStatus[i] = OK;
        }
        else
        {
            sCurrStatus.algoStatus[i] = ERR_FIPS_SELF_TEST_INCOMPLETE;
        }
    }
    sCurrStatus.globalFIPS_powerupStatus = OK;

    return status;
}

/*---------------------------------------------------------------------------*/

static void FIPS_resetStartupFail(void)
{
    FIPS_ZeroStartupStatus(&sCurrRuntimeConfig);
    sCurrStatus.startupShouldFail = 0;
    sCurrStatus.startupFailTestNumber = 0;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__
static volatile ubyte4 teststarttime;
#endif /* __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__ */
MOC_EXTERN void
FIPS_startTestMsg(const char *pFunctionName, const char *pTestName)
{
    FIPS_TESTLOG_FMT(170, "%s: Starting [%s] test.", pFunctionName, pTestName);
#ifdef __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__
    teststarttime = RTOS_getUpTimeInMS();
    FIPS_TESTLOG_FMT(171, "S-Time= %d", teststarttime);
#endif /* __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__ */
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__
static volatile ubyte4 testendtime;
#endif /* __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__ */
MOC_EXTERN void
FIPS_endTestMsg(const char *pFunctionName, const char *pTestName, MSTATUS status)
{
    if (OK > status)
    {
        FIPS_TESTLOG_FMT(172, "%s: Result [%s] FAILED.", pFunctionName, pTestName);
    }
    else
    {
        FIPS_TESTLOG_FMT(173, "%s: Result [%s] PASSED.", pFunctionName, pTestName);
    }
#ifdef __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__
    testendtime = RTOS_getUpTimeInMS();
    FIPS_TESTLOG_FMT(174, "E-Time = %d  Elapsed (mil) = %d", testendtime, testendtime-teststarttime);
#endif /* __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__ */
}

/*------------------------------------------------------------------*/

/* Sub FIPS Tests */
MOC_EXTERN MSTATUS
FIPS_knownAnswerTestsPreIntegTest(void)
{
    /* Run Known Answer Tests (KAT) */
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status = OK;

    FIPS_TESTLOG(190, "FIPS_knownAnswerTestsPreIntegTest:\t\t\tStarted...");

    if (OK > (MSTATUS)(status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
    {
        FIPS_TESTLOG(191, "FIPS_knownAnswerTestsPreIntegTest: HARDWARE_ACCEL_OPEN_CHANNEL() failed.");
        return status;
    }

    /* Run DRBG since we know we'll need it ultimately. */
    if (OK > (status = FIPS_nistRngKat()))
        goto exit;

#if (!defined(__DISABLE_DIGICERT_SHA256__))

    /* Run HMAC-SHA256 since we we'll need it for Integrity test. */
    if (OK > (status = FIPS_hmacSha256Kat(hwAccelCtx)))
        goto exit;

#endif /* (!defined(__DISABLE_DIGICERT_SHA256__)) */

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    FIPS_TESTLOG(192, "FIPS_knownAnswerTestsPreIntegTest:\t\t\tFinished");

    return status;

} /* FIPS_knownAnswerTestsPreIntegTest */

/*------------------------------------------------------------------*/

/* Sub FIPS Tests */
MOC_EXTERN MSTATUS
FIPS_knownAnswerTests(void)
{
    /* Run Known Answer Tests (KAT) */
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status = OK;

    FIPS_TESTLOG(195, "FIPS_knownAnswerTests:\t\t\tStarted...");

    if (OK > (MSTATUS)(status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
    {
        FIPS_TESTLOG(196, "FIPS_knownAnswerTests: HARDWARE_ACCEL_OPEN_CHANNEL() failed.");
        return status;
    }

    if (gpFIPSTestRandomContext == NULL)
    {
        FIPS_TESTLOG(197, "FIPS_knownAnswerTests: gpFIPSTestRandomContext == NULL.");
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_DRBG_CTR) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_RNG_DRBG_CTR_TESTNUM))
    {
        if (OK > (status = FIPS_nistRngKat()))
            goto exit;
    }

#ifdef __ENABLE_DIGICERT_FIPS_RSA__
    /* Note: this doesn't use the RSA_SIMPLE implemenation */
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_RSA) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_RSA_TESTNUM))
    {
        if (OK > (status = FIPS_rsaKat(hwAccelCtx)))
            goto exit;
    }
#endif /* __ENABLE_DIGICERT_FIPS_RSA__ */

    /* Hash algorithms */
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SHA1) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SHA1_TESTNUM))
    {
        if (OK > (status = FIPS_sha1Kat(hwAccelCtx)))
            goto exit;
    }

    /* Hash algorithms */
#if (!defined(__DISABLE_DIGICERT_SHA224__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SHA256) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SHA224_TESTNUM))
    {
        if (OK > (status = FIPS_sha224Kat(hwAccelCtx)))
            goto exit;
    }
#endif /* (!defined(__DISABLE_DIGICERT_SHA224__)) */

#if (!defined(__DISABLE_DIGICERT_SHA256__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SHA256) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SHA256_TESTNUM))
    {
        if (OK > (status = FIPS_sha256Kat(hwAccelCtx)))
            goto exit;
    }
#endif /* (!defined(__DISABLE_DIGICERT_SHA256__)) */

#if (!defined(__DISABLE_DIGICERT_SHA384__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SHA512) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SHA384_TESTNUM))
    {
        if (OK > (status = FIPS_sha384Kat(hwAccelCtx)))
            goto exit;
    }
#endif /* (!defined(__DISABLE_DIGICERT_SHA384__)) */

#if (!defined(__DISABLE_DIGICERT_SHA512__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SHA512) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SHA512_TESTNUM))
    {
        if (OK > (status = FIPS_sha512Kat(hwAccelCtx)))
            goto exit;
    }
#endif /* (!defined(__DISABLE_DIGICERT_SHA512__)) */

#if (defined(__ENABLE_DIGICERT_SHA3__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SHA3_224) ||
        POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SHA3_224_TESTNUM))
    {
        if (OK > (status = FIPS_sha3_224Kat(hwAccelCtx)))
            goto exit;
    }
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SHA3_256) ||
        POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SHA3_256_TESTNUM))
    {
        if (OK > (status = FIPS_sha3_256Kat(hwAccelCtx)))
            goto exit;
    }
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SHA3_384) ||
        POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SHA3_384_TESTNUM))
    {
        if (OK > (status = FIPS_sha3_384Kat(hwAccelCtx)))
            goto exit;
    }
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SHA3_512) ||
        POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SHA3_512_TESTNUM))
    {
        if (OK > (status = FIPS_sha3_512Kat(hwAccelCtx)))
            goto exit;
    }
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SHA3_SHAKE128) ||
        POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SHAKE_128_TESTNUM))
    {
        if (OK > (status = FIPS_sha3_shake128Kat(hwAccelCtx)))
            goto exit;
    }
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SHA3_SHAKE256) ||
        POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SHAKE_256_TESTNUM))
    {
        if (OK > (status = FIPS_sha3_shake256Kat(hwAccelCtx)))
            goto exit;
    }
#endif /* (defined(__ENABLE_DIGICERT_SHA3__)) */

    /* HMAC algorithms */
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_SHA1_TESTNUM))
    {
        if (OK > (status = FIPS_hmacSha1Kat(hwAccelCtx)))
        goto exit;
    }

#if (!defined(__DISABLE_DIGICERT_SHA224__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_SHA224_TESTNUM))
    {
        if (OK > (status = FIPS_hmacSha224Kat(hwAccelCtx)))
        goto exit;
    }
#endif /* (!defined(__DISABLE_DIGICERT_SHA224__)) */

#if (!defined(__DISABLE_DIGICERT_SHA256__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_SHA256_TESTNUM))
    {
        if (OK > (status = FIPS_hmacSha256Kat(hwAccelCtx)))
        goto exit;
    }
#endif /* (!defined(__DISABLE_DIGICERT_SHA256__)) */

#if (!defined(__DISABLE_DIGICERT_SHA384__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_SHA384_TESTNUM))
    {
        if (OK > (status = FIPS_hmacSha384Kat(hwAccelCtx)))
            goto exit;
    }
#endif /* (!defined(__DISABLE_DIGICERT_SHA384__)) */

#if (!defined(__DISABLE_DIGICERT_SHA512__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_SHA512_TESTNUM))
    {
        if (OK > (status = FIPS_hmacSha512Kat(hwAccelCtx)))
        goto exit;
    }
#endif /* (!defined(__DISABLE_DIGICERT_SHA512__)) */

#if defined(__ENABLE_DIGICERT_FIPS_SHA3__)
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_SHA3_224_TESTNUM))
    {
        if (OK > (status = FIPS_hmacSha3_224Kat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_SHA3_256_TESTNUM))
    {
        if (OK > (status = FIPS_hmacSha3_256Kat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_SHA3_384_TESTNUM))
    {
        if (OK > (status = FIPS_hmacSha3_384Kat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_SHA3_512_TESTNUM))
    {
        if (OK > (status = FIPS_hmacSha3_512Kat(hwAccelCtx)))
            goto exit;
    }
#endif /* defined(__ENABLE_DIGICERT_FIPS_SHA3__) */

    /* Symmetrical algorithms */
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_3DES) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_3DES_CBC_TESTNUM))
    {
        if (OK > (status = FIPS_tdesCbcKat(hwAccelCtx)))
            goto exit;
    }

    /* Mark that we are running all the AES tests. */
    /* Poss: setFIPS_Status_Once(FIPS_ALGO_AES, OK); */

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_AES_CBC) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_AES_CBC_TESTNUM))
    {
        if (OK > (status = FIPS_aes256CbcKat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_AES_CTR) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_AES_CTR_TESTNUM))
    {
        if (OK > (status = FIPS_aes256CtrKat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_AES_ECB) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_AES_ECB_TESTNUM))
    {
        if (OK > (status = FIPS_aes256EcbKat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_AES_CCM) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_AES_CCM_TESTNUM))
    {
        if (OK > (status = FIPS_aesCcmKat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_AES_CMAC) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_AES_CMAC_TESTNUM))
    {
        if (OK > (status = FIPS_aesCmacKat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_AES_XTS) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_AES_XTS_TESTNUM))
    {
        if (OK > (status = FIPS_aesXtsKat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_AES_CFB) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_AES_CFB_TESTNUM))
    {
        if (OK > (status = FIPS_aesCfbKat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_AES_OFB) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_AES_OFB_TESTNUM))
    {
        if (OK > (status = FIPS_aesOfbKat(hwAccelCtx)))
            goto exit;
    }

#if defined(__ENABLE_DIGICERT_GCM__)
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_AES_GCM) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_AES_GCM_TESTNUM))
    {
        if (OK > (status = FIPS_aesGcmKat(hwAccelCtx)))
            goto exit;
    }
#endif

#if (!defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__))

    /* HMAC-KDF algorithm (In Suite-B library only) */
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC_KDF) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_KDF_SHA1_TESTNUM))
    {
        if (OK > (status = FIPS_hmacKdfSha1Kat(hwAccelCtx)))
            goto exit;
    }

#if (!defined(__DISABLE_DIGICERT_SHA224__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC_KDF) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_KDF_SHA224_TESTNUM))
    {
        if (OK > (status = FIPS_hmacKdfSha224Kat(hwAccelCtx)))
            goto exit;
    }
#endif /* (!defined(__DISABLE_DIGICERT_SHA224__)) */

#if (!defined(__DISABLE_DIGICERT_SHA256__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC_KDF) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_KDF_SHA256_TESTNUM))
    {
        if (OK > (status = FIPS_hmacKdfSha256Kat(hwAccelCtx)))
            goto exit;
    }
#endif /* (!defined(__DISABLE_DIGICERT_SHA256__)) */

#if (!defined(__DISABLE_DIGICERT_SHA384__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC_KDF) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_KDF_SHA384_TESTNUM))
    {
        if (OK > (status = FIPS_hmacKdfSha384Kat(hwAccelCtx)))
            goto exit;
    }
#endif /* (!defined(__DISABLE_DIGICERT_SHA384__)) */

#if (!defined(__DISABLE_DIGICERT_SHA512__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC_KDF) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_KDF_SHA512_TESTNUM))
    {
        if (OK > (status = FIPS_hmacKdfSha512Kat(hwAccelCtx)))
            goto exit;
    }
#endif /* (!defined(__DISABLE_DIGICERT_SHA512__)) */

#if defined(__ENABLE_DIGICERT_FIPS_SHA3__)
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC_KDF) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_KDF_SHA3_224_TESTNUM))
    {
        if (OK > (status = FIPS_hmacKdfSha3_224Kat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC_KDF) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_KDF_SHA3_256_TESTNUM))
    {
        if (OK > (status = FIPS_hmacKdfSha3_256Kat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC_KDF) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_KDF_SHA3_384_TESTNUM))
    {
        if (OK > (status = FIPS_hmacKdfSha3_384Kat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_HMAC_KDF) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_HMAC_KDF_SHA3_512_TESTNUM))
    {
        if (OK > (status = FIPS_hmacKdfSha3_512Kat(hwAccelCtx)))
            goto exit;
    }
#endif /* defined(__ENABLE_DIGICERT_FIPS_SHA3__) */

#if (defined(__ENABLE_DIGICERT_DSA__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_DSA) ||
        POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_DSA_TESTNUM))
    {
        status = FIPS_dsaKat(hwAccelCtx);
        if(OK != status)
        {
            goto exit;
        }
    }
#endif /* (defined(__ENABLE_DIGICERT_DSA__)) */

#if (defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_FIPS_ECDSA__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_ECDSA) ||
        POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_ECDSA_TESTNUM))
    {
        status = FIPS_ecdsaKat(hwAccelCtx);
        if(OK != status)
        {
            goto exit;
        }
    }
#endif /* (defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_FIPS_ECDSA__)) */

#ifdef __ENABLE_DIGICERT_FIPS_EDDSA__
#if (defined(__ENABLE_DIGICERT_ECC_EDDSA__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_EDDSA) ||
        POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_EDDSA_TESTNUM))
    {
        status = FIPS_eddsaKat(hwAccelCtx);
        if (OK  != status)
        {
            goto exit;
        }
    }
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA__) */
#endif /* defined(__ENABLE_DIGICERT_FIPS_EDDSA__) */

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_DH) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_DH_TESTNUM))
    {
       if (OK > (status = FIPS_dhKat(hwAccelCtx)))
               goto exit;
    }

#if (defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_FIPS_ECDH__))
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_ECDH) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_ECDH_TESTNUM))
    {
        if (OK > (status = FIPS_ecdhKat(hwAccelCtx)))
            goto exit;
    }
#endif /* (defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_FIPS_ECDH__)) */

    /* EDDH is not a FIPS approved algorithm. When it is approved, we will add the KAT here */
#ifdef __ENABLE_DIGICERT_FIPS_EDDH__
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_EDDH) ||
        POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_EDDH_TESTNUM))
     {
         if (OK > (status = FIPS_eddhKat(hwAccelCtx)))
             goto exit;
     }
#endif /* defined(__ENABLE_DIGICERT_FIPS_EDDH__) */

#if (defined(__ENABLE_DIGICERT_PQC_KEM__))
#if defined(__ENABLE_DIGICERT_FIPS_MLKEM__)
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_MLKEM) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_MLKEM_KEY_TESTNUM))
    {
        if (OK > (status = FIPS_mlkem_key_Kat(hwAccelCtx)))
            goto exit;
    }
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_MLKEM) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_MLKEM_ENCAP_TESTNUM))
    {
        if (OK > (status = FIPS_mlkem_encap_Kat(hwAccelCtx)))
            goto exit;
    }
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_MLKEM) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_MLKEM_DECAP_TESTNUM))
    {
        if (OK > (status = FIPS_mlkem_decap_Kat(hwAccelCtx)))
            goto exit;
    }
#endif
#endif  /* defined(__ENABLE_DIGICERT_PQC_KEM__) */

#if (defined(__ENABLE_DIGICERT_PQC_SIG__))
#if defined(__ENABLE_DIGICERT_FIPS_MLDSA__)
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_MLDSA) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_MLDSA_KEY_TESTNUM))
    {
        if (OK > (status = FIPS_mldsa_key_Kat(hwAccelCtx)))
            goto exit;
    }
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_MLDSA) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_MLDSA_SIGN_TESTNUM))
    {
        if (OK > (status = FIPS_mldsa_sign_Kat(hwAccelCtx)))
            goto exit;
    }
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_MLDSA) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_MLDSA_VERIFY_TESTNUM))
    {
        if (OK > (status = FIPS_mldsa_verify_Kat(hwAccelCtx)))
            goto exit;
    }
#endif
#if defined(__ENABLE_DIGICERT_FIPS_SLHDSA__)
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SLHDSA) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SLHDSA_SHA2_KEY_TESTNUM))
    {
        if (OK > (status = FIPS_slhdsa_sha2_key_Kat(hwAccelCtx)))
            goto exit;
    }
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SLHDSA) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SLHDSA_SHA2_SIGN_TESTNUM))
    {
        if (OK > (status = FIPS_slhdsa_sha2_sign_Kat(hwAccelCtx)))
            goto exit;
    }
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SLHDSA) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SLHDSA_SHA2_VERIFY_TESTNUM))
    {
        if (OK > (status = FIPS_slhdsa_sha2_verify_Kat(hwAccelCtx)))
            goto exit;
    }

    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SLHDSA) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SLHDSA_SHAKE_KEY_TESTNUM))
    {
        if (OK > (status = FIPS_slhdsa_shake_key_Kat(hwAccelCtx)))
            goto exit;
    }
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SLHDSA) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SLHDSA_SHAKE_SIGN_TESTNUM))
    {
        if (OK > (status = FIPS_slhdsa_shake_sign_Kat(hwAccelCtx)))
            goto exit;
    }
    if(ALGO_POWERUP_ALGOIDSHOULDRUN(FIPS_ALGO_SLHDSA) ||
       POWERUP_ALGOTESTNUMSHOULDRUN(FIPS_SLHDSA_SHAKE_VERIFY_TESTNUM))
    {
        if (OK > (status = FIPS_slhdsa_shake_verify_Kat(hwAccelCtx)))
            goto exit;
    }
#endif
#endif  /* defined(__ENABLE_DIGICERT_PQC_SIG__) */

#endif /* !defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__) */

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    FIPS_TESTLOG(198, "FIPS_knownAnswerTests:\t\t\tFinished");

    return status;

} /* FIPS_knownAnswerTests */

/*------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__))
/*------------------------------------------------------------------*/
/* This code is based on the code in RANDOM_acquireDRBGCTRContext   */

static MSTATUS createFIPSTestRandomContext(void)
{
    MSTATUS status = OK;

    randomContext* newCTRContext = 0;
    RandomCtxWrapper* pWrapper = NULL;
    NIST_CTR_DRBG_Ctx* pCtx = NULL;

    const ubyte entropyBytes[64] = {
            0xb6,0x17,0x31,0x86, 0x55,0x05,0x72,0x64, 0xe2,0x8b,0xc0,0xb6, 0xfb,0x37,0x8c,0x8e,
            0xb6,0x17,0x31,0x86, 0xfb,0x37,0x8c,0x8e, 0x55,0x05,0x72,0x64, 0xe2,0x8b,0xc0,0xb6,
            0xe2,0x8b,0xc0,0xb6, 0xfb,0x37,0x8c,0x8e, 0xb6,0x17,0x31,0x86, 0x55,0x05,0x72,0x64};
    ubyte4 entropyLen = 48;
    const ubyte *persoStr = NULL;
    ubyte4 persoStrLen = 0;

    hwAccelDescr hwAccelCtx = 0;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
    {
        goto exit;
    }

    if (OK > (status =
                NIST_CTRDRBG_newDFContext (
                       MOC_SYM(hwAccelCtx) &newCTRContext,
                       NIST_CTRDRBG_DEFAULT_KEY_LEN_BYTES,
                       NIST_CTRDRBG_DEFAULT_OUT_LEN_BYTES,
                       entropyBytes, entropyLen,
                       NULL, 0, persoStr, persoStrLen)))
    {
        goto exit;
    }

    pWrapper = (RandomCtxWrapper*)newCTRContext;
    pWrapper->reseedBitCounter = 0;

    pWrapper->hwAccelCtx = hwAccelCtx;
    hwAccelCtx = 0;

    pCtx = GET_CTR_DRBG_CTX(pWrapper);
    U8INIT(pCtx->reseedCounter, 0, 1);

    gpFIPSTestRandomContext = newCTRContext;
    newCTRContext = 0;

exit:
    if (newCTRContext != NULL)
    {
        NIST_CTRDRBG_deleteContext( MOC_SYM(pWrapper->hwAccelCtx) &newCTRContext);
    }

    if (OK != status && hwAccelCtx)
    {
        (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    }
    return status;
}

#endif /* !defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__) */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_powerupSelfTestEx(
    FIPSRuntimeConfig *pfips_config)
{
    MSTATUS status = OK;

    FIPS_TESTLOG(103, "FIPS_powerupSelfTestEx: Started...");

#if defined(__ENABLE_DIGICERT_FIPS_INTEG_TEST__) && \
        defined(__ENABLE_DIGICERT_FIPS_STATIC_INTEG_TEST__)
    FIPS_TESTLOG_FMT(99, "%s", FIPS_OPS_TEST_CONST);
#endif

    /* Copy the provided config into the current config. */
    if (OK != (status = CopyRuntimeConfigToCurrent(pfips_config)))
    {
        FIPS_TESTLOG(123, "FIPS_powerupSelfTestEx: Bad configuration.");
        FIPS_ZeroStartupStatus(&sCurrRuntimeConfig);
        goto exit;
    }

    FIPS_ZeroStartupStatus(&sCurrRuntimeConfig);
    if (sDebugPrintFunction)
        FIPS_registerDebugPrint(sDebugPrintFunction);

    sCurrStatus.startupState = FIPS_SS_INPROCESS;

    /* FORCE OK so we can run HMAC SHA256 to do integrity check */
    sCurrStatus.globalFIPS_powerupStatus = OK;

    /* Set up a few things before doing the integrity check */
    FIPS_knownAnswerTestsPreIntegTest();

    /* Always do the integrity check */
#ifdef __ENABLE_DIGICERT_FIPS_INTEG_TEST__
#ifdef __ENABLE_DIGICERT_FIPS_ALWAYS_IMPORT_FIRST__
    /* Save fingerprint for import check */
    FIPS_TESTLOG(151, "FIPS_powerupSelfTestEx: Calling w/ Import FIPS_INTEG_TEST()");
    if (OK > (status = FIPS_INTEG_TESTO((ubyte*)&(sCurrStatus.fingerPrint), sizeof(sCurrStatus.fingerPrint))))
        goto exit;
#else
    FIPS_TESTLOG(152, "FIPS_powerupSelfTestEx: Calling FIPS_INTEG_TEST()");
    if (OK > (status = FIPS_INTEG_TEST()))
        goto exit;
#endif

    FIPS_TESTLOG(116, "FIPS_powerupSelfTestEx: FIPS_IntegTest Done...");
#endif /* __ENABLE_DIGICERT_FIPS_INTEG_TEST__ */

    status = RANDOM_setEntropySource(ENTROPY_SRC_EXTERNAL);

#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
    /* Setup ECC & ED mutexes needed for persistent ECC COMB tables
     * enabled by (__ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__).
     * Do this before trying to import because we need the mutexes
     * in the shared library whether we run ECC related self-tests or not.
     */
    if (OK > (status = CRYPTO_DIGI_init()))
        goto exit;

    /*
     * Create our internal test RandomContext
     */
    if (OK > (status = createFIPSTestRandomContext()))
        goto exit;
#endif /* __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__ */


    /* Minor FIPS status cleanup...
     * enabled by (__ENABLE_DIGICERT_SIGNED_ODD_COMB_PERSIST__).
     * Reset HMAC to run again. since we only did SHA-256 portion of the HMAC test
     * and Set AES top-level status to OK for cleanliness. */
    sCurrStatus.algoStatus[FIPS_ALGO_HMAC] = ERR_FIPS_SELF_TEST_INCOMPLETE;
    sCurrStatus.algoStatus[FIPS_ALGO_AES]  = OK;

#ifdef __ENABLE_DIGICERT_FIPS_ALWAYS_IMPORT_FIRST__
    FIPS_TESTLOG(117, "FIPS_powerupSelfTest: Attempt import...");
    status = FIPS_StatusImport();
    /* Always prefer imported status data when successful */
    if (OK == status)
    {
        FIPS_TESTLOG(118, "FIPS_powerupSelfTest: Import succeeded.");
    }
    else
    {
        FIPS_TESTLOG(119, "FIPS_powerupSelfTest: Status not imported.");
    }
    status = OK; /* OK if Status happened or not */
#endif /* __ENABLE_DIGICERT_FIPS_ALWAYS_IMPORT_FIRST__ */


exit:
    /* Global status is set to powerup tests status */
    FIPS_StartupTests_SaveResults(status);

    FIPS_TESTLOG(121, "FIPS_powerupSelfTestEx: exit: Calling FIPS_DumpStartupStatusData().");
    if (FIPS_TESTLOG_ENABLED)
        FIPS_DumpStartupStatusData();

#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
    RTOS_sleepMS(5000);
    dbg_dump();
#endif

    FIPS_TESTLOG(122, "FIPS_powerupSelfTestEx: Finished");

    return status;
}

/*------------------------------------------------------------------*/

/*-----------------------------------------------------------*/
/* This is the Main entry point called by the constructor.   */
/*-----------------------------------------------------------*/
/* Main FIPS Tests */
MOC_EXTERN MSTATUS
FIPS_powerupSelfTest(void)
{
    MSTATUS status = OK;
    FIPSRuntimeConfig *pdef_fips_config = NULL;
    
    FIPS_TESTLOG(107, "FIPS_powerupSelfTest: Started...");

    /* Initialize the Current config with the compile-time config. */
    /* Start w/ compile-time config. */
    FIPS_getDefaultConfig(&sCurrRuntimeConfig);
    if (sDebugPrintFunction)
        FIPS_registerDebugPrint(sDebugPrintFunction);

    /* Get another copy of the default config to pass to FIPS_powerupSelfTestEx... */
    pdef_fips_config = MALLOC(sizeof(FIPSRuntimeConfig));

    FIPS_getDefaultConfig(pdef_fips_config);

    status = FIPS_powerupSelfTestEx(pdef_fips_config);

    FREE(pdef_fips_config);

    FIPS_TESTLOG(124, "FIPS_powerupSelfTest: Finished");

    return status;
}


/*-----------------------------------------------------------------------------------------------*/
/* This function is public in production to allow the user to explicitly check self-tests status */
/*-----------------------------------------------------------------------------------------------*/
MOC_EXTERN MSTATUS FIPS_getSelftestAlgosState(FIPS_AlgoTestConfig* testConfig)
{
    MSTATUS status = OK;
    int i = 0;

    if (testConfig == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (i = FIRST_FIPS_ALGO; i <= LAST_FIPS_ALGO; i++)
    {
        testConfig->test[i].action = FIPS_SKIP;
        if (sCurrStatus.algoEnabled[i])
        {
            if (sCurrStatus.algoStatus[i] == OK)
            {
                testConfig->test[i].action = FIPS_COMPLETE;
            }
            else
            {
                testConfig->test[i].action = FIPS_INCOMPLETE;
            }
        }
    }

    if (FIPS_TESTLOG_ENABLED)
        FIPS_printAlgoTestConfig("FIPS_getSelftestAlgosState returning:", testConfig);

exit:
    return status;

}



/*----------------------------------------------------------------------------------------*/
/* This function is public in production to allow the user to explicitly force self-tests */
/*----------------------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_SelftestAlgos(FIPS_AlgoTestConfig* testConfig)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_LOG_START_SVC(FIPS_FORCE_SELFTESTS_SVC,0);

    status = FIPS_fillAlgoTestConfig(testConfig);
    if( OK != status)
    {
        goto exit;
    }

    status = FIPS_knownAnswerTests();
    if( OK != status)
    {
        goto exit;
    }

    FIPS_TESTLOG(125, "FIPS_SelftestAlgos: exit: Calling FIPS_DumpStartupStatusData().");
    if (FIPS_TESTLOG_ENABLED)
        FIPS_DumpStartupStatusData();

exit:
    FIPS_LOG_END_SVC(FIPS_FORCE_SELFTESTS_SVC,0);
    return status;

}

/*--------------------------------------------------------------------------*/
/* This function is public for CMVP versions to be used for OPs testing...  */
/*--------------------------------------------------------------------------*/

static MSTATUS FIPS_InternalStartupSelftest(FIPS_InternalPowerupTestConfig* testConfig)
{
    MSTATUS status = OK;


    status = FIPS_fillInternalPowerupTestConfig(testConfig);
    if( OK != status)
    {
        goto exit;
    }

    status = FIPS_knownAnswerTests();
    if( OK != status)
    {
        goto exit;
    }

    FIPS_TESTLOG(126, "FIPS_InternalStartupSelftest: exit: Calling FIPS_DumpStartupStatusData().");
    if (FIPS_TESTLOG_ENABLED)
        FIPS_DumpStartupStatusData();

exit:
    return status;
}

/*------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
MOC_EXTERN MSTATUS
FIPS_StatusPersist(void)
{
    return FIPS_persistWriteStatus((FIPSStartupStatus *)&sCurrStatus);
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_StatusImport(void)
{
    MSTATUS status;
    FIPSStartupStatus pBuf;

    DIGI_MEMCPY((ubyte*)&pBuf, (ubyte*)&sCurrStatus, sizeof(FIPSStartupStatus));

    status = FIPS_persistReadStatus(&pBuf);
    if (OK != status)
        goto exit;

    DIGI_MEMCPY((ubyte*)&sCurrStatus, (ubyte*)&pBuf, sizeof(FIPSStartupStatus));

exit:
    return status;
}
#endif /* !defined(__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__) */

/*------------------------------------------------------------------*/

MOC_EXTERN byteBoolean FIPS_ModeEnabled(void)
{
    if ((sCurrStatus.globalFIPS_powerupStatus == OK) && (sCurrStatus.startupState == FIPS_SS_DONE))
    {
        FIPS_TESTLOG(127, "FIPS_ModeEnabled: returning TRUE.");
        return TRUE;
    } else {
        FIPS_TESTLOG(128, "FIPS_ModeEnabled: returning FALSE.");
        return FALSE;
    }
}


/*------------------------------------------------------------------*/

MOC_EXTERN byteBoolean FIPS_isPAASupport(void)
{
    byteBoolean mypaa = FALSE;
#if (defined(__ENABLE_DIGICERT_AES_NI__) || \
     defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
    intBoolean AESpaa = FALSE;

#if (defined(__DBG_VERBOSE_PAA__))
    FIPS_TESTLOG(129, "FIPS_isPAASupport: Called...");
#endif

    AESpaa = check_for_aes_instructions();
    if (AESpaa)
    {
        FIPS_TESTLOG(133, "FIPS_isPAASupport: check_for_aes_instructions: returned TRUE.");
        mypaa = TRUE;
        goto exit;
    }
    else
    {
        /* AESpaa is FALSE, is it forced? */
#if defined(__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__)
        if (is_force_disable_aes_instructions())
        {
            FIPS_TESTLOG(134, "FIPS_isPAASupport: (PAA Force Disabled) returning FALSE.");
        }
#else /* __ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__ */
        FIPS_TESTLOG(135, "FIPS_isPAASupport: returning FALSE.");
#endif /* __ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__ */

        mypaa = FALSE;
        goto exit;
    }
#else /* MOCANA_AES_NI supported by this CPU */
    FIPS_TESTLOG(136, "FIPS_isPAASupport: (NO AES-NI support): returning FALSE.");
    mypaa = FALSE;
#endif /* MOCANA_AES_NI supported by this CPU */

exit:
    return mypaa;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_disablePAASupport(void)
{
    MSTATUS status = ERR_UNSUPPORTED_OPERATION;

#if ( defined(__DBG_VERBOSE_PAA__) )
    FIPS_TESTLOG(137, "FIPS_disablePAASupport: Called...");
#endif

#if (defined(__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__) && \
	 defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__) )
    force_disable_aes_instructions();
    FIPS_TESTLOG(138, "FIPS_disablePAASupport: force_disable_aes_instructions called.");
    status = OK;
#endif

    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_resetPAASupport(void)
{
    MSTATUS status = ERR_UNSUPPORTED_OPERATION;

#if ( defined(__DBG_VERBOSE_PAA__) )
    FIPS_TESTLOG(139, "FIPS_resetPAASupport: Called...");
#endif

#if (defined(__ENABLE_DIGICERT_FIPS_FORCE_PAA_MODE__) && \
	 defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__) )
    reset_to_default_aes_instructions();
    FIPS_TESTLOG(149, "FIPS_resetPAASupport: reset_to_default_aes_instructions called.");
    status = OK;
#endif

    return status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_FIPS_LIB_CONSTRUCTOR__

#if defined(_MSC_VER)

#pragma section(".CRT$XCU",read)
#define CONSTRUCTOR2_(f,p) \
    static void f(void); \
    __declspec(allocate(".CRT$XCU")) void (*f##_)(void) = f; \
    __pragma(comment(linker,"/include:" p #f "_")) \
    static void f(void)
#ifdef _WIN64
    #define CONSTRUCTOR(f) CONSTRUCTOR2_(f,"")
#else
    #define CONSTRUCTOR(f) CONSTRUCTOR2_(f,"_")
#endif

#define DESTRUCTOR(f) \
    static void f(void); \
    static void f(void)

#else
#define CONSTRUCTOR(f) \
        static void f(void) __attribute__((constructor)); \
        static void f(void)

#define DESTRUCTOR(f) \
        static void f(void) __attribute__((destructor)); \
        static void f(void)
#endif


DESTRUCTOR(FIPS_destructor)
{
    FIPS_Finalize();
    FIPS_Zeroize();
    FIPS_TESTLOG(110, "FIPS Destructor Finished.");
}

CONSTRUCTOR(FIPS_constructor)
{
    /* Read from function */
    sDebugPrintFunction = FIPS_getDebugPrintImplementation();

    if (sDebugPrintFunction)
	FIPS_registerDebugPrint(sDebugPrintFunction);

    FIPS_TESTLOG(101, "FIPS Constructor called.");
    FIPS_InitializeBeforeIntegrityChk();
#ifndef __DISABLE_DIGICERT_FIPS_CONSTRUCTOR_SELFTEST__
    FIPS_powerupSelfTest();
#endif
    FIPS_InitializeAfterIntegrityChk();

    FIPS_TESTLOG(108, "FIPS Constructor Finished.");

#if defined(_MSC_VER)
    atexit(FIPS_destructor);
#endif

}

#endif /* __ENABLE_DIGICERT_FIPS_LIB_CONSTRUCTOR__ */

MOC_EXTERN MSTATUS FIPS_locateFunction(const FIPS_entry_fct *table, int id, s_fct **ppOut)
{
    MSTATUS status = ERR_NOT_FOUND;
    int idx = 0;

    while (-1 != table[idx].ID)
    {
        if (id == table[idx].ID)
        {
            *ppOut = table[idx].fct;
            status = OK;
            break;
        }
        ++idx;
    }
    return status;
}

static FIPS_entry_fct fips_table[] = {
    { FIPS_RESET_STARTUP_FAIL_F_ID,         (s_fct*)FIPS_resetStartupFail},
    { FIPS_INTERNAL_STARTUP_SELFTEST_F_ID,  (s_fct*)FIPS_InternalStartupSelftest},
    { FIPS_INTERNAL_RESET_INITIAL_F_ID,     (s_fct*)FIPS_InternalResetInitialAlgoStatus},
    { FIPS_FILL_INTERNAL_POWERUP_F_ID,      (s_fct*)FIPS_fillInternalPowerupTestConfig },
    { -1, NULL } /* End of array */
};

MOC_EXTERN const FIPS_entry_fct* FIPS_getPrivileged()
{
    if (OK == FIPS_isTestMode())
	return fips_table;

    return NULL;
}

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

