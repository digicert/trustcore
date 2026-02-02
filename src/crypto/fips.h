/*
 * fips.h
 *
 * FIPS 140 Compliance
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
/**
@file       fips.h

@brief      Header file for the Nanocrypto FIPS specific functionality.
@details    Header file for the Nanocrypto FIPS specific functionality.
@flags      To enable functions in fips.{c,h}, the following flag must 
            be defined in the build environment or in moptions.h:
            + \c \__ENABLE_DIGICERT_FIPS_MODULE__ 

@filedoc    fips.h
*/

#ifndef __FIPS_HEADER__
#define __FIPS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


#if (defined(__ZEROIZE_TEST__))
#if (defined(__KERNEL__))
#include <linux/kernel.h>       /* for printk */
#define FIPS_PRINT              printk
#else
#include <stdio.h>              /* for printf */
#define FIPS_PRINT              printf
#endif
#endif /* (defined(__ZEROIZE_TEST__)) */


#ifdef __ENABLE_DIGICERT_FIPS_MODULE__

#include "../common/random.h"
#include "../common/mrtos.h"

/*-------------------------------------------------------------------*/
/* DIGICERT FIPS AlgoID numbers used to enable/disable FIPS algorithms */
/*-------------------------------------------------------------------*/

/**
@brief      FIPSAlgoNames is an enumeration of crypto algorithms used to enable or
            disable FIPS algorithms.

@details    This enum is use by the configuration functions, and in the EventLogging
            function.
            The macros FIRST_FIPS_ALGO and LAST_FIPS_ALGOs can be used to find the
            range of FIPS approved algorithms for loops. The macro
            NUM_FIPS_ALGONAME_VALUES can be used to size arrays.
*/
enum FIPSAlgoNames
{
    /*------------------------------------*/
    /* First entry is used to set/get     */
    /* overall startup status             */
    /* Externally ref'ed as FIPS_ALGO_ALL */
    /*------------------------------------*/
    FIPS_ALGO_ALL         = 0,
    /*------------------------------------*/
    /* This portion must be consecutive   */
    /* values, used as an array index     */
    /*------------------------------------*/
    FIPS_ALGO_DRBG_CTR    = 1,

    FIPS_ALGO_SHA1   = 2,
    FIPS_ALGO_SHA256 = 3,
    FIPS_ALGO_SHA512 = 4,

    FIPS_ALGO_SHA3_224 = 5,
    FIPS_ALGO_SHA3_256 = 6,
    FIPS_ALGO_SHA3_384 = 7,
    FIPS_ALGO_SHA3_512 = 8,

    FIPS_ALGO_SHA3_SHAKE128 = 9,
    FIPS_ALGO_SHA3_SHAKE256 = 10,

    FIPS_ALGO_HMAC = 11,

    FIPS_ALGO_AES      = 12,
    FIPS_ALGO_AES_ECB  = 13,
    FIPS_ALGO_AES_CBC  = 14,
    FIPS_ALGO_AES_CFB  = 15,
    FIPS_ALGO_AES_OFB  = 16,
    FIPS_ALGO_AES_CCM  = 17,
    FIPS_ALGO_AES_CTR  = 18,
    FIPS_ALGO_AES_CMAC = 19,
    FIPS_ALGO_AES_GCM  = 20,
    FIPS_ALGO_AES_XTS  = 21,

    FIPS_ALGO_3DES = 22,

    FIPS_ALGO_RSA    = 23,
    FIPS_ALGO_DSA    = 24,

    FIPS_ALGO_ECC    = 25,
    FIPS_ALGO_ECDSA  = 26,

    FIPS_ALGO_ECDH   = 27,
    FIPS_ALGO_DH     = 28,

    FIPS_ALGO_HMAC_KDF = 29,

    FIPS_ALGO_EDDSA  = 30,

    /*------------------------------------*/
    /* EDDH is not yet an approved algo   */
    /* but we are treating it as if       */
    /* it is already approved. (Doing KAT */
    /* and calling GET_FIPS_STATUS...     */
    /*------------------------------------*/
    FIPS_ALGO_EDDH   = 31,

    /*------------------------------------*/
    /* PQC algorithms                     */
    /*------------------------------------*/
    FIPS_ALGO_MLKEM  = 32,
    FIPS_ALGO_MLDSA  = 33,
    FIPS_ALGO_SLHDSA = 34,

    /*------------------------------------*/
    /* Used to range check and size arrays*/
    /*------------------------------------*/
    FIPS_APPROVED_ALGO_END = 35,

    /*------------------------------------*/
    /* Used to log events for other algos */
    /* and components                     */
    /*------------------------------------*/
    /* This portion is not used as array  */
    /* index and may be non-consecutive   */
    /*------------------------------------*/
    /*------------------------------------*/
    NON_FIPS_ALGO_RNG_FIPS186 = 50,

    NON_FIPS_ALGO_MD2     = 51,
    NON_FIPS_ALGO_MD4     = 52,
    NON_FIPS_ALGO_MD5     = 53,

    NON_FIPS_ALGO_AES_EAX = 54,
    NON_FIPS_ALGO_AES_XCBC = 55,

    NON_FIPS_ALGO_HMAC_MD5 = 56,
    FIPS_ALGO_HMAC_SHA1 = 57,

    FIPS_ALGO_RSA_OAEP = 58,
    FIPS_ALGO_RSA_PSS = 59,

    FIPS_ZEROIZE_SVC     = 70,
    FIPS_FORCE_SELFTESTS_SVC     = 71,
    FIPS_FORCE_INTEGTEST_SVC     = 72

};

/* FIPS_ALGO_ALL (0) is referenced in ssl.c & apps to get full startup status */

#define FIRST_FIPS_ALGO (FIPS_ALGO_ALL+1)
#define LAST_FIPS_ALGO ((FIPS_APPROVED_ALGO_END-1))

#define NUM_FIPS_ALGONAME_VALUES ((FIPS_APPROVED_ALGO_END+1))

#define FIRST_FIPS_SVC (FIPS_ZEROIZE_SVC)
#define LAST_FIPS_SVC ((FIPS_FORCE_INTEGTEST_SVC))

/**
@brief      FIPS_EventTypes is an enumeration of FIPS event types (typically the 
            beginning and ending of the invocation of a FIPS approved or 
            non-approved FIPS algorithm or service invocations. 

@details    This enum is passed to the application's EventLogging function.
*/
enum FIPS_EventTypes
{
    FIPS_ApprovedAlgoNone = 0,
    FIPS_ApprovedServiceStart,
    FIPS_ApprovedServiceEnd,
    FIPS_ApprovedAlgoStart,
    FIPS_ApprovedAlgoEnd,
    FIPS_UnapprovedServiceStart,
    FIPS_UnapprovedServiceEnd,
    FIPS_UnapprovedAlgoStart,
    FIPS_UnapprovedAlgoEnd
};

/**
@brief   Typedef of the application callback function to log or process FIPS events.

@details This callback function will be called at the start and end of FIPS 
         algorithms and services.

@param eventType  The type of FIPS event occurring.
@param algoId     The FIPS algorithm executing.
@param eventLogId This is an integer ID that increments with each up-call to the callback function.
@param sessionId  This is an integer ID that increments with each up-call to the callback function 
                  at the "Start" of a FIPS service or algorithm. 

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
typedef MSTATUS (*FIPS_eventLog)(const enum FIPS_EventTypes eventType,
    const enum FIPSAlgoNames algoId, ubyte4 eventLogId, ubyte4 sessionId);

/**
@brief   Typedef of the application callback function to log debug lines.

@param   logId  The numerical id for the log;

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
typedef MSTATUS (*FIPS_debugPrint)(ubyte4 logId, ...);

typedef struct FIPSRuntimeConfig
{
    enum FIPSAlgoNames randomDefaultAlgo;			/* Must be FIPS_ALGO_DRBG_CTR */
    intBoolean         useInternalEntropy;
    intBoolean	       algoEnabled[NUM_FIPS_ALGONAME_VALUES];
    char               *libPath;
    char               *sigPath;
    ubyte4             fipsMutexCnt;
    RTOS_MUTEX         fipsMutexLock;
    FIPS_eventLog      fipsEventLog;
    ubyte4             fipsEventLogId;
    ubyte8             fipsEventSessionId;
    ubyte4             fipsEventDepthLimit;
    ubyte4             fipsEventMaxThreads;
    ubyte4             *fipsEventDepth;
    RTOS_THREAD        *fipsEventTID;
    FIPS_debugPrint    fipsDebugPrint;
} FIPSRuntimeConfig;

/**
 * FIPS debug log macros
 */
#define FIPS_TESTLOG_IMPORT   MOC_EXTERN FIPSRuntimeConfig sCurrRuntimeConfig;

#define FIPS_TESTLOG(ID, VAL) { if(sCurrRuntimeConfig.fipsDebugPrint) \
	    (*sCurrRuntimeConfig.fipsDebugPrint)(ID,NULL); }

#define FIPS_TESTLOG_FMT(ID, FMT, ...) { if(sCurrRuntimeConfig.fipsDebugPrint) \
	    (*sCurrRuntimeConfig.fipsDebugPrint)(ID,__VA_ARGS__); }

#define FIPS_TESTLOG_ENABLED (sCurrRuntimeConfig.fipsDebugPrint)

/** 
@brief      FIPS_TestActions is an enumeration to control FIPS CAST timing 
            and to read the results of the CAST timing.
 
@detail     Enum values: 
            FIPS_AUTO is the default value and will execute the CAST function just-in-time.
            FIPS_FORCE will execute the CAST function immediately within a call to FIPS_SelftestAlgos().
            FIPS_SKIP not force the CAST function call, but will remain just-in-time.
*/
enum FIPS_TestActions
{
    FIPS_AUTO = 0,
    FIPS_FORCE,
    FIPS_SKIP
};

/** 
@brief      aliases for FTIPS_TestActions that make more sense when reading the values.
 
@detail     Enum values: 
            FIPS_INCOMPLETE  == FIPS_AUTO means that the CAST test for this algo has not run.
            FIPS_COMPLETE    == FIPS_SKIP means nothing to do for this CAST test. (already run).
            FIPS_SKIP not force the CAST function call, but will remain just-in-time.
*/
#define FIPS_INCOMPLETE FIPS_AUTO   /* Alias that makes sense when reading current FIPS_TestActions with FIPS_getSelftestAlgosState()*/
#define FIPS_COMPLETE   FIPS_SKIP   /* Alias that makes sense when reading... */
                                    /* NOTE: FIPS_SKIP means nothing to do. This makes sense writing and reading test actions */

typedef struct FIPS_TestSetup
{
    enum FIPS_TestActions  action;
} FIPS_TestSetup;

typedef struct FIPS_AlgoTestConfig
{
    FIPS_TestSetup test[NUM_FIPS_ALGONAME_VALUES];
} FIPS_AlgoTestConfig;

/*===============================================================*/

/**
@brief   Function to register the application EventLog callback function.

@details This function will register an application level function to be called for
         FIPS related events.

@param eventLog Typedef defined with the signature of the EventLog callback function.

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_registerEventLog(FIPS_eventLog eventLog);

/**
@brief   Function to de-register the application EventLog callback function.

@details This function causes the application level function to no longer be called for
         FIPS related events.

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_unregisterEventLog(void);

/*===============================================================*/

/**
@brief   Function to register the application debug log callback function.

@details This function will register an application level function to be called for
         FIPS debug logs.

@param   debugPrint Typedef defined with the signature of the debug print callback function.

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_registerDebugPrint(FIPS_debugPrint debugPrint);

/*===============================================================*/

/**
@brief   Function to set the "test mode" flag to allow for privileged API calls

@details This function accepts a "token", represented by a byte array, that is
         checked against a "challenge" value. If the challenge passes, the "test mode"
	 flag is permanently set. This function will return the status of the
	 challenge as OK or with an error code.

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_setTestMode(ubyte *pToken, ubyte4 tokenLen);

/**
@brief   Function to read the "test mode" flag that allows for privileged API calls

@details This function reads the "test mode" flag and returns it.

@return  \c OK (0) if in "test mode", otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_isTestMode(void);

/*===============================================================*/

/**
@brief   Function to set the EventLog depth limit.

@details This function will set the limit applied to the FIPS related event log. It
         restricts the "depth" of the function call relative to the initial call to
         a FIPS function.

@param limit  Integer value. 0  = No limit is applied;
                             >0 = Only log the events from calls at that "level" or
                                  earlier. For example, '1' would allow logs only from
                                  the initial call and not from subsequently called
                                  FIPS functions.

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_setEventLogDepthLimit(ubyte4 limit);

/**
@brief   Function to sets the maximum number of parallel threads the event log will handle;

@details This function will set the resources needed to manage FIPS related event log issued
         by threads. It is set by the user (once) and it represents the maximum number of
         threads that can run at the same time.

@param max  Integer value that is > 0.

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_setEventLogMaxThreads(ubyte4 max);

/*===============================================================*/

/**
@brief   Function to get status of a specific FIPS algorithm.

@details This function will return the overall FIPS power-up self-tests
         status, or the self-test status for a specific algorithm.

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS getFIPS_powerupStatus(int fips_algoid);

/**
@brief   Function to return TRUE/FALSE flag indicating if FIPS_MODE is enabled.

@details This function will return TRUE if required CAST self-tests
         ran successfully. It will return FALSE if any fail.

@return  \c TRUE (0) if tests were successful, FALSE otherwise.
*/
MOC_EXTERN byteBoolean FIPS_ModeEnabled(void);

/**
@brief   Function to return file paths for noteworthy FIPS relates files.

@details This function will return shared library path, the FIPS library 
         signature path (if signature is separate), and the FIPS status
         persistent path if supported by the platform.

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_getFileLocations(sbyte** ppSharedLibPath,
    sbyte** ppSigPath, sbyte** ppPersistStatusPath);

/*===============================================================*/

/**
@brief   Function to return an array of power-up self-test status.

@details This function typically only used in testing, but could
         be used to status and control when CAST tests run.

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_getSelftestAlgosState(FIPS_AlgoTestConfig* testConfig);

/**
@brief   Function to specifically run power-up CAST self-tests.

@details This function can be used to force the immediate execution of a 
         set of algorithms. This would be done to avoid delayed just-in-time 
         CAST test executions on the first use of an algorithm. 

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_SelftestAlgos(FIPS_AlgoTestConfig* testConfig);

/**
@dont_show
@internal

Doc Note: This function is for Mocana internal code use only, and
should not be included in the API documentation.
*/
MOC_EXTERN MSTATUS FIPS_SelftestIntegrity(void);

/**
@brief   Function to specifically force a zeroize of the shared FIPS 
         security parameters that the FIPS library controls. 

@details This function can be used to force the immediate zeroization
         the shared FIPS security parameters that the FIPS library controls. 
         Note: This is the global random number context and entropy depot.

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_Zeroize(void);

/**
@brief   Function to cause the FIPS library to save the current
         FIPS CAST self-test results. 

@details This function will cause the FIPS library to save the current 
         FIPS CAST self-test results. This is typically done in a single 
         application per O/S boot cycle that will have also forced the 
         self-tests to have run. This will allow future processes to bypass
         the CAST tests. 

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_StatusPersist(void);

/*===============================================================*/

/**
@brief   Function to return TRUE/FAlSE if the CPU platform supports
         PAA.

@details Function to return TRUE/FAlSE if the CPU platform supports
         PAA (specific cryptographic acceleration instructions).
         E.g. Intel AES instructions.

@return  \c TRUE if the platform supports PAA, otherwise FALSE.
*/
MOC_EXTERN byteBoolean FIPS_isPAASupport(void);

/**
@brief   Function to forcibly disable PAA instruction usage.

@details This function will forcibly disable PAA instruction usage for
         platforms that would otherwise use these PAA instructions
         for some cryptographic functions. This will result in slower
         S/W only implementations on those functions, and thus will 
         only be used during testing. 

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_disablePAASupport(void);

/**
@brief   Function to reset PAA usage to the default value.

@details This function will reset PAA usage to the default value.
         If the platform does not support PAA, then nothing is to be done.
         If the platform does support PAA, then it will be reenabled 
         if previously disabled. 

@return  \c OK (0) if successful, otherwise a negative number error
         code from merrors.h
*/
MOC_EXTERN MSTATUS FIPS_resetPAASupport(void);

/*===============================================================*/

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

#ifdef __cplusplus
}
#endif

#endif /* __FIPS_HEADER__ */
