/*
 * fips_status.c
 *
 * FIPS 140-3 Self Test Status Persistency Tools
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
#include "../common/debug_console.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#if (defined(__ENABLE_DIGICERT_ECC__))
/* Definitions of ECC curves. */
#include "../crypto/ca_mgmt.h"
#include "../crypto/ecc_edwards_keys.h"
#endif

#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
#include "../crypto/dh.h"
#endif

#if defined(__RTOS_LINUX__) || defined(__RTOS_ANDROID__)
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
/* Use '/proc/uptime' to obtain limit on timetstamp in PERSIST file */ 
#include <stdio.h>
#include <time.h>
#define __DIGICERT_PERSIST_USE_PROC_UPTIME__
/* Use file IO to PERSIST data */
#define __DIGICERT_PERSIST_USE_FILE__
#ifndef __DIGICERT_PERSIST_FILEPATH__
#define __DIGICERT_PERSIST_FILEPATH__ "/tmp/mssp"
#endif
#else
#include <linux/string.h>
#include <linux/slab.h>
#endif /* __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__ */
#endif /* defined(__RTOS_LINUX__) || defined(__RTOS_ANDROID__) */

/* The FIPS status data fields */
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"

#if (defined(__KERNEL__))
#include <linux/kernel.h>       /* for printk */
#define DBG_PRINT              printk
#else
#include <stdio.h>              /* for printf */
#define DBG_PRINT              printf
#endif

#define MOC_UPTIME_BUFSIZE 128

/* Default test log is OFF/NULL */
FIPS_debugPrint sDebugPrintFunction = NULL;

MOC_EXTERN FIPSRuntimeConfig sCurrRuntimeConfig; /* What are we configured to run */

/*---------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_registerEventLog(FIPS_eventLog eventLog)
{
    MSTATUS status = OK;

    if(NULL == eventLog)
    {
        return ERR_NULL_POINTER;
    }

    sCurrRuntimeConfig.fipsEventLog = eventLog;
    sCurrRuntimeConfig.fipsEventLogId = 0;

    return status;
}

/*---------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_unregisterEventLog(void)
{
    MSTATUS status = OK;

    sCurrRuntimeConfig.fipsEventLog = NULL;
    sCurrRuntimeConfig.fipsEventLogId = 0;

    return status;
}

MOC_EXTERN MSTATUS FIPS_registerDebugPrint(FIPS_debugPrint debugPrint)
{
    MSTATUS status = OK;

    if(NULL == debugPrint)
    {
        return ERR_NULL_POINTER;
    }

    sCurrRuntimeConfig.fipsDebugPrint = debugPrint;

    return status;
}

#ifdef __ENABLE_DIGICERT_FIPS_EVENT_LOG_DEPTH__
MOC_EXTERN MSTATUS FIPS_setEventLogMaxThreads(ubyte4 max)
{
    MSTATUS status = ERR_UNSUPPORTED_SIZE;

    if (max == 0)
        goto exit;

    if (sCurrRuntimeConfig.fipsEventMaxThreads == 0)
    {
        sCurrRuntimeConfig.fipsEventMaxThreads = max;

        /* Allocate what is needed */
        status = DIGI_CALLOC((void**)&sCurrRuntimeConfig.fipsEventDepth, max, sizeof(ubyte4));
        if (OK != status)
            goto exit;

        /* For 'max' == 1, the logger will not check this arrays */
        if (max > 1)
        {
            status = DIGI_CALLOC((void**)&sCurrRuntimeConfig.fipsEventTID, max, sizeof(RTOS_THREAD));
            if (OK != status)
                goto exit;
        }
    }
    else
        status = ERR_PREVIOUSLY_EXISTING_ITEM;

exit:
    return status;
}

MOC_EXTERN MSTATUS FIPS_setEventLogDepthLimit(ubyte4 limit)
{
    MSTATUS status = OK;

    if ((limit > 0) && (sCurrRuntimeConfig.fipsEventMaxThreads == 0))
    {
        /* Not set by user. Use default 1 */
        status = FIPS_setEventLogMaxThreads(1);
    }
    sCurrRuntimeConfig.fipsEventDepthLimit = limit;

    return status;
}
#endif /* __ENABLE_DIGICERT_FIPS_EVENT_LOG_DEPTH__ */

/*---------------------------------------------------------*/

static enum FIPS_EventTypes getProperEventType(const enum FIPS_EventTypes currEvent, const enum FIPSAlgoNames algoId,
                                               ubyte4 keySize)
{
    enum FIPS_EventTypes newEvent = currEvent;
    intBoolean isApproved = FALSE;

    /* This code must be kept in sync with the enum FIPS_EventTypes */

    /* Set isApproved based on AlgoID. */
    if ( (algoId > FIPS_ALGO_ALL) &&  (algoId < FIPS_APPROVED_ALGO_END) )
    {
        isApproved = TRUE;
    }

    /* Handle algos outside of our original list of good FIPS algos in the enum. */
    if ( (algoId == FIPS_ALGO_HMAC_SHA1) ||
         (algoId == FIPS_ALGO_RSA_PSS) )
    {
        isApproved = TRUE;
    }

    /* Handle algos that have fallen out of NIST/FIPS favor */
    if ( (algoId == FIPS_ALGO_3DES) ||
         (algoId == FIPS_ALGO_EDDH) )
    {
        isApproved = FALSE;
    }

    /* Handle svc algos that have been added as FIPS approved */
    if ( (algoId == FIPS_ZEROIZE_SVC) ||
         (algoId == FIPS_FORCE_SELFTESTS_SVC) ||
		 (algoId == FIPS_FORCE_INTEGTEST_SVC) )
    {
        isApproved = TRUE;
    }

    /* Poss un-approve based on Key-Sizes & Curves */
    if ( (isApproved == TRUE) && (keySize != 0) )
    {
        switch (algoId)
        {
            case FIPS_ALGO_AES      :
            case FIPS_ALGO_AES_ECB  :
            case FIPS_ALGO_AES_CBC  :
            case FIPS_ALGO_AES_CFB  :
            case FIPS_ALGO_AES_OFB  :
            case FIPS_ALGO_AES_CCM  :
            case FIPS_ALGO_AES_CTR  :
            case FIPS_ALGO_AES_CMAC :
            case FIPS_ALGO_AES_GCM  :
            case FIPS_ALGO_AES_XTS  :
            {
                switch (keySize) /* in bytes */
                {
                    case 16:
                    case 24:
                    case 32:
                        isApproved = TRUE;
                        break;
                    default:
                        isApproved = FALSE;
                        break;
                }
                break;
            }
            case FIPS_ALGO_RSA:
            {
                switch (keySize) /* in bits */
                {
                    case 2048:
                    case 3072:
                    case 4096:
                    case 8192:
                        isApproved = TRUE;
                        break;
                    default:
                        isApproved = FALSE;
                        break;
                }
                break;
            }
            case FIPS_ALGO_DSA:
            {
                switch (keySize) /* in bits */
                {
                    case 2048:
                    case 3072:
                        isApproved = TRUE;
                        break;
                    default:
                        isApproved = FALSE;
                        break;
                }
                break;
            }
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
            case FIPS_ALGO_DH:
            {
                switch (keySize) /* Groupnum */
                {
                    case DH_GROUP_14:
                    case DH_GROUP_FFDHE2048:
                    case DH_GROUP_15:
                    case DH_GROUP_FFDHE3072:
                    case DH_GROUP_16:
                    case DH_GROUP_FFDHE4096:
                    case DH_GROUP_17:
                    case DH_GROUP_FFDHE6144:
                    case DH_GROUP_18:
                    case DH_GROUP_FFDHE8192:
                        isApproved = TRUE;
                        break;
                    default:
                        isApproved = FALSE;
                        break;
                }
                break;
            }
#endif /* (DH) __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__ */
#ifdef __ENABLE_DIGICERT_ECC__
            case FIPS_ALGO_ECC:
            case FIPS_ALGO_ECDSA:
            case FIPS_ALGO_ECDH:
            {
                switch (keySize)
                {
                    case cid_EC_P256:
                    case cid_EC_P224:
                    case cid_EC_P384:
                    case cid_EC_P521:
                        isApproved = TRUE;
                        break;
                    default:
                        isApproved = FALSE;
                        break;
                }
                break;
            }
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
            case FIPS_ALGO_EDDSA:
            {
                switch (keySize)
                {
                    case curveEd25519:
                    case curveEd448:
                    case cid_EC_Ed25519:
                    case cid_EC_Ed448:
                    case curveX25519:
                    case curveX448:
                    case cid_EC_X25519:
                    case cid_EC_X448:
                        isApproved = TRUE;
                        break;
                    default:
                        isApproved = FALSE;
                        break;
                }
                break;
            }
#endif /* __ENABLE_DIGICERT_ECC_ED_COMMON__ */
#endif /* __ENABLE_DIGICERT_ECC__ */

#ifdef __ENABLE_DIGICERT_PQC__
	        case FIPS_ALGO_MLKEM:
	        case FIPS_ALGO_MLDSA:
	        case FIPS_ALGO_SLHDSA:
		        isApproved = TRUE;
		        break;
#endif /* __ENABLE_DIGICERT_PQC__ */

            default:
                break;
        } /* end switch AlgoId */

    } /* end if isApproved && non-zero keySize/curve */

    /* Change EventType if required */
    newEvent = currEvent;
    switch (currEvent)
    {
        case FIPS_ApprovedAlgoNone:
            break;
        case FIPS_ApprovedServiceStart:
            if (isApproved == FALSE) newEvent = FIPS_UnapprovedServiceStart;
            break;
        case FIPS_ApprovedServiceEnd:
            if (isApproved == FALSE) newEvent = FIPS_UnapprovedServiceEnd;
            break;
        case FIPS_ApprovedAlgoStart:
            if (isApproved == FALSE) newEvent = FIPS_UnapprovedAlgoStart;
            break;
        case FIPS_ApprovedAlgoEnd:
            if (isApproved == FALSE) newEvent = FIPS_UnapprovedAlgoEnd;
            break;

        case FIPS_UnapprovedServiceStart:
            if (isApproved == TRUE) newEvent = FIPS_ApprovedServiceStart;
            break;
        case FIPS_UnapprovedServiceEnd:
            if (isApproved == TRUE) newEvent = FIPS_ApprovedServiceEnd;
            break;
        case FIPS_UnapprovedAlgoStart:
            if (isApproved == TRUE) newEvent = FIPS_ApprovedAlgoStart;
            break;
        case FIPS_UnapprovedAlgoEnd:
            if (isApproved == TRUE) newEvent = FIPS_ApprovedAlgoEnd;
            break;

        default:
            newEvent = FIPS_ApprovedAlgoNone;
            break;
    } /* end switch (currEvent) */

    /*-------------------------*/
    /* Change event from Algo  */
    /* to Svc if needed.       */
    /*-------------------------*/
    if ((algoId >= FIRST_FIPS_SVC) && (algoId <= LAST_FIPS_SVC))
    {
        switch (newEvent)
        {
            case FIPS_ApprovedAlgoStart:
                newEvent = FIPS_ApprovedServiceStart;
                break;
            case FIPS_ApprovedAlgoEnd:
                newEvent = FIPS_ApprovedServiceEnd;
                break;
            /* Unreachable cases since isApproved will be TRUE with algoId in the SVC range.
            case FIPS_UnapprovedAlgoStart:
                newEvent = FIPS_UnapprovedServiceStart;
                break;
            case FIPS_UnapprovedAlgoEnd:
                newEvent = FIPS_UnapprovedServiceEnd;
                break;
            */
            default:
                break;
        } /* end switch (newEvent) */
    }

#ifdef __VERBOSE_CURVE_ALGOID_CHANGES__
    if ((FIPS_TESTLOG_ENABLED) && (keySize != 0))
    {
        FIPS_TESTLOG_FMT(600, "FIPS_logAlgoEvent OK  EventType: %02d : AlgoId: %02d : KeySize/Curve: %02d",
                         newEvent, algoId, keySize);
    }
#endif /*__VERBOSE_CURVE_ALGOID_CHANGES__ */

    return newEvent;
}

/*---------------------------------------------------------*/

static unsigned long FIPS_selectDepthEntry(RTOS_THREAD* array, size_t len, RTOS_THREAD id, byteBoolean make_new)
{
    unsigned long idx;
    unsigned long empty = len;

    for (idx = 0; idx < len; ++idx)
    {
        /* Id match */
        if (id == array[idx])
            return idx;

        if (empty == len)
        {
            if (0 == array[idx])
                empty = idx;
        }
    }

    /* No ID matched */
    if (make_new && (empty < len))
    {
        /* found open space */
        array[empty] = id;
        return empty;
    }

    /* Not found or no space! */
    return len;
}

#define MAX_UBYTE8_VALUE    (2147483647)    /* 2,147,483,647 */

MOC_EXTERN void FIPS_logAlgoEvent(enum FIPS_EventTypes eventType,
                                  const enum FIPSAlgoNames algoId, ubyte4* eventSessionId,
                                  ubyte4 keySize)
{

    enum FIPS_EventTypes newEvent = eventType;
#ifdef __ENABLE_DIGICERT_FIPS_EVENT_LOG_DEPTH__
    intBoolean           logEvent = TRUE;
#endif

    /* Determine if client has registered a callback function to report
     *  the status. Yes- log event, No- skip logging. */
    if (NULL == sCurrRuntimeConfig.fipsEventLog)
    {
        return;
    }
    else
    {
        sCurrRuntimeConfig.fipsEventLogId++;
        /* Start event has been logged. */
        if(FIPS_ApprovedServiceStart == eventType ||
                FIPS_ApprovedAlgoStart == eventType ||
                FIPS_UnapprovedServiceStart == eventType ||
                FIPS_UnapprovedAlgoStart == eventType)
        {
            /* Session Id is saved on stack. */
            *eventSessionId = sCurrRuntimeConfig.fipsEventSessionId;
            ++sCurrRuntimeConfig.fipsEventSessionId;

#ifdef __ENABLE_DIGICERT_FIPS_EVENT_LOG_DEPTH__
            /* Enforce log limit? */
            if (sCurrRuntimeConfig.fipsEventDepthLimit != 0)
            {
                unsigned long idx_t = 0l;

                /* More than one thread expected? */
                if (sCurrRuntimeConfig.fipsEventMaxThreads > 1)
                {
                    RTOS_mutexWait(sCurrRuntimeConfig.fipsMutexLock);

                    RTOS_THREAD myT = RTOS_currentThreadId();
                    idx_t = FIPS_selectDepthEntry(sCurrRuntimeConfig.fipsEventTID,
                                                  sCurrRuntimeConfig.fipsEventMaxThreads,
                                                  myT, TRUE);
                }

                if (idx_t < sCurrRuntimeConfig.fipsEventMaxThreads)
                {
                    sCurrRuntimeConfig.fipsEventDepth[idx_t]++;
                    if (sCurrRuntimeConfig.fipsEventDepthLimit < sCurrRuntimeConfig.fipsEventDepth[idx_t])
                        logEvent = FALSE;
                }

                if (sCurrRuntimeConfig.fipsEventMaxThreads > 1)
                {
                    RTOS_mutexRelease(sCurrRuntimeConfig.fipsMutexLock);
                }
            }
#endif /* __ENABLE_DIGICERT_FIPS_EVENT_LOG_DEPTH__ */
        }
#ifdef __ENABLE_DIGICERT_FIPS_EVENT_LOG_DEPTH__
        /* End event has been logged. */
        else if(FIPS_ApprovedServiceEnd == eventType ||
                FIPS_ApprovedAlgoEnd == eventType ||
                FIPS_UnapprovedServiceEnd == eventType ||
                FIPS_UnapprovedAlgoEnd == eventType)
        {
            /* Enforce log limit? */
            if (sCurrRuntimeConfig.fipsEventDepthLimit != 0)
            {
                unsigned long idx_t = 0l;

                /* More than one thread expected? */
                if (sCurrRuntimeConfig.fipsEventMaxThreads > 1)
                {
                    RTOS_mutexWait(sCurrRuntimeConfig.fipsMutexLock);

                    RTOS_THREAD myT = RTOS_currentThreadId();
                    idx_t = FIPS_selectDepthEntry(sCurrRuntimeConfig.fipsEventTID,
                                                  sCurrRuntimeConfig.fipsEventMaxThreads,
                                                  myT, FALSE);
                }

                if (idx_t < sCurrRuntimeConfig.fipsEventMaxThreads)
                {
                    if (sCurrRuntimeConfig.fipsEventDepthLimit < sCurrRuntimeConfig.fipsEventDepth[idx_t])
                        logEvent = FALSE;

                    if (sCurrRuntimeConfig.fipsEventDepth[idx_t] > 0)
                        sCurrRuntimeConfig.fipsEventDepth[idx_t]--;
                }

                if (sCurrRuntimeConfig.fipsEventMaxThreads > 1)
                {
                    /* clear at end */
                    if (sCurrRuntimeConfig.fipsEventDepth[idx_t] == 0)
                    {
                        sCurrRuntimeConfig.fipsEventTID[idx_t] = 0;
                    }
                    RTOS_mutexRelease(sCurrRuntimeConfig.fipsMutexLock);
                }
            }
        }
#endif /* __ENABLE_DIGICERT_FIPS_EVENT_LOG_DEPTH__ */

#ifdef __ENABLE_DIGICERT_FIPS_EVENT_LOG_DEPTH__
        if (logEvent)
#endif /* __ENABLE_DIGICERT_FIPS_EVENT_LOG_DEPTH__ */
        {
            /* Poss fix EventType based on AlgoID, KeySize, and CurveID. */
            newEvent = getProperEventType(eventType, algoId, keySize);

            /* Send log data to callback function. */
            (sCurrRuntimeConfig.fipsEventLog)(newEvent,
                                              algoId, sCurrRuntimeConfig.fipsEventLogId, *eventSessionId);
        }
    }
}

/*---------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
#ifdef __DIGICERT_PERSIST_USE_PROC_UPTIME__
static void FIPS_getProcUptime(double* time)
{
   char buf[MOC_UPTIME_BUFSIZE];
   FILE *fp;
   double upsecs;
   double uptime = -1;

   fp = fopen ("/proc/uptime", "r");
   if (fp != NULL)
   {
      char *b = fgets (buf, MOC_UPTIME_BUFSIZE, fp);
      if (b == buf)
      {
         char *end_ptr;
         upsecs = strtod (buf, &end_ptr);
         if (buf != end_ptr)
         {
            uptime = (0 <= upsecs ? upsecs : -1);
         }
     }

     fclose (fp);
   }

   *time = uptime;
}
#endif /* __DIGICERT_PERSIST_USE_PROC_UPTIME__ */

/*---------------------------------------------------------*/

static MSTATUS FIPS_bootStamp(ubyte4 *pStamp)
{
   MSTATUS status = OK;
#ifdef __DIGICERT_PERSIST_USE_PROC_UPTIME__
   double deltaD = 0.0;
   time_t nowTime = 0;

   nowTime = time(NULL);
   
   FIPS_getProcUptime(&deltaD);
   if (0.0 > deltaD)
   {
      status = ERR_RTOS;
      goto exit;
   }

   *pStamp = (ubyte4)nowTime - (ubyte4)deltaD;
   
exit:
#endif /* __DIGICERT_PERSIST_USE_PROC_UPTIME__ */

   return status;
}

/*---------------------------------------------------------*/

static MSTATUS FIPS_bootStampCompare(ubyte4 expected, ubyte4 actual)
{
   MSTATUS status = ERR_UNSUPPORTED_OPERATION;

#ifdef __DIGICERT_PERSIST_USE_PROC_UPTIME__
   if (expected > actual)
   {
      if (expected - actual > 2)
      {
         FIPS_TESTLOG(601, "FIPS_bootStampCompare: (a) TS not matching.");
         status = ERR_FALSE;
         goto exit;
      }
   }
   else if (expected < actual)
   {
      if (actual - expected > 2)
      {
         FIPS_TESTLOG(602, "FIPS_bootStampCompare: (b) TS not matching.");
         status = ERR_FALSE;
         goto exit;
      }
   }
   status = OK;
#endif /* __DIGICERT_PERSIST_USE_PROC_UPTIME__ */

exit:
   return status;
}

/*---------------------------------------------------------*/

static sbyte FIPS_Oct2Hex(ubyte x)
{
   return (x>9)?('A'+x-10):('0'+x);
}

static ubyte FIPS_Hex2Oct(sbyte x)
{
   return (x>'9')?(10+x-'A'):(x-'0');
}

/*---------------------------------------------------------*/

static MSTATUS FIPS_createPersistData(FIPSStartupStatus *pStatus, sbyte *pBuf, ubyte4 bufSize)
{
   MSTATUS status = OK;
   ubyte4  val = 0;
   ubyte4  szeBin;
   MSTATUS s[NUM_FIPS_ALGONAME_VALUES];
   int     i = 0;
   ubyte   *pBinary = NULL;

   /* Size check */
   szeBin = sizeof(val) + sizeof(MSTATUS)*NUM_FIPS_ALGONAME_VALUES + sizeof(pStatus->fingerPrint);
   if (szeBin*2 + 1 > bufSize)
   {
      status = ERR_BUFFER_OVERFLOW;
      goto exit;
   }
   
   /* Clear */
   DIGI_MEMSET((ubyte*)pBuf, 0, bufSize);
   DIGI_MEMSET((ubyte*)s, 0xEE, sizeof(MSTATUS)*NUM_FIPS_ALGONAME_VALUES);

   /* Get boot stamp */
   status = FIPS_bootStamp(&val);
   if (OK != status)
      goto exit;

   /* Get status flags */
   for (i = FIRST_FIPS_ALGO; i <= LAST_FIPS_ALGO; i++)
   {
      s[i] = pStatus->algoStatus[i];
   }

   /* Create binary data */
   status = DIGI_MALLOC((void**)&pBinary, szeBin);
   if (OK != status)
      goto exit;

   pBinary[0] = 0xFF & (val >> 24);
   pBinary[1] = 0xFF & (val >> 16);
   pBinary[2] = 0xFF & (val >> 8);
   pBinary[3] = 0xFF & (val);

   /* Also copy in the 0'th entry 0xEE */
   for (i = 0; i <= LAST_FIPS_ALGO; i++)
   {
      MSTATUS* pDat = (MSTATUS*)(pBinary + 4 + (sizeof(MSTATUS)*i));
      *pDat = s[i];
   }
   DIGI_MEMCPY(pBinary + (sizeof(val) + sizeof(MSTATUS)*NUM_FIPS_ALGONAME_VALUES) , pStatus->fingerPrint, sizeof(pStatus->fingerPrint));
   
   /* Convert to HEX ASCII */
   for (i = 0; i < szeBin; ++i)
   {
      pBuf[2*i]   = FIPS_Oct2Hex(0xF & (pBinary[i] >> 4));
      pBuf[2*i+1] = FIPS_Oct2Hex(0xF & pBinary[i]);
   }

exit:
   if (NULL != pBinary)
   {
     DIGI_FREE((void**)&pBinary);
   }
   return status;
}

/*---------------------------------------------------------*/

static MSTATUS FIPS_parsePersistData(const sbyte *pBuf, ubyte4 bufSize, FIPSStartupStatus *pStatus)
{
   MSTATUS status = OK;
   ubyte4  val = 0, valNow;
   ubyte4  szeBin;
   MSTATUS s[NUM_FIPS_ALGONAME_VALUES];
   int     i = 0;
   ubyte   *pBinary = NULL;
   sbyte4  cmpRes = -1;
 
   /* Size check */
   szeBin = sizeof(val) + sizeof(MSTATUS)*NUM_FIPS_ALGONAME_VALUES + sizeof(pStatus->fingerPrint);
   if (szeBin*2 != bufSize)
   {
      status = ERR_BAD_LENGTH;
      goto exit;
   }

   /* Create binary data */
   status = DIGI_MALLOC((void**)&pBinary, szeBin);
   if (OK != status)
      goto exit;

   /* Convert from HEX ASCII */
   for (i = 0; i < szeBin; ++i)
   {
      pBinary[i] = (FIPS_Hex2Oct(pBuf[2*i])) << 4;
      pBinary[i] += FIPS_Hex2Oct(pBuf[2*i+1]);
   }

   /* Get current boot stamp */
   status = FIPS_bootStamp(&valNow);
   if (OK != status)
      goto exit;

   /* Get data boot stamp */
   val = pBinary[3];
   val += pBinary[2]<<8;
   val += pBinary[1]<<16;
   val += pBinary[0]<<24;

   /* Validate stamp */
   status = FIPS_bootStampCompare(valNow, val);
   if (OK != status)
      goto exit;

   /* Validate fingerprint */
   DIGI_MEMCMP(pBinary+(sizeof(val) + sizeof(MSTATUS)*NUM_FIPS_ALGONAME_VALUES), pStatus->fingerPrint, sizeof(pStatus->fingerPrint), &cmpRes);
   if (0 != cmpRes)
   {
       status = ERR_FALSE;
       goto exit;
   }

   /* Convert data */
   /* Also copy back the 0'th entry 0xEE */
   for (i = 0; i <= LAST_FIPS_ALGO; i++)
   {
      MSTATUS* pDat = (MSTATUS*)(pBinary + 4 + (sizeof(MSTATUS)*i));
      s[i] = *pDat;
   }

   /* Set status flags */
   for (i = FIRST_FIPS_ALGO; i <= LAST_FIPS_ALGO; i++)
   {
      pStatus->algoStatus[i] = s[i];
   }

exit:
   if (NULL != pBinary)
   {
     DIGI_FREE((void**)&pBinary);
   }
   return status;
}

/*---------------------------------------------------------*/

#ifdef __DIGICERT_PERSIST_USE_FILE__

#ifdef __ENABLE_DIGICERT_FIPS_INTEG_TEST__
extern MSTATUS FIPS_INTEG_TEST_hash_binSkip(ubyte* hashReturn, const char* optionalBinFileName, ubyte4 offset);

extern MSTATUS FIPS_INTEG_TEST_hash_memory(ubyte* hashReturn, ubyte* data, ubyte4 dataLen);



static MSTATUS FIPS_hashPersistDataFile(ubyte* pHashOut, const char* fileName, ubyte4 sigLen)
{
   MSTATUS status = OK;

   status = FIPS_INTEG_TEST_hash_binSkip(pHashOut, fileName, sigLen);
   return status;
}
#endif

/*---------------------------------------------------------*/

static MSTATUS
FIPS_persistReadFileRaw(const ubyte* pFileObj, ubyte **ppRetBuffer, ubyte4 *pRetBufLength)
{
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_DIGICERT_NANOPNAC__)
    FIL *f = (FIL*) pFileObj;
    FRESULT error = 0;
    ubyte4 bytesRead = 0;
#elif defined (__ENABLE_DIGICERT_RTOS_FILEX__)
    FX_FILE *f = (FX_FILE *)pFileObj;
    ubyte4   actual_size = 0;
#elif !defined( __RTOS_WTOS__)
    FILE*   f = (FILE*) pFileObj;
#else
    int     f = (int)pFileObj;
#endif
    sbyte4  fileSize;
    ubyte*  pFileBuffer = NULL;
    MSTATUS status = OK;

    /* check input */
    if ((NULL == pFileObj) || (NULL == ppRetBuffer) || (NULL == pRetBufLength))
    {
        status = ERR_NULL_POINTER;
        goto nocleanup;
    }

    *ppRetBuffer   = NULL;
    *pRetBufLength = 0;

#if defined (__ENABLE_DIGICERT_RTOS_FILEX__)
    fileSize = f->fx_file_current_file_size ;
#elif defined (__FREERTOS_RTOS__)&& !defined(__ENABLE_DIGICERT_NANOPNAC__)
    fileSize = f_size(f) ;
#else
    /* determine size */
    if (OK > fseek(f, 0, MSEEK_END))
    {
        status = ERR_FILE_SEEK_FAILED;
        goto exit;
    }

    fileSize = (sbyte4)ftell(f);
#endif

    if (0 > fileSize)  /* ftell() returns -1 on error */
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    if (NULL == (pFileBuffer = (ubyte *) MALLOC(fileSize + 1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pFileBuffer[fileSize] = 0;
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_DIGICERT_NANOPNAC__)
    f_rewind(f) ;
#elif defined (__ENABLE_DIGICERT_RTOS_FILEX__)
    if(FX_SUCCESS != fx_file_seek(f, 0UL))
    {
         status = ERR_FILE_SEEK_FAILED;
         goto exit;
    }
#elif !defined(__RTOS_WINCE__) && !defined(__RTOS_MQX__)
    rewind(f);
#else
    if (OK > fseek(f, 0L, MSEEK_SET))
    {
        status = ERR_FILE_SEEK_FAILED;
        goto exit;
    }
#endif

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_DIGICERT_NANOPNAC__)
    error = f_read(f, pFileBuffer, fileSize, &bytesRead);
    if ((error) || (bytesRead != fileSize))
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }
#elif defined (__ENABLE_DIGICERT_RTOS_FILEX__)
    status = fx_file_read(f, pFileBuffer, fileSize, &actual_size);
    if(actual_size < fileSize )
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }
#else
    if (((ubyte4)fileSize) > fread(pFileBuffer, 1, fileSize, f))
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }
#endif

    *ppRetBuffer   = pFileBuffer;  pFileBuffer = NULL;
    *pRetBufLength = fileSize;

exit:
    if (NULL != pFileBuffer)
        FREE(pFileBuffer);

nocleanup:
    return status;

}

/*---------------------------------------------------------*/

static MSTATUS
FIPS_persistReadFile(const char* pFilename,
                     ubyte **ppRetBuffer, ubyte4 *pRetBufLength)
{
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_DIGICERT_NANOPNAC__)
    FIL file ;
    FIL *f = &file;
    FRESULT error = 0;
#elif defined (__ENABLE_DIGICERT_RTOS_FILEX__)
    FX_FILE new_file = {0};
    FX_FILE *f = &new_file;
#elif !defined(__RTOS_WTOS__)
    FILE*   f;
#else
    int     f;
#endif
    MSTATUS status = OK;

    /* check input */
    if ((NULL == pFilename) || (NULL == ppRetBuffer) || (NULL == pRetBufLength))
    {
        status = ERR_NULL_POINTER;
        goto nocleanup;
    }

    *ppRetBuffer   = NULL;
    *pRetBufLength = 0;

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_DIGICERT_NANOPNAC__)
    error = f_open(f, pFilename, (FA_READ | FA_OPEN_EXISTING)) ;
    if(error)
        f = NULL ;
#elif defined (__ENABLE_DIGICERT_RTOS_FILEX__)
    status = fx_file_open(&g_fx_media0, f, pFilename, (FX_OPEN_FOR_READ));
    if(FX_SUCCESS != status)
    {
    	f = NULL ;
    }
#else
    f = fopen(pFilename, "rb");
#endif

#ifndef __RTOS_WTOS__
    if (!f)
#else
    if (f < 0)
#endif
    {
        status = ERR_FILE_OPEN_FAILED;
        goto nocleanup;
    }

    /* Read the Raw File */
    status = FIPS_persistReadFileRaw((ubyte*)f, ppRetBuffer, pRetBufLength);

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_DIGICERT_NANOPNAC__)
    (void) f_close(f);
#elif defined (__ENABLE_DIGICERT_RTOS_FILEX__)
    fx_file_close(f);
#else
    (void) fclose(f);
#endif

nocleanup:
    return status;
}

/*---------------------------------------------------------*/

static MSTATUS
FIPS_persistWriteFile(const char* pFilename,
                      const ubyte *pBuffer, ubyte4 bufLength)
{
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_DIGICERT_NANOPNAC__)
    FIL file ;
    FIL *f = &file;
    FRESULT error = 0;
    ubyte4 bytesWritten = 0;
#elif defined (__ENABLE_DIGICERT_RTOS_FILEX__)
    FX_FILE new_file = {0};
    FX_FILE *f = &new_file;
#elif !defined(__RTOS_WTOS__)
    FILE*   f;
#else
    int     f;
#endif
    MSTATUS status = OK;

    if ( (0 == bufLength) || (NULL == pBuffer) || (NULL == pFilename))
    {
        status = ERR_INVALID_INPUT;
        goto nocleanup;
    }

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_DIGICERT_NANOPNAC__)
    error = f_open(f, pFilename, (FA_WRITE | FA_CREATE_ALWAYS)) ;
    if(error)
        f = NULL ;
#elif defined (__ENABLE_DIGICERT_RTOS_FILEX__)
    fx_file_create(&g_fx_media0, pFilename);
    if(FX_SUCCESS != fx_file_open(&g_fx_media0, f, pFilename, (FX_OPEN_FOR_WRITE)))
    {
    	f = NULL ;
    }
    else
    {
    	fx_file_truncate(f, 0);
    }
#else
    f = fopen(pFilename, "wb");
#endif

#ifndef __RTOS_WTOS__
    if (!f)
#else
    if (f < 0)
#endif
    {
        status = ERR_FILE_OPEN_FAILED;
        goto nocleanup;
    }

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_DIGICERT_NANOPNAC__)
    error = f_write(f, pBuffer, bufLength, &bytesWritten);
    if ((error) || (bytesWritten != bufLength))
    {
        status = ERR_FILE_WRITE_FAILED;
    }

#elif defined (__ENABLE_DIGICERT_RTOS_FILEX__)
    if(FX_SUCCESS != fx_file_write(f, pBuffer, bufLength))
    	status = ERR_FILE_WRITE_FAILED;
#else
    if (bufLength != (fwrite(pBuffer, 1, bufLength, f)))
        status = ERR_FILE_WRITE_FAILED;
#endif

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_DIGICERT_NANOPNAC__)
    (void) f_close(f);
#elif defined (__ENABLE_DIGICERT_RTOS_FILEX__)
    fx_file_close(f);
    fx_media_flush(&g_fx_media0);
#else
    (void) fclose(f);
#endif

nocleanup:
    return status;
}

#endif /* __DIGICERT_PERSIST_USE_FILE__ */

/*---------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_persistReadStatus(FIPSStartupStatus *pStatus)
{
   MSTATUS status = ERR_UNSUPPORTED_OPERATION;

#ifdef __DIGICERT_PERSIST_USE_FILE__
   sbyte   *tstBuf = NULL;
   ubyte4  tstBufLen;
   ubyte   hashFile[SHA256_RESULT_SIZE];
   ubyte   hashText[SHA256_RESULT_SIZE];
   sbyte4  cmpRes = 0;
   int     i;

   tstBufLen = 512;

   /* Get Hash value */
   DIGI_MEMSET((ubyte*)hashFile, 0, SHA256_RESULT_SIZE);
   DIGI_MEMSET((ubyte*)hashText, 0, SHA256_RESULT_SIZE);

   /* Read file data */
   tstBufLen = 512;
   status = FIPS_persistReadFile(__DIGICERT_PERSIST_FILEPATH__, (ubyte**)&tstBuf, &tstBufLen);
   if (OK != status)
   {
      FIPS_TESTLOG(603, "FIPS_persistReadStatus: Read failure.");
      goto exit;
   }

   /* Convert to binary */
   for (i = 0; i < SHA256_RESULT_SIZE; ++i)
   {
      hashText[i] = (FIPS_Hex2Oct(tstBuf[2*i])) << 4;
      hashText[i] += FIPS_Hex2Oct(tstBuf[2*i+1]);
   }

#ifdef __ENABLE_DIGICERT_FIPS_INTEG_TEST__
   status = FIPS_hashPersistDataFile(hashFile, __DIGICERT_PERSIST_FILEPATH__, 2*SHA256_RESULT_SIZE);
   if (OK != status)
   {
      FIPS_TESTLOG(604, "FIPS_persistReadStatus: Hash failure.");
      goto exit;
   }
#endif

   if (OK != DIGI_CTIME_MATCH(hashFile, hashText, SHA256_RESULT_SIZE, &cmpRes))
   {
      status = ERR_FIPS_INTEGRITY_FAILED;
      goto exit;
   }

   if (0 != cmpRes)
   {
      FIPS_TESTLOG(605, "FIPS_persistReadStatus: Unmatched sig.");
      status = ERR_FIPS_INTEGRITY_FAILED;
      goto exit;
   }

   status = FIPS_parsePersistData(tstBuf+(SHA256_RESULT_SIZE*2),
				  DIGI_STRLEN(tstBuf+(SHA256_RESULT_SIZE*2)), pStatus);
   if (OK != status)
   {
      FIPS_TESTLOG(606, "FIPS_persistReadStatus: Parse failure.");
      goto exit;
   }
#endif /* __DIGICERT_PERSIST_USE_FILE__ */

exit:
#ifdef __DIGICERT_PERSIST_USE_FILE__
   DIGI_FREE((void**)&tstBuf);
#endif
   return status;
}

/*---------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_persistWriteStatus(FIPSStartupStatus *pStatus)
{
   MSTATUS status = ERR_UNSUPPORTED_OPERATION;
   sbyte   tstBuf[512];
   ubyte   hash[SHA256_RESULT_SIZE];
   int     i;

   /* Data to persist */
   status = FIPS_createPersistData(pStatus, tstBuf+(SHA256_RESULT_SIZE*2),
				   sizeof(tstBuf)-(SHA256_RESULT_SIZE*2));
   if (OK != status)
   {
      FIPS_TESTLOG(607, "FIPS_persistWriteStatus: Create failure.");
      goto exit;
   }

   /* Get Hash value */
   DIGI_MEMSET((ubyte*)hash, 0, SHA256_RESULT_SIZE);
#ifdef __ENABLE_DIGICERT_FIPS_INTEG_TEST__
   status = FIPS_INTEG_TEST_hash_memory((ubyte*)hash, (ubyte*)tstBuf+(SHA256_RESULT_SIZE*2),
					              DIGI_STRLEN(tstBuf+(SHA256_RESULT_SIZE*2)));
   if (OK != status)
   {
      FIPS_TESTLOG(608, "FIPS_persistWriteStatus: Hash failure.");
      goto exit;
   }
#endif
   
   /* Convert HASH to text */
   DIGI_MEMSET((ubyte*)tstBuf, 0, SHA256_RESULT_SIZE*2);
   for (i = 0; i < SHA256_RESULT_SIZE; ++i)
   {
      tstBuf[2*i]   = FIPS_Oct2Hex(0xF & (hash[i] >> 4));
      tstBuf[2*i+1] = FIPS_Oct2Hex(0xF & hash[i]);
   }

#ifdef __DIGICERT_PERSIST_USE_FILE__
   /* Write data */
   status = FIPS_persistWriteFile(__DIGICERT_PERSIST_FILEPATH__, (ubyte*)tstBuf, DIGI_STRLEN(tstBuf));
   if (OK != status)
   {
      FIPS_TESTLOG(609, "FIPS_persistWriteStatus: Write failure.");
      goto exit;
   }

#endif /* __DIGICERT_PERSIST_USE_FILE__ */

exit:
   return status;
}

#endif /* __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__ */
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */
