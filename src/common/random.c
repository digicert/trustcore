/*
 * random.c
 *
 * Random Number FIPS-186 Factory
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_RANDOM_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../crypto/sha1.h"

#include "../common/random.h"
#include "../common/int64.h"

#include "../crypto/crypto.h"
#include "../crypto/mocsym.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
FIPS_TESTLOG_IMPORT;
#endif

#ifdef __ENABLE_DIGICERT_ECC__
#undef __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/primefld_priv.h"
#include "../crypto/primeec_priv.h"
#endif /* __ENABLE_DIGICERT_ECC__ */
#include "../harness/harness.h"
#include "../crypto/aesalgo.h"
#include "../crypto/aes.h"
#if !defined(__DISABLE_3DES_CIPHERS__)
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#endif /* ! __DISABLE_3DES_CIPHERS__ */

#include "../crypto/nist_rng.h"

#include "../common/rng_seed.h"

#include "../crypto/nist_rng_types.h"  /* This is to get the RandomContext data structures */

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_random.h"
#include "../crypto_interface/crypto_interface_sha1.h"
#include "../crypto_interface/crypto_interface_nist_ctr_drbg.h"
#endif

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_MORE_TIME__
#define MOCANA_RAND_ENTROPY3_LOOP_COUNTER 5  /* N times thru the data. */
#define MOCANA_RAND_ENTROPY2_MAX_TIME  7100
#define MOCANA_RAND_ENTROPY1_MAX_TIME  7000
#else
#define MOCANA_RAND_ENTROPY3_LOOP_COUNTER 3  /* N times thru the data. */
#define MOCANA_RAND_ENTROPY2_MAX_TIME  5100
#define MOCANA_RAND_ENTROPY1_MAX_TIME  5000
#endif

#define MOCANA_ASCII_STRING_MIN_LEN    4
#define MOCANA_ASCII_STRING_MAX_LEN  100

#ifndef __DISABLE_DIGICERT_RNG__

#ifdef __KERNEL__
#include <linux/kernel.h>       /* for printk */
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/string.h>
#define PRINTDBG printk
#else
#define PRINTDBG printf
#endif
#endif /*__DISABLE_DIGICERT_RNG__*/

#ifdef __RTOS_WIN32__
MOC_EXTERN_RANDOM_H randomContext*   g_pRandomContext = NULL;
#else
randomContext*   g_pRandomContext = NULL;
#endif

static int mEntropySource = ENTROPY_DEFAULT_SRC;


#ifndef __DISABLE_DIGICERT_RNG__
/****************************************************/
/* Entropy Performance monitoring / tracing support */
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_PERFMON__
typedef struct threadstamp
{
	ubyte tid; /* 0..3 */
    ubyte4     sleepTime;
    moctime_t  outTime;
    moctime_t  inTime;
} threadstamp;

#define MAX_TSS_SAVED 10000     /* Overkill. */
#define MAX_TSS_THREADIDS 10    /* Overkill. */
#define MAX_VERBOSE_LOG_MSGS 0  /* 0 means just save to memory. > 0 is a per-thread counter (see below) */
#define MAX_LOG_DUMP_TID_LINES 20 /* Overkill. */

static int ts_ndx_entrycount;
static int ts_ndx;
static threadstamp tss[MAX_TSS_SAVED];
static int ethreadrunCounter[MAX_TSS_THREADIDS]; /* We only need four. */

static int verbose_log_curr[MAX_TSS_THREADIDS];
static int verbose_log_max[MAX_TSS_THREADIDS];

void PERFMON_loginit()
{   int iii;
	for (iii = 0; iii < MAX_TSS_THREADIDS; iii++)
	{
		ethreadrunCounter[iii] = 0;
		verbose_log_curr[iii] = 0;
		verbose_log_max[iii] = MAX_VERBOSE_LOG_MSGS;
	}
	ts_ndx = 0;
	ts_ndx_entrycount = 0;
}

void PERFMON_logentry(int id, ubyte4 sleepTime, moctime_t *pOutTime)
{
	ethreadrunCounter[id]++;
	tss[ts_ndx].tid = id;
	tss[ts_ndx].sleepTime = sleepTime;
	tss[ts_ndx].outTime = *pOutTime;
	RTOS_deltaMS(pOutTime, &tss[ts_ndx].inTime); /* Just to get inTime. */

	ts_ndx = (ts_ndx + 1) % MAX_TSS_SAVED;
	ts_ndx_entrycount++; /* Doesn't wrap... How many entries have been logged. */

	if (verbose_log_curr[id] < verbose_log_max[id])
	{
	    PRINTDBG("E-PERF: etid[%d] : sleepTime=%d \n", id, sleepTime);
	    verbose_log_curr[id] += 1;
	}
}
#define PERFMON_PRINTDBG() PRINTDBG()

void PERFMON_dump_thread_counters(void)
{
    PRINTDBG("E-PERF: entropy threads run counters = %d : %d : %d : %d \n",ethreadrunCounter[0],ethreadrunCounter[1],ethreadrunCounter[2],ethreadrunCounter[3]);
}

void PERFMON_dump_log_tids(void)
{
	/* NOTE: If it wraps, this will only print from [0] to the curr [ndx] */
	/*       if it matters, then this can be re-done to print them all..  */
    int currlinenum = 0;
    int maxtidperline = 80;
    static char tidline[120];
    int ii = 0;
    int iiline = 0;

    DIGI_MEMSET(tidline,0,sizeof(tidline)); /* empty it. */

    while (ii <= ts_ndx)
    {
    	if (iiline > maxtidperline)
    	{   tidline[iiline] = '\0'; /* NULL terminate it. */
    		PRINTDBG("E-PERF: e-tids[]:%s\n",tidline);
    		iiline = 0;
    		DIGI_MEMSET(tidline,0,sizeof(tidline)); /* empty it. */
    		if (currlinenum++ > MAX_LOG_DUMP_TID_LINES)
    		{
        		PRINTDBG("E-PERF: e-tids[]: Data truncated...\n");
    			break;
    		}
    	}
    	tidline[iiline++] = tss[ii].tid + '0';
    	ii++;
    }
}

void PERFMON_dump_log_full(void)
{
	 PERFMON_dump_log_tids(); /* Not needed for now. */
}

#else
#define PERFMON_loginit()
#define PERFMON_logentry(i,s,o)
#define PERFMON_dump_thread_counters()
#define PERFMON_dump_log_tids()
#define PERFMON_dump_log_full()
#endif
/****************************************************/

/*------------------------------------------------------------------*/

typedef struct entropyBundle
{
    rngFIPS186Ctx   ctx;

    ubyte           ethread01running;
    ubyte           ethread02running;
    ubyte           ethread03running;

} entropyBundle;

#ifdef __FIPS_OPS_TEST__
static int rng_fail = 0;
#endif

/*------------------------------------------------------------------*/

/* prototypes */
#if !defined(__DISABLE_DIGICERT_FIPS186_RNG__) || !defined(__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__)
static void RNG_add(ubyte* a, sbyte4 aLen, const ubyte* b, sbyte4 bLen, ubyte carry) ;
#endif

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
static void RNG_scramble(rngFIPS186Ctx *pRngFipsCtx);
#endif

extern MSTATUS RANDOM_releaseContextEx(randomContext **pp_randomContext);

#ifdef __FIPS_OPS_TEST__

MOC_EXTERN void triggerRNGFail(void)
{
    rng_fail = 1;
}

MOC_EXTERN void resetRNGFail(void)
{
    rng_fail = 0;
}
#endif

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
static void
void_entropyThread1(void* context)
{
    entropyBundle *pEb = (entropyBundle *)context;
    moctime_t startTime;
    sbyte4 i;

    moctime_t outTime;
    ubyte4 sleepTime;

    RTOS_deltaMS(NULL, &startTime);

    for (i = 0; i < pEb->ctx.b; i++)
    {
        ubyte4 newval;
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
        ubyte4 oldval;
        oldval = pEb->ctx.key[i];
#endif

        newval = pEb->ctx.key[i];
        newval ^= 0x10;
        pEb->ctx.key[i] = (ubyte)newval;

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
        PRINTDBG("ethread01[%03d] %8x %8x %8x\n", i, oldval, newval, pEb->ctx.key[i]);
#endif

		sleepTime = (((RTOS_deltaMS(&startTime, &outTime) >> 1) & 0x3) + 13);
        RTOS_sleepMS(sleepTime);
        PERFMON_logentry(1, sleepTime, &outTime);
#if (defined(__KERNEL__))
		if (kthread_should_stop())
		{
			#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
				PRINTDBG("ethread01:(1) kthread_should_stop = TRUE\n");
			#endif
		    pEb->ethread01running = FALSE;
			return;
		}
#endif
    }

    pEb->ethread01running = FALSE;

    RTOS_deltaMS(NULL, &startTime);

    /* keep running until thread 3 is done (or up to 2 secs) */
    while ((FALSE != pEb->ethread03running) && (RTOS_deltaMS(&startTime, NULL) < MOCANA_RAND_ENTROPY1_MAX_TIME))
    {
        for (i = 0; i < ((pEb->ctx.b) && (FALSE != pEb->ethread03running)); i++)
        {
            ubyte4 newval;
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
            ubyte4 oldval;
            oldval = pEb->ctx.key[i];
#endif

            newval = pEb->ctx.key[i];
            newval ^= 0x10;
            pEb->ctx.key[i] = (ubyte)newval;

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
            PRINTDBG("ethread01[%03d] %8x %8x %8x\n", i, oldval, newval, pEb->ctx.key[i]);
#endif

            sleepTime = (((RTOS_deltaMS(&startTime, &outTime) >> 1) & 0x3) + 13);
            RTOS_sleepMS(sleepTime);
            PERFMON_logentry(1, sleepTime, &outTime);
#if (defined(__KERNEL__))
            if (kthread_should_stop())
            {
				#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
					PRINTDBG("ethread01:(2) kthread_should_stop = TRUE\n");
				#endif
					return;
            }
#endif
        }
    }

#ifdef __FREERTOS_RTOS__
    RTOS_taskSuspend(NULL);
#endif
    return;
}
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
static void
void_entropyThread2(void* context)
{
    entropyBundle*  pEb = (entropyBundle *)context;
    moctime_t       startTime;
    sbyte4          i;

    moctime_t       outTime;
    ubyte4          sleepTime;

    RTOS_deltaMS(NULL, &startTime);

    for (i = pEb->ctx.b-1; i >= 0; i--)
    {
        ubyte4 newval;
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
        ubyte4 oldval;
        oldval = pEb->ctx.key[i];
#endif

        newval = pEb->ctx.key[i];
        newval = (newval ^ (newval * 13) ^ (newval * 37) ^ (newval * 57)) & 0xff;
        pEb->ctx.key[i] = (ubyte)newval;
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
        PRINTDBG("ethread02[%03d] %8x %8x %8x\n", i, oldval, newval, pEb->ctx.key[i]);
#endif
        sleepTime = (((RTOS_deltaMS(&startTime, &outTime) >> 1) & 0x3) + 7);
        RTOS_sleepMS(sleepTime);
        PERFMON_logentry(2, sleepTime, &outTime);
#if (defined(__KERNEL__))
		if (kthread_should_stop())
		{
			#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
				PRINTDBG("ethread02:(1) kthread_should_stop = TRUE\n");
			#endif
		    pEb->ethread02running = FALSE;
			return;
		}
#endif
    }

    pEb->ethread02running = FALSE;

    RTOS_deltaMS(NULL, &startTime);

    /* keep running until thread 3 is done (or up to 2.1 secs) */
    while ((FALSE != pEb->ethread03running) && (RTOS_deltaMS(&startTime, NULL) < MOCANA_RAND_ENTROPY2_MAX_TIME))
    {
        for (i = pEb->ctx.b-1; ((i >= 0) && (FALSE != pEb->ethread03running)); i--)
        {
            ubyte4 newval;
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
            ubyte4 oldval;
            oldval = pEb->ctx.key[i];
#endif

            newval = pEb->ctx.key[i];
            newval = (newval ^ (newval * 13) ^ (newval * 37) ^ (newval * 57)) & 0xff;
            pEb->ctx.key[i] = (ubyte)newval;
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
            PRINTDBG("ethread02[%03d] %8x %8x %8x\n", i, oldval, newval, pEb->ctx.key[i]);
#endif
            sleepTime = (((RTOS_deltaMS(&startTime, &outTime) >> 1) & 0x3) + 7);
            RTOS_sleepMS(sleepTime);
            PERFMON_logentry(2, sleepTime, &outTime);
#if (defined(__KERNEL__))
            if (kthread_should_stop())
    		{
    			#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    				PRINTDBG("ethread02:(2) kthread_should_stop = TRUE\n");
    			#endif
    			return;
    		}
#endif
        }
    }

#ifdef __FREERTOS_RTOS__
    RTOS_taskSuspend(NULL);
#endif
    return;
}
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
static void
void_entropyThread3(void* context)
{
    entropyBundle*  pEb = (entropyBundle *)context;
    rngFIPS186Ctx*  pRngFipsCtx;
    ubyte4          i;
    moctime_t       startTime;

    moctime_t outTime;
    ubyte4 sleepTime;

    pRngFipsCtx = &pEb->ctx;

    for (i = 0; i < pRngFipsCtx->b; i += 7)
    {
        RTOS_deltaMS(NULL, &startTime);

        while (RTOS_deltaMS(&startTime, NULL) < ((i + 1) * 19))
            RNG_scramble(pRngFipsCtx);

        sleepTime = (((RTOS_deltaMS(&startTime, &outTime) >> 1) & 0x3) + 3);
        RTOS_sleepMS(sleepTime);
    	PERFMON_logentry(3, sleepTime, &outTime);
#if (defined(__KERNEL__))
    	if (kthread_should_stop())
    	{
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    		PRINTDBG("ethread03:kthread_should_stop = TRUE\n");
#endif
    		pEb->ethread03running = FALSE;
    		return;
    	}
#endif
    }

    pEb->ethread03running = FALSE;

#ifdef __FREERTOS_RTOS__
    RTOS_taskSuspend(NULL);
#endif
    return;
}
#endif

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
#if (defined(__KERNEL__))
static int int_entropyThread1(void* context)
{
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("ethread01 starting.\n");
#endif
    set_current_state(TASK_INTERRUPTIBLE);
    void_entropyThread1(context);
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("ethread01 done.\n");
#endif
    return 0;
}

static int int_entropyThread2(void* context)
{
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("ethread02 starting.\n");
#endif
    set_current_state(TASK_INTERRUPTIBLE);
    void_entropyThread2(context);
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("ethread02 done.\n");
#endif
    return 0;
}

static int int_entropyThread3(void* context)
{
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("ethread03 starting.\n");
#endif
    set_current_state(TASK_INTERRUPTIBLE);
    void_entropyThread3(context);
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("ethread03 done.\n");
#endif
    return 0;
}

#define entropyThread1 int_entropyThread1
#define entropyThread2 int_entropyThread2
#define entropyThread3 int_entropyThread3
#else
#define entropyThread1 void_entropyThread1
#define entropyThread2 void_entropyThread2
#define entropyThread3 void_entropyThread3
#endif  /* KERNEL */
#endif

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
static void
RNG_scramble(rngFIPS186Ctx *pRngFipsCtx)
{
    sbyte4  i, j;

    for (i = 0; i < 2; ++i)
    {
        ubyte* w = pRngFipsCtx->result + i * SHA1_RESULT_SIZE;

        DIGI_MEMCPY(pRngFipsCtx->scratch, pRngFipsCtx->key, pRngFipsCtx->b);

        /* add the seed to the key in the scratch area */
        if (pRngFipsCtx->pSeed && pRngFipsCtx->seedLen>0)
        {
            RNG_add((ubyte*) pRngFipsCtx->scratch, pRngFipsCtx->b,
                    (const ubyte*) pRngFipsCtx->pSeed, pRngFipsCtx->seedLen, 0);
            pRngFipsCtx->seedLen -= pRngFipsCtx->b;

            if (pRngFipsCtx->seedLen > 0 )
                pRngFipsCtx->pSeed += pRngFipsCtx->b;
        }

        /* pad with 0 to 512 bits */
        for (j = pRngFipsCtx->b; j < 64; ++j)
            pRngFipsCtx->scratch[j] = 0;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
      CRYPTO_INTERFACE_SHA1_G( pRngFipsCtx->scratch, w);
#else
      SHA1_G( pRngFipsCtx->scratch, w);
#endif

        RNG_add( (ubyte*) pRngFipsCtx->key, pRngFipsCtx->b,
                 (const ubyte*) w, SHA1_RESULT_SIZE, 1);
    }
}
#endif /* __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__ */


/*------------------------------------------------------------------*/

MOC_EXTERN sbyte4
RANDOM_rngFun(void* rngFunArg, ubyte4 length, ubyte *buffer)
{
   return RANDOM_numberGenerator((randomContext *) rngFunArg,
       buffer, (sbyte4) length);

}

/*------------------------------------------------------------------*/

#if !defined(__DISABLE_DIGICERT_FIPS186_RNG__) || !defined(__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__)
static void RNG_add( ubyte* a, sbyte4 aLen, const ubyte* b, sbyte4 bLen,
                    ubyte carry)
{
    sbyte4 i, j;

    for (i = aLen-1, j = bLen-1; i >= 0; --i, --j)
    {
        a[i] += carry;
        carry = (a[i] < carry) ? 1 : 0;

        if (j >= 0)
        {
            a[i] += b[j];
            carry += (a[i] < b[j]) ? 1 : 0;
        }
    }
}
#endif

/*------------------------------------------------------------------*/

extern ubyte*
GetNullPersonalizationString(ubyte4* pLen)
{
    *pLen = 0;
    return ((ubyte*) 0);
}

/*------------------------------------------------------------------*/

extern MSTATUS
RANDOM_acquireContext(randomContext **pp_randomContext)
{
    /* This function uses the Default algorithm defined in the header. The caller doesn't care, so we choose for him. */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_RANDOM_acquireContextEx(
        pp_randomContext, RANDOM_DEFAULT_ALGO);
#else
    return RANDOM_acquireContextEx(pp_randomContext, RANDOM_DEFAULT_ALGO);
#endif
}

/*------------------------------------------------------------------*/

extern MSTATUS
RANDOM_releaseContext(randomContext **pp_randomContext)
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_RANDOM_releaseContextEx(pp_randomContext);
#else
    return RANDOM_releaseContextEx(pp_randomContext);
#endif
}

/*------------------------------------------------------------------*/

extern MSTATUS
RANDOM_addEntropyBit(randomContext *pRandomContext, ubyte entropyBit)
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_RANDOM_addEntropyBitEx(pRandomContext, entropyBit);
#else
    return RANDOM_addEntropyBitEx(pRandomContext, entropyBit);
#endif
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS RANDOM_numberGenerator (
  randomContext *pRandomContext,
  ubyte *pRetRandomBytes,
  sbyte4 numRandomBytes)
{
    /* This function handles all types. */
    RandomCtxWrapper* pWrapper = NULL;
    if ( !pRandomContext || !pRetRandomBytes)
    {
        return ERR_NULL_POINTER;
    }

    pWrapper = (RandomCtxWrapper*)pRandomContext;

    if (IS_FIPS186_CTX(pWrapper))
    {
#ifndef __DISABLE_DIGICERT_FIPS186_RNG__
      return RANDOM_numberGeneratorFIPS186 (
        pRandomContext, pRetRandomBytes, numRandomBytes);
#else
        return ERR_INVALID_INPUT;
#endif
    }
    else if (IS_CTR_DRBG_CTX(pWrapper))
    {
#ifndef __DISABLE_DIGICERT_NIST_CTR_DRBG__
      return NIST_CTRDRBG_numberGenerator(
        MOC_SYM(pWrapper->hwAccelCtx) pRandomContext,
        pRetRandomBytes, numRandomBytes);
#else
        return ERR_INVALID_INPUT;
#endif
    }
#if (defined(__ENABLE_DIGICERT_SYM__))
    else if (IS_MOC_RAND(pWrapper))
    {
      MocRandCtx *pRandCtx = GET_MOC_RAND_CTX(pWrapper);
      MocSymCtx pCtx = (MocSymCtx)(pRandCtx->pMocSymObj);
      MSymOperatorBuffer outputBuf;
      ubyte4 resultLen;

      outputBuf.pBuffer = pRetRandomBytes;
      outputBuf.bufferSize = (ubyte4)numRandomBytes;
      outputBuf.pOutputLen = &resultLen;
      return (pCtx->SymOperator (
        pCtx, NULL, MOC_SYM_OP_GENERATE_RANDOM, NULL, (void *)&outputBuf));
    }
#endif
    else
    {
      return ERR_NULL_POINTER;
    }
}

/*------------------------------------------------------------------*/

extern MSTATUS RANDOM_numberGeneratorAdd (
    randomContext *pRandomContext,
    ubyte *pRetRandomBytes,
    ubyte4 numRandomBytes,
    ubyte *pAdditionalData,
    ubyte4 additionalDataLen
    )
{
    /* This function handles all types. */
    RandomCtxWrapper* pWrapper = NULL;
    if ( !pRandomContext || !pRetRandomBytes)
    {
        return ERR_NULL_POINTER;
    }

    pWrapper = (RandomCtxWrapper*)pRandomContext;

    if (IS_FIPS186_CTX(pWrapper))
    {
#ifndef __DISABLE_DIGICERT_FIPS186_RNG__
      return RANDOM_numberGeneratorFIPS186 (
        pRandomContext, pRetRandomBytes, (sbyte4)numRandomBytes);
#else
        return ERR_INVALID_INPUT;
#endif
    }
    else if (IS_CTR_DRBG_CTX(pWrapper))
    {
#ifndef __DISABLE_DIGICERT_NIST_CTR_DRBG__
      return NIST_CTRDRBG_generate(
        MOC_SYM(pWrapper->hwAccelCtx) pRandomContext, pAdditionalData,
        additionalDataLen, pRetRandomBytes, numRandomBytes * 8);
#else
        return ERR_INVALID_INPUT;
#endif
    }
#if (defined(__ENABLE_DIGICERT_SYM__))
    else if (IS_MOC_RAND(pWrapper))
    {
      MocRandCtx *pRandCtx = GET_MOC_RAND_CTX(pWrapper);
      MocSymCtx pCtx = (MocSymCtx)(pRandCtx->pMocSymObj);
      MSymOperatorData inputData;
      MSymOperatorBuffer outputBuf;
      ubyte4 resultLen;

      inputData.pData = pAdditionalData;
      inputData.length = additionalDataLen;
      outputBuf.pBuffer = pRetRandomBytes;
      outputBuf.bufferSize = (ubyte4)numRandomBytes;
      outputBuf.pOutputLen = &resultLen;
      return (pCtx->SymOperator (
        pCtx, NULL, MOC_SYM_OP_GENERATE_RANDOM,
        (void *)&inputData, (void *)&outputBuf));
    }
#endif
    else
    {
      return ERR_NULL_POINTER;
    }
}

/*------------------------------------------------------------------*/

extern MSTATUS RANDOM_reseedContext (
  randomContext *pCtx,
  ubyte *pEntropy,
  ubyte4 entropyLen,
  ubyte *pAdditionalData,
  ubyte4 additionalDataLen
  )
{
    MSTATUS status;
    randomContextType randType;
    RandomCtxWrapper* pWrapper = NULL;

    if (NULL == pCtx)
    {
        return ERR_NULL_POINTER;
    }

    pWrapper = (RandomCtxWrapper*)pCtx;
    randType = pWrapper->WrappedCtxType;

    switch(randType)
    {
#ifndef __DISABLE_DIGICERT_FIPS186_RNG__
        case NIST_FIPS186:
            status = RANDOM_seedFIPS186Context(pCtx, pEntropy, entropyLen);
            break;
#endif
#ifndef __DISABLE_DIGICERT_NIST_CTR_DRBG__
        case NIST_CTR_DRBG:
            status = NIST_CTRDRBG_reseed (MOC_SYM(pWrapper->hwAccelCtx)
                pCtx, pEntropy, entropyLen, pAdditionalData, additionalDataLen);
            break;
#endif
#if (defined(__ENABLE_DIGICERT_SYM__))
        case MOC_RAND:
            status = CRYPTO_reseedRandomContext (
                pCtx, pEntropy, entropyLen, pAdditionalData, additionalDataLen);
            break;
#endif
        default:
            status = ERR_RAND_INVALID_CONTEXT;
            break;
    }

    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS RANDOM_setEntropySource(ubyte EntropySrc)
{
    MSTATUS         status = OK;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    FIPS_TESTLOG_FMT(199, "\nRNG RANDOM_setEntropySource(%d)", EntropySrc);
#endif

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
    if ( (EntropySrc != ENTROPY_SRC_INTERNAL) && (EntropySrc != ENTROPY_SRC_EXTERNAL) )
    {
    	status = ERR_INVALID_ARG;
        goto exit;
    }
#else /* Only external is allowed */
    if ( (EntropySrc != ENTROPY_SRC_EXTERNAL) )
    {
    	status = ERR_INVALID_ARG;
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_DEBUGGING__
    PRINTDBG("RANDOM_setEntropySource() Setting mEntropySource == %d (was %d) \n",EntropySrc, mEntropySource);
#endif
	mEntropySource = EntropySrc;

exit:
	    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN ubyte RANDOM_getEntropySource(void)
{
    if ( (mEntropySource != ENTROPY_SRC_INTERNAL) && (mEntropySource != ENTROPY_SRC_EXTERNAL) )
    {
    	mEntropySource = ENTROPY_DEFAULT_SRC;
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_DEBUGGING__
    PRINTDBG("RANDOM_getEntropySource() (0) Returning mEntropySource == %d \n", mEntropySource);
#endif
    	return ENTROPY_DEFAULT_SRC;
    }
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_DEBUGGING__
    PRINTDBG("RANDOM_getEntropySource() (1) Returning mEntropySource == %d \n", mEntropySource);
#endif
    return mEntropySource;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS RANDOM_getAutoSeedBytes(
  ubyte *pSeedBytes,
  ubyte4 numBytes
  )
{
  MSTATUS status;

  /* Check that the operation is valid */
  MOC_VERIFY_AUTOSEED_ENABLED(status)

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
    /* Validate requested seed length, must be multiple of 8 between 8 and 64 */
  status = ERR_RAND_SEED_LEN_INVALID;
  if (numBytes < MOC_AUTOSEED_MIN_NUM_BYTES ||
    numBytes > MOC_AUTOSEED_MAX_NUM_BYTES ||
    numBytes % 8 != 0)
    goto exit;

  status = RNG_SEED_extractDepotBits(pSeedBytes, numBytes);
#endif

exit:
  return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS RANDOM_launchAutoSeed(
  randomContext *pCtx
  )
{
  MSTATUS status;
  int origEntropySource;
  RandomCtxWrapper *pWrapper = (RandomCtxWrapper *)pCtx;
  ubyte seedBytes[MOC_DEFAULT_NUM_ENTROPY_BYTES] = {0};
#if (defined(__ENABLE_DIGICERT_SYM__))
  intBoolean isMocRand = FALSE;
  intBoolean seedSupport = FALSE;
  MocSymCtx pMocSymRandObj = NULL;
  MocRandCtx *pRandCtx = NULL;
#endif

  /* Preserve the original entropy source */
  origEntropySource = mEntropySource;

  status = ERR_NULL_POINTER;
  if (NULL == pWrapper)
    goto exit;

/* Determine if this is a MocSym random object. If it is then determine if the
 * object supports a seeding operation. */
#if (defined(__ENABLE_DIGICERT_SYM__))
  status = RANDOM_isMocSymContext(&pCtx, &isMocRand);
  if (OK != status)
    goto exit;

  if (TRUE == isMocRand)
  {
    pRandCtx = GET_MOC_RAND_CTX(pWrapper);
    if(NULL == pRandCtx)
    {
      status = ERR_NULL_POINTER;
      goto exit;
    }
    pMocSymRandObj = (MocSymCtx)(pRandCtx->pMocSymObj);

    status = ERR_NULL_POINTER;
    if ( (NULL == pMocSymRandObj) || (NULL == pMocSymRandObj->SymOperator) )
      goto exit;

    status = pMocSymRandObj->SymOperator(
      pMocSymRandObj, NULL, MOC_SYM_OP_RAND_GET_SEED_TYPE, NULL, (void *)&seedSupport);
    if (OK != status)
      goto exit;

    /* If the object seeds internally then return OK */
    if (MOC_SYM_RAND_SEED_TYPE_INTERNAL == seedSupport)
        goto exit;

    /* Does this operator support direct seeding? */
    status = ERR_RAND_SEED_METHOD_NOT_SUPPORTED;
    if (MOC_SYM_RAND_SEED_TYPE_DIRECT != seedSupport)
        goto exit;
  }
#endif

  /* Guarantee the entropy source is set to internal */
  status = RANDOM_setEntropySource(ENTROPY_SRC_INTERNAL);
  if (OK != status)
    goto exit;

  /* Get the autoseed bytes */
  status = RANDOM_getAutoSeedBytes((ubyte *)seedBytes,
    MOC_DEFAULT_NUM_ENTROPY_BYTES);
  if (OK != status)
    goto exit;

  /* Seed the random context */
#if (defined(__ENABLE_DIGICERT_SYM__))
  status = CRYPTO_seedRandomContext(
    pCtx, NULL, (ubyte *)seedBytes, MOC_DEFAULT_NUM_ENTROPY_BYTES);
#else
  status = RANDOM_seedOldRandom (
    pCtx, (ubyte *)seedBytes, MOC_DEFAULT_NUM_ENTROPY_BYTES);
#endif

  DIGI_MEMSET((ubyte *)seedBytes, 0, MOC_DEFAULT_NUM_ENTROPY_BYTES);

exit:

  /* Set the entropy source back to its original value */
  mEntropySource = origEntropySource;

  return status;

} /* RANDOM_launchAutoSeed */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS RANDOM_seedOldRandom (
  randomContext *pCtx,
  ubyte *pSeedBytes,
  ubyte4 seedLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  RandomCtxWrapper *pWrapper = (RandomCtxWrapper *)pCtx;
  if (NULL == pWrapper || NULL == pSeedBytes)
    goto exit;

  status = ERR_INVALID_INPUT;
  if (IS_FIPS186_CTX(pWrapper))
  {
#ifndef __DISABLE_DIGICERT_FIPS186_RNG__
    status = RANDOM_seedFIPS186Context(pCtx, pSeedBytes, seedLen);
#else
    status = ERR_INVALID_INPUT;
#endif

  }
  else if (IS_CTR_DRBG_CTX(pWrapper))
  {
#ifndef __DISABLE_DIGICERT_NIST_CTR_DRBG__
    /* Perform a reseed. If the default RNG is being used then the reseeding
     * can take an arbitrary number of bytes. If a CTR_DRBG without a
     * derivation function is being used then the seed must be 48 bytes */
    status = NIST_CTRDRBG_reseed (MOC_SYM(pWrapper->hwAccelCtx) pCtx, pSeedBytes, seedLen, NULL, 0);
#else
    status = ERR_INVALID_INPUT;
#endif
  }

exit:
  return status;

} /* RANDOM_seedOldRandom */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SYM__

MOC_EXTERN MSTATUS RANDOM_isMocSymContext(
  randomContext **ppRandomContext,
  intBoolean *pIsMocSym
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  RandomCtxWrapper *pWrapper = NULL;

  if (NULL == ppRandomContext || NULL == pIsMocSym)
    goto exit;

  pWrapper = (RandomCtxWrapper *)*ppRandomContext;
  if (NULL == pWrapper)
    goto exit;

  *pIsMocSym = FALSE;
  status = OK;
  if (IS_MOC_RAND(pWrapper))
    *pIsMocSym = TRUE;

exit:
  return status;
}
#endif /* ifdef __ENABLE_DIGICERT_SYM__ */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_FIPS186_RNG__

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_FIPS186_INTERNAL__

extern MSTATUS
RANDOM_newFIPS186Context(randomContext **ppRandomContext,
                         ubyte b, const ubyte pXKey[/*b*/],
                         sbyte4 seedLen, const ubyte pXSeed[/*seedLen*/])
{
    FIPS_LOG_DECL_SESSION;
    RandomCtxWrapper* pWrapper = NULL;
    rngFIPS186Ctx*  pRngFipsCtx = NULL;
    MSTATUS         status = OK;

#if( defined(__ENABLE_DIGICERT_FIPS_MODULE__) )
    sbyte4          cmp = 0xA5A5;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_RNG_FIPS186,0);

    if ( b == (ubyte)seedLen )
    {
        DIGI_CTIME_MATCH( pXKey, pXSeed, b, &cmp );
        if ( 0 == cmp )
        {
            status = ERR_CRYPTO;
            goto exit;
        }
    }
#endif /* ( defined(__ENABLE_DIGICERT_FIPS_MODULE__) ) */

    if (!ppRandomContext || !pXKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    *ppRandomContext = NULL;

    if ( b < 20 || b > 64)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    if (OK != (status = DIGI_MALLOC((void **)&pWrapper, sizeof(RandomCtxWrapper))))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pWrapper->WrappedCtxType = NIST_FIPS186;
    pRngFipsCtx = GET_FIPS186_CTX(pWrapper);
    if (pRngFipsCtx == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pRngFipsCtx->rngMutex = 0;

    pRngFipsCtx->b = b;
    DIGI_MEMCPY(pRngFipsCtx->key, pXKey, b);

    pRngFipsCtx->numBytesAvail = 0;
    pRngFipsCtx->pSeed = pXSeed;
    pRngFipsCtx->seedLen = seedLen;

    /* Create mutex used to guard shared context */
    if ( OK > ( status = RTOS_mutexCreate( &pRngFipsCtx->rngMutex, (enum mutexTypes) 0, 0 ) ) )
        goto exit;

    /* setup for return */
    *ppRandomContext = pWrapper;
    pWrapper = NULL;

exit:

    RANDOM_deleteFIPS186Context((randomContext**) &pWrapper);

    FIPS_LOG_END_ALG(NON_FIPS_ALGO_RNG_FIPS186,0);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
RANDOM_deleteFIPS186Context( randomContext** pp_randomContext)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    RandomCtxWrapper* pWrapper = NULL;
    rngFIPS186Ctx* pRngFipsCtx = NULL;
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_RNG_FIPS186,0);

    if (!pp_randomContext || !*pp_randomContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pWrapper = (RandomCtxWrapper*)(*pp_randomContext);

    pRngFipsCtx = GET_FIPS186_CTX(pWrapper);
    if (pRngFipsCtx == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    RTOS_mutexFree(&pRngFipsCtx->rngMutex);

#ifdef __ZEROIZE_TEST__
    FIPS_PRINT("\nRNG - Before Zeroization\n");
    for( counter = 0; counter < sizeof(RandomCtxWrapper); counter++)
    {
        FIPS_PRINT("%02x",*((ubyte*)*pp_randomContext+counter));
    }
	FIPS_PRINT("\n");
#endif

    /* clear out data */
    DIGI_MEMSET((ubyte*) *pp_randomContext, 0x00, sizeof(RandomCtxWrapper));

#ifdef __ZEROIZE_TEST__
    FIPS_PRINT("\nRNG - After Zeroization\n");
    for( counter = 0; counter < sizeof(RandomCtxWrapper); counter++)
    {
        FIPS_PRINT("%02x",*((ubyte*)*pp_randomContext+counter));
    }
	FIPS_PRINT("\n");
#endif

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_RNG_FIPS186,0);
    if (status != OK)
    {
        return status;
    }
    else
    {
        return DIGI_FREE(pp_randomContext);
    }
}

/*------------------------------------------------------------------*/

static MSTATUS
RANDOM_acquireFIPS186Context( randomContext** ppCtx, ubyte4 keySize)
{
    FIPS_LOG_DECL_SESSION;
#if ((!defined(__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__)) && (!defined(__DISABLE_DIGICERT_RAND_SEED__)))
    RTOS_THREAD             ethread01;
    RTOS_THREAD             ethread02;
    RTOS_THREAD             ethread03;
    static entropyBundle    eb = {{0},0,0,0};

    moctime_t outTime;
    ubyte4 sleepTime;

#endif
    RandomCtxWrapper*       pWrapper = NULL;
    rngFIPS186Ctx*          pRngFipsCtx = NULL;
    ubyte                   key[MOCANA_RNG_MAX_KEY_SIZE];
#if (!  (defined(__DISABLE_DIGICERT_RAND__) || defined(__DISABLE_DIGICERT_RAND_SEED__)))
#ifndef __ENABLE_DIGICERT_FREESTANDING__
    moctime_t               startTime;
#endif
    ubyte4                  upTime, temp, i;
#endif
    MSTATUS                 status = OK;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_RNG_FIPS186,0);

#if (defined(__DISABLE_DIGICERT_RAND__))
    PRINTDBG("RANDOM_acquireContext: WARNING: __DISABLE_DIGICERT_RAND__ !!!\n");

#elif (defined(__DISABLE_DIGICERT_RAND_SEED__))
    /* only useful for benchmarking / optimizing key generation */
    DIGI_MEMSET(key, 0x00, 20);

    if (OK > (status = RANDOM_newFIPS186Context((randomContext **) &pWrapper,
                                                20, key, 0, NULL)))
    {
        goto exit;
    }
    else
    {
        pRngFipsCtx = GET_FIPS186_CTX(pWrapper);
        if (pRngFipsCtx == NULL)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
    }
#else

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_DEBUGGING__
    PRINTDBG("*** Start basic seeding... \n");
#endif

    /* basic seeding of the key */
    status = RNG_SEED_extractInitialDepotBits(key, keySize);
    if (OK != status)
      goto exit;

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_PERFMON__
    ubyte4               perfStartTime;
    ubyte4               perfStartThreadTime;
    ubyte4               perfEndTime;
    perfStartTime = RTOS_getUpTimeInMS();
    PRINTDBG("E-PERF: RANDOM_acquireContext: Starting... time=%d \n",perfStartTime);
#endif

    if (OK > (status = RANDOM_newFIPS186Context((randomContext **)&pWrapper,
                                                (ubyte) keySize, key, 0, NULL)))
    {
        goto exit;
    }
    else
    {
        pRngFipsCtx = GET_FIPS186_CTX(pWrapper);
        if (pRngFipsCtx == NULL)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
    }

#ifndef __ENABLE_DIGICERT_FREESTANDING__
    RTOS_deltaMS(NULL, &startTime);
#endif

    /* ...continue basic seeding */
    for (i = 0; i < pRngFipsCtx->b; i++)
    {
#ifdef __ENABLE_DIGICERT_FREESTANDING__
        upTime = EZFIPS_random();
#else
        upTime = RTOS_deltaMS(&startTime, NULL);
#endif
        if (((upTime & 0x3) & (pRngFipsCtx->key[i] & 0x3)) == 0x3)
        {
            temp = (pRngFipsCtx->key[upTime % pRngFipsCtx->b] + upTime);
            pRngFipsCtx->key[upTime % pRngFipsCtx->b] = (ubyte)(temp & 0xff);
        }

        temp = pRngFipsCtx->key[i] ^ upTime;
        pRngFipsCtx->key[i] = (ubyte)(temp & 0xff);
        if (OK > (status = RANDOM_numberGeneratorFIPS186((randomContext *)pWrapper, pRngFipsCtx->key, sizeof(pRngFipsCtx->key))))
		{
            goto exit;
 		}
    }
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_DEBUGGING__
    PRINTDBG("*** Finished basic seeding.\n");
#endif

    /* leverages preemptive RTOS */
#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
    if (mEntropySource == ENTROPY_SRC_INTERNAL)
    {

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_DEBUGGING__
    	PRINTDBG("*** Creating entropy threads \n", i);
#endif

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_PERFMON__
    perfStartThreadTime = RTOS_getUpTimeInMS();
    PRINTDBG("E-PERF: RANDOM_acquireContext: Starting Entropy threads... time=%d \n",perfStartThreadTime);
#endif

    PERFMON_loginit();

    /* initialize static context */
    DIGI_XORCPY(eb.ctx.result, pRngFipsCtx->result, sizeof(pRngFipsCtx->result));
    DIGI_XORCPY(eb.ctx.key, pRngFipsCtx->key, sizeof(pRngFipsCtx->key));
    DIGI_XORCPY(eb.ctx.scratch, pRngFipsCtx->scratch, sizeof(pRngFipsCtx->scratch));

    eb.ctx.b = MOCANA_RNG_MAX_KEY_SIZE;

    eb.ethread01running = eb.ethread02running = eb.ethread03running = TRUE;

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("*** creating entropy thread 01\n", i);
#endif

    if (OK > (status = RTOS_createThread(entropyThread1, &eb, (sbyte4)ENTROPY_THREAD, &ethread01)))
        goto exit;

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("*** creating entropy thread 02\n", i);
#endif

    if (OK > (status = RTOS_createThread(entropyThread2, &eb, (sbyte4)ENTROPY_THREAD, &ethread02)))
        goto exit;

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("*** creating entropy thread 03\n", i);
#endif

    if (OK > (status = RTOS_createThread(entropyThread3, &eb, (sbyte4)ENTROPY_THREAD, &ethread03)))
        goto exit;

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("*** entropy threads created \n", i);
#endif

    while (eb.ethread01running || eb.ethread02running || eb.ethread03running)
    {
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
        PRINTDBG("*** ethreads running\n");
#endif
        RNG_scramble(&eb.ctx);
		sleepTime = (((RTOS_deltaMS(&startTime, &outTime) >> 1) & 0xFF) + 1);
        RTOS_sleepMS(sleepTime);
    }

    /* xor result to heap context */
    DIGI_XORCPY(pRngFipsCtx->result, eb.ctx.result, sizeof(pRngFipsCtx->result));
    DIGI_XORCPY(pRngFipsCtx->key, eb.ctx.scratch, sizeof(pRngFipsCtx->key));
    DIGI_XORCPY(pRngFipsCtx->scratch, eb.ctx.key, sizeof(pRngFipsCtx->scratch));

    RNG_scramble(pRngFipsCtx);

    /* overwrite static context with RNG data */
    if (OK > (status = RANDOM_numberGeneratorFIPS186((randomContext *)pWrapper,
                                                     eb.ctx.key, sizeof(eb.ctx.key))) ||
        OK > (status = RANDOM_numberGeneratorFIPS186((randomContext *)pWrapper,
                                                     eb.ctx.scratch, sizeof(eb.ctx.scratch))))
    {
        goto exit;
    }

#if (defined(__KERNEL__))
	#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
		PRINTDBG("*** entropy threads already done. Not destoying them.\n");
	#endif
#else
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
	PRINTDBG("*** Calling destroyThread on entropy threads.\n");
#endif
    RTOS_destroyThread(ethread01);
    RTOS_destroyThread(ethread02);
    RTOS_destroyThread(ethread03);
#endif
#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_DEBUGGING__
    PRINTDBG("*** entropy threads done\n");
#endif

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_PERFMON__
    perfEndTime = RTOS_getUpTimeInMS();
    PRINTDBG("E-PERF: RANDOM_acquireContext: Entropy threads ran for %d milliseconds\n",(perfEndTime-perfStartThreadTime));
#endif


    	PERFMON_dump_thread_counters();
    	PERFMON_dump_log_tids();
    } /* if (mEntropySource == ENTROPY_SRC_INTERNAL) */

#endif /* ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__ */

    if (OK > (status = RANDOM_numberGeneratorFIPS186((randomContext *)pWrapper, pRngFipsCtx->key, sizeof(pRngFipsCtx->key))))
        goto exit;


#endif

    pWrapper->reseedBitCounter = 0;
    *ppCtx = (randomContext *)pWrapper;
    pWrapper = NULL;

#ifdef __ENABLE_DIGICERT_RAND_ENTROPY_THREADS_PERFMON__
    perfEndTime = RTOS_getUpTimeInMS();
    PRINTDBG("E-PERF: RANDOM_acquireContext: Done. Total process took %d milliseconds\n",(perfEndTime-perfStartTime));
#endif

exit:
    RANDOM_deleteFIPS186Context((randomContext**) &pWrapper);
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_RNG_FIPS186,0);
    return status;
}


/*--------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS RANDOM_seedFIPS186Context (
  randomContext *pRandomCtx,
  ubyte *seed,
  ubyte4 seedLen
  )
{
  RandomCtxWrapper *pWrapper;
  rngFIPS186Ctx *pRngFipsCtx;
  MSTATUS status = ERR_NULL_POINTER;
  if (NULL == pRandomCtx || NULL == seed)
    goto exit;

  pWrapper = (RandomCtxWrapper *)pRandomCtx;
  pRngFipsCtx = GET_FIPS186_CTX(pWrapper);

  status = ERR_RAND_INVALID_CONTEXT;
  if (NULL == pRngFipsCtx)
    goto exit;

  status = DIGI_MEMCPY(pRngFipsCtx->key, seed, seedLen);
  pWrapper->reseedBitCounter = 0;

exit:
  return status;

} /* RANDOM_seedFIPS186Context */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
RANDOM_numberGeneratorFIPS186(randomContext *pRandomContext, ubyte *pRetRandomBytes,
                       sbyte4 numRandomBytes)
{
    FIPS_LOG_DECL_SESSION;
    RandomCtxWrapper* pWrapper = NULL;
    rngFIPS186Ctx*  pRngFipsCtx = NULL;
    sbyte4          bytesToCopy;
    MSTATUS         status = OK;
    sbyte4          i,j;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_RNG_FIPS186,0);

    if ( !numRandomBytes)
    {
        status = OK;
        goto exit;
    }

    if ( !pRandomContext || !pRetRandomBytes)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pWrapper = (RandomCtxWrapper*)pRandomContext;
    pRngFipsCtx = GET_FIPS186_CTX(pWrapper);
    if (pRngFipsCtx == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

   /* Acquire the mutex before accessing context members shared among threads */
   if ( OK > ( status = RTOS_mutexWait(pRngFipsCtx->rngMutex) ) )
       goto exit;

    while (numRandomBytes)
    {
        if (numRandomBytes <= (sbyte4)pRngFipsCtx->numBytesAvail)
            bytesToCopy = numRandomBytes;
        else
            bytesToCopy = (sbyte4)pRngFipsCtx->numBytesAvail;

        if (0 < bytesToCopy)
        {
            DIGI_MEMCPY(pRetRandomBytes,
                       pRngFipsCtx->result +
                       (2 * SHA1_RESULT_SIZE - pRngFipsCtx->numBytesAvail),
                       bytesToCopy);

            pRngFipsCtx->numBytesAvail = pRngFipsCtx->numBytesAvail - bytesToCopy;
            pRetRandomBytes = pRetRandomBytes + bytesToCopy;
            numRandomBytes  = numRandomBytes  - bytesToCopy;
        }

        if (0 >= pRngFipsCtx->numBytesAvail)
        {
            for (i = 0; i < 2; ++i)
            {
                ubyte* w = pRngFipsCtx->result + i * SHA1_RESULT_SIZE;

                DIGI_MEMCPY( pRngFipsCtx->scratch, pRngFipsCtx->key, pRngFipsCtx->b);

                /* add the seed to the key in the scratch area */
                if (pRngFipsCtx->pSeed && pRngFipsCtx->seedLen>0)
                {
                    RNG_add( (ubyte*) pRngFipsCtx->scratch, pRngFipsCtx->b,
                             (const ubyte*) pRngFipsCtx->pSeed, pRngFipsCtx->seedLen, 0);
                    pRngFipsCtx->seedLen -= pRngFipsCtx->b;
                    if (pRngFipsCtx->seedLen > 0 )
                    {
                        pRngFipsCtx->pSeed += pRngFipsCtx->b;
                    }
                }

                /* pad with 0 to 512 bits */
                for (j = pRngFipsCtx->b; j < 64; ++j)
                {
                    pRngFipsCtx->scratch[j] = 0;
                }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                CRYPTO_INTERFACE_SHA1_G( pRngFipsCtx->scratch, w);
#else
                SHA1_G( pRngFipsCtx->scratch, w);
#endif
                RNG_add( (ubyte*) pRngFipsCtx->key, pRngFipsCtx->b, (ubyte*) w, SHA1_RESULT_SIZE, 1);
            }

            pRngFipsCtx->numBytesAvail = 2 * SHA1_RESULT_SIZE;
        }
    }

	RTOS_mutexRelease(pRngFipsCtx->rngMutex);

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_RNG_FIPS186,0);
    return status;
}

/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_KSRC_GENERATOR__))

extern MSTATUS
RANDOM_KSrcGenerator(randomContext *pRandomContext, ubyte buffer[40])
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    RandomCtxWrapper* pWrapper = NULL;
    rngFIPS186Ctx*  pRngFipsCtx = NULL;
    sbyte4          i,j;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_RNG_FIPS186,0);

    if ( !pRandomContext || !buffer)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pWrapper = (RandomCtxWrapper*)pRandomContext;
    pRngFipsCtx = GET_FIPS186_CTX(pWrapper);
    if (pRngFipsCtx == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (i = 0; i < 2; ++i)
    {
        ubyte* w = buffer + i * SHA1_RESULT_SIZE;

        DIGI_MEMCPY( pRngFipsCtx->scratch, pRngFipsCtx->key, pRngFipsCtx->b);

        /* pad with 0 to 512 bits */
        for (j = pRngFipsCtx->b; j < 64; ++j)
        {
            pRngFipsCtx->scratch[j] = 0;
        }
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_SHA1_GK( pRngFipsCtx->scratch, w);
#else
        SHA1_GK( pRngFipsCtx->scratch, w);
#endif
        RNG_add( (ubyte*) pRngFipsCtx->key, pRngFipsCtx->b,
                 (const ubyte*) w, SHA1_RESULT_SIZE, 1);
    }

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_RNG_FIPS186,0);
    return status;
}

#endif /* if (!defined(__DISABLE_DIGICERT_KSRC_GENERATOR__)) */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ADD_ENTROPY__

static MSTATUS
RANDOM_addEntropyBitFIPS186(randomContext *pRandomContext, ubyte entropyBit)
{
    FIPS_LOG_DECL_SESSION;
    RandomCtxWrapper* pWrapper = NULL;
    rngFIPS186Ctx*  pRngFipsCtx = NULL;
    ubyte4          modVal;
    ubyte4          bitPos;
    MSTATUS         status = OK;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_RNG_FIPS186,0);

    if (NULL == pRandomContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pWrapper = (RandomCtxWrapper*)pRandomContext;

    pRngFipsCtx = GET_FIPS186_CTX(pWrapper);
    if (pRngFipsCtx == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pWrapper->reseedBitCounter++;

    modVal = (8 * pRngFipsCtx->b);

    bitPos = pRngFipsCtx->bitPos = ((pRngFipsCtx->bitPos + 1) % modVal);

    if (entropyBit & 1)
    {
        ubyte4  index       = ((bitPos >> 3) % pRngFipsCtx->b);
        ubyte4  bitIndex    = (bitPos & 7);
        ubyte   byteXorMask = (1 << bitIndex);

        pRngFipsCtx->key[index] = pRngFipsCtx->key[index] ^ byteXorMask;
    }
exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_RNG_FIPS186,0);
    return status;
}

#endif /* ifndef __DISABLE_DIGICERT_ADD_ENTROPY__ */
#endif /* ifndef __DISABLE_DIGICERT_FIPS186_RNG__ */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_NIST_CTR_DRBG__

static MSTATUS
RANDOM_acquireDRBGCTRContext(randomContext **ppRandomContext)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    randomContext* newCTRContext = 0;
    RandomCtxWrapper* pWrapper = NULL;
    ubyte4 persoStrLen;
    ubyte* persoStr;
    /* we use the vetted Entropy approach used for FIPS 186 and
    use the resulting FIPS 186 context 512 bits key as the initial
    entropy and nonce for the DRBG context.
    if no derivation function used:
    SeedLen = entropy length:(SP800-90)
    AES128 256 bits
    AES192 320 bits
    AES256 384 bits
    */
    ubyte entropyBytes[MOC_DEFAULT_NUM_ENTROPY_BYTES];
    hwAccelDescr hwAccelCtx = 0;

#if( defined(__ENABLE_DIGICERT_FIPS_MODULE__) )
    NIST_CTR_DRBG_Ctx* pCtx;
#endif

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DRBG_CTR); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DRBG_CTR,0);

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
    if (mEntropySource == ENTROPY_SRC_INTERNAL)
      status = RNG_SEED_extractDepotBits(entropyBytes, MOC_DEFAULT_NUM_ENTROPY_BYTES);
    else
      status = RNG_SEED_extractInitialDepotBits(entropyBytes, MOC_DEFAULT_NUM_ENTROPY_BYTES);
#else
    status = RNG_SEED_extractDepotBits(entropyBytes, MOC_DEFAULT_NUM_ENTROPY_BYTES);
#endif

    if (OK != status)
      goto exit;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
    {
        goto exit;
    }

    persoStr = DIGICERT_RNG_GET_PERSONALIZATION_STRING( &persoStrLen);

    /* we always use the biggest entropy to provide for the maximum security
     * strength. Example: generating AES 256 keys */
#ifndef __DISABLE_DIGICERT_AES_ECB__
    status = NIST_CTRDRBG_newDFContext (
        MOC_SYM(hwAccelCtx) &newCTRContext,
      NIST_CTRDRBG_DEFAULT_KEY_LEN_BYTES,
      NIST_CTRDRBG_DEFAULT_OUT_LEN_BYTES,
        entropyBytes, MOC_DEFAULT_NUM_ENTROPY_BYTES,
        NULL, 0, persoStr, persoStrLen);
#elif (!defined(__DISABLE_3DES_CIPHERS__))
    status = NIST_CTRDRBG_newDFContext(
        MOC_SYM(hwAccelCtx) &newCTRContext, 21, THREE_DES_BLOCK_SIZE,
        entropyBytes, MOC_DEFAULT_NUM_ENTROPY_BYTES, NULL, 0,
        persoStr, persoStrLen);
#else
    status = ERR_RAND;
#endif
    if (OK != status)
      goto exit;

    pWrapper = (RandomCtxWrapper*)newCTRContext;
    pWrapper->reseedBitCounter = 0;

    pWrapper->hwAccelCtx = hwAccelCtx;
    hwAccelCtx = 0;

#if( defined(__ENABLE_DIGICERT_FIPS_MODULE__) )
    pCtx = GET_CTR_DRBG_CTX(pWrapper);
    U8INIT(pCtx->reseedCounter, 0x00010000, 0x00000000);
#endif /* ( defined(__ENABLE_DIGICERT_FIPS_MODULE__) ) */

    *ppRandomContext = newCTRContext;
    newCTRContext = 0;

exit:

    NIST_CTRDRBG_deleteContext( MOC_SYM(pWrapper->hwAccelCtx) &newCTRContext);
    DIGI_MEMSET( entropyBytes, 0, MOC_DEFAULT_NUM_ENTROPY_BYTES);

    if (OK != status && hwAccelCtx)
    {
        (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_DRBG_CTR,0);
    return status;
}

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ADD_ENTROPY__

static MSTATUS
RANDOM_addEntropyBitDRBGCTR(randomContext *pRandomContext, ubyte entropyBit)
{
    FIPS_LOG_DECL_SESSION;
    RandomCtxWrapper* pWrapper = NULL;
    NIST_CTR_DRBG_Ctx* pCtx = NULL;

    MSTATUS         status = OK;

    ubyte4 MinBitsNeeded;
    ubyte entropyBytes[MOC_DEFAULT_NUM_ENTROPY_BYTES];

    /* we are using the same vetted Entropy approach used as the one used above
     * when creating the DBRG context which we'll be reseeding.
     * See comments above for length discussion
     * */

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DRBG_CTR); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DRBG_CTR,0);

    if (NULL == pRandomContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pWrapper = (RandomCtxWrapper*)pRandomContext;

    pCtx = GET_CTR_DRBG_CTX(pWrapper);
    if (pCtx == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* First add the bit into our EntropyDepot */
    if (OK > ( status = RNG_SEED_addEntropyBit(entropyBit)))
    {
        goto exit;
    }
    pWrapper->reseedBitCounter++;

    /* If we have "enough" new entropy bits, then reseed our context */
    MinBitsNeeded = MOC_DEFAULT_NUM_ENTROPY_BYTES * 8;

    if (pWrapper->reseedBitCounter < MinBitsNeeded)
    {
        goto exit;
    }

    if (mEntropySource == ENTROPY_SRC_INTERNAL)
    {
        status = RNG_SEED_extractDepotBits(entropyBytes, MOC_DEFAULT_NUM_ENTROPY_BYTES);
    }
    else
    {
        status = RNG_SEED_extractInitialDepotBits(entropyBytes, MOC_DEFAULT_NUM_ENTROPY_BYTES);
    }
    if (OK != status)
        goto exit;

    status = NIST_CTRDRBG_reseed(MOC_SYM(pWrapper->hwAccelCtx) pRandomContext,
      entropyBytes,
      MOC_DEFAULT_NUM_ENTROPY_BYTES,
      NULL,
      0);
    if (OK != status)
      goto exit;

    pWrapper->reseedBitCounter = 0;  /* Reset the counter */

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_DRBG_CTR,0);
    return status;
}

#endif /* ifndef __DISABLE_DIGICERT_ADD_ENTROPY__ */
#endif /* ifndef __DISABLE_DIGICERT_NIST_CTR_DRBG__ */

/*------------------------------------------------------------------*/


#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__

extern MSTATUS
RANDOM_acquireContextEx(randomContext **pp_randomContext, ubyte algoId)
{
    MSTATUS status;

    status = ERR_NULL_POINTER;
    if (!pp_randomContext)
      goto exit;

    if (algoId == MODE_RNG_ANY)
    {
        algoId = RANDOM_DEFAULT_ALGO; /* The caller doesn't care, so we choose for him. */
    }
    switch (algoId)
    {
#ifndef __DISABLE_DIGICERT_FIPS186_RNG__
    case MODE_RNG_FIPS186:
        status = RANDOM_acquireFIPS186Context( pp_randomContext, MOCANA_RNG_DEFAULT_KEY_SIZE);
        break;
#endif
#ifndef __DISABLE_DIGICERT_NIST_CTR_DRBG__
    case MODE_DRBG_CTR:
        status = RANDOM_acquireDRBGCTRContext(pp_randomContext);
        break;
#endif
    default:
        status = ERR_INVALID_ARG;
        break;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
RANDOM_releaseContextEx(randomContext **pp_randomContext)
{
    /* This function handles all types. */
    MSTATUS status;
    RandomCtxWrapper* pWrapper = NULL;
    hwAccelDescr hwAccelCtx = 0;

    if (!pp_randomContext || !*pp_randomContext)
    {
        return ERR_NULL_POINTER;
    }
    pWrapper = (RandomCtxWrapper*)(*pp_randomContext);

    if (IS_FIPS186_CTX(pWrapper))
    {
#ifndef __DISABLE_DIGICERT_FIPS186_RNG__
        status = RANDOM_deleteFIPS186Context( pp_randomContext);
#else
        status = ERR_INVALID_INPUT;
#endif
    }
    else if (IS_CTR_DRBG_CTX(pWrapper))
    {
#ifndef __DISABLE_DIGICERT_NIST_CTR_DRBG__

        hwAccelCtx = pWrapper->hwAccelCtx;

        status = NIST_CTRDRBG_deleteContext( MOC_SYM(hwAccelCtx) pp_randomContext);
#else
        status = ERR_INVALID_INPUT;
#endif
    }
    else
    {
        status = ERR_NULL_POINTER;
    }

    RNG_SEED_freeDepotState();

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;
}

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ADD_ENTROPY__

extern MSTATUS
RANDOM_addEntropyBitEx(randomContext *pRandomContext, ubyte entropyBit)
{
    RandomCtxWrapper* pWrapper = NULL;
    MSTATUS         status = OK;

    if (NULL == pRandomContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pWrapper = (RandomCtxWrapper*)pRandomContext;

    if (IS_FIPS186_CTX(pWrapper))
    {
#ifndef __DISABLE_DIGICERT_FIPS186_RNG__
        status =  RANDOM_addEntropyBitFIPS186(pRandomContext, entropyBit);
#else
        status = ERR_INVALID_INPUT;
#endif
    }
#ifndef __DISABLE_DIGICERT_NIST_CTR_DRBG__
    else if (IS_CTR_DRBG_CTX(pWrapper))
    {
        status =  RANDOM_addEntropyBitDRBGCTR(pRandomContext, entropyBit);
    }
#endif
#if (defined(__ENABLE_DIGICERT_SYM__))
    else if (IS_MOC_RAND(pWrapper))
    {
        status =  CRYPTO_seedRandomContext (pRandomContext, NULL, &entropyBit, 1);
    }
#endif
    else
    {
        status = ERR_NULL_POINTER;
    }

exit:
    return status;
}

#endif /* ifndef __DISABLE_DIGICERT_ADD_ENTROPY__ */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS RANDOM_generateASCIIString(randomContext *pRandomContext, ubyte *pBuffer, ubyte4 bufferLen)
{
     MSTATUS status;
     ubyte4 totalLen, tempLen, index;
     ubyte currByte;
     ubyte temp[64];

    /* Check the args  */
    if ((NULL == pRandomContext) || (NULL == pBuffer))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* The min and max allowed are somewhat arbitrary, and another implementation
     * might allow 0 length input, or have no logical max or might choose a
     * different max.
     */
    if ((bufferLen < MOCANA_ASCII_STRING_MIN_LEN) || (bufferLen > MOCANA_ASCII_STRING_MAX_LEN))
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* Init index to tempLen, meaning we don't have any fresh random bytes in the
     * temp buffer.
     */
    totalLen = bufferLen;
    tempLen = sizeof(temp);
    index = tempLen;
    while (totalLen > 0)
    {
      /* If we ran out of temp bytes, generate some more */
      if (index >= tempLen)
      {
        status = RANDOM_numberGenerator(pRandomContext, (ubyte *)temp, sizeof(temp));
        if (OK != status)
          goto exit;

        index = 0;
      }

      /* Get the next byte of random.
       * Get rid of the most significant bit. This means that we're mapping 0x80
       * to 0x00, 0x81 to 0x01, and so on.
       */
      currByte = temp[index] & 0x7F;
      index++;

      /* If the value is an accepted character, keep it. If not, throw it away.
       *   currByte < 0x30, reject
       *   0x39 < currByte < 0x41, reject
       *   0x5A < currByte < 0x61, reject
       *   currByte > 0x7A, reject
       *
       * If the value is to be rejected, just continue on to the next byte.
       * Further work: generalize this.
       */
      if (currByte < 0x30)
        continue;
      if (currByte > 0x7A)
        continue;

    /* At this point, we know that 0x30 <= current <= 0x7a
     * If current <= 0x39, it's a number, so keep it. If it is > 0x39 we'll
     * need to make some more tests, but if not, drop to the code that copies
     * current.
     */
      if (currByte > 0x39)
      {
      /* At this point, we know that 0x3A <= current <= 0x7A
       * If current is also < 0x41, it is not an ASCII character, just move on.
       */
        if (currByte < 0x41)
          continue;

      /* At this point, we know that 0x41 <= current <= 0x7A. If it is also <=
       * 0x5A, then it is an upper-case letter, keep it. If > 0x5A, we'll need
       * to make more tests.
       */
        if (currByte > 0x5A)
        {
          /* If we reach this point, 0x5A < currByte, this check will then
           * complete the check 0x5A < currByte < 0x61
           */
          if (currByte < 0x61)
            continue;
        }
      }

      /* If we reach this point, the byte was not rejected, so use it.
       * We're filling the output buffer from the end, just to avoid creating
       * another variable.
       */
      pBuffer[totalLen - 1] = currByte;
      totalLen--;
    }

  status = OK;

exit:

  DIGI_MEMSET ((ubyte *)temp, 0, sizeof (temp));

  return status;
}

#endif /* ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ */
#endif /* ifndef __DISABLE_DIGICERT_RNG__ */
