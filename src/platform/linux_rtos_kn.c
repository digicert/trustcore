/*
 * linux_rtos_kn.c
 *
 * Linux RTOS Abstraction Layer (Kernel Mode)
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../common/moptions.h"

#if (defined(__LINUX_RTOS__) || defined (__ANDROID_RTOS__)) && defined(__KERNEL__)

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26))
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/slab.h>


#include <linux/kthread.h>

#include <linux/kernel.h>
#include <linux/string.h>

#ifdef  __ENABLE_MOC_KERNEL_THREADS_DEBUGGING__
	#define PRINTDBG printk
#else
	#define PRINTDBG
#endif

#define NANOS 1000000000
#define _REENTRANT


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_rtosInit(void)
{
#if defined(__MOC_PLATFORM_MODULE__)
    if (0 == DIGI_rtosInit())
        return OK;
    else
        return ERR_GENERAL;
#else
    return OK;
#endif /* __MOC_PLATFORM_MODULE__ */
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_rtosShutdown(void)
{
#if defined(__MOC_PLATFORM_MODULE__)
    if (0 == DIGI_rtosShutdown())
        return OK;
    else
        return ERR_GENERAL;
#else
    return OK;
#endif /* __MOC_PLATFORM_MODULE__ */
}

/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_mutexCreate(RTOS_MUTEX * pMutex, enum mutexTypes mutexType,
          int mutexCount)
{
#if defined(__MOC_PLATFORM_MODULE__)
    if (0 == DIGI_mutexCreate2(pMutex,mutexCount))
        return OK;
    else
        return ERR_RTOS_MUTEX_CREATE;
#else
    struct mutex     *mutex;
    MSTATUS          status = OK;
    MOC_UNUSED(mutexCount);

    if (NULL == (mutex = MALLOC(sizeof(*mutex)))) {
        status = ERR_RTOS_MUTEX_CREATE;
    goto exit;
    }

    mutex_init(mutex);
    *pMutex = (RTOS_MUTEX)mutex;

  exit:
    return status;

#endif /* __MOC_PLATFORM_MODULE__ */
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_mutexWait(RTOS_MUTEX mutex)
{
#if defined(__MOC_PLATFORM_MODULE__)
    if (0 == DIGI_mutexWait(mutex))
        return OK;
    else
        return ERR_RTOS_MUTEX_WAIT;
#else
    struct mutex *sem = (struct mutex *)mutex;
    MSTATUS status = OK;

    if (NULL != sem) {
        mutex_lock(sem);
    }
    return status;
#endif /* __MOC_PLATFORM_MODULE__ */
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_mutexRelease(RTOS_MUTEX mutex)
{
#if defined(__MOC_PLATFORM_MODULE__)
    if (0 == DIGI_mutexRelease(mutex))
        return OK;
    else
        return ERR_RTOS_MUTEX_RELEASE;
#else
    struct mutex *sem = (struct mutex *)mutex;
    MSTATUS status = OK;

    if (NULL != sem) {
        mutex_unlock(sem);
    }
    return status;
#endif /* __MOC_PLATFORM_MODULE__ */
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_mutexFree(RTOS_MUTEX * pMutex)
{
#if defined(__MOC_PLATFORM_MODULE__)
    if (0 == DIGI_mutexFree(pMutex))
        return OK;
    else
        return ERR_RTOS_MUTEX_FREE;
#else
    MSTATUS status = OK;

    if ((NULL == pMutex) || (NULL == *pMutex))
    {
        status = ERR_RTOS_MUTEX_FREE;
        goto exit;
    }

    FREE(*pMutex);
    *pMutex = NULL;

  exit:
    return status;
#endif /* __MOC_PLATFORM_MODULE__ */
}

/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
	// Kernel version
    int         ret = 0;
    MSTATUS     status  = OK;
	struct task_struct *pTaskSt = NULL;

	#ifdef  __ENABLE_MOC_KERNEL_THREADS_DEBUGGING__
		PRINTDBG("LINUX_createThread: Calling kthread_run w/ FuncPtr=%p context=%p\n", threadEntry, context);
	#endif

	pTaskSt = kthread_run((int (*)(void *))threadEntry, (void *)context, "MocThead");
	if (IS_ERR(pTaskSt))
    {

		#ifdef  __ENABLE_MOC_KERNEL_THREADS_DEBUGGING__
			PRINTDBG("LINUX_createThread: Bad. returning ERR_RTOS_THREAD_CREATE\n");
		#endif

        DEBUG_ERROR(DEBUG_PLATFORM, "LINUX_createThread: kthread_run error ", ret);
        status = ERR_RTOS_THREAD_CREATE;
    }
	else
	{

		#ifdef  __ENABLE_MOC_KERNEL_THREADS_DEBUGGING__
			PRINTDBG("LINUX_createThread: returning successful kthread_run w/ pTaskSt=%p\n", pTaskSt);
		#endif

	    *pRetTid = (RTOS_THREAD *)pTaskSt;
	}
    return status;

}


/*------------------------------------------------------------------*/

extern void
LINUX_destroyThread(RTOS_THREAD tid)
{
	// Kernel version
	struct task_struct *pTaskSt = (struct task_struct *)tid;

	if (pTaskSt)
	{

		#ifdef  __ENABLE_MOC_KERNEL_THREADS_DEBUGGING__
			PRINTDBG("LINUX_destroyThread: Calling kthread_stop w/ pTaskSt=%p\n", pTaskSt);
		#endif

		kthread_stop(pTaskSt);

		#ifdef  __ENABLE_MOC_KERNEL_THREADS_DEBUGGING__
			PRINTDBG("LINUX_destroyThread: Back from kthread_stop w/ pTaskSt=%p\n", pTaskSt);
		#endif

	}
}


/*------------------------------------------------------------------*/

extern sbyte4
LINUX_currentThreadId(void)
{
	#ifdef  __ENABLE_MOC_KERNEL_THREADS_DEBUGGING__
		PRINTDBG("LINUX_currentThreadId: Bad. This function is returning NULL.\n");
	#endif
	return 0;
}


/*------------------------------------------------------------------*/

extern ubyte4
LINUX_getUpTimeInMS(void)
{
#if defined(__MOC_PLATFORM_MODULE__)
    return DIGI_getUpTimeInMS();
#else
    long long jiff = get_jiffies_64() * 1000;
    do_div (jiff, HZ);
    return (ubyte4)jiff;
#endif /* __MOC_PLATFORM_MODULE__ */
}


/*------------------------------------------------------------------*/

extern void
LINUX_sleepMS(ubyte4 sleepTimeInMS)
{
#if defined(__MOC_PLATFORM_MODULE__)
    DIGI_sleepMS(sleepTimeInMS);
#else
    int tval = (sleepTimeInMS*HZ+999)/1000;

    schedule_timeout(tval);
#endif /* __MOC_PLATFORM_MODULE__ */
}


/*------------------------------------------------------------------*/

extern ubyte4
LINUX_deltaMS(const moctime_t* origin, moctime_t* curtime)
{
#if defined(__MOC_PLATFORM_MODULE__)
    return DIGI_deltaMS(origin,curtime);
#else
    ubyte4 retVal = 0;

    long long jiff = get_jiffies_64();

    /* origin and current can point to the same struct */
    if (origin)
    {
        long long diff;
        diff   = (jiff - origin->u.jiffies) * 1000;
        do_div(diff, HZ);
        retVal = (ubyte4)diff;
    }

    if (curtime)
    {
        curtime->u.jiffies = jiff;
    }

    return retVal;
#endif /* __MOC_PLATFORM_MODULE__ */
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_timeGMT(TimeDate* td)
{
#if defined(__MOC_PLATFORM_MODULE__)
    if (0 == DIGI_timeGMT(td))
        return OK;
    else
        return ERR_GENERAL;
#else

    if (NULL == td)
        return ERR_NULL_POINTER;

    /* Do nothing for now */
    memset(td, 0, sizeof(*td));

    return OK;
#endif /* __MOC_PLATFORM_MODULE__ */
}

/*------------------------------------------------------------------*/
#if !defined(__MOC_PLATFORM_MODULE__)
extern void*
LINUX_malloc(ubyte4 size)
{
    /* Don't know where I'm from, so do it as atomic to be safe */
    return kmalloc(size, GFP_ATOMIC);
}


/*------------------------------------------------------------------*/

extern void
LINUX_free(void *data)
{
    return kfree(data);
}
#endif

/*------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_DEBUG_CONSOLE__
/* Stick here temporarily to support kernel use */
extern void
DEBUG_CONSOLE_printError(sbyte4 errorClass, sbyte *pPrintString, sbyte4 value)
{
    printk("%s %d\n", pPrintString, value);
}
#endif

#endif /* (defined(__LINUX_RTOS__) && defined(__KERNEL__)) */
