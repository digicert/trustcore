/*
 * ucos_rtos.c
 *
 * uC/OS RTOS Abstraction Layer
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

/* Note: This file is not built as part of the standard Mocana DSF build process,
regardless of whether __UCOS_DIRECT_RTOS__ is defined or not.

It is part of the uC-OS support that is only built by using the Micrium supplied
application project files. */

#include "../common/moptions.h"

#ifdef __UCOS_DIRECT_RTOS__

//#include "../uCOS-III/source/os.h"
#include <os.h>
#include <net.h>

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"


/*#include "../common/constants.h"*/
#include "../common/utils.h"
#include "clk.h"


#ifndef MOCANA_UCOS_RTOS_MUTEX_LOW_PRIO
#define MOCANA_UCOS_RTOS_MUTEX_LOW_PRIO     (25)    /* you will need to custom priorities based on your design */
#endif

#ifndef MOCANA_UCOS_RTOS_THREAD_LOW_PRIO
#define MOCANA_UCOS_RTOS_THREAD_LOW_PRIO    (50)    /* you will need to custom priorities based on your design */
#endif

#ifndef MOCANA_UCOS_RTOS_STACK_SIZE
#define MOCANA_UCOS_RTOS_STACK_SIZE         (2048) /* you will need to custom based on your usage overhead */
#endif

#define _REENTRANT

#define MAX_NUM_THREADS 10

#define INT8U   unsigned char // YD added

static void *pStackBase[MAX_NUM_THREADS];





/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_rtosInit(void)
{
    int i;
    
    for (i = 0; i < MAX_NUM_THREADS; i++)
        pStackBase[i] = NULL;

	// memory pool initialization is done
	// in net_secure.c
	
    return OK;
}



/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_rtosShutdown(void)
{
    int i;

    for (i = 0; i < MAX_NUM_THREADS; i++)
    {
        if (NULL != pStackBase[i])
        {
            FREE(pStackBase[i]);
            pStackBase[i] = NULL;
        }
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    OS_MUTEX*       pTmpMutex = NULL;
    OS_ERR			err;
    MSTATUS         status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

	pTmpMutex = (OS_MUTEX*)MALLOC(sizeof(OS_MUTEX));
	if (NULL == pTmpMutex)
		goto exit;

    OSMutexCreate(pTmpMutex, "", &err);

    if (OS_ERR_NONE != err)
        goto exit;
    
    status = OK;
    *pMutex = (RTOS_MUTEX)pTmpMutex;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_mutexWait(RTOS_MUTEX mutex)
{
    OS_MUTEX*  pMutex_t = mutex;
    OS_ERR   err;
    MSTATUS  status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pMutex_t))
    {
        OSMutexPend(pMutex_t, 0, OS_OPT_PEND_BLOCKING, NULL, &err);

        if (OS_ERR_NONE == err)
            status = OK;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_mutexRelease(RTOS_MUTEX mutex)
{
    OS_MUTEX*  pMutex_t = mutex;
    OS_ERR   err;
    MSTATUS  status = ERR_RTOS_MUTEX_RELEASE;

	OSMutexPost(pMutex_t, OS_OPT_POST_NONE, &err);
    if ((NULL != pMutex_t) && (OS_ERR_NONE == err))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_mutexFree(RTOS_MUTEX* pMutex)
{
    OS_MUTEX*   pMutex_t = *pMutex;
    OS_ERR      err;
    MSTATUS     status = ERR_RTOS_MUTEX_FREE;

    if (NULL == pMutex_t)
        goto exit;

    OSMutexDel(pMutex_t, OS_OPT_DEL_ALWAYS, &err);

    if (OS_ERR_NONE != err) 
        goto exit;
    
    if (NULL != pMutex_t)
		FREE(pMutex_t);

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern ubyte4
UCOS_getUpTimeInMS(void)
{
    ubyte4 ms;
    OS_ERR	err;

    ms = OSTimeGet(&err) * (1000 / OSCfg_TickRate_Hz);

    return ms;
}


/*------------------------------------------------------------------*/

extern ubyte4
UCOS_deltaMS(const moctime_t* origin, moctime_t* current)
{
    ubyte4  retVal = 0;
    OS_ERR	err;
    CPU_INT32U   os_tick_cur;

    os_tick_cur = OSTimeGet(&err);
    
    if (origin)
    {
        retVal = (1000 / OSCfg_TickRate_Hz) * (os_tick_cur - origin->u.time[0]);
    }

    if (current)
    {
        current->u.time[0] = os_tick_cur;
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern void
UCOS_sleepMS(ubyte4 sleepTimeInMS)
{
    OS_ERR	err;

    OSTimeDlyHMSM(0u, 0u, 0u, sleepTimeInMS,
                    OS_OPT_TIME_HMSM_NON_STRICT,
                    &err);
}



/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    //static int threadPrio = MOCANA_UCOS_RTOS_THREAD_LOW_PRIO;
    static OS_PRIO entropyThreadPrio = 9;
    OS_PRIO threadPrio = 10;
    ubyte4  stackSize = ((MOCANA_UCOS_RTOS_STACK_SIZE & 0xfffffffc) + 4);       /* ensure stack size is multiple of 4 */
    //ubyte4    retVal;
    int     i;
    void*   pStackSpace;
    void*   pStackStart;
    //void*   pStackEnd;
    MSTATUS status = ERR_RTOS_THREAD_CREATE;

    if (NULL == (pStackSpace = MALLOC(stackSize)))
        goto exit;

    /* stack must be 4 byte (long) aligned !!! */
    if ((ubyte4)pStackSpace & 0x3)
    {
        /* i would be shocked to see memory allocation that doesn't */
        /* allocate on minimally four byte boundary, but apparently it could happen... */
        pStackStart = (void*)((ubyte4)pStackSpace + (4 - ((ubyte4)pStackSpace & 0x3)));          /* align start */
        // unused
        //pStackEnd   = (void*)((ubyte4)pStackSpace + stackSize - ((ubyte4)pStackSpace & 0x3));    /* align end   */
    }
    else
    {
        /* we're safe --- 4 byte aligned */
        pStackStart = pStackSpace;
        // unused
        //pStackEnd   = (void*)((ubyte4)pStackSpace + stackSize);
    }

    for (i = 0; i < MAX_NUM_THREADS; i++)
    {
        if (NULL == pStackBase[i])
        {
			OS_ERR	os_err;
			OS_TCB	*tcb = NULL;
			//CPU_CHAR name[10];
			
			tcb = (OS_TCB*)MALLOC(sizeof(OS_TCB));
			if (NULL == tcb)
			{
				goto exit;
			}
			
			//sprintf(name, "%p", tcb);
			if (threadType == ENTROPY_THREAD)
            {
                entropyThreadPrio++;
                threadPrio = entropyThreadPrio;
            }
            
			OSTaskCreate((OS_TCB      *)tcb,
                 (CPU_CHAR    *)"",
                 (OS_TASK_PTR  )threadEntry,
                 (void        *)context,
                 (OS_PRIO      )threadPrio,
                 (CPU_STK     *)pStackStart,
                 (CPU_STK_SIZE )((stackSize * (100u-90u))/100u),
                 (CPU_STK_SIZE )stackSize,
                 (OS_MSG_QTY   )0u,
                 (OS_TICK      )0u,
                 (void        *)0,
                 (OS_OPT       )(OS_OPT_TASK_STK_CHK | OS_OPT_TASK_STK_CLR),
                 (OS_ERR      *)&os_err);
			
			if (OS_ERR_NONE == os_err)
            {
                pStackBase[i] = pStackSpace;
                status = OK;
                *pRetTid = (RTOS_THREAD)tcb;
            }
            else
            {
                if (NULL != tcb)
					FREE(tcb);
            }

            break;
        }
    }

exit:
    if (OK > status)
    {
        if (NULL != pStackSpace)
            FREE(pStackSpace);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern void
UCOS_destroyThread(RTOS_THREAD tid)
{
	OS_TCB	*tcb = (OS_TCB*)tid;
    FREE(tcb);
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_timeGMT(TimeDate* td)
{
    CLK_DATE_TIME     localTime;
    
    if (NULL == td)
        return ERR_NULL_POINTER;

    Clk_GetDateTime(&localTime);

    td->m_year   = localTime.Yr;
    td->m_month  = localTime.Month;
    td->m_day    = localTime.Day;
    td->m_hour   = localTime.Hr;
    td->m_minute = localTime.Min;
    td->m_second = localTime.Sec;

    return OK;
}


extern void *UCOS_malloc(size_t size)
{

	void *rc;
	NET_ERR err;

    rc = NetSecure_BlkGet(0, size, &err);
	
	return rc;
}



extern void UCOS_free(void *ptr)
{

	NET_ERR err;

    if (ptr)
        NetSecure_BlkFree(0, ptr, &err);
}

    
#endif /* __UCOS_DIRECT_RTOS__ */


