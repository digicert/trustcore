/*
 * ucos_rtos.c
 *
 * uC/OS RTOS Abstraction Layer for UCOS 3
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

#ifdef __UCOS_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <cpu.h>
#include <os_type.h>
#include <os.h>
#include <clk.h>

#ifndef MOCANA_UCOS_RTOS_MUTEX_LOW_PRIO
#define MOCANA_UCOS_RTOS_MUTEX_LOW_PRIO     (25)    /* you will need to custom priorities based on your design */
#endif

#ifndef MOCANA_UCOS_RTOS_THREAD_LOW_PRIO
#define MOCANA_UCOS_RTOS_THREAD_LOW_PRIO    (50)    /* you will need to custom priorities based on your design */
#endif

#ifndef MOCANA_UCOS_RTOS_STACK_SIZE
#define MOCANA_UCOS_RTOS_STACK_SIZE         (8192) /* you will need to custom based on your usage overhead */
#endif

#define MAX_NUM_THREADS  10

#define _REENTRANT

#if __DIGICERT_MAX_INT__ == 64
#define WORD_ALIGN_NUM 8
#define WORD_ALIGN_MASK 0x7
#else
#define WORD_ALIGN_NUM 4
#define WORD_ALIGN_MASK 0x3
#endif

typedef struct
{
    void *pStack;
    ubyte4 stackSize;
    OS_TCB *pTcb;
    byteBoolean used;
} TaskInfo;

static TaskInfo pTaskInfos[MAX_NUM_THREADS];

/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_rtosInit(void)
{
    int i;

    for (i = 0; i < MAX_NUM_THREADS; i++)
    {
        pTaskInfos[i].pStack = NULL;
        pTaskInfos[i].stackSize = 0;
        pTaskInfos[i].pTcb = NULL;
        pTaskInfos[i].used = FALSE;
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_rtosShutdown(void)
{
    int i;

    for (i = 0; i < MAX_NUM_THREADS; i++)
    {
        if (NULL == pTaskInfos[i].pStack)
        {
            DIGI_FREE((void **)&pTaskInfos[i].pStack);
        }
        if (NULL == pTaskInfos[i].pTcb)
        {
            DIGI_FREE((void **)&pTaskInfos[i].pTcb);
        }
        pTaskInfos[i].stackSize = 0;
        pTaskInfos[i].used = FALSE;
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
#if 0
    static INT8U    prio      = MOCANA_UCOS_RTOS_MUTEX_LOW_PRIO;
#endif
    OS_MUTEX*       pNewMutex = NULL;
    OS_ERR           err;
    MSTATUS         status = ERR_RTOS_MUTEX_CREATE;
    CPU_CHAR *pName = "DefaultUCOSMutex";
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    status = DIGI_MALLOC((void **)&pNewMutex, sizeof(OS_MUTEX));
    if (OK != status)
        goto exit;

    OSMutexCreate(pNewMutex, pName, &err);
    if (err != OS_ERR_NONE)
        goto exit;

    *pMutex = pNewMutex;
    pNewMutex = NULL;
    status = OK;

exit:

    if (NULL != pNewMutex)
    {
        DIGI_FREE((void **)&pNewMutex);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_mutexWait(RTOS_MUTEX mutex)
{
    OS_MUTEX*  pMutex = (OS_MUTEX *)mutex;
    OS_ERR    err;
    MSTATUS  status = ERR_RTOS_MUTEX_WAIT;

    if (NULL != pMutex)
    {
        OSMutexPend(pMutex, 0, OS_OPT_PEND_BLOCKING, NULL, &err);

        if (OS_ERR_NONE == err)
            status = OK;
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_mutexWaitEx(RTOS_MUTEX mutex, ubyte4 timeoutMs)
{
    OS_MUTEX*  pMutex = (OS_MUTEX *)mutex;
    OS_ERR    err;
    MSTATUS  status = ERR_RTOS_MUTEX_WAIT;
    OS_TICK  NumOfTick;

    NumOfTick = timeoutMs * OSCfg_TickRate_Hz / 1000;

    if (NULL != pMutex)
    {
        OSMutexPend(pMutex, NumOfTick, OS_OPT_PEND_BLOCKING, NULL, &err);
        if (OS_ERR_NONE == err)
            status = OK;
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_mutexRelease(RTOS_MUTEX mutex)
{
    OS_MUTEX*  pMutex = (OS_MUTEX *)mutex;
    OS_ERR    err;
    MSTATUS  status = ERR_RTOS_MUTEX_RELEASE;

    if (NULL == pMutex)
        goto exit;

    OSMutexPost(pMutex, OS_OPT_POST_NONE, &err);
    if (err == OS_ERR_NONE)
        status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_mutexFree(RTOS_MUTEX* pMutex)
{
    OS_ERR       err;
    MSTATUS     status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    OSMutexDel((OS_MUTEX *)(*pMutex), OS_OPT_DEL_ALWAYS, &err);
    if (OS_ERR_NONE != err)
    	goto exit;

    if (NULL != *pMutex)
    	DIGI_FREE((void **)pMutex);

    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_semCreate(RTOS_SEM *pSem, sbyte4 initialValue)
{
    MSTATUS status = ERR_NULL_POINTER;
    OS_SEM *pNewSem = NULL;
    sbyte *pName = "DefaultSemName";
    OS_ERR err;

    if (NULL == pSem)
        goto exit;

    status = DIGI_MALLOC((void **)&pNewSem, sizeof(OS_SEM));
    if (OK != status)
        goto exit;

    OSSemCreate(*pNewSem, (CPU_CHAR *)pName, (OS_SEM_CTR)initialValue, &err);
    if (OS_ERR_NONE != err)
    	goto exit;

    *pSem = pNewSem;
    pNewSem = NULL;

exit:

    if (NULL != pNewSem)
        DIGI_FREE((void **)&pNewSem);

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_semWait(RTOS_SEM pSem)
{
    OS_ERR err;
    OS_SEM_CTR cnt;

    cnt = OSSemPend(pSem, 0, OS_OPT_PEND_BLOCKING, NULL, &err);

    if (OS_ERR_NONE != err)
    {
        return ERR_RTOS_SEM_WAIT;
    }

    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_semSignal(RTOS_SEM pSem)
{
    OS_ERR err;
    OS_SEM_CTR cnt;

    cnt = OSSemPost(pSem, OS_OPT_POST_1, &err);

    if (OS_ERR_NONE != err)
    {
        return ERR_RTOS_SEM_SIGNAL;
    }

    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_semFree(RTOS_SEM *ppSem)
{
    MSTATUS status;
    OS_ERR err;
    OS_OBJ_QTY ret;
    OS_SEM *pSem;
    OS_SEM sem;

    if ((NULL == ppSem) || (NULL == *ppSem))
    {
        return ERR_NULL_POINTER;
    }

    pSem = (OS_SEM *)*ppSem;

    if (NULL == pSem)
    {
        return ERR_NULL_POINTER;
    }

    ret = OsSemDel(pSem, OS_OPT_DEL_ALWAYS, &err);
    DIGI_FREE((void **)&pSem);

    if (OS_ERR_NONE != err)
    {
        return ERR_RTOS_SEM_FREE;
    }

    return OK;
}

/*------------------------------------------------------------------*/

extern ubyte4
UCOS_getUpTimeInMS(void)
{
    ubyte4 ms;
    OS_ERR       err;

    ms = OSTimeGet(&err) * (1000 / OSCfg_TickRate_Hz);

    return ms;
}


/*------------------------------------------------------------------*/

extern ubyte4
UCOS_deltaMS(const moctime_t* origin, moctime_t* current)
{
    ubyte4  retVal = 0;
    OS_ERR       err;

    if (origin)
    {
        retVal = (1000 / OSCfg_TickRate_Hz) * (OSTimeGet(&err) - origin->u.time[0]);
    }

    if (current)
    {
        current->u.time[0] = OSTimeGet(&err);
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern void
UCOS_sleepMS(ubyte4 sleepTimeInMS)
{
    OS_TICK  NumOfTick;
    OS_ERR       err;

    NumOfTick = sleepTimeInMS * OSCfg_TickRate_Hz / 1000;

    if (0 == NumOfTick)
        NumOfTick = 1;

    OSTimeDly(NumOfTick, OS_OPT_TIME_DLY, &err);
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    static int threadPrio = MOCANA_UCOS_RTOS_THREAD_LOW_PRIO;
    ubyte4  stackSize = ((MOCANA_UCOS_RTOS_STACK_SIZE & 0xfffffff8) + 8);       /* ensure stack size is multiple of 8 */
    int     i;
    void*   pStackSpace = NULL;
    void*   pStackStart = NULL;
    char*   threadName = NULL;
    char    madeupName[20];
    OS_TCB *pTcb = NULL;
    MSTATUS status = ERR_RTOS_THREAD_CREATE;
    OS_ERR err;

    switch (threadType)
    {
        case ENTROPY_THREAD:
        {
            threadName = "mocEntropy";
#ifdef MOCANA_ENTROPY_UCOS_STACK_SIZE
            stackSize  = MOCANA_ENTROPY_UCOS_STACK_SIZE;
#endif
            break;
        }

        case SSL_MAIN:
        {
            threadName = "mocSslMn";
#ifdef MOCANA_SSL_UCOS_STACK_SIZE
            stackSize  = MOCANA_SSL_UCOS_STACK_SIZE;
#endif
            break;
        }

        case SSL_SERVER_SESSION:
        {
            threadName = "mocSslSsn";
#ifdef MOCANA_SSL_UCOS_STACK_SIZE
            stackSize  = MOCANA_SSL_UCOS_STACK_SIZE;
#endif
            break;
        }

        case DTLS_MAIN:
        {
            threadName = "mocDtlsMn";
#ifdef MOCANA_DTLS_UCOS_STACK_SIZE
            stackSize  = MOCANA_DTLS_UCOS_STACK_SIZE;
#endif
            break;
        }

        case SSH_MAIN:
        {
            threadName = "mocSshMn";
#ifdef MOCANA_SSH_UCOS_STACK_SIZE
            stackSize  = MOCANA_SSH_UCOS_STACK_SIZE;
#endif
            break;
        }

        case SSH_SESSION:
        {
            threadName = "mocSsh";
#ifdef MOCANA_SSH_UCOS_STACK_SIZE
            stackSize  = MOCANA_SSH_UCOS_STACK_SIZE;
#endif
            break;
        }
        case EAP_MAIN:
        {
            threadName = "mocEapMn";
#ifdef MOCANA_EAP_UCOS_STACK_SIZE
            stackSize  = MOCANA_EAP_UCOS_STACK_SIZE;
#endif
            break;
        }
        case FIREWALL_MAIN:
        {
            threadName = "mocFWMn";
            break;
        }
        case FIREWALL_SERVER:
        {
            threadName = "mocFWSvr";
            break;
        }

        case HTTP_THREAD:
        {
            threadName = "mocHttp";
#ifdef MOCANA_HTTP_UCOS_STACK_SIZE
            stackSize  = MOCANA_HTTP_UCOS_STACK_SIZE;
#endif
            break;
        }

        case DEBUG_CONSOLE:
        {
            threadName = "mocDbgCon";
#ifdef MOCANA_DEBUG_CON_UCOS_STACK_SIZE
            stackSize  = MOCANA_DEBUG_CON_UCOS_STACK_SIZE;
#endif
            break;
        }

        case MOC_IPV4:
        {
            threadName = "mocIPv4";
            break;
        }

        case HARNESS_MAIN:
        {
            threadName = "mocHarn";
#ifdef MOCANA_HARNESS_MAIN_UCOS_STACK_SIZE
            stackSize  = MOCANA_HARNESS_MAIN_UCOS_STACK_SIZE;
#endif
            break;
        }

        case HARNESS_MAIN1:
        {
            threadName = "mocIpsecHarn";
#ifdef MOCANA_HARNESS_MAIN_UCOS_STACK_SIZE
            stackSize  = MOCANA_HARNESS_MAIN_UCOS_STACK_SIZE;
#endif
            break;
        }

        case IKE_MAIN:
        {
            threadName = "tMocIke";
#ifdef MOCANA_IKE_UCOS_STACK_SIZE
            stackSize  = MOCANA_IKE_UCOS_STACK_SIZE;
#endif
            break;
        }

        case RADIUS_MAIN:
        {
            threadName = "tMocRad";
#ifdef MOCANA_RADIUS_UCOS_STACK_SIZE
            stackSize  = MOCANA_RADIUS_UCOS_STACK_SIZE;
#endif
            break;
        }

        case TP_THREAD:
        {
            threadName = "tplocal";
            break;
        }
        case EST_MAIN:
        {
            threadName = "pEstMain";
            break;
        }
        default:
        {
        /*    status = ERR_RTOS_THREAD_CREATE; */
            DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"UCOS_createThread: unknown thread type.");
            DBUG_PRINT(DEBUG_PLATFORM, ("Unknown threadtype: %d Creating anyway", threadType));
            sprintf(madeupName, "EnumTask%d", threadType);
            threadName = madeupName;
            break;
        }
    }

    for (i = 0; i < MAX_NUM_THREADS; i++)
    {
        /* If we already have an allocated but unused stack of the desired size, use that */
        if ( (FALSE == pTaskInfos[i].used) && (NULL != pTaskInfos[i].pStack) && (stackSize == pTaskInfos[i].stackSize) )
        {
            pStackSpace = pTaskInfos[i].pStack;
            pTcb = pTaskInfos[i].pTcb;
            pTaskInfos[i].used = TRUE;
        }
    }

    /* We could not find an existing stack to use, allocate a new stack and TCB */
    if (NULL == pStackSpace)
    {
        for (i = 0; i < MAX_NUM_THREADS; i++)
        {
            if ( (FALSE == pTaskInfos[i].used) && (NULL == pTaskInfos[i].pStack) )
            {
                status = DIGI_MALLOC((void **)&pStackSpace, stackSize + WORD_ALIGN_NUM);
                if (OK != status)
                    goto exit;

                status = DIGI_CALLOC((void **)&pTcb, 1, sizeof(OS_TCB));
                if (OK != status)
                    goto exit;

                break;
            }
        }
    }

    /* If this is NULL, all our slots already have allocated stacks, fatal error */
    if (NULL == pStackSpace)
    {
    	status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    /* stack must be word aligned !!! */
    if ((long)pStackSpace & WORD_ALIGN_MASK)
    {
        /* i would be shocked to see memory allocation that doesn't */
        /* allocate on minimally word boundary, but apparently it could happen... */
        pStackStart = pStackSpace + (WORD_ALIGN_NUM - ((long)pStackSpace & WORD_ALIGN_MASK));          /* align start */
    }
    else
    {
        /* we're safe --- word aligned */
        pStackStart = pStackSpace;
    }

    /* Create the task with a unique priority */
    OSTaskCreate(
        pTcb,                       /* Task control block */
        (CPU_CHAR *)threadName,     /* Task name */
        (OS_TASK_PTR)threadEntry,   /* Entry point */
        context,                    /* Argument passed to thread */
        (OS_PRIO)threadPrio++,      /* Task priority which MUST be unique to each task */
        (CPU_STK *)pStackStart,     /* Stack for the new task */
        (CPU_STK)((stackSize * (100u-90u))/100u),    /* watermark limit, specifying 5% of stacksize here indicates use 95% of stack before full */
        (CPU_STK_SIZE)(stackSize / sizeof(CPU_STK_SIZE)),    /* Stack size, CPU_STK_SIZE could be in words so divide */
        (OS_MSG_QTY)0,              /* 0 for default max number of messages sent to this task */
        (OS_TICK)0,                 /* 0 for default time slice */
        (void *)0,                  /* Pointer for user supplied memory used as TCB extension, NULL for our case */
        (OS_OPT)(OS_OPT_TASK_STK_CHK | OS_OPT_TASK_STK_CLR), /* Allow stack checking and clear stack upon task creation */
        &err);
    if (err != OS_ERR_NONE)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"UCOS_createThread: OSTaskCreate() failed, return value = ", err);
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"UCOS_createThread: OSTaskCreate() failed, threadPrio = ", threadPrio);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"UCOS_createThread: OSTaskCreate() successful, threadPrio = ", threadPrio);
    DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"UCOS_createThread: OSTaskCreate() successful, threadType = ", threadType);

    /* Task was created successfully, mark it in the table */
    pTaskInfos[i].pStack = pStackSpace;
    pTaskInfos[i].stackSize = stackSize;
    pTaskInfos[i].pTcb = pTcb;
    pTaskInfos[i].used = TRUE;

    pStackSpace = NULL;
    pTcb = NULL;

    status = OK;

exit:

    if (NULL != pStackSpace)
    {
        DIGI_FREE((void **)&pStackSpace);
    }
    if (NULL != pTcb)
    {
        DIGI_FREE((void **)&pTcb);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern void
UCOS_destroyThread(RTOS_THREAD tid)
{
    ubyte4 i;
    OS_ERR err;

    for (i = 0; i < MAX_NUM_THREADS; i++)
    {
        /* The currently running task should be in our table, mark it as free to reuse the stack
         * and TCB, then delete it */
        if (pTaskInfos[i].pTcb == OSTCBCurPtr)
        {
            pTaskInfos[i].used = FALSE;
            OSTaskDel(pTaskInfos[i].pTcb, &err);
            return;
        }
    }

    /* This should not happen, but if for some reason it was not in our table delete it anyway */
    OSTaskDel(NULL, &err);
}

/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_timeGMT(TimeDate* td)
{
    MSTATUS status;
    CLK_DATE_TIME time = {0};
    CPU_BOOLEAN valid;

    if (NULL == td)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    valid = Clk_GetDateTime(&time);
    if (DEF_OK != valid)
    {
        status = ERR_RTOS_GMT_TIME_NOT_AVAILABLE;
        goto exit;
    }

    td->m_year   = (ubyte)time.Yr;
    td->m_month  = (ubyte)time.Month;
    td->m_day    = (ubyte)time.Day;
    td->m_hour   = (ubyte)time.Hr;
    td->m_minute = (ubyte)time.Min;
    td->m_second = (ubyte)time.Sec;
    status = OK;

exit:
    return status;
}

#endif /* __UCOS_RTOS__ */


