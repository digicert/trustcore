/*
 * vxworks_rtos.c
 *
 * VxWORKS RTOS Abstraction Layer
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

#ifdef __VXWORKS_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <vxWorks.h>
#include <time.h>
#include <tickLib.h>
#include <taskLib.h>
#include <sysLib.h>
#include <semLib.h>
#include <pthread.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ipcom_type.h>
#include <ipcom_sock.h>


#ifndef _REENTRANT
#define _REENTRANT
#endif

#ifndef MOCANA_DEFAULT_VXWORKS_TASK_PRIORITY
#define MOCANA_DEFAULT_VXWORKS_TASK_PRIORITY    (100)
#endif

#ifndef MOCANA_DEFAULT_VXWORKS_STACK_SIZE
#define MOCANA_DEFAULT_VXWORKS_STACK_SIZE       (20000)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    SEM_ID  mutex;
    MSTATUS status = OK;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (mutex = semBCreate(SEM_Q_PRIORITY, SEM_FULL)))
        status = ERR_RTOS_MUTEX_CREATE;
    else
        *pMutex = (RTOS_MUTEX)mutex;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_mutexWait(RTOS_MUTEX mutex)
{
    SEM_ID  mutexId = (SEM_ID)mutex;
    MSTATUS status = OK;
    if (NULL == mutexId)
        status = ERR_RTOS_MUTEX_WAIT;
    else if (ERROR == semTake(mutexId, WAIT_FOREVER))
        status = ERR_RTOS_MUTEX_WAIT;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_mutexWaitEx(RTOS_MUTEX mutex, ubyte4 timeoutMs)
{
    SEM_ID  mutexId = (SEM_ID)mutex;
    MSTATUS status = OK;
    ubyte4 clkRate = 0;
    ubyte4 timeoutClicks = 0;

    if (NULL == mutexId)
        status = ERR_RTOS_MUTEX_WAIT;

    clkRate = sysClkRateGet();

    /* For now all callers call with wait times of even seconds */
    timeoutClicks = clkRate * (timeoutMs / 1000);

    if (ERROR == semTake(mutexId, timeoutClicks))
        status = ERR_RTOS_SEM_WAIT;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_mutexRelease(RTOS_MUTEX mutex)
{
    SEM_ID  mutexId = (SEM_ID)mutex;
    MSTATUS status = OK;
    if (NULL == mutexId)
        status = ERR_RTOS_MUTEX_RELEASE;
    else if (ERROR == semGive(mutexId))
        status = ERR_RTOS_MUTEX_RELEASE;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_mutexFree(RTOS_MUTEX* pMutex)
{
    SEM_ID  mutex;
    MSTATUS status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    mutex = (SEM_ID)(*pMutex);

    if (ERROR != semDelete(mutex))
    {
        *pMutex = NULL;
        status = OK;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_semCreate(RTOS_SEM *pSem, sbyte4 initialValue)
{
    MSTATUS status = ERR_NULL_POINTER;
    SEM_ID newSem;

    if (NULL == pSem)
        goto exit;

    newSem = semCCreate(SEM_Q_FIFO, (int)initialValue);
    if (SEM_ID_NULL == newSem)
    {
        status = ERR_RTOS_SEM_INIT;
        goto exit;
    }

    *pSem = (RTOS_SEM)newSem;
    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_semTryWait(RTOS_SEM sem)
{
    MSTATUS status = OK;

    if (NULL == sem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK != semTake((SEM_ID)sem, NO_WAIT))
    {
        status = ERR_RTOS_SEM_WAIT;
        goto exit;
    }

    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern ubyte4
VXWORKS_getUpTimeInMS(void)
{
    /* CLOCKS_PER_SEC, the number of ticks per second */
    /* Order is important, prevent rounding errors */
    ubyte4 ticks = tickGet();
    ubyte4 clkRate = sysClkRateGet();
    return (((ticks%clkRate)*1000)/clkRate) + ((ticks/clkRate)*1000);
}


/*------------------------------------------------------------------*/

extern void
VXWORKS_sleepMS(ubyte4 sleepTimeInMS)
{
    /* CLOCKS_PER_SEC, the number of ticks per second */
    /* Order is important, prevent rounding errors */
    taskDelay((sleepTimeInMS * sysClkRateGet()) / 1000);
}


/*------------------------------------------------------------------*/

static void
threadStart(int int_threadEntry, int int_context,
            int a, int b, int c, int d, int e, int f, int g, int h)
{
    void(*threadEntry)(void *) = (void(*)(void*))int_threadEntry;

    if (NULL != threadEntry)
        threadEntry((void *)int_context);
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_createThread(void(*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    int     priority    = MOCANA_DEFAULT_VXWORKS_TASK_PRIORITY;
    int     stackSize   = MOCANA_DEFAULT_VXWORKS_STACK_SIZE;
    char    *threadName;
    char    madeupName[20];
    int     pthread = FALSE;

    MSTATUS status = OK;

    switch (threadType)
    {
        case ENTROPY_THREAD:
        {
#ifdef MOCANA_ENTROPY_VXWORKS_TASK_NAME
            threadName = MOCANA_ENTROPY_VXWORKS_TASK_NAME;
#else
            threadName = "mocEntropy";
#endif
#ifdef MOCANA_ENTROPY_VXWORKS_STACK_SIZE
            stackSize  = MOCANA_ENTROPY_VXWORKS_STACK_SIZE;
#endif
#ifdef MOCANA_ENTROPY_VXWORKS_TASK_PRIORITY
            priority = MOCANA_ENTROPY_VXWORKS_TASK_PRIORITY;
#endif
            break;
        }

        case SSL_MAIN:
        {
#ifdef MOCANA_SSL_VXWORKS_TASK_NAME
            threadName = MOCANA_SSL_VXWORKS_TASK_NAME;
#else
            threadName = "mocSslMn";
#endif
#ifdef MOCANA_SSL_VXWORKS_STACK_SIZE
            stackSize  = MOCANA_SSL_VXWORKS_STACK_SIZE;
#else
            stackSize  = 14000;
#endif
#ifdef MOCANA_SSL_VXWORKS_TASK_PRIORITY
            priority = MOCANA_SSL_VXWORKS_TASK_PRIORITY;
#endif
            break;
        }

        case SSL_SERVER_SESSION:
        {
#ifdef MOCANA_SSL_VXWORKS_TASK_NAME
            threadName = MOCANA_SSL_SESSION_VXWORKS_TASK_NAME;
#else
            threadName = "mocSslSsn";
#endif
#ifdef MOCANA_SSL_VXWORKS_STACK_SIZE
            stackSize  = MOCANA_SSL_VXWORKS_STACK_SIZE;
#else
            stackSize  = 14000;
#endif
#ifdef MOCANA_SSL_VXWORKS_TASK_PRIORITY
            priority = MOCANA_SSL_VXWORKS_TASK_PRIORITY;
#endif
            break;
        }

        case DTLS_MAIN:
        {
#ifdef MOCANA_DTLS_VXWORKS_TASK_NAME
            threadName = MOCANA_DTLS_VXWORKS_TASK_NAME;
#else
            threadName = "mocDtlsMn";
#endif
#ifdef MOCANA_DTLS_VXWORKS_STACK_SIZE
            stackSize  = MOCANA_DTLS_VXWORKS_STACK_SIZE;
#else
            stackSize  = 18000;
#endif
#ifdef MOCANA_DTLS_VXWORKS_TASK_PRIORITY
            priority = MOCANA_DTLS_VXWORKS_TASK_PRIORITY;
#endif
            break;
        }

        case SSH_MAIN:
        {
#ifdef MOCANA_SSH_MAIN_VXWORKS_TASK_NAME
            threadName = MOCANA_SSH_MAIN_VXWORKS_TASK_NAME;
#else
            threadName = "mocSshMn";
#endif
#ifdef MOCANA_SSH_VXWORKS_STACK_SIZE
            stackSize  = MOCANA_SSH_VXWORKS_STACK_SIZE;
#endif
#ifdef MOCANA_SSH_VXWORKS_TASK_PRIORITY
            priority = MOCANA_SSH_VXWORKS_TASK_PRIORITY;
#endif
            break;
        }

        case SSH_SESSION:
        {
#ifdef MOCANA_SSH_VXWORKS_TASK_NAME
            threadName = MOCANA_SSH_VXWORKS_TASK_NAME;
#else
            threadName = "mocSsh";
#endif
#ifdef MOCANA_SSH_VXWORKS_STACK_SIZE
            stackSize  = MOCANA_SSH_VXWORKS_STACK_SIZE;
#endif
#ifdef MOCANA_SSH_VXWORKS_TASK_PRIORITY
            priority = MOCANA_SSH_VXWORKS_TASK_PRIORITY;
#endif
            break;
        }
        case EAP_MAIN:
        {
#ifdef MOCANA_EAP_MAIN_VXWORKS_TASK_NAME
            threadName = MOCANA_EAP_MAIN_VXWORKS_TASK_NAME;
#else
            threadName = "mocEapMn";
#endif
#ifdef MOCANA_EAP_VXWORKS_STACK_SIZE
            stackSize  = MOCANA_EAP_VXWORKS_STACK_SIZE;
#endif
#ifdef MOCANA_EAP_VXWORKS_TASK_PRIORITY
            priority = MOCANA_EAP_VXWORKS_TASK_PRIORITY;
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
#ifdef MOCANA_HTTP_VXWORKS_TASK_NAME
            threadName = MOCANA_HTTP_VXWORKS_TASK_NAME;
#else
            threadName = "mocHttp";
#endif
#ifdef MOCANA_HTTP_VXWORKS_STACK_SIZE
            stackSize  = MOCANA_HTTP_VXWORKS_STACK_SIZE;
#else
            stackSize  = 14000;
#endif
#ifdef MOCANA_HTTP_VXWORKS_TASK_PRIORITY
            priority = MOCANA_HTTP_VXWORKS_TASK_PRIORITY;
#endif
            break;
        }

        case DEBUG_CONSOLE:
        {
#ifdef MOCANA_DEBUG_CON_VXWORKS_TASK_NAME
            threadName = MOCANA_DEBUG_CON_VXWORKS_TASK_NAME;
#else
            threadName = "mocDbgCon";
#endif
#ifdef MOCANA_DEBUG_CON_VXWORKS_STACK_SIZE
            stackSize  = MOCANA_DEBUG_CON_VXWORKS_STACK_SIZE;
#endif
#ifdef MOCANA_DEBUG_CON_VXWORKS_TASK_PRIORITY
            priority = MOCANA_DEBUG_CON_VXWORKS_TASK_PRIORITY;
#endif
            break;
        }

        case MOC_IPV4:
        {
            threadName = "mocIPv4";
            stackSize  = 80000;         /* Temp. code */
            priority   = 50;            /* Temp. code */
            break;
        }

        case HARNESS_MAIN:
        {
#ifdef MOCANA_HARNESS_MAIN_VXWORKS_TASK_NAME
            threadName = MOCANA_HARNESS_MAIN_VXWORKS_TASK_NAME;
#else
            threadName = "mocHarn";
#endif
#ifdef MOCANA_HARNESS_MAIN_VXWORKS_STACK_SIZE
            stackSize  = MOCANA_HARNESS_MAIN_VXWORKS_STACK_SIZE;
#endif
#ifdef MOCANA_HARNESS_MAIN_VXWORKS_TASK_PRIORITY
            priority = MOCANA_HARNESS_MAIN_VXWORKS_TASK_PRIORITY;
#else
            priority = 1;       /* interrupt q drain - run at high priority */
#endif
            break;
        }

        case HARNESS_MAIN1:
        {
#ifdef MOCANA_HARNESS_MAIN_VXWORKS_TASK_NAME
            threadName = MOCANA_HARNESS_MAIN_VXWORKS_TASK_NAME;
#else
            threadName = "mocIpsecHarn";
#endif
#ifdef MOCANA_HARNESS_MAIN_VXWORKS_STACK_SIZE
            stackSize  = MOCANA_HARNESS_MAIN_VXWORKS_STACK_SIZE;
#endif
#ifdef MOCANA_HARNESS_MAIN_VXWORKS_TASK_PRIORITY
            priority = MOCANA_HARNESS_MAIN_VXWORKS_TASK_PRIORITY;
#else
            priority = 50;       /* interrupt q drain - run at high priority */
#endif
            break;
        }

        case IKE_MAIN:
        {
#ifdef MOCANA_IKE_VXWORKS_TASK_NAME
            threadName = MOCANA_IKE_VXWORKS_TASK_NAME;
#else
            threadName = "tMocIke";
#endif
#ifdef MOCANA_IKE_VXWORKS_STACK_SIZE
            stackSize  = MOCANA_IKE_VXWORKS_STACK_SIZE;
#else
            stackSize  = 6000;
#endif
#ifdef MOCANA_IKE_VXWORKS_TASK_PRIORITY
            priority = MOCANA_IKE_VXWORKS_TASK_PRIORITY;
#endif
            pthread = TRUE;
            break;
        }

        case RADIUS_MAIN:
        {
#ifdef MOCANA_RADIUS_VXWORKS_TASK_NAME
            threadName = MOCANA_RADIUS_VXWORKS_TASK_NAME;
#else
            threadName = "tMocRad";
#endif
#ifdef MOCANA_RADIUS_VXWORKS_STACK_SIZE
            stackSize  = MOCANA_RADIUS_VXWORKS_STACK_SIZE;
#else
            stackSize  = 14000; /* TODO: needs to optimize */
#endif
#ifdef MOCANA_RADIUS_VXWORKS_TASK_PRIORITY
            priority = MOCANA_RADIUS_VXWORKS_TASK_PRIORITY;
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
#ifndef __ENABLE_DIGICERT_USE_VXWORKS_TASK__
            pthread = TRUE;
#endif
            break;
        }
        case UM_SCHED:
        {
            threadName = "umsched";
        }
        default:
        {
        /*    status = ERR_RTOS_THREAD_CREATE; */
            DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"VXWORKS_createThread: unknown thread type.");
            DBUG_PRINT(DEBUG_PLATFORM, ("Unknown threadtype: %d Creating anyway", threadType));
            sprintf(madeupName, "EnumTask%d", threadType);
            threadName = madeupName;
            break;
        }
    }

    if (FALSE == pthread)
    {
        *pRetTid = (RTOS_THREAD *)taskSpawn(threadName,            /* name of new task (stored at pStackBase) */
                         priority,              /* priority of new task */
                         0,                     /* task option word */
                         stackSize,             /* size (bytes) of stack needed plus name */
                         (FUNCPTR)threadStart,  /* entry point of new task */
                         (int)threadEntry,      /* 1st of 10 reqd task args to pass to func */
                         (int)context,          /* 2nd of 10 reqd task args to pass to func */
                         0, 0, 0, 0, 0, 0, 0, 0);
    }
    else  /* create a pThread */
    {
        status = pthread_create(pRetTid, NULL, threadEntry, context);
        if (0 != status)
        { /* create failed */
            *pRetTid = (RTOS_THREAD)ERROR;
        }
    }


    if ((RTOS_THREAD)ERROR == *pRetTid)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"VXWORKS_createThread: taskSpawn() failed.");
        status = ERR_RTOS_THREAD_CREATE;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern void
VXWORKS_destroyThread(RTOS_THREAD tid)
{
    /* Not needed with this OS */
    /* STATUS taskDelete(int tid); */
}


/*------------------------------------------------------------------*/

extern sbyte4
VXWORKS_currentThreadId()
{
    return (sbyte4) pthread_self();
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_timeGMT(TimeDate* td)
{
    time_t      currentTime = time(NULL);
    struct tm   currentDate;

    if (NULL == td)
        return ERR_NULL_POINTER;

    gmtime_r(&currentTime, &currentDate);

    td->m_year   = (ubyte)(currentDate.tm_year - 70);
    td->m_month  = (ubyte)currentDate.tm_mon + 1; /* 1..12 and gmtime returns 0.11 */
    td->m_day    = (ubyte)currentDate.tm_mday;
    td->m_hour   = (ubyte)currentDate.tm_hour;
    td->m_minute = (ubyte)currentDate.tm_min;
    td->m_second = (ubyte)currentDate.tm_sec;

    return OK;
}


/*------------------------------------------------------------------*/

extern ubyte4
VXWORKS_deltaMS(const moctime_t* origin, moctime_t* current)
{
    ubyte4 tval;
    ubyte4 retVal = 0;

    tval = tickGet();

    /* origin and current can point to the same struct */
    if (origin)
    {
        ubyte4 diff = tval - origin->u.time[0];
        ubyte4 clkRate = sysClkRateGet();
        retVal  = (((diff%clkRate)*1000)/clkRate) + ((diff/clkRate)*1000);
    }

    if (current)
    {
        current->u.time[0] = tval;
    }

    return retVal;
}

extern ubyte4
VXWORKS_deltaConstMS(const moctime_t* origin, const moctime_t* current)
{
    sbyte4 diff_sec;
    sbyte4 diff_usec;

    diff_sec  = (sbyte4)(current->u.time[0] - origin->u.time[0]);
    diff_usec = (sbyte4)(current->u.time[1] - origin->u.time[1]);

    while ( diff_usec < 0 && diff_sec > 0)
    {
        diff_usec += 1000000;
        diff_sec--;
    }

    /* belt ... */
    if ( diff_usec < 0) diff_usec = 0;

    /* ... and suspenders */
    if ( diff_sec < 0) diff_sec = 0;

    return (diff_sec * 1000 + diff_usec / 1000);
}


/*------------------------------------------------------------------*/

extern moctime_t *
VXWORKS_timerAddMS(moctime_t* pTimer, ubyte4 addNumMS)
{
    ubyte4 sec;

    sec = addNumMS / 1000;
    addNumMS %= 1000;

    pTimer->u.time[0] += sec;
    pTimer->u.time[1] += (1000 * addNumMS);

    while (pTimer->u.time[1] > 1000000)
    {
        pTimer->u.time[1] -= 1000000;
        pTimer->u.time[0]++;
    }

    return pTimer;
}



/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_recursiveMutexCreate (RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    pthread_mutex_t * pPthreadMutex= *pMutex;
    pthread_mutexattr_t attr;
    MSTATUS          status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    pthread_mutexattr_init (&attr);
    pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);

    DIGI_MEMSET((ubyte *)pPthreadMutex, 0x00, sizeof(pthread_mutex_t));

    if (!(0 > pthread_mutex_init(pPthreadMutex, &attr)))
    {
        status = OK;
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_recursiveMutexWait (RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_lock(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_recursiveMutexRelease (RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_unlock(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_recursiveMutexFree (RTOS_MUTEX* pMutex)
{
    pthread_mutex_t* pPthreadMutex;
    MSTATUS          status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    pPthreadMutex = (pthread_mutex_t *)(*pMutex);

    if (!(0 > pthread_mutex_destroy(pPthreadMutex)))
    {
        FREE(*pMutex);
        *pMutex = NULL;
        status = OK;
    }

exit:
    return status;
}
#ifdef __VX7_SR640__
VXWORKS_getHwAddrByIfname(const sbyte *ifname, sbyte *adapter_name, ubyte *macAddr, ubyte4 len)
{
    int fd = 0;
    MSTATUS status = ERR_GENERAL;
    struct ifreq        ifreq;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DB_PRINT("Error opening socket to query for interface mac address\n");
#endif
        goto exit;
    }
    DIGI_MEMSET(&ifreq, 0, sizeof(ifreq));
    (void) DIGI_STRCBCPY((sbyte *)ifreq.ifr_name, sizeof(ifreq.ifr_name), ifname);
    if (ioctl(fd, SIOCGIFLLADDR, &ifreq) < 0)
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DB_PRINT("Error: %d issuing ioctl to interface: %s", ipcom_errno, ifreq.ifr_name);
#endif
        status = ERR_GENERAL;
        goto exit;
    }
    else
    {
        DIGI_MEMCPY(macAddr, ifreq.ip_ifr_addr.sa_data, len > ifreq.ip_ifr_addr.sa_len ? ifreq.ip_ifr_addr.sa_len : len);
        status = OK;
    }

exit:
    if (fd >= 0)
        (void) close(fd);

    return status;

}

#else

VXWORKS_getHwAddrByIfname(const sbyte *ifname, sbyte *adapter_name, ubyte *macAddr, ubyte4 len)
{
    int fd = 0;
    MSTATUS status = ERR_GENERAL;
    struct Ip_ifreq        ifreq;

    fd = ipcom_socket(IP_AF_INET, IP_SOCK_DGRAM, IP_IPPROTO_UDP);
    if (fd != IP_INVALID_SOCKET)
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DB_PRINT("Error opening socket to query for interface mac address\n");
#endif
        goto exit;
    }
    DIGI_MEMSET(&ifreq, 0, sizeof(ifreq));
    (void) DIGI_STRCBCPY((sbyte *)ifreq.ifr_name, sizeof(ifreq.ifr_name), ifname);
    if (ipcom_socketioctl(fd, IP_SIOCGIFLLADDR, &ifreq) < 0)
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DB_PRINT("Error: %d issuing ioctl to interface: %s", ipcom_errno, ifreq.ifr_name);
#endif
        status = ERR_GENERAL;
        goto exit;
    }
    else
    {
        DIGI_MEMCPY(macAddr, ifreq.ip_ifr_addr.sa_data, len > ifreq.ip_ifr_addr.sa_len ? ifreq.ip_ifr_addr.sa_len : len);
        status = OK;
    }

exit:
    if (IP_INVALID_SOCKET != fd)
        (void) close(fd);

    return status;

}

#endif

/*------------------------------------------------------------------*/
#endif /* __VXWORKS_RTOS__ */
