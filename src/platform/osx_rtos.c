/*
 * osx_rtos.c
 *
 * Mac OS X RTOS Abstraction Layer
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

#ifdef __OSX_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <pthread.h>
#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
#include <fcntl.h>
#include <semaphore.h>
#endif

#include <stdio.h>
#include <sys/time.h>
#include <sys/times.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>


#define NANOS 1000000000
#define MS    1000
#define NANOS_PER_MS     (NANOS / MS)
#define _REENTRANT


/*------------------------------------------------------------------*/

extern MSTATUS
OSX_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSX_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSX_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    pthread_mutex_t* pPthreadMutex;
    MSTATUS          status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pPthreadMutex = (pthread_mutex_t*) MALLOC(sizeof(pthread_mutex_t))))
        goto exit;

    DIGI_MEMSET((ubyte *)pPthreadMutex, 0x00, sizeof(pthread_mutex_t));

    if (!(0 > pthread_mutex_init(pPthreadMutex, NULL)))
    {
        *pMutex = (RTOS_MUTEX)pPthreadMutex;
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSX_mutexWait(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status  = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_lock(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSX_mutexRelease(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_unlock(pPthreadMutex))))
         status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSX_mutexFree(RTOS_MUTEX* pMutex)
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


#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
/*------------------------------------------------------------------*/
extern MSTATUS
OSX_globalMutexCreate(char *mutexName, RTOS_GLOBAL_MUTEX* ppMutex)
{
    MSTATUS status = OK;
    sem_t *semDesc;

    //sem_unlink(mutexName);

    if ((semDesc = sem_open(mutexName, O_CREAT, 0x644, 1)) == SEM_FAILED)
    {
        status = ERR_RTOS_MUTEX_CREATE;
        goto exit;
    }

    *ppMutex = (RTOS_GLOBAL_MUTEX)semDesc;

exit:
    return status;
}

/*------------------------------------------------------------------*/
extern MSTATUS
OSX_globalMutexWait(RTOS_GLOBAL_MUTEX pMutex, ubyte4 timeoutInSecs)
{
    MSTATUS status = OK;
    sem_t *semDesc;
    ubyte4 timeoutInMSec = timeoutInSecs*1000;

    if (NULL != pMutex)
    {
        semDesc = (sem_t *)pMutex;
        if (timeoutInMSec)
        {
            do 
            {
                if (!sem_trywait(semDesc))
                    break;

                if (EAGAIN != errno)
                {
                    status = ERR_RTOS_MUTEX_WAIT;
                    break;
                }

                /* Sleep for 1 millisecond */
                OSX_sleepMS(1);

                timeoutInMSec--;
            } while (timeoutInMSec);

        }
        else
        {
            if(sem_wait(semDesc))
                status = ERR_RTOS_MUTEX_WAIT;
        }
    }
    else
        status = ERR_RTOS_MUTEX_WAIT;

exit:
    return status;
}

/*------------------------------------------------------------------*/
extern MSTATUS
OSX_globalMutexRelease(RTOS_GLOBAL_MUTEX pMutex)
{
    MSTATUS status = OK;
    sem_t *semDesc;

    if (NULL != pMutex)
    {
        semDesc = (sem_t *)pMutex;
        if(sem_post(semDesc))
            status = ERR_RTOS_MUTEX_RELEASE; 
    }
    else
        status = ERR_RTOS_MUTEX_RELEASE;

    return status;
}

/*------------------------------------------------------------------*/
extern MSTATUS
OSX_globalMutexFree(char *mutexName, RTOS_GLOBAL_MUTEX* ppMutex)
{
    MSTATUS status = ERR_RTOS_MUTEX_FREE;
    sem_t *semDesc;

    if ((NULL == ppMutex) || (NULL == *ppMutex))
        goto exit;

    semDesc = (sem_t *)(*ppMutex);

    sem_close(semDesc);
    sem_unlink(mutexName);

    status = OK;

exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/

extern ubyte4
OSX_getUpTimeInMS(void)
{
    struct tms tstruct;
    clock_t uptime;
    ubyte4 ms;

    uptime=times(&tstruct);

    if (uptime==-1)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"ERROR: Could not get time values.");
        return -1;
    }

    ms = (ubyte4)(uptime * (1000 / CLK_TCK));

    return ms;
}


/*------------------------------------------------------------------*/

extern ubyte4
OSX_deltaMS(const moctime_t* origin, moctime_t* current)
{
    struct timeval tval;
    ubyte4 retVal = 0;

    gettimeofday(&tval, NULL);

    if (origin)
   {
        struct timeval diff;
        diff.tv_sec = tval.tv_sec - ((sbyte4) origin->u.time[0]);
        diff.tv_usec = tval.tv_usec - ((sbyte4) origin->u.time[1]);

        while ( diff.tv_usec < 0 )
        {
            diff.tv_usec += 1000000;
            diff.tv_sec--;
        }
        retVal = (ubyte4)(diff.tv_sec * 1000 + diff.tv_usec / 1000);
    }

    if (current)
    {
        current->u.time[0] = (ubyte4)(tval.tv_sec);
        current->u.time[1] = (ubyte4)(tval.tv_usec);

    }
    return retVal;
}


/*------------------------------------------------------------------*/



extern void
OSX_sleepMS(ubyte4 sleepTimeInMS)
{
    struct timespec nanopause;

    nanopause.tv_sec = sleepTimeInMS / MS;
    nanopause.tv_nsec = (sleepTimeInMS - (nanopause.tv_sec * MS)) * NANOS_PER_MS;

    nanosleep(&nanopause,0);
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSX_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD* pRetTid)
{
    pthread_t   tid;
    int         ret;
    MSTATUS     status  = OK;

    /* threadType is ignored for this platform, use default values */

    if (0 > (ret = pthread_create(&tid, NULL, (void *(*)(void *))threadEntry, context)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "OSX_createThread: pthread_create error ", ret);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }

    *pRetTid = tid;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
OSX_destroyThread(RTOS_THREAD tid)
{
    pthread_detach( (pthread_t) tid); /* mark the thread for deletion */
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSX_timeGMT(TimeDate* td)
{
    time_t      currentTime = time(NULL);
    struct tm*  pCurrentTime = gmtime(&currentTime);

    if (NULL == td)
        return ERR_NULL_POINTER;

    td->m_year   = (ubyte)(pCurrentTime->tm_year - 70);
    td->m_month  = (ubyte)pCurrentTime->tm_mon + 1; /* 1..12 and gmtime returns 0.11 */;
    td->m_day    = (ubyte)pCurrentTime->tm_mday;
    td->m_hour   = (ubyte)pCurrentTime->tm_hour;
    td->m_minute = (ubyte)pCurrentTime->tm_min;
    td->m_second = (ubyte)pCurrentTime->tm_sec;

    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
OSX_condCreate(RTOS_COND* pCond, enum mutexTypes mutexType, int mutexCount)
{
    pthread_cond_t* pPthreadCond;
    MSTATUS          status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pPthreadCond = (pthread_cond_t*) MALLOC(sizeof(pthread_cond_t))))
        goto exit;

    DIGI_MEMSET((ubyte *)pPthreadCond, 0x00, sizeof(pthread_cond_t));

    if (!(0 > pthread_cond_init(pPthreadCond, NULL)))
    {
        *pCond = (RTOS_MUTEX)pPthreadCond;
        status = OK;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
OSX_condWait(RTOS_COND cond, RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    pthread_cond_t*  pPthreadCond  = (pthread_cond_t *)cond;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pPthreadMutex) && (NULL != pPthreadCond) && (!(0 > pthread_cond_wait(pPthreadCond,pPthreadMutex))))
        status = OK;

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
OSX_condSignal(RTOS_COND cond)
{
    pthread_cond_t* pPthreadCond = (pthread_cond_t *)cond;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pPthreadCond) && (!(0 > pthread_cond_signal(pPthreadCond))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSX_condFree(RTOS_COND* pCond)
{
    pthread_cond_t* pPthreadCond;
    MSTATUS          status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pCond) || (NULL == *pCond))
        goto exit;

    pPthreadCond = (pthread_cond_t *)(*pCond);

    if (!(0 > pthread_cond_destroy(pPthreadCond)))
    {
        FREE(*pCond);
        *pCond = NULL;
        status = OK;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS 
OSX_getHwAddr(ubyte *macAddr, ubyte4 len)
{
    MSTATUS status = ERR_GENERAL;
    ubyte4 macAddrFound = 0;
    struct ifaddrs *ifaddr, *ifstart;

    if (!getifaddrs(&ifaddr))
    {
        ifstart = ifaddr;
        do {
            if (!(ifaddr->ifa_flags & IFF_LOOPBACK) && (ifaddr->ifa_flags & IFF_RUNNING))
            {
                if ((ifaddr->ifa_addr)->sa_family == AF_LINK)
                {
                    len = (len > ((struct sockaddr_dl *)(ifaddr->ifa_addr))->sdl_alen) ? len : 
                        ((struct sockaddr_dl *)(ifaddr->ifa_addr))->sdl_alen;
                    DIGI_MEMCPY(macAddr, (const sbyte *)LLADDR((struct sockaddr_dl *)(ifaddr->ifa_addr)), len);
                    macAddrFound = 1;
                    status = OK;
                    break;
                }
            }

            ifaddr = ifaddr->ifa_next;
        } while (ifaddr);

        freeifaddrs(ifstart);
    }
    
    if (!macAddrFound) 
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DB_PRINT("Error: Could not find a Running/Non-Loopback ethernet interface\n");
#endif
        status = ERR_GENERAL;
    }
exit:

    return status;
}

/*------------------------------------------------------------------*/

#endif /* __OSX_RTOS__ */
