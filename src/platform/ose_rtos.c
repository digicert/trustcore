/*
 * ose_rtos.c
 *
 * OSE RTOS Abstraction Layer
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

#ifdef __OSE_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <ose.h>
#include <pthread.h>
#include <sys/time.h>
#include <efs.h>
#include <malloc.h>
#include <ose_spi/pm.sig>

#define _REENTRANT

#define MSSAPP_PM_HUNT    0x77778888        /* magic number */
union SIGNAL
{
    SIGSELECT sig_no;
    struct PmGetProgramPid appPid;
    struct PmProgramInfo appInfo;
};


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    pthread_mutex_t* pPthreadMutex;
    MSTATUS          status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pPthreadMutex = MALLOC(sizeof(pthread_mutex_t))))
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
OSE_mutexWait(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_lock(pPthreadMutex))))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_mutexRelease(RTOS_MUTEX mutex)
{
    pthread_mutex_t* pPthreadMutex = (pthread_mutex_t *)mutex;
    MSTATUS          status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pPthreadMutex) && (!(0 > pthread_mutex_unlock(pPthreadMutex))))
         status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_mutexFree(RTOS_MUTEX* pMutex)
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


/*------------------------------------------------------------------*/

extern ubyte4
OSE_getUpTimeInMS(void)
{

    return (get_systime(NULL) *(system_tick()/1000));
}


/*------------------------------------------------------------------*/

extern ubyte4
OSE_deltaMS(const moctime_t* origin, moctime_t* current)
{
    OSTICK millis;
    ubyte4  retVal = 0;

    millis = get_systime(NULL) *(system_tick()/1000);

    if (origin)
    {
        retVal = millis - origin->u.time[0];
    }

    if (current)
    {
        current->u.time[0] = (get_systime(NULL) *(system_tick()/1000));
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern void
OSE_sleepMS(ubyte4 sleepTimeInMS)
{
    /* Note: delay(0) crashes OSE kernel! */
    if (0 == sleepTimeInMS) sleepTimeInMS = 1;
    delay(sleepTimeInMS);
}


/*------------------------------------------------------------------*/


PROCESS
OSE_getBlockId()
{
    const SIGSELECT sigsel_hunt[] = { 1, MSSAPP_PM_HUNT};
    const SIGSELECT sigsel_appPid[] = { 1, PM_GET_PROGRAM_PID_REPLY};
    const SIGSELECT sigsel_appInfo[] = { 1, PM_PROGRAM_INFO_REPLY};
    union SIGNAL    *sig = alloc(sizeof(SIGSELECT), MSSAPP_PM_HUNT);
    PROCESS pm_pid, app_pid, app_blockId=0;

    /* get pid for program manager */
    hunt (PM_PGM_NAME, 0, 0, &sig);
    sig = receive (sigsel_hunt);
    if (NIL != sig)
    {
        pm_pid = sender(&sig);
        free_buf (&sig);
    }
    else
    {
        /* Error condition */
        free_buf (&sig);
        goto exit;
    }
    /* Get application program Id and then application blockId */
    sig = alloc(sizeof(struct PmGetProgramPid), PM_GET_PROGRAM_PID_REQUEST);
    sig->appPid.pid = current_process();
    send (&sig, pm_pid);
    sig = receive(sigsel_appPid);
    app_pid = sig->appPid.progpid;
    free_buf(&sig);
    /* Get application program Info */
    sig = alloc(sizeof(struct PmProgramInfo), PM_PROGRAM_INFO_REQUEST);
    sig->appInfo.progpid = app_pid;
    send (&sig, pm_pid);
    sig = receive(sigsel_appInfo);
    app_blockId = sig->appInfo.main_block;
    free_buf(&sig);

exit:
    return app_blockId;
}

/*------------------------------------------------------------------*/

extern MSTATUS
OSE_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    int                    ret;
    MSTATUS                status  = OK;
    pthread_t              tid;
    pthread_attr_t         attr;
    struct sched_param     pthread_priority;
    PROCESS        blockId;

    /* set blockId while creating pthread.*/
    blockId = OSE_getBlockId();
    pthread_attr_init(&attr);
    pthread_attr_setstopped(&attr, 1);
    if (SSL_SERVER_SESSION == threadType)
        pthread_attr_setstacksize(&attr, 8000);
    else
        pthread_attr_setstacksize(&attr, 32000);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setblock(&attr, blockId);
    pthread_priority.sched_priority = 30; /* 0- highest; 31- lowest */
    pthread_attr_setschedparam (&attr, &pthread_priority);
    /* use pthread_attr_setname to set OSE Process name */
    if (0 > (ret = pthread_create(&tid, &attr, (void *(*)(void *))threadEntry, context)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "OSE_createThread: pthread_create error ", ret);
        status = ERR_RTOS_THREAD_CREATE;
        goto exit;
    }
    efs_clone(tid);
    start(tid);

    *pRetTid = (RTOS_THREAD *)tid;
exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
OSE_destroyThread(RTOS_THREAD tid)
{
    pthread_exit(NULL);
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_timeGMT(TimeDate* td)
{
    time_t      currentTime = time(NULL);
    struct tm   gmt;

    gmtime_r(&currentTime, &gmt);

    if (NULL == td)
        return ERR_NULL_POINTER;

    td->m_year   = (ubyte)(gmt.tm_year - 70);
    td->m_month  = (ubyte)gmt.tm_mon+1; /* 1..12 and returned value is 0..11 */
    td->m_day    = (ubyte)gmt.tm_mday;
    td->m_hour   = (ubyte)gmt.tm_hour;
    td->m_minute = (ubyte)gmt.tm_min;
    td->m_second = (ubyte)gmt.tm_sec;

    return OK;
}

#endif /* __OSE_RTOS__ */
