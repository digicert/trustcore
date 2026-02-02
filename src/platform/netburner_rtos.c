/*
 * netburner_rtos.c
 *
 * NetBurner uC/OS RTOS Abstraction Layer
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

#ifdef __NETBURNER_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <basictypes.h>
#include <constants.h>
#include <ucos.h>
#include <utils.h>
#include <time.h>


#define NANOS 1000000000
#define _REENTRANT

#define MAX_NUM_THREADS 10

static void *pStackBase[MAX_NUM_THREADS];


/*------------------------------------------------------------------*/

extern MSTATUS
NETBURNER_rtosInit(void)
{
    int i;

    for (i = 0; i < MAX_NUM_THREADS; i++)
        pStackBase[i] = NULL;

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NETBURNER_rtosShutdown(void)
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
NETBURNER_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    OS_SEM*     pMutex_t;
    MSTATUS     status = ERR_RTOS_MUTEX_CREATE;
    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pMutex_t = MALLOC(sizeof(OS_SEM))))
        goto exit;

    DIGI_MEMSET((ubyte *)pMutex_t, 0x00, sizeof(OS_SEM));

    if (OS_NO_ERR != OSSemInit(pMutex_t, 0))
    {
        *pMutex = (RTOS_MUTEX)pMutex_t;
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NETBURNER_mutexWait(RTOS_MUTEX mutex)
{
    OS_SEM*  pMutex_t = (OS_SEM *)mutex;
    MSTATUS  status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pMutex_t) && (OS_NO_ERR == OSSemPend(pMutex_t, 0)) )
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NETBURNER_mutexRelease(RTOS_MUTEX mutex)
{
    OS_SEM*  pMutex_t = (OS_SEM *)mutex;
    MSTATUS  status = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pMutex_t) && (OS_NO_ERR == OSSemPost(pMutex_t)) )
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NETBURNER_mutexFree(RTOS_MUTEX* pMutex)
{
    MSTATUS     status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

        FREE(*pMutex);
        status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern ubyte4
NETBURNER_getUpTimeInMS(void)
{
    ubyte4 ms;

    ms = TimeTick * (1000 / TICKS_PER_SECOND);

    return ms;
}


/*------------------------------------------------------------------*/

extern ubyte4
NETBURNER_deltaMS(const moctime_t* origin, moctime_t* current)
{
    ubyte4  retVal = 0;

    if (origin)
    {
        retVal = (1000 / TICKS_PER_SECOND) * (TimeTick - origin->u.time[0]);
    }

    if (current)
    {
        current->u.time[0] = TimeTick;
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern void
NETBURNER_sleepMS(ubyte4 sleepTimeInMS)
{
    ubyte4  NumOfTick ;

    NumOfTick = sleepTimeInMS * TICKS_PER_SECOND / 1000;
    if (!NumOfTick)
        NumOfTick = 1;

    OSTimeDly(NumOfTick);
}


/*------------------------------------------------------------------*/

#define STACK_SIZE  15000   /* number must be dev by 4 without reminder */

extern MSTATUS
NETBURNER_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    BYTE    retVal;
    int     i;
    void*   pStackSpace;
    void*   pStackStart;
    void*   pStackEnd;
    MSTATUS status = ERR_RTOS_THREAD_CREATE;
    static int threadPrio = 51;                /* you will need to custom priorities based on your design */

    if (NULL == (pStackSpace = MALLOC(STACK_SIZE)))
        goto exit;

    /* stack must be 4 byte (long) aligned !!! */
    if ((DWORD)pStackSpace & 0x3)
    {
        pStackStart = pStackSpace + (4 - ((DWORD)pStackSpace & 0x3));           /* align start */
        pStackEnd   = pStackSpace + STACK_SIZE - ((DWORD)pStackSpace & 0x3);    /* align end   */
    }
    else  /* was already aligned */
    {
        pStackStart = pStackSpace;
        pStackEnd   = pStackSpace + STACK_SIZE;
    }


    for (i = 0; i < MAX_NUM_THREADS; i++)
    {
        if (NULL == pStackBase[i])
        {
            if (OS_NO_ERR == (retVal = OSTaskCreate((void(*)(void *))threadEntry,
                                                    context, pStackEnd, pStackStart, threadPrio++)) )
            {
                DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"NETBURNER_createThread: OSTaskCreate() successful, threadPrio = ", threadPrio);
                DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"NETBURNER_createThread: OSTaskCreate() successful, threadType = ", threadType);
                pStackBase[i] = pStackSpace;
                status = OK;
            }
            else
            {
                DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"NETBURNER_createThread: OSTaskCreate() failed, return value = ", retVal);
                DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"NETBURNER_createThread: OSTaskCreate() failed, threadPrio = ", threadPrio);
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
NETBURNER_destroyThread(RTOS_THREAD tid)
{
    /* Not needed with this OS */
}


/*------------------------------------------------------------------*/

extern MSTATUS
NETBURNER_timeGMT(TimeDate* td)
{
#if 0
    time_t      currentTime = time(NULL);
    struct tm*  pCurrentTime = gmtime(&currentTime);

    if (NULL == td)
        return ERR_NULL_POINTER;

    td->m_year   = (ubyte)(pCurrentTime->tm_year - 70);
    td->m_month  = (ubyte)pCurrentTime->tm_mon;
    td->m_day    = (ubyte)pCurrentTime->tm_mday;
    td->m_hour   = (ubyte)pCurrentTime->tm_hour;
    td->m_minute = (ubyte)pCurrentTime->tm_min;
    td->m_second = (ubyte)pCurrentTime->tm_sec;

    return OK;
#else
    return ERR_RTOS_GMT_TIME_NOT_AVAILABLE;
#endif
}

#endif /* __NETBURNER_RTOS__ */


