/*
 * dummy_rtos.c
 *
 * Dummy RTOS Abstraction Layer
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

#ifdef __DUMMY_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_mutexWait(RTOS_MUTEX mutex)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_mutexRelease(RTOS_MUTEX mutex)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_mutexFree(RTOS_MUTEX* pMutex)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern ubyte4
DUMMY_getUpTimeInMS(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern ubyte4
DUMMY_deltaMS(const moctime_t* origin, moctime_t* current)
{
    return OK;
}


/*------------------------------------------------------------------*/



extern void
DUMMY_sleepMS(ubyte4 sleepTimeInMS)
{
    return;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_createThread(void (*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD* pRetTid)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern void
DUMMY_destroyThread(RTOS_THREAD tid)
{
    return;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_timeGMT(TimeDate* td)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern ubyte4
DUMMY_deltaConstMS(const moctime_t* origin, const moctime_t* current)
{
    return 0;
}


/*------------------------------------------------------------------*/

extern moctime_t *
DUMMY_timerAddMS(moctime_t* pTimer, ubyte4 addNumMS)
{
    return NULL;
}

#endif /* __DUMMY_RTOS__ */
