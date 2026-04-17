/*
 * dummy_rtos.c
 *
 * Dummy RTOS Abstraction Layer
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
