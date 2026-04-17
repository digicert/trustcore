/*
 * THREADX_rtos.h
 *
 * THREADX RTOS Abstraction Layer
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

#ifndef THREADX_RTOS_H
#define THREADX_RTOS_H

#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"

MOC_EXTERN MSTATUS THREADX_createThread(void(*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid);
MOC_EXTERN MSTATUS THREADX_mutexFree(RTOS_MUTEX* pMutex);
MOC_EXTERN MSTATUS THREADX_mutexRelease(RTOS_MUTEX mutex);
MOC_EXTERN MSTATUS THREADX_mutexWait(RTOS_MUTEX mutex);
MOC_EXTERN MSTATUS THREADX_rtosInit(void);
MOC_EXTERN MSTATUS THREADX_rtosInit(void);
MOC_EXTERN MSTATUS THREADX_rtosShutdown(void);
MOC_EXTERN MSTATUS THREADX_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount);
MOC_EXTERN ubyte4 THREADX_deltaMS(const moctime_t* origin, moctime_t* current);
MOC_EXTERN ubyte4 THREADX_getUpTimeInMS(void);
MOC_EXTERN void THREADX_destroyThread(RTOS_THREAD tid);
MOC_EXTERN void THREADX_sleepMS(ubyte4 sleepTimeInMS);
int THREADX_timeGMT(TimeDate*t);

typedef ubyte4 (*GetTimeInMSFunc) (void);
/* Set function to use for getting time in MS */
void THREADX_setTimeMethod(GetTimeInMSFunc pGetTimeFunc);

#ifdef __RTOS_AZURE__
/* Set memory-block to use for moc mallocs */
MSTATUS THREADX_setMemPoolBlock(void *pMemoryBlock, ubyte4 blockSize);
MSTATUS THREADX_setMemPoolBlockForThreadStack(void *pMemStack, ubyte4 totalThreadStackSize);
void *THREADX_getNetworkPacketPool(void);
void *THREADX_getNetworkIpInstance(void);
#endif

void *THREADX_malloc(ubyte4 size);
void THREADX_free(void *memoryBlockPtr);

#endif
