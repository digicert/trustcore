/*
 * mrtos.c
 *
 * Mocana RTOS Helper Functions
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
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"


/*------------------------------------------------------------------*/

extern MSTATUS
MRTOS_mutexWait(RTOS_MUTEX mutex, intBoolean *pIsMutexSet)
{
    MSTATUS status;

    /* check if mutex wait has been previously called */
    if (FALSE != *pIsMutexSet)
    {
        status = ERR_RTOS_WRAP_MUTEX_WAIT;
        goto exit;
    }

    if (OK > (status = RTOS_mutexWait(mutex)))
        goto exit;

    *pIsMutexSet = TRUE;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MRTOS_mutexRelease(RTOS_MUTEX mutex, intBoolean *pIsMutexSet)
{
    MSTATUS status;

    /* make sure we are trying to release a mutex that we previously waited on */
    if (TRUE != *pIsMutexSet)
    {
        status = ERR_RTOS_WRAP_MUTEX_RELEASE;
        goto exit;
    }

    if (OK > (status = RTOS_mutexRelease(mutex)))
        goto exit;

    *pIsMutexSet = FALSE;

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__

/*------------------------------------------------------------------*/

extern MSTATUS
MRTOS_globalMutexWait(RTOS_GLOBAL_MUTEX mutex, intBoolean *pIsMutexSet,
        ubyte4 timeoutInSecs)
{
    MSTATUS status;

    /* check if mutex wait has been previously called */
    if (FALSE != *pIsMutexSet)
    {
        status = ERR_RTOS_WRAP_MUTEX_WAIT;
        goto exit;
    }

    if (OK > (status = RTOS_globalMutexWait(mutex, timeoutInSecs)))
        goto exit;

    *pIsMutexSet = TRUE;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MRTOS_globalMutexRelease(RTOS_GLOBAL_MUTEX mutex, intBoolean *pIsMutexSet)
{
    MSTATUS status;

    /* make sure we are trying to release a mutex that we previously waited on */
    if (TRUE != *pIsMutexSet)
    {
        status = ERR_RTOS_WRAP_MUTEX_RELEASE;
        goto exit;
    }

    if (OK > (status = RTOS_globalMutexRelease(mutex)))
        goto exit;

    *pIsMutexSet = FALSE;

exit:
    return status;
}
#endif
