/*
 * hw_sim_test.c
 *
 * HW ACCEL simulated initialization and opening
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__

#include "../../../common/mtypes.h"
#include "../../../common/mocana.h"
#include "../../../common/mdefs.h"
#include "../../../common/merrors.h"

#ifdef __MOC_HW_SIM_VERBOSE__
#include <stdio.h>
#endif

typedef struct HW_SIM_CTX
{
    int initialized;
    int open;
    int referenceCount;
    enum moduleNames moduleId;
    
} HW_SIM_CTX;

static HW_SIM_CTX gSimCtx = {0};

/* *********************************************************** */

extern int HW_SIM_testHwCtx(void *pHwAccelCtx, char *pCaller)
{
    HW_SIM_CTX *pCtx = NULL;
    
    if (NULL == pHwAccelCtx)
    {
#ifdef __MOC_HW_SIM_VERBOSE__
        printf("HW_ACCEL >>>> ERROR: %s: NULL hwAccelCtx\n", pCaller);
#endif
        return (int) ERR_NULL_POINTER;
    }
    
    pCtx = (HW_SIM_CTX *) pHwAccelCtx;
    
#ifdef __MOC_HW_SIM_VERBOSE__
    if (1 != pCtx->initialized)
    {
        printf("HW_ACCEL >>>> WARNING %s: hwAccelCtx not initialized\n", pCaller);
    }
#endif
    
    if (0x31415 != pCtx->open)
    {
#ifdef __MOC_HW_SIM_VERBOSE__
        printf("HW_ACCEL >>>> ERROR %s: hwAccelCtx not open, value = %d\n", pCaller, pCtx->open);
#endif
        return (int) ERR_HARDWARE_ACCEL_OPEN_SESSION;
    }
    
#ifdef __MOC_HW_SIM_VERBOSE__
    printf("HW_ACCEL >>>> SUCCESSFUL HW ROUTINE VALIDATION: %s\n", pCaller);
#endif

    return 0;
}

/* *********************************************************** */

extern int HW_SIM_init(void)
{
    gSimCtx.initialized = 1;
    gSimCtx.open = 0;
    gSimCtx.referenceCount = 0;

#ifdef __MOC_HW_SIM_VERBOSE__
    printf("HW_ACCEL >>>> INITIALIZED HW_ACCEL SIMULATOR\n");
#endif
    
    return 0;
}

/* *********************************************************** */

extern int HW_SIM_uninit (void)
{
    gSimCtx.initialized = 0;
    gSimCtx.open = 0;
    gSimCtx.referenceCount = 0;

#ifdef __MOC_HW_SIM_VERBOSE__
    printf("HW_ACCEL >>>> UNINITIALIZED HW_ACCEL SIMULATOR\n");
#endif
    
    return 0;
}

/* *********************************************************** */

extern int HW_SIM_open (enum moduleNames moduleId, void **ppHwAccelCookie)
{
    if (NULL == ppHwAccelCookie)
        return -1;
    
#ifdef __MOC_HW_SIM_VERBOSE__
    if (1 != gSimCtx.initialized)
    {
        printf("HW_ACCEL >>>> WARNING HW_SIM_open: OPENING BUT NOT INITIALIZED\n");
    }
#endif

    gSimCtx.open = 0x31415;
    gSimCtx.moduleId = moduleId;
    gSimCtx.referenceCount++;
    *ppHwAccelCookie = (void *) &gSimCtx;
    
#ifdef __MOC_HW_SIM_VERBOSE__
    printf("HW_ACCEL >>>> OPENED HW_ACCEL SIMULATOR for id %d, and ref count %d\n", 
            moduleId, gSimCtx.referenceCount);
#endif
    
    return 0;
    
}

/* *********************************************************** */

extern int HW_SIM_close (enum moduleNames moduleId, void **ppHwAccelCookie)
{
    if (NULL == ppHwAccelCookie)
        return -1;
    
#ifdef __MOC_HW_SIM_VERBOSE__
    if (1 != gSimCtx.initialized)
    {
        printf("HW_ACCEL >>>> WARNING HW_SIM_open: CLOSING BUT NOT INITIALIZED\n");
    }
#endif

    if (0x31415 != gSimCtx.open)
    {
#ifdef __MOC_HW_SIM_VERBOSE__
        printf("HW_ACCEL >>>> ERROR HW_SIM_close: CLOSING BUT NOT OPEN: value of gSimCtx.open is %d\n", gSimCtx.open);
#endif
        return (int) ERR_HARDWARE_ACCEL_OPEN_SESSION;
    }
    
    if (gSimCtx.moduleId != moduleId)
    {
#ifdef __MOC_HW_SIM_VERBOSE__
        printf("HW_ACCEL >>>> ERROR HW_SIM_close: CLOSING BUT INCORRECT MODULE ID: gSimCtx.moduleId = %d and moduleId = %d\n", (int) gSimCtx.moduleId, (int) moduleId);
#endif
        return -4;
    }
    
    if ((void *) &gSimCtx != *ppHwAccelCookie)
    {
#ifdef __MOC_HW_SIM_VERBOSE__
        printf("HW_ACCEL >>>> ERROR HW_SIM_close: CLOSING BUT WRONG POINTER ID\n");
#endif
        return -5;
    }
    
    if (!gSimCtx.referenceCount)
    {
#ifdef __MOC_HW_SIM_VERBOSE__
         printf("HW_ACCEL >>>> ERROR HW_SIM_close: CLOSING BUT REFERENCE COUNT IS ALREADY 0\n");
#endif
         return -6;
    }
    
    gSimCtx.referenceCount--;
    if(!gSimCtx.referenceCount)
    {
        gSimCtx.open = 0;
        gSimCtx.moduleId = 0;
        *ppHwAccelCookie = NULL;
    }

#ifdef __MOC_HW_SIM_VERBOSE__
    printf("HW_ACCEL >>>> CLOSED HW_ACCEL SIMULATOR, current ref count = %d.\n", gSimCtx.referenceCount);
#endif
    
    return 0;
}

#endif /* __ENABLE_DIGICERT_HW_SIMULATOR_TEST__ */
