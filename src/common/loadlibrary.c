/*
 * loadlibrary.c
 *
 * Function implementation to perform runtime dynamic library linking.
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

#ifdef __RTOS_WIN32__
#include <windows.h>
#include <stdio.h>
#endif

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_DYNAMIC_LOAD__) && ( defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__) )
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/loadlibrary.h"

#if defined(__RTOS_LINUX__)

#include <dlfcn.h>
#define OPENLIB(libName) dlopen((libName), RTLD_NOW);
#define CLOSELIB(libHandle) dlclose(libHandle);
#define LIBFUNC(libHandle, func) dlsym((libHandle), (func));

#elif defined(__RTOS_WIN32__)

#define OPENLIB(libName) LoadLibrary(TEXT(libName));
#define CLOSELIB(libHandle) FreeLibrary(libHandle);
#define LIBFUNC(libHandle, func) GetProcAddress((libHandle), (func));

#endif /* ifdef __RTOS_LINUX__ */
/*------------------------------------------------------------------------------*/

extern MSTATUS DIGICERT_loadDynamicLibrary(
    const char *pFilename,
    void **ppHandle
    )
{
    return DIGICERT_loadDynamicLibraryEx(pFilename, ppHandle);
}

extern MSTATUS DIGICERT_loadDynamicLibraryEx(
    const char *pFilename,
    void **ppHandle
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    void *pHandle = NULL;

    if (NULL == pFilename)
        goto exit;

    pHandle = OPENLIB(pFilename)
    if (NULL == pHandle)
    {
        status = ERR_DYNAMIC_LINK_FAILED;
        goto exit;
    }

    if (NULL != ppHandle)
    {
        *ppHandle = pHandle;
    }

    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------------------*/

extern MSTATUS DIGICERT_unloadDynamicLibrary(void *pHandle)
{
    MSTATUS status;

    if (NULL == pHandle)
        return ERR_NULL_POINTER;

    status = CLOSELIB(pHandle)
#ifdef __RTOS_WIN32__
    if (0 == status)
#else
    if (0 != status)
#endif
    {
      status = ERR_INSTANCE_CLOSED;
    }

    return status;
}

/*------------------------------------------------------------------------------*/

extern MSTATUS DIGICERT_getSymbolFromLibrary(
    const char *pSymbol,
    void *pLibHandle,
    void **ppSymbolAddr
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    void *pSym = NULL;

    if ( (NULL == pSymbol) || (NULL == pLibHandle) || (NULL == ppSymbolAddr) )
    {
        goto exit;
    }

    pSym = LIBFUNC(pLibHandle, pSymbol)
    if (NULL == pSym)
    {
        status = ERR_NOT_FOUND;
        goto exit;
    }

    *ppSymbolAddr = pSym;
    pSym = NULL;
    status = OK;

exit:
    return status;
}
#endif /* if defined(__ENABLE_DIGICERT_DATA_PROTECTION__) && ( defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__) ) */
