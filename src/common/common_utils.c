/*
 * common_utils.c
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

#if defined(__ENABLE_DIGICERT_COMMON_UTILS__)

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/common_utils.h"

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || (defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__))
#define DIR_SLASH   "/"
#else
#error "No directory separator specified for this platform"
#endif

/*----------------------------------------------------------------------------*/

extern MSTATUS COMMON_UTILS_unescapeNewLine(
    ubyte *pData,
    ubyte4 *pDataLen)
{
    MSTATUS status = OK;
    ubyte4 index, shift = 0;

    index = 0;
    while ((index + shift) < *pDataLen)
    {
        pData[index] = pData[index + shift];
        if ('\\' == pData[index])
        {
            pData[index] = '\n';
            shift++;
        }

        index++;
    }

    *pDataLen = index;

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS COMMON_UTILS_addPathComponentWithLength(
    sbyte *pPath,
    sbyte *pComponent,
    ubyte4 componentLen,
    sbyte **ppNewPath)
{
    MSTATUS status;
    sbyte4 pathLen, sepLen, len;
    sbyte *pNewPath = NULL;

    if (NULL == pPath || NULL == pComponent || NULL == ppNewPath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pathLen = DIGI_STRLEN(pPath);
    sepLen = DIGI_STRLEN(DIR_SLASH);

    len = pathLen + sepLen + componentLen;
    status = DIGI_MALLOC((void **) &pNewPath, len + 1);
    if (OK != status)
    {
        goto exit;
    }

    DIGI_MEMCPY(pNewPath, pPath, pathLen);
    DIGI_MEMCPY(pNewPath + pathLen, DIR_SLASH, sepLen);
    DIGI_MEMCPY(pNewPath + pathLen + sepLen, pComponent, componentLen);
    pNewPath[len] = '\0';

    if (NULL != *ppNewPath)
        DIGI_FREE((void **) ppNewPath);

    *ppNewPath = pNewPath;

exit:

    return status;
}

extern MSTATUS COMMON_UTILS_addPathComponent(
    sbyte *pPath,
    sbyte *pComponent,
    sbyte **ppNewPath)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL != pComponent)
    {
        status = COMMON_UTILS_addPathComponentWithLength(pPath, pComponent, DIGI_STRLEN(pComponent), ppNewPath);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS COMMON_UTILS_addPathExtension(
    sbyte *pPath,
    sbyte *pExtension,
    sbyte **ppNewPath)
{
    MSTATUS status;
    sbyte4 pathLen, extensionLen, len;
    sbyte *pNewPath = NULL;

    if (NULL == pPath || NULL == pExtension || NULL == ppNewPath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pathLen = DIGI_STRLEN(pPath);
    extensionLen = DIGI_STRLEN(pExtension);

    len = pathLen + extensionLen;
    status = DIGI_MALLOC((void **) &pNewPath, len + 1);
    if (OK != status)
    {
        goto exit;
    }

    DIGI_MEMCPY(pNewPath, pPath, pathLen);
    DIGI_MEMCPY(pNewPath + pathLen, pExtension, extensionLen);
    pNewPath[len] = '\0';

    if (NULL != *ppNewPath)
        DIGI_FREE((void **) ppNewPath);

    *ppNewPath = pNewPath;

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS COMMON_UTILS_splitPath(
    sbyte *path,
    sbyte **ppDirName,
    sbyte **ppFileName)
{
    MSTATUS  status = OK;
    int      idxD, idxF;

    if ( (NULL == path) || ((NULL == ppDirName) && (NULL == ppFileName)) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Clean up */
    DIGI_FREE ((void **)ppDirName);
    DIGI_FREE ((void **)ppFileName);

    /* Locate separator of dir and file name */
    for (idxD = DIGI_STRLEN ((const sbyte *)path)-1; 0 < idxD; --idxD)
    {
#if defined(__RTOS_WIN32__)
        if ('\\' == path[idxD])
#else
        if ('/' == path[idxD])
#endif
            break;
    }

    if (0 < idxD)
    {
        idxF = idxD + 1;
    }
    else
    {
        /* Did not find one? */
#if defined(__RTOS_WIN32__)
        if ('\\' == path[0])
#else
        if ('/' == path[0])
#endif
        {
            idxF = 1;
        }
        else
        {
            idxF = 0;
        }
    }

    /* Copy strings */
    if (NULL != ppDirName)
    {
        if (0 < idxD)
        {
            status = DIGI_MALLOC_MEMCPY ((void**)ppDirName, idxD+1, (void*)path, idxD);
            if (OK != status)
                goto exit;

            (*ppDirName)[idxD] = '\0';
        }
        else if (1 == idxF)
        {
            status = DIGI_MALLOC_MEMCPY ((void**)ppDirName, 2, (void*)path, 1);
            if (OK != status)
                goto exit;

            (*ppDirName)[1] = '\0';
        }
    }

    if (NULL != ppFileName)
    {
        if ((int) DIGI_STRLEN ((const sbyte *)path) > idxF)
        {
            status = DIGI_MALLOC_MEMCPY ((void**)ppFileName, (DIGI_STRLEN ((const sbyte *)path)-idxF)+1,
                                        (void*)(path+idxF), DIGI_STRLEN ((const sbyte *)path)-idxF);
            if (OK != status)
                goto exit;

            (*ppFileName)[DIGI_STRLEN ((const sbyte *)path)-idxF] = '\0';
        }
    }
exit:
    return status;
}

extern MSTATUS COMMON_UTILS_evaluatePlaceholder(
    sbyte *pPlaceholder,
    sbyte *pReplacement,
    sbyte **ppPath)
{
    MSTATUS status;
    sbyte4 len;
    sbyte *pNewPath = NULL;

    if ( (NULL == pPlaceholder) || (NULL == pReplacement) || (NULL == ppPath) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    len = DIGI_STRLEN(pPlaceholder);
    if (0 == DIGI_STRNCMP(pPlaceholder, *ppPath, len))
    {
        len = DIGI_STRLEN(*ppPath) - len + DIGI_STRLEN(pReplacement);

        status = DIGI_MALLOC((void **) &pNewPath, len + 1);
        if (OK != status)
        {
            goto exit;
        }

        DIGI_MEMCPY(pNewPath, pReplacement, DIGI_STRLEN(pReplacement));
        DIGI_MEMCPY(pNewPath + DIGI_STRLEN(pReplacement), *ppPath + DIGI_STRLEN(pPlaceholder), DIGI_STRLEN(*ppPath) - DIGI_STRLEN(pPlaceholder));
        pNewPath[len] = '\0';

        DIGI_FREE((void **) ppPath);

        *ppPath = pNewPath;
    }

    status = OK;

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_COMMON_UTILS__ */
