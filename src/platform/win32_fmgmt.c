/*
 * win32_fmgmt.c
 *
 * Windows File Management Abstraction Layer
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

#ifdef __WIN32_FMGMT__
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <direct.h>
#include <Windows.h>
#include <winbase.h>

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mfmgmt.h"

#ifndef S_ISDIR
#define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
#endif

#ifndef S_ISREG
#define S_ISREG(mode)  (((mode) & S_IFMT) == S_IFREG)
#endif

#ifndef S_ISCHR
#define S_ISCHR(mode) (((mode) & S_IFMT) == S_IFCHR)
#endif

#ifndef S_ISFIFO
#define S_ISFIFO(mode) (((mode) & S_IFMT) == _S_IFIFO)
#endif

typedef struct Win32DirectoryDescriptor
{
    HANDLE hFind;
    WIN32_FIND_DATA *pFindFileData;
} Win32DirectoryDescriptor;


/* ------------------------------------------------------------------------- */
extern MSTATUS WIN32_stat (const sbyte *pPathName, void *pStatBuf)
{
    MSTATUS status = ERR_NULL_POINTER;

    if ((NULL == pPathName) || (NULL == pStatBuf))
        goto exit;

    if (0 == stat ((const char *)pPathName, pStatBuf))
        status = OK;
    else
        status = ERR_GENERAL;

exit:
    return status;
}

extern intBoolean WIN32_pathExists (const sbyte *pFilePath, FileDescriptorInfo *pFileInfo)
{
    struct stat statFile = { 0 };

    if (NULL == pFilePath)
        return FALSE;

    if (0 != stat(pFilePath, &statFile))
    {
        if (NULL != pFileInfo)
        {
            DIGI_MEMSET ((ubyte *)pFileInfo, 0x00, sizeof (FileDescriptorInfo));
            pFileInfo->type = FTNone;
        }
        return FALSE;
    }

    if (NULL == pFileInfo)
        return TRUE;

    if (0 != S_ISREG(statFile.st_mode))       /* Test for a regular file. */
        pFileInfo->type = FTFile;
    else if (0 != S_ISDIR(statFile.st_mode))  /* Test for a directory. */
        pFileInfo->type = FTDirectory;
    else
        pFileInfo->type = FTUnknown;

    pFileInfo->fileSize = statFile.st_size;

    pFileInfo->accessTime = statFile.st_atime;
    pFileInfo->createTime = statFile.st_ctime;
    pFileInfo->modifyTime = statFile.st_mtime;

    pFileInfo->gid = statFile.st_gid;
    pFileInfo->uid = statFile.st_uid;
    pFileInfo->mode = statFile.st_mode;

    if (0 == (S_IWRITE & statFile.st_mode))
        pFileInfo->isWrite = FALSE;
    else
        pFileInfo->isWrite = TRUE;

    if (0 == (S_IREAD & statFile.st_mode))
        pFileInfo->isRead = FALSE;
    else
        pFileInfo->isRead = TRUE;

    return TRUE;
}

extern MSTATUS WIN32_mkdir (const sbyte *pDirectoryName, ubyte4 mode)
{
    MSTATUS status = ERR_NULL_POINTER;
    errno_t err = 0;
    MOC_UNUSED(mode);

    if (NULL == pDirectoryName)
        goto exit;

    if (0 == _mkdir ((const char *) pDirectoryName))
    {
        return OK;
    }

    _get_errno (&err);
    switch(err)
    {
        case EEXIST:
            /* The named file exists. */
            status = ERR_DIR_EXISTS;
            break;
        case ENOENT:
            /* A component of the path prefix specified by pDirectoryName does not name an
             * existing directory or pDirectoryName is an empty string */
            status = ERR_DIR_INVALID_PATH;
            break;
        default:
            status = ERR_GENERAL;
    };

exit:
    return status;
}

static MSTATUS WIN32_removeDirRecursive(
    sbyte *pPath, sbyte4 pathLen, sbyte4 maxPathLen,
    WIN32_FIND_DATA *pFindFileData)
{
    MSTATUS status;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD Attributes;
    sbyte4 cFileNameLen;

    /* Check remaining length of pPath to avoid overflow. pathLen does
     * not include terminating character. */
    if (pathLen + 2 > maxPathLen - 1)
    {
        status = ERR_DIR_PATH_NAME_TOO_LONG;
        goto exit;
    }

    DIGI_MEMCPY(pPath + pathLen, "\\*", 2);
    pPath[pathLen + 2] = '\0';

    hFind = FindFirstFile(pPath, pFindFileData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        status = ERR_DIR_OPEN_FAILED;
        goto exit;
    }

    /* Increment by 1 for \\. Saves operation when looping through directory
     * and appending files/directories to the path. */
    pathLen++;

    do
    {
        if ( (DIGI_STRCMP(pFindFileData->cFileName, ".") != 0) &&
             (DIGI_STRCMP(pFindFileData->cFileName, "..") != 0) )
        {
            cFileNameLen = DIGI_STRLEN(pFindFileData->cFileName);
            if (pathLen + cFileNameLen > maxPathLen - 1)
            {
                status = ERR_PATH_NAME_TOO_LONG;
                goto exit;
            }

            DIGI_MEMCPY(pPath + pathLen, pFindFileData->cFileName, cFileNameLen);
            pPath[pathLen + cFileNameLen] = '\0';

            Attributes = GetFileAttributes(pPath);
            if (0 != (Attributes & FILE_ATTRIBUTE_DIRECTORY))
            {
                status = WIN32_removeDirRecursive(
                    pPath, pathLen + cFileNameLen, maxPathLen, pFindFileData);
                if (OK != status)
                    goto exit;
            }
            else
            {
                status = WIN32_remove(pPath, FALSE);
                if (OK != status)
                    goto exit;
            }
        }
    } while (0 != FindNextFile(hFind, pFindFileData));

    FindClose(hFind); hFind = INVALID_HANDLE_VALUE;

    /* Decrement pathLen to accomodate for increment done earlier */
    pPath[pathLen - 1] = '\0';
    /* Directory should be empty now, delete it without recursing */
    status = WIN32_remove(pPath, FALSE);

exit:

    if (INVALID_HANDLE_VALUE != hFind)
    {
        FindClose(hFind);
    }

    return status;
}

extern MSTATUS WIN32_remove (const sbyte *pFilePath, intBoolean recursive)
{
    MSTATUS status = ERR_NULL_POINTER;
    struct stat statFile = { 0 };
    sbyte pPath[MAX_PATH];
    WIN32_FIND_DATA FindFileData;
    DWORD lastErr;

    if (NULL == pFilePath)
        goto exit;

    if (0 != stat(pFilePath, &statFile))
    {
        status = ERR_PATH_IS_INVALID;
        goto exit;
    }

    if (TRUE == recursive)
    {
        if (0 != S_ISDIR(statFile.st_mode))
        {
            if (DIGI_STRLEN(pFilePath) >= sizeof(pPath))
            {
                status = ERR_DIR_PATH_NAME_TOO_LONG;
                goto exit;
            }
            DIGI_STRCBCPY(pPath, sizeof(pPath), pFilePath);
            status = WIN32_removeDirRecursive(
                pPath, DIGI_STRLEN(pPath), sizeof(pPath), &FindFileData);
        }
        else
        {
            status = ERR_DIR_NOT_DIRECTORY;
        }
    }
    else
    {
        if (0 != S_ISDIR(statFile.st_mode))
        {
            /* Only deletes empty directories and subdirectories */
            if (0 != RemoveDirectory(pFilePath))
            {
                status = OK;
                goto exit;
            }
        }
        else
        {
            if (0 != DeleteFile(pFilePath))
            {
                status = OK;
                goto exit;
            }
        }

        lastErr = GetLastError();
        switch (lastErr)
        {
            case ERROR_FILE_NOT_FOUND:
                status = ERR_FILE_INVALID_PATH;
                break;
            case ERROR_ACCESS_DENIED:
                status = ERR_FILE_ACCESS_DENIED;
                break;
            default:
                status = ERR_GENERAL;
                break;
        }
    }

exit:
    return status;
}

extern MSTATUS WIN32_getDirectoryPath (const sbyte *pFilePath, sbyte *pDirectoryPath, ubyte4 directoryPathLength)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 index;
    ubyte4 pathLen;
    if (NULL == pFilePath)
        goto exit;

    pathLen = DIGI_STRLEN(pFilePath);

    for (index = pathLen; index > 0; --index)
    {
        if ( ('/' == pFilePath[index]) || ('\\' == pFilePath[index]) )
        {
            break;
        }
    }

    if (0 == index)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pathLen = index + 1; /* Account for null-term */

    if (directoryPathLength < pathLen)
    {
        status = ERR_BUFFER_TOO_SMALL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pDirectoryPath, 0x00, directoryPathLength);

    status = DIGI_MEMCPY((void *)pDirectoryPath, (const void *)pFilePath, index);
    
exit:
    return status;
}

extern MSTATUS WIN32_getDirectoryPathAlloc (const sbyte *pFilePath, sbyte **ppDirectoryPath)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 index;
    ubyte4 pathLen;
    sbyte *pTempBuf = NULL;

    if (NULL == pFilePath)
        goto exit;

    pathLen = DIGI_STRLEN(pFilePath);

    for (index = pathLen; index > 0; --index)
    {
        if ( ('/' == pFilePath[index]) || ('\\' == pFilePath[index]) )
        {
            break;
        }
    }

    if (0 == index)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pTempBuf, 1, index + 1);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *) pTempBuf, (const void *)pFilePath, index);
    if (OK != status)
        goto exit;

   *ppDirectoryPath = pTempBuf;
    pTempBuf = NULL;

    status = OK;


exit:

    if (NULL != pTempBuf)
    {
        DIGI_FREE((void **)&pTempBuf);
    }

    return status;
}

extern MSTATUS WIN32_changeCWD (const sbyte *pNewWorkingDirectory)
{
    MSTATUS status = ERR_NULL_POINTER;
    if (NULL == pNewWorkingDirectory)
        goto exit;

    if (0 != _chdir(pNewWorkingDirectory))
    {
        switch (errno)
        {
            case ENOENT:
                status = ERR_DIR_INVALID_PATH;
                break;
            default:
                status = ERR_GENERAL;
                break;
        }
    }
    else
    {
        status = OK;
    }

exit:
    return status;
}

extern MSTATUS WIN32_getFullPath (const sbyte *pRelativePath, sbyte *pAbsolutePath, ubyte4 absolutePathLength)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 neededLen;

    if ((NULL == pRelativePath) || (NULL == pAbsolutePath))
        goto exit;

    neededLen = GetFullPathNameA(pRelativePath, 0, NULL, NULL);

    if (neededLen > absolutePathLength)
    {
        status = ERR_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (0 == GetFullPathNameA(pRelativePath, absolutePathLength, pAbsolutePath, NULL))
    {
        status = ERR_GENERAL;
        goto exit;
    }

    status = OK;

exit:
    return status;
}

extern MSTATUS WIN32_getFullPathAlloc (const sbyte *pRelativePath, sbyte **ppAbsolutePath)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 neededLen;
    sbyte *pTempBuf = NULL;

    if ((NULL == pRelativePath) || (NULL == ppAbsolutePath))
        goto exit;

    neededLen = GetFullPathNameA(pRelativePath, 0, NULL, NULL);

    status = DIGI_CALLOC((void **) &pTempBuf, 1, neededLen + 1);
    if (OK != status)
        goto exit;

    if (0 == GetFullPathNameA(pRelativePath, neededLen, pTempBuf, NULL))
    {
        status = ERR_GENERAL;
        goto exit;
    }

    *ppAbsolutePath = pTempBuf;
    pTempBuf = NULL;
    status = OK;

exit:

    if (NULL != pTempBuf)
    {
        DIGI_FREE((void **) &pTempBuf);
    }

    return status;
}

/* -------------------------------------------------------------------------------- */

extern MSTATUS WIN32_closedir (DirectoryDescriptor *ppContext)
{
    MSTATUS status = ERR_NULL_POINTER;
    Win32DirectoryDescriptor *pDirCtx;
    HANDLE hFind;

    if ((NULL == ppContext) || (NULL == *ppContext))
        goto exit;

    pDirCtx = (Win32DirectoryDescriptor *)*ppContext;
    hFind = pDirCtx->hFind;

    DIGI_FREE((void **) &(pDirCtx->pFindFileData));
    FindClose(hFind);
    DIGI_FREE((void **) &pDirCtx);
    status = OK;
exit:
    return status;
}

static void WIN32_updateDirEnt(WIN32_FIND_DATA *pData, DirectoryEntry *pFileCtx)
{
    pFileCtx->pCtx = pData;
    if (pData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        pFileCtx->type = FTDirectory;
    }
    else
    {
        pFileCtx->type = FTFile;
    }
    pFileCtx->pName = pData->cFileName;
    pFileCtx->nameLength = DIGI_STRLEN((const sbyte *) pData->cFileName);
}

extern MSTATUS WIN32_getNextFile (DirectoryDescriptor *pContext, DirectoryEntry *pFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    Win32DirectoryDescriptor *pDirCtx;
    DWORD lastErr;

    if ((NULL == pContext) || (NULL == pFileCtx))
        goto exit;

    pDirCtx = (Win32DirectoryDescriptor *) pContext;

    if (INVALID_HANDLE_VALUE == pDirCtx->hFind)
    {
        status = ERR_DIR_INVALID_DESCRIPTOR;
        goto exit;
    }

    if (0 == FindNextFile(pDirCtx->hFind, pDirCtx->pFindFileData))
    {
        lastErr = GetLastError();

        switch (lastErr)
        {
            /* Ran out of files to search for. Not a fatal error. */
            case ERROR_NO_MORE_FILES:
                pFileCtx->pCtx = NULL;
                pFileCtx->type = FTNone;
                pFileCtx->pName = NULL;
                pFileCtx->nameLength = 0;
                status = OK;
                break;
            default:
                status = ERR_GENERAL;
                break;
        }
        goto exit;
    }

    WIN32_updateDirEnt(pDirCtx->pFindFileData, pFileCtx);
    status = OK;

exit:
    return status;
}

extern MSTATUS WIN32_getFirstFile (const sbyte *pDirPath, DirectoryDescriptor *ppNewDirCtx, DirectoryEntry *pFirstFile)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pFilesExt = "\\\\*.*";
    ubyte4 filesExtLen;
    ubyte4 dirPathLen;
    sbyte *pTempBuf = NULL;
    Win32DirectoryDescriptor *pRetDirCtx = NULL;
    DWORD lastErr;
    sbyte pCurDir[256] = { 0 };

    if ( (NULL == pDirPath) || (NULL == ppNewDirCtx) || (NULL == pFirstFile) )
        goto exit;

    if (0 == DIGI_STRCMP(pDirPath, "."))
    {
        status = FMGMT_getCWD(pCurDir, sizeof(pCurDir));
        if (OK != status)
        {
            goto exit;
        }
        pDirPath = (const sbyte *) pCurDir;
    }

    status = DIGI_MALLOC((void **) &pRetDirCtx, sizeof(Win32DirectoryDescriptor));
    if (OK != status)
        goto exit;

    pRetDirCtx->hFind = INVALID_HANDLE_VALUE;

    status = DIGI_MALLOC((void **) &(pRetDirCtx->pFindFileData), sizeof(WIN32_FIND_DATA));
    if (OK != status)
        goto exit;

    /* 'FindFirstFile' also returns directories, so hopefully pFilesExt
     *  will only look for files with extensions */
    filesExtLen = DIGI_STRLEN((const sbyte *) pFilesExt);
    dirPathLen = DIGI_STRLEN((const sbyte *) pDirPath);

    status = DIGI_CALLOC((void **) &pTempBuf, 1, (dirPathLen + filesExtLen + 1));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *) pTempBuf, pDirPath, dirPathLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *) (pTempBuf + dirPathLen), pFilesExt, filesExtLen);
    if (OK != status)
        goto exit;

    pRetDirCtx->hFind = FindFirstFile((const char *)pTempBuf, pRetDirCtx->pFindFileData);
    /* Filter out '.' and '..' results */
    // while ((2 >= DIGI_STRLEN((const sbyte *) pRetDirCtx->pFindFileData->cFileName)) &&
    //        (INVALID_HANDLE_VALUE != pRetDirCtx))
    // {
    //     FindNextFile(pRetDirCtx->hFind, pRetDirCtx->pFindFileData);
    // }
    if (INVALID_HANDLE_VALUE == pRetDirCtx->hFind)
    {
        lastErr = GetLastError();
        switch (lastErr)
        {
            case ERROR_DIRECTORY:
                status = ERR_DIR_NOT_DIRECTORY;
                break;
            case ERROR_PATH_NOT_FOUND:
                status = ERR_DIR_INVALID_PATH;
                break;
            default:
                status = ERR_GENERAL;
                break;
        }
        goto exit;
    }

    WIN32_updateDirEnt(pRetDirCtx->pFindFileData, pFirstFile);

    // if (INVALID_HANDLE_VALUE != pRetDirCtx->hFind)
    // {
    //     pFirstFile->type = FTFile;
    //     pFirstFile->pName = ((ubyte *) pRetDirCtx->pFindFileData->cFileName);
    //     pFirstFile->nameLength = DIGI_STRLEN((const sbyte *)pRetDirCtx->pFindFileData->cFileName);
    // }
    // else
    // {
    //     pFirstFile->type = FTNone;
    //     pFirstFile->pName = NULL;
    //     pFirstFile->nameLength = 0;
    // }

    /* Still need to call closedir w/ handle if error */
    *ppNewDirCtx = (DirectoryDescriptor) pRetDirCtx;
    pRetDirCtx = NULL;
    /* Empty dir is not an error */
    status = OK;
   
exit:

    if (NULL != pRetDirCtx)
    {
        if (INVALID_HANDLE_VALUE != pRetDirCtx->hFind)
            FindClose(pRetDirCtx->hFind);
        
        if (NULL != pRetDirCtx->pFindFileData)
        {
            DIGI_FREE((void **) &(pRetDirCtx->pFindFileData));
        }

        DIGI_FREE((void **) &pRetDirCtx);
    }

    if (NULL != pTempBuf)
    {
        DIGI_FREE((void **) &pTempBuf);
    }

    return status;
}

/* -------------------------------------------------------------------------------- */

extern MSTATUS WIN32_fopen (const sbyte *pFileName, const sbyte *pMode, FileDescriptor *ppNewContext)
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;

    if ((NULL == pFileName) || (NULL == pMode) || (NULL == ppNewContext))
        goto exit;

    pFile = fopen(pFileName, pMode);
    if (NULL != pFile)
    {
        *ppNewContext = (FileDescriptor) pFile;
        return OK;
    }
    
exit:
    return status;
}

extern MSTATUS WIN32_fclose (FileDescriptor *ppContext)
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;

    if (NULL == ppContext)
        goto exit;

    pFile = (FILE *)(*ppContext);
    if (0 == fclose(pFile))
    {
        *ppContext = NULL;
        return OK;
    }

    if (EBADF == errno)
        status = ERR_FILE_INVALID_DESCRIPTOR;
    else
        status = ERR_FILE;

exit:
    return status;
}

extern MSTATUS WIN32_fread (ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesRead)
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;
    ubyte4 readCount;

    if ((NULL == pFileCtx) || (NULL == pBuffer) || (NULL == pBytesRead))
        goto exit;

    pFile = (FILE *) pFileCtx;
    readCount = fread ((void *) pBuffer, itemSize, numOfItems, pFile);
    *pBytesRead = readCount;
    if (readCount < (itemSize * numOfItems))
    {
        /* If readCount is less than itemSize * numOfItems, then either an error occured
         * of end-of-file was reached. check if end-of-file was reached: */
        if (0 != feof (pFile))
        {
            status = OK;
            goto exit;
        }
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

    status = OK;
exit:
    return status;
}

extern MSTATUS WIN32_fwrite (const ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesWrote)
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;
    ubyte4 writeCount;

    if ((NULL == pFileCtx) || (NULL == pBuffer) || (NULL == pBytesWrote))
        goto exit;

    pFile = (FILE *) pFileCtx;
    writeCount = fwrite ((const void *) pBuffer, itemSize, numOfItems, pFile);
    *pBytesWrote = writeCount;
    if (writeCount == (itemSize * numOfItems))
    {
        status = OK;
        goto exit;
    }

    switch (errno)
    {
        case EBADF:
            status = ERR_FILE_INVALID_DESCRIPTOR;
            break;
        case ENOMEM:
            status = ERR_FILE_INSUFFICIENT_MEMORY;
            break;
        default:
            status = ERR_GENERAL;
    }

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_64_BIT__
extern MSTATUS WIN32_fseek (void *pContext, sbyte8 offset, ubyte4 whence)
#else
extern MSTATUS WIN32_fseek (void *pContext, sbyte4 offset, ubyte4 whence)
#endif
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;
    ubyte4 l_whence;

    if (NULL == pContext)
        goto exit;

    pFile = (FILE *) pContext;

    switch(whence)
    {
        case MSEEK_SET:
            l_whence = SEEK_SET;
            break;
        case MSEEK_CUR:
            l_whence = SEEK_CUR;
            break;
        case MSEEK_END:
            l_whence = SEEK_END;
            break;
        default:
            status = ERR_FILE_INVALID_ARGUMENTS;
            goto exit;
    }

   if (0 == fseek (pFile, offset, l_whence))
   {
        return OK;
   }

    switch (errno)
    {
        case EINVAL:
            /* whence is not SEEK_SET, SEEK_END, or SEEK_CURR. or the resulting
             * file offset would be negative. */
            status = ERR_FILE_INVALID_ARGUMENTS;
            break;
        case ESPIPE:
            /* pFile is associated with a pipe, socket of FIFO */
            status = ERR_FILE_INVALID_DESCRIPTOR;
            break;
        case EBADF:
            /* pFile is not a open file descriptor */
            status = ERR_FILE_INVALID_DESCRIPTOR;
            break;
        default:
            status = ERR_GENERAL;
    };

exit:
    return status;
}

/* ------------------------------------------------------------------------- */

extern MSTATUS WIN32_getEnvironmentVariableValue (const sbyte *pEnvVarName, sbyte *pEnvVarValue, ubyte4 EnvVarValueLength)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 lenNeeded;

    if ((NULL == pEnvVarName) || (NULL == pEnvVarValue))
        goto exit;

    lenNeeded = GetEnvironmentVariable(pEnvVarName, NULL, 0);

    if (lenNeeded > EnvVarValueLength)
    {
        status = ERR_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (0 == GetEnvironmentVariable(pEnvVarName, pEnvVarValue, EnvVarValueLength))
    {
        status = ERR_GENERAL;
    }
    else
    {
        status = OK;
    }


exit:
    return status;
}

extern MSTATUS WIN32_getEnvironmentVariableValueAlloc (const sbyte *pEnvVarName, sbyte **ppEnvVarValue)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 lenNeeded;
    sbyte *pTempBuf = NULL;

    if ((NULL == pEnvVarName) || (NULL == ppEnvVarValue))
        goto exit;

    lenNeeded = GetEnvironmentVariable(pEnvVarName, NULL, 0);

    status = DIGI_CALLOC((void **)&pTempBuf, 1, lenNeeded + 1);
    if (OK != status)
        goto exit;

    if (0 == GetEnvironmentVariable(pEnvVarName, pTempBuf, lenNeeded))
    {
        status = ERR_GENERAL;
        goto exit;
    }

    *ppEnvVarValue = pTempBuf;
    pTempBuf = NULL;

exit:

    if (NULL != pTempBuf)
    {
        DIGI_FREE((void **)&pTempBuf);
    }

    return status;
}

extern MSTATUS WIN32_getProcessPath (sbyte *pDirectoryPath, ubyte4 directoryPathLength, ubyte4 *pBytesRead)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 length;

    if ( (NULL == pDirectoryPath) || (NULL == pBytesRead) )
        goto exit;

    length = GetModuleFileName(NULL, pDirectoryPath, directoryPathLength);
    if (0 == length)
    {
        if (ERROR_INSUFFICIENT_BUFFER == GetLastError())
            status = ERR_BUFFER_TOO_SMALL;
        else
            status = ERR_GENERAL;
        goto exit;
    }
    else if (length == directoryPathLength)
    {
        /* Not enough space for NULL terminating character */
        status = ERR_BUFFER_TOO_SMALL;
        goto exit;
    }

    *pBytesRead = length;

    status = OK;

exit:
    return status;
}

extern MSTATUS WIN32_getProcessPathAlloc (sbyte **ppDirectoryPath)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 length;
    ubyte pBuffer[MAX_PATH];

    if (NULL == ppDirectoryPath)
        goto exit;

    status = FMGMT_getProcessPath(pBuffer, MAX_PATH, &length);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC_MEMCPY(ppDirectoryPath, length + 1, pBuffer, length);
    if (OK != status)
        goto exit;

    (*ppDirectoryPath)[length] = '\0';

exit:

    return status;
}

extern MSTATUS WIN32_rename (const sbyte *pOldName, sbyte *pNewName)
{
    MSTATUS status = ERR_NULL_POINTER;

    if ((NULL == pOldName) || (NULL == pNewName))
        goto exit;

    if (0 == rename (pOldName, pNewName))
    {
        status = OK;
        goto exit;
    }

    switch (errno)
    {
        case EACCES:
            /* Permission denied. */
            status = ERR_DIR_ACCESS_DENIED;
            break;
        case ENFILE:
            /* The system-wide limit on total number of open files has been reached */
            status = ERR_DIR_MAX_OPEN_FILES;
            break;
        case ENOENT:
            /* Directory does not exist, or pDirPath is an empty string */
            status = ERR_DIR_INVALID_PATH;
            break;
        case ENOMEM:
            /* Insufficient memory to complete the operation. */
            status = ERR_DIR_INSUFFICIENT_MEMORY;
            break;
        case ENOTDIR:
            /* pDirPath is not a directory. */
            status = ERR_DIR_NOT_DIRECTORY;
            break;
        default:
            status = ERR_GENERAL;
    };

exit:
    return status;
}

extern MSTATUS WIN32_getCWD(sbyte *pCwd, ubyte4 cwdLength)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCwd)
        goto exit;

    if (NULL != getcwd (pCwd, cwdLength))
        return OK;

    switch (errno)
    {
        case ERANGE:
            /* absolute path name is larger than cwdLength */
            status = ERR_BUFFER_OVERFLOW;
            break;
#if 0
        case ENOMEM:
            /* If the buffer provided to getcwd is NULL then Windows allocates
             * the buffer and returns it to the caller. This API never passes
             * a NULL buffer so this case should never be hit.
             */
            status = ERR_MEM_ALLOC_FAIL;
            break;
#endif
        default:
            status = ERR_GENERAL;
            break;
    };

exit:
    return status;
}

extern MSTATUS WIN32_fflush(FileDescriptor pFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;

    if (NULL == pFileCtx)
        goto exit;

    pFile = (FILE *) pFileCtx;

    if (0 == fflush (pFile))
        return OK;

    /* only error fflush returns is EBADF */
    status = ERR_FILE_INVALID_DESCRIPTOR;

exit:
    return status; 
}

extern MSTATUS WIN32_fprintf(FileDescriptor pFileCtx, const sbyte *pFormat, ...)
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;
    va_list args;

    if ((NULL == pFileCtx) || (NULL == pFormat))
        goto exit;

    va_start (args, pFormat);
    pFile = (FILE *) pFileCtx;

    if (0 <= vfprintf (pFile, pFormat, args))
    {
        status = OK;
    }
    else if (ferror (pFile))
    {
        status = ERR_FILE_INVALID_ARGUMENTS;
    }

    va_end(args);

exit:
    return status;
}

extern MSTATUS WIN32_ftell(FileDescriptor pFileCtx, ubyte4 *pOffset)
{
    MSTATUS status = ERR_NULL_POINTER;
    long offset;

    if ( (NULL == pFileCtx) || (NULL == pOffset) )
    {
        goto exit;
    }

    *pOffset = 0;
    offset = ftell(pFileCtx);
    if (0 <= offset)
    {
        *pOffset = offset;
        status = OK;
        goto exit;
    }

    switch (errno)
    {
        case EBADF:
            status = ERR_FILE_INVALID_DESCRIPTOR;
            break;
        case EINVAL:
            status = ERR_FILE_INVALID_ARGUMENTS;
            break;
        default:
            status = ERR_GENERAL;
            break;
    }

exit:

    return status;
}

extern sbyte* WIN32_fgets (sbyte *pString, ubyte4 stringLen, FileDescriptor pFileCtx)
{
    if ((NULL == pString) || (NULL == pFileCtx))
        return NULL;

    return fgets (pString, stringLen, (FILE *) pFileCtx);
}

extern sbyte4 WIN32_fgetc(FileDescriptor pFileCtx)
{
    sbyte4 c;
    if (NULL == pFileCtx)
        return MOC_EOF;

    c = fgetc((FILE *) pFileCtx);
    if (EOF == c)
        return MOC_EOF;

    return c;
}

extern sbyte4 WIN32_fputs (sbyte *pString, FileDescriptor pFileCtx)
{
    if ((NULL == pString) || (NULL == pFileCtx))
        return -1; /* nonnegative value on success */

    return fputs (pString, (FILE *) pFileCtx);
}

/* Execute Process API needed */
#endif /* __WIN32_FMGMT__ */
