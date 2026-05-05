/*
 * freertos_fmgmt.c
 *
 * FreeRTOS File Management Abstraction Layer
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

#ifdef __FREERTOS_FMGMT__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/mfmgmt.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ff.h"

typedef struct
{
    DIR *pDir;
    FILINFO fileInfo;
} FreeRtosDirDescriptorWrapper;

extern intBoolean FREERTOS_pathExists (const sbyte *pFilePath, FileDescriptorInfo *pFileInfo)
{
    FILINFO  statFile = {0};

    if (NULL == pFilePath)
    {
        return FALSE;
    }

    if (0 != f_stat(pFilePath, &statFile))
    {
        if (NULL != pFileInfo)
        {
            DIGI_MEMSET (pFileInfo, 0x00, sizeof (FileDescriptorInfo));
            pFileInfo->type = FTNone;
        }
        return FALSE;
    }

    if (NULL == pFileInfo)
        return TRUE;

    /* If this is not a directory, assume a regular file */
    if (AM_DIR & statFile.fattrib)
    {
        pFileInfo->type = FTDirectory;
    }
    else
    {
        pFileInfo->type = FTFile;
    }

    pFileInfo->fileSize = (sbyte4)statFile.fsize;

    /* TODO: ftime is 32 bit, may need to combine with statFile.fdate and translate
     * to 64 bit time value */
    pFileInfo->modifyTime = statFile.ftime;

    if (AM_RDO & statFile.fattrib)
    {
        pFileInfo->isRead = TRUE;
        pFileInfo->isWrite = FALSE;
    }
    else
    {
        pFileInfo->isRead = TRUE;
        pFileInfo->isWrite = TRUE;
    }

    return TRUE;
}

extern MSTATUS FREERTOS_rename (const sbyte *pOldName, sbyte *pNewName)
{
    MSTATUS status = ERR_NULL_POINTER;

    if ((NULL == pOldName) || (NULL == pNewName))
        goto exit;

    if (0 == f_rename (pOldName, pNewName))
    {
        status = OK;
        goto exit;
    }

    status = ERR_FILE;

exit:
    return status;
}

extern MSTATUS FREERTOS_mkdir (const sbyte *pDirectoryName, ubyte4 mode)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pDirectoryName)
        goto exit;

    if (0 == (status = f_mkdir (pDirectoryName)))
    {
        return OK;
    }
    if ( FR_EXIST == status || FR_NO_FILE == status || FR_NO_PATH == status)
    {
        status = OK;
    }
    else
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"FREERTOS_mkdir: status = ", status);
        status = ERR_DIR_OPEN_FAILED;
    }

exit:
    return status;
}

static MSTATUS recursiveDelete (sbyte *pPath)
{
    MSTATUS status = OK;
    DirectoryDescriptor pDir = NULL;
    DirectoryEntry dirEntry;

    status = FREERTOS_remove (pPath, FALSE);
    if (OK == status)
    {
        goto exit;
    }

    if (FR_DENIED != status)
    {
        status = ERR_FILE;
        goto exit;
    }
    else
    {
        /* This is a non-empty directory - recurse it, delete the contents and try again */

        status = FREERTOS_getFirstFile (pPath, &pDir, &dirEntry);
        if (OK != status)
            goto exit;

        if (FTNone == dirEntry.type)
        {

        }
        else
        {
            ubyte pFullPath[256];
            ubyte *pFileName;
            ubyte4 fileNameLength;
            do
            {
                pFileName = dirEntry.pName;
                fileNameLength = dirEntry.nameLength;
                if (!(((2 == fileNameLength) && 0 == DIGI_STRNICMP((sbyte *)pFileName, (sbyte *)"..", 2)) ||
                      ((1 == fileNameLength) && 0 == DIGI_STRNICMP((sbyte *)pFileName, (sbyte *) ".", 1))))
                {
                    if((strlen(pPath) + strlen(pFileName) + 2) > sizeof(pFullPath))
                    {
                        status = ERR_DIR_INSUFFICIENT_MEMORY;
                        goto exit;
                    }
                    sprintf(pFullPath, "%s/%s", pPath, pFileName);
                    status = recursiveDelete (pFullPath);
                }
                status = FREERTOS_getNextFile (pDir, &dirEntry);
                if (OK != status)
                    goto exit;

            } while (FTNone != dirEntry.type);
        }
        
        if (NULL != pDir)
        {
            (void) FREERTOS_closeDir(&pDir);
        }

        status = recursiveDelete (pPath);
    }

exit:

    if (NULL != pDir)
    {
        (void) FREERTOS_closeDir(&pDir);
    }

    return status;
}

extern MSTATUS FREERTOS_remove (const sbyte *pFilePath, intBoolean recursive)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 tflags;

    if (NULL == pFilePath)
        goto exit;

    if (TRUE == recursive)
    {
        return recursiveDelete (pFilePath);
    }
    else
    {
        if (0 == f_unlink (pFilePath))
            return OK;
    }

    status = ERR_DIR_ACCESS_DENIED;

exit:
    return status;
}

extern MSTATUS FREERTOS_changeCWD (const sbyte *pNewCwd)
{
    MSTATUS status = ERR_NULL_POINTER;
    if (NULL == pNewCwd)
        goto exit;

    if (0 == f_chdir (pNewCwd))
        return OK;

    status = ERR_DIR_CHANGE_FAILED;

exit:
    return status;
}

extern MSTATUS FREERTOS_getCWD (sbyte *pCwd, ubyte4 cwdLength)
{
    MSTATUS status = ERR_NULL_POINTER;
    FRESULT res = FR_OK;

    if (NULL == pCwd)
        goto exit;

    res = f_getcwd (pCwd, cwdLength);
    if (OK == res)
    {
        status = OK;
        goto exit;
    }

    status = ERR_DIR_ACCESS_DENIED;

exit:
    return status;
}

/* -------------------------------------------------------------------------------- */

extern MSTATUS FREERTOS_getNextFile (DirectoryDescriptor pDirCtx, DirectoryEntry *pFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    FRESULT res = FR_OK;
    DirectoryEntry *pNewDirEntryCtx = NULL;
    FreeRtosDirDescriptorWrapper *pWrapper = NULL;
    DIR *pDir;

    if ((NULL == pDirCtx) || (NULL == pFileCtx))
        goto exit;

    pWrapper = (FreeRtosDirDescriptorWrapper *)pDirCtx;

    if (NULL == pWrapper->pDir)
        goto exit;

    pDir = (DIR *)(pWrapper->pDir);

    /* Previous entries from getNextFile calls are not guaranteed to be valid, overwrite
     * the FILINFO structure in the wrapper for every call */
    res = f_readdir (pDir, &pWrapper->fileInfo);
    if ((FR_OK != res) || (!pDir->sect))
    {
        pFileCtx->pCtx = NULL;
        pFileCtx->type = FTNone;
        pFileCtx->pName = NULL;
        pFileCtx->nameLength = 0;

        if (0 != res)
            status = ERR_DIR_INVALID_DESCRIPTOR;
        else
            status = OK;

        goto exit;
    }

    pFileCtx->pCtx = NULL;
    pFileCtx->pName = pWrapper->fileInfo.fname;
    pFileCtx->nameLength = DIGI_STRLEN ((const sbyte *) pWrapper->fileInfo.fname);

    /* If this is not a directory, assume a regular file */
    if (AM_DIR & pWrapper->fileInfo.fattrib)
    {
        pFileCtx->type = FTDirectory;
    }
    else
    {
        pFileCtx->type = FTFile;
    }

    status = OK;

exit:
    return status;
}

extern MSTATUS FREERTOS_getFirstFile (const sbyte *pDirPath, DirectoryDescriptor *ppNewDirCtx, DirectoryEntry *pFirstFile)
{
    MSTATUS status = ERR_NULL_POINTER;
    FRESULT res = FR_OK;
    DIR *pDir = NULL;
    FreeRtosDirDescriptorWrapper *pWrapper = NULL;
    sbyte pCurDir[256] = { 0 };

    if ((NULL == pDirPath) || (NULL == ppNewDirCtx))
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

    status = DIGI_CALLOC((void **)&pDir, 1, sizeof(DIR));
    if (OK != status)
        goto exit;

    res = f_opendir (pDir, pDirPath);
    if (FR_OK == res)
    {
        status = DIGI_CALLOC((void **)&pWrapper, 1, sizeof(FreeRtosDirDescriptorWrapper));
        if (OK != status)
            goto exit;

        pWrapper->pDir = pDir;
        *ppNewDirCtx = (DirectoryDescriptor) pWrapper;

        status = FREERTOS_getNextFile ((DirectoryDescriptor) pWrapper, pFirstFile);
        goto exit;
    }

    status = ERR_DIR_OPEN_FAILED;

exit:

    if(OK != status)
    {
        *ppNewDirCtx = NULL;
        if(pDir)
        {
            f_closedir(pDir);
            DIGI_FREE((void **)&pDir);
        }

        if (pWrapper)
        {
            DIGI_FREE((void **)&pWrapper);
        }
    }
    return status;
}

extern MSTATUS FREERTOS_closeDir (DirectoryDescriptor *ppDirCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    DIR *pDir = NULL;
    FreeRtosDirDescriptorWrapper *pWrapper = NULL;
    ubyte4 i = 0;
    FRESULT res = FR_OK;

    if (NULL == ppDirCtx)
        goto exit;

    pWrapper = (FreeRtosDirDescriptorWrapper *)(*ppDirCtx);
    if (NULL != pWrapper)
    {
        /* Free the wrapper */
        pDir = pWrapper->pDir;
        DIGI_FREE((void **)&pWrapper);

        /* Close the dir */
        res = f_closedir(pDir);
        DIGI_FREE((void **)&pDir);
        if (FR_OK == res)
        {
            *ppDirCtx = NULL;
            return OK;
        }
    }

    status = ERR_DIR_CLOSE_FAILED;

exit:
    return status;
}


/* -------------------------------------------------------------------------------- */

extern MSTATUS FREERTOS_fopen (const sbyte *pFileName, const sbyte *pMode, FileDescriptor *ppNewFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    FRESULT res = FR_OK;
    FIL *pFile;
    BYTE mode = 0;

    if ((NULL == pFileName) || (NULL == pMode) || (NULL == ppNewFileCtx))
        goto exit;

    status = ERR_INVALID_INPUT;


    if(pMode)
    {
        switch(pMode[0])
        {
            case 'r':
              mode = FA_READ;
              if( '+' == pMode[1])
                  mode |= FA_WRITE;
              break;
            case 'w':
              mode = FA_WRITE|FA_CREATE_ALWAYS;
              if( '+' == pMode[1])
                  mode |= FA_READ;
              break;
            case 'a':
              mode = FA_OPEN_ALWAYS;
              if( '+' == pMode[1])
                  mode |= FA_READ;
              break;
        }
    }

    status = DIGI_MALLOC((void **)&pFile, sizeof(FIL));
    if (OK != status)
        goto exit;

    res = f_open(pFile, pFileName, mode);
    if(FR_OK == res)
    {
        *ppNewFileCtx = (FileDescriptor) pFile;
        return OK;
    }

    *ppNewFileCtx = NULL;
    status = ERR_FILE_OPEN_FAILED;

exit:
    return status;
}

extern MSTATUS FREERTOS_fclose (FileDescriptor *ppFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    FRESULT res = FR_OK;
    FIL *pFile;

    if ((NULL == ppFileCtx) || (NULL == *ppFileCtx))
        goto exit;

    pFile = (FIL *)(*ppFileCtx);
    res = f_close(pFile);
    DIGI_FREE((void **)&pFile);
    *ppFileCtx = NULL;
    if (FR_OK == res)
    {
        status = OK;
    }
    else
    {
        status = ERR_FILE_CLOSE_FAILED;
    }
exit:
    return status;
}

extern MSTATUS FREERTOS_fread (ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesRead)
{
    MSTATUS status = ERR_NULL_POINTER;
    FRESULT res = FR_OK;
    FIL *pFile;
    ubyte4 readCount;
    ubyte4 size;

    if ((NULL == pFileCtx) || (NULL == pBuffer) || (NULL == pBytesRead))
        goto exit;

    if ((0 == itemSize) || (0 == numOfItems))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pFile = (FIL *) pFileCtx;

    /* Compute the total size and check for overflow */
    size = itemSize * numOfItems;

    res = f_read (pFile, (void *) pBuffer, size, &readCount);
    *pBytesRead = readCount;
    if (readCount < (itemSize * numOfItems))
    {
        /* If readCount is less than itemSize * numOfItems, then either an error occured
         * of end-of-file was reached. check if end-of-file was reached: */
        if (0 != f_eof (pFile))
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

extern MSTATUS FREERTOS_fwrite (const ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesWrote)
{
    MSTATUS status = ERR_NULL_POINTER;
    FRESULT res = FR_OK;
    FIL *pFile;
    ubyte4 writeCount;
    ubyte4 size;

    if ((NULL == pFileCtx) || (NULL == pBuffer) || (NULL == pBytesWrote))
        goto exit;

    if ((0 == itemSize) || (0 == numOfItems))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pFile = (FIL *) pFileCtx;

    /* Compute the total size and check for overflow */
    size = itemSize * numOfItems;

    res = f_write (pFile, (const void *) pBuffer, size, &writeCount);
    *pBytesWrote = writeCount;
    if ( (FR_OK == res) && (writeCount == (itemSize * numOfItems)) )
    {
        status = OK;
        goto exit;
    }

    status = ERR_FILE_WRITE_FAILED;

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_64_BIT__
extern MSTATUS FREERTOS_fseek (FileDescriptor pFileCtx, sbyte8 offset, ubyte4 m_whence)
#else
extern MSTATUS FREERTOS_fseek (FileDescriptor pFileCtx, sbyte4 offset, ubyte4 m_whence)
#endif
{
    MSTATUS status = ERR_NULL_POINTER;
    FIL *pFile;

    if (NULL == pFileCtx)
        goto exit;

    pFile = (FIL *) pFileCtx;

    switch (m_whence)
    {
        case MSEEK_SET:
            break;
        case MSEEK_CUR:
            offset = (f_tell(pFile) + (offset)) ;
            break;
        case MSEEK_END:
            offset = (file_size(pFile) - (offset)) ;
/*            f_lseek(fp->obj.objsize);  */
            break;
        default:
            status = ERR_FILE_INVALID_ARGUMENTS;
            goto exit;
    }

    if (0 == f_lseek (pFile, offset))
    {
        return OK;
    }

    status = ERR_FILE_SEEK_FAILED;

exit:
    return status;
}

extern MSTATUS FREERTOS_ftell (FileDescriptor pFileCtx, ubyte4 *pOffset)
{
    MSTATUS status = ERR_NULL_POINTER;
    FIL *pFile;
    sbyte4 offset;

    if ((NULL == pFileCtx) || (NULL == pOffset))
        goto exit;

    *pOffset = 0;
    pFile = (FIL *) pFileCtx;

    offset = f_tell (pFile);
    if (0 <= offset)
    {
        *pOffset = offset;
        status = OK;
        goto exit;
    }
    status = ERR_FILE_BAD_DATA;

exit:
    return status;
}

extern MSTATUS FREERTOS_fprintf (FileDescriptor pFileCtx, const sbyte *pFormat, ...)
{
    MSTATUS status = ERR_NULL_POINTER;
    FIL *pFile;
    va_list args;
    int iCount = 0;
    int iRet = 0;
    char printBuf[512];

    if ((NULL == pFileCtx) || (NULL == pFormat))
        goto exit;

    va_start (args, pFormat);
    pFile = (FIL *) pFileCtx;

    iCount = vsnprintf( printBuf, 512, pFormat, args );
    va_end( args );
    if(iCount > 0)
    {
      f_write (pFile, printBuf, iCount, &iRet);
      if(iRet != iCount)
          status = ERR_FILE;
    }
    status = OK;


exit:
    return status;
}

/* ------------------------------------------------------------------------- */

extern MSTATUS FREERTOS_fflush (FileDescriptor pFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    FIL *pFile;

    if (NULL == pFileCtx)
        goto exit;

    pFile = (FIL *) pFileCtx;

    if (0 == f_sync (pFile))
        return OK;

    status = ERR_FILE;

exit:
    return status;
}

/* ------------------------------------------------------------------------- */

extern sbyte* FREERTOS_fgets (sbyte *pString, ubyte4 stringLen, FileDescriptor pFileCtx)
{
    if ((NULL == pString) || (NULL == pFileCtx))
        return NULL;

    return f_gets (pString, stringLen, (FIL *) pFileCtx);
}

extern sbyte4 FREERTOS_fputs (sbyte *pString, FileDescriptor pFileCtx)
{
    if ((NULL == pString) || (NULL == pFileCtx))
        return -1; /* nonnegative value on success */

    return f_puts (pString, (FIL *) pFileCtx);
}

/* ------------------------------------------------------------------------- */

extern MSTATUS FREERTOS_getDirectoryPath (const sbyte *pFilePath, sbyte *pDirectoryPath, ubyte4 directoryPathLength)
{
    MSTATUS status;
    ubyte4 filePathLength;
    ubyte4 lastSlash;
    ubyte4 i;

    if (NULL == pFilePath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    filePathLength = DIGI_STRLEN (pFilePath);

    /* copy buffer and store the location of the last slash */
    for (i = 0; i < filePathLength; i++)
    {
        if ('/' == pFilePath[i]) lastSlash = i;
        pDirectoryPath[i] =  pFilePath[i];
    }

    pDirectoryPath[lastSlash] = '\0';

    status = OK;
exit:
    return status;
}

extern MSTATUS FREERTOS_getDirectoryPathAlloc (const sbyte *pFilePath, sbyte **ppDirectoryPath)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pDirectoryPath = NULL;
    ubyte4 directoryPathLength;
    ubyte4 filePathLength;
    ubyte4 lastSlash = 0;
    ubyte4 i;

    if ((NULL == pFilePath) || (NULL == ppDirectoryPath))
        goto exit;

    *ppDirectoryPath = NULL;

    filePathLength = DIGI_STRLEN (pFilePath);
    /* copy buffer and store the location of the last slash */
    for (i = 0; i < filePathLength; i++)
    {
        if ('/' == pFilePath[i]) lastSlash = i;
    }
    if(!lastSlash)
    {
        status = ERR_FILE;
        goto exit;
    }
    status = DIGI_MALLOC ((void **) &pDirectoryPath, lastSlash + 1);
    if (OK != status)
        goto exit;

    directoryPathLength = lastSlash;

    status = DIGI_MEMCPY ((void *) pDirectoryPath, pFilePath, directoryPathLength);
    if (OK != status)
        goto exit;

    pDirectoryPath[directoryPathLength] = '\0';
    *ppDirectoryPath = pDirectoryPath;
    pDirectoryPath = NULL;

exit:
    if (NULL != pDirectoryPath)
        DIGI_FREE((void **) &pDirectoryPath);

    return status;
}

extern MSTATUS FREERTOS_getFullPath (const sbyte *pRelativePath, sbyte *pAbsolutePath, ubyte4 absolutePathLength)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 relativeLength;
    if ((NULL == pRelativePath) || (NULL == pAbsolutePath))
        goto exit;

    relativeLength = DIGI_STRLEN (pRelativePath);
    if (absolutePathLength < (1 + relativeLength))
    {
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    status = DIGI_MEMCPY (pAbsolutePath, pRelativePath, relativeLength);
    if (OK != status)
        goto exit;

    pAbsolutePath[relativeLength] = '\0';

exit:
    return status;
}

extern MSTATUS FREERTOS_getFullPathAlloc (const sbyte *pRelativePath, sbyte **ppAbsolutePath)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte absolutePathComputedLength;
    sbyte *pAbsolutePath = NULL;

    if ((NULL == pRelativePath) || (NULL == ppAbsolutePath))
        goto exit;

    absolutePathComputedLength = DIGI_STRLEN (pRelativePath);

    status = DIGI_MALLOC((void **) &pAbsolutePath, absolutePathComputedLength + 1);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY ((void *) pAbsolutePath, pRelativePath, absolutePathComputedLength);
    if (OK != status)
        goto exit;

    pAbsolutePath[absolutePathComputedLength] = '\0';

    *ppAbsolutePath = pAbsolutePath;
    pAbsolutePath = NULL;

exit:
    if (NULL != pAbsolutePath)
        DIGI_FREE ((void **) &pAbsolutePath);

    return status;
}


extern MSTATUS FREERTOS_getEnvironmentVariableValue (const sbyte *pVariableName, sbyte *pValueBuffer, ubyte4 valueBufferLength)
{
    return ERR_NOT_IMPLEMENTED;
}

extern MSTATUS FREERTOS_getEnvironmentVariableValueAlloc (const sbyte *pVariableName, sbyte **ppValueBuffer)
{
    return ERR_NOT_IMPLEMENTED;
}

extern MSTATUS FREERTOS_getProcessPath (sbyte *pDirectoryPath, ubyte4 directoryPathLength, ubyte4 *pBytesRead)
{
    return ERR_NOT_IMPLEMENTED;
}

extern MSTATUS FREERTOS_getProcessPathAlloc (sbyte **ppDirectoryPath)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif /* __FREERTOS_FMGMT__ */
