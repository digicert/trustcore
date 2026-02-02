/*
 * osx_fmgmt.c
 *
 * OS X File Management Abstraction Layer
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

#ifdef __OSX_FMGMT__
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#define __USE_XOPEN_EXTENDED
#include <ftw.h>

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mfmgmt.h"

#define PROCESS_PATH_LEN_MAX PATH_MAX

extern intBoolean OSX_pathExists (const sbyte *pFilePath, FileDescriptorInfo *pFileInfo)
{
    struct stat statFile = { 0 };

    if (NULL == pFilePath)
        return FALSE;

    if (0 != stat((const char *) pFilePath, &statFile))
    {
        if (NULL != pFileInfo)
        {
            DIGI_MEMSET ((ubyte *) pFileInfo, 0x00, sizeof(FileDescriptorInfo));
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
    else if (0 != S_ISLNK(statFile.st_mode))  /* Test for a symbolic link. */
        pFileInfo->type = FTFile;
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

#if 0
    else if (0 != S_ISBLK(statFile.st_mode))  /* Test for a block special file. */
        *pFileInfo = isBlockFile;
    else if (0 != S_ISCHR(statFile.st_mode))  /* Test for a character special file. */
        *pFileInfo = isCharFile;
    else if (0 != S_ISFIFO(statFile.st_mode)) /* Test for a pipe of FIFO special file. */
        *pFileInfo = isFifo;
    else if (0 != S_ISSOCK(statFile.st_mode)) /* Test for a socket. */
        *pFileInfo = isSocket;
#endif

    return TRUE;
}

extern MSTATUS OSX_rename (const sbyte *pOldName, sbyte *pNewName)
{
    MSTATUS status = ERR_NULL_POINTER;

    if ((NULL == pOldName) || (NULL == pNewName))
        goto exit;

    if (0 == rename ((const char *) pOldName, (const char *) pNewName))
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
            break;
    };

exit:
    return status;
}

extern MSTATUS OSX_mkdir (const sbyte *pDirectoryName, ubyte4 mode)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pDirectoryName)
        goto exit;

    if (0 == mkdir ((const char *) pDirectoryName, mode))
    {
        return OK;
    }

    switch(errno)
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
#if 0
        case EACCES:
            /* Search permission is denied on a component of the path prefix, or write
             * permission is denied on the parent directory of the directory to be created. */
            status = ERR_DIR_ACCESS_DENIED;
            break;
        case ELOOP:
            /* A loop exists in symbolic links encountered during resolution of the
             * pDirectoryName argument. */
            status = ERR_DIR_SYMLINK_LOOP;
            break;
        case EMLINK:
            /* The link count of the parent directory would exceed max number of symbolic links. */
            status = ERR_DIR_MAX_SYMLINKS;
            break;
        case ENAMETOOLONG:
            /* The length of the pDirectoryName argument exceeds maximum path length or path
             * name component is longer than maximum path name length. */
            status = ERR_DIR_PATH_NAME_TOO_LONG;
            break;
        case ENOSPC:
            /* The file system does not contain enough space to hold the contents of the new
             * directory or to extend the parent directory of the new directory. */
            status = ERR_DIR_INSUFFICIENT_MEMORY;
            break;
        case ENOTDIR:
            /* A component of the path prefix is not a directory. */
            status = ERR_DIR_INVALID_PATH;
            break;
        case EROFS:
            /* The parent directory resides on a read-only file system. */
            status = ERR_DIR_ACCESS_DENIED;
            break;
#endif
        default:
            status = ERR_GENERAL;
            break;
    };

exit:
    return status;
}

extern MSTATUS OSX_remove (const sbyte *pFilePath, intBoolean recursive);

static int removeCallBack (const char *pFilePath, const struct stat *pStat, int flag, struct FTW *pFtw)
{
   MSTATUS status; 

   return OSX_remove ((const sbyte *) pFilePath, FALSE);
}

extern MSTATUS OSX_remove (const sbyte *pFilePath, intBoolean recursive)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 tflags;

    if (NULL == pFilePath)
        goto exit;

    if (TRUE == recursive)
    {
        tflags = FTW_F | FTW_D | FTW_DNR | FTW_NS | FTW_DP | FTW_SLN;

        if (0 == nftw ((const char *) pFilePath, removeCallBack, tflags, FTW_DEPTH | FTW_PHYS))
        {
            return OK;
        }
    }
    else
    {
        if (0 == remove ((const char *) pFilePath))
            return OK;
    }

    switch (errno)
    {
        case EACCES:
            /* Write access to the directory containing pFilePath is not allowed for
             * the process's effective UID, or one of the directories in pFilePath did
             * not allow search permission. */
            status = ERR_FILE_ACCESS_DENIED;
            break;
        case ENOENT:
            /* A component in pFilePath does not exist or is a dangling symbolic link, or
             * pFilePath is empty. */
            status = ERR_FILE_INVALID_PATH;
            break;
        case EBUSY:
            /* The file pFilePath cannot be unlinked because it is being used by the
             * system or another process. */
            status = ERR_FILE_IN_USE;
            break;
        case ENAMETOOLONG:
            /* pFilePath is too long. */
            status = ERR_FILE_NAME_TOO_LONG;
            break;
        case EISDIR:
            /* pFilePath refers to a directory. */
            status = ERR_FILE_IS_DIRECTORY;
            break;
        case ENOTEMPTY:
            status = ERR_DIR_NOT_EMPTY;
            break;
        default:
            status = ERR_GENERAL;
            break;
    };

exit:
    return status;
}

extern MSTATUS OSX_changeCWD (const sbyte *pNewCwd)
{
    MSTATUS status = ERR_NULL_POINTER;
    if (NULL == pNewCwd)
        goto exit;

    if (0 == chdir ((const char *) pNewCwd))
        return OK;

    switch (errno)
    {
        case EACCES:
            /* Search permission is denied for one of the components of pNewCwd */
            status = ERR_DIR_ACCESS_DENIED;
            break;
        case ENOENT:
            /* The directory specified in pNewCwd does not exist. */
            status = ERR_DIR_INVALID_PATH;
            break;
        case ENOTDIR:
            /* A component of pNewCwd is not a directory. */
            status = ERR_DIR_INVALID_PATH;
            break;
        case ENAMETOOLONG:
            /* pNewCwd is too long. */
            status = ERR_DIR_PATH_NAME_TOO_LONG;
            break;
        default:
            status = ERR_GENERAL;
            break;
    };

exit:
    return status;
}

extern MSTATUS OSX_getCWD (sbyte *pCwd, ubyte4 cwdLength)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCwd)
        goto exit;

    if (NULL != getcwd ((char *) pCwd, cwdLength))
        return OK;

    switch (errno)
    {
        case EACCES:
            /* Search permission is denied for one of the components of pNewPwd */
            status = ERR_DIR_ACCESS_DENIED;
            break;
        case ENOENT:
            /* The directory specified in pNewPwd does not exist. */
            status = ERR_DIR_INVALID_PATH;
            break;
        case ENOTDIR:
            /* A component of pNewPwd is not a directory. */
            status = ERR_DIR_INVALID_PATH;
            break;
        case ENAMETOOLONG:
            /* pNewPwd is too long. */
            status = ERR_DIR_PATH_NAME_TOO_LONG;
            break;
        case ERANGE:
            /* absolute path name is larger than cwdLength */
            status = ERR_BUFFER_OVERFLOW;
            break;
        default:
            status = ERR_GENERAL;
            break;
    };

exit:
    return status;
}

/* -------------------------------------------------------------------------------- */

extern MSTATUS OSX_getNextFile (DirectoryDescriptor pDirCtx, DirectoryEntry *pFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    struct dirent *pDirEntry = NULL;
    DirectoryEntry *pNewDirEntryCtx = NULL;
    DIR *pDir;

    if ((NULL == pDirCtx) || (NULL == pFileCtx))
        goto exit;

    pDir = (DIR *)(pDirCtx);

    /* If the end of the directory stream is reached, NULL is returned and
     * errno is not changed. If an error occurs, NULL is returned and errno
     * is set appropriately. To distinguish end of stream from an error, set
     * errno to zero before calling readdir() and check the value of errno
     * if NULL is returned. */
    errno = 0;

    pDirEntry = readdir (pDir);
    if (NULL == pDirEntry)
    {
        pFileCtx->pCtx = NULL;
        pFileCtx->type = FTNone;
        pFileCtx->pName = NULL;
        pFileCtx->nameLength = 0;

        if (0 != errno)
            status = ERR_DIR_INVALID_DESCRIPTOR;
        else
            status = OK;

        goto exit;
    }

    pFileCtx->pCtx = (void *) pDirEntry;
    pFileCtx->pName = (ubyte *) pDirEntry->d_name;
    pFileCtx->nameLength = DIGI_STRLEN ((const sbyte *) pFileCtx->pName);

    switch (pDirEntry->d_type)
    {
        case DT_BLK:
            pFileCtx->type = FTBlockFile;
            break;
        case DT_CHR:
            pFileCtx->type = FTCharFile;
            break;
        case DT_DIR:
            pFileCtx->type = FTDirectory;
            break;
        case DT_FIFO:
            pFileCtx->type = FTFifo;
            break;
        case DT_LNK:
            pFileCtx->type = FTSymLink;
            break;
        case DT_REG:
            pFileCtx->type = FTFile;
            break;
        case DT_SOCK:
            pFileCtx->type = FTSocket;
            break;
        case DT_UNKNOWN:
            pFileCtx->type = FTUnknown;
            break;
        default:
            pFileCtx->type = FTUnknown;
            break;

    };

    status = OK;

exit:
    return status;
}

extern MSTATUS OSX_getFirstFile (const sbyte *pDirPath, DirectoryDescriptor *ppNewDirCtx, DirectoryEntry *pFirstFile)
{
    MSTATUS status = ERR_NULL_POINTER;
    DIR *pDir = NULL;
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

    pDir = opendir ((const char *) pDirPath);
    if (NULL != pDir)
    {
        *ppNewDirCtx = (DirectoryDescriptor) pDir;

        status = OSX_getNextFile ((DirectoryDescriptor) pDir, pFirstFile);
        goto exit;
    }

    *ppNewDirCtx = NULL;
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
            break;
    };

exit:
    return status;
}

extern MSTATUS OSX_closeDir (DirectoryDescriptor *ppDirCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    DIR *pDir = NULL;

    if (NULL == ppDirCtx)
        goto exit;

    pDir = (DIR *)(*ppDirCtx);
    if (0 == closedir(pDir))
    {
        *ppDirCtx = NULL;
        return OK;
    }

    /* Only error closedir() sets is EBADF: Invalid directory stream descriptor */
    status = ERR_DIR_INVALID_DESCRIPTOR;

exit:
    return status;
}


/* -------------------------------------------------------------------------------- */

extern MSTATUS OSX_fopen (const sbyte *pFileName, const sbyte *pMode, FileDescriptor *ppNewFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;

    if ((NULL == pFileName) || (NULL == pMode) || (NULL == ppNewFileCtx))
        goto exit;

    pFile = fopen((const char *) pFileName, (const char *) pMode);
    if (NULL != pFile)
    {
        *ppNewFileCtx = (FileDescriptor) pFile;
        return OK;
    }

    *ppNewFileCtx = NULL;
    switch (errno)
    {
        case EINVAL:
            /* pMode is invalid */
            status = ERR_FILE_BAD_MODE;
            break;
        case EACCES:
            /* The requested access to file is denied. */
            status = ERR_FILE_ACCESS_DENIED;
            break;
        case EEXIST:
            /* pFileName already exists */
            status = ERR_FILE_EXISTS;
            break;
        case ENOENT:
            /* Component of directory in pFileName does not exist, or
             * is a dangling symbolic link. */
            status = ERR_FILE_INVALID_PATH;
            break;
        case EISDIR:
            /* pFileName refers to a directory and the access requested involved
             * writing */
            status = ERR_FILE_IS_DIRECTORY;
            break;
        default:
            status = ERR_GENERAL;
            break;
    };

exit:
    return status;
}

extern MSTATUS OSX_fclose (FileDescriptor *ppFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;

    if (NULL == ppFileCtx)
        goto exit;

    pFile = (FILE *)(*ppFileCtx);
    if (0 == fclose (pFile))
    {
        *ppFileCtx = NULL;
        return OK;
    }

    if (EBADF == errno)
        status = ERR_FILE_INVALID_DESCRIPTOR;
    else
        status = ERR_FILE;

exit:
    return status;
}

extern MSTATUS OSX_fread (ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesRead)
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

extern MSTATUS OSX_fwrite (const ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesWrote)
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
            break;
    }

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_64_BIT__
extern MSTATUS OSX_fseek (FileDescriptor pFileCtx, sbyte8 offset, ubyte4 m_whence)
#else
extern MSTATUS OSX_fseek (FileDescriptor pFileCtx, sbyte4 offset, ubyte4 m_whence)
#endif
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;
    ubyte4 whence;

    if (NULL == pFileCtx)
        goto exit;

    pFile = (FILE *) pFileCtx;

    switch (m_whence)
    {
        case MSEEK_SET:
            whence = SEEK_SET;
            break;
        case MSEEK_CUR:
            whence = SEEK_CUR;
            break;
        case MSEEK_END:
            whence = SEEK_END;
            break;
        default:
            status = ERR_FILE_INVALID_ARGUMENTS;
            goto exit;
    }

    if (0 == fseek (pFile, offset, whence))
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
            break;
    };

exit:
    return status;
}

/* ------------------------------------------------------------------------- */

extern MSTATUS OSX_fflush (FileDescriptor pFileCtx)
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

/* ------------------------------------------------------------------------- */

extern MSTATUS OSX_fprintf (FileDescriptor pFileCtx, const sbyte *pFormat, ...)
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;
    va_list args;

    if ((NULL == pFileCtx) || (NULL == pFormat))
        goto exit;

    va_start (args, pFormat);
    pFile = (FILE *) pFileCtx;

    if (0 <= vfprintf (pFile, (const char *) pFormat, args))
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

extern MSTATUS OSX_ftell (FileDescriptor pFileCtx, ubyte4 *pOffset)
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;
    sbyte4 offset;

    if ((NULL == pFileCtx) || (NULL == pOffset))
        goto exit;

    *pOffset = 0;

    offset = ftell (pFileCtx);
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
        case EOVERFLOW:
            status = ERR_BUFFER_OVERFLOW;
            break;
        case ESPIPE:
            status = ERR_FILE_INVALID_DESCRIPTOR;
            break;
        default:
            status = ERR_GENERAL;
            break;
    }

exit:
    return status;
}

extern sbyte* OSX_fgets (sbyte *pString, ubyte4 stringLen, FileDescriptor pFileCtx)
{
    if ((NULL == pString) || (NULL == pFileCtx))
        return NULL;

    return (sbyte *) fgets ((char *) pString, stringLen, (FILE *) pFileCtx);
}

extern sbyte4 OSX_fgetc (FileDescriptor pFileCtx)
{
    sbyte4 c;
    if (NULL == pFileCtx)
        return MOC_EOF;

    c = fgetc ((FILE *) pFileCtx);
    if (EOF == c)
        return MOC_EOF;

    return c;
} 

extern sbyte4 OSX_fputs (sbyte *pString, FileDescriptor pFileCtx)
{
    if ((NULL == pString) || (NULL == pFileCtx))
        return -1; /* nonnegative value on success */

    return fputs ((const char *) pString, (FILE *) pFileCtx);
}

/* ------------------------------------------------------------------------- */

extern MSTATUS OSX_getDirectoryPath (const sbyte *pFilePath, sbyte *pDirectoryPath, ubyte4 directoryPathLength)
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

extern MSTATUS OSX_getDirectoryPathAlloc (const sbyte *pFilePath, sbyte **ppDirectoryPath)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pDirectoryPath = NULL;
    ubyte4 directoryPathLength;
    ubyte4 filePathLength;
    ubyte4 lastSlash;
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

    status = DIGI_MALLOC ((void **) &pDirectoryPath, lastSlash);
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

extern MSTATUS OSX_getFullPath (const sbyte *pRelativePath, sbyte *pAbsolutePath, ubyte4 absolutePathLength)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte pAbsPath [PATH_MAX + 1] = { 0 };
    ubyte4 absolutePathComputedLength;
    ubyte4 fileNameLength;

    if ((NULL == pAbsolutePath) || (NULL == pRelativePath))
        goto exit;

    if (0 == DIGI_STRLEN(pRelativePath))
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (NULL == realpath (pRelativePath, pAbsPath))
    {
        switch (errno)
        {
            case EACCES:
                /* Read or search permission was denied for a component of pRelativePath. */
                status = ERR_FILE_ACCESS_DENIED;
                goto exit;
            case ENAMETOOLONG:
                /* The length of pRelativePath argument exceeds PATH_MAX or a pathname component is
                 * longer than NAME_MAX. */
                status = ERR_FILE_NAME_TOO_LONG;
                goto exit;
            case ENOENT:
                /* A component of pRelativePath does not name an existing file or pRelativePath is
                 * an empty string. */
                break;
            case ENOTDIR:
                /* A component of the path prefix is not a directory. */
                status = ERR_FILE_INVALID_PATH;
                goto exit;
            default:
                status = ERR_GENERAL;
                goto exit;
        }
    }

    absolutePathComputedLength = DIGI_STRLEN ((const sbyte *) pAbsPath);
    if (1 + absolutePathComputedLength > absolutePathLength)
        return ERR_BUFFER_OVERFLOW;

    status = DIGI_MEMCPY ((void *) pAbsolutePath, pAbsPath, absolutePathComputedLength);
    if (OK != status)
        goto exit;

    pAbsolutePath[absolutePathComputedLength] = '\0';

exit:
    return status;
}

extern MSTATUS OSX_getFullPathAlloc (const sbyte *pRelativePath, sbyte **ppAbsolutePath)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte pAbsPath [PATH_MAX + 1] = { 0 };
    ubyte4 absolutePathComputedLength;
    sbyte *pAbsolutePath = NULL;

    if (NULL == ppAbsolutePath)
        goto exit;

    *ppAbsolutePath = NULL;

    status = OSX_getFullPath(pRelativePath, pAbsPath, PATH_MAX);
    if (OK != status)
        goto exit;

    absolutePathComputedLength = DIGI_STRLEN ((const sbyte *) pAbsPath);

    status = DIGI_MALLOC((void **) &pAbsolutePath, absolutePathComputedLength + 1);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY ((void *) pAbsolutePath, pAbsPath, absolutePathComputedLength);
    if (OK != status)
        goto exit;

    pAbsolutePath[absolutePathComputedLength] = '\0';

    *ppAbsolutePath = pAbsolutePath;
    pAbsolutePath = NULL;

exit:
    if (NULL != pAbsolutePath)
        DIGI_FREE((void **) &pAbsolutePath);

    return status;
}


extern MSTATUS OSX_getEnvironmentVariableValue (const sbyte *pVariableName, sbyte *pValueBuffer, ubyte4 valueBufferLength)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pValue;
    ubyte4 valueLength;

    if ((NULL == pVariableName) || (NULL == pValueBuffer))
        goto exit;

    pValue = (sbyte *) getenv ((const char *) pVariableName);
    if (NULL == pValue)
        return ERR_FILE_NOT_EXIST;

    valueLength = DIGI_STRLEN ((const sbyte *) pValue);

    /* value length + null terminator */
    if ((valueLength + 1) > valueBufferLength)
        return ERR_BUFFER_OVERFLOW;

    status = DIGI_MEMCPY ((void *) pValueBuffer, pValue, valueLength);
    if (OK != status)
        goto exit;

    pValueBuffer[valueLength] = '\0';

exit:
    return status;
}

extern MSTATUS OSX_getEnvironmentVariableValueAlloc (const sbyte *pVariableName, sbyte **ppValueBuffer)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pValue;
    sbyte *pValueBuffer = NULL;
    ubyte4 valueLength;

    if ((NULL == pVariableName) || (NULL == ppValueBuffer))
        goto exit;

    *ppValueBuffer = NULL;
    pValue = (sbyte *) getenv ((const char *) pVariableName);
    if (NULL == pValue)
        return ERR_FILE_NOT_EXIST;

    valueLength = DIGI_STRLEN ((const sbyte *) pValue);

    status = DIGI_MALLOC ((void **) &pValueBuffer, valueLength + 1);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *) pValueBuffer, pValue, valueLength);
    if (OK != status)
        goto exit;

    pValueBuffer[valueLength] = '\0';

    *ppValueBuffer = pValueBuffer;
    pValueBuffer = NULL;

exit:

    return status;
}

extern MSTATUS OSX_getProcessPath (sbyte *pDirectoryPath, ubyte4 directoryPathLength, ubyte4 *pBytesRead)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte pDirPath[PROCESS_PATH_LEN_MAX];
    sbyte pRealPath[PROCESS_PATH_LEN_MAX];
    sbyte4 length = sizeof(pDirPath);

    if ((NULL == pDirectoryPath) || (NULL == pBytesRead))
        goto exit;

    if (directoryPathLength == 0)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (0 == _NSGetExecutablePath(pDirPath, &length))
    {
        if (NULL == realpath((const char *) pDirPath, (char *) pRealPath))
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
        length = DIGI_STRLEN(pRealPath);
        if (length + 1 > directoryPathLength)
        {
            status = ERR_BUFFER_TOO_SMALL;
            goto exit;
        }
        DIGI_MEMCPY(pDirectoryPath, pRealPath, length);
        pDirectoryPath[length] = '\0';

        *pBytesRead = length;

        status = OK;
        goto exit;
    }

    switch (errno)
    {
        case EACCES:
            /* Search permission is denied for a component of the path prefix. */
            status = ERR_FILE_ACCESS_DENIED;
            break;
        case EINVAL:
            /* directoryPathLength is not positive. Or the named file
             * is not a symbolic link. */
            status = ERR_FILE_INVALID_ARGUMENTS;
            break;
        case ENAMETOOLONG:
            /* A pathname or a component of a pathname was too long. */
            status = ERR_FILE_NAME_TOO_LONG;
            break;
        case ENOENT:
            /* The named file*/
            status = ERR_FILE_INVALID_PATH;
            break;
        case ENOTDIR:
            /* A component of the path prefix is not a directory */
            status = ERR_FILE_INVALID_PATH;
            break;
        default:
            status = ERR_GENERAL;
            break;
    }
exit:
    return status;
}

extern MSTATUS OSX_getProcessPathAlloc (sbyte **ppDirectoryPath)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 length;
    ubyte pBuffer[PROCESS_PATH_LEN_MAX];

    if (NULL == ppDirectoryPath)
        goto exit;

    status = FMGMT_getProcessPath((sbyte *) pBuffer, PROCESS_PATH_LEN_MAX, &length);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC_MEMCPY((void **) ppDirectoryPath, length + 1, pBuffer, length);
    if (OK != status)
        goto exit;

    (*ppDirectoryPath)[length] = '\0';

exit:

    return status;
}
#endif /* __OSX_FMGMT__ */
