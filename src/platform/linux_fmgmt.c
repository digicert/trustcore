/*
 * linux_fmgmt.c
 *
 * Linux File Management Abstraction Layer
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

#include "../common/moptions.h"

#ifdef __LINUX_FMGMT__
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#define __USE_XOPEN_EXTENDED
#ifndef __RTOS_FREERTOS_ESP32__
#include <ftw.h>
#endif

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mfmgmt.h"

#define PROCESS_PATH_LEN_MAX 1024

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
#define MOUNT_PATH_MAX_LEN 256
static ubyte pMountPath[MOUNT_PATH_MAX_LEN];
static ubyte4 mountPathLen = 0;
#define WORKING_DIR_PATH_MAX_LEN 256
static ubyte pWorkingDirPath[WORKING_DIR_PATH_MAX_LEN];
static ubyte4 workingDirPathLen = 0;

extern signed int TP_setMountPoint (unsigned char *pNewMountPath)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 mountPathLength;

    if (NULL == pNewMountPath)
    {
        return ERR_NULL_POINTER;
    }

    mountPathLength = DIGI_STRLEN (pNewMountPath);
    if ((1 > mountPathLength) || (MOUNT_PATH_MAX_LEN <= (mountPathLength + 1)))
    {
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    status = DIGI_MEMCPY (pMountPath, pNewMountPath, mountPathLength);
    if (OK != status)
        goto exit;

    pMountPath[mountPathLength] = '\0';
    mountPathLen = mountPathLength;
exit:
    return status;
}

extern intBoolean LINUX_needFullPath ()
{
    return ((0 < mountPathLen) || (0 < workingDirPathLen));
}
#else
extern signed int TP_setMountPoint (unsigned char *pNewMountPath)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

extern MSTATUS LINUX_getFullPathAllocAux (const sbyte *pRelativePath, sbyte **ppAbsolutePath, intBoolean prefixMount);

extern intBoolean LINUX_pathExists (const sbyte *pFilePath, FileDescriptorInfo *pFileInfo)
{
    struct stat statFile = { 0 };
    ubyte *pFPath = NULL;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif

    if (NULL == pFilePath)
        return FALSE;

    pFPath = (ubyte *) pFilePath;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == LINUX_needFullPath ())
    {
        if (OK > LINUX_getFullPathAllocAux (pFilePath, (sbyte **) &pFPath, TRUE))
            return FALSE;

        freePath = TRUE;
    }
#endif

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (0 != lstat((const char*)pFPath, &statFile))
#else
    if (0 != stat((const char*)pFPath, &statFile))
#endif
    {
        if (NULL != pFileInfo)
        {
            DIGI_MEMSET ((ubyte *) pFileInfo, 0x00, sizeof (FileDescriptorInfo));
            pFileInfo->type = FTNone;
        }
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
        if (TRUE == freePath)
            DIGI_FREE ((void **) &pFPath);
#endif
        return FALSE;
    }

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        DIGI_FREE ((void **) &pFPath);
#endif

    if (NULL == pFileInfo)
    {
        return TRUE;
    }

    if (0 != S_ISREG(statFile.st_mode))       /* Test for a regular file. */
        pFileInfo->type = FTFile;
    else if (0 != S_ISDIR(statFile.st_mode))  /* Test for a directory. */
        pFileInfo->type = FTDirectory;
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    else if (0 != S_ISLNK(statFile.st_mode))  /* Test for a symbolic link. */
        return FALSE; /* We do not support symbolic links */
#endif
    else
        pFileInfo->type = FTUnknown;

    pFileInfo->fileSize = statFile.st_size;

    pFileInfo->accessTime = statFile.st_atime;
    pFileInfo->createTime = statFile.st_ctime;
    pFileInfo->modifyTime = statFile.st_mtime;

    pFileInfo->gid = statFile.st_gid;
    pFileInfo->uid = statFile.st_uid;
    pFileInfo->mode = statFile.st_mode;

    if (0 == (S_IWUSR & statFile.st_mode))
        pFileInfo->isWrite = FALSE;
    else
        pFileInfo->isWrite = TRUE;

    if (0 == (S_IRUSR & statFile.st_mode))
        pFileInfo->isRead = FALSE;
    else
        pFileInfo->isRead = TRUE;

    return TRUE;
}

extern MSTATUS LINUX_rename (const sbyte *pOldName, sbyte *pNewName)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pOldPath = NULL;
    sbyte *pNewPath = NULL;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freeOldPath = FALSE;
    intBoolean freeNewPath = FALSE;
#endif

    if ((NULL == pOldName) || (NULL == pNewName))
        goto exit;

    pOldPath = (sbyte *) pOldName;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == LINUX_needFullPath ())
    {
        status = LINUX_getFullPathAllocAux (pOldName, (sbyte **) &pOldPath, TRUE);
        if (OK != status)
            goto exit;
        freeOldPath = TRUE;
    }
#endif
    pNewPath = pNewName;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == LINUX_needFullPath ())
    {
        status = LINUX_getFullPathAllocAux (pNewName, (sbyte **) &pNewPath, TRUE);
        if (OK != status)
            goto exit;
        freeNewPath = TRUE;
    }
#endif

    errno = 0;
    if (0 == rename ((const char*)pOldPath, (const char*)pNewPath))
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
            /* old argument names a directory and new argument names a non-directory. */
            status = ERR_DIR_NOT_DIRECTORY;
            break;
        case EISDIR:
            /* the new argument poitns to a directory and the old argument points to
             * a file that is not a directory. */
            status = ERR_DIR_IS_DIRECTORY;
            break;
        case EEXIST:
            /* the link named by new id a directory and is not an empty directory. */
            status = ERR_DIR_EXISTS;
            break;
        default:
            status = ERR_GENERAL;
    };

exit:
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freeOldPath)
        DIGI_FREE ((void **) &pOldPath);

    if (TRUE == freeNewPath)
        DIGI_FREE ((void **) &pNewPath);
#endif
    return status;
}

extern MSTATUS LINUX_mkdir (const sbyte *pDirectoryName, ubyte4 mode)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pDPath = NULL;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif

    if (NULL == pDirectoryName)
        goto exit;

    pDPath = (sbyte *)pDirectoryName;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == LINUX_needFullPath ())
    {
        status = LINUX_getFullPathAllocAux (pDirectoryName, &pDPath, TRUE);
        if (OK != status)
            goto exit;
        freePath = TRUE;
    }
#endif

    if (0 == mkdir ((const char*)pDPath, mode))
    {
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
        if (TRUE == freePath)
            DIGI_FREE ((void **) &pDPath);
#endif
        return OK;
    }

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        DIGI_FREE ((void **) &pDPath);
#endif

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
        default:
            status = ERR_GENERAL;
    };

exit:
    return status;
}

extern MSTATUS LINUX_remove (const sbyte *pFilePath, intBoolean recursive);

#ifndef __RTOS_FREERTOS_ESP32__
static int removeCallBack (const char *pFilePath, const struct stat *pStat, int flag, struct FTW *pFtw)
{
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    /* mountPathLen is 0 if pMountPath is not set */
   return LINUX_remove (pFilePath + mountPathLen, FALSE);
#else
   return LINUX_remove ((const sbyte*)pFilePath, FALSE);
#endif
}
#else
static
MSTATUS recursiveDelete(const sbyte *pPath)
{
    sbyte *pDestDir = NULL;
    struct stat statFile = { 0 };
    DIR *pDir;
    struct dirent *pDent;
    int len;
    int plen, dlen;
    MSTATUS status = OK;

    /* Get file information */
    if (0 == stat(pPath, &statFile))
    {
        if ((statFile.st_mode & S_IFMT) == S_IFDIR)
        {
            pDir = opendir(pPath);
            while ((pDent = readdir(pDir)) != NULL)
            {
                if (pDent->d_name[0] && (pDent->d_name[0] != '.'))
                {
                    /* Append path to name */
                    plen = DIGI_STRLEN(pPath);
                    dlen = DIGI_STRLEN(pDent->d_name);
                    len = plen + dlen + 2;
                    status = DIGI_MALLOC((void **) &pDestDir, len);
                    if (OK != status)
                    {
                        break;
                    }
                    status = DIGI_MEMCPY(pDestDir, pPath, plen);
                    if (OK != status)
                    {
                        DIGI_FREE((void **) &pDestDir);
                        break;
                    }
                    pDestDir[plen] = '/';
                    status = DIGI_MEMCPY(&pDestDir[plen+1], pDent->d_name, dlen);
                    if (OK != status)
                    {
                        DIGI_FREE((void **) &pDestDir);
                        break;
                    }
                    pDestDir[len-1] = 0;

                    if (pDent->d_type == DT_DIR)
                    {
                        recursiveDelete(pDestDir);
                    }
                    else if (pDent->d_type == DT_REG)
                    {
                        if (remove(pDestDir) != 0)
                        {
                            DIGI_FREE((void **) &pDestDir);
                            status = ERR_GENERAL;
                            break;
                        }
                    }
                    DIGI_FREE((void **) &pDestDir);
                }
            }

            closedir(pDir);

            /* delete this directory */
            rmdir(pPath);
        }
        else if ((statFile.st_mode & S_IFMT) == S_IFREG)
        {
            if (remove(pPath) != 0)
            {
                status = ERR_GENERAL;
            }
        }
    }
    
    return status; 
}
#endif

extern MSTATUS LINUX_remove (const sbyte *pFilePath, intBoolean recursive)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 tflags;
    ubyte *pFPath = NULL;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif

    if (NULL == pFilePath)
        return ERR_NULL_POINTER;

    pFPath = (ubyte *) pFilePath;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == LINUX_needFullPath ())
    {
        status = LINUX_getFullPathAllocAux (pFilePath, (sbyte **) &pFPath, TRUE);
        if (OK != status)
            return status;
        freePath = TRUE;
    }
#endif

    if (TRUE == recursive)
    {
#ifndef __RTOS_FREERTOS_ESP32__
        errno = 0;
        tflags = FTW_F | FTW_D | FTW_DNR | FTW_NS | FTW_DP | FTW_SLN;

        if (0 == nftw ((const char*)pFPath, removeCallBack, tflags, FTW_DEPTH | FTW_PHYS))
        {
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
            if (TRUE == freePath)
                DIGI_FREE ((void **) &pFPath);
#endif
            return OK;
        }
#else
        if (0 == recursiveDelete(pFPath))
        {
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
            if (TRUE == freePath)
                DIGI_FREE ((void **) &pFPath);
#endif
            return OK;
        }
#endif
    }
    else
    {
        errno = 0;
        if (0 == remove ((const char*)pFPath))
        {
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
            if (TRUE == freePath)
                DIGI_FREE ((void **) &pFPath);
#endif
            return OK;
        }
    }

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        DIGI_FREE ((void **) &pFPath);
#endif

    switch (errno)
    {
        case EACCES:
            /* Write access to the directory containing pFPath is not allowed for
             * the process's effective UID, or one of the directories in pFPath did
             * not allow search permission. */
            status = ERR_FILE_ACCESS_DENIED;
            break;
        case ENOENT:
            /* A component in pFPath does not exist or is a dangling symbolic link, or
             * pFPath is empty. */
            status = ERR_FILE_INVALID_PATH;
            break;
        case EBUSY:
            /* The file pFPath cannot be unlinked because it is being used by the
             * system or another process. */
            status = ERR_FILE_IN_USE;
            break;
        case ENAMETOOLONG:
            /* pFPath is too long. */
            status = ERR_FILE_NAME_TOO_LONG;
            break;
        case EISDIR:
            /* pFPath refers to a directory. */
            status = ERR_FILE_IS_DIRECTORY;
            break;
        case ENOTEMPTY:
            status = ERR_DIR_NOT_EMPTY;
            break;
        default:
            status = ERR_GENERAL;
    };

    return status;
}

extern MSTATUS LINUX_changeCWD (const sbyte *pNewCwd)
{
    MSTATUS status = ERR_NULL_POINTER;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    ubyte *pDPath = NULL;
    ubyte4 newCwdLength = 0;
    FileDescriptorInfo fileInfo = { 0 };
#endif
    if (NULL == pNewCwd)
        return status;

#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (0 == chdir ((const char*)pNewCwd))
    {
        return OK;
    }

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
    };
#else
    if ('/' != pNewCwd[0])
    {
        status = ERR_DIR_INVALID_PATH;
        goto exit;
    }

    pDPath = (sbyte *)pNewCwd;

    /* Make sure path we are changing to actually exists */
    if (TRUE == FMGMT_pathExists (pDPath, &fileInfo))
    {
        if (FTDirectory == fileInfo.type)
        {
            newCwdLength = DIGI_STRLEN ((const sbyte *) pNewCwd);
            if ((1 > newCwdLength) || (WORKING_DIR_PATH_MAX_LEN <= (newCwdLength + 1)))
            {
                status = ERR_BUFFER_TOO_SMALL;
                goto exit;
            }

            status = DIGI_MEMCPY (pWorkingDirPath, pNewCwd, newCwdLength);
            if (OK != status)
                goto exit;

            pWorkingDirPath[newCwdLength] = '\0';
            workingDirPathLen = newCwdLength;
        }
        else
        {
            /* ENOTDIR */
            status = ERR_DIR_INVALID_PATH;
        }
    }
    else
    {
        /* ENOENT */
        status = ERR_DIR_INVALID_PATH;
    }
exit:
#endif
    return status;
}

extern MSTATUS LINUX_getCWD (sbyte *pCwd, ubyte4 cwdLength)
{
    MSTATUS status = ERR_NULL_POINTER;
    if (NULL == pCwd)
        goto exit;

#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__

    if (NULL != getcwd ((char*)pCwd, cwdLength))
        return OK;

    switch (errno)
    {
        case EACCES:
            /* Search permission is denied for one of the components of pCwd */
            status = ERR_DIR_ACCESS_DENIED;
            break;
        case ENOENT:
            /* The current working directory has been unlinked. */
            status = ERR_DIR_INVALID_PATH;
            break;
        case ENAMETOOLONG:
            /* the absolute path string exceeds PATH_MAX. */
            status = ERR_DIR_PATH_NAME_TOO_LONG;
            break;
        case ERANGE:
            /* absolute path name is larger than cwdLength */
            status = ERR_BUFFER_OVERFLOW;
            break;
        default:
            status = ERR_GENERAL;
    };
#else
    if (0 < workingDirPathLen)
    {
        if ((workingDirPathLen + 1) > cwdLength)
        {
            status = ERR_BUFFER_TOO_SMALL;
            goto exit;
        }

        status = DIGI_MEMCPY (pCwd, pWorkingDirPath, workingDirPathLen);
        if (OK != status)
            goto exit;

        pCwd[workingDirPathLen] = '\0';
    }
    else
    {
        if (2 > cwdLength)
        {
            status = ERR_BUFFER_TOO_SMALL;
            goto exit;
        }

        pCwd[0] = '/';
        pCwd[1] = '\0';
        status = OK;
    }
#endif
exit:
    return status;
}

/* -------------------------------------------------------------------------------- */

extern MSTATUS LINUX_getNextFile (DirectoryDescriptor pDirCtx, DirectoryEntry *pFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    struct dirent *pDirEntry = NULL;
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

    pDirEntry = readdir(pDir);
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
    pFileCtx->pName = (ubyte*)pDirEntry->d_name;
    pFileCtx->nameLength = DIGI_STRLEN ((const sbyte *) pFileCtx->pName);

    switch (pDirEntry->d_type)
    {
#ifndef __RTOS_FREERTOS_ESP32__
        case DT_BLK:
            pFileCtx->type = FTBlockFile;
            break;
        case DT_CHR:
            pFileCtx->type = FTCharFile;
            break;
#endif
        case DT_DIR:
            pFileCtx->type = FTDirectory;
            break;
#ifndef __RTOS_FREERTOS_ESP32__
        case DT_FIFO:
            pFileCtx->type = FTFifo;
            break;
        case DT_LNK:
            pFileCtx->type = FTSymLink;
            break;
#endif
        case DT_REG:
            pFileCtx->type = FTFile;
            break;
#ifndef __RTOS_FREERTOS_ESP32__
        case DT_SOCK:
            pFileCtx->type = FTSocket;
            break;
#endif
        case DT_UNKNOWN:
            pFileCtx->type = FTUnknown;
            break;
        default:
            pFileCtx->type = FTUnknown;

    };

    status = OK;

exit:
    return status;
}

extern MSTATUS LINUX_getFirstFile (const sbyte *pDirPath, DirectoryDescriptor *ppNewDirCtx, DirectoryEntry *pFirstFile)
{
    MSTATUS status = ERR_NULL_POINTER;
    DIR *pDir = NULL;
    sbyte *pDPath = NULL;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    sbyte pCurDir[256] = { 0 };

    if ((NULL == pDirPath) || (NULL == ppNewDirCtx) || (NULL == pFirstFile))
        goto exit;

    if (0 == DIGI_STRCMP(pDirPath, (const sbyte*)"."))
    {
        status = FMGMT_getCWD(pCurDir, sizeof(pCurDir));
        if (OK != status)
        {
            goto exit;
        }
        pDirPath = (const sbyte *) pCurDir;
    }

    pDPath = (sbyte *)pDirPath;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == LINUX_needFullPath ())
    {
        status = LINUX_getFullPathAllocAux (pDirPath, (sbyte **) &pDPath, TRUE);
        if (OK != status)
            goto exit;
        freePath = TRUE;
    }
#endif

    pDir = opendir ((const char*)pDPath);
    if (NULL != pDir)
    {
        *ppNewDirCtx = (DirectoryDescriptor) pDir;

        status = LINUX_getNextFile ((DirectoryDescriptor) pDir, pFirstFile);
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
            /* Directory does not exist, or pDPath is an empty string */
            status = ERR_DIR_INVALID_PATH;
            break;
        case ENOMEM:
            /* Insufficient memory to complete the operation. */
            status = ERR_DIR_INSUFFICIENT_MEMORY;
            break;
        case ENOTDIR:
            /* pDPath is not a directory. */
            status = ERR_DIR_NOT_DIRECTORY;
            break;
        default:
            status = ERR_GENERAL;
    };

exit:
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        DIGI_FREE ((void **) &pDPath);
#endif
    return status;
}

extern MSTATUS LINUX_closeDir (DirectoryDescriptor *ppDirCtx)
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

extern MSTATUS LINUX_fopen (const sbyte *pFileName, const sbyte *pMode, FileDescriptor *ppNewFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;
    sbyte *pFPath = NULL;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif

    if ((NULL == pFileName) || (NULL == pMode) || (NULL == ppNewFileCtx))
        return ERR_NULL_POINTER;

    *ppNewFileCtx = NULL;
    pFPath = (sbyte *) pFileName;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == LINUX_needFullPath ())
    {
        status = LINUX_getFullPathAllocAux (pFileName, (sbyte **) &pFPath, TRUE);
        if (OK != status)
            return status;
        freePath = TRUE;
    }

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (DIGI_STRNCMP(pFPath, MANDATORY_BASE_PATH, DIGI_STRLEN(MANDATORY_BASE_PATH)) != 0)
    {
        /* File path must start with the mandatory base path */
        if (TRUE == freePath)
            DIGI_FREE ((void **) &pFPath);
        return ERR_FILE_INSECURE_PATH;
    }
#endif /* __ENABLE_DIGICERT_SECURE_PATH__ */
#endif /* __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__ */

    pFile = fopen((const char* __restrict)pFPath, (const char* __restrict)pMode);
    if (NULL != pFile)
    {
        *ppNewFileCtx = (FileDescriptor) pFile;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
        if (TRUE == freePath)
            DIGI_FREE ((void **) &pFPath);
#endif
        return OK;
    }

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        DIGI_FREE ((void **) &pFPath);
#endif

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
            /* pFPath already exists */
            status = ERR_FILE_EXISTS;
            break;
        case ENOENT:
            /* Component of directory in pFPath does not exist, or
             * is a dangling symbolic link. */
            status = ERR_FILE_INVALID_PATH;
            break;
        case EISDIR:
            /* pFPath refers to a directory and the access requested involved
             * writing */
            status = ERR_FILE_IS_DIRECTORY;
            break;
        default:
            status = ERR_GENERAL;
    };

    return status;
}

extern MSTATUS LINUX_fclose (FileDescriptor *ppFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;

    if ((NULL == ppFileCtx) || (NULL == *ppFileCtx))
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

extern MSTATUS LINUX_fread (ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesRead)
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

extern MSTATUS LINUX_fwrite (const ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesWrote)
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
extern MSTATUS LINUX_fseek (FileDescriptor pFileCtx, sbyte8 offset, ubyte4 m_whence)
#else
extern MSTATUS LINUX_fseek (FileDescriptor pFileCtx, sbyte4 offset, ubyte4 m_whence)
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
    };

exit:
    return status;
}

/* ------------------------------------------------------------------------- */

extern MSTATUS LINUX_fflush (FileDescriptor pFileCtx)
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

extern MSTATUS LINUX_fprintf (FileDescriptor pFileCtx, const sbyte *pFormat, ...)
{
    MSTATUS status = ERR_NULL_POINTER;
    FILE *pFile;
    va_list args;

    if ((NULL == pFileCtx) || (NULL == pFormat))
        goto exit;

    va_start (args, pFormat);
    pFile = (FILE *) pFileCtx;

    if (0 <= vfprintf (pFile, (const char* __restrict)pFormat, args))
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

extern MSTATUS LINUX_ftell (FileDescriptor pFileCtx, ubyte4 *pOffset)
{
    MSTATUS status = ERR_NULL_POINTER;
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
    }

exit:
    return status;
}

extern sbyte* LINUX_fgets (sbyte *pString, ubyte4 stringLen, FileDescriptor pFileCtx)
{
    if ((NULL == pString) || (NULL == pFileCtx))
        return NULL;

    return (sbyte*)fgets ((char* __restrict)pString, stringLen, (FILE *) pFileCtx);
}

extern sbyte4 LINUX_fgetc (FileDescriptor pFileCtx)
{
    sbyte4 c;
    if (NULL == pFileCtx)
        return MOC_EOF;

    c = fgetc ((FILE *) pFileCtx);
    if (EOF == c)
        return MOC_EOF;

    return c;
}

extern sbyte4 LINUX_fputs (sbyte *pString, FileDescriptor pFileCtx)
{
    if ((NULL == pString) || (NULL == pFileCtx))
        return -1; /* nonnegative value on success */

    return fputs ((const char* __restrict)pString, (FILE *) pFileCtx);
}

/* ------------------------------------------------------------------------- */

extern MSTATUS LINUX_getDirectoryPath (const sbyte *pFilePath, sbyte *pDirectoryPath, ubyte4 directoryPathLength)
{
    MSTATUS status;
    ubyte4 filePathLength;
    ubyte4 lastSlash = 0;
    ubyte4 i;
    ubyte *pFPath = NULL;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif

    if (NULL == pFilePath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pFPath = (ubyte *) pFilePath;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == LINUX_needFullPath ())
    {
        status = LINUX_getFullPathAllocAux (pFilePath, (sbyte **) &pFPath, FALSE);
        if (OK != status)
            goto exit;
        freePath = TRUE;
    }
#endif
    filePathLength = DIGI_STRLEN ((const sbyte*)pFPath);

    /* copy buffer and store the location of the last slash */
    for (i = 0; i < filePathLength; i++)
    {
        if ('/' == pFPath[i]) lastSlash = i;
        pDirectoryPath[i] =  pFPath[i];
    }

    pDirectoryPath[lastSlash] = '\0';

    status = OK;
exit:
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        DIGI_FREE ((void **) &pFPath);
#endif
    return status;
}

extern MSTATUS LINUX_getDirectoryPathAlloc (const sbyte *pFilePath, sbyte **ppDirectoryPath)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pDirectoryPath = NULL;
    ubyte4 directoryPathLength;
    ubyte4 filePathLength;
    ubyte4 lastSlash = 0;
    ubyte4 i;
    sbyte *pFPath = NULL;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif

    if ((NULL == pFilePath) || (NULL == ppDirectoryPath))
        goto exit;

    *ppDirectoryPath = NULL;
    pFPath = (sbyte *) pFilePath;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == LINUX_needFullPath ())
    {
        status = LINUX_getFullPathAllocAux (pFilePath, (sbyte **) &pFPath, FALSE);
        if (OK != status)
            goto exit;
        freePath = TRUE;
    }
#endif

    filePathLength = DIGI_STRLEN (pFPath);
    /* copy buffer and store the location of the last slash */
    for (i = 0; i < filePathLength; i++)
    {
        if ('/' == pFPath[i]) lastSlash = i;
    }

    if (0 == lastSlash)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    status = DIGI_MALLOC ((void **) &pDirectoryPath, lastSlash + 1);
    if (OK != status)
        goto exit;

    directoryPathLength = lastSlash;

    status = DIGI_MEMCPY ((void *) pDirectoryPath, pFPath, directoryPathLength);
    if (OK != status)
        goto exit;

    pDirectoryPath[directoryPathLength] = '\0';
    *ppDirectoryPath = pDirectoryPath;
    pDirectoryPath = NULL;

exit:
    if (NULL != pDirectoryPath)
        DIGI_FREE((void **) &pDirectoryPath);

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        DIGI_FREE ((void **) &pFPath);
#endif
    return status;
}

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
static int moveToNextSlash (ubyte *ptr, sbyte4 *ptrIndex, sbyte4 size)
{
    intBoolean foundSlash = FALSE;
    sbyte4 i = *ptrIndex;

    i++;
    while ((i < size) && (FALSE == foundSlash))
    {
        if ('/' == ptr[i])
        {
            foundSlash = TRUE;
        }
        else
        {
            i++;
        }
    }

    *ptrIndex = i;
    return 0;
}

static int moveToPrevSlash (ubyte *ptr, sbyte4 *ptrIndex)
{
    sbyte i = *ptrIndex;
    intBoolean foundSlash = FALSE;

    if (i <= 0)
        return -1;

    while ((i > 0) && (FALSE == foundSlash))
    {
        i--;
        if ('/' == ptr[i]) foundSlash = TRUE;
    }

    if (FALSE == foundSlash)
        return -1;

    *ptrIndex = i;
    return 0;
}

static int copyTokenToBuffer (ubyte *pSrc, sbyte4 *srcIndex, sbyte4 srcSize,
                    ubyte *pDst, sbyte4 *dstIndex, sbyte4 dstSize)
{
    intBoolean foundSlash = FALSE;
    sbyte4 s = *srcIndex;
    sbyte4 d = *dstIndex;
    while ((s < srcSize) && (FALSE == foundSlash))
    {
        pDst[d] = pSrc[s];
        s++;
        d++;
        if ('/' == pSrc[s])
        {
            foundSlash = TRUE;
        }
    }

    *srcIndex = s;
    *dstIndex = d;
    return 0;
}

static intBoolean isDoubleDotOp (ubyte *ptr, sbyte4 index, sbyte4 size)
{
    sbyte4 remainingSize = size - index;

    if (remainingSize < 2)
    {
        return FALSE;
    }
    else if ((size - index) == 2)
    {
        if (('.' == ptr[index + 1]) && ('.' == ptr[index + 2]))
            return TRUE;
        return FALSE;
    }
    else
    {
        if (('.' == ptr[index + 1]) && ('.' == ptr[index + 2]) && ('/' == ptr[index + 3]))
            return TRUE;
        return FALSE;
    }
}

static MSTATUS LINUX_getFullPathAux (const sbyte *pRelativePath, sbyte *pAbsolutePath, ubyte4 absolutePathLength, intBoolean prefixMount)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 absolutePathComputedLength;
    ubyte4 mountPathLength = 0;
    ubyte4 directoryPathLength = 0;
    ubyte4 relativePathLength;
    ubyte *pTmp;
    sbyte4 tmpIndex;
    sbyte4 tmpLen;
    ubyte *pDst;
    sbyte4 dstIndex;
    sbyte4 dstLen;
    ubyte *pOutTmp = NULL;
    sbyte4 outTmpLen = 0;

    if ((0 == mountPathLen) && (0 == workingDirPathLen))
    {
        /* If both mount point and working directory are NULL,
         * leave relative path as is. */
        relativePathLength = DIGI_STRLEN (pRelativePath);
        status = DIGI_MEMCPY (pAbsolutePath, pRelativePath, relativePathLength);
        if (OK != status)
            goto exit;

        pAbsolutePath[relativePathLength] = '\0';
        goto exit;
    }
    /* MOUNT PATH -- block */
    if ((0 < mountPathLen) && (TRUE == prefixMount))
        mountPathLength = mountPathLen;

    /* If mount path is /, there is nothing to prefix */
    if ((mountPathLength == 1) && ('/' == pMountPath[0]))
        mountPathLength = 0;
    /* MOUNT PATH -- block end */

    relativePathLength = DIGI_STRLEN (pRelativePath);

    if (0 < workingDirPathLen)
    {
        directoryPathLength = DIGI_STRLEN (pWorkingDirPath);

        if ((1 == relativePathLength) && ('.' == pRelativePath[0]))
        {
            if ((workingDirPathLen + 1) > absolutePathLength)
            {
                return ERR_BUFFER_TOO_SMALL;
            }
            status = DIGI_MEMCPY (pAbsolutePath, pWorkingDirPath, workingDirPathLen);
            goto exit;
        }
        else if ((1 < relativePathLength) && (('.' == pRelativePath[0]) &&
            ('/' == pRelativePath[1])))
        {
            /* Path provided is of the form "./path/to/file", initial "./"
             * can be ignored in generating full path. */
            pRelativePath++;
            pRelativePath++;
            relativePathLength--;
            relativePathLength--;
        }
    }

    /* mountPathLength is zero if prefixMount is FALSE or pMountPath is NULL.
     * workingDirPathLen is zero if pWorkingDirPath is NULL. */
    absolutePathComputedLength = mountPathLength + workingDirPathLen + relativePathLength + 2;
    if (absolutePathComputedLength > absolutePathLength)
        return ERR_BUFFER_TOO_SMALL;

    pTmp = pAbsolutePath;
    /* Add mount point if present and requested. */
    if ((TRUE == prefixMount) && (1 < mountPathLength))
    {
        status = DIGI_MEMCPY (pTmp, pMountPath, mountPathLength);
        pTmp += mountPathLength;
    }

    /* Add working directory if present, and if pRelativePath doesn't start
     * with a forward slash. */
    if ((0 < workingDirPathLen) && (relativePathLength > 1) && ('/' != pRelativePath[0]))
    {
        status = DIGI_MEMCPY (pTmp, pWorkingDirPath, workingDirPathLen);
        pTmp += workingDirPathLen;
    }

    if ((relativePathLength > 1) && ('/' != pRelativePath[0]))
    {
        pTmp[0] = '/';
        pTmp++;
    }

    status = DIGI_MEMCPY (pTmp, pRelativePath, relativePathLength);
    pTmp += relativePathLength; 
    pTmp[0] = '\0';

   /* resolve .. operator */
    tmpLen = outTmpLen =  (sbyte4) DIGI_STRLEN (pAbsolutePath);
    status = DIGI_MALLOC((void **) &pOutTmp, outTmpLen + 1);
    if (OK != status)
        goto exit;

    pTmp = pAbsolutePath;
    tmpIndex = 0;
    pDst = pOutTmp;
    dstIndex = 0;
    dstLen = outTmpLen;
    while (tmpIndex < tmpLen)
    {
        if (TRUE == isDoubleDotOp (pTmp, tmpIndex, tmpLen))
        {
            if (0 > moveToPrevSlash (pDst, &dstIndex))
            {
                goto exit;
            }
            moveToNextSlash (pTmp, &tmpIndex, tmpLen);
        }
        else
        {
            copyTokenToBuffer (pTmp, &tmpIndex, tmpLen, pDst, &dstIndex, dstLen);
        }
    }
    pDst[dstIndex] = '\0';

    status = DIGI_MEMCPY (pAbsolutePath, pDst, dstIndex);
    if (OK != status)
        goto exit;
    pAbsolutePath[dstIndex] = '\0';
exit:
    if (NULL != pOutTmp)
        DIGI_FREE((void **) &pOutTmp);
    return status;
}
#endif /* __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__ */

extern MSTATUS LINUX_getFullPath (const sbyte *pRelativePath, sbyte *pAbsolutePath, ubyte4 absolutePathLength)
{
    MSTATUS status = ERR_NULL_POINTER;
#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    sbyte pAbsPath [PATH_MAX + 1] = { 0 };
    ubyte4 absolutePathComputedLength;
#endif

    if ((NULL == pAbsolutePath) || (NULL == pRelativePath))
        goto exit;

    if (0 == DIGI_STRLEN(pRelativePath))
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__

    if (NULL == realpath ((const char* __restrict)pRelativePath, (char* __restrict)pAbsPath))
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
                * an empty string. Already checked for pRelativePath as an empty
                * string. Must be that pRelativePath does not exist. Do not return
                * an error and return full name back to the user. */
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
#else
    status = LINUX_getFullPathAux (pRelativePath, pAbsolutePath, absolutePathLength, FALSE);
#endif

exit:

    return status;
}

extern MSTATUS LINUX_getFullPathAllocAux (const sbyte *pRelativePath, sbyte **ppAbsolutePath, intBoolean prefixMount)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte pAbsPath [PATH_MAX + 1] = { 0 };
    ubyte4 absolutePathComputedLength;
    sbyte *pAbsolutePath = NULL;

    if (NULL == ppAbsolutePath)
        goto exit;

    *ppAbsolutePath = NULL;

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    status = LINUX_getFullPathAux (pRelativePath, pAbsPath, PATH_MAX, prefixMount);
#else
    status = LINUX_getFullPath (pRelativePath, pAbsPath, PATH_MAX);
#endif
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

extern MSTATUS LINUX_getFullPathAlloc (const sbyte *pRelativePath, sbyte **ppAbsolutePath)
{
    return LINUX_getFullPathAllocAux (pRelativePath, ppAbsolutePath, FALSE);
}


extern MSTATUS LINUX_getEnvironmentVariableValue (const sbyte *pVariableName, sbyte *pValueBuffer, ubyte4 valueBufferLength)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pValue;
    ubyte4 valueLength;

    if ((NULL == pVariableName) || (NULL == pValueBuffer))
        goto exit;

    pValue = (sbyte*)getenv ((const char*)pVariableName);
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

extern MSTATUS LINUX_getEnvironmentVariableValueAlloc (const sbyte *pVariableName, sbyte **ppValueBuffer)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pValue;
    sbyte *pValueBuffer = NULL;
    ubyte4 valueLength;

    if ((NULL == pVariableName) || (NULL == ppValueBuffer))
        goto exit;

    *ppValueBuffer = NULL;
    pValue = (sbyte*)getenv ((const char*)pVariableName);
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

    if (NULL != pValueBuffer)
    {
        (void) DIGI_FREE((void **) &pValueBuffer);
    }

    return status;
}

extern MSTATUS LINUX_getProcessPath (sbyte *pDirectoryPath, ubyte4 directoryPathLength, ubyte4 *pBytesRead)
{
#if defined(__ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__)
    return ERR_NOT_IMPLEMENTED;
#else
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 length;

    if ((NULL == pDirectoryPath) || (NULL == pBytesRead))
        goto exit;

    if (directoryPathLength == 0)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    length = readlink("/proc/self/exe", (char* __restrict)pDirectoryPath, directoryPathLength);
    if (-1 != length)
    {
        /* readlink does not NULL terminate. If the buffer does not have enough
         * room to add a NULL terminate character, throw an error. */
        if (length == (sbyte4) directoryPathLength)
        {
            status = ERR_BUFFER_TOO_SMALL;
            goto exit;
        }
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
    }
exit:
    return status;
#endif
}

extern MSTATUS LINUX_getProcessPathAlloc (sbyte **ppDirectoryPath)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 length = 0;
    ubyte pBuffer[PROCESS_PATH_LEN_MAX];

    if (NULL == ppDirectoryPath)
        goto exit;

    status = FMGMT_getProcessPath((sbyte*)pBuffer, PROCESS_PATH_LEN_MAX, &length);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC_MEMCPY((void **) ppDirectoryPath, length + 1, pBuffer, length);
    if (OK != status)
        goto exit;

    (*ppDirectoryPath)[length] = '\0';

exit:

    return status;
}
#endif /* __LINUX_FMGMT__ */
