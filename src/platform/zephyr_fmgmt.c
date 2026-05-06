/*
 * zephyr_fmgmt.c
 *
 * Zephyr File Management Abstraction Layer
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

#ifdef __ZEPHYR_FMGMT__
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#define PATH_MAX 256
#include <zephyr/fs/fs.h>

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mfmgmt.h"
#include "../common/common_utils.h"

#define FPRINTF_MAX_SIZE 256
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
#define MOUNT_PATH_MAX_LEN 256
static ubyte pMountPath[MOUNT_PATH_MAX_LEN];
static ubyte4 mountPathLen = 0;
#define WORKING_DIR_PATH_MAX_LEN 256
static ubyte pWorkingDirPath[WORKING_DIR_PATH_MAX_LEN];
static ubyte4 workingDirPathLen = 0;

static ubyte pOutTmp[WORKING_DIR_PATH_MAX_LEN];

typedef struct DirectoryDescriptorInfo {
    struct fs_dir_t dirCtx;
    ubyte pDirPath[WORKING_DIR_PATH_MAX_LEN];
} DirectoryDescriptorInfo;

extern signed int TP_setMountPoint(unsigned char *pNewMountPath)
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

extern intBoolean ZEPHYR_needFullPath()
{
    return ((0 < mountPathLen) || (0 < workingDirPathLen));
}
#else
extern signed int TP_setMountPoint(unsigned char *pNewMountPath)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

extern MSTATUS ZEPHYR_getFullPathAllocAux(const sbyte *pRelativePath, sbyte **ppAbsolutePath, intBoolean prefixMount);

extern intBoolean ZEPHYR_pathExists(const sbyte *pFilePath, FileDescriptorInfo *pFileInfo)
{
    struct fs_dirent entry = {0};
    ubyte *pFPath = NULL;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    sbyte4 ret = 0;

    if (NULL == pFilePath)
        return FALSE;

    pFPath = (ubyte *) pFilePath;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == ZEPHYR_needFullPath())
    {
        if (OK > ZEPHYR_getFullPathAllocAux(pFilePath, (sbyte **) &pFPath, TRUE))
            return FALSE;

        freePath = TRUE;
    }
#endif

    ret = fs_stat(pFPath, &entry);
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        DIGI_FREE ((void **) &pFPath);
#endif
    if (ret != 0)
    {
        if (NULL != pFileInfo)
        {
            DIGI_MEMSET ((ubyte *) pFileInfo, 0x00, sizeof (FileDescriptorInfo));
            pFileInfo->type = FTNone;
        }
        return FALSE;
    }

    if (NULL == pFileInfo)
    {
        return TRUE;
    }

    if (FS_DIR_ENTRY_FILE == entry.type)  /* Test for a regular file. */
        pFileInfo->type = FTFile;
    else if (FS_DIR_ENTRY_DIR == entry.type) /* Test for a directory. */
        pFileInfo->type = FTDirectory;
    else
        pFileInfo->type = FTUnknown;

    pFileInfo->fileSize = entry.size; /* directories are size 0 */

    pFileInfo->accessTime = 0;
    pFileInfo->createTime = 0;
    pFileInfo->modifyTime = 0;

    pFileInfo->gid = 0;
    pFileInfo->uid = 0;
    pFileInfo->mode = 0;
    pFileInfo->isWrite = TRUE;
    pFileInfo->isRead = TRUE;

    return TRUE;
}

extern MSTATUS ZEPHYR_rename(const sbyte *pOldName, sbyte *pNewName)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pOldPath = NULL;
    sbyte *pNewPath = NULL;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freeOldPath = FALSE;
    intBoolean freeNewPath = FALSE;
#endif
    sbyte4 ret;

    if ((NULL == pOldName) || (NULL == pNewName))
        goto exit;

    pOldPath = (sbyte *) pOldName;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == ZEPHYR_needFullPath())
    {
        status = ZEPHYR_getFullPathAllocAux(pOldName, (sbyte **) &pOldPath, TRUE);
        if (OK != status)
            goto exit;
        freeOldPath = TRUE;
    }
#endif
    pNewPath = pNewName;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == ZEPHYR_needFullPath())
    {
        status = ZEPHYR_getFullPathAllocAux(pNewName, (sbyte **) &pNewPath, TRUE);
        if (OK != status)
            goto exit;
        freeNewPath = TRUE;
    }
#endif

    ret = fs_rename((const char*)pOldPath, (const char*)pNewPath);
    if (ret == 0)
    {
        status = OK;
        goto exit;
    }

    switch (ret)
    {
        case -EACCES:
            /* Permission denied. */
            status = ERR_DIR_ACCESS_DENIED;
            break;
        case -ENFILE:
            /* The system-wide limit on total number of open files has been reached */
            status = ERR_DIR_MAX_OPEN_FILES;
            break;
        case -EINVAL:
            /* Directory does not exist, or pDirPath is an empty string */
            status = ERR_DIR_INVALID_PATH;
            break;
        case -ENOMEM:
            /* Insufficient memory to complete the operation. */
            status = ERR_DIR_INSUFFICIENT_MEMORY;
            break;
        case -ENOTDIR:
            /* old argument names a directory and new argument names a non-directory. */
            status = ERR_DIR_NOT_DIRECTORY;
            break;
        case -EISDIR:
            /* the new argument poitns to a directory and the old argument points to
             * a file that is not a directory. */
            status = ERR_DIR_IS_DIRECTORY;
            break;
        case -EEXIST:
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

static sbyte4 recursiveDelete(sbyte *pFilePath);
extern MSTATUS ZEPHYR_mkdir(const sbyte *pDirectoryName, ubyte4 mode)
{
    MOC_UNUSED(mode);
    struct fs_dirent entry = {0};
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pDPath = NULL;
    sbyte *pDirPath = NULL;
    sbyte *pFileName = NULL;
    sbyte4 i;
    sbyte4 size;

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    sbyte4 ret;

    if (NULL == pDirectoryName)
        goto exit;

    pDPath = (sbyte *)pDirectoryName;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == ZEPHYR_needFullPath())
    {
        status = ZEPHYR_getFullPathAllocAux(pDirectoryName, &pDPath, TRUE);
        if (OK != status)
            goto exit;
        freePath = TRUE;
    }
#endif

    if (pDPath[DIGI_STRLEN(pDPath) - 1] == '/')
        pDPath[DIGI_STRLEN(pDPath) - 1] = '\0';

    status = DIGI_removeDuplicateSlashes(pDPath);
    if (OK != status)
        goto exit;

    i = 1; /* we skip first byte which is a slash / */
    size = DIGI_STRLEN(pDPath);
    while (i < size)
    {
        if (pDPath[i] == '/')
        {
            pDPath[i] = '\0';
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
            /* ignore mount point */
            if (0 == DIGI_STRCMP(pDPath, pMountPath))
            {
                pDPath[i] = '/';
                goto next;
            }
#endif

            ret = fs_stat(pDPath, &entry);
            if (ret == -ENOENT)
            {
                ret = fs_mkdir((const char*)pDPath);
                pDPath[i] = '/';
                if (ret != 0)
                {
                    status = COMMON_UTILS_splitPath(pDPath, &pDirPath, &pFileName);
                    if (OK != status)
                    {
                        goto error;
                    }

                    DIGI_FREE((void **) pFileName);
                    ret = recursiveDelete(pDirPath);
                    DIGI_FREE((void **) pDirPath);
                    goto error;
                }
            }
            else
            {
                pDPath[i] = '/';
            }
        }

next:
        i++;
    }

    ret = fs_stat(pDPath, &entry);
    if (ret == -ENOENT)
    {
        ret = fs_mkdir((const char*)pDPath);
    }

error:
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        DIGI_FREE ((void **) &pDPath);
#endif

    switch(ret)
    {
        case 0:
            status = OK;
            break;
        case -EEXIST:
            status = ERR_DIR_EXISTS;
            break;
        default:
            status = ERR_GENERAL;
            break;
    };

exit:
    return status;
}

static sbyte4 recursiveDelete(sbyte *pFilePath) {
    MSTATUS status = OK;
    struct fs_dir_t dir;
    struct fs_dirent entry;
    ubyte *pFPath = NULL;
    sbyte4 ret;

    fs_dir_t_init(&dir);
    ret = fs_opendir(&dir, pFilePath);
    if (ret < 0) {
        return ret;
    }

    while (true) {
        ret = fs_readdir(&dir, &entry);
        if (ret < 0) {
            fs_closedir(&dir);
            return ret;
        }

        if (entry.name[0] == '\0') {
            break;
        }

        if (DIGI_STRCMP(entry.name, ".") == 0 || DIGI_STRCMP(entry.name, "..") == 0) {
            continue;
        }

        if (NULL != pFPath)
        {
            DIGI_FREE((void **) &pFPath);
            pFPath = NULL;
        }

        status = DIGI_MALLOC((void **) &pFPath, DIGI_STRLEN(pFilePath) + DIGI_STRLEN(entry.name) + 2);
        if (OK != status)
            return -1;

        status = DIGI_MEMCPY (pFPath, pFilePath, DIGI_STRLEN(pFilePath));
        if (OK != status)
            return -1;

        pFPath[DIGI_STRLEN(pFilePath)] = '/';

        status = DIGI_MEMCPY (pFPath + DIGI_STRLEN(pFilePath) + 1, entry.name, DIGI_STRLEN(entry.name));
        if (OK != status)
            return -1;

        pFPath[DIGI_STRLEN(pFilePath) + 1 + DIGI_STRLEN(entry.name)] = '\0';

        if (entry.type == FS_DIR_ENTRY_FILE) {
            ret = fs_unlink(pFPath);
            if (ret < 0) {
                fs_closedir(&dir);
                return ret;
            }
        } else if (entry.type == FS_DIR_ENTRY_DIR) {
            ret = recursiveDelete(pFPath);
            if (ret < 0) {
                fs_closedir(&dir);
                return ret;
            }
        }
    }

    fs_closedir(&dir);

    ret = fs_unlink(pFilePath);
    if (ret < 0) {
        return ret;
    }

    if (NULL != pFPath)
    {
        DIGI_FREE((void **) &pFPath);
        pFPath = NULL;
    }

    return 0;
}

extern MSTATUS ZEPHYR_remove(const sbyte *pFilePath, intBoolean recursive)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pFPath = NULL;
    struct fs_dirent entry = {0};
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    sbyte4 ret;
    MOC_UNUSED(recursive);

    if (NULL == pFilePath)
        return ERR_NULL_POINTER;

    pFPath = (ubyte *) pFilePath;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == ZEPHYR_needFullPath())
    {
        status = ZEPHYR_getFullPathAllocAux(pFilePath, (sbyte **) &pFPath, TRUE);
        if (OK != status)
            return status;
        freePath = TRUE;
    }
#endif

    ret = fs_stat(pFPath, &entry);
    if (0 == ret)
    {
        if (FS_DIR_ENTRY_DIR == entry.type)
        {
            ret = recursiveDelete(pFPath);
        }
        else if (FS_DIR_ENTRY_FILE == entry.type)
        {
            ret = fs_unlink((const char*)pFPath);
        }
    }

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        DIGI_FREE ((void **) &pFPath);
#endif
    if (ret == 0)
    {
        return OK;

    }

    switch (ret)
    {
        case -EACCES:
            /* Write access to the directory containing pFPath is not allowed for
             * the process's effective UID, or one of the directories in pFPath did
             * not allow search permission. */
            status = ERR_FILE_ACCESS_DENIED;
            break;
        case -EINVAL:
            /* A component in pFPath does not exist or is a dangling symbolic link, or
             * pFPath is empty. */
            status = ERR_FILE_INVALID_PATH;
            break;
        case -EBUSY:
            /* The file pFPath cannot be unlinked because it is being used by the
             * system or another process. */
            status = ERR_FILE_IN_USE;
            break;
        case -ENAMETOOLONG:
            /* pFPath is too long. */
            status = ERR_FILE_NAME_TOO_LONG;
            break;
        case -EISDIR:
            /* pFPath refers to a directory. */
            status = ERR_FILE_IS_DIRECTORY;
            break;
        case -ENOTEMPTY:
            status = ERR_DIR_NOT_EMPTY;
            break;
        default:
            status = ERR_GENERAL;
    };

    return status;
}

extern MSTATUS ZEPHYR_changeCWD(const sbyte *pNewCwd)
{
    MSTATUS status = ERR_NULL_POINTER;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    ubyte *pDPath = NULL;
    ubyte4 newCwdLength = 0;
    FileDescriptorInfo fileInfo = { 0 };
#endif
    if (NULL == pNewCwd)
        return status;

    if ('/' != pNewCwd[0])
    {
        status = ERR_DIR_INVALID_PATH;
        goto exit;
    }

    pDPath = (sbyte *)pNewCwd;

    /* Make sure path we are changing to actually exists */
    if (TRUE == ZEPHYR_pathExists(pDPath, &fileInfo))
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

    return status;
}

extern MSTATUS ZEPHYR_getCWD (sbyte *pCwd, ubyte4 cwdLength)
{
    MSTATUS status = ERR_NULL_POINTER;
    if (NULL == pCwd)
        goto exit;

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

exit:
    return status;
}

/* -------------------------------------------------------------------------------- */

extern MSTATUS ZEPHYR_getNextFile(DirectoryDescriptor pDirCtx, DirectoryEntry *pFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    struct fs_dir_t *pDir;
    struct fs_dirent entry = {0};
    FileDescriptorInfo fileInfo;
    DirectoryDescriptorInfo *pDirInfo = NULL;
    sbyte *pFullName = NULL;
    sbyte4 ret;

    if ((NULL == pDirCtx) || (NULL == pFileCtx))
        goto exit;

    pDirInfo = (DirectoryDescriptorInfo *)pDirCtx;
    pDir = &(pDirInfo->dirCtx);

    ret = fs_readdir(pDir, &entry);
    if (ret != 0 || entry.name[0] == 0)
    {
        pFileCtx->pCtx = NULL;
        pFileCtx->type = FTNone;
        pFileCtx->pName = NULL;
        pFileCtx->nameLength = 0;

        if (ret < 0)
            status = ERR_DIR_INVALID_DESCRIPTOR;
        else
            status = OK;

        goto exit;
    }

    status = DIGI_MALLOC_MEMCPY((void **) &pFileCtx->pName, DIGI_STRLEN(entry.name) + 1,
        entry.name, DIGI_STRLEN(entry.name) + 1);
    if (OK != status)
        goto exit;

    pFileCtx->pCtx = (void *) NULL;
    pFileCtx->nameLength = DIGI_STRLEN ((const sbyte *) pFileCtx->pName);

    status = COMMON_UTILS_addPathComponent(
        (sbyte *) pDirInfo->pDirPath, (sbyte *) entry.name, &pFullName);
    if (OK != status)
        goto exit;

    if (FALSE == ZEPHYR_pathExists(pFullName, &fileInfo))
    {
        DIGI_FREE((void **) &pFullName);
        status = ERR_GENERAL;
        goto exit;
    }
    DIGI_FREE((void **) &pFullName);

    if (OK != status)
        goto exit;

    switch (entry.type)
    {
        case FS_DIR_ENTRY_DIR:
            pFileCtx->type = FTDirectory;
            break;
        case FS_DIR_ENTRY_FILE:
            pFileCtx->type = FTFile;
            break;
        default:
            pFileCtx->type = FTUnknown;

    };

    status = OK;

exit:
    DIGI_FREE((void **) &pFullName);
    return status;
}

extern MSTATUS ZEPHYR_getFirstFile(const sbyte *pDirPath, DirectoryDescriptor *ppNewDirCtx, DirectoryEntry *pFirstFile)
{
    MSTATUS status = ERR_NULL_POINTER;
    struct fs_dir_t *pDir = NULL;
    sbyte *pDPath = NULL;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    sbyte pCurDir[PATH_MAX] = { 0 };
    sbyte4 ret = 0;
    DirectoryDescriptorInfo *pDirInfo = NULL;

    if ((NULL == pDirPath) || (NULL == ppNewDirCtx) || (NULL == pFirstFile))
        goto exit;

    if (0 == DIGI_STRCMP(pDirPath, (const sbyte*)"."))
    {
        status = ZEPHYR_getCWD(pCurDir, sizeof(pCurDir));
        if (OK != status)
        {
            goto exit;
        }
        pDirPath = (const sbyte *) pCurDir;
    }

    pDPath = (sbyte *)pDirPath;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == ZEPHYR_needFullPath ())
    {
        status = ZEPHYR_getFullPathAllocAux(pDirPath, (sbyte **) &pDPath, TRUE);
        if (OK != status)
            goto exit;
        freePath = TRUE;
    }
#endif

    status = DIGI_MALLOC((void **) &pDirInfo, sizeof(*pDirInfo));
    if (OK != status)
        goto exit;

    pDir = &(pDirInfo->dirCtx);
    fs_dir_t_init(pDir);

    ret = fs_opendir(pDir, (const char*)pDPath);
    if (ret == 0)
    {
        snprintf(pDirInfo->pDirPath, sizeof(pDirInfo->pDirPath), "%s", pDPath);
        *ppNewDirCtx = (DirectoryDescriptor) pDirInfo;

        status = ZEPHYR_getNextFile((DirectoryDescriptor) pDirInfo, pFirstFile);
        goto exit;
    }

    *ppNewDirCtx = NULL;
    switch (ret)
    {
        case -EACCES:
            /* Permission denied. */
            status = ERR_DIR_ACCESS_DENIED;
            break;
        case -ENFILE:
            /* The system-wide limit on total number of open files has been reached */
            status = ERR_DIR_MAX_OPEN_FILES;
            break;
        case -ENOENT:
            /* Directory does not exist, or pDPath is an empty string */
            status = ERR_DIR_INVALID_PATH;
            break;
        case -ENOMEM:
            /* Insufficient memory to complete the operation. */
            status = ERR_DIR_INSUFFICIENT_MEMORY;
            break;
        case -ENOTDIR:
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
    if (ret != 0 && NULL != pDir)
    {
        DIGI_FREE((void **) &pDir);
        pDir = NULL;
    }

    return status;
}

extern MSTATUS ZEPHYR_closeDir(DirectoryDescriptor *ppDirCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    DirectoryDescriptorInfo *pDirInfo = NULL;
    struct fs_dir_t *pDir = NULL;

    if (NULL == ppDirCtx)
        goto exit;

    pDirInfo = (DirectoryDescriptorInfo *)(*ppDirCtx);

    pDir = &(pDirInfo->dirCtx);
    if (0 == fs_closedir(pDir))
    {
        DIGI_FREE((void **) ppDirCtx);
        *ppDirCtx = NULL;
        return OK;
    }

    status = ERR_DIR_INVALID_DESCRIPTOR;

exit:
    return status;
}


/* -------------------------------------------------------------------------------- */

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
static MSTATUS ZEPHYR_getFullPathAux(const sbyte *pRelativePath, sbyte *pAbsolutePath, ubyte4 absolutePathLength, intBoolean prefixMount);

/* This function has no malloc usage */
extern MSTATUS ZEPHYR_fopenEx(const sbyte *pFileName, const sbyte *pMode, FileDescriptor pFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    struct fs_file_t *pFile = NULL;
    sbyte pFPathBuffer[WORKING_DIR_PATH_MAX_LEN];
    int ret;
    fs_mode_t flags = 0;

    if ((NULL == pFileName) || (NULL == pMode) || (NULL == pFileCtx))
        return ERR_NULL_POINTER;

    pFile = (struct fs_file_t *) pFileCtx;
    status = ZEPHYR_getFullPathAux(pFileName, pFPathBuffer, WORKING_DIR_PATH_MAX_LEN, TRUE);
    if (OK != status)
        return status;

    if(pMode)
    {
        switch(pMode[0])
        {
            case 'r':
              flags = FS_O_READ;
              if( '+' == pMode[1])
                  flags |= FS_O_WRITE;
              break;
            case 'w':
              flags = FS_O_WRITE|FS_O_CREATE;
              if( '+' == pMode[1])
                  flags |= FS_O_READ;
              break;
            case 'a':
              flags = FS_O_APPEND;
              if( '+' == pMode[1])
                  flags |= FS_O_READ;
              break;
        }
    }

    fs_file_t_init(pFile);

    ret = fs_open(pFile, pFPathBuffer, (fs_mode_t)flags);
    if (ret == 0)
    {
        return OK;
    }

    switch (ret)
    {
        case -EINVAL:
            /* pMode is invalid */
            status = ERR_FILE_BAD_MODE;
            break;
        case -EACCES:
            /* The requested access to file is denied. */
            status = ERR_FILE_ACCESS_DENIED;
            break;
        case -EEXIST:
            /* pFPath already exists */
            status = ERR_FILE_EXISTS;
            break;
        case -ENOENT:
            /* Component of directory in pFPath does not exist, or
             * is a dangling symbolic link. */
            status = ERR_FILE_INVALID_PATH;
            break;
        case -EISDIR:
            /* pFPath refers to a directory and the access requested involved
             * writing */
            status = ERR_FILE_IS_DIRECTORY;
            break;
        default:
            status = ERR_GENERAL;
    };

    return status;
}

extern MSTATUS ZEPHYR_fcloseEx(FileDescriptor pFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    struct fs_file_t *pFile;
    int ret;

    if (NULL == pFileCtx)
        goto exit;

    pFile = (struct fs_file_t *)(pFileCtx);
    ret = fs_close(pFile);
    if (ret == 0)
    {
        DIGI_MEMSET(pFileCtx, 0x00, sizeof(struct fs_file_t));
        return OK;
    }

    status = ERR_FILE;

exit:
    return status;
}
#endif


/* -------------------------------------------------------------------------------- */

extern MSTATUS ZEPHYR_fopen(const sbyte *pFileName, const sbyte *pMode, FileDescriptor *ppNewFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    struct fs_file_t *pFile = NULL;
    sbyte *pFPath = NULL;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    int ret;
    fs_mode_t flags = 0;

    if ((NULL == pFileName) || (NULL == pMode) || (NULL == ppNewFileCtx))
        return ERR_NULL_POINTER;

    *ppNewFileCtx = NULL;
    pFPath = (sbyte *) pFileName;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == ZEPHYR_needFullPath ())
    {
        status = ZEPHYR_getFullPathAllocAux(pFileName, (sbyte **) &pFPath, TRUE);
        if (OK != status)
            return status;
        freePath = TRUE;
    }
#endif

    status = DIGI_removeDuplicateSlashes(pFPath);
    if (OK != status)
    {
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
        if (TRUE == freePath)
            DIGI_FREE ((void **) &pFPath);
#endif
        return status;
    }

    if(pMode)
    {
        switch(pMode[0])
        {
            case 'r':
              flags = FS_O_READ;
              if( '+' == pMode[1])
                  flags |= FS_O_WRITE;
              break;
            case 'w':
              flags = FS_O_WRITE|FS_O_CREATE;
              if( '+' == pMode[1])
                  flags |= FS_O_READ;
              break;
            case 'a':
              flags = FS_O_APPEND;
              if( '+' == pMode[1])
                  flags |= FS_O_READ;
              break;
        }
    }

    status = DIGI_MALLOC((void **)&pFile, sizeof(struct fs_file_t));
    if (OK != status)
        return status;

    fs_file_t_init(pFile);

    ret = fs_open(pFile, pFPath, (fs_mode_t)flags);
    if (ret == 0)
    {
        *ppNewFileCtx = (FileDescriptor) pFile;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
        if (TRUE == freePath)
            DIGI_FREE ((void **) &pFPath);
#endif
        return OK;
    }

    DIGI_FREE((void **)&pFile);

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        DIGI_FREE ((void **) &pFPath);
#endif

    switch (ret)
    {
        case -EINVAL:
            /* pMode is invalid */
            status = ERR_FILE_BAD_MODE;
            break;
        case -EACCES:
            /* The requested access to file is denied. */
            status = ERR_FILE_ACCESS_DENIED;
            break;
        case -EEXIST:
            /* pFPath already exists */
            status = ERR_FILE_EXISTS;
            break;
        case -ENOENT:
            /* Component of directory in pFPath does not exist, or
             * is a dangling symbolic link. */
            status = ERR_FILE_INVALID_PATH;
            break;
        case -EISDIR:
            /* pFPath refers to a directory and the access requested involved
             * writing */
            status = ERR_FILE_IS_DIRECTORY;
            break;
        default:
            status = ERR_GENERAL;
    };

    return status;
}

extern MSTATUS ZEPHYR_fclose(FileDescriptor *ppFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    struct fs_file_t *pFile;
    int ret;

    if ((NULL == ppFileCtx) || (NULL == *ppFileCtx))
        goto exit;

    pFile = (struct fs_file_t *)(*ppFileCtx);
    ret = fs_close(pFile);
    DIGI_FREE((void **)ppFileCtx);
    if (ret == 0)
    {
        *ppFileCtx = NULL;
        return OK;
    }

    status = ERR_FILE;

exit:
    return status;
}

extern MSTATUS ZEPHYR_fread(ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesRead)
{
    MSTATUS status = ERR_NULL_POINTER;
    struct fs_file_t *pFile;
    ubyte4 readCount;

    if ((NULL == pFileCtx) || (NULL == pBuffer) || (NULL == pBytesRead))
        goto exit;

    pFile = (struct fs_file_t *) pFileCtx;
    readCount = fs_read(pFile, (void *) pBuffer, itemSize * numOfItems);
    *pBytesRead = readCount;

    status = OK;
exit:
    return status;
}

extern MSTATUS ZEPHYR_fwrite(const ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesWrote)
{
    MSTATUS status = ERR_NULL_POINTER;
    struct fs_file_t *pFile;
    ubyte4 writeCount;

    if ((NULL == pFileCtx) || (NULL == pBuffer) || (NULL == pBytesWrote))
        goto exit;

    pFile = (struct fs_file_t *) pFileCtx;
    writeCount = fs_write(pFile, (const void *) pBuffer, itemSize*numOfItems);
    *pBytesWrote = writeCount;

    if (writeCount == (itemSize * numOfItems))
    {
        status = OK;
        goto exit;
    }

    switch (writeCount)
    {
        case -EBADF:
            status = ERR_FILE_INVALID_DESCRIPTOR;
            break;
        case -ENOMEM:
            status = ERR_FILE_INSUFFICIENT_MEMORY;
            break;
        default:
            status = ERR_GENERAL;
    }

exit:
    return status;
}


#ifdef __ENABLE_DIGICERT_64_BIT__
extern MSTATUS ZEPHYR_fseek(FileDescriptor pFileCtx, sbyte8 offset, ubyte4 m_whence)
#else
extern MSTATUS ZEPHYR_fseek(FileDescriptor pFileCtx, sbyte4 offset, ubyte4 m_whence)
#endif
{
    MSTATUS status = ERR_NULL_POINTER;
    struct fs_file_t *pFile;
    sbyte4 whence;
    int ret = 0;

    if (NULL == pFileCtx)
        goto exit;

    pFile = (struct fs_file_t *) pFileCtx;

    switch (m_whence)
    {
        case MSEEK_SET:
            whence = FS_SEEK_SET;
            break;
        case MSEEK_CUR:
            whence = FS_SEEK_CUR;
            break;
        case MSEEK_END:
            whence = FS_SEEK_END;
            break;
        default:
            status = ERR_FILE_INVALID_ARGUMENTS;
            goto exit;
    }

    ret = fs_seek(pFile, offset, whence);
    if (ret == 0)
    {
        return OK;
    }

    switch (ret)
    {
        case -EINVAL:
            /* whence is not SEEK_SET, SEEK_END, or SEEK_CURR. or the resulting
             * file offset would be negative. */
            status = ERR_FILE_INVALID_ARGUMENTS;
            break;
        case -ESPIPE:
            /* pFile is associated with a pipe, socket of FIFO */
            status = ERR_FILE_INVALID_DESCRIPTOR;
            break;
        case -EBADF:
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

extern MSTATUS ZEPHYR_fflush(FileDescriptor pFileCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    struct fs_file_t *pFile;

    if (NULL == pFileCtx)
        goto exit;

    pFile = (struct fs_file_t *) pFileCtx;

    if (0 == fs_sync(pFile))
        return OK;

    /* only error fflush returns is EBADF */
    status = ERR_FILE_INVALID_DESCRIPTOR;

exit:
    return status;
}

/* ------------------------------------------------------------------------- */

extern MSTATUS ZEPHYR_fprintf(FileDescriptor pFileCtx, const sbyte *pFormat, ...)
{
    MSTATUS status = ERR_NULL_POINTER;
    va_list args;
    sbyte pLBuffer[FPRINTF_MAX_SIZE];
    sbyte *pBuffer = pLBuffer;
    sbyte4 size = 0;
    sbyte4 bytesWritten;

    if (NULL == pFormat || NULL == pFileCtx)
        goto exit;

    va_start(args, pFormat);
    size = vsnprintf(NULL, 0, pFormat, args);
    va_end(args);

    if (size > FPRINTF_MAX_SIZE)
    {
        status = DIGI_MALLOC((void **) &pBuffer, size + 1);
        if (OK != status)
            goto exit;
    }

    va_start(args, pFormat);
    vsnprintf(pBuffer, size + 1, pFormat, args);
    va_end(args);

    status = ZEPHYR_fwrite(pBuffer, 1, DIGI_STRLEN(pBuffer), pFileCtx, &bytesWritten);

exit:
    if (size > FPRINTF_MAX_SIZE)
        DIGI_FREE((void **) &pBuffer);
    return status;
}

/* ------------------------------------------------------------------------- */

extern MSTATUS ZEPHYR_ftell(FileDescriptor pFileCtx, ubyte4 *pOffset)
{
    MSTATUS status = ERR_NULL_POINTER;
    struct fs_file_t *pFile = NULL;
    sbyte4 offset;

    if ((NULL == pFileCtx) || (NULL == pOffset))
        goto exit;

    *pOffset = 0;

    pFile = (struct fs_file_t *) pFileCtx;
    offset = fs_tell(pFile);
    if (0 <= offset)
    {
        *pOffset = offset;
        status = OK;
        goto exit;
    }

    switch (offset)
    {
        case -EBADF:
            status = ERR_FILE_INVALID_DESCRIPTOR;
            break;
        case -EOVERFLOW:
            status = ERR_BUFFER_OVERFLOW;
            break;
        case -ESPIPE:
            status = ERR_FILE_INVALID_DESCRIPTOR;
            break;
        default:
            status = ERR_GENERAL;
    }

exit:
    return status;
}

extern sbyte* ZEPHYR_fgets(sbyte *pString, ubyte4 stringLen, FileDescriptor pFileCtx)
{
    ubyte4 i = 0;
    sbyte c;
    sbyte4 ret;

    if ((NULL == pString) || (NULL == pFileCtx))
        return NULL;

    while (i < stringLen - 1) {
        ret = fs_read((struct fs_file_t *) pFileCtx, &c, 1);
        if (ret <= 0)
            break;

        pString[i++] = c;
        if(c == '\n')
            break;
    }

    pString[i] = '\0';

    return (i > 0) ? pString: NULL;
}

extern sbyte4 ZEPHYR_fgetc(FileDescriptor pFileCtx)
{
    sbyte c;
    sbyte4 ret;

    if (NULL == pFileCtx)
        return MOC_EOF;

    ret = fs_read((struct fs_file_t *) pFileCtx, &c, 1);
    if (ret <= 0)
        return MOC_EOF;

    return c;
}

extern sbyte4 ZEPHYR_fputs(sbyte *pString, FileDescriptor pFileCtx)
{
    MSTATUS status;
    sbyte4 bytesWritten = 0;

    status = ZEPHYR_fwrite(pString, 1, DIGI_STRLEN(pString), pFileCtx, &bytesWritten);
    if (OK != status)
        return status;

    return bytesWritten;
}

/* ------------------------------------------------------------------------- */

extern MSTATUS ZEPHYR_getDirectoryPath(const sbyte *pFilePath, sbyte *pDirectoryPath, ubyte4 directoryPathLength)
{
    MSTATUS status;
    ubyte4 filePathLength;
    ubyte4 lastSlash = 0;
    ubyte4 i;
    ubyte *pFPath = NULL;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    MOC_UNUSED(directoryPathLength);

    if (NULL == pFilePath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pFPath = (ubyte *) pFilePath;
#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == ZEPHYR_needFullPath ())
    {
        status = ZEPHYR_getFullPathAllocAux(pFilePath, (sbyte **) &pFPath, FALSE);
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

extern MSTATUS ZEPHYR_getDirectoryPathAlloc(const sbyte *pFilePath, sbyte **ppDirectoryPath)
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
    if (TRUE == ZEPHYR_needFullPath ())
    {
        status = ZEPHYR_getFullPathAllocAux(pFilePath, (sbyte **) &pFPath, FALSE);
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
static int moveToNextSlash(ubyte *ptr, sbyte4 *ptrIndex, sbyte4 size)
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

static int moveToPrevSlash(ubyte *ptr, sbyte4 *ptrIndex)
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

static int copyTokenToBuffer(ubyte *pSrc, sbyte4 *srcIndex, sbyte4 srcSize,
                    ubyte *pDst, sbyte4 *dstIndex, sbyte4 dstSize)
{
    intBoolean foundSlash = FALSE;
    sbyte4 s = *srcIndex;
    sbyte4 d = *dstIndex;
    MOC_UNUSED(dstSize);
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

static intBoolean isDoubleDotOp(ubyte *ptr, sbyte4 index, sbyte4 size)
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

static MSTATUS ZEPHYR_getFullPathAux(const sbyte *pRelativePath, sbyte *pAbsolutePath, ubyte4 absolutePathLength, intBoolean prefixMount)
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
    sbyte4 outTmpLen = 0;
    sbyte4 cmpRes = -1;

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

    /* if path already has prefix, add nothing */
    if (OK == DIGI_MEMCMP(pMountPath, pRelativePath, mountPathLength, &cmpRes) && (0 == cmpRes))
    {
        mountPathLength = 0;
    }
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

    status = DIGI_MEMCPY(pTmp, pRelativePath, relativePathLength);
    pTmp += relativePathLength;
    pTmp[0] = '\0';

   /* resolve .. operator */
    tmpLen = outTmpLen =  (sbyte4) DIGI_STRLEN(pAbsolutePath);

    if (tmpLen + 1 > WORKING_DIR_PATH_MAX_LEN)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    pTmp = pAbsolutePath;
    tmpIndex = 0;
    pDst = pOutTmp;
    dstIndex = 0;
    dstLen = outTmpLen;
    while (tmpIndex < tmpLen)
    {
        if (TRUE == isDoubleDotOp(pTmp, tmpIndex, tmpLen))
        {
            if (0 > moveToPrevSlash(pDst, &dstIndex))
            {
                goto exit;
            }
            moveToNextSlash(pTmp, &tmpIndex, tmpLen);
        }
        else
        {
            copyTokenToBuffer(pTmp, &tmpIndex, tmpLen, pDst, &dstIndex, dstLen);
        }
    }
    pDst[dstIndex] = '\0';

    status = DIGI_MEMCPY(pAbsolutePath, pDst, dstIndex);
    if (OK != status)
        goto exit;
    pAbsolutePath[dstIndex] = '\0';
exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__ */

extern MSTATUS ZEPHYR_getFullPath(const sbyte *pRelativePath, sbyte *pAbsolutePath, ubyte4 absolutePathLength)
{
    MSTATUS status = ERR_NULL_POINTER;

    if ((NULL == pAbsolutePath) || (NULL == pRelativePath))
        goto exit;

    if (0 == DIGI_STRLEN(pRelativePath))
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    status = ZEPHYR_getFullPathAux (pRelativePath, pAbsolutePath, absolutePathLength, TRUE);

exit:

    return status;
}

extern MSTATUS ZEPHYR_getFullPathAllocAux(const sbyte *pRelativePath, sbyte **ppAbsolutePath, intBoolean prefixMount)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte pAbsPath [PATH_MAX + 1] = { 0 };
    ubyte4 absolutePathComputedLength;
    sbyte *pAbsolutePath = NULL;

    if (NULL == ppAbsolutePath)
        goto exit;

    *ppAbsolutePath = NULL;

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    status = ZEPHYR_getFullPathAux (pRelativePath, pAbsPath, PATH_MAX, prefixMount);
#else
    status = ZEPHYR_getFullPath (pRelativePath, pAbsPath, PATH_MAX);
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

extern MSTATUS ZEPHYR_getFullPathAlloc(const sbyte *pRelativePath, sbyte **ppAbsolutePath)
{
    return ZEPHYR_getFullPathAllocAux(pRelativePath, ppAbsolutePath, TRUE);
}


extern MSTATUS ZEPHYR_getEnvironmentVariableValue(const sbyte *pVariableName, sbyte *pValueBuffer, ubyte4 valueBufferLength)
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

extern MSTATUS ZEPHYR_getEnvironmentVariableValueAlloc(const sbyte *pVariableName, sbyte **ppValueBuffer)
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

#endif /* __ZEPHYR_FMGMT__ */
