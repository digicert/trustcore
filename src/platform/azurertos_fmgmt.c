/*
 * azurertos_fmgmt.c
 *
 * AzureRTOS File Management Abstraction Layer
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

#ifdef __AZURE_FMGMT__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/mfmgmt.h"

#include <stdio.h>
#include <stdarg.h>

#ifdef __CLM_FILEX__

/*
 * This project uses ThreadX + NetX Duo but NOT FileX.  clm_vfs.c provides
 * all persistent file I/O through the UTILS_* API.  This file implements the
 * AZURERTOS_f* family that mfmgmt.h maps to FMGMT_f* so that TrustCore
 * modules (e.g. mime_parser.c) can call FMGMT_fgets/ftell/fseek at runtime.
 *
 * Design
 * ──────
 * AZURERTOS_fopen  — load the file into a heap buffer (read) or prepare an
 *                    accumulation buffer (write/append), return a handle.
 * AZURERTOS_fclose — flush write buffers to the VFS; free the handle.
 * fread/fwrite/fseek/ftell/fgets/fprintf/fflush — operate on the in-memory
 *                    buffer tracked by the handle.
 *
 */

#include "../common/utils.h"   /* UTILS_readFile / UTILS_writeFile / UTILS_appendFile */
#include <string.h>

/* clm_vfs.c provides this: returns 1 if the path is a directory sentinel
 * (created by UTILS_mkdir), 0 for regular files or non-existent paths.     */
extern int VFS_isDirectory(const char *path);

/* ── file handle ──────────────────────────────────────────────────────── */

#define AZ_FMGMT_PATH_MAX  256U
#define AZ_FMGMT_WR_INIT   512U   /* initial write-buffer capacity */
#define AZ_FMGMT_SIZE_MAX  ((ubyte4)-1)

typedef struct {
    ubyte  *pData;          /* heap buffer: loaded file (read) or accumulated data (write) */
    ubyte4  len;            /* number of valid bytes in pData */
    ubyte4  cap;            /* allocated capacity of pData (write mode only) */
    ubyte4  pos;            /* current read/write position */
    ubyte   writable;       /* 1 = write/append mode */
    ubyte   appendMode;     /* 1 = append: seek to end before every write */
    char    path[AZ_FMGMT_PATH_MAX];
} AzFmgmtHandle;

static AzFmgmtHandle *handle_alloc(void)
{
    AzFmgmtHandle *h = NULL;
    MSTATUS st = DIGI_MALLOC((void **)&h, sizeof(AzFmgmtHandle));
    if (OK != st || h == NULL)
        return NULL;
    DIGI_MEMSET((ubyte *)h, 0, sizeof(AzFmgmtHandle));
    return h;
}

static void handle_free(AzFmgmtHandle **ppH)
{
    if (!ppH || !*ppH) return;
    if ((*ppH)->pData)
        DIGI_FREE((void **)&(*ppH)->pData);
    DIGI_FREE((void **)ppH);
}

/* ── AZURERTOS_fopen ──────────────────────────────────────────────────── */

extern MSTATUS AZURERTOS_fopen(const sbyte *pFileName, const sbyte *pMode,
                               FileDescriptor *ppNewFileCtx)
{
    MSTATUS        status  = OK;
    AzFmgmtHandle *h       = NULL;
    ubyte         *pBuf    = NULL;
    ubyte4         bufLen  = 0;
    ubyte          isWrite = 0, isAppend = 0, isRead = 0;
    ubyte          mustExist = 0, truncate = 0;
    const sbyte   *p;

    if (!pFileName || !pMode || !ppNewFileCtx)
        return ERR_NULL_POINTER;

    if (DIGI_STRLEN(pFileName) >= AZ_FMGMT_PATH_MAX)
        return ERR_FILE_NAME_TOO_LONG;

    *ppNewFileCtx = NULL;

    /* The primary mode controls creation and truncation; '+' only adds access. */
    switch (*pMode) {
        case 'r': isRead = 1; mustExist = 1; break;
        case 'w': isWrite = 1; truncate = 1; break;
        case 'a': isWrite = 1; isAppend = 1; break;
        default:  return ERR_INVALID_INPUT;
    }

    for (p = pMode + 1; *p; ++p) {
        switch (*p) {
            case '+': isRead   = 1; isWrite  = 1; break;
            case 'b': break; /* binary – no-op */
            default:  return ERR_INVALID_INPUT;
        }
    }

    h = handle_alloc();
    if (!h) return ERR_MEM_ALLOC_FAIL;

    snprintf(h->path, AZ_FMGMT_PATH_MAX, "%s", (const char *)pFileName); /* snprintf always null-terminates */
    h->writable   = isWrite;
    h->appendMode = isAppend;

    if (isRead || isAppend) {
        /* r/r+ require existing content; a/a+ may start with a new file */
        MSTATUS rdSt = UTILS_readFile((const char *)pFileName, &pBuf, &bufLen);
        if (OK == rdSt) {
            h->pData = pBuf;
            h->len   = bufLen;
            h->cap   = bufLen;
            pBuf     = NULL; /* owned by h now */
        } else if (mustExist) {
            /* r/r+ require an existing file */
            status = ERR_FILE_OPEN_FAILED;
            goto exit;
        }
        /* append with no existing file starts empty */
    }

    if (truncate) {
        /* truncate: discard whatever was loaded */
        if (h->pData) {
            DIGI_FREE((void **)&h->pData);
            h->pData = NULL;
        }
        h->len = 0;
        h->cap = 0;
    }

    if (isAppend && h->pData) {
        /* seek to end so writes append */
        h->pos = h->len;
    }

    *ppNewFileCtx = (FileDescriptor)h;
    h = NULL; /* ownership transferred */

exit:
    if (h) handle_free(&h);
    if (pBuf) DIGI_FREE((void **)&pBuf);
    return status;
}

/* ── AZURERTOS_fclose ─────────────────────────────────────────────────── */

extern MSTATUS AZURERTOS_fclose(FileDescriptor *ppFileCtx)
{
    MSTATUS        status = OK;
    AzFmgmtHandle *h;

    if (!ppFileCtx || !*ppFileCtx)
        return ERR_NULL_POINTER;

    h = (AzFmgmtHandle *)*ppFileCtx;

    if (h->writable && h->len > 0) {
        status = UTILS_writeFile((const char *)h->path,
                                 (const ubyte *)h->pData,
                                 h->len);
    }

    handle_free(&h);
    *ppFileCtx = NULL;
    return status;
}

/* ── AZURERTOS_fread ──────────────────────────────────────────────────── */

extern MSTATUS AZURERTOS_fread(ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems,
                               FileDescriptor pFileCtx, ubyte4 *pBytesRead)
{
    AzFmgmtHandle *h;
    ubyte4         want, avail, got;

    if (!pBuffer || !pBytesRead || !pFileCtx)
        return ERR_NULL_POINTER;

    *pBytesRead = 0;
    h     = (AzFmgmtHandle *)pFileCtx;

    if (numOfItems != 0U && itemSize > AZ_FMGMT_SIZE_MAX / numOfItems)
        return ERR_INVALID_INPUT;

    want  = itemSize * numOfItems;
    avail = (h->pos < h->len) ? (h->len - h->pos) : 0U;
    got   = (want < avail) ? want : avail;

    if (got > 0 && h->pData) {
        DIGI_MEMCPY(pBuffer, h->pData + h->pos, got);
        h->pos    += got;
        *pBytesRead = got;
    }
    return OK;
}

/* ── AZURERTOS_fwrite ─────────────────────────────────────────────────── */

extern MSTATUS AZURERTOS_fwrite(const ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems,
                                FileDescriptor pFileCtx, ubyte4 *pBytesWrote)
{
    AzFmgmtHandle *h;
    ubyte4         total, newLen;
    ubyte         *pNew = NULL;
    MSTATUS        status = OK;

    if (!pBuffer || !pBytesWrote || !pFileCtx)
        return ERR_NULL_POINTER;

    *pBytesWrote = 0;
    h     = (AzFmgmtHandle *)pFileCtx;

    if (numOfItems != 0U && itemSize > AZ_FMGMT_SIZE_MAX / numOfItems)
        return ERR_INVALID_INPUT;

    total = itemSize * numOfItems;

    if (!h->writable)
        return ERR_FILE_WRITE_FAILED;

    if (h->appendMode)
        h->pos = h->len;

    if (total > AZ_FMGMT_SIZE_MAX - h->pos)
        return ERR_BUFFER_TOO_SMALL;

    newLen = h->pos + total;
    if (newLen > h->cap) {
        ubyte4 newCap = newLen;

        if (newLen <= AZ_FMGMT_SIZE_MAX / 2U)
            newCap = newLen * 2U;
        if (newCap < AZ_FMGMT_WR_INIT)
            newCap = AZ_FMGMT_WR_INIT;

        status = DIGI_MALLOC((void **)&pNew, newCap);
        if (OK != status || !pNew)
            return ERR_MEM_ALLOC_FAIL;
        if (h->pData && h->len)
            DIGI_MEMCPY(pNew, h->pData, h->len);
        if (h->pData)
            DIGI_FREE((void **)&h->pData);
        h->pData = pNew;
        h->cap   = newCap;
    }

    DIGI_MEMCPY(h->pData + h->pos, pBuffer, total);
    h->pos  += total;
    if (h->pos > h->len)
        h->len = h->pos;

    *pBytesWrote = total;
    return OK;
}

/* ── AZURERTOS_fseek ──────────────────────────────────────────────────── */

#ifdef MOC_64BIT_SEEK
extern MSTATUS AZURERTOS_fseek(FileDescriptor pFileCtx, sbyte8 offset, ubyte4 m_whence)
#else
extern MSTATUS AZURERTOS_fseek(FileDescriptor pFileCtx, sbyte4 offset, ubyte4 m_whence)
#endif
{
    AzFmgmtHandle *h;
    sbyte8         newPos;

    if (!pFileCtx) return ERR_NULL_POINTER;
    h = (AzFmgmtHandle *)pFileCtx;

    switch (m_whence) {
        case MSEEK_SET: newPos = (sbyte8)offset;              break;
        case MSEEK_CUR: newPos = (sbyte8)h->pos + offset;    break;
        case MSEEK_END: newPos = (sbyte8)h->len + offset;    break;
        default:        return ERR_INVALID_INPUT;
    }

    if (newPos < 0)
        newPos = 0;
    if ((ubyte4)newPos > h->len)
        newPos = (sbyte8)h->len;

    h->pos = (ubyte4)newPos;
    return OK;
}

/* ── AZURERTOS_ftell ──────────────────────────────────────────────────── */

extern MSTATUS AZURERTOS_ftell(FileDescriptor pFileCtx, ubyte4 *pOffset)
{
    if (!pFileCtx || !pOffset) return ERR_NULL_POINTER;
    *pOffset = ((AzFmgmtHandle *)pFileCtx)->pos;
    return OK;
}

/* ── AZURERTOS_fgets ──────────────────────────────────────────────────── */

extern sbyte *AZURERTOS_fgets(sbyte *pString, ubyte4 stringLen, FileDescriptor pFileCtx)
{
    AzFmgmtHandle *h;
    ubyte4         i;
    const ubyte   *src;

    if (!pString || !stringLen || !pFileCtx)
        return NULL;

    h = (AzFmgmtHandle *)pFileCtx;

    if (!h->pData || h->pos >= h->len)
        return NULL; /* EOF */

    src = h->pData + h->pos;
    for (i = 0; i < stringLen - 1U && h->pos < h->len; ++i) {
        sbyte c = (sbyte)*src++;
        h->pos++;
        pString[i] = c;
        if (c == '\n') { ++i; break; }
    }
    pString[i] = '\0';
    return (i > 0) ? pString : NULL;
}

/* ── AZURERTOS_fprintf ────────────────────────────────────────────────── */

extern MSTATUS AZURERTOS_fprintf(FileDescriptor pFileCtx, const sbyte *pFormat, ...)
{
    char    buf[256];
    int     n;
    ubyte4  wrote = 0;
    va_list args;

    if (!pFileCtx || !pFormat) return ERR_NULL_POINTER;

    va_start(args, pFormat);
    n = vsnprintf(buf, sizeof(buf), (const char *)pFormat, args);
    va_end(args);

    if (n < 0) return ERR_INVALID_INPUT;         /* encoding error */
    if (n >= (int)sizeof(buf)) return ERR_BUFFER_TOO_SMALL; /* output truncated, buf holds < n bytes */
    if (n == 0) return OK;
    return AZURERTOS_fwrite((const ubyte *)buf, 1U, (ubyte4)n, pFileCtx, &wrote);
}

/* ── AZURERTOS_fflush ─────────────────────────────────────────────────── */

extern MSTATUS AZURERTOS_fflush(FileDescriptor pFileCtx)
{
    (void)pFileCtx;
    return OK; /* RAM buffer — nothing to flush */
}

/* ── AZURERTOS_pathExists ─────────────────────────────────────────────── */

extern intBoolean AZURERTOS_pathExists(const sbyte *pFilePath,
                                       FileDescriptorInfo *pFileInfo)
{
    intBoolean exists = FALSE;
    MSTATUS    status;

    if (!pFilePath) return FALSE;

    if (pFileInfo)
        DIGI_MEMSET((ubyte *)pFileInfo, 0, sizeof(*pFileInfo));

    status = UTILS_checkFile((const char *)pFilePath, NULL, &exists);
    (void)status;

    if (exists && pFileInfo) {
        pFileInfo->type   = VFS_isDirectory((const char *)pFilePath) ? FTDirectory : FTFile;
        pFileInfo->isRead = FALSE;
    }
    return exists;
}

/* ── AZURERTOS_remove ─────────────────────────────────────────────────── */

extern MSTATUS AZURERTOS_remove(const sbyte *pFilePath, intBoolean isDirectory)
{
    (void)isDirectory;
    if (!pFilePath) return ERR_NULL_POINTER;
    return UTILS_deleteFile((const char *)pFilePath);
}

/* ── AZURERTOS_rename ─────────────────────────────────────────────────── */

extern MSTATUS AZURERTOS_rename(const sbyte *pOldName, sbyte *pNewName)
{
    MSTATUS status;
    ubyte  *pBuf   = NULL;
    ubyte4  bufLen = 0;

    if (!pOldName || !pNewName) return ERR_NULL_POINTER;

    status = UTILS_readFile((const char *)pOldName, &pBuf, &bufLen);
    if (OK != status) return status;

    status = UTILS_writeFile((const char *)pNewName, pBuf, bufLen);
    DIGI_FREE((void **)&pBuf);
    if (OK != status) return status;

    return UTILS_deleteFile((const char *)pOldName);
}

/* ── AZURERTOS_mkdir ──────────────────────────────────────────────────── */

extern MSTATUS AZURERTOS_mkdir(const sbyte *pPath, ubyte4 mode)
{
    (void)mode;
    if (!pPath) return ERR_NULL_POINTER;
    return UTILS_mkdir((const char *)pPath); /* clm_vfs: no-op, returns OK */
}

/* ── AZURERTOS_changeCWD / AZURERTOS_getCWD ───────────────────────────── */

extern MSTATUS AZURERTOS_changeCWD(const sbyte *pPath)
{
    (void)pPath;
    return OK; /* no real directory concept in RAM VFS */
}

extern MSTATUS AZURERTOS_getCWD(sbyte *pBuf, ubyte4 bufLen)
{
    if (!pBuf || !bufLen) return ERR_NULL_POINTER;
    snprintf((char *)pBuf, bufLen, "%s", "/"); /* snprintf always null-terminates */
    return OK;
}

/* ── directory iteration stubs ───────────────────────────────────────── */

extern MSTATUS AZURERTOS_getFirstFile(const sbyte *pDirPath,
                                      DirectoryDescriptor *ppNewDirCtx,
                                      DirectoryEntry *pFirstFile)
{
    (void)pDirPath; (void)pFirstFile;
    if (ppNewDirCtx) *ppNewDirCtx = NULL;
    return ERR_NOT_FOUND;
}

extern MSTATUS AZURERTOS_getNextFile(DirectoryDescriptor pDirCtx,
                                     DirectoryEntry *pFileCtx)
{
    (void)pDirCtx; (void)pFileCtx;
    return ERR_NOT_FOUND;
}

extern MSTATUS AZURERTOS_closeDir(DirectoryDescriptor *ppDirCtx)
{
    (void)ppDirCtx;
    return OK;
}

/* ── path helpers ────────────────────────────────────────────────────── */

extern MSTATUS AZURERTOS_getFullPath(const sbyte *pRelPath, sbyte *pAbsBuf,
                                     ubyte4 absBufLen)
{
    if (!pRelPath || !pAbsBuf || !absBufLen) return ERR_NULL_POINTER;
    if (DIGI_STRLEN(pRelPath) >= absBufLen) return ERR_BUFFER_TOO_SMALL;
    snprintf((char *)pAbsBuf, absBufLen, "%s", (const char *)pRelPath); /* snprintf always null-terminates */
    return OK;
}

extern MSTATUS AZURERTOS_getDirectoryPathAlloc(const sbyte *pPath,
                                               sbyte **ppDirPath)
{
    MSTATUS status;
    ubyte4  len;
    sbyte  *p;

    if (!pPath || !ppDirPath) return ERR_NULL_POINTER;

    len    = (ubyte4)DIGI_STRLEN(pPath) + 1U;
    status = DIGI_MALLOC((void **)ppDirPath, len);
    if (OK != status || !*ppDirPath)
        return ERR_MEM_ALLOC_FAIL;

    DIGI_MEMCPY(*ppDirPath, pPath, len);

    /* strip trailing filename: find last '/' (guard against underflow when pPath is empty) */
    if (len >= 2U) {
        p = *ppDirPath + len - 2U;
        while (p > *ppDirPath && *p != '/')
            --p;
        if (*p == '/')
            *(p + 1U) = '\0';
    } else {
        (*ppDirPath)[0] = '\0';
    }

    return OK;
}

extern MSTATUS AZURERTOS_getEnvironmentVariableValueAlloc(const sbyte *pName,
                                                          sbyte **ppValue)
{
    (void)pName;
    if (ppValue) *ppValue = NULL;
    return ERR_NOT_FOUND;
}

#else /* __CLM_FILEX__ */

/* Set File Media for AzureRTOS platform.
 * Applications should define this pointer and set it against the file-media to use.
 * Set the FX_MEDIA ptr before calling any file management APIs.
 */
FX_MEDIA *pAzureRtosFileMedia = NULL;
FX_MEDIA *gp_fx_media0 = NULL;

/* Used to store CWD path. Once the CWD is set pCwdLocalPath will be
 * non-NULL. This is to ensure that any file APIs restore the local
 * path correctly. */
static FX_LOCAL_PATH cwdLocalPath;
static FX_LOCAL_PATH *pCwdLocalPath = NULL;

/* -------------------------------------------------------------------------------- */
typedef struct
{
    /* Current directory */
    sbyte *pDirPath;
    /* Path to restore back */
    FX_LOCAL_PATH *pPrevLocalPath;

    CHAR entryName[FX_MAX_LONG_NAME_LEN];
} AzureRtosDirDescriptor;

/* -------------------------------------------------------------------------------- */

static MSTATUS checkFileMedia()
{
    MSTATUS status = OK;
    static byteBoolean isMediaOk = FALSE;
    UINT ret = FX_SUCCESS;
    CHAR *dirDefaultPath = NULL;

    if (isMediaOk)
    {
        goto exit;
    }

    if (NULL == pAzureRtosFileMedia)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    ret = fx_directory_default_get(pAzureRtosFileMedia, &dirDefaultPath);
    switch (ret)
    {
        case FX_MEDIA_NOT_OPEN:
        case FX_PTR_ERROR:
        case FX_CALLER_ERROR:
        default:
        {
            DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"fx_directory_default_get: status = ", status);
            status = ERR_RTOS_FILE_MEDIA_NOT_READY;
            break;
        }
        case FX_SUCCESS:
        {
            status = OK;
            break;
        }
    }

    isMediaOk = (OK == status) ? TRUE : FALSE;

exit:
    return status;
}


/* -------------------------------------------------------------------------------- */


extern intBoolean AZURERTOS_pathExists (const sbyte *pFilePath, FileDescriptorInfo *pFileInfo)
{
    MSTATUS status = OK;
    UINT ret = FX_SUCCESS;
    UINT attrs = 0;
    intBoolean doesExist = FALSE;

    if (NULL == pFilePath)
    {
        status = ERR_NULL_POINTER;
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"AZURERTOS_pathExists: status = ", status);
        goto exit;
    }

    status = checkFileMedia();
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_pathExists: Error accessing File-Media status = ",
                   status);
        goto exit;
    }

    if (pFileInfo)
    {
        DIGI_MEMSET ((ubyte *)pFileInfo, 0x00, sizeof (*pFileInfo));
        pFileInfo->type = FTNone;
    }
    ret = fx_file_attributes_read(pAzureRtosFileMedia,
                                (CHAR *)pFilePath,
                                &attrs);
    switch (ret)
    {
        case FX_SUCCESS:
        {
          doesExist = TRUE;
          if (pFileInfo)
          {
        	  pFileInfo->type = FTFile;
        	  pFileInfo->isRead = (FX_READ_ONLY & attrs);
          }
          break;
        }
        case FX_NOT_A_FILE:
        {
          doesExist = TRUE;
          if (pFileInfo)
        	  pFileInfo->type = FTDirectory;

          break;
        }
        case FX_NOT_FOUND:
        {
            doesExist = FALSE;
            break;
        }
        case FX_MEDIA_NOT_OPEN:
        case FX_SECTOR_INVALID:
        case FX_FAT_READ_ERROR:
        case FX_NO_MORE_ENTRIES:
        case FX_NO_MORE_SPACE:
        case FX_IO_ERROR:
        case FX_PTR_ERROR:
        case FX_CALLER_ERROR:
        default:
        {
            doesExist = FALSE;
            DEBUG_ERROR(DEBUG_PLATFORM,
                        (sbyte *)"AZURERTOS_pathExists: Error accessing File-Media. FX status = ",
                        ret);
            break;
        }
    }

    if (FALSE == doesExist || NULL == pFileInfo)
    {
      goto exit;
    }

exit:
    return doesExist;
}

extern MSTATUS AZURERTOS_rename (const sbyte *pOldName, sbyte *pNewName)
{
    MSTATUS status = OK;
    UINT ret = FX_SUCCESS;

    if ((NULL == pOldName) || (NULL == pNewName))
    {
      status = ERR_NULL_POINTER;
      goto exit;
    }

    status = checkFileMedia();
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_rename: Error accessing File-Media status = ",
                   status);
        goto exit;
    }

    ret = fx_file_rename(pAzureRtosFileMedia,
                         (CHAR*)pOldName,
                         (CHAR*)pNewName);

    /* Attempt to rename with dir api if file-type is not a file */
    if (FX_NOT_A_FILE == ret)
    {
        ret = fx_directory_rename(pAzureRtosFileMedia, (CHAR*)pOldName, (CHAR*)pNewName);
    }

    if (FX_SUCCESS != ret)
    {
        status = ERR_FILE;
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_rename: Error renaming file. Return-Code = ",
                   ret);
        goto exit;
    }

    status = OK;
exit:
    return status;
}

/* -------------------------------------------------------------------------------- */

static MSTATUS recursiveDelete(const sbyte *pFilePath, FX_LOCAL_PATH *pPrevPath)
{
    MSTATUS status = OK;
    UINT ret = FX_SUCCESS;
    UINT attributes;
    FX_LOCAL_PATH prevLocalPath;
    CHAR entryName[FX_MAX_LONG_NAME_LEN];
    CHAR temp[FX_MAX_LONG_NAME_LEN] = { 0 };
    byteBoolean doPathRestore = FALSE;

    ret = fx_directory_local_path_set(pAzureRtosFileMedia,
                                      &prevLocalPath,
                                      (CHAR*)pFilePath);
    if (FX_SUCCESS != ret)
    {
        status = ERR_FILE;
        goto exit;
    }
    doPathRestore = TRUE;

    ret = fx_directory_first_full_entry_find( pAzureRtosFileMedia,
                                              (CHAR *)entryName,
                                              &attributes,
                                              NULL,
                                              NULL, NULL, NULL,
                                              NULL, NULL, NULL);
    while(FX_SUCCESS == ret)
    {
        /* Only process paths which are not "." or ".." */
        if (DIGI_STRCMP(entryName, ".") &&
               DIGI_STRCMP(entryName, ".."))
        {
            if (FX_DIRECTORY & attributes)
            {
            	DIGI_MEMCPY(temp, pFilePath, DIGI_STRLEN(pFilePath));
            	temp[DIGI_STRLEN(pFilePath)] = '/';
            	DIGI_MEMCPY(temp + DIGI_STRLEN(pFilePath) + 1, entryName, DIGI_STRLEN(entryName));
            	temp[DIGI_STRLEN(pFilePath) + 1 + DIGI_STRLEN(entryName)] = '\0';
                /* Recurse if entry is a directory */
                status = recursiveDelete((const sbyte *)temp, &prevLocalPath);
            }
            else
            {
                /* If entry is a file then delete it */
                status = AZURERTOS_remove((const sbyte *)entryName, FALSE);
            }

            if (OK != status)
            {
                goto exit;
            }
        }

        ret = fx_directory_next_full_entry_find(pAzureRtosFileMedia,
                                              entryName,
                                              &attributes,
                                              NULL,
                                              NULL, NULL, NULL,
                                              NULL, NULL, NULL);
    }

    if (FX_NO_MORE_ENTRIES == ret)
    {
        /* Directory is empty, delete it now */
    	status = AZURERTOS_remove((const sbyte *)pFilePath, FALSE);
    }
    else
    {
        /* Error condition */
        status = ERR_FILE;
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"recursiveDelete: Error finding directory entry. Return-code = ",
                   ret);
        goto exit;
    }

exit:
    if (TRUE == doPathRestore)
    {
    	if (NULL != pPrevPath)
    	{
    		ret = fx_directory_local_path_restore(pAzureRtosFileMedia, pPrevPath);
    	}
    	else
    	{
    		ret = fx_directory_local_path_clear(pAzureRtosFileMedia);
    	}
        if (FX_SUCCESS != ret)
        {
            status = ERR_FILE;
            DEBUG_ERROR(DEBUG_PLATFORM,
                       (sbyte *)"recursiveDelete: Error restoring local path. Return-code = ",
                       ret);
            goto exit;
        }
    }

    return status;
}

extern MSTATUS AZURERTOS_remove (const sbyte *pFilePath, intBoolean recursive)
{
    MSTATUS status = OK;
    UINT ret = FX_SUCCESS;

    if (NULL == pFilePath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = checkFileMedia();
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_remove: Error accessing File-Media status = ",
                   status);
        goto exit;
    }

    if (TRUE == recursive)
    {
          status = recursiveDelete(pFilePath, pCwdLocalPath);
    }
    else
    {
        ret = fx_file_delete(pAzureRtosFileMedia,
                              (CHAR *)pFilePath);

        if (FX_NOT_A_FILE == ret)
        {
            ret = fx_directory_delete(pAzureRtosFileMedia,
                                      (CHAR *)pFilePath);
        }

        if ( (FX_SUCCESS != ret) && (FX_NOT_FOUND != ret) )
        {
          status = ERR_FILE;
          DEBUG_ERROR(DEBUG_PLATFORM,
                     (sbyte *)"AZURERTOS_remove: Error removing file. Return-Code = ",
                     ret);
          goto exit;
        }
        status = OK;
    }

exit:
    return status;
}


/* -------------------------------------------------------------------------------- */

extern MSTATUS AZURERTOS_getFirstFile (const sbyte *pDirPath, DirectoryDescriptor *ppNewDirCtx, DirectoryEntry *pFirstFile)
{
    MSTATUS status = OK;
    UINT    ret = FX_SUCCESS;
    AzureRtosDirDescriptor *pDirDescriptor = NULL;
    FX_LOCAL_PATH *prevLocalPath = NULL;
    UINT attributes = 0;
    ubyte4 dirPathLen = 0;
    UINT clearPath = 0;
    sbyte pCurDir[256] = { 0 };

    if ((NULL == pDirPath) || (NULL == ppNewDirCtx))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == DIGI_STRCMP(pDirPath, "."))
    {
        status = FMGMT_getCWD(pCurDir, sizeof(pCurDir));
        if (OK != status)
        {
            goto exit;
        }
        pDirPath = (const sbyte *) pCurDir;
    }

    status = DIGI_CALLOC((void **)&prevLocalPath,
                        1, sizeof(*prevLocalPath));
    if (OK != status)
        goto exit;

    ret = fx_directory_local_path_set(pAzureRtosFileMedia,
                                      prevLocalPath,
                                      (CHAR*)pDirPath);
    if (FX_SUCCESS != ret)
    {
        status = ERR_FILE;
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_getFirstFile: Error setting local path. Return-code = ",
                   ret);
        goto exit;
    }
    clearPath = 1;

    status = DIGI_CALLOC((void **)&pDirDescriptor,
                        1, sizeof(*pDirDescriptor));
    if (OK != status)
        goto exit;

    ret = fx_directory_first_full_entry_find( pAzureRtosFileMedia,
                                              (CHAR *)pDirDescriptor->entryName,
                                              &attributes,
                                              NULL,
                                              NULL, NULL, NULL,
                                              NULL, NULL, NULL);
 
    switch(ret)
    {
        case FX_SUCCESS:
            pFirstFile->pCtx = NULL;
            pFirstFile->nameLength = DIGI_STRLEN ((const sbyte *)pDirDescriptor->entryName);
            pFirstFile->pName = (ubyte *)pDirDescriptor->entryName;
            /* If this is not a directory, assume a regular file */
            pFirstFile->type = (FX_DIRECTORY & attributes) ?  FTDirectory : FTFile;
            break;

        case FX_NO_MORE_ENTRIES:
            pFirstFile->pCtx = NULL;
            pFirstFile->pName = NULL;
            pFirstFile->nameLength = 0;
            pFirstFile->type = FTNone;
            break;

        default:
            status = ERR_DIR_READ_FAILED;
            DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_getNextFile: Error accessing File-Media status = ",
                   ret);
            goto exit;
    }

    dirPathLen = DIGI_STRLEN ((const sbyte *)pDirPath);
    status = DIGI_MALLOC((void **)&(pDirDescriptor->pDirPath),dirPathLen+1);
    if (OK != status)
        goto exit;
        
    status = DIGI_MEMCPY(pDirDescriptor->pDirPath, pDirPath, dirPathLen);
    if (OK != status)
        goto exit;

    pDirDescriptor->pDirPath[dirPathLen] = 0;
    pDirDescriptor->pPrevLocalPath = prevLocalPath; prevLocalPath = NULL;

    *ppNewDirCtx = (DirectoryDescriptor) pDirDescriptor;  pDirDescriptor = NULL;

exit:

    if (clearPath)
    {
    	if (NULL != pCwdLocalPath)
    	{
    		fx_directory_local_path_restore(pAzureRtosFileMedia, pCwdLocalPath);
    	}
    	else
    	{
    		fx_directory_local_path_clear(pAzureRtosFileMedia);
    	}
    }

    if (NULL != prevLocalPath)
    {
        DIGI_FREE((void **)&prevLocalPath);
    }

    if (NULL != pDirDescriptor)
    {
        if (NULL != pDirDescriptor->pDirPath)
        {
            DIGI_FREE((void **) &pDirDescriptor->pDirPath);
        }

        DIGI_FREE((void **) &pDirDescriptor);
    }

    return status;
}

extern MSTATUS AZURERTOS_getNextFile (DirectoryDescriptor pDirCtx, DirectoryEntry *pFileCtx)
{
    MSTATUS status = OK;
    UINT ret = FX_SUCCESS;
    UINT attributes = 0;
    AzureRtosDirDescriptor *pDirDescriptor = NULL;
    CHAR *pRetPath = NULL;
    UINT clearPath = 0;

    if ((NULL == pDirCtx) || (NULL == pFileCtx))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pDirDescriptor = (AzureRtosDirDescriptor *)pDirCtx;
    if (NULL == pDirDescriptor->pDirPath)
    {
    	status = ERR_NULL_POINTER;
        goto exit;
    }

    ret = fx_directory_local_path_restore(pAzureRtosFileMedia,
            pDirDescriptor->pPrevLocalPath);
    if (FX_SUCCESS != ret)
    {
        status = ERR_FILE;
        goto exit;
    }
    clearPath = 1;

    ret = fx_directory_next_full_entry_find(pAzureRtosFileMedia,
                                      (CHAR *)pDirDescriptor->entryName,
                                      &attributes,
                                      NULL,
                                      NULL, NULL, NULL,
                                      NULL, NULL, NULL);
    switch(ret)
    {
        case FX_SUCCESS:
            pFileCtx->pCtx = NULL;
            pFileCtx->nameLength = DIGI_STRLEN ((const sbyte *)pDirDescriptor->entryName);
            pFileCtx->pName = (ubyte *)pDirDescriptor->entryName;
            /* If this is not a directory, assume a regular file */
            pFileCtx->type = (FX_DIRECTORY & attributes) ? FTDirectory : FTFile;
            break;

        case FX_NO_MORE_ENTRIES:
            pFileCtx->pCtx = NULL;
            pFileCtx->pName = NULL;
            pFileCtx->nameLength = 0;
            pFileCtx->type = FTNone;
            break;

        default:
            status = ERR_DIR_READ_FAILED;
            DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_getNextFile: Error accessing File-Media status = ",
                   ret);
            goto exit;
    }

    status = OK;

exit:
    if (clearPath)
    {
    	if (NULL != pCwdLocalPath)
    	{
    		fx_directory_local_path_restore(pAzureRtosFileMedia, pCwdLocalPath);
    	}
    	else
    	{
    		fx_directory_local_path_clear(pAzureRtosFileMedia);
    	}
    }
    return status;
}

extern MSTATUS AZURERTOS_closeDir (DirectoryDescriptor *ppDirCtx)
{
    MSTATUS status = OK, fstatus;
    UINT ret = FX_SUCCESS;
    AzureRtosDirDescriptor *pDirDescriptor = NULL;

    if ((NULL == ppDirCtx) || (NULL == *ppDirCtx))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pDirDescriptor = (AzureRtosDirDescriptor*)(*ppDirCtx);
    if (NULL != pDirDescriptor->pPrevLocalPath)
    {
        fstatus = DIGI_FREE((void **)&pDirDescriptor->pPrevLocalPath);
        if (OK == status)
            status = fstatus;
    }

    if (NULL != pDirDescriptor->pDirPath)
    {
        fstatus = DIGI_FREE((void **)&pDirDescriptor->pDirPath);
        if (OK == status)
            status = fstatus;
    }

    fstatus = DIGI_FREE((void **)ppDirCtx);
    if (OK == status)
        status = fstatus;

exit:
    return status;
}

/* -------------------------------------------------------------------------------- */

extern MSTATUS AZURERTOS_changeCWD (const sbyte *pNewCwd)
{
    MSTATUS status = OK;
    UINT ret = FX_SUCCESS;

    if (NULL == pNewCwd)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    ret = fx_directory_local_path_set(pAzureRtosFileMedia,
                                      &cwdLocalPath,
                                      (CHAR*)pNewCwd);
    if (FX_SUCCESS != ret)
    {
        status = ERR_DIR_CHANGE_FAILED;
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_changeCWD: Error setting local path. Return-code = ",
                   ret);
        goto exit;
    }

    pCwdLocalPath = &cwdLocalPath;
    status = OK;

exit:
    return status;
}

extern MSTATUS AZURERTOS_getCWD (sbyte *pCwd, ubyte4 cwdLength)
{
    MSTATUS status = OK;
    UINT ret = FX_SUCCESS;
    CHAR *returnPathName = NULL;
    UINT returnPathLen = 0;
    
    if (NULL == pCwd || 0 == cwdLength)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    ret = fx_directory_local_path_get(pAzureRtosFileMedia, &returnPathName);
    if (FX_SUCCESS != ret)
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
           (sbyte *)"AZURERTOS_getCWD: Error restoring local path. Return-code = ",
           ret);
        status = ERR_DIR_CHANGE_FAILED;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TRUSTPOINT_LOCAL__)
    if (NULL == returnPathName)
    {
        returnPathName = "/mocana";
    }
#endif

    returnPathLen = DIGI_STRLEN ((const sbyte *)returnPathName);
    if (cwdLength <= returnPathLen)
    {
        status = ERR_BUFFER_TOO_SMALL;
        goto exit;
    }

    status = DIGI_MEMSET((ubyte *)pCwd, 0, cwdLength);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pCwd, returnPathName, returnPathLen);
    if (OK != status)
        goto exit;

    status = OK;

exit:
    /* returnPathName does not need to be freed */
    return status;
}


extern MSTATUS AZURERTOS_mkdir (const sbyte *pDirectoryName, ubyte4 mode)
{
    MSTATUS status = OK;
    UINT    ret = FX_SUCCESS;

    if (NULL == pDirectoryName)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    ret = fx_directory_create(pAzureRtosFileMedia, (CHAR *)pDirectoryName);
    if ((FX_SUCCESS != ret) && (FX_ALREADY_CREATED != ret))
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
           (sbyte *)"AZURERTOS_mkdir: Error creating directory. Return-code = ",
           ret);
        status = ERR_FILE_CREATE_FAILED;
        goto exit;
    }

    status = OK;

exit:
    return status;
}

/* -------------------------------------------------------------------------------- */

extern MSTATUS AZURERTOS_fopen (const sbyte *pFileName, const sbyte *pMode, FileDescriptor *ppNewFileCtx)
{
    MSTATUS     status = OK;
    FX_FILE     *pFile = NULL;
    UINT        ret;
    UINT        mode = 0;
    ubyte	    modeIdx;
    ubyte 		deleteFile = 0;
    ubyte       createFile = 0;

    if ((NULL == pFileName) || (NULL == pMode) || (NULL == ppNewFileCtx))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = checkFileMedia();
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_fopen: Error accessing File-Media status = ",
                   status);
        goto exit;
    }

    modeIdx = 0;
    while (pMode[modeIdx])
    {
        switch(pMode[modeIdx])
        {
            case '+':
                mode |= FX_OPEN_FOR_WRITE;
                deleteFile = 0;
                break;

            case 'r':
                mode = FX_OPEN_FOR_READ;
                deleteFile = 0;
                break;

            case 'w':
                mode = FX_OPEN_FOR_WRITE;
                deleteFile = 1;
                createFile = 1;

                break;

            case 'a':
                mode = FX_OPEN_FOR_WRITE;
                deleteFile = 0;
                createFile = 1;
                break;

            case 'b':
                /* Binary mode is always on */
                break;

            default:
                status = ERR_INVALID_INPUT;
                goto exit;
        }

        modeIdx++;
    }

    if (mode & FX_OPEN_FOR_WRITE && createFile)
    {
        ret = fx_file_create(pAzureRtosFileMedia, pFileName);
        if (FX_ALREADY_CREATED == ret)
        {
            if (deleteFile)
            {
                ret = fx_file_delete(pAzureRtosFileMedia, pFileName);
                if (ret != FX_SUCCESS)
                {
                    status = ERR_FILE_CREATE_FAILED;
                    goto exit;
                }
                ret = fx_file_create(pAzureRtosFileMedia, pFileName);
            }
            else
            {
                ret = FX_SUCCESS;
            }
        }
        if (FX_SUCCESS != ret)
        {
            status = ERR_FILE_CREATE_FAILED;
            goto exit;
        }
    }

    status = DIGI_MALLOC((void **)&pFile, sizeof(*pFile));
    if (OK != status)
        goto exit;

    ret = fx_file_open(pAzureRtosFileMedia, pFile,
                       (CHAR *)pFileName, mode);
    if (FX_SUCCESS != ret)
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_fopen: Error status = ",
                   ret);
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    ret = fx_file_seek(pFile, 0UL);
    if (FX_SUCCESS != ret)
    {
         status = ERR_FILE_SEEK_FAILED;
         goto exit;

    }

    *ppNewFileCtx = (FileDescriptor) pFile;
    pFile = NULL;

exit: 
    if (OK != status)
    {
        if (NULL != pFile)
        {
            DIGI_FREE((void **)&pFile);
        }
    }
    return status;
}

extern MSTATUS AZURERTOS_fclose (FileDescriptor *ppFileCtx)
{
    MSTATUS     status = OK;
    FX_FILE     *pFile = NULL;
    UINT        ret = FX_SUCCESS;

    if (NULL == ppFileCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (NULL == *ppFileCtx)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = checkFileMedia();
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_fclose: Error accessing File-Media status = ",
                   status);
        goto exit;
    }

    pFile = (FX_FILE*)(*ppFileCtx);
    ret = fx_file_close(pFile);
    if (FX_SUCCESS != ret)
    {
        status = ERR_FILE;
        DEBUG_ERROR(DEBUG_PLATFORM,
                    (sbyte *)"AZURERTOS_fclose: Error closing file. Return-Code = ",
                 ret);
    }
    DIGI_FREE((void **)&pFile);
    *ppFileCtx = NULL;
 
exit:
   return status;
}

extern MSTATUS AZURERTOS_fread (ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesRead)
{
    MSTATUS status = OK;
    UINT    ret = FX_SUCCESS;
    FX_FILE *pFile = NULL;
    ULONG   readCount=0;

    if ((NULL == pFileCtx) || (NULL == pBuffer) || (NULL == pBytesRead))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pBytesRead = 0;

    if ((0 == itemSize) || (0 == numOfItems))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = checkFileMedia();
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_fread: Error accessing File-Media status = ",
                   ret);
        goto exit;
    }

    pFile = (FX_FILE *) pFileCtx;

    ret = fx_file_read(pFile, 
                    (VOID *)pBuffer,
                    (itemSize * numOfItems),
                    &readCount);
    if (ret == FX_SUCCESS || ret == FX_END_OF_FILE)
    {
        *pBytesRead = readCount;
        status = OK;
    }
    else
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
                    (sbyte *)"AZURERTOS_fread: Error reading file. Return-Code = ",
                 ret);
        status = ERR_FILE_READ_FAILED;
    }

exit:
    return status;
}

extern MSTATUS AZURERTOS_fwrite (const ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesWrote)
{
    MSTATUS status = OK;
    UINT    ret = FX_SUCCESS;
    FX_FILE *pFile = NULL;

    if ((NULL == pFileCtx) || (NULL == pBuffer) || (NULL == pBytesWrote))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == itemSize) || (0 == numOfItems))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = checkFileMedia();
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_fwrite: Error accessing File-Media status = ",
                   ret);
        goto exit;
    }

    pFile = (FX_FILE *) pFileCtx;
    ret = fx_file_write(pFile,
                    (VOID *)pBuffer,
                    itemSize * numOfItems);

    if (FX_SUCCESS == ret)
    {
        status = OK;
    }
    else
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
                    (sbyte *)"AZURERTOS_fwrite: Error writing to file. Return-Code = ",
                 ret);
        status = ERR_FILE_WRITE_FAILED;
    }

    *pBytesWrote = (itemSize * numOfItems);

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_64_BIT__
extern MSTATUS AZURERTOS_fseek (FileDescriptor pFileCtx, sbyte8 offset, ubyte4 m_whence)
#else
extern MSTATUS AZURERTOS_fseek (FileDescriptor pFileCtx, sbyte4 offset, ubyte4 m_whence)
#endif
{
    MSTATUS status = OK;
    FX_FILE *pFile = NULL;
    UINT    ret = FX_SUCCESS;
    UINT    seekFrom;

    if (NULL == pFileCtx)
    {
        status = ERR_NULL_POINTER;
    }

    status = checkFileMedia();
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_fseek: Error accessing File-Media status = ",
                   ret);
        goto exit;
    }

    switch (m_whence)
    {
        case MSEEK_SET:
            seekFrom = FX_SEEK_BEGIN;
            break;
        case MSEEK_CUR:
            seekFrom = FX_SEEK_FORWARD;
            break;
        case MSEEK_END:
            seekFrom = FX_SEEK_END;
            break;
        default:
            status = ERR_FILE_INVALID_ARGUMENTS;
            goto exit;
    }

    pFile = (FX_FILE *) pFileCtx;

    ret = fx_file_extended_relative_seek(pFile,
                        offset, seekFrom);
    if (FX_SUCCESS != ret)
    {
        status = ERR_FILE_SEEK_FAILED;
        DEBUG_ERROR(DEBUG_PLATFORM,
                    (sbyte *)"AZURERTOS_fseek: Error seeking in file. Return-Code = ",
                 ret);
        goto exit;
    }

    status = OK;
exit:
    return status;
}

extern MSTATUS AZURERTOS_fprintf (FileDescriptor pFileCtx, const sbyte *pFormat, ...)
{
    MSTATUS status = OK;
    FX_FILE *pFile = NULL;
    UINT    ret = FX_SUCCESS;
    va_list args;
    int iCount = 0;
    char printBuf[256];

    if ((NULL == pFileCtx) || (NULL == pFormat))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = checkFileMedia();
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_fprintf: Error accessing File-Media status = ",
                   ret);
        goto exit;
    }


    va_start (args, pFormat);
    pFile = (FX_FILE *) pFileCtx;

    iCount = vsnprintf(printBuf, sizeof(printBuf), (const char *)pFormat, args);
    va_end( args );
    if(iCount > 0)
    {
        ret = fx_file_write(pFile,
                        (VOID *)printBuf,
                        iCount);
        if(FX_SUCCESS != ret)
        {
            status = ERR_FILE;
            DEBUG_ERROR(DEBUG_PLATFORM,
                        (sbyte *)"AZURERTOS_fprintf: Error writing to file. Return-Code = ",
                     ret);
            goto exit;
        }
    }

    status = OK;
exit:
    return status;
}

/* ------------------------------------------------------------------------- */

extern MSTATUS AZURERTOS_fflush (FileDescriptor pFileCtx)
{
    MSTATUS status = OK;
    UINT    ret = FX_SUCCESS;

    status = checkFileMedia();
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_fflush: Error accessing File-Media status = ",
                   ret);
        goto exit;
    }

    ret = fx_media_flush(pAzureRtosFileMedia);
    if (FX_SUCCESS != ret)
    {
        status = ERR_FILE;
        DEBUG_ERROR(DEBUG_PLATFORM,
                   (sbyte *)"AZURERTOS_fflush: Error flush operation, return = ",
                   ret);
        goto exit;
    }

    status = OK;
exit:
    return status;
}



/* ------------------------------------------------------------------------- */


extern sbyte* AZURERTOS_fgets (sbyte *pString, ubyte4 stringLen, FileDescriptor pFileCtx)
{
    return NULL;
}


/* ------------------------------------------------------------------------- */

extern MSTATUS AZURERTOS_getEnvironmentVariableValueAlloc(const sbyte *pVariableName, sbyte **ppValueBuffer)
{
    return ERR_NOT_IMPLEMENTED;
}


/* ------------------------------------------------------------------------- */

extern MSTATUS AZURERTOS_getDirectoryPathAlloc (const sbyte *pFilePath, sbyte **ppDirectoryPath)
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

extern MSTATUS AZURERTOS_getFullPath (const sbyte *pRelativePath, sbyte *pAbsolutePath, ubyte4 absolutePathLength)
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

extern MSTATUS AZURERTOS_ftell (FileDescriptor pFileCtx, ubyte4 *pOffset)
{
    MSTATUS status = ERR_NULL_POINTER;
    FX_FILE *pFile = (FX_FILE *)pFileCtx;
    sbyte4 offset;

    if ((NULL == pFileCtx) || (NULL == pOffset))
        goto exit;

    *pOffset = 0;

    if (pFile->fx_file_media_ptr == pAzureRtosFileMedia)
    {
        offset = pFile->fx_file_current_file_offset;
        if (0 <= offset)
        {
            *pOffset = offset;
            status = OK;
            goto exit;
        }
        else
            status = ERR_GENERAL;
    }
    else
        status = ERR_FILE_INVALID_DESCRIPTOR;

exit:
    return status;
}

extern MSTATUS AZURERTOS_setFileMedia(FX_MEDIA *pMedia)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (pMedia)
    {
        pAzureRtosFileMedia = pMedia;
        gp_fx_media0 = pMedia;
        status = OK;
    }

    return status;
}
#endif /* __CLM_FILEX__ */

#endif /* __AZURE_FMGMT__ */
