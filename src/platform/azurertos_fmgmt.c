/*
 * azurertos_fmgmt.c
 *
 * AzureRTOS File Management Abstraction — RAM-VFS edition
 *
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
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 * AGPL v3 / Commercial dual-license — see repo LICENSE.md.
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
#include "../common/utils.h"   /* UTILS_readFile / UTILS_writeFile / UTILS_appendFile */

/* clm_vfs.c provides this: returns 1 if the path is a directory sentinel
 * (created by UTILS_mkdir), 0 for regular files or non-existent paths.     */
extern int VFS_isDirectory(const char *path);

#include <string.h>
#include <stdarg.h>
#include <stdio.h>

/* ── file handle ──────────────────────────────────────────────────────── */

#define AZ_FMGMT_PATH_MAX  256U
#define AZ_FMGMT_WR_INIT   512U   /* initial write-buffer capacity */

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
    const sbyte   *p;

    if (!pFileName || !pMode || !ppNewFileCtx)
        return ERR_NULL_POINTER;

    *ppNewFileCtx = NULL;

    /* parse mode string */
    for (p = pMode; *p; ++p) {
        switch (*p) {
            case 'r': isRead   = 1; break;
            case 'w': isWrite  = 1; break;
            case 'a': isWrite  = 1; isAppend = 1; break;
            case '+': isRead   = 1; isWrite  = 1; break;
            case 'b': break; /* binary – no-op */
            default:  return ERR_INVALID_INPUT;
        }
    }
    if (!isRead && !isWrite)
        return ERR_INVALID_INPUT;

    h = handle_alloc();
    if (!h) return ERR_MEM_ALLOC_FAIL;

    strncpy(h->path, (const char *)pFileName, AZ_FMGMT_PATH_MAX - 1U);
    h->path[AZ_FMGMT_PATH_MAX - 1U] = '\0';
    h->writable   = isWrite;
    h->appendMode = isAppend;

    if (isRead || isAppend) {
        /* try to load existing content; ignore "not found" for write modes */
        MSTATUS rdSt = UTILS_readFile((const char *)pFileName, &pBuf, &bufLen);
        if (OK == rdSt) {
            h->pData = pBuf;
            h->len   = bufLen;
            h->cap   = bufLen;
            pBuf     = NULL; /* owned by h now */
        } else if (!isWrite) {
            /* pure read and file does not exist */
            status = ERR_FILE_OPEN_FAILED;
            goto exit;
        }
        /* write/append with no existing file: start empty */
    }

    if (isWrite && !isAppend) {
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
    total = itemSize * numOfItems;

    if (!h->writable)
        return ERR_FILE_WRITE_FAILED;

    if (h->appendMode)
        h->pos = h->len;

    newLen = h->pos + total;
    if (newLen > h->cap) {
        ubyte4 newCap = (newLen * 2U > AZ_FMGMT_WR_INIT) ? newLen * 2U : AZ_FMGMT_WR_INIT;
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

    if (n <= 0) return OK;
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
    strncpy((char *)pBuf, "/", (size_t)bufLen);
    pBuf[bufLen - 1U] = '\0';
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
    strncpy((char *)pAbsBuf, (const char *)pRelPath, (size_t)(absBufLen - 1U));
    pAbsBuf[absBufLen - 1U] = '\0';
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

    /* strip trailing filename: find last '/' */
    p = *ppDirPath + len - 2U;
    while (p > *ppDirPath && *p != '/')
        --p;
    if (*p == '/')
        *(p + 1U) = '\0';

    return OK;
}

extern MSTATUS AZURERTOS_getEnvironmentVariableValueAlloc(const sbyte *pName,
                                                          sbyte **ppValue)
{
    (void)pName;
    if (ppValue) *ppValue = NULL;
    return ERR_NOT_FOUND;
}

#endif /* __AZURE_FMGMT__ */
