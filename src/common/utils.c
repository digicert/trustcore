/*
 * utils.c
 *
 * Utility code for storing and retrieving keys
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

#ifndef __DISABLE_MOCANA_FILE_SYSTEM_HELPER__

/* Force Linux file handling for freertos simulator */
#if defined(__FREERTOS_SIMULATOR__) || defined(__RTOS_FREERTOS_ESP32__)
#ifdef __RTOS_FREERTOS__
#undef __RTOS_FREERTOS__
#endif
#ifdef __FREERTOS_RTOS__
#undef __FREERTOS_RTOS__
#endif
#ifndef __LINUX_RTOS__
#define __LINUX_RTOS__
#endif
#ifndef __RTOS_LINUX__
#define __RTOS_LINUX__
#endif
#endif

#ifdef __MQX_RTOS__
#include <mqx.h>
#include <fio.h>
#endif

#if !( defined(__MQX_RTOS__) || defined(__UCOS_DIRECT_RTOS__) )
#include <stdio.h>
#if !defined(__RTOS_WINCE__)
#include <errno.h>
#endif
#endif

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mocana.h"
#include "../common/random.h"
#include "../common/utils.h"
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
#include "../common/mfmgmt.h"
#endif
#if !defined (__FREERTOS_RTOS__)
#include <sys/stat.h>
#endif
#if defined (__RTOS_ZEPHYR__)
#include <zephyr/fs/fs.h>
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
#include "ff.h"
#ifndef f_size
#define f_size file_size
#endif
#ifndef f_rewind
#define f_rewind(fp) f_lseek((fp), 0)
#endif
#endif
#if defined _MSC_VER
#include <direct.h>
#endif

#ifdef __UCOS_DIRECT_RTOS__
#include <fs.h>
#include <fs_api.h>
#define FILE FS_FILE
#define fopen fs_fopen
#define fseek fs_fseek
#define ftell fs_ftell
#define rewind fs_rewind
#define fread fs_fread
#define fclose fs_fclose
#define fwrite fs_fwrite
#define SEEK_END FS_SEEK_END
#endif /* __UCOS_DIRECT_RTOS__ */

#if defined (__ENABLE_MOCANA_RTOS_FILEX__)
#include "fx_api.h"
extern FX_MEDIA *gp_fx_media0;
#endif

#ifdef __ENABLE_DIGICERT_POSIX_SUPPORT__
#include <fcntl.h>
#include <unistd.h>
#endif

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
#ifndef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
#error "__ENABLE_DIGICERT_SECURE_PATH__ requires __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__ to be defined"
#endif
#ifndef MANDATORY_BASE_PATH
#error "MANDATORY_BASE_PATH must be defined if __ENABLE_DIGICERT_SECURE_PATH__ is enabled"
#endif
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
UTILS_readFileRaw(const ubyte* pFileObj, ubyte **ppRetBuffer, ubyte4 *pRetBufLength)
{
#if defined (__RTOS_ZEPHYR__)
    int ret;
    struct fs_file_t *f = (struct fs_file_t *) pFileObj;
    ubyte4 bytesRead = 0;
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    FIL *f = (FIL*) pFileObj;
    FRESULT error = 0;
    ubyte4 bytesRead = 0;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
	FX_FILE *f = (FX_FILE *)pFileObj;
	ubyte4   actual_size = 0;
#elif !defined( __RTOS_WTOS__)
    FILE*   f = (FILE*) pFileObj;
#else
    int     f = (int)pFileObj;
#endif
    sbyte4  fileSize;
    ubyte*  pFileBuffer = NULL;
    MSTATUS status = OK;

    /* check input */
    if ((NULL == pFileObj) || (NULL == ppRetBuffer) || (NULL == pRetBufLength))
    {
        status = ERR_NULL_POINTER;
        goto nocleanup;
    }

    *ppRetBuffer   = NULL;
    *pRetBufLength = 0;

#if defined (__RTOS_ZEPHYR__)
    ret = fs_seek(f, 0, MSEEK_END);
    if (ret < 0)
    {
        status = ERR_FILE_SEEK_FAILED;
        goto exit;
    }

    fileSize = (sbyte4)fs_tell(f);
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    fileSize = f->fx_file_current_file_size ;
#elif defined (__FREERTOS_RTOS__)&& !defined(__ENABLE_MOCANA_NANOPNAC__)
    fileSize = f_size(f) ;
#else
    /* determine size */
    if (OK > fseek(f, 0, MSEEK_END))
    {
        status = ERR_FILE_SEEK_FAILED;
        goto exit;
    }

    fileSize = (sbyte4)ftell(f);
#endif

    if (0 > fileSize)  /* ftell() returns -1 on error */
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    if (NULL == (pFileBuffer = (ubyte *) MALLOC(fileSize + 1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pFileBuffer[fileSize] = 0;
#if defined (__RTOS_ZEPHYR__)
    if (OK > fs_seek(f, 0L, MSEEK_SET))
    {
        status = ERR_FILE_SEEK_FAILED;
        goto exit;
    }
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    f_rewind(f) ;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    if(FX_SUCCESS != fx_file_seek(f, 0UL))
    {
         status = ERR_FILE_SEEK_FAILED;
         goto exit;

    }
#elif !defined(__RTOS_WINCE__) && !defined(__RTOS_MQX__)
    rewind(f);
#else
    if (OK > fseek(f, 0L, MSEEK_SET))
    {
        status = ERR_FILE_SEEK_FAILED;
        goto exit;
    }
#endif

#if defined (__RTOS_ZEPHYR__)
    bytesRead = fs_read(f, pFileBuffer, fileSize);
    if (bytesRead < (ubyte4)fileSize)
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    error = f_read(f, pFileBuffer, fileSize, &bytesRead);
    if ((error) || (bytesRead != fileSize))
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    status = fx_file_read(f, pFileBuffer, fileSize, &actual_size);
    if(actual_size < fileSize )
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }
#else
    if (((ubyte4)fileSize) > fread(pFileBuffer, 1, fileSize, f))
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }
#endif

    *ppRetBuffer   = pFileBuffer;  pFileBuffer = NULL;
    *pRetBufLength = fileSize;

exit:
    if (NULL != pFileBuffer)
        FREE(pFileBuffer);

nocleanup:
    return status;

} /* UTILS_readFileRaw */

/*------------------------------------------------------------------*/

#if !defined(__ENABLE_MOCANA_NANOPNAC__)
extern MSTATUS
UTILS_mkdir(const char* directory)
{
    int  status;
#if defined (__RTOS_ZEPHYR__)
    int ret;
#endif
    ubyte *pDPath = (ubyte *)directory;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;

    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (directory, (sbyte **) &pDPath, TRUE);
        if (OK > status)
            return status;

        freePath = TRUE;
    }
#endif

#if defined (__RTOS_ZEPHYR__)
    ret = fs_mkdir(pDPath);
    if (ret == 0)
    {
        status = OK;
    }
    else
    {
        status = ERR_FILE;
    }
#elif defined _MSC_VER
        status = _mkdir(pDPath);
#elif defined(__RTOS_VXWORKS__)
    #if defined(__VX7_SR640__)
        status = mkdir(pDPath, 0700);
    #else
        status = mkdir(pDPath);
    #endif
#elif defined(__FREERTOS_RTOS__)
        status = f_mkdir(pDPath);
#else
        status = mkdir((const char*)pDPath, 0700);
#endif
#if defined(__FREERTOS_RTOS__)
        if(status == FR_EXIST)
        {
            status = ERR_FILE_EXISTS;
        }
#else
        if (0 > status) {
            if (errno == EEXIST)
                status = ERR_FILE_EXISTS;
        }
#endif
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        MOC_FREE ((void **) &pDPath);
#endif
return (MSTATUS)status;

}
#endif

#ifdef __ENABLE_DIGICERT_POSIX_SUPPORT__
extern MSTATUS
UTILS_readFile(const char* pFilename,
               ubyte **ppRetBuffer, ubyte4 *pRetBufLength)
{
    char *pResolvedPath = NULL;
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    struct stat orig_st = { 0 };
    struct stat open_st = { 0 };
#endif
    FILE*   f = NULL;
    int     fd = -1;
    ubyte *pFPath = NULL;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    MSTATUS status = OK;

    /* check input */
    if ((NULL == pFilename) || (NULL == ppRetBuffer) || (NULL == pRetBufLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetBuffer   = NULL;
    *pRetBufLength = 0;

    pFPath = (ubyte *) pFilename;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath())
    {
        status = FMGMT_getFullPathAllocAux(pFilename, (sbyte **) &pFPath, TRUE);
        if (OK > status)
            goto exit;

        freePath = TRUE;
    }
#endif

    pResolvedPath = realpath((const char *)pFPath, NULL);
    if (pResolvedPath == NULL)
    {
        status = ERR_FILE_NOT_EXIST;
        goto exit;
    }

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (MOC_STRNCMP(pResolvedPath, MANDATORY_BASE_PATH, MOC_STRLEN(MANDATORY_BASE_PATH)) != 0)
    {
        /* File path must start with the mandatory base path */
        status = ERR_FILE_INSECURE_PATH;
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_SECURE_PATH__ */
#endif

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (lstat(pResolvedPath, &orig_st) != 0)
    {
        status = ERR_FILE_NOT_EXIST;
        goto exit;
    }

    if (!S_ISREG(orig_st.st_mode))
    {
        status = ERR_FILE_BAD_TYPE;
        goto exit;
    }
#endif

    fd = open((const char* __restrict)pResolvedPath, O_RDONLY | O_NOFOLLOW);
    if (fd >= 0)
    {
        f = fdopen(fd, "rb");
        if (NULL == f)
        {
            close(fd);
            status = ERR_FILE_OPEN_FAILED;
            goto exit;
        }
    }
    else
    {
        f = NULL;
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        MOC_FREE ((void **) &pFPath);

    freePath = FALSE; /* Reset freePath to avoid double free */
#endif

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if(fstat(fd, &open_st) != 0)
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    /* tamper check */
    if ((orig_st.st_mode != open_st.st_mode) ||
        (orig_st.st_ino  != open_st.st_ino) ||
        (orig_st.st_dev  != open_st.st_dev))
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }
#endif

    /* Read the Raw File */
    status = UTILS_readFileRaw((ubyte*)f, ppRetBuffer, pRetBufLength);

exit:
    if (NULL != f)
        fclose(f);
    free(pResolvedPath);
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        MOC_FREE ((void **) &pFPath);
#endif
    return status;

} /* UTILS_readFile */
#else
extern MSTATUS
UTILS_readFile(const char* pFilename,
               ubyte **ppRetBuffer, ubyte4 *pRetBufLength)
{
#if defined (__RTOS_ZEPHYR__)
    struct fs_file_t fs_file;
    struct fs_file_t *f = NULL;
    int ret = 0;
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    FIL file ;
    FIL *f = &file;
    FRESULT error = 0;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
	FX_FILE new_file = {0};
	FX_FILE *f = &new_file;
#elif !defined(__RTOS_WTOS__)
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    struct stat st = { 0 };
#endif
    FILE*   f;
#else
    int     f;
#endif
    ubyte *pFPath = NULL;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    MSTATUS status = OK;

    /* check input */
    if ((NULL == pFilename) || (NULL == ppRetBuffer) || (NULL == pRetBufLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetBuffer   = NULL;
    *pRetBufLength = 0;

    pFPath = (ubyte *) pFilename;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (pFilename, (sbyte **) &pFPath, TRUE);
        if (OK > status)
            goto exit;

        freePath = TRUE;
    }

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (MOC_STRNCMP(pFPath, MANDATORY_BASE_PATH, MOC_STRLEN(MANDATORY_BASE_PATH)) != 0)
    {
        /* File path must start with the mandatory base path */
        status = ERR_FILE_INSECURE_PATH;
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_SECURE_PATH__ */
#endif

#if defined (__RTOS_ZEPHYR__)
    fs_file_t_init(&fs_file);

    ret = fs_open(&fs_file, pFPath, (fs_mode_t)FS_O_READ);
    if (ret != 0)
        f = NULL;
    else
        f = &fs_file;
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    error = f_open(f, pFPath, (FA_READ | FA_OPEN_EXISTING)) ;
    if(error)
        f = NULL ;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    status = fx_file_open(gp_fx_media0, f, pFPath, (FX_OPEN_FOR_READ));
    if(FX_SUCCESS != status)
    {
    	f = NULL ;
    }
#else
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (lstat(pFPath, &st) != 0)
    {
        status = ERR_FILE_NOT_EXIST;
        goto exit;
    }

    if (!S_ISREG(st.st_mode))
    {
        status = ERR_FILE_BAD_TYPE;
        goto exit;
    }
#endif

    f = fopen((const char* __restrict)pFPath, "rb");
#endif

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        MOC_FREE ((void **) &pFPath);
#endif

#ifndef __RTOS_WTOS__
    if (!f)
#else
    if (f < 0)
#endif
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    /* Read the Raw File */
    status = UTILS_readFileRaw((ubyte*)f, ppRetBuffer, pRetBufLength);

#if defined (__RTOS_ZEPHYR__)
    (void) fs_close(f);
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
        (void) f_close(f);
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    fx_file_close(f);
#else
    (void) fclose(f);
#endif

exit:
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        MOC_FREE ((void **) &pFPath);
#endif
    return status;

} /* UTILS_readFile */
#endif /* __ENABLE_DIGICERT_POSIX_SUPPORT__ */


/*------------------------------------------------------------------*/

extern MSTATUS
UTILS_freeReadFile(ubyte **ppRetBuffer)
{
    if ((NULL != ppRetBuffer) && (NULL != *ppRetBuffer))
    {
        FREE(*ppRetBuffer);
        *ppRetBuffer = NULL;
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UTILS_writeFile(const char* pFilename,
                const ubyte *pBuffer, ubyte4 bufLength)
{
#if defined(__RTOS_ZEPHYR__)
    struct fs_file_t fs_file;
    struct fs_file_t *f = NULL;
    int ret = 0;
    sbyte4 bytesWritten = 0;
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
        FIL file ;
        FIL *f = &file;
        FRESULT error = 0;
        ubyte4 bytesWritten = 0;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
	FX_FILE new_file = {0};
	FX_FILE *f = &new_file;
#elif !defined(__RTOS_WTOS__)
    FILE*   f;
#else
    int     f;
#endif
    ubyte *pFPath = NULL;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    MSTATUS status = OK;

    if ( (0 == bufLength) || (NULL == pBuffer) || (NULL == pFilename))
    {
        status = ERR_INVALID_INPUT;
        goto nocleanup;
    }

    pFPath = (ubyte *) pFilename;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (pFilename, (sbyte **) &pFPath, TRUE);
        if (OK > status)
            goto nocleanup;

        freePath = TRUE;
    }

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (MOC_STRNCMP(pFPath, MANDATORY_BASE_PATH, MOC_STRLEN(MANDATORY_BASE_PATH)) != 0)
    {
        /* File path must start with the mandatory base path */
        status = ERR_FILE_INSECURE_PATH;
        if (TRUE == freePath)
            MOC_FREE((void **) &pFPath);
        goto nocleanup;
    }
#endif /* __ENABLE_DIGICERT_SECURE_PATH__ */
#endif

#if defined(__RTOS_ZEPHYR__)
    fs_file_t_init(&fs_file);

    ret = fs_open(&fs_file, pFPath, (fs_mode_t)FS_O_WRITE|FS_O_CREATE);
    if (ret != 0)
        f = NULL;
    else
        f = &fs_file;
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    error = f_open(f, pFPath, (FA_WRITE | FA_CREATE_ALWAYS)) ;
    if(error)
        f = NULL ;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    fx_file_create(gp_fx_media0, pFPath);
    if(FX_SUCCESS != fx_file_open(gp_fx_media0, f, pFPath, (FX_OPEN_FOR_WRITE)))
    {
    	f = NULL ;
    }
    else
    {
    	fx_file_truncate(f, 0);
    }
#elif defined (__ENABLE_DIGICERT_POSIX_SUPPORT__)
    int fd = open((const char* __restrict)pFPath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd >= 0)
    {
        f = fdopen(fd, "wb");
        if (NULL == f)
        {
            close(fd);
        }
    }
    else
    {
        f = NULL;
    }
#else
    f = fopen((const char* __restrict)pFPath, "wb");
#endif

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        MOC_FREE ((void **) &pFPath);
#endif

#ifndef __RTOS_WTOS__
    if (!f)
#else
    if (f < 0)
#endif
    {
        status = ERR_FILE_OPEN_FAILED;
        goto nocleanup;
    }

#if defined(__RTOS_ZEPHYR__)
    bytesWritten = fs_write(f, pBuffer, bufLength);
    if (bytesWritten < 0)
    {
        status = ERR_FILE_WRITE_FAILED;
    }
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    error = f_write(f, pBuffer, bufLength, &bytesWritten);
    if ((error) || (bytesWritten != bufLength))
    {
        status = ERR_FILE_WRITE_FAILED;
    }

#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    if(FX_SUCCESS != fx_file_write(f, pBuffer, bufLength))
    	status = ERR_FILE_WRITE_FAILED;
#else
    if (bufLength != (fwrite(pBuffer, 1, bufLength, f)))
        status = ERR_FILE_WRITE_FAILED;
#endif

#if defined(__RTOS_ZEPHYR__)
    (void) fs_close(f);
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    (void) f_close(f);
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    fx_file_close(f);
    fx_media_flush(gp_fx_media0);
#else
    (void) fclose(f);
#endif

nocleanup:
    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_POSIX_SUPPORT__
extern MSTATUS
UTILS_appendFile(const char* pFilename,
                 const ubyte *pBuffer, ubyte4 bufLength)
{
    char *pResolvedPath = NULL;
    char *pTempPath = NULL;
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    struct stat orig_st = { 0 };
    struct stat open_st = { 0 };
    byteBoolean fileExists = FALSE;
#endif
    FILE*   f = NULL;
    int     fd = -1;
    ubyte *pFPath = NULL;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    MSTATUS status = OK;

    if ( (0 == bufLength) || (NULL == pBuffer) || (NULL == pFilename))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pFPath = (ubyte *) pFilename;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (pFilename, (sbyte **) &pFPath, TRUE);
        if (OK > status)
            goto exit;

        freePath = TRUE;
    }
#endif

    pResolvedPath = realpath((const char *)pFPath, NULL);
    if (NULL == pResolvedPath)
    {
        if (errno == ENOENT)
        {
            /* File does not exist, will create new file */
            pTempPath = (char *)pFPath;
        }
        else
        {
            status = ERR_FILE_NOT_EXIST;
            goto exit;
        }
    }
    else
    {
        pTempPath = pResolvedPath;
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
        fileExists = TRUE;
#endif
    }

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (MOC_STRNCMP(pTempPath, MANDATORY_BASE_PATH, MOC_STRLEN(MANDATORY_BASE_PATH)) != 0)
    {
        /* File path must start with the mandatory base path */
        status = ERR_FILE_INSECURE_PATH;
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_SECURE_PATH__ */
#endif /* __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__ */

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (TRUE == fileExists)
    {
        if (lstat(pTempPath, &orig_st) != 0)
        {
            status = ERR_FILE_NOT_EXIST;
            goto exit;
        }

        if (!S_ISREG(orig_st.st_mode))
        {
            status = ERR_FILE_BAD_TYPE;
            goto exit;
        }
    }
#endif

    fd = open((const char* __restrict)pTempPath, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd >= 0)
    {
        f = fdopen(fd, "ab");
        if (NULL == f)
        {
            close(fd);
            status = ERR_FILE_OPEN_FAILED;
            goto exit;
        }
    }
    else
    {
        f = NULL;
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        MOC_FREE ((void **) &pFPath);

    freePath = FALSE; /* Reset freePath to avoid double free */
#endif

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (fileExists)
    {
        if(fstat(fd, &open_st) != 0)
        {
            status = ERR_FILE_OPEN_FAILED;
            goto exit;
        }

        /* tamper check */
        if ((orig_st.st_mode != open_st.st_mode) ||
            (orig_st.st_ino  != open_st.st_ino) ||
            (orig_st.st_dev  != open_st.st_dev))
        {
            status = ERR_FILE_OPEN_FAILED;
            goto exit;
        }
    }
#endif

    /* Append to the Raw File */
    if (bufLength != (fwrite(pBuffer, 1, bufLength, f)))
    {
        status = ERR_FILE_WRITE_FAILED;
    }

exit:
    if (NULL != f)
        fclose(f);

    free(pResolvedPath);
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        MOC_FREE ((void **) &pFPath);
#endif
    return status;
}
#else
extern MSTATUS
UTILS_appendFile(const char* pFilename,
                const ubyte *pBuffer, ubyte4 bufLength)
{
#if defined(__RTOS_ZEPHYR__)
    struct fs_file_t fs_file;
    struct fs_file_t *f = NULL;
    int ret = 0;
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
            FIL file ;
            FIL *f = &file;
            FRESULT error = 0;
            ubyte4 bytesWritten = 0;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
	FX_FILE new_file = {0};
	FX_FILE *f = &new_file;
#elif !defined(__RTOS_WTOS__)
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    struct stat st = { 0 };
#endif
    FILE*   f;
#else
    int     f;
#endif
    ubyte *pFPath = NULL;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    MSTATUS status = OK;

    if ( (0 == bufLength) || (NULL == pBuffer) || (NULL == pFilename))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pFPath = (ubyte *) pFilename;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (pFilename, (sbyte **) &pFPath, TRUE);
        if (OK > status)
            goto exit;

        freePath = TRUE;
    }

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (MOC_STRNCMP(pFPath, MANDATORY_BASE_PATH, MOC_STRLEN(MANDATORY_BASE_PATH)) != 0)
    {
        /* File path must start with the mandatory base path */
        status = ERR_FILE_INSECURE_PATH;
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_SECURE_PATH__ */
#endif

#if defined(__RTOS_ZEPHYR__)
    fs_file_t_init(&fs_file);

    ret = fs_open(&fs_file, pFPath, (fs_mode_t)FS_O_APPEND|FS_O_CREATE);
    if (ret != 0)
        f = NULL;
    else
        f = &fs_file;
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    error = f_open(f, pFPath, (FA_WRITE | FA_OPEN_ALWAYS)) ;
    if(error)
        f = NULL ;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    fx_file_create(gp_fx_media0, pFPath);
    if(FX_SUCCESS != fx_file_open(gp_fx_media0, f, pFPath, (FX_OPEN_FOR_WRITE)))
    {
    	f = NULL ;
    }
    else
    {
    	fx_file_seek(f, ~0UL); /* goto the end of the file */
    }
#else
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (lstat(pFPath, &st) != 0)
    {
        status = ERR_FILE_NOT_EXIST;
        goto exit;
    }

    if (!S_ISREG(st.st_mode))
    {
        status = ERR_FILE_BAD_TYPE;
        goto exit;
    }
#endif

    f = fopen((const char* __restrict)pFPath, "ab");
#endif

#ifndef __RTOS_WTOS__
    if (!f)
#else
    if (f < 0)
#endif
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

#if defined(__RTOS_ZEPHYR__)
    ret = fs_write(f, pBuffer, bufLength);
    if (ret < 0)
    {
        status = ERR_FILE_WRITE_FAILED;
    }
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    error = f_lseek(f, f_size(f));
    error = f_write(f, pBuffer, bufLength, &bytesWritten);
    if ((error) || (bytesWritten != bufLength))
    {
        status = ERR_FILE_WRITE_FAILED;
    }
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    if(FX_SUCCESS != fx_file_write(f, pBuffer, bufLength))
    	status = ERR_FILE_WRITE_FAILED;
#else
    if (bufLength != (fwrite(pBuffer, 1, bufLength, f)))
        status = ERR_FILE_WRITE_FAILED;
#endif

#if defined(__RTOS_ZEPHYR__)
    (void) fs_close(f);
#elif defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
        (void) f_close(f);
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    fx_file_close(f);
    fx_media_flush(gp_fx_media0);
#else
    (void) fclose(f);
#endif

exit:
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        MOC_FREE ((void **) &pFPath);
#endif
    return status;
}
#endif /* __ENABLE_DIGICERT_POSIX_SUPPORT__ */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_POSIX_SUPPORT__
extern MSTATUS
UTILS_copyFile(const char* pSrcFilename, const char* pDestFilename, ubyte4 bufLength)
{
    char *pResolvedSrcPath = NULL;
    char *pResolvedDestPath = NULL;
    char *pTempPath = NULL;
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    struct stat orig_st = { 0 };
    struct stat open_st = { 0 };
#endif
    FILE*   fin = NULL;
    int     fdin = -1;
    FILE*   fout = NULL;
    int     fdout = -1;
    ubyte *pSrcPath = NULL;
    ubyte *pDstPath = NULL;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freeSrcPath = FALSE;
    intBoolean freeDstPath = FALSE;
#endif
    MSTATUS status = OK;
    ssize_t nread = 0;
    char *buffer = NULL;

    if ( (0 == bufLength) || (NULL == pSrcFilename) || (NULL == pDestFilename))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pSrcPath = (ubyte *) pSrcFilename;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (pSrcFilename, (sbyte **) &pSrcPath, TRUE);
        if (OK > status)
            goto exit;

        freeSrcPath = TRUE;
    }
#endif

    pResolvedSrcPath = realpath((const char *)pSrcPath, NULL);
    if (NULL == pResolvedSrcPath)
    {
        status = ERR_FILE_NOT_EXIST;
        goto exit;
    }

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (MOC_STRNCMP(pResolvedSrcPath, MANDATORY_BASE_PATH, MOC_STRLEN(MANDATORY_BASE_PATH)) != 0)
    {
        /* File path must start with the mandatory base path */
        status = ERR_FILE_INSECURE_PATH;
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_SECURE_PATH__ */
#endif

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (lstat(pResolvedSrcPath, &orig_st) != 0)
    {
        status = ERR_FILE_NOT_EXIST;
        goto exit;
    }

    if (!S_ISREG(orig_st.st_mode))
    {
        status = ERR_FILE_BAD_TYPE;
        goto exit;
    }
#endif

    fdin = open((const char* __restrict)pResolvedSrcPath, O_RDONLY | O_NOFOLLOW);
    if (fdin < 0)
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if(fstat(fdin, &open_st) != 0)
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    /* tamper check */
    if ((orig_st.st_mode != open_st.st_mode) ||
        (orig_st.st_ino  != open_st.st_ino) ||
        (orig_st.st_dev  != open_st.st_dev))
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }
#endif

    fin = fdopen(fdin, "rb");
    if (NULL == fin)
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    pDstPath = (ubyte *) pDestFilename;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (pDestFilename, (sbyte **) &pDstPath, TRUE);
        if (OK > status)
            goto exit;
        freeDstPath = TRUE;
    }
#endif

    pResolvedDestPath = realpath((const char *)pDstPath, NULL);
    if (NULL == pResolvedDestPath)
    {
        if (ENOENT == errno)
        {
            /* File does not exist, will create new file */
            pTempPath = (char *)pDstPath;
        }
        else
        {
            status = ERR_FILE_NOT_EXIST;
            goto exit;
        }
    }
    else
    {
        pTempPath = pResolvedDestPath;
    }

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (MOC_STRNCMP(pTempPath, MANDATORY_BASE_PATH, MOC_STRLEN(MANDATORY_BASE_PATH)) != 0)
    {
        /* File path must start with the mandatory base path */
        status = ERR_FILE_INSECURE_PATH;
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_SECURE_PATH__ */
#endif

    fdout = open((const char* __restrict)pTempPath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fdout < 0)
    {
        status = ERR_FILE_CREATE_FAILED;
        goto exit;
    }

    fout = fdopen(fdout, "wb");
    if (NULL == fout)
    {
        status = ERR_FILE_CREATE_FAILED;
        goto exit;
    }

    status = MOC_MALLOC((void **)&buffer, bufLength);
    if (OK != status)
    {
        goto exit;
    }

    while (nread = fread(buffer, 1, bufLength, fin), nread > 0)
    {
        char *out_ptr = buffer;
        ssize_t nwritten = 0;

        do
        {
            nwritten = fwrite(out_ptr, 1, nread, fout);
            if (nwritten > 0)
            {
                nread -= nwritten;
                out_ptr += nwritten;
            }
            else
            {
                status = ERR_FILE_WRITE_FAILED;
                goto exit;
            }
        } while (nread > 0);
    }

    if (0 == nread)
    {
        if (fclose(fout) < 0)
        {
            fout = NULL;

            status = ERR_FILE_CLOSE_FAILED;
            goto exit;
        }
        fclose(fin);

        fout = NULL;
        fin = NULL;

        /* Success! */
        status = OK;
    }
    else
    {
        status = ERR_FILE_READ_FAILED;
    }

exit:
    if (NULL != buffer)
    {
        MOC_FREE((void **)&buffer);
    }
    if (NULL != fout)
    {
        fclose(fout);
    }
    if (NULL != fin)
    {
        fclose(fin);
    }
    free(pResolvedSrcPath);
    free(pResolvedDestPath);
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freeSrcPath)
        MOC_FREE((void **)&pSrcPath);
    if (TRUE == freeDstPath)
        MOC_FREE((void **)&pDstPath);
#endif
    return status;
}
#elif (defined(__RTOS_ZEPHYR__) || (defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)))
extern MSTATUS
UTILS_copyFile(const char* pSrcFilename, const char* pDestFilename, ubyte4 dataLength)
{
    MSTATUS status = OK;
    ubyte* pBuf = NULL;
    ubyte4 bufLen;

    if ( (NULL == pSrcFilename) || (NULL == pSrcFilename))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if(OK > (status = UTILS_readFile(pSrcFilename, &pBuf, &bufLen)))
        goto exit;

    if ((dataLength != 0) && (bufLen > dataLength))
        bufLen = dataLength;

    if(OK > (status = UTILS_writeFile(pDestFilename, pBuf, bufLen)))
        goto exit;

exit:
    if(pBuf)
        MOC_FREE((void **)&pBuf);
    return status;

}
#else
extern MSTATUS
UTILS_copyFile(const char* pSrcFilename, const char* pDestFilename, ubyte4 bufLength)
{
#if defined(__ENABLE_MOCANA_RTOS_FILEX__)
	FX_FILE finFile = { 0 };
	FX_FILE *fin = NULL;
	FX_FILE foutFile = { 0 };
	FX_FILE *fout = NULL;
#else
#ifndef __RTOS_WTOS__
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    struct stat st = { 0 };
#endif
    FILE*   fin = NULL;
    FILE*   fout = NULL;
#else
    int     fin = -1;
    int     fout = -1;
#endif
#endif
    MSTATUS status = OK;
    char *myBuf = NULL;
#if defined(__ENABLE_MOCANA_RTOS_FILEX__)
    ULONG nread = 0;
#elif defined(__QNX_RTOS__) || defined(__RTOS_ZEPHYR__)
    sbyte4 nread = 0;
#else
    ssize_t nread = 0;
#endif
    ubyte *pSrcPath = NULL;
    ubyte *pDstPath = NULL;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freeSrcPath = FALSE;
    intBoolean freeDstPath = FALSE;
#endif

    if ( (0 == bufLength) || (NULL == pSrcFilename) || (NULL == pDestFilename))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pSrcPath = (ubyte *) pSrcFilename;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (pSrcFilename, (sbyte **) &pSrcPath, TRUE);
        if (OK > status)
            goto exit;

        freeSrcPath = TRUE;
    }

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (MOC_STRNCMP(pSrcPath, MANDATORY_BASE_PATH, MOC_STRLEN(MANDATORY_BASE_PATH)) != 0)
    {
        /* File path must start with the mandatory base path */
        status = ERR_FILE_INSECURE_PATH;
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_SECURE_PATH__ */
#endif

#if defined(__ENABLE_MOCANA_RTOS_FILEX__)
    status = fx_file_open(gp_fx_media0, &finFile, (CHAR *) pSrcPath, FX_OPEN_FOR_READ);
    if (FX_SUCCESS != status)
#else
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (lstat(pSrcPath, &st) != 0)
    {
        status = ERR_FILE_NOT_EXIST;
        goto exit;
    }

    if (!S_ISREG(st.st_mode))
    {
        status = ERR_FILE_BAD_TYPE;
        goto exit;
    }
#endif

    fin = fopen((const char* __restrict)pSrcPath, "rb");
#ifndef __RTOS_WTOS__
    if (NULL == fin)
#else
    if (fin < 0)
#endif
#endif
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }
#if defined(__ENABLE_MOCANA_RTOS_FILEX__)
    fin = &finFile;
    fx_file_seek(fin, 0UL);
#endif

    pDstPath = (ubyte *) pDestFilename;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (pDestFilename, (sbyte **) &pDstPath, TRUE);
        if (OK > status)
            goto exit;

        freeDstPath = TRUE;
    }

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (MOC_STRNCMP(pDstPath, MANDATORY_BASE_PATH, MOC_STRLEN(MANDATORY_BASE_PATH)) != 0)
    {
        /* File path must start with the mandatory base path */
        status = ERR_FILE_INSECURE_PATH;
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_SECURE_PATH__ */
#endif
#if defined(__ENABLE_MOCANA_RTOS_FILEX__)
    status = fx_file_create(gp_fx_media0, (CHAR *) pDstPath);
    if (FX_ALREADY_CREATED != status && FX_SUCCESS != status)
    {
    	status = ERR_FILE_CREATE_FAILED;
    	goto exit;
    }
    status = fx_file_open(gp_fx_media0, &foutFile, (CHAR *) pDstPath, FX_OPEN_FOR_WRITE);
    if (FX_SUCCESS != status)
#else
    fout = fopen((const char* __restrict)pDstPath, "wb");
#ifndef __RTOS_WTOS__
    if (NULL == fout )
#else
    if (fout < 0)
#endif
#endif
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }
#if defined(__ENABLE_MOCANA_RTOS_FILEX__)
    fout = &foutFile;
    fx_file_truncate(fout, 0);
#endif

    status = MOC_MALLOC((void **)&myBuf,bufLength);
    if (OK != status)
    {
        goto exit;
    }

#if defined(__ENABLE_MOCANA_RTOS_FILEX__)
    while ((FX_SUCCESS == (status = fx_file_read(fin, myBuf, bufLength, &nread))) && (nread > 0))
#else
    while (nread = fread(myBuf, 1, bufLength, fin), nread > 0)
#endif
    {
        char *out_ptr = myBuf;
#if defined(__QNX_RTOS__) || defined(__RTOS_ZEPHYR__)
        sbyte4 nwritten;
#else
        ssize_t nwritten;
#endif

        do {
#if defined(__ENABLE_MOCANA_RTOS_FILEX__)
        	status = fx_file_write(fout, myBuf, nread);
        	if (FX_SUCCESS != status)
        	{
        		status = ERR_FILE_WRITE_FAILED;
        		goto exit;
        	}
        	nwritten = nread;
#else
            nwritten = fwrite(out_ptr, 1, nread, fout);
#endif

            if (nwritten >= 0)
            {
                nread -= nwritten;
                out_ptr += nwritten;
            }
#ifdef EINTR
            else if (errno != EINTR)
#else
            else
#endif
            {
                status = ERR_FILE_WRITE_FAILED;
                goto exit;
            }
        } while (nread > 0);
    }

    if (0 == nread)
    {
#if defined(__ENABLE_MOCANA_RTOS_FILEX__)
    	fx_file_close(fin);
    	fin = NULL;
    	fx_file_close(fout);
    	fout = NULL;
#else
        if (fclose(fout) < 0)
        {
#ifndef __RTOS_WTOS__
            fout = NULL;
#else
            fout = -1;
#endif
            status = ERR_FILE_CLOSE_FAILED;
            goto exit;
        }
        fclose(fin);
        /* I really care about the fclose(fout), but not the
         * result of fclose(fin) when deciding on a successful copy. */
#ifndef __RTOS_WTOS__
        fout = NULL;
        fin = NULL;
#else
        fout = -1;
        fin = -1;
#endif
#endif
        /* Success! */
        status = OK;
    }
    else
    {
        status = ERR_FILE_READ_FAILED;
    }

exit:
#if defined(__ENABLE_MOCANA_RTOS_FILEX__)
	if (NULL != fout)
	{
		fx_file_close(fout);
	}
	if (NULL != fin)
	{
		fx_file_close(fin);
	}
#else
#ifndef __RTOS_WTOS__
    if (fout != NULL)
#else
    if (fout >= 0)
#endif
    {
        fclose(fout);
    }

#ifndef __RTOS_WTOS__
    if (fin != NULL)
#else
    if (fin >= 0)
#endif
    {
        fclose(fin);
    }
#endif
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freeSrcPath)
        MOC_FREE((void **) &pSrcPath);
    if (TRUE == freeDstPath)
        MOC_FREE((void **) &pDstPath);
#endif

    MOC_FREE((void **)&myBuf);

    return status;
}
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
UTILS_initReadFile(UTILS_FILE_STREAM_CTX *pCtx, const char *pFilename)
{
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    FIL file ;
    FIL *pFile = &file;
    FRESULT error = 0;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    FX_FILE new_file = {0};
    FX_FILE *pFile = &new_file;
#elif !defined(__RTOS_WTOS__)
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    struct stat st = { 0 };
#endif
    FILE*   pFile = NULL;
#else
    int     pFile;
#endif
    ubyte *pFPath = NULL;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    MSTATUS status = OK;
    sbyte4  fileSize = 0;

    if (NULL == pCtx || NULL == pFilename)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx->pFileStream = NULL;

    pFPath = (ubyte *) pFilename;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (pFilename, (sbyte **) &pFPath, TRUE);
        if (OK > status)
            goto exit;

        freePath = TRUE;
    }

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (MOC_STRNCMP(pFPath, MANDATORY_BASE_PATH, MOC_STRLEN(MANDATORY_BASE_PATH)) != 0)
    {
        /* File path must start with the mandatory base path */
        status = ERR_FILE_INSECURE_PATH;
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_SECURE_PATH__ */
#endif

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    error = f_open(pFile, pFPath, (FA_READ | FA_OPEN_EXISTING));
    if(error)
        pFile = NULL ;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    status = fx_file_open(gp_fx_media0, pFile, pFPath, (FX_OPEN_FOR_READ));
    if(FX_SUCCESS != status)
    {
        pFile = NULL ;
    }
#else
#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (lstat(pFPath, &st) != 0)
    {
        status = ERR_FILE_NOT_EXIST;
        goto exit;
    }

    if (!S_ISREG(st.st_mode))
    {
        status = ERR_FILE_BAD_TYPE;
        goto exit;
    }
#endif

    pFile = fopen((const char* __restrict)pFPath, "rb");
#endif

#ifndef __RTOS_WTOS__
    if (!pFile)
#else
    if (pFile < 0)
#endif
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    /* Get the file size and reset the file back to the beginning */

#if defined (__ENABLE_MOCANA_RTOS_FILEX__)
    fileSize = pFile->fx_file_current_file_size ;
#elif defined (__FREERTOS_RTOS__)&& !defined(__ENABLE_MOCANA_NANOPNAC__)
    fileSize = f_size(pFile) ;
#else
    /* determine size */
    if (OK > fseek(pFile, 0, MSEEK_END))
    {
        status = ERR_FILE_SEEK_FAILED;
        goto exit;
    }

    fileSize = (sbyte4)ftell(pFile);
#endif

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    f_rewind(pFile) ;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    if(FX_SUCCESS != fx_file_seek(pFile, 0UL))
    {
        status = ERR_FILE_SEEK_FAILED;
        goto exit;

    }
#elif !defined(__RTOS_WINCE__) && !defined(__RTOS_MQX__)
    rewind(pFile);
#else
    if (OK > fseek(pFile, 0L, MSEEK_SET))
    {
        status = ERR_FILE_SEEK_FAILED;
        goto exit;
    }
#endif

    pCtx->fileSize = (ubyte4) fileSize;
    pCtx->bytesRead = 0;
    pCtx->pFileStream = (void *)pFile;
    pFile = NULL;

exit:
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        MOC_FREE ((void **) &pFPath);
#endif

    if (NULL != pFile)
    {
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
        (void) f_close(pFile);
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
        fx_file_close(pFile);
        fx_media_flush(gp_fx_media0);
#else
        (void) fclose(pFile);
#endif
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
UTILS_initWriteFile(UTILS_FILE_STREAM_CTX *pCtx, const char *pFilename)
{
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    FIL file ;
    FIL *pFile = &file;
    FRESULT error = 0;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    FX_FILE new_file = {0};
    FX_FILE *pFile = &new_file;
#elif !defined(__RTOS_WTOS__)
    FILE*   pFile;
#else
    int     pFile;
#endif
    ubyte *pFPath = NULL;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    MSTATUS status = OK;

    if (NULL == pCtx || NULL == pFilename)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx->pFileStream = NULL;

    pFPath = (ubyte *) pFilename;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (pFilename, (sbyte **) &pFPath, TRUE);
        if (OK > status)
            goto exit;

        freePath = TRUE;
    }

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (MOC_STRNCMP(pFPath, MANDATORY_BASE_PATH, MOC_STRLEN(MANDATORY_BASE_PATH)) != 0)
    {
        /* File path must start with the mandatory base path */
        status = ERR_FILE_INSECURE_PATH;
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_SECURE_PATH__ */
#endif

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    error = f_open(pFile,  pFPath, (FA_WRITE | FA_CREATE_ALWAYS));
    if(error)
        pFile = NULL ;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    fx_file_create(gp_fx_media0, pFilename);
    if(FX_SUCCESS != fx_file_open(gp_fx_media0, pFile, pFPath, (FX_OPEN_FOR_WRITE)))
    {
        pFile = NULL ;
    }
    else
    {
        fx_file_truncate(pFile, 0);
    }
#elif defined (__ENABLE_DIGICERT_POSIX_SUPPORT__)
    int fd = open((const char* __restrict)pFPath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd >= 0)
    {
        pFile = fdopen(fd, "wb");
        if (NULL == pFile)
        {
            close(fd);
        }
    }
    else
    {
        pFile = NULL;
    }
#else
    pFile = fopen((const char *)pFPath, "wb");
#endif

#ifndef __RTOS_WTOS__
    if (!pFile)
#else
    if (pFile < 0)
#endif
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    pCtx->pFileStream = (void *) pFile;
    pCtx->fileSize = 0; /* unused */
    pCtx->bytesRead = 0; /* unused */
    pFile = NULL;

exit:
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        MOC_FREE ((void **) &pFPath);
#endif

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
UTILS_updateReadFile(UTILS_FILE_STREAM_CTX *pCtx, ubyte *pBuffer, ubyte4 bufferLen, ubyte4 *pBytesRead, byteBoolean *pDone)
{
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    FIL *pFile = 0;
    FRESULT error = 0;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    FX_FILE *pFile = 0;
#elif !defined( __RTOS_WTOS__)
    FILE*   pFile = 0;
#else
    int     pFile = 0;
#endif
    sbyte4  bytesToRead = 0;
    sbyte4  bytesRead = 0;
    MSTATUS status = OK;

    if ( NULL == pCtx || NULL == pBuffer || NULL == pBytesRead || NULL == pDone || NULL == pCtx->pFileStream )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pBytesRead = 0;
    *pDone = FALSE;

    if (pCtx->bytesRead >= pCtx->fileSize)
    {
        *pDone = TRUE;
        goto exit;
    }
    else
    {
        if (bufferLen < pCtx->fileSize - pCtx->bytesRead)
        {
            bytesToRead = (sbyte4) bufferLen;
        }
        else
        {
            bytesToRead = (sbyte4) (pCtx->fileSize - pCtx->bytesRead);
        }
    }

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    pFile = (FIL*) pCtx->pFileStream;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    pFile = (FX_FILE *) pCtx->pFileStream;
#elif !defined( __RTOS_WTOS__)
    pFile = (FILE *) pCtx->pFileStream;
#else
    pFile = (int) pCtx->pFileStream;
#endif

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    error = f_read(pFile, pBuffer, bytesToRead, &bytesRead);
    if (error || bytesToRead != bytesRead)
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    status = (MSTATUS) fx_file_read(pFile, pBuffer, bytesToRead, &bytesRead);
    if(bytesRead < bytesToRead )
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }
#else
    bytesRead = (sbyte4) fread(pBuffer, 1, bytesToRead, pFile);
    if(bytesRead < bytesToRead )
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }
#endif

    pCtx->bytesRead += (ubyte4) bytesRead;
    if (pCtx->bytesRead >= pCtx->fileSize)
        *pDone = TRUE;

    *pBytesRead = (ubyte4) bytesRead;

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
UTILS_updateWriteFile(UTILS_FILE_STREAM_CTX *pCtx, ubyte *pBuffer, ubyte4 bufferLen)
{

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    FIL *pFile = 0;
    FRESULT error = 0;
    ubyte4 bytesWritten = 0;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    FX_FILE *pFile = 0;
#elif !defined( __RTOS_WTOS__)
    FILE*   pFile = 0;
#else
    int     pFile = 0;
#endif
    MSTATUS status = OK;

    if (NULL == pCtx || NULL == pBuffer || NULL == pCtx->pFileStream)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pCtx->fileSize)
    {
        /* context was initialized for read, not for writing! */
        status = ERR_INVALID_INPUT;
        goto exit;
    }

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    pFile = (FIL*) pCtx->pFileStream;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    pFile = (FX_FILE *) pCtx->pFileStream;
#elif !defined( __RTOS_WTOS__)
    pFile = (FILE *) pCtx->pFileStream;
#else
    pFile = (int) pCtx->pFileStream;
#endif

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    error = f_write(pFile, pBuffer, bufferLen, &bytesWritten);
    if ((error) || (bytesWritten != bufferLen))
    {
        status = ERR_FILE_WRITE_FAILED;
    }
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    if(FX_SUCCESS != fx_file_write(pFile, pBuffer, bufferLen))
        status = ERR_FILE_WRITE_FAILED;
#else
    if (bufferLen != (fwrite(pBuffer, 1, bufferLen, pFile)))
        status = ERR_FILE_WRITE_FAILED;
#endif

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
UTILS_closeFile(UTILS_FILE_STREAM_CTX *pCtx)
{

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    FIL *pFile = 0;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    FX_FILE *pFile = 0;
#elif !defined( __RTOS_WTOS__)
    FILE*   pFile = 0;
#else
    int     pFile = 0;
#endif
    MSTATUS status = OK;

    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pCtx->pFileStream)
        goto exit;  /* status OK, nothing to close */

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    pFile = (FIL*) pCtx->pFileStream;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    pFile = (FX_FILE *) pCtx->pFileStream;
#elif !defined( __RTOS_WTOS__)
    pFile = (FILE *) pCtx->pFileStream;
#else
    pFile = (int) pCtx->pFileStream;
#endif

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    (void) f_close(pFile);
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    fx_file_close(pFile);
    fx_media_flush(gp_fx_media0);
#else
    (void) fclose(pFile);
#endif

    pCtx->fileSize = 0;
    pCtx->bytesRead = 0;

exit:

    return status;
}

/*------------------------------------------------------------------*/

#if defined(__RTOS_ZEPHYR__)
extern MSTATUS
UTILS_deleteFile(const char *pFilename)
{
    return FMGMT_remove(pFilename, TRUE);
}
#else
extern MSTATUS
UTILS_deleteFile(const char *pFilename)
{
    MSTATUS status = OK;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif
    ubyte *pFPath = (ubyte *) pFilename;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (pFilename, (sbyte **) &pFPath, TRUE);
        if (OK > status)
            return status;

        freePath = TRUE;
    }
#endif

#if !defined(__ENABLE_MOCANA_RTOS_FILEX__)
#if defined(__RTOS_FREERTOS__)
    status = f_unlink(pFPath);
#else
    status = remove((const char*)pFPath);
#endif
#else
    UINT ret;
    ret = fx_file_delete(gp_fx_media0, (CHAR *) pFPath);
    if (FX_NOT_A_FILE == ret)
    {
    	ret = fx_directory_delete(gp_fx_media0, (CHAR *) pFPath);
    }
    if (FX_SUCCESS != ret)
    {
    	status = ERR_FILE;
    }
#endif

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == freePath)
        MOC_FREE ((void **) &pFPath);
#endif
    return status;
}
#endif

/*------------------------------------------------------------------*/
#ifndef __ENABLE_MOCANA_NANOPNAC__	/* NanoPNAC doesn;t requires File system build*/
#if defined(__RTOS_ZEPHYR__)
extern MSTATUS
UTILS_checkFile(const char *pFileName, const char *pExt, intBoolean *pFileExist)
{
    MSTATUS status = OK;
    sbyte *pFileNameExt = NULL;
    ubyte *pFPath = NULL;

    if ( (NULL == pFileName) || (NULL == pFileExist) )
    {
        status =  ERR_NULL_POINTER;
        goto exit;
    }

    pFPath = (ubyte *) pFileName;
    if (NULL != pExt)
    {
        status = MOC_CALLOC(
            (void **) &pFileNameExt, 1, MOC_STRLEN((const sbyte *) pFileName) + MOC_STRLEN((const sbyte *) pExt) + 1);
        if (OK != status)
        {
            goto exit;
        }

        status = MOC_MEMCPY(pFileNameExt, pFileName, MOC_STRLEN((const sbyte *) pFileName));
        if (OK != status)
        {
            goto exit;
        }

        status = MOC_MEMCPY(
            pFileNameExt + MOC_STRLEN((const sbyte *) pFileName), pExt, MOC_STRLEN((const sbyte *) pExt));
        if (OK != status)
        {
            goto exit;
        }

        pFPath = (ubyte *) pFileNameExt;
    }

    *pFileExist = FALSE;
    if (TRUE == FMGMT_pathExists(pFileNameExt, NULL))
    {
        *pFileExist = TRUE;
    }
exit:
    if (NULL != pFileNameExt)
    {
        MOC_FREE((void **) &pFileNameExt);
    }

    return status;
}
#else
extern MSTATUS
UTILS_checkFile(const char *pFileName, const char *pExt, intBoolean *pFileExist)
{
    MSTATUS status = OK;
    ubyte4 exist;
    sbyte *pFileNameExt = NULL;
    ubyte *pFPath = NULL;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    intBoolean freePath = FALSE;
#endif

    if ( (NULL == pFileName) || (NULL == pFileExist) )
    {
        status =  ERR_NULL_POINTER;
        goto exit;
    }

    pFPath = (ubyte *) pFileName;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (pFileName, (sbyte **) &pFPath, TRUE);
        if (OK > status)
            goto exit;

        freePath = TRUE;
    }
#endif

    if (NULL != pExt)
    {
        status = MOC_CALLOC(
            (void **) &pFileNameExt, 1, MOC_STRLEN((const sbyte *) pFPath) + MOC_STRLEN((const sbyte *) pExt) + 1);
        if (OK != status)
        {
            goto exit;
        }

        status = MOC_MEMCPY(pFileNameExt, pFPath, MOC_STRLEN((const sbyte *) pFPath));
        if (OK != status)
        {
            goto exit;
        }

        status = MOC_MEMCPY(
            pFileNameExt + MOC_STRLEN((const sbyte *) pFPath), pExt, MOC_STRLEN((const sbyte *) pExt));
        if (OK != status)
        {
            goto exit;
        }

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
        if (TRUE == freePath)
            MOC_FREE ((void **) &pFPath);
#endif
        pFPath = (ubyte *) pFileNameExt;

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
        /* avoid double free of pFileNameExt */
        freePath = FALSE;
#endif
    }

#ifdef __RTOS_FREERTOS__
    FILINFO  buffer = {0};
#elif defined(__ENABLE_MOCANA_RTOS_FILEX__)
    UINT attrs = 0;
    UINT ret;
#else
    struct stat buffer;
#endif
    *pFileExist = FALSE;

#ifdef __RTOS_FREERTOS__
    exist = f_stat( (const char*)pFPath, &buffer);
#elif defined(__ENABLE_MOCANA_RTOS_FILEX__)
    ret = fx_file_attributes_read(gp_fx_media0, (CHAR *) pFPath, &attrs);
    switch (ret)
    {
    	case FX_SUCCESS:
    	case FX_NOT_A_FILE:
    		exist = 0;
    		break;
    	case FX_NOT_FOUND:
    		exist = 1;
    		break;
    	default:
    		status = ERR_FILE_EXISTS;
    		goto exit;
    }
#else
    exist = stat( (const char*)pFPath, &buffer);
#endif
    if( 0 == exist)
    {
        *pFileExist = TRUE;
    }

exit:
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
        if (TRUE == freePath)
            MOC_FREE ((void **) &pFPath);
#endif

    if (NULL != pFileNameExt)
    {
        MOC_FREE((void **) &pFileNameExt);
    }

    return status;
}
#endif /* __RTOS_ZEPHYR__ */
#endif
#endif /* __DISABLE_MOCANA_FILE_SYSTEM_HELPER__ */
