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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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

/*------------------------------------------------------------------*/

extern MSTATUS
UTILS_readFileRaw(const ubyte* pFileObj, ubyte **ppRetBuffer, ubyte4 *pRetBufLength)
{
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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

#if defined (__ENABLE_MOCANA_RTOS_FILEX__)
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
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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

#if defined _MSC_VER
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

extern MSTATUS
UTILS_readFile(const char* pFilename,
               ubyte **ppRetBuffer, ubyte4 *pRetBufLength)
{
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    FIL file ;
    FIL *f = &file;
    FRESULT error = 0;
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

    /* check input */
    if ((NULL == pFilename) || (NULL == ppRetBuffer) || (NULL == pRetBufLength))
    {
        status = ERR_NULL_POINTER;
        goto nocleanup;
    }

    *ppRetBuffer   = NULL;
    *pRetBufLength = 0;

    pFPath = (ubyte *) pFilename;
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
    if (TRUE == FMGMT_needFullPath ())
    {
        status = FMGMT_getFullPathAllocAux (pFilename, (sbyte **) &pFPath, TRUE);
        if (OK > status)
            goto nocleanup;

        freePath = TRUE;
    }
#endif

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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
        goto nocleanup;
    }

    /* Read the Raw File */
    status = UTILS_readFileRaw((ubyte*)f, ppRetBuffer, pRetBufLength);

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
        (void) f_close(f);
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    fx_file_close(f);
#else
    (void) fclose(f);
#endif

nocleanup:
    return status;

} /* UTILS_readFile */


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
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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
#endif

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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
#else
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

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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

extern MSTATUS
UTILS_appendFile(const char* pFilename,
                const ubyte *pBuffer, ubyte4 bufLength)
{
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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
#endif

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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
    int fd = open((const char* __restrict)pFPath, O_CREAT| O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR);
    if (fd >= 0)
    {
        f = fdopen(fd, "ab");
        if (NULL == f)
        {
            close(fd);
        }
    }
    else
    {
        f = NULL;
    }
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

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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
#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
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
#elif defined(__QNX_RTOS__)
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
#endif

#if defined(__ENABLE_MOCANA_RTOS_FILEX__)
    status = fx_file_open(gp_fx_media0, &finFile, (CHAR *) pSrcPath, FX_OPEN_FOR_READ);
    if (FX_SUCCESS != status)
#else
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
    int fd = open((const char* __restrict)pDstPath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd >= 0)
    {
        fout = fdopen(fd, "wb");
        if (NULL == fout)
        {
            close(fd);
        }
    }
    else
    {
        fout = NULL;
    }
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
#ifdef __QNX_RTOS__
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
    MSTATUS status = OK;

    if (NULL == pCtx || NULL == pFilename)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx->pFileStream = NULL;

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_MOCANA_NANOPNAC__)
    error = f_open(pFile, pFilename, (FA_WRITE | FA_CREATE_ALWAYS));
    if(error)
        pFile = NULL ;
#elif defined (__ENABLE_MOCANA_RTOS_FILEX__)
    fx_file_create(gp_fx_media0, pFilename);
    if(FX_SUCCESS != fx_file_open(gp_fx_media0, pFile, pFilename, (FX_OPEN_FOR_WRITE)))
    {
        pFile = NULL ;
    }
    else
    {
        fx_file_truncate(pFile, 0);
    }
#else
    int fd = open((const char* __restrict)pFilename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
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

/*------------------------------------------------------------------*/
#ifndef __ENABLE_MOCANA_NANOPNAC__	/* NanoPNAC doesn;t requires File system build*/
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
            goto exit;;

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
#endif
#endif /* __DISABLE_MOCANA_FILE_SYSTEM_HELPER__ */
