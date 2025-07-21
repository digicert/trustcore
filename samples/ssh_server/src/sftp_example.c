/*
 * sftp_example.c
 *
 * SSH File Transfer Protocol Example Callback Code
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

/* Add to your makefile */
#include "common/moptions.h"

#if ((defined(__ENABLE_MOCANA_SSH_SERVER_EXAMPLE__) || defined(__ENABLE_MOCANA_SSH_ASYNC_SERVER_API__)) && defined(__ENABLE_MOCANA_SSH_FTP_SERVER__))
#include "common/mtypes.h"
#include "common/mocana.h"
#include "crypto/hw_accel.h"

#include "common/mdefs.h"
#include "common/merrors.h"
#include "common/mstdlib.h"
#include "common/mrtos.h"
#include "common/vlong.h"
#include "common/mfmgmt.h"

#include "ssh/ssh_filesys.h"
#include "ssh/sftp.h"


#ifdef __RTOS_WIN32__
#ifdef CR
#undef CR
#endif
#include <windows.h>
#include <winbase.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <errno.h>
#endif

#ifdef __RTOS_VXWORKS__
#include <vxWorks.h>
#include <dirent.h>
#endif

#ifdef __RTOS_LINUX__
#include <dirent.h>
#endif

#if defined( __RTOS_OSX__) || defined(__RTOS_OPENBSD__)
#include <dirent.h>
#endif

#ifdef __RTOS_CYGWIN__
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#endif

#ifdef __RTOS_SOLARIS__
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#endif

#ifdef __RTOS_QNX__
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#endif

#ifdef __RTOS_OSE__
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#endif

#include <stdio.h>
#include <string.h>
/*#include <stdlib.h>*/

/*------------------------------------------------------------------*/

static sbyte *
createPathName(const sbyte *pLongPath, sbyte *pFilename)
{
    sbyte*  pFullPath = NULL;
    sbyte4  longLength;
    sbyte4  nameLength;

    /* example function, which combines the path and file name */
    if ((NULL == pLongPath) || (0 == (longLength = MOC_STRLEN((const sbyte *)pLongPath))))
        longLength = 0;

    if ((NULL == pFilename) || (0 == (nameLength = MOC_STRLEN((const sbyte *)pFilename))))
        nameLength = 0;

    if (NULL == (pFullPath = malloc(1 + longLength + 1 + nameLength + 1)))
        return pFullPath;

    if (longLength)
    {
        /* note: for your file system you may want to prepend some other data here */
        pFullPath[0] = '.';

        memcpy(1 + pFullPath, pLongPath, longLength);

        longLength++;
    }

    if (nameLength)
    {
        if(longLength)
        {
            if ('/' != pLongPath[longLength - 1])
            {
                longLength++;
                pFullPath[longLength - 1] = '/';
            }
        }
        memcpy(longLength + pFullPath, pFilename, nameLength);
    }

    pFullPath[longLength + nameLength] = '\0';

    return pFullPath;
}


/*------------------------------------------------------------------*/

/* this example code assumes support for POSIX */

static sbyte4
SFTP_EXAMPLE_openUpcall(sbyte4 connectionInstance, void* sftpInternelDescr,
                        sbyte *pLongPath, sbyte *pFilename, sbyte4 flags)
{
    FileDescriptor fd = 0;
    sbyte*  pFileFlags;
    sbyte*  pFullPath = NULL;
    sbyte4  status = SSH_FTP_OK;
    MOC_UNUSED(connectionInstance);

    /* setup fopen file flag string */
    if (flags & SFTP_OPEN_FILE_READ_BINARY)
        pFileFlags = (sbyte *)"rb";
    else if (flags & SFTP_OPEN_FILE_WRITE_BINARY)
        pFileFlags = (sbyte *)"wb";
    else
    {
        status = SSH_FTP_PERMISSION_DENIED;
        goto exit;
    }

    /* open the file handle */
    if (NULL == (pFullPath = createPathName(pLongPath, pFilename)))
    {
        status = SSH_FTP_FAILURE;
        goto exit;
    }

    status = FMGMT_fopen (pFullPath, pFileFlags, &fd);
    if (OK != status)
    {
        status = SSH_FTP_FAILURE;
        goto exit;
    }

    SSH_sftpSetCookie(sftpInternelDescr, (void*) fd);

    printf("SFTP_EXAMPLE_openUpcall: open (%s), mode = (%s)\n", pFullPath, pFileFlags);

exit:
    if (NULL != pFullPath)
        free(pFullPath);

    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_readUpcall(sbyte4 connectionInstance, void* sftpInternelDescr)
{
    FileDescriptor   fd = (FileDescriptor) SSH_sftpGetCookie(sftpInternelDescr);
    sbyte*  pBuffer;
    sbyte4  bufferSize;
    sbyte4  numBytesRead;
    sbyte4  fileSize;
    sbyte4  status = SSH_FTP_OK;
    MOC_UNUSED(connectionInstance);

    /* determine size */
    status = FMGMT_fseek (fd, 0, MSEEK_END);
    if (OK != status)
    {
        status = SSH_FTP_FAILURE;
        goto exit;
    }

    status = FMGMT_ftell (fd, (ubyte4 *) &fileSize);
    if (OK != status)
    {
        status = SSH_FTP_FAILURE;
        goto exit;
    }

    if ((0 == fileSize) || (SSH_sftpReadLocation(sftpInternelDescr) >= fileSize))
    {
        /* end of file reached */
        status = SSH_FTP_EOF;
        goto exit;
    }

    /* set the position to read from */
    status = FMGMT_fseek (fd, SSH_sftpReadLocation(sftpInternelDescr), MSEEK_SET);
    if (OK != status)
    {
        status = SSH_FTP_FAILURE;
        goto exit;
    }

    /* fetch the buffer, and max bytes that can be sent at the moment */
    pBuffer    = SSH_sftpReadBuffer(sftpInternelDescr);
    bufferSize = SSH_sftpReadBufferSize(sftpInternelDescr);

    /* check if enough bytes have been read */
    status = FMGMT_fread ((ubyte *) pBuffer, 1, bufferSize, fd, (ubyte4 *) &numBytesRead);
    if (OK != status)
    {
        status = SSH_FTP_FAILURE;
        goto exit;
    }

    /* end of file reached */
    if (0 == numBytesRead)
        status = SSH_FTP_EOF;

    /* set the number of bytes waiting to be sent */
    SSH_sftpNumBytesRead(sftpInternelDescr, numBytesRead);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_writeUpcall(sbyte4 connectionInstance, void* sftpInternelDescr)
{
    FileDescriptor   fd = (FileDescriptor)SSH_sftpGetCookie(sftpInternelDescr);
    sbyte*  pBuffer;
    sbyte4  bufferSize;
    sbyte4  numBytesWritten;
    sbyte4  status = SSH_FTP_OK;
    MOC_UNUSED(connectionInstance);

    /* set the position to write from */
    status = FMGMT_fseek (fd, SSH_sftpWriteLocation(sftpInternelDescr), MSEEK_SET);
    if (OK != status)
    {
        status = SSH_FTP_FAILURE;
        goto exit;
    }

    /* fetch the buffer, and max bytes that can be sent at the moment */
    pBuffer    = SSH_sftpWriteBuffer(sftpInternelDescr);
    bufferSize = SSH_sftpWriteBufferSize(sftpInternelDescr);

    /* write the bytes  */
    status = FMGMT_fwrite ((ubyte *)pBuffer, 1, bufferSize, fd, (ubyte4 *) &numBytesWritten);
    if (OK != status)
    {
        status = SSH_FTP_FAILURE;
        goto exit;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_closeUpcall(sbyte4 connectionInstance, void* sftpInternelDescr)
{
    FileDescriptor pFileCtx = (FileDescriptor) SSH_sftpGetCookie(sftpInternelDescr);
    FMGMT_fclose ((FileDescriptor *) &pFileCtx);
    MOC_UNUSED(connectionInstance);

    return SSH_FTP_OK;
}


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_getOpenFileStats(sbyte4 connectionInstance,
                              sbyte4 cookie,
                              sftpFileObjDescr* p_sftpFileDescr)
{
    sbyte4  result   = SSH_FTP_OK; /* SSH_FTP_OP_UNSUPPORTED; */
    sbyte4  fileSize = 0;
    sbyte4  accessTime;
    sbyte4  createTime;
    sbyte4  modifyTime;
    sbyte4  isRead  = SFTP_TRUE;
    sbyte4  isWrite = SFTP_TRUE;
    sbyte4  isDirectory = SFTP_FALSE;
    MOC_UNUSED(connectionInstance);

    accessTime = createTime = modifyTime = 0;       /* default file dates to Jan 1, 1970 */

    /* open the file handle */
    {
#ifdef __RTOS_WIN32__
        struct _stat statResults;

        if (0 == _fstat(fileno((FILE *)cookie), &statResults))
        {
            accessTime  = statResults.st_atime;
            createTime  = statResults.st_ctime;
            modifyTime  = statResults.st_mtime;
            fileSize    = statResults.st_size;
            isDirectory = (statResults.st_mode & _S_IFDIR) ? SFTP_TRUE : SFTP_FALSE;
            result      = SSH_FTP_OK;

            if (0 == (statResults.st_mode & _S_IWRITE))
                isWrite = SFTP_FALSE;

        }
#endif
    }

    /* the caller has already filled in the other fields */
    /* (e.g. fileName, fileNameLength, and memberOfDirectory) */
    p_sftpFileDescr->isReadable       = isRead;
    p_sftpFileDescr->isWriteable      = isWrite;
    p_sftpFileDescr->readAccessGroup  = 0;
    p_sftpFileDescr->writeAccessGroup = 0;
    p_sftpFileDescr->fileSize         = fileSize;
    p_sftpFileDescr->isDirectory      = isDirectory;

    p_sftpFileDescr->fileAccessTime   = accessTime;
    p_sftpFileDescr->fileCreationTime = createTime;
    p_sftpFileDescr->fileModifyTime   = modifyTime;

    return result;
}


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_getFileStats(sbyte4 connectionInstance,
                          ubyte *pPath,
                          ubyte *pPathExt,
                          sftpFileObjDescr* p_sftpFileDescr)
{
    sbyte4  result   = SSH_FTP_NO_SUCH_FILE;
    sbyte4  fileSize = 0;
    sbyte4  accessTime;
    sbyte4  createTime;
    sbyte4  modifyTime;
    sbyte4  isRead  = SFTP_TRUE;
    sbyte4  isWrite = SFTP_TRUE;
    sbyte4  isDirectory = SFTP_FALSE;
    sbyte*  pFullPath = NULL;
    FileDescriptorInfo fileInfo;
    MOC_UNUSED(connectionInstance);

    accessTime = createTime = modifyTime = 0;       /* default file dates to Jan 1, 1970 */

    /* open the file handle */
    if (NULL != (pFullPath = createPathName((sbyte *)pPath, (sbyte *)pPathExt)))
    {
        if (TRUE == FMGMT_pathExists (pFullPath, &fileInfo))
        {
            accessTime  = fileInfo.accessTime;
            createTime  = fileInfo.createTime;
            modifyTime  = fileInfo.modifyTime;
            fileSize    = fileInfo.fileSize;
            isDirectory = (FTDirectory == fileInfo.type) ? SFTP_TRUE : SFTP_FALSE;

            isWrite     = (TRUE == fileInfo.isWrite) ? SFTP_TRUE : SFTP_FALSE;
            isRead      = (TRUE == fileInfo.isRead)  ? SFTP_TRUE : SFTP_FALSE;

            result = SSH_FTP_OK;
        }
    }

    /* the caller has already filled in the other fields */
    /* (e.g. fileName, fileNameLength, and memberOfDirectory) */
    p_sftpFileDescr->isReadable       = isRead;
    p_sftpFileDescr->isWriteable      = isWrite;
    p_sftpFileDescr->readAccessGroup  = 0;
    p_sftpFileDescr->writeAccessGroup = 0;
    p_sftpFileDescr->fileSize         = fileSize;
    p_sftpFileDescr->isDirectory      = isDirectory;

    p_sftpFileDescr->fileAccessTime   = accessTime;
    p_sftpFileDescr->fileCreationTime = createTime;
    p_sftpFileDescr->fileModifyTime   = modifyTime;

    if (NULL != pFullPath)
        free(pFullPath);

    return result;
}


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_removeFileUpcall(sbyte4 connectionInstance, sbyte *pPath)
{
    sbyte*  pFullPath = NULL;
    sbyte4  result = SSH_FTP_FAILURE;
    MOC_UNUSED(connectionInstance);

    /* delete a file */
    if (NULL != (pFullPath = createPathName(pPath, NULL)))
        if (OK == FMGMT_remove (pFullPath, FALSE))
            result = SSH_FTP_OK;

    if (NULL != pFullPath)
        free(pFullPath);

    return result;
}


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_renameFileUpcall(sbyte4 connectionInstance,
                              sbyte *pOldFilename, sbyte *pNewFilename)
{
    /* both files should be in the same directory */
    sbyte*  pOldFullPath = NULL;
    sbyte*  pNewFullPath = NULL;
    sbyte4  result = SSH_FTP_FAILURE;
    MOC_UNUSED(connectionInstance);

    /* rename a file */
    if (NULL != (pOldFullPath = createPathName(pOldFilename, NULL)))
        if (NULL != (pNewFullPath = createPathName(pNewFilename, NULL)))
            if (OK == FMGMT_rename (pOldFullPath, pNewFullPath))
                result = SSH_FTP_OK;

    if (NULL != pOldFullPath)
        free(pOldFullPath);

    if (NULL != pNewFullPath)
        free(pNewFullPath);

    return result;
}


/*------------------------------------------------------------------*/

#ifdef __RTOS_WIN32__
/* Windows specific example implementation: Windows is actually one of the more difficult platforms to support */
static sbyte4
SFTP_EXAMPLE_handleOpenDynamicDirectory(sbyte4 connectionInstance, const sbyte *pDirectoryPath, void* *pDirCookie)
{
    MOC_UNUSED(connectionInstance);
    MOC_UNUSED(pDirectoryPath);

    *pDirCookie = (void*)INVALID_HANDLE_VALUE;

    return SSH_FTP_OK;
}


/*------------------------------------------------------------------*/

extern sbyte4
convertTimeToOtherTime(ubyte4 *time,
                       ubyte4 *timeOffset,
                       ubyte4 *timeMultiply,
                       ubyte4 *timeDivisor,
                       ubyte4 *newTime,
                       sbyte4 numUnits)
{
    vlong*  pTime         = NULL;
    vlong*  pTimeOffset   = NULL;
    vlong*  pTimeMultiply = NULL;
    vlong*  pTimeDivisor  = NULL;
    vlong*  pTemp         = NULL;
    vlong*  pVlongQueue   = NULL;
    MSTATUS status;

    /* convert operands to vlongs */
    if (OK > (status = VLONG_vlongFromUByte4String(time, numUnits, &pTime)))
        goto exit;

    if (OK > (status = VLONG_vlongFromUByte4String(timeOffset, numUnits, &pTimeOffset)))
        goto exit;

    if (OK > (status = VLONG_vlongFromUByte4String(timeMultiply, numUnits, &pTimeMultiply)))
        goto exit;

    if (OK > (status = VLONG_vlongFromUByte4String(timeDivisor, numUnits, &pTimeDivisor)))
        goto exit;

    if (FALSE == VLONG_isVlongZero(pTimeMultiply))
    {
        if (OK > (status = VLONG_makeVlongFromVlong(pTime, &pTemp, &pVlongQueue)))
            goto exit;

        if (OK > (status = VLONG_vlongSignedMultiply(pTemp, pTime, pTimeMultiply)))
            goto exit;

        VLONG_freeVlong(&pTime, &pVlongQueue);
        pTime = pTemp; pTemp = NULL;
    }

    if (FALSE == VLONG_isVlongZero(pTimeDivisor))
    {
        if (OK > (status = VLONG_operatorDivideSignedVlongs(pTime, pTimeDivisor, &pTemp, &pVlongQueue)))
            goto exit;

        VLONG_freeVlong(&pTime, &pVlongQueue);
        pTime = pTemp; pTemp = NULL;
    }

    /* adjust time by offset */
    if (OK > (status = VLONG_subtractSignedVlongs(pTime, pTimeOffset, &pVlongQueue)))
        goto exit;

    newTime[0] = pTime->pUnits[0];
    newTime[1] = pTime->pUnits[1];

exit:
    VLONG_freeVlong(&pTime, 0);
    VLONG_freeVlong(&pTimeOffset, 0);
    VLONG_freeVlong(&pTimeMultiply, 0);
    VLONG_freeVlong(&pTimeDivisor, 0);
    VLONG_freeVlong(&pTemp, 0);
    VLONG_freeVlongQueue(&pVlongQueue);

    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_convertLocalTimeToSftpTime(FILETIME *pLocalTime, sftpFileObjDescr* p_sftpFileDescr, sbyte4 index)
{
    /* The FILETIME structure is a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601. */

    /* typedef struct _FILETIME {
     * DWORD dwLowDateTime;
     * DWORD dwHighDateTime;   019DB46C9F163000
     * } FILETIME;
     */
    ubyte4    time[2];
#if 0
    ubyte4    offset[2]   = { 0x019DB1DE, 0xD53E8000 };
    ubyte4    multiply[2] = { 0x00000000, 0x00000000 };
    ubyte4    divisor[2]  = { 0x00000000, 0x00989680 };
#else
    ubyte4    offset[2]   = { 0x00000002, 0xB6109100 };
    ubyte4    multiply[2] = { 0x00000000, 0x00000000 };
    ubyte4    divisor[2]  = { 0x00000000, 0x00989680 };
#endif
    ubyte4    newtime[2];
    MSTATUS         status;

    time[0] = pLocalTime->dwHighDateTime;
    time[1] = pLocalTime->dwLowDateTime;

    if (OK > (status = convertTimeToOtherTime(time, offset, multiply, divisor, newtime, 2)))
        goto exit;

    switch (index)
    {
        case 0:
            p_sftpFileDescr->fileAccessTime   = newtime[0];
            break;

        case 1:
            p_sftpFileDescr->fileCreationTime = newtime[0];
            break;

        case 2:
            p_sftpFileDescr->fileModifyTime   = newtime[0];
            break;

        default:
            break;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_handleReadDynamicDirectory(sbyte4 connectionInstance, sbyte *pLongDirectoryName,
                                        sftpFileObjDescr* p_sftpFileDescr, void* *pDirCookie)
{
    HANDLE          h = (HANDLE)(*pDirCookie);
    WIN32_FIND_DATA fd;
    MOC_UNUSED(connectionInstance);

    if (INVALID_HANDLE_VALUE == h)
    {
        sbyte*   pFullPath = NULL;

        if (NULL != (pFullPath = createPathName(pLongDirectoryName, "*.*")))
        {
#ifdef __RTOS_WIN32__
            if (INVALID_HANDLE_VALUE == (h = FindFirstFile((LPCSTR)pFullPath, &fd)))
#else
			if (INVALID_HANDLE_VALUE == (h = FindFirstFile(pFullPath, &fd)))
#endif
            {
                free(pFullPath);

                return SSH_FTP_FAILURE;
            }

            free(pFullPath);
        }
        else return SSH_FTP_FAILURE;

        *pDirCookie = h;
    }
    else
    {
        if (0 == FindNextFile(h, &fd))
            return SSH_FTP_FAILURE;
    }

    memset(p_sftpFileDescr, 0x00, sizeof(sftpFileObjDescr));

    /* for purposes of this example code, we don't want to return any system or special files */
    while (0 != (fd.dwFileAttributes & (FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ENCRYPTED | FILE_ATTRIBUTE_HIDDEN)))
        if (0 == FindNextFile(h, &fd))
            return SSH_FTP_FAILURE;

    /* copy data --- just care about the file name */
    if ((0 == MOC_STRLEN((const sbyte *)fd.cAlternateFileName)) || (SFTP_MAX_FILENAME_LENGTH > MOC_STRLEN((const sbyte*)fd.cFileName)))
    {
        strncpy((sbyte *)(p_sftpFileDescr->fileName),(const char*) fd.cFileName, SFTP_MAX_FILENAME_LENGTH);
        if (SFTP_MAX_FILENAME_LENGTH =< (p_sftpFileDescr->fileNameLength = MOC_STRLEN((const sbyte*)fd.cFileName)))
        {
            /* if source is equal to or greater than specified limit, no null terminator is appended */
            p_sftpFileDescr->fileName[SFTP_MAX_FILENAME_LENGTH] = '\0';
            p_sftpFileDescr->fileNameLength = SFTP_MAX_FILENAME_LENGTH - 1;
        }
    }
    else
    {
        strncpy((sbyte *)(p_sftpFileDescr->fileName), (const char *)fd.cAlternateFileName, SFTP_MAX_FILENAME_LENGTH);
        if (SFTP_MAX_FILENAME_LENGTH =< (p_sftpFileDescr->fileNameLength = MOC_STRLEN((const sbyte*)fd.cAlternateFileName)))
        {
            /* if source is equal to or greater than specified limit, no null terminator is appended */
            p_sftpFileDescr->fileName[SFTP_MAX_FILENAME_LENGTH] = '\0';
            p_sftpFileDescr->fileNameLength = SFTP_MAX_FILENAME_LENGTH - 1;
        }
    }

    if (SFTP_TRUE == (p_sftpFileDescr->isDirectory = (0 != (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) ? SFTP_TRUE : SFTP_FALSE))
    {
        SFTP_EXAMPLE_convertLocalTimeToSftpTime(&(fd.ftCreationTime),  p_sftpFileDescr, 0);
        SFTP_EXAMPLE_convertLocalTimeToSftpTime(&(fd.ftCreationTime),  p_sftpFileDescr, 1);
        SFTP_EXAMPLE_convertLocalTimeToSftpTime(&(fd.ftCreationTime),  p_sftpFileDescr, 2);
    }
    else
    {
        SFTP_EXAMPLE_convertLocalTimeToSftpTime(&(fd.ftLastAccessTime), p_sftpFileDescr, 0);
        SFTP_EXAMPLE_convertLocalTimeToSftpTime(&(fd.ftCreationTime),   p_sftpFileDescr, 1);
        SFTP_EXAMPLE_convertLocalTimeToSftpTime(&(fd.ftLastWriteTime),  p_sftpFileDescr, 2);
    }

    p_sftpFileDescr->isReadable       = SFTP_TRUE;
    p_sftpFileDescr->isWriteable      = (fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY) ? SFTP_FALSE : SFTP_TRUE;
    p_sftpFileDescr->readAccessGroup  = 0;
    p_sftpFileDescr->writeAccessGroup = 0;
    p_sftpFileDescr->fileSize         = fd.nFileSizeLow;

    return SSH_FTP_OK;
}


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_handleCloseDynamicDirectory(sbyte4 connectionInstance, void **pDirCookie)
{
    HANDLE h = (HANDLE)(*pDirCookie);
    MOC_UNUSED(connectionInstance);

    if (INVALID_HANDLE_VALUE != h)
        FindClose(h);

    return SSH_FTP_OK;
}

#else


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_handleOpenDynamicDirectory(sbyte4 connectionInstance, const sbyte *pLongDirectoryName,
                                        void* *pDirCookie)
{
    sbyte*  pDirPath = NULL;
    sbyte4  result = SSH_FTP_FAILURE;

    if (NULL == (pDirPath = createPathName(pLongDirectoryName, NULL)))
        goto exit;

    printf("SFTP_EXAMPLE_handleOpenDynamicDirectory: dir = (%s)\n", pDirPath);
    free(pDirPath);

    *pDirCookie = NULL;

    result = SSH_FTP_OK;

exit:
    return result;
}


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_handleReadDynamicDirectory(sbyte4 connectionInstance, sbyte *pLongDirectoryName,
                                        sftpFileObjDescr* p_sftpFileDescr, void* *pDirCookie)
{
    MSTATUS status;
    sbyte*  pDirPath = NULL;
    DirectoryDescriptor pDir = (DirectoryDescriptor) *pDirCookie;
    DirectoryEntry entry;

    if (NULL == pDir)
    {
        if (NULL == (pDirPath = createPathName(pLongDirectoryName, NULL)))
            return SSH_FTP_FAILURE;

        status = FMGMT_getFirstFile (pDirPath, &pDir, &entry);
        free (pDirPath);
        if (OK != status)
            return  SSH_FTP_FAILURE;

        *pDirCookie = pDir;
    }
    else
    {
        /* get next file if already initialized */
        status = FMGMT_getNextFile (pDir, &entry);
        if (OK != status)
            return SSH_FTP_FAILURE;
    }

    while (1)
    {
        if (FTNone != entry.type)
        {
            sbyte4 length = entry.nameLength;

            if ((2 >= length) && ((0 == MOC_STRCMP((sbyte *) entry.pName, (sbyte *) ".")) || (0 == MOC_STRCMP((sbyte *) entry.pName, (sbyte *) ".."))))
                goto next;

            if (length > (SFTP_MAX_FILENAME_LENGTH-1))
                length = (SFTP_MAX_FILENAME_LENGTH-1);

            strncpy((char *)p_sftpFileDescr->fileName, (char *) entry.pName, length);
            p_sftpFileDescr->fileName[length] = '\0';
            p_sftpFileDescr->fileNameLength = length;

            SFTP_EXAMPLE_getFileStats(connectionInstance, (ubyte *)pLongDirectoryName,
                                     (ubyte *)p_sftpFileDescr->fileName, p_sftpFileDescr);

            return SSH_FTP_OK;
        }
        else
        {
            break;
        }

next:
        status = FMGMT_getNextFile (pDir, &entry);
        if (OK != status)
            return SSH_FTP_FAILURE;
    }


    return SSH_FTP_FAILURE;
}


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_handleCloseDynamicDirectory(sbyte4 connectionInstance, void **pDirCookie)
{
    DirectoryDescriptor pDir = (DirectoryDescriptor)(*pDirCookie);

    FMGMT_closeDir (&pDir);
    return SSH_FTP_OK;
}
#endif /*  (defined(__RTOS_VXWORKS__) || defined(__RTOS_LINUX__)) */


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_handleCreateDirectory(sbyte4 connectionInstance, sbyte *pCreateDirectoryName)
{
    sbyte*  pNewPath;
    sbyte4  result = SSH_FTP_FAILURE;
    sbyte4  status;
    MOC_UNUSED(connectionInstance);

    if (NULL == (pNewPath = createPathName(pCreateDirectoryName, NULL)))
        goto exit;

    status = FMGMT_mkdir (pNewPath, 0777);
    free(pNewPath);
    if (OK != status)
    {
        switch (status)
        {
            case ERR_DIR_EXISTS:
                result = SSH_FTP_FILE_ALREADY_EXISTS;
                break;
            case ERR_DIR_INVALID_PATH:
                result = SSH_FTP_NO_SUCH_PATH;
                break;
            default:
                result = SSH_FTP_FAILURE;
        };
        goto exit;
    }

    result = SSH_FTP_OK;
exit:
    return result;
}


/*------------------------------------------------------------------*/

static sbyte4
SFTP_EXAMPLE_handleRemoveDirectory(sbyte4 connectionInstance, sbyte *pRemoveDirectoryName)
{
    sbyte*   pRemovePath;
    sbyte4   result = SSH_FTP_FAILURE;
    sbyte4   status;
    MOC_UNUSED(connectionInstance);

    if (NULL == (pRemovePath = createPathName(pRemoveDirectoryName, NULL)))
        goto exit;

    status = FMGMT_remove (pRemovePath, FALSE);
    free(pRemovePath);
    if (OK != status)
    {
        switch (status)
        {
            case ERR_FILE_INVALID_PATH:
                result = SSH_FTP_NO_SUCH_PATH;
                break;
            case ERR_DIR_NOT_EMPTY:
                result = SSH_FTP_PERMISSION_DENIED;
                break;
            default:
                result = SSH_FTP_FAILURE;
        };
        goto exit;
    }

    result = SSH_FTP_OK;

exit:
    return result;
}


/*------------------------------------------------------------------*/

extern void
SFTP_EXAMPLE_init(void)
{
    /* open, read, write are needed for basic functionality */
    SSH_sftpSettings()->funcPtrOpenFileUpcall  = SFTP_EXAMPLE_openUpcall;
    SSH_sftpSettings()->funcPtrReadFileUpcall  = SFTP_EXAMPLE_readUpcall;
    SSH_sftpSettings()->funcPtrWriteFileUpcall = SFTP_EXAMPLE_writeUpcall;
    SSH_sftpSettings()->funcPtrCloseFileUpcall = SFTP_EXAMPLE_closeUpcall;

    /* optional, but good to have functionality */
    SSH_sftpSettings()->funcPtrGetFileStats    = SFTP_EXAMPLE_getFileStats;
    SSH_sftpSettings()->funcPtrGetOpenFileStats = SFTP_EXAMPLE_getOpenFileStats;
    SSH_sftpSettings()->funcPtrRemoveFile      = SFTP_EXAMPLE_removeFileUpcall;
    SSH_sftpSettings()->funcPtrRenameFile      = SFTP_EXAMPLE_renameFileUpcall;

    SSH_sftpSettings()->funcPtrOpenDirUpcall   = SFTP_EXAMPLE_handleOpenDynamicDirectory;
    SSH_sftpSettings()->funcPtrReadDirUpcall   = SFTP_EXAMPLE_handleReadDynamicDirectory;
    SSH_sftpSettings()->funcPtrCloseDirUpcall  = SFTP_EXAMPLE_handleCloseDynamicDirectory;

    /* directory specific methods */
    SSH_sftpSettings()->funcPtrCreateDir       = SFTP_EXAMPLE_handleCreateDirectory;
    SSH_sftpSettings()->funcPtrRemoveDir       = SFTP_EXAMPLE_handleRemoveDirectory;
}

#endif /* ((defined(__ENABLE_MOCANA_SSH_SERVER_EXAMPLE__) || defined(__ENABLE_MOCANA_SSH_ASYNC_SERVER_API__)) && defined(__ENABLE_MOCANA_SSH_FTP_SERVER__)) */
