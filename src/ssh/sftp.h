/*
 * sftp.h
 *
 * SFTP Developer API
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

/**
@file       sftp.h
@brief      NanoSSH SFTP server developer API header.
@details    This header file contains definitions, structures, and function
            declarations used by the NanoSSH SFTP server.

@since 1.41
@version 2.02 and later

@flags
To build products using this header file, the following flag must be defined in
moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@filedoc    sftp.h
*/


/*------------------------------------------------------------------*/

#ifndef __SFTP_HEADER__
#define __SFTP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__

#define SFTP_OPEN_FILE_READ_BINARY      1
#define SFTP_OPEN_FILE_WRITE_BINARY     2

#define SSH_FTP_OK                      0
#define SSH_FTP_EOF                     1
#define SSH_FTP_NO_SUCH_FILE            2
#define SSH_FTP_PERMISSION_DENIED       3
#define SSH_FTP_FAILURE                 4
#define SSH_FTP_BAD_MESSAGE             5
#define SSH_FTP_NO_CONNECTION           6
#define SSH_FTP_CONNECTION_LOST         7
#define SSH_FTP_OP_UNSUPPORTED          8
#define SSH_FTP_INVALID_HANDLE          9
#define SSH_FTP_NO_SUCH_PATH            10
#define SSH_FTP_FILE_ALREADY_EXISTS     11
#define SSH_FTP_WRITE_PROTECT           12
#define SSH_FTP_NO_MEDIA                13


/*------------------------------------------------------------------*/

/**
@brief      Configuration settings and callback function pointers for NanoSSH
            FTP servers.

@details    This structure is used for NanoSSH FTP Server configuration. Each
            included callback function should be customized for your application
            and then registered by assigning it to the appropriate structure
            function pointer(s).

@since 1.41
@version 2.02 and later

@flags
To use this structure, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

*/
typedef struct
{
/**
@brief      Respond to a file open request.

@brief      This callback function is invoked when a user issues a file open
            request (for either reading or writing).

@ingroup    cb_sshs_sftp_file_io

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sftpInternelDescr    State information for a specific open file
                              connection (similar to a connection instance).
@param pLongDirectoryName   Pointer to string specifying full directory path of
                              the file.
@param pFilename            Pointer to string specifying the name of the file to
                              open.
@param flags                Combination of bit flag constant(s) specifying the
                              file's permissions (\c SFTP_OPEN_FILE_READ_BINARY
                              and/or \c SFTP_OPEN_FILE_WRITE_BINARY).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sftp.h
*/
    sbyte4 (*funcPtrOpenFileUpcall)    (sbyte4 connectionInstance, void* sftpInternelDescr, sbyte *pLongDirectoryName, sbyte *pFilename, sbyte4 flags);

/**
@brief      Respond to a file download request.

@details    This callback function is invoked when a %client downloads
            (requests) a file by using \c get.

@ingroup    cb_sshs_sftp_file_io

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sftpInternelDescr    State information for a specific open file
                              connection (similar to a connection instance).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sftp.h
*/
    sbyte4 (*funcPtrReadFileUpcall)    (sbyte4 connectionInstance, void* sftpInternelDescr);

/**
@brief      Respond to a file upload request.

@details    This callback function is invoked when a %client uploads a file by
            using \c put.

@ingroup    cb_sshs_sftp_file_io

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sftpInternelDescr    State information for a specific open file
                              connection (similar to a connection instance).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sftp.h
*/
    sbyte4 (*funcPtrWriteFileUpcall)   (sbyte4 connectionInstance, void* sftpInternelDescr);

/**
@brief      Respond to a file close request.

@details    This callback function is invoked when a user is finished viewing,
            modifying, or adding a file.

@ingroup    cb_sshs_sftp_file_io

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param sftpInternelDescr    State information for a specific open file
                              connection (similar to a connection instance).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sftp.h
*/
    sbyte4 (*funcPtrCloseFileUpcall)   (sbyte4 connectionInstance, void* sftpInternelDescr);

/**
@brief      Respond to a directory listing request.

@details    This callback function is invoked when a user requests a directory
            listing.

@ingroup    cb_sshs_sftp_dir_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pLongDirectoryName   Pointer to string specifying full directory path of
                              the file.
@param pDirCookie           On return, pointer to structure containing
                              directory's contents.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sftp.h
*/
    sbyte4 (*funcPtrOpenDirUpcall)     (sbyte4 connectionInstance, const sbyte *pLongDirectoryName, void* *pDirCookie);

/**
@brief      Respond to a file list request.

@details    This callback function is invoked when a user requests a list of
            files in a directory.

@ingroup    cb_sshs_sftp_dir_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pLongDirectoryName   Pointer to string specifying full directory path of
                              the file.
@param p_sftpFileDescr      On return, pointer to structure containing a single
                              file's or directory's descriptor.
@param pDirCookie           On invocation, cookie containing the information
                              necessary to traverse a directory listing; on
                              return, pointer to the file handle.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sftp.h
*/
    sbyte4 (*funcPtrReadDirUpcall)     (sbyte4 connectionInstance, sbyte *pLongDirectoryName, sftpFileObjDescr* p_sftpFileDescr, void* *pDirCookie);

/**
@brief      Respond to completion of a file list command or directory list 
            command.

@details    This callback function is invoked upon completion of a file list
            command or directory list command.

@ingroup    cb_sshs_sftp_dir_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pDirCookie           Pointer to directory name identifier cookie.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sftp.h
*/
    sbyte4 (*funcPtrCloseDirUpcall)    (sbyte4 connectionInstance, void **pDirCookie);

/**
@brief      Respond to a user's request for file metadata.

@details    This callback function is invoked when a user wants to get metadata
            about a file, such as file size or permissions.

@ingroup    cb_sshs_sftp_file_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pPath                Pointer to string specifying full directory path of
                              the file.
@param pPathExt             Pointer to string containing file name.
@param p_sftpFileDescr      On return, pointer to structure containing a single
                              file's or directory's descriptor.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sftp.h
*/
    sbyte4 (*funcPtrGetFileStats)      (sbyte4 connectionInstance, ubyte *pPath, ubyte *pPathExt, sftpFileObjDescr* p_sftpFileDescr);

/**
@brief      Respond to a user's request for an open file's metadata.

@details    This callback function is invoked when a user wants to get metadata
            about an open file, such as file size or permissions.

@ingroup    cb_sshs_sftp_file_mgmt

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param cookie               Application-specific data (typically a file
                              descriptor).
@param p_sftpFileDescr      On return, pointer to structure containing a single
                              file's or directory's descriptor.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sftp.h
*/
    sbyte4 (*funcPtrGetOpenFileStats)  (sbyte4 connectionInstance, sbyte4 cookie, sftpFileObjDescr* p_sftpFileDescr);

/**
@brief      Respond to a file remove (delete) request.

@details    This callback function is invoked when a user issues a file remove
            (delete) request.

@ingroup    cb_sshs_sftp_file_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pRemoveFilename      Pointer to string containing name of the file to
                              remove (delete).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sftp.h
*/
    sbyte4 (*funcPtrRemoveFile)        (sbyte4 connectionInstance, sbyte *pRemoveFilename);

/**
@brief      Respond to a file rename request.

@details    This callback function is invoked when a user issues a file rename
            request.

@ingroup    cb_sshs_sftp_file_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pOldFilename         Pointer to string containing existing file name.
@param pNewFilename         Pointer to string containing new file name.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sftp.h
*/
    sbyte4 (*funcPtrRenameFile)        (sbyte4 connectionInstance, sbyte *pOldFilename, sbyte *pNewFilename);

/**
@brief      Respond to a directory create (make) request.

@details    This callback function is invoked when a user issues a create (make)
            directory command.

@ingroup    cb_sshs_sftp_dir_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@param connectionInstance       Connection instance returned from
                                  SSH_acceptConnection() or
                                  SSH_ASYNC_acceptConnection().
@param pCreateDirectoryName     Pointer to string containing desired directory
                                  name.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sftp.h
*/
    sbyte4 (*funcPtrCreateDir)         (sbyte4 connectionInstance, sbyte *pCreateDirectoryName);

/**
@brief      Respond to a directory remove (delete) request.

@details    This callback function is invoked when a user issues a directory
            remove (delete) request.

@ingroup    cb_sshs_sftp_dir_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@param connectionInstance       Connection instance returned from
                                  SSH_acceptConnection() or
                                  SSH_ASYNC_acceptConnection().
@param pRemoveDirectoryName     Pointer to string containing name of the
                                  directory to remove (delete).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    sftp.h
*/
    sbyte4 (*funcPtrRemoveDir)         (sbyte4 connectionInstance, sbyte *pRemoveDirectoryName);

} sftpSettings;


/*------------------------------------------------------------------*/

/**
@brief      Get a pointer to NanoSSH SFTP server settings.

@details    This function returns a pointer to NanoSSH SFTP Server settings,
            which consist entirely of upcall function pointers.

@ingroup    func_ssh_sftp_server_mgmt

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__
+ \c \__ENABLE_MOCANA_SSH_SERVER__

@inc_file sftp.h

@return     Pointer to NanoSSH SFTP server settings.

@funcdoc    sftp.c
*/
MOC_EXTERN sftpSettings* SSH_sftpSettings(void);

/**
@brief      Set an individual SFTP user's permissions.

@details    This function sets an individual SFTP user's permissions, granting or
            restricting read, write, and delete access to files and directories.
            The function should be called from within a custom authentication
            upcall.

@ingroup    func_ssh_sftp_server_security_context_init

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__
+ \c \__ENABLE_MOCANA_SSH_SERVER__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param memberGroups         Sum of bitmasks specifying desired file and directory
                              access.

@inc_file sftp.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sftp.c
*/
MOC_EXTERN sbyte4   SSH_sftpSetMemberOfGroups(sbyte4 connectionInstance, ubyte4 memberGroups);

/**
@brief      Define an SFTP client's default home directory.

@details    This function defines an SFTP client's default home directory. The
            function must be called during the SSH authentication phase.

@ingroup    func_ssh_sftp_server_security_context_init

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__
+ \c \__ENABLE_MOCANA_SSH_SERVER__

@param connectionInstance   Connection instance returned from
                              SSH_acceptConnection() or
                              SSH_ASYNC_acceptConnection().
@param pHomeDirectory       Pointer to string identifier for the user's home
                              directory.

@inc_file sftp.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sftp.c
*/
MOC_EXTERN sbyte4   SSH_sftpSetHomeDirectory(sbyte4 connectionInstance, sbyte *pHomeDirectory);

/**
@brief      Save a cookie containing custom information about a context
            connection.

@details    This function saves a cookie containing custom information about a
            context connection.

@ingroup    func_ssh_sftp_server_context_state

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_SERVER__
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@inc_file sftp.h

@param sftpInternelDescr    State information for a desired open file
                              connection (similar to a connection instance).
@param sftpCookie           Cookie data (custom information).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous SFTP servers.

@sa SSH_sftpGetCookie

@code
static sbyte4
SFTP_EXAMPLE_openUpcall(sbyte4 connectionInstance,
                        sbyte4 sftpInternelDescr,
                        ubyte *pLongPath,
                        ubyte *pFilename,
                        sbyte4 flags)
{
    FILE*   fd = 0;
    ubyte*   pFileFlags;
    ubyte*   pFullPath = NULL;
    sbyte4     status = SSH_FTP_OK;

    // setup fopen file flag string
    if (flags & SFTP_OPEN_FILE_READ_BINARY)
        pFileFlags = "rb";
    else if (flags & SFTP_OPEN_FILE_WRITE_BINARY)
        pFileFlags = "wb";
    else {
        status = SSH_FTP_PERMISSION_DENIED;
        goto exit;
    }

    // open the file handle
    if (NULL != (pFullPath = createPathName(pLongPath, pFilename)))
        fd = fopen(pFullPath, pFileFlags);

    if (!fd)
        status = SSH_FTP_FAILURE;

    SSH_sftpSetCookie(sftpInternelDescr, (sbyte4)fd);

exit:
    if (NULL != pFullPath)
        free(pFullPath);

    return status;
}
@endcode

@funcdoc    ssh_ftp.c
*/
MOC_EXTERN void     SSH_sftpSetCookie(void* sftpInternelDescr, void* sftpCookie);

/**
@brief      Get a connection's cookie (containing custom information).

@details    This function gets a cookie containing custom information about a
            context connection. Your application should call this function
            after calls to SSH_sftpSetCookie(), or to make custom SFTP upcalls.

@ingroup    func_ssh_sftp_server_context_state

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_SERVER__
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@inc_file sftp.h

@param sftpInternelDescr    State information for a specific open file
                              connection (similar to a connection instance).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark This function is applicable to synchronous SFTP servers.

@sa SSH_sftpSetCookie

@code
static void
SFTP_EXAMPLE_closeUpcall(sbyte4 connectionInstance,
                         sbyte4 sftpInternelDescr)
{
    fclose((FILE *)SSH_sftpGetCookie(sftpInternelDescr));
}
@endcode

@funcdoc    ssh_ftp.c
*/
MOC_EXTERN void*   SSH_sftpGetCookie(void* sftpInternelDescr);

/**
@brief      Get a file's read byte position.

@details    This function (typically used within an SFTP read file upcall)
            returns a file's read byte position.

@ingroup    func_ssh_sftp_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_SERVER__
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@inc_file sftp.h

@param sftpInternelDescr    State information for a specific open file 
                              connection (similar to a connection instance).

@return     0-based byte index of file's current read location.

@remark     This function is applicable to synchronous SFTP servers.

@code
static sbyte4
SFTP_EXAMPLE_readUpcall(sbyte4 connectionInstance, sbyte4 sftpInternelDescr)
{
    FILE*   fd = (FILE *)SSH_sftpGetCookie(sftpInternelDescr);
    ubyte*   pBuffer;
    sbyte4     bufferSize;
    sbyte4     numBytesRead;
    sbyte4     fileSize;
    sbyte4     status = SSH_FTP_OK;

    fseek(fd, 0, SEEK_END);                   // determine size
    fileSize = ftell(fd);

    if ((0 == fileSize) ||
        (SSH_sftpReadLocation(sftpInternelDescr) >= fileSize))
    {   // eof reached
        status = SSH_FTP_EOF;
        goto exit;
    }

    // set the position to read from
    fseek(fd, SSH_sftpReadLocation(sftpInternelDescr), SEEK_SET);

    // fetch max bytes that can be sent at the moment
    pBuffer    = SSH_sftpReadBuffer(sftpInternelDescr);
    bufferSize = SSH_sftpReadBufferSize(sftpInternelDescr);

    // check if enough bytes have been read
    numBytesRead = fread(pBuffer, 1, bufferSize, fd);

    // end of file reached
    if (0 == numBytesRead)
        status = SSH_FTP_EOF;

    // set the number of bytes waiting to be sent
    SSH_sftpNumBytesRead(sftpInternelDescr, numBytesRead);

exit:
    return status;
}
@endcode

@funcdoc    ssh_ftp.c
*/
MOC_EXTERN sbyte4   SSH_sftpReadLocation(void* sftpInternelDescr);

/**
@brief      Get a pointer to a buffer containing a file's read data.

@details    This function returns a pointer to a buffer in which data read from 
            a file is stored.

@ingroup    func_ssh_sftp_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_SERVER__
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@inc_file sftp.h

@param sftpInternelDescr    State information for a specific open file
                              connection (similar to a connection instance).

@return     Pointer to a buffer containing a file's read data.

@remark     This function is applicable to synchronous SFTP servers.

@code
static sbyte4
SFTP_EXAMPLE_readUpcall(sbyte4 connectionInstance, sbyte4 sftpInternelDescr)
{
    FILE*   fd = (FILE *)SSH_sftpGetCookie(sftpInternelDescr);
    ubyte*   pBuffer;
    sbyte4     bufferSize;
    sbyte4     numBytesRead;
    sbyte4     fileSize;
    sbyte4     status = SSH_FTP_OK;

    fseek(fd, 0, SEEK_END);            // determine size
    fileSize = ftell(fd);

    if ((0 == fileSize) ||
        (SSH_sftpReadLocation(sftpInternelDescr) >= fileSize))
    { // eof reached
        status = SSH_FTP_EOF;
        goto exit;
    }

    // set the position to read from
    fseek(fd, SSH_sftpReadLocation(sftpInternelDescr), SEEK_SET);

    // fetch max bytes that can be sent at the moment
    pBuffer    = SSH_sftpReadBuffer(sftpInternelDescr);
    bufferSize = SSH_sftpReadBufferSize(sftpInternelDescr);

    // check if enough bytes have been read
    numBytesRead = fread(pBuffer, 1, bufferSize, fd);

    if (0 == numBytesRead)                // eof reached
        status = SSH_FTP_EOF;

    // set the number of bytes waiting to be sent
    SSH_sftpNumBytesRead(sftpInternelDescr, numBytesRead);

exit:
    return status;
}
@endcode

@funcdoc    ssh_ftp.c
*/
MOC_EXTERN sbyte*   SSH_sftpReadBuffer(void* sftpInternelDescr);

/**
@brief      Get the number of read bytes a %client is requesting.

@details    This function returns the number of read bytes a %client is
            requesting (or the maximum size of the read buffer if the buffer is
            too small for the number of bytes requested).

@ingroup    func_ssh_sftp_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_SERVER__
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@inc_file sftp.h

@param sftpInternelDescr    State information for a specific open file
                              connection (similar to a connection instance).

@return     Number of read bytes a %client is requesting (or the maximum size
            of the read buffer if the buffer is too small for the number of
            bytes requested).

@remark     This function is applicable to synchronous SFTP servers.

@code
static sbyte4
SFTP_EXAMPLE_readUpcall(sbyte4 connectionInstance, sbyte4 sftpInternelDescr)
{
    FILE*   fd = (FILE *)SSH_sftpGetCookie(sftpInternelDescr);
    ubyte*   pBuffer;
    sbyte4     bufferSize;
    sbyte4     numBytesRead;
    sbyte4     fileSize;
    sbyte4     status = SSH_FTP_OK;

    fseek(fd, 0, SEEK_END);         // determine size
    fileSize = ftell(fd);

    if ((0 == fileSize) ||
        (SSH_sftpReadLocation(sftpInternelDescr) >= fileSize)) {   // eof reached
        status = SSH_FTP_EOF;
        goto exit;
    }

    // set the position to read from
    fseek(fd, SSH_sftpReadLocation(sftpInternelDescr), SEEK_SET);

    // fetch max bytes that can be sent at the moment
    pBuffer    = SSH_sftpReadBuffer(sftpInternelDescr);
    bufferSize = SSH_sftpReadBufferSize(sftpInternelDescr);

    // check if enough bytes have been read
    numBytesRead = fread(pBuffer, 1, bufferSize, fd);

    // end of file reached
    if (0 == numBytesRead)
        status = SSH_FTP_EOF;

    // set the number of bytes waiting to be sent
    SSH_sftpNumBytesRead(sftpInternelDescr, numBytesRead);

exit:
    return status;
}
@endcode

@funcdoc    ssh_ftp.c
*/
MOC_EXTERN sbyte4   SSH_sftpReadBufferSize(void* sftpInternelDescr);

/**
@brief      Set an sftp file descriptor's $\c numBytesRead value to the number of
            bytes read from the incoming socket.

@details    This function sets an sftp file descriptor's \p numBytesRead value
            to the number of bytes read from the incoming socket.

@ingroup    func_ssh_sftp_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_SERVER__
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@inc_file sftp.h

@param sftpInternelDescr    State information for a specific open file
                              connection (similar to a connection instance).
@param numBytesRead         Number of bytes read.

@return     None.

@remark     This function is applicable to synchronous SFTP servers.

@code
static sbyte4
SFTP_EXAMPLE_readUpcall(sbyte4 connectionInstance, sbyte4 sftpInternelDescr)
{
    FILE*   fd = (FILE *)SSH_sftpGetCookie(sftpInternelDescr);
    ubyte*   pBuffer;
    sbyte4     bufferSize;
    sbyte4     numBytesRead;
    sbyte4     fileSize;
    sbyte4     status = SSH_FTP_OK;

    fseek(fd, 0, SEEK_END);         // determine size
    fileSize = ftell(fd);

    if ((0 == fileSize) ||
        (SSH_sftpReadLocation(sftpInternelDescr) >= fileSize))
    {   // eof reached
        status = SSH_FTP_EOF;
        goto exit;
    }

    // set the position to read from
    fseek(fd, SSH_sftpReadLocation(sftpInternelDescr), SEEK_SET);

    // fetch max bytes that can be sent at the moment
    pBuffer    = SSH_sftpReadBuffer(sftpInternelDescr);
    bufferSize = SSH_sftpReadBufferSize(sftpInternelDescr);

    // check if enough bytes have been read
    numBytesRead = fread(pBuffer, 1, bufferSize, fd);

    if (0 == numBytesRead)          // if eof reached
        status = SSH_FTP_EOF;

    // set the number of bytes waiting to be sent
    SSH_sftpNumBytesRead(sftpInternelDescr, numBytesRead);

exit:
    return status;
}
@endcode

@funcdoc    ssh_ftp.c
*/
MOC_EXTERN void     SSH_sftpNumBytesRead(void* sftpInternelDescr, sbyte4 numBytesRead);

/**
@brief      Get a file's write byte position.

@details    This function (typically used within an SFTP write file upcall)
            returns a file's write byte position.

@ingroup    func_ssh_sftp_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_SERVER__
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@inc_file sftp.h

@param sftpInternelDescr    State information for a specific open file
                              connection (similar to a connection instance).

@return     0-based byte index of file's current write location.

@remark     This function is applicable to synchronous SFTP servers.

@code
static sbyte4
SFTP_EXAMPLE_writeUpcall(sbyte4 connectionInstance, sbyte4 sftpInternelDescr)
{
    FILE*   fd = (FILE *)SSH_sftpGetCookie(sftpInternelDescr);
    ubyte*   pBuffer;
    sbyte4     bufferSize;
    sbyte4     numBytesWritten;
    sbyte4     status = SSH_FTP_OK;

    // set the position to write from
    fseek(fd, SSH_sftpWriteLocation(sftpInternelDescr), SEEK_SET);

    // fetch buffer and max bytes that can be sent at the moment
    pBuffer    = SSH_sftpWriteBuffer(sftpInternelDescr);
    bufferSize = SSH_sftpWriteBufferSize(sftpInternelDescr);

    // write the bytes
    numBytesWritten = fwrite(pBuffer, 1, bufferSize, fd);

    if (bufferSize < numBytesWritten)
    {
        // write failed
        status = SSH_FTP_FAILURE;
    }

exit:
    return status;
}
@endcode

@funcdoc    ssh_ftp.c
*/
MOC_EXTERN sbyte4   SSH_sftpWriteLocation(void* sftpInternelDescr);

/**
@brief      Get a pointer to a buffer (received from an SFTP %client)
            containing data to write to a file.

@details    This function returns a pointer to a buffer (received from an SFTP
            %client) containing data to write to a file.

@ingroup    func_ssh_sftp_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_SERVER__
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@inc_file sftp.h

@param sftpInternelDescr    State information for a specific open file
                              connection (similar to a connection instance).

@return     Pointer to the buffer containing data to write.

@remark     This function is applicable to synchronous SFTP servers.

@code
static sbyte4
SFTP_EXAMPLE_writeUpcall(sbyte4 connectionInstance, sbyte4 sftpInternelDescr)
{
    FILE*   fd = (FILE *)SSH_sftpGetCookie(sftpInternelDescr);
    ubyte*   pBuffer;
    sbyte4     bufferSize;
    sbyte4     numBytesWritten;
    sbyte4     status = SSH_FTP_OK;

    // set the position to write from
    fseek(fd, SSH_sftpWriteLocation(sftpInternelDescr), SEEK_SET);

    // fetch buffer and max bytes that can be sent at the moment
    pBuffer    = SSH_sftpWriteBuffer(sftpInternelDescr);
    bufferSize = SSH_sftpWriteBufferSize(sftpInternelDescr);

    // write the bytes
    numBytesWritten = fwrite(pBuffer, 1, bufferSize, fd);

    if (bufferSize < numBytesWritten)
    {
        // write failed
        status = SSH_FTP_FAILURE;
    }

exit:
    return status;
}
@endcode

@funcdoc    ssh_ftp.c
*/
MOC_EXTERN sbyte*   SSH_sftpWriteBuffer(void* sftpInternelDescr);

/**
@brief      Get the number of bytes written to a file by an SFTP write upcall
            handler.

@details    This function returns the number of bytes written to a file by an
            SFTP write upcall handler.

@ingroup    func_ssh_sftp_server_msg

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_SERVER__
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__

@inc_file sftp.h

@param sftpInternelDescr    State information for a specific open file
                              connection (similar to a connection instance).

@return     Number of bytes written by the SFTP write upcall handler.

@remark     This function is applicable to synchronous SFTP servers.

@code
static sbyte4
SFTP_EXAMPLE_writeUpcall(sbyte4 connectionInstance, sbyte4 sftpInternelDescr)
{
    FILE*   fd = (FILE *)SSH_sftpGetCookie(sftpInternelDescr);
    ubyte*   pBuffer;
    sbyte4     bufferSize;
    sbyte4     numBytesWritten;
    sbyte4     status = SSH_FTP_OK;

    // set the position to write from
    fseek(fd, SSH_sftpWriteLocation(sftpInternelDescr), SEEK_SET);

    // fetch buffer and max bytes that can be sent at the moment
    pBuffer    = SSH_sftpWriteBuffer(sftpInternelDescr);
    bufferSize = SSH_sftpWriteBufferSize(sftpInternelDescr);

    // write the bytes
    numBytesWritten = fwrite(pBuffer, 1, bufferSize, fd);

    if (bufferSize < numBytesWritten)
    {
        // write failed
        status = SSH_FTP_FAILURE;
    }

exit:
    return status;
}
@endcode

@funcdoc    ssh_ftp.c
*/
MOC_EXTERN sbyte4   SSH_sftpWriteBufferSize(void* sftpInternelDescr);

#endif /* __ENABLE_MOCANA_SSH_FTP_SERVER__ */

#ifdef __cplusplus
}
#endif

#endif /* __SFTP_HEADER__ */

