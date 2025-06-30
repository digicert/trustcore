/*
 * sshc_filesys.h
 *
 * SFTPC File System Descriptor
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
/**
@file       sshc_filesys.h
@brief      NanoSSH Client SFTP developer API header.
@details    This header file contains definitions, structures, and function
            declarations used by NanoSSH %client SFTP.

@since 1.41
@version 5.4 and later

@todo_version (\__cplusplus wrapper added ...)

@flags
To use this file's enumerations, structures, and functions, the following flag
must be defined:
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@filedoc    sshc_filesys.h
*/

#ifndef __SSHC_FILESYS_HEADER__
#define __SSHC_FILESYS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_MOCANA_SSH_FTP_CLIENT__

#ifndef SFTP_MAX_FILENAME_LENGTH
#define SFTP_MAX_FILENAME_LENGTH    64
#endif

/**
 * @dont_show
 * @internal
 */
typedef struct
{
    ubyte   fileName[SFTP_MAX_FILENAME_LENGTH];
    ubyte4  fileNameLength;

    ubyte4  readAccessGroup;
    ubyte4  writeAccessGroup;
    ubyte4  executeAccessGroup;

    sbyte4  isReadable;
    sbyte4  isWriteable;

    sbyte4  fileSize;           /* directories can assign this zero */

    /* if your file system does not support time, set to a default (date/)time */
    sbyte4  fileAccessTime;     /* file last accessed time */
    sbyte4  fileCreationTime;   /* file creation time */
    sbyte4  fileModifyTime;     /* file modify time */

    /* added functionality to support directory listings */
    sbyte4  isDirectory;

} sftpFileObjDescr;


/*------------------------------------------------------------------*/

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
@brief      Callback function pointers for NanoSSH Client SFTP operations.

@details    This structure is used for NanoSSH Client SFTP configuration.
            Each  callback function should be customized for your application
            and then registered by assigning it to the appropriate structure
            function pointer(s).

@since 1.41
@version 5.4 and later

@flags
To use this structure's callbacks, the following flag
must be defined:
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

*/
typedef struct
{
/**
@brief      Respond to a file download request.

@details    This callback function is invoked when a server downloads
            (requests) a file by using \c get.

@ingroup    cb_sshc_sftp_server

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@param connectionInstance       Connection instance returned from SSHC_connect().
@param p_sftpFileHandleDescr    File handle descriptor returned
                                  from SSHC_openFile(). Contains state
                                  information for a specific open file
                                  connection (similar to a connection instance).

@return         \c OK (0) if successful; otherwise a negative number error code
                that is meaningful within the context of your application.

@callbackdoc    sshc_filesys.h
*/
    sbyte4 (*funcPtrReadFileUpcall)       (sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Respond to a file upload request.

@details    This callback function is invoked when a %server uploads a file by
            using \c put.

@ingroup    cb_sshc_sftp_server

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@param connectionInstance       Connection instance returned from SSHC_connect().
@param p_sftpFileHandleDescr    File handle descriptor returned from
                                SSHC_openFile(). Contains state information
                                for a specific open file connection (similar
                                to a connection instance).

@return         \c OK (0) if successful; otherwise a negative number error code
                that is meaningful within the context of your application.

@callbackdoc    sshc_filesys.h
*/
    sbyte4 (*funcPtrWriteFileUpcall)      (sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Respond to a file close request.

@details    This callback function is invoked when a user is finished viewing,
            modifying, or adding a file.

@ingroup    cb_sshc_sftp_server

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@param connectionInstance       Connection instance returned from SSHC_connect().
@param p_sftpFileHandleDescr    File handle descriptor returned
                                  from SSHC_openFile(). Contains state
                                  information for a specific open file
                                  connection (similar to a connection instance).

@return         \c OK (0) if successful; otherwise a negative number error code
                that is meaningful within the context of your application.

@callbackdoc    sshc_filesys.h
*/
    sbyte4 (*funcPtrCloseFileUpcall)      (sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Respond to a file open request.

@details    This callback function is invoked when a user issues a file open
            request (for either reading or writing).

@ingroup    cb_sshc_sftp_server

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@param connectionInstance       Connection instance returned from SSHC_connect().
@param p_sftpFileHandleDescr    File handle descriptor returned from
                                  SSHC_openFile(). Contains state information
                                  for a specific open file connection (similar
                                  to a connection instance).

@return         \c OK (0) if successful; otherwise a negative number error code
                that is meaningful within the context of your application.

@callbackdoc    sshc_filesys.h
*/
    sbyte4 (*funcPtrOpenFileClientUpcall) (sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr);

/**
@brief      Respond to a file open request.

@details    This is an optional callback that you can implement and invoke
            anytime to obtain the SSH server's response to NanoSSH client.
            This is particularly useful when a NanoSSH API method returns an
            error code and you want to learn the low-level details from the
            server's message, and display or log that information.

@ingroup    cb_sshc_sftp_server

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@param connectionInstance       Connection instance returned from SSHC_connect().
@param statusCode               Error/status code contained in the payload of
                                  the server's response. The location of the
                                  error code in the payload varies by server
                                  response type, as per the RFC.
@param message                  Message text contained in the payload of the
                                  server's response. The location of the
                                  message in the payload varies by server
                                  response type, as per the RFC.
@param messageLength            Number of bytes in the server's response
                                  message text. The location of the message
                                  length in the payload varies by server
                                  response type, as per the RFC.
@param pLanguage                Language tag in the server's response, as
                                  defined in RFC 1766.
@param languageLength           Number of bytes in the language tag of the
                                  server's response.

@return         \c OK (0) if successful; otherwise a negative number error code
                that is meaningful within the context of your application.

@callbackdoc    sshc_filesys.h
*/
    void   (*funcPtrStatus)               (sbyte4 connectionInstance, ubyte4 statusCode, ubyte *message, ubyte4 messageLength, ubyte *pLanguage, ubyte4 languageLength);

} sftpClientSettings;


/*------------------------------------------------------------------*/

MOC_EXTERN sftpClientSettings *SSHC_sftpClientSettings(void);

#define SFTP_TRUE               1
#define SFTP_FALSE              0

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN void   SSHC_sftpSetWriteLocation(sftpcFileHandleDescr *p_sftpFileHandleDescr, sbyte4 location);

/**
@brief      Point a write buffer to a chunk of data to be transfered.

@details    This function points a write buffer to a chunk of data to be
            transfered.

@ingroup    func_ssh_sftp_put

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc_filesys.h

@param p_sftpFileHandleDescr    Pointer to a file handle descriptor whose write
                                  buffer pointer you want to set.
@param pBuffer                  Pointer to chunk of data to transfer.

@return     None.

@remark     This function is applicable to synchronous SFTP clients.

@sa     SSHC_sftpSetWriteBufferSize()

@funcdoc    sshc_ftp.c
*/
MOC_EXTERN void   SSHC_sftpSetWriteBuffer(sftpcFileHandleDescr *p_sftpFileHandleDescr, sbyte *pBuffer);

/**
@brief      Set the size of a write buffer pointing to a chunk of data to be
            transfered.

@details    This function sets the size of a write buffer pointing to a chunk
            of data to be transfered.

@ingroup    func_ssh_sftp_put

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_MOCANA_SSH_CLIENT__
+ \c \__ENABLE_MOCANA_SSH_FTP_CLIENT__

@inc_file sshc_filesys.h

@param p_sftpFileHandleDescr    Pointer to a file handle descriptor whose write
                                  buffer size you want to set.
@param bufSize                  Number of bytes to set the write buffer size to.

@return     None.

@remark     This function is applicable to synchronous SFTP clients.

@sa SSHC_sftpSetWriteBuffer()

@funcdoc    sshc_ftp.c
*/
MOC_EXTERN void   SSHC_sftpSetWriteBufferSize(sftpcFileHandleDescr *p_sftpFileHandleDescr, sbyte4 bufSize);
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN ubyte4 SSHC_sftpGetMaxWrite(sbyte4 connectionInstance);

#endif /* __ENABLE_MOCANA_SSH_FTP_CLIENT__ */

#ifdef __cplusplus
}
#endif

#endif /* __SSHC_FILESYS_HEADER__ */
