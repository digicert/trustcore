/*
 * ssh_filesys.h
 *
 * SFTP File System Descriptor
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

#ifndef __SSH_FILESYS_HEADER__
#define __SSH_FILESYS_HEADER__

#ifndef SFTP_MAX_FILENAME_LENGTH
#define SFTP_MAX_FILENAME_LENGTH    64
#endif

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

/* the size of the directory and file definition tables */
MOC_EXTERN sbyte4 SFTP_NUM_FILES(void);

#define SFTP_TRUE               1
#define SFTP_FALSE              0

MOC_EXTERN sftpFileObjDescr sftpFiles[];

#endif /* __SSH_FILESYS_HEADER__ */
