/*
 * ssh_filesys.h
 *
 * SFTP File System Descriptor
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
