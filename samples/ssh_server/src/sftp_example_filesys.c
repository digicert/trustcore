/*
 * sftp_example_filesys.c
 *
 * Example SFTP File System Descriptor
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
 */

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../ssh/ssh_filesys.h"

/* if you want to have group accesses (bit masks), define some groups here */
#define SFTP_GROUP_EVERYONE      0
#define SFTP_GROUP_SSL_ADMIN     1
#define SFTP_GROUP_SSH_ADMIN     2
#define SFTP_GROUP_POWER_USER    3

#define HARDWIRED_LENGTH         1000

/*!-!-!-! our macro, SFTP_FILENAME_MACRO, makes life easier, unfortunately, some compilers can't handle this macro */
/* a macro to make definitions a little simpler */
#define SFTP_FILENAME_MACRO(X)   #X, (sizeof(#X)-1)

/* customize this table... parent directory permissions override per file permissions */
/*!-!-!-! no slashes */
sftpFileObjDescr sftpFiles[] =
{
    { "/",          1,  SFTP_GROUP_EVERYONE,  SFTP_GROUP_EVERYONE,  SFTP_GROUP_EVERYONE,  SFTP_TRUE, SFTP_TRUE, HARDWIRED_LENGTH, 0, 0, 0, SFTP_TRUE },
    { "/temp",      5,  SFTP_GROUP_EVERYONE,  SFTP_GROUP_EVERYONE,  SFTP_GROUP_EVERYONE,  SFTP_TRUE, SFTP_TRUE, HARDWIRED_LENGTH, 0, 0, 0, SFTP_TRUE },
    { "/temp/temp", 10, SFTP_GROUP_EVERYONE,  SFTP_GROUP_EVERYONE,  SFTP_GROUP_EVERYONE,  SFTP_TRUE, SFTP_TRUE, HARDWIRED_LENGTH, 0, 0, 0, SFTP_TRUE },
    { "/logs",      5,  SFTP_GROUP_EVERYONE,  SFTP_GROUP_EVERYONE,  SFTP_GROUP_EVERYONE,  SFTP_TRUE, SFTP_TRUE, HARDWIRED_LENGTH, 0, 0, 0, SFTP_TRUE },
    { "/ssl",       4,  SFTP_GROUP_SSL_ADMIN, SFTP_GROUP_SSL_ADMIN, SFTP_GROUP_SSH_ADMIN, SFTP_TRUE, SFTP_TRUE, HARDWIRED_LENGTH, 0, 0, 0, SFTP_TRUE },
    { "/ssh",       4,  SFTP_GROUP_SSH_ADMIN, SFTP_GROUP_SSH_ADMIN, SFTP_GROUP_SSH_ADMIN, SFTP_TRUE, SFTP_TRUE, HARDWIRED_LENGTH, 0, 0, 0, SFTP_TRUE },
    { "/ftp",       4,  SFTP_GROUP_SSH_ADMIN, SFTP_GROUP_SSH_ADMIN, SFTP_GROUP_SSH_ADMIN, SFTP_TRUE, SFTP_TRUE, HARDWIRED_LENGTH, 0, 0, 0, SFTP_TRUE }
};

extern sbyte4
SFTP_NUM_FILES(void)
{
    return (sizeof(sftpFiles) / sizeof(sftpFileObjDescr));
}
