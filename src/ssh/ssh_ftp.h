/*
 * ssh_ftp.h
 *
 * SSH File Transfer Protocol Handler
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



/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSH_SERVER__) && defined(__ENABLE_DIGICERT_SSH_FTP_SERVER__))

#ifndef __SSH_FTP_HEADER__
#define __SSH_FTP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define SFTP_CURRENT_PATH(X)                    (X)->sessionState.pCurrentPath
#define SFTP_GROUP_ACCESS(X)                    (X)->sessionState.sftpGroupAccessPermissions


/*------------------------------------------------------------------*/

typedef struct
{
    ubyte4              flags;
    ubyte               type;                  /* always present */

    ubyte8              size;                  /* present only if flag SIZE */
    sshStringBuffer*    owner;                 /* present only if flag OWNERGROUP */
    sshStringBuffer*    group;                 /* present only if flag OWNERGROUP */
    ubyte4              permissions;           /* present only if flag PERMISSIONS */
    ubyte8              atime;                 /* present only if flag ACCESSTIME */
    ubyte4              atime_nseconds;        /* present only if flag SUBSECOND_TIMES */
    ubyte8              createtime;            /* present only if flag CREATETIME */
    ubyte4              createtime_nseconds;   /* present only if flag SUBSECOND_TIMES */
    ubyte8              mtime;                 /* present only if flag MODIFYTIME */
    ubyte4              mtime_nseconds;        /* present only if flag SUBSECOND_TIMES */
    sshStringBuffer*    acl;                   /* present only if flag ACL */

} ATTR;


/*------------------------------------------------------------------*/
/* This is for internal use only */
MOC_EXTERN MSTATUS SSH_FTP_initStringBuffers(void);
/* This is for internal use only */
MOC_EXTERN MSTATUS SSH_FTP_freeStringBuffers(void);

/* This is for internal use only */
MOC_EXTERN MSTATUS SSH_FTP_doProtocol(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen);
/* This is for internal use only */
MOC_EXTERN MSTATUS SSH_FTP_closeAllOpenHandles(sshContext *pContextSSH);

#ifdef __cplusplus
}
#endif

#endif /* __SSH_FTP_HEADER__ */
#endif /* (defined(__ENABLE_DIGICERT_SSH_SERVER__) && defined(__ENABLE_DIGICERT_SSH_FTP_SERVER__)) */

