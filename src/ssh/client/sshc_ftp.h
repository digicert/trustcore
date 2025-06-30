/*
 * sshc_ftp.h
 *
 * SSH File Transfer Protocol Client
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

#ifndef __SSHC_FTP_HEADER__
#define __SSHC_FTP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

typedef struct ATTRClient
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

} ATTRClient;


/*------------------------------------------------------------------*/

typedef struct
{
    void*               pString;        /* sbyte* for open, sshStringBuffer* most other times */
    ubyte4              stringLen;      /* unused if pString is sshStringBuffer */
    ubyte4              param1;         /* varies */
    void*               pPtr;           /* varies */

} sshcSFTPCommonArgs;

typedef sbyte4        (*funcPtrSFTPRequest)(sbyte4 connectionInstance, sshcSFTPCommonArgs *args);


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN sbyte4 SSHC_FTP_SendFTPHello(sbyte4 connectionInstance);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN sbyte4 SSHC_negotiateSFTPRequest(sbyte4 connectionInstance, funcPtrSFTPRequest func, sshcSFTPCommonArgs *args);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_FTP_doProtocol(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN sbyte4  SSHC_FTP_freeAllHandles(sshClientContext *pContextSSH);

#ifdef __cplusplus
}
#endif

#endif
