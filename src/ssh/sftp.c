/*
 * sftp.c
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
@file       sftp.c
@brief      NanoSSH SFTP server developer API.
@details    This file contains NanoSSH SFTP server API functions.

@since 1.41
@version 2.02 and later

@flags
To enable any of this file's functions, the following flags must be defined in
moptions.h:
+ \c \__ENABLE_MOCANA_SSH_FTP_SERVER__
+ \c \__ENABLE_MOCANA_SSH_SERVER__

@filedoc    sftp.c
*/

#include "../common/moptions.h"

#if (defined(__ENABLE_MOCANA_SSH_SERVER__) && defined(__ENABLE_MOCANA_SSH_FTP_SERVER__))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mem_pool.h"
#include "../common/moc_stream.h"
#include "../common/circ_buf.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../crypto/dsa.h"
#include "../crypto/dh.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../common/sizedbuffer.h"
#include "../crypto/cert_store.h"
#include "../crypto/ca_mgmt.h"
#include "../ssh/ssh_str.h"
#include "../ssh/ssh_context.h"
#include "../ssh/ssh_server.h"
#include "../ssh/ssh_ftp.h"
#include "../ssh/ssh_filesys.h"
#include "../ssh/sftp.h"


/*------------------------------------------------------------------*/

static sftpSettings     m_sftpSettings;
/**
 * @dont_show
 * @internal
 */
extern sbyte4              g_sshMaxConnections;
/**
 * @dont_show
 * @internal
 */
extern sshConnectDescr* g_connectTable;


/*------------------------------------------------------------------*/

extern sftpSettings *
SSH_sftpSettings(void)
{
    return &m_sftpSettings;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
extern sbyte4
SSH_sftpSetMemberOfGroups(sbyte4 connectionInstance, ubyte4 memberGroups)
{
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    for (index = 0; index < g_sshMaxConnections; index++)
        if (connectionInstance == g_connectTable[index].instance)
        {
            SFTP_GROUP_ACCESS(g_connectTable[index].pContextSSH) = memberGroups;
            status = OK;
            break;
        }

    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_FTP_SERVER__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
extern sbyte4
SSH_sftpSetHomeDirectory(sbyte4 connectionInstance, sbyte *pHomeDirectory)
{
    sbyte4     index;
    MSTATUS status = ERR_SSH_BAD_ID;

    if (NULL == pHomeDirectory)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (index = 0; index < g_sshMaxConnections; index++)
        if (connectionInstance == g_connectTable[index].instance)
        {
            ubyte4  stringLength = 0;

            while ('\0' != pHomeDirectory[stringLength])
                stringLength++;

            if (OK <= (status = SSH_STR_makeStringBuffer(&(SFTP_CURRENT_PATH(g_connectTable[index].pContextSSH)), stringLength)))
                MOC_MEMCPY(SFTP_CURRENT_PATH(g_connectTable[index].pContextSSH)->pString, (ubyte *)pHomeDirectory, stringLength);

            break;
        }

exit:
    return (sbyte4)status;
}
#endif /* __ENABLE_MOCANA_SSH_FTP_SERVER__ */

#endif /* (defined(__ENABLE_MOCANA_SSH_SERVER__) && defined(__ENABLE_MOCANA_SSH_FTP_SERVER__)) */
