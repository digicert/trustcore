/*
 * sshc_ftp.c
 *
 * SSH File Transfer Protocol -- Client
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
@file       sshc_ftp.c
@brief      NanoSSH SFTP Client developer API.
@details    This file contains NanoSSH SFTP Client API functions.

@since 1.41
@version 2.02 and later

@todo_version (changes to many functions, structs)

@flags
To enable any of this file's functions, the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_CLIENT__
+ \c \__ENABLE_DIGICERT_SSH_FTP_CLIENT__

Whether the following flags are defined determines which functions are enabled:
+ \c \__ENABLE_DIGICERT_SSH_FTP_CLIENT__

@filedoc    sshc_ftp.c
*/

#include "../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_SSH_CLIENT__) && defined(__ENABLE_DIGICERT_SSH_FTP_CLIENT__))

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/debug_console.h"
#include "../../common/memory_debug.h"
#include "../../common/mem_pool.h"
#include "../../common/int64.h"
#include "../../common/circ_buf.h"
#include "../../crypto/dsa.h"
#include "../../crypto/sha1.h"
#include "../../crypto/dh.h"
#include "../../crypto/crypto.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif
#include "../../crypto/pubcrypto.h"
#include "../../common/sizedbuffer.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/ca_mgmt.h"
#include "../../ssh/ssh_defs.h"
#include "../../ssh/dump_mesg.h"
#include "../../ssh/client/sshc.h"
#include "../../ssh/client/sshc_filesys.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc_context.h"
#include "../../ssh/client/sshc_in_mesg.h"
#include "../../ssh/client/sshc_client.h"
#include "../../ssh/client/sshc_session.h"
#include "../../ssh/client/sshc_ftp.h"
#include "../../ssh/client/sshc_trans.h"
#include "../../ssh/client/sshc_utils.h"
#include "../../ssh/client/sshc_str_house.h"


/*------------------------------------------------------------------*/

#define SSHC_SFTP_CLIENT_VERSION           4
#define MOCANA_SSC_FTP_LOW_VER             2

#define SSH_FTP_PACKET_LENGTH_FIELD_SIZE   4
#define SSH_FTP_PACKET_TYPE_FIELD_SIZE     1
#define SSH_FTP_REQUEST_ID_FIELD_SIZE      4
#define SSH_FTP_REQUEST_PFLAGS_SIZE        4

#define kMaxFtpMessageSize                 34000

#define SSHC_FTP_TIMEOUT_MS    100

static ATTRClient clientSFTPOpenFileATTR = {
    0,
    SSH_FILEXFER_TYPE_REGULAR,
    U8INT(0, 0 ),
    NULL,
    NULL,
    0,
    U8INT( 0, 0 ),
    0,
    U8INT( 0, 0 ),
    0,
    U8INT( 0, 0 ),
    0,
    NULL
};

static ATTRClient clientSFTPMakeDirATTR = {
    0,
    SSH_FILEXFER_TYPE_DIRECTORY,
    U8INT( 0, 0 ),
    NULL,
    NULL,
    0,
    U8INT( 0, 0 ),
    0,
    U8INT( 0, 0 ),
    0,
    U8INT( 0, 0 ),
    0,
    NULL
};

/*
 * if need this can become a routine, if locking becomes required.
 */
#define NEW_REQUEST_ID()                   ++(pContextSSH->requestCounter)


/*------------------------------------------------------------------*/

/* defined in sshc.c */
extern MSTATUS SSHC_doProtocolSession(sbyte4 connectionInstance, intBoolean useTimeout, ubyte4 timeout);


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSHC_negotiateSFTPRequest(sbyte4 connectionInstance, funcPtrSFTPRequest func, sshcSFTPCommonArgs *args)
{
    MSTATUS           status;
    sshcConnectDescr* pDescr;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    pDescr->mesgType = SSH_SESSION_NOTHING;

    if (0 > (status = (func)(connectionInstance, args)))
        goto exit;


    status = SSHC_doProtocolSession(connectionInstance, FALSE, TIMEOUT_SSHC_UPPER_LAYER);

exit:
    return (sbyte4)status;

} /* SSHC_negotiateSFTPRequest */


/*------------------------------------------------------------------*/

static ubyte4
getAttrLength(ATTRClient *pAttr, ubyte4 version)
{
    ubyte4  flags = pAttr->flags;
    ubyte4  attrLength;

    attrLength = 4;         /* flags:4 */

    if (3 < version)        /* type field */
        attrLength++;

    if (flags & SSH_FILEXFER_ATTR_SIZE)
        attrLength += 8;

    if (flags & SSH_FILEXFER_ATTR_OWNERGROUP)
    {
        attrLength += 4 + pAttr->owner->stringLen;
        attrLength += 4 + pAttr->group->stringLen;
    }

    if (flags & SSH_FILEXFER_ATTR_PERMISSIONS)
        attrLength += 4;

    if (flags & SSH_FILEXFER_ATTR_ACCESSTIME)
    {
        attrLength += 8;

        if (3 < version)
            if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
                attrLength += 4;
    }

    if (flags & SSH_FILEXFER_ATTR_CREATETIME)
    {
        attrLength += 8;

        if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
            attrLength += 4;
    }

    if (flags & SSH_FILEXFER_ATTR_MODIFYTIME)
    {
        attrLength += 8;

        if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
            attrLength += 4;
    }

    if (flags & SSH_FILEXFER_ATTR_ACL)
        attrLength += 4 + pAttr->acl->stringLen;

    return attrLength;

} /* getAttrLength */


/*------------------------------------------------------------------*/

static MSTATUS
getAttr(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, ATTRClient *pRetATTR, ubyte4 version)
{
    sshStringBuffer* pDummyString = NULL;
    ubyte4           extended_count = 0;    /* present only if flag EXTENDED */
    ubyte4           flags;
    ubyte4           dummyInt;
    MSTATUS          status   = OK;

    if (OK > (status = SSHC_UTILS_getInteger(pBuffer, bufSize, pBufIndex, &(flags))))
        goto exit;

    pRetATTR->flags = flags;

    if (3 < version)
        if (OK > (status = SSHC_UTILS_getByte(pBuffer, bufSize, pBufIndex, &(pRetATTR->type))))
            goto exit;

    if (flags & SSH_FILEXFER_ATTR_SIZE)
        if (OK > (status = SSHC_UTILS_getInteger64(pBuffer, bufSize, pBufIndex, &(pRetATTR->size))))
            goto exit;

    if (3 < version)
    {
        if (flags & SSH_FILEXFER_ATTR_OWNERGROUP)
        {
            if (OK > (status = SSH_STR_copyStringFromPayload2(pBuffer, bufSize, pBufIndex, &(pRetATTR->owner))))
                goto exit;

            DEBUG_RELABEL_MEMORY(pRetATTR->owner);

            if (OK > (status = SSH_STR_copyStringFromPayload2(pBuffer, bufSize, pBufIndex, &(pRetATTR->group))))
                goto exit;

            DEBUG_RELABEL_MEMORY(pRetATTR->group);
        }
    }
    else
    {
        if (flags & SSH_FILEXFER_ATTR_UIDGID)
        {
            if (OK > (status = SSHC_UTILS_getInteger(pBuffer, bufSize, pBufIndex, &(dummyInt))))
                goto exit;

            if (OK > (status = SSHC_UTILS_getInteger(pBuffer, bufSize, pBufIndex, &(dummyInt))))
                goto exit;
        }
    }

    if (flags & SSH_FILEXFER_ATTR_PERMISSIONS)
        if (OK > (status = SSHC_UTILS_getInteger(pBuffer, bufSize, pBufIndex, &(pRetATTR->permissions))))
            goto exit;

    if (flags & SSH_FILEXFER_ATTR_ACCESSTIME)
    {
        if (OK > (status = SSHC_UTILS_getInteger64(pBuffer, bufSize, pBufIndex, &(pRetATTR->atime))))
            goto exit;

        if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
            if (OK > (status = SSHC_UTILS_getInteger(pBuffer, bufSize, pBufIndex, &(pRetATTR->atime_nseconds))))
                goto exit;
    }

    if (flags & SSH_FILEXFER_ATTR_CREATETIME)
    {
        if (OK > (status = SSHC_UTILS_getInteger64(pBuffer, bufSize, pBufIndex, &(pRetATTR->createtime))))
            goto exit;

        if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
            if (OK > (status = SSHC_UTILS_getInteger(pBuffer, bufSize, pBufIndex, &(pRetATTR->createtime_nseconds))))
                goto exit;
    }

    if (flags & SSH_FILEXFER_ATTR_MODIFYTIME)
    {
        if (OK > (status = SSHC_UTILS_getInteger64(pBuffer, bufSize, pBufIndex, &(pRetATTR->mtime))))
            goto exit;

        if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
            if (OK > (status = SSHC_UTILS_getInteger(pBuffer, bufSize, pBufIndex, &(pRetATTR->mtime_nseconds))))
                goto exit;
    }

    if (flags & SSH_FILEXFER_ATTR_ACL)
    {
        if (OK > (status = SSH_STR_copyStringFromPayload2(pBuffer, bufSize, pBufIndex, &(pRetATTR->acl))))
            goto exit;

        DEBUG_RELABEL_MEMORY(pRetATTR->acl);
    }

    if (flags & SSH_FILEXFER_ATTR_EXTENDED)
        if (OK > (status = SSHC_UTILS_getInteger(pBuffer, bufSize, pBufIndex, &extended_count)))
            goto exit;

    while (0 < extended_count)
    {
        /* fetch and dump extended type */
        if (OK > (status = SSH_STR_copyStringFromPayload2(pBuffer, bufSize, pBufIndex, &pDummyString)))
        {
            if(NULL != pDummyString)
                SSH_STR_freeStringBuffer(&pDummyString);
            goto exit;
        }

        SSH_STR_freeStringBuffer(&pDummyString);

        /* fetch and dump extended data */
        if (OK > (status = SSH_STR_copyStringFromPayload2(pBuffer, bufSize, pBufIndex, &pDummyString)))
        {
            if(NULL != pDummyString)
                SSH_STR_freeStringBuffer(&pDummyString);
            goto exit;
        }

        SSH_STR_freeStringBuffer(&pDummyString);

        extended_count--;
    }

exit:
#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "getAttr: status = ", status);
#endif

    return status;

} /* getAttr */


/*------------------------------------------------------------------*/

static MSTATUS
freeAttr(ATTRClient *pFreeATTR)
{
    if (NULL == pFreeATTR)
        return ERR_NULL_POINTER;

    SSH_STR_freeStringBuffer(&(pFreeATTR->owner));
    SSH_STR_freeStringBuffer(&(pFreeATTR->group));
    SSH_STR_freeStringBuffer(&(pFreeATTR->acl));

    DIGI_MEMSET((ubyte *)pFreeATTR, 0x00, sizeof(ATTRClient));

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
setAttr(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex, ATTRClient *pATTR, ubyte4 version)
{
    ubyte4  flags  = ((pATTR->flags) & (~(SSH_FILEXFER_ATTR_EXTENDED)));
    MSTATUS status = OK;

    if (OK > (status = SSHC_UTILS_setInteger(pPayload, payloadLength, pBufIndex, flags)))
        goto exit;

    if (3 < version)
        if (OK > (status = SSHC_UTILS_setByte(pPayload, payloadLength, pBufIndex, pATTR->type)))
            goto exit;

    if (flags & SSH_FILEXFER_ATTR_SIZE)
        if (OK > (status = SSHC_UTILS_setInteger64(pPayload, payloadLength, pBufIndex, &pATTR->size)))
            goto exit;

    if (flags & SSH_FILEXFER_ATTR_OWNERGROUP)
    {
        if (OK > (status = SSH_STR_copyStringToPayload(pPayload, payloadLength, pBufIndex, pATTR->owner)))
            goto exit;

        if (OK > (status = SSH_STR_copyStringToPayload(pPayload, payloadLength, pBufIndex, pATTR->group)))
            goto exit;
    }

    if (flags & SSH_FILEXFER_ATTR_PERMISSIONS)
        if (OK > (status = SSHC_UTILS_setInteger(pPayload, payloadLength, pBufIndex, pATTR->permissions)))
            goto exit;

    if (3 < version)
    {
        if (flags & SSH_FILEXFER_ATTR_ACCESSTIME)
        {
            if (OK > (status = SSHC_UTILS_setInteger64(pPayload, payloadLength, pBufIndex, &pATTR->atime)))
                goto exit;

            if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
                if (OK > (status = SSHC_UTILS_setInteger(pPayload, payloadLength, pBufIndex, pATTR->atime_nseconds)))
                    goto exit;
        }

        if (flags & SSH_FILEXFER_ATTR_CREATETIME)
        {
            if (OK > (status = SSHC_UTILS_setInteger64(pPayload, payloadLength, pBufIndex, &pATTR->createtime)))
                goto exit;

            if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
                if (OK > (status = SSHC_UTILS_setInteger(pPayload, payloadLength, pBufIndex, pATTR->createtime_nseconds)))
                    goto exit;
        }

        if (flags & SSH_FILEXFER_ATTR_MODIFYTIME)
        {
            if (OK > (status = SSHC_UTILS_setInteger64(pPayload, payloadLength, pBufIndex, &pATTR->mtime)))
                goto exit;

            if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
                if (OK > (status = SSHC_UTILS_setInteger(pPayload, payloadLength, pBufIndex, pATTR->mtime_nseconds)))
                    goto exit;
        }
    }
    else
    {
        if (flags & SSH_FILEXFER_ATTR_ACCESSTIME)
        {
            if (OK > (status = SSHC_UTILS_setInteger(pPayload, payloadLength, pBufIndex, LOW_U8(pATTR->atime))))
                goto exit;

            if (OK > (status = SSHC_UTILS_setInteger(pPayload, payloadLength, pBufIndex, LOW_U8(pATTR->mtime))))
                goto exit;
        }
    }

    if (flags & SSH_FILEXFER_ATTR_ACL)
        if (OK > (status = SSH_STR_copyStringToPayload(pPayload, payloadLength, pBufIndex, pATTR->acl)))
            goto exit;

exit:
#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSHC, "setAttr: status = ", status);
#endif

    return status;

} /* setAttr */


/*------------------------------------------------------------------*/

/*
 * payloadLength must include 1 byte for the packet type field
 */
static void
setupFtpMessageHeader(ubyte *pMessage, ubyte4 mesgType, ubyte4 payloadLength)
{
    pMessage[0] = (ubyte)(payloadLength >> 24);
    pMessage[1] = (ubyte)(payloadLength >> 16);
    pMessage[2] = (ubyte)(payloadLength >> 8);
    pMessage[3] = (ubyte)(payloadLength);

    pMessage[4] = (ubyte)mesgType;
} /* setupFtpMessageHeader */


/*------------------------------------------------------------------*/

static MSTATUS
sendFtpMessage(sshClientContext *pContextSSH, ubyte *pMessage, ubyte4 mesgLen)
{
    ubyte4  numBytesWritten = 0;
    MSTATUS status;

    if (OK <= (status = SSHC_SESSION_sendMessage(pContextSSH, pMessage, mesgLen, &numBytesWritten)))
    {
        /* verify write completed */
        if (mesgLen != numBytesWritten)
            status = ERR_SFTP_MESG_FRAGMENTED;
    }

#ifdef __ENABLE_ALL_DEBUGGING__
    DUMP_MESG_sftpMessage(4 + pMessage, mesgLen - 4, TRUE);
#endif /* __ENABLE_ALL_DEBUGGING__ */

    return status;
} /* sendFtpMessage */


/*------------------------------------------------------------------*/

static MSTATUS
sendFtpHello(sshClientContext *pContextSSH)
{
#define SFTP_VERSION_FIELD_SIZE 4
#define SFTP_HELLO_SIZE_TOTAL   SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE + SFTP_VERSION_FIELD_SIZE

    MSTATUS status;
    ubyte helloBuff[SFTP_HELLO_SIZE_TOTAL];
    ubyte4 bufIndex = 0;

    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    setupFtpMessageHeader(helloBuff, SSH_FXP_INIT,
                            SSH_FTP_PACKET_TYPE_FIELD_SIZE + SFTP_VERSION_FIELD_SIZE);
    bufIndex += SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE;

    /* set data -- client sftp version */
    if (0 > (status = SSHC_UTILS_setInteger(helloBuff, SFTP_HELLO_SIZE_TOTAL, &bufIndex, SSHC_SFTP_CLIENT_VERSION)))
        goto exit;

    status = sendFtpMessage(pContextSSH, helloBuff, SFTP_HELLO_SIZE_TOTAL);

exit:
    return status;

} /* sendFtpHello */


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSHC_FTP_SendFTPHello(sbyte4 connectionInstance)
{
    sshcConnectDescr *pDescr;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
        return ERR_SESSION;

    return sendFtpHello(pDescr->pContextSSH);

} /* SSHC_FTP_SendFTPHello */


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
SSHC_FTP_handleFtpVersion(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    ubyte4  bufIndex      = 0;
    ubyte4  serverVersion = 0;
    MSTATUS status;

    if ((NULL == pContextSSH) || (NULL == pNewMesg))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* !!!! are we expecting a version number? */

    /* skip past length and type */
    if (OK > (status = SSHC_UTILS_getInteger(pNewMesg, newMesgLen, &bufIndex, &serverVersion)))
        goto exit;

    /* check sftp version (we support versions 2-4) */
    if (MOCANA_SSC_FTP_LOW_VER > serverVersion)
    {
        /* don't support older versions, we need to exit */
        DIGICERT_log(MOCANA_SSH, LS_WARNING, (sbyte *)"Server SFTP/SCP version unsupported, please upgrade server software.");

        status = ERR_SFTP_UNSUPPORTED_VERSION;
        goto exit;
    }
    else
    {
        SSH_FTP_VERSION(pContextSSH) = (serverVersion > SSHC_SFTP_CLIENT_VERSION) ? SSHC_SFTP_CLIENT_VERSION : serverVersion;

        if (NULL != SSHC_sshClientSettings()->funcPtrOpenSftp)
            if (OK > (status = (SSHC_sshClientSettings()->funcPtrOpenSftp)(pContextSSH->connectionInstance, SSH_SESSION_OPEN_SFTP, pNewMesg, newMesgLen)))
                goto exit;

        SSH_SESSION_STATE(pContextSSH) = kSftpOpenState;
        pContextSSH->sessionState.isShellActive = SSHC_SFTP_SESSION_ESTABLISHED;
    }

exit:
    return status;

} /* SSHC_FTP_handleFtpVersion */


/*------------------------------------------------------------------*/

static sftpcFileHandleDescr*
getUnusedHandleDescr(sshClientContext *pContextSSH)
{
    sftpcFileHandleDescr *p_sftpFileHandleDescr;
    sftpcFileHandleDescr *pRet = NULL;
    sbyte4 i;

    for (i = SFTP_NUM_HANDLES, p_sftpFileHandleDescr = SSH_FTP_FILE_HANDLE_TABLE(pContextSSH);
         0 < i; i--, p_sftpFileHandleDescr++)
    {
        if (!p_sftpFileHandleDescr->isFileHandleInUse)
        {
            /* clear out previous settings */
            DIGI_MEMSET((ubyte *)p_sftpFileHandleDescr, 0x00, sizeof(sftpcFileHandleDescr));

            p_sftpFileHandleDescr->isFileHandleInUse = TRUE;
            pRet = p_sftpFileHandleDescr;
            break;
        }
    }

    return pRet;

} /* getUnusedHandleDescr */


/*------------------------------------------------------------------*/

static sftpcFileHandleDescr*
findHandleDescrFromHandle(sshClientContext *pContextSSH, sshStringBuffer* pFindHandle)
{
    sftpcFileHandleDescr *p_sftpFileHandleDescr;
    sftpcFileHandleDescr *pRet = NULL;
    sbyte4  memCmp;
    sbyte4 i;

    if (NULL == pFindHandle)
        goto exit;

    for (i = SFTP_NUM_HANDLES, p_sftpFileHandleDescr = SSH_FTP_FILE_HANDLE_TABLE(pContextSSH);
         0 < i; i--, p_sftpFileHandleDescr++)
    {
        if (p_sftpFileHandleDescr->isFileHandleInUse &&
                (NULL != ((sshStringBuffer *)p_sftpFileHandleDescr->pHandleName)) &&
                (pFindHandle->stringLen == ((sshStringBuffer *)p_sftpFileHandleDescr->pHandleName)->stringLen) &&
                (OK == DIGI_MEMCMP(pFindHandle->pString, ((sshStringBuffer *)p_sftpFileHandleDescr->pHandleName)->pString,
                              pFindHandle->stringLen, &memCmp)) &&
                (0 == memCmp))
        {
            pRet = p_sftpFileHandleDescr;
            break;
        }
    }

exit:
    return pRet;

} /* findHandleDescrFromHandle */


/*------------------------------------------------------------------*/

static sftpcFileHandleDescr*
findHandleDescrFromRequestID(sshClientContext *pContextSSH, ubyte4 requestID)
{
    sftpcFileHandleDescr *p_sftpFileHandleDescr;
    sftpcFileHandleDescr *pRet = NULL;
    sbyte4 i;

    for (i = SFTP_NUM_HANDLES, p_sftpFileHandleDescr = SSH_FTP_FILE_HANDLE_TABLE(pContextSSH);
         0 < i; i--, p_sftpFileHandleDescr++)
    {
        if (p_sftpFileHandleDescr->isFileHandleInUse && (p_sftpFileHandleDescr->requestID == requestID))
        {
            pRet = p_sftpFileHandleDescr;
            break;
        }
    }

    return pRet;

} /* findHandleDescrFromRequestID */


/*------------------------------------------------------------------*/

static void
markHandleDescrRequestComplete(sftpcFileHandleDescr* p_sftpFileHandleDescr)
{
    if (p_sftpFileHandleDescr)
    {
        p_sftpFileHandleDescr->requestID = 0;
        p_sftpFileHandleDescr->request = 0;
    }

} /* markHandleDescrRequestComplete */


/*------------------------------------------------------------------*/

static void
markHandleDescrUnused(sftpcFileHandleDescr* p_sftpFileHandleDescr)
{
    if (p_sftpFileHandleDescr)
    {
        sshStringBuffer *pStr = (sshStringBuffer*)(p_sftpFileHandleDescr->pHandleName);

        p_sftpFileHandleDescr->clientWrtLoc = 0;
        p_sftpFileHandleDescr->cookie = 0;
        SSH_STR_freeStringBuffer(&pStr);
        p_sftpFileHandleDescr->pHandleName = NULL;
        p_sftpFileHandleDescr->isFileHandleInUse = FALSE;
    }

} /* markHandleDescrUnused */


/*------------------------------------------------------------------*/

static MSTATUS
fileClosedComplete(sbyte4 connectionInstance, sftpcFileHandleDescr* p_sftpFileHandleDescr)
{
    MSTATUS status = OK;

    if (NULL == p_sftpFileHandleDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != SSHC_sftpClientSettings()->funcPtrCloseFileUpcall)
    {
        status = (SSHC_sftpClientSettings()->funcPtrCloseFileUpcall)(connectionInstance, p_sftpFileHandleDescr);
    }

    markHandleDescrRequestComplete(p_sftpFileHandleDescr);
    markHandleDescrUnused(p_sftpFileHandleDescr);

exit:
    return status;

} /* fileClosedComplete */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_sendWrite(sshClientContext *pContextSSH, sshStringBuffer* pHandle)
{
    sftpcFileHandleDescr *p_sftpFileHandleDescr;
    ubyte*  pBuffer = NULL;
    ubyte4  buflen, rqstheadlen, datalen;
    ubyte4  bufIndex = 0;
    ubyte8  offset;      /* note we don't actually support > 4G files */
    ubyte4  rqstID;
    MSTATUS status = OK;

    if ((NULL == pContextSSH) || (NULL == pHandle))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    rqstID = NEW_REQUEST_ID();

    if (NULL == (p_sftpFileHandleDescr = findHandleDescrFromHandle(pContextSSH, pHandle)))
    {
        status = ERR_FILE_WRITE_FAILED;
        goto exit;
    }

    datalen = p_sftpFileHandleDescr->writeBufferSize - p_sftpFileHandleDescr->clientWrtLoc;

    /* if all pending data written, get some more */
    if ((0 == datalen) && (NULL != SSHC_sftpClientSettings()->funcPtrWriteFileUpcall))
    {
        p_sftpFileHandleDescr->clientWrtLoc = 0;

        status = (SSHC_sftpClientSettings()->funcPtrWriteFileUpcall)(pContextSSH->connectionInstance, p_sftpFileHandleDescr);

        if (SSH_FTP_OK != status)
            goto exit;

        datalen = p_sftpFileHandleDescr->writeBufferSize;
    }

    if (0 == datalen)
    {
        status = SSH_FTP_EOF;   /* NOT AN ERROR! */
        goto exit;              /* time to close */
    }

    if (datalen > SSHC_SYNC_BUFFER_SIZE)
        datalen = SSHC_SYNC_BUFFER_SIZE;

    rqstheadlen = SSH_FTP_PACKET_TYPE_FIELD_SIZE +
              SSH_FTP_REQUEST_ID_FIELD_SIZE +
              pHandle->stringLen +
              8 +
              4 +
              SSH_FTP_PACKET_LENGTH_FIELD_SIZE;

    if (rqstheadlen > pContextSSH->sessionState.windowSize)
        return OK; /* try again later */

    if (datalen > (pContextSSH->sessionState.windowSize - rqstheadlen))
        datalen = pContextSSH->sessionState.windowSize - rqstheadlen;

    buflen = rqstheadlen + datalen;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pBuffer, SSH_FXP_WRITE, buflen - SSH_FTP_PACKET_LENGTH_FIELD_SIZE);
    bufIndex += SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE;

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, rqstID)))
        goto exit;

    if (0 > (status = DIGI_MEMCPY(pBuffer + bufIndex, pHandle->pString, pHandle->stringLen)))
        goto exit;

    bufIndex += pHandle->stringLen;

    U8INIT(offset, 0, (ubyte4)p_sftpFileHandleDescr->writeLocation);

    if (0 > (status = SSHC_UTILS_setInteger64(pBuffer, buflen, &bufIndex, &offset)))
        goto exit;

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, datalen)))
        goto exit;

#if 0
    DEBUG_ERROR(DEBUG_SSHC, "SSHC_FTP_sendWrite: offset = ", p_sftpFileHandleDescr->writeLocation);
    DEBUG_ERROR(DEBUG_SSHC, "SSHC_FTP_sendWrite: writing = ", datalen);
#endif

    if (0 > (status = DIGI_MEMCPY(pBuffer + bufIndex, (ubyte *)(p_sftpFileHandleDescr->pWriteBuffer + p_sftpFileHandleDescr->clientWrtLoc), datalen)))
        goto exit;

    bufIndex += datalen;

    if (bufIndex != buflen)
    {
        status = ERR_PAYLOAD;
        goto exit;
    }

    p_sftpFileHandleDescr->requestID = rqstID;
    p_sftpFileHandleDescr->request = SSH_FXP_WRITE;

    if (0 > (status = sendFtpMessage(pContextSSH, pBuffer, buflen)))
        goto exit;

    p_sftpFileHandleDescr->writeLocation += datalen;
    p_sftpFileHandleDescr->clientWrtLoc += datalen;

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* SSHC_FTP_sendWrite */


/*------------------------------------------------------------------*/

static MSTATUS
sendOpenFileRequest(sshClientContext *pContextSSH, ubyte* pFName, ubyte4 pFNameLen,
                    ubyte4 pflags, ATTRClient *pAttr, sftpcFileHandleDescr **ppFHD)
{
    sftpcFileHandleDescr *p_sftpFileHandleDescr;
    ubyte4  buflen, rqstlen;
    ubyte4  bufIndex = 0;
    ubyte*  pBuffer = NULL;
    ubyte4  rqstID;
    MSTATUS status;

    if ((NULL == pContextSSH) || (NULL == pFName) || (NULL == pAttr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    rqstID = NEW_REQUEST_ID();
    *ppFHD = NULL;

    /* read or write, not both */
    if (((SSH_FXF_READ | SSH_FXF_WRITE) == (pflags & (SSH_FXF_READ | SSH_FXF_WRITE))) || (pflags & SSH_FXF_TEXT))
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    rqstlen = SSH_FTP_PACKET_TYPE_FIELD_SIZE +
              SSH_FTP_REQUEST_ID_FIELD_SIZE +
              4 + pFNameLen +
              SSH_FTP_REQUEST_PFLAGS_SIZE +
              getAttrLength(pAttr, SSH_FTP_VERSION(pContextSSH));

    buflen =  SSH_FTP_PACKET_LENGTH_FIELD_SIZE +
              rqstlen;

    if (NULL == (pBuffer = MALLOC(buflen))) {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pBuffer, SSH_FXP_OPEN, rqstlen);

    bufIndex += SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE;

    if (NULL == (p_sftpFileHandleDescr = getUnusedHandleDescr(pContextSSH)))
    {
        status = ERR_SFTP_TOO_MANY_OPEN_HANDLES;
        goto exit;
    }

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, rqstID)))
        goto exit;

    if (0 > (status = SSH_STR_copyBytesAsStringToPayload(pBuffer, buflen, &bufIndex, pFName, pFNameLen)))
        goto exit;

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, pflags)))
        goto exit;

    if (0 > (status = setAttr(pBuffer, buflen, &bufIndex, pAttr, SSH_FTP_VERSION(pContextSSH))))
        goto exit;

    p_sftpFileHandleDescr->requestID = rqstID;
    p_sftpFileHandleDescr->request = SSH_FXP_OPEN;

    status = sendFtpMessage(pContextSSH, pBuffer, buflen);
    *ppFHD = p_sftpFileHandleDescr;

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* sendOpenFileRequest */


/*------------------------------------------------------------------*/

/*
 * args:
 *      pString = file name
 *      stringLen = file name length
 *      param1 = one of (SFTP_OPEN_FILE_READ_BINARY, SFTP_OPEN_FILE_WRITE_BINARY)
 *      ppFHD = if successful request sent, returns associated sftpcFileHandleDescr.
 */
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSHC_FTP_OpenFileRequest(sbyte4 connectionInstance, sshcSFTPCommonArgs *args)
{
    ubyte4  pflags;
    sshcConnectDescr* pDescr;
    MSTATUS status;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    pflags = (args->param1 == SFTP_OPEN_FILE_WRITE_BINARY) ? (SSH_FXF_WRITE|SSH_FXF_CREAT|SSH_FXF_TRUNC) : SSH_FXF_READ;

    status = sendOpenFileRequest(pDescr->pContextSSH, args->pString, args->stringLen,
                    pflags, &clientSFTPOpenFileATTR, (sftpcFileHandleDescr**)&args->pPtr);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static intBoolean funcFileOpenTest(sshcConnectDescr *pDescr, void *cookie)
{
    /* this is tested for NULL in DoOpenFile */
    sftpcFileHandleDescr *p_sftpFileHandleDescr = (sftpcFileHandleDescr*)cookie;
    MOC_UNUSED(pDescr);

    return ((NULL != p_sftpFileHandleDescr->pHandleName) ||
            (SSH_FTP_OK != p_sftpFileHandleDescr->requestStatusResponse));
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_openFile(sbyte4 connectionInstance, ubyte* pFName, ubyte4 fileNameLen,
              sbyte4 readOrWrite, sftpcFileHandleDescr **pp_retSftpFileHandleDescr)
{
    sshcSFTPCommonArgs args;
    MSTATUS status;

    if ((NULL == pFName) || (NULL == pp_retSftpFileHandleDescr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pp_retSftpFileHandleDescr = NULL;

    args.pString   = pFName;         /* sbyte* for open, sshStringBuffer* most other times */
    args.stringLen = fileNameLen;    /* unused if pString is sshStringBuffer */
    args.param1    = readOrWrite;    /* varies */
    args.pPtr      = NULL;           /* varies */

    if (0 > (status = SSHC_FTP_OpenFileRequest(connectionInstance, &args)))
        goto exit;

    if (NULL == args.pPtr)
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    status = SSHC_doProtocolCommon(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER,
                                   funcFileOpenTest, args.pPtr);

    *pp_retSftpFileHandleDescr = args.pPtr;

exit:
    return status;

} /* SSHC_openFile */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_handleStatus(sshClientContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4                  bufIndex = 0;
    sftpcFileHandleDescr*   p_sftpFileHandleDescr = NULL;
    ubyte4                  id;
    ubyte4                  statusCode;
    sshStringBuffer*        message = NULL;
    sshStringBuffer*        language = NULL;
    int                     result;
    ubyte4                  request;
    MSTATUS                 status;

    if ((NULL == pContextSSH) || (NULL == pPayload))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* potentially a sftpcFileHandleDescr can get stuck in use.
     * We need to timestamp the sftpcFileHandleDescr entries, and scan
     * occasionally or reuse old ones.
     */
    if (0 > (status = SSHC_UTILS_getInteger(pPayload, payloadLength, &bufIndex, &id)))
    {
        goto exit;
    }

    if (NULL == (p_sftpFileHandleDescr = findHandleDescrFromRequestID(pContextSSH, id)))
    {
        status = ERR_SFTP_BAD_REQUEST_ID;
        goto exit;
    }

    p_sftpFileHandleDescr->response = SSH_FXP_STATUS;

    if (0 > (status = SSHC_UTILS_getInteger(pPayload, payloadLength, &bufIndex, &statusCode)))
    {
        markHandleDescrUnused(p_sftpFileHandleDescr);
        goto exit;
    }

    if (2 < SSH_FTP_VERSION(pContextSSH))
    {
        if (payloadLength >= bufIndex + 8)
        {
            /* 8 == two empty strings */
            if (0 <= (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &message)))
            {
                DEBUG_RELABEL_MEMORY(message);

                status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &language);

                DEBUG_RELABEL_MEMORY(language);
            }
        }
    }
    else if (payloadLength != bufIndex)
    {
        status = ERR_SFTP_MESSAGE_TOO_LONG;
        markHandleDescrUnused(p_sftpFileHandleDescr);
        goto exit;
    }

    if (NULL != SSHC_sftpClientSettings()->funcPtrStatus)
    {
        (SSHC_sftpClientSettings()->funcPtrStatus)(pContextSSH->connectionInstance, statusCode,
                            (NULL != message) ? message->pString : NULL,
                            (NULL != message) ? message->stringLen : 0,
                            (NULL != language) ? language->pString : NULL,
                            (NULL != language) ? language->stringLen : 0);
    }

    request = p_sftpFileHandleDescr->request;
    markHandleDescrRequestComplete(p_sftpFileHandleDescr);  /* maybe need to move later */
    p_sftpFileHandleDescr->requestStatusResponse = statusCode;

    switch (statusCode)
    {
        case SSH_FTP_OK:
        {
            switch (request)
            {
                case SSH_FXP_WRITE:
                {
                    result = SSHC_FTP_sendWrite(pContextSSH, p_sftpFileHandleDescr->pHandleName);

                    /* OK and EOF are both OK */
                    if (result < 0)
                    {
                        status = ERR_FILE_WRITE_FAILED;
                        markHandleDescrUnused(p_sftpFileHandleDescr);
                        goto exit;
                    }

                    goto exit;
                }

                case SSH_FXP_CLOSE:
                {
                    status = fileClosedComplete(pContextSSH->connectionInstance, p_sftpFileHandleDescr);
                    goto exit;
                }

                default:
                    break;      /* clear the record anyway. */
            }
        }

        case SSH_FTP_EOF:   /* !!!! Probably due to a read at end of file. */
        {
            DEBUG_ERROR(DEBUG_SSHC, "SSHC_FTP_handleStatus: end of file reached, statusCode = ", statusCode);
            break;
        }

        default:
        {
            DEBUG_ERROR(DEBUG_SSHC, "SSHC_FTP_handleStatus: unknown statusCode = ", statusCode);
            break;
        }
    }

exit:
    SSH_STR_freeStringBuffer(&message);
    SSH_STR_freeStringBuffer(&language);

    return status;

} /* SSHC_FTP_handleStatus */



/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_handleHandle(sshClientContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    MSTATUS status;
    ubyte4 bufIndex = 0;
    sftpcFileHandleDescr *p_sftpFileHandleDescr;
    ubyte4 id;
    sshStringBuffer *pHandle = NULL;

    if ((NULL == pContextSSH) || (NULL == pPayload))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* are we expecting a file handle here??? */

    if (0 > (status = SSHC_UTILS_getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    if (NULL == (p_sftpFileHandleDescr = findHandleDescrFromRequestID(pContextSSH, id)))
    {
        status = ERR_SFTP_BAD_REQUEST_ID;
        goto exit;
    }

    p_sftpFileHandleDescr->response = SSH_FXP_HANDLE;

    if (0 > (status = SSH_STR_copyStringFromPayload(pPayload, payloadLength, &bufIndex, &pHandle)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pHandle);

    p_sftpFileHandleDescr->pHandleName = pHandle;
    p_sftpFileHandleDescr->cookie = 0;

    p_sftpFileHandleDescr->readLocation = 0;
    p_sftpFileHandleDescr->writeLocation = 0;

    /*
     * NOTE: If directory operations are added, this routine will
     * need refinement here, since it's assumed that we got here because
     * of a file open request.
     */
    if (NULL != SSHC_sftpClientSettings()->funcPtrOpenFileClientUpcall)
        status = (SSHC_sftpClientSettings()->funcPtrOpenFileClientUpcall)(pContextSSH->connectionInstance, p_sftpFileHandleDescr);

exit:
    return status;

} /* SSHC_FTP_handleHandle */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_sendRead(sshClientContext *pContextSSH, sshStringBuffer* pHandle, ubyte4 readLocation)
{
    sftpcFileHandleDescr *p_sftpFileHandleDescr;
    ubyte*  pBuffer = NULL;
    ubyte4  buflen, rqstlen;
    ubyte4  bufIndex = 0;
    ubyte8  offset;      /* note we don't actually support > 4G files */
    ubyte4  rqstID;
    MSTATUS status;

    if ((NULL == pContextSSH) || (NULL == pHandle))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    rqstID = NEW_REQUEST_ID();

    if (NULL == (p_sftpFileHandleDescr = findHandleDescrFromHandle(pContextSSH, pHandle)))
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

    if (0 == SSHC_SFTP_GetMaxBytesToRead())
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

    /*
     * This code assumes that the entire contents of the read buffer are handled
     * at every read upcall. Note that the readLocation is the location of the
     * file on the server side. Also you should be aware that the
     * sftpcFileHandleDescr->readBuffer is not used -- the data is passed up
     * without intermediate buffering.
     */

    rqstlen = SSH_FTP_PACKET_TYPE_FIELD_SIZE +
              SSH_FTP_REQUEST_ID_FIELD_SIZE +
              pHandle->stringLen +
              8 +
              4;
    buflen  = SSH_FTP_PACKET_LENGTH_FIELD_SIZE +
              rqstlen;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pBuffer, SSH_FXP_READ, rqstlen);
    bufIndex += SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE;

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, rqstID)))
        goto exit;

    if (0 > (status = DIGI_MEMCPY(pBuffer + bufIndex, pHandle->pString, pHandle->stringLen)))
        goto exit;

    bufIndex += pHandle->stringLen;
    U8INIT(offset, 0, readLocation);

    if (0 > (status = SSHC_UTILS_setInteger64(pBuffer, buflen, &bufIndex, &offset)))
        goto exit;

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, SSHC_SFTP_GetMaxBytesToRead())))
        goto exit;

#if 0
    DEBUG_ERROR(DEBUG_SSHC, "SSHC_FTP_sendRead: offset = ", readLocation);
    DEBUG_ERROR(DEBUG_SSHC, "SSHC_FTP_sendRead: requesting = ", SSHC_SFTP_GetMaxBytesToRead());
#endif

    p_sftpFileHandleDescr->requestID = rqstID;
    p_sftpFileHandleDescr->request = SSH_FXP_READ;

    status = sendFtpMessage(pContextSSH, pBuffer, buflen);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* SSHC_FTP_sendRead */


/*------------------------------------------------------------------*/

static intBoolean
funcFileReadFileTest(sshcConnectDescr *pDescr, void *cookie)
{
    sftpcFileHandleDescr *p_sftpFileHandleDescr = (sftpcFileHandleDescr*)cookie;
    MOC_UNUSED(pDescr);

    return (SSH_FTP_OK != p_sftpFileHandleDescr->requestStatusResponse);
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_readFile(sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    sshcConnectDescr* pDescr;
    MSTATUS status;

    if (NULL == p_sftpFileHandleDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (NULL == (p_sftpFileHandleDescr = findHandleDescrFromHandle(pDescr->pContextSSH, p_sftpFileHandleDescr->pHandleName)))
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

    if (0 > (status = SSHC_FTP_sendRead(pDescr->pContextSSH, (sshStringBuffer*)p_sftpFileHandleDescr->pHandleName, p_sftpFileHandleDescr->readLocation)))
        goto exit;

    status = SSHC_doProtocolCommon(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER,
                                   funcFileReadFileTest, p_sftpFileHandleDescr);

exit:
    return status;

} /* SSHC_readFile */


/*------------------------------------------------------------------*/

static intBoolean
funcFileWriteFileTest(sshcConnectDescr *pDescr, void *cookie)
{
    sftpcFileHandleDescr *p_sftpFileHandleDescr = (sftpcFileHandleDescr*)cookie;
    MOC_UNUSED(pDescr);

    return ((0 == p_sftpFileHandleDescr->writeBufferSize) ||
            (SSH_FTP_OK != p_sftpFileHandleDescr->requestStatusResponse));
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_writeFile(sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    sshcConnectDescr* pDescr;
    MSTATUS status;

    if (NULL == p_sftpFileHandleDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (NULL == (p_sftpFileHandleDescr = findHandleDescrFromHandle(pDescr->pContextSSH, p_sftpFileHandleDescr->pHandleName)))
    {
        status = ERR_FILE_WRITE_FAILED;
        goto exit;
    }

    /*
     * if we get through the sends status will == SSH_FTP_EOF, and we don't want to
     * call SSHC_doProtocolCommon() because likely it well get stuck pending.
     */
    if (0 != (status = SSHC_FTP_sendWrite(pDescr->pContextSSH, (sshStringBuffer*)p_sftpFileHandleDescr->pHandleName)))
        goto exit;

    status = SSHC_doProtocolCommon(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER,
                                   funcFileWriteFileTest, p_sftpFileHandleDescr);

exit:
    return status;

} /* SSHC_writeFile */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_handleData(sshClientContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    sftpcFileHandleDescr*   p_sftpFileHandleDescr;
    ubyte4                  bufIndex = 0;
    ubyte4                  id;
    ubyte4                  readBufferSize;
    MSTATUS                 status;

    if ((NULL == pContextSSH) || (NULL == pPayload))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 > (status = SSHC_UTILS_getInteger(pPayload, payloadLength, &bufIndex, &id)))
    {
        goto exit;
    }

    if (NULL == (p_sftpFileHandleDescr = findHandleDescrFromRequestID(pContextSSH, id)))
    {
        status = ERR_SFTP_BAD_REQUEST_ID;
        goto exit;
    }

    p_sftpFileHandleDescr->response = SSH_FXP_DATA;

    /* is this worth checking on? */
    if (p_sftpFileHandleDescr->requestID != id)
    {
        status = ERR_SFTP_MALFORMED_MESSAGE;
        goto exit;
    }

    switch (p_sftpFileHandleDescr->request)
    {
        case SSH_FXP_READ:
        {
            if (0 > (status = SSHC_UTILS_getInteger(pPayload, payloadLength, &bufIndex, &readBufferSize)))
                goto exit;

            if ((readBufferSize > payloadLength) || (readBufferSize + bufIndex) > payloadLength)
            {
                status = ERR_SFTP_MALFORMED_MESSAGE;
                goto exit;
            }

            p_sftpFileHandleDescr->readBufferSize = readBufferSize;    /* overloading server field, kind of misnomer */

            p_sftpFileHandleDescr->pReadBuffer = (sbyte *)pPayload + bufIndex;

            /* now commit data */
            if (NULL != SSHC_sftpClientSettings()->funcPtrReadFileUpcall)
                status = (SSHC_sftpClientSettings()->funcPtrReadFileUpcall)(pContextSSH->connectionInstance, p_sftpFileHandleDescr);

            if (SSH_FTP_OK != status)
            {
                p_sftpFileHandleDescr->requestStatusResponse = status;
                goto exit;
            }

            /* send next read request */
            if (OK > (status = SSHC_FTP_sendRead(pContextSSH, p_sftpFileHandleDescr->pHandleName, p_sftpFileHandleDescr->readLocation + readBufferSize)))
                goto exit;

            p_sftpFileHandleDescr->readLocation += readBufferSize;

            break;
        }
        default:
        {
            status = ERR_SFTP_BAD_REQUEST_ID;
            break;
        }
    }

exit:
    return status;

} /* SSHC_FTP_handleData */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_handleName(sshClientContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    sftpcFileHandleDescr*   p_sftpFileHandleDescr;
    ubyte4                  bufIndex = 0;
    ubyte4                  id;
    ubyte4                  count;
    MSTATUS                 status;

    if ((NULL == pContextSSH) || (NULL == pPayload))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 > (status = SSHC_UTILS_getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    if (NULL == (p_sftpFileHandleDescr = findHandleDescrFromRequestID(pContextSSH, id)))
    {
        status = ERR_SFTP_BAD_REQUEST_ID;
        goto exit;
    }

    p_sftpFileHandleDescr->response = SSH_FXP_NAME;

    /* is this worth checking on? */
    if (p_sftpFileHandleDescr->requestID != id)
    {
        status = ERR_SFTP_MALFORMED_MESSAGE;
        goto exit;
    }

    if (0 > (status = SSHC_UTILS_getInteger(pPayload, payloadLength, &bufIndex, &count)))
        goto exit;

    if ((SSH_FXP_REALPATH == p_sftpFileHandleDescr->request) && (1 != count))
    {
        /* for realpath, there should *always* be only one item */
        status = ERR_SFTP_MALFORMED_MESSAGE;
        goto exit;
    }

    switch (p_sftpFileHandleDescr->request)
    {
        case SSH_FXP_READDIR:
        {
            /* prevent a memory leak */
            if (p_sftpFileHandleDescr->pFileListingPayload)
                FREE(p_sftpFileHandleDescr->pFileListingPayload);

            /* clone the buffer */
            if (NULL == (p_sftpFileHandleDescr->pFileListingPayload = MALLOC(payloadLength - bufIndex)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            DIGI_MEMCPY(p_sftpFileHandleDescr->pFileListingPayload, bufIndex + pPayload, payloadLength - bufIndex);
            p_sftpFileHandleDescr->fileListingCount = count;
            p_sftpFileHandleDescr->fileListingPosition = 0;
            p_sftpFileHandleDescr->fileListingBufIndex = 0;
            p_sftpFileHandleDescr->fileListingPayloadLen = payloadLength - bufIndex;

            break;
        }

        case SSH_FXP_REALPATH:
        {
            sshStringBuffer *pFilename = NULL;

            /* free previous run's data to prevent a memory leak */
            SSH_STR_freeStringBuffer((sshStringBuffer **)&p_sftpFileHandleDescr->pFilename);

            if (OK > (status = freeAttr(p_sftpFileHandleDescr->pATTR)))
                goto exit;

            /* extract filename / path */
            if (0 > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pFilename)))
            {
                if(NULL != pFilename)
                    SSH_STR_freeStringBuffer(&pFilename);
                goto exit;
            }

            p_sftpFileHandleDescr->pFilename = (void *)pFilename;

            DEBUG_RELABEL_MEMORY(pFilename);

            /* plus v3 long name */
            if (3 >= SSH_FTP_VERSION(pContextSSH))
            {
                sshStringBuffer *pTmpLongName = NULL;

                if (0 > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pTmpLongName)))
                {
                    if(NULL != pTmpLongName)
                        SSH_STR_freeStringBuffer(&pTmpLongName);
                    goto exit;
                }

                SSH_STR_freeStringBuffer(&pTmpLongName);
            }

            /* prevent a memory leak */
            if (p_sftpFileHandleDescr->pFileListingPayload)
                FREE(p_sftpFileHandleDescr->pFileListingPayload);

            /* clone the buffer */
            if (NULL == (p_sftpFileHandleDescr->pFileListingPayload = MALLOC(payloadLength - bufIndex)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            DIGI_MEMCPY(p_sftpFileHandleDescr->pFileListingPayload, bufIndex + pPayload, payloadLength - bufIndex);
            p_sftpFileHandleDescr->fileListingCount = 1;
            p_sftpFileHandleDescr->fileListingPosition = 0;
            p_sftpFileHandleDescr->fileListingBufIndex = 0;
            p_sftpFileHandleDescr->fileListingPayloadLen = payloadLength - bufIndex;

            break;
        }

        default:
        {
            status = ERR_SFTP_BAD_REQUEST_ID;
            break;
        }
    }

exit:
    return status;

} /* SSHC_FTP_handleName */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_handleAttrs(sshClientContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    sftpcFileHandleDescr*   p_sftpFileHandleDescr;
    ubyte4                  bufIndex = 0;
    ubyte4                  id;
    MSTATUS                 status;

    if ((NULL == pContextSSH) || (NULL == pPayload))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 > (status = SSHC_UTILS_getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    if (NULL == (p_sftpFileHandleDescr = findHandleDescrFromRequestID(pContextSSH, id)))
    {
        status = ERR_SFTP_BAD_REQUEST_ID;
        goto exit;
    }

    p_sftpFileHandleDescr->response = SSH_FXP_ATTRS;

    /* is this worth checking on? */
    if (p_sftpFileHandleDescr->requestID != id)
    {
        status = ERR_SFTP_MALFORMED_MESSAGE;
        goto exit;
    }

    /* Process ATTR */
    /* free previous run's data to prevent a memory leak */
    if (OK > (status = freeAttr(p_sftpFileHandleDescr->pATTR)))
        goto exit;

    /* prevent a memory leak */
    if (p_sftpFileHandleDescr->pFileListingPayload)
        FREE(p_sftpFileHandleDescr->pFileListingPayload);

    /* clone the buffer */
    if (NULL == (p_sftpFileHandleDescr->pFileListingPayload = MALLOC(payloadLength - bufIndex)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(p_sftpFileHandleDescr->pFileListingPayload, bufIndex + pPayload, payloadLength - bufIndex);
    p_sftpFileHandleDescr->fileListingCount = 1;
    p_sftpFileHandleDescr->fileListingPosition = 0;
    p_sftpFileHandleDescr->fileListingBufIndex = 0;
    p_sftpFileHandleDescr->fileListingPayloadLen = payloadLength - bufIndex;

exit:
    return status;

} /* SSHC_FTP_handleAttrs */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_freeHandle(sftpcFileHandleDescr* p_sftpFileHandleDescr)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (p_sftpFileHandleDescr)
    {
        if (NULL != (p_sftpFileHandleDescr)->pATTR)
        {
            if (NULL != ((p_sftpFileHandleDescr)->pATTR)->owner)
            {
                FREE(((p_sftpFileHandleDescr)->pATTR)->owner);
                ((p_sftpFileHandleDescr)->pATTR)->owner = NULL;
            }
            if (NULL != ((p_sftpFileHandleDescr)->pATTR)->acl)
            {
                FREE(((p_sftpFileHandleDescr)->pATTR)->acl);
                ((p_sftpFileHandleDescr)->pATTR)->acl = NULL;
            }
            if (NULL != ((p_sftpFileHandleDescr)->pATTR)->group)
            {
                FREE(((p_sftpFileHandleDescr)->pATTR)->group);
                ((p_sftpFileHandleDescr)->pATTR)->group = NULL;
            }
            FREE((p_sftpFileHandleDescr)->pATTR);
            (p_sftpFileHandleDescr)->pATTR = NULL;
        }

        if (NULL != (p_sftpFileHandleDescr)->pFileListingPayload)
        {
            FREE((p_sftpFileHandleDescr)->pFileListingPayload);
            (p_sftpFileHandleDescr)->pFileListingPayload = NULL;
        }

        SSH_STR_freeStringBuffer((sshStringBuffer **)&((p_sftpFileHandleDescr)->pFilename));
        SSH_STR_freeStringBuffer((sshStringBuffer **)&((p_sftpFileHandleDescr)->pHandleName));

        markHandleDescrRequestComplete(p_sftpFileHandleDescr);
        markHandleDescrUnused(p_sftpFileHandleDescr);

        status = OK;
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
sendFileClose(sshClientContext *pContextSSH, sshStringBuffer* pHandle)
{
    sftpcFileHandleDescr*   p_sftpFileHandleDescr = NULL;
    ubyte*                  pBuffer = NULL;
    ubyte4                  buflen, rqstlen;
    ubyte4                  bufIndex = 0;
    ubyte4                  rqstID = NEW_REQUEST_ID();
    MSTATUS                 status;

    if (NULL == pHandle)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (p_sftpFileHandleDescr = findHandleDescrFromHandle(pContextSSH, pHandle)))
    {
        status = ERR_FILE_WRITE_FAILED;
        goto fail;
    }

    rqstlen = SSH_FTP_PACKET_TYPE_FIELD_SIZE +
              SSH_FTP_REQUEST_ID_FIELD_SIZE +
              pHandle->stringLen;
    buflen  = SSH_FTP_PACKET_LENGTH_FIELD_SIZE +
              rqstlen;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto fail;
    }

    setupFtpMessageHeader(pBuffer, SSH_FXP_CLOSE, rqstlen);
    bufIndex += SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE;

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, rqstID)))
        goto fail;

    if (0 > (status = DIGI_MEMCPY(pBuffer + bufIndex, pHandle->pString, pHandle->stringLen)))
        goto fail;
    bufIndex += pHandle->stringLen;


    p_sftpFileHandleDescr->requestID = rqstID;
    p_sftpFileHandleDescr->request = SSH_FXP_CLOSE;

    if (OK > (status = sendFtpMessage(pContextSSH, pBuffer, buflen)))
        goto fail;

    goto exit;

fail:
    /* trying to send close, but fail. Call the close upcall,
     * clear the record anyway. Better than a leak.
     */
    if (NULL != p_sftpFileHandleDescr)
        fileClosedComplete(pContextSSH->connectionInstance, p_sftpFileHandleDescr);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* sendFileClose */


/*------------------------------------------------------------------*/

static intBoolean
funcFileCloseTest(sshcConnectDescr *pDescr, void *cookie)
{
    /* this is tested for NULL in DoOpenFile */
    sftpcFileHandleDescr *p_sftpFileHandleDescr = (sftpcFileHandleDescr*)cookie;
    MOC_UNUSED(pDescr);

    return ((NULL == p_sftpFileHandleDescr->pHandleName) ||
            (SSH_FTP_OK != p_sftpFileHandleDescr->requestStatusResponse));
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_closeFile(sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    sshcConnectDescr*    pDescr;
    MSTATUS              status;

    if (NULL == p_sftpFileHandleDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (NULL != (p_sftpFileHandleDescr = findHandleDescrFromHandle(pDescr->pContextSSH, p_sftpFileHandleDescr->pHandleName)))
    {
        if (0 > (status = sendFileClose(pDescr->pContextSSH, (sshStringBuffer*)p_sftpFileHandleDescr->pHandleName)))
            goto exit;

        status = SSHC_doProtocolCommon(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER,
                                    funcFileCloseTest, p_sftpFileHandleDescr);
    }
    else
    {
        /* no need to send a close, just free the resource */
        status = SSHC_FTP_freeHandle(p_sftpFileHandleDescr);
    }

exit:
    return status;

} /* SSHC_closeFile */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_sendMakeDir(sshClientContext *pContextSSH,
                     sftpcFileHandleDescr* p_sftpFileHandleDescr,
                     ubyte *pNewDirName, ubyte4 newDirNameLen,
                     ATTRClient *pAttr)
{
    ubyte*  pBuffer = NULL;
    ubyte4  buflen;
    ubyte4  rqstlen;
    ubyte4  bufIndex = 0;
    ubyte4  rqstID;
    MSTATUS status;

    if ((NULL == pContextSSH) || (NULL == p_sftpFileHandleDescr) || (NULL == pNewDirName) || (NULL == pAttr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    rqstID = NEW_REQUEST_ID();

    rqstlen = SSH_FTP_PACKET_TYPE_FIELD_SIZE +
              SSH_FTP_REQUEST_ID_FIELD_SIZE +
              (4 + newDirNameLen) +
              getAttrLength(pAttr, SSH_FTP_VERSION(pContextSSH));

    buflen  = SSH_FTP_PACKET_LENGTH_FIELD_SIZE +
              rqstlen;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pBuffer, SSH_FXP_MKDIR, rqstlen);
    bufIndex += SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE;

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, rqstID)))
        goto exit;

    if (0 > (status = SSH_STR_copyBytesAsStringToPayload(pBuffer, buflen, &bufIndex,
                                                          pNewDirName, newDirNameLen)))
    {
        goto exit;
    }

    if (OK > (status = setAttr(pBuffer, buflen, &bufIndex, pAttr, SSH_FTP_VERSION(pContextSSH))))
        goto exit;

    p_sftpFileHandleDescr->requestID = rqstID;
    p_sftpFileHandleDescr->request   = SSH_FXP_MKDIR;

    status = sendFtpMessage(pContextSSH, pBuffer, buflen);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* SSHC_FTP_sendMakeDir */


/*------------------------------------------------------------------*/

static intBoolean
funcFileMkDirFileTest(sshcConnectDescr *pDescr, void *cookie)
{
    /* this is tested for NULL in DoOpenFile */
    sftpcFileHandleDescr *p_sftpFileHandleDescr = (sftpcFileHandleDescr*)cookie;
    MOC_UNUSED(pDescr);

    return (0 == p_sftpFileHandleDescr->request);
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_mkdir(sbyte4 connectionInstance, ubyte *pNewDirName, ubyte4 newDirNameLen,
           sftpcFileHandleDescr** pp_sftpFileHandleDescr, void *pFuture)
{
    sshcConnectDescr*       pDescr;
    MSTATUS                 status;
    MOC_UNUSED(pFuture);

    if ((NULL == pNewDirName) || (NULL == pp_sftpFileHandleDescr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pp_sftpFileHandleDescr = NULL;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (NULL == (*pp_sftpFileHandleDescr = getUnusedHandleDescr((sshClientContext *)pDescr->pContextSSH)))
    {
        status = ERR_SFTP_TOO_MANY_OPEN_HANDLES;
        goto exit;
    }

    if (OK > (status = SSHC_FTP_sendMakeDir(pDescr->pContextSSH, *pp_sftpFileHandleDescr, pNewDirName, newDirNameLen, &clientSFTPMakeDirATTR)))
        goto exit;

    status = SSHC_doProtocolCommon(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER,
                                   funcFileMkDirFileTest, *pp_sftpFileHandleDescr);

exit:
    if (OK > status)
        SSHC_freeHandle(connectionInstance, pp_sftpFileHandleDescr);

    return status;

} /* SSHC_mkdir */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_sendRemoveDir(sshClientContext *pContextSSH,
                       sftpcFileHandleDescr* p_sftpFileHandleDescr,
                       ubyte *pRemoveDirName, ubyte4 removeDirNameLen)
{
    ubyte*  pBuffer = NULL;
    ubyte4  buflen;
    ubyte4  rqstlen;
    ubyte4  bufIndex = 0;
    ubyte4  rqstID;
    MSTATUS status;

    if ((NULL == pContextSSH) || (NULL == p_sftpFileHandleDescr) || (NULL == pRemoveDirName))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    rqstID = NEW_REQUEST_ID();

    rqstlen = SSH_FTP_PACKET_TYPE_FIELD_SIZE +
              SSH_FTP_REQUEST_ID_FIELD_SIZE +
              (4 + removeDirNameLen);

    buflen  = SSH_FTP_PACKET_LENGTH_FIELD_SIZE +
              rqstlen;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pBuffer, SSH_FXP_RMDIR, rqstlen);
    bufIndex += SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE;

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, rqstID)))
        goto exit;

    if (0 > (status = SSH_STR_copyBytesAsStringToPayload(pBuffer, buflen, &bufIndex,
                                                          pRemoveDirName, removeDirNameLen)))
    {
        goto exit;
    }

    p_sftpFileHandleDescr->requestID = rqstID;
    p_sftpFileHandleDescr->request   = SSH_FXP_RMDIR;

    status = sendFtpMessage(pContextSSH, pBuffer, buflen);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* SSHC_FTP_sendRemoveDir */


/*------------------------------------------------------------------*/

static intBoolean
funcFileRmDirFileTest(sshcConnectDescr *pDescr, void *cookie)
{
    /* this is tested for NULL in DoOpenFile */
    sftpcFileHandleDescr *p_sftpFileHandleDescr = (sftpcFileHandleDescr*)cookie;
    MOC_UNUSED(pDescr);

    return (0 == p_sftpFileHandleDescr->request);
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_rmdir(sbyte4 connectionInstance, ubyte *pRemoveDirName, ubyte4 removeDirNameLen,
           sftpcFileHandleDescr** pp_sftpFileHandleDescr)
{
    sshcConnectDescr*       pDescr;
    MSTATUS                 status;

    if ((NULL == pRemoveDirName) || (NULL == pp_sftpFileHandleDescr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pp_sftpFileHandleDescr = NULL;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (NULL == (*pp_sftpFileHandleDescr = getUnusedHandleDescr((sshClientContext *)pDescr->pContextSSH)))
    {
        status = ERR_SFTP_TOO_MANY_OPEN_HANDLES;
        goto exit;
    }

    if (OK > (status = SSHC_FTP_sendRemoveDir(pDescr->pContextSSH, *pp_sftpFileHandleDescr, pRemoveDirName, removeDirNameLen)))
        goto exit;

    status = SSHC_doProtocolCommon(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER,
                                   funcFileRmDirFileTest, *pp_sftpFileHandleDescr);

exit:
    if (OK > status)
        SSHC_freeHandle(connectionInstance, pp_sftpFileHandleDescr);

    return status;

} /* SSHC_rmdir */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_sendRemoveFile(sshClientContext *pContextSSH,
                        sftpcFileHandleDescr* p_sftpFileHandleDescr,
                        ubyte *pRemoveFileName, ubyte4 removeFileNameLen)
{
    ubyte*  pBuffer = NULL;
    ubyte4  buflen;
    ubyte4  rqstlen;
    ubyte4  bufIndex = 0;
    ubyte4  rqstID;
    MSTATUS status;

    if ((NULL == pContextSSH) || (NULL == p_sftpFileHandleDescr) || (NULL == pRemoveFileName))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    rqstID = NEW_REQUEST_ID();

    rqstlen = SSH_FTP_PACKET_TYPE_FIELD_SIZE +
              SSH_FTP_REQUEST_ID_FIELD_SIZE +
              (4 + removeFileNameLen);

    buflen  = SSH_FTP_PACKET_LENGTH_FIELD_SIZE +
              rqstlen;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pBuffer, SSH_FXP_REMOVE, rqstlen);
    bufIndex += SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE;

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, rqstID)))
        goto exit;

    if (0 > (status = SSH_STR_copyBytesAsStringToPayload(pBuffer, buflen, &bufIndex,
                                                          pRemoveFileName, removeFileNameLen)))
    {
        goto exit;
    }

    p_sftpFileHandleDescr->requestID = rqstID;
    p_sftpFileHandleDescr->request   = SSH_FXP_REMOVE;

    status = sendFtpMessage(pContextSSH, pBuffer, buflen);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* SSHC_FTP_sendRemoveFile */


/*------------------------------------------------------------------*/

static intBoolean
funcFileRmFileTest(sshcConnectDescr *pDescr, void *cookie)
{
    /* this is tested for NULL in DoOpenFile */
    sftpcFileHandleDescr *p_sftpFileHandleDescr = (sftpcFileHandleDescr*)cookie;
    MOC_UNUSED(pDescr);

    return (0 == p_sftpFileHandleDescr->request);
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_removeFile(sbyte4 connectionInstance, ubyte *pRemoveFileName, ubyte4 removeFileNameLen,
                sftpcFileHandleDescr** pp_sftpFileHandleDescr)
{
    sshcConnectDescr*       pDescr;
    MSTATUS                 status;

    if ((NULL == pRemoveFileName) || (NULL == pp_sftpFileHandleDescr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pp_sftpFileHandleDescr = NULL;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (NULL == (*pp_sftpFileHandleDescr = getUnusedHandleDescr((sshClientContext *)pDescr->pContextSSH)))
    {
        status = ERR_SFTP_TOO_MANY_OPEN_HANDLES;
        goto exit;
    }

    if (OK > (status = SSHC_FTP_sendRemoveFile(pDescr->pContextSSH, *pp_sftpFileHandleDescr, pRemoveFileName, removeFileNameLen)))
        goto exit;

    status = SSHC_doProtocolCommon(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER,
                                   funcFileRmFileTest, *pp_sftpFileHandleDescr);

exit:
    if (OK > status)
        SSHC_freeHandle(connectionInstance, pp_sftpFileHandleDescr);

    return status;

} /* SSHC_removeFile */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_sendRealpath(sshClientContext *pContextSSH,
                      sftpcFileHandleDescr* p_sftpFileHandleDescr,
                      ubyte *pRealpath, ubyte4 realpathLen)
{
    ubyte*  pBuffer = NULL;
    ubyte4  buflen;
    ubyte4  rqstlen;
    ubyte4  bufIndex = 0;
    ubyte4  rqstID;
    MSTATUS status;

    if ((NULL == pContextSSH) || (NULL == p_sftpFileHandleDescr) || (NULL == pRealpath))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    rqstID = NEW_REQUEST_ID();

    rqstlen = SSH_FTP_PACKET_TYPE_FIELD_SIZE +
              SSH_FTP_REQUEST_ID_FIELD_SIZE +
              (4 + realpathLen);

    buflen  = SSH_FTP_PACKET_LENGTH_FIELD_SIZE +
              rqstlen;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pBuffer, SSH_FXP_REALPATH, rqstlen);
    bufIndex += SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE;

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, rqstID)))
        goto exit;

    if (0 > (status = SSH_STR_copyBytesAsStringToPayload(pBuffer, buflen, &bufIndex,
                                                          pRealpath, realpathLen)))
    {
        goto exit;
    }

    p_sftpFileHandleDescr->requestID = rqstID;
    p_sftpFileHandleDescr->request   = SSH_FXP_REALPATH;

    status = sendFtpMessage(pContextSSH, pBuffer, buflen);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* SSHC_FTP_sendRealpath */


/*------------------------------------------------------------------*/

static intBoolean
funcFileRealPathFileTest(sshcConnectDescr *pDescr, void *cookie)
{
    /* this is tested for NULL in DoOpenFile */
    sftpcFileHandleDescr *p_sftpFileHandleDescr = (sftpcFileHandleDescr*)cookie;
    MOC_UNUSED(pDescr);

    return ((SSH_FXP_REALPATH != p_sftpFileHandleDescr->request) || (NULL != p_sftpFileHandleDescr->pFilename));
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_realpath(sbyte4 connectionInstance, ubyte *pRealpath, ubyte4 realpathLen,
              sftpcFileHandleDescr** pp_sftpFileHandleDescr,
              ubyte **ppRetRealpath, ubyte4 *pRetRealpathLen)
{
    sshStringBuffer*        pTempString;
    sshcConnectDescr*       pDescr;
    MSTATUS                 status;

    if ((NULL == pRealpath) || (NULL == ppRetRealpath) || (NULL == pRetRealpathLen) || (NULL == pp_sftpFileHandleDescr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pp_sftpFileHandleDescr = NULL;
    *ppRetRealpath   = NULL;
    *pRetRealpathLen = 0;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (NULL == (*pp_sftpFileHandleDescr = getUnusedHandleDescr((sshClientContext *)pDescr->pContextSSH)))
    {
        status = ERR_SFTP_TOO_MANY_OPEN_HANDLES;
        goto exit;
    }

    /* alloc memory for attr structure */
    if (NULL == ((*pp_sftpFileHandleDescr)->pATTR = MALLOC(sizeof(ATTRClient))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* initialize to zero to prevent bad pointer references, etc */
    DIGI_MEMSET((ubyte *)(*pp_sftpFileHandleDescr)->pATTR, 0x00, sizeof(ATTRClient));

    if (OK > (status = SSHC_FTP_sendRealpath(pDescr->pContextSSH, *pp_sftpFileHandleDescr, pRealpath, realpathLen)))
        goto exit;

    if (OK > (status = SSHC_doProtocolCommon(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER,
                                             funcFileRealPathFileTest, *pp_sftpFileHandleDescr)))
    {
        goto exit;
    }

    if (SSH_FXP_NAME == (*pp_sftpFileHandleDescr)->response)
    {
        pTempString = (sshStringBuffer *)((*pp_sftpFileHandleDescr)->pFilename);

        if (NULL == (*ppRetRealpath = MALLOC(1 + pTempString->stringLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(*ppRetRealpath, pTempString->pString, pTempString->stringLen);
        (*ppRetRealpath)[pTempString->stringLen] = '\0';
        *pRetRealpathLen = pTempString->stringLen;

        /* extract attr */
        if (OK > (status = getAttr((*pp_sftpFileHandleDescr)->pFileListingPayload,
                                (*pp_sftpFileHandleDescr)->fileListingPayloadLen,
                                &((*pp_sftpFileHandleDescr)->fileListingBufIndex),
                                (*pp_sftpFileHandleDescr)->pATTR, SSH_FTP_VERSION(pDescr->pContextSSH))))
        {
            goto exit;
        }
    }

exit:
    if (OK > status)
        SSHC_freeHandle(connectionInstance, pp_sftpFileHandleDescr);

    return status;

} /* SSHC_realpath */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_sendOpenDir(sshClientContext *pContextSSH,
                     sftpcFileHandleDescr* p_sftpFileHandleDescr,
                     ubyte *pPath, ubyte4 pathLen)
{
    ubyte*  pBuffer = NULL;
    ubyte4  buflen;
    ubyte4  rqstlen;
    ubyte4  bufIndex = 0;
    ubyte4  rqstID;
    MSTATUS status;

    if ((NULL == pContextSSH) || (NULL == p_sftpFileHandleDescr) || (NULL == pPath))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    rqstID = NEW_REQUEST_ID();

    rqstlen = SSH_FTP_PACKET_TYPE_FIELD_SIZE +
              SSH_FTP_REQUEST_ID_FIELD_SIZE +
              (4 + pathLen);

    buflen  = SSH_FTP_PACKET_LENGTH_FIELD_SIZE +
              rqstlen;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pBuffer, SSH_FXP_OPENDIR, rqstlen);
    bufIndex += SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE;

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, rqstID)))
        goto exit;

    if (0 > (status = SSH_STR_copyBytesAsStringToPayload(pBuffer, buflen, &bufIndex,
                                                          pPath, pathLen)))
    {
        goto exit;
    }

    p_sftpFileHandleDescr->requestID = rqstID;
    p_sftpFileHandleDescr->request   = SSH_FXP_OPENDIR;

    status = sendFtpMessage(pContextSSH, pBuffer, buflen);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* SSHC_FTP_sendOpenDir */


/*------------------------------------------------------------------*/

static intBoolean
funcFileOpenDirFileTest(sshcConnectDescr *pDescr, void *cookie)
{
    /* this is tested for NULL in DoOpenFile */
    sftpcFileHandleDescr *p_sftpFileHandleDescr = (sftpcFileHandleDescr*)cookie;
    MOC_UNUSED(pDescr);

    return ((NULL != p_sftpFileHandleDescr->pHandleName) ||
            (SSH_FTP_OK != p_sftpFileHandleDescr->requestStatusResponse));
}


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_sendReadDir(sshClientContext *pContextSSH,
                     sftpcFileHandleDescr* p_sftpFileHandleDescr,
                     sshStringBuffer* pHandle)
{
    ubyte*  pBuffer = NULL;
    ubyte4  buflen;
    ubyte4  rqstlen;
    ubyte4  bufIndex = 0;
    ubyte4  rqstID;
    MSTATUS status;

    if ((NULL == pContextSSH) || (NULL == p_sftpFileHandleDescr) || (NULL == pHandle))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    rqstID = NEW_REQUEST_ID();

    rqstlen = SSH_FTP_PACKET_TYPE_FIELD_SIZE +
              SSH_FTP_REQUEST_ID_FIELD_SIZE +
              (pHandle->stringLen);

    buflen  = SSH_FTP_PACKET_LENGTH_FIELD_SIZE +
              rqstlen;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pBuffer, SSH_FXP_READDIR, rqstlen);
    bufIndex += SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE;

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, rqstID)))
        goto exit;

    DIGI_MEMCPY(bufIndex + pBuffer, pHandle->pString, pHandle->stringLen);

    p_sftpFileHandleDescr->requestID = rqstID;
    p_sftpFileHandleDescr->request   = SSH_FXP_READDIR;

    status = sendFtpMessage(pContextSSH, pBuffer, buflen);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* SSHC_FTP_sendOpenDir */


/*------------------------------------------------------------------*/

static intBoolean
funcFileReadDirFileTest(sshcConnectDescr *pDescr, void *cookie)
{
    /* this is tested for NULL in DoOpenFile */
    sftpcFileHandleDescr *p_sftpFileHandleDescr = (sftpcFileHandleDescr*)cookie;
    MOC_UNUSED(pDescr);

    return ((0 != p_sftpFileHandleDescr->fileListingCount) ||
            (SSH_FTP_OK != p_sftpFileHandleDescr->requestStatusResponse));
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_openDirectory(sbyte4 connectionInstance, ubyte *pPath, ubyte4 pathLen,
                   sftpcFileHandleDescr** pp_sftpFileHandleDescr)
{
    sshcConnectDescr*       pDescr;
    MSTATUS                 status;

    if ((NULL == pPath) || (NULL == pp_sftpFileHandleDescr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pp_sftpFileHandleDescr = NULL;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (NULL == (*pp_sftpFileHandleDescr = getUnusedHandleDescr((sshClientContext *)pDescr->pContextSSH)))
    {
        status = ERR_SFTP_TOO_MANY_OPEN_HANDLES;
        goto exit;
    }

    /* alloc memory for attr structure */
    if (NULL == ((*pp_sftpFileHandleDescr)->pATTR = MALLOC(sizeof(ATTRClient))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* initialize to zero to prevent bad pointer references, etc */
    DIGI_MEMSET((ubyte *)(*pp_sftpFileHandleDescr)->pATTR, 0x00, sizeof(ATTRClient));

    /* open directory */
    if (OK > (status = SSHC_FTP_sendOpenDir(pDescr->pContextSSH, *pp_sftpFileHandleDescr, pPath, pathLen)))
        goto exit;

    if (OK > (status = SSHC_doProtocolCommon(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER,
                                             funcFileOpenDirFileTest, *pp_sftpFileHandleDescr)))
    {
        goto exit;
    }

    if (SSH_FTP_OK != ((*pp_sftpFileHandleDescr)->requestStatusResponse))
        goto exit;

    /* fetch the first batch of directory listing data */
    if (OK > (status = SSHC_FTP_sendReadDir(pDescr->pContextSSH, *pp_sftpFileHandleDescr, (sshStringBuffer *)((*pp_sftpFileHandleDescr)->pHandleName))))
        goto exit;

    if (OK > (status = SSHC_doProtocolCommon(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER,
                                             funcFileReadDirFileTest, *pp_sftpFileHandleDescr)))
    {
        goto exit;
    }

exit:
    if (OK > status)
        SSHC_freeHandle(connectionInstance, pp_sftpFileHandleDescr);

    return status;

} /* SSHC_openDirectory */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_readDirectory(sbyte4 connectionInstance,
                   sftpcFileHandleDescr* p_sftpFileHandleDescr,
                   ubyte **ppRetFilename, ubyte4 *pRetFilenameLen)
{
    sshStringBuffer*    pFilename = NULL;
    sshStringBuffer*    pTempFilename = NULL;
    sshcConnectDescr*   pDescr;
    MSTATUS             status;

    if ((NULL == p_sftpFileHandleDescr) || (NULL == ppRetFilename) || (NULL == pRetFilenameLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetFilename   = NULL;
    *pRetFilenameLen = 0;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (p_sftpFileHandleDescr->fileListingPosition == p_sftpFileHandleDescr->fileListingCount)
    {
        /* if there are no more pending directory name entries, send in a new request */

        /* so we can tell if got more directory entries...  */
        p_sftpFileHandleDescr->fileListingCount = 0;

        if (OK > (status = SSHC_FTP_sendReadDir(pDescr->pContextSSH, p_sftpFileHandleDescr, (sshStringBuffer *)p_sftpFileHandleDescr->pHandleName)))
            goto exit;

        if (OK > (status = SSHC_doProtocolCommon(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER,
                                                 funcFileReadDirFileTest, p_sftpFileHandleDescr)))
        {
            goto exit;
        }

        if (0 == p_sftpFileHandleDescr->fileListingCount)
        {
            /* end of directory list reached */
            goto exit;
        }
    }

    /* extract filename */
    if (0 > (status = SSH_STR_copyStringFromPayload2(p_sftpFileHandleDescr->pFileListingPayload,
                                                      p_sftpFileHandleDescr->fileListingPayloadLen,
                                                      &p_sftpFileHandleDescr->fileListingBufIndex, &pFilename)))
    {
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pFilename);

    /* skip long file name */
    if (3 >= SSH_FTP_VERSION(pDescr->pContextSSH))
    {
        if (0 > (status = SSH_STR_copyStringFromPayload2(p_sftpFileHandleDescr->pFileListingPayload,
                                                        p_sftpFileHandleDescr->fileListingPayloadLen,
                                                        &p_sftpFileHandleDescr->fileListingBufIndex, &pTempFilename)))
        {
            goto exit;
        }

        DEBUG_RELABEL_MEMORY(pTempFilename);
    }

    /* free previous run's attr */
    if (OK > (status = freeAttr(p_sftpFileHandleDescr->pATTR)))
        goto exit;

    /* extract attr */
    if (OK > (status = getAttr(p_sftpFileHandleDescr->pFileListingPayload,
                               p_sftpFileHandleDescr->fileListingPayloadLen,
                               &p_sftpFileHandleDescr->fileListingBufIndex,
                               p_sftpFileHandleDescr->pATTR, SSH_FTP_VERSION(pDescr->pContextSSH))))
    {
        goto exit;
    }

    /* clone filename */
    if (NULL == (*ppRetFilename = MALLOC(1 + pFilename->stringLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(*ppRetFilename, pFilename->pString, pFilename->stringLen);
    (*ppRetFilename)[pFilename->stringLen] = '\0';
    *pRetFilenameLen = pFilename->stringLen;

    /* increment for next time we enter this function */
    p_sftpFileHandleDescr->fileListingPosition++;

exit:
    SSH_STR_freeStringBuffer(&pFilename);
    SSH_STR_freeStringBuffer(&pTempFilename);

    return status;

} /* SSHC_readDirectory */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_sendCloseDir(sshClientContext *pContextSSH,
                      sftpcFileHandleDescr* p_sftpFileHandleDescr,
                      sshStringBuffer* pHandle)
{
    ubyte*  pBuffer = NULL;
    ubyte4  buflen;
    ubyte4  rqstlen;
    ubyte4  bufIndex = 0;
    ubyte4  rqstID;
    MSTATUS status;

    if ((NULL == pContextSSH) || (NULL == p_sftpFileHandleDescr) || (NULL == pHandle))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    rqstID = NEW_REQUEST_ID();

    rqstlen = SSH_FTP_PACKET_TYPE_FIELD_SIZE +
              SSH_FTP_REQUEST_ID_FIELD_SIZE +
              (pHandle->stringLen);

    buflen  = SSH_FTP_PACKET_LENGTH_FIELD_SIZE +
              rqstlen;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pBuffer, SSH_FXP_CLOSE, rqstlen);
    bufIndex += SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE;

    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, rqstID)))
        goto exit;

    DIGI_MEMCPY(bufIndex + pBuffer, pHandle->pString, pHandle->stringLen);

    p_sftpFileHandleDescr->requestID = rqstID;
    p_sftpFileHandleDescr->request   = SSH_FXP_CLOSE;

    status = sendFtpMessage(pContextSSH, pBuffer, buflen);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* SSHC_FTP_sendCloseDir */


/*------------------------------------------------------------------*/

static intBoolean
funcFileCloseDirFileTest(sshcConnectDescr *pDescr, void *cookie)
{
    /* this is tested for NULL in DoOpenFile */
    sftpcFileHandleDescr *p_sftpFileHandleDescr = (sftpcFileHandleDescr*)cookie;
    MOC_UNUSED(pDescr);

    return (SSH_FXP_CLOSE != p_sftpFileHandleDescr->request);
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_closeDirectory(sbyte4 connectionInstance, sftpcFileHandleDescr* p_sftpFileHandleDescr)
{
    sshcConnectDescr*   pDescr;
    MSTATUS             status;

    if (NULL == p_sftpFileHandleDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    /* open directory */
    if (OK > (status = SSHC_FTP_sendCloseDir(pDescr->pContextSSH, p_sftpFileHandleDescr, p_sftpFileHandleDescr->pHandleName)))
        goto exit;

    if (OK > (status = SSHC_doProtocolCommon(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER,
                                             funcFileCloseDirFileTest, p_sftpFileHandleDescr)))
    {
        goto exit;
    }

exit:
    return status;

} /* SSHC_closeDirectory */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_FTP_sendGetStat(sshClientContext *pContextSSH,
                     sftpcFileHandleDescr* p_sftpFileHandleDescr,
                     ubyte *pGetStatFile, ubyte4 getStatFileLen)
{
    ubyte*  pBuffer = NULL;
    ubyte4  buflen;
    ubyte4  rqstlen;
    ubyte4  bufIndex = 0;
    ubyte4  rqstID;
    MSTATUS status;

    if ((NULL == pContextSSH) || (NULL == p_sftpFileHandleDescr) || (NULL == pGetStatFile))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    rqstID = NEW_REQUEST_ID();

    rqstlen = SSH_FTP_PACKET_TYPE_FIELD_SIZE +
              SSH_FTP_REQUEST_ID_FIELD_SIZE +
              (4 + getStatFileLen);

    if (3 < SSH_FTP_VERSION(pContextSSH))
        rqstlen = rqstlen + 4;

    buflen  = SSH_FTP_PACKET_LENGTH_FIELD_SIZE +
              rqstlen;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pBuffer, SSH_FXP_STAT, rqstlen);
    bufIndex += SSH_FTP_PACKET_LENGTH_FIELD_SIZE + SSH_FTP_PACKET_TYPE_FIELD_SIZE;

    /* set request id */
    if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, rqstID)))
        goto exit;

    /* set path for stat */
    if (0 > (status = SSH_STR_copyBytesAsStringToPayload(pBuffer, buflen, &bufIndex,
                                                          pGetStatFile, getStatFileLen)))
    {
        goto exit;
    }

    /* set flags for stat */
    if (3 < SSH_FTP_VERSION(pContextSSH))
        if (0 > (status = SSHC_UTILS_setInteger(pBuffer, buflen, &bufIndex, SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS)))
            goto exit;

    p_sftpFileHandleDescr->requestID = rqstID;
    p_sftpFileHandleDescr->request   = SSH_FXP_STAT;

    status = sendFtpMessage(pContextSSH, pBuffer, buflen);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* SSHC_FTP_sendGetStat */


/*------------------------------------------------------------------*/

static intBoolean
funcFileGetStatTest(sshcConnectDescr *pDescr, void *cookie)
{
    sftpcFileHandleDescr *p_sftpFileHandleDescr = (sftpcFileHandleDescr*)cookie;
    MOC_UNUSED(pDescr);

    return (0 != p_sftpFileHandleDescr->response);
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_getFileStat(sbyte4 connectionInstance, ubyte *pGetStatFile, ubyte4 getStatFileLen,
                 sftpcFileHandleDescr** pp_sftpFileHandleDescr)
{
    sshcConnectDescr*       pDescr;
    MSTATUS                 status;

    if ((NULL == pGetStatFile) || (NULL == pp_sftpFileHandleDescr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pp_sftpFileHandleDescr = NULL;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (NULL == (*pp_sftpFileHandleDescr = getUnusedHandleDescr((sshClientContext *)pDescr->pContextSSH)))
    {
        status = ERR_SFTP_TOO_MANY_OPEN_HANDLES;
        goto exit;
    }

    /* alloc memory for attr structure */
    if (NULL == ((*pp_sftpFileHandleDescr)->pATTR = MALLOC(sizeof(ATTRClient))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* initialize to zero to prevent bad pointer references, etc */
    DIGI_MEMSET((ubyte *)(*pp_sftpFileHandleDescr)->pATTR, 0x00, sizeof(ATTRClient));

    if (OK > (status = SSHC_FTP_sendGetStat(pDescr->pContextSSH, *pp_sftpFileHandleDescr, pGetStatFile, getStatFileLen)))
        goto exit;

    if (OK > (status = SSHC_doProtocolCommon(connectionInstance, TRUE, TIMEOUT_SSHC_UPPER_LAYER,
                                             funcFileGetStatTest, *pp_sftpFileHandleDescr)))
    {
        goto exit;
    }

    /* free previous run's attr */
    if (OK > (status = freeAttr((*pp_sftpFileHandleDescr)->pATTR)))
        goto exit;

    /* extract attr */
    if (OK > (status = getAttr((*pp_sftpFileHandleDescr)->pFileListingPayload,
                               (*pp_sftpFileHandleDescr)->fileListingPayloadLen,
                               &((*pp_sftpFileHandleDescr)->fileListingBufIndex),
                               (*pp_sftpFileHandleDescr)->pATTR, SSH_FTP_VERSION(pDescr->pContextSSH))))
    {
        goto exit;
    }

exit:
    if (OK > status)
        SSHC_freeHandle(connectionInstance, pp_sftpFileHandleDescr);

    return status;

} /* SSHC_getFileStat */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_freeHandle(sbyte4 connectionInstance, sftpcFileHandleDescr** pp_sftpFileHandleDescr)
{
    MSTATUS status;
    MOC_UNUSED(connectionInstance);

    if (NULL == pp_sftpFileHandleDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK == (status = SSHC_FTP_freeHandle(*pp_sftpFileHandleDescr)))
        *pp_sftpFileHandleDescr = NULL;

exit:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern sbyte4
SSHC_FTP_freeAllHandles(sshClientContext *pContextSSH)
{
    sftpcFileHandleDescr *p_sftpFileHandleDescr;
    sbyte4 i;

    for (i = SFTP_NUM_HANDLES, p_sftpFileHandleDescr = SSH_FTP_FILE_HANDLE_TABLE(pContextSSH);
         0 < i; i--, p_sftpFileHandleDescr++)
    {
        if (p_sftpFileHandleDescr->isFileHandleInUse)
        {
            SSHC_FTP_freeHandle(p_sftpFileHandleDescr);
        }
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_freeFilename(sbyte4 connectionInstance, ubyte **ppFreeFilename)
{
    MSTATUS status = OK;
    MOC_UNUSED(connectionInstance);

    if (NULL == ppFreeFilename)
    {
        status = ERR_NULL_POINTER;
    }
    else if (*ppFreeFilename)
    {
        FREE(*ppFreeFilename);
        *ppFreeFilename = NULL;
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
checkBuffer(sshClientContext *pContextSSH, ubyte4 requestedSize)
{
    MSTATUS status = OK;

    if (pContextSSH->sftpIncomingBufferSize >= requestedSize)
        goto exit;

    if (NULL != pContextSSH->p_sftpIncomingBuffer)
        FREE(pContextSSH->p_sftpIncomingBuffer);

    pContextSSH->sftpIncomingBufferSize = requestedSize;

    if (NULL == (pContextSSH->p_sftpIncomingBuffer = MALLOC(requestedSize)))
        status = ERR_MEM_ALLOC_FAIL;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
sftpReceiveMessage(sshClientContext *pContextSSH,
                   ubyte **ppPacketPayload, ubyte4 *pPacketLength)
{
    ubyte4  readNumBytes;
    MSTATUS status = OK;

    if (SFTP_RECEIVE_MESSAGE_BODY == pContextSSH->sftpState)
        goto nextState;

    pContextSSH->sftpState = SFTP_RECEIVE_MESSAGE_LENGTH;

    readNumBytes = ((4 - pContextSSH->sftpNumBytesInBuffer) < (*pPacketLength)) ? (4 - pContextSSH->sftpNumBytesInBuffer) : (*pPacketLength);

    if (0 == readNumBytes)
        goto exit;

    DIGI_MEMCPY(pContextSSH->sftpNumBytesInBuffer + pContextSSH->sftpLengthBuffer, *ppPacketPayload, readNumBytes);

    *pPacketLength -= readNumBytes;
    *ppPacketPayload += readNumBytes;
    pContextSSH->sftpNumBytesInBuffer += readNumBytes;

    /* not enough bytes to complete reading length field */
    if (4 > pContextSSH->sftpNumBytesInBuffer)
        goto exit;

    /* get the size */
    pContextSSH->sftpNumBytesRequired  = ((ubyte4)(pContextSSH->sftpLengthBuffer[3]));
    pContextSSH->sftpNumBytesRequired |= ((ubyte4)(pContextSSH->sftpLengthBuffer[2])) << 8;
    pContextSSH->sftpNumBytesRequired |= ((ubyte4)(pContextSSH->sftpLengthBuffer[1])) << 16;
    pContextSSH->sftpNumBytesRequired |= ((ubyte4)(pContextSSH->sftpLengthBuffer[0])) << 24;

    /* look for overrun attack */
    if ((kMaxFtpMessageSize < pContextSSH->sftpNumBytesRequired) || (0 == pContextSSH->sftpNumBytesRequired))
    {
        /* buffer overrun (attack?) */
        status = ERR_SFTP_MESSAGE_TOO_LONG;
        goto exit;
    }

    /* grow buffer support here */
    if (OK > (status = checkBuffer(pContextSSH, 2048 + pContextSSH->sftpNumBytesRequired)))
        goto exit;

    pContextSSH->sftpState = SFTP_RECEIVE_MESSAGE_BODY;
    pContextSSH->sftpNumBytesInBuffer = 0;

nextState:
    readNumBytes = ((pContextSSH->sftpNumBytesRequired - pContextSSH->sftpNumBytesInBuffer) < (*pPacketLength)) ? (pContextSSH->sftpNumBytesRequired - pContextSSH->sftpNumBytesInBuffer) : (*pPacketLength);

    if (0 == readNumBytes)
        goto exit;

    DIGI_MEMCPY(pContextSSH->sftpNumBytesInBuffer + pContextSSH->p_sftpIncomingBuffer, *ppPacketPayload, readNumBytes);

    *pPacketLength -= readNumBytes;
    *ppPacketPayload += readNumBytes;
    pContextSSH->sftpNumBytesInBuffer += readNumBytes;

    /* not enough bytes to complete message body */
    if (pContextSSH->sftpNumBytesRequired > pContextSSH->sftpNumBytesInBuffer)
        goto exit;

    pContextSSH->sftpState = SFTP_RECEIVE_MESSAGE_COMPLETED;
    pContextSSH->sftpNumBytesInBuffer = 0;

exit:
    return status;

} /* sftpReceiveMessage */


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
SSHC_FTP_doProtocol(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    MSTATUS     (*funcMethod)(sshClientContext *pContextSSH, ubyte *, ubyte4) = NULL;
    ubyte*      pPayload = NULL;
    ubyte4      payloadLength = 0;
    MSTATUS     status = OK;

    if ((NULL == pContextSSH) || (NULL == pNewMesg))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    while (0 < newMesgLen)
    {
        if (OK > (status = sftpReceiveMessage(pContextSSH, &pNewMesg, &newMesgLen)))
            goto exit;

        if (SFTP_RECEIVE_MESSAGE_COMPLETED != pContextSSH->sftpState)
            continue;

        pPayload = 1 + pContextSSH->p_sftpIncomingBuffer;
        payloadLength = pContextSSH->sftpNumBytesRequired - 1;

#ifdef __ENABLE_ALL_DEBUGGING__
        DUMP_MESG_sftpMessage(pPayload - 1, payloadLength + 1, FALSE);
#endif /* __ENABLE_ALL_DEBUGGING__ */

        RTOS_deltaMS(NULL, &SSH_TIMER_START_TIME(pContextSSH));   /* to avoid false timeouts, reset the timeout for each message successfully received */

        switch (*(pContextSSH->p_sftpIncomingBuffer))
        {
            case SSH_FXP_VERSION:
                funcMethod = SSHC_FTP_handleFtpVersion;
                break;

            case SSH_FXP_STATUS:
                funcMethod = SSHC_FTP_handleStatus;
                break;

            case SSH_FXP_HANDLE:
                funcMethod = SSHC_FTP_handleHandle;
                break;

            case SSH_FXP_DATA:
                funcMethod = SSHC_FTP_handleData;
                break;

            case SSH_FXP_NAME:
                funcMethod = SSHC_FTP_handleName;
                break;

            case SSH_FXP_ATTRS:
                funcMethod = SSHC_FTP_handleAttrs;
                break;

            default:
                funcMethod = NULL;
                break;
        }

        if (NULL != funcMethod)  /* don't count or pass in type field */
            status = funcMethod(pContextSSH, pPayload, payloadLength);
        else
            status = ERR_SFTP_MALFORMED_MESSAGE;

        if (OK > status)
            goto exit;

        if (0 != newMesgLen)
        {
            DEBUG_ERROR(DEBUG_SSHC, "SSHC_FTP_doProtocol: not zero --- newMesgLen = ", newMesgLen);
        }
    }

exit:
#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSHC, "SSHC_FTP_doProtocol: status = ", status);
#endif

    return status;

} /* SSHC_FTP_doProtocol */


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern void
SSHC_sftpSetWriteLocation(sftpcFileHandleDescr *p_sftpFileHandleDescr, sbyte4 location)
{
    p_sftpFileHandleDescr->writeLocation = location;
}


/*------------------------------------------------------------------*/

extern void
SSHC_sftpSetWriteBuffer(sftpcFileHandleDescr *p_sftpFileHandleDescr, sbyte *pBuffer)
{
    p_sftpFileHandleDescr->pWriteBuffer = pBuffer;
}


/*------------------------------------------------------------------*/

extern void
SSHC_sftpSetWriteBufferSize(sftpcFileHandleDescr *p_sftpFileHandleDescr, sbyte4 bufSize)
{
    p_sftpFileHandleDescr->writeBufferSize = bufSize;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern ubyte4
SSHC_sftpGetMaxWrite(sbyte4 connectionInstance)
{
    sshcConnectDescr *pDescr;
    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
        return 0;

    return pDescr->pContextSSH->sessionState.windowSize;
}


/*------------------------------------------------------------------*/

extern void
SSHC_sftpSetCookie(sftpcFileHandleDescr *p_sftpFileHandleDescr, void* sftpCookie)
{
    p_sftpFileHandleDescr->cookie = sftpCookie;
}


/*------------------------------------------------------------------*/

extern void*
SSHC_sftpGetCookie(sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    return p_sftpFileHandleDescr->cookie;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_sftpReadLocation(sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    return p_sftpFileHandleDescr->readLocation;
}


/*------------------------------------------------------------------*/

extern sbyte*
SSHC_sftpReadBuffer(sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    return p_sftpFileHandleDescr->pReadBuffer;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_sftpReadBufferSize(sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    return p_sftpFileHandleDescr->readBufferSize;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_sftpNumBytesRead(sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    return p_sftpFileHandleDescr->readLocation;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_sftpWriteLocation(sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    return p_sftpFileHandleDescr->writeLocation;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_sftpNumBytesWritten(sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    return p_sftpFileHandleDescr->writeLocation;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_sftpRequestStatusCode(sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    return p_sftpFileHandleDescr->requestStatusResponse;
}


/*------------------------------------------------------------------*/

extern sbyte*
SSHC_sftpWriteBuffer(sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    return p_sftpFileHandleDescr->pWriteBuffer;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_sftpWriteBufferSize(sftpcFileHandleDescr *p_sftpFileHandleDescr)
{
    return p_sftpFileHandleDescr->writeBufferSize;
}


/*------------------------------------------------------------------*/

extern void
SSHC_sftpGetDirEntryFileSize(sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr, ubyte4 *pRetFileSize, intBoolean *pRetIsPresent)
{
    MOC_UNUSED(connectionInstance);

    if (pRetIsPresent)
        *pRetIsPresent = FALSE;

    if ((NULL != p_sftpFileHandleDescr) && (NULL != pRetFileSize))
    {
        if (p_sftpFileHandleDescr->pATTR)
        {
            *pRetFileSize = (SSH_FILEXFER_ATTR_SIZE & p_sftpFileHandleDescr->pATTR->flags) ? LOW_U8(p_sftpFileHandleDescr->pATTR->size) : 0;

            if (pRetIsPresent)
                *pRetIsPresent = TRUE;
        }
    }
}


/*------------------------------------------------------------------*/

extern void
SSHC_sftpGetDirEntryFileType(sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr, ubyte4 *pRetFileType, intBoolean *pRetIsPresent)
{
    sshcConnectDescr *pDescr;

    if (pRetIsPresent)
        *pRetIsPresent = FALSE;

    pDescr = SSHC_getConnectionFromInstance(connectionInstance);

    /* type is only available for SFTPv4(+) */
    if ((NULL != pDescr) && (3 < SSH_FTP_VERSION(pDescr->pContextSSH)) && (NULL != p_sftpFileHandleDescr) && (NULL != pRetFileType))
    {
        if (p_sftpFileHandleDescr->pATTR)
        {
            *pRetFileType = p_sftpFileHandleDescr->pATTR->type;

            if (pRetIsPresent)
                *pRetIsPresent = TRUE;
        }
    }
}


/*------------------------------------------------------------------*/

extern void
SSHC_sftpGetDirEntryFilePermission(sbyte4 connectionInstance, sftpcFileHandleDescr *p_sftpFileHandleDescr, ubyte4 *pRetFilePermission, intBoolean *pRetIsPresent)
{
    MOC_UNUSED(connectionInstance);

    if (pRetIsPresent)
        *pRetIsPresent = FALSE;

    if ((NULL != p_sftpFileHandleDescr) && (NULL != pRetFilePermission))
    {
        if (p_sftpFileHandleDescr->pATTR)
        {
            *pRetFilePermission = (SSH_FILEXFER_ATTR_PERMISSIONS & p_sftpFileHandleDescr->pATTR->flags) ? p_sftpFileHandleDescr->pATTR->permissions : 0;

            if (pRetIsPresent)
                *pRetIsPresent = TRUE;
        }
    }
}


#endif /* (defined(__ENABLE_DIGICERT_SSH_CLIENT__) && defined(__ENABLE_DIGICERT_SSH_FTP_CLIENT__)) */
