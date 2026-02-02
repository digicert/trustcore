/*
 * ssh_ftp.c
 *
 * SSH File Transfer Protocol Handler
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
@file       ssh_ftp.c
@brief      NanoSSH FTP server developer API.
@details    This file contains FTP Server API functions.

@since 1.41
@version 2.02 and later

@flags
To enable any of this file's functions, the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_FTP_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_SERVER__

@todo_techpubs (ensure that documentation is correct wrt references to "SFTP"
                and "FTP" server; the defines and filename indicate "FTP" but
                many function names are "_sftp" for "ssh ftp")

@filedoc    ssh_ftp.c
*/

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_SSH_SERVER__) && defined(__ENABLE_DIGICERT_SSH_FTP_SERVER__))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/mocana.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mem_pool.h"
#include "../common/moc_stream.h"
#include "../common/debug_console.h"
#include "../common/int64.h"
#include "../crypto/crypto.h"
#include "../crypto/dsa.h"
#include "../crypto/dh.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../common/sizedbuffer.h"
#include "../crypto/cert_store.h"
#include "../crypto/ca_mgmt.h"
#include "../ssh/ssh_defs.h"
#include "../ssh/ssh_str.h"
#include "../ssh/ssh_context.h"
#include "../ssh/ssh_auth.h"
#include "../ssh/ssh_str_house.h"
#include "../ssh/ssh_session.h"
#include "../ssh/ssh_ftp.h"
#include "../ssh/ssh.h"
#include "../ssh/ssh_filesys.h"
#include "../ssh/dump_mesg.h"
#include "../ssh/sftp.h"


/*------------------------------------------------------------------*/

#if 0
#define __DEBUG_SSH_FTP__
#endif

#ifndef SFTP_READFILE_BUF_SIZE
#define SFTP_READFILE_BUF_SIZE  512
#endif

#ifndef __DEBUG_SSH_FTP__
#define SEND_SFTP_STATUS_MACRO(XX,YY,ZZ)        sendStatusMessage(XX,YY,ZZ)
#else
#define SEND_SFTP_STATUS_MACRO(XX,YY,ZZ)        debugSendStatusMessage(XX,YY,ZZ,__LINE__)
#endif

#define MOCANA_SSH_FTP_SERVER_VERSION           3
#define MOCANA_SSH_FTP_SERVER_LOW_VER           2

#define kMaxFtpMessageSize                      34000

#define _S_IFDIR                                0040000
#define _S_IFREG                                0100000
#define _S_IFMT                                 0170000

#define _S_IREAD                                0000400
#define _S_IWRITE                               0000200

#define kOpenDirectoryState                     1
#define kReadDirectoryState                     2
#define kCloseDirectoryState                    3
#define kDoneDirectoryState                     4

#ifndef SFTP_MAX_PATH_DEPTH
#define SFTP_MAX_PATH_DEPTH     (32)
#endif


/*------------------------------------------------------------------*/

/* sftp/scp related strings */
static sshStringBuffer ssh_ftp_newline;
static sshStringBuffer ssh_ftp_canonical;

static sshStringBuffer ssh_ftp_ok;
static sshStringBuffer ssh_ftp_eof;
static sshStringBuffer ssh_ftp_no_such_file;
static sshStringBuffer ssh_ftp_permission_denied;
static sshStringBuffer ssh_ftp_bad_message;
static sshStringBuffer ssh_ftp_op_unsupported;
static sshStringBuffer ssh_ftp_invalid_handle;
static sshStringBuffer ssh_ftp_no_such_path;
static sshStringBuffer ssh_ftp_file_already_exists;
static sshStringBuffer ssh_ftp_write_protect;
static sshStringBuffer ssh_ftp_general_failure;


/*------------------------------------------------------------------*/

extern MSTATUS
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for DigiCert internal code use only, and
 * should not be included in the API documentation.
 */
SSH_FTP_initStringBuffers(void)
{
#define INIT_SSH_STRING_BUFFER(X,Y)    if (OK > (status = SSH_STR_HOUSE_initStringBuffer(X,Y))) goto exit

    MSTATUS status;

    /* types */
    INIT_SSH_STRING_BUFFER(&ssh_ftp_newline, (sbyte *)"newline");
    INIT_SSH_STRING_BUFFER(&ssh_ftp_canonical, (sbyte *)"\\n");

    /* error message strings */
    INIT_SSH_STRING_BUFFER(&ssh_ftp_ok, (sbyte *)"SSH SFTP/SCP request succeeded.");
    INIT_SSH_STRING_BUFFER(&ssh_ftp_eof, (sbyte *)"SSH SFTP/SCP error: eof reached.");
    INIT_SSH_STRING_BUFFER(&ssh_ftp_no_such_file, (sbyte *)"SSH SFTP/SCP error: no such file.");
    INIT_SSH_STRING_BUFFER(&ssh_ftp_permission_denied, (sbyte *)"SSH SFTP/SCP error: access denied.");
    INIT_SSH_STRING_BUFFER(&ssh_ftp_bad_message, (sbyte *)"SSH SFTP/SCP error: malformed message request.");
    INIT_SSH_STRING_BUFFER(&ssh_ftp_op_unsupported, (sbyte *)"SSH SFTP/SCP error: unsupported request.");
    INIT_SSH_STRING_BUFFER(&ssh_ftp_invalid_handle, (sbyte *)"SSH SFTP/SCP error: invalid handle.");
    INIT_SSH_STRING_BUFFER(&ssh_ftp_no_such_path, (sbyte *)"SSH SFTP/SCP error: no such path.");
    INIT_SSH_STRING_BUFFER(&ssh_ftp_file_already_exists, (sbyte *)"SSH SFTP/SCP error: file already exists.");
    INIT_SSH_STRING_BUFFER(&ssh_ftp_write_protect, (sbyte *)"SSH SFTP/SCP error: file write protected.");
    INIT_SSH_STRING_BUFFER(&ssh_ftp_general_failure, (sbyte *)"SSH SFTP/SCP error: general.");

exit:
    return status;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for DigiCert internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
SSH_FTP_freeStringBuffers(void)
{
#define FREE_SSH_STRING_BUFFER(X)    if (NULL != X.pString) { FREE(X.pString); X.pString = NULL; }

    FREE_SSH_STRING_BUFFER(ssh_ftp_newline);
    FREE_SSH_STRING_BUFFER(ssh_ftp_canonical);

    FREE_SSH_STRING_BUFFER(ssh_ftp_ok);
    FREE_SSH_STRING_BUFFER(ssh_ftp_eof);
    FREE_SSH_STRING_BUFFER(ssh_ftp_no_such_file);
    FREE_SSH_STRING_BUFFER(ssh_ftp_permission_denied);
    FREE_SSH_STRING_BUFFER(ssh_ftp_bad_message);
    FREE_SSH_STRING_BUFFER(ssh_ftp_op_unsupported);
    FREE_SSH_STRING_BUFFER(ssh_ftp_invalid_handle);
    FREE_SSH_STRING_BUFFER(ssh_ftp_no_such_path);
    FREE_SSH_STRING_BUFFER(ssh_ftp_file_already_exists);
    FREE_SSH_STRING_BUFFER(ssh_ftp_write_protect);
    FREE_SSH_STRING_BUFFER(ssh_ftp_general_failure);

    return OK;
}


/*------------------------------------------------------------------*/

static void
setupFtpMessageHeader(ubyte *pMessage, ubyte4 mesgType, ubyte4 payloadLength)
{
    pMessage[0] = (ubyte)(payloadLength >> 24);
    pMessage[1] = (ubyte)(payloadLength >> 16);
    pMessage[2] = (ubyte)(payloadLength >> 8);
    pMessage[3] = (ubyte)(payloadLength);

    pMessage[4] = (ubyte)mesgType;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for DigiCert internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
getByte(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, ubyte *pRetByte)
{
    MSTATUS status = OK;

    if (((*pBufIndex) + 1) > bufSize)
    {
        /* not enough bytes to get one byte */
        status = ERR_SFTP_BAD_PAYLOAD_LENGTH;
        goto exit;
    }

    pBuffer += (*pBufIndex);

    *pRetByte   = *pBuffer;
    *pBufIndex += 1;

exit:
#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "getByte: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for DigiCert internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
getInteger(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, ubyte4 *pRetInteger)
{
    ubyte4  retInteger;
    MSTATUS status = OK;

    if (((*pBufIndex) + 4) > bufSize)
    {
        /* not enough bytes to get */
        status = ERR_SFTP_BAD_PAYLOAD_LENGTH;
        goto exit;
    }

    pBuffer += (*pBufIndex);

    retInteger  = ((ubyte4)pBuffer[3]);
    retInteger |= ((ubyte4)pBuffer[2]) << 8;
    retInteger |= ((ubyte4)pBuffer[1]) << 16;
    retInteger |= ((ubyte4)pBuffer[0]) << 24;

    *pRetInteger = retInteger;
    *pBufIndex  += 4;

exit:
#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "getInteger: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for DigiCert internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
getInteger64(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, ubyte8 *pRetInteger64)
{
    ubyte4  retInteger;
    MSTATUS status = OK;

    if (((*pBufIndex) + 8) > bufSize)
    {
        /* not enough bytes to get */
        status = ERR_SFTP_BAD_PAYLOAD_LENGTH;
        goto exit;
    }

    pBuffer += (*pBufIndex);

    retInteger  = ((ubyte4)pBuffer[3]);
    retInteger |= ((ubyte4)pBuffer[2]) << 8;
    retInteger |= ((ubyte4)pBuffer[1]) << 16;
    retInteger |= ((ubyte4)pBuffer[0]) << 24;

    U8INIT_HI((*pRetInteger64), retInteger);

    retInteger  = ((ubyte4)pBuffer[7]);
    retInteger |= ((ubyte4)pBuffer[6]) << 8;
    retInteger |= ((ubyte4)pBuffer[5]) << 16;
    retInteger |= ((ubyte4)pBuffer[4]) << 24;

    U8INIT_LO((*pRetInteger64), retInteger);

    *pBufIndex  += 8;

exit:
#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "getInteger64: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
getAttr(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, ATTR *pRetATTR, ubyte4 version)
{
    sshStringBuffer* pDummyString = NULL;
    ubyte4           extended_count = 0;    /* present only if flag EXTENDED */
    ubyte4           flags;
    MSTATUS          status   = OK;

    if (OK > (status = getInteger(pBuffer, bufSize, pBufIndex, &(flags))))
        goto exit;

    pRetATTR->flags = flags;

    if (3 < version)
        if (OK > (status = getByte(pBuffer, bufSize, pBufIndex, &(pRetATTR->type))))
            goto exit;

    if (flags & SSH_FILEXFER_ATTR_SIZE)
        if (OK > (status = getInteger64(pBuffer, bufSize, pBufIndex, &(pRetATTR->size))))
            goto exit;

    if (flags & SSH_FILEXFER_ATTR_OWNERGROUP)
    {
        if (OK > (status = SSH_STR_copyStringFromPayload2(pBuffer, bufSize, pBufIndex, &(pRetATTR->owner))))
            goto exit;

        if (OK > (status = SSH_STR_copyStringFromPayload2(pBuffer, bufSize, pBufIndex, &(pRetATTR->group))))
            goto exit;
    }

    if (flags & SSH_FILEXFER_ATTR_PERMISSIONS)
        if (OK > (status = getInteger(pBuffer, bufSize, pBufIndex, &(pRetATTR->permissions))))
            goto exit;

    if (flags & SSH_FILEXFER_ATTR_ACCESSTIME)
    {
        if (OK > (status = getInteger64(pBuffer, bufSize, pBufIndex, &(pRetATTR->atime))))
            goto exit;

        if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
            if (OK > (status = getInteger(pBuffer, bufSize, pBufIndex, &(pRetATTR->atime_nseconds))))
                goto exit;
    }

    if (flags & SSH_FILEXFER_ATTR_CREATETIME)
    {
        if (OK > (status = getInteger64(pBuffer, bufSize, pBufIndex, &(pRetATTR->createtime))))
            goto exit;

        if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
            if (OK > (status = getInteger(pBuffer, bufSize, pBufIndex, &(pRetATTR->createtime_nseconds))))
                goto exit;
    }

    if (flags & SSH_FILEXFER_ATTR_MODIFYTIME)
    {
        if (OK > (status = getInteger64(pBuffer, bufSize, pBufIndex, &(pRetATTR->mtime))))
            goto exit;

        if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
            if (OK > (status = getInteger(pBuffer, bufSize, pBufIndex, &(pRetATTR->mtime_nseconds))))
                goto exit;
    }

    if (flags & SSH_FILEXFER_ATTR_ACL)
        if (OK > (status = SSH_STR_copyStringFromPayload2(pBuffer, bufSize, pBufIndex, &(pRetATTR->acl))))
            goto exit;

    if (flags & SSH_FILEXFER_ATTR_EXTENDED)
        if (OK > (status = getInteger(pBuffer, bufSize, pBufIndex, &extended_count)))
            goto exit;

    while (0 < extended_count)
    {
        /* fetch and dump extended type */
        if (OK > (status = SSH_STR_copyStringFromPayload2(pBuffer, bufSize, pBufIndex, &pDummyString)))
            goto exit;

        SSH_STR_freeStringBuffer(&pDummyString);

        /* fetch and dump extended data */
        if (OK > (status = SSH_STR_copyStringFromPayload2(pBuffer, bufSize, pBufIndex, &pDummyString)))
            goto exit;

        SSH_STR_freeStringBuffer(&pDummyString);

        extended_count--;
    }

exit:
#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "getAttr: status = ", status);
#endif

    if (NULL != pDummyString)
        SSH_STR_freeStringBuffer(&pDummyString);

    return status;

} /* getAttr */


/*------------------------------------------------------------------*/

static MSTATUS
freeAttr(ATTR *pFreeATTR)
{
    if (NULL == pFreeATTR)
        return ERR_NULL_POINTER;

    SSH_STR_freeStringBuffer(&(pFreeATTR->owner));
    SSH_STR_freeStringBuffer(&(pFreeATTR->group));
    SSH_STR_freeStringBuffer(&(pFreeATTR->acl));

    DIGI_MEMSET((ubyte *)pFreeATTR, 0x00, sizeof(ATTR));

    return OK;
}


/*------------------------------------------------------------------*/

static ubyte4
getAttrLength(ATTR *pAttr, ubyte4 version)
{
    ubyte4  flags = pAttr->flags;
    ubyte4  attrLength;

    attrLength = 4;         /* flags:4 */

    if (3 < version)        /* type field */
        attrLength++;

    if (flags & SSH_FILEXFER_ATTR_SIZE)
        attrLength += 8;

    if ((3 > version) && (flags & 0x02))
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
setByte(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex, ubyte byteValue)
{
    MSTATUS status = OK;

    if ((payloadLength <= (*pBufIndex)) || (1 > (payloadLength - (*pBufIndex))))
    {
        /* not enough room to set byte */
        status = ERR_SFTP_PAYLOAD_TOO_SMALL;
        goto exit;
    }

    pPayload += (*pBufIndex);
    *pPayload   = (ubyte)(byteValue);
    *pBufIndex += 1;

exit:
#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "setByte: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
setInteger(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex, ubyte4 integerValue)
{
    MSTATUS status = OK;

    if ((payloadLength <= (*pBufIndex)) || (4 > (payloadLength - (*pBufIndex))))
    {
        /* not enough room to set integer */
        status = ERR_SFTP_PAYLOAD_TOO_SMALL;
        goto exit;
    }

    pPayload += (*pBufIndex);

    pPayload[0] = (ubyte)(integerValue >> 24);
    pPayload[1] = (ubyte)(integerValue >> 16);
    pPayload[2] = (ubyte)(integerValue >> 8);
    pPayload[3] = (ubyte)(integerValue);

    *pBufIndex += 4;

exit:
#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "setInteger: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
setInteger64(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex, ubyte8 *pIntegerValue64)
{
    ubyte4  tempValue;
    MSTATUS status = OK;

    if ((payloadLength <= (*pBufIndex)) || (8 > (payloadLength - (*pBufIndex))))
    {
        /* not enough room to set integer */
        status = ERR_SFTP_PAYLOAD_TOO_SMALL;
        goto exit;
    }

    pPayload += (*pBufIndex);

    tempValue = HI_U8((*pIntegerValue64));

    pPayload[0] = (ubyte)(tempValue >> 24);
    pPayload[1] = (ubyte)(tempValue >> 16);
    pPayload[2] = (ubyte)(tempValue >> 8);
    pPayload[3] = (ubyte)(tempValue);

    tempValue = LOW_U8((*pIntegerValue64));

    pPayload[4] = (ubyte)(tempValue >> 24);
    pPayload[5] = (ubyte)(tempValue >> 16);
    pPayload[6] = (ubyte)(tempValue >> 8);
    pPayload[7] = (ubyte)(tempValue);

    *pBufIndex += 8;

exit:
#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "setInteger64: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
setString(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex, ubyte *pString, sbyte4 stringLen)
{
    MSTATUS status = OK;

    while (0 < stringLen)
    {
        if (OK > (status = setByte(pPayload, payloadLength, pBufIndex, *pString)))
            break;

        pString++;
        stringLen--;
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
setAttr(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex, ATTR *pATTR, ubyte4 version)
{
    ubyte4  flags  = ((pATTR->flags) & (~(SSH_FILEXFER_ATTR_EXTENDED)));
    MSTATUS status = OK;

    if (OK > (status = setInteger(pPayload, payloadLength, pBufIndex, flags)))
        goto exit;

    if (3 < version)
        if (OK > (status = setByte(pPayload, payloadLength, pBufIndex, pATTR->type)))
            goto exit;

    if (flags & SSH_FILEXFER_ATTR_SIZE)
        if (OK > (status = setInteger64(pPayload, payloadLength, pBufIndex, &pATTR->size)))
            goto exit;

    if ((2 < version) && (flags & SSH_FILEXFER_ATTR_OWNERGROUP))
    {
        if (OK > (status = SSH_STR_copyStringToPayload(pPayload, payloadLength, pBufIndex, pATTR->owner)))
            goto exit;

        if (OK > (status = SSH_STR_copyStringToPayload(pPayload, payloadLength, pBufIndex, pATTR->group)))
            goto exit;
    }

    if (flags & SSH_FILEXFER_ATTR_PERMISSIONS)
        if (OK > (status = setInteger(pPayload, payloadLength, pBufIndex, pATTR->permissions)))
            goto exit;

    if (3 < version)
    {
        if (flags & SSH_FILEXFER_ATTR_ACCESSTIME)
        {
            if (OK > (status = setInteger64(pPayload, payloadLength, pBufIndex, &pATTR->atime)))
                goto exit;

            if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
                if (OK > (status = setInteger(pPayload, payloadLength, pBufIndex, pATTR->atime_nseconds)))
                    goto exit;
        }

        if (flags & SSH_FILEXFER_ATTR_CREATETIME)
        {
            if (OK > (status = setInteger64(pPayload, payloadLength, pBufIndex, &pATTR->createtime)))
                goto exit;

            if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
                if (OK > (status = setInteger(pPayload, payloadLength, pBufIndex, pATTR->createtime_nseconds)))
                    goto exit;
        }

        if (flags & SSH_FILEXFER_ATTR_MODIFYTIME)
        {
            if (OK > (status = setInteger64(pPayload, payloadLength, pBufIndex, &pATTR->mtime)))
                goto exit;

            if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
                if (OK > (status = setInteger(pPayload, payloadLength, pBufIndex, pATTR->mtime_nseconds)))
                    goto exit;
        }
    }
    else
    {
        if (flags & SSH_FILEXFER_ATTR_ACCESSTIME)
        {
            if (OK > (status = setInteger(pPayload, payloadLength, pBufIndex, LOW_U8(pATTR->atime))))
                goto exit;

            if (OK > (status = setInteger(pPayload, payloadLength, pBufIndex, LOW_U8(pATTR->mtime))))
                goto exit;
        }
    }

    if ((2 < version) && (flags & SSH_FILEXFER_ATTR_ACL))
        if (OK > (status = SSH_STR_copyStringToPayload(pPayload, payloadLength, pBufIndex, pATTR->acl)))
            goto exit;

exit:
#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "setAttr: status = ", status);
#endif

    return status;

} /* setAttr */


/*------------------------------------------------------------------*/

static MSTATUS
sendFtpMessage(sshContext *pContextSSH, ubyte *pMessage, ubyte4 mesgLen)
{
    ubyte4  numBytesWritten = 0;
    MSTATUS status;

    if (OK <= (status = DIGI_STREAM_write(pContextSSH->sessionState.pSftpOutStreamDescr, pMessage, mesgLen, &numBytesWritten)))
    {
        /* verify write completed */
        if (mesgLen != numBytesWritten)
            status = ERR_SFTP_MESG_FRAGMENTED;
    }

#ifdef __ENABLE_ALL_DEBUGGING__
    DUMP_MESG_sftpMessage(4 + pMessage, mesgLen - 4, TRUE);
#endif /* __ENABLE_ALL_DEBUGGING__ */

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
compactPath(sshStringBuffer* pLongPath,
            sshStringBuffer** ppRetCompactPath, ubyte4 *pRetResult)
{
    ubyte4* pIndexStack;
    sbyte4  stackPointer   = -1;
    ubyte*  pTraverse      = pLongPath->pString;
    ubyte4  traverseLength = pLongPath->stringLen;
    ubyte4  index1         = 0;
    MSTATUS status;

    if (NULL == (pIndexStack = MALLOC(sizeof(ubyte4) * SFTP_MAX_PATH_DEPTH)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = SSH_STR_makeStringBuffer(ppRetCompactPath, 2 + pLongPath->stringLen)))
        goto exit;

    while (0 < traverseLength)
    {
        if ((1 == traverseLength) && ('.' == pTraverse[0]))
        {
            /* ignore trailing '.' */
            pTraverse      = pTraverse      + 1;
            traverseLength = traverseLength - 1;
            continue;
        }

        /* skip redundant slashes */
        if ((2 <= traverseLength) && ('/' == pTraverse[0]) && ('/' == pTraverse[1]))
        {
            pTraverse      = pTraverse      + 1;
            traverseLength = traverseLength - 1;
            continue;
        }

        if ('/' == pTraverse[0])
        {
            if (3 <= traverseLength)
            {
                /* case '/..' */
                if (('.' == pTraverse[1]) && ('.' == pTraverse[2]))
                {
                    /* '..' must be followed by a slash or nothing */
                    if (3 < traverseLength)
                    {
                        if ('/' != pTraverse[3])
                        {
                            *pRetResult = SSH_FTP_NO_SUCH_PATH;
                            goto exit;
                        }
                    }

                    pTraverse      = pTraverse      + 3;
                    traverseLength = traverseLength - 3;

                    /* rewind index1 back to the last slash */
                    if (0 > stackPointer)
                    {
                        /* nothing left to rewind */
                        index1                          = 0;
                        stackPointer                    = -1;
                        continue;
                    }

                    index1 = pIndexStack[stackPointer--];

                    if (0 > stackPointer)
                    {
                        /* nothing left to rewind */
                        index1                          = 0;
                        stackPointer                    = -1;
                    }
                    continue;
                }
            }

            if (2 <= traverseLength)
            {
                /* case '/.' */
                if ('.' == pTraverse[1])
                {
                    if ((2 == traverseLength) || ((2 < traverseLength) && ('/' == pTraverse[2])) )
                    {
                        /* ignore '/.' (exactly) and '/./' (pattern), however allow /.foo */
                        pTraverse = pTraverse + 2;
                        traverseLength = traverseLength - 2;
                        continue;
                    }
                }
            }

            /* remove trailing '/'s */
            if (1 == traverseLength)
            {
                pTraverse      = pTraverse      + 1;
                traverseLength = traverseLength - 1;
                continue;
            }

            if ((SFTP_MAX_PATH_DEPTH - 1) <= stackPointer)
            {
                /* file system deeper than we support */
                *pRetResult = SSH_FTP_NO_SUCH_PATH;
                goto exit;
            }

            /* store for recall on '..' */
            pIndexStack[++stackPointer] = index1;

            /* dup '/foo' */
            pTraverse      = pTraverse      + 1;
            traverseLength = traverseLength - 1;
            (*ppRetCompactPath)->pString[index1] = '/';
            index1 = index1 + 1;
        }

        while ((0 < traverseLength) && ('/' != pTraverse[0]))
        {
            (*ppRetCompactPath)->pString[index1] = pTraverse[0];
            index1 = index1 + 1;

            pTraverse      = pTraverse      + 1;
            traverseLength = traverseLength - 1;
        }
    }

    (*ppRetCompactPath)->stringLen = index1;
    (*ppRetCompactPath)->pString[index1] = '\0';

exit:
    if (NULL != pIndexStack)
        FREE(pIndexStack);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
formPath(sshContext *pContextSSH, sshStringBuffer* pLongPath,
         sshStringBuffer** ppRetCompactPath, ubyte4 *pRetResult)
{
    sshStringBuffer* pConcatString = NULL;
    MSTATUS          status;

    if (!((0 < pLongPath->stringLen) && ('/' == pLongPath->pString[0])))
    {
        ubyte4 stringLen = 0;

        if ((NULL != SFTP_CURRENT_PATH(pContextSSH)) && (0 < SFTP_CURRENT_PATH(pContextSSH)->stringLen))
            stringLen = SFTP_CURRENT_PATH(pContextSSH)->stringLen;

        if (OK > (status = SSH_STR_makeStringBuffer(&pConcatString, stringLen + 1 + pLongPath->stringLen)))
            goto exit;

        /* assume root directory, if no home directory is set */
        if (0 < stringLen)
            DIGI_MEMCPY(pConcatString->pString, SFTP_CURRENT_PATH(pContextSSH)->pString, stringLen);

        pConcatString->pString[stringLen] = '/';
        stringLen++;

        if (0 < pLongPath->stringLen)
            DIGI_MEMCPY(stringLen + pConcatString->pString, pLongPath->pString, pLongPath->stringLen);

        pLongPath = pConcatString;
    }

    if (OK <= (status = compactPath(pLongPath, ppRetCompactPath, pRetResult)))
        if (0 == (*ppRetCompactPath)->stringLen)
        {
            (*ppRetCompactPath)->pString[0] = '/';
            (*ppRetCompactPath)->pString[1] = '\0';
            (*ppRetCompactPath)->stringLen  = 1;
        }

exit:
    SSH_STR_freeStringBuffer(&pConcatString);

    return status;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for DigiCert internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
handleFtpHello(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    ubyte4  bufIndex      = 0;
    ubyte4  clientVersion = 0;
    MSTATUS status;

    /* skip past length and type */
    if (OK > (status = getInteger(pNewMesg, newMesgLen, &bufIndex, &clientVersion)))
        goto exit;

    /* check sftp version (we support versions 2-4) */
    if (MOCANA_SSH_FTP_SERVER_LOW_VER > clientVersion)
    {
        /* don't support older versions, we need to exit */
        DIGICERT_log((sbyte4)MOCANA_SSH, (sbyte4)LS_WARNING, (sbyte *)"Client SFTP/SCP version unsupported, please upgrade client software.");

        status = ERR_SFTP_UNSUPPORTED_VERSION;
        goto exit;
    }
    else
    {
        /* send our hello string back */
        ubyte   replyMessage[9];

        bufIndex = 0;

        if (MOCANA_SSH_FTP_SERVER_VERSION < clientVersion)
            clientVersion = MOCANA_SSH_FTP_SERVER_VERSION;

#ifdef __DEBUG_SSH_FTP__
    DEBUG_ERROR(DEBUG_SSH_SFTP, "SFTP: Client connection accepted, version = ", clientVersion);
#endif /* __DEBUG_SSH_FTP__ */

        SSH_FTP_VERSION(pContextSSH) = clientVersion;
        SSH_SESSION_STATE(pContextSSH) = kSftpOpenState;

        setupFtpMessageHeader(replyMessage, SSH_FXP_VERSION, 5);

        setInteger(&replyMessage[5], 4, &bufIndex, clientVersion);

/* !!! future add suport for
ssh_ftp_newline
ssh_ftp_canonical
*/

        status = sendFtpMessage(pContextSSH, replyMessage, 9);
    }

exit:
#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleFtpHello: status = ", status);
#endif

    return status;

} /* handleFtpHello */


/*------------------------------------------------------------------*/

static void
dumpHex(ubyte *pDumpHexValue, ubyte4 hexValue)
{
    sbyte4 index;

    for (index = 8; 0 < index; index--)
    {
        pDumpHexValue[index - 1] = returnHexDigit(hexValue);
        hexValue = (hexValue >> 8);
    }
}


/*------------------------------------------------------------------*/

static MSTATUS
createFileHandle(sbyte4 handleIndex, sshStringBuffer **ppRetFileHandle)
{
    sshStringBuffer*    pRetStringBuffer = NULL;
    MSTATUS             status = OK;

    if (OK > (status = SSH_STR_makeStringBuffer(&pRetStringBuffer, 9)))
        goto exit;

    /* store handleIndex as part of the file handle string, for easy uniqueness checks */
    dumpHex(pRetStringBuffer->pString, handleIndex);

    pRetStringBuffer->pString[8] = '@';

    *ppRetFileHandle = pRetStringBuffer;
    pRetStringBuffer = NULL;

exit:
    SSH_STR_freeStringBuffer(&pRetStringBuffer);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "createFileHandle: status = ", status);
#endif

    return status;

} /* createFileHandle */


/*------------------------------------------------------------------*/

static MSTATUS
sendStatusMessage(sshContext *pContextSSH, ubyte4 id, ubyte4 result)
{
    ubyte*              pReplyMessage = NULL;
    ubyte4              payloadLength;
    sshStringBuffer*    pErrorMessage = NULL;
    ubyte4              bufIndex;
    MSTATUS             status;

    if ((3 == SSH_FTP_VERSION(pContextSSH)) && (SSH_FTP_OP_UNSUPPORTED < result))
        result = SSH_FTP_FAILURE;

    switch (result)
    {
        case SSH_FTP_OK:
            pErrorMessage = &ssh_ftp_ok;
            break;

        case SSH_FTP_EOF:
            pErrorMessage = &ssh_ftp_eof;
            break;

        case SSH_FTP_NO_SUCH_FILE:
            pErrorMessage = &ssh_ftp_no_such_file;
            break;

        case SSH_FTP_PERMISSION_DENIED:
            pErrorMessage = &ssh_ftp_permission_denied;
            break;

        case SSH_FTP_BAD_MESSAGE:
            pErrorMessage = &ssh_ftp_bad_message;
            break;

        case SSH_FTP_OP_UNSUPPORTED:
            pErrorMessage = &ssh_ftp_op_unsupported;
            break;

        case SSH_FTP_INVALID_HANDLE:
            pErrorMessage = &ssh_ftp_invalid_handle;
            break;

        case SSH_FTP_NO_SUCH_PATH:
            pErrorMessage = &ssh_ftp_no_such_path;
            break;

        case SSH_FTP_FILE_ALREADY_EXISTS:
            pErrorMessage = &ssh_ftp_file_already_exists;
            break;

        case SSH_FTP_WRITE_PROTECT:
            pErrorMessage = &ssh_ftp_write_protect;
            break;

        case SSH_FTP_FAILURE:
        case SSH_FTP_CONNECTION_LOST:
        case SSH_FTP_NO_CONNECTION:
        case SSH_FTP_NO_MEDIA:
        default:
            pErrorMessage = &ssh_ftp_general_failure;
            result = SSH_FTP_FAILURE;
            break;
    }

    /* payloadLength = length + mesg type + id + error code + error message + language */
    if (2 < SSH_FTP_VERSION(pContextSSH))
        payloadLength = 4 + 1 + 8 + 4 + pErrorMessage->stringLen + ssh_languageTag.stringLen;
    else
        payloadLength = 4 + 1 + 8;

    /* length field plus payload */
    if (NULL == (pReplyMessage = MALLOC(payloadLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pReplyMessage, SSH_FXP_STATUS, payloadLength - 4);

    bufIndex = 5;

    setInteger(pReplyMessage, payloadLength, &bufIndex, id);

    if (OK > (status = setInteger(pReplyMessage, payloadLength, &bufIndex, result)))
        goto exit;

    if (2 < SSH_FTP_VERSION(pContextSSH))
    {
        if (OK > (status = SSH_STR_copyStringToPayload(pReplyMessage, payloadLength, &bufIndex, pErrorMessage)))
            goto exit;

        DIGI_MEMCPY(bufIndex + pReplyMessage, ssh_languageTag.pString, ssh_languageTag.stringLen);
    }

    /* send length + message payload */
    status = sendFtpMessage(pContextSSH, pReplyMessage, payloadLength);

exit:
    if (NULL != pReplyMessage)
        FREE(pReplyMessage);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "sendStatusMessage: status = ", status);
#endif

    return status;

} /* sendStatusMessage */


/*------------------------------------------------------------------*/

static MSTATUS
sendNameMessage(sshContext *pContextSSH, ubyte4 id, sshStringBuffer *pFilename, ATTR *pAttr, intBoolean isReadDir)
{
    ubyte*              pReplyMessage = NULL;
    ubyte4              replyLength;
    ubyte4              bufIndex;
    MSTATUS             status;

    if (3 >= SSH_FTP_VERSION(pContextSSH))
        pAttr->flags &= (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_ACCESSTIME | SSH_FILEXFER_ATTR_PERMISSIONS);

    /* payloadLength = mesg len + mesg type + id + count + file name + attr */
    replyLength = 4 + 1 + 8 + 4 + pFilename->stringLen + getAttrLength(pAttr, SSH_FTP_VERSION(pContextSSH));

    /* plus v3 long name */
    if (3 >= SSH_FTP_VERSION(pContextSSH))
    {
        if (FALSE == isReadDir)
            replyLength += 4 + pFilename->stringLen;
        else
            replyLength += 4 + 55 + pFilename->stringLen;
    }

    /* length field plus payload */
    if (NULL == (pReplyMessage = MALLOC(replyLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pReplyMessage, SSH_FXP_NAME, replyLength - 4);

    bufIndex = 5;

    setInteger(pReplyMessage, replyLength, &bufIndex, id);

    if (OK > (status = setInteger(pReplyMessage, replyLength, &bufIndex, 1)))   /* count is one */
        goto exit;

    if (OK > (status = SSH_STR_copyStringToPayload(pReplyMessage, replyLength, &bufIndex, pFilename)))
        goto exit;

    if ((3 >= SSH_FTP_VERSION(pContextSSH)) && (FALSE == isReadDir))
    {
        if (OK > (status = SSH_STR_copyStringToPayload(pReplyMessage, replyLength, &bufIndex, pFilename)))
            goto exit;
    }
    else if ((3 >= SSH_FTP_VERSION(pContextSSH)) && (TRUE == isReadDir))
    {
        ubyte4 numDigits;
        sbyte4 index;
        ubyte  buf[11];

        /* SFTP spec: However, clients SHOULD NOT attempt to parse the longname field for file attributes; they SHOULD use the attrs field instead. */
        /* All of this code to generate a longname for a junkie client that foolishly parses this string.  Ugh! */

        /* -rwxr-xr-x   1 mjos     staff      348911 Mar 25 14:29 t-filexfer */
        /* 1234567890 123 12345678 12345678 12345678 123456789012 */

        /* never use sprintf(), it's not safe */
        if (OK > (status = setInteger(pReplyMessage, replyLength, &bufIndex, 55 + pFilename->stringLen)))
            goto exit;

        if (OK > (status = setByte(pReplyMessage, replyLength, &bufIndex, (SSH_FILEXFER_TYPE_DIRECTORY == pAttr->type) ? 'd' : '-')))
            goto exit;

        if (OK > (status = setByte(pReplyMessage, replyLength, &bufIndex, (_S_IREAD & pAttr->permissions) ? 'r' : '-')))
            goto exit;

        if (OK > (status = setByte(pReplyMessage, replyLength, &bufIndex, (_S_IWRITE & pAttr->permissions) ? 'w' : '-')))
            goto exit;

        for (index = 0; index < 7; index++)
            if (OK > (status = setByte(pReplyMessage, replyLength, &bufIndex, '-')))
                goto exit;

        for (index = 0; index < 3; index++)
            if (OK > (status = setByte(pReplyMessage, replyLength, &bufIndex, ' ')))
                goto exit;

        if (OK > (status = setByte(pReplyMessage, replyLength, &bufIndex, '1')))
            goto exit;

        if (OK > (status = setByte(pReplyMessage, replyLength, &bufIndex, ' ')))
            goto exit;

        for (index = 0; index < 8; index++)
            if (OK > (status = setByte(pReplyMessage, replyLength, &bufIndex, 'O')))
                goto exit;

        if (OK > (status = setByte(pReplyMessage, replyLength, &bufIndex, ' ')))
            goto exit;

        for (index = 0; index < 8; index++)
            if (OK > (status = setByte(pReplyMessage, replyLength, &bufIndex, 'G')))
                goto exit;

        DIGI_UTOA((LOW_U8(pAttr->size) % 99999999), buf, &numDigits);

        for (index = 0; index < (sbyte4)(1 + (8 - numDigits)); index++)
            if (OK > (status = setByte(pReplyMessage, replyLength, &bufIndex, ' ')))
                goto exit;

        if (OK > (status = setString(pReplyMessage, replyLength, &bufIndex, buf, numDigits)))
            goto exit;

        if (OK > (status = setString(pReplyMessage, replyLength, &bufIndex, (ubyte *)" Jan  1 00:01 ", 14)))
            goto exit;

        if (OK > (status = setString(pReplyMessage, replyLength, &bufIndex, pFilename->pString, pFilename->stringLen)))
            goto exit;
    }

    if (OK > (status = setAttr(pReplyMessage, replyLength, &bufIndex, pAttr, SSH_FTP_VERSION(pContextSSH))))
        goto exit;

    /* send length + message payload */
    status = sendFtpMessage(pContextSSH, pReplyMessage, replyLength);

exit:
    if (NULL != pReplyMessage)
        FREE(pReplyMessage);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "sendNameMessage: status = ", status);
#endif

    return status;

} /* sendNameMessage */


/*------------------------------------------------------------------*/

static MSTATUS
sendAttrsMessage(sshContext *pContextSSH, ubyte4 id, ATTR *pAttr)
{
    ubyte*              pReplyMessage = NULL;
    ubyte4              replyLength;
    ubyte4              bufIndex;
    MSTATUS             status;

    if (3 == SSH_FTP_VERSION(pContextSSH))
        pAttr->flags &= (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_ACCESSTIME | SSH_FILEXFER_ATTR_PERMISSIONS);

    /* payloadLength = mesg length + mesg type + id + attr */
    replyLength = 4 + 1 + 4 + getAttrLength(pAttr, SSH_FTP_VERSION(pContextSSH));

    /* length field plus payload */
    if (NULL == (pReplyMessage = MALLOC(replyLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pReplyMessage, SSH_FXP_ATTRS, replyLength - 4);

    bufIndex = 5;

    setInteger(pReplyMessage, replyLength, &bufIndex, id);

    if (OK > (status = setAttr(pReplyMessage, replyLength, &bufIndex, pAttr, SSH_FTP_VERSION(pContextSSH))))
        goto exit;

    /* send length + message payload */
    status = sendFtpMessage(pContextSSH, pReplyMessage, replyLength);

exit:
    if (NULL != pReplyMessage)
        FREE(pReplyMessage);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "sendAttrsMessage: status = ", status);
#endif

    return status;

} /* sendAttrsMessage */


/*------------------------------------------------------------------*/

static MSTATUS
sendHandleMessage(sshContext *pContextSSH, ubyte4 id, sshStringBuffer *pHandle)
{
    ubyte*              pReplyMessage = NULL;
    ubyte4              replyLength;
    ubyte4              bufIndex;
    MSTATUS             status;

    /* payloadLength = mesg length + mesg type + id + handle string */
    replyLength = 4 + 1 + 4 + 4 + pHandle->stringLen;

    /* length field plus payload */
    if (NULL == (pReplyMessage = MALLOC(replyLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    setupFtpMessageHeader(pReplyMessage, SSH_FXP_HANDLE, replyLength - 4);

    bufIndex = 5;

    if (OK > (status = setInteger(pReplyMessage, replyLength, &bufIndex, id)))
        goto exit;

    if (OK > (status = SSH_STR_copyStringToPayload(pReplyMessage, replyLength, &bufIndex, pHandle)))
        goto exit;

    /* send length + message payload */
    status = sendFtpMessage(pContextSSH, pReplyMessage, replyLength);

exit:
    if (NULL != pReplyMessage)
        FREE(pReplyMessage);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "sendHandleMessage: status = ", status);
#endif

    return status;

} /* sendHandleMessage */


/*------------------------------------------------------------------*/

#ifdef __DEBUG_SSH_FTP__
static MSTATUS
debugSendStatusMessage(sshContext *pContextSSH, ubyte4 id, ubyte4 result, sbyte4 lineNum)
{
    if (SSH_FTP_OP_UNSUPPORTED == result)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "SFTP: SSH_FTP_OP_UNSUPPORTED at line ", lineNum);

    return sendStatusMessage(pContextSSH, id, result);
}
#endif /* __DEBUG_SSH_FTP__ */


/*------------------------------------------------------------------*/

static MSTATUS
getVirtualFileIndex(sshContext *pContextSSH, sshStringBuffer* pPath, sbyte4 *pRetFileIndex, sftpFileObjDescr** ppRetSftpFileDescr)
{
    sbyte4  index;
    MSTATUS status = OK;
    MOC_UNUSED(pContextSSH);

    /* default to root directory */
    *pRetFileIndex = 0;

    for (index = SFTP_NUM_FILES() - 1; 0 <= index; index--)
    {
        if (pPath->stringLen >= sftpFiles[index].fileNameLength)
        {
            sbyte4 result;

            if (OK > (status = DIGI_MEMCMP(sftpFiles[index].fileName, pPath->pString, sftpFiles[index].fileNameLength, &result)))
                goto exit;

            if (0 == result)
            {
                if (pPath->stringLen == sftpFiles[index].fileNameLength)
                {
                    if (NULL != ppRetSftpFileDescr)
                        *ppRetSftpFileDescr = &(sftpFiles[index]);

                    *pRetFileIndex = index;
                    break;
                }

                if ('/' == pPath->pString[sftpFiles[index].fileNameLength])
                {
                    *pRetFileIndex = index;
                    break;
                }
            }
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static void
dupFromSftpDescr(sshContext *pContextSSH, sftpFileObjDescr *p_sftpFile, sbyte4 fileObjectIndex, ATTR *pRetAttr)
{
    if (SFTP_TRUE != p_sftpFile->isDirectory)
    {
        /* path leads to a file */
        pRetAttr->flags           = SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_ACCESSTIME | SSH_FILEXFER_ATTR_CREATETIME | SSH_FILEXFER_ATTR_MODIFYTIME;
        pRetAttr->type            = SSH_FILEXFER_TYPE_REGULAR;
        pRetAttr->permissions     = _S_IFREG;
    }
    else
    {
        /* leads to a dynamically discovered sub-directory */
        pRetAttr->flags           = SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACCESSTIME | SSH_FILEXFER_ATTR_CREATETIME | SSH_FILEXFER_ATTR_MODIFYTIME;
        pRetAttr->type            = SSH_FILEXFER_TYPE_DIRECTORY;
        pRetAttr->permissions     = _S_IFDIR;
    }

    U8INIT(pRetAttr->atime, 0, p_sftpFile->fileAccessTime);
    U8INIT(pRetAttr->createtime, 0, p_sftpFile->fileCreationTime);
    U8INIT(pRetAttr->mtime, 0, p_sftpFile->fileModifyTime);

    if ((SFTP_TRUE == p_sftpFile->isReadable) &&
        (p_sftpFile->readAccessGroup == (p_sftpFile->readAccessGroup & SFTP_GROUP_ACCESS(pContextSSH))) &&
        (sftpFiles[fileObjectIndex].readAccessGroup == (sftpFiles[fileObjectIndex].readAccessGroup & SFTP_GROUP_ACCESS(pContextSSH))))
    {
        pRetAttr->permissions |= _S_IREAD;
    }

    if ((SFTP_TRUE == p_sftpFile->isWriteable) &&
        (p_sftpFile->writeAccessGroup == (p_sftpFile->writeAccessGroup & SFTP_GROUP_ACCESS(pContextSSH))) &&
        (sftpFiles[fileObjectIndex].writeAccessGroup == (sftpFiles[fileObjectIndex].writeAccessGroup & SFTP_GROUP_ACCESS(pContextSSH))))
    {
        pRetAttr->permissions |= _S_IWRITE;
    }

    U8INIT(pRetAttr->size, 0, p_sftpFile->fileSize);
}


/*------------------------------------------------------------------*/

static MSTATUS
getFileStats(sshContext *pContextSSH, sshStringBuffer *pPath, sbyte4 *pFileDescrIndex,
             ATTR* pRetAttr, ubyte4* pResult)
{
    sftpFileObjDescr*  p_sftpFileDescr = NULL;
    sftpFileObjDescr   sftpTempDescr;
    MSTATUS         status;

    DIGI_MEMSET((ubyte *)(&sftpTempDescr), 0x00, sizeof(sftpFileObjDescr));

    if (OK > (status = getVirtualFileIndex(pContextSSH, pPath, pFileDescrIndex, &p_sftpFileDescr)))
        goto exit;

    if (NULL == p_sftpFileDescr)
    {
        if (NULL != SSH_sftpSettings()->funcPtrGetFileStats)
        {
            status = OK;

            if (SSH_FTP_OK > (sbyte4)(*pResult = SSH_sftpSettings()->funcPtrGetFileStats(CONNECTION_INSTANCE(pContextSSH), pPath->pString, NULL, &sftpTempDescr)))
            {
                status = (MSTATUS)(*pResult);
                goto exit;
            }

            p_sftpFileDescr = &sftpTempDescr;
        }
        else
        {
            *pResult = SSH_FTP_NO_SUCH_FILE;
            goto exit;
        }
    }

    dupFromSftpDescr(pContextSSH, p_sftpFileDescr, *pFileDescrIndex, pRetAttr);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
getFileStatsForOpenFile(sshContext *pContextSSH, sbyte4 handleIndex,
                        ATTR* pRetAttr, ubyte4* pResult)
{
    sftpFileObjDescr*   p_sftpFileDescr = NULL;
    sftpFileObjDescr    sftpTempDescr;
    MSTATUS             status = OK;

    DIGI_MEMSET((ubyte *)(&sftpTempDescr), 0x00, sizeof(sftpFileObjDescr));

    if (NULL == SSH_sftpSettings()->funcPtrGetOpenFileStats)
        goto exit;

    if (SSH_FTP_OK > (sbyte4)((usize)(*pResult = SSH_sftpSettings()->funcPtrGetOpenFileStats((sbyte4)CONNECTION_INSTANCE(pContextSSH),(sbyte4) ((usize)SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].cookie), &sftpTempDescr))))
    {
        status = (MSTATUS)(*pResult);
        goto exit;
    }

    p_sftpFileDescr = &sftpTempDescr;

    dupFromSftpDescr(pContextSSH, p_sftpFileDescr, 0, pRetAttr);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
getHandleIndex(sshContext *pContextSSH)
{
    /* find a vacant file handle, initialize somewhat */
    sbyte4     retIndex = ERR_SFTP_TOO_MANY_OPEN_HANDLES;
    sbyte4  index;

    for (index = 0; index < SFTP_NUM_HANDLES; index++)
    {
        if (FALSE == SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[index].isFileHandleInUse)
        {
            SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[index].isFileHandleInUse = TRUE;
            SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[index].pFullPath = NULL;
            SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[index].pHandleName = NULL;
            retIndex = index;
            break;
        }
    }

    return retIndex;
}


/*------------------------------------------------------------------*/

static sbyte4
findHandleIndex(sshContext *pContextSSH, sshStringBuffer* pFindHandle)
{
    /* find specified file handle */
    sbyte4     retIndex = ERR_SFTP_TOO_MANY_OPEN_HANDLES;
    sbyte4  index;
    sbyte4  memCmp;

    for (index = 0; index < SFTP_NUM_HANDLES; index++)
    {
        ubyte *pTemp = ((sshStringBuffer *)SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[index].pHandleName)->pString;

        if ((TRUE == SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[index].isFileHandleInUse) &&
            (pFindHandle->stringLen == ((sshStringBuffer *)(SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[index].pHandleName))->stringLen) &&
            (OK == DIGI_MEMCMP(pFindHandle->pString, pTemp, pFindHandle->stringLen, &memCmp)) &&
            (0 == memCmp))
        {
            retIndex = index;
            break;
        }
    }

    return retIndex;
}


/*------------------------------------------------------------------*/

static intBoolean
isWithinDirectory(sftpFileObjDescr *pThisFile, sshStringBuffer *pWithinThisPath)
{
    ubyte4      index;
    intBoolean  isWithin = FALSE;
    sbyte4      result;

    /* is the path longer than the full path name? */
    if (pWithinThisPath->stringLen > pThisFile->fileNameLength)
        goto exit;

    DIGI_MEMCMP(pWithinThisPath->pString, pThisFile->fileName, pWithinThisPath->stringLen, &result);

    /* make sure the strings match */
    if (0 != result)
        goto exit;

    /* is it an exact match? */
    if (pWithinThisPath->stringLen == pThisFile->fileNameLength)
        goto exit;

    /* next character should be a slash */
    if (1 < pWithinThisPath->stringLen)
        if ('/' != pThisFile->fileName[pWithinThisPath->stringLen])
            goto exit;

    /* verify this file is immediately within this path */
    for (index = 1 + pWithinThisPath->stringLen; index < pThisFile->fileNameLength; index++)
        if ('/' == pThisFile->fileName[index])
            goto exit;

    isWithin = TRUE;

exit:
    return isWithin;
}


/*------------------------------------------------------------------*/

static intBoolean
isStaticFileObjectEntry(sshContext *pContextSSH, sshStringBuffer *pThisFile)
{
    sbyte4      result;
    sbyte4      index;
    intBoolean  isDefined = FALSE;
    MOC_UNUSED(pContextSSH);

    /* look in table for file */
    for (index = 0; index < SFTP_NUM_FILES(); index++)
    {
        if (sftpFiles[index].fileNameLength == pThisFile->stringLen)
        {
            DIGI_MEMCMP(sftpFiles[index].fileName, pThisFile->pString, pThisFile->stringLen, &result);

            if (0 == result)
            {
                isDefined = TRUE;
                break;
            }
        }
    }

    return isDefined;
}


/*------------------------------------------------------------------*/

extern void
SSH_sftpSetCookie(void* sftpInternelDescr, void* sftpCookie)
{
    sftpFileHandleDescr *p_sftpFileHandleDescr = (sftpFileHandleDescr *)sftpInternelDescr;

    p_sftpFileHandleDescr->cookie = sftpCookie;
}


/*------------------------------------------------------------------*/

extern void*
SSH_sftpGetCookie(void* sftpInternelDescr)
{
    sftpFileHandleDescr *p_sftpFileHandleDescr = (sftpFileHandleDescr *)sftpInternelDescr;

    return p_sftpFileHandleDescr->cookie;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSH_sftpReadLocation(void* sftpInternelDescr)
{
    sftpFileHandleDescr *p_sftpFileHandleDescr = (sftpFileHandleDescr *)sftpInternelDescr;

    return p_sftpFileHandleDescr->readLocation;
}


/*------------------------------------------------------------------*/

extern sbyte*
SSH_sftpReadBuffer(void* sftpInternelDescr)
{
    sftpFileHandleDescr *p_sftpFileHandleDescr = (sftpFileHandleDescr *)sftpInternelDescr;

    return p_sftpFileHandleDescr->pReadBuffer;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSH_sftpReadBufferSize(void* sftpInternelDescr)
{
    sftpFileHandleDescr *p_sftpFileHandleDescr = (sftpFileHandleDescr *)sftpInternelDescr;

    return p_sftpFileHandleDescr->readBufferSize;
}


/*------------------------------------------------------------------*/

extern void
SSH_sftpNumBytesRead(void* sftpInternelDescr, sbyte4 numBytesRead)
{
    sftpFileHandleDescr *p_sftpFileHandleDescr = (sftpFileHandleDescr *)sftpInternelDescr;

    p_sftpFileHandleDescr->numBytesRead = numBytesRead;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSH_sftpWriteLocation(void* sftpInternelDescr)
{
    sftpFileHandleDescr *p_sftpFileHandleDescr = (sftpFileHandleDescr *)sftpInternelDescr;

    return p_sftpFileHandleDescr->writeLocation;
}


/*------------------------------------------------------------------*/

extern sbyte*
SSH_sftpWriteBuffer(void* sftpInternelDescr)
{
    sftpFileHandleDescr *p_sftpFileHandleDescr = (sftpFileHandleDescr *)sftpInternelDescr;

    return p_sftpFileHandleDescr->pWriteBuffer;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSH_sftpWriteBufferSize(void* sftpInternelDescr)
{
    sftpFileHandleDescr *p_sftpFileHandleDescr = (sftpFileHandleDescr *)sftpInternelDescr;

    return p_sftpFileHandleDescr->writeBufferSize;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleFileOpen(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pFilename = NULL;
    sshStringBuffer*    pNewFilename = NULL;
    sshStringBuffer*    pRetFileHandle = NULL;
    ubyte4              pflags;
    ATTR                attr;
    ubyte4              bufIndex = 0;
    ubyte4              result = SSH_FTP_NO_SUCH_FILE;
    sbyte4              handleIndex;
    sbyte4              fileObjectIndex = 0;
    sftpFileHandleDescr*p_sftpFileHandleDescr;
    sbyte4              fileFlags = 0;
    MSTATUS             status = OK;

    /* clear attr structure */
    DIGI_MEMSET((ubyte *)&attr, 0x00, sizeof(ATTR));

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out filename */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pFilename)))
        goto exit;

    /* get pflags */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &pflags)))
        goto exit;

    /* get ATTR */
    if (OK > (status = getAttr(pPayload, payloadLength, &bufIndex, &attr, SSH_FTP_VERSION(pContextSSH))))
        goto exit;
#if 0
    /* !!!! disable until Putty fixes their client.  Not really a problem for now. */
    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }
#endif

    if (NULL == SSH_sftpSettings()->funcPtrOpenFileUpcall)
    {
        result = SSH_FTP_OP_UNSUPPORTED;
        goto send;
    }

    if (pflags & SSH_FXF_READ)
        fileFlags = SFTP_OPEN_FILE_READ_BINARY;
    if (pflags & SSH_FXF_WRITE)
        fileFlags = SFTP_OPEN_FILE_WRITE_BINARY;

    if ((0 == fileFlags) || ((SFTP_OPEN_FILE_READ_BINARY | SFTP_OPEN_FILE_WRITE_BINARY) == fileFlags))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    /* open the file handle */
    result = SSH_FTP_OK;

    if (OK > (status = formPath(pContextSSH, pFilename, &pNewFilename, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    freeAttr(&attr);

    if (OK > (status = getFileStats(pContextSSH, pNewFilename, &fileObjectIndex, &attr, &result)))
        goto exit;

    if ((SSH_FTP_OK != result) &&
        (!((SSH_FTP_NO_SUCH_FILE == result) && (SFTP_OPEN_FILE_WRITE_BINARY == fileFlags))))
    {
        goto send;
    }

    /* not a file but a directory */
    if ((SSH_FTP_OK == result) && (attr.permissions & _S_IFDIR))
    {
        result = SSH_FTP_NO_SUCH_FILE;
        goto send;
    }


    /* make sure user has read or write directory permissions */
    if ((SFTP_OPEN_FILE_READ_BINARY == fileFlags) &&
        (sftpFiles[fileObjectIndex].readAccessGroup != (sftpFiles[fileObjectIndex].readAccessGroup & SFTP_GROUP_ACCESS(pContextSSH))))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    if ((SFTP_OPEN_FILE_WRITE_BINARY == fileFlags) &&
        (sftpFiles[fileObjectIndex].writeAccessGroup != (sftpFiles[fileObjectIndex].writeAccessGroup & SFTP_GROUP_ACCESS(pContextSSH))))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    /* check pflags against attr */
    if (((SFTP_OPEN_FILE_READ_BINARY  == fileFlags) && (_S_IREAD  != (attr.permissions & _S_IREAD))) ||
        ((SFTP_OPEN_FILE_WRITE_BINARY == fileFlags) && (_S_IWRITE != (attr.permissions & _S_IWRITE))))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    if (0 > (handleIndex = getHandleIndex(pContextSSH)))
    {
        /* too many open file handles */
        result = SSH_FTP_FAILURE;
        goto send;
    }

    if (OK > (status = createFileHandle(handleIndex, &pRetFileHandle)))
    {
        goto exit;
    }

    /* setup for subsequent read/write requests */
    p_sftpFileHandleDescr = &SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex];

    p_sftpFileHandleDescr->isDirectoryHandle = FALSE;
    p_sftpFileHandleDescr->pHandleName = pRetFileHandle;
    p_sftpFileHandleDescr->fileObjectIndex = (void *)((usize)fileObjectIndex);
    p_sftpFileHandleDescr->cookie = 0;

    /* callback user code here, verify file opened */
    result = SSH_FTP_FAILURE;

    if (NULL != SSH_sftpSettings()->funcPtrOpenFileUpcall)
        result = SSH_sftpSettings()->funcPtrOpenFileUpcall(CONNECTION_INSTANCE(pContextSSH),
                                                           (void*)p_sftpFileHandleDescr,
                                                           (sbyte *)pNewFilename->pString, (sbyte *)NULL, fileFlags);

    /* if error, cleanup and then exit */
    if (SSH_FTP_OK != result)
    {
        SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].isFileHandleInUse = FALSE;
        p_sftpFileHandleDescr->pHandleName = NULL;
        goto send;
    }

    /* send back an SSH_FXP_HANDLE message */
    status = sendHandleMessage(pContextSSH, id, pRetFileHandle);
    pRetFileHandle = NULL;

    goto exit;

send:
    /* send back an SSH_FXP_STATUS message */
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pFilename);
    SSH_STR_freeStringBuffer(&pNewFilename);
    SSH_STR_freeStringBuffer(&pRetFileHandle);
    freeAttr(&attr);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleFileOpen: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
closeHandle(sshContext *pContextSSH, sbyte4 handleIndex, sbyte4 *pResult)
{
    sshStringBuffer*    pHandleName = NULL;
    sshStringBuffer*    pFullPath   = NULL;
    MSTATUS             status      = OK;

    if (FALSE == SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].isDirectoryHandle)
    {
        /* call user code back */
        if (NULL != SSH_sftpSettings()->funcPtrCloseFileUpcall)
        {
            *pResult = SSH_sftpSettings()->funcPtrCloseFileUpcall(CONNECTION_INSTANCE(pContextSSH), (void*)(&SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex]));

            if (0 > *pResult)
            {
                status = (MSTATUS)*pResult;
            }
        }
        else *pResult = SSH_FTP_OK;
    }
    else
    {
        if ((kOpenDirectoryState != SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadState) &&
            (kDoneDirectoryState != SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadState))
        {
            /* only close directory if it has not been closed already, or if it got past the "to be" open state */
            SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadState = kDoneDirectoryState;

            if (NULL != SSH_sftpSettings()->funcPtrCloseDirUpcall)
            {
                *pResult = SSH_sftpSettings()->funcPtrCloseDirUpcall((sbyte4)CONNECTION_INSTANCE(pContextSSH),
                                                                   (void*)&(SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadCookie));

                if (0 > *pResult)
                {
                    status = (MSTATUS)*pResult;
                }
            }
        }
        else *pResult = SSH_FTP_OK;
    }

    SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].isFileHandleInUse = FALSE;
    SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].fileObjectIndex = 0;
    SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].cookie = 0;

    pFullPath = (sshStringBuffer *)(SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pFullPath);
    SSH_STR_freeStringBuffer(&pFullPath);
    SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pFullPath = NULL;

    pHandleName = (sshStringBuffer *)(SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pHandleName);
    SSH_STR_freeStringBuffer(&pHandleName);
    SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pHandleName = NULL;

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleFileClose(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pHandle  = NULL;
    ubyte4              bufIndex = 0;
    sbyte4              result = SSH_FTP_INVALID_HANDLE;
    sbyte4              handleIndex;
    MSTATUS             status = OK;

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out our file handle descriptor */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pHandle)))
        goto exit;

    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    /* close the file handle */
    if (0 > (handleIndex = findHandleIndex(pContextSSH, pHandle)))
        goto send;

    if (OK > (status = closeHandle(pContextSSH, handleIndex, &result)))
        goto exit;

send:
    /* send back an SSH_FXP_STATUS message */
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pHandle);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleFileClose: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleFileRead(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pHandle  = NULL;
    sbyte*              pRetMesg = NULL;
    ubyte8              offset;
    ubyte4              length;
    ubyte4              bufIndex = 0;
    sbyte4              handleIndex;
    sbyte4              result = SSH_FTP_OP_UNSUPPORTED;
    sbyte4              readBufferSize;
    sftpFileHandleDescr*p_sftpFileHandleDescr;
    MSTATUS             status = OK;

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out our file handle descriptor */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pHandle)))
        goto exit;

    /* get offset */
    if (OK > (status = getInteger64(pPayload, payloadLength, &bufIndex, &offset)))
        goto exit;

    /* get length */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &length)))
        goto exit;

    readBufferSize = (length > SFTP_READFILE_BUF_SIZE) ? SFTP_READFILE_BUF_SIZE : length;

    if (NULL == (pRetMesg = MALLOC(13 + readBufferSize)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    if ((0 != HI_U8(offset)) || (NULL == SSH_sftpSettings()->funcPtrReadFileUpcall))
    {
        result = SSH_FTP_FAILURE;
        goto send;
    }

    /* read from the file handle */
    if (0 > (handleIndex = findHandleIndex(pContextSSH, pHandle)))
        goto send;

    p_sftpFileHandleDescr = &SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex];

    p_sftpFileHandleDescr->readLocation = LOW_U8(offset);
    p_sftpFileHandleDescr->pReadBuffer = 13 + pRetMesg;
    p_sftpFileHandleDescr->readBufferSize = readBufferSize;

    /* invoke callback code */
    if (NULL != SSH_sftpSettings()->funcPtrReadFileUpcall)
    {
        result = SSH_sftpSettings()->funcPtrReadFileUpcall(CONNECTION_INSTANCE(pContextSSH), (void*)p_sftpFileHandleDescr);

        /* handle severe errors */
        if (0 > result)
        {
            status = (MSTATUS)result;
            goto exit;
        }
    }

    if (SSH_FTP_OK != result)
        goto send;

    /* send back an SSH_FXP_DATA message here */
    bufIndex = 0;

    setInteger((ubyte *)pRetMesg, 13, &bufIndex, p_sftpFileHandleDescr->numBytesRead + 1 + 8);

    if (OK > (status = setByte((ubyte *)pRetMesg, 13, &bufIndex, SSH_FXP_DATA)))
        goto exit;

    if (OK > (status = setInteger((ubyte *)pRetMesg, 13, &bufIndex, id)))
        goto exit;

    if (OK > (status = setInteger((ubyte *)pRetMesg, 13, &bufIndex, p_sftpFileHandleDescr->numBytesRead)))
        goto exit;

    status = sendFtpMessage(pContextSSH, (ubyte *)pRetMesg, p_sftpFileHandleDescr->numBytesRead + 13);
    goto exit;

send:
    /* send back an SSH_FXP_STATUS message */
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pHandle);
    if (NULL != pRetMesg)
        FREE(pRetMesg);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleFileRead: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleFileWrite(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pHandle  = NULL;
    ubyte8              offset;
    ubyte*              pData  = NULL;
    ubyte4              dataLen = 0;
    ubyte4              bufIndex = 0;
    ubyte4              result = SSH_FTP_INVALID_HANDLE;
    sftpFileHandleDescr*p_sftpFileHandleDescr;
    sbyte4                 handleIndex;
    MSTATUS             status = OK;

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out our file handle descriptor */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pHandle)))
        goto exit;

    /* get offset */
    if (OK > (status = getInteger64(pPayload, payloadLength, &bufIndex, &offset)))
        goto exit;

    /* copy out data */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &dataLen)))
        goto exit;

    pData = bufIndex + pPayload;
    bufIndex += dataLen;

    /* prevent overrun attacks */
    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    if (0 > (handleIndex = findHandleIndex(pContextSSH, pHandle)))
        goto send;

    p_sftpFileHandleDescr = &SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex];
    p_sftpFileHandleDescr->writeLocation = LOW_U8(offset);
    p_sftpFileHandleDescr->pWriteBuffer = (sbyte *)pData;
    p_sftpFileHandleDescr->writeBufferSize = dataLen;

    if (NULL == SSH_sftpSettings()->funcPtrWriteFileUpcall)
    {
        result = SSH_FTP_OP_UNSUPPORTED;
        goto send;
    }

    /* write data to the file handle */
    result = SSH_sftpSettings()->funcPtrWriteFileUpcall(CONNECTION_INSTANCE(pContextSSH), (void*)p_sftpFileHandleDescr);

send:
    /* send back an SSH_FXP_STATUS message */
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pHandle);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleFileWrite: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleRemoveFile(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pFilename = NULL;
    sshStringBuffer*    pRemoveFile = NULL;
    ATTR                attr;
    ubyte4              bufIndex  = 0;
    ubyte4              result = SSH_FTP_OP_UNSUPPORTED;
    sbyte4              fileObjectIndex = 0;
    MSTATUS             status = OK;

    /* clear attr structure */
    DIGI_MEMSET((ubyte *)&attr, 0x00, sizeof(ATTR));

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out our file handle descriptor */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pFilename)))
        goto exit;

    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    if (NULL == SSH_sftpSettings()->funcPtrRemoveFile)
        goto send;

    result = SSH_FTP_OK;

    if (OK > (status = formPath(pContextSSH, pFilename, &pRemoveFile, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    if (OK > (status = getFileStats(pContextSSH, pRemoveFile, &fileObjectIndex, &attr, &result)))
        goto exit;

    /* not a file but a directory */
    if (attr.permissions & _S_IFDIR)
    {
        result = SSH_FTP_NO_SUCH_FILE;
        goto send;
    }

    /* make sure user has read or write directory permissions */
    if (sftpFiles[fileObjectIndex].writeAccessGroup != (sftpFiles[fileObjectIndex].writeAccessGroup & SFTP_GROUP_ACCESS(pContextSSH)))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    if (sftpFiles[fileObjectIndex].executeAccessGroup != (sftpFiles[fileObjectIndex].executeAccessGroup & SFTP_GROUP_ACCESS(pContextSSH)))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    /* check pflags against attr */
    if (_S_IWRITE != (attr.permissions & _S_IWRITE))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    result = SSH_sftpSettings()->funcPtrRemoveFile(CONNECTION_INSTANCE(pContextSSH),
                                                   (sbyte *)(pRemoveFile->pString));

    /* send back an SSH_FXP_STATUS message */
send:
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pFilename);
    SSH_STR_freeStringBuffer(&pRemoveFile);
    freeAttr(&attr);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleFileRemove: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleRenameFile(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pOldPath = NULL;
    sshStringBuffer*    pNewPath = NULL;
    sshStringBuffer*    pOldFullPath = NULL;
    sshStringBuffer*    pNewFullPath = NULL;
    ubyte4              bufIndex = 0;
    ubyte4              result = SSH_FTP_PERMISSION_DENIED;
    sbyte4              oldfileObjectIndex = -1;
    sbyte4              newfileObjectIndex = -1;
    ATTR                attr;
    MSTATUS             status = OK;

    /* clear attr structure */
    DIGI_MEMSET((ubyte *)&attr, 0x00, sizeof(ATTR));

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out old path */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pOldPath)))
        goto exit;

    /* copy out new path */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pNewPath)))
        goto exit;

    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    if (NULL == SSH_sftpSettings()->funcPtrRenameFile)
        goto send;

    result = SSH_FTP_OK;

    if (OK > (status = formPath(pContextSSH, pOldPath, &pOldFullPath, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    if (OK > (status = formPath(pContextSSH, pNewPath, &pNewFullPath, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    /* protect static files */
    if ((TRUE == isStaticFileObjectEntry(pContextSSH, pOldFullPath)) ||
        (TRUE == isStaticFileObjectEntry(pContextSSH, pNewFullPath)) )
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    if (OK > (status = getFileStats(pContextSSH, pOldFullPath, &oldfileObjectIndex, &attr, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    /* not file but a directory */
    if (attr.permissions & _S_IFDIR)
    {
        result = SSH_FTP_NO_SUCH_PATH;
        goto send;
    }

    /* make sure user has read and write directory permissions */
    if (sftpFiles[oldfileObjectIndex].readAccessGroup != (sftpFiles[oldfileObjectIndex].readAccessGroup & SFTP_GROUP_ACCESS(pContextSSH)))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    if (sftpFiles[oldfileObjectIndex].executeAccessGroup != (sftpFiles[oldfileObjectIndex].executeAccessGroup & SFTP_GROUP_ACCESS(pContextSSH)))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    if (sftpFiles[oldfileObjectIndex].writeAccessGroup != (sftpFiles[oldfileObjectIndex].writeAccessGroup & SFTP_GROUP_ACCESS(pContextSSH)))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    /* check pflags against attr */
    if ((_S_IWRITE | _S_IREAD) != (attr.permissions & (_S_IWRITE | _S_IREAD)))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    freeAttr(&attr);

    if (OK > (status = getFileStats(pContextSSH, pNewFullPath, &newfileObjectIndex, &attr, &result)))
        goto exit;

    /* cannot rename file to a pre-existing file */
    if (SSH_FTP_OK == result)
    {
        result = SSH_FTP_FILE_ALREADY_EXISTS;
        goto send;
    }

    /* rename file */
    result = SSH_sftpSettings()->funcPtrRenameFile(CONNECTION_INSTANCE(pContextSSH), (sbyte *)(pOldFullPath->pString), (sbyte *)(pNewFullPath->pString));

    /* send back an SSH_FXP_STATUS message */
send:
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pOldPath);
    SSH_STR_freeStringBuffer(&pNewPath);
    SSH_STR_freeStringBuffer(&pOldFullPath);
    SSH_STR_freeStringBuffer(&pNewFullPath);
    freeAttr(&attr);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleRenameFile: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleCreateDirectory(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pPath       = NULL;
    sshStringBuffer*    pCreatePath = NULL;
    ATTR                attr;
    ubyte4              bufIndex = 0;
    ubyte4              result = SSH_FTP_PERMISSION_DENIED;
    sbyte4              fileObjectIndex = 0;
    MSTATUS             status = OK;

    /* clear attr structure */
    DIGI_MEMSET((ubyte *)&attr, 0x00, sizeof(ATTR));

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out path */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pPath)))
        goto exit;

    /* copy out ATTR */
    if (OK > (status = getAttr(pPayload, payloadLength, &bufIndex, &attr, SSH_FTP_VERSION(pContextSSH))))
        goto exit;

    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    /* create directory here */
    if (NULL == SSH_sftpSettings()->funcPtrCreateDir)
    {
        result = SSH_FTP_OP_UNSUPPORTED;
        goto send;
    }

    result = SSH_FTP_OK;

    if (OK > (status = formPath(pContextSSH, pPath, &pCreatePath, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    /* protect static files */
    if (TRUE == isStaticFileObjectEntry(pContextSSH, pCreatePath))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    freeAttr(&attr);

    if (OK > (status = getFileStats(pContextSSH, pCreatePath, &fileObjectIndex, &attr, &result)))
        goto exit;

    /* make sure the user has permission to execute and write permissions to this directory */
    if ((sftpFiles[fileObjectIndex].executeAccessGroup != (sftpFiles[fileObjectIndex].executeAccessGroup & SFTP_GROUP_ACCESS(pContextSSH))) ||
        (sftpFiles[fileObjectIndex].writeAccessGroup   != (sftpFiles[fileObjectIndex].writeAccessGroup   & SFTP_GROUP_ACCESS(pContextSSH))))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    result = SSH_sftpSettings()->funcPtrCreateDir(CONNECTION_INSTANCE(pContextSSH), (sbyte *)(pCreatePath->pString));

send:
    /* send back an SSH_FXP_STATUS message */
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pCreatePath);
    SSH_STR_freeStringBuffer(&pPath);
    freeAttr(&attr);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleCreateDirectory: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleRemoveDirectory(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pPath       = NULL;
    sshStringBuffer*    pRemovePath = NULL;
    ATTR                attr;
    ubyte4              bufIndex = 0;
    ubyte4              result   = SSH_FTP_PERMISSION_DENIED;
    sbyte4              fileObjectIndex = 0;
    MSTATUS             status   = OK;

    /* clear attr structure */
    DIGI_MEMSET((ubyte *)&attr, 0x00, sizeof(ATTR));

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out path */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pPath)))
        goto exit;

    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    /* remove directory here */
    if (NULL == SSH_sftpSettings()->funcPtrRemoveDir)
    {
        result = SSH_FTP_OP_UNSUPPORTED;
        goto send;
    }

    result = SSH_FTP_OK;

    if (OK > (status = formPath(pContextSSH, pPath, &pRemovePath, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    /* protect static files */
    if (TRUE == isStaticFileObjectEntry(pContextSSH, pRemovePath))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    if (OK > (status = getFileStats(pContextSSH, pRemovePath, &fileObjectIndex, &attr, &result)))
        goto exit;

    /* not a directory but a file */
    if (!(attr.permissions & _S_IFDIR))
    {
        result = SSH_FTP_NO_SUCH_PATH;
        goto send;
    }

    /* make sure the user has permission to execute and write permissions to this directory */
    if ((sftpFiles[fileObjectIndex].executeAccessGroup != (sftpFiles[fileObjectIndex].executeAccessGroup & SFTP_GROUP_ACCESS(pContextSSH))) ||
        (sftpFiles[fileObjectIndex].writeAccessGroup   != (sftpFiles[fileObjectIndex].writeAccessGroup   & SFTP_GROUP_ACCESS(pContextSSH))))
    {
        result = SSH_FTP_PERMISSION_DENIED;
        goto send;
    }

    if (0 > (status = result = (SSH_sftpSettings()->funcPtrRemoveDir(CONNECTION_INSTANCE(pContextSSH), (sbyte *)(pRemovePath->pString)))))
        goto exit;

send:
    /* send back an SSH_FXP_STATUS message */
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pPath);
    SSH_STR_freeStringBuffer(&pRemovePath);
    freeAttr(&attr);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleRemoveDirectory: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleOpenDirectory(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pPath = NULL;
    sshStringBuffer*    pReplyPath = NULL;
    sshStringBuffer*    pRetFileHandle = NULL;
    ubyte4              bufIndex = 0;
    ubyte4              result;
    sbyte4              handleIndex;
    sbyte4              fileObjectIndex = 0;
    ATTR                attr;
    MSTATUS             status = OK;

    /* clear attr structure */
    DIGI_MEMSET((ubyte *)&attr, 0x00, sizeof(ATTR));

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out path */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pPath)))
        goto exit;

    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    /* open directory */
    result = SSH_FTP_OK;

    if (OK > (status = formPath(pContextSSH, pPath, &pReplyPath, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    if (OK > (status = getFileStats(pContextSSH, pReplyPath, &fileObjectIndex, &attr, &result)))
        goto exit;

    /* not a directory but a file */
    if (!(attr.permissions & _S_IFDIR))
    {
        result = SSH_FTP_NO_SUCH_PATH;
        goto send;
    }

    if (0 > (handleIndex = getHandleIndex(pContextSSH)))
    {
        /* too many open file handles */
        result = SSH_FTP_FAILURE;
        goto send;
    }

    if (OK > (status = createFileHandle(handleIndex, &pRetFileHandle)))
    {
        goto exit;
    }

    /* setup for subsequent readdir */
    SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].isDirectoryHandle = TRUE;
    SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pFullPath = pReplyPath; pReplyPath = NULL;
    SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadCookie = 0;
    SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pHandleName = pRetFileHandle;
    SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].fileObjectIndex = 0;
    SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadState = kOpenDirectoryState;
    SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadCookie = 0;

    /* send back an SSH_FXP_HANDLE message */
    status = sendHandleMessage(pContextSSH, id, pRetFileHandle);
    pRetFileHandle = NULL;

    goto exit;

send:
    /* send back an SSH_FXP_STATUS message */
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pPath);
    SSH_STR_freeStringBuffer(&pReplyPath);
    SSH_STR_freeStringBuffer(&pRetFileHandle);
    freeAttr(&attr);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleOpenDirectory: status = ", status);
#endif

    return status;

} /* handleOpenDirectory */


/*------------------------------------------------------------------*/

static MSTATUS
handleReadDirectory(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pHandle     = NULL;
    sshStringBuffer*    pFilename   = NULL;
    sshStringBuffer*    pConcatPath = NULL;
    sshStringBuffer*    pLookupPath = NULL;
    sftpFileObjDescr    sftpFile;
    ubyte4              bufIndex = 0;
    sbyte4              fileObjectIndex;
    sbyte4              handleIndex;
    ATTR                attr;
    ubyte4              result = SSH_FTP_INVALID_HANDLE;
    ubyte*              pTempName  = NULL;
    ubyte4              tmpNameLen = 0;
    MSTATUS             status = OK;

    /* clear attr structure */
    DIGI_MEMSET((ubyte *)&attr, 0x00, sizeof(ATTR));

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out handle */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pHandle)))
        goto exit;

    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    /* read directory */
    if (0 > (handleIndex = findHandleIndex(pContextSSH, pHandle)))
        goto send;

    fileObjectIndex = (sbyte4) ((usize)SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].fileObjectIndex);

    while (fileObjectIndex < SFTP_NUM_FILES())
    {
        if (TRUE == isWithinDirectory(&(sftpFiles[fileObjectIndex]), SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pFullPath))
        {
            /* save position for next readdir */
            SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].fileObjectIndex = (void*)((usize)(fileObjectIndex + 1));      /* move to next row */
            break;
        }

        fileObjectIndex++;
    }

    if (SFTP_NUM_FILES() > fileObjectIndex)
    {
        pTempName = SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pFullPath->stringLen + sftpFiles[fileObjectIndex].fileName;
        tmpNameLen = sftpFiles[fileObjectIndex].fileNameLength - SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pFullPath->stringLen;

        if ((1 < tmpNameLen) && ('/' == *pTempName))
        {
            pTempName++;
            tmpNameLen--;
        }

        dupFromSftpDescr(pContextSSH, &sftpFiles[fileObjectIndex], fileObjectIndex, &attr);

        goto skip;
    }

    SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].fileObjectIndex = (void*)((usize)(SFTP_NUM_FILES() + 1));

    /* handle dynamic directory */
    if (kOpenDirectoryState == SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadState)
    {
        SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadState = kReadDirectoryState;

        if (NULL != SSH_sftpSettings()->funcPtrOpenDirUpcall)
        {
            /* handle if open fails */
            if (SSH_FTP_OK != SSH_sftpSettings()->funcPtrOpenDirUpcall(CONNECTION_INSTANCE(pContextSSH),
                                                              (sbyte *)(SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pFullPath->pString),
                                                              &SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadCookie))
            {
                /* unable to open directory */
                SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadState = kDoneDirectoryState;
            }

        }
    }

    if (kReadDirectoryState == SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadState)
    {
        ubyte4      tmpResult = SSH_FTP_OK;
        sbyte4      dirResult = SSH_FTP_EOF;
        intBoolean  doWhile   = FALSE;

        if (NULL != SSH_sftpSettings()->funcPtrReadDirUpcall)
        {
            do
            {
                dirResult = SSH_sftpSettings()->funcPtrReadDirUpcall(CONNECTION_INSTANCE(pContextSSH),
                                                                     (sbyte *)(SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pFullPath->pString), &sftpFile,
                                                                     &(SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadCookie));

                if (0 > dirResult)
                {
                    status = (MSTATUS)dirResult;
                    goto exit;
                }

                if (SSH_FTP_OK == dirResult)
                {
                    if (('.' == sftpFile.fileName[0]) && (1 == sftpFile.fileNameLength))
                    {
                        doWhile = TRUE;
                        continue;
                    }

                    /* free in case we loop */
                    SSH_STR_freeStringBuffer(&pConcatPath);
                    SSH_STR_freeStringBuffer(&pLookupPath);

                    /* concat path with file name */
                    if (OK > (status = SSH_STR_makeStringBuffer(&pConcatPath, SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pFullPath->stringLen + 1 + sftpFile.fileNameLength)))
                        goto exit;

                    DIGI_MEMCPY(pConcatPath->pString, SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pFullPath->pString, SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pFullPath->stringLen);

                    pConcatPath->pString[SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pFullPath->stringLen] = '/';

                    DIGI_MEMCPY(SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].pFullPath->stringLen + 1 + pConcatPath->pString, sftpFile.fileName, sftpFile.fileNameLength);

                    /* condense full path */
                    tmpResult = SSH_FTP_OK;

                    if (OK > (status = formPath(pContextSSH, pConcatPath, &pLookupPath, &tmpResult)))
                        goto exit;

                    doWhile = isStaticFileObjectEntry(pContextSSH, pLookupPath);
                }
            }
            while ((SSH_FTP_OK == dirResult) && (SSH_FTP_OK == tmpResult) && (TRUE == doWhile));
        }

        if (SSH_FTP_OK != dirResult)
            SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadState = kCloseDirectoryState;
        else
        {
            freeAttr(&attr);

            if (OK > (status = getVirtualFileIndex(pContextSSH, pLookupPath, &fileObjectIndex, NULL)))
                goto exit;

            dupFromSftpDescr(pContextSSH, &sftpFile, fileObjectIndex, &attr);
            pTempName = sftpFile.fileName;
            tmpNameLen = sftpFile.fileNameLength;
        }
    }

    if (kCloseDirectoryState == SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadState)
    {
        SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadState = kDoneDirectoryState;

        if (NULL != SSH_sftpSettings()->funcPtrCloseDirUpcall)
            SSH_sftpSettings()->funcPtrCloseDirUpcall((sbyte4)CONNECTION_INSTANCE(pContextSSH),
                                                      (void*)&SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadCookie);
    }

    if (kDoneDirectoryState == SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].directoryReadState)
    {
        result = SSH_FTP_EOF;
        /* save position for next readdir */
        SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].fileObjectIndex = ((void *)(usize)fileObjectIndex);
        goto send;
    }

skip:
    /* send back an SSH_FXP_NAME message */
    if (OK > (status = SSH_STR_makeStringBuffer(&pFilename, tmpNameLen)))
        goto exit;

    DIGI_MEMCPY(pFilename->pString, pTempName, tmpNameLen);

    status = sendNameMessage(pContextSSH, id, pFilename, &attr, TRUE);

    goto exit;

send:
    /* send back an SSH_FXP_STATUS message */
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pHandle);
    SSH_STR_freeStringBuffer(&pFilename);
    SSH_STR_freeStringBuffer(&pConcatPath);
    SSH_STR_freeStringBuffer(&pLookupPath);
    freeAttr(&attr);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleReadDirectory: status = ", status);
#endif

    return status;

} /* handleReadDirectory */


/*------------------------------------------------------------------*/

static MSTATUS
handleStatFile(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pPath = NULL;
    sshStringBuffer*    pStatPath = NULL;
    ubyte4              flags = 0;
    ubyte4              bufIndex = 0;
    ATTR                attr;
    ubyte4              result = SSH_FTP_BAD_MESSAGE;
    sbyte4              fileObjectIndex = 0;
    MSTATUS             status = OK;

    /* clear attr structure */
    DIGI_MEMSET((ubyte *)&attr, 0x00, sizeof(ATTR));

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out path */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pPath)))
        goto exit;

    /* get flags */
    if (3 < SSH_FTP_VERSION(pContextSSH))
        if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &flags)))
            goto exit;

    if (payloadLength != bufIndex)
        goto send;

    /* get stats */
    result = SSH_FTP_OK;

    if (OK > (status = formPath(pContextSSH, pPath, &pStatPath, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    if (OK > (status = getFileStats(pContextSSH, pStatPath, &fileObjectIndex, &attr, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    /* send back an SSH_FXP_ATTRS message */
    status = sendAttrsMessage(pContextSSH, id, &attr);
    goto exit;

send:
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pPath);
    SSH_STR_freeStringBuffer(&pStatPath);
    freeAttr(&attr);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleStatFile: status = ", status);
#endif

    return status;

} /* handleStatFile */


/*------------------------------------------------------------------*/

static MSTATUS
handleStatNoSymbolicLinkFile(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pPath = NULL;
    sshStringBuffer*    pStatPath = NULL;
    ubyte4              flags;
    ubyte4              bufIndex = 0;
    ATTR                attr;
    ubyte4              result = SSH_FTP_BAD_MESSAGE;
    sbyte4              fileObjectIndex = 0;
    MSTATUS             status = OK;

    /* clear attr structure */
    DIGI_MEMSET((ubyte *)&attr, 0x00, sizeof(ATTR));

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out path */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pPath)))
        goto exit;

    /* get flags */
    if (3 < SSH_FTP_VERSION(pContextSSH))
        if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &flags)))
            goto exit;

    if (payloadLength != bufIndex)
        goto send;

    /* get stats */
    result = SSH_FTP_OK;

    if (OK > (status = formPath(pContextSSH, pPath, &pStatPath, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    if (OK > (status = getFileStats(pContextSSH, pStatPath, &fileObjectIndex, &attr, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    /* send back an SSH_FXP_STATUS message */
    status = sendAttrsMessage(pContextSSH, id, &attr);
    goto exit;

send:
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pPath);
    SSH_STR_freeStringBuffer(&pStatPath);
    freeAttr(&attr);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleStatNoSymbolicLinkFile: status = ", status);
#endif

    return status;

} /* handleStatNoSymbolicLinkFile*/


/*------------------------------------------------------------------*/

static MSTATUS
handleStatForOpenFile(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pHandle = NULL;
    ubyte4              flags;
    ubyte4              bufIndex = 0;
    ATTR                attr;
    sbyte4              handleIndex;
    ubyte4              result = SSH_FTP_OP_UNSUPPORTED;
    MSTATUS             status = OK;

    /* clear attr structure */
    DIGI_MEMSET((ubyte *)&attr, 0x00, sizeof(ATTR));

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out handle */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pHandle)))
        goto exit;

    /* get flags */
    if (3 < SSH_FTP_VERSION(pContextSSH))
        if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &flags)))
            goto exit;

    if (payloadLength != bufIndex)
        goto send;

    if (0 > (handleIndex = findHandleIndex(pContextSSH, pHandle)))
        goto send;

    if (TRUE == SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].isDirectoryHandle)
        goto send;

    /* get stats for open file here */
    if (OK > (status = getFileStatsForOpenFile(pContextSSH, handleIndex, &attr, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    status = sendAttrsMessage(pContextSSH, id, &attr);
    goto exit;

send:
    /* send back an SSH_FXP_STATUS message */
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pHandle);
    freeAttr(&attr);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleStatForOpenFile: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleSetFileStat(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pPath = NULL;
    ATTR                attr;
    ubyte4              bufIndex = 0;
    ubyte4              result = SSH_FTP_OP_UNSUPPORTED;
    MSTATUS             status = OK;

    /* clear attr structure */
    DIGI_MEMSET((ubyte *)&attr, 0x00, sizeof(ATTR));

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out path */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pPath)))
        goto exit;

    /* copy out ATTR */
    if (OK > (status = getAttr(pPayload, payloadLength, &bufIndex, &attr, SSH_FTP_VERSION(pContextSSH))))
        goto exit;

    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    /* !!!! change file stat */
    result = SSH_FTP_OK;

send:
    /* send back an SSH_FXP_STATUS message */
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pPath);
    freeAttr(&attr);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleSetFileStat: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleSetOpenFileStat(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pHandle = NULL;
    ATTR                attr;
    ubyte4              bufIndex = 0;
    ubyte4              result = SSH_FTP_OP_UNSUPPORTED;
    MSTATUS             status = OK;

    /* clear attr structure */
    DIGI_MEMSET((ubyte *)&attr, 0x00, sizeof(ATTR));

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out handle */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pHandle)))
        goto exit;

    /* copy out ATTR */
    if (OK > (status = getAttr(pPayload, payloadLength, &bufIndex, &attr, SSH_FTP_VERSION(pContextSSH))))
        goto exit;

    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    /* change open file stats here */

send:
    /* send back an SSH_FXP_STATUS message */
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pHandle);
    freeAttr(&attr);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleSetOpenFileStat: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleReadSymbolicLink(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pPath = NULL;
    ubyte4              bufIndex = 0;
    ubyte4              result = SSH_FTP_OP_UNSUPPORTED;
    MSTATUS             status = OK;

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out path */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pPath)))
        goto exit;

    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    /* !!!! read symbolic link here */

send:
    /* send back an SSH_FXP_STATUS message */
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pPath);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleReadSymbolicLink: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleCreateSymbolicLink(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pLinkPath = NULL;
    sshStringBuffer*    pTargetPath = NULL;
    ubyte4              bufIndex = 0;
    ubyte4              result = SSH_FTP_PERMISSION_DENIED;
    MSTATUS             status = OK;

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out link path */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pLinkPath)))
        goto exit;

    /* copy out target path */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pTargetPath)))
        goto exit;

    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    /* !!!! create symbolic link here */

send:
    /* send back an SSH_FXP_STATUS message */
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pLinkPath);
    SSH_STR_freeStringBuffer(&pTargetPath);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleCreateSymbolicLink: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleCreateRealPath(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4              id;
    sshStringBuffer*    pPath      = NULL;
    sshStringBuffer*    pReplyPath = NULL;
    ubyte4              bufIndex   = 0;
    ubyte4              result     = SSH_FTP_OK;
    ATTR                attr;
    sbyte4              fileObjectIndex = 0;
    MSTATUS             status     = OK;

    /* clear attr structure */
    DIGI_MEMSET((ubyte *)&attr, 0x00, sizeof(ATTR));

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    /* copy out path */
    if (OK > (status = SSH_STR_copyStringFromPayload2(pPayload, payloadLength, &bufIndex, &pPath)))
        goto exit;

    if (payloadLength != bufIndex)
    {
        result = SSH_FTP_BAD_MESSAGE;
        goto send;
    }

    if (OK > (status = formPath(pContextSSH, pPath, &pReplyPath, &result)))
        goto exit;

    if (SSH_FTP_OK != result)
        goto send;

    if (OK > (status = getFileStats(pContextSSH, pReplyPath, &fileObjectIndex, &attr, &result)))
        goto exit;

    if (0 != result)
        goto send;

    /* send back an SSH_FXP_NAME message here */
    attr.flags = 0;
    status = sendNameMessage(pContextSSH, id, pReplyPath, &attr, FALSE);
    goto exit;

send:
    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, result);

exit:
    SSH_STR_freeStringBuffer(&pPath);
    SSH_STR_freeStringBuffer(&pReplyPath);
    freeAttr(&attr);

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleCreateRealPath: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleUnsupportedRequest(sshContext *pContextSSH, ubyte *pPayload, ubyte4 payloadLength)
{
    ubyte4  id;
    ubyte4  bufIndex   = 0;
    MSTATUS status;

    /* get transaction id */
    if (OK > (status = getInteger(pPayload, payloadLength, &bufIndex, &id)))
        goto exit;

    status = SEND_SFTP_STATUS_MACRO(pContextSSH, id, SSH_FTP_OP_UNSUPPORTED);

exit:

#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "handleUnsupportedRequest: status = ", status);
#endif

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
checkBuffer(sshContext *pContextSSH, ubyte4 requestedSize)
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
sftpReceiveMessage(sshContext *pContextSSH,
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
SSH_FTP_closeAllOpenHandles(sshContext *pContextSSH)
{
    sbyte4     handleIndex;
    sbyte4  result;

    DIGI_STREAM_close(&(pContextSSH->sessionState.pSftpOutStreamDescr));

    for (handleIndex = 0; SFTP_NUM_HANDLES > handleIndex; handleIndex++)
        if (TRUE == SSH_FTP_FILE_HANDLE_TABLE(pContextSSH)[handleIndex].isFileHandleInUse)
            closeHandle(pContextSSH, handleIndex, &result);

    return OK;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
SSH_FTP_doProtocol(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    MSTATUS     (*funcMethod)(sshContext *pContextSSH, ubyte *, ubyte4) = NULL;
    ubyte*      pPayload = NULL;
    ubyte4      payloadLength = 0;
    MSTATUS     status = OK;

    while (0 < newMesgLen)
    {
        if (OK > (status = DIGI_STREAM_flush(pContextSSH->sessionState.pSftpOutStreamDescr, NULL, NULL)))
            goto exit;

        if (OK > (status = sftpReceiveMessage(pContextSSH, &pNewMesg, &newMesgLen)))
            goto exit;

        if (SFTP_RECEIVE_MESSAGE_COMPLETED != pContextSSH->sftpState)
            continue;

#ifdef __ENABLE_ALL_DEBUGGING__
        DUMP_MESG_sftpMessage(pContextSSH->p_sftpIncomingBuffer, pContextSSH->sftpNumBytesRequired, FALSE);
#endif /* __ENABLE_ALL_DEBUGGING__ */

        pPayload = 1 + pContextSSH->p_sftpIncomingBuffer;
        payloadLength = pContextSSH->sftpNumBytesRequired - 1;

        switch (*(pContextSSH->p_sftpIncomingBuffer))
        {
            case SSH_FXP_INIT:
                funcMethod = handleFtpHello;
                break;

            case SSH_FXP_OPEN:
                funcMethod = handleFileOpen;
                break;

            case SSH_FXP_CLOSE:
                funcMethod = handleFileClose;
                break;

            case SSH_FXP_READ:
                funcMethod = handleFileRead;
                break;

            case SSH_FXP_WRITE:
                funcMethod = handleFileWrite;
                break;

            case SSH_FXP_LSTAT:
                funcMethod = handleStatNoSymbolicLinkFile;
                break;

            case SSH_FXP_FSTAT:
                funcMethod = handleStatForOpenFile;
                break;

            case SSH_FXP_SETSTAT:
                funcMethod = handleSetFileStat;
                break;

            case SSH_FXP_FSETSTAT:
                funcMethod = handleSetOpenFileStat;
                break;

            case SSH_FXP_OPENDIR:
                funcMethod = handleOpenDirectory;
                break;

            case SSH_FXP_READDIR:
                funcMethod = handleReadDirectory;
                break;

            case SSH_FXP_REMOVE:
                funcMethod = handleRemoveFile;
                break;

            case SSH_FXP_MKDIR:
                funcMethod = handleCreateDirectory;
                break;

            case SSH_FXP_RMDIR:
                funcMethod = handleRemoveDirectory;
                break;

            case SSH_FXP_REALPATH:
                funcMethod = handleCreateRealPath;
                break;

            case SSH_FXP_STAT:
                funcMethod = handleStatFile;
                break;

            case SSH_FXP_RENAME:
                funcMethod = handleRenameFile;
                break;

            case SSH_FXP_READLINK:
                if (2 < SSH_FTP_VERSION(pContextSSH))
                    funcMethod = handleReadSymbolicLink;
                break;

            case SSH_FXP_SYMLINK:
                if (2 < SSH_FTP_VERSION(pContextSSH))
                    funcMethod = handleCreateSymbolicLink;
                break;

            case SSH_FXP_VERSION:
                /* generates an error */
                funcMethod = NULL;
                break;

            default:
                funcMethod = handleUnsupportedRequest;
                break;
        }

        if (NULL != funcMethod)
            status = funcMethod(pContextSSH, pPayload, payloadLength);
        else
            status = ERR_SFTP_MALFORMED_MESSAGE;

        if (OK > status)
            goto exit;

    } /* while loop */

exit:
#ifdef __DEBUG_SSH_FTP__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSH_SFTP, "SSH_FTP_doProtocol: status = ", status);
#endif

    return status;

} /* SSH_FTP_doProtocol */

#endif /* (defined(__ENABLE_DIGICERT_SSH_SERVER__) && defined(__ENABLE_DIGICERT_SSH_FTP_SERVER__)) */

/* !!!! idle timeout - these are handled at the lower layer, but would be nice to handle them here */
/* !!!! max session timeout */
