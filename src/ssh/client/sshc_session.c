/*
 * sshc_session.c
 *
 * SSH Client Session Handler
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

#include "../../common/moptions.h"

#ifdef __ENABLE_MOCANA_SSH_CLIENT__

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
#include "../../common/circ_buf.h"
#include "../../crypto/dsa.h"
#include "../../crypto/dh.h"
#include "../../crypto/crypto.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif
#include "../../crypto/pubcrypto.h"
#include "../../common/sizedbuffer.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/ca_mgmt.h"
#include "../../ssh/ssh_defs.h"
#include "../../ssh/client/sshc.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc_str_house.h"
#include "../../ssh/client/sshc_context.h"
#include "../../ssh/client/sshc_out_mesg.h"
#include "../../ssh/client/sshc_client.h"
#include "../../ssh/client/sshc_session.h"
#include "../../ssh/client/sshc_filesys.h"
#include "../../ssh/client/sshc_ftp.h"
#include "../../ssh/client/sshc_trans.h"
#include "../../ssh/client/sshc_utils.h"

extern sbyte4 SSH_INTERNAL_API_setOpenState(sbyte4 connectionInstance);

#define SSH2_MSG_USERAUTH_LOW               (50)
#define SSH2_MSG_USERAUTH_HIGH              (79)


/*------------------------------------------------------------------*/

static sbyte4  m_channel = 0;

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
static MSTATUS getSessionDataFromChannel(sshcConnectDescr* pDescr,sshClientContext* pContextSSH, sbyte4 channel, sshcPfSession** ppSession );
static MSTATUS sendOpenLpfSessionChannel(sshClientContext *pContextSSH, sshcPfSession* pSession, ubyte* pConnectHost, ubyte4 connectPort, ubyte* pSrc, ubyte4 srcPort);
static MSTATUS destroyLocalPortFwdSession(sshcConnectDescr* pDescr,sshClientContext* pContextSSH, sbyte4 channel);
static MSTATUS sendLpfClose( sshClientContext* pContextSSH, ubyte4 channel );
static MSTATUS sendLpfEof( sshClientContext* pContextSSH, ubyte4 channel );
#endif /*__ENABLE_MOCANA_SSH_PORT_FORWARDING__*/

/*------------------------------------------------------------------*/

static ubyte4
getUbyte4(ubyte *pInteger)
{
    ubyte4 value;

    value  = ((ubyte4)pInteger[0]) << 24;
    value |= ((ubyte4)pInteger[1]) << 16;
    value |= ((ubyte4)pInteger[2]) <<  8;
    value |= ((ubyte4)pInteger[3]);

    return value;
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

extern MSTATUS
SSHC_SESSION_sendMessage(sshClientContext *pContextSSH, ubyte *pMesg,
                         ubyte4 mesgLen, ubyte4 *pBytesSent)
{
    ubyte*  pMessage = NULL;
    ubyte4  numBytesToWrite;
    ubyte4  numBytesWritten;
    MSTATUS status = OK;

    *pBytesSent = 0;

    /* nothing to send */
    if (0 == mesgLen)
        goto exit;

    /* make sure session is open, before sending data to client */
    if ((FALSE          == pContextSSH->sessionState.isShellActive) ||
        (SESSION_CLOSED == pContextSSH->sessionState.channelState))
    {
        status = ERR_SESSION_NOT_OPEN;
        goto exit;
    }

    if (TRUE == pContextSSH->isReKeyOccuring)
    {
        /* session is open, but we're in a re-key exchange state */
        goto exit;
    }

    if (NULL == (pMessage = MALLOC(mesgLen + 9)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* send as much data as client window is able to handle */
    if (mesgLen > pContextSSH->sessionState.windowSize)
        mesgLen = pContextSSH->sessionState.windowSize;

    /* write the message out in chunks */
    while (0 < mesgLen)
    {
        if (OK > (status = (SSHC_OUT_MESG_sendMessageSize(pContextSSH, mesgLen + 9,
                                                          &numBytesToWrite))))
        {
            goto exit;
        }

        /* the protocol governor */
        if (numBytesToWrite > pContextSSH->sessionState.maxPacketSize)
            numBytesToWrite = pContextSSH->sessionState.maxPacketSize;

        /* subtract message header */
        numBytesToWrite -= 9;

        pMessage[0] = SSH_MSG_CHANNEL_DATA;

        pMessage[1] = (ubyte)((pContextSSH->sessionState.recipientChannel) >> 24);
        pMessage[2] = (ubyte)((pContextSSH->sessionState.recipientChannel) >> 16);
        pMessage[3] = (ubyte)((pContextSSH->sessionState.recipientChannel) >>  8);
        pMessage[4] = (ubyte)((pContextSSH->sessionState.recipientChannel));

        pMessage[5] = (ubyte)(numBytesToWrite >> 24);
        pMessage[6] = (ubyte)(numBytesToWrite >> 16);
        pMessage[7] = (ubyte)(numBytesToWrite >>  8);
        pMessage[8] = (ubyte)(numBytesToWrite);

        MOC_MEMCPY(pMessage + 9, pMesg, numBytesToWrite);

        if (OK > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, pMessage,
                                                     numBytesToWrite + 9, &numBytesWritten)))
        {
            goto exit;
        }

        pMesg       += numBytesToWrite;
        mesgLen     -= numBytesToWrite;
        *pBytesSent += numBytesToWrite;
        pContextSSH->sessionState.windowSize -= numBytesToWrite;
    }

exit:
    if (NULL != pMessage)
        FREE(pMessage);

    return status;

} /* SSHC_SESSION_sendMessage */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_SESSION_handleGlobalMesgReq(sshClientContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4  numBytesWritten;
    ubyte   msgReqFailed = SSH_MSG_REQUEST_FAILURE;
    MSTATUS status       = OK;

    /* ignore this message type, unless we are forced to reply */
    if (6 < mesgLen)
    {
        ubyte4 length = getUbyte4(1 + pMesg);

        if (length < mesgLen)
        {
            if (1 == pMesg[1 + 4 + length])
            {
                /* we don't like the message */
                status = SSHC_OUT_MESG_sendMessage(pContextSSH, &msgReqFailed, 1, &numBytesWritten);
            }
        }
    }

    return status;

} /* SSHC_SESSION_handleGlobalMesgReq */


/*------------------------------------------------------------------*/

static MSTATUS
sendOpenSessionChannel(sshClientContext *pContextSSH)
{

/*   byte      SSH_MSG_CHANNEL_OPEN
     string    channel type (restricted to US-ASCII) "session"
     uint32    sender channel
     uint32    initial window size
     uint32    maximum packet size
     ...       extra data
*/
    MSTATUS status;
    ubyte* pBuffer;
    ubyte4 buflen;
    ubyte4 myChannel = ++m_channel;
    ubyte4 bufIndex = 0;
    ubyte4 windowSize;
    ubyte4 written;

    buflen = 1 +
             sshc_sessionService.stringLen +
             4 +
             4 +
             4;

    if (NULL == (pBuffer = MALLOC(buflen))) {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *pBuffer = SSH_MSG_CHANNEL_OPEN;
    bufIndex++;

    MOC_MEMCPY(pBuffer + bufIndex, sshc_sessionService.pString, sshc_sessionService.stringLen);
    bufIndex += sshc_sessionService.stringLen;

    /* client channel */
    *(pBuffer + bufIndex    )  = (ubyte)(myChannel >> 24);
    *(pBuffer + bufIndex + 1)  = (ubyte)(myChannel >> 16);
    *(pBuffer + bufIndex + 2)  = (ubyte)(myChannel >> 8);
    *(pBuffer + bufIndex + 3)  = (ubyte)(myChannel);

    /* initial window size */
    windowSize = MAX_SESSION_WINDOW_SIZE;
    *(pBuffer + bufIndex + 4) = 0;
    *(pBuffer + bufIndex + 5) = 0;
    *(pBuffer + bufIndex + 6) = (ubyte)(windowSize >>  8);
    *(pBuffer + bufIndex + 7) = (ubyte)(windowSize);

    /* max packet size -- uses window size */
    *(pBuffer + bufIndex + 8)  = 0;
    *(pBuffer + bufIndex + 9)  = 0;
    *(pBuffer + bufIndex + 10) = (ubyte)(windowSize >>  8);
    *(pBuffer + bufIndex + 11) = (ubyte)(windowSize);

    pContextSSH->sessionState.clientChannel    = myChannel;

#ifdef __ENABLE_MOCANA_SSH_FTP_CLIENT__
    pContextSSH->sessionState.clientWindowSize = windowSize;
#endif

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pBuffer, buflen, &written);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* sendOpenSessionChannel */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_SESSION_OpenSessionChannel(sbyte4 connectionInstance)
{
    MSTATUS status;
    sshcConnectDescr *pConn;

    if (NULL == (pConn = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (TRUE == pConn->pContextSSH->sessionState.isChannelActive)
    {
        /* for now we only support 1 session at a time */
        status = ERR_SSH_DISCONNECT_TOO_MANY_CONNECTIONS;
        goto exit;
    }

    status = sendOpenSessionChannel(pConn->pContextSSH);

exit:
    return status;

} /* SSHC_SESSION_OpenSessionChannel */


/*------------------------------------------------------------------*/

static MSTATUS
sendCloseSessionChannel(sshClientContext *pContextSSH)
{
    ubyte   payload[5];
    ubyte4  numBytesWritten;
    MSTATUS status = OK;

    if (OK > (status = SSHC_SESSION_sendMessage(pContextSSH, (ubyte *)CRLF, 2, &numBytesWritten)))
        goto exit;

    /* make sure session is open, before sending a session close */
    if ((TRUE           != pContextSSH->sessionState.isChannelActive) ||
        (SESSION_CLOSED == pContextSSH->sessionState.channelState))
    {
        goto exit;
    }

    /*
      byte      SSH_MSG_CHANNEL_EOF
      uint32    recipient channel
     */
    payload[0] = SSH_MSG_CHANNEL_EOF;
    payload[1] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 24);
    payload[2] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 16);
    payload[3] = (ubyte)(pContextSSH->sessionState.recipientChannel >>  8);
    payload[4] = (ubyte)(pContextSSH->sessionState.recipientChannel);

    if (OK > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesWritten)))
        goto exit;

    /*
      byte      SSH_MSG_CHANNEL_CLOSE
      uint32    recipient channel
     */
    payload[0] = SSH_MSG_CHANNEL_CLOSE;
    payload[1] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 24);
    payload[2] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 16);
    payload[3] = (ubyte)(pContextSSH->sessionState.recipientChannel >>  8);
    payload[4] = (ubyte)(pContextSSH->sessionState.recipientChannel);

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesWritten);

exit:
    /* if rxdClosed is TRUE, we know server already sent SSH_MSG_CHANNEL_CLOSE,
     * can close session. */
    if (TRUE == pContextSSH->sessionState.rxdClosed)
        pContextSSH->sessionState.channelState = SESSION_CLOSED;

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_SSH_SERVICE, (sbyte*)"sendCloseSessionChannel: SSHC_OUT_MESG_sendMessage failed. status: ", status);
    }
#endif
    return status;
} /* sendCloseSessionChannel */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_SESSION_CloseSessionChannel(sbyte4 connectionInstance)
{
    MSTATUS status;
    sshcConnectDescr *pConn;

    if (NULL == (pConn = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (FALSE == pConn->pContextSSH->sessionState.isChannelActive)
    {
        status = ERR_SSH_DISCONNECT_CHANNEL_CLOSED;
        goto exit;
    }

    status = sendCloseSessionChannel(pConn->pContextSSH);

exit:
    return status;

} /* SSHC_SESSION_CloseSessionChannel */


/*------------------------------------------------------------------*/

/*
 * WARNING:  it is assumed that pRequestType and pData are (essentially) string
 * constants inited by sshc_str_house code, the length is included in the string data
 * and that the memory for these things is not freed.
 */
static MSTATUS
sendChannelRequest(sshClientContext *pContextSSH,
                   sshStringBuffer *pRequestType,
                   enum sshcChannelReqType channelRqstType,
                   byteBoolean wantReply,
                   sshStringBuffer *pData)
{
    MSTATUS status;
    ubyte* pBuffer;
    ubyte4 buflen;
    ubyte4 bufIndex = 0;
    ubyte4 written;

    pContextSSH->sessionState.channelRqstType = kChannelRequestNothing;

    buflen = 1 + 4 + pRequestType->stringLen + 1;

    if (NULL != pData)
        buflen +=  pData->stringLen;

    if (NULL == (pBuffer = MALLOC(buflen))) {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *pBuffer = SSH_MSG_CHANNEL_REQUEST;
    bufIndex++;

    if (0 > (status = setInteger(pBuffer, buflen, &bufIndex, pContextSSH->sessionState.recipientChannel)))
        goto exit;

    MOC_MEMCPY(pBuffer + bufIndex, pRequestType->pString, pRequestType->stringLen);
    bufIndex += pRequestType->stringLen;

    *(pBuffer + bufIndex) = wantReply;
    bufIndex++;

    if (NULL != pData)
        MOC_MEMCPY(pBuffer + bufIndex, pData->pString, pData->stringLen);

    if (0 > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, pBuffer, buflen, &written)))
       goto exit;

    pContextSSH->sessionState.channelRqstType = channelRqstType;

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* sendChannelRequest */


/*------------------------------------------------------------------*/

static MSTATUS
sendPtyChannelRequest(sshClientContext *pContextSSH,
                      sshStringBuffer *pRequestType,
                      byteBoolean wantReply,
                      sshStringBuffer *pTerminalType,
                      sshStringBuffer *pTerminalModes)
{
    ubyte*  pBuffer;
    ubyte4  buflen;
    ubyte4  bufIndex = 0;
    ubyte4  written;
    MSTATUS status;

    /* RFC 4254, section 6.2 */
    buflen = 1 + 4 + pRequestType->stringLen + 1 + pTerminalType->stringLen + 4 + 4 + 4 + 4 + pTerminalModes->stringLen;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *pBuffer = SSH_MSG_CHANNEL_REQUEST;
    bufIndex++;

    if (0 > (status = setInteger(pBuffer, buflen, &bufIndex, pContextSSH->sessionState.recipientChannel)))
        goto exit;

    MOC_MEMCPY(pBuffer + bufIndex, pRequestType->pString, pRequestType->stringLen);
    bufIndex += pRequestType->stringLen;

    *(pBuffer + bufIndex) = wantReply;
    bufIndex++;

    /* TERM environment variable */
    MOC_MEMCPY(pBuffer + bufIndex, pTerminalType->pString, pTerminalType->stringLen);
    bufIndex += pTerminalType->stringLen;

    /* terminal width, characters (e.g., 80) */
    if (0 > (status = setInteger(pBuffer, buflen, &bufIndex, 80)))
        goto exit;

    /* terminal height, characters (e.g., 24) */
    if (0 > (status = setInteger(pBuffer, buflen, &bufIndex, 24)))
        goto exit;

    /* terminal width, pixels */
    if (0 > (status = setInteger(pBuffer, buflen, &bufIndex, 0)))
        goto exit;

    /* terminal height, pixels */
    if (0 > (status = setInteger(pBuffer, buflen, &bufIndex, 0)))
        goto exit;

    /* encoded terminal modes (see RFC 4254 section 8) */
    MOC_MEMCPY(pBuffer + bufIndex, pTerminalModes->pString, pTerminalModes->stringLen);
    bufIndex += pTerminalModes->stringLen;

    if (0 > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, pBuffer, buflen, &written)))
       goto exit;

    pContextSSH->sessionState.channelRqstType = kChannelRequestPty;

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* sendPtyChannelRequest */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_SESSION_SendSubsystemSFTPChannelRequest(sbyte4 connectionInstance)
{
    sshcConnectDescr* pDescr;
    MSTATUS status;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    status = sendChannelRequest(pDescr->pContextSSH, &sshc_subSystem, kChannelRequestSubsystem, TRUE, &sshc_sftpExec);

exit:
    return status;

}  /* SSHC_SESSION_SendSubsystemSFTPChannelRequest */


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_SESSION_sendWindowChangeChannelRequest(sshClientContext *pContextSSH,
                                            ubyte4 width, ubyte4 height)
{
    ubyte*  pBuffer;
    ubyte4  buflen;
    ubyte4  bufIndex = 0;
    ubyte4  written;
    MSTATUS status;

    /* RFC 4254, section 6.7 */
    buflen = 1 + 4 + sshc_windowChange.stringLen + 1 + 4 + 4 + 4 + 4;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *pBuffer = SSH_MSG_CHANNEL_REQUEST;
    bufIndex++;

    if (0 > (status = setInteger(pBuffer, buflen, &bufIndex, pContextSSH->sessionState.recipientChannel)))
        goto exit;

    /* "window-change" */
    MOC_MEMCPY(pBuffer + bufIndex, sshc_windowChange.pString, sshc_windowChange.stringLen);
    bufIndex += sshc_windowChange.stringLen;

    *(pBuffer + bufIndex) = FALSE;
    bufIndex++;

    /* terminal width, characters (e.g., 24) */
    if (0 > (status = setInteger(pBuffer, buflen, &bufIndex, width)))
        goto exit;

    /* terminal height, characters (e.g., 24) */
    if (0 > (status = setInteger(pBuffer, buflen, &bufIndex, height)))
        goto exit;

    /* terminal width, pixels */
    if (0 > (status = setInteger(pBuffer, buflen, &bufIndex, 0)))
        goto exit;

    /* terminal height, pixels */
    if (0 > (status = setInteger(pBuffer, buflen, &bufIndex, 0)))
        goto exit;

    if (0 > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, pBuffer, buflen, &written)))
       goto exit;

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* sendPtyChannelRequest */


/*------------------------------------------------------------------*/

static ubyte m_encodeTerminalModes[] = { 0x03, 0x00, 0x00, 0x00, 0x7f, 0x80, 0x00, 0x00, 0x96, 0x00, 0x81, 0x00, 0x00, 0x96, 0x00, 0x00 };

extern sbyte4
SSHC_SESSION_sendPtyOpenRequest(sbyte4 connectionInstance)
{
    ubyte*              pBuffer;
    ubyte4              bufLen = 4 + sizeof(m_encodeTerminalModes);
    ubyte4              bufIndex = 0;
    sshStringBuffer*    pTerminalModes = NULL;
    sshcConnectDescr*   pDescr;
    MSTATUS             status;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    if (OK > (status = SSH_STR_makeStringBuffer(&pTerminalModes, bufLen)))
        goto exit;

    pBuffer = pTerminalModes->pString;

    if (0 > (status = setInteger(pBuffer, bufLen, &bufIndex, sizeof(m_encodeTerminalModes))))
        goto exit;

    MOC_MEMCPY(pBuffer + bufIndex, m_encodeTerminalModes, sizeof(m_encodeTerminalModes));

    status = sendPtyChannelRequest(pDescr->pContextSSH, &sshc_ptyTerminal, TRUE, &sshc_terminalEnv, pTerminalModes);

exit:
    SSH_STR_freeStringBuffer(&pTerminalModes);

    return status;

}  /* SSHC_SESSION_sendPtyOpenRequest */


/*------------------------------------------------------------------*/

extern sbyte4
SSHC_SESSION_sendShellOpenRequest(sbyte4 connectionInstance)
{
    sshcConnectDescr* pDescr;
    MSTATUS status;

    if (NULL == (pDescr = SSHC_getConnectionFromInstance(connectionInstance)))
    {
         status = ERR_SSH_BAD_ID;
         goto exit;
    }

    status = sendChannelRequest(pDescr->pContextSSH, &sshc_shellType, kChannelRequestShell, TRUE, NULL);

exit:
    return status;

}  /* SSHC_SESSION_sendShellOpenRequest */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_SESSION_handleOpenConfirmation(sshClientContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    MSTATUS status = OK;
    ubyte4  myChannel;
    ubyte4  serverChannel;
    ubyte4  serverWindowSize;
    ubyte4  serverMaxPktSize;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    sshcPfSession*  pSession = NULL;
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

    if (mesgLen != 1 + 4 + 4 + 4 + 4)
    {
        status = ERR_SESSION_BAD_PAYLOAD;
        goto exit;
    }

    myChannel = getUbyte4(pMesg + 1);
    serverChannel = getUbyte4(pMesg + 5);
    serverWindowSize = getUbyte4(pMesg + 9);
    serverMaxPktSize = getUbyte4(pMesg + 13);

    if (myChannel == pContextSSH->sessionState.clientChannel)
    {
        /* notify upper layer of open channel */
        if (NULL != SSHC_sshClientSettings()->funcPtrSessionOpen)
            if (OK > (status = (SSHC_sshClientSettings()->funcPtrSessionOpen)(pContextSSH->connectionInstance, SSH_SESSION_OPEN, NULL, 0)))
                goto exit;

        pContextSSH->sessionState.isChannelActive  = TRUE;
        pContextSSH->sessionState.channelState     = SESSION_OPEN;
        pContextSSH->sessionState.recipientChannel = serverChannel;
        pContextSSH->sessionState.maxWindowSize    = serverWindowSize;
        pContextSSH->sessionState.maxPacketSize    = serverMaxPktSize;
        pContextSSH->sessionState.windowSize       = serverWindowSize;
        pContextSSH->sessionState.isEof            = FALSE;
        pContextSSH->sessionState.rxdClosed        = FALSE;

        /* initialize sftp */
#ifdef __ENABLE_MOCANA_SSH_FTP_CLIENT__
        pContextSSH->sftpState              = SFTP_NOTHING;
        pContextSSH->sftpIncomingBufferSize = 0;
        pContextSSH->sftpNumBytesInBuffer   = 0;
        pContextSSH->sftpNumBytesRequired   = 0;
#endif
    }
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    else if ( OK == ( status = getSessionDataFromChannel( NULL , pContextSSH, myChannel, &pSession ) ) )
    {
        /* notify upper layer of open channel */
        if (NULL != SSHC_sshClientSettings()->funcPtrPortFwdSessionOpen)
            (SSHC_sshClientSettings()->funcPtrPortFwdSessionOpen)(pContextSSH->connectionInstance, SSH_SESSION_OPEN, NULL, 0, myChannel);

        pSession->lpfSessionData.isChannelActive  = TRUE;
        pSession->lpfSessionData.channelState     = SESSION_OPEN;
        pSession->lpfSessionData.recipientChannel = serverChannel;
        pSession->lpfSessionData.maxWindowSize    = serverWindowSize;
        pSession->lpfSessionData.maxPacketSize    = serverMaxPktSize;
        pSession->lpfSessionData.windowSize       = serverWindowSize;
    }
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
    else
    {
        status = ERR_SESSION_BAD_PAYLOAD;
        goto exit;
    }

exit:
    return status;

}  /* SSHC_SESSION_handleOpenConfirmation */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_SESSION_handleOpenFailure(sshClientContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    MSTATUS status = ERR_SESSION_BAD_PAYLOAD;
    ubyte4  myChannel;
    ubyte4 bufIndex;
    sshStringBuffer *info = NULL;
    sshStringBuffer *language = NULL;
    intBoolean       isPortForwardSession = FALSE;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    sshcPfSession*  pSession = NULL;
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

    if (mesgLen < 1 + 4 + 4)   /* being cautious about whether all servers send info/language */
    {
        status = ERR_SESSION_BAD_PAYLOAD;
        goto exit;
    }

    bufIndex = 1;
    myChannel = getUbyte4(pMesg + bufIndex);
    if (myChannel != pContextSSH->sessionState.clientChannel)
    {
        isPortForwardSession = FALSE;
    }
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    else if ( OK == ( status = getSessionDataFromChannel( NULL , pContextSSH, myChannel, &pSession ) ) )
    {
        destroyLocalPortFwdSession( NULL , pContextSSH, myChannel );
        isPortForwardSession = TRUE;
    }
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
    else
    {
        status = ERR_SESSION_BAD_PAYLOAD;
        goto exit;
    }


    bufIndex += 4;

    /* Skip 4 bytes for serverChannel */
    bufIndex += 4;

    if (mesgLen >= (bufIndex + 4))
    {
        if (0 > (status = SSH_STR_copyStringFromPayload2(pMesg, mesgLen,
                              &bufIndex, &info)))
        {
            goto exit;
        }

        DEBUG_RELABEL_MEMORY(info);

        if (mesgLen >= (bufIndex + 4))
        {
            if (0 > (status = SSH_STR_copyStringFromPayload2(pMesg, mesgLen,
                                  &bufIndex, &language)))
            {
                goto exit;
            }

            DEBUG_RELABEL_MEMORY(language);
        }
    }

    if ( FALSE == isPortForwardSession )
    {
        if (NULL != SSHC_sshClientSettings()->funcPtrSessionOpenFail)
        {
            status = (SSHC_sshClientSettings()->funcPtrSessionOpenFail)(pContextSSH->connectionInstance,
                                                                        (NULL == info)     ? NULL : info->pString,
                                                                        (NULL == info)     ? 0    : info->stringLen,
                                                                        (NULL == language) ? NULL : language->pString,
                                                                        (NULL == language) ? 0    : language->stringLen);
        }
    }
    else
    {
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
        if (NULL != SSHC_sshClientSettings()->funcPtrPortFwdSessionOpenFail)
        {
            status = (SSHC_sshClientSettings()->funcPtrPortFwdSessionOpenFail)(pContextSSH->connectionInstance,
                                                                                   (NULL == info)     ? NULL : info->pString,
                                                                                   (NULL == info)     ? 0    : info->stringLen,
                                                                                   (NULL == language) ? NULL : language->pString,
                                                                                   (NULL == language) ? 0    : language->stringLen,
                                                                                   myChannel);
        }
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
    }

exit:
    if (NULL != info)
        SSH_STR_freeStringBuffer(&info);

    if (NULL != language)
        SSH_STR_freeStringBuffer(&language);

    DEBUG_ERROR(DEBUG_SSH_SERVICE,"SSHC_SESSION_handleOpenFailure: status ",status);
    return status;

} /* SSHC_SESSION_handleOpenFailure */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_SESSION_handleWindowAdjust(sshClientContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4  recipientChannel;
    ubyte4  numBytesAdd;
    MSTATUS status = ERR_SESSION_BAD_PAYLOAD;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    sshcPfSession*  pSession = NULL;
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

    if (9 == mesgLen)
    {
        recipientChannel = getUbyte4(pMesg + 1);
        numBytesAdd      = getUbyte4(pMesg + 5);

        status = ERR_SESSION_NOT_OPEN;

/* OpenSSH sends this before sending SSH_MSG_CHANNEL_SUCCESS
 *      if ((pContextSSH->sessionState.clientChannel == recipientChannel) &&
 *          (FALSE != pContextSSH->sessionState.isShellActive))
 */
        if (pContextSSH->sessionState.clientChannel == recipientChannel)
        {
            pContextSSH->sessionState.windowSize += numBytesAdd;
            status = OK;
        }
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
        else if ( OK == ( status = getSessionDataFromChannel( NULL , pContextSSH, recipientChannel, &pSession ) ) )
        {
            pSession->lpfSessionData.windowSize += numBytesAdd;
            status = OK;
        }
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
    }

    return status;

} /* SSHC_SESSION_handleWindowAdjust */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_SESSION_handleCloseSession(sshClientContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4  recipientChannel;
    MSTATUS status = ERR_SESSION_BAD_PAYLOAD;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    sshcPfSession*  pSession = NULL;
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

    if (5 == mesgLen)
    {
        recipientChannel = getUbyte4(pMesg + 1);
        status = ERR_SESSION_NOT_OPEN;

        if ((pContextSSH->sessionState.clientChannel == recipientChannel) &&
            (TRUE == pContextSSH->sessionState.isChannelActive))
        {
            /* notify upper layer session has been closed */
            pContextSSH->sessionState.isChannelActive = FALSE;
            pContextSSH->sessionState.channelState = SESSION_CLOSED;
            pContextSSH->sessionState.rxdClosed = TRUE;

            if (NULL != SSHC_sshClientSettings()->funcPtrClosed)
                if (OK > (status = (SSHC_sshClientSettings()->funcPtrClosed)(pContextSSH->connectionInstance, SSH_SESSION_CLOSED, NULL, 0)))
                    goto exit;

            status = OK;
        }
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
        else if ( OK == ( status = getSessionDataFromChannel( NULL , pContextSSH, recipientChannel, &pSession ) ) )
        {
            /* notify upper layer session has been closed */

            if (NULL != SSHC_sshClientSettings()->funcPtrPortForwardClosed)
                (SSHC_sshClientSettings()->funcPtrPortForwardClosed)(pContextSSH->connectionInstance,
                                                                          SSH_SESSION_CLOSED,
                                                                          NULL,
                                                                          0,
                                                                          recipientChannel);

            /* Send close session if we haven't sent it */
            if ( SESSION_CLOSED != pSession->lpfSessionData.channelState )
            {
                sendLpfClose( pContextSSH, recipientChannel );
            }

            /* There is no need to manage the session data, just destroy it */
            destroyLocalPortFwdSession( NULL , pContextSSH, recipientChannel );
            status = OK;
        }
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
    }

exit:
    return status;

} /* SSHC_SESSION_handleCloseSession */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_SESSION_handleEofSession(sshClientContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4  recipientChannel;
    MSTATUS status = ERR_SESSION_BAD_PAYLOAD;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    sshcPfSession*  pSession = NULL;
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */


    if (5 == mesgLen)
    {
        recipientChannel = getUbyte4(pMesg + 1);
        status = ERR_SESSION_NOT_OPEN;

        if ((pContextSSH->sessionState.clientChannel == recipientChannel) &&
            (TRUE == pContextSSH->sessionState.isChannelActive))
        {
            /* notify upper layer the server wishes to end the session */
            pContextSSH->sessionState.isEof = TRUE;

            if (NULL != (SSHC_sshClientSettings()->funcPtrEof))
                if (OK > (status = (SSHC_sshClientSettings()->funcPtrEof)(pContextSSH->connectionInstance, SSH_SESSION_EOF, NULL, 0)))
                    goto exit;

            status = OK;
        }
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
        else if ( OK == ( status = getSessionDataFromChannel( NULL , pContextSSH, recipientChannel, &pSession ) ) )
        {
            /* notify upper layer session has been closed */
            if (NULL != SSHC_sshClientSettings()->funcPtrPortForwardEof)
                (SSHC_sshClientSettings()->funcPtrPortForwardEof)(pContextSSH->connectionInstance,
                                                                          SESSION_CLOSING,
                                                                          NULL,
                                                                          0,
                                                                          recipientChannel);

            /* Send EOF session if we haven't sent it */
            if ( TRUE != pSession->lpfSessionData.isEof )
            {
                sendLpfEof( pContextSSH, recipientChannel );
                sendLpfClose( pContextSSH, recipientChannel );
            }

            status = OK;
        }
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
    }

exit:
    return status;

} /* SSHC_SESSION_handleEofSession */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_SESSION_handleChannelRequest(sshClientContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    intBoolean          isReplyRequired;
    ubyte               payload[5];
    ubyte4              recipientChannel;
    MSTATUS             status = ERR_SESSION_NOT_OPEN;

    recipientChannel = getUbyte4(pMesg + 1);

    if ((pContextSSH->sessionState.clientChannel == recipientChannel) &&
        (TRUE == pContextSSH->sessionState.isChannelActive) )
    {
        ubyte4 numBytesWritten;

        if ((mesgLen < (1 + 4 + 4 + 1)) || ((mesgLen - (1 + 4 + 4 + 1)) < getUbyte4(pMesg + 5)))
        {
            status = ERR_SESSION_BAD_PAYLOAD;
            goto exit;
        }

        isReplyRequired = (0 == pMesg[1 + 4 + 4 + getUbyte4(pMesg + 5)]) ? FALSE : TRUE;

        /* only reply, if requested */
        if (TRUE == isReplyRequired)
        {
            payload[0] = SSH_MSG_CHANNEL_FAILURE;
            payload[1] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 24);
            payload[2] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 16);
            payload[3] = (ubyte)(pContextSSH->sessionState.recipientChannel >>  8);
            payload[4] = (ubyte)(pContextSSH->sessionState.recipientChannel);

            if (OK > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesWritten)))
                goto exit;
        }
    }

exit:
    return status;

} /* SSHC_SESSION_handleChannelRequest */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
static MSTATUS
SSHC_SESSION_handleRequestSuccess(sshClientContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    MSTATUS             status = OK;
    sbyte4              i;

    for (i = 0; i < SSH_MAX_RPF_HOSTS; i++)
    {
        if ((TRUE == pContextSSH->rpfTable[i].inUse) && (FALSE == pContextSSH->rpfTable[i].isConfirmed))
        {
            if (0 == pContextSSH->rpfTable[i].bindPort)
            {
                /* parse assigned port no. */
                if(4 < mesgLen)
                    pContextSSH->rpfTable[i].assignedBindPort  = getUbyte4(pMesg+1);
                else
                {
                    status = ERR_SSH_UNEXPECTED_END_MESSAGE;
                    DEBUG_ERROR(DEBUG_SSH_SERVICE,"Port is not assigned ",(-1));
                    goto exit;
                }
            }
            else
                pContextSSH->rpfTable[i].assignedBindPort = pContextSSH->rpfTable[i].bindPort;

            pContextSSH->rpfTable[i].isConfirmed = TRUE;
            break;
        }
    }
exit:
    if(i < SSH_MAX_RPF_HOSTS)
        SSHC_sshClientSettings()->funcPtrRemotePortReqStatus(status, pContextSSH->rpfTable[i].assignedBindPort);
    return status;

} /* SSHC_SESSION_handleRequestSuccess */

/*------------------------------------------------------------------*/

static MSTATUS addRpfSessionToContext( sshClientContext* pDescr, sbyte4 index, sshcPfSession*  pSession )
{
    MSTATUS       status = OK;
    sshcPfSession* pTemp = NULL;

    sshClientContext *pSshContext = pDescr;

    if(NULL == pSshContext->rpfTable[index].pRpfSessionHead)
    {
        pSshContext->rpfTable[index].pRpfSessionHead = pSession;
    }
    else
    {
        pTemp = pSshContext->rpfTable[index].pRpfSessionHead;
        pSession->pNextSession = pTemp;
        pSshContext->rpfTable[index].pRpfSessionHead = pSession;
    }

    return status;
}/* addRpfSessionToContext */

/*------------------------------------------------------------------*/

MSTATUS SSHC_SESSION_createRemotePortFwdSession(sshClientContext *pSshContext, sshcPfSession**  ppRpfSession, sbyte4 rpfIndex, ubyte4 serverChannel, ubyte4 initWindowSize, ubyte4 maxPacketSize, ubyte4* pChannel)
{
    MSTATUS status = OK;
    sshcPfSession*  pRpfSession = NULL;

    if (NULL == ppRpfSession)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( NULL == ( pRpfSession = MALLOC( sizeof(sshcPfSession) ) ) )
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    MOC_MEMSET( (ubyte*)pRpfSession, 0x00, sizeof(sshcPfSession) );
    /* Insert the new channel number into Session data -- Calling application
       will use this channel number to map differentlocal port forwarding sessions */
    pRpfSession->lpfSessionData.clientChannel = ++m_channel;

    if ( OK > ( status = addRpfSessionToContext(pSshContext, rpfIndex, pRpfSession) ) )
        goto exit;

    pRpfSession->lpfSessionData.isChannelActive     = TRUE;
    pRpfSession->lpfSessionData.isShellActive       = TRUE;
    pRpfSession->lpfSessionData.channelState        = SESSION_OPEN;
    pRpfSession->lpfSessionData.recipientChannel    = serverChannel; 
    pRpfSession->lpfSessionData.maxWindowSize       = initWindowSize;
    pRpfSession->lpfSessionData.maxPacketSize       = maxPacketSize;
    pRpfSession->lpfSessionData.windowSize          = initWindowSize;
    pRpfSession->lpfSessionData.serverWindowSize    = MAX_SESSION_WINDOW_SIZE;

    /* Return the channel number only if everything is Okay */
    (*pChannel) = pRpfSession->lpfSessionData.clientChannel;
    *ppRpfSession  = pRpfSession;
exit:
    return status;
} /* SSHC_SESSION_createRemotePortFwdSession */

/*------------------------------------------------------------------*/

static MSTATUS
SSHC_SESSION_handleChannelOpen(sshClientContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte               failType;
    sshcPfSession*      pRpfSession = NULL;
    sshStringBuffer*    failMessage;
    ubyte*              pPayload    = NULL;
    ubyte4              recipientChannel;
    ubyte4              numBytesWritten;
    ubyte4              initWindowSize;
    ubyte4              maxPacketSize;
    ubyte4              channelTypeLength;
    sbyte4              channelChoice;
    sshStringBuffer*    pDstLocation = NULL;
    ubyte2              dstPort;
    sshStringBuffer*    pSrcLocation = NULL;
    ubyte2              srcPort;
    ubyte4              sshChannel;
    ubyte4              sshWindowSize;
    MSTATUS             status;
    sbyte4              i,j;

    ubyte               ignoreRequest = TRUE;    /* always default to safest path */

    channelTypeLength = getUbyte4(1 + pMesg);

    /* make sure we have some minimal number of bytes, before processing */
    if ((mesgLen - (1 + 4 + 32)) < channelTypeLength)
    {
        status = ERR_SESSION_BAD_PAYLOAD;
        goto exit;
    }

    /* we need recipientChannel whether we accept or fail on this request */
    recipientChannel = getUbyte4(pMesg + 1 + 4 + channelTypeLength);
    initWindowSize   = getUbyte4(pMesg + 1 + 4 + channelTypeLength + 4);
    maxPacketSize    = getUbyte4(pMesg + 1 + 4 + channelTypeLength + 8);

    failType    = SSH_OPEN_UNKNOWN_CHANNEL_TYPE;
    failMessage = &sshc_channelUnknown;

    ubyte4 index = 1 + 4 + channelTypeLength + 12;

    if (mesgLen < (index + 16))
    {
        status = ERR_SESSION_BAD_PAYLOAD;
        goto exit;
    }

    if (OK > (status = SSH_STR_copyStringFromPayload(pMesg, mesgLen, &index, &pDstLocation)))
        goto exit;

    dstPort = (ubyte2)getUbyte4(pMesg + index); index += 4;

    /* check the condition for the dest port it might be zero if we send 0 in request */
    if (4 >= pDstLocation->stringLen)
    {
        /* if destination port is zero, fail */
        goto sendfail;
    }

    if (OK > (status = SSH_STR_copyStringFromPayload(pMesg, mesgLen, &index, &pSrcLocation)))
        goto exit;

    srcPort = (ubyte2)getUbyte4(pMesg + index); index += 4;

    if (mesgLen != index)
    {
        status = ERR_SESSION_BAD_PAYLOAD;
        goto exit;
    }

    /* check against our own entry to make sure we had initiated a global request for this */
    for (i = 0; i < SSH_MAX_RPF_HOSTS; i++)
    {
        if ((TRUE == pContextSSH->rpfTable[i].inUse) && (TRUE == pContextSSH->rpfTable[i].isConfirmed))
        {
            /* pDstLocation->pString getting wrong have to test */
            if ((!MOC_STRNICMP((sbyte *) pContextSSH->rpfTable[i].pBindAddr, (sbyte *) (pDstLocation->pString + 4),( pDstLocation->stringLen-4))) && (dstPort == pContextSSH->rpfTable[i].bindPort))
                break;
        }
    }

    /* there is some problem in above comp. */
    if (i == SSH_MAX_RPF_HOSTS)
    {
        /* entry not found */
        goto sendfail;
    }

    if (OK > (status = SSHC_SESSION_createRemotePortFwdSession(pContextSSH, &pRpfSession, i,
                                                               recipientChannel,initWindowSize,
                                                               maxPacketSize, &sshChannel)))
        goto exit;

    /* handler may block, re-direct, or use non-socket interface to transport */
    if (NULL != SSHC_sshClientSettings()->funcPtrPortForwardConnect)
    {
        /* pass-by-reference allows custom code to alter connect address and port */
        if (OK > (status = (MSTATUS)SSHC_sshClientSettings()->funcPtrPortForwardConnect(CONNECTION_INSTANCE(pContextSSH),
                                                                      SSH_REMOTE_PORT_FORWARDING,
                                                                      (sbyte*)pContextSSH->rpfTable[i].pHostAddr,
                                                                      pContextSSH->rpfTable[i].hostPort, &ignoreRequest,
                                                                      sshChannel)))
        {
            destroyLocalPortFwdSession(NULL, pContextSSH, sshChannel);
            goto sendfail;
        }
    }
    else
        destroyLocalPortFwdSession(NULL, pContextSSH, sshChannel);

    /* no errors, but callback wants to block location */
    if (ignoreRequest)
        goto sendfail;

    for(j = 0; j < SSH_MAX_REMOTE_PORT_FWD_CHANNEL; j++)
    {
        if(pContextSSH->rpfTable[i].channelList[j] <= 0)
        {
            pContextSSH->rpfTable[i].channelList[j] = sshChannel;
            break;
        }
    }

    if (NULL == (pPayload = MALLOC(1 + 4 + 4 + 4 + 4)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* accept open a session request */
    pPayload[0]  = SSH_MSG_CHANNEL_OPEN_CONFIRMATION;

    pPayload[1]  = (ubyte)(recipientChannel >> 24);
    pPayload[2]  = (ubyte)(recipientChannel >> 16);
    pPayload[3]  = (ubyte)(recipientChannel >>  8);
    pPayload[4]  = (ubyte)(recipientChannel);

    pPayload[5]  = (ubyte)(sshChannel >> 24);
    pPayload[6]  = (ubyte)(sshChannel >> 16);
    pPayload[7]  = (ubyte)(sshChannel >>  8);
    pPayload[8]  = (ubyte)(sshChannel);

    sshWindowSize = MAX_SESSION_WINDOW_SIZE;
    pPayload[9]  = 0;
    pPayload[10] = 0;
    pPayload[11] = (ubyte)(sshWindowSize >>  8);
    pPayload[12] = (ubyte)(sshWindowSize);

    sshWindowSize = MAX_SESSION_WINDOW_SIZE;
    pPayload[13] = 0;
    pPayload[14] = 0;
    pPayload[15] = (ubyte)(sshWindowSize >>  8);
    pPayload[16] = (ubyte)(sshWindowSize);

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pPayload, 17, &numBytesWritten);

    goto exit;

sendfail:
    if (NULL == (pPayload = MALLOC(1 + 4 + 4 + failMessage->stringLen + sshc_languageTag.stringLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* send back failure notification */
    pPayload[0] = SSH_MSG_CHANNEL_OPEN_FAILURE;

    /* store recipient channel */
    pPayload[1] = (ubyte)(recipientChannel >> 24);
    pPayload[2] = (ubyte)(recipientChannel >> 16);
    pPayload[3] = (ubyte)(recipientChannel >>  8);
    pPayload[4] = (ubyte)(recipientChannel);

    /* store fail reason code */
    pPayload[5] = 0;
    pPayload[6] = 0;
    pPayload[7] = 0;
    pPayload[8] = failType;

    /* copy reason for failure */
    if (OK > (status = MOC_MEMCPY(9 + pPayload, failMessage->pString, failMessage->stringLen)))
        goto exit;

    /* copy language tag */
    if (OK > (status = MOC_MEMCPY(9 + pPayload + failMessage->stringLen, sshc_languageTag.pString, sshc_languageTag.stringLen)))
        goto exit;

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pPayload, 9 + failMessage->stringLen + sshc_languageTag.stringLen, &numBytesWritten);

exit:
    if (NULL != pPayload)
        FREE(pPayload);

    SSH_STR_freeStringBuffer(&pDstLocation);
    SSH_STR_freeStringBuffer(&pSrcLocation);

    return status;

} /* handleChannelOpenReq */
#endif

/*------------------------------------------------------------------*/

static MSTATUS
SSHC_SESSION_handleChannelSuccess(sshClientContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    MSTATUS             status = OK;
    MOC_UNUSED(pMesg);
    MOC_UNUSED(mesgLen);

    switch (pContextSSH->sessionState.channelRqstType)
    {
        case kChannelRequestSubsystem:
        {
            /* subsystem sftp */
            pContextSSH->sessionState.isShellActive = SSHC_SFTP_SESSION_ESTABLISHED;

            if (NULL != (SSHC_sshClientSettings()->funcPtrOpenShell))
                if (OK > (status = (SSHC_sshClientSettings()->funcPtrOpenShell)(pContextSSH->connectionInstance, SSH_SESSION_OPEN_SFTP, NULL, 0)))
                    goto exit;

            break;
        }

        case kChannelRequestPty:
        {
            /* pty */
            if (NULL != (SSHC_sshClientSettings()->funcPtrPtyRequest))
                if (OK > (status = (SSHC_sshClientSettings()->funcPtrPtyRequest)(pContextSSH->connectionInstance, SSH_SESSION_OPEN_PTY, NULL, 0)))
                    goto exit;

            break;
        }

        case kChannelRequestShell:
        {
            /* shell */
            pContextSSH->sessionState.isShellActive = SSHC_SHELL_SESSION_ESTABLISHED;

            if (NULL != (SSHC_sshClientSettings()->funcPtrOpenShell))
                if (OK > (status = (SSHC_sshClientSettings()->funcPtrOpenShell)(pContextSSH->connectionInstance, SSH_SESSION_OPEN_SHELL, NULL, 0)))
                    goto exit;

            break;
        }

        case kChannelRequestNothing:
        default:
        {
            /* spurious channel response */
            status = ERR_SSH_SESSION_UNEXPECTED_RESPONSE;
            break;
        }
    }

exit:
    return status;

} /* SSHC_SESSION_handleChannelSuccess */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_SESSION_handleIncomingMessage(sshClientContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte   payload[9];
    ubyte4  recipientChannel;
    ubyte4  numBytesWritten;
    MSTATUS status = ERR_SESSION_NOT_OPEN;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    sshcPfSession*   pSession = NULL;
#endif

    /* process incoming data message */
    recipientChannel = getUbyte4(pMesg + 1);

    if ((pContextSSH->sessionState.clientChannel == recipientChannel) &&
        (FALSE != pContextSSH->sessionState.isShellActive))
    {
        ubyte4 dataLen = getUbyte4(pMesg + 5);
        ubyte* pData   = pMesg + 9;

        /* ignore all data messages, if client has eof'd */
        if (TRUE == pContextSSH->sessionState.isEof)
        {
            status = OK;
            goto exit;
        }

        status = ERR_SESSION_BAD_PAYLOAD;

#ifdef __ENABLE_MOCANA_SSH_MAX_PACKET_SIZE_ERROR__
        if(dataLen > MAX_SESSION_WINDOW_SIZE)
        {
	
            DEBUG_PRINTNL(DEBUG_SSH_MESSAGES, (sbyte *) "dataLen exceeds maxPacketSize");
            goto exit ;
        }
#endif /* __ENABLE_MOCANA_SSH_MAX_PACKET_SIZE_ERROR__ */

        if (mesgLen == (dataLen + 9))
        {
            intBoolean ackIt = FALSE;

            status = OK;

            /* client governor, ignore data beyond our window */
            if ((MAX_SESSION_WINDOW_SIZE - pContextSSH->sessionState.unAckRecvdData) < dataLen)
                dataLen = (MAX_SESSION_WINDOW_SIZE - pContextSSH->sessionState.unAckRecvdData);

            /* increment un-ack counter */
            pContextSSH->sessionState.unAckRecvdData += dataLen;

            /* notify upper layer that message data has been received */
            /* copy the message data */
#if defined(__ENABLE_MOCANA_SSH_FTP_CLIENT__)
            if (SSHC_SFTP_SESSION_ESTABLISHED == pContextSSH->sessionState.isShellActive)
            {
                if (OK > (status = SSHC_FTP_doProtocol(pContextSSH, pData, dataLen)))
                    goto exit;
                if ((MAX_SESSION_WINDOW_SIZE/2) < pContextSSH->sessionState.unAckRecvdData)
                    ackIt = TRUE;
            }
            else
            {
                if (NULL != (SSHC_sshClientSettings()->funcPtrReceivedData))
                   if (OK > (status = (SSHC_sshClientSettings()->funcPtrReceivedData)(pContextSSH->connectionInstance, SSH_SESSION_DATA, pData, dataLen)))
                       goto exit;
            }
#else
            if (NULL != (SSHC_sshClientSettings()->funcPtrReceivedData))
                if (OK > (status = (SSHC_sshClientSettings()->funcPtrReceivedData)(pContextSSH->connectionInstance, SSH_SESSION_DATA, pData, dataLen)))
                    goto exit;
#endif

            if (TRUE == ackIt)
            {
                /* ack the message data */
                payload[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;

                payload[1] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 24);
                payload[2] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 16);
                payload[3] = (ubyte)(pContextSSH->sessionState.recipientChannel >>  8);
                payload[4] = (ubyte)(pContextSSH->sessionState.recipientChannel);

                payload[5] = (ubyte)((pContextSSH->sessionState.unAckRecvdData) >> 24);
                payload[6] = (ubyte)((pContextSSH->sessionState.unAckRecvdData) >> 16);
                payload[7] = (ubyte)((pContextSSH->sessionState.unAckRecvdData) >>  8);
                payload[8] = (ubyte)((pContextSSH->sessionState.unAckRecvdData));

                status = SSHC_OUT_MESG_sendMessage(pContextSSH, payload, 9, &numBytesWritten);
                
                pContextSSH->sessionState.unAckRecvdData = 0;
                
            }
        }
    }
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    else if ( OK == ( status = getSessionDataFromChannel( NULL, pContextSSH, recipientChannel, &pSession ) ) )
    {
        ubyte4 dataLen = getUbyte4(pMesg + 5);
        ubyte* pData   = pMesg + 9;

        /* ignore all data messages, if client has eof'd */
        if (TRUE == pSession->lpfSessionData.isEof)
        {
            status = OK;
            goto exit;
        }

        status = ERR_SESSION_BAD_PAYLOAD;

#ifdef __ENABLE_MOCANA_SSH_MAX_PACKET_SIZE_ERROR__
        if(dataLen > MAX_SESSION_WINDOW_SIZE)
        {
	
            goto exit ;
        }
#endif /* __ENABLE_MOCANA_SSH_MAX_PACKET_SIZE_ERROR__ */

        if (mesgLen == (dataLen + 9))
        {
            /* client governor, ignore data beyond our window */
            if ((MAX_SESSION_WINDOW_SIZE - pContextSSH->sessionState.unAckRecvdData) < dataLen)
                dataLen = (MAX_SESSION_WINDOW_SIZE - pContextSSH->sessionState.unAckRecvdData);

            /* increment un-ack counter */
            pContextSSH->sessionState.unAckRecvdData += dataLen;

            /* notify upper layer that message data has been received */
            /* copy the message data */
            if (NULL != (SSHC_sshClientSettings()->funcPtrPortFwdReceivedData))
                (SSHC_sshClientSettings()->funcPtrPortFwdReceivedData)(pContextSSH->connectionInstance,
                                                                            SSH_SESSION_DATA,
                                                                            pData,
                                                                            dataLen,
                                                                            recipientChannel);

            /* ack the message data */
            payload[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;

            payload[1] = (ubyte)(pSession->lpfSessionData.recipientChannel >> 24);
            payload[2] = (ubyte)(pSession->lpfSessionData.recipientChannel >> 16);
            payload[3] = (ubyte)(pSession->lpfSessionData.recipientChannel >>  8);
            payload[4] = (ubyte)(pSession->lpfSessionData.recipientChannel);

            payload[5] = (ubyte)(dataLen >> 24);
            payload[6] = (ubyte)(dataLen >> 16);
            payload[7] = (ubyte)(dataLen >>  8);
            payload[8] = (ubyte)(dataLen);

            status = SSHC_OUT_MESG_sendMessage(pContextSSH, payload, 9, &numBytesWritten);

            pContextSSH->sessionState.unAckRecvdData -= dataLen;
        }
    }
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

exit:
    return status;

} /* SSHC_SESSION_handleIncomingMessage */

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_SESSION_sendWindowAdjust(sshClientContext *pContextSSH, ubyte mesgType, ubyte4 numBytesToAck)
{
    ubyte4  numBytesWritten;
    ubyte   payload[9];
    MSTATUS status;

    /* ack the message data */
    payload[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;

    payload[1] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 24);
    payload[2] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 16);
    payload[3] = (ubyte)(pContextSSH->sessionState.recipientChannel >>  8);
    payload[4] = (ubyte)(pContextSSH->sessionState.recipientChannel);

    payload[5] = (ubyte)(numBytesToAck >> 24);
    payload[6] = (ubyte)(numBytesToAck >> 16);
    payload[7] = (ubyte)(numBytesToAck >>  8);
    payload[8] = (ubyte)(numBytesToAck);

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, payload, 9, &numBytesWritten);

    if (OK <= status)
        if (9 != numBytesWritten)
            status = ERR_SSH_SEND_ACK_FAIL;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_SESSION_receiveMessage(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    MSTATUS status = OK;

    /* while in the connect phase, ignore auth messages */
    if ((SSH2_MSG_USERAUTH_LOW <= *pNewMesg) && (SSH2_MSG_USERAUTH_HIGH >= *pNewMesg))
        goto exit;

    switch (*pNewMesg)
    {
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
        {
            status = SSHC_SESSION_handleOpenConfirmation(pContextSSH, pNewMesg, newMesgLen);
             break;
        }
        case SSH_MSG_CHANNEL_OPEN_FAILURE:
        {
            status = SSHC_SESSION_handleOpenFailure(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_CHANNEL_CLOSE:
        {
            status = SSHC_SESSION_handleCloseSession(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_GLOBAL_REQUEST:
        {
            status = SSHC_SESSION_handleGlobalMesgReq(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_CHANNEL_OPEN:
        {
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
            status = SSHC_SESSION_handleChannelOpen(pContextSSH, pNewMesg, newMesgLen);
#else
            status = ERR_SSH_DISCONNECT_SERVICE_NOT_AVAILABLE;
#endif
            break;
        }
        case SSH_MSG_CHANNEL_WINDOW_ADJUST:
        {
            status = SSHC_SESSION_handleWindowAdjust(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_CHANNEL_DATA:
        {
            status = SSHC_SESSION_handleIncomingMessage(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_CHANNEL_EOF:
        {
            status = SSHC_SESSION_handleEofSession(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_CHANNEL_REQUEST:
        {
            status = SSHC_SESSION_handleChannelRequest(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_CHANNEL_SUCCESS:
        {
            status = SSHC_SESSION_handleChannelSuccess(pContextSSH, pNewMesg, newMesgLen);
            break;
        }

        case SSH_MSG_CHANNEL_FAILURE:
        {
            status = ERR_SSH_UNSUPPORTED_FEATURE_REQUEST;
            break;
        }

        case SSH_MSG_KEXINIT:
        {
            SSH_UPPER_STATE(pContextSSH) = kReduxTransAlgorithmExchange;

            if (FALSE == pContextSSH->isReKeyInitiatedByMe)
            {
                if (NULL != SSHC_sshClientSettings()->funcPtrSessionReKey) /* Callback Invoke */
                {
                   if (OK > (status = (SSHC_sshClientSettings()->funcPtrSessionReKey(pContextSSH->connectionInstance, TRUE /* Initiated By Remote */))))
                      break; /* Callback returned Error */
                }

                /* we only send our algorithm list, if they initiated the rekey */
                if (OK > (status = SSHC_TRANS_sendClientAlgorithms(pContextSSH)))
                    break;

                pContextSSH->isReKeyOccuring = TRUE;
            }
            else
            {
                /* at this point, we no longer care, so we reset for next time around */
                pContextSSH->isReKeyInitiatedByMe = FALSE;

                if (NULL != SSHC_sshClientSettings()->funcPtrSessionReKey) /* Callback Invoke */
                {
                  SSHC_sshClientSettings()->funcPtrSessionReKey(pContextSSH->connectionInstance, FALSE /* Initiated By local */);
                }
            }

            status = SSHC_TRANS_doProtocol(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_UNIMPLEMENTED:
            break;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
        case SSH_MSG_REQUEST_SUCCESS:
            status = SSHC_SESSION_handleRequestSuccess(pContextSSH, pNewMesg, newMesgLen);
            break;

        case SSH_MSG_REQUEST_FAILURE:
            status = ERR_SSH_REMOTE_PORT_UNAVAILABLE;
            break;
#endif

        default:
        {
            ubyte   payload[5];
            ubyte4  seqNum = INBOUND_SEQUENCE_NUM(pContextSSH);
            ubyte4  numBytesSent;

            payload[0] = SSH_MSG_UNIMPLEMENTED;
            payload[1] = (ubyte)(seqNum >> 24);
            payload[2] = (ubyte)(seqNum >> 16);
            payload[3] = (ubyte)(seqNum >>  8);
            payload[4] = (ubyte)(seqNum);

            status = SSHC_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesSent);

            break;
        }
    }

exit:
    return status;

} /* SSHC_SESSION_receiveMessage */


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_SESSION_sendStdErrMessage(sshClientContext *pContextSSH, ubyte *pMesg,
                              ubyte4 mesgLen, ubyte4 *pBytesSent)
{
    ubyte*  pMessage = NULL;
    ubyte4  numBytesToWrite;
    ubyte4  numBytesWritten;
    MSTATUS status = OK;

    *pBytesSent = 0;

    /* nothing to send */
    if (0 == mesgLen)
        goto exit;

    /* make sure session is open, before sending data to client */
    if ((FALSE          == pContextSSH->sessionState.isShellActive) ||
        (SESSION_CLOSED == pContextSSH->sessionState.channelState))
    {
        status = ERR_SESSION_NOT_OPEN;
        goto exit;
    }

    if (NULL == (pMessage = MALLOC(mesgLen + 13)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* send as much data as client window is able to handle */
    if (mesgLen > pContextSSH->sessionState.windowSize)
        mesgLen = pContextSSH->sessionState.windowSize;

    /* write the message out in chunks */
    while (0 < mesgLen)
    {
        if (OK > (status = (SSHC_OUT_MESG_sendMessageSize(pContextSSH, mesgLen + 13,
                                                         &numBytesToWrite))))
        {
            goto exit;
        }

        /* the protocol governor */
        if (numBytesToWrite > pContextSSH->sessionState.maxPacketSize)
            numBytesToWrite = pContextSSH->sessionState.maxPacketSize;

        /* subtract message header */
        numBytesToWrite -= 13;

        pMessage[0]  = SSH_MSG_CHANNEL_EXTENDED_DATA;
        pMessage[1]  = (ubyte)((pContextSSH->sessionState.recipientChannel) >> 24);
        pMessage[2]  = (ubyte)((pContextSSH->sessionState.recipientChannel) >> 16);
        pMessage[3]  = (ubyte)((pContextSSH->sessionState.recipientChannel) >>  8);
        pMessage[4]  = (ubyte)((pContextSSH->sessionState.recipientChannel));

        /* data_type_code */
        pMessage[5]  = (ubyte)(SSH_EXTENDED_DATA_STDERR >> 24);
        pMessage[6]  = (ubyte)(SSH_EXTENDED_DATA_STDERR >> 16);
        pMessage[7]  = (ubyte)(SSH_EXTENDED_DATA_STDERR >>  8);
        pMessage[8]  = (ubyte)(SSH_EXTENDED_DATA_STDERR);

        pMessage[9]  = (ubyte)(numBytesToWrite >> 24);
        pMessage[10] = (ubyte)(numBytesToWrite >> 16);
        pMessage[11] = (ubyte)(numBytesToWrite >>  8);
        pMessage[12] = (ubyte)(numBytesToWrite);

        MOC_MEMCPY(pMessage + 13, pMesg, numBytesToWrite);

        if (OK > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, pMessage,
                                                    numBytesToWrite + 13, &numBytesWritten)))
        {
            goto exit;
        }

        pMesg       += numBytesToWrite;
        mesgLen     -= numBytesToWrite;
        *pBytesSent += numBytesToWrite;
        pContextSSH->sessionState.windowSize -= numBytesToWrite;
    }

exit:
    if (NULL != pMessage)
        FREE(pMessage);

    return status;

} /* SSHC_SESSION_sendStdErrMessage */


/*------------------------------------------------------------------*/

extern void
SSHC_SESSION_sendClose(sshClientContext *pContextSSH)
{
    ubyte   payload[5];
    ubyte4  numBytesWritten;
    MSTATUS status = OK;

    if (OK > (status = SSHC_SESSION_sendMessage(pContextSSH, (ubyte *)CRLF, 2, &numBytesWritten)))
        goto exit;

    /* make sure session is open, before sending a session close */
    if ((TRUE           != pContextSSH->sessionState.isChannelActive) ||
        (SESSION_CLOSED == pContextSSH->sessionState.channelState))
    {
        goto exit;
    }

    payload[0] = SSH_MSG_CHANNEL_EOF;
    payload[1] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 24);
    payload[2] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 16);
    payload[3] = (ubyte)(pContextSSH->sessionState.recipientChannel >>  8);
    payload[4] = (ubyte)(pContextSSH->sessionState.recipientChannel);

    if (OK > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesWritten)))
        goto exit;

    payload[0] = SSH_MSG_CHANNEL_CLOSE;
    payload[1] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 24);
    payload[2] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 16);
    payload[3] = (ubyte)(pContextSSH->sessionState.recipientChannel >>  8);
    payload[4] = (ubyte)(pContextSSH->sessionState.recipientChannel);

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesWritten);

exit:
    /* so we know that the session is really closed */
    pContextSSH->sessionState.channelState = SESSION_CLOSED;

    if (OK <= status)
        SSHC_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_BY_APPLICATION);
#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_SSH_SERVICE, (sbyte*)"SSHC_SESSION_sendClose: SSHC_OUT_MESG_sendMessage failed. status: ", status);
    }
#endif
} /* SSHC_SESSION_sendClose */


/*------------------------------------------------------------------*/

extern void
SSHC_SESSION_Close(sshcConnectDescr* pDescr)
{
    if (NULL != pDescr)
        SSHC_SESSION_sendClose(pDescr->pContextSSH);

} /* SSHC_SESSION_Close */

/*------------------------------------------------------------------*/
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
static MSTATUS addLpfSessionToContext( sshcConnectDescr* pDescr, sshcPfSession*  pSession )
{
    MSTATUS       status = OK;
    sshcPfSession* pTemp = NULL;

    if ( NULL == pDescr->pContextSSH->pLpfHead )
    {
        pDescr->pContextSSH->pLpfHead = pSession;
    }
    else
    {
        pTemp = pDescr->pContextSSH->pLpfHead;
        while( NULL != pTemp->pNextSession )
        {
            pTemp = pTemp->pNextSession;
        }
        pTemp->pNextSession = pSession;
    }

    return status;
}/* addLpfSessionToContext */

/*------------------------------------------------------------------*/

static MSTATUS getSessionDataFromChannel(sshcConnectDescr* pDescr,sshClientContext* pContextSSH, sbyte4 channel, sshcPfSession** ppSession )
{
    MSTATUS         status = ERR_SSH_BAD_ID;
    sshcPfSession*  pTemp = NULL;
    sbyte4          i;

    if ( (NULL == pDescr) && (NULL == pContextSSH) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( NULL != pDescr )
    {
        pTemp = pDescr->pContextSSH->pLpfHead;
    }
    else
    {
        pTemp = pContextSSH->pLpfHead;
    }

    if ( NULL != pTemp )
    {
        while( NULL != pTemp )
        {
            if ( /*( FALSE == pTemp->lpfSessionData.isChannelActive ) &&*/
                 ( channel == (sbyte4) pTemp->lpfSessionData.clientChannel ) )
            {
                (*ppSession) = pTemp;
                status = OK;
                break;
            }
            pTemp = pTemp->pNextSession;
        }

        if (pTemp)
            goto exit;
    }

    if( NULL == pContextSSH)
        pContextSSH = pDescr->pContextSSH;

    /* go through RPF nodes now */
    for (i = 0; i < SSH_MAX_RPF_HOSTS; i++)
    {
        for (pTemp = pContextSSH->rpfTable[i].pRpfSessionHead; pTemp != NULL; pTemp = pTemp->pNextSession)
        {
            if (channel == (sbyte4) pTemp->lpfSessionData.clientChannel)
                break;
        }
        if (pTemp)
        {
            (*ppSession) = pTemp;
            status = OK;
            break;
        }
    }

exit:
    return status;
} /* getSessionDataFromChannel */

/*------------------------------------------------------------------*/

extern MSTATUS destroyLocalPortFwdSession(sshcConnectDescr* pDescr,sshClientContext* pContextSSH, sbyte4 channel)
{
    MSTATUS               status = ERR_SSH_BAD_ID;
    sshcPfSession*        pTemp     = NULL;
    sshcPfSession*        pFollower = NULL;
    sshClientContext*     pContextTemp = NULL;
    sbyte4              i;

    if ( NULL != pDescr )
    {
        pTemp = pDescr->pContextSSH->pLpfHead;
        pContextTemp = pDescr->pContextSSH;
    }
    else if(NULL != pContextSSH)
    {
        pTemp = pContextSSH->pLpfHead;
        pContextTemp = pContextSSH;
    }
    else
        goto exit;

    while( NULL != pTemp )
    {
        if ( channel == (sbyte4) pTemp->lpfSessionData.clientChannel )
        {
            if ( NULL == pFollower )
            {
                pContextTemp->pLpfHead = pTemp->pNextSession;
            }
            else
            {
                pFollower->pNextSession = pTemp->pNextSession;
            }
            FREE(pTemp);
            pTemp = NULL;
            status = OK;
        }
        else
        {
            pFollower = pTemp;
            pTemp = pTemp->pNextSession;
        }
    }/* End of while loop */

    if( NULL == pContextSSH)
        pContextSSH = pDescr->pContextSSH;

    for (i = 0; i < SSH_MAX_RPF_HOSTS; i++)
    {
        pFollower = NULL;
        for (pTemp = pContextSSH->rpfTable[i].pRpfSessionHead; pTemp != NULL; pTemp = pTemp->pNextSession)
        {
            if (channel == (sbyte4) pTemp->lpfSessionData.clientChannel)
            {
                if ( NULL == pFollower )
                {
                    pContextSSH->rpfTable[i].pRpfSessionHead = pTemp->pNextSession;
                }
                else
                {
                    pFollower->pNextSession = pTemp->pNextSession;
                }
                FREE(pTemp);
                pTemp = NULL;
                status = OK;
                break;
            }
            else
            {
                pFollower = pTemp;
            }
        }
        if (OK == status)
            break;
    }

exit:
    return status;
} /* destroyLocalPortFwdSession */

/*------------------------------------------------------------------*/

static MSTATUS sendOpenLpfSessionChannel(sshClientContext *pContextSSH, sshcPfSession* pSession,
                                         ubyte* pConnectHost, ubyte4 connectPort,
                                         ubyte* pSrc, ubyte4 srcPort)
{

/*   byte      SSH_MSG_CHANNEL_OPEN
     string    channel type (restricted to US-ASCII) "session"
     uint32    sender channel
     uint32    initial window size
     uint32    maximum packet size
     ...       extra data
*/
    MSTATUS status;
    ubyte* pBuffer;
    ubyte4 buflen;
    ubyte4 myChannel = pSession->lpfSessionData.clientChannel;
    ubyte4 bufIndex = 0;
    ubyte4 windowSize;
    ubyte4 written;
    ubyte4 hostLen = MOC_STRLEN((sbyte *)pConnectHost);
    ubyte4 srcLen  = MOC_STRLEN((sbyte *)pSrc);

    buflen = 1 +
             sshc_lpfSessionService.stringLen +
             4 +
             4 +
             4 +
             hostLen + 4 +
             4 +
             srcLen + 4 +
             4;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *pBuffer = SSH_MSG_CHANNEL_OPEN;
    bufIndex++;

    MOC_MEMCPY(pBuffer + bufIndex, sshc_lpfSessionService.pString, sshc_lpfSessionService.stringLen);
    bufIndex += sshc_lpfSessionService.stringLen;

    /* client channel */
    *(pBuffer + bufIndex    )  = (ubyte)(myChannel >> 24);
    *(pBuffer + bufIndex + 1)  = (ubyte)(myChannel >> 16);
    *(pBuffer + bufIndex + 2)  = (ubyte)(myChannel >> 8);
    *(pBuffer + bufIndex + 3)  = (ubyte)(myChannel);

    /* initial window size */
    windowSize = MAX_SESSION_WINDOW_SIZE;
    *(pBuffer + bufIndex + 4) = 0;
    *(pBuffer + bufIndex + 5) = 0;
    *(pBuffer + bufIndex + 6) = (ubyte)(windowSize >>  8);
    *(pBuffer + bufIndex + 7) = (ubyte)(windowSize);

    /* max packet size -- uses window size */
    *(pBuffer + bufIndex + 8)  = 0;
    *(pBuffer + bufIndex + 9)  = 0;
    *(pBuffer + bufIndex + 10) = (ubyte)(windowSize >>  8);
    *(pBuffer + bufIndex + 11) = (ubyte)(windowSize);

    bufIndex += 12;

    if ( OK > ( status = SSH_STR_copyBytesAsStringToPayload( pBuffer, buflen, &bufIndex, pConnectHost, hostLen ) ) )
        goto exit;

    if ( OK > ( status = SSHC_UTILS_setInteger( pBuffer, buflen, &bufIndex, connectPort ) ) )
        goto exit;

    if ( OK > ( status = SSH_STR_copyBytesAsStringToPayload( pBuffer, buflen, &bufIndex, pSrc, srcLen ) ) )
        goto exit;

    if ( OK > ( status = SSHC_UTILS_setInteger( pBuffer, buflen, &bufIndex, srcPort ) ) )
        goto exit;

    /*Following line is commented to avoid compilation error while SFTP isn't enabled, more testing needed*/
    /*pSession->lpfSessionData.clientWindowSize = windowSize;*/

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pBuffer, buflen, &written);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* sendOpenLpfSessionChannel */

/*------------------------------------------------------------------*/

MSTATUS SSHC_SESSION_createLocalPortFwdSession(sshcConnectDescr* pDescr, sbyte4* pChannel)
{
    MSTATUS status = OK;
    sshcPfSession*  pLpfSession = NULL;

    (*pChannel) = 0;
    if ( NULL == ( pLpfSession = MALLOC( sizeof(sshcPfSession) ) ) )
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    MOC_MEMSET( (ubyte*)pLpfSession, 0x00, sizeof(sshcPfSession) );

    /* Insert the new channel number into Session data -- Calling application
       will use this channel number to map differentlocal port forwarding sessions */
    pLpfSession->lpfSessionData.clientChannel = ++m_channel;

    if ( OK > ( status = addLpfSessionToContext(pDescr,pLpfSession) ) )
        goto exit;
    /* Return the channel number only if everything is Okay */
    (*pChannel) = pLpfSession->lpfSessionData.clientChannel;
    /* Mark this channel inactive and closed*/
    pLpfSession->lpfSessionData.isChannelActive = FALSE;
    pLpfSession->lpfSessionData.isShellActive   = FALSE;
    pLpfSession->lpfSessionData.channelState    = SESSION_CLOSED;

exit:
    return status;
} /* SSHC_SESSION_createLocalPortFwdSession */

/*------------------------------------------------------------------*/

MSTATUS SSHC_SESSION_startPortFwdSession(sshcConnectDescr* pDescr, sbyte4  channel,
                                         ubyte* pConnectHost, ubyte4 connectPort,
                                         ubyte* pSrc, ubyte4 srcPort)
{
    MSTATUS           status = OK;
    sshcPfSession*  pSession = NULL;

    if ( OK > ( status = getSessionDataFromChannel( pDescr, NULL, channel, &pSession ) ) )
        goto exit;

    if ( OK > ( status = sendOpenLpfSessionChannel(pDescr->pContextSSH, pSession,
                                                   pConnectHost, connectPort,
                                                   pSrc, srcPort) ) )
        goto exit;

exit:
    return status;
} /* SSHC_SESSION_startPortFwdSession */

/*------------------------------------------------------------------*/

extern MSTATUS SSHC_SESSION_sendLocalPortFwdMessage(sshcConnectDescr* pDescr, ubyte4 channel,
                                                    ubyte *pMesg, ubyte4 mesgLen, ubyte4 *pBytesSent)
{
    ubyte*  pMessage = NULL;
    ubyte4  numBytesToWrite;
    ubyte4  numBytesWritten;
    MSTATUS status = OK;
    sshcPfSession*  pSession = NULL;

    *pBytesSent = 0;

    /* nothing to send */
    if (0 == mesgLen)
        goto exit;

    if ( OK > ( status = getSessionDataFromChannel( pDescr, NULL, channel, &pSession ) ) )
        goto exit;

    /* make sure session is open, before sending data to client */
    if ((FALSE          == pSession->lpfSessionData.isChannelActive ) ||
        (SESSION_CLOSED == pSession->lpfSessionData.channelState) ||
        (TRUE           == pSession->lpfSessionData.isEof ) )
    {
        status = ERR_SESSION_NOT_OPEN;
        goto exit;
    }

    if (NULL == (pMessage = MALLOC(mesgLen + 9)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (mesgLen > pSession->lpfSessionData.windowSize)
        mesgLen = pSession->lpfSessionData.windowSize;

    /* write the message out in chunks */
    while (0 < mesgLen)
    {
        if (OK > (status = (SSHC_OUT_MESG_sendMessageSize(pDescr->pContextSSH, mesgLen + 9,
                                                          &numBytesToWrite))))
        {
            goto exit;
        }

        /* the protocol governor */
        if (numBytesToWrite > pSession->lpfSessionData.maxPacketSize)
            numBytesToWrite = pSession->lpfSessionData.maxPacketSize;

        /* subtract message header */
        numBytesToWrite -= 9;

        pMessage[0] = SSH_MSG_CHANNEL_DATA;

        pMessage[1] = (ubyte)((pSession->lpfSessionData.recipientChannel) >> 24);
        pMessage[2] = (ubyte)((pSession->lpfSessionData.recipientChannel) >> 16);
        pMessage[3] = (ubyte)((pSession->lpfSessionData.recipientChannel) >>  8);
        pMessage[4] = (ubyte)((pSession->lpfSessionData.recipientChannel));

        pMessage[5] = (ubyte)(numBytesToWrite >> 24);
        pMessage[6] = (ubyte)(numBytesToWrite >> 16);
        pMessage[7] = (ubyte)(numBytesToWrite >>  8);
        pMessage[8] = (ubyte)(numBytesToWrite);

        MOC_MEMCPY(pMessage + 9, pMesg, numBytesToWrite);

        if (OK > (status = SSHC_OUT_MESG_sendMessage(pDescr->pContextSSH, pMessage,
                                                     numBytesToWrite + 9, &numBytesWritten)))
        {
            goto exit;
        }

        pMesg       += numBytesToWrite;
        mesgLen     -= numBytesToWrite;
        *pBytesSent += numBytesToWrite;
        pSession->lpfSessionData.windowSize -= numBytesToWrite;
    }

exit:
    if (NULL != pMessage)
        FREE(pMessage);

    return status;

} /* SSHC_SESSION_sendLocalPortFwdMessage */

/*------------------------------------------------------------------*/

extern MSTATUS sendRpfStart( sshClientContext* pContextSSH,  ubyte* pBindHost, ubyte4 bindPort)
{
/*   byte      SSH_MSG_GLOBAL_REQUEST
     string    channel type (restricted to US-ASCII) "tcpip-forward"
     boolean   want reply
     string    address to bind
     uint32    port no. to bind
*/
    ubyte* pBuffer = NULL;
    ubyte4 bufIndex = 0;
    ubyte4 bufsize = 0;
    ubyte4  written = 0;
    ubyte4 bindLen = MOC_STRLEN((sbyte *)pBindHost);
    MSTATUS         status = OK;

    bufsize = 1 +
             sshc_rpfForwardService.stringLen +
             1 +
             4 +
             bindLen + 4; 

    if (NULL == (pBuffer = MALLOC(bufsize)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *pBuffer = SSH_MSG_GLOBAL_REQUEST;
    bufIndex++;

    MOC_MEMCPY(pBuffer + bufIndex, sshc_rpfForwardService.pString, sshc_rpfForwardService.stringLen);
    bufIndex += sshc_rpfForwardService.stringLen;

    /* want reply = TRUE, by default */
    *(pBuffer + bufIndex) = 1;
    bufIndex++;

    /* length of bindAddress string */
    *(pBuffer + bufIndex    )  = (ubyte)(bindLen >> 24);
    *(pBuffer + bufIndex + 1)  = (ubyte)(bindLen >> 16);
    *(pBuffer + bufIndex + 2)  = (ubyte)(bindLen >> 8);
    *(pBuffer + bufIndex + 3)  = (ubyte)(bindLen);
    bufIndex += 4;

    /* bind Address */
    MOC_MEMCPY(pBuffer + bufIndex, pBindHost, bindLen);
    bufIndex += bindLen;

    /* bind port */
    *(pBuffer + bufIndex    )  = (ubyte)(bindPort >> 24);
    *(pBuffer + bufIndex + 1)  = (ubyte)(bindPort >> 16);
    *(pBuffer + bufIndex + 2)  = (ubyte)(bindPort >> 8);
    *(pBuffer + bufIndex + 3)  = (ubyte)(bindPort);
    bufIndex += 4;

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pBuffer, bufsize, &written);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;
} /* sendRpfStart */

/*------------------------------------------------------------------*/

extern MSTATUS sendCancelRpfReq( sshClientContext* pContextSSH,  ubyte* pBindHost, ubyte4 bindPort, ubyte* pHostAddr, ubyte4 hostPort)
{
/*   byte      SSH_MSG_GLOBAL_REQUEST
    string    channel type (restricted to US-ASCII) "cancel-tcpip-forward"
    boolean   want reply
    string    address to bind
    uint32    port no. to bind
*/
    ubyte* pBuffer = NULL;
    ubyte4 bufIndex = 0;
    ubyte4 bufsize = 0;
    ubyte4  written = 0;
    ubyte4 bindLen = MOC_STRLEN((sbyte *)pBindHost);
    MSTATUS         status = OK;
    sbyte4 i,j;

    bufsize = 1 +
            sshc_rpfCancelForwardService.stringLen +
            1 +
            4 +
            bindLen + 4; 

    if (NULL == (pBuffer = MALLOC(bufsize)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *pBuffer = SSH_MSG_GLOBAL_REQUEST;
    bufIndex++;

    MOC_MEMCPY(pBuffer + bufIndex, sshc_rpfCancelForwardService.pString, sshc_rpfCancelForwardService.stringLen);
    bufIndex += sshc_rpfCancelForwardService.stringLen;

    /* want reply = TRUE, by default */
    *(pBuffer + bufIndex) = 1;
    bufIndex++;

    /* length of bindAddress string */
    *(pBuffer + bufIndex    )  = (ubyte)(bindLen >> 24);
    *(pBuffer + bufIndex + 1)  = (ubyte)(bindLen >> 16);
    *(pBuffer + bufIndex + 2)  = (ubyte)(bindLen >> 8);
    *(pBuffer + bufIndex + 3)  = (ubyte)(bindLen);
    bufIndex += 4;

    /* bind Address */
    MOC_MEMCPY(pBuffer + bufIndex, pBindHost, bindLen);
    bufIndex += bindLen;

    /* bind port */
    *(pBuffer + bufIndex    )  = (ubyte)(bindPort >> 24);
    *(pBuffer + bufIndex + 1)  = (ubyte)(bindPort >> 16);
    *(pBuffer + bufIndex + 2)  = (ubyte)(bindPort >> 8);
    *(pBuffer + bufIndex + 3)  = (ubyte)(bindPort);
    bufIndex += 4;

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pBuffer, bufsize, &written);

    /* free all the allocated sesion by this connection */
    for (i = 0; i < SSH_MAX_RPF_HOSTS; i++)
    {
        /* check if entry is already present. If so, then this is a duplicate request */
        if (pContextSSH->rpfTable[i].inUse)
        {
            if((!MOC_STRCMP((sbyte *) pContextSSH->rpfTable[i].pHostAddr, (sbyte *) pHostAddr)) &&
                           (pContextSSH->rpfTable[i].hostPort == hostPort))
            {
                for(j = 0; j < SSH_MAX_REMOTE_PORT_FWD_CHANNEL; j++)
                {
                    destroyLocalPortFwdSession(NULL, pContextSSH,
                                           pContextSSH->rpfTable[i].channelList[j]);
                }
            }
        }
    }
exit:
        if (NULL != pBuffer)
        FREE(pBuffer);

    return status;
} /* sendCancelRpfReq */

/*------------------------------------------------------------------*/

static MSTATUS sendLpfEof( sshClientContext* pContextSSH, ubyte4 channel )
{
    ubyte   payload[5];
    ubyte4  numBytesWritten;
    sshcPfSession*  pSession = NULL;
    MSTATUS         status = OK;

    if ( OK > ( status = getSessionDataFromChannel( NULL, pContextSSH, channel, &pSession ) ) )
        goto exit;

    /* make sure session is open, before sending a session close */
    if ((TRUE           == pSession->lpfSessionData.isEof) ||
        (SESSION_CLOSED == pSession->lpfSessionData.channelState))
    {
        status = ERR_SESSION_NOT_OPEN;
        goto exit;
    }

    /* Keep a record that we have already sent EOF for this session */
    pSession->lpfSessionData.isEof = TRUE;

    payload[0] = SSH_MSG_CHANNEL_EOF;
    payload[1] = (ubyte)(pSession->lpfSessionData.recipientChannel >> 24);
    payload[2] = (ubyte)(pSession->lpfSessionData.recipientChannel >> 16);
    payload[3] = (ubyte)(pSession->lpfSessionData.recipientChannel >>  8);
    payload[4] = (ubyte)(pSession->lpfSessionData.recipientChannel);

    if (OK > SSHC_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesWritten))
        goto exit;

exit:
    return status;
} /* sendLpfEof */

/*------------------------------------------------------------------*/

static MSTATUS sendLpfClose( sshClientContext* pContextSSH, ubyte4 channel )
{
    ubyte   payload[5];
    ubyte4  numBytesWritten;
    sshcPfSession*  pSession = NULL;
    MSTATUS         status = OK;

    if ( OK > ( status = getSessionDataFromChannel( NULL, pContextSSH, channel, &pSession ) ) )
        goto exit;

    /* make sure session is open, before sending a session close */
    if ( SESSION_CLOSED == pSession->lpfSessionData.channelState )
    {
        status = ERR_SESSION_NOT_OPEN;
        goto exit;
    }

    /* Keep a record that we have already sent CLOSE for this session */
    pSession->lpfSessionData.channelState = SESSION_CLOSED;

    payload[0] = SSH_MSG_CHANNEL_CLOSE;
    payload[1] = (ubyte)(pSession->lpfSessionData.recipientChannel >> 24);
    payload[2] = (ubyte)(pSession->lpfSessionData.recipientChannel >> 16);
    payload[3] = (ubyte)(pSession->lpfSessionData.recipientChannel >>  8);
    payload[4] = (ubyte)(pSession->lpfSessionData.recipientChannel);

    if (OK > SSHC_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesWritten))
        goto exit;

exit:
    return status;
} /* sendLpClose */

/*------------------------------------------------------------------*/

extern MSTATUS SSHC_SESSION_sendLocalPortFwdClose(sshcConnectDescr* pDescr, ubyte4 channel)
{
    MSTATUS         status = OK;

    if ( OK > ( status = sendLpfEof( pDescr->pContextSSH, channel ) ) )
        goto exit;

    if ( OK > ( status = sendLpfClose( pDescr->pContextSSH, channel ) ) )
        goto exit;

exit:
    return status;
} /* SSHC_SESSION_sendLocalPortFwdClose */

#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

#endif /* __ENABLE_MOCANA_SSH_CLIENT__ */


