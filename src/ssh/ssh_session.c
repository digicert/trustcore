/*
 * ssh_session.c
 *
 * SSH Session Handler
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

#include "../common/moptions.h"

#ifdef __ENABLE_MOCANA_SSH_SERVER__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mem_pool.h"
#include "../common/circ_buf.h"
#include "../common/moc_stream.h"
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
#include "../ssh/ssh_defs.h"
#include "../ssh/ssh_str.h"
#include "../ssh/ssh_context.h"
#include "../ssh/ssh_auth.h"
#include "../ssh/ssh_out_mesg.h"
#include "../ssh/ssh_trans.h"
#include "../ssh/ssh_session.h"
#include "../ssh/ssh_str_house.h"
#include "../ssh/ssh_server.h"
#include "../ssh/ssh_ftp.h"
#include "../ssh/ssh.h"
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_dh.h"
#endif


extern sbyte4 SSH_INTERNAL_API_setOpenState(sbyte4 connectionInstance);


/*------------------------------------------------------------------*/

#ifndef MOCANA_SSH_CONNECT_STR_LEN
#define MOCANA_SSH_CONNECT_STR_LEN          (32)
#endif

#define SSH_CHANNEL_NUMBER                  (0x051807D2)
#define SSH_PF_CHANNEL_NUMBER               (0x061807D5)

#define SSH_OPEN_UPCALL                     SSH_sshSettings()->funcPtrSessionOpen
#define SSH_SESSION_CLOSE_UPCALL            SSH_sshSettings()->funcPtrClosed
#define SSH_SESSION_CHANNEL_CLOSE_UPCALL    SSH_sshSettings()->funcPtrCloseChannel
#define SSH_SESSION_EOF_UPCALL              SSH_sshSettings()->funcPtrEof
#define SSH_RECEIVE_UPCALL                  SSH_sshSettings()->funcPtrReceivedData
#define SSH_STDERR_UPCALL                   SSH_sshSettings()->funcPtrStdErr
#define SSH_SESSION_PTY_UPCALL              SSH_sshSettings()->funcPtrPtyRequest
#define SSH_SESSION_OPEN_SHELL_UPCALL       SSH_sshSettings()->funcPtrOpenShell
#define SSH_SESSION_OPEN_SFTP_UPCALL        SSH_sshSettings()->funcPtrOpenSftp
#define SSH_SESSION_WINDOW_CHANGE_UPCALL    SSH_sshSettings()->funcPtrWindowChange
#define SSH_SESSION_BREAK_OP_UPCALL         SSH_sshSettings()->funcPtrBreakOp
#define SSH_SESSION_EXEC_START_UPCALL       SSH_sshSettings()->funcPtrExec
#define SSH_SESSION_REKEY_UPCALL            SSH_sshSettings()->funcPtrSessionReKey
#define SSH_PORT_FWD_RECEIVE_UPCALL         SSH_sshSettings()->funcPortFwdReceivedData
#define SSH_PORT_FWD_SESSION_CLOSE_UPCALL   SSH_sshSettings()->funcPortFwdPtrClosed
#define SSH_PORT_FWD_SESSION_EOF_UPCALL     SSH_sshSettings()->funcPortFwdPtrEof

#define SFTP_SESSION_ESTABLISHED            (TRUE + 1)
#define SCP_SESSION_ESTABLISHED             (TRUE + 2)


/*------------------------------------------------------------------*/

enum requestEnums
{
    kSessionRequest,
    kForwardRequest,
    kForwardCancelRequest,
    kDirectRequest
};


/*------------------------------------------------------------------*/

typedef struct
{
    sshStringBuffer*    pRequestString;
    enum requestEnums   requestType;

} requestTypeDescr;


/*------------------------------------------------------------------*/

static requestTypeDescr ssh_sessionTypes[] =
{
    { &ssh_sessionService,       kSessionRequest       },
    { &ssh_forwardService,       kForwardRequest       },
    { &ssh_cancelforwardService, kForwardCancelRequest },
    { &ssh_directService,        kDirectRequest        }
};

#define NUM_CHANNEL_TYPES (sizeof(ssh_sessionTypes)/sizeof(requestTypeDescr))

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
static MSTATUS isPfChannelActive(sshContext *pContextSSH, ubyte4 ownChannel, sshPfSession** ppSession);
static MSTATUS sendLpfClose(sshContext *pContextSSH, sshPfSession*  pPfSession);
static MSTATUS sendLpfEof(sshContext *pContextSSH, sshPfSession*  pPfSession);
static MSTATUS createPortFwdChannelNumber(sshContext *pContextSSH, sshPfSession* pNewSession, ubyte4* pChannelNo);
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

/*------------------------------------------------------------------*/

static sbyte4
findChoice(ubyte *pChannelType, ubyte4 channelTypeLength)
{
    sbyte4  index  = NUM_CHANNEL_TYPES - 1;
    sbyte4  result = -1;
    sbyte4  memResult;

    while (0 <= index)
    {
        if ((channelTypeLength == ssh_sessionTypes[index].pRequestString->stringLen) &&
            (OK <= MOC_MEMCMP(pChannelType, (ubyte *)ssh_sessionTypes[index].pRequestString->pString, channelTypeLength, &memResult)) &&
            (0 == memResult))
        {
            result = index;
            break;
        }

        index--;
    }

    return result;
}


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
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
extern MSTATUS 
SSH_SESSION_sendPortFwdOpen(sshContext *pContextSSH,
                                         ubyte* pConnectHost, ubyte4 connectPort,
                                         ubyte* pSrc,ubyte4 srcPort, ubyte4 *rmyChannel)
{

/*   byte      SSH_MSG_CHANNEL_OPEN
     string    channel type (restricted to US-ASCII) "session"
     uint32    sender channel
     uint32    initial window size
     uint32    maximum packet size
     ...       extra data
*/
    MSTATUS status;
    sshStringBuffer*    chMesg;
    sshStringBuffer*    srcAdd = (sshStringBuffer*)pSrc;
    ubyte* pBuffer = NULL;
    ubyte4 buflen = 0;
    ubyte4 myChannel = 0;
    ubyte4 bufIndex = 0;
    ubyte4 windowSize = 0;
    ubyte4 written = 0;
    ubyte4 hostLen = MOC_STRLEN((sbyte *) pConnectHost);
    sshPfSession*   pTmpSession = NULL;

    chMesg = &ssh_forwardedService;
    if ( NULL == ( pTmpSession = MALLOC( sizeof(sshPfSession) ) ) )
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    MOC_MEMSET( (ubyte*)pTmpSession, 0x00, sizeof(sshPfSession) );
    
    createPortFwdChannelNumber(pContextSSH, pTmpSession, &myChannel);

    *rmyChannel = myChannel;
    pTmpSession->ownChannel = myChannel;
    pTmpSession->pfSessionData.isShellActive    = TRUE;
    pTmpSession->pfSessionData.isChannelActive  = TRUE;

    buflen = 1 +
             chMesg->stringLen+
             4 +
             4 +
             4 +
             hostLen + 4 +
             4 +
             srcAdd->stringLen +
             4;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *pBuffer = SSH_MSG_CHANNEL_OPEN;
    bufIndex++;

    MOC_MEMCPY(pBuffer + bufIndex, chMesg->pString, chMesg->stringLen);
    bufIndex += chMesg->stringLen;

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

    MOC_MEMCPY(pBuffer + bufIndex, srcAdd->pString, srcAdd->stringLen);
    bufIndex += srcAdd->stringLen;

    *(pBuffer + bufIndex    )  = (ubyte)(srcPort >> 24);
    *(pBuffer + bufIndex + 1)  = (ubyte)(srcPort >> 16);
    *(pBuffer + bufIndex + 2)  = (ubyte)(srcPort >> 8);
    *(pBuffer + bufIndex + 3)  = (ubyte)(srcPort);
    bufIndex += 4;


    if ( OK > ( status = SSH_STR_copyBytesAsStringToPayload( pBuffer, buflen, &bufIndex, pConnectHost, hostLen ) ) )
        goto exit;

    *(pBuffer + bufIndex    )  = (ubyte)(connectPort >> 24);
    *(pBuffer + bufIndex + 1)  = (ubyte)(connectPort >> 16);
    *(pBuffer + bufIndex + 2)  = (ubyte)(connectPort >> 8);
    *(pBuffer + bufIndex + 3)  = (ubyte)(connectPort);

    status = SSH_OUT_MESG_sendMessage(pContextSSH, pBuffer, buflen, &written);

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

}

/*------------------------------------------------------------------*/

static MSTATUS handleChannelOpenConfirmation(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    MSTATUS status = OK;
    ubyte4  myChannel;
    ubyte4  serverChannel;
    ubyte4  serverWindowSize;
    ubyte4  serverMaxPktSize;

    sshPfSession*  pSession = NULL;

    if(NULL == pMesg)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (mesgLen != 1 + 4 + 4 + 4 + 4)
    {
        status = ERR_SESSION_BAD_PAYLOAD;
        goto exit;
    }

    myChannel = getUbyte4(pMesg + 1);
    serverChannel = getUbyte4(pMesg + 5);
    serverWindowSize = getUbyte4(pMesg + 9);
    serverMaxPktSize = getUbyte4(pMesg + 13);

    if ( OK == ( status = isPfChannelActive(pContextSSH, myChannel, &pSession ) ) )
    {
        /* notify upper layer of open channel */
        if (NULL != SSH_sshSettings()->funcPtrRemotePortFwdSessionOpen)
            (SSH_sshSettings()->funcPtrRemotePortFwdSessionOpen)(CONNECTION_INSTANCE(pContextSSH), serverChannel,myChannel);

        pSession->pfSessionData.isChannelActive  = TRUE;
        pSession->pfSessionData.channelState     = SESSION_OPEN;
        pSession->pfSessionData.recipientChannel = serverChannel;
        pSession->pfSessionData.maxWindowSize    = serverWindowSize;
        pSession->pfSessionData.maxPacketSize    = serverMaxPktSize;
        pSession->pfSessionData.windowSize       = serverWindowSize;
    }
    else
    {
        status = ERR_SESSION_BAD_PAYLOAD;
        goto exit;
    }

exit:
    return status;
}
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
/*------------------------------------------------------------------*/
static MSTATUS
handleGlobalMesgReq(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4              numBytesWritten;
    ubyte               msgReqFailed = SSH_MSG_REQUEST_FAILURE;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__ 
    ubyte               msgReqSuc = SSH_MSG_REQUEST_SUCCESS;
    ubyte4              dstPort;
    ubyte4              orgPort;
#endif
    MSTATUS             status       = OK;
    ubyte4              channelTypeLength;
    sbyte4              channelChoice;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__ 
    sshStringBuffer*    pDstLocation = NULL;
    byteBoolean         bFreeDstLocation = FALSE ;
    byteBoolean         WantReply;
#endif

    channelTypeLength = getUbyte4(1 + pMesg);

    /* make sure we have some minimal number of bytes, before processing */
    if ((mesgLen - (1 + 4)) < channelTypeLength)
    {
        status = ERR_SESSION_BAD_PAYLOAD;
        goto exit;
    }

    /* find the type of channel the user requires */
    channelChoice = findChoice(1 + pMesg, 4 + channelTypeLength);
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__ 
    /* Get the 'want reply' content */
    WantReply     = pMesg[1 + 4 + channelTypeLength];
#endif

    switch(channelChoice)
    {
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__ 
        /* Handle reverse port forwarding */
        case kForwardRequest:
        {
            ubyte4 index = 1 + 4 + channelTypeLength + 1; 
            /* fetch the bind address parameter from mesg */
            bFreeDstLocation = TRUE ;
            if (OK > (status = SSH_STR_copyStringFromPayload(pMesg, mesgLen, &index, &pDstLocation)))
                goto exit;

            /* get the port to listen on */ 
            dstPort = getUbyte4(pMesg + index);
            orgPort = dstPort; /* needed when requested port no. is 0 */

            if (MOCANA_UPPER_PRIVILEGE_PORT >= dstPort && dstPort != 0)
            {
                status = SSH_OUT_MESG_sendMessage(pContextSSH, &msgReqFailed, 1, &numBytesWritten);
                goto exit;
            }
            else
            {
                ubyte   MsgBuf[5];
                ubyte4  bytesWrtn;
                ubyte4  msgLen;

                if(0 == dstPort)
                {
                    sbyte4  port = 0;
                    status = -1;
                    while(OK > status) 
                    {
                        dstPort = MOCANA_SSH_REVERSE_PORT_FWD_PORT_VALUE + port;
                        status = (MSTATUS)SSH_sshSettings()->funcCheckPort(dstPort);
                        if(1000 < port && OK > status)
                        {
                            status = SSH_OUT_MESG_sendMessage(pContextSSH, &msgReqFailed, 1, &numBytesWritten);
                            goto exit;
                        }
                        port += 100;
                    }

                    MsgBuf[0] = msgReqSuc;
                    msgLen = 1;

                    if(1 == WantReply)
                    {
                        MsgBuf[1] = (ubyte)(dstPort >> 24);
                        MsgBuf[2] = (ubyte)(dstPort >> 16);
                        MsgBuf[3] = (ubyte)(dstPort >> 8);
                        MsgBuf[4] = (ubyte)(dstPort);
                        msgLen +=4;
                    }
                }
                else
                {
                    if(OK > (status = (MSTATUS)SSH_sshSettings()->funcCheckPort(dstPort)))
                    {
                        status = SSH_OUT_MESG_sendMessage(pContextSSH, &msgReqFailed, 1, &numBytesWritten);
                         goto exit;
                    }
                    MsgBuf[0] = msgReqSuc;
                    msgLen = 1;
                }

                if(OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, MsgBuf, msgLen, &bytesWrtn)))
                    goto exit;

                if(OK > (status = (MSTATUS)SSH_sshSettings()->funcStartTcpIpForward(CONNECTION_INSTANCE(pContextSSH),(ubyte*) pDstLocation,                                                                           dstPort, orgPort)))
                {
                    goto exit;
                }
                bFreeDstLocation = FALSE ;
            }
            break;
        }
        case kForwardCancelRequest:
        {
            ubyte4              index = 1 + 4 + channelTypeLength + 1;
            sshStringBuffer*    bindAdd = NULL;
            ubyte4              bindPort;

            if (OK > (status = SSH_STR_copyStringFromPayload(pMesg, mesgLen, &index, &bindAdd)))
                goto exit;
            /* bind support is not added yet, there is need to check the bind address here */
            /* in the mean time, don't leak memory... */
            FREE(bindAdd);
            bindPort = getUbyte4(pMesg + index);
            if(NULL != SSH_sshSettings()->funcCancelTcpIpForward)
                status = SSH_sshSettings()->funcCancelTcpIpForward(CONNECTION_INSTANCE(pContextSSH),
                                                                   bindPort);

            break;
        }
#endif 
        default:
        {
            ubyte4 length = getUbyte4(1 + pMesg);

            if (length < mesgLen)
            {
                if (1 == pMesg[1 + 4 + length])
                {
                    /* we don't like the message */
                    status = SSH_OUT_MESG_sendMessage(pContextSSH, &msgReqFailed, 1, &numBytesWritten);
                }
            }
        }
    }
exit:
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__ 
    if(bFreeDstLocation == TRUE)
    {
        SSH_STR_freeStringBuffer(&pDstLocation);
    }
#endif
    return status;
}

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
/*------------------------------------------------------------------*/

static MSTATUS
createPortFwdChannelNumber(sshContext *pContextSSH, sshPfSession* pNewSession, ubyte4* pChannelNo)
{
    MSTATUS         status = OK;
    sshPfSession*   pTemp  = NULL;
    ubyte4          offset = 0;

    if ( NULL == pContextSSH->pPfSessionHead )
    {
        pContextSSH->pPfSessionHead = pNewSession;
    }
    else
    {
        pTemp = pContextSSH->pPfSessionHead;
        offset = 1;
        while ( NULL != pTemp->pNextSession )
        {
            offset++;
            pTemp = pTemp->pNextSession;
        }
        pTemp->pNextSession = pNewSession;
    }

    (*pChannelNo) = ( SSH_PF_CHANNEL_NUMBER + offset );
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
isPfChannelActive(sshContext *pContextSSH, ubyte4 ownChannel, sshPfSession** ppSession )
{
    MSTATUS         status = ERR_SSH_BAD_ID;
    sshPfSession*   pTemp  = pContextSSH->pPfSessionHead;

    if ( NULL != pTemp )
    {
        while ( NULL != pTemp )
        {
            if ( ( ownChannel == pTemp->ownChannel ) &&
                 ( TRUE == pTemp->pfSessionData.isChannelActive ) &&
                 ( TRUE == pTemp->pfSessionData.isShellActive ) )
            {
                (*ppSession) = pTemp;
                status = OK;
                break;
            }
            else
            {
                pTemp = pTemp->pNextSession;
            }
        } /* end of while loop */
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
closePfChannel(sshContext *pContextSSH, ubyte4 ownChannel)
{
    MSTATUS         status     = ERR_SSH_BAD_ID;
    sshPfSession*   pTemp      = pContextSSH->pPfSessionHead;
    sshPfSession*   pFollower  = NULL;

    if ( NULL != pTemp )
    {
        while ( NULL != pTemp )
        {
            if ( ( ownChannel == pTemp->ownChannel ) &&
                 ( TRUE == pTemp->pfSessionData.isChannelActive ) &&
                 ( TRUE == pTemp->pfSessionData.isShellActive ) )
            {
                if ( NULL == pFollower )
                {
                    pContextSSH->pPfSessionHead = pTemp->pNextSession;
                }
                else
                {
                    pFollower->pNextSession = pTemp->pNextSession;
                }
                FREE( pTemp );
                pTemp = NULL;
                status = OK;
                break;
            }
            else
            {
                pFollower = pTemp;
                pTemp = pTemp->pNextSession;
            }
        } /* end of while loop */
    }

    return status;
}

#endif /* #ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
/*------------------------------------------------------------------*/
#define MIN_OPEN_CHANNEL_MSG_LEN (1/*type*/+ 4/*channel type lengh*/ + 4 + 4 + 4)
static MSTATUS
handleChannelOpenReq(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte               failType;
    sshStringBuffer*    failMessage;
    ubyte*              pPayload    = NULL;
    ubyte4              recipientChannel;
    ubyte4              numBytesWritten;
    ubyte4              initWindowSize;
    ubyte4              maxPacketSize;
    ubyte4              channelTypeLength;
    sbyte4              channelChoice;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    sbyte*              pConnectString = NULL;
    sshStringBuffer*    pDstLocation = NULL;
    ubyte2              dstPort;
    sshStringBuffer*    pSrcLocation = NULL;
    ubyte2              srcPort;
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
    ubyte4              sshChannel;
    ubyte4              sshWindowSize;
    enum sshSessionTypes sessionEvent;
    MSTATUS             status;

    if (mesgLen < MIN_OPEN_CHANNEL_MSG_LEN)
    {
        status = ERR_SESSION_BAD_PAYLOAD;
        goto exit;
    } 
    channelTypeLength = getUbyte4(1 + pMesg);

    /* make sure we have some minimal number of bytes, before processing */
    if ((mesgLen - (1 + 4 + 12)) < channelTypeLength)
    {
        status = ERR_SESSION_BAD_PAYLOAD;
        goto exit;
    }

    /* we need recipientChannel whether we accept or fail on this request */
    recipientChannel = getUbyte4(pMesg + 1 + 4 + channelTypeLength);
    initWindowSize   = getUbyte4(pMesg + 1 + 4 + channelTypeLength + 4);
    maxPacketSize    = getUbyte4(pMesg + 1 + 4 + channelTypeLength + 8);

    failType    = SSH_OPEN_UNKNOWN_CHANNEL_TYPE;
    failMessage = &ssh_channelUnknown;

    /* find the type of channel the user requires */
    channelChoice = findChoice(1 + pMesg, 4 + channelTypeLength);

    switch (channelChoice)
    {
        case kSessionRequest:       /* session */
        {
            sessionEvent = SSH_SESSION_OPEN;

            if (TRUE == pContextSSH->sessionState.isChannelActive)
            {
                failType    = SSH_OPEN_RESOURCE_SHORTAGE;
                failMessage = &ssh_resourceShort;
                goto sendfail;
            }

            pContextSSH->sessionState.isChannelActive  = TRUE;
            pContextSSH->sessionState.channelState     = SESSION_OPEN;
            pContextSSH->sessionState.recipientChannel = recipientChannel;
            pContextSSH->sessionState.maxWindowSize    = initWindowSize;
            pContextSSH->sessionState.maxPacketSize    = maxPacketSize;
            pContextSSH->sessionState.windowSize       = initWindowSize;
            pContextSSH->sessionState.serverWindowSize = MAX_SESSION_WINDOW_SIZE;

            pContextSSH->sessionState.isEof            = FALSE;

            sshChannel = SSH_CHANNEL_NUMBER;
            break;
        }

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
        case kDirectRequest:        /* direct-tcpip */
        {
            ubyte4 index = 1 + 4 + channelTypeLength + 12;
            ubyte4 connectStrLen;
            sshPfSession*   pTmpSession = NULL;

            sessionEvent = SSH_SESSION_OPEN_PF;

            /* check if user is capable/allowed direct-tcpip access */
            if (MOCANA_SSH_ALLOW_DIRECT_TCPIP != (pContextSSH->portForwardingPermissions & MOCANA_SSH_ALLOW_DIRECT_TCPIP))
                goto sendfail;

            if (mesgLen < (index + 16))
            {
                status = ERR_SESSION_BAD_PAYLOAD;
                goto exit;
            }

            if (OK > (status = SSH_STR_copyStringFromPayload(pMesg, mesgLen, &index, &pDstLocation)))
                goto exit;

            dstPort = (ubyte2)getUbyte4(pMesg + index); index += 4;

            if ((0 == dstPort) || (4 >= pDstLocation->stringLen))
            {
                /* if destination port is zero, fail */
                goto sendfail;
            }

            if ((MOCANA_UPPER_PRIVILEGE_PORT >= dstPort) &&
                (MOCANA_SSH_ALLOW_PRIVILEGED_DIRECT_TCPIP != (pContextSSH->portForwardingPermissions & MOCANA_SSH_ALLOW_PRIVILEGED_DIRECT_TCPIP)))
            {
                /* destination port is less-than-or-equal (typically 1024) without privilege access, fail*/
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

            connectStrLen = (MOCANA_SSH_CONNECT_STR_LEN < pDstLocation->stringLen - 4) ? MOCANA_SSH_CONNECT_STR_LEN : (pDstLocation->stringLen - 4);

            if ( NULL == ( pTmpSession = MALLOC( sizeof(sshPfSession) ) ) )
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            MOC_MEMSET( (ubyte*)pTmpSession, 0x00, sizeof(sshPfSession) );
            
            createPortFwdChannelNumber(pContextSSH, pTmpSession, &sshChannel);

            if (NULL != (pConnectString = MALLOC(1 + connectStrLen)))
            {
                sbyte4 ignoreRequest = TRUE;    /* always default to safest path */

                /* clone and null terminate string */
                MOC_MEMCPY((ubyte *)pConnectString, 4 + pDstLocation->pString, connectStrLen);
                pConnectString[connectStrLen] = '\0';
                /* handler may block, re-direct, or use non-socket interface to transport */
                if (NULL != SSH_sshSettings()->funcPtrConnect)
                {
                    /* pass-by-reference allows custom code to alter connect address and port */
                    if (OK > (status = (MSTATUS)SSH_sshSettings()->funcPtrConnect(CONNECTION_INSTANCE(pContextSSH), SSH_PF_DATA,
                                                                                  (ubyte *)pConnectString, dstPort, &ignoreRequest,
                                                                                  recipientChannel)))
                        goto exit;
                }

                /* no errors, but callback wants to block location */
                if (ignoreRequest)
                    goto sendfail;
                else
                {
                    if (OK > (status = SSH_INTERNAL_API_setOpenState(CONNECTION_INSTANCE(pContextSSH))))
                        goto exit;
                }
            }
            else
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            pTmpSession->ownChannel = sshChannel;
            pTmpSession->pfSessionData.isShellActive    = TRUE;
            pTmpSession->pfSessionData.isChannelActive  = TRUE;
            pTmpSession->pfSessionData.recipientChannel = recipientChannel;
            pTmpSession->pfSessionData.maxWindowSize    = initWindowSize;
            pTmpSession->pfSessionData.maxPacketSize    = maxPacketSize;
            pTmpSession->pfSessionData.windowSize       = initWindowSize;
            pTmpSession->pfSessionData.serverWindowSize = MAX_SESSION_WINDOW_SIZE;

            break;
        }
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

        default:
            goto sendfail;
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

    status = SSH_OUT_MESG_sendMessage(pContextSSH, pPayload, 17, &numBytesWritten);

    /* notify upper layer of open channel */
    if ((OK <= status) && (NULL != SSH_OPEN_UPCALL))
    {
        status = SSH_OPEN_UPCALL(CONNECTION_INSTANCE(pContextSSH), sessionEvent, NULL, 0);
    }

    goto exit;

sendfail:
    if (NULL == (pPayload = MALLOC(1 + 4 + 4 + failMessage->stringLen + ssh_languageTag.stringLen)))
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
    if (OK > (status = MOC_MEMCPY(9 + pPayload + failMessage->stringLen, ssh_languageTag.pString, ssh_languageTag.stringLen)))
        goto exit;

    status = SSH_OUT_MESG_sendMessage(pContextSSH, pPayload, 9 + failMessage->stringLen + ssh_languageTag.stringLen, &numBytesWritten);

exit:
    if (NULL != pPayload)
        FREE(pPayload);

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    if (NULL != pConnectString)
        FREE(pConnectString);

    SSH_STR_freeStringBuffer(&pDstLocation);
    SSH_STR_freeStringBuffer(&pSrcLocation);
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

    return status;

} /* handleChannelOpenReq */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_SESSION_sendWindowAdjust(sshContext *pContextSSH, ubyte mesgType, ubyte4 numBytesToAck)
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

    status = SSH_OUT_MESG_sendMessage(pContextSSH, payload, 9, &numBytesWritten);

    if (OK <= status)
        if (9 != numBytesWritten)
            status = ERR_SSH_SEND_ACK_FAIL;

    return status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
extern MSTATUS
SSH_SESSION_sendPortFwdWindowAdjust(sshContext *pContextSSH, ubyte mesgType, ubyte4 numBytesToAck, ubyte4 recipientChannel )
{
    ubyte4  numBytesWritten;
    ubyte   payload[9];
    MSTATUS status;

    /* ack the message data */
    payload[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;

    payload[1] = (ubyte)(recipientChannel >> 24);
    payload[2] = (ubyte)(recipientChannel >> 16);
    payload[3] = (ubyte)(recipientChannel >>  8);
    payload[4] = (ubyte)(recipientChannel);

    payload[5] = (ubyte)(numBytesToAck >> 24);
    payload[6] = (ubyte)(numBytesToAck >> 16);
    payload[7] = (ubyte)(numBytesToAck >>  8);
    payload[8] = (ubyte)(numBytesToAck);

    status = SSH_OUT_MESG_sendMessage(pContextSSH, payload, 9, &numBytesWritten);

    if (OK <= status)
        if (9 != numBytesWritten)
            status = ERR_SSH_SEND_ACK_FAIL;

    return status;
}
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

/*------------------------------------------------------------------*/

static MSTATUS
handleWindowAdjust(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4  recipientChannel;
    ubyte4  numBytesAdd;
    MSTATUS status = ERR_SESSION_BAD_PAYLOAD;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    sshPfSession*  pSession = NULL;
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

    if (9 == mesgLen)
    {
        recipientChannel = getUbyte4(pMesg + 1);
        numBytesAdd      = getUbyte4(pMesg + 5);

        status = ERR_SESSION_NOT_OPEN;

        if ((SSH_CHANNEL_NUMBER == recipientChannel) &&
            ((FALSE != pContextSSH->sessionState.isShellActive) || (FALSE != pContextSSH->sessionState.isExecActive)))
        {
            pContextSSH->sessionState.windowSize += numBytesAdd;
            status = OK;
        }
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
        else if ( OK == ( status = isPfChannelActive( pContextSSH, recipientChannel, &pSession ) ) )
        {
            pSession->pfSessionData.windowSize += numBytesAdd;
            status = OK;
        }
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleCloseSession(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4  recipientChannel;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    sshPfSession* pSession = NULL;
#endif /* #ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

    MSTATUS status = ERR_SESSION_BAD_PAYLOAD;

    if (5 == mesgLen)
    {
        recipientChannel = getUbyte4(pMesg + 1);
        status = ERR_SESSION_NOT_OPEN;

        if ((SSH_CHANNEL_NUMBER == recipientChannel) &&
            (TRUE == pContextSSH->sessionState.isChannelActive))
        {
            /*  RFC 4254 5.3: .. a party MUST send back an SSH_MSG_CHANNEL_CLOSE .. */
            SSH_SESSION_sendCloseChannel(pContextSSH);
            status = OK;

            /* notify upper layer session has been closed */
            pContextSSH->sessionState.isChannelActive  = FALSE;
            pContextSSH->sessionState.channelState     = SESSION_CLOSED;

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
            if (SFTP_SESSION_ESTABLISHED == pContextSSH->sessionState.isShellActive)
            {
                SSH_FTP_closeAllOpenHandles(pContextSSH);
            }
#endif

#ifdef __ENABLE_MOCANA_SSH_SERIAL_CHANNEL__
            if (NULL != SSH_SESSION_CHANNEL_CLOSE_UPCALL)
                status = SSH_SESSION_CHANNEL_CLOSE_UPCALL(CONNECTION_INSTANCE(pContextSSH), SSH_SESSION_CHANNEL_CLOSED, NULL, 0);
#else
            if (NULL != SSH_SESSION_CLOSE_UPCALL)
                status = SSH_SESSION_CLOSE_UPCALL(CONNECTION_INSTANCE(pContextSSH), SSH_SESSION_CLOSED, NULL, 0);
#endif

        }
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
        else if ( OK == ( status = isPfChannelActive( pContextSSH, recipientChannel, &pSession ) ) )
        {

            if (NULL != SSH_PORT_FWD_SESSION_CLOSE_UPCALL)
                status = SSH_PORT_FWD_SESSION_CLOSE_UPCALL(CONNECTION_INSTANCE(pContextSSH),
                                                           SSH_PF_CLOSED,
                                                           NULL,
                                                           0,
                                                           pSession->pfSessionData.recipientChannel );

            /* Send SESSION CLOSE if we haven't sent it yet */
            if ( SESSION_CLOSED != pSession->pfSessionData.channelState )
            {
                sendLpfClose(pContextSSH,pSession);
            }
            /* Close the channel data structure */
            closePfChannel(pContextSSH, pSession->ownChannel);
            status = OK;
        }
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
    }
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleEofSession(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4  recipientChannel;
    MSTATUS status = ERR_SESSION_BAD_PAYLOAD;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    sshPfSession* pSession = NULL;
#endif /* #ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
    if (5 == mesgLen)
    {
        recipientChannel = getUbyte4(pMesg + 1);
        status = ERR_SESSION_NOT_OPEN;

        if ((SSH_CHANNEL_NUMBER == recipientChannel) &&
            (TRUE == pContextSSH->sessionState.isChannelActive))
        {
            status = OK;

            /* notify upper layer the client wishes to end the session */
            pContextSSH->sessionState.isEof = TRUE;

            if (NULL != SSH_SESSION_EOF_UPCALL)
                status = SSH_SESSION_EOF_UPCALL(CONNECTION_INSTANCE(pContextSSH), SSH_SESSION_EOF, NULL, 0);
        }
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
        else if ( OK == ( status = isPfChannelActive( pContextSSH, recipientChannel, &pSession ) ) )
        {

            if (NULL != SSH_PORT_FWD_SESSION_EOF_UPCALL)
                status = SSH_PORT_FWD_SESSION_EOF_UPCALL(CONNECTION_INSTANCE(pContextSSH),
                                                           SSH_PF_EOF,
                                                           NULL,
                                                           0,
                                                           pSession->pfSessionData.recipientChannel );

            if ( TRUE != pSession->pfSessionData.isEof )
            {
                sendLpfEof(pContextSSH,pSession);
                sendLpfClose(pContextSSH,pSession);
            }
            status = OK;
        }
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleIncomingMessage(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4  recipientChannel;
    MSTATUS status = ERR_SESSION_NOT_OPEN;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    sshPfSession* pSession = NULL;
#endif /* #ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

    /* ignore all data messages, if client has eof'd */
    if (TRUE == pContextSSH->sessionState.isEof)
    {
        status = OK;
        goto exit;
    }

    /* process incoming data message */
    recipientChannel = getUbyte4(pMesg + 1);

    if ((SSH_CHANNEL_NUMBER == recipientChannel) &&
        ((FALSE != pContextSSH->sessionState.isShellActive) || (FALSE != pContextSSH->sessionState.isExecActive)) )
    {
        ubyte4 dataLen = getUbyte4(pMesg + 5);
        ubyte* pData   = pMesg + 9;

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
#ifdef __ENABLE_MOCANA_SSH_SCP_SERVER__
#if 0 /* CUSTOM_SCP for future release */
            if (SCP_SESSION_ESTABLISHED == pContextSSH->sessionState.isShellActive)
            {
                if (OK > (status = CUSTOM_SCP_READ(CONNECTION_INSTANCE(pContextSSH), pData, dataLen)))
                    goto exit;

                ackIt = TRUE;
            }
            else
#endif
#endif /* __ENABLE_MOCANA_SSH_SCP_SERVER__ */
#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
            if (SFTP_SESSION_ESTABLISHED == pContextSSH->sessionState.isShellActive)
            {
                if (OK > (status = SSH_FTP_doProtocol(pContextSSH, pData, dataLen)))
                    goto exit;
                if ((MAX_SESSION_WINDOW_SIZE/2) < pContextSSH->sessionState.unAckRecvdData)
                    ackIt = TRUE;
            }
            else
#endif
            {
                if (NULL != SSH_RECEIVE_UPCALL)
                {
                   if (OK > (status = SSH_RECEIVE_UPCALL(CONNECTION_INSTANCE(pContextSSH), SSH_SESSION_DATA, pData, dataLen)))
                       goto exit;
                }
                else
                {
                    ackIt = TRUE;
                }
            }

            if (ackIt)
            {
                status = SSH_SESSION_sendWindowAdjust(pContextSSH, SSH_SESSION_DATA, pContextSSH->sessionState.unAckRecvdData);

                pContextSSH->sessionState.unAckRecvdData = 0;
            }
        }
    }
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    else if ( OK == ( status = isPfChannelActive( pContextSSH, recipientChannel, &pSession ) ) )
    {
        ubyte4 dataLen = getUbyte4(pMesg + 5);
        ubyte* pData   = pMesg + 9;

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
            if ((MAX_SESSION_WINDOW_SIZE - pSession->pfSessionData.unAckRecvdData) < dataLen)
                dataLen = (MAX_SESSION_WINDOW_SIZE - pSession->pfSessionData.unAckRecvdData);

            /* increment un-ack counter */
            pSession->pfSessionData.unAckRecvdData += dataLen;

            /* notify upper layer that message data has been received */
            /* forward the data here */
            if (NULL != SSH_PORT_FWD_RECEIVE_UPCALL)
                if (OK > (status = SSH_PORT_FWD_RECEIVE_UPCALL(CONNECTION_INSTANCE(pContextSSH),
                                                                                   SSH_PF_DATA,
                                                                                   pData,
                                                                                   dataLen,
                                                                                   pSession->pfSessionData.recipientChannel )))
                    goto exit;
        }
    }
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

exit:
    return status;

} /* handleIncomingMessage */


/*------------------------------------------------------------------*/

static MSTATUS
handleIncomingExtendedData(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4  recipientChannel;
    ubyte4  typeCode;
    MSTATUS status = ERR_SESSION_NOT_OPEN;

    /* ignore all data messages, if client has eof'd */
    if (TRUE == pContextSSH->sessionState.isEof)
    {
        status = OK;
        goto exit;
    }

    /* process incoming data message */
    recipientChannel = getUbyte4(pMesg + 1);
    typeCode = getUbyte4(pMesg + 5);

    if ((SSH_EXTENDED_DATA_STDERR == typeCode) &&
        (SSH_CHANNEL_NUMBER == recipientChannel) &&
        (FALSE != pContextSSH->sessionState.isShellActive))
    {
        ubyte4 dataLen = getUbyte4(pMesg + 9);
        ubyte* pData   = pMesg + 13;

        status = ERR_SESSION_BAD_PAYLOAD;

        if (mesgLen == (dataLen + 13))
        {
            /* client governor, ignore data beyond our window */
            if ((MAX_SESSION_WINDOW_SIZE - pContextSSH->sessionState.unAckRecvdData) < dataLen)
                dataLen = (MAX_SESSION_WINDOW_SIZE - pContextSSH->sessionState.unAckRecvdData);

            /* increment un-ack counter */
            pContextSSH->sessionState.unAckRecvdData += dataLen;

            /* notify upper layer that message data has been received */
#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
            if (SFTP_SESSION_ESTABLISHED != pContextSSH->sessionState.isShellActive)
#endif
#ifdef __ENABLE_MOCANA_SSH_SCP_SERVER__
            if (SCP_SESSION_ESTABLISHED != pContextSSH->sessionState.isShellActive)
#endif
                if (NULL != SSH_STDERR_UPCALL)
                    if (OK > (status = SSH_STDERR_UPCALL(CONNECTION_INSTANCE(pContextSSH), SSH_SESSION_STDERR, pData, dataLen)))
                        goto exit;
        }
    }

exit:
    return status;

} /* handleIncomingExtendedData */


/*------------------------------------------------------------------*/

extern sshStringBuffer ssh_scpExec;

#define MIN_CHANNEL_REQUEST_MSG_LEN (1/*type*/+ 4/*recipient channel */ + 4 + 1)
static MSTATUS
handleChannelRequest(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    sbyte4(*callbackFunc)(sbyte4 connectionInstance, enum sshSessionTypes sessionEvent, ubyte *, ubyte4);
    sbyte4 callbackEvent   = -1;
    ubyte* pCallbackData   = NULL;
    ubyte4 callbackDataLen = 0;

    terminalState*      pTerminal = (terminalState *)pContextSSH->pTerminal;
    sshStringBuffer*    pTerminalEnvironment = NULL;
    sshStringBuffer*    pTerminalEncoded     = NULL;
    intBoolean          isReplyRequired;
    intBoolean          isGoodMessage        = FALSE;
    ubyte               payload[5];
    ubyte4              recipientChannel;
    sbyte4              result;
    MSTATUS             status = ERR_SESSION_NOT_OPEN;

    callbackFunc = NULL;
	if (mesgLen < MIN_CHANNEL_REQUEST_MSG_LEN)
    {
        status = ERR_SESSION_BAD_PAYLOAD;
        goto exit;
    }
    recipientChannel = getUbyte4(pMesg + 1);

    if ((SSH_CHANNEL_NUMBER == recipientChannel) &&
        (TRUE == pContextSSH->sessionState.isChannelActive) )
    {
        ubyte4 numBytesWritten;

        if ((mesgLen - (1 + 4 + 4 + 1)) < getUbyte4(pMesg + 5))
        {
            status = ERR_SESSION_BAD_PAYLOAD;
            goto exit;
        }

        isReplyRequired = (0 == pMesg[1 + 4 + 4 + getUbyte4(pMesg + 5)]) ? FALSE : TRUE;

        if (OK > (status = MOC_MEMCMP(pMesg + 5, ssh_terminalType.pString, ssh_terminalType.stringLen, &result)))
            goto exit;

        if (0 == result)
        {
            ubyte4 index;

            /* handle pty-req */
            isGoodMessage = TRUE;

            index = 1 + 4 + ssh_terminalType.stringLen + 1;

            if (OK > (status = SSH_STR_copyStringFromPayload(pMesg, mesgLen, &index, &pTerminalEnvironment)))
                goto exit;

            /* verify message contains terminal settings */
            if (index + 4 > mesgLen)
            {
                status = ERR_SESSION_BAD_PAYLOAD;
                goto exit;
            }

            /* fetch new terminal settings */
            pTerminal->width       = getUbyte4(pMesg + index);
            pTerminal->height      = getUbyte4(pMesg + index + 4);
            pTerminal->pixelWidth  = getUbyte4(pMesg + index + 8);
            pTerminal->pixelHeight = getUbyte4(pMesg + index + 12);

            index += 16;

            if (OK > (status = SSH_STR_copyStringFromPayload(pMesg, mesgLen, &index, &pTerminalEncoded)))
                goto exit;

            if (index != mesgLen)
            {
                status = ERR_SESSION_BAD_PAYLOAD;
                goto exit;
            }

            /* duplicate terminal environment & encoding bytes */
            if (NULL == (pTerminal->pTerminalEnvironment = MALLOC(pTerminalEnvironment->stringLen - 3)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            MOC_MEMCPY((ubyte *)(pTerminal->pTerminalEnvironment), (4 + pTerminalEnvironment->pString), pTerminalEnvironment->stringLen - 4);
            pTerminal->pTerminalEnvironment[pTerminalEnvironment->stringLen - 4] = '\0';
            pTerminal->terminalEnvironmentLength = pTerminalEnvironment->stringLen - 4;

            if (4 < pTerminalEncoded->stringLen)
            {
                if (NULL == (pTerminal->pEncodedTerminalModes = MALLOC(pTerminalEncoded->stringLen - 4)))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                MOC_MEMCPY((ubyte *)pTerminal->pEncodedTerminalModes, 4 + pTerminalEncoded->pString, pTerminalEncoded->stringLen - 4);
                pTerminal->encodedTerminalModes = pTerminalEncoded->stringLen - 4;
            }

            callbackFunc  = SSH_SESSION_PTY_UPCALL;
            callbackEvent = SSH_SESSION_PTY_REQUEST;
        }

        if (OK > (status = MOC_MEMCMP(pMesg + 5, ssh_shellType.pString, ssh_shellType.stringLen, &result)))
            goto exit;

        if (0 == result)
        {
#ifdef __ENABLE_ALL_DEBUGGING__
    DEBUG_PRINTNL(DEBUG_SSH_SERVICE, (sbyte *)("handleChannelRequest: Open State Event."));
#endif
            /* handle shell */
            if ((mesgLen != (1 + 4 + ssh_shellType.stringLen + 1)) ||
                (FALSE != pContextSSH->sessionState.isShellActive))
            {
                status = ERR_SESSION_BAD_PAYLOAD;
                goto exit;
            }

            pContextSSH->sessionState.isShellActive = TRUE;
            isGoodMessage = TRUE;

            callbackFunc  = SSH_SESSION_OPEN_SHELL_UPCALL;
            callbackEvent = SSH_SESSION_OPEN_SHELL;
        }

        if (OK > (status = MOC_MEMCMP(pMesg + 5, ssh_windowChange.pString, ssh_windowChange.stringLen, &result)))
            goto exit;

        if (0 == result)
        {
            /* handle window-change */
            isGoodMessage = TRUE;

            /* verify message contains terminal settings */
            if ((1 + 4 + ssh_windowChange.stringLen + 1 + 16) != mesgLen)
            {
                status = ERR_SESSION_BAD_PAYLOAD;
                goto exit;
            }

            /* fetch new terminal settings */
            pTerminal->width       = getUbyte4(pMesg + 1 + 4 + ssh_windowChange.stringLen + 1);
            pTerminal->height      = getUbyte4(pMesg + 1 + 4 + ssh_windowChange.stringLen + 1 +  4);
            pTerminal->pixelWidth  = getUbyte4(pMesg + 1 + 4 + ssh_windowChange.stringLen + 1 +  8);
            pTerminal->pixelHeight = getUbyte4(pMesg + 1 + 4 + ssh_windowChange.stringLen + 1 + 12);

            callbackFunc  = SSH_SESSION_WINDOW_CHANGE_UPCALL;
            callbackEvent = SSH_SESSION_WINDOW_CHANGE;
        }

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
        /*!!!! disable upcalls when SFTP is enabled */
        if (OK > (status = MOC_MEMCMP(pMesg + 5, ssh_subSystem.pString, ssh_subSystem.stringLen, &result)))
            goto exit;

        if (0 == result)
        {
            /*!!!! look for sftp */
            pContextSSH->sessionState.isShellActive = SFTP_SESSION_ESTABLISHED;

            /* initialize */
            pContextSSH->sftpState                  = SFTP_NOTHING;
            pContextSSH->sftpIncomingBufferSize     = 0;
            pContextSSH->sftpNumBytesInBuffer       = 0;
            pContextSSH->sftpNumBytesRequired       = 0;

            isGoodMessage = TRUE;

            if ((1 + 4 + ssh_subSystem.stringLen + 1 + 8) != mesgLen)
            {
                status = ERR_SESSION_BAD_PAYLOAD;
                goto exit;
            }

            if (OK > (status = MOC_STREAM_open(&(pContextSSH->sessionState.pSftpOutStreamDescr),
                                               (void*)pContextSSH, SFTP_SERVER_STREAM_BUF_SIZE,
                                               (funcStreamWriteData)SSH_SESSION_sendMessage)))
            {
                goto exit;
            }

            callbackFunc  = SSH_SESSION_OPEN_SFTP_UPCALL;
            callbackEvent = SSH_SESSION_OPEN_SFTP;
        }
#endif /* __ENABLE_MOCANA_SSH_FTP_SERVER__ */

        if (OK > (status = MOC_MEMCMP(pMesg + 5, ssh_execRequest.pString, ssh_execRequest.stringLen, &result)))
            goto exit;

        if (0 == result)
        {
#ifdef __ENABLE_MOCANA_SSH_EXEC__
            /* handle break */
            isGoodMessage = TRUE;

            /* verify message contains exec settings */
            if ((1 + 4 + ssh_execRequest.stringLen + 1 + 4) > mesgLen)
            {
                status = ERR_SESSION_BAD_PAYLOAD;
                goto exit;
            }

            callbackDataLen = getUbyte4(pMesg + 1 + 4 + ssh_execRequest.stringLen + 1);

            if ((1 + 4 + ssh_execRequest.stringLen + 1 + 4 + callbackDataLen) != mesgLen)
            {
                status = ERR_SESSION_BAD_PAYLOAD;
                goto exit;
            }

            /* setup for exec command callback */
            callbackFunc    = SSH_SESSION_EXEC_START_UPCALL;
            callbackEvent   = SSH_SESSION_OPEN_EXEC;
            pCallbackData   = pMesg + 1 + 4 + ssh_execRequest.stringLen + 1 + 4;

            if (NULL != callbackFunc)
                pContextSSH->sessionState.isExecActive = TRUE;
#else
            status = ERR_SSH_DISCONNECT_BY_APPLICATION;
            goto exit;
#endif /* __ENABLE_MOCANA_SSH_EXEC__ */
        }

        if (OK > (status = MOC_MEMCMP(pMesg + 5, ssh_breakOperation.pString, ssh_breakOperation.stringLen, &result)))
            goto exit;

        if (0 == result)
        {
            /* handle break */
            isGoodMessage = TRUE;

            /* verify message contains break settings */
            if ((1 + 4 + ssh_breakOperation.stringLen + 1 + 4) != mesgLen)
            {
                status = ERR_SESSION_BAD_PAYLOAD;
                goto exit;
            }

            /* fetch break length in milliseconds */
            pTerminal->breakLength = getUbyte4(pMesg + 1 + 4 + ssh_breakOperation.stringLen + 1);

            callbackFunc  = SSH_SESSION_BREAK_OP_UPCALL;
            callbackEvent = SSH_SESSION_BREAK_OP;
        }

#ifdef __ENABLE_MOCANA_SSH_SCP_SERVER__
#if 0 /* CUSTOM_SCP for future release */
        /* NOTE: This is not original SCP support (RCP over SSH). */
        else
        {
            /* obviously a bad length */
            if (18 < mesgLen)
            {
                /* check for the existance of "exec" */
                if (OK > (status = MOC_MEMCMP((pMesg + 5), ssh_scpExec.pString, ssh_scpExec.stringLen, &result)))
                    goto exit;

                if (0 == result)
                {
                    sbyte4 scpCmdLength;

                    /* verify message length matches expected length */
                    if ((1 + 4 + ssh_scpExec.stringLen + 4) >= mesgLen)
                    {
                        status = ERR_SESSION_BAD_PAYLOAD;
                        goto exit;
                    }

                    scpCmdLength = getUbyte4(pMesg + 1 + 4 + ssh_scpExec.stringLen + 1);

                    if ((1 + 4 + ssh_scpExec.stringLen + 5 + scpCmdLength) != mesgLen)
                    {
                        status = ERR_SESSION_BAD_PAYLOAD;
                        goto exit;
                    }

                    pContextSSH->sessionState.isShellActive = SCP_SESSION_ESTABLISHED;
                    isGoodMessage = TRUE;

                    /* force connection OPEN */
                    status = SSH_INTERNAL_API_setOpenState(CONNECTION_INSTANCE(pContextSSH));

                    if (OK > status)
                        goto exit;

                    status = CUSTOM_SCP_OPEN(SOCKET(pContextSSH), pMesg+5+ssh_scpExec.stringLen + 5, scpCmdLength);

                    if (OK > status)
                        goto exit;
                }
            }
        }
#endif
#endif /* __ENABLE_MOCANA_SSH_SCP_SERVER__ */

        /* only reply, if requested */
        if (FALSE == isReplyRequired)
            goto skip_reply;

        if (TRUE == isGoodMessage)
            payload[0] = SSH_MSG_CHANNEL_SUCCESS;
        else
            payload[0] = SSH_MSG_CHANNEL_FAILURE;

        payload[1] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 24);
        payload[2] = (ubyte)(pContextSSH->sessionState.recipientChannel >> 16);
        payload[3] = (ubyte)(pContextSSH->sessionState.recipientChannel >>  8);
        payload[4] = (ubyte)(pContextSSH->sessionState.recipientChannel);

        if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesWritten)))
            goto exit;

skip_reply:
        /* open shell */
        if (SSH_SESSION_OPEN_SHELL == callbackEvent || SSH_SESSION_OPEN_EXEC == callbackEvent)
            if (OK > (status = SSH_INTERNAL_API_setOpenState(CONNECTION_INSTANCE(pContextSSH))))
                goto exit;

        if ((NULL != callbackFunc) && (-1 != callbackEvent))
            status = (MSTATUS)callbackFunc(CONNECTION_INSTANCE(pContextSSH), callbackEvent, pCallbackData, callbackDataLen);
    }

exit:
    SSH_STR_freeStringBuffer(&pTerminalEnvironment);
    SSH_STR_freeStringBuffer(&pTerminalEncoded);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleGlobalRequestResponse(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen)
{
    MSTATUS status = OK;

    if (SSH_sshSettings()->funcPtrReplyPing)
        status = (MSTATUS)SSH_sshSettings()->funcPtrReplyPing(CONNECTION_INSTANCE(pContextSSH), SSH_SESSION_PING_REPLY, NULL, 0);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_SESSION_receiveMessage(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    MSTATUS status = OK;

    /* while in the connect phase, ignore auth messages */
    if ((SSH2_MSG_USERAUTH_LOW <= *pNewMesg) && (SSH2_MSG_USERAUTH_HIGH >= *pNewMesg))
        goto exit;

    switch (*pNewMesg)
    {
        case SSH_MSG_CHANNEL_CLOSE:
        {
            status = handleCloseSession(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_GLOBAL_REQUEST:
        {
            status = handleGlobalMesgReq(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_CHANNEL_OPEN:
        {
            status = handleChannelOpenReq(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_CHANNEL_WINDOW_ADJUST:
        {
            status = handleWindowAdjust(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_CHANNEL_DATA:
        {
            status = handleIncomingMessage(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
        {
            status = handleIncomingExtendedData(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_CHANNEL_EOF:
        {
            status = handleEofSession(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_CHANNEL_REQUEST:
        {
            status = handleChannelRequest(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_REQUEST_SUCCESS:
        case SSH_MSG_REQUEST_FAILURE:
        {
            /* currently only the "ping" uses these message types */
            status = handleGlobalRequestResponse(pContextSSH, pNewMesg, newMesgLen);
            break;
        }
        case SSH_MSG_KEXINIT:
        {
            SSH_UPPER_STATE(pContextSSH) = kReduxTransAlgorithmExchange;

            if (FALSE == pContextSSH->isReKeyInitiatedByMe)
            {
                if (NULL != SSH_SESSION_REKEY_UPCALL) // Callback Invoke
                {
                  if (OK > (status = SSH_SESSION_REKEY_UPCALL(CONNECTION_INSTANCE(pContextSSH), TRUE /* Initiated By Remote */)))
                    break; // Callback returned Error
                }
                /* we only send our algorithm list, if they initiated the rekey */
                if (OK > (status = SSH_TRANS_sendServerAlgorithms(pContextSSH)))
                    break;

                pContextSSH->isReKeyOccuring = TRUE;
            }
            else
            {
                /* at this point, we no longer care, so we reset for next time around */
                pContextSSH->isReKeyInitiatedByMe = FALSE;
                if (NULL != SSH_SESSION_REKEY_UPCALL) // Callback Invoke
                {
                  SSH_SESSION_REKEY_UPCALL(CONNECTION_INSTANCE(pContextSSH), FALSE /* Initiated By local */);
                }
            }

            status = SSH_TRANS_doProtocol(pContextSSH, pNewMesg, newMesgLen);   /* !!! verify */
            break;
        }
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
        {
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
            status = handleChannelOpenConfirmation(pContextSSH, pNewMesg, newMesgLen);
            break;
#endif
        }
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

            status = SSH_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesSent);

            break;
        }
    }

exit:
    return status;

} /* SSH_SESSION_receiveMessage */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
extern MSTATUS
SSH_SESSION_forwardMessage(sshContext *pContextSSH, ubyte *pMesg,
                           ubyte4 mesgLen, ubyte4 *pBytesSent,
                           sshPfSession*  pPfSession)
{
    ubyte*  pMessage = NULL;
    ubyte4  numBytesToWrite;
    ubyte4  numBytesWritten;
    ubyte4  recipientChannel;
    MSTATUS status = OK;

    *pBytesSent = 0;

    /* nothing to send */
    if (0 == mesgLen)
        goto exit;

    /* make sure session is open, before sending data to client */
    if ((FALSE          == pPfSession->pfSessionData.isShellActive) ||
        (SESSION_CLOSED == pPfSession->pfSessionData.channelState))
    {
        status = ERR_SESSION_NOT_OPEN;
        goto exit;
    }

    if (NULL == (pMessage = MALLOC(mesgLen + 9)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* send as much data as client window is able to handle */
    if (mesgLen > pPfSession->pfSessionData.windowSize)
        mesgLen = pPfSession->pfSessionData.windowSize;

    recipientChannel = pPfSession->pfSessionData.recipientChannel;

    /* write the message out in chunks */
    while (0 < mesgLen)
    {
        if (OK > (status = (SSH_OUT_MESG_sendMessageSize(pContextSSH, mesgLen + 9,
                                                         &numBytesToWrite))))
        {
            goto exit;
        }

        /* the protocol governor */
        if (numBytesToWrite > pPfSession->pfSessionData.maxPacketSize)
            numBytesToWrite = pPfSession->pfSessionData.maxPacketSize;

        /* subtract message header */
        numBytesToWrite -= 9;

        pMessage[0] = SSH_MSG_CHANNEL_DATA;

        pMessage[1] = (ubyte)((recipientChannel) >> 24);
        pMessage[2] = (ubyte)((recipientChannel) >> 16);
        pMessage[3] = (ubyte)((recipientChannel) >>  8);
        pMessage[4] = (ubyte)((recipientChannel));

        pMessage[5] = (ubyte)(numBytesToWrite >> 24);
        pMessage[6] = (ubyte)(numBytesToWrite >> 16);
        pMessage[7] = (ubyte)(numBytesToWrite >>  8);
        pMessage[8] = (ubyte)(numBytesToWrite);

        MOC_MEMCPY(pMessage + 9, pMesg, numBytesToWrite);

        if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, pMessage,
                                                    numBytesToWrite + 9, &numBytesWritten)))
        {
            goto exit;
        }

        pMesg       += numBytesToWrite;
        mesgLen     -= numBytesToWrite;
        *pBytesSent += numBytesToWrite;
        pPfSession->pfSessionData.windowSize -= numBytesToWrite;
    }

exit:
    if (NULL != pMessage)
        FREE(pMessage);

    return status;

} /* SSH_SESSION_forwardMessage */
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_SESSION_sendMessage(sshContext *pContextSSH, ubyte *pMesg,
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
    if (((FALSE == pContextSSH->sessionState.isShellActive) && (FALSE == pContextSSH->sessionState.isExecActive)) ||
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

    /* send as much data as client window is able to handle */
    if (mesgLen > pContextSSH->sessionState.windowSize)
        mesgLen = pContextSSH->sessionState.windowSize;

    if (NULL == (pMessage = MALLOC(mesgLen + 9)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* write the message out in chunks */
    while (0 < mesgLen)
    {
        if (OK > (status = (SSH_OUT_MESG_sendMessageSize(pContextSSH, mesgLen + 9,
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

        if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, pMessage,
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

} /* SSH_SESSION_sendMessage */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_PING__
extern MSTATUS
SSH_SESSION_sendPingMessage(sshContext *pContextSSH)
{
    ubyte*  pMessage = NULL;
    ubyte*  pTemp;
    ubyte4  numBytesWritten;
    MSTATUS status = OK;

    if (NULL == (pMessage = MALLOC(1 + ssh_pingChannel.stringLen + 1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pTemp = pMessage;

    *pTemp = SSH_MSG_GLOBAL_REQUEST;  pTemp++;

    MOC_MEMCPY(pTemp, ssh_pingChannel.pString, ssh_pingChannel.stringLen);
    pTemp = pTemp + ssh_pingChannel.stringLen;

    /* want reply == yes */
    *pTemp = 0x01;

    if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, pMessage,
                                                ssh_pingChannel.stringLen + 2, &numBytesWritten)))
    {
        goto exit;
    }

exit:
    if (NULL != pMessage)
        FREE(pMessage);

    return status;

} /* SSH_SESSION_sendPingMessage */
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_SESSION_sendStdErrMessage(sshContext *pContextSSH, ubyte *pMesg,
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
        if (OK > (status = (SSH_OUT_MESG_sendMessageSize(pContextSSH, mesgLen + 13,
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

        if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, pMessage,
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

} /* SSH_SESSION_sendStdErrMessage */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
static MSTATUS sendLpfEof(sshContext *pContextSSH, sshPfSession*  pPfSession)
{
    ubyte   payload[5];
    ubyte4  numBytesWritten;
    ubyte4  recipientChannel;
    MSTATUS status = OK;

    /* make sure session is open, before sending a session close */
    if ((FALSE           == pPfSession->pfSessionData.isEof ) &&
        (SESSION_CLOSED  != pPfSession->pfSessionData.channelState ))
    {
        recipientChannel = pPfSession->pfSessionData.recipientChannel;

        pPfSession->pfSessionData.isEof = TRUE;

        payload[0] = SSH_MSG_CHANNEL_EOF;
        payload[1] = (ubyte)(recipientChannel >> 24);
        payload[2] = (ubyte)(recipientChannel >> 16);
        payload[3] = (ubyte)(recipientChannel >>  8);
        payload[4] = (ubyte)(recipientChannel);

        if (OK > SSH_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesWritten))
            goto exit;
    }
    else
    {
        status = ERR_SESSION_NOT_OPEN;
    }
exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS sendLpfClose(sshContext *pContextSSH, sshPfSession*  pPfSession)
{
    ubyte   payload[5];
    ubyte4  numBytesWritten;
    ubyte4  recipientChannel;
    MSTATUS status = OK;

    /* make sure session is open, before sending a session close */
    if (SESSION_CLOSED != pPfSession->pfSessionData.channelState)
    {
        recipientChannel = pPfSession->pfSessionData.recipientChannel;

        pPfSession->pfSessionData.channelState = SESSION_CLOSED;

        payload[0] = SSH_MSG_CHANNEL_CLOSE;
        payload[1] = (ubyte)(recipientChannel >> 24);
        payload[2] = (ubyte)(recipientChannel >> 16);
        payload[3] = (ubyte)(recipientChannel >>  8);
        payload[4] = (ubyte)(recipientChannel);

        if (OK > SSH_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesWritten))
            goto exit;
    }
    else
    {
        status = ERR_SESSION_NOT_OPEN;
    }
exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS SSH_SESSION_lpfSendClose(sshContext *pContextSSH, sshPfSession*  pPfSession)
{
    MSTATUS status = OK;

    if ( OK > ( status = sendLpfEof( pContextSSH, pPfSession ) ) )
        goto exit;

    if ( OK > ( status = sendLpfClose( pContextSSH, pPfSession ) ) )
        goto exit;

exit:
    return status;
}
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

extern MSTATUS SSH_SESSION_sendCloseChannel(sshContext *pContextSSH)
{
    ubyte   payload[5];
    ubyte4  numBytesWritten;
    ubyte4  recipientChannel;
    MSTATUS status = OK;

    /* make sure session is open, before sending a session close */
    if ((TRUE           == pContextSSH->sessionState.isChannelActive) &&
        (SESSION_CLOSED != pContextSSH->sessionState.channelState))
    {
        recipientChannel = pContextSSH->sessionState.recipientChannel;

        payload[0] = SSH_MSG_CHANNEL_EOF;
        payload[1] = (ubyte)(recipientChannel >> 24);
        payload[2] = (ubyte)(recipientChannel >> 16);
        payload[3] = (ubyte)(recipientChannel >>  8);
        payload[4] = (ubyte)(recipientChannel);

        if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesWritten)))
            goto exit;

        payload[0] = SSH_MSG_CHANNEL_CLOSE;
        payload[1] = (ubyte)(recipientChannel >> 24);
        payload[2] = (ubyte)(recipientChannel >> 16);
        payload[3] = (ubyte)(recipientChannel >>  8);
        payload[4] = (ubyte)(recipientChannel);

        status = SSH_OUT_MESG_sendMessage(pContextSSH, payload, 5, &numBytesWritten);

        MOC_MEMSET(pContextSSH->sshKeyExCtx.pBytesSharedSecret, 0x00, pContextSSH->sshKeyExCtx.bytesSharedSecretLen);
        MOC_FREE((void**)&(pContextSSH->sshKeyExCtx.pBytesSharedSecret));
        pContextSSH->sshKeyExCtx.bytesSharedSecretLen = 0;
        
    }

exit:
#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_SSH_SERVICE, (sbyte*)"SSH_SESSION_sendCloseChannel: SSH_OUT_MESG_sendMessage failed. status: ", status);
    }
#endif
    return status;
}

/*------------------------------------------------------------------*/

extern void
SSH_SESSION_sendClose(sshContext *pContextSSH, MSTATUS errorCode)
{
    MSTATUS status;
    intBoolean wasAlreadyClosed = (SESSION_CLOSED == pContextSSH->sessionState.channelState);

    status = SSH_SESSION_sendCloseChannel(pContextSSH);
    /* so we know that the session is really closed */
    pContextSSH->sessionState.channelState = SESSION_CLOSED;

    if (OK == status)
    {
        /* Don't send disconnect message if client already closed the channel,
         * or for client-initiated EOF and timeouts to prevent TCP RST */
        if ((TRUE == wasAlreadyClosed)
              || (TRUE == pContextSSH->sessionState.isEof)
#ifdef __ENABLE_MOCANA_SSH_MAX_SESSION_TIME_LIMIT__
              || (ERR_SSH_MAX_SESSION_TIME_LIMIT_EXCEEDED == pContextSSH->errorCode)
#endif
        )
        {
            /* Client initiated the close or timeout - skip disconnect to avoid TCP RST */
            MOC_MEMSET(pContextSSH->sshKeyExCtx.pBytesSharedSecret, 0x00, pContextSSH->sshKeyExCtx.bytesSharedSecretLen);
            MOC_FREE((void**)&(pContextSSH->sshKeyExCtx.pBytesSharedSecret));
            pContextSSH->sshKeyExCtx.bytesSharedSecretLen = 0;
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_DH_freeDhContext(&(pContextSSH->sshKeyExCtx.p_dhContext), NULL);
#else
            DH_freeDhContext(&(pContextSSH->sshKeyExCtx.p_dhContext), NULL);
#endif
        }
        else
        {
            if (OK != errorCode)
            {
                /* Send disconnect for server-initiated closes */
                SSH_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_BY_APPLICATION);
            }
        }
    }
}

#endif /* __ENABLE_MOCANA_SSH_SERVER__ */

