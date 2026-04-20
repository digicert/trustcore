/*
 * ssh_session.h
 *
 * SSH Session Header
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

#ifndef __SSH_SESSION_HEADER__
#define __SSH_SESSION_HEADER__

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_SESSION_sendMessage(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen, ubyte4 *pBytesSent);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_SESSION_sendPingMessage(sshContext *pContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_SESSION_sendStdErrMessage(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen, ubyte4 *pBytesSent);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_SESSION_receiveMessage(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_SESSION_sendCloseChannel(sshContext *pContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN void    SSH_SESSION_sendClose(sshContext *pContextSSH, MSTATUS errorCode);

#ifdef __ENABLE_DIGICERT_SSH_PORT_FORWARDING__
/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_SESSION_forwardMessage(sshContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen, ubyte4 *pBytesSent,sshPfSession*  pPfSession);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_SESSION_sendPortFwdOpen(sshContext *pContextSSH, ubyte* pConnectHost, ubyte4 connectPort, ubyte* pSrc,ubyte4 srcPort, ubyte4 *rmyChannel);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_SESSION_lpfSendClose(sshContext *pContextSSH, sshPfSession*  pPfSession);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_SESSION_sendPortFwdWindowAdjust(sshContext *pContextSSH, ubyte mesgType, ubyte4 numBytesToAck, ubyte4 recipientChannel);
#endif /* __ENABLE_DIGICERT_SSH_PORT_FORWARDING__ */

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_SESSION_sendWindowAdjust(sshContext *pContextSSH, ubyte mesgType, ubyte4 numBytesToAck);


#endif /* __SSH_SESSION_HEADER__ */
