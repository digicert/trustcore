/*
 * sshc_session.h
 *
 * SSH Developer API
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

#ifndef __SSHC_SESSION_HEADER__
#define __SSHC_SESSION_HEADER__

#define MAX_SSHC_SESSION_WINDOW_SIZE        MAX_SESSION_WINDOW_SIZE

#define SSHC_SHELL_SESSION_ESTABLISHED      (1)
#define SSHC_SFTP_SESSION_ESTABLISHED       (2)


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN sbyte4 SSHC_SESSION_OpenSessionChannel(sbyte4 connectionInstance);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN sbyte4 SSHC_SESSION_CloseSessionChannel(sbyte4 connectionInstance);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN sbyte4 SSHC_SESSION_SendSubsystemSFTPChannelRequest(sbyte4 connectionInstance);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN sbyte4 SSHC_SESSION_sendPtyOpenRequest(sbyte4 connectionInstance);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN sbyte4 SSHC_SESSION_sendShellOpenRequest(sbyte4 connectionInstance);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN void SSHC_SESSION_Close(sshcConnectDescr* pDescr);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_SESSION_sendMessage(sshClientContext *pContextSSH, ubyte *pMesg, ubyte4 mesgLen, ubyte4 *pBytesSent);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_SESSION_receiveMessage(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_SESSION_sendWindowAdjust(sshClientContext *pContextSSH, ubyte mesgType, ubyte4 numBytesToAck);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_SESSION_sendWindowChangeChannelRequest(sshClientContext *pContextSSH, ubyte4 width, ubyte4 height);

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_SESSION_createLocalPortFwdSession(sshcConnectDescr* pDescr, sbyte4* pChannel);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_SESSION_startPortFwdSession(sshcConnectDescr* pDescr, sbyte4  channel,
                                                ubyte* pConnectHost, ubyte4 connectPort,
                                                ubyte* pSrc, ubyte4 srcPort);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_SESSION_sendLocalPortFwdMessage(sshcConnectDescr* pDescr, ubyte4 channel,
                                                    ubyte *pMesg, ubyte4 mesgLen, ubyte4 *pBytesSent);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_SESSION_sendLocalPortFwdClose(sshcConnectDescr* pDescr, ubyte4 channel);

/**
 * @dont_show
 * @internal
 */
extern MSTATUS sendRpfStart( sshClientContext* pContextSSH,  ubyte* pBindHost, ubyte4 bindPort);

/**
 * @dont_show
 * @internal
 */
extern MSTATUS sendCancelRpfReq( sshClientContext* pContextSSH,  ubyte* pBindHost, ubyte4 bindPort, ubyte* pHostAddr, ubyte4 hostPort);

#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

#endif /* __SSHC_SESSION_HEADER__ */
