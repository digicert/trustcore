/*
 * ssh_server.h
 *
 * SSH Server Header
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

#ifndef __SSH_SERVER_HEADER__
#define __SSH_SERVER_HEADER__

#define CONNECT_CLOSING         -1
#define CONNECT_DISABLED        0
#define CONNECT_CLOSED          1
#define CONNECT_NEGOTIATE       2
#define CONNECT_OPEN            3


/*------------------------------------------------------------------*/

typedef struct
{
    sbyte4          instance;
    sshContext*     pContextSSH;
    sbyte4          connectionState;

    sbyte4          isSocketClosed;
    TCP_SOCKET      socket;

#ifndef __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__
    /* non-blocking read data buffers */
    ubyte*          pReadBuffer;
    ubyte*          pReadBufferPosition;
    ubyte4          numBytesRead;

    /* synchronous simulation upcall handler data */
    circBufDescr*   pCircBufDescr;

#ifdef __ENABLE_DIGICERT_SSH_STREAM_API__
    ubyte4          lenStream;
    sbyte4          mesgType;
#endif

#endif

} sshConnectDescr;


/*------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__
#ifdef __USE_DIGICERT_SSH_SERVER__
MOC_EXTERN MSTATUS  SSH_SERVER_start(void);
MOC_EXTERN void     SSH_SERVER_stop(void);
MOC_EXTERN void     SSH_SERVER_disconnectClients(void);
MOC_EXTERN void     SSH_SERVER_releaseMutex(void);

#endif /* __USE_DIGICERT_SSH_SERVER__ */
#endif /* __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__ */

#endif /* __SSH_SERVER_HEADER__ */

