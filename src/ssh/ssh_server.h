/*
 * ssh_server.h
 *
 * SSH Server Header
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

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
    /* non-blocking read data buffers */
    ubyte*          pReadBuffer;
    ubyte*          pReadBufferPosition;
    ubyte4          numBytesRead;

    /* synchronous simulation upcall handler data */
    circBufDescr*   pCircBufDescr;

#ifdef __ENABLE_MOCANA_SSH_STREAM_API__
    ubyte4          lenStream;
    sbyte4          mesgType;
#endif

#endif

} sshConnectDescr;


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
#ifdef __USE_MOCANA_SSH_SERVER__
MOC_EXTERN MSTATUS  SSH_SERVER_start(void);
MOC_EXTERN void     SSH_SERVER_stop(void);
MOC_EXTERN void     SSH_SERVER_disconnectClients(void);
MOC_EXTERN void     SSH_SERVER_releaseMutex(void);

#endif /* __USE_MOCANA_SSH_SERVER__ */
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */

#endif /* __SSH_SERVER_HEADER__ */

