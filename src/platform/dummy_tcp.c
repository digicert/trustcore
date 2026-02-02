/*
 * dummy_tcp.c
 *
 * Dummy TCP Abstraction Layer
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

#ifdef __DUMMY_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/moc_net.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

/*------------------------------------------------------------------*/

static void
ignoreSignal(int ignoreParam)
{
    return;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_TCP_init()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_TCP_closeSocket(TCP_SOCKET socket)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer,
                     ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                      ubyte4 *pNumBytesWritten)
{
    return OK;
}

#endif /* __DUMMY_TCP__ */
