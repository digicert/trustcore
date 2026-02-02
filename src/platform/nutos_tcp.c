/*
 * nutos_tcp.c
 *
 * NutOS TCP Abstraction Layer
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

#ifdef __NUTOS_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <cfg/os.h>

#include <string.h>
#include <io.h>
#include <fcntl.h>
#include <netinet/tcp.h>

#include <dev/board.h>
#include <dev/urom.h>
#include <dev/nplmmc.h>
#include <dev/sbimmc.h>
#include <fs/phatfs.h>

#include <sys/version.h>
#include <sys/thread.h>
#include <sys/timer.h>
#include <sys/heap.h>
#include <sys/confnet.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <net/route.h>


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_TCP_init()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

static ubyte2 hackPortForNow;

extern MSTATUS
NUTOS_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    /* no concept of bind/listen */
    *listenSocket = NULL;
    hackPortForNow = portNumber;

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    MSTATUS     status = OK;

    if (NULL == (*clientSocket = NutTcpCreateSocket()))
    {
        status = ERR_TCP_ACCEPT_ERROR;
        goto exit;
    }

    /* hack for now...  need to add another argument */
    if (NutTcpAccept(*clientSocket, hackPortForNow))
        status = ERR_TCP_ACCEPT_ERROR;

exit:
    return status;

} /* NUTOS_TCP_acceptSocket */


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    MSTATUS status = OK;
    /* ubyte2  mss = 1460; */

    if (NULL == (*pConnectSocket = NutTcpCreateSocket()))
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }

    /* NutTcpSetSockOpt(*pConnectSocket, TCP_MAXSEG, &mss, sizeof(mss)); */

    if (NutTcpConnect(*pConnectSocket, inet_addr(pIpAddress), portNo))
        status = ERR_TCP_CONNECT_ERROR;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_TCP_closeSocket(TCP_SOCKET socket)
{
    if (NULL != socket)
        NutTcpCloseSocket(socket);

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer,
                     ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    /* not obvious how to set a timeout for recv */
    int     retValue;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesRead))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pNumBytesRead = 0;

    retValue = NutTcpSetSockOpt(socket, SO_RCVTIMEO, &msTimeout, sizeof(msTimeout));

    if (retValue < 0)
    {
        status = ERR_TCP_SOCKOPT_ERROR;
        goto exit;
    }

    retValue = NutTcpReceive(socket, pBuffer, (u_short)maxBytesToRead);

    if (retValue < 0)
    {
        status = ERR_TCP_READ_ERROR;
        goto exit;
    }

    *pNumBytesRead = retValue;

    status = OK;

exit:
    return status;

} /* NUTOS_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                      ubyte4 *pNumBytesWritten)
{
    int     retValue;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pNumBytesWritten = 0;

    retValue = NutTcpSend((TCP_SOCKET)socket, (const char *)pBuffer, numBytesToWrite);

    if (0 > retValue)
    {
        status = ERR_TCP_WRITE_ERROR;
        goto exit;
    }

    *pNumBytesWritten = retValue;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUTOS_TCP_getPeerName(TCP_SOCKET socket, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr)
{
    /* not obvious how to get the peer's src-address or src-port */
    return ERR_TCP_GETSOCKNAME;
}


#endif /* __NUTOS_TCP__ */
