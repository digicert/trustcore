/*
 * microchip_bsd_tcp.c
 *
 * Microchip (BSD interface) TCP Abstraction Layer
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

#ifdef __MICROCHIP_BSD_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include "TCPIPConfig.h"

#if (!defined(STACK_USE_BERKELEY_API))
#error Microchip BSD API not enabled
#endif

#include "TCPIP Stack/TCPIP.h"


/*------------------------------------------------------------------*/

extern MSTATUS
MICROCHIP_TCP_init()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MICROCHIP_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MICROCHIP_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct sockaddr_in  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    int                 one     = 1;
    MSTATUS             status  = OK;

    newSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (0 > newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "MICROCHIP_TCP_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    if (0 > setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)))
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "MICROCHIP_TCP_listenSocket: setsockopt(SO_REUSEADDR) error");
        status = ERR_TCP_SOCKOPT_ERROR;
        goto error_cleanup;
    }

    DIGI_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct sockaddr_in));

    saServer.sin_family         = AF_INET;
    saServer.sin_port           = htons(portNumber);
    saServer.sin_addr.s_addr    = INADDR_ANY;

    nRet = bind(newSocket, (struct sockaddr*)&saServer, sizeof(struct sockaddr));
    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "MICROCHIP_TCP_listenSocket: bind() error : ", nRet);
        DEBUG_ERROR(DEBUG_PLATFORM, "MICROCHIP_TCP_listenSocket: bind() socket : ", newSocket);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = listen(newSocket, SOMAXCONN);
    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "MICROCHIP_TCP_listenSocket: listen() error: ", nRet);
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }


    *listenSocket = newSocket;
    goto exit;

error_cleanup:
    closesocket(newSocket);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MICROCHIP_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    struct sockaddr_in  sockAddr;
    unsigned int        nLen            = sizeof(struct sockaddr_in);
    TCP_SOCKET          newClientSocket;
    MSTATUS             status          = OK;

    newClientSocket = accept(listenSocket, (struct sockaddr*)&sockAddr, &nLen);

    if (SOCKET_ERROR == newClientSocket)
    {
        status = ERR_TCP_ACCEPT_ERROR;
        goto exit;
    }

    *clientSocket = newClientSocket;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MICROCHIP_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    struct sockaddr_in  server;
    MSTATUS             status = OK;

    if (0 >= (*pConnectSocket = socket(AF_INET, SOCK_STREAM, 0)))
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&server, 0x00, sizeof(struct sockaddr_in));

    server.sin_family = AF_INET;
    server.sin_port = htons(portNo);
    inet_pton(AF_INET,(char  *) pIpAddress, &server.sin_addr);

    if (0 != connect(*pConnectSocket, (struct sockaddr *)&server, sizeof(server)))
        status = ERR_TCP_CONNECT_ERROR;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MICROCHIP_TCP_closeSocket(TCP_SOCKET socket)
{
    closesocket(socket);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MICROCHIP_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer,
                     ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    int             retValue;
    MSTATUS         status;

    if ((NULL == pBuffer) || (NULL == pNumBytesRead))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pNumBytesRead = 0;

    retValue = recv(socket, pBuffer, maxBytesToRead, 0);

    if (SOCKET_ERROR == retValue)
    {
        status = ERR_TCP_READ_ERROR;
        goto exit;
    }

    *pNumBytesRead = retValue;
    status = OK;

exit:
    return status;

} /* MICROCHIP_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
MICROCHIP_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                      ubyte4 *pNumBytesWritten)
{
    int     retValue;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    retValue = send((TCP_SOCKET)socket, (const char *)pBuffer, numBytesToWrite, 0);

    if (SOCKET_ERROR == retValue)
    {
        status = ERR_TCP_WRITE_ERROR;
        goto exit;
    }

    *pNumBytesWritten = retValue;
    status = OK;

exit:
    return status;
}

#endif /* __MICROCHIP_BSD_TCP__ */
