/*
 * deos_tcp.c
 *
 * DDC-I DEOS TCP Abstraction Layer
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

#ifdef __DEOS_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <deos.h>
#include <timeout.h>
#include <socketapi.h>
#include <lwip-socket.h>


static clientConnectionHandleType gTcpConnHandle;

/* define the following macros according to MTL configuration */
/* note: setupTCPTransport needs to be called from the same thread
 * where the connection is being handled
 */
#define DEOS_TCP_CONFIG_FILE    "mailbox-transport.config"
#define DEOS_TCP_CONFIG_ID      "transportConfigurationId"
#define DEOS_TCP_CONN_ID        "tcpConnectionId"
#define MAX_CONN_ALLOWED        1


/*------------------------------------------------------------------*/

static int
setupTCPTransport(clientConnectionHandleType *connectionHandle, char* connectionId)
{
    int setupStatus, setupError;
    void * sendBuffer;
    DWORD bufferSizeInBytes;

    setupStatus = socketTransportInitialize(DEOS_TCP_CONFIG_FILE,
                    DEOS_TCP_CONFIG_ID, (DWORD)waitIndefinitely, &setupError);
    if (setupStatus != transportSuccess)
        goto exit;

    setupStatus = socketTransportClientInitialize((DWORD)waitIndefinitely, &setupError);
    if (setupStatus != transportSuccess)
        goto exit;

    setupStatus = socketTransportCreateConnection(connectionId,
                     (DWORD)waitIndefinitely, COMPATIBILITY_ID_2, connectionHandle,
                     &sendBuffer, &bufferSizeInBytes, &setupError);
    if (setupStatus != transportSuccess)
        goto exit;

    setupStatus = socketTransportSetConnectionForThread(currentThreadHandle(),
                    *connectionHandle, (DWORD)waitIndefinitely, &setupError);

exit:
    return setupStatus;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_TCP_init()
{
#ifdef DEOS_TCP_CONFIG_FILE
    if (transportSuccess != setupTCPTransport(&gTcpConnHandle, DEOS_TCP_CONN_ID))
    {
        return ERR_TCP;
    }
#endif

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct sockaddr_in  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    int                 one     = 1;
    MSTATUS             status  = OK;

    newSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (0 > newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "DEOS_TCP_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct sockaddr_in));

    saServer.sin_family         = AF_INET;
    saServer.sin_port           = htons(portNumber);
    saServer.sin_addr           = INADDR_ANY;

    nRet = bind(newSocket, (struct sockaddr*)&saServer, sizeof(struct sockaddr));
    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "DEOS_TCP_listenSocket: bind() error : ", nRet);
        DEBUG_ERROR(DEBUG_PLATFORM, "DEOS_TCP_listenSocket: bind() socket : ", newSocket);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = listen(newSocket, MAX_CONN_ALLOWED);
    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "DEOS_TCP_listenSocket: listen() error: ", nRet);
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
DEOS_TCP_acceptSocket(TCP_SOCKET *clientSocket,
                      TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    fd_set              socketList;
    struct timeval      timeout;
    struct sockaddr_in  sockAddr;
    unsigned int        nLen = sizeof(struct sockaddr_in);
    TCP_SOCKET          newClientSocket;
    MSTATUS             status = OK;

    while (1)
    {
        /* add the socket of interest to the list */
        FD_ZERO(&socketList);
        FD_SET(listenSocket, &socketList);

        /* poll every second to check break signal */
        timeout.tv_sec  = 1;
        timeout.tv_usec = 0;

        if (0 == select(FD_SETSIZE, &socketList, NULL, NULL, &timeout))
        {
            /* time out occurred, check for break signal */
            if (TRUE == *isBreakSignalRequest)
                goto exit;

            continue;
        }

        newClientSocket = accept(listenSocket, (struct sockaddr*)&sockAddr, &nLen);
        break;
    }

    if (0 > newClientSocket)
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
DEOS_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
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
    server.sin_addr = inet_addr((char*)pIpAddress);

    if (0 != connect(*pConnectSocket, (struct sockaddr *)&server, sizeof(server)))
        status = ERR_TCP_CONNECT_ERROR;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_TCP_closeSocket(TCP_SOCKET socket)
{
    closesocket(socket);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer,
                     ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    fd_set          socketList;
    struct timeval  timeout;
    int             retValue;
    MSTATUS         status;

    if ((NULL == pBuffer) || (NULL == pNumBytesRead))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }


    if (TCP_NO_TIMEOUT != msTimeout)
    {
        /* handle timeout case */

        /* add the socket of interest to the list */
        FD_ZERO(&socketList);
        FD_SET(socket, &socketList);

        /* compute timeout (milliseconds) */
        timeout.tv_sec  = msTimeout / 1000;
        timeout.tv_usec = (msTimeout % 1000) * 1000;    /* convert ms to us */

        /* Note: Windows ignores the first parameter '1' */
        /* other platforms may want (highest socket + 1) */

        /*  The first argument to select is the highest file
            descriptor value plus 1. In most cases, you can
            just pass FD_SETSIZE and you'll be fine. */

        if (0 == select(FD_SETSIZE, &socketList, NULL, NULL, &timeout))
        {
            status = ERR_TCP_READ_TIMEOUT;
            goto exit;
        }
    }


    *pNumBytesRead = 0;

    retValue = recv(socket, pBuffer, maxBytesToRead, 0);

    if (retValue < 0)
    {
        status = ERR_TCP_READ_ERROR;
        goto exit;
    }

    if (0 == retValue)
    {
        status = ERR_TCP_SOCKET_CLOSED;
        goto exit;
    }

    *pNumBytesRead = retValue;

    status = OK;

exit:

    return status;

} /* DEOS_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
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
DEOS_TCP_getPeerName(TCP_SOCKET socket, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr)
{
    struct sockaddr_in      myAddress = { 0 };
    socklen_t               addrLen = sizeof(myAddress);
    MSTATUS                 status = OK;

    if (0 > getpeername(socket, (struct sockaddr *)&myAddress, &addrLen))
    {
        status = ERR_TCP_GETSOCKNAME;
        goto exit;
    }

    *pRetPortNo = htons(myAddress.sin_port);
    *pRetAddr = htonl(myAddress.sin_addr);

exit:
    return status;
}

#endif /* __DEOS_TCP__ */
