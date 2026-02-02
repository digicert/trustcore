/*
 * wince_tcp.c
 *
 * WinCE TCP Abstraction Layer
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

#ifdef __WINCE_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <stdio.h>
#include <winsock2.h>
#include <Ws2tcpip.h>


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_TCP_init()
{
    static int init = 0;

    if (0 == init)
    {
        /* only initialize winsock once at startup */
        WSADATA wsaData;
        int res = WSAStartup( 0x0101, &wsaData);

        init = 1;

        if (res != 0)
        {
            return ERR_TCP_INIT_FAIL;
        }
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    SOCKADDR_IN     saServer;
    TCP_SOCKET      newSocket;
    int             nRet;

    newSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (newSocket == INVALID_SOCKET)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "Could not create listen socket");
        return ERR_TCP_LISTEN_SOCKET_ERROR;
    }

    DIGI_MEMSET((ubyte *)&saServer, 0x00, sizeof(saServer));

    saServer.sin_port = htons(portNumber);
    saServer.sin_family = AF_INET;
    saServer.sin_addr.s_addr = INADDR_ANY;

    nRet = bind(newSocket, (LPSOCKADDR)&saServer, sizeof(struct sockaddr));
    if (nRet == SOCKET_ERROR)
    {
        int lastErr = WSAGetLastError();
        closesocket(newSocket);
        DEBUG_ERROR(DEBUG_PLATFORM, "bind() error : ", lastErr);
        return ERR_TCP_LISTEN_BIND_ERROR;
    }

    nRet = listen(newSocket, SOMAXCONN);
    if (nRet == SOCKET_ERROR)
    {
        int lastErr = WSAGetLastError();
        closesocket(newSocket);
        DEBUG_ERROR(DEBUG_PLATFORM, "listen() error: ", lastErr);
        return ERR_TCP_LISTEN_ERROR;
    }

    *listenSocket = newSocket;
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket,
                       intBoolean *isBreakSignalRequest)
{
    fd_set*         pSocketList = NULL;
    struct timeval  timeout;
    int             nLen = sizeof(SOCKADDR_IN);
    SOCKADDR_IN     sockAddr;
    TCP_SOCKET      newClientSocket = INVALID_SOCKET;
    MSTATUS         status = OK;

    if (NULL == (pSocketList = MALLOC(sizeof(fd_set))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    while (1)
    {
        /* add the socket of interest to the list */
        FD_ZERO(pSocketList);
        FD_SET(listenSocket, pSocketList);

        /* poll every second to check break signal */
        timeout.tv_sec  = 1;
        timeout.tv_usec = 0;

        /* Note: Windows ignores the first parameter */
        /* other platforms may want FD_SETSIZE or (highest socket + 1) */
        if (0 == select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout))
        {
            /* time out occurred, check for break signal */
            if (TRUE == *isBreakSignalRequest)
                goto exit;

            continue;
        }

        newClientSocket = accept(listenSocket, (LPSOCKADDR)&sockAddr, &nLen);
        break;
    }

    if (newClientSocket == INVALID_SOCKET)
    {
        status = ERR_TCP_ACCEPT_ERROR;
        goto exit;
    }

    *clientSocket = newClientSocket;

exit:
    if (NULL != pSocketList)
        FREE(pSocketList);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    SOCKADDR_IN server;
    MSTATUS     status = OK;

    *pConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (INVALID_SOCKET == *pConnectSocket)
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&server, 0x00, sizeof(server));

    server.sin_family = AF_INET;
    server.sin_port = htons(portNo);
    server.sin_addr.S_un.S_addr = inet_addr(pIpAddress);

    if (connect(*pConnectSocket, (SOCKADDR*)&server, sizeof(server)))
    {
        status = ERR_TCP_CONNECT_ERROR;
        goto exit;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_TCP_closeSocket(TCP_SOCKET socket)
{
    closesocket(socket);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead,
                              ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    fd_set*         pSocketList = NULL;
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
        if (NULL == (pSocketList = MALLOC(sizeof(fd_set))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* add the socket of interest to the list */
        FD_ZERO(pSocketList);
        FD_SET(socket, pSocketList);

        /* compute timeout (milliseconds) */
        timeout.tv_sec  = msTimeout / 1000;
        timeout.tv_usec = (msTimeout % 1000) * 1000;    /* convert ms to us */

        /* Note: Windows ignores the first parameter '1' */
        /* other platforms may want (highest socket + 1) */
        if (0 == select(1, pSocketList, NULL, NULL, &timeout))
        {
            status = ERR_TCP_READ_TIMEOUT;
            goto exit;
        }
    }

    *pNumBytesRead = 0;

    retValue = recv((SOCKET)socket, pBuffer, maxBytesToRead, 0);

    if (SOCKET_ERROR == retValue)
    {
        if (WSAEWOULDBLOCK != WSAGetLastError())
        {
            status = ERR_TCP_READ_ERROR;
            goto exit;
        }

        /* handles non-blocking socket */
        status = OK;
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
    if (NULL != pSocketList)
        FREE(pSocketList);

    return status;

} /* WINCE_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                      ubyte4 *pNumBytesWritten)
{
#ifdef __TEST_NON_BLOCK_SOCKET__
    static int count = 0;
#endif
    int     retValue;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __TEST_NON_BLOCK_SOCKET__
    count = (count + 1) % 7;

    if (count)
    {
        *pNumBytesWritten = 0;
        status = OK;
        goto exit;
    }

    numBytesToWrite = 1;
#endif

    retValue = send((SOCKET)socket, (const char FAR *)pBuffer, numBytesToWrite, 0);

    if (SOCKET_ERROR == retValue)
    {
        int lastError = WSAGetLastError();
        if (WSAEWOULDBLOCK != lastError)
        {
            status = ERR_TCP_WRITE_ERROR;
            goto exit;
        }

        /* handles non-blocking socket */
        retValue = 0;
    }

    *pNumBytesWritten = retValue;
    status = OK;

exit:

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WINCE_TCP_getPeerName(TCP_SOCKET socket, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr)
{
    struct sockaddr_in      myAddress = { 0 };
    sbyte4                  addrLen = sizeof(myAddress);
    MSTATUS                 status = OK;

    if (0 > getpeername(socket, (struct sockaddr *)&myAddress, &addrLen))
    {
        status = ERR_TCP_GETSOCKNAME;
        goto exit;
    }

    *pRetPortNo = htons(myAddress.sin_port);
#ifdef __ENABLE_DIGICERT_IPV6__
    pRetAddr->family = AF_INET;
    pRetAddr->uin.addr = htonl(myAddress.sin_addr.s_addr);
#else
    *pRetAddr = htonl(myAddress.sin_addr.s_addr);
#endif

exit:
    return status;
}


#endif /* __WINCE_TCP__ */
