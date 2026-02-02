/*
 * win32_tcp.c
 *
 * Win32 TCP Abstraction Layer
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

#if defined(__ENABLE_DIGICERT_WIN_STUDIO_BUILD__)
#include <winsock2.h>
#include <Ws2tcpip.h>
#endif
#include "../common/moptions.h"

#ifdef __WIN32_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/moc_net.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#ifdef CR
#undef CR
#endif

#include <stdio.h>
#include <winsock2.h>
#include <Ws2tcpip.h>


static int gIsTcpInit = 0;


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_init()
{
    if (0 == gIsTcpInit)
    {
        /* only initialize winsock once at startup */
        WSADATA wsaData;
        int res = WSAStartup( 0x0101, &wsaData);

        gIsTcpInit = 1;

        if (res != 0)
        {
            return ERR_TCP_INIT_FAIL;
        }
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_shutdown()
{
    if (gIsTcpInit)
    {
        WSACleanup();
        gIsTcpInit = 0;
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    TCP_SOCKET           newSocket;
    int                  nRet;
    ADDRINFO             Hints, *AddrInfo;
    char                 Port[10];
    int                  RetVal;

    WIN32_TCP_init();
    newSocket = (TCP_SOCKET)socket(M_AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (newSocket == INVALID_SOCKET)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"Could not create listen socket");
        return ERR_TCP_LISTEN_SOCKET_ERROR;
    }

    memset(&Hints, 0, sizeof (Hints));

    Hints.ai_family = M_AF_INET;
    Hints.ai_socktype = SOCK_STREAM;
    Hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

    _itoa(portNumber, Port, 10);

    /*passing null should default to local loopback */
    RetVal = getaddrinfo(NULL, Port, &Hints, &AddrInfo);
    if (RetVal != 0) {
        DEBUG_ERROR(DEBUG_PLATFORM, "getaddrinfo failed with error %d ",
                RetVal);
        WIN32_TCP_shutdown();
        return ERR_TCP_LISTEN_ADDRINFO;
    }

    nRet = bind(newSocket, AddrInfo->ai_addr, (int) AddrInfo->ai_addrlen);
    if (nRet == SOCKET_ERROR)
    {
        int lastErr = WSAGetLastError();
        closesocket(newSocket);
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"bind() error : ", lastErr);
        return ERR_TCP_LISTEN_BIND_ERROR;
    }

    nRet = listen(newSocket, SOMAXCONN);
    if (nRet == SOCKET_ERROR)
    {
        int lastErr = WSAGetLastError();
        closesocket(newSocket);
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"listen() error: ", lastErr);
        return ERR_TCP_LISTEN_ERROR;
    }

    *listenSocket = newSocket;
    freeaddrinfo(AddrInfo);
    return OK;
}


/*------------------------------------------------------------------*/

/**
 * This function restricts the listen socket to only accept connections
 * from the 'localhost' address.
 */
extern MSTATUS
WIN32_TCP_listenSocketLocal(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    TCP_SOCKET           newSocket;
    int                  nRet;
    ADDRINFO             Hints, *AddrInfo;
    char                 Port[10];
    int                  RetVal;

    WIN32_TCP_init();
    newSocket = (TCP_SOCKET)socket(M_AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (newSocket == INVALID_SOCKET)
    {
        return ERR_TCP_LISTEN_SOCKET_ERROR;
    }

    memset(&Hints, 0, sizeof (Hints));

    Hints.ai_family = M_AF_INET;
    Hints.ai_socktype = SOCK_STREAM;
    Hints.ai_flags = AI_NUMERICHOST;

    _itoa(portNumber, Port, 10);

    RetVal = getaddrinfo(NULL, Port, &Hints, &AddrInfo);
    if (RetVal != 0) {
        WIN32_TCP_shutdown();
        return ERR_TCP_LISTEN_ADDRINFO;
    }

    nRet = bind(newSocket, AddrInfo->ai_addr, (int) AddrInfo->ai_addrlen);
    if (nRet == SOCKET_ERROR)
    {
        int lastErr = WSAGetLastError();
        closesocket(newSocket);
        return ERR_TCP_LISTEN_BIND_ERROR;
    }

    nRet = listen(newSocket, SOMAXCONN);
    if (nRet == SOCKET_ERROR)
    {
        int lastErr = WSAGetLastError();
        closesocket(newSocket);
        return ERR_TCP_LISTEN_ERROR;
    }

    *listenSocket = newSocket;
    freeaddrinfo(AddrInfo);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket,
                       intBoolean *isBreakSignalRequest)
{
    fd_set*              pSocketList = NULL;
    struct timeval       timeout;
    int                  nLen = sizeof(SOCKADDR_STORAGE);
    SOCKADDR_STORAGE     sockAddr;
    TCP_SOCKET           newClientSocket = INVALID_SOCKET;
    MSTATUS              status = OK;

    if (NULL == (pSocketList = (fd_set *) MALLOC(sizeof(fd_set))))
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

        newClientSocket = (TCP_SOCKET)accept(listenSocket, (LPSOCKADDR)&sockAddr, &nLen);
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
WIN32_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{

    MSTATUS              status = OK;

    ADDRINFO             Hints, *AddrInfo;
    char                 c_port[16];
    int                  RetVal;

    WIN32_TCP_init();
    *pConnectSocket = (TCP_SOCKET)socket(M_AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (INVALID_SOCKET == *pConnectSocket)
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }

    memset(&Hints, 0, sizeof (Hints));

    Hints.ai_family = M_AF_INET;
    Hints.ai_socktype = SOCK_STREAM;
    Hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

    sprintf(c_port, "%d", portNo);

    RetVal = getaddrinfo((char *)pIpAddress, c_port, &Hints,  &AddrInfo);
    if (RetVal != 0) {
        DEBUG_ERROR(DEBUG_PLATFORM, "getaddrinfo failed with error %d ",
                    RetVal);
        WIN32_TCP_shutdown();
        return ERR_TCP_CONNECT_ERROR;
    }

    SETSCOPE( (*(struct sockaddr_in6 *)(AddrInfo->ai_addr)),SCOPEID )

    if (connect(*pConnectSocket, AddrInfo->ai_addr, (int) AddrInfo->ai_addrlen))
    {
        status = ERR_TCP_CONNECT_ERROR;
        goto exit;
    }
    freeaddrinfo(AddrInfo);
exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_closeSocket(TCP_SOCKET socket)
{
    closesocket(socket);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead,
                              ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    fd_set*         pSocketList = NULL;
    struct timeval  timeout;
    int             retValue;
    MSTATUS         status;
    int                err;

    if ((NULL == pBuffer) || (NULL == pNumBytesRead))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (TCP_NO_TIMEOUT != msTimeout)
    {
        /* handle timeout case */
        if (NULL == (pSocketList = (fd_set *) MALLOC(sizeof(fd_set))))
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

    retValue = recv((SOCKET)socket, (char *)pBuffer, maxBytesToRead, 0);

    if (SOCKET_ERROR == retValue)
    {
        if (WSAEWOULDBLOCK != (err = WSAGetLastError()) )
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

} /* WIN32_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
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
WIN32_TCP_getPeerName(TCP_SOCKET socket, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr)
{
    SOCKADDR_STORAGE        myAddress = { 0 };
    sbyte4                  addrLen = sizeof(myAddress);
    MSTATUS                 status = OK;

    if (0 > getpeername(socket, (LPSOCKADDR)&myAddress, &addrLen))
    {
        status = ERR_TCP_GETSOCKNAME;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == myAddress.ss_family)
    {
        pRetAddr->family = AF_INET6;
        *pRetPortNo = htons(((struct sockaddr_in6 *)&myAddress)->sin6_port);
        DIGI_MEMCPY((ubyte *) pRetAddr->uin.addr6,
                   ((struct sockaddr_in6 *)&myAddress)->sin6_addr.s6_addr, 16);
    }
    else
    {
        pRetAddr->family = AF_INET;
        *pRetPortNo = htons(((struct sockaddr_in *)&myAddress)->sin_port);
        pRetAddr->uin.addr = htonl(((struct sockaddr_in *)&myAddress)->
                                                            sin_addr.s_addr);
    }
#else
    *pRetPortNo = htons(((struct sockaddr_in *)&myAddress)->sin_port);
    *pRetAddr = htonl(((struct sockaddr_in *)&myAddress)->sin_addr.s_addr);
#endif

exit:
    return status;
}


#endif /* __WIN32_TCP__ */
