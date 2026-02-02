/*
 * lwip_tcp.c
 *
 * Lwip TCP Abstraction Layer
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
#include <errno.h>

#include "../common/moptions.h"

#ifdef __LWIP_TCP__

#define _REENTRANT

/*
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
*/
#if 0
#include "../lwip/src/include/lwip/sockets.h"
#endif
#include "lwip/sockets.h"
#include "lwip/netdb.h"
/* ADDED by Rich */

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
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
LWIP_TCP_init()
{
/* ADDED by Rich
    signal(SIGPIPE, ignoreSignal);
    signal(SIGALRM, ignoreSignal);
*/

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LWIP_TCP_shutdown()
{
    /* ADDED by Rich - TODO - figure out how to gracefully shut down */
    /* lwip_shutdown() */
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LWIP_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct sockaddr_in  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    int                 one     = 1;
    MSTATUS             status  = OK;

    newSocket = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (0 > newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "LWIP_TCP_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    /* ADDED by Rich - SO_REUSEADDR is supported if SO_REUSE is defined to 1
     * - check in sockets.c
     */
#if SO_REUSE
    if (0 > lwip_setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)))
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "LWIP_TCP_listenSocket: setsockopt(SO_REUSEADDR) error");
        status = ERR_TCP_SOCKOPT_ERROR;
        goto error_cleanup;
    }
#endif

    DIGI_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct sockaddr_in));

    saServer.sin_family         = AF_INET;
    saServer.sin_port           = htons(portNumber);
    saServer.sin_addr.s_addr    = INADDR_ANY;

    nRet = lwip_bind(newSocket, (struct sockaddr*)&saServer, sizeof(struct sockaddr));
    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "LWIP_TCP_listenSocket: bind() error : ", nRet);
        DEBUG_ERROR(DEBUG_PLATFORM, "LWIP_TCP_listenSocket: bind() socket : ", newSocket);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    /* nRet = lwip_listen(newSocket, SOMAXCONN); */
    /* ADDED by Rich - fix this later  lwip code calls this a backlog - What! */
    nRet = lwip_listen(newSocket, 1);
    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "LWIP_TCP_listenSocket: listen() error: ", nRet);
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }


    *listenSocket = newSocket;
    goto exit;

error_cleanup:
    lwip_close(newSocket);

exit:
    return status;
}

extern MSTATUS
LWIP_TCP_listenSocketLocal(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct sockaddr_in  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    int                 one     = 1;
    MSTATUS             status  = OK;

    newSocket = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (0 > newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "LWIP_TCP_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

/* ADDED by Rich - seems not supported by lwip - check in sockets.c */
#if 0
    if (0 > lwip_setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)))
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "LWIP_TCP_listenSocket: setsockopt(SO_REUSEADDR) error");
        status = ERR_TCP_SOCKOPT_ERROR;
        goto error_cleanup;
    }
#endif

    DIGI_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct sockaddr_in));

    saServer.sin_family         = AF_INET;
    saServer.sin_port           = htons(portNumber);
    saServer.sin_addr.s_addr    = ntohl(INADDR_LOOPBACK);

    nRet = lwip_bind(newSocket, (struct sockaddr*)&saServer, sizeof(struct sockaddr));
    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "LWIP_TCP_listenSocket: bind() error : ", nRet);
        DEBUG_ERROR(DEBUG_PLATFORM, "LWIP_TCP_listenSocket: bind() socket : ", newSocket);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    /* nRet = lwip_listen(newSocket, SOMAXCONN); */
    /* ADDED by Rich - fix this later  lwip code calls this a backlog - What! */
    nRet = lwip_listen(newSocket, 1);
    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "LWIP_TCP_listenSocket: listen() error: ", nRet);
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }


    *listenSocket = newSocket;
    goto exit;

error_cleanup:
    lwip_close(newSocket);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LWIP_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    fd_set*             pSocketList     = NULL;
    struct timeval      timeout;
    struct sockaddr_in  sockAddr;
    unsigned int                 nLen            = sizeof(struct sockaddr_in);
    TCP_SOCKET          newClientSocket;
    MSTATUS             status          = OK;



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

        if (0 == lwip_select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout))
        {
            /* time out occurred, check for break signal */
            if (TRUE == *isBreakSignalRequest)
                goto exit;

            continue;
        }

        newClientSocket = lwip_accept(listenSocket, (struct sockaddr*)&sockAddr, &nLen);
        break;
    }

    if (0 > newClientSocket)
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
LWIP_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    struct sockaddr_in  server;
    MSTATUS             status = OK;

    if (0 > (*pConnectSocket = lwip_socket(AF_INET, SOCK_STREAM, 0)))
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&server, 0x00, sizeof(struct sockaddr_in));

    server.sin_family = AF_INET;
    server.sin_port = htons(portNo);
    inet_pton(AF_INET,(char  *) pIpAddress, &server.sin_addr);

    if (0 != lwip_connect(*pConnectSocket, (struct sockaddr *)&server, sizeof(server)))
        status = ERR_TCP_CONNECT_ERROR;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LWIP_TCP_closeSocket(TCP_SOCKET socket)
{
    lwip_close(socket);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LWIP_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer,
                     ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    fd_set*         pSocketList = NULL;
    struct timeval  timeout;
    int             retValue;
    MSTATUS         status;
    int             attempt = 3;

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

        /*  The first argument to select is the highest file
            descriptor value plus 1. In most cases, you can
            just pass FD_SETSIZE and you'll be fine. */


        if (0 == lwip_select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout))
        {
            status = ERR_TCP_READ_TIMEOUT;
            goto exit;
        }
    }


    *pNumBytesRead = 0;

read_socket:
    retValue = lwip_recv(socket, pBuffer, maxBytesToRead, 0);

    if (retValue < 0)
    {
        status = ERR_TCP_READ_ERROR;
        goto exit;
    }

    if (0 == retValue)
    {
        if (--attempt)
        {
            goto read_socket;
        }
        status = ERR_TCP_SOCKET_CLOSED;
        goto exit;
    }

    *pNumBytesRead = retValue;

    status = OK;

exit:
    if (NULL != pSocketList)
        FREE(pSocketList);

    return status;

} /* LWIP_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
LWIP_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                      ubyte4 *pNumBytesWritten)
{
    int     retValue;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    retValue = lwip_send(socket, (void*)pBuffer, numBytesToWrite, 0);

    if (0 > retValue)
    {
        /* if (EWOULDBLOCK != errno) */
        if (1)
        {
            status = ERR_TCP_WRITE_ERROR;
            goto exit;
        }
    }

    *pNumBytesWritten = retValue;
    status = OK;

exit:

    return status;
}

extern MSTATUS
LWIP_TCP_getHostByName(char *pHost, char *pAddr)
{
    struct addrinfo hints, *pRes = NULL, *pTmp = NULL;
    int errcode;
    char addrStr[20];
    void *pData;
    MSTATUS status = OK;

    if (OK > (status = DIGI_MEMSET((ubyte*)&hints, 0, sizeof (hints))))
    {
        goto exit;
    }
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_PASSIVE;

    errcode = getaddrinfo ((const char *)pHost, NULL, &hints, &pRes);
    if (errcode != 0)
    {
        status = ERR_HTTP;
        DEBUG_ERROR(DEBUG_SCEP_EXAMPLE, "Failed to get addrinfo: ", errcode);
        goto exit;
    }
    pTmp = pRes;
    while (pTmp)
    {
        inet_ntop (pTmp->ai_family, pTmp->ai_addr->sa_data, addrStr, sizeof(addrStr));

        switch (pTmp->ai_family)
        {
            case AF_INET:
                pData = &((struct sockaddr_in *) pTmp->ai_addr)->sin_addr;
                break;
#ifdef __ENABLE_DIGICERT_IPV6__
            case AF_INET6:
                pData = &(((struct sockaddr_in6 *) pTmp->ai_addr)->sin6_addr);
                break;
#endif
        }
        inet_ntop (pTmp->ai_family, pData, addrStr, sizeof(addrStr));
        pTmp = pTmp->ai_next;
    }

    if (OK != (status = DIGI_MEMCPY((ubyte*)pAddr, addrStr, DIGI_STRLEN((const sbyte*)addrStr))))
    {
        goto exit;
    }
    pAddr[DIGI_STRLEN((const sbyte *)addrStr)] = '\0';


exit:
    if (pRes != NULL)
        freeaddrinfo(pRes);
    return status;
}

#endif /* __LWIP_TCP__ */
