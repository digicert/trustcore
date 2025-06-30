/*
 * linux_tcp.c
 *
 * Linux TCP Abstraction Layer
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

/* GNU C Library version 2.32 introduced an attribute
 * to tag deprecated functions as warnings. sigignore()
 * has been deprecated and replaced with sigaction(). */
#if !((2 == __GLIBC__) && (32 <= __GLIBC_MINOR__) || \
     (3 <= __GLIBC__))
#define _XOPEN_SOURCE 500  /* for sigignore().  man feature_test_macros(7) */
#endif

#include "../common/moptions.h"

#ifdef __LINUX_TCP__

/* prevent duplicate symbols if compiling concurrently with LWIP */
#undef __LWIP_STACK__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/moc_net.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <linux/net.h>
#include <fcntl.h>

/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_TCP_init()
{
#ifndef __RTOS_ANDROID__
#if ((2 == __GLIBC__) && (32 <= __GLIBC_MINOR__) || \
     (3 <= __GLIBC__))
    struct sigaction act = {0};
    /* sa_handler specifies the action to be associated with signum
     * set value to SIG_IGN to ignore signal */
    act.sa_handler = SIG_IGN;

    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGPIPE, &act, NULL);
    sigaction(SIGALRM, &act, NULL);
#else
    sigignore(SIGHUP);
    sigignore(SIGINT);
    sigignore(SIGPIPE);
    sigignore(SIGALRM);
#endif
#endif
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct SOCKADDR_IN  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    int                 one     = 1;
    MSTATUS             status  = OK;

    newSocket = socket(M_AF_INET, SOCK_STREAM, 0);
    if (0 > newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    if (0 > setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)))
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocket: setsockopt(SO_REUSEADDR) error");
        status = ERR_TCP_SOCKOPT_ERROR;
        goto error_cleanup;
    }

    MOC_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct SOCKADDR_IN));

    SETFAMILY(saServer)
    SETPORT(saServer,portNumber)
    ZERO_OUT(saServer)

    nRet = bind(newSocket, (struct sockaddr*)&saServer, sizeof(struct SOCKADDR_IN));
    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocket: bind() error : ", nRet);
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocket: bind() socket : ", newSocket);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = listen(newSocket, SOMAXCONN);
    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocket: listen() error: ", nRet);
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }

    *listenSocket = newSocket;
    goto exit;

error_cleanup:
    close(newSocket);

exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
LINUX_TCP_listenSocketAddrInternal(TCP_SOCKET *listenSocket, struct SOCKADDR_IN *pSaServer)
{
    TCP_SOCKET          newSocket;
    int                 nRet;
    int                 one     = 1;
    MSTATUS             status  = OK;

    /* Internal method, NULL check not needed for pSaServer */

    newSocket = socket(M_AF_INET, SOCK_STREAM, 0);
    if (0 > newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocketAddrInternal: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    if (0 > setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)))
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocketAddrInternal: setsockopt(SO_REUSEADDR) error");
        status = ERR_TCP_SOCKOPT_ERROR;
        goto error_cleanup;
    }

    nRet = bind(newSocket, (struct sockaddr*)pSaServer, sizeof(struct SOCKADDR_IN));
    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocketAddrInternal: bind() error : ", nRet);
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocketAddrInternal: bind() socket : ", newSocket);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = listen(newSocket, SOMAXCONN);
    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocketAddrInternal: listen() error: ", nRet);
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }

    *listenSocket = newSocket;
    goto exit;

error_cleanup:
    close(newSocket);

exit:
    return status;
}

/*------------------------------------------------------------------*/

/**
 * This function restricts the listen socket to only accept connections
 * from the 'localhost' address.
 */
extern MSTATUS
LINUX_TCP_listenSocketLocal(TCP_SOCKET *pListenSocket, ubyte2 portNumber)
{
    struct SOCKADDR_IN  saServer;

    MOC_MEMSET((ubyte *) &saServer, 0x00, sizeof(struct SOCKADDR_IN));

    SETFAMILY(saServer)
    SETPORT(saServer,portNumber)
#ifdef __ENABLE_MOCANA_IPV6__
    /* AHW: ZERO_OUT is only implemented for IPv4! Stick to this and fix for IPv6, when we know how */
    ZERO_OUT(saServer) /* NO OP */
#else
    saServer.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);
#endif

    return LINUX_TCP_listenSocketAddrInternal(pListenSocket, &saServer);
}

/*------------------------------------------------------------------*/

/**
 * This function restricts the listen socket to only accept connections
 * from the caller provided address.
 */
extern MSTATUS LINUX_TCP_listenSocketAddr(
    TCP_SOCKET *pListenSocket, sbyte *pIpAddress, ubyte2 portNumber)
{
    MSTATUS status;
    struct SOCKADDR_IN saServer;
    int netStatus;

    if (NULL == pIpAddress)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    MOC_MEMSET((ubyte *) &saServer, 0x00, sizeof(struct SOCKADDR_IN));

    SETFAMILY(saServer)
    SETPORT(saServer,portNumber)
#ifdef __ENABLE_MOCANA_IPV6__
    /* AHW: ZERO_OUT is only implemented for IPv4! Stick to this and fix for IPv6, when we know how */
    ZERO_OUT(saServer) /* NO OP */
#else
    /* Validate IPv4 address */
    netStatus = inet_pton(AF_INET, (const char *) pIpAddress, &saServer.sin_addr);
    if (1 != netStatus)
    {
        status = ERR_TCP_BAD_ADDRESS;
        goto exit;
    }
#endif

    status = LINUX_TCP_listenSocketAddrInternal(pListenSocket, &saServer);

exit:

    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_NONBLOCKING_SOCKET_CONNECT__
extern MSTATUS
LINUX_TCP_listenSocketNonBlocking(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct SOCKADDR_IN  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    int                 one     = 1;
    int                   flags = 0;
    MSTATUS             status  = OK;

    newSocket = socket(M_AF_INET, SOCK_STREAM, 0);
    if (0 > newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    flags = fcntl(newSocket, F_GETFL);
    if (0 > (fcntl(newSocket, F_SETFL, (flags | O_NONBLOCK))))
    {
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    if (0 > setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)))
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocket: setsockopt(MOC_GCID_VAL(module_id) SO_REUSEADDR) error");
        status = ERR_TCP_SOCKOPT_ERROR;
        goto error_cleanup;
    }

    MOC_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct SOCKADDR_IN));

    SETFAMILY(saServer)
    SETPORT(saServer,portNumber)
    ZERO_OUT(saServer)

    nRet = bind(newSocket, (struct sockaddr*)&saServer, sizeof(struct SOCKADDR_IN));
    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocket: bind() error : ", nRet);
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocket: bind() socket : ", newSocket);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = listen(newSocket, SOMAXCONN);
    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocket: listen() error: ", nRet);
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }

    *listenSocket = newSocket;
    goto exit;

error_cleanup:
    close(newSocket);

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    fd_set*             pSocketList     = NULL;
    struct timeval      timeout;
    struct SOCKADDR_IN  sockAddr;
    int                 nLen            = sizeof(struct SOCKADDR_IN);
    TCP_SOCKET          newClientSocket;
    MSTATUS             status          = OK;

    if (NULL == (pSocketList = (fd_set*) MALLOC(sizeof(fd_set))))
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

        if (0 == select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout))
        {
            /* time out occurred, check for break signal */
            if (TRUE == *isBreakSignalRequest)
                goto exit;

            continue;
        }

        newClientSocket = accept(listenSocket, (struct sockaddr*)&sockAddr,
                                (socklen_t *)&nLen);
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

} /* LINUX_TCP_acceptSocket */

/*------------------------------------------------------------------*/

extern MSTATUS LINUX_TCP_acceptSocketTimeout(
    TCP_SOCKET *clientSocket,
    TCP_SOCKET listenSocket,
    ubyte4 timeoutSeconds)
{
    fd_set*             pSocketList     = NULL;
    struct timeval      timeout;
    struct timeval     *pTimeout = NULL;
    struct SOCKADDR_IN  sockAddr;
    int                 nLen            = sizeof(struct SOCKADDR_IN);
    TCP_SOCKET          newClientSocket;
    MSTATUS             status          = OK;

    if (NULL == (pSocketList = (fd_set*) MALLOC(sizeof(fd_set))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* add the socket of interest to the list */
    FD_ZERO(pSocketList);
    FD_SET(listenSocket, pSocketList);

    /* poll every second to check break signal */
    if (0 != timeoutSeconds)
    {
        timeout.tv_sec  = timeoutSeconds;
        timeout.tv_usec = 0;
        pTimeout = &timeout;
    }

    if (0 == select(FD_SETSIZE, pSocketList, NULL, NULL, pTimeout))
    {
        status = ERR_TCP_ACCEPT_ERROR;
        goto exit;
    }

    newClientSocket = accept(listenSocket, (struct sockaddr*)&sockAddr,
                            (socklen_t *)&nLen);

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

} /* LINUX_TCP_acceptSocket */

/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    MSTATUS             status = OK;
    int         ai_family   = AF_UNSPEC;
    struct sockaddr_in  server;
#ifdef __ENABLE_MOCANA_IPV6__
    struct sockaddr_in6  server_6;
#endif
    int net_status;

    if (!pConnectSocket || !pIpAddress)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    

#ifdef __ENABLE_MOCANA_IPV6__
    MOC_MEMSET((ubyte *)&server_6, 0x00, sizeof(struct SOCKADDR_IN));
    SETPORT(server_6,portNo)
#endif
    MOC_MEMSET((ubyte *)&server, 0x00, sizeof(struct sockaddr_in));
    server.sin_port = htons(portNo);

#ifdef __ENABLE_MOCANA_IPV6__
    net_status = inet_pton(AF_INET6, (const char *) pIpAddress, &server_6.SIN_ADDR);
    if (net_status == 1)    /* valid IPv6 address */
    {
       ai_family = AF_INET6;
       SETFAMILY(server_6)
       SETSCOPE(server_6)
    }
    else
#endif
    {
       net_status = inet_pton(AF_INET, (const char *) pIpAddress, &server.sin_addr);
       if (net_status == 1) /* valid IPv4 text address */
       {
           ai_family = AF_INET;
           server.sin_family = AF_INET;
       }
    }
    if(AF_UNSPEC == ai_family)
    {
        status = ERR_TCP_CONNECT_ERROR;
        goto exit;
    }
    
    if (0 > (*pConnectSocket = socket(ai_family, SOCK_STREAM, 0)))
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }
#ifdef __ENABLE_MOCANA_IPV6__
    if(ai_family == AF_INET6)
    {
        if (0 != connect(*pConnectSocket, (struct sockaddr *)&server_6, sizeof(server_6)))
        {
            status = ERR_TCP_CONNECT_ERROR;
            (void) close(*pConnectSocket); /* connection failed, close socket */
        }
    }
    else
#endif
    {
        if (0 != connect(*pConnectSocket, (struct sockaddr *)&server, sizeof(server)))
        {
            status = ERR_TCP_CONNECT_ERROR;
            (void) close(*pConnectSocket); /* connection failed, close socket */
        }
    }
exit:
    return status;
}


/*------------------------------------------------------------------*/
extern MSTATUS
LINUX_TCP_connectSocketTimeout(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo, ubyte4 msTimeout)
{
    struct sockaddr_in  server;
#ifdef __ENABLE_MOCANA_IPV6__
    struct sockaddr_in6  server_6;
#endif
    int                   flags = 0;
    MSTATUS               status = OK;
    TCP_SOCKET            connectSocket = -1;
    int                   ai_family   = AF_UNSPEC;
    int                   net_status;

    if (!pConnectSocket || !pIpAddress)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_MOCANA_IPV6__
    MOC_MEMSET((ubyte *)&server_6, 0x00, sizeof(struct SOCKADDR_IN));
    SETPORT(server_6,portNo)
#endif
    MOC_MEMSET((ubyte *)&server, 0x00, sizeof(struct sockaddr_in));
    server.sin_port = htons(portNo);

#ifdef __ENABLE_MOCANA_IPV6__
    net_status = inet_pton(AF_INET6, (const char *) pIpAddress, &server_6.SIN_ADDR);
    if (net_status == 1)    /* valid IPv6 address */
    {
       ai_family = AF_INET6;
       SETFAMILY(server_6)
       SETSCOPE(server_6)
    }
    else
#endif
    {
       net_status = inet_pton(AF_INET, (const char *) pIpAddress, &server.sin_addr);
       if (net_status == 1) /* valid IPv4 text address */
       {
           ai_family = AF_INET;
           server.sin_family = AF_INET;
       }
    }
    if(AF_UNSPEC == ai_family)
    {
        status = ERR_TCP_CONNECT_ERROR;
        goto exit;
    }

    if (0 > (connectSocket = socket(ai_family, SOCK_STREAM, 0)))
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }

    flags = fcntl(connectSocket, F_GETFL);
    if (0 > fcntl(connectSocket, F_SETFL, flags | O_NONBLOCK))
    {
        status = ERR_TCP_CONNECT_ERROR;
        goto closeSocket;
    }

#ifdef __ENABLE_MOCANA_IPV6__
    if(ai_family == AF_INET6)
    {
        net_status = connect(connectSocket, (struct sockaddr *)&server_6, sizeof(server_6));
    }
    else
#endif
    {
        net_status = connect(connectSocket, (struct sockaddr *)&server, sizeof(server));
    }

    if (0 != net_status)
    {
        status = ERR_TCP_CONNECT_ERROR;

        if (EINPROGRESS == errno || EAGAIN == errno)
        {
            /* do a select */
            fd_set*         pSocketList = NULL;
            struct timeval  timeout;

            if (NULL == (pSocketList = MALLOC(sizeof(fd_set))))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto closeSocket;
            }

            /* add the socket of interest to the list */
            FD_ZERO(pSocketList);
            FD_SET(connectSocket, pSocketList);

            /* set timeout */
            timeout.tv_sec  = msTimeout / 1000;
            timeout.tv_usec = msTimeout % 1000 * 1000;

            if (0 <  select(FD_SETSIZE, NULL, pSocketList, NULL, &timeout))
                status = OK;
            else if (EALREADY == errno)
                status = ERR_TCP_CONNECT_EALREADY;
            else
                status = ERR_TCP_CONNECT_INPROGRESS;

            FREE (pSocketList);
        }
    }

    /* restore original flags (with blocking state) */
    if (0 > fcntl(connectSocket, F_SETFL, flags))
    {
        status = ERR_TCP_CONNECT_ERROR;
        goto closeSocket;
    }

closeSocket:
    if (OK > status)
        close(connectSocket);
    else
        *pConnectSocket = connectSocket;
exit:
    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_NONBLOCKING_SOCKET_CONNECT__
extern MSTATUS
LINUX_TCP_connectSocketNonBlocking(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    struct sockaddr_in  server;
#ifdef __ENABLE_MOCANA_IPV6__
    struct sockaddr_in6  server_6;
#endif
    int                   flags = 0;
    MSTATUS               status = OK;
    TCP_SOCKET            connectSocket = -1;
    int                   ai_family   = AF_UNSPEC;
    int                   net_status;



    if (!pConnectSocket || !pIpAddress)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    
#ifdef __ENABLE_MOCANA_IPV6__
    MOC_MEMSET((ubyte *)&server_6, 0x00, sizeof(struct SOCKADDR_IN));
    SETPORT(server_6,portNo)
#endif
    MOC_MEMSET((ubyte *)&server, 0x00, sizeof(struct sockaddr_in));
    server.sin_port = htons(portNo);

#ifdef __ENABLE_MOCANA_IPV6__
    net_status = inet_pton(AF_INET6, (const char *) pIpAddress, &server_6.SIN_ADDR);
    if (net_status == 1)    /* valid IPv6 address */
    {
       ai_family = AF_INET6;
       SETFAMILY(server_6)
       SETSCOPE(server_6)
    }
    else
#endif
    {
       net_status = inet_pton(AF_INET, (const char *) pIpAddress, &server.sin_addr);
       if (net_status == 1) /* valid IPv4 text address */
       {
           ai_family = AF_INET;
           server.sin_family = AF_INET;
       }
    }
    if(AF_UNSPEC == ai_family)
    {
        status = ERR_TCP_CONNECT_ERROR;
        goto exit;
    }

    if (!(*pConnectSocket))
    {
    
        if (0 > (connectSocket = socket(ai_family, SOCK_STREAM, 0)))
        {
            status = ERR_TCP_CONNECT_CREATE;
            goto exit;
        }

        flags = fcntl(connectSocket, F_GETFL);
        if (0 > (fcntl(connectSocket, F_SETFL, (flags | O_NONBLOCK))))
        {
            status = ERR_TCP_CONNECT_ERROR;
            goto closeSocket;
        }

    }
    else
    {
        connectSocket = *pConnectSocket;
    }
#ifdef __ENABLE_MOCANA_IPV6__
    if(ai_family == AF_INET6)
    {
        net_status = connect(connectSocket, (struct sockaddr *)&server_6, sizeof(server_6));
    }
    else
#endif
    {
        net_status = connect(connectSocket, (struct sockaddr *)&server, sizeof(server));
    }

    if (0 != net_status)
    {
        status = ERR_TCP_CONNECT_ERROR;

        if (EINPROGRESS == errno || EAGAIN == errno)
        {
            /* do a select */
            fd_set*         pSocketList = NULL;
            struct timeval  timeout;

            if (NULL == (pSocketList = MALLOC(sizeof(fd_set))))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            /* add the socket of interest to the list */
            FD_ZERO(pSocketList);
            FD_SET(connectSocket, pSocketList);

            /* set timeout */
            timeout.tv_sec  = 5;
            timeout.tv_usec = 0;

            if (0 <  select(FD_SETSIZE, NULL, pSocketList, NULL, &timeout))
            {
                *pConnectSocket = connectSocket;
                status = OK;
            }
            else if (EALREADY == errno)
                status = ERR_TCP_CONNECT_EALREADY;
            else
                status = ERR_TCP_CONNECT_INPROGRESS;

            FREE (pSocketList);
        }
        else
        {
            status = ERR_TCP_CONNECT_ERROR;
        }
    }
    else
    {
        *pConnectSocket = connectSocket;
        goto exit;
    }

closeSocket:
    if (OK > status)
        close(connectSocket);
exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_TCP_closeSocket(TCP_SOCKET socket)
{
    close(socket);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer,
                     ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead, ubyte4 msTimeout)
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
        if (NULL == (pSocketList = (fd_set*) MALLOC(sizeof(fd_set))))
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


        if (0 == select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout))
        {
            status = ERR_TCP_READ_TIMEOUT;
            goto exit;
        }
    }


    *pNumBytesRead = 0;

    retValue = recv(socket, pBuffer, maxBytesToRead, 0);

    if (retValue < 0)
    {
        if ((EWOULDBLOCK == errno) || (EAGAIN == errno))
            status = ERR_TCP_WOULDBLOCK;
        else
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
    if (NULL != pSocketList)
        FREE(pSocketList);

    return status;

} /* LINUX_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_TCP_readSocketAvailableEx(TCP_SOCKET socket, sbyte *pBuffer,
                     ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    fd_set*         pSocketList = NULL;
    struct timeval  timeout;
    int             retValue;
    MSTATUS         status;
    int             selectValue;

    if ((NULL == pBuffer) || (NULL == pNumBytesRead))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (TCP_NO_TIMEOUT != msTimeout)
    {
        /* handle timeout case */
        if (NULL == (pSocketList = (fd_set*) MALLOC(sizeof(fd_set))))
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

        selectValue = select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout);
        if (0 == selectValue)
        {
            status = ERR_TCP_READ_TIMEOUT;
            goto exit;
        }
        else if (-1 == selectValue)
        {
            *pNumBytesRead = 0;
            status = ERR_TCP_SELECT_ERROR;
            goto exit;
        }
    }


    *pNumBytesRead = 0;

    retValue = recv(socket, pBuffer, maxBytesToRead, 0);

    if (retValue < 0)
    {
        if ((EWOULDBLOCK == errno) || (EAGAIN == errno))
            status = ERR_TCP_WOULDBLOCK;
        else
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
    if (NULL != pSocketList)
        FREE(pSocketList);

    return status;

} /* LINUX_TCP_readSocketAvailableEx */


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
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
        if ((errno == EWOULDBLOCK) || (errno == EAGAIN))
            status = ERR_TCP_WOULDBLOCK;
        else
            status = ERR_TCP_WRITE_ERROR;

        *pNumBytesWritten = 0;
        goto exit;
    }

    *pNumBytesWritten = retValue;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
LINUX_TCP_getPeerName(TCP_SOCKET socket, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr)
{
    struct sockaddr_in6 myAddress6 = { 0 };
    struct sockaddr_in  myAddress = { 0 };
    socklen_t           addrLen;
    struct sockaddr     sa;
    socklen_t           len = (socklen_t) sizeof(struct sockaddr);
    MSTATUS             status = OK;

    if(getsockname(socket, &sa, &len))
    {
        status = ERR_TCP_GETSOCKNAME;
	    goto exit;
    }
#ifdef __ENABLE_MOCANA_IPV6__
    if (sa.sa_family == AF_INET6)
    {
        addrLen = sizeof(struct sockaddr_in6);
        if (0 > getpeername(socket, (struct sockaddr *)&myAddress6, &addrLen))
        {
            status = ERR_TCP_GETSOCKNAME;
            goto exit;
        }
        *pRetPortNo = htons(myAddress6.SIN_PORT);
        pRetAddr->family = myAddress6.sin6_family;
        MOC_MEMCPY((ubyte *)pRetAddr->uin.addr6, myAddress6.SIN_ADDR.S_ADDR, 16); 
        pRetAddr->uin.addr6[4] = myAddress6.sin6_scope_id;

    }
    else 
#endif
    if(sa.sa_family == AF_INET)
    {
        addrLen = sizeof(struct sockaddr_in);
        if (0 > getpeername(socket, (struct sockaddr *)&myAddress, &addrLen))
        {
            status = ERR_TCP_GETSOCKNAME;
            goto exit;
        }

        *pRetPortNo = htons(myAddress.sin_port);
#ifdef __ENABLE_MOCANA_IPV6__
        pRetAddr->family = myAddress.sin_family;
        pRetAddr->uin.addr = htonl(myAddress.sin_addr.s_addr);
#else
        *pRetAddr = htonl(myAddress.sin_addr.s_addr);
#endif
    }

exit:
    return status;
}


extern MSTATUS
LINUX_unixDomain_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *soc_path)
{
    MSTATUS             status = OK;
    struct sockaddr_un server = {0};
    int                sunPathSize = 0;

    if(NULL == soc_path)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (0 > (*pConnectSocket = socket(AF_UNIX, SOCK_STREAM, 0)))
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }
    server.sun_family = AF_UNIX;
    sunPathSize = (sizeof(server.sun_path) / sizeof(char)) - 1;
    strncpy(server.sun_path, (const char *) soc_path, sunPathSize);

    if (0 != connect(*pConnectSocket, (struct sockaddr *)&server, sizeof(struct sockaddr_un)))
    {
        status = ERR_TCP_CONNECT_ERROR;
        (void) close(*pConnectSocket); /* connection failed, close socket */
    }

exit:
    return status;
}

extern MSTATUS
LINUX_unixDomain_listenSocket(TCP_SOCKET *listenSocket, sbyte *soc_path)
{
    struct sockaddr_un  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    MSTATUS             status  = OK;
    int                 sunPathSize = 0;

    if(NULL == soc_path)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    newSocket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (0 > newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"LINUX_unixDomain_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    sunPathSize = (sizeof(saServer.sun_path) / sizeof(char)) - 1;
    MOC_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct sockaddr_un));
    saServer.sun_family = AF_UNIX;
    strncpy(saServer.sun_path, (const char *) soc_path, sunPathSize);

    nRet = bind(newSocket, (struct sockaddr*)&saServer, sizeof(struct sockaddr_un));
    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"LINUX_unixDomain_listenSocket: bind() error : ", nRet);
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"LINUX_unixDomain_listenSocket: bind() socket : ", newSocket);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = listen(newSocket, SOMAXCONN);
    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"LINUX_TCP_listenSocket: listen() error: ", nRet);
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }

    *listenSocket = newSocket;
    goto exit;

error_cleanup:
    close(newSocket);

exit:
    return status;
}


extern MSTATUS
LINUX_unixDomain_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    fd_set*             pSocketList     = NULL;
    struct timeval      timeout;
    TCP_SOCKET          newClientSocket;
    MSTATUS             status          = OK;

    if (NULL == (pSocketList = (fd_set*) MALLOC(sizeof(fd_set))))
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

        if (0 == select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout))
        {
            /* time out occurred, check for break signal */
            if (TRUE == *isBreakSignalRequest)
                goto exit;

            continue;
        }

        newClientSocket = accept(listenSocket, 0, 0);
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

} /* LINUX_TCP_acceptSocket */



extern MSTATUS
LINUX_unixDomain_closeSocket(TCP_SOCKET socket)
{
    close(socket);
    return OK;
}


#endif /* __LINUX_TCP__ */
