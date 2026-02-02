/*
 * nnos_tcp.c
 *
 * Nnos TCP Abstraction Layer
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

#ifdef __NNOS_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <NNstyle.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <macros.h>
/* #include <sockLib.h> */
#include <time.h>
/* #include <selectLib.h> */
/* #include <inetLib.h> */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/time.h>


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_TCP_init()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct sockaddr_in  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    int                 one     = 1;
    MSTATUS             status  = OK;

    newSocket = socket(AF_INET, SOCK_STREAM, 0);

    DIGI_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct sockaddr));

    if (0 > newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "NNOS_TCP_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    if (0 > setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, (char *)(&one), sizeof(int)))
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "NNOS_TCP_listenSocket: setsockopt(SO_REUSEADDR) error");
        status = ERR_TCP_SOCKOPT_ERROR;
        goto error_cleanup;
    }

    saServer.sin_family      = AF_INET;
    saServer.sin_addr.s_addr = htonl(INADDR_ANY);
    saServer.sin_port        = htons(portNumber);

    nRet = bind(newSocket, (struct sockaddr*)&saServer, sizeof(struct sockaddr));
    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "NNOS_TCP_listenSocket: bind() error : ", nRet);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = listen(newSocket, SOMAXCONN);
    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "NNOS_TCP_listenSocket: listen() error: ", nRet);
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

extern MSTATUS
NNOS_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    fd_set*             pSocketList;
    struct timeval      timeout;
    struct sockaddr_in  sockAddr;
    int                 nLen            = sizeof(struct sockaddr_in);
    TCP_SOCKET          newClientSocket;
    MSTATUS             status          = OK;

    if (NULL == (pSocketList = (fd_set*)malloc(sizeof(fd_set))))
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

        newClientSocket = accept(listenSocket, (struct sockaddr*)&sockAddr, &nLen);
        break;
    }

    if (0 > newClientSocket)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "NNOS_TCP_acceptSocket: accept() failed, return = ", newClientSocket);
        status = ERR_TCP_ACCEPT_ERROR;
        goto exit;
    }

    *clientSocket = newClientSocket;

exit:
    if (NULL != pSocketList)
        free(pSocketList);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
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
    server.sin_addr.s_addr = inet_addr((char *)pIpAddress);

    if (0 != connect(*pConnectSocket, (struct sockaddr *)&server, sizeof(server)))
        status = ERR_TCP_CONNECT_ERROR;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_TCP_closeSocket(TCP_SOCKET iSocket)
{
    DEBUG_ERROR(DEBUG_PLATFORM, "NNOS_TCP_closeSocket: socket = ", iSocket);
    close(iSocket);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_TCP_readSocketAvailable(TCP_SOCKET iSocket, sbyte *pBuffer, ubyte4 maxBytesToRead,
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
        if (NULL == (pSocketList = (fd_set*)malloc(sizeof(fd_set))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* add the socket of interest to the list */
        /* we do a quick check first to avoid VxWork's TCP/IP select() bug */
        FD_ZERO(pSocketList);
        FD_SET(iSocket, pSocketList);

        timeout.tv_sec  = 0;
        timeout.tv_usec = 5;

        /*  The first argument to select is the highest file
            descriptor value plus 1. In most cases, you can
            just pass FD_SETSIZE and you'll be fine. */
        if (0 == select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout))
        {
            /* add the socket of interest to the list */
            FD_ZERO(pSocketList);
            FD_SET(iSocket, pSocketList);

            /* compute timeout (milliseconds) */
            timeout.tv_sec  = msTimeout / 1000;
            timeout.tv_usec = (msTimeout % 1000) * 1000;    /* convert ms to us */

            /*  The first argument to select is the highest file
                descriptor value plus 1. In most cases, you can
                just pass FD_SETSIZE and you'll be fine. */
            if (0 == select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout))
            {
                status = ERR_TCP_READ_TIMEOUT;
                goto exit;
            }
        }
    }

    *pNumBytesRead = 0;

    retValue = recv(iSocket, pBuffer, maxBytesToRead, 0);

    if (retValue < 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "NNOS_TCP_readSocketAvailable: recv() failed, return = ", retValue);
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
        free(pSocketList);

    if (OK > status)
        DEBUG_ERROR(DEBUG_PLATFORM, "NNOS_TCP_readSocketAvailable: status = ", status);

    return status;

} /* NNOS_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
NNOS_TCP_writeSocket(TCP_SOCKET iSocket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                        ubyte4 *pNumBytesWritten)
{
    int     retValue;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    retValue = send((TCP_SOCKET)iSocket, (const char *)pBuffer, numBytesToWrite, 0);

    if (0 > retValue)
    {
printf("NNOS_TCP_writeSocket: send() failed return = %d, errno = %d.\n", retValue, errno);
printf("NNOS_TCP_writeSocket: attempted to write %d bytes on socket %d.\n", numBytesToWrite, iSocket);
        DEBUG_ERROR(DEBUG_PLATFORM, "NNOS_TCP_writeSocket: send() failed, return = ", retValue);
        status = ERR_TCP_WRITE_ERROR;
        goto exit;
    }

    *pNumBytesWritten = retValue;
    status = OK;

exit:
    return status;
}

#endif /* __NNOS_TCP__ */

