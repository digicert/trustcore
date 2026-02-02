/*
 * psos_tcp.c
 *
 * pSOS TCP Abstraction Layer
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

#ifdef __PSOS_TCP__

#include <psos.h>
#include <version.h>
#if VERSION >= 250
#include <signal.h>
#endif
#include <time.h>
#include <pna.h>
#include <string.h>
#include <errno.h>

#ifdef NULL
#undef NULL
#endif

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../common/mrtos.h"

#ifdef  SOMAXCONN
#undef  SOMAXCONN
#endif

#define SOMAXCONN 10

#ifndef SC_SOCKADDR
#define SC_SOCKADDR sockaddr_in
#endif

#ifndef EV_PRIV2
#define EV_PRIV2    (1 << 1)
#endif


/*------------------------------------------------------------------*/

static unsigned long local_inet_addr(char *ipaddr)
{
    int            i, k;
    char           *byteAddr[4];
    char           addr[32];

    /* Convert the host address from string to number */
    strncpy(addr, ipaddr, 32);
    k = 0;
    byteAddr[k++] = (char *) &addr[0];
    for (i = 0; (i < 32) && (addr[i] != '\0'); i++) {
        if (addr[i] == '.') {
            addr[i] = '\0';
            /* *** FIX HERE - dont let anything other than 4 */
            if (k > 3) return (-1);
            byteAddr[k++] = (char *) &addr[i + 1];
        }
    }

    /* *** FIX HERE - dont let anything other than 4 */
    if (k != 4)
        return (-1);

    /* return the host address */
    return (htonl(((atol(byteAddr[0]) << 24) | (atol(byteAddr[1]) << 16)
            | (atol(byteAddr[2]) << 8) | (atol(byteAddr[3]))
            | (atol(byteAddr[3])))));
}


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_TCP_init()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
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
        DEBUG_PRINTNL(DEBUG_PLATFORM, "PSOS_TCP_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    if (0 > setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, (char *)(&one), sizeof(int)))
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "PSOS_TCP_listenSocket: setsockopt(SO_REUSEADDR) error");
        status = ERR_TCP_SOCKOPT_ERROR;
        goto error_cleanup;
    }

    saServer.sin_family      = AF_INET;
    saServer.sin_addr.s_addr = htonl(INADDR_ANY);
    saServer.sin_port        = htons(portNumber);

    nRet = bind(newSocket, (struct  SC_SOCKADDR *)&saServer, sizeof(struct sockaddr));
    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "PSOS_TCP_listenSocket: bind() error : ", nRet);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = listen(newSocket, SOMAXCONN);
    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "PSOS_TCP_listenSocket: listen() error: ", nRet);
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
PSOS_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    fd_set*             pSocketList;
    struct timeval      timeout;
    struct sockaddr_in  sockAddr;
    int                 nLen            = sizeof(struct sockaddr_in);
    TCP_SOCKET          newClientSocket;
    MSTATUS             status          = OK;
    ULONG               events = 0;

    if (NULL == (pSocketList = (fd_set*)MALLOC(sizeof(fd_set))))
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

            ev_receive(EV_PRIV2, EV_NOWAIT | EV_ANY, 0, &events);

            if (events)
            {
                *isBreakSignalRequest = TRUE;
                goto exit;
            }

            continue;
        }

        newClientSocket = accept(listenSocket, (struct SC_SOCKADDR *)&sockAddr, &nLen);
        break;
    }

    if (0 > newClientSocket)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "PSOS_TCP_acceptSocket: accept() failed, return = ", newClientSocket);
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
PSOS_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    struct sockaddr_in server;
    MSTATUS            status = OK;

    *pConnectSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (*pConnectSocket < 0)
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&server, 0x00, sizeof(struct sockaddr_in));

    server.sin_family = AF_INET;
    server.sin_port = htons(portNo);
    server.sin_addr.s_addr = local_inet_addr(pIpAddress);

    if (connect(*pConnectSocket, (struct SC_SOCKADDR *)&server, sizeof(server)) < 0)
        status = ERR_TCP_CONNECT_ERROR;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_TCP_closeSocket(TCP_SOCKET socket)
{
    DEBUG_ERROR(DEBUG_PLATFORM, "PSOS_TCP_closeSocket: socket = ", socket);
    close(socket);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead,
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
        if (NULL == (pSocketList = (fd_set*)MALLOC(sizeof(fd_set))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* add the socket of interest to the list */
        /* we do a quick check first to avoid select() bug */
        FD_ZERO(pSocketList);
        FD_SET(socket, pSocketList);

        timeout.tv_sec  = 0;
        timeout.tv_usec = 5;

        /*  The first argument to select is the highest file
            descriptor value plus 1. In most cases, you can
            just pass FD_SETSIZE and you'll be fine. */
        if (0 == select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout))
        {
            /* add the socket of interest to the list */
            FD_ZERO(pSocketList);
            FD_SET(socket, pSocketList);

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

    retValue = recv(socket, pBuffer, maxBytesToRead, 0);

    if (retValue < 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "PSOS_TCP_readSocketAvailable: recv() failed, return = ", retValue);
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

    if (OK > status)
        DEBUG_ERROR(DEBUG_PLATFORM, "PSOS_TCP_readSocketAvailable: status = ", status);

    return status;

} /* PSOS_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                        ubyte4 *pNumBytesWritten)
{
    int     retValue;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    retValue = send((TCP_SOCKET)socket, pBuffer, numBytesToWrite, 0);

    if (0 > retValue)
    {
        if (EWOULDBLOCK != errno)
        {
            DEBUG_ERROR(DEBUG_PLATFORM, "PSOS_TCP_writeSocket: send() failed, return = ", retValue);
            status = ERR_TCP_WRITE_ERROR;
            goto exit;
        }

        retValue = 0;
    }

    *pNumBytesWritten = retValue;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PSOS_TCP_shareSocket(TCP_SOCKET socket)
{
    unsigned long   tid;
    MSTATUS         status = ERR_TCP_SOCKET_SHARE;

    /* the current running thread grabs the socket from the parent thread */
    if (0 == t_ident(NULL, 0, &tid))
    {
        if (0 <= shr_socket(socket, tid))
            status = OK;
    }

    return status;
}

#endif /* __PSOS_TCP__ */
