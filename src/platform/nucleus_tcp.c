/*
 * nucleus_tcp.c
 *
 * Nucleus TCP Abstraction Layer
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

#ifdef __NUCLEUS_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <nucleus.h>
#include <Target.h>
#include <sockext.h>
#include <externs.h>
#include <socketd.h>

#ifndef SOMAXCONN
#define SOMAXCONN   10
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_TCP_init()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct addr_struct  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    MSTATUS             status  = OK;

    newSocket = NU_Socket(NU_FAMILY_IP, NU_TYPE_STREAM, NU_NONE);
    if (0 > newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "NUCLEUS_TCP_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    DIGI_MEMSET(&saServer, 0x00, sizeof(saServer));

    saServer.family = NU_FAMILY_IP;
    saServer.port   = (ubyte2)portNumber;
    *((uint32 *)saServer.id.is_ip_addrs) = IP_ADDR_ANY;

    /* bind socket to local address */
    if (0 > (nRet = NU_Bind(newSocket, (struct addr_struct *)&saServer, 0)))
    {
        NU_Close_Socket(newSocket);
        DEBUG_ERROR(DEBUG_PLATFORM, "LINUX_TCP_listenSocket: NU_Bind() error : ", nRet);
        DEBUG_ERROR(DEBUG_PLATFORM, "LINUX_TCP_listenSocket: NU_Bind() socket : ", newSocket);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    /* listen for new connections */
    if (NU_SUCCESS != (nRet = NU_Listen(newSocket, SOMAXCONN)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "NUCLEUS_TCP_listenSocket: listen() error: ", nRet);
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }

    *listenSocket = newSocket;
    goto exit;

error_cleanup:
    NU_Close_Socket(newSocket);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket,
                         intBoolean *isBreakSignalRequest)
{
    fd_set*             pSocketList     = NULL;
    struct timeval      timeout;
    struct addr_struct  sockAddr;
    int                 nLen            = sizeof(struct sockaddr_in);
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

        if (0 == select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout))
        {
            /* time out occurred, check for break signal */
            if (TRUE == *isBreakSignalRequest)
                goto exit;

            continue;
        }

        DIGI_MEMSET(&sockAddr, 0x00, sizeof(sockAddr));
        newClientSocket = NU_Accept(listenSocket, (struct addr_struct*)&sockAddr, 0);
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
NUCLEUS_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    ubyte4      remote_ip_addr;
    addr_struct server;
    MSTATUS     status = OK;

    *pConnectSocket = NU_Socket(NU_FAMILY_IP, NU_TYPE_STREAM, NU_NONE);
    if (0 >= *pConnectSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "NUCLEUS_TCP_connectSocket: Could not create connect socket");
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }

    server.family = NU_FAMILY_IP;
    server.port   = (ubyte2)htons(portNo);

    /*!!!! may need to  bind to an interface, not sure if different than Linux */
    server.id.is_ip_addrs[0] = (uint8)((remote_ip_addr)       & 0xff);
    server.id.is_ip_addrs[1] = (uint8)((remote_ip_addr >> 8)  & 0xff);
    server.id.is_ip_addrs[2] = (uint8)((remote_ip_addr >> 16) & 0xff);
    server.id.is_ip_addrs[3] = (uint8)((remote_ip_addr >> 24) & 0xff);

    if (0 != NU_Connect(*pConnectSocket, (struct addr_struct *)&server, sizeof(server)))
        status = ERR_TCP_CONNECT_ERROR;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_TCP_closeSocket(TCP_SOCKET socket)
{
    NU_Close_Socket(socket);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer,
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
        status = ERR_TCP_READ_ERROR;
        goto exit;
    }

    *pNumBytesRead = retValue;

    status = OK;

exit:
    if (NULL != pSocketList)
        FREE(pSocketList);

    return status;

} /* NUCLEUS_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
NUCLEUS_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
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

#endif /* __NUCLEUS_TCP__ */
