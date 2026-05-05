/*
 * freertos_tcp.c
 *
 * freertos TCP Abstraction Layer
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */
#include <errno.h>

#include "../common/moptions.h"

#ifdef __FREERTOS_TCP__

#define _REENTRANT

#include <FreeRTOS.h>
#include "task.h"
#include "semphr.h"
#ifndef __RTOS_FREERTOS_ESP32__
#include <FreeRTOS_IP.h>
#include "FreeRTOS_Sockets.h"
#endif

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#define FREERTOS_INVALID_SOCKET	( ( void * ) ~0U )


/*------------------------------------------------------------------*/

static void
ignoreSignal(int ignoreParam)
{
    return;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_init()
{

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct freertos_sockaddr  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    int                 one     = 1;
    TickType_t          xNoTimeout = pdMS_TO_TICKS( 1000UL );
    WinProperties_t xWinProps;
    MSTATUS             status  = OK;

    newSocket = FreeRTOS_socket(FREERTOS_AF_INET, FREERTOS_SOCK_STREAM, FREERTOS_IPPROTO_TCP);
    if (0 == newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "FREERTOS_TCP_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }


    DIGI_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct freertos_sockaddr));

    saServer.sin_family         = FREERTOS_AF_INET;
    saServer.sin_port           = FreeRTOS_htons(portNumber);
    saServer.sin_addr    = 0ul;

    nRet = FreeRTOS_bind(newSocket, (struct freertos_sockaddr*)&saServer, sizeof(struct freertos_sockaddr));
    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "LWIP_TCP_listenSocket: bind() error : ", nRet);
        DEBUG_ERROR(DEBUG_PLATFORM, "FREERTOS_TCP_listenSocket: bind() socket : ", newSocket);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = FreeRTOS_listen(newSocket, 1);
    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "FREERTOS_TCP_listenSocket: listen() error: ", nRet);
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }
    FreeRTOS_setsockopt( newSocket, 0, FREERTOS_SO_RCVTIMEO, ( void * ) &xNoTimeout, sizeof( xNoTimeout ) );
    FreeRTOS_setsockopt( newSocket, 0, FREERTOS_SO_SNDTIMEO, ( void * ) &xNoTimeout, sizeof( xNoTimeout ) );

    memset( &xWinProps, '\0', sizeof( xWinProps ) );
        /* The parent socket itself won't get connected.  The properties below
        will be inherited by each new child socket. */
    xWinProps.lTxBufSize = 15 * ipconfigTCP_MSS;
    xWinProps.lTxWinSize = 6;
    xWinProps.lRxBufSize = 15 * ipconfigTCP_MSS;
    xWinProps.lRxWinSize = 6;

        /* Set the window and buffer sizes. */
    FreeRTOS_setsockopt( newSocket, 0, FREERTOS_SO_WIN_PROPERTIES, ( void * ) &xWinProps,	sizeof( xWinProps ) );


    *listenSocket = newSocket;
    goto exit;

error_cleanup:
FreeRTOS_closesocket(newSocket);

exit:
    return status;
}

extern MSTATUS
FREERTOS_TCP_listenSocketLocal(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct freertos_sockaddr  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    TickType_t          xNoTimeout = pdMS_TO_TICKS( 1000UL );
    WinProperties_t xWinProps;
    int                 one     = 1;
    MSTATUS             status  = OK;

    newSocket = FreeRTOS_socket(FREERTOS_AF_INET, FREERTOS_SOCK_STREAM, FREERTOS_IPPROTO_TCP);
    if (0 == newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "FREERTOS_TCP_listenSocketLocal: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }


    DIGI_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct freertos_sockaddr));

    saServer.sin_family         = FREERTOS_AF_INET;
    saServer.sin_port           = FreeRTOS_htons(portNumber);
    saServer.sin_addr    = FreeRTOS_ntohl(0x7f000001ul);

    nRet = FreeRTOS_bind(newSocket, (struct freertos_sockaddr*)&saServer, sizeof(struct freertos_sockaddr));
    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "FREERTOS_TCP_listenSocketLocal: bind() error : ", nRet);
        DEBUG_ERROR(DEBUG_PLATFORM, "FREERTOS_TCP_listenSocketLocal: bind() socket : ", newSocket);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }
    FreeRTOS_setsockopt( newSocket, 0, FREERTOS_SO_RCVTIMEO, ( void * ) &xNoTimeout, sizeof( xNoTimeout ) );
    FreeRTOS_setsockopt( newSocket, 0, FREERTOS_SO_SNDTIMEO, ( void * ) &xNoTimeout, sizeof( xNoTimeout ) );

    nRet = FreeRTOS_listen(newSocket, 1);
    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "FREERTOS_TCP_listenSocketLocal: listen() error: ", nRet);
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }

    memset( &xWinProps, '\0', sizeof( xWinProps ) );
        /* The parent socket itself won't get connected.  The properties below
        will be inherited by each new child socket. */
    xWinProps.lTxBufSize = 15 * ipconfigTCP_MSS;
    xWinProps.lTxWinSize = 6;
    xWinProps.lRxBufSize = 15 * ipconfigTCP_MSS;
    xWinProps.lRxWinSize = 6;

        /* Set the window and buffer sizes. */
    FreeRTOS_setsockopt( newSocket, 0, FREERTOS_SO_WIN_PROPERTIES, ( void * ) &xWinProps,	sizeof( xWinProps ) );


    *listenSocket = newSocket;
    goto exit;

error_cleanup:
    FreeRTOS_closesocket(newSocket);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    SocketSet_t             pSocketList     = NULL;
    TickType_t      timeout =  pdMS_TO_TICKS( 1000UL );
    struct freertos_sockaddr  sockAddr;
    socklen_t                 nLen            = sizeof(struct freertos_sockaddr);
    TCP_SOCKET          newClientSocket;
    TickType_t          xNoTimeout = pdMS_TO_TICKS( 1000UL );
    MSTATUS             status          = OK;



    if (NULL == (pSocketList = FreeRTOS_CreateSocketSet()))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

        /* add the socket of interest to the list */
    FreeRTOS_FD_SET(listenSocket, pSocketList, eSELECT_READ|eSELECT_EXCEPT);

    while (1)
    {

        /* poll every second to check break signal */

        if (0 == FreeRTOS_select(pSocketList,  timeout))
        {
            /* time out occurred, check for break signal */
            if (TRUE == *isBreakSignalRequest)
                goto exit;

            continue;
        }
        if( FreeRTOS_FD_ISSET( listenSocket, pSocketList ) )
        {
            newClientSocket = FreeRTOS_accept(listenSocket, &sockAddr, &nLen);
            break;
        }
    }

    if( ( newClientSocket != NULL ) && ( newClientSocket != FREERTOS_INVALID_SOCKET ) )
    {
        *clientSocket = newClientSocket;
        FreeRTOS_setsockopt( newClientSocket, 0, FREERTOS_SO_RCVTIMEO, ( void * ) &xNoTimeout, sizeof( xNoTimeout ) );
        FreeRTOS_setsockopt( newClientSocket, 0, FREERTOS_SO_SNDTIMEO, ( void * ) &xNoTimeout, sizeof( xNoTimeout ) );
    }
    else
    {
        status = ERR_TCP_ACCEPT_ERROR;
        goto exit;
    }

exit:

    if (NULL != pSocketList)
    {
        FreeRTOS_FD_CLR(listenSocket, pSocketList, eSELECT_ALL);
        FreeRTOS_DeleteSocketSet(pSocketList);
    }
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    struct freertos_sockaddr  server;
    MSTATUS             status = OK;
    TickType_t xTimeoutTime = pdMS_TO_TICKS( 1000 );
    WinProperties_t xWinProps;


    DIGI_MEMSET((ubyte *)&server, 0x00, sizeof(struct freertos_sockaddr));

    server.sin_family = FREERTOS_AF_INET;
    server.sin_port = FreeRTOS_htons(portNo);
    server.sin_addr = FreeRTOS_inet_addr((const char  *) pIpAddress);
    if(0 == server.sin_addr)
    {
        status = ERR_TCP_CONNECT_ERROR;
        goto exit;
    }
    if (0 == (*pConnectSocket = FreeRTOS_socket(FREERTOS_AF_INET, FREERTOS_SOCK_STREAM, FREERTOS_IPPROTO_TCP)))
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }
    FreeRTOS_setsockopt( *pConnectSocket, 0, FREERTOS_SO_RCVTIMEO, ( void * ) &xTimeoutTime, sizeof( TickType_t ) );
    FreeRTOS_setsockopt( *pConnectSocket, 0, FREERTOS_SO_SNDTIMEO, ( void * ) &xTimeoutTime, sizeof( TickType_t ) );

    memset( &xWinProps, '\0', sizeof( xWinProps ) );
        /* The parent socket itself won't get connected.  The properties below
        will be inherited by each new child socket. */
    xWinProps.lTxBufSize = 24 * ipconfigTCP_MSS;
    xWinProps.lTxWinSize = 6;
    xWinProps.lRxBufSize = 24 * ipconfigTCP_MSS;
    xWinProps.lRxWinSize = 6;

        /* Set the window and buffer sizes. */
    FreeRTOS_setsockopt( *pConnectSocket, 0, FREERTOS_SO_WIN_PROPERTIES, ( void * ) &xWinProps,	sizeof( xWinProps ) );

    if (0 != FreeRTOS_connect(*pConnectSocket, &server, sizeof(server)))
    {
        status = ERR_TCP_CONNECT_ERROR;
        FreeRTOS_closesocket(*pConnectSocket);
        *pConnectSocket = 0;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_closeSocket(TCP_SOCKET socket)
{
    FreeRTOS_closesocket(socket);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer,
                     ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    SocketSet_t         pSocketList = NULL;
    TickType_t  timeout =  0;
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
        if (NULL == (pSocketList = FreeRTOS_CreateSocketSet()))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* add the socket of interest to the list */
        FreeRTOS_FD_SET(socket, pSocketList, eSELECT_READ|eSELECT_EXCEPT);

        /* compute timeout (milliseconds) */
        timeout  = pdMS_TO_TICKS(msTimeout);



        if (0 == FreeRTOS_select(pSocketList,  timeout))
        {
            status = ERR_TCP_READ_TIMEOUT;
            goto exit;
        }
        if( !FreeRTOS_FD_ISSET( socket, pSocketList ) )
        {
            status = ERR_TCP_READ_TIMEOUT;
            goto exit;
        }
    }


    *pNumBytesRead = 0;

    retValue = FreeRTOS_recv(socket, pBuffer, maxBytesToRead, 0);

    if (retValue < 0)
    {
        status = ERR_TCP_READ_ERROR;
        goto exit;
    }


    *pNumBytesRead = retValue;

    status = OK;

exit:
    if (NULL != pSocketList)
    {
        FreeRTOS_FD_CLR(socket, pSocketList, eSELECT_ALL);
        FreeRTOS_DeleteSocketSet(pSocketList);
    }

    return status;

} /* FREERTOS_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                      ubyte4 *pNumBytesWritten)
{
    int     retValue;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    retValue = FreeRTOS_send(socket, (void*)pBuffer, numBytesToWrite, 0);

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

extern MSTATUS FREERTOS_TCP_getHostByName(char* pDomainName, char* pIpAddress)
{
    return OK;
}

#endif /* __FREERTOS_TCP__ */
