/*
 * rtcs_tcp.c
 *
 * RTCS TCP Abstraction Layer
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

#ifdef __RTCS_TCP__

#include <mqx.h>
#include <rtcs.h>

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mtcp.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/moc_net.h"

/*------------------------------------------------------------------*/

extern MSTATUS
RTCS_TCP_init()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
RTCS_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
RTCS_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct sockaddr_in  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    int                 one     = 1;
    MSTATUS             status  = OK;

    newSocket = socket(AF_INET, SOCK_STREAM, 0);

    DIGI_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct sockaddr_in));

    if (RTCS_SOCKET_ERROR == newSocket)
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        printf("RTCS_TCP_listenSocket: Could not create listen socket\n");
#endif
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    saServer.sin_family      = AF_INET;
    saServer.sin_addr.s_addr = INADDR_ANY;
    saServer.sin_port        = portNumber;

    nRet = bind(newSocket, /*(struct sockaddr*)*/&saServer, sizeof(struct sockaddr_in));
    if (0 > nRet)
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        printf("RTCS_TCP_listenSocket: bind() error : %d  %d\n", nRet, newSocket);
#endif
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = listen(newSocket, 5);
    if (nRet != 0)
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        printf("RTCS_TCP_listenSocket: listen() error: %d", nRet);
#endif
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }

    *listenSocket = newSocket;
    goto exit;

error_cleanup:
    shutdown(newSocket, FLAG_CLOSE_TX);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
RTCS_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    struct sockaddr_in  sockAddr;
    int                 nLen            = sizeof(struct sockaddr_in);
    TCP_SOCKET          newClientSocket;
    MSTATUS             status          = OK;

    newClientSocket = accept(listenSocket, /*(struct sockaddr*)*/&sockAddr, (unsigned short *)&nLen);

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
RTCS_TCP_closeSocket(TCP_SOCKET socket)
{
    shutdown(socket, FLAG_CLOSE_TX);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
RTCS_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead,
                                ubyte4 *pNumBytesRead, ubyte4 msTimeout)
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

    if ((0 > retValue) || (RTCS_ERROR == retValue))
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

} /* RTCS_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
RTCS_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer,
                        ubyte4 numBytesToWrite, ubyte4 *pNumBytesWritten)
{
    int     retValue;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    retValue = send((TCP_SOCKET)socket, (char *)pBuffer, numBytesToWrite, 0);

    if (0 > retValue)
    {
        status = ERR_TCP_WRITE_ERROR;
        goto exit;
    }

#ifdef __ENABLE_ALL_DEBUGGING__
    if (retValue != numBytesToWrite)
        printf("RTCS_TCP_writeSocket: %d != %d\n", retValue, numBytesToWrite);
#endif

    *pNumBytesWritten = retValue;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/


extern MSTATUS
RTCS_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    struct SOCKADDR_IN  server;

    int option;
    MSTATUS             status = OK;

    if (0 >= (*pConnectSocket = socket(M_AF_INET, SOCK_STREAM, 0)))
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }


    SETFAMILY(server)

    server.sin_port = portNo;

    inet_aton((char *)pIpAddress, &(server.SIN_ADDR));

    option = 256;
    setsockopt(*pConnectSocket, SOL_TCP, OPT_TBSIZE, &option, sizeof(option));
    setsockopt(*pConnectSocket, SOL_TCP, OPT_RBSIZE, &option, sizeof(option));

    if (0 != connect(*pConnectSocket, (struct sockaddr_in *)&server, sizeof(server)))
        status = ERR_TCP_CONNECT_ERROR;
exit:
    return status;
}


#endif /* __RTCS_TCP__ */


