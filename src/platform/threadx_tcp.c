/*
 * THREADX_tcp.c
 *
 * THREADX TCP Abstraction Layer
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
#ifdef ROM_A_1
#include <pt_gram_ns.h>
#endif

#if defined(__THREADX_TCP__) && !defined(__DISABLE_DIGICERT_TCP_INTERFACE__)
#include "../common/moptions.h"
#include "nx_bsd.h"
#include "nx_api.h"
#include "../src/framework/sf_el_nx/nx_renesas_synergy.h"
#include "common_data.h"
#include "nx_api.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/moc_net.h"
#include "../common/mdefs.h"
#include "../common/mtcp.h"
#include <limits.h>

#ifdef DKS7G2
#define ETH_CHANNEL 1
#else
#define ETH_CHANNEL 0
#endif

//Checks the return status of an nx_ API call
#define NX_CHECK_ERROR(X) if(NX_SUCCESS != (nxStatus = (X))){ goto exit; }

//Checks the return status of an nx_ API call and sets the Mocana status
//to the error code specified by Y
#define NX_CHECK_MERROR(X,Y) if(NX_SUCCESS != (nxStatus = (X))){ status = Y; goto exit; }
NX_TCP_SOCKET server_socket;
NX_TCP_SOCKET sock2;
NX_PACKET_POOL pool_0;


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_TCP_BSD_connectSocket(TCP_SOCKET *pConnectSocket, MOC_IP_ADDRESS pIpAddress, ubyte2 portNo)
{
    struct SOCKADDR_IN  server;
    MSTATUS             status = OK;
    int socketFd;

    socketFd = socket(M_AF_INET,SOCK_STREAM,0);
    if(-1 == socketFd){
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    } else {
        *pConnectSocket = socketFd;
    }

    DIGI_MEMSET((ubyte *)&server, 0x00, sizeof(struct SOCKADDR_IN));

    SETFAMILY(server)
    SETPORT(server,portNo)

    inet_pton(M_AF_INET, (char *)pIpAddress, &server.SIN_ADDR);

    ULONG a = IP_ADDRESS(192,168,2,90);
    if (0 != connect(*pConnectSocket, (struct sockaddr *)&server, sizeof(server)))
    {
        status = ERR_TCP_CONNECT_ERROR;
        int err;
        err = errno;
        (void) soc_close(*pConnectSocket);
    }

exit:
    return status;
} /* THREADX_TCP_BSD_connectSocket */


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_TCP_BSD_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer,
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

    if(maxBytesToRead > INT_MAX){
        status = ERR_UNSUPPORTED_SIZE;
        goto exit;
    }

    if (0 != msTimeout)
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
        timeout.tv_sec  = (time_t)(msTimeout / 1000);
        timeout.tv_usec = (LONG)((msTimeout % 1000) * 1000);    /* convert ms to us */

        if (0 == select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout))
        {
            status = ERR_TCP_READ_TIMEOUT;
            goto exit;
        }
    }


    *pNumBytesRead = 0;

    retValue = recv(socket, pBuffer, (int)maxBytesToRead, 0);

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

    *pNumBytesRead = (ubyte4)retValue;

    status = OK;

exit:
    if (NULL != pSocketList)
        FREE(pSocketList);

    return status;

} /* THREADX_TCP_BSD_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_TCP_BSD_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                      ubyte4 *pNumBytesWritten)
{
    int     retValue;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if(numBytesToWrite > INT_MAX){
        status = ERR_UNSUPPORTED_SIZE;
        goto exit;
    }


    retValue = send((TCP_SOCKET)socket, (const char *)pBuffer, (int)numBytesToWrite, 0);
    if (0 > retValue)
    {
        if ((errno == EWOULDBLOCK) || (errno == EAGAIN))
            status = ERR_TCP_WOULDBLOCK;
        else
            status = ERR_TCP_WRITE_ERROR;

        *pNumBytesWritten = 0;
        goto exit;
    }

    *pNumBytesWritten = (ubyte4)retValue;
    status = OK;

exit:
    return status;
} /* THREADX_TCP_BSD_writeSocket */


/*------------------------------*/

extern MSTATUS
THREADX_TCP_BSD_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct SOCKADDR_IN  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    int                 one     = 1;
    MSTATUS             status  = OK;

    newSocket = socket(M_AF_INET, SOCK_STREAM, 0);
    if (0 > newSocket)
    {
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    if (0 > setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)))
    {
        status = ERR_TCP_SOCKOPT_ERROR;
        goto error_cleanup;
    }

    DIGI_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct SOCKADDR_IN));

    SETFAMILY(saServer)
    SETPORT(saServer,portNumber)
    ZERO_OUT(saServer)

    nRet = bind(newSocket, (struct sockaddr*)&saServer, sizeof(struct SOCKADDR_IN));
    if (0 > nRet)
    {
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = listen(newSocket, NX_BSD_MAX_SOCKETS);
    if (nRet != 0)
    {
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }

    *listenSocket = newSocket;
    goto exit;

error_cleanup:
    THREADX_TCP_BSD_closeSocket(newSocket);

exit:
    return status;
} /* THREADX_TCP_BSD_listenSocket */


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_TCP_init()
{
    /* Initialization is done by generated nx_bsd_init() function */
    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_TCP_shutdown()
{
    return OK;
}

/*------------------------------------------------------------------*/


extern MSTATUS
THREADX_TCP_BSD_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
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
    if (NULL != pSocketList)
        FREE(pSocketList);

    return status;

}  /* THREADX_TCP_BSD_acceptSocket */

/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_TCP_BSD_closeSocket(TCP_SOCKET socket)
{
    int status;
    status = soc_close(socket);
    if(-1 == status){
        return ERR_TCP_SOCKET_CLOSE_FAIL;
    } else {
        return OK;
    }
}

/*------------------------------------------------------------------*/
#endif /* __THREADX_TCP__ */
