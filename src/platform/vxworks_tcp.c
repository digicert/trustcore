/*
 * vxworks_tcp.c
 *
 * VxWorks TCP Abstraction Layer
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

#ifdef __VXWORKS_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mtcp.h"
#include "../common/moc_net.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../common/mrtos.h"

#include <vxWorks.h>
#include <sockLib.h>
#include <time.h>
#include <selectLib.h>
#include <inetLib.h>
#include <stdlib.h>
#include <errnoLib.h>
#include <hostLib.h>
#include <stdio.h>
#include <string.h>

#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)

/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_TCP_init()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    TCP_SOCKET          newSocket;
    int                 nRet;
    struct addrinfo     Hints, *AddrInfo;
    int                 one     = 1;
    MSTATUS             status  = OK;
    sbyte               *pPort = NULL;
    int                 RetVal;


    newSocket = socket(M_AF_INET, SOCK_STREAM, 0);

    if (0 > newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"VXWORKS_TCP_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        return status;
/*        goto exit; */    /* can not go to exit with AddrInfo being setup */
    }

    DIGI_MEMSET((ubyte *)&Hints, 0 , sizeof(struct addrinfo));

    Hints.ai_family = M_AF_INET;
    Hints.ai_socktype = SOCK_STREAM;
    Hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

    if (NULL == (pPort = MALLOC(10)))
    {
        close(newSocket);
        return ERR_MEM_ALLOC_FAIL;
    }
    
    sprintf((char *)pPort, "%d", portNumber);

    RetVal = getaddrinfo(NULL, (char *)pPort, &Hints, &AddrInfo);
    if (RetVal != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "getaddrinfo failed with error %d ",
                RetVal);
        close(newSocket);
        return ERR_TCP_LISTEN_ADDRINFO;
    }

    if (0 > setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, (char *)(&one), sizeof(int)))
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"VXWORKS_TCP_listenSocket: setsockopt(SO_REUSEADDR) error");
        status = ERR_TCP_SOCKOPT_ERROR;
        goto error_cleanup;
    }

    nRet = bind(newSocket, AddrInfo->ai_addr, AddrInfo->ai_addrlen);
    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "VXWORKS_TCP_listenSocket: bind() error : ", nRet);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = listen(newSocket, SOMAXCONN);
    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "VXWORKS_TCP_listenSocket: listen() error: ", nRet);
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }

    *listenSocket = newSocket;
    goto exit;

error_cleanup:
    close(newSocket);

exit:
    freeaddrinfo(AddrInfo);

    if (NULL != pPort)
    {
        (void) DIGI_FREE((void **) &pPort);
    }

    return status;
}


/*------------------------------------------------------------------*/

/**
 * This function restricts the listen socket to only accept connections
 * from the 'localhost' address.
 */
extern MSTATUS
VXWORKS_TCP_listenSocketLocal(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    TCP_SOCKET          newSocket;
    int                 nRet;
    struct addrinfo     Hints, *AddrInfo;
    int                 one     = 1;
    MSTATUS             status  = OK;
    sbyte               *pPort;
    int                 RetVal;


    newSocket = socket(M_AF_INET, SOCK_STREAM, 0);

    if (0 > newSocket)
    {
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        return status;
    }

    DIGI_MEMSET((ubyte *)&Hints, 0 , sizeof(struct addrinfo));

    Hints.ai_family = M_AF_INET;
    Hints.ai_socktype = SOCK_STREAM;
    Hints.ai_flags = AI_NUMERICHOST;

    if (NULL == (pPort = MALLOC(10)))
    {
        close(newSocket);
        return ERR_MEM_ALLOC_FAIL;
    }

    sprintf((char *)pPort, "%d", portNumber);

    RetVal = getaddrinfo(NULL, (char *)pPort, &Hints, &AddrInfo);
    if (RetVal != 0)
    {
        close(newSocket);
        return ERR_TCP_LISTEN_ADDRINFO;
    }

    if (0 > setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, (char *)(&one), sizeof(int)))
    {
        status = ERR_TCP_SOCKOPT_ERROR;
        goto error_cleanup;
    }

    nRet = bind(newSocket, AddrInfo->ai_addr, AddrInfo->ai_addrlen);
    if (0 > nRet)
    {
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = listen(newSocket, SOMAXCONN);
    if (nRet != 0)
    {
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }

    *listenSocket = newSocket;
    goto exit;

error_cleanup:
    close(newSocket);

exit:
    freeaddrinfo(AddrInfo);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    fd_set*                    pSocketList;
    struct timeval             timeout;
#if (!defined(_WRS_VXWORKS_MAJOR) || (_WRS_VXWORKS_MAJOR < 6) || (_WRS_VXWORKS_MAJOR ==6 && _WRS_VXWORKS_MINOR<5))
    struct sockaddr_in         sockAddr;
    int                        nLen            = sizeof(struct sockaddr_in);
#else
    struct sockaddr_storage    sockAddr;
    int                        nLen            = sizeof(struct sockaddr_storage);
#endif

    TCP_SOCKET                 newClientSocket;
    MSTATUS                    status          = OK;

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
        DEBUG_ERROR(DEBUG_PLATFORM, "VXWORKS_TCP_acceptSocket: accept() failed, return = ", newClientSocket);
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
VXWORKS_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    MSTATUS                     status = OK;
    struct addrinfo             Hints, *AddrInfo;
    sbyte                       *c_port = NULL;
    sbyte4                      RetVal;

    *pConnectSocket = socket(M_AF_INET, SOCK_STREAM, 0);

    if (ERROR == *pConnectSocket)
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }

    DIGI_MEMSET((void *)&Hints, 0, sizeof(Hints));
    Hints.ai_family = M_AF_INET;
    Hints.ai_socktype = SOCK_STREAM;
    Hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

    if (NULL == (c_port = MALLOC(10)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    
    sprintf((char *)c_port, "%d", portNo);

    RetVal = getaddrinfo((char *)pIpAddress, (char *)c_port, &Hints,  &AddrInfo);
    if (RetVal != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "getaddrinfo failed with error %d ",
                    RetVal);
        status = ERR_TCP_CONNECT_ERROR;
        goto exit;
    }

    if (ERROR == connect(*pConnectSocket, AddrInfo->ai_addr, AddrInfo->ai_addrlen))
        status = ERR_TCP_CONNECT_ERROR;

    freeaddrinfo(AddrInfo);
exit:
    if(c_port != NULL)
        FREE(c_port);

    DEBUG_ERROR(DEBUG_PLATFORM, "VXWORKS_TCP_connectSocket: status = ", status);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_TCP_closeSocket(TCP_SOCKET socket)
{
    DEBUG_ERROR(DEBUG_PLATFORM, "VXWORKS_TCP_closeSocket: socket = ", socket);
    close(socket);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead,
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

    *pNumBytesRead = 0;

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

    retValue = recv(socket, (char *)pBuffer, maxBytesToRead, 0);

    if (retValue < 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "VXWORKS_TCP_readSocketAvailable: recv() failed, return = ", retValue);
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
        DEBUG_ERROR(DEBUG_PLATFORM, "VXWORKS_TCP_readSocketAvailable: status = ", status);

    return status;

} /* VXWORKS_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
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
        int err = errnoGet();

        if (EWOULDBLOCK != err)
        {
            DEBUG_ERROR(DEBUG_PLATFORM, "VXWORKS_TCP_writeSocket: send() failed, return = ", err);
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

extern MSTATUS
VXWORKS_TCP_getPeerName(TCP_SOCKET socket, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr)
{
    struct sockaddr_in      myAddress = { 0 };
    socklen_t               addrLen = sizeof(myAddress);
    MSTATUS                 status = OK;

    if (0 > getpeername(socket, (struct sockaddr *)&myAddress, &addrLen))
    {
        status = ERR_TCP_GETSOCKNAME;
        goto exit;
    }

    *pRetPortNo = htons(myAddress.SIN_PORT);
/*    *pRetPortNo = (myAddress.SIN_PORT); */
#ifdef __ENABLE_DIGICERT_IPV6__
    pRetAddr->family = AF_INET;
    pRetAddr->uin.addr = htonl(myAddress.SIN_ADDR.S_ADDR);
#else
    *pRetAddr = htonl(myAddress.SIN_ADDR.S_ADDR);
/*    *pRetAddr = (myAddress.SIN_ADDR.S_ADDR); */
#endif

exit:
    return status;
}


#endif /* __VXWORKS_TCP__ */

