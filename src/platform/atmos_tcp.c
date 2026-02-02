/*
 * atmos_tcp.c
 *
 * ATMOS TCP Abstraction Layer
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

#ifdef __ATMOS_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include "posix_config.h"

#define  ATMOS_WRFD_READY_TIMEOUT       10    /* 10 seconds wait till FD is ready */
#define  ATMOS_WRFD_READY_MAXRETRIES    3     /* Max. number of retries */

#if ((!defined(__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)) && (!defined(__DISABLE_DIGICERT_ATMOS_PORT_NOTICE__)))
#error Port not complete for non-async APIs
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_TCP_init()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct sockaddr_in  saServer;
    TCP_SOCKET          newSocket;
    int                 nRet;
    int                 one     = 1;
    MSTATUS             status  = OK;

    newSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (0 > newSocket)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "ATMOS_TCP_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    if (0 > setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)))
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "ATMOS_TCP_listenSocket: setsockopt(SO_REUSEADDR) error");
        status = ERR_TCP_SOCKOPT_ERROR;
        goto error_cleanup;
    }

    DIGI_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct sockaddr_in));

    saServer.sin_family         = AF_INET;
    saServer.sin_port           = htons(portNumber);
    saServer.sin_addr.s_addr    = INADDR_ANY;

    nRet = bind(newSocket, (struct sockaddr*)&saServer, sizeof(struct sockaddr));

    if (0 > nRet)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "ATMOS_TCP_listenSocket: bind() error : ", nRet);
        DEBUG_ERROR(DEBUG_PLATFORM, "ATMOS_TCP_listenSocket: bind() socket : ", newSocket);
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    nRet = listen(newSocket, SOMAXNUMBER);

    if (nRet != 0)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "ATMOS_TCP_listenSocket: listen() error: ", nRet);
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
ATMOS_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    fd_set*             pSocketList     = NULL;
    struct timeval      timeout;
    struct sockaddr_in  sockAddr;
    int                 nLen            = sizeof(struct sockaddr_in);
    TCP_SOCKET          newClientSocket;
    MSTATUS             status          = OK;


    if (NULL == (pSocketList = malloc(sizeof(fd_set))))
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

        if (0 == select(listenSocket+1, pSocketList, NULL, NULL, &timeout))
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
        free(pSocketList);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
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
    inet_pton(AF_INET, (char *)pIpAddress, &server.sin_addr);

    if (0 != connect(*pConnectSocket, (struct sockaddr *)&server, sizeof(server)))
        status = ERR_TCP_CONNECT_ERROR;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_TCP_closeSocket(TCP_SOCKET pSocket)
{
    close(pSocket);

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_TCP_readSocketAvailable(TCP_SOCKET pSocket, sbyte *pBuffer,
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
        if (NULL == (pSocketList = malloc(sizeof(fd_set))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* add the socket of interest to the list */
        FD_ZERO(pSocketList);
        FD_SET(pSocket, pSocketList);

        /* compute timeout (milliseconds) */
        timeout.tv_sec  = msTimeout / 1000;
        timeout.tv_usec = (msTimeout % 1000) * 1000;    /* convert ms to us */

        /* Note: Windows ignores the first parameter '1' */
        /* other platforms may want (highest socket + 1) */

        /*  The first argument to select is the highest file
            descriptor value plus 1. In most cases, you can
            just pass FD_SETSIZE and you'll be fine. */


        if (0 == select(pSocket + 1, pSocketList, NULL, NULL, &timeout))
        {
            status = ERR_TCP_READ_TIMEOUT;
            goto exit;
        }
    }


    *pNumBytesRead = 0;

    retValue = recv(pSocket, pBuffer, maxBytesToRead, 0);

    if (retValue < 0)
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
    if (NULL != pSocketList)
        free(pSocketList);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ATMOS_TCP_writeSocket(TCP_SOCKET iSocket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                      ubyte4 *pNumBytesWritten)
{
    int     lRetValue;
    int     ii;
    ubyte4  lNumBytesRemWrite = numBytesToWrite;
    ubyte4  lOffSet = 0;
    int     lFd = iSocket;
    fd_set  lWriteFdSet;
    struct  timeval  lTimeout;
    int     lErrno = 0;
    int     lRet = 0;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    ii = 0;
    while (1)
    {
        if (lNumBytesRemWrite == 0)
            break;

        FD_ZERO(&lWriteFdSet);
        FD_SET(iSocket, &lWriteFdSet);

        /* Perform SELECT, wait till FD is writable */
        lTimeout.tv_sec = ATMOS_WRFD_READY_TIMEOUT;
        lTimeout.tv_usec = 0;

        lRet = atmos_select(lFd + 1, NULL, &lWriteFdSet, NULL, &lTimeout, NULL);
        if (lRet == -1)
        {
            status = ERR_TCP_WRITE_ERROR;
            goto exit;
        }

        if (FD_ISSET(lFd, &lWriteFdSet)) /* FD is WRITEable */
        {
            lRetValue = send((TCP_SOCKET)iSocket, (const char *)(pBuffer + lOffSet),
                                                          lNumBytesRemWrite, 0);
            lErrno = __get_errno();
            if (lErrno == EAGAIN)
            {
                /* Cannot WRITE fully, or cannot WRITE now */
                if (lRetValue != -1)  /* if WROTE partially */
                {
                    lNumBytesRemWrite -= lRetValue;
                    lOffSet += lRetValue;
                }
            }
            else if (0 > lRetValue)
            {
                /* Failure in WRITE, connection reset by peer*/
                DEBUG_ERROR(DEBUG_PLATFORM,
                       "ATMOS_TCP_writeSocket: send() failed, return = ", lRetValue);

                status = ERR_TCP_WRITE_ERROR;
                goto exit;
            }
            else
            {
                /* everything hunky dory */
                lNumBytesRemWrite -= lRetValue;
                lOffSet += lRetValue;

                if (lOffSet >= numBytesToWrite) /* Written the BYTES necesary to WRITE */
                    break;
            }
        }
        else
        {
            /* Out of select, it is a TIMEOUT, TRY max retries  */
            if (ii >= ATMOS_WRFD_READY_MAXRETRIES)
            {
                /* declare WRITE error */
                status = ERR_TCP_WRITE_ERROR;
                goto exit;
            }
        }

        ii++;
    }

    *pNumBytesWritten = lOffSet;
    status = OK;

exit:
    return status;
}



#if 0
extern MSTATUS
ATMOS_TCP_writeSocket(TCP_SOCKET iSocket, sbyte *pBuffer, ubyte4 numBytesToWrite,
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
        DEBUG_ERROR(DEBUG_PLATFORM, "ATMOS_TCP_writeSocket: send() failed, return = ", retValue);
        status = ERR_TCP_WRITE_ERROR;
        goto exit;
    }

    *pNumBytesWritten = retValue;
    status = OK;

exit:
    return status;
}
#endif

#endif /* __ATMOS_TCP__ */

