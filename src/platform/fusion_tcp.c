/*
 * fusion_tcp.c
 *
 * FUSION TCP Abstraction Layer
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

#ifdef __FUSION_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mtcp.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"

#ifndef __FUSION_TCP_API_7_DOT_1__
#include <fns_sockapi.h>
#else
#include <fns_sockapi.h>
#define fns_socket      fnsSocket
#define fns_setsockopt  fnsSetSockOpt
#define fns_bind        fnsBind
#define fns_listen      fnsListen
#define fns_accept      fnsAccept
#define fns_select      fnsSelect
#define fns_recv        fnsRecv
#define fns_send        fnsSend
#define fns_close       fnsClose
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
FUSION_TCP_init()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FUSION_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FUSION_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    struct sockaddr_in  saServer;
    TCP_SOCKET          newSocket;
    int                 one     = 1;
    MSTATUS             status  = ERR_TCP_LISTEN_SOCKET_ERROR;
    int                 err;

    newSocket = fns_socket(AF_INET, SOCK_STREAM, 0, &err);

    if ((FNS_ENOERR != err) || (0 >= newSocket))
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        printf("FUSION_TCP_listenSocket: Could not create listen socket\n");
#endif
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&saServer, 0x00, sizeof(struct sockaddr));

    if ((0 > fns_setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(int), &err)) ||
        (FNS_ENOERR != err))
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        printf("FUSION_TCP_listenSocket: setsockopt(SO_REUSEADDR) error");
#endif
        status = ERR_TCP_SOCKOPT_ERROR;
        goto error_cleanup;
    }

    saServer.sin_family      = AF_INET;
    saServer.sin_addr.s_addr = htonl(INADDR_ANY);
    saServer.sin_port        = htons(portNumber);

    rc = fns_bind(s, (struct sockaddr *)addr, addrlen, &err);

    if ((0 > fns_bind(newSocket, (struct sockaddr *)&saServer, sizeof(struct sockaddr), &err)) || (FNS_ENOERR != err))
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        printf("FUSION_TCP_listenSocket: bind() error : %d  %d\n", err, newSocket);
#endif
        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    if ((fns_listen(newSocket, 5, &err) != 0) || (FNS_ENOERR != err))
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        printf("FUSION_TCP_listenSocket: listen() error: %d", err);
#endif
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }

    *listenSocket = newSocket;
    status = OK;
    goto exit;

error_cleanup:
    fns_close(newSocket, &err);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FUSION_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    fd_set*             pSocketList;
    struct timeval      timeout;
    struct sockaddr_in  sockAddr;
    int                 nLen            = sizeof(struct sockaddr_in);
    TCP_SOCKET          newClientSocket;
    int                 err;
    MSTATUS             status          = OK;

    if (NULL == (pSocketList = (fd_set*)MALLOC(sizeof(fd_set))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    newClientSocket = -1;

    while (1)
    {
        /* add the socket of interest to the list */
        FD_ZERO(pSocketList);
        FD_SET(listenSocket, pSocketList);

        /* poll every second to check break signal */
        timeout.tv_sec  = 1;
        timeout.tv_usec = 0;

        if (0 == fns_select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout, &err))
        {
            /* time out occurred, check for break signal */
            if (TRUE == *isBreakSignalRequest)
                goto exit;

            continue;
        }

        if (FNS_ENOERR != err)
            newClientSocket = fns_accept(listenSocket, (struct sockaddr*)&sockAddr, &nLen, &err);

        break;
    }

    if ((0 >= newClientSocket) || (FNS_ENOERR != err))
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
FUSION_TCP_closeSocket(TCP_SOCKET socket)
{
    int err;

    fns_close(socket, &err);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FUSION_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead,
                               ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    fd_set*         pSocketList = NULL;
    struct timeval  timeout;
    int             retValue;
    int             err;
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
            if (0 == fns_select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout, &err))
            {
                status = ERR_TCP_READ_TIMEOUT;
                goto exit;
            }
        }
    }

    *pNumBytesRead = 0;

    retValue = fns_recv(socket, pBuffer, maxBytesToRead, 0, &err);

    if ((FNS_ENOERR != err) || (retValue < 0))
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
        FREE(pSocketList);

    return status;

} /* FUSION_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
FUSION_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer,
                       ubyte4 numBytesToWrite, ubyte4 *pNumBytesWritten)
{
    int     retValue;
    int     err;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    retValue = fns_send(socket, (char *)pBuffer, numBytesToWrite, 0, &err);

    if ((FNS_ENOERR != err) || (0 > retValue))
    {
        status = ERR_TCP_WRITE_ERROR;
        goto exit;
    }

    *pNumBytesWritten = retValue;
    status = OK;

exit:
    return status;
}

#endif /* __FUSION_TCP__ */

