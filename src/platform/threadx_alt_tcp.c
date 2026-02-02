/*
 * THREADX_alt_tcp.c
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

#include "../common/moptions.h"

#ifdef __THREADX_TCP__

#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mtcp.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <tx_api.h>
#include <nx_api.h>
#include <nx_port.h>
#include <nx_user.h>


/* defined in threadx_alt_rtos.c */
extern NX_IP            mMocIpInstance;
extern NX_PACKET_POOL   mMocPacketPool;

#define THREADX_TCP_QUEUE_MAX       32
#define THREADX_TCP_WINDOW_SIZE     4096


/*------------------------------------------------------------------*/

typedef struct
{
    UINT            isListenSocket;
    UINT            serverPort;
    NX_TCP_SOCKET*  pTcpSocket;
    ubyte           buffer[THREADX_TCP_WINDOW_SIZE];
    ubyte4          used;      /* number of bytes used in buffer */
    ubyte4          offset;    /* offset of remaining bytes */
} THREADX_TCP_interface;


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_TCP_init()
{
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
THREADX_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    MSTATUS                 status  = ERR_TCP_LISTEN_SOCKET_ERROR;
    UINT                    nxStatus;
    ULONG                   actualStatus;
    THREADX_TCP_interface*  pTcpIf = NULL;

    if (NULL == listenSocket)
        return ERR_NULL_POINTER;

    /* Ensure the IP instance has been initialized.  */
    nxStatus =  nx_ip_status_check(&mMocIpInstance, NX_IP_INITIALIZE_DONE,
                                   &actualStatus, 100);

    if (NX_SUCCESS != nxStatus)
    {
        goto exit;
    }

    /* allocate THREADX_TCP_interface */
    if (NULL == (pTcpIf = MALLOC(sizeof(THREADX_TCP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pTcpIf, 0x00, sizeof(THREADX_TCP_interface));

    if (NULL == (pTcpIf->pTcpSocket = MALLOC(sizeof(NX_TCP_SOCKET))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pTcpIf->pTcpSocket, 0x00, sizeof(NX_TCP_SOCKET));

    /* Create a socket.  */
    nxStatus =  nx_tcp_socket_create(&mMocIpInstance, pTcpIf->pTcpSocket, "listenSocket",
                                      NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                                      THREADX_TCP_WINDOW_SIZE,
                                      NX_NULL, NX_NULL);

    if (NX_SUCCESS != nxStatus)
    {
        goto error_cleanup;
    }

    /* Setup this thread to listen.  */
    nxStatus =  nx_tcp_server_socket_listen(&mMocIpInstance, (UINT)portNumber,
                                             pTcpIf->pTcpSocket, THREADX_TCP_QUEUE_MAX, NX_NULL);

    if (NX_SUCCESS != nxStatus)
    {
        goto error_cleanup;
    }

    pTcpIf->isListenSocket = 1;
    pTcpIf->serverPort = (UINT)portNumber;

    *listenSocket = (TCP_SOCKET)pTcpIf;

    status = OK;
    goto exit;

error_cleanup:
    nx_tcp_server_socket_unlisten(&mMocIpInstance, (UINT)portNumber);

    if (pTcpIf)
    {
        if (pTcpIf->pTcpSocket)
            FREE(pTcpIf->pTcpSocket);

        FREE(pTcpIf);
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_TCP_listenSocketLocal(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    return ERR_UNSUPPORTED_OPERATION;
}

/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    MSTATUS                 status = OK;
    UINT                    nxStatus;
    THREADX_TCP_interface*  pClientSocket = NULL;
    THREADX_TCP_interface*  pTcpIf = (THREADX_TCP_interface *)listenSocket;

    if ((NULL == clientSocket) || (NULL == pTcpIf))
        return ERR_NULL_POINTER;

    nxStatus =  nx_tcp_server_socket_accept(pTcpIf->pTcpSocket, NX_WAIT_FOREVER);

    if (NX_SUCCESS != nxStatus)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, "THREADX_TCP_acceptSocket: nx_tcp_server_socket_accept() returns ", nxStatus);

        status = ERR_TCP_ACCEPT_ERROR;
        goto exit;
    }

    if (NULL == (pClientSocket = MALLOC(sizeof(THREADX_TCP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pClientSocket, 0x00, sizeof(THREADX_TCP_interface));

    pClientSocket->isListenSocket = 0;
    pClientSocket->serverPort = pTcpIf->serverPort;
    pClientSocket->pTcpSocket = pTcpIf->pTcpSocket;

    *clientSocket = (TCP_SOCKET)pClientSocket;

exit:

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_TCP_closeSocket(TCP_SOCKET socket)
{
    MSTATUS                 status = ERR_TCP_SOCKET_CLOSED;
    THREADX_TCP_interface*  pTcpIf = (THREADX_TCP_interface *)socket;

    if (NULL == pTcpIf)
        return ERR_NULL_POINTER;

    nx_tcp_socket_disconnect(pTcpIf->pTcpSocket, NX_NO_WAIT);

    if (pTcpIf->serverPort)
    {
        /* for server */
        nx_tcp_server_socket_unaccept(pTcpIf->pTcpSocket);

        if (!pTcpIf->isListenSocket)
        {
            if (NX_SUCCESS != nx_tcp_server_socket_relisten(&mMocIpInstance, pTcpIf->serverPort, pTcpIf->pTcpSocket))
            {
                goto exit;
            }
        }
        else
        {
            nx_tcp_socket_delete(pTcpIf->pTcpSocket);
            nx_tcp_server_socket_unlisten(&mMocIpInstance, pTcpIf->serverPort);
        }
    }
    else
    {
        /* for client */
        nx_tcp_client_socket_unbind(pTcpIf->pTcpSocket);
        nx_tcp_socket_delete(pTcpIf->pTcpSocket);
    }

    status = OK;

exit:

    if (pTcpIf)
    {
        if (pTcpIf->isListenSocket || !pTcpIf->serverPort)
        {
            if (pTcpIf->pTcpSocket)
                FREE(pTcpIf->pTcpSocket);
        }

        FREE(pTcpIf);
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
THREADX_TCP_getFromBuffer( THREADX_TCP_interface* pTcpIf, sbyte *pBuffer,
                           ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead)
{
    ubyte4 numBytesReturned = pTcpIf->used - pTcpIf->offset;

    if ( numBytesReturned > maxBytesToRead)
    {
        numBytesReturned = maxBytesToRead;
    }

    DIGI_MEMCPY(pBuffer, pTcpIf->buffer + pTcpIf->offset, numBytesReturned);
    *pNumBytesRead = numBytesReturned;
    /* update internal pointers */
    pTcpIf->offset += numBytesReturned;
    if ( pTcpIf->offset == pTcpIf->used) /* all bytes used -> reset */
    {
        pTcpIf->offset = pTcpIf->used = 0;
    }
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead,
                                ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    MSTATUS                 status = ERR_TCP_READ_ERROR;
    UINT                    nxStatus = 0;
    NX_PACKET*              pPacket = NULL;
    ULONG                   packetLen;
    THREADX_TCP_interface*  pTcpIf = (THREADX_TCP_interface *)socket;
    UINT                    count = 0;

    if ((NULL == pTcpIf) || (NULL == pBuffer) || (NULL == pNumBytesRead))
        return ERR_NULL_POINTER;

    /* first check if there are some data remaining in our buffer */
    if (pTcpIf->offset < pTcpIf->used)
    {
        return THREADX_TCP_getFromBuffer( pTcpIf, pBuffer, maxBytesToRead, pNumBytesRead);
    }

read_again:
    nxStatus = nx_tcp_socket_receive(pTcpIf->pTcpSocket, &pPacket, msTimeout);

    if (NX_SUCCESS != nxStatus)
    {
        if (NX_NO_PACKET == nxStatus)
        {
            /* If no packet was retrieved then sleep for a while to let the TCP
             * thread handle other packets and then retry.
             */
            tx_thread_sleep(100);
            if (count++ < 6)
                goto read_again;

            status = ERR_TCP_READ_TIMEOUT;
        }
        else if (NX_NOT_CONNECTED == nxStatus)
        {
            status = ERR_TCP_SOCKET_CLOSED;
        }
        DEBUG_ERROR(DEBUG_PLATFORM, "THREADX_TCP_readSocketAvailable: nx_tcp_socket_receive() returns ", nxStatus);
        goto exit;
    }

    /* figure out the length of the thing we received */
    nx_packet_length_get (pPacket, &packetLen);

    if (packetLen > maxBytesToRead)
    {
        /* we can assume if we are here that our buffer is empty */
        if (packetLen > THREADX_TCP_WINDOW_SIZE)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        /* our buffer is allocated and has enough bytes */
        if (NX_SUCCESS != nx_packet_data_retrieve( pPacket, pTcpIf->buffer, (ULONG*)&pTcpIf->used))
        {
            goto exit;
        }

        /* return from our buffer */
        if (OK > ( status = THREADX_TCP_getFromBuffer( pTcpIf, pBuffer,
                                                       maxBytesToRead, pNumBytesRead)))
        {
            goto exit;
        }
    }
    else
    {
        /* we can return the whole thing as is */
        if (NX_SUCCESS != nx_packet_data_retrieve(pPacket, pBuffer, (ULONG*)pNumBytesRead))
        {
            goto exit;
        }
    }

    status = OK;

exit:
    if (NULL != pPacket)
    {
        if (NX_SUCCESS != nx_packet_release(pPacket))
            status = ERR_TCP_READ_ERROR;
    }

    return status;

} /* THREADX_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                        ubyte4 *pNumBytesWritten)
{
    MSTATUS                 status = ERR_TCP_WRITE_ERROR;
    NX_PACKET*              pPacket = NULL;
    THREADX_TCP_interface*  pTcpIf = (THREADX_TCP_interface *)socket;

    if (NULL == pTcpIf)
        return ERR_NULL_POINTER;

    if (NX_SUCCESS != nx_packet_allocate(&mMocPacketPool, &pPacket, NX_TCP_PACKET, NX_NO_WAIT))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NX_SUCCESS != nx_packet_data_append(pPacket, (VOID *) pBuffer, numBytesToWrite, &mMocPacketPool, NX_NO_WAIT))
    {
        if (NULL != pPacket)
            nx_packet_release(pPacket);

        goto exit;
    }

    if (NX_SUCCESS != (status = nx_tcp_socket_send(pTcpIf->pTcpSocket, pPacket, NX_WAIT_FOREVER)))
    {
        status = ERR_TCP_WRITE_ERROR;
        goto exit;
    }

    *pNumBytesWritten = numBytesToWrite;

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *ipAddress, ubyte2 portNo)
{
    MSTATUS                 status = OK;
    UINT                    nxStatus;
    THREADX_TCP_interface*  pTcpIf = NULL;

    if ((NULL == pConnectSocket) || (NULL == ipAddress))
        return ERR_NULL_POINTER;

    *pConnectSocket = NULL;

    if (NULL == (pTcpIf = MALLOC(sizeof(THREADX_TCP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pTcpIf, 0x00, sizeof(THREADX_TCP_interface));

    if (NULL == (pTcpIf->pTcpSocket = MALLOC(sizeof(NX_TCP_SOCKET))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto error_cleanup;
    }

    DIGI_MEMSET((ubyte *)pTcpIf->pTcpSocket, 0x00, sizeof(NX_TCP_SOCKET));

    nxStatus =  nx_tcp_socket_create(&mMocIpInstance, pTcpIf->pTcpSocket, "clientTcpSocket",
                                      NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                                      THREADX_TCP_WINDOW_SIZE,
                                      NX_NULL, NX_NULL);

    if (NX_SUCCESS != nxStatus)
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto error_cleanup;
    }

    nxStatus = nx_tcp_client_socket_bind(pTcpIf->pTcpSocket, NX_ANY_PORT, NX_NO_WAIT);

    if (NX_SUCCESS != nxStatus)
    {
        status = ERR_TCP_CONNECT_CREATE;
        nx_tcp_socket_delete(pTcpIf->pTcpSocket);
        goto error_cleanup;
    }

    nxStatus = nx_tcp_client_socket_connect(pTcpIf->pTcpSocket, THREADX_inet_addr(ipAddress), portNo, NX_WAIT_FOREVER);

    if (NX_SUCCESS != nxStatus)
    {
        status = ERR_TCP_CONNECT_ERROR;
        nx_tcp_client_socket_unbind(pTcpIf->pTcpSocket);
        nx_tcp_socket_delete(pTcpIf->pTcpSocket);
        goto error_cleanup;
    }

    *pConnectSocket = (TCP_SOCKET)pTcpIf;
    goto exit;

error_cleanup:
    if (pTcpIf)
    {
        if (pTcpIf->pTcpSocket)
        {
            FREE(pTcpIf->pTcpSocket);
        }

        FREE(pTcpIf);
    }

exit:
    return status;
}

#endif /* __THREADX_TCP__ */

