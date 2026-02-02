/*
 * ucos_tcp.c
 *
 * uC-OS TCP Abstraction Layer
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

/* Note: This file is not built as part of the standard Mocana DSF build process,
regardless of whether __UCOS_DIRECT_RTOS__ is defined or not.

It is part of the uC-OS support that is only built by using the Micrium supplied
application project files. */

#include "../common/moptions.h"

#ifdef __UCOS_DIRECT_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/moc_net.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"


#include <net.h>


#ifndef SOMAXCONN
#define SOMAXCONN       (10)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_TCP_init(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_TCP_shutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
#if 0
    TCP_SOCKET          newSocket;
    NET_SOCK_ADDR_IP    saServer;
    NET_ERR             err;

    newSocket = NetSock_Open(NET_SOCK_ADDR_FAMILY_IP_V4, NET_SOCK_TYPE_STREAM,
                             NET_SOCK_PROTOCOL_TCP, &err);

    if (NET_SOCK_ERR_NONE != err)
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"Could not create listen socket");
        return ERR_TCP_LISTEN_SOCKET_ERROR;
    }

    Mem_Clr((void *)&saServer, sizeof(saServer));

    saServer.AddrFamily = NET_SOCK_ADDR_FAMILY_IP_V4;
    saServer.Addr       = NET_UTIL_HOST_TO_NET_32(NET_SOCK_ADDR_IP_WILDCARD);
    saServer.Port       = NET_UTIL_HOST_TO_NET_16(portNumber);

    NetSock_Bind((NET_SOCK_ID)newSocket, (NET_SOCK_ADDR *)&saServer, (NET_SOCK_ADDR_LEN)NET_SOCK_ADDR_SIZE, &err);

    if (NET_SOCK_ERR_NONE != err)
    {
        NetSock_Close(newSocket, &err);
        return ERR_TCP_LISTEN_ERROR;
    }

    NetSock_Listen(newSocket, SOMAXCONN, &err);

    if (NET_SOCK_ERR_NONE != err)
    {
        NetSock_Close(newSocket, &err);
        return ERR_TCP_LISTEN_ERROR;
    }

    *listenSocket = newSocket;

    return OK;
#else
    // This function is not available using the Micrium NetSecure layer
    return ERR_TCP_LISTEN_SOCKET_ERROR;
#endif
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket,
                      intBoolean *isBreakSignalRequest)
{
#if 0
    NET_SOCK_ADDR_LEN   nLen;
    NET_SOCK_ADDR       sockAddr;
    TCP_SOCKET          newClientSocket;
    NET_ERR             err;
    MSTATUS             status = OK;

    nLen = sizeof(sockAddr);
    newClientSocket = NetSock_Accept((NET_SOCK_ID)listenSocket, &sockAddr, &nLen, &err);

    if (NET_SOCK_ERR_NONE != err)
    {
        status = ERR_TCP_ACCEPT_ERROR;
        goto exit;
    }

    *clientSocket = newClientSocket;

exit:
    return status;
#else
    // This function is not available using the Micrium NetSecure layer
    return ERR_TCP_ACCEPT_ERROR;
#endif
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
#if 0
    NET_IP_ADDR     serverIpAddress;
    NET_SOCK_ADDR_IP   serverAddr;
    NET_ERR         err;
    MSTATUS         status = OK;
    NET_SOCK_RTN_CODE conn_rtn_code;

    *pConnectSocket = NetSock_Open(NET_SOCK_ADDR_FAMILY_IP_V4, NET_SOCK_TYPE_STREAM, NET_SOCK_PROTOCOL_TCP, &err);

    if (NET_SOCK_ERR_NONE != err)
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }

    serverIpAddress = NetASCII_Str_to_IP(pIpAddress, &err);

    if (NET_ASCII_ERR_NONE != err)
    {
        status = ERR_TCP_CONNECT_CREATE;
        NetSock_Close(*pConnectSocket, &err);
        goto exit;
    }

    Mem_Clr((void *)&serverAddr, (CPU_SIZE_T) NET_SOCK_ADDR_SIZE);
    serverAddr.AddrFamily = NET_SOCK_ADDR_FAMILY_IP_V4;
    serverAddr.Addr       = NET_UTIL_HOST_TO_NET_32(serverIpAddress);
    serverAddr.Port       = NET_UTIL_HOST_TO_NET_16(portNo);

    conn_rtn_code = NetSock_Conn((NET_SOCK_ID)*pConnectSocket, (NET_SOCK_ADDR*)&serverAddr, sizeof(serverAddr), &err);

    if (NET_SOCK_BSD_ERR_NONE != conn_rtn_code)
    {
        status = ERR_TCP_CONNECT_ERROR;
        NetSock_Close(*pConnectSocket, &err);
        goto exit;
    }

exit:
    return status;
#else
    // This function is not available using the Micrium NetSecure layer
    return ERR_TCP_CONNECT_ERROR;
#endif
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_TCP_closeSocket(TCP_SOCKET socket)
{
#if 0
    NET_ERR err;

    NetSock_Close(socket, &err);

    return OK;
#else
    // This function is not available using the Micrium NetSecure layer
    return ERR_TCP_SOCKET_CLOSED;
#endif
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead,
                              ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    NET_SOCK_RTN_CODE   retValue;
    NET_ERR             err;
    MSTATUS             status;
    NET_SOCK            *p_sock;  // gy: socket is a NET_SOCK pointer
    NET_SOCK_ID         sock_id;
    CPU_BOOLEAN         block;

    if ((NULL == pBuffer) || (NULL == pNumBytesRead))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == socket) {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    p_sock = (NET_SOCK*)socket;
    sock_id = p_sock->ID;

	NetSock_IsUsed(sock_id, &err);
    if (err !=  NET_SOCK_ERR_NONE) {
        SSL_TRACE_DBG(("%s: sock id %d shows up as not in use\n", __FUNCTION__, sock_id));
		status = ERR_TCP_NO_SUCH_SOCKET;
		goto exit;
    }

    *pNumBytesRead = 0;

    retValue =  NetSock_RxDataHandlerStream((NET_SOCK_ID        ) sock_id,
                                            (NET_SOCK          *) p_sock,
                                            (void              *) pBuffer,
                                            (CPU_INT16U         ) maxBytesToRead,
                                            (NET_SOCK_API_FLAGS ) NET_SOCK_FLAG_NONE,
                                            (NET_SOCK_ADDR     *) 0,
                                            (NET_SOCK_ADDR_LEN *) 0,
                                            (NET_ERR           *)&err);

	if (1 == retValue) {
		*pNumBytesRead = 1;
	}

    switch (err) {
        case NET_SOCK_ERR_NONE:
             break;


        case NET_SOCK_ERR_CLOSED:
             return ERR_TCP_SOCKET_CLOSED;


        case NET_ERR_RX:
             block = DEF_BIT_IS_SET(p_sock->Flags, NET_SOCK_FLAG_SOCK_NO_BLOCK);
             if(block == DEF_YES) {
                 return ERR_TCP_READ_BLOCK_FAIL;
             }
             return ERR_TCP_READ_ERROR;
             break;


		case NET_SOCK_ERR_RX_Q_EMPTY:
        case NET_SOCK_ERR_RX_Q_CLOSED:
        case NET_SOCK_ERR_NOT_USED:
        case NET_SOCK_ERR_FAULT:
        case NET_SOCK_ERR_CONN_FAIL:
        case NET_SOCK_ERR_INVALID_FAMILY:
        case NET_SOCK_ERR_INVALID_PROTOCOL:
        case NET_SOCK_ERR_INVALID_STATE:
        case NET_SOCK_ERR_INVALID_OP:
        case NET_SOCK_ERR_INVALID_ADDR_LEN:
        case NET_CONN_ERR_INVALID_CONN:
        case NET_CONN_ERR_NOT_USED:
        case NET_CONN_ERR_NULL_PTR:
        case NET_CONN_ERR_INVALID_ADDR_LEN:
        case NET_CONN_ERR_ADDR_NOT_USED:
        default:
			 SSL_TRACE_DBG(("%s: net_err is %d\n", __FUNCTION__, err));
             return ERR_TCP_READ_ERROR;
    }

    *pNumBytesRead = retValue;
    status = OK;

exit:
    return status;

} /* UCOS_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                     ubyte4 *pNumBytesWritten)
{
    int         retValue;
    MSTATUS     status;
    NET_ERR     err;
    NET_SOCK    *p_sock;  // socket is a NET_SOCK pointer
    NET_SOCK_ID sock_id;
    CPU_BOOLEAN block;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == socket) {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    p_sock = (NET_SOCK*)socket;
    sock_id = p_sock->ID;

    retValue =  NetSock_TxDataHandlerStream((NET_SOCK_ID       ) sock_id,
                                            (NET_SOCK         *) p_sock,
                                            (void             *) pBuffer,
                                            (CPU_INT16U        ) numBytesToWrite,
                                            (NET_SOCK_API_FLAGS) NET_SOCK_FLAG_NONE,
                                            (NET_ERR          *)&err);

    switch (err) {
        case NET_SOCK_ERR_NONE:
             break;

        case NET_SOCK_ERR_CLOSED:
             return ERR_TCP_SOCKET_CLOSED;

        case NET_ERR_TX:
             block = DEF_BIT_IS_CLR(p_sock->Flags, NET_SOCK_FLAG_SOCK_NO_BLOCK);
             if(block == DEF_YES) {
                 return ERR_TCP_WRITE_BLOCK_FAIL;
             }
             return ERR_TCP_WRITE_ERROR;

        case NET_SOCK_ERR_NOT_USED:
        case NET_SOCK_ERR_FAULT:
        case NET_SOCK_ERR_CONN_FAIL:
        case NET_SOCK_ERR_INVALID_PROTOCOL:
        case NET_SOCK_ERR_INVALID_STATE:
        case NET_SOCK_ERR_INVALID_OP:
        case NET_SOCK_ERR_INVALID_DATA_SIZE :
        case NET_SOCK_ERR_TX_Q_CLOSED:
        case NET_SOCK_ERR_LINK_DOWN:
        case NET_CONN_ERR_INVALID_CONN:
        case NET_CONN_ERR_NOT_USED:   
        default:
             return ERR_TCP_WRITE_ERROR;
    }

    *pNumBytesWritten = retValue;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_TCP_getPeerName(TCP_SOCKET socket, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr)
{
    /* doesn't look like APIs are available to get at the connection data... */
    return ERR_TCP_GETSOCKNAME;
}


#endif /* __UCOS_TCP__ */
