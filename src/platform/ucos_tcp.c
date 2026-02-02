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

#include "../common/moptions.h"

#ifdef __UCOS_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/moc_net.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <net_sock.h>

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
    saServer.Addr       = NET_UTIL_HOST_TO_NET_32(NET_SOCK_ADDR_IP_WILD_CARD);
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
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket,
                      intBoolean *isBreakSignalRequest)
{
    NET_SOCK_ADDR_LEN   nLen;
    NET_SOCK_ADDR       sockAddr;
    TCP_SOCKET          newClientSocket;
    NET_ERR             err;
    MSTATUS             status = OK;

    nLen = sizeof(sockAddr);
    newClientSocket = NetSock_Accept((NET_SOCK_ID)listenSocket, &sockAddr, &nLen, &err);

    if (NET_SOCK_ERR_NONE == err)
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
UCOS_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    NET_IP_ADDR     serverIpAddress;
    NET_SOCK_ADDR   serverAddr;
    NET_ERR         err;
    MSTATUS         status = OK;

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

    Mem_Clr((void *)&serverAddr, sizeof(serverAddr));
    serverAddr.AddrFamily = NET_SOCK_ADDR_FAMILY_IP_V4;
    serverAddr.Addr       = NET_UTIL_HOST_TO_NET_32(serverIpAddress);
    serverAddr.Port       = NET_UTIL_HOST_TO_NET_16(portNo);

    conn_rtn_code = NetSock_Conn((NET_SOCK_ID)*pConnectSocket, &serverAddr, sizeof(serverAddr), &err);

    if (NET_SOCK_ERR_NONE != err)
    {
        status = ERR_TCP_CONNECT_ERROR;
        NetSock_Close(*pConnectSocket, &err);
        goto exit;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_TCP_closeSocket(TCP_SOCKET socket)
{
    NET_ERR err;

    NetSock_Close(socket, &err);

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UCOS_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead,
                              ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    NET_SOCK_RTN_CODE   retValue;
    NET_ERR             err;
    MSTATUS             status;

    if ((NULL == pBuffer) || (NULL == pNumBytesRead))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if 0
    /* bummer! doesn't look like the TCP/IP stack supports select() or any other timeout mechanism for receives */
    if (TCP_NO_TIMEOUT != msTimeout)
    {
    }
#endif

    *pNumBytesRead = 0;

    retValue = NetSock_RxData(socket, (char *)pBuffer, maxBytesToRead, NET_SOCK_FLAG_NONE, &err);

    if (NET_SOCK_ERR_NONE != err)
    {
        status = ERR_TCP_READ_ERROR;
        goto exit;
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
    int     retValue;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    retValue = (int)NetSock_TxData(socket, pBuffer, numBytesToWrite, NET_SOCK_FLAG_NONE, &err);

    if (NET_SOCK_ERR_NONE != err)
    {
        status = ERR_TCP_READ_ERROR;
        goto exit;
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
