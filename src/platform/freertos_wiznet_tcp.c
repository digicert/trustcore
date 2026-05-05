/*
 * FREERTOS_tcp.c
 *
 * FREERTOS TCP Abstraction Layer
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

#include "../common/moptions.h"

#ifdef __WIZNET_TCP__

#include "FREERTOS_Wiznet_sock.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#define _REENTRANT

#if !defined(__IAR_SYSTEMS_ICC__)
#include <sys/types.h>
#endif
#include <signal.h>

#include <stdio.h>
#include <signal.h>


sbyte get_socket_number() {
    for(ubyte i=0; i<_WIZCHIP_SOCK_NUM_; i++) {
        if(m_socketNumber[i] == 0) {
            m_socketNumber[i] = 1;
            return i;
        }
    }
    return FAIL;
}

sbyte clear_socket_number(ubyte socketNumber) {
    if(socketNumber < _WIZCHIP_SOCK_NUM_) {
        m_socketNumber[socketNumber] = 0;
        return socketNumber;
    }
    return FAIL;
}

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
    TCP_SOCKET          newSocket = FAIL;
    int                 nRet;
    MSTATUS             status  = OK;

    DB_PRINT("FREERTOS_TCP_listenSocket() portNumber = %d\r\n", portNumber);

    uint8_t socketNumber = 0;

    newSocket = socket(get_socket_number(), Sn_MR_TCP, portNumber, SF_TCP_NODELAY);
    socketNumber = newSocket;
    if( newSocket == FAIL )
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte*)"FREERTOS_TCP_listenSocket: Could not create listen socket");
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    if((nRet = listen(socketNumber)) == SOCK_OK) {
        while((nRet = getSn_SR(socketNumber)) == SOCK_LISTEN) {
            while(1) {
                if((nRet = getSn_SR(socketNumber)) == SOCK_ESTABLISHED) {
                    break;
                } else { /* Something went wrong with remote peer, maybe the connection was closed unexpectedly */
                    DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"FREERTOS_TCP_listenSocket: bind() error : ");
                    DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)"FREERTOS_TCP_listenSocket: bind() socket : ");
                    status = ERR_TCP_LISTEN_BIND_ERROR;
                    goto error_cleanup;
                }
            }
        }
    } else {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte*)"FREERTOS_TCP_listenSocket: listen() error: ", nRet);
        status = ERR_TCP_LISTEN_ERROR;
        goto error_cleanup;
    }

    *listenSocket = newSocket;
    DB_PRINT("New Listen Socket Created ...\r\n");
    goto exit;

    error_cleanup:
    FREERTOS_TCP_closeSocket(newSocket);

    exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_acceptSocket(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    DB_PRINT("FREERTOS_TCP_acceptSocket() on listen socket number %d\r\n", *clientSocket);
    MSTATUS             status          = OK;
    *clientSocket = listenSocket;
    return status;

} /* FREERTOS_TCP_acceptSocket */


uint32_t parseIPV4string(signed char* ipAddress, uint8_t *remoteIP) {

    int a, b, c, d;
    sscanf((const char *)ipAddress, "%d.%d.%d.%d", &a, &b, &c, &d);
    remoteIP[0] = ((uint8_t)a);
    remoteIP[1] = ((uint8_t)b);
    remoteIP[2] = ((uint8_t)c);
    remoteIP[3] = ((uint8_t)d);

    uint32_t retVal =  ((uint8_t)a) | ((uint8_t)b) << 8 | ((uint8_t)c) << 16 | ((uint8_t)d) << 24;
    return retVal;

}

/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    DB_PRINT("FREERTOS_TCP_connectSocket() = %s on port = %d\r\n", pIpAddress, portNo);
    MSTATUS             status = OK;
    int8_t socketNumber = FAIL;
    int retVal = 0;
    uint8_t remoteIP[4];

    socketNumber = get_socket_number();
    if( 0 > socketNumber) {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }
    *pConnectSocket = socket(socketNumber, Sn_MR_TCP, portNo, SF_TCP_NODELAY);
    if( *pConnectSocket != socketNumber )
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }

    /*
    retVal = setsockopt(socketNumber, SO_KEEPALIVESEND, NULL);
    retVal = ctlsocket(socketNumber, CS_SET_IOMODE , SOCK_IO_BLOCK);
    DB_PRINT("setsockopt return val = %d\r\n", retVal);
     */

    DB_PRINT("socket() created socket number = %d\r\n", *pConnectSocket);
    parseIPV4string(pIpAddress, remoteIP);
    retVal = connect(*pConnectSocket, (uint8_t  *)remoteIP, portNo);
    DB_PRINT("socket connect return val = %d\r\n", retVal);
    if (SOCK_OK  != retVal)
        status = ERR_TCP_CONNECT_ERROR;

    exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_closeSocket(TCP_SOCKET socket)
{
    DB_PRINT("FREERTOS_TCP_closeSocket() socket number = %d\r\n", socket);
    close(socket);
    clear_Socket_Number(socket);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer,
        ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    int             retValue;
    MSTATUS         status;

    DB_PRINT("xPortGetFreeHeapSize() = %d\r\n",xPortGetFreeHeapSize());
    DB_PRINT("FREERTOS_TCP_readSocketAvailable() socket number = %d & maxBytesToRead = %d\r\n", socket, maxBytesToRead);

    if ((NULL == pBuffer) || (NULL == pNumBytesRead))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (TCP_NO_TIMEOUT != msTimeout)
    {
        /* handle timeout case */
    }

    *pNumBytesRead = 0;

    retValue = recv(socket, (uint8_t *)pBuffer, maxBytesToRead);
    DB_PRINT("FREERTOS_TCP_readSocketAvailable() read bytes = %d\r\n", retValue);

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

    return status;

} /* FREERTOS_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
        ubyte4 *pNumBytesWritten)
{
    DB_PRINT("FREERTOS_TCP_writeSocket() socket number = %d & numBytesToWrite = %d\r\n", socket, numBytesToWrite);

    int     retValue;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    retValue = send(socket, (uint8_t *)pBuffer, numBytesToWrite);
    DB_PRINT("FREERTOS_TCP_writeSocket() retValue = %d\r\n", retValue);

    if (0 > retValue)
    {
        retValue = getSn_SR(socket);
        DB_PRINT("getSn_SR(socket) retValue = %d\r\n", retValue);

        retValue = 0;
        status = ERR_TCP_WRITE_ERROR;
        goto exit;
    } else {

        *pNumBytesWritten = retValue;
        status = OK;
    }
    exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_TCP_getPeerName(TCP_SOCKET socket, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr)
{
    MSTATUS                 status = OK;
    status = ERR_TCP_GETSOCKNAME;
    return status;
}


#endif /* __FREERTOS_TCP__ */
