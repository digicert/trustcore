/*
 * deos_udp.c
 *
 * DDC-I DEOS UDP Abstraction Layer
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

#ifdef __DEOS_UDP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <deos.h>
#include <timeout.h>
#include <socketapi.h>
#include <lwip-socket.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>


static clientConnectionHandleType gUdpConnHandle;

/* define the following macros according to MTL configuration */
/* note: setupUDPTransport needs to be called from the same thread
 * where the connection is being handled
 */
#define DEOS_UDP_CONFIG_FILE    "mailbox-transport.config"
#define DEOS_UDP_CONFIG_ID      "transportConfigurationId"
#define DEOS_UDP_CONN_ID        "udpConnectionId"


/*------------------------------------------------------------------*/

typedef struct
{
    int        udpFd;
    union
    {
        struct sockaddr_in v4;
#ifdef __ENABLE_DIGICERT_IPV6__
        struct sockaddr_in6 v6;
#endif
    } serverAddress;

} DEOS_UDP_interface;


/*------------------------------------------------------------------*/

static int
setupUDPTransport(clientConnectionHandleType *connectionHandle, char* connectionId)
{
    int setupStatus, setupError;
    void * sendBuffer;
    DWORD bufferSizeInBytes;

    setupStatus = socketTransportInitialize(DEOS_UDP_CONFIG_FILE,
                    DEOS_UDP_CONFIG_ID, (DWORD)waitIndefinitely, &setupError);
    if (setupStatus != transportSuccess)
        goto exit;

    setupStatus = socketTransportClientInitialize((DWORD)waitIndefinitely, &setupError);
    if (setupStatus != transportSuccess)
        goto exit;

    setupStatus = socketTransportCreateConnection(connectionId,
                     (DWORD)waitIndefinitely, COMPATIBILITY_ID_2, connectionHandle,
                     &sendBuffer, &bufferSizeInBytes, &setupError);
    if (setupStatus != transportSuccess)
        goto exit;

    setupStatus = socketTransportSetConnectionForThread(currentThreadHandle(),
                    *connectionHandle, (DWORD)waitIndefinitely, &setupError);

exit:
    return setupStatus;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_UDP_init(void)
{
#ifdef DEOS_UDP_CONFIG_FILE
    if (transportSuccess != setupUDPTransport(&gUdpConnHandle, DEOS_UDP_CONN_ID))
    {
        return ERR_UDP;
    }
#endif

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_UDP_shutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
DEOS_UDP_bindConnect(void **ppRetUdpDescr,
                        MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                        MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                        intBoolean isNonBlocking, intBoolean connected)
{
    DEOS_UDP_interface*  pUdpIf = NULL;
    MSTATUS              status = ERR_UDP;
    struct sockaddr_in   myAddr = { 0 };

    MOC_UNUSED(isNonBlocking);

    if (NULL == ppRetUdpDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (connected && !dstAddress)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetUdpDescr = NULL;

    /* allocate DEOS_UDP_interface */
    if (NULL == (pUdpIf = (DEOS_UDP_interface*) MALLOC(sizeof(DEOS_UDP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pUdpIf, 0x00, sizeof(DEOS_UDP_interface));

    /* handle socket source end-point */
    myAddr.sin_family = AF_INET;
    myAddr.sin_addr = htonl(srcAddress);

    if (MOC_UDP_ANY_PORT != srcPortNo)
        myAddr.sin_port = htons(srcPortNo);

    if (0 > (pUdpIf->udpFd = socket(AF_INET, SOCK_DGRAM, 0)))
    {
        status = ERR_UDP_SOCKET;
        goto exit;
    }

    if (0 > bind(pUdpIf->udpFd, (struct sockaddr *)&myAddr, sizeof(myAddr)))
    {
        status = ERR_UDP_BIND;
        goto exit;
    }

    if (connected)
    {
        /* handle socket destination end-point */
        pUdpIf->serverAddress.v4.sin_family = AF_INET;
        pUdpIf->serverAddress.v4.sin_addr = htonl(dstAddress);
        pUdpIf->serverAddress.v4.sin_port = htons(dstPortNo);

        if (0 > connect(pUdpIf->udpFd, (struct sockaddr *)&(pUdpIf->serverAddress), sizeof(struct sockaddr_in)))
        {
            status = ERR_UDP_CONNECT;
            goto exit;
        }
    }

    *ppRetUdpDescr = pUdpIf;  pUdpIf = NULL;

    status = OK;

exit:
    if (NULL != pUdpIf)
    {
        if (0 != pUdpIf)
            closesocket(pUdpIf->udpFd);

        FREE(pUdpIf);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_UDP_connect(void **ppRetUdpDescr,
                  MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                  MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                  intBoolean isNonBlocking)
{
    return DEOS_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                               dstAddress, dstPortNo, isNonBlocking, TRUE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_UDP_simpleBind(void **ppRetUdpDescr,
                   MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                   intBoolean isNonBlocking)
{
    return DEOS_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                               0, 0, isNonBlocking, FALSE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_UDP_unbind(void **ppReleaseUdpDescr)
{
    DEOS_UDP_interface*  pUdpIf;
    MSTATUS             status = ERR_NULL_POINTER;

    if (NULL == ppReleaseUdpDescr)
        goto exit;

    pUdpIf = *((DEOS_UDP_interface **)ppReleaseUdpDescr);

    /* de-allocate DEOS_UDP_interface */
    if (NULL != pUdpIf)
    {
        if (0 != pUdpIf)
            closesocket(pUdpIf->udpFd);

        FREE(pUdpIf);
    }

    *ppReleaseUdpDescr = NULL;

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_UDP_send(void *pUdpDescr, ubyte *pData, ubyte4 dataLength)
{
    DEOS_UDP_interface*  pUdpIf = (DEOS_UDP_interface *)pUdpDescr;
    MSTATUS             status = OK;

    if (0 > send(pUdpIf->udpFd, (char *)pData, dataLength, 0))
        status = ERR_UDP_WRITE;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress, ubyte2 peerPortNo,
                   ubyte *pData, ubyte4 dataLength)
{
    DEOS_UDP_interface*    pUdpIf = (DEOS_UDP_interface *)pUdpDescr;
    MSTATUS                status = OK;
    struct sockaddr_in     destAddress = { 0 };

    destAddress.sin_family = AF_INET;
    destAddress.sin_addr = htonl(peerAddress);
    destAddress.sin_port = htons(peerPortNo);

    if (0 > sendto(pUdpIf->udpFd, (char *)pData, dataLength, 0,
                   (struct sockaddr *) &destAddress, sizeof(destAddress)))
    {
        status = ERR_UDP_WRITE;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_UDP_recv(void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    DEOS_UDP_interface*  pUdpIf = (DEOS_UDP_interface *)pUdpDescr;
    int                  result;
    MSTATUS              status = OK;

    *pRetDataLength = 0;

    result = recv(pUdpIf->udpFd, (char *)pBuf, bufSize, 0);

    if (SOCKET_ERROR == result)
    {
        if (EAGAIN != errno)
             status = ERR_UDP_READ;
    }
    else *pRetDataLength = (ubyte4)result;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_UDP_recvFrom(void *pUdpDescr, MOC_IP_ADDRESS_S *pPeerAddress, ubyte2* pPeerPortNo,
                     ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    DEOS_UDP_interface*     pUdpIf = (DEOS_UDP_interface *)pUdpDescr;
    int                     result;
    MSTATUS                 status = OK;
    struct sockaddr_in      fromAddress = { 0 };
    int                     fromLen = sizeof(fromAddress);

    *pRetDataLength = 0;

    result = recvfrom(pUdpIf->udpFd, (char *)pBuf, bufSize, 0,
                      (struct sockaddr *) &fromAddress, (socklen_t *)&fromLen);

    if (SOCKET_ERROR == result)
    {
        if (EAGAIN != errno)
            status = ERR_UDP_READ;

        goto exit;
    }

    *pRetDataLength = (ubyte4)result;
    *pPeerAddress = ntohl(fromAddress.sin_addr);
    *pPeerPortNo = ntohs(fromAddress.sin_port);

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_UDP_getSrcPortAddr(void *pUdpDescr, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr)
{
    DEOS_UDP_interface*    pUdpIf = (DEOS_UDP_interface *)pUdpDescr;
    struct sockaddr_in     myAddress;
    sbyte4                 addrLen = sizeof(myAddress);
    MSTATUS                status = OK;

    DIGI_MEMSET((ubyte *)&myAddress, 0x00, sizeof(myAddress));

    if (0 > getsockname(pUdpIf->udpFd, (struct sockaddr *)&myAddress,
                        (socklen_t *)&addrLen))
    {
        status = ERR_UDP_GETSOCKNAME;
        goto exit;
    }

    *pRetPortNo = htons(myAddress.sin_port);
    *pRetAddr   = htonl(myAddress.sin_addr);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DEOS_UDP_selReadAvl(void *ppUdpDescr[], sbyte4 numUdpDescr,
                    ubyte4 msTimeout)
{
    MSTATUS         status = OK;
    fd_set          socketList;
    struct timeval  timeout;
    int             ret;
    sbyte4          i;

    if (0 >= numUdpDescr) goto exit;

    if (NULL == ppUdpDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* add the socket of interest to the list */
    FD_ZERO(&socketList);

    for (i=0; i < numUdpDescr; i++)
    {
        DEOS_UDP_interface *pUdpIf = (DEOS_UDP_interface *) ppUdpDescr[i];
        if (NULL != pUdpIf)
        {
            FD_SET(pUdpIf->udpFd, &socketList);
        }
    }

    /* compute timeout (milliseconds) */
    timeout.tv_sec  = msTimeout / 1000;
    timeout.tv_usec = (msTimeout % 1000) * 1000;    /* convert ms to us */

    /* Note: Windows ignores the first parameter '1' */
    /* other platforms may want (highest socket + 1) */
    ret = select(FD_SETSIZE, &socketList, NULL, NULL, &timeout);
    if (0 == ret) /* timed out */
    {
        status = ERR_UDP_READ_TIMEOUT;
        goto exit;
    }
    if (SOCKET_ERROR == ret)
    {
        status = ERR_UDP_READ;
        goto exit;
    }

    for (i=0; i < numUdpDescr; i++)
    {
        DEOS_UDP_interface *pUdpIf = (DEOS_UDP_interface *) ppUdpDescr[i];
        if (NULL != pUdpIf)
        {
            if (!FD_ISSET(pUdpIf->udpFd, &socketList))
                ppUdpDescr[i] = NULL; /* !!! */
        }
    }

exit:

    return status;
}
#endif /* __DEOS_UDP__ */

