/*
 * irix_udp.c
 *
 * IRIX UDP Abstraction Layer
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

#ifdef __IRIX_UDP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>


/*------------------------------------------------------------------*/

typedef struct
{
    int        udpFd;
    struct sockaddr_in  serverAddress;
    ubyte2              lclPort;

} IRIX_UDP_interface;


/*------------------------------------------------------------------*/

#ifndef SOCKET_ERROR
#define SOCKET_ERROR    (-1)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IRIX_UDP_init(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
IRIX_UDP_shutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
IRIX_UDP_getInterfaceAddress(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress)
{
    MSTATUS status = OK;

    *pRetIpAddress = ntohl(INADDR_ANY);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
IRIX_UDP_getAddressOfHost(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress)
{
    MSTATUS status = ERR_UDP_HOSTNAME_NOT_FOUND;

    if (NULL != pHostName)
    {
        struct hostent *pHostAddr;

        if (NULL != (pHostAddr = gethostbyname(pHostName)))
        {
            *pRetIpAddress = ntohl(*((MOC_IP_ADDRESS *)pHostAddr->h_addr));
            status = OK;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
IRIX_UDP_bindConnect(void **ppRetUdpDescr,
                    MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                    MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                    intBoolean isNonBlocking, intBoolean connected)
{
    IRIX_UDP_interface*  pUdpIf = NULL;
    struct sockaddr_in      myAddr;
    MSTATUS                 status = ERR_UDP;

    if (NULL == ppRetUdpDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetUdpDescr = NULL;

    /* allocate IRIX_UDP_interface */
    if (NULL == (pUdpIf = MALLOC(sizeof(IRIX_UDP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pUdpIf, 0x00, sizeof(IRIX_UDP_interface));
    DIGI_MEMSET((ubyte *)&myAddr, 0x00, sizeof(struct sockaddr_in));

    /* handle socket source end-point */
    myAddr.sin_family = AF_INET;
    myAddr.sin_addr.s_addr = htonl(srcAddress);

    if (MOC_UDP_ANY_PORT == srcPortNo)
        myAddr.sin_port = 0;
    else
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

    if (FALSE != connected)
    {
        /* handle socket destination end-point */
        pUdpIf->serverAddress.sin_family = AF_INET;
        pUdpIf->serverAddress.sin_addr.s_addr = htonl(dstAddress);
        pUdpIf->serverAddress.sin_port = htons(dstPortNo);

        if (0 > connect(pUdpIf->udpFd, (struct sockaddr *)&(pUdpIf->serverAddress), sizeof(pUdpIf->serverAddress)))
        {
            status = ERR_UDP_CONNECT;
            goto exit;
        }
    }

    if (FALSE != isNonBlocking)
    {
        unsigned long flags;

        if (-1 == (flags = fcntl(pUdpIf->udpFd, F_GETFL, 0)))
            flags = 0;

        fcntl(pUdpIf->udpFd, F_SETFL, flags | O_NONBLOCK);
    }

    *ppRetUdpDescr = pUdpIf;  pUdpIf = NULL;

    status = OK;

exit:
    if (NULL != pUdpIf)
    {
        if (0 != pUdpIf)
            close(pUdpIf->udpFd);

        FREE(pUdpIf);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
IRIX_UDP_connect(void **ppRetUdpDescr,
                  MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                  MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                  intBoolean isNonBlocking)
{
    return IRIX_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                               dstAddress, dstPortNo, isNonBlocking, TRUE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
IRIX_UDP_simpleBind(void **ppRetUdpDescr,
                   MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                   intBoolean isNonBlocking)
{
    return IRIX_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                               0, 0, isNonBlocking, FALSE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
IRIX_UDP_unbind(void **ppReleaseUdpDescr)
{
    IRIX_UDP_interface*  pUdpIf;
    MSTATUS                 status = ERR_NULL_POINTER;

    if (NULL == ppReleaseUdpDescr)
        goto exit;

    pUdpIf = *((IRIX_UDP_interface **)ppReleaseUdpDescr);

    /* de-allocate IRIX_UDP_interface */
    if (NULL != pUdpIf)
    {
        if (0 != pUdpIf)
            close(pUdpIf->udpFd);

        FREE(pUdpIf);
    }

    *ppReleaseUdpDescr = NULL;

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
IRIX_UDP_send(void *pUdpDescr, ubyte *pData, ubyte4 dataLength)
{
    IRIX_UDP_interface*  pUdpIf = (IRIX_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    if (0 > send(pUdpIf->udpFd, (char *)pData, dataLength, 0))
        status = ERR_UDP_WRITE;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
IRIX_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress, ubyte2 peerPortNo,
               ubyte *pData, ubyte4 dataLength)
{
    IRIX_UDP_interface*  pUdpIf = (IRIX_UDP_interface *)pUdpDescr;
    struct sockaddr_in      destAddress;
    MSTATUS                 status = OK;

    destAddress.sin_family = AF_INET;
    destAddress.sin_addr.s_addr = htonl(peerAddress);
    destAddress.sin_port = htons(peerPortNo);

    if (0 > sendto(pUdpIf->udpFd, (char *)pData, dataLength, 0,
                   (struct sockaddr *)&destAddress, sizeof(destAddress)))
    {
        status = ERR_UDP_WRITE;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
IRIX_UDP_recv(void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    IRIX_UDP_interface*  pUdpIf = (IRIX_UDP_interface *)pUdpDescr;
    ssize_t                 result;
    MSTATUS                 status = OK;

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
IRIX_UDP_recvFrom(void *pUdpDescr, MOC_IP_ADDRESS* pPeerAddress, ubyte2* pPeerPortNo,
                 ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    IRIX_UDP_interface*  pUdpIf = (IRIX_UDP_interface *)pUdpDescr;
    int                     result;
    struct sockaddr_in      fromAddress;
    int                     fromLen = sizeof(fromAddress);
    MSTATUS                 status = OK;

    *pRetDataLength = 0;

    result = recvfrom(pUdpIf->udpFd, (char *)pBuf, bufSize, 0,
                     (struct sockaddr *) &fromAddress, &fromLen);

    if (SOCKET_ERROR == result)
    {
        if (EAGAIN != errno)
            status = ERR_UDP_READ;

        goto exit;
    }

    *pRetDataLength = (ubyte4)result;
    *pPeerAddress = ntohl(fromAddress.sin_addr.s_addr);
    *pPeerPortNo = ntohs(fromAddress.sin_port);

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
IRIX_UDP_getSrcPortAddr(void *pUdpDescr, ubyte2 *pRetPortNo, MOC_IP_ADDRESS *pRetAddr)
{
    IRIX_UDP_interface*  pUdpIf = (IRIX_UDP_interface *)pUdpDescr;
    struct sockaddr_in      myAddress;
    sbyte4                  addrLen = sizeof(struct sockaddr_in);
    MSTATUS                 status = OK;

    DIGI_MEMSET((ubyte *)&myAddress, 0, sizeof(myAddress));

    if (0 > getsockname(pUdpIf->udpFd, (struct sockaddr *)&myAddress,
                        (socklen_t *)&addrLen))
    {
        status = ERR_UDP_GETSOCKNAME;
        goto exit;
    }

    *pRetPortNo = htons(myAddress.sin_port);
    *pRetAddr   = htonl(myAddress.sin_addr.s_addr);

exit:
    return status;
}

#endif /* __IRIX_UDP__ */

