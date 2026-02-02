/*
 * hpux_udp.c
 *
 * HP-UX UDP Abstraction Layer
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

#ifdef __HPUX_UDP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#define _REENTRANT

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

/* original */
#include <sys/ioctl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>


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

} HPUX_UDP_interface;


/*------------------------------------------------------------------*/

#ifndef SOCKET_ERROR
#define SOCKET_ERROR    (-1)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
HPUX_UDP_init(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HPUX_UDP_shutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HPUX_UDP_getInterfaceAddress(sbyte *pHostName, MOC_IP_ADDRESS_S *pRetIpAddress)
{
    /* for example code we just default to the primary interface */
    char            myHostName[255/*HOST_NAME_MAX*/];
    struct hostent* pHostAddr;
    MSTATUS         status = ERR_UDP_INTERFACE_NOT_FOUND;

    if (NULL == pHostName)
    {
        if (SOCKET_ERROR == gethostname(myHostName, sizeof(myHostName)))
            goto exit;

        pHostName = (sbyte *)myHostName;
    }

    if (NULL != (pHostAddr = gethostbyname((char *)pHostName)))
    {
        *pRetIpAddress = ntohl(*((MOC_IP_ADDRESS *)pHostAddr->h_addr));
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HPUX_UDP_getAddressOfHost(sbyte *pHostName, MOC_IP_ADDRESS_S *pRetIpAddress)
{
    MSTATUS status = ERR_UDP_HOSTNAME_NOT_FOUND;

    if (NULL != pHostName)
    {
        struct hostent *pHostAddr;

        if (NULL != (pHostAddr = gethostbyname((char *)pHostName)))
        {
            *pRetIpAddress = ntohl(*((MOC_IP_ADDRESS *)pHostAddr->h_addr));
            status = OK;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HPUX_UDP_bindConnect(void **ppRetUdpDescr,
                      MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                      MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                      intBoolean isNonBlocking, intBoolean connected)
{
    HPUX_UDP_interface*  pUdpIf = NULL;
    MSTATUS               status = ERR_UDP;

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

    /* allocate HPUX_UDP_interface */
    if (NULL == (pUdpIf = (HPUX_UDP_interface*) MALLOC(sizeof(HPUX_UDP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pUdpIf, 0x00, sizeof(HPUX_UDP_interface));

    /* handle socket source end-point */
    {
        struct sockaddr_in myAddr = { 0 };

        myAddr.sin_family = AF_INET;
        myAddr.sin_addr.s_addr = htonl(srcAddress);

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
    }

    if (connected)
    {
        /* handle socket destination end-point */
        pUdpIf->serverAddress.v4.sin_family = AF_INET;
        pUdpIf->serverAddress.v4.sin_addr.s_addr = htonl(dstAddress);
        pUdpIf->serverAddress.v4.sin_port = htons(dstPortNo);

        if (0 > connect(pUdpIf->udpFd, (struct sockaddr *)&(pUdpIf->serverAddress), sizeof(struct sockaddr_in)))
        {
            status = ERR_UDP_CONNECT;
            goto exit;
        }
    }

    if (FALSE != isNonBlocking)
    {
        int on = 1;

        if (-1 == ioctl(pUdpIf->udpFd, FIONBIO, &on))
        {
            status = ERR_UDP_SOCKET;
            goto exit;
        }
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
HPUX_UDP_connect(void **ppRetUdpDescr,
                  MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                  MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                  intBoolean isNonBlocking)
{
    return HPUX_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                               dstAddress, dstPortNo, isNonBlocking, TRUE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
HPUX_UDP_simpleBind(void **ppRetUdpDescr,
                     MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                     intBoolean isNonBlocking)
{
    return HPUX_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                               0, 0, isNonBlocking, FALSE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
HPUX_UDP_unbind(void **ppReleaseUdpDescr)
{
    HPUX_UDP_interface*    pUdpIf;
    MSTATUS                 status = ERR_NULL_POINTER;

    if (NULL == ppReleaseUdpDescr)
        goto exit;

    pUdpIf = *((HPUX_UDP_interface **)ppReleaseUdpDescr);

    /* de-allocate HPUX_UDP_interface */
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
HPUX_UDP_send(void *pUdpDescr, ubyte *pData, ubyte4 dataLength)
{
    HPUX_UDP_interface*    pUdpIf = (HPUX_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    if (0 > send(pUdpIf->udpFd, pData, dataLength, 0))
        status = ERR_UDP_WRITE;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HPUX_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress, ubyte2 peerPortNo,
                 ubyte *pData, ubyte4 dataLength)
{
    HPUX_UDP_interface*    pUdpIf = (HPUX_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    {
        struct sockaddr_in destAddress = { 0 };
        destAddress.sin_family = AF_INET;
        destAddress.sin_addr.s_addr = htonl(peerAddress);
        destAddress.sin_port = htons(peerPortNo);

        if (0 > sendto(pUdpIf->udpFd, (char *)pData, dataLength, 0,
                       (struct sockaddr *) &destAddress, sizeof(destAddress)))
        {
            status = ERR_UDP_WRITE;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HPUX_UDP_getFd(void *pUdpDescr, sbyte4 *fd)
{
    HPUX_UDP_interface*    pUdpIf = (HPUX_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    *fd = pUdpIf->udpFd;

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
HPUX_UDP_recv(void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    HPUX_UDP_interface*    pUdpIf = (HPUX_UDP_interface *)pUdpDescr;
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
HPUX_UDP_recvFrom(void *pUdpDescr, MOC_IP_ADDRESS_S *pPeerAddress, ubyte2* pPeerPortNo,
                   ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    HPUX_UDP_interface*      pUdpIf = (HPUX_UDP_interface *)pUdpDescr;
    int                     result;
    struct sockaddr_in      fromAddress = { 0 };
    int                     fromLen = sizeof(fromAddress);
    MSTATUS                 status = OK;

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
    *pPeerAddress = ntohl(fromAddress.sin_addr.s_addr);
    *pPeerPortNo = ntohs(fromAddress.sin_port);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HPUX_UDP_getSrcPortAddr(void *pUdpDescr, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr)
{
    HPUX_UDP_interface*    pUdpIf = (HPUX_UDP_interface *)pUdpDescr;
    struct sockaddr_in      myAddress;
    socklen_t               addrLen = sizeof(myAddress);
    MSTATUS                 status = OK;

    DIGI_MEMSET((ubyte *)&myAddress, 0x00, sizeof(myAddress));

    if (0 > getsockname(pUdpIf->udpFd, (struct sockaddr *)&myAddress, (socklen_t *)&addrLen))
    {
        status = ERR_UDP_GETSOCKNAME;
        goto exit;
    }

    *pRetPortNo = htons(myAddress.sin_port);
    *pRetAddr   = htonl(myAddress.sin_addr.s_addr);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HPUX_UDP_selReadAvl(void *ppUdpDescr[], sbyte4 numUdpDescr, ubyte4 msTimeout)
{
    MSTATUS         status = OK;

    fd_set*         pSocketList = NULL;
    struct timeval  timeout;
    int             ret;
    sbyte4          i;

    if (0 >= numUdpDescr) goto exit;

    if (NULL == ppUdpDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pSocketList = MALLOC(sizeof(fd_set))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* add the socket of interest to the list */
    FD_ZERO(pSocketList);

    for (i=0; i < numUdpDescr; i++)
    {
        HPUX_UDP_interface *pUdpIf = (HPUX_UDP_interface *) ppUdpDescr[i];
        if (NULL != pUdpIf)
        {
            FD_SET(pUdpIf->udpFd, pSocketList);
        }
    }

    /* compute timeout (milliseconds) */
    timeout.tv_sec  = msTimeout / 1000;
    timeout.tv_usec = (msTimeout % 1000) * 1000;    /* convert ms to us */

    /* Note: Windows ignores the first parameter '1' */
    /* other platforms may want (highest socket + 1) */
    ret = select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout);
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
        HPUX_UDP_interface *pUdpIf = (HPUX_UDP_interface *) ppUdpDescr[i];
        if (NULL != pUdpIf)
        {
            if (!FD_ISSET(pUdpIf->udpFd, pSocketList))
                ppUdpDescr[i] = NULL; /* !!! */
        }
    }

exit:
    if (NULL != pSocketList)
        FREE(pSocketList);

    return status;
}


#endif /* __HPUX_UDP__ */
