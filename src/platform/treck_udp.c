/*
 * Treck UDP Abstraction Layer
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

#ifdef __TRECK_UDP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <trsocket.h>


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

} TRECK_UDP_interface;


/*------------------------------------------------------------------*/

#ifndef SOCKET_ERROR
#define SOCKET_ERROR    (-1)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
TRECK_UDP_init(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
TRECK_UDP_shutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

#define MAKE_IP_ADDRESS(A,B,C,D)    (((A) << 24) || ((B) << 16) || ((C) << 8) || (D))

extern MSTATUS
TRECK_UDP_getInterfaceAddress(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress)
{
    /* need to customize this... */
    *pRetIpAddress = ntohl(MAKE_IP_ADDRESS(192,168,0,100));

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
TRECK_UDP_getAddressOfHost(sbyte *pHostName, MOC_IP_ADDRESS_S *pRetIpAddress)
{
    MSTATUS status = ERR_UDP_HOSTNAME_NOT_FOUND;

    if (NULL != pHostName)
    {
        ttUserIpAddress hostAddr;

        if (0 <= tfDnsGetHostByName((char *)pHostName, &hostAddr))
        {
            *pRetIpAddress = ntohl(hostAddr);
            status = OK;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
TRECK_UDP_bindConnect(void **ppRetUdpDescr,
                      MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                      MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                      intBoolean isNonBlocking, intBoolean connected)
{
    TRECK_UDP_interface*  pUdpIf = NULL;
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

    /* allocate TRECK_UDP_interface */
    if (NULL == (pUdpIf = MALLOC(sizeof(TRECK_UDP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pUdpIf, 0x00, sizeof(TRECK_UDP_interface));

    /* handle socket source end-point */
#ifdef __ENABLE_DIGICERT_IPV6__
    if ((srcAddress && (AF_INET6 == srcAddress->family)) ||
        (!srcAddress && dstAddress && (AF_INET6 == dstAddress->family)))
    {
        struct sockaddr_in6 myAddr;
        DIGI_MEMSET((ubyte *)&myAddr, 0x00, sizeof(struct sockaddr_in6));

        myAddr.sin6_family = AF_INET6;

        if (MOC_UDP_ANY_PORT == srcPortNo)
            myAddr.sin6_port = 0;
        else
            myAddr.sin6_port = htons(srcPortNo);

        if (srcAddress)
            DIGI_MEMCPY(myAddr.sin6_addr.s6_addr, srcAddress->uin.addr6, 16);

        if (0 > (pUdpIf->udpFd = socket(AF_INET6, SOCK_DGRAM, 0)))
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
    else
#endif
    {
        struct sockaddr_in myAddr;
        DIGI_MEMSET((ubyte *)&myAddr, 0x00, sizeof(struct sockaddr_in));

        myAddr.sin_family = AF_INET;
#ifdef __ENABLE_DIGICERT_IPV6__
        if (srcAddress)
            myAddr.sin_addr.s_addr = htonl(srcAddress->uin.addr);
#else
        myAddr.sin_addr.s_addr = htonl(srcAddress);
#endif
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
    }

    if (FALSE != connected)
    {
        /* handle socket destination end-point */
#ifdef __ENABLE_DIGICERT_IPV6__
        if (AF_INET6 == dstAddress->family)
        {
            pUdpIf->serverAddress.v6.sin6_family = AF_INET6;
            pUdpIf->serverAddress.v6.sin6_port = htons(dstPortNo);
            DIGI_MEMCPY(pUdpIf->serverAddress.v6.sin6_addr.s6_addr, dstAddress->uin.addr6, 16);

            if (0 > connect(pUdpIf->udpFd, (struct sockaddr *)&(pUdpIf->serverAddress), sizeof(struct sockaddr_in6)))
            {
                status = ERR_UDP_CONNECT;
                goto exit;
            }
        }
        else
#endif
        {
            pUdpIf->serverAddress.v4.sin_family = AF_INET;
#ifdef __ENABLE_DIGICERT_IPV6__
            pUdpIf->serverAddress.v4.sin_addr.s_addr = htonl(dstAddress->uin.addr);
#else
            pUdpIf->serverAddress.v4.sin_addr.s_addr = htonl(dstAddress);
#endif
            pUdpIf->serverAddress.v4.sin_port = htons(dstPortNo);

            if (0 > connect(pUdpIf->udpFd, (struct sockaddr *)&(pUdpIf->serverAddress), sizeof(struct sockaddr_in)))
            {
                status = ERR_UDP_CONNECT;
                goto exit;
            }
        }
    }

    if (FALSE != isNonBlocking)
    {
        int on = 1;

        if (-1 == tfIoctl(pUdpIf->udpFd, FIONBIO, &on))
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
TRECK_UDP_connect(void **ppRetUdpDescr,
                  MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                  MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                  intBoolean isNonBlocking)
{
    return TRECK_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                                 dstAddress, dstPortNo, isNonBlocking, TRUE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
TRECK_UDP_simpleBind(void **ppRetUdpDescr,
                     MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                     intBoolean isNonBlocking)
{
    return TRECK_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                                 0, 0, isNonBlocking, FALSE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
TRECK_UDP_unbind(void **ppReleaseUdpDescr)
{
    TRECK_UDP_interface*    pUdpIf;
    MSTATUS                 status = ERR_NULL_POINTER;

    if (NULL == ppReleaseUdpDescr)
        goto exit;

    pUdpIf = *((TRECK_UDP_interface **)ppReleaseUdpDescr);

    /* de-allocate TRECK_UDP_interface */
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
TRECK_UDP_send(void *pUdpDescr, ubyte *pData, ubyte4 dataLength)
{
    TRECK_UDP_interface*    pUdpIf = (TRECK_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    if (0 > send(pUdpIf->udpFd, (const char *)pData, (int)dataLength, 0))
        status = ERR_UDP_WRITE;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
TRECK_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress, ubyte2 peerPortNo,
                 ubyte *pData, ubyte4 dataLength)
{
    TRECK_UDP_interface*    pUdpIf = (TRECK_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == peerAddress->family)
    {
        struct sockaddr_in6 destAddress;

        destAddress.sin6_family = AF_INET6;
        destAddress.sin6_port = htons(peerPortNo);
        DIGI_MEMCPY(destAddress.sin6_addr.s6_addr, peerAddress->uin.addr6, 16);

        if (0 > sendto(pUdpIf->udpFd, (char *)pData, dataLength, 0,
                       (struct sockaddr *) &destAddress, sizeof(destAddress)))
        {
            status = ERR_UDP_WRITE;
        }
    }
    else
#endif
    {
        struct sockaddr_in destAddress;

        destAddress.sin_family = AF_INET;
#ifdef __ENABLE_DIGICERT_IPV6__
        destAddress.sin_addr.s_addr = htonl(peerAddress->uin.addr);
#else
        destAddress.sin_addr.s_addr = htonl(peerAddress);
#endif
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
TRECK_UDP_getFd(void *pUdpDescr, sbyte4 *fd)
{
    TRECK_UDP_interface*    pUdpIf = (TRECK_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    *fd = pUdpIf->udpFd;

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
TRECK_UDP_recv(void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    TRECK_UDP_interface*    pUdpIf = (TRECK_UDP_interface *)pUdpDescr;
    int                     result;
    MSTATUS                 status = OK;

    *pRetDataLength = 0;

    result = recv(pUdpIf->udpFd, (char *)pBuf, bufSize, 0);

    if (SOCKET_ERROR == result)
    {
        if (TM_EAGAIN != tfGetSocketError(pUdpIf->udpFd))
            status = ERR_UDP_READ;
    }
    else *pRetDataLength = (ubyte4)result;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
TRECK_UDP_recvFrom(void *pUdpDescr, MOC_IP_ADDRESS_S *pPeerAddress, ubyte2* pPeerPortNo,
                   ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    TRECK_UDP_interface*    pUdpIf = (TRECK_UDP_interface *)pUdpDescr;
    int                     result;
    MSTATUS                 status = OK;

#ifdef __ENABLE_DIGICERT_IPV6__
    struct sockaddr_in6     fromAddress;
#else
    struct sockaddr_in      fromAddress;
#endif
    int                     fromLen = sizeof(fromAddress);

    *pRetDataLength = 0;

    DIGI_MEMSET((ubyte *)&fromAddress, 0x00, sizeof(fromAddress));

    result = recvfrom(pUdpIf->udpFd, (char *)pBuf, bufSize, 0,
                     (struct sockaddr *) &fromAddress, &fromLen);

    if (SOCKET_ERROR == result)
    {
        if (TM_EAGAIN != tfGetSocketError(pUdpIf->udpFd))
            status = ERR_UDP_READ;

        goto exit;
    }

    *pRetDataLength = (ubyte4)result;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == fromAddress.sin6_family)
    {
        pPeerAddress->family = AF_INET6;
        *pPeerPortNo = ntohs(fromAddress.sin6_port);
        DIGI_MEMCPY((ubyte *) pPeerAddress->uin.addr6, fromAddress.sin6_addr.s6_addr, 16);
    }
    else
    {
        struct sockaddr_in *pFromAddress = (struct sockaddr_in *)&fromAddress;
        pPeerAddress->family = AF_INET;
        *pPeerPortNo = ntohs(pFromAddress->sin_port);
        pPeerAddress->uin.addr = ntohl(pFromAddress->sin_addr.s_addr);
    }
#else
    *pPeerAddress = ntohl(fromAddress.sin_addr.s_addr);
    *pPeerPortNo = ntohs(fromAddress.sin_port);
#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
TRECK_UDP_getSrcPortAddr(void *pUdpDescr, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr)
{
    TRECK_UDP_interface*    pUdpIf = (TRECK_UDP_interface *)pUdpDescr;

#ifdef __ENABLE_DIGICERT_IPV6__
    struct sockaddr_in6     myAddress;
#else
    struct sockaddr_in      myAddress;
#endif
    sbyte4                  addrLen = sizeof(myAddress);
    MSTATUS                 status = OK;

    DIGI_MEMSET((ubyte *)&myAddress, 0x00, sizeof(myAddress));

    if (0 > getsockname(pUdpIf->udpFd, (struct sockaddr *)&myAddress, &addrLen))
    {
        status = ERR_UDP_GETSOCKNAME;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == myAddress.sin6_family)
    {
        pRetAddr->family = AF_INET6;
        *pRetPortNo = ntohs(myAddress.sin6_port);
        DIGI_MEMCPY((ubyte *) pRetAddr->uin.addr6, myAddress.sin6_addr.s6_addr, 16);
    }
    else
    {
        struct sockaddr_in *pMyAddress = (struct sockaddr_in *)&myAddress;
        pRetAddr->family = AF_INET;
        *pRetPortNo = ntohs(pMyAddress->sin_port);
        pRetAddr->uin.addr = ntohl(pMyAddress->sin_addr.s_addr);
    }
#else
    *pRetPortNo = htons(myAddress.sin_port);
    *pRetAddr   = htonl(myAddress.sin_addr.s_addr);
#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
TRECK_UDP_selReadAvl(void *ppUdpDescr[], sbyte4 numUdpDescr, ubyte4 msTimeout)
{
    fd_set*         pSocketList = NULL;
    struct timeval  timeout;
    int             ret;
    sbyte4          i;
    int             biggestSocket = -1;
    MSTATUS         status = OK;

    if (NULL == ppUdpDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 >= numUdpDescr)
        goto exit;

    if (NULL == (pSocketList = MALLOC(sizeof(fd_set))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* add the socket of interest to the list */
    FD_ZERO(pSocketList);

    for (i = 0; i < numUdpDescr; i++)
    {
        TRECK_UDP_interface *pUdpIf = (TRECK_UDP_interface *) ppUdpDescr[i];

        if (NULL != pUdpIf)
        {
            FD_SET(pUdpIf->udpFd, pSocketList);

            if (biggestSocket < pUdpIf->udpFd)
                biggestSocket = pUdpIf->udpFd;
        }
    }

    /* compute timeout (milliseconds) */
    timeout.tv_sec  = msTimeout / 1000;
    timeout.tv_usec = (msTimeout % 1000) * 1000;    /* convert ms to us */

    /* Note: Windows ignores the first parameter '1' */
    /* other platforms may want (highest socket + 1) */
    ret = select(1 + biggestSocket, pSocketList, NULL, NULL, &timeout);

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
        TRECK_UDP_interface *pUdpIf = (TRECK_UDP_interface *) ppUdpDescr[i];

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


#endif /* __TRECK_UDP__ */
