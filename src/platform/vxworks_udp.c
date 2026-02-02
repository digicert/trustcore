/*
 * vxworks_udp.c
 *
 * VxWorks UDP Abstraction Layer
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

#include <stdio.h>

#include "../common/moptions.h"

#ifdef __VXWORKS_UDP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <vxWorks.h>
#include <sockLib.h>
#include <inetLib.h>
#include <time.h>
#include <selectLib.h>
#include <stdioLib.h>
#include <strLib.h>
#include <hostLib.h>
#include <ioLib.h>


/*------------------------------------------------------------------*/

#if (defined(_WRS_VXWORKS_MAJOR) && (_WRS_VXWORKS_MAJOR > 5) && !(_WRS_VXWORKS_MAJOR ==6 && _WRS_VXWORKS_MINOR<5))
  /* 6.5 */
  #define M_SOCKADDR    struct sockaddr_storage
  #define MS_FAMILY     ss_family
#elif defined (__ENABLE_DIGICERT_IPV6__)
  /* 5.5 */
  #define M_SOCKADDR    struct sockaddr_in6
  #define MS_FAMILY     sin6_family
#else
  #define M_SOCKADDR    struct sockaddr_in
  #define MS_FAMILY     sin_family
#endif


typedef struct
{
    int                 udpFd;
    M_SOCKADDR          serverAddress;

} VXWORKS_UDP_interface;


/*------------------------------------------------------------------*/

#ifndef SOCKET_ERROR
#define SOCKET_ERROR    (-1)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_UDP_init(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_UDP_shutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_UDP_getInterfaceAddress(sbyte *pHostName,
                                MOC_IP_ADDRESS_S *pRetIpAddress)
{
    MSTATUS     status;
    char        myHostName[255/*HOST_NAME_MAX*/];

    if (NULL == pHostName)
    {
        if (SOCKET_ERROR == gethostname(myHostName, sizeof(myHostName)))
        {
            status = ERR_UDP_INTERFACE_NOT_FOUND;
            goto exit;
        }
        pHostName = (sbyte *)myHostName;
    }

    status = VXWORKS_UDP_getAddressOfHost(pHostName, pRetIpAddress);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_UDP_getAddressOfHost(sbyte *pHostName,
                            MOC_IP_ADDRESS_S *pRetIpAddress)
{
    MSTATUS status = ERR_UDP_HOSTNAME_NOT_FOUND;
    struct hostent *pHostAddr;

    if (NULL == pHostName)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /*** cdsxxx
    // Prepare for the gethostbyname to fail by assuming that the HostName is
    // a dot notation string
    status = DIGI_NET_NAME_TO_IPADDR(pRetIpAddress, pHostName);
    *pRetIpAddress = ntohl(*pRetIpAddress);
    ***/

    if (NULL != (pHostAddr = gethostbyname((char *)pHostName)))
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        if (AF_INET6 == pHostAddr->h_addrtype)
        {
            pRetIpAddress->family = AF_INET6;
            DIGI_MEMCPY((ubyte *) pRetIpAddress->uin.addr6, pHostAddr->h_addr, 16);
            status = OK;
        }
        else
#endif
        if (AF_INET == pHostAddr->h_addrtype)
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            pRetIpAddress->family = AF_INET;
            pRetIpAddress->uin.addr = ntohl(*((ubyte4 *) pHostAddr->h_addr));
#else
            *pRetIpAddress = ntohl(*((ubyte4 *) pHostAddr->h_addr));
#endif
            status = OK;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
VXWORKS_UDP_bindConnect(void **ppRetUdpDescr,
                        MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                        MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                        intBoolean isNonBlocking, intBoolean connected)
{
    VXWORKS_UDP_interface   *pUdpIf = NULL;
    MSTATUS                 status = ERR_UDP;

    M_SOCKADDR              *myAddr;

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

    /* allocate VXWORKS_UDP_interface */
    if (NULL == (pUdpIf = (VXWORKS_UDP_interface*)
                            MALLOC(sizeof(VXWORKS_UDP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    myAddr = &pUdpIf->serverAddress;
    DIGI_MEMSET((ubyte *)pUdpIf, 0x00, sizeof(VXWORKS_UDP_interface));

    /* handle socket source end-point */
#ifdef __ENABLE_DIGICERT_IPV6__
    if ((srcAddress && (AF_INET6 == srcAddress->family)) ||
        (!srcAddress &&
         connected && (AF_INET6 == dstAddress->family)))
    {
        myAddr->MS_FAMILY = AF_INET6;

        if (MOC_UDP_ANY_PORT != srcPortNo)
            ((struct sockaddr_in6 *)myAddr)->sin6_port = htons(srcPortNo);

        if (srcAddress)
        {
            ((struct sockaddr_in6 *)myAddr)->sin6_scope_id =
                                                    srcAddress->uin.addr6[4];
            DIGI_MEMCPY(((struct sockaddr_in6 *)myAddr)->sin6_addr.s6_addr,
                       srcAddress->uin.addr6, 16);
        }

        if (dstAddress && (!srcAddress || (0 == srcAddress->uin.addr6[4])))
        {
            ((struct sockaddr_in6 *)myAddr)->sin6_scope_id =
                                                    dstAddress->uin.addr6[4];
        }
    }
    else
#endif
    {
        myAddr->MS_FAMILY = AF_INET;

        if (MOC_UDP_ANY_PORT != srcPortNo)
            ((struct sockaddr_in *)myAddr)->sin_port = htons(srcPortNo);

#ifdef __ENABLE_DIGICERT_IPV6__
        if (srcAddress)
            ((struct sockaddr_in *)myAddr)->sin_addr.s_addr =
                                                htonl(srcAddress->uin.addr);
#else
        ((struct sockaddr_in *)myAddr)->sin_addr.s_addr = htonl(srcAddress);
#endif
    }

    if (0 > (pUdpIf->udpFd = socket(myAddr->MS_FAMILY, SOCK_DGRAM, IPPROTO_UDP)))
    {
        status = ERR_UDP_SOCKET;
        goto exit;
    }

    if (0 > bind(pUdpIf->udpFd, (struct sockaddr *)myAddr, sizeof(*myAddr)))
    {
        status = ERR_UDP_BIND;
        goto exit;
    }

    if (connected)
    {
        /* handle socket destination end-point */
#ifdef __ENABLE_DIGICERT_IPV6__
        if (AF_INET6 == dstAddress->family)
        {
            myAddr->MS_FAMILY = AF_INET6;
            ((struct sockaddr_in6 *)myAddr)->sin6_port = htons(dstPortNo);
            DIGI_MEMCPY(((struct sockaddr_in6 *)myAddr)->sin6_addr.s6_addr,
                       dstAddress->uin.addr6, 16);
        }
        else
#endif
        {
            myAddr->MS_FAMILY = AF_INET;
#ifdef __ENABLE_DIGICERT_IPV6__
            ((struct sockaddr_in *)myAddr)->sin_addr.s_addr =
                                                    htonl(dstAddress->uin.addr);
#else
            ((struct sockaddr_in *)myAddr)->sin_addr.s_addr = htonl(dstAddress);
#endif
            ((struct sockaddr_in *)myAddr)->sin_port = htons(dstPortNo);
        }

        if (0 > connect(pUdpIf->udpFd, (struct sockaddr *)myAddr,
                        sizeof(*myAddr)))
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
        if (0 < pUdpIf->udpFd)
            close(pUdpIf->udpFd);

        FREE(pUdpIf);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_UDP_connect(void **ppRetUdpDescr,
                MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                intBoolean isNonBlocking)
{
    return VXWORKS_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                                dstAddress, dstPortNo, isNonBlocking, TRUE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_UDP_simpleBind(void **ppRetUdpDescr,
                    MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                    intBoolean isNonBlocking)
{
    return VXWORKS_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                                0, 0, isNonBlocking, FALSE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_UDP_unbind(void **ppReleaseUdpDescr)
{
    VXWORKS_UDP_interface   *pUdpIf;
    MSTATUS                 status = ERR_NULL_POINTER;

    if (NULL == ppReleaseUdpDescr)
        goto exit;

    pUdpIf = *((VXWORKS_UDP_interface **)ppReleaseUdpDescr);

    /* de-allocate VXWORKS_UDP_interface */
    if (NULL != pUdpIf)
    {
        if (0 < pUdpIf->udpFd)
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
VXWORKS_UDP_send(void *pUdpDescr, ubyte *pData, ubyte4 dataLength)
{
    VXWORKS_UDP_interface   *pUdpIf = (VXWORKS_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    if (0 > send(pUdpIf->udpFd, pData, dataLength, 0))
        status = ERR_UDP_WRITE;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress,
                ubyte2 peerPortNo, ubyte *pData, ubyte4 dataLength)
{
    VXWORKS_UDP_interface   *pUdpIf = (VXWORKS_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    M_SOCKADDR              destAddress = { 0 };
    int tolen = 0;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == peerAddress->family)
    {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&destAddress;

        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(peerPortNo);
        DIGI_MEMCPY(addr->sin6_addr.s6_addr, peerAddress->uin.addr6, 16);

        if (0 == (addr->sin6_scope_id =
            ((struct sockaddr_in6 *)&pUdpIf->serverAddress)->sin6_scope_id))
            addr->sin6_scope_id = peerAddress->uin.addr6[4];
        tolen = sizeof(struct sockaddr_in6) ;
    }
    else
    {
        ((struct sockaddr_in *)&destAddress)->sin_family = AF_INET;
        ((struct sockaddr_in *)&destAddress)->sin_addr.s_addr =
                                                htonl(peerAddress->uin.addr);
        ((struct sockaddr_in *)&destAddress)->sin_port = htons(peerPortNo);
        tolen = sizeof(struct sockaddr_in) ;
    }
#else
    ((struct sockaddr_in *)&destAddress)->sin_family = AF_INET;
    ((struct sockaddr_in *)&destAddress)->sin_addr.s_addr = htonl(peerAddress);
    ((struct sockaddr_in *)&destAddress)->sin_port = htons(peerPortNo);
    tolen = sizeof(struct sockaddr_in) ;
#endif

    if (0 > sendto(pUdpIf->udpFd, (char *)pData, dataLength, 0,
                   (struct sockaddr *)&destAddress, tolen))
    {
        status = ERR_UDP_WRITE;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_UDP_getFd(void *pUdpDescr, UDP_SOCKET *fd)
{
    VXWORKS_UDP_interface   *pUdpIf = (VXWORKS_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    *fd = pUdpIf->udpFd;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_UDP_recv(void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize,
                ubyte4 *pRetDataLength)
{
    VXWORKS_UDP_interface   *pUdpIf = (VXWORKS_UDP_interface *)pUdpDescr;
    int                     result;
    MSTATUS                 status = OK;

    *pRetDataLength = 0;

    result = recv(pUdpIf->udpFd, (char *)pBuf, bufSize, 0);

    if (0 > result)
    {
        status = ERR_UDP_READ;
    }
    else *pRetDataLength = (ubyte4)result;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_UDP_recvFrom(void *pUdpDescr, MOC_IP_ADDRESS_S *pPeerAddress,
                    ubyte2 *pPeerPortNo, ubyte *pBuf, ubyte4 bufSize,
                    ubyte4 *pRetDataLength)
{
    VXWORKS_UDP_interface   *pUdpIf = (VXWORKS_UDP_interface *)pUdpDescr;
    int                     result;
    MSTATUS                 status = OK;

    M_SOCKADDR              fromAddress = { 0 };
    int                     fromLen = sizeof(fromAddress);

    *pRetDataLength = 0;

    result = recvfrom(pUdpIf->udpFd, (char *)pBuf, bufSize, 0,
                      (struct sockaddr *)&fromAddress, &fromLen);

    if (0 > result)
    {
        status = ERR_UDP_READ;

        goto exit;
    }

    *pRetDataLength = (ubyte4)result;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == pUdpIf->serverAddress.MS_FAMILY)
    /*if (AF_INET6 == fromAddress.MS_FAMILY)*/
    {
        pPeerAddress->family = AF_INET6;
        *pPeerPortNo = ntohs(((struct sockaddr_in6 *)&fromAddress)->sin6_port);
        DIGI_MEMCPY((ubyte *) pPeerAddress->uin.addr6,
                ((struct sockaddr_in6 *)&fromAddress)->sin6_addr.s6_addr, 16);
        /* we need to preserve the scope id for later */
        pPeerAddress->uin.addr6[4] = ((struct sockaddr_in6 *)&fromAddress)->
                                                            sin6_scope_id;
    }
    else
    {
        pPeerAddress->family = AF_INET;
        *pPeerPortNo = ntohs(((struct sockaddr_in *)&fromAddress)->sin_port);
        pPeerAddress->uin.addr = ntohl(((struct sockaddr_in *)&fromAddress)->
                                                            sin_addr.s_addr);
    }
#else
    *pPeerAddress = ntohl(((struct sockaddr_in *)&fromAddress)->
                                                            sin_addr.s_addr);
    *pPeerPortNo = ntohs(((struct sockaddr_in *)&fromAddress)->sin_port);
#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_UDP_getSrcPortAddr(void *pUdpDescr, ubyte2 *pRetPortNo,
                            MOC_IP_ADDRESS_S *pRetAddr)
{
    VXWORKS_UDP_interface   *pUdpIf = (VXWORKS_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    M_SOCKADDR              myAddress = { 0 };
    socklen_t               addrLen = sizeof(myAddress);

    if (0 > getsockname(pUdpIf->udpFd, (struct sockaddr *)&myAddress,
                        &addrLen))
    {
        status = ERR_UDP_GETSOCKNAME;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == pUdpIf->serverAddress.MS_FAMILY)
    /*if (AF_INET6 == myAddress.MS_FAMILY)*/
    {
        pRetAddr->family = AF_INET6;
        *pRetPortNo = ntohs(((struct sockaddr_in6 *)&myAddress)->sin6_port);
        DIGI_MEMCPY((ubyte *) pRetAddr->uin.addr6,
                   ((struct sockaddr_in6 *)&myAddress)->sin6_addr.s6_addr, 16);
    }
    else
    {
        pRetAddr->family = AF_INET;
        *pRetPortNo = ntohs(((struct sockaddr_in *)&myAddress)->sin_port);
        pRetAddr->uin.addr = ntohl(((struct sockaddr_in *)&myAddress)->
                                                            sin_addr.s_addr);
    }
#else
    /*check htons */
    *pRetPortNo = htons(((struct sockaddr_in *)&myAddress)->sin_port);
    *pRetAddr = htonl(((struct sockaddr_in *)&myAddress)->sin_addr.s_addr);
#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VXWORKS_UDP_selReadAvl(void *ppUdpDescr[], sbyte4 numUdpDescr,
                    ubyte4 msTimeout)
{
    MSTATUS         status = OK;

    fd_set*         pSocketList = NULL;
    struct timeval  timeout;
    int             ret;
    sbyte4          i;

    int             udpFdMax = 0;

    if (0 >= numUdpDescr) goto exit;

    if (NULL == ppUdpDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pSocketList = (fd_set *) MALLOC(sizeof(fd_set))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* add the socket of interest to the list */
    FD_ZERO(pSocketList);

    for (i=0; i < numUdpDescr; i++)
    {
        VXWORKS_UDP_interface *pUdpIf = (VXWORKS_UDP_interface *) ppUdpDescr[i];
        if (NULL != pUdpIf)
        {
            FD_SET(pUdpIf->udpFd, pSocketList);

            if (udpFdMax < pUdpIf->udpFd)
                udpFdMax = pUdpIf->udpFd;
        }
    }

    /* compute timeout (milliseconds) */
    timeout.tv_sec  = msTimeout / 1000;
    timeout.tv_usec = (msTimeout % 1000) * 1000;    /* convert ms to us */

    /* Note: want (highest socket + 1) */
    ret = select(udpFdMax+1, pSocketList, NULL, NULL, &timeout);
    if (0 == ret) /* timed out */
    {
        status = ERR_UDP_READ_TIMEOUT;
        goto exit;
    }
    if (0 > ret)
    {
        status = ERR_UDP_READ;
        goto exit;
    }

    for (i=0; i < numUdpDescr; i++)
    {
        VXWORKS_UDP_interface *pUdpIf = (VXWORKS_UDP_interface *) ppUdpDescr[i];
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


#endif /* __VXWORKS_UDP__ */
