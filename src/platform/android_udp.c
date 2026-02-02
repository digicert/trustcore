/*
 * android_udp.c
 *
 * Android UDP Abstraction Layer
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

#ifdef __ANDROID_UDP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#define _REENTRANT

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>


/*------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_IPV6__
#define M_SOCKADDR              struct sockaddr_in
#define MS_FAMILY               sin_family
#define GET_MOC_IPADDR4(a)      a
#define SET_MOC_IPADDR4(s, v)   s = v
#else
#define M_SOCKADDR              struct sockaddr_in6
#define MS_FAMILY               sin6_family
#define GET_MOC_IPADDR4(a)      (a)->uin.addr
#define SET_MOC_IPADDR4(s, v)   (s).family = AF_INET; (s).uin.addr = v
#endif

typedef struct
{
    int         udpFd;
    M_SOCKADDR  serverAddress;

} ANDROID_UDP_interface;


/*------------------------------------------------------------------*/

#ifndef SOCKET_ERROR
#define SOCKET_ERROR    (-1)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_UDP_init(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_UDP_shutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_UDP_getInterfaceAddress(sbyte *pHostName,
                                MOC_IP_ADDRESS_S *pRetIpAddress)
{
/*  MSTATUS status = OK;

    *pRetIpAddress = ntohl(INADDR_ANY);
*/
    /* for example code we just default to the primary interface */
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

    status = ANDROID_UDP_getAddressOfHost(pHostName, pRetIpAddress);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_UDP_getAddressOfHost(sbyte *pHostName, MOC_IP_ADDRESS_S *pRetIpAddress)
{
    MSTATUS status = ERR_UDP_HOSTNAME_NOT_FOUND;

    if (NULL != pHostName)
    {
        struct hostent *pHostAddr;

        if (NULL != (pHostAddr = gethostbyname((char *)pHostName)))
        {
            SET_MOC_IPADDR4(*pRetIpAddress, ntohl(*((ubyte4 *) pHostAddr->h_addr)));
            status = OK;
        }
#ifdef __ENABLE_DIGICERT_IPV6__
        else
        {
            struct addrinfo    Hints = { 0 }, *AddrInfo;
            int         RetVal;
            /*Hints.ai_canonname = (char *)pHostName;*/
            Hints.ai_family = AF_INET6;
            Hints.ai_socktype = SOCK_DGRAM;
            Hints.ai_flags = AI_PASSIVE;
            RetVal = getaddrinfo((char *)pHostName, NULL, &Hints, &AddrInfo);

            if (0 != RetVal)
            {
                status = ERR_UDP_GETADDR;
                return status;
            }

            pRetIpAddress->family = AF_INET6;
            DIGI_MEMCPY((ubyte *) pRetIpAddress->uin.addr6,
                       (ubyte *) ((struct sockaddr_in6 *) AddrInfo->ai_addr)->sin6_addr.s6_addr, 16);
            pRetIpAddress->uin.addr6[4] = ((struct sockaddr_in6 *) AddrInfo->ai_addr)->sin6_scope_id;
            freeaddrinfo(AddrInfo);
            status = OK;
        }
#endif
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
ANDROID_UDP_bindConnect(void **ppRetUdpDescr,
                        MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                        MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                        intBoolean isNonBlocking, intBoolean connected)
{
    ANDROID_UDP_interface   *pUdpIf = NULL;
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

    /* allocate ANDROID_UDP_interface */
    if (NULL == (pUdpIf = (ANDROID_UDP_interface*)
                            MALLOC(sizeof(ANDROID_UDP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    myAddr = &pUdpIf->serverAddress;
    #define SERVER_ADDR ((struct sockaddr_in *)myAddr)
    DIGI_MEMSET((ubyte *)pUdpIf, 0x00, sizeof(ANDROID_UDP_interface));

    /* handle socket source end-point */
#ifdef __ENABLE_DIGICERT_IPV6__
    if ((srcAddress && (AF_INET6 == srcAddress->family)) ||
        (!srcAddress &&
         connected && (AF_INET6 == dstAddress->family)))
    {
        myAddr->sin6_family = AF_INET6;
        myAddr->sin6_port = htons(srcPortNo);
        if (srcAddress)
        {
            DIGI_MEMCPY(myAddr->sin6_addr.s6_addr, srcAddress->uin.addr6, 16);
            myAddr->sin6_scope_id = srcAddress->uin.addr6[4];
        }
        if (connected && (0 == myAddr->sin6_scope_id))
        {
            myAddr->sin6_scope_id = dstAddress->uin.addr6[4];
        }
    }
    else
#endif
    {
        SERVER_ADDR->sin_family = AF_INET;
        SERVER_ADDR->sin_port = htons(srcPortNo);
        SERVER_ADDR->sin_addr.s_addr = htonl(GET_MOC_IPADDR4(srcAddress));
    }

    if (0 > (pUdpIf->udpFd = socket(myAddr->MS_FAMILY, SOCK_DGRAM, 0)))
    {
        status = ERR_UDP_SOCKET;
        goto exit;
    }

    if (0 > bind(pUdpIf->udpFd, (struct sockaddr *)myAddr, sizeof(*myAddr)))
    {
        status = ERR_UDP_BIND;
        goto exit;
    }

    /* handle socket destination end-point */
    if (connected)
    {
        /* handle socket destination end-point */
#ifdef __ENABLE_DIGICERT_IPV6__
        if (AF_INET6 == dstAddress->family)
        {
            myAddr->sin6_family = AF_INET6;
            myAddr->sin6_port = htons(dstPortNo);
            DIGI_MEMCPY(myAddr->sin6_addr.s6_addr, dstAddress->uin.addr6, 16);
        }
        else
#endif
        {
            SERVER_ADDR->sin_family = AF_INET;
            SERVER_ADDR->sin_port = htons(dstPortNo);
            SERVER_ADDR->sin_addr.s_addr = htonl(GET_MOC_IPADDR4(dstAddress));
        }

        if (0 > connect(pUdpIf->udpFd, (struct sockaddr *)myAddr, sizeof(*myAddr)))
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
ANDROID_UDP_connect(void **ppRetUdpDescr,
                MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                intBoolean isNonBlocking)
{
    return ANDROID_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                                dstAddress, dstPortNo, isNonBlocking, TRUE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_UDP_simpleBind(void **ppRetUdpDescr,
                    MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                    intBoolean isNonBlocking)
{
    return ANDROID_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                                0, 0, isNonBlocking, FALSE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_UDP_unbind(void **ppReleaseUdpDescr)
{
    ANDROID_UDP_interface   *pUdpIf;
    MSTATUS                 status = ERR_NULL_POINTER;

    if (NULL == ppReleaseUdpDescr)
        goto exit;

    pUdpIf = *((ANDROID_UDP_interface **)ppReleaseUdpDescr);

    /* de-allocate ANDROID_UDP_interface */
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
ANDROID_UDP_send(void *pUdpDescr, ubyte *pData, ubyte4 dataLength)
{
    ANDROID_UDP_interface   *pUdpIf = (ANDROID_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    if (0 > send(pUdpIf->udpFd, pData, dataLength, 0))
        status = ERR_UDP_WRITE;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress,
                ubyte2 peerPortNo, ubyte *pData, ubyte4 dataLength)
{
    ANDROID_UDP_interface   *pUdpIf = (ANDROID_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == peerAddress->family)
    {
        struct sockaddr_in6 destAddress = { 0 };

        destAddress.sin6_family = AF_INET6;
        destAddress.sin6_port = htons(peerPortNo);
        DIGI_MEMCPY(destAddress.sin6_addr.s6_addr, peerAddress->uin.addr6, 16);

        if (0 == (destAddress.sin6_scope_id =
                ((struct sockaddr_in6 *)&pUdpIf->serverAddress)->sin6_scope_id))
        {
            destAddress.sin6_scope_id = peerAddress->uin.addr6[4];
        }

        if (0 > sendto(pUdpIf->udpFd, (char *)pData, dataLength, 0,
                       (struct sockaddr *)&destAddress, sizeof(destAddress)))
        {
            status = ERR_UDP_WRITE;
        }
    }
    else
#endif
    {
        struct sockaddr_in destAddress = { 0 };

        destAddress.sin_family = AF_INET;
        destAddress.sin_port = htons(peerPortNo);
        destAddress.sin_addr.s_addr = htonl(GET_MOC_IPADDR4(peerAddress));

        if (0 > sendto(pUdpIf->udpFd, (char *)pData, dataLength, 0,
                       (struct sockaddr *)&destAddress, sizeof(destAddress)))
        {
            status = ERR_UDP_WRITE;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_UDP_getFd(void *pUdpDescr, sbyte4 *fd)
{
    ANDROID_UDP_interface   *pUdpIf = (ANDROID_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    *fd = pUdpIf->udpFd;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_UDP_recv(void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize,
                ubyte4 *pRetDataLength)
{
    ANDROID_UDP_interface   *pUdpIf = (ANDROID_UDP_interface *)pUdpDescr;
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
ANDROID_UDP_recvFrom(void *pUdpDescr, MOC_IP_ADDRESS_S *pPeerAddress,
                    ubyte2 *pPeerPortNo, ubyte *pBuf, ubyte4 bufSize,
                    ubyte4 *pRetDataLength)
{
    ANDROID_UDP_interface   *pUdpIf = (ANDROID_UDP_interface *)pUdpDescr;
    int                     result;
    MSTATUS                 status = OK;

    M_SOCKADDR              fromAddress = { 0 };
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

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == pUdpIf->serverAddress.MS_FAMILY)
    /*if (AF_INET6 == fromAddress.MS_FAMILY)*/
    {
        pPeerAddress->family = AF_INET6;
        *pPeerPortNo = ntohs(fromAddress.sin6_port);
        DIGI_MEMCPY((ubyte *) pPeerAddress->uin.addr6, fromAddress.sin6_addr.s6_addr, 16);
        /* we need to preserve the scope id for later */
        pPeerAddress->uin.addr6[4] = fromAddress.sin6_scope_id;
    }
    else
#endif
    {
        #define FROM_ADDR ((struct sockaddr_in *) &fromAddress)
        SET_MOC_IPADDR4(*pPeerAddress, ntohl(FROM_ADDR->sin_addr.s_addr));
        *pPeerPortNo = ntohs(FROM_ADDR->sin_port);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_UDP_getSrcPortAddr(void *pUdpDescr, ubyte2 *pRetPortNo,
                            MOC_IP_ADDRESS_S *pRetAddr)
{
    ANDROID_UDP_interface   *pUdpIf = (ANDROID_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    M_SOCKADDR              myAddress = { 0 };
    sbyte4                  addrLen = sizeof(myAddress);

    if (0 > getsockname(pUdpIf->udpFd, (struct sockaddr *)&myAddress,
                        (socklen_t *)&addrLen))
    {
        status = ERR_UDP_GETSOCKNAME;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == pUdpIf->serverAddress.MS_FAMILY)
    /*if (AF_INET6 == myAddress.MS_FAMILY)*/
    {
        pRetAddr->family = AF_INET6;
        *pRetPortNo = ntohs(myAddress.sin6_port);
        DIGI_MEMCPY((ubyte *) pRetAddr->uin.addr6, myAddress.sin6_addr.s6_addr, 16);
    }
    else
#endif
    {
        #define MY_ADDR ((struct sockaddr_in *) &myAddress)
        *pRetPortNo = ntohs(MY_ADDR->sin_port);
        SET_MOC_IPADDR4(*pRetAddr, ntohl(MY_ADDR->sin_addr.s_addr));
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_UDP_selReadAvl(void *ppUdpDescr[], sbyte4 numUdpDescr,
                    ubyte4 msTimeout)
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

    if (NULL == (pSocketList = (fd_set *) MALLOC(sizeof(fd_set))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* add the socket of interest to the list */
    FD_ZERO(pSocketList);

    for (i=0; i < numUdpDescr; i++)
    {
        ANDROID_UDP_interface *pUdpIf = (ANDROID_UDP_interface *) ppUdpDescr[i];
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
        ANDROID_UDP_interface *pUdpIf = (ANDROID_UDP_interface *) ppUdpDescr[i];
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


#endif /* __ANDROID_UDP__ */
