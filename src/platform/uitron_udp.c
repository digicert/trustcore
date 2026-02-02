/*
 * uitron_udp.c
 *
 * uITRON UDP Abstraction Layer
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

#ifdef __UITRON_UDP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"


/*------------------------------------------------------------------*/

typedef struct
{
    intBoolean          isSimpleBind;
    SOCKET              udpFd;
    union
    {
        struct sockaddr_in  v4;
#ifdef __ENABLE_DIGICERT_IPV6__
        struct sockaddr_in6  v6;
#endif
    } serverAddress;
    ubyte2              lclPort;

} UITRON_UDP_interface;


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_UDP_init()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_UDP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_UDP_getInterfaceAddress(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress)
{
    /* for Windows example code we just default to the primary interface */
    sbyte       myHostName[MAX_PATH];
    MSTATUS     status = ERR_UDP_INTERFACE_NOT_FOUND;
    struct hostent *pHostAddr;

#ifdef __ENABLE_DIGICERT_IPV6__
    static MOC_IP_ADDRESS_S hostAddress;
#endif

    if (NULL == pHostName)
    {
        if (SOCKET_ERROR == gethostname(myHostName, sizeof(myHostName)))
        {
            goto exit;
        }
        pHostName = myHostName;
    }

    if (NULL != (pHostAddr = gethostbyname(pHostName)))
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        hostAddress.family = AF_INET;
        hostAddress.uin.addr = ntohl(*((ubyte4 *)pHostAddr->h_addr));
        *pRetIpAddress = &hostAddress;
#else
        *pRetIpAddress = ntohl(*((MOC_IP_ADDRESS *)pHostAddr->h_addr));
#endif
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_UDP_getAddressOfHost(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress)
{
    MSTATUS status = ERR_UDP_HOSTNAME_NOT_FOUND;

#ifdef __ENABLE_DIGICERT_IPV6__
    static MOC_IP_ADDRESS_S hostAddress;
#endif

    if (NULL != pHostName)
    {
        struct hostent FAR *pHostAddr;

        if (NULL != (pHostAddr = gethostbyname(pHostName)))
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            hostAddress.family = AF_INET;
            hostAddress.uin.addr = ntohl(*((ubyte4 *)pHostAddr->h_addr));
            *pRetIpAddress = &hostAddress;
#else
            *pRetIpAddress = ntohl(*((MOC_IP_ADDRESS *)pHostAddr->h_addr));
#endif
            status = OK;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
UITRON_UDP_bindConnect(void **ppRetUdpDescr,
                      MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                      MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                      intBoolean isNonBlocking, intBoolean connected)
{
    UITRON_UDP_interface*    pUdpIf = NULL;
    unsigned long           flags;
    MSTATUS                 status = ERR_UDP;

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

    /* allocate UITRON_UDP_interface */
    if (NULL == (pUdpIf = MALLOC(sizeof(UITRON_UDP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pUdpIf, 0x00, sizeof(UITRON_UDP_interface));

    /* force artificial constraint to match VxWorks and other embedded RTOSes */
    pUdpIf->isSimpleBind = ((TRUE == connected) ? FALSE : TRUE);

    /* handle socket source end-point */
#ifdef __ENABLE_DIGICERT_IPV6__
    if ((srcAddress && (AF_INET6 == srcAddress->family)) ||
        (!srcAddress && dstAddress && (AF_INET6 == dstAddress->family)))
    {
        struct sockaddr_in6 myAddr;
        DIGI_MEMSET((ubyte *)&myAddr, 0x00, sizeof(myAddr));

        myAddr.sin6_family = AF_INET6;

        if (MOC_UDP_ANY_PORT == srcPortNo)
            myAddr.sin6_port = 0;
        else
            myAddr.sin6_port = htons(srcPortNo);

        if (srcAddress)
            DIGI_MEMCPY(myAddr.sin6_addr.s6_addr, srcAddress->uin.addr6, 16);

        if (0 > (pUdpIf->udpFd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)))
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
        DIGI_MEMSET((ubyte *)&myAddr, 0x00, sizeof(myAddr));

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

        if (0 > (pUdpIf->udpFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)))
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
            pUdpIf->serverAddress.v4.sin_port = htons(dstPortNo);
#ifdef __ENABLE_DIGICERT_IPV6__
            pUdpIf->serverAddress.v4.sin_addr.s_addr = htonl(dstAddress->uin.addr);
#else
            pUdpIf->serverAddress.v4.sin_addr.s_addr = htonl(dstAddress);
#endif
            if (0 > connect(pUdpIf->udpFd, (struct sockaddr *)&(pUdpIf->serverAddress), sizeof(struct sockaddr_in)))
            {
                status = ERR_UDP_CONNECT;
                goto exit;
            }
        }
    }

    if (0 != (flags = (unsigned long)isNonBlocking))
    {
        if (0 > ioctlsocket(pUdpIf->udpFd, FIONBIO, &flags))
        {
            status = ERR_UDP_IOCTL;
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
UITRON_UDP_connect(void **ppRetUdpDescr,
                  MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                  MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                  intBoolean isNonBlocking)
{
    return UITRON_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                                 dstAddress, dstPortNo, isNonBlocking, TRUE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_UDP_simpleBind(void **ppRetUdpDescr,
                        MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                        intBoolean isNonBlocking)
{
    return UITRON_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                                 0, 0, isNonBlocking, FALSE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_UDP_unbind(void **ppReleaseUdpDescr)
{
    UITRON_UDP_interface*    pUdpIf;
    MSTATUS                 status = ERR_NULL_POINTER;

    if (NULL == ppReleaseUdpDescr)
        goto exit;

    pUdpIf = *((UITRON_UDP_interface **)ppReleaseUdpDescr);

    /* de-allocate UITRON_UDP_interface */
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
UITRON_UDP_send(void *pUdpDescr, ubyte *pData, ubyte4 dataLength)
{
    UITRON_UDP_interface*    pUdpIf = (UITRON_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    /* force artificial constraint to match VxWorks and other embedded RTOSes */
    if (TRUE == pUdpIf->isSimpleBind)
    {
        /* must use UDP_connect() with UDP_send() */
        return ERR_UDP_BIND_CTX;
    }

    if (0 > send(pUdpIf->udpFd, (char *)pData, dataLength, 0))
        status = ERR_UDP_WRITE;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress, ubyte2 peerPortNo,
                 ubyte *pData, ubyte4 dataLength)
{
    UITRON_UDP_interface*    pUdpIf = (UITRON_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    /* force artificial constraint to match VxWorks and other embedded RTOSes */
    if (TRUE != pUdpIf->isSimpleBind)
    {
        /* must use UDP_simpleBind() with UDP_sendTo() */
        return ERR_UDP_BIND_CTX;
    }

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
UITRON_UDP_getFd(void *pUdpDescr, sbyte4 *fd)
{
    UITRON_UDP_interface*   pUdpIf = (UITRON_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    *fd = pUdpIf->udpFd;

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_UDP_recv(void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    UITRON_UDP_interface*    pUdpIf = (UITRON_UDP_interface *)pUdpDescr;
    int                     result;
    MSTATUS                 status = OK;

    *pRetDataLength = 0;

    /* force artificial constraint to match VxWorks and other embedded RTOSes */
    if (TRUE == pUdpIf->isSimpleBind)
    {
        /* must use UDP_connect() with UDP_recv() */
        status = ERR_UDP_BIND_CTX;
        goto exit;
    }

    result = recv(pUdpIf->udpFd, (char *)pBuf, bufSize, 0);

    if (SOCKET_ERROR == result)
    {
        int lastErr;
        if (WSAEWOULDBLOCK != (lastErr= WSAGetLastError()))
            status = ERR_UDP_READ;

        goto exit;
    }
    else *pRetDataLength = (ubyte4)result;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_UDP_recvFrom(void *pUdpDescr, MOC_IP_ADDRESS* pPeerAddress, ubyte2* pPeerPortNo,
                   ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    UITRON_UDP_interface*    pUdpIf = (UITRON_UDP_interface *)pUdpDescr;
    int                     result;
    MSTATUS                 status = OK;
#ifdef __ENABLE_DIGICERT_IPV6__
    static MOC_IP_ADDRESS_S peerAddress;

    struct sockaddr_in6     fromAddress;
#else
    struct sockaddr_in      fromAddress;
#endif
    int                     fromLen = sizeof(fromAddress);

    *pRetDataLength = 0;

    /* force artificial constraint to match VxWorks and other embedded RTOSes */
    if (TRUE != pUdpIf->isSimpleBind)
    {
        /* must use UDP_simpleBind() with UDP_recvFrom() */
        status = ERR_UDP_BIND_CTX;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&fromAddress, 0x00, sizeof(fromAddress));

    result = recvfrom(pUdpIf->udpFd, (char *)pBuf, bufSize, 0,
                        (struct sockaddr *) &fromAddress, &fromLen);

    if (SOCKET_ERROR == result)
    {
        int lastErr;
        if (WSAEWOULDBLOCK != (lastErr= WSAGetLastError()))
            status = ERR_UDP_READ;

        goto exit;
    }

    *pRetDataLength = (ubyte4)result;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == fromAddress.sin6_family)
    {
        peerAddress.family = AF_INET6;
        *pPeerPortNo = ntohs(fromAddress.sin6_port);
        DIGI_MEMCPY(peerAddress.uin.addr6, fromAddress.sin6_addr.s6_addr, 16);
    }
    else
    {
        struct sockaddr_in *pFromAddress = (struct sockaddr_in *)&fromAddress;
        peerAddress.family = AF_INET;
        *pPeerPortNo = ntohs(pFromAddress->sin_port);
        peerAddress.uin.addr = ntohl(pFromAddress->sin_addr.s_addr);
    }
    *pPeerAddress = &peerAddress;
#else
    *pPeerAddress = ntohl(fromAddress.sin_addr.s_addr);
    *pPeerPortNo = ntohs(fromAddress.sin_port);
#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_UDP_getSrcPortAddr(void *pUdpDescr, ubyte2 *pRetPortNo, MOC_IP_ADDRESS *pRetAddr)
{
    UITRON_UDP_interface*    pUdpIf = (UITRON_UDP_interface *)pUdpDescr;
#ifdef __ENABLE_DIGICERT_IPV6__
    static MOC_IP_ADDRESS_S retAddr;

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
        retAddr.family = AF_INET6;
        *pRetPortNo = htons(myAddress.sin6_port);
        DIGI_MEMCPY(retAddr.uin.addr6, myAddress.sin6_addr.s6_addr, 16);
    }
    else
    {
        struct sockaddr_in *pMyAddress = (struct sockaddr_in *)&myAddress;
        retAddr.family = AF_INET;
        *pRetPortNo = htons(pMyAddress->sin_port);
        retAddr.uin.addr = pMyAddress->sin_addr.s_addr;
    }
    *pRetAddr = &retAddr;
#else
    *pRetPortNo = htons(myAddress.sin_port);
    *pRetAddr = htonl(myAddress.sin_addr.s_addr);
#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_UDP_selReadAvl(void *ppUdpDescr[], sbyte4 numUdpDescr, ubyte4 msTimeout)
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
        UITRON_UDP_interface *pUdpIf = (UITRON_UDP_interface *) ppUdpDescr[i];

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
        UITRON_UDP_interface *pUdpIf = (UITRON_UDP_interface *) ppUdpDescr[i];
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


#endif /* __UITRON_UDP__ */
