/*
 * freertos_udp.c
 *
 * FREERTOS UDP Abstraction Layer
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

#include <errno.h>

#include "../common/moptions.h"

#ifdef __FREERTOS_UDP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <FreeRTOS.h>
#include "task.h"
#include "semphr.h"
#include <FreeRTOS_IP.h>
#include "FreeRTOS_Sockets.h"

/*------------------------------------------------------------------*/

typedef struct
{
    Socket_t        udpFd;
    union
    {
        struct freertos_sockaddr v4;
    } serverAddress;

} FRTOS_UDP_interface;


/*------------------------------------------------------------------*/

#ifndef SOCKET_ERROR
#define SOCKET_ERROR    (-1)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_init(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_shutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_getInterfaceAddress(sbyte *pHostName, MOC_IP_ADDRESS_S *pRetIpAddress)
{
    MSTATUS     status = ERR_UDP_INTERFACE_NOT_FOUND;

    status = ERR_LWIP_UNSUPPORTED_FUNCTION;
    goto exit;


exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_getAddressOfHost(sbyte *pHostName, MOC_IP_ADDRESS_S *pRetIpAddress)
{
    MSTATUS status = OK;
    ubyte4 ulIPAddress = 0;

#ifdef __ENABLE_DIGICERT_IPV6__
    status = ERR_LWIP_UNSUPPORTED_FUNCTION;
#else
    if( ( *pHostName >= '0' ) && ( *pHostName <= '9' ) )
    {
        ulIPAddress = FreeRTOS_inet_addr( pHostName );
    }
    if(!ulIPAddress)
    {
        ulIPAddress =  FreeRTOS_gethostbyname(pHostName);
    }
    *pRetIpAddress = ulIPAddress;
#endif
    return status;
}



/*------------------------------------------------------------------*/

static MSTATUS
FREERTOS_UDP_bindConnect(void **ppRetUdpDescr,
                        MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                        MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                        intBoolean isNonBlocking, intBoolean connected)
{
    FRTOS_UDP_interface*  pUdpIf = NULL;
    MSTATUS               status = ERR_UDP;
    TickType_t xTimeoutTime = pdMS_TO_TICKS( 200 );

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

    /* allocate FRTOS_UDP_interface */
    if (NULL == (pUdpIf = (FRTOS_UDP_interface*) MALLOC(sizeof(FRTOS_UDP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pUdpIf, 0x00, sizeof(FRTOS_UDP_interface));

    /* handle socket source end-point */
#ifdef __ENABLE_DIGICERT_IPV6__
    status = ERR_LWIP_UNSUPPORTED_FUNCTION;
    goto exit;
#if 0    
    if ((srcAddress && (AF_INET6 == srcAddress->family)) ||
        (!srcAddress &&
         connected && (AF_INET6 == dstAddress->family)))
    {
        struct sockaddr_in6 myAddr;
        myAddr.sin6_family = AF_INET6;

        if (MOC_UDP_ANY_PORT == srcPortNo)
            myAddr.sin6_port = 0;
        else
            myAddr.sin6_port = htons(srcPortNo);

        if (srcAddress)
        {
            pUdpIf->serverAddress.v6.sin6_scope_id =
            myAddr.sin6_scope_id = srcAddress->uin.addr6[4];
            DIGI_MEMCPY(myAddr.sin6_addr.s6_addr, srcAddress->uin.addr6, 16);
        }

        if (dstAddress && (!srcAddress || (0 == srcAddress->uin.addr6[4])))
        {
            pUdpIf->serverAddress.v6.sin6_scope_id = dstAddress->uin.addr6[4];
        }

        if (0 > (pUdpIf->udpFd = lwip_socket(AF_INET6, SOCK_DGRAM, 0)))
        {
            status = ERR_UDP_SOCKET;
            goto exit;
        }

        if (0 > lwip_bind(pUdpIf->udpFd, (struct sockaddr *)&myAddr, sizeof(myAddr)))
        {
            status = ERR_UDP_BIND;
            goto exit;
        }
    }
    else
#endif    
#endif
    {
        struct freertos_sockaddr myAddr;
        myAddr.sin_family = FREERTOS_AF_INET;

#ifdef __ENABLE_DIGICERT_IPV6__
        if (srcAddress)
            myAddr.sin_addr.s_addr = htonl(srcAddress->uin.addr);
#else
        myAddr.sin_addr = FreeRTOS_htonl(srcAddress);
#endif
        if (MOC_UDP_ANY_PORT == srcPortNo)
            myAddr.sin_port = 0;
        else
            myAddr.sin_port = FreeRTOS_htons(srcPortNo);

        if (0 == (pUdpIf->udpFd = FreeRTOS_socket(FREERTOS_AF_INET, FREERTOS_SOCK_DGRAM, FREERTOS_IPPROTO_UDP)))
        {
            status = ERR_UDP_SOCKET;
            goto exit;
        }

        if (0 > FreeRTOS_bind(pUdpIf->udpFd, &myAddr, sizeof(myAddr)))
        {
            status = ERR_UDP_BIND;
            goto exit;
        }
    }
    FreeRTOS_setsockopt( pUdpIf->udpFd, 0, FREERTOS_SO_RCVTIMEO, ( void * ) &xTimeoutTime, sizeof( TickType_t ) );
    FreeRTOS_setsockopt( pUdpIf->udpFd, 0, FREERTOS_SO_SNDTIMEO, ( void * ) &xTimeoutTime, sizeof( TickType_t ) );

    if (connected)
    {
        /* handle socket destination end-point */
#ifdef __ENABLE_DIGICERT_IPV6__
#if 0
        if (AF_INET6 == dstAddress->family)
        {
            pUdpIf->serverAddress.v6.sin6_family = AF_INET6;
            pUdpIf->serverAddress.v6.sin6_port = htons(dstPortNo);
            DIGI_MEMCPY(pUdpIf->serverAddress.v6.sin6_addr.s6_addr, dstAddress->uin.addr6, 16);

            if (0 > lwip_connect(pUdpIf->udpFd, (struct sockaddr *)&(pUdpIf->serverAddress), sizeof(struct sockaddr_in6)))
            {
                status = ERR_UDP_CONNECT;
                goto exit;
            }
        }
        else
#endif
#endif
        {
            pUdpIf->serverAddress.v4.sin_family = FREERTOS_AF_INET;
#ifdef __ENABLE_DIGICERT_IPV6__
            pUdpIf->serverAddress.v4.sin_addr = htonl(dstAddress->uin.addr);
#else
            pUdpIf->serverAddress.v4.sin_addr = FreeRTOS_htonl(dstAddress);
#endif
            pUdpIf->serverAddress.v4.sin_port = FreeRTOS_htons(dstPortNo);

            if (0 > FreeRTOS_connect(pUdpIf->udpFd, &(pUdpIf->serverAddress.v4), sizeof(struct freertos_sockaddr)))
            {
                status = ERR_UDP_CONNECT;
                goto exit;
            }
        }
    }


    *ppRetUdpDescr = pUdpIf;  pUdpIf = NULL;

    status = OK;

exit:
    if (NULL != pUdpIf)
    {
        if (0 != pUdpIf)
            FreeRTOS_closesocket(pUdpIf->udpFd);

        FREE(pUdpIf);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_connect(void **ppRetUdpDescr,
                  MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                  MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                  intBoolean isNonBlocking)
{
    return FREERTOS_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                               dstAddress, dstPortNo, isNonBlocking, TRUE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_simpleBind(void **ppRetUdpDescr,
                   MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                   intBoolean isNonBlocking)
{
    return FREERTOS_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                               0, 0, isNonBlocking, FALSE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_unbind(void **ppReleaseUdpDescr)
{
    FRTOS_UDP_interface*  pUdpIf;
    MSTATUS             status = ERR_NULL_POINTER;

    if (NULL == ppReleaseUdpDescr)
        goto exit;

    pUdpIf = *((FRTOS_UDP_interface **)ppReleaseUdpDescr);

    /* de-allocate LWIP_UDP_interface */
    if (NULL != pUdpIf)
    {
        if (0 != pUdpIf)
            FreeRTOS_closesocket(pUdpIf->udpFd);

        FREE(pUdpIf);
    }

    *ppReleaseUdpDescr = NULL;

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_send(void *pUdpDescr, ubyte *pData, ubyte4 dataLength)
{
    FRTOS_UDP_interface*  pUdpIf = (FRTOS_UDP_interface *)pUdpDescr;
    MSTATUS             status = OK;

    if (0 > FreeRTOS_send(pUdpIf->udpFd, (char *)pData, dataLength, 0))
        status = ERR_UDP_WRITE;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress, ubyte2 peerPortNo,
                   ubyte *pData, ubyte4 dataLength)
{
    FRTOS_UDP_interface*    pUdpIf = (FRTOS_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

#ifdef __ENABLE_DIGICERT_IPV6__
#if 0
    if (AF_INET6 == peerAddress->family)
    {
        struct sockaddr_in6 destAddress;
        destAddress.sin6_family = AF_INET6;
        destAddress.sin6_port = htons(peerPortNo);
        if (0 == (destAddress.sin6_scope_id = pUdpIf->serverAddress.v6.sin6_scope_id))
            destAddress.sin6_scope_id = peerAddress->uin.addr6[4];
        DIGI_MEMCPY(destAddress.sin6_addr.s6_addr, peerAddress->uin.addr6, 16);

        if (0 > lwip_sendto(pUdpIf->udpFd, (char *)pData, dataLength, 0,
                       (struct sockaddr *) &destAddress, sizeof(destAddress)))
        {
            status = ERR_UDP_WRITE;
        }
    }
    else
#endif
#endif
    {
        struct freertos_sockaddr destAddress;
        destAddress.sin_family = FREERTOS_AF_INET;

#ifdef __ENABLE_DIGICERT_IPV6__
        destAddress.sin_addr.s_addr = htonl(peerAddress->uin.addr);
#else
        destAddress.sin_addr = FreeRTOS_htonl(peerAddress);
#endif
        destAddress.sin_port = FreeRTOS_htons(peerPortNo);

        if (0 > FreeRTOS_sendto(pUdpIf->udpFd, (char *)pData, dataLength, 0,
                        &destAddress, sizeof(destAddress)))
        {
            status = ERR_UDP_WRITE;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_getFd(void *pUdpDescr, UDP_SOCKET *fd)
{
    FRTOS_UDP_interface   *pUdpIf = (FRTOS_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    *fd = pUdpIf->udpFd;

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_recv(void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    FRTOS_UDP_interface*  pUdpIf = (FRTOS_UDP_interface *)pUdpDescr;
    ssize_t             result;
    MSTATUS             status = OK;

    *pRetDataLength = 0;

    result = FreeRTOS_recv(pUdpIf->udpFd, (char *)pBuf, bufSize, 0);

    if (0 > result)
    {
         status = ERR_UDP_READ;
    }
    else *pRetDataLength = (ubyte4)result;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_recvFrom(void *pUdpDescr, MOC_IP_ADDRESS_S *pPeerAddress, ubyte2* pPeerPortNo,
                     ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    FRTOS_UDP_interface*    pUdpIf = (FRTOS_UDP_interface *)pUdpDescr;
    int                     result;
    MSTATUS                 status = OK;

#ifdef __ENABLE_DIGICERT_IPV6__
    struct sockaddr_in6     fromAddress = { 0 };
#else
    struct freertos_sockaddr      fromAddress = { 0 };
#endif
    int                     fromLen = sizeof(fromAddress);

    *pRetDataLength = 0;

    result = FreeRTOS_recvfrom(pUdpIf->udpFd, (char *)pBuf, bufSize, 0,
                       &fromAddress, (socklen_t *)&fromLen);

    if (0 > result)
    {
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
        /* we need to preserve the scope id for later */
        pPeerAddress->uin.addr6[4] = fromAddress.sin6_scope_id;
    }
    else
    {
        struct sockaddr_in *pFromAddress = (struct sockaddr_in *)&fromAddress;
        pPeerAddress->family = AF_INET;
        *pPeerPortNo = ntohs(pFromAddress->sin_port);
        pPeerAddress->uin.addr = ntohl(pFromAddress->sin_addr.s_addr);
    }
#else
    *pPeerAddress = FreeRTOS_ntohl(fromAddress.sin_addr);
    *pPeerPortNo = FreeRTOS_ntohs(fromAddress.sin_port);
#endif

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_getSrcPortAddr(void *pUdpDescr, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr)
{
    FRTOS_UDP_interface*    pUdpIf = (FRTOS_UDP_interface *)pUdpDescr;

#ifdef __ENABLE_DIGICERT_IPV6__
    struct sockaddr_in6     myAddress;
#else
    struct freertos_sockaddr      myAddress;
#endif
    sbyte4                  addrLen = sizeof(myAddress);
    MSTATUS                 status = OK;

    DIGI_MEMSET((ubyte *)&myAddress, 0x00, sizeof(myAddress));

    FreeRTOS_GetLocalAddress(pUdpIf->udpFd, &myAddress);

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
    *pRetPortNo = FreeRTOS_htons(myAddress.sin_port);
    *pRetAddr   = FreeRTOS_htonl(myAddress.sin_addr);
#endif

exit:
    return status;
}

extern MSTATUS
FREERTOS_UDP_selReadAvl(void *ppUdpDescr[], sbyte4 numUdpDescr,
                    ubyte4 msTimeout)
{
    MSTATUS         status = OK;

    SocketSet_t         pSocketList = NULL;
    TickType_t  timeout;
    int             ret;
    sbyte4          i;

    if (0 >= numUdpDescr) goto exit;

    if (NULL == ppUdpDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pSocketList =  FreeRTOS_CreateSocketSet()))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* add the socket of interest to the list */

    for (i=0; i < numUdpDescr; i++)
    {
        FRTOS_UDP_interface *pUdpIf = (FRTOS_UDP_interface *) ppUdpDescr[i];
        if (NULL != pUdpIf)
        {
            FreeRTOS_FD_SET(pUdpIf->udpFd, pSocketList, eSELECT_READ|eSELECT_EXCEPT);
        }
    }

    /* compute timeout (milliseconds) */
    timeout  = pdMS_TO_TICKS(msTimeout);

    ret = FreeRTOS_select(pSocketList,  timeout);
    if (0 == ret) /* timed out */
    {
        status = ERR_UDP_READ_TIMEOUT;
        goto exit;
    }

    for (i=0; i < numUdpDescr; i++)
    {
        FRTOS_UDP_interface *pUdpIf = (FRTOS_UDP_interface *) ppUdpDescr[i];
        if (NULL != pUdpIf)
        {
            if (!FreeRTOS_FD_ISSET(pUdpIf->udpFd, pSocketList))
                ppUdpDescr[i] = NULL; /* !!! */
        }
    }

exit:
    if (NULL != pSocketList)
        FreeRTOS_DeleteSocketSet(pSocketList);

    return status;
}
#endif /* __LWIP_UDP__ */

