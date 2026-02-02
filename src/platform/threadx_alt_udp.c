/*
 * threadx_alt_udp.c
 *
 * GHS THREADX UDP Abstraction Layer
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

#ifdef __THREADX_UDP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <tx_api.h>
#include <nx_api.h>
#include <nx_port.h>
#include <nx_user.h>


#define THREADX_UDP_QUEUE_MAX       32
#define UDP_RECV_TIMEOUT            10
#define UDP_SEND_TIMEOUT            NX_WAIT_FOREVER

/* defined in threadx_alt_rtos.c */
extern NX_IP            mMocIpInstance;
extern NX_PACKET_POOL   mMocPacketPool;

typedef MOC_IP_ADDRESS (*fpSetHostName)(const char *pHostname);

fpSetHostName fpHostName = NULL;


/*------------------------------------------------------------------*/

typedef struct
{
    NX_UDP_SOCKET*  pUdpSocket;

    /* next two fields allow us to simulate "binding" the interface
       to a destination */
    ULONG           dstAddress;
    UINT            dstPortNo;
} THREADX_UDP_interface;


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_init(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_shutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_getInterfaceAddress(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress)
{
    MSTATUS status = OK;

    ULONG srcAddr = 0;
    ULONG netmask;

    /* for example code we just default to the primary interface */

    if (NX_SUCCESS != nx_ip_address_get(&mMocIpInstance, &srcAddr, &netmask))
    {
        status = ERR_UDP_GETSOCKNAME;
    }

    if (0 != srcAddr)
        *pRetIpAddress = srcAddr; /* might need htonl/ntohl - not clear what format the NetX stack handles addresses */

    return status;
}

/*------------------------------------------------------------------*/
extern void
THREADX_setGetAddressOfHostMethod(fpSetHostName fp)
{
    if (NULL != fp)
        fpHostName = fp;

    return;
}

/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_getAddressOfHost(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress)
{
    MSTATUS status = ERR_UDP_HOSTNAME_NOT_FOUND;

    if (pHostName && pRetIpAddress)
    {
        if (NULL != fpHostName)
        {
            *pRetIpAddress = fpHostName(pHostName);
            status = OK;
        }
        else
            status = ERR_UDP_INTERFACE_NOT_FOUND;
    }
    else
        status = ERR_NULL_POINTER;

    return status;
}

/*------------------------------------------------------------------*/

extern ubyte4
THREADX_inet_addr (char *addrstr)
{
    ubyte4 ulIPAddress = 0, retIPAddr = 0, temp;
    ubyte i;
    const sbyte *pIter;

    if (NULL == addrstr)
    {
        goto exit;
    }

    pIter = (const sbyte *) addrstr;
    for (i = 0; i < 3; i++)
    {
        temp = DIGI_ATOL(pIter, &pIter);
        if (temp > 255)
            goto exit;

        if (*pIter++ != '.')
            goto exit;

        ulIPAddress |= temp << ((3 - i) * 8);
    }

    temp = DIGI_ATOL(pIter, &pIter);
    if (temp > 255)
        goto exit;

    ulIPAddress |= temp;

    if (*pIter++ != '\0')
        goto exit;

    retIPAddr = ulIPAddress;

exit:
    return retIPAddr;
}

/*------------------------------------------------------------------*/

extern void
THREADX_inet_ntoa (ubyte4 ulIPAddress, char *addrstr)
{
    sprintf(
        addrstr, "%u.%u.%u.%u",
        ((unsigned) (((ulIPAddress) >> 24) & 0xFFUL)),
        ((unsigned) (((ulIPAddress) >> 16) & 0xFFUL)),
        ((unsigned) (((ulIPAddress) >> 8) & 0xFFUL)),
        ((unsigned) ((ulIPAddress) & 0xFFUL)));
    return;
}

/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_bindConnect(void **ppRetUdpDescr,
                      MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                      MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                      intBoolean isNonBlocking, intBoolean connected)
{
    /* ThreadX model doesn't specifically bind destination address/port to
       a socket - they must be explicitly passed in udp_socket_send so we store
       those in our local UDP descriptor */

    THREADX_UDP_interface*  pUdpIf = NULL;
    MSTATUS                 status = ERR_UDP;
    ULONG                   blockingType = NX_WAIT_FOREVER;

    if (NULL == ppRetUdpDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetUdpDescr = NULL;

    /* allocate THREADX_UDP_interface */
    if (NULL == (pUdpIf = MALLOC(sizeof(THREADX_UDP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pUdpIf, 0x00, sizeof(THREADX_UDP_interface));

    if (NULL == (pUdpIf->pUdpSocket = MALLOC(sizeof(NX_UDP_SOCKET))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pUdpIf->pUdpSocket, 0x00, sizeof(NX_UDP_SOCKET));

    if (NX_SUCCESS != nx_udp_socket_create(&mMocIpInstance, pUdpIf->pUdpSocket,
                                           "mocUdpSocket", NX_IP_NORMAL,
                                           NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                                           THREADX_UDP_QUEUE_MAX))
    {
        status = ERR_UDP_SOCKET;
        goto exit;
    }

    if (isNonBlocking)
    {
        blockingType = NX_NO_WAIT;
    }

    if (0 > nx_udp_socket_bind(pUdpIf->pUdpSocket, (UINT) srcPortNo, blockingType))
    {
        status = ERR_UDP_BIND;
        goto exit;
    }

    if (connected)
    {
        pUdpIf->dstAddress = dstAddress;
        pUdpIf->dstPortNo = dstPortNo;
    }

    *ppRetUdpDescr = pUdpIf;
    pUdpIf = NULL;

    status = OK;

exit:
    if (NULL != pUdpIf)
    {
        if (NULL != pUdpIf->pUdpSocket)
        {
            nx_udp_socket_delete(pUdpIf->pUdpSocket); /* should check this return value? */
            FREE(pUdpIf->pUdpSocket);
        }

        FREE(pUdpIf);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_connect(void **ppRetUdpDescr,
                  MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                  MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                  intBoolean isNonBlocking)
{
    return THREADX_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                                 dstAddress, dstPortNo, isNonBlocking, TRUE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_simpleBind(void **ppRetUdpDescr,
                     MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                     intBoolean isNonBlocking)
{
    return THREADX_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                                 0, 0, isNonBlocking, FALSE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_unbind(void **ppReleaseUdpDescr)
{
    THREADX_UDP_interface*  pUdpIf;
    MSTATUS                 status = ERR_NULL_POINTER;

    if (NULL == ppReleaseUdpDescr)
        goto exit;

    pUdpIf = *((THREADX_UDP_interface **)ppReleaseUdpDescr);

    /* de-allocate THREADX_UDP_interface */
    if (NULL != pUdpIf)
    {
        if (NULL != pUdpIf->pUdpSocket)
        {
            nx_udp_socket_unbind(pUdpIf->pUdpSocket);
            nx_udp_socket_delete(pUdpIf->pUdpSocket);
            FREE(pUdpIf->pUdpSocket);
        }
        FREE(pUdpIf);
    }

    *ppReleaseUdpDescr = NULL;

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_send(void *pUdpDescr, ubyte *pData, ubyte4 dataLength)
{
    THREADX_UDP_interface*  pUdpIf = (THREADX_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;
    NX_PACKET *             pPacket = NULL;

    if (NX_SUCCESS != nx_packet_allocate(&mMocPacketPool, &pPacket, NX_UDP_PACKET, UDP_SEND_TIMEOUT))
    {
        status = ERR_UDP_WRITE;
        goto exit;
    }

    if (NX_SUCCESS != nx_packet_data_append(pPacket, (VOID *) pData, dataLength, &mMocPacketPool, UDP_SEND_TIMEOUT))
    {
        if (NULL != pPacket)
            nx_packet_release(pPacket);

        status = ERR_UDP_WRITE;
        goto exit;
    }

    if (NX_SUCCESS != nx_udp_socket_send(pUdpIf->pUdpSocket, pPacket,
                                         pUdpIf->dstAddress,
                                         (UINT) pUdpIf->dstPortNo))
    {
        status = ERR_UDP_WRITE;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress, ubyte2 peerPortNo,
                 ubyte *pData, ubyte4 dataLength)
{
    THREADX_UDP_interface*  pUdpIf = (THREADX_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;
    NX_PACKET *             pPacket = NULL;

    if (NX_SUCCESS != nx_packet_allocate(&mMocPacketPool, &pPacket, NX_UDP_PACKET, UDP_SEND_TIMEOUT))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NX_SUCCESS != nx_packet_data_append(pPacket, (VOID *) pData, dataLength, &mMocPacketPool, UDP_SEND_TIMEOUT))
    {
        if (NULL != pPacket)
            nx_packet_release(pPacket);

        status = ERR_UDP_WRITE;
        goto exit;
    }

    if (NX_SUCCESS != nx_udp_socket_send(pUdpIf->pUdpSocket, pPacket,
                                         peerAddress, (UINT) peerPortNo))
    {
        status = ERR_UDP_WRITE;
    }

exit:
/* do we need to free the packet?? send will free it, but what if there's an error appending the data? */
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_getFd(void *pUdpDescr, sbyte4 *fd)
{
    THREADX_UDP_interface*  pUdpIf = (THREADX_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    /* don't know if we need this function - the "fd" is an internal NetX struct */
    *fd = (sbyte4) pUdpIf->pUdpSocket;

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_recv(void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    THREADX_UDP_interface*  pUdpIf = (THREADX_UDP_interface *)pUdpDescr;
    NX_PACKET *             pPacket = NULL;
    MSTATUS                 status = OK;

    *pRetDataLength = 0;

    if (NX_SUCCESS != nx_udp_socket_receive(pUdpIf->pUdpSocket, &pPacket, UDP_RECV_TIMEOUT)) /* TX_WAIT_FOREVER */
    {
        status = ERR_UDP_READ;
    }
    else
    {
        if (NX_SUCCESS != nx_packet_data_retrieve(pPacket,(void *)pBuf, (ULONG *) pRetDataLength))
            status = ERR_UDP_READ;
    }

    if (NULL != pPacket)
    {
        if (NX_SUCCESS != nx_packet_release(pPacket))
            status = ERR_UDP_READ;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_recvFrom(void *pUdpDescr, MOC_IP_ADDRESS* pPeerAddress, ubyte2* pPeerPortNo,
                   ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    THREADX_UDP_interface*  pUdpIf = (THREADX_UDP_interface *)pUdpDescr;
    NX_PACKET *             pPacket = NULL;
    int                     result;
    MSTATUS                 status = OK;
    UINT                    remotePort;

    *pRetDataLength = 0;

    if (NX_SUCCESS != nx_udp_socket_receive(pUdpIf->pUdpSocket, &pPacket, UDP_RECV_TIMEOUT)) /* TX_WAIT_FOREVER */
    {
        status = ERR_UDP_READ;
        goto exit;
    }
    else
    {
        if (NX_SUCCESS != nx_packet_data_retrieve(pPacket,(void *)pBuf, (ULONG *) pRetDataLength))
            status = ERR_UDP_READ;
    }

    if (NX_SUCCESS != nx_udp_source_extract(pPacket, pPeerAddress, &remotePort))
    {
        status = ERR_UDP_READ;
        goto exit;
    }
    else
    {
    /* I don't like this cast, but I think NetX uses a 4-byte field for port numbers */
        *pPeerPortNo = (ubyte2) remotePort;
    }

exit:
    if (NULL != pPacket)
    {
        if (NX_SUCCESS != nx_packet_release(pPacket))
            status = ERR_UDP_READ;
    }
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_getSrcPortAddr(void *pUdpDescr, ubyte2 *pRetPortNo, MOC_IP_ADDRESS *pRetAddr)
{
    THREADX_UDP_interface*  pUdpIf = (THREADX_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;
    UINT                    localPort;
    ULONG                   netmask;
    ULONG                   srcAddr;

    if (NX_SUCCESS != nx_udp_socket_port_get(pUdpIf->pUdpSocket, &localPort))
    {
        status = ERR_UDP_GETSOCKNAME;
        goto exit;
    }

    *pRetPortNo = (ubyte2) localPort;

    if (NX_SUCCESS != nx_ip_address_get(&mMocIpInstance, &srcAddr, &netmask))
    {
        status = ERR_UDP_GETSOCKNAME;
        goto exit;
    }
    *pRetAddr = srcAddr;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_UDP_selReadAvl(void *ppUdpDescr[], sbyte4 numUdpDescr, ubyte4 msTimeout)
{
    MSTATUS         status = OK;
#if 0

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
        THREADX_UDP_interface *pUdpIf = (THREADX_UDP_interface *) ppUdpDescr[i];
        if (NULL != pUdpIf)
            FD_SET(pUdpIf->pUdpSocket, pSocketList);
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
        THREADX_UDP_interface *pUdpIf = (THREADX_UDP_interface *) ppUdpDescr[i];
        if (NULL != pUdpIf)
        {
            if (!FD_ISSET(pUdpIf->pUdpSocket, pSocketList))
                ppUdpDescr[i] = NULL; /* !!! */
        }
    }

exit:
    if (NULL != pSocketList)
        FREE(pSocketList);
#endif

    return status;
}


#endif /* __THREADX_UDP__ */
