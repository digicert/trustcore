/*
 * OSE_udp.c
 *
 * OSE UDP Abstraction Layer
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

#ifdef __OSE_UDP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <ose.h>
#include <inet.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>


/*------------------------------------------------------------------*/

typedef struct
{
    int                 udpFd;
    struct sockaddr_in  serverAddress;

} OSE_UDP_interface;


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_UDP_init(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_UDP_shutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_UDP_getInterfaceAddress(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress)
{
/*  MSTATUS status = OK;

    *pRetIpAddress = ntohl(INADDR_ANY);
*/
    /* for example code we just default to the primary interface */
    char        myHostName[255/*HOST_NAME_MAX*/];
    MSTATUS     status = ERR_UDP_INTERFACE_NOT_FOUND;
    struct hostent *pHostAddr;

    if (NULL == pHostName)
    {
        if (0 > gethostname(myHostName, sizeof(myHostName)))
        {
            goto exit;
        }
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
OSE_UDP_getAddressOfHost(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress)
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
OSE_UDP_bindConnect(void **ppRetUdpDescr,
                      MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                      MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                      intBoolean isNonBlocking, intBoolean connected)
{
    OSE_UDP_interface*  pUdpIf = NULL;
    struct sockaddr_in      myAddr;
    MSTATUS                 status = ERR_UDP;

    if (NULL == ppRetUdpDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetUdpDescr = NULL;

    /* allocate OSE_UDP_interface */
    if (NULL == (pUdpIf = MALLOC(sizeof(OSE_UDP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pUdpIf, 0x00, sizeof(OSE_UDP_interface));
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

    /* handle socket destination end-point */
    if (FALSE != connected)
    {
        /* handle socket destination end-point */
        pUdpIf->serverAddress.sin_family = AF_INET;
        pUdpIf->serverAddress.sin_addr.s_addr = htonl(dstAddress);
        pUdpIf->serverAddress.sin_port = htons(dstPortNo);

        if (0 > connect(pUdpIf->udpFd, (struct sockaddr *)&(pUdpIf->serverAddress),
                        sizeof(pUdpIf->serverAddress)))
        {
            status = ERR_UDP_CONNECT;
            goto exit;
        }
    }

    if (FALSE != isNonBlocking)
    {
        int on = 1;

        if (-1 == inet_ioctl(pUdpIf->udpFd, FIONBIO, (char *)&on))
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
OSE_UDP_connect(void **ppRetUdpDescr,
                  MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                  MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                  intBoolean isNonBlocking)
{
    return OSE_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                                 dstAddress, dstPortNo, isNonBlocking, TRUE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_UDP_simpleBind(void **ppRetUdpDescr,
                     MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                     intBoolean isNonBlocking)
{
    return OSE_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                                 0, 0, isNonBlocking, FALSE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_UDP_unbind(void **ppReleaseUdpDescr)
{
    OSE_UDP_interface*  pUdpIf;
    MSTATUS                 status = ERR_NULL_POINTER;

    if (NULL == ppReleaseUdpDescr)
        goto exit;

    pUdpIf = *((OSE_UDP_interface **)ppReleaseUdpDescr);

    /* de-allocate OSE_UDP_interface */
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
OSE_UDP_send(void *pUdpDescr, ubyte *pData, ubyte4 dataLength)
{
    OSE_UDP_interface*    pUdpIf = (OSE_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    if (0 > inet_send(pUdpIf->udpFd, pData, dataLength, 0))
        status = ERR_UDP_WRITE;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress, ubyte2 peerPortNo,
                 ubyte *pData, ubyte4 dataLength)
{
    OSE_UDP_interface*    pUdpIf = (OSE_UDP_interface *)pUdpDescr;
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
OSE_UDP_getFd(void *pUdpDescr, sbyte4 *fd)
{
    OSE_UDP_interface*  pUdpIf = (OSE_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    *fd = pUdpIf->udpFd;

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
OSE_UDP_recv(void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    OSE_UDP_interface*    pUdpIf = (OSE_UDP_interface *)pUdpDescr;
    ssize_t                 result;
    MSTATUS                 status = OK;

    *pRetDataLength = 0;

    result = recv(pUdpIf->udpFd, (char *)pBuf, bufSize, 0);

    if (0 > result)
    {
        if (EAGAIN != errno)
             status = ERR_UDP_READ;
    }
    else *pRetDataLength = (ubyte4)result;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_UDP_recvFrom(void *pUdpDescr, MOC_IP_ADDRESS* pPeerAddress, ubyte2* pPeerPortNo,
                   ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    OSE_UDP_interface*    pUdpIf = (OSE_UDP_interface *)pUdpDescr;
    int                     result;
    struct sockaddr_in      fromAddress;
    int                     fromLen = sizeof(fromAddress);
    MSTATUS                 status = OK;

    *pRetDataLength = 0;

    result = recvfrom(pUdpIf->udpFd, (char *)pBuf, bufSize, 0,
                     (struct sockaddr *) &fromAddress, &fromLen);

    if (0 > result)
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
OSE_UDP_getSrcPortAddr(void *pUdpDescr, ubyte2 *pRetPortNo, MOC_IP_ADDRESS *pRetAddr)
{
    OSE_UDP_interface*    pUdpIf = (OSE_UDP_interface *)pUdpDescr;
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


/*------------------------------------------------------------------*/

extern MSTATUS
OSE_UDP_selReadAvl(void *ppUdpDescr[], sbyte4 numUdpDescr, ubyte4 msTimeout)
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
        OSE_UDP_interface *pUdpIf = (OSE_UDP_interface *) ppUdpDescr[i];
        if (NULL != pUdpIf)
            FD_SET(pUdpIf->udpFd, pSocketList);
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
    if (0 > ret)
    {
        status = ERR_UDP_READ;
        goto exit;
    }

    for (i=0; i < numUdpDescr; i++)
    {
        OSE_UDP_interface *pUdpIf = (OSE_UDP_interface *) ppUdpDescr[i];
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


#endif /* __OSE_UDP__ */
