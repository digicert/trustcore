/*
 * FREERTOS_Wiznet_udp.c
 *
 * FREERTOS UDP Abstraction Layer: provides the API to be called for performing the
 * the UDP socket related work using Wiznet IOMedia library.
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

#include "../common/moptions.h"

#ifdef __WIZNET_UDP__

#include "FREERTOS_Wiznet_sock.h"
#include "../wpa2/wpa2_wiznet.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"


ubyte m_socketNumber[_WIZCHIP_SOCK_NUM_];

#define _REENTRANT

#include <errno.h>
#if !defined(__IAR_SYSTEMS_ICC__)
#include <sys/types.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <signal.h>


typedef struct
{
    int                 udpFd;
} FREERTOS_UDP_interface;


extern MSTATUS
FREERTOS_UDP_init()
{
    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/
extern MSTATUS
FREERTOS_UDP_getInterfaceAddress(sbyte *pHostName,
                                MOC_IP_ADDRESS_S *pRetIpAddress)
{
    return OK;
}

extern MSTATUS
FREERTOS_UDP_getAddressOfHost(sbyte *pHostName, MOC_IP_ADDRESS_S *pRetIpAddress)
{
    return OK;
}

/**********************************************************************
*
*  NAME
*  FREERTOS_UDP_bindConnect  -- Creating a socket to read/write data over socket.
*
*  SYNOPSIS
*  static MSTATUS FREERTOS_UDP_bindConnect(void **ppRetUdpDescr,
*                        MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
*                        MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
*                        intBoolean isNonBlocking, intBoolean connected)
*
*
*  FUNCTION
*  This function is called as a part of UDP socket abstraction.
*
*  INPUTS
*    ppRetUdpDescr       : udp socket descriptor
*    srcAddress         : source machine ip address
*    srcPortNo          : source port number to receive data
*    dstAddress         : destination machine ip address
*    dstPortNo          : Destination port number to recive data from
*    isNonBlocking      : is the socket cretaed as blocking or non blocking.
*    connected          : Is socket already connected
*
*  RESULT
*   Returns an error code, or OK
*
**********************************************************************/
static MSTATUS
FREERTOS_UDP_bindConnect(void **ppRetUdpDescr,
                        MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                        MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                        intBoolean isNonBlocking, intBoolean connected)
{

    UDP_SOCKET          newSocket = FAIL;
    int                     nRet;
    MSTATUS                 status  = OK;
    FREERTOS_UDP_interface  *pUdpIf = NULL;
    uint8_t socketNumber = 0;
    sbyte sock  = -1;

/*  DB_PRINT("connect UDP socket to port number = %d\r\n", srcPortNo);&/



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

    /* allocate FREERTOS_UDP_interface */
    if (NULL == (pUdpIf = (FREERTOS_UDP_interface*)
                            MALLOC(sizeof(FREERTOS_UDP_interface))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)pUdpIf, 0x00, sizeof(FREERTOS_UDP_interface));

    sock = get_socket_number();

    newSocket = socket(sock, Sn_MR_UDP, srcPortNo, 0x00);

    if( newSocket == FAIL )
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte*)"FREERTOS_UDP_bindConnect: Could not create listen socket");
        status = ERR_UDP_SOCKET;
        goto exit;
    }
    /*FREERTOS_UDP_interface*/
    pUdpIf->udpFd = sock;
    *ppRetUdpDescr = pUdpIf;  pUdpIf = NULL;

exit:
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

/**********************************************************************
*
*  NAME
*  FREERTOS_UDP_unbind  -- Creating a socket to read/write data over socket.
*
*  SYNOPSIS
*  static MSTATUS FREERTOS_UDP_unbind(void **ppReleaseUdpDescr)
*
*
*  FUNCTION
*  This function is called as a part of UDP socket abstraction. to unbind socket from a port.
*
*  INPUTS
*    ppRetUdpDescr       : udp socket descriptor
*
*  RESULT
*   Returns an error code, or OK
*
**********************************************************************/
extern MSTATUS
FREERTOS_UDP_unbind(void **ppReleaseUdpDescr)
{
    FREERTOS_UDP_interface     *pUdpIf;
    MSTATUS                 status = ERR_NULL_POINTER;

    if (NULL == ppReleaseUdpDescr)
        goto exit;

    pUdpIf = *((FREERTOS_UDP_interface **)ppReleaseUdpDescr);

    /* de-allocate LINUX_UDP_interface */
    if (NULL != pUdpIf)
    {
        if (0 < pUdpIf->udpFd)
        {
            close(pUdpIf->udpFd);
            clear_socket_number(pUdpIf->udpFd);
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
FREERTOS_UDP_send(void *pUdpDescr, ubyte *pData, ubyte4 dataLength)
{
    return OK;
}


/*------------------------------------------------------------------*/
/**********************************************************************
*
*  NAME
*  FREERTOS_UDP_sendTo  -- Creating a socket to read/write data over socket.
*
*  SYNOPSIS
*  static MSTATUS FREERTOS_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress,
*                ubyte2 peerPortNo, ubyte *pData, ubyte4 dataLength)
*
*
*  FUNCTION
*  This function is called as a part of UDP socket abstraction to send data to provided
*  ip and port.
*
*  INPUTS
*    ppRetUdpDescr       : udp socket descriptor
*    peerAddress        : destination machine ip address
*    peerPortNo     : Destination port number to recive data from
*    pData          : pointer to buffer that need to be transmitted..
*    dataLength     : Length of data to be transmitted.
*
*  RESULT
*   Returns an error code, or OK
*
**********************************************************************/
extern MSTATUS
FREERTOS_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress,
                ubyte2 peerPortNo, ubyte *pData, ubyte4 dataLength)
{
    FREERTOS_UDP_interface  *pUdpIf = (FREERTOS_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;
    uint8_t                 address[sizeof(MOC_IP_ADDRESS)];


    if((NULL == pUdpIf)||(pUdpIf->udpFd < 0))
    {
        return ERR_UDP_WRITE;
    }
    DIGI_MEMCPY(address, &peerAddress, sizeof(MOC_IP_ADDRESS));
    if (0 > sendto(pUdpIf->udpFd, (char *)pData, dataLength,address ,peerPortNo))
    {
        status = ERR_UDP_WRITE;
    }

    return status;
}


/*------------------------------------------------------------------*/
/**********************************************************************
*
*  NAME
*  FREERTOS_UDP_getFd  -- Creating a socket to read/write data over socket.
*
*  SYNOPSIS
*  static MSTATUS FREERTOS_UDP_getFd(void *pUdpDescr,sbyte4 *fd)
*
*
*  FUNCTION
*  This function is called as a part of UDP socket abstraction to fetch the socket descriptor
* from descriptor pointer.
*
*  INPUTS
*    ppRetUdpDescr       : udp socket descriptor
*    fd             : pointer to file descriptor to be filled.
*
*  RESULT
*   Returns an error code, or OK
*
**********************************************************************/
extern MSTATUS
FREERTOS_UDP_getFd(void *pUdpDescr, sbyte4 *fd)
{
    FREERTOS_UDP_interface     *pUdpIf = (FREERTOS_UDP_interface *)pUdpDescr;
    MSTATUS                 status = OK;

    *fd = pUdpIf->udpFd;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_recv(void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize,
                ubyte4 *pRetDataLength)
{
    return OK;
}


/*------------------------------------------------------------------*/
/**********************************************************************
*
*  NAME
*  FREERTOS_UDP_recvFrom  -- Creating a socket to read/write data over socket.
*
*  SYNOPSIS
*  static MSTATUS FREERTOS_UDP_recvFrom(void *pUdpDescr,
*                           MOC_IP_ADDRESS_S *pPeerAddress,
*                     ubyte2 *pPeerPortNo, ubyte *pBuf, ubyte4 bufSize,
*                           ubyte4 *pRetDataLength)
*
*
*  FUNCTION
*  This function is called as a part of UDP socket abstraction.
*
*  INPUTS
*    pUdpDescr          : udp socket descriptor
*    pPeerAddress       : pointer to source machine ip address
*    pPeerPortNo        : source port number to receive data
*    pBuf               : Buffer to data received
*    bufSize            : Size of buffer passed.
*    pRetDataLength : Pointer to size of data received.
*
*  RESULT
*   Returns an error code, or OK
*
**********************************************************************/
extern MSTATUS
FREERTOS_UDP_recvFrom(void *pUdpDescr, MOC_IP_ADDRESS_S *pPeerAddress,
                    ubyte2 *pPeerPortNo, ubyte *pBuf, ubyte4 bufSize,
                    ubyte4 *pRetDataLength)
{
    FREERTOS_UDP_interface     *pUdpIf = (FREERTOS_UDP_interface *)pUdpDescr;
    int                     result;
    MSTATUS                 status = OK;
    ubyte2                  svr_port;
    ubyte                   svr_addr[ETH_ALEN];

    *pRetDataLength = 0;

    if(pUdpIf->udpFd < 0)
    {
        return ERR_UDP_READ;
    }
    if((result = getSn_RX_RSR(pUdpIf->udpFd)) > 0)
    {
        result = recvfrom(pUdpIf->udpFd, (ubyte *)pBuf, bufSize, svr_addr, &svr_port);
        if(0 >= result)
        {
            return ERR_UDP_READ;
        }
        DIGI_MEMCPY(pPeerAddress, svr_addr, sizeof(MOC_IP_ADDRESS));
        *pPeerPortNo = svr_port;
    }
    else
    {
        return ERR_UDP_READ;
    }

    *pRetDataLength = (ubyte4)result;
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_UDP_getSrcPortAddr(void *pUdpDescr, ubyte2 *pRetPortNo,
                            MOC_IP_ADDRESS_S *pRetAddr)
{
    return OK;
}


/*------------------------------------------------------------------*/
/**********************************************************************
*
*  NAME
*  FREERTOS_UDP_selReadAvl  -- Creating a socket to read/write data over socket.
*
*  SYNOPSIS
*  static MSTATUS FREERTOS_UDP_selReadAvl(void *ppUdpDescr[], sbyte4 numUdpDescr,
*                    ubyte4 msTimeout)
*
*
*  FUNCTION
*  This function is called as a part of UDP socket abstraction.
*
*  INPUTS
*    ppUdpDescr[]           : udp socket descriptor array
*    numUdpDescr        : Number of entries in ppUdpDescr
*    msTimeout      : Timeout for select call
*
*  RESULT
*   Returns an error code, or OK
*
**********************************************************************/
extern MSTATUS
FREERTOS_UDP_selReadAvl(void *ppUdpDescr[], sbyte4 numUdpDescr,
                    ubyte4 msTimeout)
{
    MSTATUS         status = OK;

    int             ret = 0;
    sbyte4          i;

    if (0 >= numUdpDescr) goto exit;

    if (NULL == ppUdpDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (i=0; i < numUdpDescr; i++)
    {
        FREERTOS_UDP_interface *pUdpIf = (FREERTOS_UDP_interface *) ppUdpDescr[i];
        if (NULL != pUdpIf)
        {
            ret  = wizchip_select(pUdpIf->udpFd);
            if(0 >= ret )
            {
                /* Error scenario set descriptor to NULL.*/
                ppUdpDescr[i] = NULL; /* !!! */
            }
        }
    }

exit:
    return status;
}


#endif /* __WIZNET_UDP__ */
