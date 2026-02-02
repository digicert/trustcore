/*
 * MOCANA UDP Abstraction Layer
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

#ifdef __DIGICERT_UDP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/mstdlib.h"

#define _REENTRANT

/*------------------------------------------------------------------*/

#ifndef SOCKET_ERROR
#define SOCKET_ERROR    (-1)
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
MO_UDP_init(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MO_UDP_shutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MO_UDP_getInterfaceAddress(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress)
{
    MSTATUS status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MO_UDP_getAddressOfHost(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress)
{
    MSTATUS status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MO_UDP_bindConnect(void **ppRetUdpDescr,
                      MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                      MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                      intBoolean isNonBlocking, intBoolean connected)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MO_UDP_connect(void **ppRetUdpDescr,
                  MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                  MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                  intBoolean isNonBlocking)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MO_UDP_simpleBind(void **ppRetUdpDescr,
                     MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                     intBoolean isNonBlocking)
{
    return OK;

}


/*------------------------------------------------------------------*/

extern MSTATUS
MO_UDP_unbind(void **ppReleaseUdpDescr)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MO_UDP_send(void *pUdpDescr, ubyte *pData, ubyte4 dataLength)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MO_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress, ubyte2 peerPortNo,
                 ubyte *pData, ubyte4 dataLength)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MO_UDP_getFd(void *pUdpDescr, sbyte4 *fd)
{
    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
MO_UDP_recv(void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MO_UDP_recvFrom(void *pUdpDescr, MOC_IP_ADDRESS* pPeerAddress, ubyte2* pPeerPortNo,
                   ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    return OK;
}


#endif /* __DIGICERT_UDP__ */
