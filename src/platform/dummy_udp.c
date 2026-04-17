/*
 * dummy_udp.c
 *
 * Dummy UDP Abstraction Layer
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

#ifdef __DUMMY_UDP__

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
    int dummy;
} DUMMY_UDP_interface;


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_UDP_init(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_UDP_shutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_UDP_getInterfaceAddress(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_UDP_getAddressOfHost(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress)
{
    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
DUMMY_UDP_bindConnect(void **ppRetUdpDescr,
                    MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                    MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                    intBoolean isNonBlocking, intBoolean connected)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_UDP_connect(void **ppRetUdpDescr,
                  MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                  MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo,
                  intBoolean isNonBlocking)
{
    return DUMMY_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                               dstAddress, dstPortNo, isNonBlocking, TRUE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_UDP_simpleBind(void **ppRetUdpDescr,
                   MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo,
                   intBoolean isNonBlocking)
{
    return DUMMY_UDP_bindConnect(ppRetUdpDescr, srcAddress, srcPortNo,
                               0, 0, isNonBlocking, FALSE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_UDP_unbind(void **ppReleaseUdpDescr)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_UDP_send(void *pUdpDescr, ubyte *pData, ubyte4 dataLength)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_UDP_sendTo(void *pUdpDescr, MOC_IP_ADDRESS peerAddress, ubyte2 peerPortNo,
               ubyte *pData, ubyte4 dataLength)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_UDP_recv(void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_UDP_recvFrom(void *pUdpDescr, MOC_IP_ADDRESS* pPeerAddress, ubyte2* pPeerPortNo,
                 ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength)
{
    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DUMMY_UDP_getSrcPortAddr(void *pUdpDescr, ubyte2 *pRetPortNo, MOC_IP_ADDRESS *pRetAddr)
{
    return OK;
}

#endif /* __DUMMY_UDP__ */

