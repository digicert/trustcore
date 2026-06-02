/**
 * @file  ipsec_flow.h
 * @brief NanoSec IPsec SA flow cache header.
 *
 * @details    This file contains IPsec Security Association flow cache definitions.
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


/*------------------------------------------------------------------*/

#ifndef __IPSEC_FLOW_HEADER__
#define __IPSEC_FLOW_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

struct sadb;
struct spd;

MOC_EXTERN sbyte4 IPSEC_flowGet(struct sadb **ppxSa, struct spd **ppxSp,
                                MOC_IP_ADDRESS daddr, MOC_IP_ADDRESS saddr,
                                ubyte oProtocol,
                                ubyte2 wDestPort, ubyte2 wSrcPort);

MOC_EXTERN sbyte4 IPSEC_flowDel(MOC_IP_ADDRESS daddr, MOC_IP_ADDRESS saddr,
                                ubyte oProtocol,
                                ubyte2 wDestPort, ubyte2 wSrcPort);

MOC_EXTERN void IPSEC_flowPrint(void);


/*------------------------------------------------------------------*/
/* internal use only */

extern MSTATUS IPSEC_flowInit(void);
extern MSTATUS IPSEC_flowFlush(void);

extern MSTATUS IPSEC_flowPut(struct sadb *pxSa, struct spd *pxSp,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                             ubyte oMode,
#endif
                             MOC_IP_ADDRESS daddr, MOC_IP_ADDRESS saddr,
                             ubyte oProtocol,
                             ubyte2 wDestPort, ubyte2 wSrcPort);

extern MSTATUS IPSEC_flowCheck(struct sadb *pxSa, struct spd **ppxSp,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                               ubyte oMode,
#endif
                               MOC_IP_ADDRESS daddr, MOC_IP_ADDRESS saddr,
                               ubyte oProtocol,
                               ubyte2 wDestPort, ubyte2 wSrcPort);


#ifdef __cplusplus
}
#endif

#endif /* __IPSEC_FLOW_HEADER__ */

