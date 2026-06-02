/**
 * @file  ipsec_frag.h
 * @brief NanoSec IPsec IP datagram fragmentation header.
 *
 * @details    This file contains IP fragmentation and reassembly declarations.
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

#ifndef __IPSEC_FRAG_HEADER__
#define __IPSEC_FRAG_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

#ifndef TIMEOUT_IPSEC_REASSEMBLY
#define TIMEOUT_IPSEC_REASSEMBLY (1500)   /* Reassembly Time out in ms */
#endif
#ifndef IPSEC_DGRAM_SIZE_MAX
#define IPSEC_DGRAM_SIZE_MAX     (8192)   /* Maximum IP payload size */
#endif
#ifndef IPSEC_DGRAM_MAX
#define IPSEC_DGRAM_MAX          (5)      /* Maximum number of pending IP datagrams */
#endif
#ifndef IPSEC_PACKETS_MAX
#define IPSEC_PACKETS_MAX        (5)      /* Maximum number of packets per IP datagram */
#endif


/*------------------------------------------------------------------*/

MOC_EXTERN sbyte4 IPSEC_fragInit(void);
MOC_EXTERN sbyte4 IPSEC_fragFlush(void);


/*------------------------------------------------------------------*/
/* Re-Assembly                                                      */
/*   parameters: call by reference of IP packet buffer and size     */
/*       Note: the input buffer will not be freed by this routine.  */
/*   return value:                                                  */
/*     OK : fragment copied and buffered                            */
/*     STATUS_IPSEC_BYPASS : datagram bypassed or reassembled       */
/*       In the latter case, the referenced value of 'pwBufferSize' */
/*       is adjusted to the datagram's actual size, and the re-     */
/*       assembled datagram (referenced by 'ppBuffer') may be newly */
/*       allocated, in which case the buffer must be freed by       */
/*       caller when it is no longer needed.                        */

MOC_EXTERN sbyte4 IPSEC_fragRcv(ubyte **ppBuffer, ubyte2 *pwBufferSize);


/*------------------------------------------------------------------*/
/* Fragmentation                                                    */
/*   parameters: IP packet buffer and size, MTU, 'send' function    */
/*   return value:                                                  */
/*     OK : packet fragmented and sent                              */
/*     STATUS_IPSEC_BYPASS : no fragmentation is required           */

typedef sbyte4 (*funcPtrIPsecFragSend)(void *context, ubyte *pBuffer, ubyte2 wBufferSize);

MOC_EXTERN sbyte4 IPSEC_fragSnd(ubyte *pBuffer, ubyte2 wBufferSize, ubyte2 wMtu, funcPtrIPsecFragSend pFunc, void *sendCtx);


#ifdef __cplusplus
}
#endif

#endif /* __IPSEC_FRAG_HEADER__ */

