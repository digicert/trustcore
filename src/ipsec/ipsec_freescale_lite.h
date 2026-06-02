/**
 * @file  ipsec_freescale_lite.h
 * @brief NanoSec IPsec Freescale lite header.
 *
 * @details    This header file contains definitions and declarations for
 *             IPsec implementation optimized for Freescale platforms.
 * @since      1.41
 * @version    5.3 and later
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

#ifndef __IPSEC_HEADER__
#define __IPSEC_HEADER__

/* To enable IPsec, #define __ENABLE_DIGICERT_IPSEC_SERVICE__ in "moptions.h". */

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/
/* To customize, #define the following symbols in "moptions.h".     */

/* internal sizes */
#ifndef IPSEC_SADB_MAX
#define IPSEC_SADB_MAX          (128)   /* maximum # of IPsec SA's */
#endif
#ifndef IPSEC_SPD_MAX
#define IPSEC_SPD_MAX           (16)    /* maximum # of IPsec policies (per direction); <= 16383 (0x3fff) */
#endif
#ifndef IPSEC_NEST_MAX
#define IPSEC_NEST_MAX          (2)     /* maximum SA bundle size; e.g. 2=AH+ESP */
#endif


#if defined(__ENABLE_IPSEC_NULL_TUNNEL__) && defined(__DISABLE_IPSEC_TUNNEL_MODE__)
#undef __ENABLE_IPSEC_NULL_TUNNEL__
#endif


/*------------------------------------------------------------------*/

#define MOC_COOKIE(c)
#define MOC_COOKIE_VALUE(c)
#define MOC_COOKIE_REQ_VALUE(c) , 0
#define MOC_COOKIE1(c)          void
#define MOC_COOKIE1_VALUE(c)
#define SET_MOC_COOKIE(d, s)
#define MOC_COOKIE_UNUSED(c)    MOC_UNUSED(c);
#ifdef USE_MOC_COOKIE
    #undef USE_MOC_COOKIE
#endif


#define MOC_INTF(i)
#define MOC_INTF_ID(i)
#define MOC_INTF_REQ_ID(i)      , 0
#define MOC_INTF_OPAQ(o, i)
#define MOC_INTF_OPAQ_ID(o, i)
#define MOC_INTF_UNUSED(i)      MOC_UNUSED(i);


/*------------------------------------------------------------------*/

MOC_EXTERN sbyte4 IPSEC_init(void);
MOC_EXTERN sbyte4 IPSEC_flush(void);


/*------------------------------------------------------------------*/
/* Apply IPsec policies to an outbound packet. If security is re-   */
/* quired, security associations (SAs) are applied to protect the   */
/* packet.                                                          */

#define IPSEC_apply(b,s,l,o,c) IPSEC_applyEx(b,s,l,o,NULL)


/*------------------------------------------------------------------*/
/* Check if the inbound packet should be permitted to pass through  */
/* to the upper IP layers. IPsec processing is performed on a pro-  */
/* tected packet (i.e. with an AH or ESP payload).                  */

#define IPSEC_permit(b,s,l,o,c) IPSEC_permitEx(b,s,l,o,NULL)


/*------------------------------------------------------------------*/
/* internal use only */

struct spd;

MOC_EXTERN sbyte4 IPSEC_ready(MOC_IP_ADDRESS dwDestAddr,
                          MOC_IP_ADDRESS dwSrcAddr,
                          ubyte oProto,
                          intBoolean bFragOff, intBoolean bMoreFrags,
                          ubyte2 wDestPort, ubyte2 wSrcPort,
                          intBoolean bInbound, struct spd **ppxSP,
                          sbyte4 ifid, ubyte4 cookie);


struct ipsecCtx;

MOC_EXTERN sbyte4 IPSEC_applyEx(ubyte *pBuffer, ubyte2 wBufSize,
                                ubyte2 *pwLength, ubyte2 *pwOffset,
                                struct ipsecCtx *ctx);


MOC_EXTERN sbyte4 IPSEC_permitEx(ubyte *pBuffer, ubyte2 wBufSize,
                                 ubyte2 *pwLength, ubyte2 *pwOffset,
                                 struct ipsecCtx *ctx);


/*------------------------------------------------------------------*/

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__

#include "../ipsec/ipsec_defs.h"

#if (defined(__LINUX_RTOS__) && defined(__KERNEL__))
struct sk_buff;
struct nf_info;
#elif ((defined(__QNX_RTOS__) && defined(_KERNEL)) || \
       (defined(__VXWORKS_RTOS__) && !defined(IPCOM_KERNEL)))
struct mbuf;
#elif ((defined(__OSE_RTOS__) || defined(__VXWORKS_RTOS__)) && defined(IPCOM_KERNEL))
struct Ipcom_pkt_struct;
struct Ipnet_netif_struct;
#endif

#endif

struct sadb;

typedef struct ipsecCtx
{
    struct spd *pxSp;
    struct sadb *axSaUsed[IPSEC_NEST_MAX];

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
    intBoolean bAsyncEnabled;

    sbyte4 status;

    ubyte2 wBufSize;    /* out */
    ubyte2 wOffset;     /* out */

    ubyte *poPayload;   /* in */

#ifdef __ENABLE_DIGICERT_IPV6__
    ubyte *poNextHeader;
#endif
    ubyte2 wIpHdrLen;
    ubyte2 wLength;
    MOC_IP_ADDRESS_S dwSrcAddr;
    MOC_IP_ADDRESS_S dwDestAddr;

    ubyte2 wIPsecHdrLen;/* in */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    ubyte  oMode;       /* in */
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2 wUdpEncPort;
#endif
    sbyte4 counter;

#if defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
    ubyte4 adwSeqNbr[IPSEC_NEST_MAX];   /* in */
#endif
    hwAccelDescr    hwAccelCtx;

    BulkCtx pCipherCtx;

#if (defined(__LINUX_RTOS__) && defined(__KERNEL__))
    struct sk_buff *skb;
    struct nf_info *info;
#elif ((defined(__QNX_RTOS__) && defined(_KERNEL)) || \
       (defined(__VXWORKS_RTOS__) && !defined(IPCOM_KERNEL)))
    struct mbuf *mb;
    ubyte *data;
#elif ((defined(__OSE_RTOS__) || defined(__VXWORKS_RTOS__)) && defined(IPCOM_KERNEL))
    struct Ipcom_pkt_struct *pkt;
    struct Ipnet_netif_struct *netif;
    void *rt;
    void *nexthop;
    ubyte flags;
#endif

#endif /* __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__ */

} *IPSECCTX;


#ifdef __cplusplus
}
#endif

#endif /* __IPSEC_HEADER__ */

