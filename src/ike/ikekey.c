/**
 * @file  ikekey.c
 * @brief IKE IPsec SA key management.
 *
 * @details    IKE developer API for IPsec SA installation and management.
 * @since      1.41
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     Additionally, the following flag must NOT be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_PFKEY__
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

#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && !defined(__ENABLE_DIGICERT_PFKEY__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_protos.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"
#include "../ipsec/spd.h"
#include "../ipsec/sadb.h"
#include "../ike/ike.h"
#include "../ike/ikekey.h"
#include "../ike/ike_event.h"
#include "../ike/ike_utils.h"


#if defined(__VXWORKS_RTOS__) && defined(__ENABLE_DIGICERT_IPSEC_SERVICE__)
#define IPSEC_IKE_SETTINGS  IKE_ikeSettings_ex
#else
#define IPSEC_IKE_SETTINGS  IKE_ikeSettings
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
IKE_keyAcquire(MOC_IP_ADDRESS dwDestAddr, MOC_IP_ADDRESS dwSrcAddr,
               ubyte oUlp,
               ubyte2 wDestPort, ubyte2 wSrcPort,
               SPD pxSp
               MOC_INTF(ifid)
               MOC_COOKIE(cookie))
{
    MSTATUS status = OK;

    struct ike_event evt = { 0 };
    sbyte4 i;

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    intBoolean bGdoi = FALSE;
#endif
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    MOC_IP_ADDRESS dstAddr = dwDestAddr;
    MOC_IP_ADDRESS srcAddr = dwSrcAddr;
#else
    #define dstAddr dwDestAddr
    #define srcAddr dwSrcAddr
#endif

    /* check send() function */
    if (NULL == IPSEC_IKE_SETTINGS()->funcPtrIkeEvtSend)
    {
        DIGICERT_log(MOCANA_IKE, LS_MAJOR, (sbyte *)"IKE_ikeSettings()->funcPtrIkeEvtSend not set");
        status = ERR_IKE_CONFIG;
        goto exit;
    }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_MODE_TUNNEL == pxSp->oMode)
    {
        if (!ISZERO_MOC_IPADDR(pxSp->dwTunlDestIP))
            dstAddr = REF_MOC_IPADDR(pxSp->dwTunlDestIP);

        if (!ISZERO_MOC_IPADDR(pxSp->dwTunlSrcIP))
            srcAddr = REF_MOC_IPADDR(pxSp->dwTunlSrcIP);
    }

#ifdef __ENABLE_IPSEC_COOKIE__
    if((ISZERO_MOC_IPADDR(pxSp->dwTunlDestIP) || ISZERO_MOC_IPADDR(pxSp->dwTunlSrcIP)) &&
        IKE_ikeSettings()->funcPtrIpsecGetTunnelIP)
    {
        status = (MSTATUS)IKE_ikeSettings()->funcPtrIpsecGetTunnelIP( &dstAddr,
                    &srcAddr MOC_INTF_REQ_ID(ifid) MOC_COOKIE_REQ_VALUE(cookie));
        if(OK > status)
        {
            goto exit;
        }
    }
#endif

#endif

    /* sanity check */
#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == dstAddr->family)
    {
        const ubyte *addr6 = GET_MOC_IPADDR6(dstAddr);
        if (0xFF == addr6[0]) /* multicast */
        {
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
            bGdoi = TRUE;
#else
            status = ERR_IPSEC;
            goto exit;
#endif
        }
    }
    else
#endif
    {
        ubyte4 dwAddr = GET_MOC_IPADDR4(dstAddr);
#ifndef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        if ((dwAddr & 0xe0000000) == 0xe0000000)
            bGdoi = TRUE;
        else if (0 == dwAddr)
#else
        if ((0 == dwAddr) ||
            /* check multicast/broadcast */
            ((dwAddr & 0xe0000000) == 0xe0000000))
#endif
#else
#if defined( __ENABLE_DIGICERT_GDOI_CLIENT__) && defined (__ENABLE_DIGICERT_IPSEC_SERVICE__)
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    if (pxSp->isUnicastGDOI || pxSp->isGdoi || ((dwAddr & 0xe0000000) == 0xe0000000))
#else
        if (pxSp->isGdoi || ((dwAddr & 0xe0000000) == 0xe0000000))
#endif
            bGdoi = TRUE;
        else
#endif
#endif
        {
            status = ERR_IPSEC;
            goto exit;
        }
    }

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) && !defined(__DISABLE_IPSEC_TUNNEL_MODE__)
    if (bGdoi &&
        (IPSEC_MODE_TUNNEL == pxSp->oMode) &&
        !ISZERO_MOC_IPADDR(dstAddr))
    {
        /* jic - tunnel mode w/ multicast dest address */
        status = ERR_IPSEC;
        goto exit;
    }
#endif
#ifndef __ENABLE_DIGICERT_GDOI_CLIENT__   /* for GDOI client allow 0 value*/
    TEST_MOC_IPADDR6(srcAddr,
    {
        const ubyte *addr6 = GET_MOC_IPADDR6(srcAddr);
        if (0xFF == addr6[0]) /* multicast */
        {
            status = ERR_IPSEC;
            goto exit;
        }
    })
    {
        ubyte4 dwAddr = GET_MOC_IPADDR4(srcAddr);
        if ((0 == dwAddr) ||
            /* check multicast/broadcast */
            ((dwAddr & 0xe0000000) == 0xe0000000))
        {
            status = ERR_IPSEC;
            goto exit;
        }
    }
#endif

    /* initialize event */
    evt.type = IKE_KEY_TYPE_ACQUIRE;

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    if (bGdoi)
    {
        evt.type |= IKE_KEY_MOD_GDOI; /* !!! */
    }
#endif
    COPY_MOC_IPADDR(evt.dwDestAddr, dstAddr);
    COPY_MOC_IPADDR(evt.dwSrcAddr, srcAddr);
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    if(pxSp->fqdn[0] != 0)
    {
        DIGI_MEMCPY(evt.fqdn, pxSp->fqdn, MOC_MAX_FQDN_LEN);
    }
#endif

#ifdef __ENABLE_IPSEC_NAT_T__
    /*evt.wUdpEncPort     = pxSp->wUdpEncPort;*/
#endif
    evt.oUlp = (IPSEC_SP_FLAG_PFP_ULP & pxSp->flags)
             ? oUlp : pxSp->oProto;

    if ((IPSEC_SP_FLAG_PFP_RPORT & pxSp->flags)
#ifdef __ENABLE_IPSEC_PORT_RANGE__
     || (0 != pxSp->wDestPortEnd)
#endif
        )
        evt.wDestPort = wDestPort;
    else
        evt.wDestPort = pxSp->wDestPort;

    if ((IPSEC_SP_FLAG_PFP_LPORT & pxSp->flags)
#ifdef __ENABLE_IPSEC_PORT_RANGE__
     || (0 != pxSp->wSrcPortEnd)
#endif
        )
        evt.wSrcPort = wSrcPort;
    else
        evt.wSrcPort = pxSp->wSrcPort;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    evt.oMode               = pxSp->oMode;
#else
    evt.oMode               = IPSEC_MODE_TRANSPORT;
#endif

#if !defined(__DISABLE_IPSEC_TUNNEL_MODE__) || defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
    if (
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        (IPSEC_MODE_TUNNEL == evt.oMode) ||
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        bGdoi ||
#endif
        FALSE)
    {
        if (IPSEC_SP_FLAG_PFP_RADDR & pxSp->flags)
        {
            evt.dwDestIP    =
            evt.dwDestIPEnd = DEREF_MOC_IPADDR(dwDestAddr);
        }
        else
        {
            evt.dwDestIP    = pxSp->dwDestIP;
            evt.dwDestIPEnd = pxSp->dwDestIPEnd;
        }

        if (IPSEC_SP_FLAG_PFP_LADDR & pxSp->flags)
        {
            evt.dwSrcIP     =
            evt.dwSrcIPEnd  = DEREF_MOC_IPADDR(dwSrcAddr);
        }
        else
        {
            evt.dwSrcIP     = pxSp->dwSrcIP;
            evt.dwSrcIPEnd  = pxSp->dwSrcIPEnd;
        }
    }
#endif /* !defined(__DISABLE_IPSEC_TUNNEL_MODE__) || defined(__ENABLE_DIGICERT_GDOI_CLIENT__) */

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    evt.ifid            = pxSp->ifid;
#endif
    SET_MOC_COOKIE(evt.cookie, cookie)

    evt.oSaLen          = pxSp->oSaLen;
    for (i = evt.oSaLen - 1; i >= 0; i--)
        evt.pxSa[i]     = pxSp->pxSa[i];

    evt.dwSpdId         = pxSp->dwId;
    evt.spdIndex        = pxSp->index;

    evt.dwExpSecs       = pxSp->dwSaSecs;
    evt.dwExpKBytes     = (pxSp->dwSaBytes + 1023) / (ubyte4)1024;

    /* send event */
    status = IPSEC_IKE_SETTINGS()->funcPtrIkeEvtSend((ubyte *)&evt, sizeof(evt),
                                                  srcAddr
                                                  MOC_COOKIE_REQ_VALUE(cookie));

exit:
    return status;
} /* IKE_keyAcquire */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_keyAcqExp(SADB pxSa, ubyte2 type)
{
    MSTATUS status;

    struct ike_event evt = { 0 };
    SPD pxSp = pxSa->pxSp;
    sbyte4 i;

    /* check send() function */
    if (NULL == IPSEC_IKE_SETTINGS()->funcPtrIkeEvtSend)
    {
        DIGICERT_log(MOCANA_IKE, LS_MAJOR, (sbyte *)"IKE_ikeSettings()->funcPtrIkeEvtSend not set");
        status = ERR_IKE_CONFIG;
        goto exit;
    }

    if (NULL == pxSp) /* jic */
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* initialize event */
    evt.type            = type;

    evt.dwDestAddr      = pxSa->dwSaDestAddr;
    evt.dwSrcAddr       = pxSa->dwSaSrcAddr;

#ifdef __ENABLE_IPSEC_NAT_T__
    evt.wUdpEncPort     = ((IPSEC_SA_FLAG_NAT_PEER & pxSa->saFlags)
                        ? pxSa->wSaUdpEncPort : 0);
#endif
    evt.dwIkeSaId       = pxSa->dwIkeSaId;
    evt.ikeSaLoc        = pxSa->ikeSaLoc;

    evt.wDestPort       = pxSa->wSaDestPort;
    evt.wSrcPort        = pxSa->wSaSrcPort;

    evt.oUlp            = pxSa->oSaUlp;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_MODE_TUNNEL == (
    evt.oMode           = pxSa->oSaMode))
    {
        evt.dwDestIP    = pxSa->dwSaDestIP;
        evt.dwDestIPEnd = pxSa->dwSaDestIPEnd;

        evt.dwSrcIP     = pxSa->dwSaSrcIP;
        evt.dwSrcIPEnd  = pxSa->dwSaSrcIPEnd;
    }
#else
    evt.oMode           = IPSEC_MODE_TRANSPORT;
#endif /* __DISABLE_IPSEC_TUNNEL_MODE__ */

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    evt.ifid            = pxSp->ifid;
#endif
    SET_MOC_COOKIE(evt.cookie, pxSa->cookie)

    evt.oSaLen          = pxSp->oSaLen;
    for (i = evt.oSaLen - 1; i >= 0; i--)
        evt.pxSa[i]     = pxSp->pxSa[i];

    evt.dwSpdId         = pxSp->dwId;
    evt.spdIndex        = pxSp->index;

    evt.dwExpSecs       = pxSp->dwSaSecs;
    evt.dwExpKBytes     = (pxSp->dwSaBytes + 1023) / (ubyte4)1024;

    /* send event */
    status = IPSEC_IKE_SETTINGS()->funcPtrIkeEvtSend((ubyte *)&evt, sizeof(evt),
                                                  REF_MOC_IPADDR(pxSa->dwSaSrcAddr)
                                                  MOC_COOKIE_REQ_VALUE(pxSa->cookie));

exit:
    return status;
} /* IKE_keyAcqExp */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_keyInform(MOC_IP_ADDRESS dwDestAddr,
              MOC_IP_ADDRESS dwSrcAddr,
#ifdef __ENABLE_IPSEC_NAT_T__
              ubyte2 wUdpEncPort,
#endif
              ubyte4 dwSpi, ubyte oProtocol,
              ubyte4 dwIkeSaId, sbyte4 ikeSaLoc,
              ubyte2 type
              MOC_COOKIE(cookie))
{
    MSTATUS status = OK;

    struct ike_event evt = { 0 };

    /* check send() function */
    if (NULL == IPSEC_IKE_SETTINGS()->funcPtrIkeEvtSend)
    {
        DIGICERT_log(MOCANA_IKE, LS_WARNING, (sbyte *)"IKE_ikeSettings()->funcPtrIkeEvtSend not set");
        status = ERR_IKE_CONFIG;
        goto exit;
    }

    /* initialize event */
    evt.type        = type;

    COPY_MOC_IPADDR(evt.dwDestAddr, dwDestAddr);
    COPY_MOC_IPADDR(evt.dwSrcAddr, dwSrcAddr);

#ifdef __ENABLE_IPSEC_NAT_T__
    evt.wUdpEncPort = wUdpEncPort;
#endif
    evt.dwIkeSaId   = dwIkeSaId;
    evt.ikeSaLoc    = ikeSaLoc;

    evt.oProtocol   = oProtocol;
    evt.dwSpi       = dwSpi;

    SET_MOC_COOKIE(evt.cookie, cookie)

    /* send event */
    status = IPSEC_IKE_SETTINGS()->funcPtrIkeEvtSend((ubyte *)&evt, sizeof(evt),
                                                  ((IKE_KEY_MOD_OUTBOUND & type)
                                                   ? dwSrcAddr : dwDestAddr)
                                                  MOC_COOKIE_REQ_VALUE(cookie));

exit:
    return status;
} /* IKE_keyInform */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_keyInfoEx(SADB pxSa,
#ifdef __ENABLE_IPSEC_NAT_T__
              ubyte2 wUdpEncPort,
#endif
              ubyte4 dwSpi,
              ubyte2 type)
{
    MSTATUS status = OK;

    struct ike_event evt = { 0 };
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    SPD pxSp = pxSa->pxSp;

    if (NULL == pxSp) /* jic */
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
#endif

    /* check send() function */
    if (NULL == IPSEC_IKE_SETTINGS()->funcPtrIkeEvtSend)
    {
        DIGICERT_log(MOCANA_IKE, LS_WARNING, (sbyte *)"IKE_ikeSettings()->funcPtrIkeEvtSend not set");
        status = ERR_IKE_CONFIG;
        goto exit;
    }

    /* initialize event */
    evt.type        = type;

    evt.dwDestAddr  = pxSa->dwSaDestAddr;
    evt.dwSrcAddr   = pxSa->dwSaSrcAddr;

#ifdef __ENABLE_IPSEC_NAT_T__
    evt.wUdpEncPort = wUdpEncPort;
#endif
    evt.dwIkeSaId   = pxSa->dwIkeSaId;
    evt.ikeSaLoc    = pxSa->ikeSaLoc;

    evt.oProtocol   = pxSa->oSaProto;
    evt.dwSpi       = dwSpi;

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    evt.ifid        = pxSp->ifid;
#endif
    SET_MOC_COOKIE(evt.cookie, pxSa->cookie)

    /* send event */
    status = IPSEC_IKE_SETTINGS()->funcPtrIkeEvtSend((ubyte *)&evt, sizeof(evt),
                                            ((IKE_KEY_MOD_OUTBOUND & type)
                                             ? REF_MOC_IPADDR(evt.dwSrcAddr)
                                             : REF_MOC_IPADDR(evt.dwDestAddr))
                                            MOC_COOKIE_REQ_VALUE(evt.cookie));

exit:
    return status;
} /* IKE_keyInfoEx */


#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) && !defined(__ENABLE_DIGICERT_PFKEY__) */

