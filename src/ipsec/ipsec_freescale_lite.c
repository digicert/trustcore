/**
 * @file  ipsec_freescale_lite.c
 * @brief NanoSec IPsec Freescale lite implementation.
 *
 * @details    This file contains IPsec implementation optimized for Freescale platforms.
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IPSEC_SERVICE__
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
 *     +   \c \__ENABLE_DIGICERT_HARNESS__
 *     Additionally, the following flags must not be defined:
 *     +   \c \__DISABLE_IPSEC_TUNNEL_MODE__
 *     +   \c \__ENABLE_IPSEC_INTERFACE_ID__
 *     +   \c \__ENABLE_IPSEC_COOKIE__
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

#if defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) && \
    defined(__ENABLE_DIGICERT_IKE_SERVER__) && \
    !defined(__DISABLE_IPSEC_TUNNEL_MODE__) && \
    !defined(__ENABLE_IPSEC_INTERFACE_ID__) && \
    !defined(__ENABLE_IPSEC_COOKIE__) && \
    defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) && \
    defined(__ENABLE_DIGICERT_HARNESS__)

#ifdef __ENABLE_DIGICERT_IPV6__
#error Must not define __ENABLE_DIGICERT_IPV6__
#endif
#ifndef __ENABLE_IPSEC_FLOW__
#warning Should define __ENABLE_IPSEC_FLOW__
#endif

/* async 'enabled', single-pass ESP w/ auth only, no crypto alloc. */

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/random.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../harness/harness.h"

#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec6.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_crypto.h"
#include "../ipsec/ipsec_utils.h"
#include "../ipsec/ipsec_protos.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"
#include "../ipsec/spd.h"
#include "../ipsec/sadb.h"
#ifdef __ENABLE_IPSEC_FLOW__
#include "../ipsec/ipsec_flow.h"
#endif
#include "../ike/ike.h"
#include "../ike/ikekey.h"

#if defined(__HW_OFFLOAD_SINGLE_PASS_SUPPORT__) && \
    defined(__IPSEC_SINGLE_PASS_SUPPORT__)

/*------------------------------------------------------------------*/

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
#include <linux/interrupt.h>
#include <linux/spinlock.h>


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
static DEFINE_SPINLOCK(hwAccelLock_in);
static DEFINE_SPINLOCK(hwAccelLock_out);
#else
static spinlock_t hwAccelLock_in = SPIN_LOCK_UNLOCKED;
static spinlock_t hwAccelLock_out = SPIN_LOCK_UNLOCKED;
#endif


#define LOCK_HARNESS(_hw, _encr) \
{\
    spinlock_t *_lock = (_encr ? &hwAccelLock_out : &hwAccelLock_in);\
    spin_lock_bh(_lock);\


#define UNLOCK_HARNESS(_hw, _encr) \
    spin_unlock_bh(_lock);\
}

#endif /* defined(__LINUX_RTOS__) && defined(__KERNEL__) */

#ifndef LOCK_HARNESS
#define LOCK_HARNESS(_hw, _encr)
#endif
#ifndef UNLOCK_HARNESS
#define UNLOCK_HARNESS(_hw, _encr)
#endif

#ifndef INIT_HARNESS_LOCK
#define INIT_HARNESS_LOCK
#endif
#ifndef DEL_HARNESS_LOCK
#define DEL_HARNESS_LOCK
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_INIT__
extern moctime_t gStartTime;
#else
moctime_t gStartTime;
#endif


/*------------------------------------------------------------------*/

#ifndef EXIT_IPSEC
#define EXIT_IPSEC  { DB_PRINT("%s [%d]: %s()=%d\n", __FILE__, __LINE__, __FUNCTION__, (int)status); goto exit; }
#endif


/*------------------------------------------------------------------*/

#ifndef LOCK_SA
#define LOCK_SA(sa)
#endif
#ifndef UNLOCK_SA
#define UNLOCK_SA(sa)
#endif

#ifndef LOCK_SP
#define LOCK_SP(sp)
#endif
#ifndef UNLOCK_SP
#define UNLOCK_SP(sp)
#endif


/*------------------------------------------------------------------*/

/* IP header Identification value - outbound tunnel mode packet */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
#ifndef ATOMIC_NEXT_IPHDR_ID

static ubyte2 wEthIPSec_ID = 0;

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    #include <asm/atomic.h>
    static atomic_t ips_id = { 0 };
    #define NEXT_IPHDR_ID atomic_add_return(1, &ips_id)
#else
    #define NEXT_IPHDR_ID ++wEthIPSec_ID    /* WARNING: not thread-safe */
#endif

#else
    #define NEXT_IPHDR_ID ATOMIC_NEXT_IPHDR_ID
#endif
#endif


/*------------------------------------------------------------------*/

#define GET_PKT_INFO(pxHdr, bufSize, wLength, wHdrLen, oProtocol, bFragOff, bMoreFrags, _st) \
    if (sizeof(struct ipHdr) > bufSize)\
    {\
        status = _st;\
        EXIT_IPSEC \
    }\
\
    wHdrLen = (pxHdr->ip_vhl & 0x0F) << 2;\
    wLength = GET_NTOHS(pxHdr->ip_len);\
\
    /* check length */\
    if (sizeof(struct ipHdr) > wHdrLen ||\
        wHdrLen > wLength)\
    {\
        status = ERR_IPSEC_BAD_IP;\
        EXIT_IPSEC \
    }\
\
    if (wLength > bufSize)\
    {\
        status = _st;\
        EXIT_IPSEC \
    }\
\
    oProtocol = pxHdr->ip_p;\
\
    {\
        ubyte2 wFragOff = GET_NTOHS(pxHdr->ip_off);\
        bFragOff   = (IP_OFFMASK & wFragOff) ? TRUE : FALSE;\
        bMoreFrags = (IP_MF & (~(IP_OFFMASK) & wFragOff)) ? TRUE : FALSE;\
    }\

#define GET_PKT_INFO_IN(pxHdr, bufSize, wLength, wHdrLen, oProtocol, bFragOff, bMoreFrags) \
        GET_PKT_INFO(pxHdr, bufSize, wLength, wHdrLen, oProtocol, bFragOff, bMoreFrags, ERR_IPSEC_BAD_IP) \

#define GET_PKT_INFO_OUT(pxHdr, bufSize, wLength, wHdrLen, oProtocol, bFragOff, bMoreFrags) \
    { \
        ubyte2 _bufSize = bufSize; \
        GET_PKT_INFO(pxHdr, _bufSize, wLength, wHdrLen, oProtocol, bFragOff, bMoreFrags, ERR_IPSEC_BUFFER_OVERFLOW) \
    }


/*------------------------------------------------------------------*/

#define GET_ULP_PORTS(poPayload, wPayloadLen, oUlp, bFragOff, wDestPort, wSrcPort) \
    wSrcPort = 0;\
    wDestPort = 0;\
\
    if (!bFragOff)\
    switch (oUlp)\
    {\
    case IPPROTO_TCP :\
        {\
            struct tcpHdr *pxTcp = (struct tcpHdr *)poPayload;\
            if (wPayloadLen < (sizeof(ubyte2) * 2)/*sizeof(struct tcpHdr)*/)\
            {\
                status = ERR_IPSEC_BAD_TCP;\
                EXIT_IPSEC \
            }\
\
            SET_NTOHS(wSrcPort, pxTcp->th_sport);\
            SET_NTOHS(wDestPort, pxTcp->th_dport);\
        }\
        break;\
    case IPPROTO_UDP :\
        {\
            struct udpHdr *pxUdp = (struct udpHdr *)poPayload;\
            if (wPayloadLen < sizeof(struct udpHdr))\
            {\
                status = ERR_IPSEC_BAD_ULP;\
                EXIT_IPSEC \
            }\
\
            SET_NTOHS(wSrcPort, pxUdp->uh_sport);\
            SET_NTOHS(wDestPort, pxUdp->uh_dport);\
        }\
        break;\
    case IPPROTO_ICMP :\
        {\
            if (wPayloadLen < sizeof(ubyte2))\
            {\
                status = ERR_IPSEC_BAD_ULP;\
                EXIT_IPSEC \
            }\
\
            wSrcPort = DIGI_NTOHS(poPayload);\
        }\
        break;\
    }\


/*------------------------------------------------------------------*/

#define UPD_TUNNEL_IPHDR(dwDestAddr, dwSrcAddr, poHdr, pxHdr, oProtocol, bFragOff, bMoreFrags, flags) \
{\
    ubyte2 wFragOff = GET_NTOHS(pxHdr->ip_off);\
\
    if (poHdr != (ubyte*)pxHdr)\
    {\
        ((struct ipHdr *)poHdr)->ip_tos = pxHdr->ip_tos;\
        ((struct ipHdr *)poHdr)->ip_ttl = pxHdr->ip_ttl;\
        pxHdr = (struct ipHdr *)poHdr;\
    }\
\
    if (bFragOff || bMoreFrags) /* adjust fragmentation */ \
        wFragOff &= ~(IP_OFFMASK | IP_MF);\
\
    if (IPSEC_SP_FLAG_DF & flags) /* do not copy DF bit */ \
    {\
        if (IPSEC_SP_FLAG_DF_BIT & flags)\
            wFragOff |= IP_DF;      /* set */ \
        else \
            wFragOff &= ~(IP_DF);   /* clear */ \
    }\
\
    SET_HTONS(pxHdr->ip_off, wFragOff);\
\
              pxHdr->ip_vhl= 0x45; /* 4 | ((ubyte)wHdrLen >> 2) */ \
    SET_HTONS(pxHdr->ip_id,  NEXT_IPHDR_ID);/* generate ID */ \
    SET_HTONL(pxHdr->ip_src, GET_MOC_IPADDR4(dwSrcAddr));    /* replace src address */ \
    SET_HTONL(pxHdr->ip_dst, GET_MOC_IPADDR4(dwDestAddr));   /* replace dest address */ \
\
    oProtocol = IPPROTO_IPIP;\
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_init(void)
{
    MSTATUS status;

#ifdef __DISABLE_DIGICERT_INIT__
    RTOS_deltaMS(NULL, &gStartTime);
#endif

    INIT_HARNESS_LOCK

    if (OK > (status = IPSEC_cryptoInit()))
        goto exit;

    if (OK > (status = IPSEC_initSadb()))
        goto exit;

    if (OK > (status = IPSEC_initSpd()))
        goto exit;

#if !defined(__DISABLE_IPSEC_TUNNEL_MODE__) && !defined(ATOMIC_NEXT_IPHDR_ID)
    if (OK > (status = RANDOM_numberGenerator(g_pRandomContext, (ubyte *)&wEthIPSec_ID, sizeof(wEthIPSec_ID))))
        goto exit;

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    atomic_set(&ips_id, (int)wEthIPSec_ID);
#endif
#endif

#ifdef __ENABLE_IPSEC_FLOW__
    IPSEC_flowInit();
#endif

exit:
    return (sbyte4)status;
} /* IPSEC_init */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_flush(void)
{
    MSTATUS status;

#ifdef __ENABLE_IPSEC_FLOW__
    IPSEC_flowFlush();
#endif
    status = IPSEC_flushSpd();
    status = IPSEC_flushSadb();
    status = IPSEC_cryptoUninit();

    DEL_HARNESS_LOCK

    return (sbyte4)status;
} /* IPSEC_flush */


/*------------------------------------------------------------------*/

#if defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__)

static MSTATUS
AntiReplay(ubyte4 dwSeqNbr, SADB pxSa, intBoolean bCheckOnly)
{
    /* anti-replay by checking seq no in the sliding replay window */
    MSTATUS status = OK;

    ubyte4 dwRlyWndBytes = IPSEC_REPLAY_SIZE / 8; /* bytes */
    ubyte4 dwRlySize = dwRlyWndBytes * 8; /* bits/packets */
    ubyte *poReplayWindow = pxSa->poReplayWindow;

    ubyte4 dwSeqNbrRlyStart, dwSeqNbrRlyEnd;

    intBoolean bLastRlyWndPkt = FALSE;
    sbyte4 j;

    LOCK_SA(pxSa)

    --dwSeqNbr;
    dwSeqNbrRlyStart = ATOMIC_GET(pxSa->dwSeqNbr);
    dwSeqNbrRlyEnd = dwSeqNbrRlyStart + dwRlySize;

    /* drop if the seq no falls to the left of the replay window */
    if (dwSeqNbr < dwSeqNbrRlyStart)
    {
        status = ERR_IPSEC_DROP_REPLAY_LATE;
        EXIT_IPSEC
    }

    /* if seq no. falls inside the replay window */
    if ((dwSeqNbr < dwSeqNbrRlyEnd) || (dwSeqNbrRlyEnd < dwSeqNbrRlyStart))
    {
        ubyte4 dwOffset = dwSeqNbr - dwSeqNbrRlyStart;

        /* drop if the seq no is not new */
        if (poReplayWindow[dwOffset / 8] & (((ubyte)1) << (dwOffset % 8)))
        {
            status = ERR_IPSEC_DROP_REPLAY_OLD;
            EXIT_IPSEC
        }

        if (bCheckOnly) goto exit;

        /* mark as old */
        poReplayWindow[dwOffset / 8] |= (((ubyte)1) << (dwOffset % 8));

        if ((dwSeqNbr + 1) == dwSeqNbrRlyEnd)
            bLastRlyWndPkt = TRUE;
    }

    else if (bCheckOnly) goto exit;

    /* otherwise, advance the replay window */
    else
    {
        ubyte oBytes = 0;
        ubyte4 dwShift = dwSeqNbr - dwSeqNbrRlyEnd + 1;

        /* shift the replay window */
        if (dwShift < dwRlySize)
        {
            ubyte oBits = (ubyte)((dwRlySize - dwShift) % 8);
            oBytes = (ubyte)((dwRlySize - dwShift) / 8);
            if (0 < oBits)
            {
                for (j=0; j <= oBytes; j++)
                {
                    ubyte *b = &(poReplayWindow[dwRlyWndBytes - oBytes + j - 1]);
                    *b >>= (8 - oBits);
                    if (j != oBytes) *b |= (*(b+1) << oBits);
                }
                ++oBytes;
            }
            DIGI_MEMMOVE(poReplayWindow,
                        poReplayWindow + dwRlyWndBytes - oBytes,
                        oBytes);
        }
        DIGI_MEMSET(poReplayWindow + oBytes, 0x00, dwRlyWndBytes - oBytes);

        /* mark as old */
        poReplayWindow[dwRlyWndBytes - 1] |= ((ubyte)1 << 7);
        ATOMIC_SET(pxSa->dwSeqNbr, dwSeqNbr - dwRlySize + 1);

        if (1 == dwShift)
            bLastRlyWndPkt = TRUE;
    }

    /* advance the entire replay window, if possible */
    if (bLastRlyWndPkt && ((ubyte4)(dwSeqNbr + dwRlySize) > dwSeqNbr))
    {
        for (j = (sbyte4)dwRlyWndBytes - 1; j >= 0; j--)
        {
            if (0xff != poReplayWindow[j])
                break;
        }
        if (0 > j)
        {
            ATOMIC_SET(pxSa->dwSeqNbr, dwSeqNbr + 1);
            DIGI_MEMSET(poReplayWindow, 0x00, dwRlyWndBytes);
            /*for (j=0; j < (sbyte4)dwRlyWndBytes; j++)
                poReplayWindow[j] = 0x00;*/
        }
    }

exit:
    UNLOCK_SA(pxSa)
    return status;
} /* AntiReplay */

#endif /* defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__) */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_ready(MOC_IP_ADDRESS dwDestAddr,
            MOC_IP_ADDRESS dwSrcAddr,
            ubyte oProto,
            intBoolean bFragOff, intBoolean bMoreFrags,
            ubyte2 wDestPort, ubyte2 wSrcPort,
            intBoolean bInbound,
            SPD *ppxSP, sbyte4 ifid, ubyte4 cookie)
{
    MSTATUS status = OK;

    SPD pxSP = NULL;
    intBoolean bCheckPorts = !(bInbound ? bFragOff : (bFragOff || bMoreFrags));

    MOC_INTF_UNUSED(ifid)
    MOC_COOKIE_UNUSED(cookie)

    /* get SP for this packet */
    pxSP = IPSEC_getSp(dwDestAddr, dwSrcAddr,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                       0, 0,
#endif
                       oProto, bCheckPorts,
                       wDestPort, wSrcPort,
                       bInbound
                       MOC_INTF_OPAQ_ID(FALSE, ifid)
                       MOC_COOKIE_VALUE(cookie));

    /* check fragmentation */
    if (!bCheckPorts && (NULL != pxSP))
    {
        /* special case: fragmented tcp/udp packets */
        if ((((IPPROTO_TCP == oProto) || (IPPROTO_UDP == oProto)) &&
             ((0 != pxSP->oProto) &&
              ((0 != pxSP->wDestPort) || (0 != pxSP->wSrcPort)
#ifdef __ENABLE_IPSEC_PORT_RANGE__
               || (0 != pxSP->wDestPortEnd) || (0 != pxSP->wSrcPortEnd)
#endif
               )))
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        /* In tunnel mode, IP packet payload can be fragmented. */
        /* Transport mode cannot be applied on fragments. */
            || (!bInbound && (IPSEC_MODE_TUNNEL != pxSP->oMode))
#endif
            )
        {
            status = ERR_IPSEC_FRAGMENTATION;
            pxSP = NULL;
            goto exit;
        }
    }

    /* get action */
    if ((NULL == pxSP) || (IPSEC_ACTION_BYPASS == pxSP->oAction))
    {
        status = STATUS_IPSEC_BYPASS; /* bypass */
        goto exit;
    }

    if (IPSEC_ACTION_DROP == pxSP->oAction)
    {
        status = ERR_IPSEC_DROP; /* drop */
        goto exit;
    }

exit:
    if (NULL != ppxSP)
        *ppxSP = pxSP;
    return (sbyte4)status;
} /* IPSEC_ready */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_permitEx(ubyte *pBuffer, ubyte2 wBufSize, ubyte2 *pwLength, ubyte2 *pwOffset, IPSECCTX ctx)
{
    MSTATUS status = OK;

    /* perform IPsec inbound processing */

    ubyte *poHdr;

    struct ipHdr *pxHdr = NULL;
    ubyte2 wHdrLen;
    ubyte2 wLength = 0;
    ubyte  oProtocol;
    ubyte *poPayload;
    ubyte2 wPayloadLen;

    MOC_IP_ADDRESS_S dwDestAddr, dwSrcAddr;
    ubyte2 wDestPort, wSrcPort;

    intBoolean bFragOff, bMoreFrags;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    ubyte  oMode = 0;
    MOC_IP_ADDRESS_S dwTunlDestIP, dwTunlSrcIP;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2 wUdpEncPort = 0;
#endif
    sbyte4 i, iNest = 0;
    ubyte4 timenow;

    SPD pxSP = NULL;

    /* store applied nested SA's */
    SADB axSaUsed[IPSEC_NEST_MAX] = { NULL };
#if defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
    ubyte4 adwSeqNbr[IPSEC_NEST_MAX] = { 0 }; /* for anti-replay */
#endif

    hwAccelDescr hwAccelCtx;

    if ((NULL != ctx) && (0 < (iNest = ctx->counter)))
    {
        /* async job finished, continue processing */
        ubyte2 wIPSecHdrLen = ctx->wIPsecHdrLen;
        SADB pxSa;
        SADB_cipherSuiteInfo* pCipherSuite;

        hwAccelCtx = ctx->hwAccelCtx;

        poHdr = pBuffer;

        pxHdr = (struct ipHdr *)poHdr;

        wHdrLen = ctx->wIpHdrLen;
        wLength = ctx->wLength;
        dwSrcAddr = ctx->dwSrcAddr;
        dwDestAddr = ctx->dwDestAddr;

        poPayload = ctx->poPayload;
        /*poPayload   = poHdr + wHdrLen;*/
        wPayloadLen = wLength - wHdrLen;

        bFragOff = FALSE;
        bMoreFrags = FALSE;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        oMode = ctx->oMode;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
        wUdpEncPort = ctx->wUdpEncPort;
#endif
        for (i=0; i < iNest; i++)
        {
            axSaUsed[i] = ctx->axSaUsed[i];
#if defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
            adwSeqNbr[i] = ctx->adwSeqNbr[i];
#endif
        }
        pxSa = axSaUsed[iNest-1];

        /* delete cipher context */
        if (ctx->pCipherCtx)
        {
            if (NULL != (pCipherSuite = pxSa->pCipherSuite)) /* jic */
            {
                DOWN_SA_LOCK(pxSa)

                if ((ctx->pCipherCtx == pxSa->pCipherCtx) && /* jic */
                    (0 >= --pxSa->users) &&
                    (IPSEC_SA_FLAG_DELETED & pxSa->saFlags))
                {
                    pCipherSuite->pBEAlgo->deleteFunc(MOC_SYM(hwAccelCtx)
                                                      &pxSa->pCipherCtx);
                    pxSa->pCipherCtx = NULL;
                }
                UP_SA_LOCK(pxSa)
            }
            /*ctx->pCipherCtx = NULL;*/ /* do not reset yet!!! */
        }

        if (OK > (status = (MSTATUS) ctx->status))
            EXIT_IPSEC

        /* decrypt */
        {
            ctx->pCipherCtx = NULL;
        }

        /* remove esp trailer */
        if (wPayloadLen < (wIPSecHdrLen + poPayload[wPayloadLen - 2] + 2))
        {
            status = ERR_IPSEC_BAD_ESP;
            EXIT_IPSEC
        }
        oProtocol = poPayload[wPayloadLen - 1];
        if (IPPROTO_NONE == oProtocol) /* dummy packet; ESP (v3) support of TFC, see RFC4303 2.6-7 */
        {
            status = STATUS_IPSEC_DUMMY;
            /*iNest++;*/ /* already incremented! */
            goto exit;
        }
        wLength -= poPayload[wPayloadLen - 2] + 2; /* remove padded octets from length calculation */
        wPayloadLen = wLength - wHdrLen;

        /* remove esp header */
        /* if (0 != wIPSecHdrLen) */
        {
            wLength -= wIPSecHdrLen;
            wPayloadLen -= wIPSecHdrLen;

            if (pwOffset)
                poPayload += wIPSecHdrLen;
            else
                DIGI_MEMMOVE(poPayload, poPayload + wIPSecHdrLen, wPayloadLen);
        }

        goto permit;
    }

    if (OK > (status = IPSEC_getHwAccelChannel(&hwAccelCtx, TRUE)))
        goto nocleanup;

    poHdr = pBuffer;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
start:
#endif
    /* get ip packet info */
    if (1 > wBufSize)
    {
        status = ERR_IPSEC_BAD_IP;
        EXIT_IPSEC
    }

    /* check IP version */
    switch (poHdr[0] & 0xF0)
    {
    case 0x40 :
        pxHdr = (struct ipHdr *)poHdr;
        GET_PKT_INFO_IN(pxHdr, wBufSize,
                        wLength, wHdrLen, oProtocol, bFragOff, bMoreFrags)

        SET_MOC_IPADDR4(dwSrcAddr,  GET_NTOHL(pxHdr->ip_src));
        SET_MOC_IPADDR4(dwDestAddr, GET_NTOHL(pxHdr->ip_dst));
        break;

    default :
        status = ERR_IPSEC_BAD_IP;
        EXIT_IPSEC
        break;
    }

    poPayload   = poHdr + wHdrLen;
    wPayloadLen = wLength - wHdrLen;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    /* handle tunnelled IP packet */
    if (IPSEC_MODE_TUNNEL == oMode)
    {
        /* decrement TTL, if necessary */
        if (!SAME_MOC_IPADDR(REF_MOC_IPADDR(dwTunlDestIP), dwDestAddr)) /* forwarded */
        {
            {
                if (0 == pxHdr->ip_ttl)
                {
                    status = ERR_IPSEC_DROP_TTL;
                    EXIT_IPSEC
                }
            }
        }

        goto end;
    }
#endif /* !__DISABLE_IPSEC_TUNNEL_MODE__ */

#if defined(__ENABLE_IPSEC_NAT_T__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
permit:
#endif
    /* process nested transforms */
    if (!bFragOff)
    for (/*iNest=0*/;
         (iNest < IPSEC_NEST_MAX) &&
         ((IPPROTO_AH == oProtocol) || (IPPROTO_ESP == oProtocol));
         iNest++)
    {
        SADB pxSa;
        ubyte4 dwSpi;
        SADB_hmacSuiteInfo* pHmacSuite;
        ubyte2 wIcvLen, wIPSecHdrLen;

        sbyte4 compareResult;

        /* get SPI */
        if (IPPROTO_AH == oProtocol)
        {
            pxSa = NULL;
        }
        else
        {
            if (wPayloadLen < sizeof(struct espHdr)/* 8 */)
            {
                status = ERR_IPSEC_BAD_ESP;
                EXIT_IPSEC
            }
            SET_NTOHL(dwSpi, ((struct espHdr *)poPayload)->dwSpi);
/*        }*/

        /* find SA */
        if (OK > (status = IPSEC_findSa(dwSpi, REF_MOC_IPADDR(dwDestAddr),
                                        REF_MOC_IPADDR(dwSrcAddr),
                                        oProtocol,
#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && defined(__IKE_MULTI_HOMING__)
                                        TRUE,
#endif
                                        &pxSa)))
        {
            /* SA already deleted */
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            if (NULL != pxSa->pxSp) /* auto. keyed */
            {
                timenow = RTOS_deltaMS(&gStartTime, NULL);
                if (((timenow - pxSa->dwSaLastRekey) < (ubyte4)60000) /* 1 min (grace period) - FOR NOW */
                    && !IPSEC_expireSa(timenow, pxSa))
                    status = OK;

                /* send notification discreetly */
                if ((timenow - pxSa->dwSaFirstUsed) > (ubyte4)300000) /* 5 mins - FOR NOW */
                    IPSEC_delSa(pxSa, TRUE);
            }

            if (OK > status)
#endif
                goto exit;
        }

        }

        if (NULL == pxSa) /* no SA found */
        {
            if (0 < iNest)
            {
                /* drop packet */
                status = ERR_IPSEC_DROP_FINDSA_FAIL;
                goto exit;
            }

#ifdef __ENABLE_IPSEC_NAT_T__
            if (0 != wUdpEncPort)
            {
                /* this packet is probably not for us */
                if (bMoreFrags)
                    status = ERR_IPSEC_FRAGMENTATION;
                else
                    status = STATUS_IPSEC_BYPASS; /* bypass */
                goto exit;
            }
#endif
            break; /* decide whether to drop/bypass later */
        }

        LOCK_SA(pxSa)
        ++pxSa->dwSaTotPackets;
        UNLOCK_SA(pxSa)

        if (NULL == ctx) /* jic */
        {
            status = ERR_HARDWARE_ACCEL_NO_MEMORY;
            goto exit;
        }

        /* source IP address mismatch */
        if (!ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr) &&
            !SAME_MOC_IPADDR(REF_MOC_IPADDR(dwSrcAddr), pxSa->dwSaSrcAddr))
#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && !defined(__DISABLE_IPSEC_TUNNEL_MODE__)
        if ((NULL == pxSa->pxSp) ||
            (IPSEC_MODE_TUNNEL != pxSa->oSaMode)) /* !!! */
#endif
        {
            /* Note: SPD/SADB may be out of sync due to Mobility migration
               or new NAT-T mapping. */
            status = ERR_IPSEC_DROP_BAD_SRC_ADDR;
            EXIT_IPSEC
        }

#ifdef __ENABLE_IPSEC_NAT_T__
        /* peer NAT port mismatch */
        if (pxSa->wSaUdpEncPort != wUdpEncPort)
        {
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            if (pxSa->pxSp) /* auto. keyed */
            {
                if (!(IPSEC_SA_FLAG_NAT_PEER & pxSa->saFlags) &&
                    SAME_MOC_IPADDR(REF_MOC_IPADDR(dwSrcAddr), pxSa->dwSaSrcAddr))
                {
                    status = ERR_IPSEC_DROP_BAD_UDPENC_PORT;
                    EXIT_IPSEC
                }
            }
            else
#endif
            if (0 != pxSa->wSaUdpEncPort)
            {
                status = ERR_IPSEC_DROP_BAD_UDPENC_PORT;
                EXIT_IPSEC
            }
        }
#endif /* __ENABLE_IPSEC_NAT_T__ */

        if (bMoreFrags) /* fragmented esp/ah */
        {
            status = ERR_IPSEC_FRAGMENTATION;
            EXIT_IPSEC
        }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (0 == oMode)
            oMode = pxSa->oSaMode;
        else if (0 != pxSa->oSaMode)
        {
            if (oMode != pxSa->oSaMode)
            {
                status = ERR_IPSEC_DROP_BAD_MODE;
                EXIT_IPSEC
            }
        }
#endif

#ifdef __ENABLE_IPSEC_NAT_T__
        /* remove udp-encap. header, if any */
        if ((0 != wUdpEncPort) && (0 == iNest))
        {
            if (!pwOffset)
            {
                poPayload -= sizeof(struct udpHdr);
                DIGI_MEMMOVE(poPayload, poPayload + sizeof(struct udpHdr), wPayloadLen);
            }
        }
#endif

        /* save applied SA - to be checked with SP later */
        axSaUsed[iNest] = pxSa;

        pHmacSuite = pxSa->pHmacSuite;
        wIcvLen = pHmacSuite ? pHmacSuite->wIcvLen : 0;

        if (NULL == pHmacSuite)
        {
            status = ERR_IPSEC;
            EXIT_IPSEC
        }

        /* process ESP */
        {
            SADB_cipherSuiteInfo* pCipherSuite = pxSa->pCipherSuite;

            /* get esp header length */
            wIPSecHdrLen = sizeof(struct espHdr);
            if (NULL != pCipherSuite)
                wIPSecHdrLen += pCipherSuite->wIvLen;
            else
            {
                status = ERR_IPSEC;
                EXIT_IPSEC
            }

            if (wPayloadLen < (wIPSecHdrLen + wIcvLen + 2))
            {
                /* Note: 2 bytes for ESP trailer (pad length and next header) */
                status = ERR_IPSEC_BAD_ESP;
                EXIT_IPSEC
            }

#if defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
            /* check replay */
            if (pxSa->pxSp) /* auto. keyed */
            {
                sbyte4 j=0;

                /* anti-replay may be selected only if auth. is enabled */
                if (NULL == pHmacSuite)
                {
                    for (j = iNest - 1; j >= 0; j--)
                    {
                        if (NULL != axSaUsed[j]->pHmacSuite)
                            break;
                    }
                }

                if (0 <= j) /* auth. exists, check replay window */
                {
                    if (0 == (adwSeqNbr[iNest] =
                                GET_NTOHL(((struct espHdr *)poPayload)->dwSeqNbr)))
                    {
                        status = ERR_IPSEC_DROP_BAD_SEQ;
                        EXIT_IPSEC
                    }
                    if (OK != (status = AntiReplay(adwSeqNbr[iNest], pxSa, TRUE)))
                        goto exit;
                }
            }
#endif

            /* exclude esp auth trailing icv from total length */
            wLength -= wIcvLen;
            wPayloadLen -= wIcvLen;

            {
                ctx->poPayload = poPayload;

                ctx->counter = iNest + 1;
                ctx->wIpHdrLen = wHdrLen;
                ctx->wLength = wLength;

                ctx->wIPsecHdrLen = wIPSecHdrLen;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                ctx->oMode = oMode;
#endif
                if (0 == iNest)
                {
                    ctx->dwSrcAddr = dwSrcAddr;
                    ctx->dwDestAddr = dwDestAddr;
#ifdef __ENABLE_IPSEC_NAT_T__
                    ctx->wUdpEncPort = wUdpEncPort;
#endif
                    ctx->hwAccelCtx = hwAccelCtx;
                }

                ctx->axSaUsed[iNest] = pxSa;
#if defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
                ctx->adwSeqNbr[iNest] = adwSeqNbr[iNest];
#endif
            }

                /* authenticate and decrypt in a single pass */
                {
                    typeForSinglePass singlePassCookie;
                    if (
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
                        (NULL == pxSa->pxSp) && /* manually keyed */
#endif
                        !(IPSEC_SA_FLAG_INBOUND & pxSa->saFlags))
                        singlePassCookie = (typeForSinglePass)
                            IPSEC_getSinglePassType(pCipherSuite, pHmacSuite, TRUE);
                    else
                        singlePassCookie = pxSa->dwSinglePassCookie;

                    {
                        BulkCtx pCipherCtx;
                        /*DIGI_MEMSET(poPayload + wPayloadLen, 0x00, wIcvLen);*/ /* testing only */

                        DOWN_SA_LOCK(pxSa)
                        pCipherCtx = pxSa->pCipherCtx;
                        if (NULL == pCipherCtx) /* jic */
                            status = ERR_IPSEC_DROP_FINDSA_FAIL;
                        else
                        pxSa->users++;
                        UP_SA_LOCK(pxSa)

                        if (OK > status) EXIT_IPSEC

                        {
                            ctx->pCipherCtx = pCipherCtx;
                        }

                        LOCK_HARNESS(hwAccelCtx, FALSE)
                        HARNESS_assignAsyncCtx(hwAccelCtx, ctx);

                        status = HWOFFLOAD_doSinglePassDecryption(MOC_SYM(hwAccelCtx)
                                                    MOCANA_IPSEC,
                                                    singlePassCookie, 0,
                                                    pCipherCtx,
                                                    pxSa->poAuthKey,
                                                    pHmacSuite->wKeyLen,
                                                    poPayload, wPayloadLen,             /* hmac data */
                                                    poPayload + wIPSecHdrLen,           /* crypto data */
                                                    wPayloadLen - wIPSecHdrLen,
                                                    NULL,                    /* crypto out pointer (new) */
                                                    poPayload + sizeof(struct espHdr), /* IV */
                                                    pCipherSuite->wIvLen,
                                                    poPayload + wPayloadLen, /* ICV - to be verified or modified */
                                                    wIcvLen, &compareResult);

                        HARNESS_assignAsyncCtx(hwAccelCtx, NULL);
                        UNLOCK_HARNESS(hwAccelCtx, FALSE)

                        {
                            if (OK > status)
                            {
                            }
                            else
                            {
                                /* queue async job */
                                if (pwLength) *pwLength = 0;
                                return OK;
                            }
                        }
                        DOWN_SA_LOCK(pxSa)
                        pxSa->users--;
                        UP_SA_LOCK(pxSa)

                        {
                                EXIT_IPSEC
                        }
                    }
                }

        } /* process ESP */

    } /* for (iNest=0; */

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    /* tunnelled inner IP packet? */
    if ((IPSEC_MODE_TRANSPORT != oMode) &&
        ((IPPROTO_IPIP == oProtocol)
         ))
    {
        if (0 == iNest) /* no transform has been performed */
            goto end;

        if (0 == oMode) /* FOR NOW */
            oMode = IPSEC_MODE_TUNNEL;

        /* remember tunnel IP's */
        dwTunlSrcIP = dwSrcAddr;
        dwTunlDestIP = dwDestAddr;

        /* remove outer ip header */
        if (pwOffset)
            poHdr = poPayload;
        else
            DIGI_MEMMOVE(poHdr, poPayload, wPayloadLen);

        wBufSize = wPayloadLen;
        goto start; /* get inner packet info */
    }
    else
    {
        if (IPSEC_MODE_TUNNEL == oMode)
        {
            status = ERR_IPSEC_DROP_BAD_MODE;
            EXIT_IPSEC
        }

        ZERO_MOC_IPADDR(dwTunlSrcIP);
        ZERO_MOC_IPADDR(dwTunlDestIP);
    }
#endif /* __DISABLE_IPSEC_TUNNEL_MODE__ */

    if (0 < iNest)
    {
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (0 == oMode)
            oMode = IPSEC_MODE_TRANSPORT;
#endif
        /* update ip header fields */
        {
            SET_HTONS(pxHdr->ip_len, wLength);
                      pxHdr->ip_p  = oProtocol; /* copy next header */

            /* recalculate checksum */
            SET_IPHDR_CSUM(pxHdr->ip_sum, poHdr, wHdrLen)
        }
    }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
end:
#endif
    GET_ULP_PORTS(poPayload, wPayloadLen, oProtocol, bFragOff,
                  wDestPort, wSrcPort)

#ifdef __ENABLE_IPSEC_FLOW__
    if (1 == iNest)
    {
        if (OK <= IPSEC_flowCheck(axSaUsed[0], &pxSP,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                                  oMode,
#endif
                                  REF_MOC_IPADDR(dwDestAddr),
                                  REF_MOC_IPADDR(dwSrcAddr),
                                  oProtocol, wDestPort, wSrcPort))
        {
            goto done;
        }
    }
#endif

    /* check flow against applied SA's */
    for (i=0; i < iNest; i++)
    {
        SADB pxSa = axSaUsed[i]; /* applied SA */

        /* ulp */
        if (((0 != pxSa->oSaUlp) && (oProtocol != pxSa->oSaUlp)) ||
        /* ports */
            (!bFragOff &&
             (((0 != pxSa->wSaDestPort) && (wDestPort != pxSa->wSaDestPort)) ||
              ((0 != pxSa->wSaSrcPort) && (wSrcPort != pxSa->wSaSrcPort))))
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        /* private network */                                    ||
            ((IPSEC_MODE_TUNNEL == oMode) &&
             (CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
                           REF_MOC_IPADDR(pxSa->dwSaDestIPEnd),
                           REF_MOC_IPADDR(dwDestAddr), 0) ||
              CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaSrcIP),
                           REF_MOC_IPADDR(pxSa->dwSaSrcIPEnd),
                           REF_MOC_IPADDR(dwSrcAddr), 0)))
#endif
            )
        {
            status = ERR_IPSEC_MISMATCH_FLOW;
            EXIT_IPSEC
        }
    } /* for */

    /* get SP for the processed packet */
    if (OK > (status = (MSTATUS)
                       IPSEC_ready(REF_MOC_IPADDR(dwDestAddr),
                                   REF_MOC_IPADDR(dwSrcAddr),
                                   oProtocol,
                                   bFragOff, bMoreFrags,
                                   wDestPort, wSrcPort,
                                   TRUE, /* inbound */
                                   &pxSP
                                   MOC_INTF_REQ_ID(ifid)
                                   MOC_COOKIE_REQ_VALUE(cookie))))
    {
        if (ERR_IPSEC_FRAGMENTATION == status)
#ifdef __ENABLE_IPSEC_NAT_T__
        if (IPPROTO_UDP != oProtocol)
#endif
        {
            /* check 1st fragment only */
            status = STATUS_IPSEC_BYPASS; /* bypass */
            goto exit;
        }

        if (STATUS_IPSEC_BYPASS == status)
        {
            /* drop? */
            if ((0 < iNest)
                )
            {
                status = ERR_IPSEC_MISMATCH_BYPASS;
                EXIT_IPSEC
            }

#ifdef __ENABLE_IPSEC_NAT_T__
            /* check udp-encap. esp */
            if ((0 == wUdpEncPort) && (IPPROTO_UDP == oProtocol))
            {
                if (bFragOff)
                {
                    status = ERR_IPSEC_FRAGMENTATION;
                    EXIT_IPSEC
                }

                if (((IKE_NAT_UDP_PORT == wDestPort) ||
                     (IKE_NAT_UDP_PORT == wSrcPort)) &&
                    (sizeof(struct udpHdr) < wPayloadLen))
                {
                    struct udpHdr *pxUdp = (struct udpHdr *)poPayload;
                    ubyte *poPayload1 = poPayload + sizeof(struct udpHdr);
                    ubyte2 wPayloadLen1 = wPayloadLen - sizeof(struct udpHdr);

                    /* not NAT-Keepalive */
                    if (((sizeof(ubyte) > wPayloadLen1) || (0xFF != *poPayload1) ||
                         ((sizeof(ubyte)+sizeof(struct udpHdr)) != GET_NTOHS(pxUdp->uh_ulen))) &&
                    /* not NAT IKE */
                        ((sizeof(ubyte4) >= wPayloadLen1) ||
                         (0 != GET_NTOHL(((struct espHdr *)poPayload1)->dwSpi))))
                    {
                        /* jic */
                        if (0 != (wUdpEncPort = wSrcPort)) /* GET_NTOHS(pxUdp->uh_sport) */
                        {
                            wLength -= sizeof(struct udpHdr);
                            wPayloadLen = wPayloadLen1;
                            poPayload = poPayload1;
                            oProtocol = IPPROTO_ESP;

                            goto permit;
                        }
                    }
                }
            }
#endif /* __ENABLE_IPSEC_NAT_T__ */

            goto exit;
        } /* if (STATUS_IPSEC_BYPASS == status) */

        EXIT_IPSEC
    }

    if (iNest != pxSP->oSaLen)
    {
        /* security policy mismatch */
        if (0 < iNest)
            status = ERR_IPSEC_MISMATCH_BUNDLE;
        else
        {
            status = ERR_IPSEC_MISMATCH_PERMIT; /* packet not processed! */

            if (IPPROTO_ESP == oProtocol)
            {
                if (IPSEC_PROTO_AH != pxSP->pxSa[0].oSecuProto)
                    status = ERR_IPSEC_DROP_FINDSA_FAIL;
            }
            else if (IPPROTO_AH == oProtocol)
            {
                if (IPSEC_PROTO_AH == pxSP->pxSa[0].oSecuProto)
                    status = ERR_IPSEC_DROP_FINDSA_FAIL;
            }
        }

        EXIT_IPSEC
    }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    /* match SP mode */
    if ((0 != pxSP->oMode) && (oMode != pxSP->oMode))
    {
        status = ERR_IPSEC_MISMATCH_MODE;
        EXIT_IPSEC
    }
#endif

    /* match SP against applied SA's */
    for (i=0; i < iNest; i++)
    {
        SADB pxSa = axSaUsed[i]; /* applied SA */

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if (pxSP == pxSa->pxSp) /* auto. keyed */
        {
            if (i == pxSa->iNest) /* jic */
                continue;
        }
        else
#endif
        {
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            /* check tunnel IP addr's */
            if ((IPSEC_MODE_TUNNEL == oMode) &&
                ((!ISZERO_MOC_IPADDR(pxSP->dwTunlSrcIP) &&
                  !SAME_MOC_IPADDR(REF_MOC_IPADDR(dwTunlSrcIP), pxSP->dwTunlSrcIP)) ||
                 (!ISZERO_MOC_IPADDR(pxSP->dwTunlDestIP) &&
                  !SAME_MOC_IPADDR(REF_MOC_IPADDR(dwTunlDestIP), pxSP->dwTunlDestIP))))
            {
                status = ERR_IPSEC_MISMATCH_TADDR; /* mismatch */
                EXIT_IPSEC
            }
#endif
        }

        /* check crypto algos */
        if (!IPSEC_matchSp(NULL, pxSa, pxSP, i))
        {
            status = ERR_IPSEC_MISMATCH_SAINFO; /* mismatch */
            EXIT_IPSEC
        }
    } /* for */

#ifdef __ENABLE_IPSEC_FLOW__
    if (1 == iNest)
    {
        IPSEC_flowPut(axSaUsed[0], pxSP,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                      oMode,
#endif
                      REF_MOC_IPADDR(dwDestAddr), REF_MOC_IPADDR(dwSrcAddr),
                      oProtocol, wDestPort, wSrcPort);
    }

done:
#endif

#ifdef __ENABLE_IPSEC_NAT_T__
    /* fix tcp/udp checksum */
    if (0 != wUdpEncPort) /* udp-encap. */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_MODE_TUNNEL != oMode) /* transport mode only */
#endif
    {
        if (IPPROTO_UDP == oProtocol)
        {
            if (wPayloadLen < sizeof(struct udpHdr)) /* jic */
            {
                status = ERR_IPSEC_BAD_ULP;
                EXIT_IPSEC
            }

            SetUdpChecksum(poPayload,
                           RET_MOC_IPADDR4(dwSrcAddr),
                           RET_MOC_IPADDR4(dwDestAddr));
        }
        else if (IPPROTO_TCP == oProtocol)
        {
            if (wPayloadLen < sizeof(struct tcpHdr)) /* jic */
            {
                status = ERR_IPSEC_BAD_TCP;
                EXIT_IPSEC
            }

            SetTcpChecksum(poPayload,
                           RET_MOC_IPADDR4(dwSrcAddr),
                           RET_MOC_IPADDR4(dwDestAddr),
                           wPayloadLen);
        }
    }
#endif /* __ENABLE_IPSEC_NAT_T__ */

#if defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
    /* update replay window */
    for (i=0; i < iNest; i++)
    {
        if (adwSeqNbr[i])
        {
            if (OK != (status = AntiReplay(adwSeqNbr[i], axSaUsed[i], FALSE)))
                goto exit;
        }
    }
#endif

    /* update applied SA's */
    timenow = RTOS_deltaMS(&gStartTime, NULL);
    for (i=0; i < iNest; i++)
    {
        SADB pxSa = axSaUsed[i]; /* applied SA */
        LOCK_SA(pxSa)

        ++pxSa->dwSaCurPackets;

        if (0 == (pxSa->dwSaLastUsed = timenow))
            pxSa->dwSaLastUsed = 1;  /* jic sys time wraps backs to 0 */

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if (pxSa->pxSp) /* auto. keyed */
        {
            SADB pxSaM = pxSa->pxSaM; /* mirrored outbound SA */
            if (pxSaM && (pxSa->dwIdM == pxSaM->dwId))
            {
                pxSaM->dwSaFirstUsed = 0; /* for DPD */
                pxSaM->saFlags |= IPSEC_SA_FLAG_MATURE;
            }

            /* inform IKE of SA connection, if necessary */
            for (;;)
            {
                ubyte4 dwSaSpi=0;

                if ((timenow - pxSa->dwSaEstablished) < (ubyte4)30000) /* 30 secs - FOR NOW */
                {
                    /* stop re-transmission of the final quick mode message */
                    if (IPSEC_SA_FLAG_MATURE & pxSa->saFlags)
                        break;

                    dwSaSpi = pxSa->dwSaSpi;
                }
                else
                {
                    /* for IKE_SA rekeying */
                    if (pxSa->dwSaFirstUsed &&
                        ((timenow - pxSa->dwSaFirstUsed) < (ubyte4)300000)) /* 5 mins - FOR NOW */
                        break;

                    if (0 == (pxSa->dwSaFirstUsed = timenow))
                        pxSa->dwSaFirstUsed = 1; /* jic */
                }

                IKE_keyInform(REF_MOC_IPADDR(pxSa->dwSaDestAddr),
                              REF_MOC_IPADDR(pxSa->dwSaSrcAddr),
#ifdef __ENABLE_IPSEC_NAT_T__
                              0,/*pxSa->wSaUdpEncPort,*/
#endif
                              dwSaSpi, pxSa->oSaProto,
                              pxSa->dwIkeSaId, pxSa->ikeSaLoc,
                              IKE_KEY_TYPE_CONNECTED
                              MOC_COOKIE_VALUE(cookie));
                break;
            }

            pxSa->saFlags |= IPSEC_SA_FLAG_MATURE;
        }
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

        /*if (ctx) ctx->axSaUsed[i] = pxSa;*/

        UNLOCK_SA(pxSa)
    } /* update applied SA's */

    /* OK */
    if (ctx) ctx->pxSp = pxSP;

    if (pwLength) *pwLength = wLength;

    if (pwOffset)
    {
        ubyte *poHdrNew = poPayload - wHdrLen;
        if (poHdrNew != poHdr)
        {
            DIGI_MEMMOVE(poHdrNew, poHdr, wHdrLen);
        }
        *pwOffset = (ubyte2)(poHdrNew - pBuffer);
    }

exit:
    IPSEC_releaseHwAccelChannel(&hwAccelCtx);

nocleanup:
    return (sbyte4)status;
} /* IPSEC_permitEx */


/*------------------------------------------------------------------*/

static MSTATUS
IPSEC_get(MOC_IP_ADDRESS dwDestAddr, MOC_IP_ADDRESS dwSrcAddr,
          ubyte oProto,
          intBoolean bFragOff, intBoolean bMoreFrags,
          ubyte *poPayload, ubyte2 wPayloadLen,
          ubyte2 wDestPort, ubyte2 wSrcPort,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
          MOC_IP_ADDRESS *pdwTunlDestIP,
          MOC_IP_ADDRESS *pdwTunlSrcIP,
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
          ubyte2 *pwUdpEncPort,
#endif
          SPD *ppxSP, SADB *axSa
          MOC_INTF(ifid)
          MOC_COOKIE(cookie))
{
    MSTATUS status = OK;

    SPD pxSP = (ppxSP ? *ppxSP : NULL);

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    MOC_IP_ADDRESS dwTunlDestIP=0, dwTunlSrcIP=0;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2 wUdpEncPort=0;
#endif
#ifdef __ENABLE_IPSEC_FLOW__
    intBoolean bSaveFlow = axSa ? (NULL == axSa[0]) : TRUE;
#endif
    SADB axSaTmp[IPSEC_NEST_MAX] = { NULL };
    SADB *ppxSa = axSa ? axSa : axSaTmp;

    /* get SP */
    if (!pxSP)
    if (OK > (status = (MSTATUS)
                       IPSEC_ready(dwDestAddr, dwSrcAddr, oProto,
                                   bFragOff, bMoreFrags,
                                   wDestPort, wSrcPort,
                                   FALSE, /* outbound */
                                   &pxSP
                                   MOC_INTF_REQ_ID(ifid)
                                   MOC_COOKIE_REQ_VALUE(cookie))))
        goto exit;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_MODE_TUNNEL == pxSP->oMode)
    {
        if (!ISZERO_MOC_IPADDR(pxSP->dwTunlDestIP))
            dwTunlDestIP = REF_MOC_IPADDR(pxSP->dwTunlDestIP);
        if (!ISZERO_MOC_IPADDR(pxSP->dwTunlSrcIP))
            dwTunlSrcIP = REF_MOC_IPADDR(pxSP->dwTunlSrcIP);
    }
#endif

    /* get SA */
    if (!ppxSa[0])
    if (OK > (status = IPSEC_getSa(dwDestAddr, dwSrcAddr, oProto,
                                   wDestPort, wSrcPort,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                                   dwTunlDestIP, dwTunlSrcIP,
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
                                   wUdpEncPort,
#endif
                                   pxSP, ppxSa MOC_COOKIE_VALUE(cookie))))
    {
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        /* acquiring new SA */
        MSTATUS st;
        if (OK > (st = IKE_keyAcquire(dwDestAddr, dwSrcAddr, oProto,
                                      wDestPort, wSrcPort,
                                      pxSP
                                      MOC_COOKIE_VALUE(cookie))))
            status = st;
#endif
        goto exit;
    }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_MODE_TUNNEL == pxSP->oMode)
    {
        if (pxSP->oSaLen) /* jic */
        {
            if (!dwTunlDestIP && !ISZERO_MOC_IPADDR(ppxSa[0]->dwSaDestAddr))
                dwTunlDestIP = REF_MOC_IPADDR(ppxSa[0]->dwSaDestAddr);

            if (!dwTunlSrcIP && !ISZERO_MOC_IPADDR(ppxSa[0]->dwSaSrcAddr))
                dwTunlSrcIP = REF_MOC_IPADDR(ppxSa[0]->dwSaSrcAddr);
        }

        if (!dwTunlDestIP)
            dwTunlDestIP = dwDestAddr;

        if (!dwTunlSrcIP)
            dwTunlSrcIP = dwSrcAddr;
    }
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    if (!wUdpEncPort && pxSP->oSaLen)
        wUdpEncPort = ppxSa[0]->wSaUdpEncPort;
#endif

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (pdwTunlDestIP) *pdwTunlDestIP = dwTunlDestIP;
    if (pdwTunlSrcIP) *pdwTunlSrcIP = dwTunlSrcIP;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    if (pwUdpEncPort) *pwUdpEncPort = wUdpEncPort;
#endif

#ifdef __ENABLE_IPSEC_FLOW__
    if (bSaveFlow && (1 == pxSP->oSaLen))
    {
        IPSEC_flowPut(ppxSa[0], pxSP,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                      pxSP->oMode,
#endif
                      dwDestAddr, dwSrcAddr,
                      oProto, wDestPort, wSrcPort);
    }
#endif

    /* rekey SA, due to DPD */
#if !defined(__DISABLE_IPSEC_DPD__) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
    if (pxSP->oSaLen) /* jic */
    {
        SADB pxSa = ppxSa[0];
        if ((pxSP == pxSa->pxSp) && /* !!! */
            /* pxSa->dwSaLastUsed && */ pxSa->dwSaFirstUsed)
        {
            ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
            ubyte4 timeoutEvent = 60000/* 1000*60 */; /* 60 seconds - FOR NOW */
            if (!pxSa->dwSaLastRekey || ((timenow - pxSa->dwSaLastRekey) > timeoutEvent))
            {
                ubyte4 timespan = pxSa->dwSaLastUsed - pxSa->dwSaFirstUsed;
                ubyte4 timeoutWait = 20000/* 1000*20 */; /* 20 seconds - FOR NOW */
                if (timespan > timeoutWait)
                {
                    SADB pxSaM = pxSa->pxSaM; /* get mirrored inbound SA */
                    if (pxSaM)
                    {
                        if (!pxSaM->dwSaLastUsed || /* mirrored SA never used */
                            (pxSaM->dwId != pxSa->dwIdM)) /* mirrored SA deleted */
                        {
                            timeoutWait = 300000/* 1000*60*5 */; /* 5 minutes - FOR NOW */
                            if (timespan < timeoutWait)
                                goto exit;
                        }
                        else if (!(((timenow - pxSaM->dwSaLastUsed) > (timenow - pxSa->dwSaLastUsed)) &&
                                   ((pxSa->dwSaLastUsed - pxSaM->dwSaLastUsed) > timeoutEvent)))
                            goto exit;

                        /* rekeying SA now!!! */
                        if (OK <= IKE_keyAcqExp(pxSa, IKE_KEY_TYPE_ACQUIRE))
                            pxSa->dwSaLastRekey = timenow;

                        /*goto exit;*/
                    }
                    else
                    {
                        /* shouldn't get here! */
                    }
                }
            }
        }
    } /* rekey */
#endif /* ! __DISABLE_IPSEC_DPD__ */

exit:
    if (NULL != ppxSP)
        *ppxSP = pxSP;
    return status;
} /* IPSEC_get */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_applyEx(ubyte *pBuffer, ubyte2 wBufSize, ubyte2 *pwLength, ubyte2 *pwOffset, IPSECCTX ctx)
{
    MSTATUS status = OK;

    /* perform IPsec outbound processing */

    ubyte2 wOffset;
    ubyte *poHdr;

    struct ipHdr *pxHdr = NULL;
    ubyte2 wHdrLen;
    ubyte2 wLength;/*, wOrigLen = 0;*/

    ubyte  oProtocol;
    ubyte *poPayload;
    ubyte2 wPayloadLen;

    MOC_IP_ADDRESS_S dwDestAddr, dwSrcAddr;
    ubyte2 wDestPort, wSrcPort;

    intBoolean bFragOff, bMoreFrags;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    ubyte  oMode;
    MOC_IP_ADDRESS dwTunlDestIP, dwTunlSrcIP;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2 wUdpEncPort;
#endif
    sbyte4 i, iNest;
    ubyte4 timenow;

    SPD pxSP = (NULL != ctx) ? ctx->pxSp : NULL;

    /* store applied nested SA's */
    SADB axSaUsed[IPSEC_NEST_MAX] = { NULL };

    hwAccelDescr hwAccelCtx;

    if (!((NULL != ctx) && ctx->bAsyncEnabled)) /* jic */
    {
        status = ERR_IPSEC;
        EXIT_IPSEC
    }

    if (0 <= (i = ctx->counter - 1))
    {
        /* async job finished, continue processing */
        SADB pxSa;

        hwAccelCtx = ctx->hwAccelCtx;

        /* wOrigLen = wBufSize; */
        wBufSize = ctx->wBufSize;

        wOffset = ctx->wOffset;
        poHdr = pBuffer + wOffset;

        pxHdr = (struct ipHdr *)poHdr;

        wHdrLen = ctx->wIpHdrLen;
        wLength = ctx->wLength;
#if (defined(__ENABLE_IPSEC_NAT_T__) && defined(__ENABLE_DIGICERT_IKE_SERVER__))
        dwSrcAddr = ctx->dwSrcAddr;
        dwDestAddr = ctx->dwDestAddr;
#endif
        poPayload   = poHdr + wHdrLen;
        wPayloadLen = wLength - wHdrLen;

#ifdef __ENABLE_IPSEC_NAT_T__
        wUdpEncPort = ctx->wUdpEncPort;
#endif
        for (iNest=0/*i*/; iNest < pxSP->oSaLen; iNest++)
            axSaUsed[iNest] = ctx->axSaUsed[iNest];

        pxSa = axSaUsed[i];

        /* delete cipher context */
        if (ctx->pCipherCtx)
        {
            SADB_cipherSuiteInfo* pCipherSuite = pxSa->pCipherSuite;
            if (pCipherSuite) /* jic */
            {
                DOWN_SA_LOCK(pxSa)

                if ((ctx->pCipherCtx == pxSa->pCipherCtx) && /* jic */
                    (0 >= --pxSa->users) &&
                    (IPSEC_SA_FLAG_DELETED & pxSa->saFlags))
                {
                    pCipherSuite->pBEAlgo->deleteFunc(MOC_SYM(hwAccelCtx)
                                                      &pxSa->pCipherCtx);
                    pxSa->pCipherCtx = NULL;
                }
                UP_SA_LOCK(pxSa)
            }
            ctx->pCipherCtx = NULL;
        }

        if (OK > (status = (MSTATUS) ctx->status))
            EXIT_IPSEC

        SET_HTONS(pxHdr->ip_len, wLength);

        SET_IPHDR_CSUM(pxHdr->ip_sum, poHdr, wHdrLen)

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        oMode = IPSEC_MODE_TRANSPORT;
#endif
        i--;
        goto apply;
    }

    if (OK > (status = IPSEC_getHwAccelChannel(&hwAccelCtx, FALSE)))
        goto nocleanup;

    if (NULL != ctx)
        axSaUsed[0] = ctx->axSaUsed[0];

    wOffset = (pwOffset ? *pwOffset : 0);
    poHdr = pBuffer + wOffset;

    /* get ip packet info */
    if ((1 + wOffset) > wBufSize)
    {
        status = ERR_IPSEC_BUFFER_OVERFLOW;
        EXIT_IPSEC
    }

    /* check IP version */
    switch (poHdr[0] & 0xF0)
    {
    case 0x40 :
        pxHdr = (struct ipHdr *)poHdr;
        GET_PKT_INFO_OUT(pxHdr, (wBufSize - wOffset),
                         wLength, wHdrLen, oProtocol, bFragOff, bMoreFrags)

        SET_MOC_IPADDR4(dwSrcAddr,  GET_NTOHL(pxHdr->ip_src));
        SET_MOC_IPADDR4(dwDestAddr, GET_NTOHL(pxHdr->ip_dst));
        break;
    default :
        status = ERR_IPSEC_BAD_IP;
        EXIT_IPSEC
        break;
    }

    poPayload   = poHdr + wHdrLen;
    wPayloadLen = wLength - wHdrLen;

    /* get SP and SA bundle for this packet */
    GET_ULP_PORTS(poPayload, wPayloadLen, oProtocol, bFragOff,
                  wDestPort, wSrcPort)

    if (OK > (status = IPSEC_get(REF_MOC_IPADDR(dwDestAddr),
                                 REF_MOC_IPADDR(dwSrcAddr),
                                 oProtocol,
                                 bFragOff, bMoreFrags,
                                 poPayload, wPayloadLen,
                                 wDestPort, wSrcPort,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                                 &dwTunlDestIP, &dwTunlSrcIP,
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
                                 &wUdpEncPort,
#endif
                                 &pxSP, axSaUsed
                                 MOC_INTF_ID(ifid)
                                 MOC_COOKIE_VALUE(cookie))))
    {
        goto exit;
    }

    iNest = pxSP->oSaLen;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    oMode = pxSP->oMode;

    /* transport or tunnel */
    if (IPSEC_MODE_TUNNEL == oMode) /* tunnel mode */
    {
        /* If tunnel IP addr. is unspecified (==0), use inner private IP addr. */
        if (0 != dwTunlDestIP)
            COPY_MOC_IPADDR(dwDestAddr, dwTunlDestIP); /* dest. gateway */

        if (0 != dwTunlSrcIP)
        {
            if (!SAME_MOC_IPADDR(dwTunlSrcIP, dwSrcAddr)) /* forwarding */
            {
                COPY_MOC_IPADDR(dwSrcAddr, dwTunlSrcIP);

                /* decrement TTL */
                {
                    if (0 == pxHdr->ip_ttl)
                    {
                        status = ERR_IPSEC_DROP_TTL;
                        EXIT_IPSEC
                    }
                }
            }
        }
    }
#endif /* __DISABLE_IPSEC_TUNNEL_MODE__ */

    /* for book-keeping */
    for (i=0; i < iNest; i++)
    {
        SADB pxSa = axSaUsed[i];
        LOCK_SA(pxSa)
        ++pxSa->dwSaTotPackets;
        UNLOCK_SA(pxSa)
    }
/*
    wOrigLen = wLength;
*/
    i = iNest - 1;

apply:
    /* process nested IPSec transforms (start with innermost SA) */
    for (; i >= 0; i--)
    {
        SADB pxSa = axSaUsed[i];
        SADB_hmacSuiteInfo* pHmacSuite = pxSa->pHmacSuite;
        ubyte2 wIcvLen = (pHmacSuite ? pHmacSuite->wIcvLen : 0);
        ubyte oSecuProto = pxSP->pxSa[i].oSecuProto;/* AH, ESP, ESP_AUTH, or ESP_NULL */

        ubyte2 wIPSecHdrLen;
        ubyte4 dwSeqNbr;

        switch (oSecuProto)
        {
        /* process ESP */
        case IPSEC_PROTO_ESP_AUTH :     /* ESP with authentication */
        {
            ubyte2 wIvLen=0, wLengthNew;
            ubyte oPadLen=0, *poPad;
            struct espHdr *pxEsph;
            sbyte4 j;

            /* set up encryption */
            SADB_cipherSuiteInfo* pCipherSuite = pxSa->pCipherSuite;
            if (NULL != pCipherSuite)
            {
                ubyte2 wBlockLen, wLen;

                if (NULL == pHmacSuite)
                {
                    status = ERR_IPSEC;
                    EXIT_IPSEC
                }

                wIvLen = pCipherSuite->wIvLen; /* IV size */
                wBlockLen = (ubyte2) pCipherSuite->pBEAlgo->blockSize;

                /* calculate pad length */
                /* Note: 2 bytes for trailing pad length and next header */
                if (0 != (wLen = (((
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                                    (IPSEC_MODE_TUNNEL == oMode) ? wLength :
#endif
                                    wPayloadLen) + 2) % wBlockLen)))
                {
                    oPadLen = wBlockLen - wLen;
                }
            }
            else
            {
                status = ERR_IPSEC;
                EXIT_IPSEC
            }

            /* calculate extra packet header length */
            wIPSecHdrLen = sizeof(struct espHdr) + wIvLen;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            if (IPSEC_MODE_TUNNEL == oMode) /* add outer ip header length */
            {
                wHdrLen = sizeof(struct ipHdr);
                wIPSecHdrLen += wHdrLen;
            }
#endif
            /* check new packet length (include ICV) */
            /* Note: 2 bytes for trailing pad length and next header */
            wLengthNew = wLength + oPadLen + 2
                         ;
            if (wIPSecHdrLen > wOffset) wLengthNew += wIPSecHdrLen;

            if (wBufSize < (wLengthNew + wIcvLen + wOffset))
            {
                status = ERR_IPSEC_BUFFER_OVERFLOW;
                EXIT_IPSEC
            }
            if (wIPSecHdrLen <= wOffset) wLengthNew += wIPSecHdrLen;


#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            switch (oMode)
            {
            case IPSEC_MODE_TRANSPORT :
#endif
                /* make room for ESP header */
                if (wIPSecHdrLen <= wOffset)
                {
                    DIGI_MEMMOVE(poHdr - wIPSecHdrLen, poHdr, wHdrLen);
                    wOffset -= wIPSecHdrLen;
                    poHdr -= wIPSecHdrLen;

                    pxHdr = (struct ipHdr *)poHdr;
                    poPayload = poHdr + wHdrLen;
                }
                else

                DIGI_MEMMOVE(poPayload + wIPSecHdrLen, poPayload, wPayloadLen);

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                break;
/*          case IPSEC_MODE_TUNNEL : */
            default :
                /* duplicate outer ip header - options shouldn't be copied */
                if (wIPSecHdrLen <= wOffset)
                {
                    wOffset -= wIPSecHdrLen;
                    poHdr -= wIPSecHdrLen;
                }
                else

                DIGI_MEMMOVE(poHdr + wIPSecHdrLen, poHdr, wLength);
                poPayload = poHdr + wHdrLen;
                wIPSecHdrLen -= wHdrLen; /* exclude outer ip header length */

                /* update outer ip header fields */
                UPD_TUNNEL_IPHDR(dwDestAddr, dwSrcAddr, poHdr, pxHdr,
                                 oProtocol,
                                 bFragOff, bMoreFrags,
                                 pxSP->flags)

                break;
            }
#endif /* #ifndef __DISABLE_IPSEC_TUNNEL_MODE__ */

            wLength = wLengthNew;
            wPayloadLen = wLength - wHdrLen;

            /* fill esp next header protocol */
            poPayload[wPayloadLen - 1] = oProtocol;     /* next header */
            /*oProtocol = IPPROTO_ESP; */

            /* fill padding */
            poPayload[wPayloadLen - 2]  = oPadLen;
            poPad = poPayload + (wPayloadLen - 2 - oPadLen);
            for (j=0; j < oPadLen; j++) poPad[j] = j + 1;

            /* fill in esp fields */
            pxEsph = (struct espHdr *)poPayload;
            SET_HTONL(pxEsph->dwSpi, pxSa->dwSaSpi);            /* SPI */
            SET_HTONL(pxEsph->dwSeqNbr,             /* sequence number */
                      dwSeqNbr = ATOMIC_INC_GET(pxSa->dwSeqNbr));
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            if ((0 == dwSeqNbr) && pxSa->pxSp) /* jic - wraps back to 0 */
            {
                ATOMIC_SET(pxSa->dwSeqNbr, -1);
                status = ERR_IPSEC_DROP_GETSA_FAIL;
                EXIT_IPSEC
            }
#endif
            /* update ip header fields */
            {
                /*SET_HTONS(pxHdr->ip_len, wLength);*/
                          pxHdr->ip_p  = IPPROTO_ESP;   /* replace next protocol field with ESP */
            }

            {
                ctx->wOffset = wOffset;
                ctx->wIpHdrLen = wHdrLen;
                ctx->wLength = wLength;

                if (0 == ctx->counter)
                {
                    sbyte4 j;
                    for (j=0; j < iNest; j++) ctx->axSaUsed[j] = axSaUsed[j];

                    ctx->pxSp = pxSP;
                    ctx->wBufSize = wBufSize;

#ifdef __ENABLE_IPSEC_NAT_T__
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
                    ctx->dwSrcAddr = dwSrcAddr;
                    ctx->dwDestAddr = dwDestAddr;
#endif
                    ctx->wUdpEncPort = wUdpEncPort;
#endif
                    ctx->hwAccelCtx = hwAccelCtx;
                }
                ctx->counter = i + 1;
            }

                /* encrypt and authenticate in a single pass */
                {
                    BulkCtx pCipherCtx;

                    /* fill IV with random data */
                    {
                        if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,
                                                poPayload + sizeof(struct espHdr), wIvLen)))
                            EXIT_IPSEC
                    }

                    DOWN_SA_LOCK(pxSa)
                    pCipherCtx = pxSa->pCipherCtx;
                    if (NULL == pCipherCtx) /* jic */
                        status = ERR_IPSEC_DROP_GETSA_FAIL;
                    else
                    pxSa->users++;
                    UP_SA_LOCK(pxSa)

                    if (OK > status) EXIT_IPSEC

                    {
                        ctx->wLength += wIcvLen;
                        ctx->pCipherCtx = pCipherCtx;
                    }

                    LOCK_HARNESS(hwAccelCtx, TRUE)
                    HARNESS_assignAsyncCtx(hwAccelCtx, ctx);

                    status = HWOFFLOAD_doSinglePassEncryption(MOC_SYM(hwAccelCtx)
                                                MOCANA_IPSEC,
                                                pxSa->dwSinglePassCookie, 0,
                                                pCipherCtx,
                                                pxSa->poAuthKey,
                                                pHmacSuite->wKeyLen,
                                                poPayload, wPayloadLen,
                                                poPayload + wIPSecHdrLen,
                                                wPayloadLen - wIPSecHdrLen,
                                                NULL,           /* pointer to new packet location */
                                                poPayload + sizeof(struct espHdr), /* IV */
                                                wIvLen, wIcvLen, 0);

                    HARNESS_assignAsyncCtx(hwAccelCtx, NULL);
                    UNLOCK_HARNESS(hwAccelCtx, TRUE)

                    {
                        if (OK > status)
                        {
                        }
                        else
                        {
                            /* queue async job */
                            if (pwLength) *pwLength = 0;
                            return OK;
                        }
                    }
                    DOWN_SA_LOCK(pxSa)
                    pxSa->users--;
                    UP_SA_LOCK(pxSa)

                    {
                            EXIT_IPSEC
                    }
                }

            break;
        }

        default : /* invalid protocol */
            status = ERR_IPSEC;
            EXIT_IPSEC
        } /* switch (oSecuProto) { */

    } /* for (i */

#ifdef __ENABLE_IPSEC_NAT_T__
    if (0 != wUdpEncPort)
    {
        ubyte2 wSrcNattPort = IKE_NAT_UDP_PORT;

        struct udpHdr *pxUdp;

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if (NULL != IKE_ikeSettings()->funcPtrIkeNattSend)
        {
            sbyte4 st = IKE_ikeSettings()->funcPtrIkeNattSend(
                                                REF_MOC_IPADDR(dwDestAddr), wUdpEncPort,
                                                poPayload, wPayloadLen,
                                                REF_MOC_IPADDR(dwSrcAddr)
                                                MOC_COOKIE_REQ_VALUE(cookie));

            if (0 < st)
            {
                wSrcNattPort = (ubyte2)st;
            }
            else if (0 == st)
            {
                status = STATUS_IPSEC_NATT;
                goto done;
            }
            else
            {
                status = (MSTATUS)st;
                EXIT_IPSEC
            }
        }
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

        /* add UDP-encapsulation */
        wLength += sizeof(struct udpHdr);

        if (sizeof(struct udpHdr) <= wOffset)
        {
            DIGI_MEMMOVE(poHdr - sizeof(struct udpHdr), poHdr, wHdrLen);
            wOffset -= sizeof(struct udpHdr);
            poHdr -= sizeof(struct udpHdr);

            pxHdr = (struct ipHdr *)poHdr;
            poPayload = poHdr + wHdrLen;
        }
        else
        {
            if (wBufSize < (wLength + wOffset))
            {
                status = ERR_IPSEC_BUFFER_OVERFLOW;
                EXIT_IPSEC
            }
            DIGI_MEMMOVE(poPayload + sizeof(struct udpHdr), poPayload, wPayloadLen);
        }
        wPayloadLen += sizeof(struct udpHdr);

        pxUdp = (struct udpHdr *)poPayload;

        SET_HTONS(pxUdp->uh_sport, wSrcNattPort);   /* source port */
        SET_HTONS(pxUdp->uh_dport, wUdpEncPort);    /* destination port */
        SET_HTONS(pxUdp->uh_ulen,  wPayloadLen);    /* udp length */
        /*SET_HTONS(pxUdp->uh_sum,   0);*/          /* udp checksum */

        {
            SetUdpChecksum(poPayload,
                           RET_MOC_IPADDR4(dwSrcAddr),
                           RET_MOC_IPADDR4(dwDestAddr));
            SET_HTONS(pxHdr->ip_len, wLength);
                      pxHdr->ip_p  = IPPROTO_UDP;

            SET_IPHDR_CSUM(pxHdr->ip_sum, poHdr, wHdrLen)
        }
    }
#endif /* __ENABLE_IPSEC_NAT_T__ */

#if defined(__ENABLE_IPSEC_NAT_T__)
done:
#endif
    /* update applied SA's */
    timenow = RTOS_deltaMS(&gStartTime, NULL);
    for (i=0; i < iNest; i++)
    {
        SADB pxSa = axSaUsed[i]; /* applied SA */
        LOCK_SA(pxSa)

        ++pxSa->dwSaCurPackets;

        if (0 == (pxSa->dwSaLastUsed = timenow))
            pxSa->dwSaLastUsed = 1;  /* jic sys time wraps backs to 0 */

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if (pxSa->pxSp) /* auto. keyed */
        {
            if (!pxSa->dwSaFirstUsed) /* for DPD */
            {
                if (pxSa->pxSaM) /* mirrored inbound SA */
                    pxSa->dwSaFirstUsed = pxSa->dwSaLastUsed;
            }
        }
#endif
        UNLOCK_SA(pxSa)
    } /* update applied SA's */

    /* OK */
    if (pwLength) *pwLength = wLength;
    if (pwOffset) *pwOffset = wOffset;

exit:
    IPSEC_releaseHwAccelChannel(&hwAccelCtx);

nocleanup:
    return (sbyte4)status;
} /* IPSEC_applyEx */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_keyInitiate(IPSECKEY pxKey)
{
    MSTATUS status;

#ifndef __ENABLE_DIGICERT_IPV6__
    #define destAddr pxKey->dwDestAddr
    #define srcAddr pxKey->dwSrcAddr
#else
    MOC_IP_ADDRESS_S destAddr, srcAddr;
    if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
    {
        if (pxKey->dwDestAddr) {
            SET_MOC_IPADDR6(destAddr, pxKey->dwDestAddr); }
        else {
            ZERO_MOC_IPADDR(destAddr); }

        if (pxKey->dwSrcAddr) {
            SET_MOC_IPADDR6(srcAddr, pxKey->dwSrcAddr); }
        else {
            ZERO_MOC_IPADDR(srcAddr); }
    }
    else
    {
        SET_MOC_IPADDR4(destAddr, pxKey->dwDestAddr);
        SET_MOC_IPADDR4(srcAddr, pxKey->dwSrcAddr);
    }
#endif /* __ENABLE_DIGICERT_IPV6__ */

    status = IPSEC_get(REF_MOC_IPADDR(destAddr), REF_MOC_IPADDR(srcAddr),
                       pxKey->oUlp,
                       FALSE, FALSE, NULL, 0,
                       pxKey->wDestPort, pxKey->wSrcPort,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                       NULL, NULL,
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
                       NULL,
#endif
                       NULL, NULL
                       MOC_INTF_ID(pxKey->ifid)
                       MOC_COOKIE_VALUE(pxKey->cookie));

    if (ERR_IPSEC_DROP_GETSA_FAIL == status)
        status = OK;
    else if (OK == status)
        status = STATUS_IPSEC_GETSA_SUCCESS;

    return (sbyte4)status;
} /* IPSEC_keyInitiate */

#endif /* defined( SINGLE_PASS ) */
#endif /* defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) */

