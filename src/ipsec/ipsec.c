/**
 * @file  ipsec.c
 * @brief NanoSec IPsec implementation.
 *
 * @details    This file contains NanoSec IPsec core implementation.
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IPSEC_SERVICE__
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

#if defined(__ENABLE_DIGICERT_IPSEC_SERVICE__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/random.h"
#include "../common/debug_console.h"
#ifdef __ENABLE_IPSEC_ESN__
#include "../common/int64.h"
#endif
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

#if defined(__LINUX_RTOS__) && defined(__KERNEL__) && defined(__EXTERNAL_SEED__)
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/types.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__

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

#elif defined(__QNX_RTOS__)

#elif defined(__VXWORKS_RTOS__) && !defined(INCLUDE_IPNET_STACK)

#elif defined(__OSE_RTOS__) || defined(__VXWORKS_RTOS__)
#ifndef IPCOM_KERNEL
#define IPCOM_KERNEL
#endif
#include <ipcom_os.h>

static Ipcom_mutex hwAccelLock_in;
static Ipcom_mutex hwAccelLock_out;

#define INIT_HARNESS_LOCK \
    ipcom_mutex_create(&hwAccelLock_out); \
    ipcom_mutex_create(&hwAccelLock_in);

#define DEL_HARNESS_LOCK \
    ipcom_mutex_delete(&hwAccelLock_in); \
    ipcom_mutex_delete(&hwAccelLock_out);

#define LOCK_HARNESS(_hw, _encr) \
{\
    Ip_u32 msr = ipcom_interrupt_disable();\
    Ipcom_mutex *_lock = (_encr ? &hwAccelLock_out : &hwAccelLock_in);\
    ipcom_mutex_lock(*_lock);\


#define UNLOCK_HARNESS(_hw, _encr) \
    ipcom_mutex_unlock(*_lock);\
    ipcom_interrupt_enable(msr);\
}

#endif

#ifndef LOCK_HARNESS
#define LOCK_HARNESS(_hw, _encr)
#endif
#ifndef UNLOCK_HARNESS
#define UNLOCK_HARNESS(_hw, _encr)
#endif

#endif /* __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__ */

#ifndef INIT_HARNESS_LOCK
#define INIT_HARNESS_LOCK
#endif
#ifndef DEL_HARNESS_LOCK
#define DEL_HARNESS_LOCK
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_INIT__
MOC_EXTERN_DATA_DECL moctime_t gStartTime;
#else
MOC_EXTERN_DATA_DECL moctime_t gStartTime;
#endif


/*------------------------------------------------------------------*/

#ifndef LOG_IPSEC_APPLY_SUCCESS
#define LOG_IPSEC_APPLY_SUCCESS(_sp_proto, _len)
#endif

#ifndef LOG_IPSEC_PERMIT_SUCCESS
#define LOG_IPSEC_PERMIT_SUCCESS(_sp_proto, _len)
#endif

#ifndef LOG_IPSEC_PERMIT_FAIL
#define LOG_IPSEC_PERMIT_FAIL(_st, _proto, _spi, _sa)
#endif

#ifndef EXIT_IPSEC
#define EXIT_IPSEC  { DB_PRINT("%s [%d]: %s()=%d\n", __FILE__, __LINE__, __FUNCTION__, (int)status); goto exit; }
#endif

#ifndef DBG_STATUS
#define DBG_STATUS(_st) { DB_PRINT("%s [%d]: %s()=%d\n", __FILE__, __LINE__, __FUNCTION__, (int)_st); }
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IPSEC_ESN__
#if __DIGICERT_MAX_INT__ == 64
#define SEQ_MAX 0xffffffffffffffffull
#else
static ubyte8 g_seqMax = { 0xFFFFFFFF, 0xFFFFFFFF };
#define SEQ_MAX g_seqMax
#endif
#else
#define SEQ_MAX 0xFFFFFFFF
#endif

#ifndef ATOMIC_SET
#define ATOMIC_SET(v, i)    v = (ATOMIC_T)(i)
#endif

#ifndef ATOMIC_INC_GET
#ifdef __ENABLE_IPSEC_ESN__
#if __DIGICERT_MAX_INT__ == 64
#define ATOMIC_INC_GET(v)   ++(v)
#else
#define ATOMIC_INC_GET(v)   v = u8_Add32(v, 1)
#endif
#else
#define ATOMIC_INC_GET(v)   ++(v)
#endif
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
#elif defined(__VXWORKS_RTOS__)
    static ATOMIC_T ips_id = { 0 };
    #define NEXT_IPHDR_ID ATOMIC_INC_GET(ips_id)
#else
    #define NEXT_IPHDR_ID ++wEthIPSec_ID    /* WARNING: not thread-safe */
#endif

#else
    #define NEXT_IPHDR_ID ATOMIC_NEXT_IPHDR_ID
#endif
#endif


/*------------------------------------------------------------------*/

#ifndef __IPSEC_INLINE__

static MSTATUS
GetPktInfo(struct ipHdr *pxHdr, ubyte2 wBufSize,
           ubyte2 *pwLength, ubyte2 *pwHdrLen, ubyte *poProtocol,
           intBoolean *pbFragOff, intBoolean *pbMoreFrags,
           intBoolean bIn)
{
    MSTATUS status = OK;

    ubyte2 wHdrLen;
    ubyte2 wLength;
    ubyte2 wFragOff;

    if (sizeof(struct ipHdr) > wBufSize)
    {
        status = (bIn ? ERR_IPSEC_BAD_IP : ERR_IPSEC_BUFFER_OVERFLOW);
        EXIT_IPSEC
    }

    wHdrLen = (pxHdr->ip_vhl & 0x0F) << 2;
    wLength = GET_NTOHS(pxHdr->ip_len);

    /* check length */
    if (sizeof(struct ipHdr) > wHdrLen ||
        wHdrLen > wLength)
    {
        status = ERR_IPSEC_BAD_IP;
        EXIT_IPSEC
    }

    if (wLength > wBufSize)
    {
        status = (bIn ? ERR_IPSEC_BAD_IP : ERR_IPSEC_BUFFER_OVERFLOW);
        EXIT_IPSEC
    }

    *pwLength    = wLength;
    *pwHdrLen    = wHdrLen;
    *poProtocol  = pxHdr->ip_p;

    wFragOff = GET_NTOHS(pxHdr->ip_off);
    *pbFragOff   = (IP_OFFMASK & wFragOff) ? TRUE : FALSE;
    *pbMoreFrags = (IP_MF & (~(IP_OFFMASK) & wFragOff)) ? TRUE : FALSE;

exit:
    return status;
} /* GetPktInfo */

#define GET_PKT_INFO(pxHdr, bufSize, wLength, wHdrLen, oProtocol, bFragOff, bMoreFrags, _in) \
    if (OK > (status = GetPktInfo(pxHdr, bufSize, \
                                  &wLength, &wHdrLen, &oProtocol, \
                                  &bFragOff, &bMoreFrags, _in))) \
        goto exit; \

#define GET_PKT_INFO_IN(pxHdr, bufSize, wLength, wHdrLen, oProtocol, bFragOff, bMoreFrags) \
    GET_PKT_INFO(pxHdr, bufSize, wLength, wHdrLen, oProtocol, bFragOff, bMoreFrags, TRUE)

#define GET_PKT_INFO_OUT(pxHdr, bufSize, wLength, wHdrLen, oProtocol, bFragOff, bMoreFrags) \
    GET_PKT_INFO(pxHdr, bufSize, wLength, wHdrLen, oProtocol, bFragOff, bMoreFrags, FALSE)

#else

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

#endif /* __IPSEC_INLINE__ */


/*------------------------------------------------------------------*/

#ifndef __IPSEC_INLINE__

static MSTATUS
GetUlpPorts(ubyte *poPayload, ubyte2 wPayloadLen, ubyte oUlp,
            intBoolean bFragOff,
            ubyte2 *pwDestPort, ubyte2 *pwSrcPort)
{
    MSTATUS status = OK;

    *pwSrcPort = 0;
    *pwDestPort = 0;

    switch (oUlp)
    {
    case IPPROTO_TCP :
        if (!bFragOff)
        {
            struct tcpHdr *pxTcp = (struct tcpHdr *)poPayload;
            if (wPayloadLen < (sizeof(ubyte2) * 2)/*sizeof(struct tcpHdr)*/)
            {
                status = ERR_IPSEC_BAD_TCP;
                EXIT_IPSEC
            }

            SET_NTOHS(*pwSrcPort, pxTcp->th_sport);
            SET_NTOHS(*pwDestPort, pxTcp->th_dport);
        }
        break;
    case IPPROTO_UDP :
        if (!bFragOff)
        {
            struct udpHdr *pxUdp = (struct udpHdr *)poPayload;
            if (wPayloadLen < sizeof(struct udpHdr))
            {
                status = ERR_IPSEC_BAD_ULP;
                EXIT_IPSEC
            }

            SET_NTOHS(*pwSrcPort, pxUdp->uh_sport);
            SET_NTOHS(*pwDestPort, pxUdp->uh_dport);
        }
        break;
    case IPPROTO_ICMP :
    case IPPROTO_ICMPV6 :
        if (!bFragOff)
        {
            if (wPayloadLen < sizeof(ubyte2))
            {
                status = ERR_IPSEC_BAD_ULP;
                EXIT_IPSEC
            }

            *pwSrcPort = DIGI_NTOHS(poPayload);
        }
        break;
    }

exit:
    return status;
} /* GetUlpPorts */

#define GET_ULP_PORTS(poPayload, wPayloadLen, oUlp, bFragOff, wDestPort, wSrcPort) \
    if (OK != (status = GetUlpPorts(poPayload, wPayloadLen, oUlp, \
                                    bFragOff, &(wDestPort), &(wSrcPort)))) \
        goto exit; \

#else

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
    case IPPROTO_ICMPV6 :\
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

#endif /* __IPSEC_INLINE__ */


/*------------------------------------------------------------------*/

#if !defined(__DISABLE_IPSEC_TUNNEL_MODE__)

static void
UpdTunlIpHdr(MOC_IP_ADDRESS dwDestAddr, MOC_IP_ADDRESS dwSrcAddr,
             ubyte *poHdr, struct ipHdr **ppxHdr,
#ifdef __ENABLE_DIGICERT_IPV6__
             struct ip6Hdr **ppxHdr6,
             ubyte *poProtocol, ubyte **ppoNextHeader,
#endif
             SPD pxSp)
{
    ubyte4 flags = pxSp->flags;

    struct ipHdr *pxHdr = *ppxHdr;
#ifdef __ENABLE_DIGICERT_IPV6__
    struct ip6Hdr *pxHdr6 = *ppxHdr6;

    if (pxHdr6)
        *poProtocol = IPPROTO_IPV6; /* IPv6-in-IP encapsulation type */
    else
        *poProtocol = IPPROTO_IPIP; /* IP encapsulation type */
#endif

    TEST_MOC_IPADDR6(dwDestAddr,
    {
        /* IPv6 outer header */
        if (!pxHdr6) /* IPv4 inner header */
        {
            ubyte ip_tos = pxHdr->ip_tos;
            ubyte ip_ttl = pxHdr->ip_ttl; /* if forwarding, assuimg decremented already */

            *ppxHdr = NULL;
            *ppxHdr6 = pxHdr6 = (struct ip6Hdr *)poHdr;
            *ppoNextHeader = &(pxHdr6->ip6_nexthdr);
            SET_HTONL(pxHdr6->ip6_vtf, (0x60000000 | ((ubyte4)ip_tos << IP6_TC_SHIFT)));
                      pxHdr6->ip6_hop_limit = ip_ttl;
        }
        else /* IPv6 inner header */
        {
            if (poHdr != (ubyte*)pxHdr6)
            {
                DIGI_MEMCPY(poHdr, (ubyte*)pxHdr6, SIZEOF_IP6_HDR);
                *ppxHdr6 = pxHdr6 = (struct ip6Hdr *)poHdr;
                *ppoNextHeader = &(pxHdr6->ip6_nexthdr);
            }
        }

        DIGI_MEMCPY(pxHdr6->ip6_saddr, GET_MOC_IPADDR6(dwSrcAddr), 16);    /* replace src address */
        DIGI_MEMCPY(pxHdr6->ip6_daddr, GET_MOC_IPADDR6(dwDestAddr), 16);   /* replace dest address */
    })
    {
        /* IPv4 outer header */
#ifdef __ENABLE_DIGICERT_IPV6__
        if (!pxHdr) /* IPv6 inner header */
        {
            ubyte4 ip6_tc = (IP6_TC & GET_NTOHL(pxHdr6->ip6_vtf));
            ubyte ip6_hop_limit = pxHdr6->ip6_hop_limit;

            *ppxHdr6 = NULL;
            *ppxHdr = pxHdr = (struct ipHdr *)poHdr;
                      pxHdr->ip_tos = (ubyte)(ip6_tc >> IP6_TC_SHIFT);
            SET_HTONS(pxHdr->ip_off,  0);
                      pxHdr->ip_ttl = ip6_hop_limit; /* if forwarding, assuimg decremented already */
        }
        else /* IPv4 inner header */
#endif
        {
            ubyte2 wFragOff = GET_NTOHS(pxHdr->ip_off);

            if (poHdr != (ubyte*)pxHdr)
            {
/*              DIGI_MEMCPY(poHdr, (ubyte*)pxHdr, sizeof(struct ipHdr)); */
                          ((struct ipHdr *)poHdr)->ip_tos = pxHdr->ip_tos;
/*              SET_HTONS(((struct ipHdr *)poHdr)->ip_off,  wFragOff);  */
                          ((struct ipHdr *)poHdr)->ip_ttl = pxHdr->ip_ttl;
                *ppxHdr = pxHdr = (struct ipHdr *)poHdr;
            }

            /* adjust fragmentation */
            wFragOff &= ~(IP_OFFMASK | IP_MF);

            if (IPSEC_SP_FLAG_DF & flags) /* no copy (DF bit) */
            {
                if (IPSEC_SP_FLAG_DF_BIT & flags)
                    wFragOff |= IP_DF;      /* set */
                else
                    wFragOff &= ~(IP_DF);   /* clear */
            }

            SET_HTONS(pxHdr->ip_off, wFragOff);
        }
                  pxHdr->ip_vhl= 0x45; /* 4 | ((ubyte)wHdrLen >> 2) */
        SET_HTONS(pxHdr->ip_id,  NEXT_IPHDR_ID);/* generate ID */
        SET_HTONL(pxHdr->ip_src, GET_MOC_IPADDR4(dwSrcAddr));    /* replace src address */
        SET_HTONL(pxHdr->ip_dst, GET_MOC_IPADDR4(dwDestAddr));   /* replace dest address */
    }

    /* handle DSCP value */
#ifdef CUSTOM_IPSEC_MAP_DSCP
    if (IPSEC_SP_FLAG_DSCP & flags) /* no copy */
    {
        CUSTOM_IPSEC_MAP_DSCP(poHdr, pxSp->pDscpMapping) ;
    }
#endif

    return;
} /* UpdTunlIpHdr */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPV6__
#define UPD_TUNNEL_IPHDR(_da, _sa, _hn, _hf, _hs, _p, _n, _sp) \
    UpdTunlIpHdr(REF_MOC_IPADDR(_da), REF_MOC_IPADDR(_sa),\
                 _hn, &(_hf), &(_hs), &(_p), &(_n),\
                 _sp);
#else
#define UPD_TUNNEL_IPHDR(_da, _sa, _hn, _hf, _hs, _p, _n, _sp) \
    UpdTunlIpHdr(REF_MOC_IPADDR(_da), REF_MOC_IPADDR(_sa),\
                 _hn, &(_hf),\
                 _sp);\
    oProtocol = IPPROTO_IPIP;
#endif

#endif /* !defined(__DISABLE_IPSEC_TUNNEL_MODE__) */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__

static MSTATUS
DoAsyncCipher(hwAccelDescr hwAccelCtx, SADB pxSa,
              IPSECCTX ctx,
              const BulkEncryptionAlgo* pAlgo,
              ubyte* iv, ubyte* data, sbyte4 dataLength, sbyte4 encrypt)
{
    MSTATUS status = OK;
    BulkCtx pCipherCtx;

    DOWN_SA_LOCK(pxSa)
    pCipherCtx = pxSa->pCipherCtx;
    if (NULL == pCipherCtx) /* jic */
        status = (encrypt ? ERR_IPSEC_DROP_GETSA_FAIL : ERR_IPSEC_DROP_FINDSA_FAIL);
    else
    pxSa->users++;
    UP_SA_LOCK(pxSa)

    if (OK > status) goto exit;

    ctx->pCipherCtx = pCipherCtx;

#ifdef __ENABLE_DIGICERT_HARNESS__
    LOCK_HARNESS(hwAccelCtx, encrypt)
    HARNESS_assignAsyncCtx(hwAccelCtx, ctx);
#endif
    if (OK > (status = pAlgo->cipherFunc(hwAccelCtx, pCipherCtx,
                                         data, dataLength,
                                         encrypt, iv)))
    {
        ctx->pCipherCtx = NULL;

        DOWN_SA_LOCK(pxSa)
        pxSa->users--;
        UP_SA_LOCK(pxSa)
    }

#ifdef __ENABLE_DIGICERT_HARNESS__
    HARNESS_assignAsyncCtx(hwAccelCtx, NULL);
    UNLOCK_HARNESS(hwAccelCtx, encrypt)
#endif

exit:
    return status;
} /* DoAsyncCipher */


/*------------------------------------------------------------------*/

static MSTATUS
DoAsyncHmac(hwAccelDescr hwAccelCtx,
            IPSECCTX ctx,
            ubyte* key, SADB_hmacSuiteInfo *pHmacSuite,
            ubyte* text, sbyte4 textLen, ubyte* result, sbyte4 encrypt)
{
    MSTATUS status;

    if (encrypt)
    {
        if ((ctx->wOffset + ctx->wLength + pHmacSuite->wDigestOrgLen)
            > ctx->wBufSize)
        {
            ctx->wIcvLen = pHmacSuite->wDigestOrgLen;
            result = ctx->poDigest;
        }
        else
        ctx->wIcvLen = pHmacSuite->wIcvLen;
        ctx->wLength += pHmacSuite->wIcvLen;
    }

#ifdef __ENABLE_DIGICERT_HARNESS__
    LOCK_HARNESS(hwAccelCtx, encrypt)
    HARNESS_assignAsyncCtx(hwAccelCtx, ctx);
#endif
    status = pHmacSuite->hmacFunc(hwAccelCtx,
                                  key, pHmacSuite->wKeyLen,
                                  text, textLen, result);
#ifdef __ENABLE_DIGICERT_HARNESS__
    HARNESS_assignAsyncCtx(hwAccelCtx, NULL);
    UNLOCK_HARNESS(hwAccelCtx, encrypt)
#endif
    return status;
} /* DoAsyncHmac */

#endif /* __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__ */


/*------------------------------------------------------------------*/

#ifdef __KERNEL__
/* This pointer holds a reference to IKE settings from moc_ipsec_mod.ko. */
static ikeSettings *pGlobalIkeSettings = NULL;

/* This function is called during initialization phase of moc_ipsec_mod.ko. */
extern sbyte4
IPSEC_setIkeSettings(void *pIkeSettings) {
    if (NULL == pIkeSettings) {
        return ERR_NULL_POINTER;
    }
    pGlobalIkeSettings = (ikeSettings *)pIkeSettings;
    return OK;
}

extern ikeSettings*
IKE_ikeSettings(void) {
    static ikeSettings pTmp;
    if (NULL == pGlobalIkeSettings)
    {
        DIGI_MEMSET((void *) &pTmp, 0x00, sizeof(pTmp));
        return &pTmp;
    }
    return pGlobalIkeSettings;
}
#endif /* __KERNEL__ */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_init(void)
{
    MSTATUS status;

#if defined(__VXWORKS_RTOS__) && defined(__EXTERNAL_SEED__)
    ubyte4 randomSeed;
    sbyte4 count;
#endif
#if defined(__LINUX_RTOS__) && defined(__KERNEL__) && defined(__EXTERNAL_SEED__)
    ubyte4 randomSeed;
    sbyte4 count;
    struct file *pFilp = NULL;
    ssize_t (*fop_read)(struct file *, char *, size_t, loff_t *);
    ssize_t ret = -EINVAL;
    static mm_segment_t old_fs;
#endif

#ifdef __DISABLE_DIGICERT_INIT__
    RTOS_deltaMS(NULL, &gStartTime);
#endif

    INIT_HARNESS_LOCK

    if (OK > (status = IPSEC_cryptoInit()))
        goto exit;

    if (OK > (status = IPSEC_initSadb()))
        goto exit;
#ifndef __ENABLE_DIGICERT_GDOI_SERVER__
    if (OK > (status = IPSEC_initSpd()))
        goto exit;
#endif

#if defined(__LINUX_RTOS__) && defined(__KERNEL__) && defined(__EXTERNAL_SEED__)

    /* open /dev/random */
    pFilp = filp_open("/dev/random", O_RDONLY, 0);
    if((pFilp == NULL) || (IS_ERR(pFilp)))
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    /* read 1 byte from /dev/random into buf */
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    if(pFilp->f_op && (fop_read = pFilp->f_op->read) != NULL)
    {
        ret = fop_read(pFilp, (char *)&randomSeed, 4, &pFilp->f_pos);
        if(ret < 0 || ret > 4)
        {
            status = ERR_FILE_READ_FAILED;
            goto exit;
        }
    }

    for (count = 32; count > 0; count--)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > (status = CRYPTO_INTERFACE_RANDOM_addEntropyBitEx(g_pRandomContext, (ubyte)(randomSeed & 1))))
#else
        if (OK > (status = RANDOM_addEntropyBit(g_pRandomContext, (ubyte)(randomSeed & 1))))
#endif
        {
            goto exit;
        }
        randomSeed >>= 1;
    }
#endif

#if defined(__VXWORKS_RTOS__) && defined(__EXTERNAL_SEED__)

    randomSeed = ipcom_random();
    for (count = 32; count > 0; count--)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > (status = CRYPTO_INTERFACE_RANDOM_addEntropyBitEx(g_pRandomContext, (ubyte)(randomSeed & 1))))
#else
        if (OK > (status = RANDOM_addEntropyBit(g_pRandomContext, (ubyte)(randomSeed & 1))))
#endif
        {
            goto exit;
        }
        randomSeed >>= 1;
    }

#endif

#if !defined(__DISABLE_IPSEC_TUNNEL_MODE__) && !defined(ATOMIC_NEXT_IPHDR_ID)
    if (OK > (status = RANDOM_numberGenerator(g_pRandomContext, (ubyte *)&wEthIPSec_ID, sizeof(wEthIPSec_ID))))
        goto exit;

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    atomic_set(&ips_id, (int)wEthIPSec_ID);
#elif defined(__VXWORKS_RTOS__)
    ATOMIC_SET(ips_id, wEthIPSec_ID);
#endif
#endif

#ifdef __ENABLE_IPSEC_FLOW__
    IPSEC_flowInit();
#endif

exit:
#if defined(__LINUX_RTOS__) && defined(__KERNEL__) && defined(__EXTERNAL_SEED__)
    if((NULL != pFilp) && !(IS_ERR(pFilp)))
    {
        filp_close(pFilp,NULL);
        set_fs(old_fs);
    }
#endif

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
#ifndef __ENABLE_DIGICERT_GDOI_SERVER__
    IPSEC_flushSpd();
#endif

    if (OK > (status = IPSEC_flushSadb()))
        goto exit;

    status = IPSEC_cryptoUninit();

    DEL_HARNESS_LOCK
exit:
    return (sbyte4)status;
} /* IPSEC_flush */


/*------------------------------------------------------------------*/

#if defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__)

#ifdef __ENABLE_IPSEC_ESN__
#if __DIGICERT_MAX_INT__ == 64
#define U8_Lt(_x, _y)       (_x < _y)
#define u8_Sub(_x, _y)      (((ubyte8) _x) - ((ubyte8) _y))
#define u8_Sub32(_x, _y)    (((ubyte8) _x) - ((ubyte8) _y))

#else
#define U8_Lt(_x, _y)       ((HI_U8(_x) < HI_U8(_y)) || \
                             ((HI_U8(_x) == HI_U8(_y)) && \
                              (LOW_U8(_x) < LOW_U8(_y))))

static ubyte8
u8_Sub(ubyte8 a, ubyte8 b)
{
    b.upper32 = ~(b.upper32);
    b.lower32 = ~(b.lower32) + (ubyte4)1;
    if (0 == b.lower32) b.upper32 += (ubyte4)1;

    a.upper32 += b.upper32;
    a.lower32 += b.lower32;
    if (a.lower32 < b.lower32) a.upper32 += (ubyte4)1;

    return a;
}

static ubyte8
u8_Sub32(ubyte8 a, ubyte4 b)
{
    if (b)
    {
        ubyte8 c;
        c.upper32 = 0xffffffff;
        c.lower32 = ~b + (ubyte4)1;

        a.upper32 += c.upper32;
        a.lower32 += c.lower32;
        if (a.lower32 < c.lower32) a.upper32 += (ubyte4)1;
    }

    return a;
}

#endif
#endif /* __ENABLE_IPSEC_ESN__ */


/*------------------------------------------------------------------*/

static MSTATUS
AntiReplay(
#ifdef __ENABLE_IPSEC_ESN__
           ubyte4 dwSeql, ubyte4 dwSeqh,
#else
           ubyte4 dwSeqNbr,
#endif
           SADB pxSa, intBoolean bCheckOnly)
{
    /* anti-replay by checking seq no in the sliding replay window */
    MSTATUS status = OK;

    ubyte4 dwRlyWndBytes = IPSEC_REPLAY_SIZE / 8; /* bytes */
    ubyte4 dwRlySize = dwRlyWndBytes * 8; /* bits/packets */
    ubyte *poReplayWindow = pxSa->u.i.poReplayWindow;

#ifdef __ENABLE_IPSEC_ESN__
    ubyte8 dwSeqNbr = U8INT(dwSeqh, dwSeql);
    ubyte8 dwSeqNbrRlyStart, dwSeqNbrRlyEnd;
#else
    ubyte4 dwSeqNbrRlyStart, dwSeqNbrRlyEnd;
#endif
    intBoolean bLastRlyWndPkt = FALSE;
    sbyte4 j;

    LOCK_SA(pxSa)

    /* drop if the seq no falls to the left of the replay window */
    dwSeqNbrRlyStart = ATOMIC_GET(pxSa->u.i.seqB);
#ifdef __ENABLE_IPSEC_ESN__
    if (U8_Lt(dwSeqNbr, dwSeqNbrRlyStart))
#else
    if (dwSeqNbr < dwSeqNbrRlyStart)
#endif
    {
        status = ERR_IPSEC_DROP_REPLAY_LATE;
        EXIT_IPSEC
    }

    /* if seq no. falls inside the replay window */
#ifdef __ENABLE_IPSEC_ESN__
    dwSeqNbrRlyEnd = u8_Add32(dwSeqNbrRlyStart, dwRlySize);
    if (U8_Lt(dwSeqNbr, dwSeqNbrRlyEnd) || U8_Lt(dwSeqNbrRlyEnd, dwSeqNbrRlyStart))
    {
        ubyte4 dwOffset = LOW_U8(u8_Sub(dwSeqNbr, dwSeqNbrRlyStart));
#else
    dwSeqNbrRlyEnd = dwSeqNbrRlyStart + dwRlySize;
    if ((dwSeqNbr < dwSeqNbrRlyEnd) || (dwSeqNbrRlyEnd < dwSeqNbrRlyStart))
    {
        ubyte4 dwOffset = dwSeqNbr - dwSeqNbrRlyStart;
#endif
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
#ifdef __ENABLE_IPSEC_ESN__
        ubyte4 dwShift = LOW_U8(u8_Add32(u8_Sub(dwSeqNbr, dwSeqNbrRlyEnd), 1));
#else
        ubyte4 dwShift = dwSeqNbr - dwSeqNbrRlyEnd + 1;
#endif
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

#ifdef __ENABLE_IPSEC_ESN__
        ATOMIC_SET(pxSa->u.i.seqB, u8_Sub32(dwSeqNbr, (dwRlySize - 1)));
#else
        ATOMIC_SET(pxSa->u.i.seqB, dwSeqNbr - dwRlySize + 1);
#endif
        if (1 == dwShift)
            bLastRlyWndPkt = TRUE;
    }

    /* advance the entire replay window, if possible */
    if (bLastRlyWndPkt)
    {
#ifdef __ENABLE_IPSEC_ESN__
        if (U8_Lt(u8_Add32(dwSeqNbr, dwRlySize), dwSeqNbr))
#else
        if ((dwSeqNbr + dwRlySize) < dwSeqNbr)
#endif
            goto exit;

        for (j = (sbyte4)dwRlyWndBytes - 1; j >= 0; j--)
        {
            if (0xff != poReplayWindow[j])
                break;
        }
        if (0 > j)
        {
#ifdef __ENABLE_IPSEC_ESN__
            ATOMIC_SET(pxSa->u.i.seqB, u8_Add32(dwSeqNbr, 1));
#else
            ATOMIC_SET(pxSa->u.i.seqB, dwSeqNbr + 1);
#endif
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
              ((0 != pxSP->wDestPort || 0 != pxSP->wDestPortCount) || (0 != pxSP->wSrcPort)
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

    if(NULL != pxSP)
    {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
       DB_PRINT("\n ipsec_ready action =%d ",pxSP->oAction);
#endif
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

#ifdef USE_MOC_COOKIE
extern sbyte4
IPSEC_permit(ubyte *pBuffer, ubyte2 wBufSize, ubyte2 *pwLength, ubyte2 *pwOffset, ubyte4 cookie)
{
    struct ipsecCtx ctx = { 0 };
    ctx.cookie = cookie;
    return IPSEC_permitEx(pBuffer, wBufSize, pwLength, pwOffset, &ctx);
}
#endif


extern sbyte4
IPSEC_permitEx(ubyte *pBuffer, ubyte2 wBufSize, ubyte2 *pwLength, ubyte2 *pwOffset, IPSECCTX ctx)
{
    MSTATUS status = OK;

    /* perform IPsec inbound processing */

    ubyte *poHdr;
#ifdef __ENABLE_DIGICERT_IPV6__
    ubyte *poNextHeader;
    struct ip6Hdr *pxHdr6 = NULL;
#endif
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
    ubyte oMode = 0;
    intBoolean bCE = FALSE;
    MOC_IP_ADDRESS_S dwTunlDestIP = MOC_IPADDR_NONE,
                     dwTunlSrcIP = MOC_IPADDR_NONE;
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
    ubyte4 adwSeql[IPSEC_NEST_MAX] = { 0 }; /* for anti-replay */
#ifdef __ENABLE_IPSEC_ESN__
    ubyte4 adwSeqh[IPSEC_NEST_MAX] = { 0 };
#endif
#endif
#ifdef __ENABLE_IPSEC_ESN__
    ubyte8 aSeqT[IPSEC_NEST_MAX] = { 0 }; /* for ESN */
#endif

#ifdef __ENABLE_DIGICERT_HARNESS__
    ubyte* poOrigBuf = NULL;
    ubyte* poAuthKey/*[IPSEC_AUTHKEY_MAX]*/ = NULL;
#endif
#if defined(__ENABLE_DIGICERT_HARNESS__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    ubyte* poDigest/*[IPSEC_DIGEST_MAX]*/ = NULL;
#endif

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    sbyte4 ifid = (NULL != ctx) ? ctx->ifid : 0;
#endif
#ifdef USE_MOC_COOKIE
    ubyte4 cookie = (NULL != ctx) ? ctx->cookie : 0;
#endif
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx;

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
    intBoolean bUseAsync = (NULL != ctx) && ctx->bAsyncEnabled;

    if (bUseAsync && (0 < (iNest = ctx->counter)))
    {
        /* async job finished, continue processing */
        ubyte2 wIPSecHdrLen = ctx->wIPsecHdrLen;
        SADB pxSa;
        SADB_cipherSuiteInfo* pCipherSuite;

        hwAccelCtx = ctx->hwAccelCtx;

#ifdef __ENABLE_DIGICERT_HARNESS__
        if (ctx->pBuffer)
        {
            poOrigBuf = pBuffer;
            pBuffer = ctx->pBuffer;
        }
#endif
        poHdr = pBuffer;
#ifdef __ENABLE_DIGICERT_IPV6__
        poNextHeader = ctx->poNextHeader;

        if (0x60 == (poHdr[0] & 0xF0))
            pxHdr6 = (struct ip6Hdr *)poHdr;
        else
#endif
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
            adwSeql[i] = ctx->adwSeql[i];
#ifdef __ENABLE_IPSEC_ESN__
            adwSeqh[i] = ctx->adwSeqh[i];
#endif
#endif
        }
        pxSa = axSaUsed[iNest-1];

#ifdef __ENABLE_DIGICERT_HARNESS__
        poAuthKey = ctx->poAuthKey;
#endif
        poDigest = ctx->poDigest;

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
        {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
            DB_PRINT("\n ipsec_permit fail2");
#endif
            EXIT_IPSEC
        }
        /* compare ICVs */
        if (0 != ctx->wIcvLen)
        {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
            DB_PRINT("\n ipsec_permit icv comparison");
#endif
            sbyte4 compareResult;
            if (OK > (status = DIGI_MEMCMP(poPayload + wPayloadLen,
                                          poDigest,
                                          ctx->wIcvLen,
                                          &compareResult)))
        {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
                DB_PRINT("\n ipsec_permit icv memcmp failed");
#endif
                EXIT_IPSEC
        }

            if (0 != compareResult)
            {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
                DB_PRINT("\n ipsec_permit icv memcmp failed drop auth fail");
#endif
        status = ERR_IPSEC_DROP_AUTH_FAIL;  /* esp auth. failed */
                EXIT_IPSEC
            }

            ctx->wIcvLen = 0;
        }

        /* decrypt */
        if (NULL == ctx->pCipherCtx)
        {
            if (NULL == (pCipherSuite = pxSa->pCipherSuite))
                goto next; /* auth only */

            /* decipher esp */
            if (OK > (status = DoAsyncCipher(hwAccelCtx, pxSa, ctx,
                                             pCipherSuite->pBEAlgo,
                                             poPayload + sizeof(struct espHdr), /* IV */
                                             poPayload + wIPSecHdrLen,
                                             wPayloadLen - wIPSecHdrLen,
                                             FALSE)))
        {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
                DB_PRINT("\n ipsec_permit esp cipher failed");
#endif
        EXIT_IPSEC
        }

            /* queue async job */
            if (pwLength) *pwLength = 0;
            return OK;
        }
        else /* done */
        {
            ctx->pCipherCtx = NULL;
        }
next:
        /* remove esp trailer */
        if (wPayloadLen < (wIPSecHdrLen + poPayload[wPayloadLen - 2] + 2))
        {
            status = ERR_IPSEC_BAD_ESP;
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
            DB_PRINT("\n ipsec_permit bad esp");
#endif
        EXIT_IPSEC
        }
        oProtocol = poPayload[wPayloadLen - 1];
        if (IPPROTO_NONE == oProtocol) /* dummy packet; ESP (v3) support of TFC, see RFC4303 2.6-7 */
        {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
            DB_PRINT("\n ipsec_permit dummy esp");
#endif
        status = STATUS_IPSEC_DUMMY;
            /*iNest++;*/ /* already incremented! */
            goto exit;
        }
        wLength -= poPayload[wPayloadLen - 2] + 2; /* remove padded octets from length calculation */
        wPayloadLen = wLength - wHdrLen;

        /* remove esp header */
        if (0 != wIPSecHdrLen)
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
#endif /* __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__ */

    if (OK > (status = IPSEC_getHwAccelChannel(&hwAccelCtx, TRUE)))
        goto nocleanup;
#endif

    poHdr = pBuffer;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
start:
#endif
    /* get ip packet info */
    if (1 > wBufSize)
    {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
        DB_PRINT("\n ipsec_permit bad ip");
#endif
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

#ifdef __ENABLE_DIGICERT_IPV6__
    case 0x60:
    {
        ubyte *poDestAddr = NULL;

        pxHdr6 = (struct ip6Hdr *)poHdr;
        if (OK > (status = GetPktInfo6(pxHdr6, wBufSize,
                                       &wLength, &wHdrLen,
                                       &poNextHeader, &poDestAddr,
                                       &bFragOff, &bMoreFrags, TRUE)))
            goto exit;

        oProtocol = *poNextHeader;

        SET_MOC_IPADDR6(dwSrcAddr,  pxHdr6->ip6_saddr);
        if (poDestAddr) {
            SET_MOC_IPADDR6(dwDestAddr, poDestAddr); }
        else {
            SET_MOC_IPADDR6(dwDestAddr, pxHdr6->ip6_daddr); }
        break;
    }
#endif
    default :
        status = ERR_IPSEC_BAD_IP;
        EXIT_IPSEC
        /*break;*/
    }
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
    DB_PRINT("\n ipsec_permit check tunnel dwSrcAddr=%x dwDestAddr=%x protocol=%d ",dwSrcAddr, dwDestAddr,oProtocol);
#endif
    poPayload   = poHdr + wHdrLen;
    wPayloadLen = wLength - wHdrLen;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    /* handle tunnelled IP packet */
    if (IPSEC_MODE_TUNNEL == oMode)
    {
        /* decrement TTL, if necessary */
        if (!SAME_MOC_IPADDR(REF_MOC_IPADDR(dwTunlDestIP), dwDestAddr)) /* forwarded */
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            if (pxHdr6)
            {
                /* Hop Limit must be 255 - Neighbor Discovery (RFC2461) */
                if (IPPROTO_ICMPV6 == oProtocol)
                {
                    GET_ULP_PORTS(poPayload, wPayloadLen, oProtocol, bFragOff,
                                  wDestPort, wSrcPort)

                    if (((ICMPV6_ND_ADV << 8) == wSrcPort) ||
                        ((ICMPV6_ND_SOL << 8) == wSrcPort))
                        goto end_ports;
                }

                if (0 != pxHdr6->ip6_hop_limit)
                    --pxHdr6->ip6_hop_limit;
            }
            else
#endif
            {
                if (0 == pxHdr->ip_ttl)
                {
                    status = ERR_IPSEC_DROP_TTL;
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
                DB_PRINT("\n ipsec_permit drop ttl");
#endif
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
        ubyte4 dwSeql;
#ifdef __ENABLE_IPSEC_ESN__
        ubyte4 dwSeqh = 0;
        ubyte2 wSeghLen = 0;
        ubyte temp[8];
#endif
        SADB_hmacSuiteInfo* pHmacSuite;
        SADB_cipherSuiteInfo* pCipherSuite;
        AeadAlgo* pAeadAlgo;
        ubyte2 wIcvLen, wIPSecHdrLen;

#if !defined(__ENABLE_DIGICERT_HARNESS__) && !defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
        ubyte poDigest[IPSEC_DIGEST_MAX];
#endif
#ifndef __ENABLE_DIGICERT_HARNESS__
        ubyte *poAuthKey = NULL;
#endif
        sbyte4 compareResult;

        /* get SPI */
        if (IPPROTO_AH == oProtocol)
        {
            if (wPayloadLen < sizeof(struct authHdr)/* 12 */)
            {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
                DB_PRINT("\n ipsec_permit bad ah");
#endif
        status = ERR_IPSEC_BAD_AH;
                EXIT_IPSEC
            }
            SET_NTOHL(dwSpi, ((struct authHdr *)poPayload)->dwSpi);
            SET_NTOHL(dwSeql, ((struct authHdr *)poPayload)->dwSeqNbr);
        }
        else
        {
            if (wPayloadLen < sizeof(struct espHdr)/* 8 */)
            {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
            DB_PRINT("\n ipsec_permit bad esp");
#endif
        status = ERR_IPSEC_BAD_ESP;
                EXIT_IPSEC
            }
            SET_NTOHL(dwSpi, ((struct espHdr *)poPayload)->dwSpi);
            SET_NTOHL(dwSeql, ((struct espHdr *)poPayload)->dwSeqNbr);
        }

#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
        DB_PRINT("\n ipsec_permit findsa ");
#endif
    /* find SA */
        if (OK > (status = IPSEC_findSa(dwSpi, REF_MOC_IPADDR(dwDestAddr),
                                        REF_MOC_IPADDR(dwSrcAddr),
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
                                        "",
#endif
                                        oProtocol,
                                        TRUE,
                                        &pxSa)))
        {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
            DB_PRINT("\n ipsec_permit findsa failed");
#endif
            /* SA already deleted */
#if defined(__ENABLE_DIGICERT_IKE_SERVER__) || defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
            if (NULL != pxSa) /* jic */
            {
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
                else
#endif
                {
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
                    if (IPSEC_SA_FLAG_GDOI & pxSa->saFlags)
                    {
                        /* Note: dwSaLastRekey is used as time of expiration
                           See IPSEC_expireSa() */
                        timenow = RTOS_deltaMS(&gStartTime, NULL);
                        if ((timenow - pxSa->dwSaLastRekey) < (ubyte4)60000) /* 1 min grace period */
                            status = OK;
                    }
#endif
                }
            }

            if (OK > status)
#endif
            {
                LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
            DB_PRINT("\n ipsec_permit permit fail ");
#endif
        goto exit;
            }
        }

        if (NULL == pxSa) /* no SA found */
        {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
        DB_PRINT("\n no pxSa obtained");
#endif
        if (0 < iNest)
            {
                /* drop packet */
                status = ERR_IPSEC_DROP_FINDSA_FAIL;
                LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
            DB_PRINT("\n ipsec_permit permit findsa fail ");
#endif
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

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) && defined(__ENABLE_DIGICERT_HARNESS__)
        if (!bUseAsync && /* jic */
            HARNESS_isAsyncModeEnabled(hwAccelCtx, NULL))
        {
            status = ERR_HARDWARE_ACCEL_NO_MEMORY;
            goto exit;
        }
#endif

        /* match source IP address */
        if (!ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr) &&
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
            (((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) && CheckIpRange(REF_MOC_IPADDR(pxSa->dwSaDestIP),
                            REF_MOC_IPADDR(pxSa->dwSaDestIPEnd), /* as in case of unicats src and dest will be part of same unicast range*/
                            dwSrcAddr,0)) || ((pxSa->dwSaDestIPEnd && (pxSa->dwSaDestIP != pxSa->dwSaDestIPEnd)) ||
                            ((pxSa->fqdn == 0) && !SAME_MOC_IPADDR(REF_MOC_IPADDR(dwSrcAddr), pxSa->dwSaSrcAddr)))||
                            (pxSa->fqdn && pxSa->dwSaSrcIPCount && (checkIpinList(dwSrcAddr, pxSa->dwSaSrcIPList, pxSa->dwSaSrcIPCount)))))
#else
            !SAME_MOC_IPADDR(REF_MOC_IPADDR(dwSrcAddr), pxSa->dwSaSrcAddr))
#endif
#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && !defined(__DISABLE_IPSEC_TUNNEL_MODE__)
        if ((NULL == pxSa->pxSp) ||
            (IPSEC_MODE_TUNNEL != pxSa->oSaMode)) /* !!! */
#endif
        {
            /* Note: SPD/SADB may be out of sync due to Mobility migration
               or new NAT-T mapping. */
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
            DB_PRINT("\n ipsec_permit bad src addr");
#endif
        status = ERR_IPSEC_DROP_BAD_SRC_ADDR;
            LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
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
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
                    DB_PRINT("\n ipsec_permit bad udp encr");
#endif
                    status = ERR_IPSEC_DROP_BAD_UDPENC_PORT;
                    LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                    EXIT_IPSEC
                }
            }
            else
#endif
            if (0 != pxSa->wSaUdpEncPort)
            {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
                DB_PRINT("\n ipsec_permit bad udp encr2");
#endif
                status = ERR_IPSEC_DROP_BAD_UDPENC_PORT;
                /* LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa) */
                EXIT_IPSEC
            }
        }
#endif /* __ENABLE_IPSEC_NAT_T__ */

        if (bMoreFrags) /* fragmented esp/ah */
        {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
            DB_PRINT("\n ipsec_permit bad fragmentation");
#endif
            status = ERR_IPSEC_FRAGMENTATION;
            EXIT_IPSEC
        }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (0 == oMode)
        {
            oMode = pxSa->oSaMode;
        }
        else if (0 != pxSa->oSaMode)
        {
            if (oMode != pxSa->oSaMode)
            {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
                DB_PRINT("\n ipsec_permit bad mode");
#endif
        status = ERR_IPSEC_DROP_BAD_MODE;
                LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
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

        pCipherSuite = pxSa->pCipherSuite;
        pAeadAlgo = pCipherSuite ? pCipherSuite->pAeadAlgo : NULL;
        pHmacSuite = pxSa->pHmacSuite;
        wIcvLen = pHmacSuite ? pHmacSuite->wIcvLen : 0;

        /* allocate transient storage */
#if defined(__ENABLE_DIGICERT_HARNESS__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
        while (0 == iNest)
        {
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
            if (bUseAsync)
            {
                poDigest = ctx->poDigest;
#ifdef __ENABLE_DIGICERT_HARNESS__
                poAuthKey = ctx->poAuthKey;

                if (!ctx->bCryptoAlloc) break;

                if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, wLength, TRUE,
                                                (void**) &ctx->pBuffer)))
                    EXIT_IPSEC

                poOrigBuf = pBuffer;
                pBuffer = ctx->pBuffer;
            }
            else
#else
            }
#endif
#endif /* __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__ */

#ifdef __ENABLE_DIGICERT_HARNESS__
            {
                poOrigBuf = pBuffer;
                pBuffer = NULL; /* jic */
                if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, wLength +
                                        IPSEC_DIGEST_MAX + IPSEC_AUTHKEY_MAX,
                                        TRUE, (void**) &pBuffer)))
                    EXIT_IPSEC

                poDigest = pBuffer + wLength;
                poAuthKey = poDigest + IPSEC_DIGEST_MAX;
            }

            /*DIGI_MEMCPY(pBuffer, poOrigBuf, wLength);*/
            DIGI_MEMCPY(pBuffer, poHdr, wHdrLen);
            DIGI_MEMCPY(pBuffer + wHdrLen, poPayload, wPayloadLen);

#ifdef __ENABLE_DIGICERT_IPV6__
            if (pxHdr6)
            {
                poNextHeader = pBuffer + (poNextHeader - poHdr);
                pxHdr6 = (struct ip6Hdr *)pBuffer;
            }
            else
#endif
            pxHdr = (struct ipHdr *)pBuffer;
            poPayload = pBuffer + wHdrLen;
            poHdr = pBuffer;
#endif /* __ENABLE_DIGICERT_HARNESS__ */

            break;
        } /* while (0 == iNest) */
#endif /* defined(__ENABLE_DIGICERT_HARNESS__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) */

        if (NULL != pHmacSuite)
        {
#ifdef __ENABLE_DIGICERT_HARNESS__
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
            if (bUseAsync && !ctx->bCryptoAlloc)
                poAuthKey = pxSa->poAuthKey;
            else
#endif
            DIGI_MEMCPY(poAuthKey, pxSa->poAuthKey, pHmacSuite->wKeyLen);
#else
            poAuthKey = pxSa->poAuthKey;
#endif
        }

#ifdef __ENABLE_IPSEC_ESN__
        /* track ESNs */
        if (IPSEC_SA_FLAG_ESN & pxSa->saFlags)
        {
            ubyte8 seqT = ATOMIC_GET(pxSa->u.i.seqT);
            ubyte4 dwSeqTl = LOW_U8(seqT);
            dwSeqh = HI_U8(seqT);

            if (dwSeql > dwSeqTl)
            {
                if ((0 == dwSeqh) ||
                    ((dwSeql - dwSeqTl) < (ubyte4)0x80000000))
                {
                    U8INIT(aSeqT[iNest], dwSeqh, dwSeql);
                }
                else
                {
                    dwSeqh--;
                }
            }
            else if ((0 != (dwSeqh + 1)) &&
                     ((dwSeqTl - dwSeql) > (ubyte4)0x80000000))
            {
                ++dwSeqh;
                U8INIT(aSeqT[iNest], dwSeqh, dwSeql);
            }
            else if ((0 == dwSeql) && (0 == dwSeqh))
            {
                status = ERR_IPSEC_DROP_BAD_SEQ;
                LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                EXIT_IPSEC
            }
        }
#endif /* __ENABLE_IPSEC_ESN__ */

#if defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
        /* check replay */
        while (pxSa->pxSp) /* auto. keyed */
        {
            /* anti-replay may be selected only if auth. is enabled */
            if ((IPPROTO_ESP == oProtocol) &&
                (NULL == pAeadAlgo) &&
                (NULL == pHmacSuite))
            {
                sbyte4 j;
                for (j = iNest - 1; j >= 0; j--)
                {
                    SADB pxSaTmp = axSaUsed[j];
                    if (NULL != pxSaTmp->pHmacSuite)
                        break;

                    if ((NULL != pxSaTmp->pCipherSuite) &&
                        (NULL != pxSaTmp->pCipherSuite->pAeadAlgo))
                        break;
                }
                if (0 > j) break;
            }

            /* auth. exists, check replay window */
            if (0 == dwSeql)
#ifdef __ENABLE_IPSEC_ESN__
            if (0 == dwSeqh)
#endif
            {
                status = ERR_IPSEC_DROP_BAD_SEQ;
                LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                EXIT_IPSEC
            }

            if (OK != (status = AntiReplay(dwSeql,
#ifdef __ENABLE_IPSEC_ESN__
                                           dwSeqh,
#endif
                                           pxSa, TRUE)))
            {
                LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                goto exit;
            }

            adwSeql[iNest] = dwSeql;
#ifdef __ENABLE_IPSEC_ESN__
            adwSeqh[iNest] = dwSeqh;
#endif
            break;
        }
#endif /* IPSEC_REPLAY_SIZE */

        /* process AH */
        if (IPPROTO_AH == oProtocol)
        {
            ubyte oTos, oTtl;
            ubyte2 wFragOff;
#ifdef __ENABLE_DIGICERT_IPV6__
            ubyte4 vtf;
#endif
            ubyte poIcv[IPSEC_ICV_MAX];

            struct authHdr *pxAh = (struct authHdr *)poPayload;

            /* check ICV algorithm */
            if (NULL == pHmacSuite) /* jic */
            {
                status = ERR_IPSEC_NULL_AUTH;
                LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                EXIT_IPSEC
            }

            /* get ah header length */
            wIPSecHdrLen = ((pxAh->oPayloadLen + 2) << 2);
            if ((wPayloadLen < wIPSecHdrLen) ||
                (sizeof(struct authHdr) > wIPSecHdrLen))
            {
                status = ERR_IPSEC_BAD_AH;
                LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                EXIT_IPSEC
            }

            /* check ICV length */
            if (wIcvLen > (wIPSecHdrLen - sizeof(struct authHdr)))
            {
                /* inconsistent w/ SA */
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
                DB_PRINT("\n ipsec_permit bad icv");
#endif
                status = ERR_IPSEC_DROP_BAD_ICV;
                LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                EXIT_IPSEC
            }

            /* save mutable fields and prepare data */
            /* assume dest addr field is already filled with predicted value */
#ifdef __ENABLE_DIGICERT_IPV6__
            if (pxHdr6)
            {
                SET_NTOHL(vtf,   pxHdr6->ip6_vtf);
                          oTtl = pxHdr6->ip6_hop_limit;

                SET_HTONL(pxHdr6->ip6_vtf,        0x60000000);
                          pxHdr6->ip6_hop_limit = 0;
            }
            else
#endif
            {
                          oTos    = pxHdr->ip_tos;
                          oTtl    = pxHdr->ip_ttl;
                SET_NTOHS(wFragOff, pxHdr->ip_off);

                /* temporaly fill with 0 for ICV calculation */
                          pxHdr->ip_tos = 0;
                          pxHdr->ip_ttl = 0;
                SET_HTONS(pxHdr->ip_off,  0);
                SET_HTONS(pxHdr->ip_sum,  0);
            }

            /* store received ICV to temporary location before calculating new ICV */
            DIGI_MEMCPY(poIcv, poPayload + sizeof(struct authHdr), wIcvLen);
            DIGI_MEMSET(poPayload + sizeof(struct authHdr), 0x00, wIcvLen);

            /* calculate ICV */
#ifdef __ENABLE_IPSEC_ESN__
            if (IPSEC_SA_FLAG_ESN & pxSa->saFlags)
            {
                DIGI_HTONL(poHdr + wLength, dwSeqh); /* !!! */
                wSeghLen = 4;
            }
#endif
            if (OK != (status = pHmacSuite->hmacFunc(MOC_HASH(hwAccelCtx)
                                                     poAuthKey,
                                                     pHmacSuite->wKeyLen,
                                                     poHdr, wLength
#ifdef __ENABLE_IPSEC_ESN__
                                                            + wSeghLen
#endif
                                                                   ,
                                                     poDigest)))
            {
                LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                EXIT_IPSEC
            }

            /* compare ICVs */
            if (OK > (status = DIGI_MEMCMP(poIcv, poDigest, wIcvLen, &compareResult)))
            {
                /* LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa) */
                EXIT_IPSEC
            }

            if (0 != compareResult)
            {
                status = ERR_IPSEC_DROP_AUTH_FAIL;  /* authentication failed */
                LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                EXIT_IPSEC
            }

            oProtocol = pxAh->oNextHeader; /* !!! */

#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
        DB_PRINT("\n protocol extracted from ah=%d ", oProtocol);
#endif
        /* restore ip header fields */
#ifdef __ENABLE_DIGICERT_IPV6__
            if (pxHdr6)
            {
                SET_HTONL(pxHdr6->ip6_vtf,        vtf);
                          pxHdr6->ip6_hop_limit = oTtl;
            }
            else
#endif
            {
                          pxHdr->ip_tos = oTos;
                          pxHdr->ip_ttl = oTtl;
                SET_HTONS(pxHdr->ip_off,  wFragOff);
            }
        }

        /* process ESP */
        else/* if (IPPROTO_ESP == oProtocol)*/
        {
            ubyte2 wIvLen=0;
            ubyte oSaltLen=0, oTagLen=0;

            /* get esp header length */
            wIPSecHdrLen = sizeof(struct espHdr);

            if (NULL != pCipherSuite)
            {
                wIvLen = pCipherSuite->wIvLen;
                wIPSecHdrLen += wIvLen;
                if (NULL != pAeadAlgo)
                {
                    oSaltLen = (ubyte) pAeadAlgo->implicitNonceSize;
                    oTagLen = (ubyte) pAeadAlgo->tagSize;
                }
            }

            if (wPayloadLen < (wIPSecHdrLen + wIcvLen + 2
                                                      + oTagLen
                                ))
            {
                /* Note: 2 bytes for ESP trailer (pad length and next header) */
                status = ERR_IPSEC_BAD_ESP;
                LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                EXIT_IPSEC
            }

            /* exclude esp auth trailing icv from total length */
            wLength -= wIcvLen;
            wPayloadLen -= wIcvLen;

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
            if (bUseAsync)
            {
                ctx->poPayload = poPayload;

                ctx->counter = iNest + 1;
                ctx->wIpHdrLen = wHdrLen;
                ctx->wLength = wLength;
                ctx->wIcvLen = wIcvLen;
#ifdef __ENABLE_DIGICERT_IPV6__
                ctx->poNextHeader = poNextHeader;
#endif
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
                ctx->adwSeql[iNest] = adwSeql[iNest];
#ifdef __ENABLE_IPSEC_ESN__
                ctx->adwSeqh[iNest] = adwSeqh[iNest];
#endif
#endif
            }
#endif /* __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__ */

            /* process esp authentification */
            if (NULL != pHmacSuite)
            {
#if defined(__HW_OFFLOAD_SINGLE_PASS_SUPPORT__) && defined(__IPSEC_SINGLE_PASS_SUPPORT__)
                /* authenticate and decrypt in a single pass */
                if (NULL != pCipherSuite)
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

                    if (NO_SINGLE_PASS != singlePassCookie)
                    {
                        BulkCtx pCipherCtx;

                        DIGI_MEMCPY(poDigest, poPayload + wPayloadLen, wIcvLen);
                        /*DIGI_MEMSET(poPayload + wPayloadLen, 0x00, wIcvLen);*/ /* testing only */

#if !defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
                        if (NULL == (pCipherCtx = pCipherSuite->pBEAlgo->createFunc(
                                                            MOC_SYM(hwAccelCtx)
                                                            pxSa->poEncrKey,
                                                            pxSa->wEncrKeyLen,
                                                            FALSE)))
                        {
                            status = ERR_HARDWARE_ACCEL_NO_MEMORY;
                            EXIT_IPSEC
                        }
#else
                        DOWN_SA_LOCK(pxSa)
                        pCipherCtx = pxSa->pCipherCtx;
                        if (NULL == pCipherCtx) /* jic */
                            status = ERR_IPSEC_DROP_FINDSA_FAIL;
                        else
                        pxSa->users++;
                        UP_SA_LOCK(pxSa)

                        if (OK > status) EXIT_IPSEC

                        if (bUseAsync)
                        {
                            ctx->pCipherCtx = pCipherCtx;
                        }
#ifdef __ENABLE_DIGICERT_HARNESS__
                        LOCK_HARNESS(hwAccelCtx, FALSE)
                        HARNESS_assignAsyncCtx(hwAccelCtx, ctx);
#endif
#endif
                        status = HWOFFLOAD_doSinglePassDecryption(MOC_SYM(hwAccelCtx)
                                                    MOCANA_IPSEC,
                                                    singlePassCookie, 0,
                                                    pCipherCtx,
                                                    poAuthKey,
                                                    pHmacSuite->wKeyLen,
                                                    poPayload, wPayloadLen,             /* hmac data */
                                                    poPayload + wIPSecHdrLen,           /* crypto data */
                                                    wPayloadLen - wIPSecHdrLen,
                                                    NULL,                    /* crypto out pointer (new) */
                                                    poPayload + sizeof(struct espHdr), /* IV */
                                                    pCipherSuite->wIvLen,
                                                    poPayload + wPayloadLen, /* ICV - to be verified or modified */
                                                    wIcvLen, &compareResult);

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
#ifdef __ENABLE_DIGICERT_HARNESS__
                        HARNESS_assignAsyncCtx(hwAccelCtx, NULL);
                        UNLOCK_HARNESS(hwAccelCtx, FALSE)
#endif
                        if (bUseAsync)
                        {
                            if (OK > status)
                            {
                                ctx->pCipherCtx = NULL;
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
#else
                        pCipherSuite->pBEAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &pCipherCtx);
#endif

                        if (OK > status)
                        {
                            if (ERR_HARDWARE_ACCEL_SINGLE_PASS_LOOKUP_FAIL != status)
                                EXIT_IPSEC
                        }
                        else
                        {
                            if (compareResult) wIcvLen = 0; /* verified */
                            pHmacSuite = NULL;
                            pCipherSuite = NULL;
                        }
                    }
                }
                if (NULL != pHmacSuite)
#endif /* SINGLE_PASS */

                /* calculate ICV for esp payload except auth field */
                {
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
                    if (bUseAsync)
                    {
                        if (OK > (status = DoAsyncHmac(hwAccelCtx, ctx,
                                                       poAuthKey,
                                                       pHmacSuite,
                                                       poPayload, wPayloadLen,
                                                       poDigest,
                                                       FALSE)))
                            EXIT_IPSEC

                        /* queue async job */
                        if (pwLength) *pwLength = 0;
                        return OK;
                    }
#endif
#ifdef __ENABLE_IPSEC_ESN__
                    if (IPSEC_SA_FLAG_ESN & pxSa->saFlags)
                    {
                        DIGI_MEMCPY(temp, poPayload + wPayloadLen, 4);
                        DIGI_HTONL(poPayload + wPayloadLen, dwSeqh);
                        wSeghLen = 4;
                    }
#endif
                    if (OK != (status = pHmacSuite->hmacFunc(MOC_HASH(hwAccelCtx)
                                                             poAuthKey,
                                                             pHmacSuite->wKeyLen,
                                                             poPayload, wPayloadLen
#ifdef __ENABLE_IPSEC_ESN__
                                                                        + wSeghLen
#endif
                                                                                   ,
                                                             poDigest)))
                    {
                        LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                        EXIT_IPSEC
                    }

#ifdef __ENABLE_IPSEC_ESN__
                    if (wSeghLen)
                    {
                        DIGI_MEMCPY(poPayload + wPayloadLen, temp, 4);
                        wSeghLen = 0; /* jic */
                    }
#endif
                }

                /* compare ICVs */
                if (0 != wIcvLen)
                {
                    if (OK > (status = DIGI_MEMCMP(poPayload + wPayloadLen,
                                                  poDigest, wIcvLen, &compareResult)))
                    {
                        /* LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa) */
                        EXIT_IPSEC
                    }

                    if (0 != compareResult)
                    {
                        status = ERR_IPSEC_DROP_AUTH_FAIL;  /* esp auth. failed */
                        LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                        EXIT_IPSEC
                    }
                }
            } /* if (NULL != pHmacSuite) */

            /* decipher esp */
            if (NULL != pCipherSuite)
            {
                if (NULL != pCipherSuite->pBEAlgo)
                {
                    /* the length of encrypted data should be multiple of block length */
                    if ((wPayloadLen - wIPSecHdrLen) % pCipherSuite->pBEAlgo->blockSize)
                    {
                        status = ERR_IPSEC_DROP_BAD_BLOCK;
                        LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                        EXIT_IPSEC
                    }

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
                    if (bUseAsync)
                    {
                        if (OK > (status = DoAsyncCipher(hwAccelCtx, pxSa, ctx,
                                                         pCipherSuite->pBEAlgo,
                                                         poPayload + sizeof(struct espHdr), /* IV */
                                                         poPayload + wIPSecHdrLen,
                                                         wPayloadLen - wIPSecHdrLen,
                                                         FALSE)))
                            EXIT_IPSEC

                        /* queue async job */
                        if (pwLength) *pwLength = 0;
                        return OK;
                    }
#endif
                }

                if (NULL != pAeadAlgo)
                {
                    ubyte poIv[IPSEC_IV_MAX]; /* for now */
                    BulkCtx aead_ctx = NULL;
#ifdef __ENABLE_IPSEC_ESN__
                    if (IPSEC_SA_FLAG_ESN & pxSa->saFlags)
                    {
                        DIGI_MEMCPY(temp, poPayload-4, 8);
                        DIGI_MEMCPY(poPayload-4, poPayload, 4);
                        DIGI_HTONL(poPayload, dwSeqh);

                        wIPSecHdrLen += (ubyte2)4;
                        wPayloadLen += (ubyte2)4;
                        poPayload -= 4;
                        wSeghLen = 4;
                    }
#endif
#ifndef __ENABLE_IPSEC_LOCKLESS_CRYPTO__
                    DOWN_SA_LOCK(pxSa)
                    aead_ctx = pxSa->pCipherCtx;
#else
                    if(pAeadAlgo->cloneFunc)
                    {
                        status = pAeadAlgo->cloneFunc(MOC_SYM(hwAccelCtx)
                                                     pxSa->pCipherCtx,
                                                     &aead_ctx);
                    }
                    else
                    {
                        status = ERR_NULL_POINTER;
                    }
                    if ((OK > status) || (NULL == aead_ctx))
                    {
                        LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                        EXIT_IPSEC
                    }
#endif
                    /* construct nonce (i.e. salt + iv) */
                    DIGI_MEMCPY(poIv, pxSa->poEncrKey + (pxSa->wEncrKeyLen - oSaltLen), oSaltLen);
                    DIGI_MEMCPY(poIv + oSaltLen, poPayload + sizeof(struct espHdr)
#ifdef __ENABLE_IPSEC_ESN__
                                                            + wSeghLen
#endif
                                                                                 , wIvLen);

                    if (pCipherSuite->bAeadNull)
                        status = pAeadAlgo->cipherFunc(MOC_SYM(hwAccelCtx)
                                                   aead_ctx,
                                                   poIv, oSaltLen + wIvLen,     /* Nonce */
                                                   poPayload,                   /* AAD */
                                                   wPayloadLen - oTagLen,
                                                   poPayload + (wPayloadLen - oTagLen), /* ciphertext (empty) */
                                                   0,
                                                   oTagLen,                     /* ICV */
                                                   FALSE);
                    else
                        status = pAeadAlgo->cipherFunc(MOC_SYM(hwAccelCtx)
                                                   aead_ctx,
                                                   poIv, oSaltLen + wIvLen,     /* Nonce */
                                                   poPayload,                   /* AAD */
                                                   sizeof(struct espHdr)  /*wIPSecHdrLen - wIvLen,*/
#ifdef __ENABLE_IPSEC_ESN__
                                                       + wSeghLen
#endif
                                                                        ,
                                                   poPayload + wIPSecHdrLen,    /* ciphertext */
                                                   wPayloadLen - (wIPSecHdrLen + oTagLen),
                                                   oTagLen,                     /* ICV */
                                                   FALSE);
#ifndef __ENABLE_IPSEC_LOCKLESS_CRYPTO__
                    UP_SA_LOCK(pxSa)
#else
                    pAeadAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &aead_ctx);
#endif
#ifdef __ENABLE_IPSEC_ESN__
                    if (wSeghLen)
                    {
                        DIGI_MEMCPY(poPayload, temp, 8);
                        wIPSecHdrLen -= (ubyte2)4;
                        wPayloadLen -= (ubyte2)4;
                        poPayload += 4;
                    }
#endif
                    if (OK > status)
                    {
                        LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                        EXIT_IPSEC
                    }

                    wPayloadLen -= oTagLen;
                    wLength -= oTagLen;
                }
                else
                {
                    BulkCtx bctx = NULL;
                    BulkCtx cipher_ctx = NULL;
                    bctx = pxSa->pCipherCtxM ? pxSa->pCipherCtxM : pxSa->pCipherCtx;
#if 1
#ifndef __ENABLE_IPSEC_LOCKLESS_CRYPTO__
                    DOWN_SA_LOCK(pxSa)
                    cipher_ctx = bctx;
#else
                    byteBoolean bDelCtx = FALSE;
                    if(pCipherSuite->pBEAlgo->cloneFunc)
                    {
                        status = pCipherSuite->pBEAlgo->cloneFunc(MOC_SYM(hwAccelCtx)
                                                         bctx,
                                                         &cipher_ctx);
                        if ((OK > status) || (NULL == cipher_ctx))
                        {
                            LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                            EXIT_IPSEC
                        }
                        bDelCtx = TRUE;
                    }
                    else
                    {
                         cipher_ctx = bctx;
                    }
#endif

                    status = pCipherSuite->pBEAlgo->cipherFunc(
                                                   MOC_SYM(hwAccelCtx)
                                                   cipher_ctx,
                                                   poPayload + wIPSecHdrLen,
                                                   wPayloadLen - wIPSecHdrLen,
                                                   FALSE,
                                                   poPayload + sizeof(struct espHdr) /* IV */);
#ifndef __ENABLE_IPSEC_LOCKLESS_CRYPTO__
                    UP_SA_LOCK(pxSa)
#else
                    if(TRUE == bDelCtx)
                    {
                        pCipherSuite->pBEAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &cipher_ctx);
                    }
#endif
#else
                    status = CRYPTO_Process(MOC_SYM(hwAccelCtx)
                                                   pCipherSuite->pBEAlgo,
                                                   pxSa->poEncrKey,
                                                   pxSa->wEncrKeyLen,
                                                   poPayload + sizeof(struct espHdr), /* IV */
                                                   poPayload + wIPSecHdrLen,
                                                   wPayloadLen - wIPSecHdrLen,
                                                   FALSE);
#endif
                    if (OK > status)
                    {
                        LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                        EXIT_IPSEC
                    }
                }
            } /* if (NULL != pCipherSuite) */

            /* remove esp trailer */
            if (wPayloadLen < (wIPSecHdrLen + poPayload[wPayloadLen - 2] + 2))
            {
                status = ERR_IPSEC_BAD_ESP;
                LOG_IPSEC_PERMIT_FAIL(status, oProtocol, dwSpi, pxSa)
                EXIT_IPSEC
            }

            oProtocol = poPayload[wPayloadLen - 1];

            if (IPPROTO_NONE == oProtocol) /* dummy packet; ESP (v3) support of TFC, see RFC4303 2.6-7 */
            {
                status = STATUS_IPSEC_DUMMY;
                goto exit;
            }
            wLength -= poPayload[wPayloadLen - 2] + 2; /* remove padded octets from length calculation */
            wPayloadLen = wLength - wHdrLen;
        } /* process ESP */

        /* remove ah/esp header */
        wLength -= wIPSecHdrLen;
        wPayloadLen -= wIPSecHdrLen;

        if (pwOffset)
            poPayload += wIPSecHdrLen;
        else
            DIGI_MEMMOVE(poPayload, poPayload + wIPSecHdrLen, wPayloadLen);

    } /* for (iNest=0; */

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    /* tunnelled inner IP packet? */
    if ((IPSEC_MODE_TRANSPORT != oMode) &&
        ((IPPROTO_IPIP == oProtocol)
#ifdef __ENABLE_DIGICERT_IPV6__
         || (IPPROTO_IPV6 == oProtocol)
#endif
         ))
    {
#ifndef __ENABLE_IPSEC_NULL_TUNNEL__
        if (0 == iNest) /* no transform has been performed */
            goto end;
#endif
        if (0 == oMode) /* FOR NOW */
            oMode = IPSEC_MODE_TUNNEL;

        /* remember tunnel IP header */
        dwTunlSrcIP = dwSrcAddr;
        dwTunlDestIP = dwDestAddr;

#ifdef __ENABLE_DIGICERT_IPV6__
        if (pxHdr6)
        {
            if (IP6_CE == (IP6_ECN & GET_NTOHL(pxHdr6->ip6_vtf)))
                bCE = TRUE;

            pxHdr6 = NULL;
        }
        else
#endif
        {
            if (IP_CE == (IP_ECN & pxHdr->ip_tos))
                bCE = TRUE;

            pxHdr = NULL;
        }

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
    }
#endif /* __DISABLE_IPSEC_TUNNEL_MODE__ */

    if (0 < iNest)
    {
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (0 == oMode)
            oMode = IPSEC_MODE_TRANSPORT;
#endif
        /* update ip header fields */
#ifdef __ENABLE_DIGICERT_IPV6__
        if (pxHdr6)
        {
            SET_HTONS(pxHdr6->ip6_payload_len, wLength - SIZEOF_IP6_HDR);
            *poNextHeader = oProtocol;
        }
        else
#endif
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

#if !defined(__DISABLE_IPSEC_TUNNEL_MODE__) && defined(__ENABLE_DIGICERT_IPV6__)
end_ports:
#endif

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
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
            if (pxSP && pxSP->ifid && (ifid != pxSP->ifid))
                pxSP = NULL;
            else
#endif
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
#ifdef USE_MOC_COOKIE
        /* developer customized cookie */                        ||
            ((0 != pxSa->cookie) && (cookie != pxSa->cookie))
#endif
            )
        {
            status = ERR_IPSEC_MISMATCH_FLOW;
            LOG_IPSEC_PERMIT_FAIL(status, pxSa->oSaProto, pxSa->dwSaSpi, pxSa)
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
#ifdef __ENABLE_IPSEC_NULL_TUNNEL__
                || (IPSEC_MODE_TUNNEL == oMode)
#endif
                )
            {
                /* LOG_IPSEC_PERMIT_FAIL */
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
            if(!pxSP && ((IPPROTO_AH == oProtocol) || (IPPROTO_ESP == oProtocol)))
            {
                status = ERR_IPSEC_DROP;
            }

            goto exit;
        } /* if (STATUS_IPSEC_BYPASS == status) */

        /* LOG_IPSEC_PERMIT_FAIL */
        EXIT_IPSEC
    }

    if (iNest != pxSP->oSaLen)
    {
        /* Bypass ICMPv6 Neighbor Discovery (RFC2461) msg, if applicable. */
#ifdef __ENABLE_DIGICERT_IPV6__
        if (!iNest && pxHdr6 && pxSP &&
            (IPPROTO_ICMPV6 == oProtocol))
        {
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            if ((IPSEC_MODE_TUNNEL != pxSP->oMode) ||
                ((ISZERO_MOC_IPADDR(pxSP->dwTunlSrcIP) ||
                  SAME_MOC_IPADDR(REF_MOC_IPADDR(dwSrcAddr), pxSP->dwTunlSrcIP)) &&
                 (ISZERO_MOC_IPADDR(pxSP->dwTunlDestIP) ||
                  SAME_MOC_IPADDR(REF_MOC_IPADDR(dwDestAddr), pxSP->dwTunlDestIP))))
#endif
            if (((ICMPV6_ND_SOL << 8) == wSrcPort) ||
                ((ICMPV6_ND_ADV << 8) == wSrcPort))
            {
                status = STATUS_IPSEC_BYPASS; /* !!! */
                EXIT_IPSEC
            }
        }
#endif
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

        /* LOG_IPSEC_PERMIT_FAIL */
        EXIT_IPSEC
    }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    /* match SP mode */
    if ((0 != pxSP->oMode) && (oMode != pxSP->oMode))
    {
        status = ERR_IPSEC_MISMATCH_MODE;
        /* LOG_IPSEC_PERMIT_FAIL */
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
                LOG_IPSEC_PERMIT_FAIL(status, pxSa->oSaProto, pxSa->dwSaSpi, pxSa)
                EXIT_IPSEC
            }
#endif
        }

        /* check crypto algos */
        if (!IPSEC_matchSp(NULL, pxSa, pxSP, i))
        {
            status = ERR_IPSEC_MISMATCH_SAINFO; /* mismatch */
            LOG_IPSEC_PERMIT_FAIL(status, pxSa->oSaProto, pxSa->dwSaSpi, pxSa)
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

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    /* copy ECN field (i.e. CE) */
    if (bCE && (IPSEC_SP_FLAG_ECN & pxSP->flags))
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        if (pxHdr6)
        {
            ubyte4 vtf = GET_NTOHL(pxHdr6->ip6_vtf);
            switch (IP6_ECN & vtf)
            {
            case IP6_ECT_0 : /* ECT(0) */
            case IP6_ECT_1 : /* ECT(1) */
                vtf &= ~(IP6_ECN);
                SET_HTONL(pxHdr6->ip6_vtf, (IP6_CE | vtf));
                break;
            }
        }
        else
#endif
        {
            switch (IP_ECN & pxHdr->ip_tos)
            {
            case IP_ECT_0 : /* ECT(0) */
            case IP_ECT_1 : /* ECT(1) */
                pxHdr->ip_tos &= ~(IP_ECN);
                pxHdr->ip_tos |= IP_CE;
                SET_IPHDR_CSUM(pxHdr->ip_sum, poHdr, wHdrLen)
                break;
            }
        }
    }
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
#ifdef __ENABLE_DIGICERT_IPV6__
            if (pxHdr6)
                SetUdp6Checksum(poPayload,
                                RET_MOC_IPADDR6(dwSrcAddr),
                                RET_MOC_IPADDR6(dwDestAddr));
            else
#endif
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
#ifdef __ENABLE_DIGICERT_IPV6__
            if (pxHdr6)
                SetTcp6Checksum(poPayload,
                                RET_MOC_IPADDR6(dwSrcAddr),
                                RET_MOC_IPADDR6(dwDestAddr),
                                wPayloadLen);
            else
#endif
            SetTcpChecksum(poPayload,
                           RET_MOC_IPADDR4(dwSrcAddr),
                           RET_MOC_IPADDR4(dwDestAddr),
                           wPayloadLen);
        }
#ifdef __ENABLE_DIGICERT_IPV6__
        else if ((IPPROTO_ICMPV6 == oProtocol) && pxHdr6)
        {
            if (wPayloadLen < sizeof(struct icmp6Hdr)) /* jic */
            {
                status = ERR_IPSEC_BAD_ULP;
                EXIT_IPSEC
            }
            SetIcmp6Checksum(poPayload,
                             RET_MOC_IPADDR6(dwSrcAddr),
                             RET_MOC_IPADDR6(dwDestAddr),
                             wPayloadLen);
        }
#endif
    }
#endif /* __ENABLE_IPSEC_NAT_T__ */

#if defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
    /* update replay window */
    for (i=0; i < iNest; i++)
    {
        if (adwSeql[i]
#ifdef __ENABLE_IPSEC_ESN__
         || adwSeqh[i]
#endif
            )
        {
            if (OK != (status = AntiReplay(adwSeql[i],
#ifdef __ENABLE_IPSEC_ESN__
                                           adwSeqh[i],
#endif
                                           axSaUsed[i], FALSE)))
                goto exit;
        }
    }
#endif
#ifdef __ENABLE_IPSEC_ESN__
    for (i=0; i < iNest; i++)
    {
        if (!ISZERO_U8(aSeqT[i]))
        {
            ATOMIC_SET(axSaUsed[i]->u.i.seqT, aSeqT[i]);
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

#ifndef __DISABLE_IPSEC_KBYTES__
        {
        ubyte2 wNewBytes = pxSa->wSaCurBytes + wLength;
        if (1024 <= wNewBytes)
        {
            ubyte4 dwSaCurKBytes = pxSa->dwSaCurKBytes;
            ubyte4 dwNewKBytes = dwSaCurKBytes + (ubyte4)(wNewBytes / 1024);
            wNewBytes = wNewBytes % 1024;

             /* jic KBytes wraps back to 0 */
            if (pxSa->dwSaExpKBytes && (dwSaCurKBytes > dwNewKBytes))
            {
                wNewBytes += (ubyte2)((dwNewKBytes + 1) * 1024);
                dwNewKBytes = ~((ubyte4)0);
            }
            pxSa->dwSaCurKBytes = dwNewKBytes;
        }
        pxSa->wSaCurBytes = wNewBytes;
        }
#endif
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

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
                IKE_keyInfoEx(pxSa,
#ifdef __ENABLE_IPSEC_NAT_T__
                              0,/*pxSa->wSaUdpEncPort,*/
#endif
                              dwSaSpi, IKE_KEY_TYPE_CONNECTED);
#else
                IKE_keyInform(REF_MOC_IPADDR(pxSa->dwSaDestAddr),
                              REF_MOC_IPADDR(pxSa->dwSaSrcAddr),
#ifdef __ENABLE_IPSEC_NAT_T__
                              0,/*pxSa->wSaUdpEncPort,*/
#endif
                              dwSaSpi, pxSa->oSaProto,
                              pxSa->dwIkeSaId, pxSa->ikeSaLoc,
                              IKE_KEY_TYPE_CONNECTED
                              MOC_COOKIE_VALUE(cookie));
#endif
                break;
            }

            pxSa->saFlags |= IPSEC_SA_FLAG_MATURE;
        }
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

        LOG_IPSEC_PERMIT_SUCCESS(pxSP->pxSa[i].oSecuProto, wLength)

        /*if (ctx) ctx->axSaUsed[i] = pxSa;*/

        UNLOCK_SA(pxSa)
    } /* update applied SA's */

    /* OK */
    if (ctx) ctx->pxSp = pxSP;

    if (pwLength) *pwLength = wLength;

#ifdef __ENABLE_DIGICERT_HARNESS__
    if (poOrigBuf)
    {
        /*DIGI_MEMCPY(poOrigBuf, pBuffer, wLength);*/
        DIGI_MEMCPY(poOrigBuf, poHdr, wHdrLen);
        DIGI_MEMCPY(poOrigBuf + wHdrLen, poPayload, wPayloadLen);
        if (pwOffset) *pwOffset = 0;
    }
    else
#endif
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
    /* book-keeping - for selected SP */
    if (NULL != pxSP)
    {
        LOCK_SP(pxSP)

        ++pxSP->dwTotPackets;
        if ((OK <= status) || (STATUS_IPSEC_DUMMY == status))
        {
            ++pxSP->dwCurPackets;
#ifndef __DISABLE_IPSEC_KBYTES__
            pxSP->wCurBytes += wLength;
            if (1024 <= pxSP->wCurBytes)
            {
                pxSP->dwCurKBytes += (pxSP->wCurBytes / 1024);
                pxSP->wCurBytes = (pxSP->wCurBytes % 1024);
            }
#endif
        }

        UNLOCK_SP(pxSP)
    }

#ifdef __ENABLE_DIGICERT_HARNESS__
    if (poOrigBuf && pBuffer) CRYPTO_FREE(hwAccelCtx, TRUE, (void**) &pBuffer);
#endif

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    IPSEC_releaseHwAccelChannel(&hwAccelCtx);

nocleanup:
#endif
    if(-8810 != status)
    {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
        DB_PRINT("\n ipsec_permit return status=%d", status);
#endif
    }
    return (sbyte4)status;
} /* IPSEC_permitEx */


/*------------------------------------------------------------------*/

static MSTATUS
IPSEC_get(MOC_IP_ADDRESS dwDestAddr, MOC_IP_ADDRESS dwSrcAddr,
          ubyte oProto,
          intBoolean bFragOff, intBoolean bMoreFrags,
          ubyte *poPayload, ubyte2 wPayloadLen,
          ubyte2 wDestPort, ubyte2 wSrcPort,
#ifdef CUSTOM_IPSEC_FILTER_DSCP
          ubyte oDscp,
#endif
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
    SADB pxSa = ppxSa[0];

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
    {
        goto exit;
    }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_MODE_TUNNEL == pxSP->oMode)
    {
        if (!ISZERO_MOC_IPADDR(pxSP->dwTunlDestIP))
            dwTunlDestIP = REF_MOC_IPADDR(pxSP->dwTunlDestIP);
        if (!ISZERO_MOC_IPADDR(pxSP->dwTunlSrcIP))
            dwTunlSrcIP = REF_MOC_IPADDR(pxSP->dwTunlSrcIP);

#ifdef __ENABLE_IPSEC_COOKIE__
        if((ISZERO_MOC_IPADDR(pxSP->dwTunlDestIP) || ISZERO_MOC_IPADDR(pxSP->dwTunlSrcIP))
              && !ppxSa[0] && IKE_ikeSettings()->funcPtrIpsecGetTunnelIP)
        {
            status = (MSTATUS)IKE_ikeSettings()->funcPtrIpsecGetTunnelIP( &dwTunlDestIP,
                    &dwTunlSrcIP MOC_INTF_REQ_ID(ifid) MOC_COOKIE_REQ_VALUE(cookie));
            if(OK > status)
            {
                goto exit;
            }
        }
#endif
    }
#endif

    /* get SA */
    if (pxSa) ; else
    if (OK > (status = IPSEC_getSa(dwDestAddr, dwSrcAddr, oProto,
                                   wDestPort, wSrcPort,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                                   dwTunlDestIP, dwTunlSrcIP,
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
                                   wUdpEncPort,
#endif
#ifdef CUSTOM_IPSEC_FILTER_DSCP
                                   oDscp,
#endif
                                   pxSP, ppxSa MOC_COOKIE_VALUE(cookie))))
    {
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        /* acquiring new SA */
        MSTATUS st;
        if (OK > (st = IKE_keyAcquire(dwDestAddr, dwSrcAddr, oProto,
                                      wDestPort, wSrcPort,
                                      pxSP
                                      MOC_INTF_ID(ifid)
                                      MOC_COOKIE_VALUE(cookie))))
        {
            DBG_STATUS(st)
        }
#endif
        goto exit;
    }
    else pxSa = ppxSa[0];

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_MODE_TUNNEL == pxSP->oMode)
    {
        if (pxSP->oSaLen) /* jic */
        {
            if (!dwTunlDestIP && !ISZERO_MOC_IPADDR(pxSa->dwSaDestAddr))
                dwTunlDestIP = REF_MOC_IPADDR(pxSa->dwSaDestAddr);

            if (!dwTunlSrcIP && !ISZERO_MOC_IPADDR(pxSa->dwSaSrcAddr))
                dwTunlSrcIP = REF_MOC_IPADDR(pxSa->dwSaSrcAddr);
        }

        if (!dwTunlDestIP)
            dwTunlDestIP = dwDestAddr;

        if (!dwTunlSrcIP)
            dwTunlSrcIP = dwSrcAddr;
    }
#endif

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
    while (!pxSa->pxSp && !(IPSEC_SA_FLAG_GDOI & pxSa->saFlags))
    {
        ubyte4 timenow;
        MOC_IP_ADDRESS saDestAddr = REF_MOC_IPADDR(pxSa->dwSaDestAddr);
#ifndef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
        TEST_MOC_IPADDR6(saDestAddr,
        {
            const ubyte *addr6 = GET_MOC_IPADDR6(saDestAddr);
            if (0xFF != addr6[0]) break; /* not multicast */
        })
        {
            if ((0xe0000000 & GET_MOC_IPADDR4(saDestAddr)) != 0xe0000000)
                break;  /* not multicast/broadcast */
        }
#else
        if (pxSa->dwSaDestIPEnd || ((0xe0000000 & GET_MOC_IPADDR4(saDestAddr)) != 0xe0000000))  /* Check for multicast as well as unicast*/
        {
            break;
        }
#endif

        /* trigger GDOI exchange if found SA is non-GDOI group key */
        timenow = RTOS_deltaMS(&gStartTime, NULL);
        if (pxSa->dwSaLastRekey && /* wait a little? */
            ((timenow - pxSa->dwSaLastRekey) < (ubyte4)60000)) /* ms FOR NOW */
            break;

        if (OK <= IKE_keyAcquire(dwDestAddr, dwSrcAddr, oProto, wDestPort, wSrcPort,
                                 pxSP MOC_INTF_ID(ifid) MOC_COOKIE_VALUE(cookie)))
            pxSa->dwSaLastRekey = timenow;

        break;
    }
#endif

#ifdef __ENABLE_IPSEC_NAT_T__
    if (!wUdpEncPort && pxSP->oSaLen)
        wUdpEncPort = pxSa->wSaUdpEncPort;
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
        IPSEC_flowPut(pxSa, pxSP,
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
        if ((pxSP == pxSa->pxSp) && /* !!! */
            /* pxSa->dwSaLastUsed && */ pxSa->dwSaFirstUsed)
        {
            ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
            ubyte4 timeoutEvent = 60000/* 1000*60 */; /* 60 seconds - FOR NOW */
            if (!pxSa->dwSaLastRekey || ((timenow - pxSa->dwSaLastRekey) > timeoutEvent))
            {
                ubyte4 lastUsed = pxSa->dwSaLastUsed;
                ubyte4 timespan = lastUsed - pxSa->dwSaFirstUsed;
                ubyte4 timeoutWait = 20000/* 1000*20 */; /* 20 seconds - FOR NOW */
                if (timespan > timeoutWait)
                {
                    SADB pxSaM = pxSa->pxSaM; /* get mirrored inbound SA */
                    if (pxSaM)
                    {
                        ubyte4 lastUsedM = pxSaM->dwSaLastUsed;
                        if (!lastUsedM || /* mirrored SA never used */
                            (pxSaM->dwId != pxSa->dwIdM)) /* mirrored SA deleted */
                        {
                            timeoutWait = 300000/* 1000*60*5 */; /* 5 minutes - FOR NOW */
                            if (timespan < timeoutWait)
                                goto exit;
                        }
                        else
                        {
                            timenow = RTOS_deltaMS(&gStartTime, NULL); /* !!! */
                            if (!(((timenow - lastUsedM) > (timenow - lastUsed)) &&
                                  ((lastUsed - lastUsedM) > timeoutEvent)))
                                goto exit;
                        }

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

#ifdef USE_MOC_COOKIE
extern sbyte4
IPSEC_apply(ubyte *pBuffer, ubyte2 wBufSize, ubyte2 *pwLength, ubyte2 *pwOffset, ubyte4 cookie)
{
    struct ipsecCtx ctx = { 0 };
    ctx.cookie = cookie;
    return IPSEC_applyEx(pBuffer, wBufSize, pwLength, pwOffset, &ctx);
}
#endif


extern sbyte4
IPSEC_applyEx(ubyte *pBuffer, ubyte2 wBufSize, ubyte2 *pwLength, ubyte2 *pwOffset, IPSECCTX ctx)
{
    MSTATUS status = OK;

    /* perform IPsec outbound processing */

    ubyte2 wOffset;
    ubyte *poHdr;
#ifdef __ENABLE_DIGICERT_IPV6__
    ubyte *poNextHeader;
    struct ip6Hdr *pxHdr6 = NULL;
#endif
    struct ipHdr *pxHdr = NULL;
    ubyte2 wHdrLen;
    ubyte2 wLength, wOrigLen = 0;

    ubyte  oProtocol;
    ubyte *poPayload;
    ubyte2 wPayloadLen;

    MOC_IP_ADDRESS_S dwDestAddr, dwSrcAddr;
    ubyte2 wDestPort, wSrcPort;
#ifdef CUSTOM_IPSEC_FILTER_DSCP
    ubyte oDscp;
#endif
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

#ifdef __ENABLE_DIGICERT_HARNESS__
    ubyte* poOrigBuf = NULL;
    ubyte* poAuthKey/*[IPSEC_AUTHKEY_MAX]*/ = NULL;
#endif
#if defined(__ENABLE_DIGICERT_HARNESS__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    ubyte* poDigest/*[IPSEC_DIGEST_MAX]*/ = NULL;
    ubyte* poIv/*[IPSEC_IV_MAX]*/ = NULL;
#endif

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    sbyte4 ifid = (NULL != ctx) ? ctx->ifid : 0;
#endif
#ifdef USE_MOC_COOKIE
    ubyte4 cookie = (NULL != ctx) ? ctx->cookie : 0;
#endif


#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx;

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
    intBoolean bUseAsync = (NULL != ctx) && ctx->bAsyncEnabled;

    if (bUseAsync && (0 <= (i = ctx->counter - 1)))
    {
        /* async job finished, continue processing */
        SADB pxSa;

        hwAccelCtx = ctx->hwAccelCtx;

#ifdef __ENABLE_DIGICERT_HARNESS__
        if (ctx->pBuffer)
        {
            poOrigBuf = pBuffer;
            pBuffer = ctx->pBuffer;
        }
#endif
        wOrigLen = wBufSize;
        wBufSize = ctx->wBufSize;

        wOffset = ctx->wOffset;
        poHdr = pBuffer + wOffset;
#ifdef __ENABLE_DIGICERT_IPV6__
        poNextHeader = ctx->poNextHeader;

        if (0x60 == (poHdr[0] & 0xF0))
            pxHdr6 = (struct ip6Hdr *)poHdr;
        else
#endif
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

#ifdef __ENABLE_DIGICERT_HARNESS__
        poAuthKey = ctx->poAuthKey;
#endif
        poDigest = ctx->poDigest;
        poIv = ctx->poIv;

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

        /* authenticate */
        if (0 == ctx->wIcvLen)
        {
            SADB_hmacSuiteInfo* pHmacSuite = pxSa->pHmacSuite;
            if (NULL != pHmacSuite)
            {
#ifdef __ENABLE_DIGICERT_HARNESS__
                if (!ctx->bCryptoAlloc)
                    poAuthKey = pxSa->poAuthKey;
#else
                ubyte *poAuthKey = pxSa->poAuthKey;
#endif
                if (OK > (status = DoAsyncHmac(hwAccelCtx, ctx,
                                               poAuthKey,
                                               pHmacSuite,
                                               poPayload, wPayloadLen,
                                               poPayload + wPayloadLen,
                                               TRUE)))
                    EXIT_IPSEC

                /* queue async job */
                if (pwLength) *pwLength = 0;
                return OK;
            }
        }
        else
        {
            SADB_hmacSuiteInfo* pHmacSuite = pxSa->pHmacSuite;
            if (NULL != pHmacSuite) /* jic */
            {
                ubyte2 wIcvLen = pHmacSuite->wIcvLen;
                if (wIcvLen < ctx->wIcvLen)
                {
                    DIGI_MEMCPY(poPayload + wPayloadLen - wIcvLen, poDigest, wIcvLen);
                }
            }
            ctx->wIcvLen = 0;
#ifdef __ENABLE_DIGICERT_IPV6__
            if (pxHdr6)
                SET_HTONS(pxHdr6->ip6_payload_len, wLength - SIZEOF_IP6_HDR);
            else
#endif
            SET_HTONS(pxHdr->ip_len, wLength);
        }

#ifdef __ENABLE_DIGICERT_IPV6__
        if (pxHdr)
#endif
        {
            SET_IPHDR_CSUM(pxHdr->ip_sum, poHdr, wHdrLen)
        }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        oMode = IPSEC_MODE_TRANSPORT;
#endif
        i--;
        goto apply;
    }
#endif /* __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__ */

    if (OK > (status = IPSEC_getHwAccelChannel(&hwAccelCtx, FALSE)))
        goto nocleanup;
#endif

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

#ifdef CUSTOM_IPSEC_FILTER_DSCP
        oDscp = pxHdr->ip_tos;
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
        pxHdr6 = NULL; /* jic */
        break;

    case 0x60:
    {
        ubyte *poDestAddr = NULL;

        pxHdr = NULL; /* jic */
        pxHdr6 = (struct ip6Hdr *)poHdr;
        if (OK > (status = GetPktInfo6(pxHdr6, wBufSize - wOffset,
                                       &wLength, &wHdrLen,
                                       &poNextHeader, &poDestAddr,
                                       &bFragOff, &bMoreFrags, FALSE)))
            goto exit;

        oProtocol = *poNextHeader;

        SET_MOC_IPADDR6(dwSrcAddr,  pxHdr6->ip6_saddr);
        if (poDestAddr) {
            SET_MOC_IPADDR6(dwDestAddr, poDestAddr); }
        else {
            SET_MOC_IPADDR6(dwDestAddr, pxHdr6->ip6_daddr); }

#ifdef CUSTOM_IPSEC_FILTER_DSCP
        oDscp = (ubyte)((IP6_TC & GET_NTOHL(pxHdr6->ip6_vtf))
                         >> IP6_TC_SHIFT);
#endif
    }
#endif /* __ENABLE_DIGICERT_IPV6__ */
        break;
    default :
        status = ERR_IPSEC_BAD_IP;
        EXIT_IPSEC
        /*break;*/
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
#ifdef CUSTOM_IPSEC_FILTER_DSCP
                                 oDscp,
#endif
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
        /* Bypass ICMPv6 Neighbor Discovery (RFC2461) message, if applicable.
           IKE (IPv6) traffic does not go through if these messges fail!
         */
#ifdef __ENABLE_DIGICERT_IPV6__
        if (pxHdr6 && pxSP &&
            (IPPROTO_ICMPV6 == oProtocol) &&
            (ERR_IPSEC_DROP_GETSA_FAIL == status))
        {
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            if ((IPSEC_MODE_TUNNEL != pxSP->oMode) ||
                ((ISZERO_MOC_IPADDR(pxSP->dwTunlSrcIP) ||
                  SAME_MOC_IPADDR(REF_MOC_IPADDR(dwSrcAddr), pxSP->dwTunlSrcIP)) &&
                 (ISZERO_MOC_IPADDR(pxSP->dwTunlDestIP) ||
                  SAME_MOC_IPADDR(REF_MOC_IPADDR(dwDestAddr), pxSP->dwTunlDestIP))))
#endif
            if (((ICMPV6_ND_SOL << 8) == wSrcPort) ||
                ((ICMPV6_ND_ADV << 8) == wSrcPort))
            {
                status = STATUS_IPSEC_BYPASS; /* !!! */
            }
        }
#endif
        if (STATUS_IPSEC_BYPASS != status)
            EXIT_IPSEC
        else
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
#ifdef __ENABLE_DIGICERT_IPV6__
                if (pxHdr6)
                {
                    /* Hop Limit must be 255 - Neighbor Discovery (RFC2461) */
                    if (!((IPPROTO_ICMPV6 == oProtocol) &&
                          (((ICMPV6_ND_ADV << 8) == wSrcPort) ||
                           ((ICMPV6_ND_SOL << 8) == wSrcPort))))

                    if (0 != pxHdr6->ip6_hop_limit)
                        --pxHdr6->ip6_hop_limit;
                }
                else
#endif
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
    wOrigLen = wLength;

    i = iNest - 1;

    /* allocate transient storage */

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
    if (bUseAsync)
    {
#ifdef __ENABLE_DIGICERT_HARNESS__
        if (ctx->bCryptoAlloc)
        {
            if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, wBufSize, TRUE,
                                            (void**) &ctx->pBuffer)))
                EXIT_IPSEC

            poOrigBuf = pBuffer;
            pBuffer = ctx->pBuffer;
            DIGI_MEMCPY(pBuffer + wOffset, poHdr, wLength);

            poHdr = pBuffer + wOffset;
#ifdef __ENABLE_DIGICERT_IPV6__
            if (pxHdr6)
            {
                poNextHeader = pBuffer + (poNextHeader - poOrigBuf);
                pxHdr6 = (struct ip6Hdr *)poHdr;
            }
            else
#endif
            pxHdr = (struct ipHdr *)poHdr;
            poPayload = poHdr + wHdrLen;
        }
        poAuthKey = ctx->poAuthKey;
#endif
        poDigest = ctx->poDigest;
        poIv = ctx->poIv;

        goto apply;
    }
#endif /* __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__ */

#ifdef __ENABLE_DIGICERT_HARNESS__
    poOrigBuf = pBuffer;
    pBuffer = NULL; /* jic */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, wBufSize +
                            IPSEC_IV_MAX + IPSEC_DIGEST_MAX + IPSEC_AUTHKEY_MAX,
                            TRUE, (void**) &pBuffer)))
        EXIT_IPSEC

    poIv = pBuffer + wBufSize;
    poDigest = poIv + IPSEC_IV_MAX;
    poAuthKey = poDigest + IPSEC_DIGEST_MAX;

    DIGI_MEMCPY(pBuffer + wOffset, poHdr, wLength);

    poHdr = pBuffer + wOffset;
#ifdef __ENABLE_DIGICERT_IPV6__
    if (pxHdr6)
    {
        poNextHeader = pBuffer + (poNextHeader - poOrigBuf);
        pxHdr6 = (struct ip6Hdr *)poHdr;
    }
    else
#endif
    pxHdr = (struct ipHdr *)poHdr;
    poPayload = poHdr + wHdrLen;
#endif /* __ENABLE_DIGICERT_HARNESS__ */

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
apply:
#endif
    /* process nested IPSec transforms (start with innermost SA) */
    for (; i >= 0; i--)
    {
        SADB pxSa = axSaUsed[i];
        SADB_hmacSuiteInfo* pHmacSuite = pxSa->pHmacSuite;
        ubyte2 wIcvLen = (pHmacSuite ? pHmacSuite->wIcvLen : 0);
        ubyte oSecuProto = pxSP->pxSa[i].oSecuProto;/* AH, ESP, ESP_AUTH, or ESP_NULL */

        ubyte2 wIPSecHdrLen;
        ubyte4 dwSeql;
#ifdef __ENABLE_IPSEC_ESN__
        ubyte4 dwSeqh;
        ubyte2 wSeghLen = 0;
        ubyte8 seq;
#endif
#if !defined(__ENABLE_DIGICERT_HARNESS__) && !defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
        ubyte poDigest[IPSEC_DIGEST_MAX];
#endif
#ifndef __ENABLE_DIGICERT_HARNESS__
        ubyte *poAuthKey = pxSa->poAuthKey;
#else
        if (NULL != pHmacSuite)
        {
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
            if (bUseAsync && !ctx->bCryptoAlloc)
                poAuthKey = pxSa->poAuthKey;
            else
#endif
            {
                DIGI_MEMCPY(poAuthKey, pxSa->poAuthKey, pHmacSuite->wKeyLen);
            }
        }
#endif

        /* process AH */
        switch (oSecuProto)
        {
        case IPSEC_PROTO_AH :
        {
            ubyte oAhHdrLen; /* AH header length in 32bit - 2; including ICV */
            struct authHdr *pxAh;
            ubyte oTos, oTtl;
            ubyte2 wFragOff;
#ifdef __ENABLE_DIGICERT_IPV6__
            ubyte4 vtf;
#endif
            if (NULL == pHmacSuite)
            {
                status = ERR_IPSEC_NULL_AUTH;
                EXIT_IPSEC
            }

            /* calculate extra packet length */
            wIPSecHdrLen = sizeof(struct authHdr) + wIcvLen;

            /* add explicit ICV padding; see RFC4302 3.3.3.2.1. */
            IF_MOC_IPADDR6(dwDestAddr,
                wIPSecHdrLen = ((wIPSecHdrLen + 7) / 8) * 8;
            )
            wIPSecHdrLen = ((wIPSecHdrLen + 3) / 4) * 4;
            oAhHdrLen = (ubyte)((wIPSecHdrLen >> 2) - 2); /* see RFC4302 2.2. */

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            if (IPSEC_MODE_TUNNEL == oMode) /* add outer ip header length */
            {
                IF_MOC_IPADDR6(dwDestAddr,
                    wHdrLen = SIZEOF_IP6_HDR;
                )
                wHdrLen = sizeof(struct ipHdr);
                wIPSecHdrLen += wHdrLen;
            }
#endif
            /* get new packet length */
            wLength += wIPSecHdrLen;
#ifdef __ENABLE_IPSEC_ESN__
            if (IPSEC_SA_FLAG_ESN & pxSa->saFlags)
            {
                /* ESN requires 4 implicit bytes for ICV calculation */
                if (wIPSecHdrLen > wOffset)
                {
                    if (wBufSize < (wLength + wOffset + (ubyte2)4))
                    {
                        status = ERR_IPSEC_BUFFER_OVERFLOW;
                        EXIT_IPSEC
                    }
                }
                else if (wBufSize < (wLength + (ubyte2)4))
                {
                    status = ERR_IPSEC_BUFFER_OVERFLOW;
                    EXIT_IPSEC
                }
            }
            else
#endif
            if ((wIPSecHdrLen > wOffset) && (wBufSize < (wLength + wOffset)))
            {
                status = ERR_IPSEC_BUFFER_OVERFLOW;
                EXIT_IPSEC
            }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            switch (oMode)
            {
            case IPSEC_MODE_TRANSPORT :
#endif
                /* make room for AH */
                if (wIPSecHdrLen <= wOffset)
                {
                    DIGI_MEMMOVE(poHdr - wIPSecHdrLen, poHdr, wHdrLen);
                    wOffset -= wIPSecHdrLen;
                    poHdr -= wIPSecHdrLen;
#ifdef __ENABLE_DIGICERT_IPV6__
                    if (pxHdr6)
                    {
                        poNextHeader -= wIPSecHdrLen;
                        pxHdr6 = (struct ip6Hdr *)poHdr;
                    }
                    else
#endif
                    pxHdr = (struct ipHdr *)poHdr;
                    poPayload = poHdr + wHdrLen;
                }
                else

                DIGI_MEMMOVE(poPayload + wIPSecHdrLen, poPayload, wPayloadLen);
                wPayloadLen += wIPSecHdrLen;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                break;
/*          case IPSEC_MODE_TUNNEL : */
            default :
                /* add outer ip header - options shouldn't be copied */
                if (wIPSecHdrLen <= wOffset)
                {
                    wOffset -= wIPSecHdrLen;
                    poHdr -= wIPSecHdrLen;
                }
                else

                DIGI_MEMMOVE(poHdr + wIPSecHdrLen, poHdr, wLength - wIPSecHdrLen);
                wPayloadLen = wLength - wHdrLen;
                poPayload = poHdr + wHdrLen;

                /* update outer ip header fields */
                UPD_TUNNEL_IPHDR(dwDestAddr, dwSrcAddr, poHdr, pxHdr, pxHdr6,
                                 oProtocol, poNextHeader,
                                 pxSP)

                break;
            }
#endif /* #ifndef __DISABLE_IPSEC_TUNNEL_MODE__ */

            /* fill in ah header */
            pxAh = (struct authHdr *)poPayload;
            pxAh->oNextHeader = oProtocol;  /* move next original next protocol field to AH */
            oProtocol = IPPROTO_AH;

            SET_HTONS(pxAh->wReserved, 0);                      /* must be 0 */
            SET_HTONL(pxAh->dwSpi, pxSa->dwSaSpi);              /* SPI */

#ifdef __ENABLE_IPSEC_ESN__
            seq = ATOMIC_INC_GET(pxSa->u.o.seq);
            dwSeqh = HI_U8(seq);
            dwSeql = LOW_U8(seq);
#else
            dwSeql = ATOMIC_INC_GET(pxSa->u.o.seq);
#endif
            SET_HTONL(pxAh->dwSeqNbr, dwSeql);                  /* sequence number */

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            if ((0 == dwSeql) && pxSa->pxSp) /* jic - wraps back to 0 */
#ifdef __ENABLE_IPSEC_ESN__
            if (!(IPSEC_SA_FLAG_ESN & pxSa->saFlags) || (0 == dwSeqh))
#endif
            {
                ATOMIC_SET(pxSa->u.o.seq, SEQ_MAX);
                status = ERR_IPSEC_DROP_GETSA_FAIL;
                EXIT_IPSEC
            }
#endif
            pxAh->oPayloadLen   = oAhHdrLen;                    /* payload length */

            /* update ip header fields */
#ifdef __ENABLE_DIGICERT_IPV6__
            if (pxHdr6)
            {
                SET_HTONS(pxHdr6->ip6_payload_len, wLength - SIZEOF_IP6_HDR);
                *poNextHeader = IPPROTO_AH;             /* replace next protocol field with AH */

                SET_NTOHL(vtf,   pxHdr6->ip6_vtf);
                          oTtl = pxHdr6->ip6_hop_limit;

                SET_HTONL(pxHdr6->ip6_vtf,        0x60000000);
                          pxHdr6->ip6_hop_limit = 0;
            }
            else
#endif
            {
                SET_HTONS(pxHdr->ip_len, wLength);
                          pxHdr->ip_p  = IPPROTO_AH;    /* replace next protocol field with AH */
                SET_HTONS(pxHdr->ip_sum, 0);

                /* store mutable field values */
                          oTos    = pxHdr->ip_tos;
                          oTtl    = pxHdr->ip_ttl;
                SET_NTOHS(wFragOff, pxHdr->ip_off);

                /* temporaly fill with 0 for ICV calculation */
                          pxHdr->ip_tos = 0;
                          pxHdr->ip_ttl = 0;
                SET_HTONS(pxHdr->ip_off,  0);
            }

            DIGI_MEMSET(poPayload + sizeof(struct authHdr), 0x00, wIcvLen);

            /* calculate ICV */
#ifdef __ENABLE_IPSEC_ESN__
            if (IPSEC_SA_FLAG_ESN & pxSa->saFlags)
            {
                DIGI_HTONL(poHdr + wLength, dwSeqh);
                wSeghLen = 4;
            }
#endif
            if (OK != (status = pHmacSuite->hmacFunc(MOC_HASH(hwAccelCtx)
                                                     poAuthKey,
                                                     pHmacSuite->wKeyLen,
                                                     poHdr, wLength
#ifdef __ENABLE_IPSEC_ESN__
                                                            + wSeghLen
#endif
                                                                   ,
                                                     poDigest)))
                EXIT_IPSEC

            DIGI_MEMCPY(poPayload + sizeof(struct authHdr), poDigest, wIcvLen);

            /* restore mutable field values */
#ifdef __ENABLE_DIGICERT_IPV6__
            if (pxHdr6)
            {
                SET_HTONL(pxHdr6->ip6_vtf,        vtf);
                          pxHdr6->ip6_hop_limit = oTtl;
            }
            else
#endif
            {
                          pxHdr->ip_tos = oTos;
                          pxHdr->ip_ttl = oTtl;
                SET_HTONS(pxHdr->ip_off,  wFragOff);
            }

            break;
        }

        /* process ESP */
        case IPSEC_PROTO_ESP :          /* ESP without authentication */
        case IPSEC_PROTO_ESP_AUTH :     /* ESP with authentication */
        case IPSEC_PROTO_ESP_NULL :     /* Null encryption with authentication */
        {
            ubyte2 wIvLen=0, wLengthNew;
            ubyte oPadLen=0, *poPad;
            struct espHdr *pxEsph;
            sbyte4 j;

            AeadAlgo* pAeadAlgo = NULL;
            ubyte oSaltLen=0, oTagLen=0;

            /* set up encryption */
            SADB_cipherSuiteInfo* pCipherSuite = pxSa->pCipherSuite;
            if (NULL != pCipherSuite)
            {
                ubyte2 wBlockLen, wLen;

                wIvLen = pCipherSuite->wIvLen; /* IV size */
                if (NULL != (pAeadAlgo = pCipherSuite->pAeadAlgo))
                {
                    oSaltLen = (ubyte) pAeadAlgo->implicitNonceSize;
                    oTagLen = (ubyte) pAeadAlgo->tagSize;
                    wBlockLen = 4;
                }
                else
                {
                    wBlockLen = (ubyte2) pCipherSuite->pBEAlgo->blockSize;
                    if (wBlockLen % 4)
                        wBlockLen = (ubyte2)(4 * ((wBlockLen / 4) + 1));
                }

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
            else /* padding in absence of encryption; see RFC4303 2.4 */
            {
                ubyte2 wAlignLen, wLen;

                IF_MOC_IPADDR6(dwDestAddr,
                    wAlignLen = 8;
                )
                wAlignLen = 4;

                if (0 != (wLen = (((
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                                    (IPSEC_MODE_TUNNEL == oMode) ? wLength :
#endif
                                    wPayloadLen) + 2) % wAlignLen)))
                {
                    oPadLen = wAlignLen - wLen;
                }
            }

            /* calculate extra packet header length */
            wIPSecHdrLen = sizeof(struct espHdr) + wIvLen;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            if (IPSEC_MODE_TUNNEL == oMode) /* add outer ip header length */
            {
                IF_MOC_IPADDR6(dwDestAddr,
                    wHdrLen = SIZEOF_IP6_HDR;
                )
                wHdrLen = sizeof(struct ipHdr);
                wIPSecHdrLen += wHdrLen;
            }
#endif
            /* check new packet length (include ICV) */
            /* Note: 2 bytes for trailing pad length and next header */
            wLengthNew = wLength + oPadLen + 2
                       + oTagLen;

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
#ifdef __ENABLE_DIGICERT_IPV6__
                    if (pxHdr6)
                    {
                        poNextHeader -= wIPSecHdrLen;
                        pxHdr6 = (struct ip6Hdr *)poHdr;
                    }
                    else
#endif
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
                UPD_TUNNEL_IPHDR(dwDestAddr, dwSrcAddr, poHdr, pxHdr, pxHdr6,
                                 oProtocol, poNextHeader,
                                 pxSP)

                break;
            }
#endif /* #ifndef __DISABLE_IPSEC_TUNNEL_MODE__ */

            wLength = wLengthNew;
            wPayloadLen = wLength - wHdrLen;

            /* fill padding */
            poPad = poPayload + (wPayloadLen - 2 - oPadLen
                                             - oTagLen);
            for (j=0; j < oPadLen; j++) poPad[j] = j + 1;
            poPad[oPadLen] = oPadLen;

            /* fill esp next header protocol */
            poPad[oPadLen + 1] = oProtocol;         /* next header */
            oProtocol = IPPROTO_ESP;

            /* fill in esp fields */
            pxEsph = (struct espHdr *)poPayload;
            SET_HTONL(pxEsph->dwSpi, pxSa->dwSaSpi);            /* SPI */

#ifdef __ENABLE_IPSEC_ESN__
            seq = ATOMIC_INC_GET(pxSa->u.o.seq);
            dwSeqh = HI_U8(seq);
            dwSeql = LOW_U8(seq);
#else
            dwSeql = ATOMIC_INC_GET(pxSa->u.o.seq);
#endif
            SET_HTONL(pxEsph->dwSeqNbr, dwSeql);    /* sequence number */

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
            if ((0 == dwSeql) && pxSa->pxSp) /* jic - wraps back to 0 */
#ifdef __ENABLE_IPSEC_ESN__
            if (!(IPSEC_SA_FLAG_ESN & pxSa->saFlags) || (0 == dwSeqh))
#endif
            {
                ATOMIC_SET(pxSa->u.o.seq, SEQ_MAX);
                status = ERR_IPSEC_DROP_GETSA_FAIL;
                EXIT_IPSEC
            }
#endif
            /* update ip header fields */
#ifdef __ENABLE_DIGICERT_IPV6__
            if (pxHdr6)
            {
                SET_HTONS(pxHdr6->ip6_payload_len, wLength - SIZEOF_IP6_HDR);
                *poNextHeader = IPPROTO_ESP;            /* replace next protocol field with ESP */
            }
            else
#endif
            {
                SET_HTONS(pxHdr->ip_len, wLength);
                          pxHdr->ip_p  = IPPROTO_ESP;   /* replace next protocol field with ESP */
            }

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
            if (bUseAsync)
            {
                ctx->wOffset = wOffset;
                ctx->wIpHdrLen = wHdrLen;
                ctx->wLength = wLength;
#ifdef __ENABLE_DIGICERT_IPV6__
                ctx->poNextHeader = poNextHeader;
#endif
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
#endif /* __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__ */

            /* encrypt esp payload */
            if (NULL != pCipherSuite)
            {
#if !defined(__ENABLE_DIGICERT_HARNESS__) && !defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
                ubyte poIv[IPSEC_IV_MAX];
#endif
#if defined(__HW_OFFLOAD_SINGLE_PASS_SUPPORT__) && defined(__IPSEC_SINGLE_PASS_SUPPORT__)
                /* encrypt and authenticate in a single pass */
                if ((NULL != pHmacSuite) &&
                    (NO_SINGLE_PASS != pxSa->dwSinglePassCookie))
                {
                    BulkCtx pCipherCtx;

                    /* fill IV with random data */
                    if (0 != wIvLen)
                    {
                        if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,
                                                poPayload + sizeof(struct espHdr), wIvLen)))
                            EXIT_IPSEC
                    }

#if !defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
                    if (NULL == (pCipherCtx = pCipherSuite->pBEAlgo->createFunc(
                                                        MOC_SYM(hwAccelCtx)
                                                        pxSa->poEncrKey,
                                                        pxSa->wEncrKeyLen,
                                                        TRUE)))
                    {
                        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
                        EXIT_IPSEC
                    }
#else
                    DOWN_SA_LOCK(pxSa)
                    pCipherCtx = pxSa->pCipherCtx;
                    if (NULL == pCipherCtx) /* jic */
                        status = ERR_IPSEC_DROP_GETSA_FAIL;
                    else
                    pxSa->users++;
                    UP_SA_LOCK(pxSa)

                    if (OK > status) EXIT_IPSEC

                    if (bUseAsync)
                    {
                        ctx->wIcvLen = wIcvLen;
                        ctx->wLength += wIcvLen;

                        ctx->pCipherCtx = pCipherCtx;
                    }
#ifdef __ENABLE_DIGICERT_HARNESS__
                    LOCK_HARNESS(hwAccelCtx, TRUE)
                    HARNESS_assignAsyncCtx(hwAccelCtx, ctx);
#endif
#endif
                    status = HWOFFLOAD_doSinglePassEncryption(MOC_SYM(hwAccelCtx)
                                                MOCANA_IPSEC,
                                                pxSa->dwSinglePassCookie, 0,
                                                pCipherCtx,
                                                poAuthKey,
                                                pHmacSuite->wKeyLen,
                                                poPayload, wPayloadLen,
                                                poPayload + wIPSecHdrLen,
                                                wPayloadLen - wIPSecHdrLen,
                                                NULL,           /* pointer to new packet location */
                                                poPayload + sizeof(struct espHdr), /* IV */
                                                wIvLen, wIcvLen, 0);

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
#ifdef __ENABLE_DIGICERT_HARNESS__
                    HARNESS_assignAsyncCtx(hwAccelCtx, NULL);
                    UNLOCK_HARNESS(hwAccelCtx, TRUE)
#endif
                    if (bUseAsync)
                    {
                        if (OK > status)
                        {
                            ctx->wIcvLen = 0;
                            ctx->wLength = wLength;
                            ctx->pCipherCtx = NULL;
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
#else
                    pCipherSuite->pBEAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &pCipherCtx);
#endif

                    if (OK > status)
                    {
                        if (ERR_HARDWARE_ACCEL_SINGLE_PASS_LOOKUP_FAIL != status)
                            EXIT_IPSEC
                    }
                    else
                    {
                        /* ICV was appended at the end of packet */
                        wLength += wIcvLen;
                        wPayloadLen += wIcvLen;
#ifdef __ENABLE_DIGICERT_IPV6__
                        if (pxHdr6)
                            SET_HTONS(pxHdr6->ip6_payload_len, wLength - SIZEOF_IP6_HDR);
                        else
#endif
                        SET_HTONS(pxHdr->ip_len, wLength);
                        break;
                    }
                }
#endif /* SINGLE_PASS */

                /* initialize IV with random data */
                if (0 != wIvLen)
                {
                    ubyte *poIvEx = poIv + oSaltLen;
                    if (OK > (status = RANDOM_numberGenerator(g_pRandomContext, poIvEx, wIvLen)))
                        EXIT_IPSEC

                    /* fill in the explicit IV */
                    DIGI_MEMCPY(poPayload + sizeof(struct espHdr), poIvEx, wIvLen);
                }

                /* encrypt esp */
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
                if (bUseAsync)
                {
                    if (OK > (status = DoAsyncCipher(hwAccelCtx, pxSa, ctx,
                                                     pCipherSuite->pBEAlgo,
                                                     poIv, /* to be modified */
                                                     poPayload + wIPSecHdrLen,
                                                     wPayloadLen - wIPSecHdrLen,
                                                     TRUE)))
                        EXIT_IPSEC

                    /* queue async job */
                    if (pwLength) *pwLength = 0;
                    return OK;
                }
#endif

                if (NULL != pAeadAlgo)
                {
                    BulkCtx aead_ctx = NULL;
#ifdef __ENABLE_IPSEC_ESN__
                    ubyte temp[8];
                    if (IPSEC_SA_FLAG_ESN & pxSa->saFlags)
                    {
                        DIGI_MEMCPY(temp, poPayload-4, 8);
                        DIGI_MEMCPY(poPayload-4, poPayload, 4);
                        DIGI_HTONL(poPayload, dwSeqh);

                        wIPSecHdrLen += (ubyte2)4;
                        wPayloadLen += (ubyte2)4;
                        poPayload -= 4;
                        wSeghLen = 4;
                    }
#endif
#ifndef __ENABLE_IPSEC_LOCKLESS_CRYPTO__
                    DOWN_SA_LOCK(pxSa)
                    aead_ctx = pxSa->pCipherCtx;
#else
                    if(pAeadAlgo->cloneFunc)
                    {
                        status = pAeadAlgo->cloneFunc(MOC_SYM(hwAccelCtx)
                                                     pxSa->pCipherCtx,
                                                     &aead_ctx);
                    }
                    else
                    {
                        status = ERR_NULL_POINTER;
                    }
                    if ((OK > status) || (NULL == aead_ctx))
                    {
                        EXIT_IPSEC
                    }
#endif
                    /* retrieve implicit nonce (i.e. salt) */
                    DIGI_MEMCPY(poIv, pxSa->poEncrKey + (pxSa->wEncrKeyLen - oSaltLen), oSaltLen);

                    if (pCipherSuite->bAeadNull)
                        status = pAeadAlgo->cipherFunc(MOC_SYM(hwAccelCtx)
                                                   aead_ctx,
                                                   poIv, oSaltLen + wIvLen,     /* Nonce */
                                                   poPayload,                   /* AAD */
                                                   wPayloadLen - oTagLen,
                                                   poPayload + (wPayloadLen - oTagLen), /* plaintext (empty) */
                                                   0,
                                                   oTagLen,                     /* ICV */
                                                   TRUE);
                    else
                        status = pAeadAlgo->cipherFunc(MOC_SYM(hwAccelCtx)
                                                   aead_ctx,
                                                   poIv, oSaltLen + wIvLen,     /* Nonce */
                                                   poPayload,                   /* AAD */
                                                   sizeof(struct espHdr)  /*wIPSecHdrLen - wIvLen,*/
#ifdef __ENABLE_IPSEC_ESN__
                                                       + wSeghLen
#endif
                                                                        ,
                                                   poPayload + wIPSecHdrLen,    /* plaintext */
                                                   wPayloadLen - (wIPSecHdrLen + oTagLen),
                                                   oTagLen,                     /* ICV */
                                                   TRUE);
#ifndef __ENABLE_IPSEC_LOCKLESS_CRYPTO__
                    UP_SA_LOCK(pxSa)
#else
                    pAeadAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &aead_ctx);
#endif
#ifdef __ENABLE_IPSEC_ESN__
                    if (wSeghLen)
                    {
                        DIGI_MEMCPY(poPayload, temp, 8);
                        wIPSecHdrLen -= (ubyte2)4;
                        wPayloadLen -= (ubyte2)4;
                        poPayload += 4;
                        wSeghLen = 0; /* jic */
                    }
#endif
                    if (OK > status) { EXIT_IPSEC }
                }
                else
                {
                    BulkCtx cipher_ctx = NULL;
#if 1
#ifndef __ENABLE_IPSEC_LOCKLESS_CRYPTO__
                    DOWN_SA_LOCK(pxSa)
                    cipher_ctx = pxSa->pCipherCtx;
#else
                    byteBoolean bDelCtx = FALSE;
                    if(pCipherSuite->pBEAlgo->cloneFunc)
                    {
                        status = pCipherSuite->pBEAlgo->cloneFunc(MOC_SYM(hwAccelCtx)
                                                         pxSa->pCipherCtx,
                                                         &cipher_ctx);
                        if ((OK > status) || (NULL == cipher_ctx))
                        {
                            EXIT_IPSEC
                        }
                        bDelCtx = TRUE;
                    }
                    else
                    {
                         cipher_ctx = pxSa->pCipherCtx;
                    }
#endif
                    status = pCipherSuite->pBEAlgo->cipherFunc(
                                                   MOC_SYM(hwAccelCtx)
                                                   cipher_ctx,
                                                   poPayload + wIPSecHdrLen,
                                                   wPayloadLen - wIPSecHdrLen,
                                                   TRUE,
                                                   poIv /* to be modified */);
#ifndef __ENABLE_IPSEC_LOCKLESS_CRYPTO__
                    UP_SA_LOCK(pxSa)
#else
                    if(TRUE == bDelCtx)
                    {
                        pCipherSuite->pBEAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &cipher_ctx);
                    }
#endif
#else
                    status = CRYPTO_Process(MOC_SYM(hwAccelCtx)
                                                   pCipherSuite->pBEAlgo,
                                                   pxSa->poEncrKey,
                                                   pxSa->wEncrKeyLen,
                                                   poIv, /* to be modified */
                                                   poPayload + wIPSecHdrLen,
                                                   wPayloadLen - wIPSecHdrLen,
                                                   TRUE);
#endif
                    if (OK > status) { EXIT_IPSEC }
                }
            }

            /* authenticate the esp payload */
            if (NULL != pHmacSuite)
            {
                intBoolean bCopy;

                /* calculate ICV for esp payload except Auth field*/
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
                if (bUseAsync)
                {
                    if (OK > (status = DoAsyncHmac(hwAccelCtx, ctx,
                                                   poAuthKey,
                                                   pHmacSuite,
                                                   poPayload, wPayloadLen,
                                                   poPayload + wPayloadLen,
                                                   TRUE)))
                        EXIT_IPSEC

                    /* queue async job */
                    if (pwLength) *pwLength = 0;
                    return OK;
                }
#endif
#ifdef __ENABLE_IPSEC_ESN__
                if (IPSEC_SA_FLAG_ESN & pxSa->saFlags)
                {
                    DIGI_HTONL(poPayload + wPayloadLen, dwSeqh);
                    wSeghLen = 4;
                    bCopy = TRUE;
                }
                else
#endif
                bCopy = ((wOffset + wLength + pHmacSuite->wDigestOrgLen) > wBufSize);

                if (OK != (status = pHmacSuite->hmacFunc(MOC_HASH(hwAccelCtx)
                                                         poAuthKey,
                                                         pHmacSuite->wKeyLen,
                                                         poPayload, wPayloadLen
#ifdef __ENABLE_IPSEC_ESN__
                                                                    + wSeghLen
#endif
                                                                               ,
                                                         (bCopy ? poDigest :
                                                          (poPayload + wPayloadLen)))))
                    EXIT_IPSEC

                if (bCopy) DIGI_MEMCPY(poPayload + wPayloadLen, poDigest, wIcvLen);

                /* append ICV at the end of packet */
                wLength += wIcvLen;
                wPayloadLen += wIcvLen;
#ifdef __ENABLE_DIGICERT_IPV6__
                if (pxHdr6)
                    SET_HTONS(pxHdr6->ip6_payload_len, wLength - SIZEOF_IP6_HDR);
                else
#endif
                SET_HTONS(pxHdr->ip_len, wLength);
            }
            break;
        }

        default : /* invalid protocol */
            status = ERR_IPSEC;
            EXIT_IPSEC
        } /* switch (oSecuProto) { */

        /* re-calculate ip header checksum */
#ifdef __ENABLE_DIGICERT_IPV6__
        if (pxHdr)
#endif
        {
            SET_IPHDR_CSUM(pxHdr->ip_sum, poHdr, wHdrLen)
        }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        oMode = IPSEC_MODE_TRANSPORT;
#endif
    } /* for (i */

#ifdef __ENABLE_IPSEC_NULL_TUNNEL__
    /* in case of IP in IP wo/ security */
    if (0 == iNest) /* must be tunnel mode */
    {
        IF_MOC_IPADDR6(dwDestAddr,
            wHdrLen = SIZEOF_IP6_HDR;
        )
        wHdrLen = sizeof(struct ipHdr);

        wLength += wHdrLen;
        if (wHdrLen > wOffset)
        if (wBufSize < (wLength + wOffset))
        {
            status = ERR_IPSEC_BUFFER_OVERFLOW;
            EXIT_IPSEC
        }

        /* duplicate outer ip header - options shouldn't be copied */
        if (wHdrLen <= wOffset)
        {
            wOffset -= wHdrLen;
            poHdr -= wHdrLen;
        }
        else

        DIGI_MEMMOVE(poHdr + wHdrLen, poHdr, wOrigLen);
        poPayload = poHdr + wHdrLen;
        wPayloadLen = wOrigLen;

        /* update outer ip header fields */
        UPD_TUNNEL_IPHDR(dwDestAddr, dwSrcAddr, poHdr, pxHdr, pxHdr6,
                         oProtocol, poNextHeader,
                         pxSP)

#ifdef __ENABLE_DIGICERT_IPV6__
        if (pxHdr6)
        {
            SET_HTONS(pxHdr6->ip6_payload_len, wLength - SIZEOF_IP6_HDR);
            *poNextHeader = oProtocol;
        }
        else
#endif
        {
            SET_HTONS(pxHdr->ip_len, wLength);
                      pxHdr->ip_p  = oProtocol;  /* replace next protocol field with IPIP */

            /* re-calculate ip header checksum */
            SET_IPHDR_CSUM(pxHdr->ip_sum, poHdr, wHdrLen)
        }

        goto done;
    }
#endif /* __ENABLE_IPSEC_NULL_TUNNEL__ */

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
#ifdef __ENABLE_DIGICERT_IPV6__
            if (pxHdr6)
            {
                poNextHeader -= sizeof(struct udpHdr);
                pxHdr6 = (struct ip6Hdr *)poHdr;
            }
            else
#endif
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

#ifdef __ENABLE_DIGICERT_IPV6__
        if (pxHdr6)
        {
            SetUdp6Checksum(poPayload,
                            RET_MOC_IPADDR6(dwSrcAddr),
                            RET_MOC_IPADDR6(dwDestAddr));
            SET_HTONS(pxHdr6->ip6_payload_len, wLength - SIZEOF_IP6_HDR);
            *poNextHeader = IPPROTO_UDP;
        }
        else
#endif
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

#if defined(__ENABLE_IPSEC_NULL_TUNNEL__) || (defined(__ENABLE_IPSEC_NAT_T__) && defined(__ENABLE_DIGICERT_IKE_SERVER__))
done:
#endif
    /* update applied SA's */
    timenow = RTOS_deltaMS(&gStartTime, NULL);
    for (i=0; i < iNest; i++)
    {
        SADB pxSa = axSaUsed[i]; /* applied SA */
        LOCK_SA(pxSa)

        ++pxSa->dwSaCurPackets;

#ifndef __DISABLE_IPSEC_KBYTES__
        {
        ubyte2 wNewBytes = pxSa->wSaCurBytes + wOrigLen; /* use original length */
        if (1024 <= wNewBytes)
        {
            ubyte4 dwSaCurKBytes = pxSa->dwSaCurKBytes;
            ubyte4 dwNewKBytes = dwSaCurKBytes + (ubyte4)(wNewBytes / 1024);
            wNewBytes = wNewBytes % 1024;

             /* jic KBytes wraps back to 0 */
            if (pxSa->dwSaExpKBytes && (dwSaCurKBytes > dwNewKBytes))
            {
                wNewBytes += (ubyte2)((dwNewKBytes + 1) * 1024);
                dwNewKBytes = ~((ubyte4)0);
            }
            pxSa->dwSaCurKBytes = dwNewKBytes;
        }
        pxSa->wSaCurBytes = wNewBytes;
        }
#endif
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

        LOG_IPSEC_APPLY_SUCCESS(pxSP->pxSa[i].oSecuProto, wOrigLen)

        UNLOCK_SA(pxSa)
    } /* update applied SA's */

    /* OK */
    if (pwLength) *pwLength = wLength;
    if (pwOffset) *pwOffset = wOffset;

#ifdef __ENABLE_DIGICERT_HARNESS__
    if (poOrigBuf) DIGI_MEMCPY(poOrigBuf + wOffset, poHdr, wLength);
#endif

exit:
    /* book-keeping - for selected SP */
    if (NULL != pxSP)
    {
        LOCK_SP(pxSP)

        ++pxSP->dwTotPackets;
        if ((OK <= status)
#if defined(__ENABLE_IPSEC_NAT_T__) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
            || (STATUS_IPSEC_NATT == status)
#endif
            )
        {
            ++pxSP->dwCurPackets;
#ifndef __DISABLE_IPSEC_KBYTES__
            pxSP->wCurBytes += wOrigLen; /* use original length */
            if (1024 <= pxSP->wCurBytes)
            {
                pxSP->dwCurKBytes += (pxSP->wCurBytes / 1024);
                pxSP->wCurBytes = (pxSP->wCurBytes % 1024);
            }
#endif
        }

        UNLOCK_SP(pxSP)
    }

#ifdef __ENABLE_DIGICERT_HARNESS__
    if (poOrigBuf && pBuffer) CRYPTO_FREE(hwAccelCtx, TRUE, (void**) &pBuffer);
#endif

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    IPSEC_releaseHwAccelChannel(&hwAccelCtx);

nocleanup:
#endif
    return (sbyte4)status;
} /* IPSEC_applyEx */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IKE_SERVER__

#if defined(__VXWORKS_RTOS__)
extern sbyte4
IPSEC_keyInitiate_ex(IPSECKEY pxKey)
#else
extern sbyte4
IPSEC_keyInitiate(IPSECKEY pxKey)
#endif
{
    MSTATUS status;

#ifndef __ENABLE_DIGICERT_IPV6__
    #define destAddr pxKey->dwDestAddr
    #define srcAddr pxKey->dwSrcAddr
#else
    MOC_IP_ADDRESS_S destAddr, srcAddr;
    if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
    {
        if (pxKey->dwDestAddr)
        {
            SET_MOC_IPADDR6(destAddr, pxKey->dwDestAddr);
        }
        else
        {
            ZERO_MOC_IPADDR(destAddr);
            destAddr.family = AF_INET6;
        }

        if (pxKey->dwSrcAddr)
        {
            SET_MOC_IPADDR6(srcAddr, pxKey->dwSrcAddr);
        }
        else
        {
            ZERO_MOC_IPADDR(srcAddr);
            srcAddr.family = AF_INET6;
        }
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
#ifdef CUSTOM_IPSEC_FILTER_DSCP
                       0, /* for now */
#endif
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

#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */


#endif /* defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) */

