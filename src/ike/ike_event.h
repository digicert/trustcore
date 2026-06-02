/**
 * @file  ike_event.h
 * @brief IKE event handling.
 *
 * @details    IKE event queue and pending exchange management.
 * @since      1.41
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
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
/* internal use only */

#ifndef __IKE_EVENT_HEADER__
#define __IKE_EVENT_HEADER__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

#define IKE_EVENT_FLAG_INUSE        (0x0001)
#define IKE_EVENT_FLAG_INXCHG       (0x0002)
#define IKE_EVENT_FLAG_NATT         (0x0004)


/*------------------------------------------------------------------*/

typedef struct ike_event
{

    MOC_IP_ADDRESS_S dwDestAddr;
    MOC_IP_ADDRESS_S dwSrcAddr;

    ubyte2  type;           /* see "ikekey.h" */
#if 1 /* defined(__ENABLE_IPSEC_NAT_T__) */
    ubyte2  wUdpEncPort;
#endif
    ubyte4  dwIkeSaId;      /* ID of IKE_SA previously negotiated under */
    sbyte4  ikeSaLoc;       /* IKE_SA's locator */

    /* notify */
    ubyte4  dwSpi;          /* SPI */

    /* acquire */
    ubyte2  wDestPort;
    ubyte2  wSrcPort;
    ubyte   oUlp;           /* upper layer protocol (e.g. 0, IPPROTO_TCP, IPPROTO_UDP) */
    /* notify */
    ubyte   oProtocol;      /* IPPROTO_AH or IPPROTO_ESP */

#if 1 /* !defined(__DISABLE_IPSEC_TUNNEL_MODE__) || defined(__ENABLE_DIGICERT_GDOI_CLIENT__) */
    ubyte   oMode;
    MOC_IP_ADDRESS_S dwDestIP, dwDestIPEnd;
    MOC_IP_ADDRESS_S dwSrcIP, dwSrcIPEnd;
#endif
#ifndef __ENABLE_DIGICERT_PFKEY__
    ubyte   oSaLen;         /* SA bundle size */
    struct sainfo pxSa[IPSEC_NEST_MAX]; /* SA bundle, outermost header first */
#else
    ubyte   oCombLen;                   /* SA Combos (i.e. PF_KEY sadb_comb) */
    struct sainfo pxSa[PFKEY_COMB_MAX]; /* 0=none; must specify length, no wildcards!!! */
#endif
    ubyte4  dwSpdId;        /* ID of trigger IPsec SP */
    sbyte4  spdIndex;       /* index to trigger IPsec SP */

    ubyte4  dwExpSecs;      /* lifetime; e.g. propagated from SPD */
    ubyte4  dwExpKBytes;

    ubyte4  dwSeqNo;

#if 1 /* defined(__ENABLE_IPSEC_INTERFACE_ID__) */
    sbyte4  ifid;
#endif
#if 1 /* defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__) */
    ubyte4  cookie;         /* developer customizable cookie; e.g. PF_KEY reqid */
#endif
#ifdef __ENABLE_DIGICERT_PFKEY__
    ubyte   oReplay;
#endif

#ifdef __ENABLE_IKE_REDIRECT__
    MOC_IP_ADDRESS_S dwOldPeerIP;
#endif

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    sbyte       fqdn[MOC_MAX_FQDN_LEN];
#endif

} *IKEEVT;

/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
typedef struct policy_events
{
    ubyte4              twait;
    ubyte4              tstart;
    struct ike_event    m_rekeyEvt;
    intBoolean          in_use;
    intBoolean          negotiation_status;  /* to track if negotiation is ongoing or not*/
}MCPEVENT;
#endif
/*------------------------------------------------------------------*/

struct ipsecsa;

typedef struct ike_event_q
{
    ubyte2  flags;
    ubyte4  dwId;           /* internal ID */

#ifdef __IKE_UPDATE_TIMER__
    IKE_TIMER_EVT_T expTimerId;
    IKE_TIMER_HDL_T expTimerHdl;
    IKE_TIMER_EVT_T initTimerId;
    IKE_TIMER_HDL_T initTimerHdl;
#endif
    ubyte4  dwTimeQueued;   /* system uptime (in ms) when event is queued */

    ubyte4  dwOldIkeSaId;

#if 1 /*defined(__IKE_MULTI_HOMING__) */
    sbyte4  serverInstance;
#endif
    struct ipsecsa *pxIPsecSa;
    struct ike_event evt;

} *IKEEVT_EX;


/*------------------------------------------------------------------*/

struct ikesa;
struct ipsecsa;
struct ikePeerConfig;

#define IKED_STATE_INIT      0x01
#define IKED_STATE_SHUTDOWN  0x02

extern MSTATUS IKE_clearEvents(sbyte4 state);

#ifdef __IKE_UPDATE_TIMER__
extern void IKE_evtInitTimerEvent(sbyte4 timeout, ubyte4 evtId, void *evt, ubyte4 timerId);
extern void IKE_evtExpTimerEvent(sbyte4 unused, ubyte4 evtId, void *evt, ubyte4 timerId);
#else
extern MSTATUS IKE_handleEvents(void);
#endif

extern MSTATUS IKE_evtXchg(struct ikesa *pxSa);

MOC_EXTERN_DATA_DECL MSTATUS IKE_evtGetAddr(IKEEVT pxEvt,
                              MOC_IP_ADDRESS *pHostAddr,
                              MOC_IP_ADDRESS *pPeerAddr);

extern MSTATUS IKE_evtGetPeerAddr(IKEEVT pxEvt,
                                  MOC_IP_ADDRESS *pPeerAddr,
                                  ubyte2* pwPeerPort);

extern MSTATUS IKE_evtAcquire(struct ikesa *pxSa,
                              struct ipsecsa *pxIPsecSa,
                              ubyte2 type, ubyte4 dwSpdId,
                              intBoolean bTransport);

extern MSTATUS IKE_evtRecvEx(ikePeerConfig* config, IKEEVT pxEvt,
                             sbyte4 serverInstance, intBoolean bUseNattPort);

extern struct ikePeerConfig* IKE_findPeerConfigFromEvent(struct ike_event_q*);

#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
extern void GDOI_resetNegotiationStatus(struct ike_event * evt);
#endif
#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

#endif /* __IKE_EVENT_HEADER__ */

