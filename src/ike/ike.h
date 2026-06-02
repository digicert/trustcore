/**
 * @file  ike.h
 * @brief NanoIKE developer API.
 *
 * @details    IKEv1 and IKEv2 developer API function declarations and structures.
 * @since      1.41
 * @version    6.5.1 and later
 *
 * @flags      Whether the following flags are defined determines which definitions and
 *     structure fields are defined and which function declarations are enabled:
 *     +   \c \__ENABLE_IKE_AGGRESSIVE_MODE__
 *     +   \c \__ENABLE_IKE_CP__
 *     +   \c \__ENABLE_IKE_EAP_ONLY__
 *     +   \c \__ENABLE_IKE_FRAGMENTATION__
 *     +   \c \__ENABLE_IKE_HYBRID_RSA__
 *     +   \c \__ENABLE_IKE_MODE_CFG__
 *     +   \c \__ENABLE_IKE_MULTI_AUTH__
 *     +   \c \__ENABLE_IKE_OCSP_EXT__
 *     +   \c \__ENABLE_IKE_SIG_AUTH_RFC7427__
 *     +   \c \__ENABLE_IKE_XAUTH__
 *     +   \c \__ENABLE_IPSEC_COOKIE__
 *     +   \c \__ENABLE_IPSEC_NAT_T__
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     +   \c \__ENABLE_DIGICERT_EAP_RADIUS__
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
 *     +   \c \__IKE_MULTI_HOMING__
 *     +   \c \__IKE_MULTI_THREADED__
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

#ifndef __IKE_HEADER__
#define __IKE_HEADER__

/* To enable IKE, #define __ENABLE_DIGICERT_IKE_SERVER__ in "moptions.h". */

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/
/* To customize, #define the following symbols in "moptions.h".     */

/* internal sizes */
#ifndef IKE_SA_MAX
#if (defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)) && defined(__ENABLE_DIGICERT_MULTICAST_MCP__)
#define IKE_SA_MAX          (256)    /* maximum # of phase 1 negotiations/channels */
#else
#define IKE_SA_MAX          (32)    /* maximum # of phase 1 negotiations/channels */
#endif
#endif
#ifndef IKE_REDIRECT_MAX
#define IKE_REDIRECT_MAX    IKE_SA_MAX - 1  /* number of SAs after which redirect will be sent. Should be < IKE_SA_MAX */
#endif
#ifndef IKE_IPSECSA_MAX
#if (defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)) && defined(__ENABLE_DIGICERT_MULTICAST_MCP__)
#define IKE_IPSECSA_MAX     (256)     /* maximum # of phase 2 negotiations per established phase 1 channel */
#else
#define IKE_IPSECSA_MAX     (8)     /* maximum # of phase 2 negotiations per established phase 1 channel */
#endif
#endif
#ifndef IKE_P2_SA_MAX
#define IKE_P2_SA_MAX       (1)     /* maximum # of SA payloads per quick mode negotiation */
#endif
#ifndef IKE_EVENT_MAX
#if (defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)) && defined(__ENABLE_DIGICERT_MULTICAST_MCP__)
#define IKE_EVENT_MAX       (256)    /* maximum # of pending phase 2 exchanges, as 1 event is stored for 20 seconds */
#else
#define IKE_EVENT_MAX       (64)
#endif
#endif
#ifndef IKE_CERT_CACHE_MAX
#define IKE_CERT_CACHE_MAX  (32)    /* maximum # of cached certificates */
#endif
#ifndef IKE_CERT_CHAIN_MAX
#define IKE_CERT_CHAIN_MAX  (4)     /* maximum # of certificate chains */
#endif
#ifndef IKE_NONCE_SIZE
#define IKE_NONCE_SIZE      (16)    /* nonce size; between 8 (16 for IKEv2) and 256, inclusive */
#endif

#ifndef IKE_P2_MAX
#define IKE_P2_MAX          IKE_IPSECSA_MAX /* backward Comp. */
#endif

#ifndef IKE_PSK_MAX
#define IKE_PSK_MAX         (256)
#endif

#ifndef IKE_DH_MAX
#define IKE_DH_MAX          (32)
#endif

#ifndef IKE_FRAG_BUCKETS_MAX
#define IKE_FRAG_BUCKETS_MAX (5)
#endif
#ifndef IKE2_FRAG_MAX
#define IKE2_FRAG_MAX       (10)
#endif

#ifndef IKE_WINDOW_SIZE
#define IKE_WINDOW_SIZE     IKE_P2_MAX  /* [v2] window size; must > 0 */
#endif

#ifndef IKE_DPC_FUNC_MAX
#define IKE_DPC_FUNC_MAX    (16)    /* maximum # of functions for multi-threaded Delayed Procure Call */
#endif

#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__

#define MOC_MAX_HEARTBEAT_INTERFACES 2
#define MOC_MAX_HEARTBEAT_ENCR_KEYS 2

#endif


/* private attribute type */
/* see RFC 2407 4.5 p13 & RFC 2409 Appendix A p34 */
#ifdef __ENABLE_IPSEC_COOKIE__
#ifndef IPSEC_COOKIE_TYPE
#define IPSEC_COOKIE_TYPE (24576)
#endif
#endif

#ifdef __ENABLE_IKE_PPK_RFC8784__
#define IKE_PPK_PSK_MIN_LEN   (32)
#define IKE_PPK_PSK_MAX_LEN   (256)
#define IKE_PPK_ID_MIN_LEN   (8)
#define IKE_PPK_ID_MAX_LEN   (64)
#endif

/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_HOMING__
#define MOC_MTHM(serverInstance)            , sbyte4 serverInstance
#define MOC_MTHM_VALUE(serverInstance)      , serverInstance
#define MOC_MTHM_REQ_VALUE                  MOC_MTHM_VALUE
#else
#define MOC_MTHM(serverInstance)
#define MOC_MTHM_VALUE(serverInstance)
#define MOC_MTHM_REQ_VALUE(serverInstance)  , 0
#endif

#ifdef __ENABLE_IPSEC_NAT_T__
#define MOC_NATT(bUseNattPort)              , intBoolean bUseNattPort
#define MOC_NATT_VALUE(bUseNattPort)        , bUseNattPort
#define MOC_NATT_REQ_VALUE                  MOC_NATT_VALUE
#else
#define MOC_NATT(bUseNattPort)
#define MOC_NATT_VALUE(bUseNattPort)
#define MOC_NATT_REQ_VALUE(bUseNattPort)    , 0
#endif


/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_THREADED__
#define IKE_MUTEX       RTOS_RWLOCK
#define IKE_LOCK_R      RTOS_rwLockWaitR(g_ikeMtx)
#define IKE_UNLOCK_R    RTOS_rwLockReleaseR(g_ikeMtx)
#define IKE_LOCK_W      RTOS_rwLockWaitW(g_ikeMtx)
#define IKE_UNLOCK_W    RTOS_rwLockReleaseW(g_ikeMtx)

#else
#define IKE_MUTEX       RTOS_MUTEX

#ifdef __RTOS_WIN32__
extern sbyte4 tidGlobalLock;
#else
extern RTOS_THREAD tidGlobalLock;
#endif

#ifdef __ENABLE_DIGICERT_IKE_RECURSIVE_MUTEX__
#define IKE_LOCK_RW      { \
    RTOS_recursiveMutexWait(g_ikeMtx) ; \
    tidGlobalLock = RTOS_currentThreadId(); \
}

#define IKE_UNLOCK_RW    { \
    tidGlobalLock = 0;\
    RTOS_recursiveMutexRelease (g_ikeMtx) ;\
}
#else
#define IKE_LOCK_RW      { \
    RTOS_mutexWait(g_ikeMtx) ; \
    tidGlobalLock = RTOS_currentThreadId(); \
}

#define IKE_UNLOCK_RW    { \
    tidGlobalLock = 0;\
    RTOS_mutexRelease (g_ikeMtx) ;\
}
#endif

#define IKE_LOCK_R      IKE_LOCK_RW
#define IKE_UNLOCK_R    IKE_UNLOCK_RW
#define IKE_LOCK_W      IKE_LOCK_RW
#define IKE_UNLOCK_W    IKE_UNLOCK_RW

#define IKE_AUTO_LOCK(_lockstatus) { \
    if (tidGlobalLock != RTOS_currentThreadId()) { \
        IKE_LOCK_RW; \
        _lockstatus = FALSE; \
    } \
    else { \
        _lockstatus = TRUE; \
    } \
}

#define IKE_AUTO_UNLOCK { \
    if (tidGlobalLock == RTOS_currentThreadId()) { \
        IKE_UNLOCK_RW; \
    } \
}

#endif /* __IKE_MULTI_THREADED__ */

/* extern IKE_MUTEX g_ikeMtx; */

#ifdef __IKE_UPDATE_TIMER__
/** @private @internal */
typedef ubyte4 IKE_TIMER_EVT_T;
typedef void* IKE_TIMER_HDL_T;
#endif


/*------------------------------------------------------------------*/
/* To override the following default settings dynamically, modify
   corresponding fields in IKE_ikeSettings() after invoking IKE_init().
 */

#define MOC_IKE_VERSION         (1)

/* ISAKMP SA lifetime */
#define ISAKMP_SA_LIFE_SECS     (3600)  /* 1 hour */
#define ISAKMP_SA_LIFE_SECS_MAX (86400) /* 1 day */

/* IPsec SA lifetime */
#define IPSEC_SA_LIFE_SECS      (28800) /* 8 hours (RFC2407 4.5) */
#define IPSEC_SA_LIFE_SECS_MAX  (86400) /* 1 day */

/* phase 1 - mode/DH group */
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
#define IKE_P1_MODE             (2)     /* ISAKMP_XCHG_IDPROT - main mode */
#endif
#define IKE_P1_DH_GROUP         (0)     /* 0=use 1st supported
                                           [v1] aggressive mode
                                           [v2] default group for IKE_SA_INIT */
/* phase 2 - quick mode PFS */
#define IKE_P2_PFS              0xffff  /* OAKLEY_GROUP_DEFAULT - use phase 1 DH group */

/* Variables for Multiple Multicast MCP */
#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
#define TIMEOUT_IKE_EVENT       (10)    /* In new design MCP keygen thread will take care of multicast renegotiation so event can be deleted as soon as negotiation timeout occurs*/
#define TIMEOUT_IKE_DPD         (60)    /* Reduced Primary to Secondary fallback time*/
#define WAIT_IKE_RETRANSMIT     (2800)  /* ms (2.8 seconds) */
#endif

/* timeouts */
#define TIMEOUT_IKE_NEGOTIATION (20)    /* secs */
#ifndef TIMEOUT_IKE_EVENT
#define TIMEOUT_IKE_EVENT       (60)    /* secs (1 minute) */
#endif
#ifndef TIMEOUT_IKE_DPD
#define TIMEOUT_IKE_DPD         (300)   /* secs (5 minutes) */
#endif
#define INTERVAL_IKE_KEEPALIVE  (300)   /* secs */
#ifndef WAIT_IKE_RETRANSMIT
#define WAIT_IKE_RETRANSMIT     (3800)  /* ms (3.8 seconds) */
#endif

/* for reference */
#define IKE_DEFAULT_UDP_PORT    (500)
#define IKE_NAT_UDP_PORT        (4500)

#ifndef IKE_GDOI_UDP_PORT
#define IKE_GDOI_UDP_PORT       (848)
#endif

#ifdef __DYNAMIC_IKE_DEFAULT_UDP_PORT__
/**
 * @private
 * @internal
 */
extern ubyte2 g_ikeDefaultUdpPort;      /* should not be 0 */

#undef IKE_DEFAULT_UDP_PORT
#define IKE_DEFAULT_UDP_PORT g_ikeDefaultUdpPort
#endif

#ifndef __ENABLE_IPSEC_NAT_T__
#define IKE_DEFAULT_BUFFER_SIZE (1472)  /* 1500 (MTU) - 20 (IP) - 8 (UDP)  */
#else
#define IKE_DEFAULT_BUFFER_SIZE (1468)  /* 1500 (MTU) - 20 (IP) - 8 (UDP) - 4 (non-ESP marker) */
#endif

#define IKE_FRAG_SIZE           (548)   /* ISAKMP_HDR_SIZE + FRAG_HDR_SIZE + FRAG_DATA_SIZE */
                                        /* [RFC7383] 2.5.1. RECOMMENDED 576 - 20(IP) - 8(UDP) */

/* RFC 5685 Redirect Timeouts */
#define MAX_REDIRECTS                   (5)
#define REDIRECT_LOOP_DETECT_PERIOD     (300)


/*------------------------------------------------------------------*/

struct certDistinguishedName;
struct certDescriptor;
struct ikePeerConfig;
struct ikesa;
struct ocspSettings;
struct certStore;

/**
 * @private
 * @internal
 */
typedef sbyte4 (*XAUTH_aaaCallbackFun)(void *xauthTrans,
                    const sbyte *userName, const sbyte *password,
                    const sbyte *passCode, const sbyte *nextPin,
                    const sbyte *message, const sbyte *domain,
                    const sbyte *challenge, ubyte2 challengeLen,
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                    const sbyte *perp,
#endif
                    ubyte cfgType, ubyte2 authTypeOrStatus);

/**
 * @private
 * @internal
 */
typedef sbyte4 (*EAPPERP_aaaCallbackFun)(void *eapperpTrans,
                                         const sbyte *pPerp,
                                         ubyte cfgType,
                                         ubyte2 Status);

/**
 * @private
 * @internal
 */
typedef sbyte4 (*XAUTH_userCallbackFun)(void *xauthTrans,
                    const sbyte *userName, const sbyte *password,
                    const sbyte *passCode, const sbyte *nextPin,
                    const sbyte *answer
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                  , const sbyte *perp
#endif
                                        );

/**
 * @private
 * @internal
 */
typedef sbyte4 (*EAPPERP_userCallbackFun)(void *eapperpTrans,
                                          const sbyte *pPerp);


/**
 * @private
 * @internal
 */
typedef sbyte4 (*CERT_statusCallbackFun)(void *data, sbyte4 result);

/* ikeSettings structure
 */
/**
@brief      Configuration settings and callback function pointers for NanoSec
            IKE.

@details    This structure is used for IKE automatic keying and SA
            configuration. Which products and features you've included (by
            defining the appropriate flags in moptions.h) determine which
            fields and callback functions are present in this structure. Each
            included callback function should be customized for your
            application and then registered by assigning it to the appropriate
            structure function pointer(s).

@since 1.41
@version 5.3 and later

The default values for the following basic settings are suitable for most systems:\n
<tt>
&nbsp;&nbsp;&nbsp;&nbsp;IKE_ikeSettings()->ikeBufferSize = 2048;\n
&nbsp;&nbsp;&nbsp;&nbsp;IKE_ikeSettings()->ikeTimeoutNegotiation = 15;\n
&nbsp;&nbsp;&nbsp;&nbsp;IKE_ikeSettings()->ikeTimeoutEvent = 60;\n
&nbsp;&nbsp;&nbsp;&nbsp;IKE_ikeSettings()->ikeTimeoutDpd = 300;\n
</tt>

Additionally, you should specify values for the following SA (security
association) settings:

+ <b>Phase 1 SA Lifetimes</b>&mdash;Set the proposed expiration and maximum
    lifetimes (in seconds) to use as the initiator and responder:
 + <b>Initiator</b>&mdash;When your application is the IKE initiator, it
    proposes an expiration time (the value of \c ikeP1LifeSecs) to the
    responder. The responder may accept it or propose a shorter expiration
    time (which the NanoSec IKE initiator will accept.)\n
 + <b>Responder</b>&mdash;When your application is the IKE responder, it checks
    whether the initiator's proposed expiration time is shorter than or equal to
    the maximum lifetime (the value of \c ikeP1LifeSecsMax). If so, the time is
    accepted. If not, NanoSec IKE proposes its maximum lifetime, which the
    initiator can accept or reject.\n The default values for the lifetime settings are:\n
    <tt>&nbsp;&nbsp;&nbsp;&nbsp;IKE_ikeSettings()->ikeP1LifeSecs = 3600;\n
    &nbsp;&nbsp;&nbsp;&nbsp;IKE_ikeSettings()->ikeP1LifeSecsMax = 86400;</tt>\n
    To propose an infinite lifetime (that is, no expiration), set
    \c ikeP1LifeSecs to 0.\n
\n
+ <b>Phase 2 SA Lifetimes</b>&mdash;Set the proposed expiration and maximum
    lifetimes (in seconds) to use as the initiator and responder:
 + <b>Initiator</b>&mdash;When your application is the IKE initiator, it
    proposes an expiration time (the value of \c ikeP2LifeSecs) to the
    responder. The responder may accept it or propose a shorter expiration
    time (which the NanoSec IKE initiator will accept.)
 + <b>Responder</b>&mdash;When your application is the IKE responder, it checks
    whether the initiator's proposed expiration time is shorter than or equal to
    the maximum lifetime (the value of \c ikeP2LifeSecsMax). If so, the time is
    accepted. If not, the NanoSec IKE responder proposes its maximum lifetime,
    which the initiator may accept or reject.\n The default values for the
    lifetime settings are:\n
    <tt>&nbsp;&nbsp;&nbsp;&nbsp;IKE_ikeSettings()->ikeP2LifeSecs = 28800;\n
    &nbsp;&nbsp;&nbsp;&nbsp;IKE_ikeSettings()->ikeP2LifeSecsMax = 86400;</tt>\n
    To propose an infinite lifetime (that is, no expiration), set
    \c ikeP2LifeSecs to 0.\n
\n
+ <b>Exchange Modes</b>&mdash;Set the Perfect Forward Security (PFS):\n
    <tt>&nbsp;&nbsp;&nbsp;&nbsp;IKE_ikeSettings()->ikeP2PFS = OAKLEY_GROUP_DEFAULT; // Use the same group as in Phase 1</tt>\n
    A setting of 0 for \c ikeP2PFS specifies No Perfect Forward Security, in
    which case keying material from the Phase 1 DH exchange is used. Other
    valid settings are groups 1, 2, 5 and 14.\n
    Note that PFS is required in IKEv2 SA rekeying [RFC7296][RFC5996] 1.3.2 (in
    which case 0 will default to OAKLEY_GROUP_DEFAULT).\n
\n
+ <b>NanoSec IKE Server Callback Functions</b>&mdash;Register your
    application-specific callback functions for NanoSecIKE to invoke. These
    callbacks must be customized for your application; refer to the sample
    code in @ref ike_example.c for details.\n
    <tt>&nbsp;&nbsp;&nbsp;&nbsp;IKE_ikeSettings()->funcPtrIkeXchgSend = IKE_SAMPLE_ikeXchgSend; // Sends an exchange message to a peer's IKE server.\n
    &nbsp;&nbsp;&nbsp;&nbsp;IKE_ikeSettings()->funcPtrIkeEvtSend = IKE_SAMPLE_ikeEvtSend; // Sends an event message to the host IKE server. (The IPsec instance does this to request new SAs).\n
    &nbsp;&nbsp;&nbsp;&nbsp;IKE_ikeSettings()->funcPtrIkeGetHostAddr = IKE_SAMPLE_ikeGetHostAddr; // Retrieves IP addressof the (local) host IKE server.</tt>

@flags
No flag definitions are required to use this structure.

@todo   Add notes to the callbacks that are predefined in mcp/ike_server.c//MCP_init, saying that the user must not change them.
*/
typedef struct ikeSettings
{
    /**
    @brief      Number of bytes in outgoing message buffer.
    @details    Number of bytes in outgoing message buffer.
    */
    ubyte4  ikeBufferSize;          /* buffer size; for outgoing messages */

    /**
    @brief      Number of seconds (> 0) to wait for negotiation.
    @details    Number of seconds (> 0) to wait for negotiation.
    */
    ubyte4  ikeTimeoutNegotiation;  /* seconds > 0 */

    /**
    @brief      Number of seconds (> 0) to wait for the timeout event.
    @details    Number of seconds (> 0) to wait for the timeout event.
    */
    ubyte4  ikeTimeoutEvent;        /* seconds > 0 */

    /**
    @brief      Number of seconds (> 0) to wait for a peer response before
                declaring the peer dead.
    @details    Number of seconds (> 0) to wait for a peer response before
                declaring the peer dead (Default = 300 (5 minutes)); specify 0
                for no dead peer detection.
    */
    ubyte4  ikeTimeoutDpd;          /* seconds; 0=passive */

#if 1 /*defined(__ENABLE_IPSEC_NAT_T__) */
    /**
    @brief      Number of seconds (> 0) between NAT-T Keepalive UDP packet
                transmissions.
    @details    Number of seconds (> 0) between transmissions of NAT-T Keepalive
                UDP packets for a host behind NAT (Default = 5 (minutes)).
    @note       This field is applicable only if the
                \c \__ENABLE_IPSEC_NAT_T__ flag is defined.
    */
    ubyte4  ikeIntervalKeepalive;   /* seconds > 0 */
#endif

    /**
    @brief      Number of milliseconds (> 0) to wait until IKE message
                retransmission.
    @details    Number of milliseconds (> 0) to wait before retransmission of
                IKE messages (Default = 3800 (3.8 seconds)).
    */
    ubyte4  ikeWaitRetransmit;      /* ms > 0 */

    /**
    @brief      Controls if IKEv2 Responder should send COOKIE Notify payload.
    @details    Controls whether IKEv2 Responder should a Notify payload of type
                COOKIE during IKE_SA_INIT exchange (default is \c FALSE).
    @since 6.5.1
    @version 6.5.1 and later
    */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This field is not applicable for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    byteBoolean bNotifyCookie;      /* [v2] Responder sending Notify payload */

    /* phase 1 */
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    /**
    @brief      Phase 1 negotiation mode.
    @details    Phase 1 negotiation mode:\n
                &bull; 2 = main (\c ISAKMP_XCHG_IDPROT)\n
                &bull; 4 = aggressive (\c ISAKMP_XCHG_AGGR)
    @note       This field is defined only if the
                \c \__ENABLE_IKE_AGGRESSIVE_MODE__ flag is defined.
    */
    ubyte   ikeP1Mode;
#endif

    /**
    @brief      IKE: Phase 1 DH group; IKEv2: IKE_SA_INIT default DH group.
    @details    IKE: Phase 1 DH group; IKEv2: IKE_SA_INIT default DH group.\n
                &bull; 0 = use first supported
                &bull; 1 = \c OAKLEY_GROUP_MODP768
                &bull; 2 = \c OAKLEY_GROUP_MODP1024
    */
    ubyte2  ikeP1DHgroup;

    /**
    @brief      Default IKE version.
    @details    Default IKE version. One (1) to specify IKE; two (2) to specify IKEv2.
    */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This field is not applicable for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    ubyte   ikeVersion;             /* [v2] default IKE version to use */

    /**
    @brief      Initiator-proposed Phase 1 SA expiration time.
    @details    Initiator-proposed Phase 1 SA expiration time. Zero (0) to
                specify an infinite lifetime (that is, no expiration).
    */
    ubyte4  ikeP1LifeSecs;          /* 0=no expiration, unless ikeP1LifeSecsMax != 0 */

    /**
    @brief      Responder's maximum Phase 1 SA lifetime.
    @details    Responder's maximum Phase 1 SA lifetime (in seconds). When
                specified (non-zero) and if the initiator's proposed expiration
                time is longer than this maximum lifetime, Mocana IKE proposes
                its maximum lifetime (which the initiator may accept or reject).
    */
    ubyte4  ikeP1LifeSecsMax;       /* 0=unspecified */

    /**
    @brief      Responder's minimum Phase 1 SA lifetime.
    @details    Responder's minimum Phase 1 SA lifetime (in seconds). When
                specified (non-zero) and if the initiator's proposed expiration
                time is shorter than this minimum lifetime, Mocana IKE proposes
                its minimum lifetime (which the initiator may accept or reject).
    */
    ubyte4  ikeP1LifeSecsMin;

    /**
    @brief      Initiator-proposed Phase 1 number of KB to encrypt before
                requiring rekeying.
    @details    Initiator-proposed Phase 1 number of KB to encrypt before
                requiring rekeying; zero (0) to specify no limit.
    */
    ubyte4  ikeP1LifeKBytes;        /* 0=no limit, unless ikeP1LifeKBytesMax != 0 */

    /**
    @brief      Responder's maximum Phase 1 KB to encrypt before requiring
                rekeying.
    @details    Responder's maximum Phase 1 KB to encrypt before requiring
                rekeying. If the initiator's proposed number of KB is less than
                this maximum KB, the proposed KB value is accepted. If not,
                Mocana IKE proposes its maximum KBs (which the initiator may
                accept or reject).
    */
    ubyte4  ikeP1LifeKBytesMax;     /* 0=unspecified, o/w >= ikeP1LifeKBytes */

    /**
    @brief      PFS (Perfect Forward Security) exchange mode.
    @details    PFS (Perfect Forward Security) exchange mode. Zero (0) to
                specify No Perfect Forward Security, in which case keying
                material from the Phase1 DH exchange is used. -1 to use the
                \c OAKLEY_GROUP_DEFAULT (for [v1], the P1 DH group; for [v2],
                the parent IKE_SA DH group). Other valid settings are groups 1,
                2, 5, and 14. Note that PFS is required in IKEv2 SA rekeying
                [RFC7296][RFC5996] 1.3.2 (in which case 0 will default to
                OAKLEY_GROUP_DEFAULT).
    */
    ubyte2  ikeP2PFS;               /* 0=no PFS, 1=OAKLEY_GROUP_MODP768, 2=OAKLEY_GROUP_MODP1024 */
                                    /* -1=OAKLEY_GROUP_DEFAULT
                                       i.e. use [v1] P1 DH group or [v2] parent IKE_SA's DH group */

    /* phase 2 quick mode */
    /**
    @brief      Initiator-proposed Phase 2 SA expiration time.
    @details    Initiator-proposed Phase 2 SA expiration time. Zero (0) to
                specify an infinite lifetime (that is, no expiration).
    */
    ubyte4  ikeP2LifeSecs;          /* 0=unspecified, check ikeP2LifeSecsMax instead */

    /**
    @brief      Responder's maximum Phase 2 SA lifetime.
    @details    Responder's maximum Phase 2 SA lifetime (in seconds). When
                specified (non-zero) and if the initiator's proposed expiration
                time is longer than this maximum lifetime, Mocana IKE proposes
                its maximum lifetime (which the initiator may accept or reject).
    @note       If both \c ikeP2LifeSecsMax and \c ikeP2LifeSecsMin are zero(0),
                28800 secs is used (See [RFC2407] 4.5)
    */
    ubyte4  ikeP2LifeSecsMax;       /* 0=unspecified */
                                    /* Note: if both are unspecified, 28800 secs is used (8 hrs, RFC2407 4.5) */
    /**
    @brief      Responder's minimum Phase 2 SA lifetime.
    @details    Responder's minimum Phase 2 SA lifetime (in seconds). When
                specified (non-zero) and if the initiator's proposed expiration
                time is shorter than this minimum lifetime, Mocana IKE proposes
                its minimum lifetime (which the initiator may accept or reject).
    @note       If both \c ikeP2LifeSecsMin and \c ikeP2LifeSecsMax are zero(0),
                28800 secs is used (See [RFC2407] 4.5)
    */
    ubyte4  ikeP2LifeSecsMin;

    /**
    @brief      Initiator-proposed Phase 2 number of KB to encrypt before
                requiring rekeying.
    @details    Initiator-proposed Phase 2 number of KB to encrypt before
                requiring rekeying; zero (0) to specify no limit.
    */
    ubyte4  ikeP2LifeKBytes;        /* 0=no limit, unless ikeP2LifeKBytesMax != 0 */

    /**
    @brief      Responder's maximum Phase 2 KB to encrypt before requiring
                rekeying.
    @details    Responder's maximum Phase 2 KB to encrypt before requiring
                rekeying. If the initiator's proposed number of KB is less than
                this maximum KB, the proposed KB value is accepted. If not,
                Mocana IKE proposes its maximum KBs (which the initiator may
                accept or reject).
    */
    ubyte4  ikeP2LifeKBytesMax;     /* 0=unspecified, o/w >= ikeP2LifeKBytes */

    /**
    @brief      (IKEv2 only) Time (number of seconds before SA expiration) at
                which reauthentication (IKE_SA_INIT) is attempted.
    @details    (IKEv2 only) Time (number of seconds before SA expiration) at
                which reauthorization (IKE_SA_INIT) is attempted; specify 0 for
                no automatic reauthentication.
    */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This field is not applicable for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    ubyte4  ikeReauthSecs;         /* [v2] Lifetime (in secs) left before repeating IKE_SA_INIT (rfc4478);
                                       0=no repeated auth. (original responder) */

#ifdef __ENABLE_IKE_FRAGMENTATION__
    /**
    @brief      Controls if IKE fragmentation is disabled.
    @details    Controls whether IKE fragmentation is disabled (default is \c FALSE).
    @note       This field is defined only if the
                \c \__ENABLE_IKE_FRAGMENTATION__ flag is defined.
    */
    byteBoolean bNoIkeFrag;

    /**
    @brief      Maximum number of IKE message bytes allowed before fragmentation
                may occur.
    @details    Maximum number of IKE message bytes allowed before fragmentation
                may occur.
    @note       This field is defined only if the
                \c \__ENABLE_IKE_FRAGMENTATION__ flag is defined.
    */
    ubyte2      ikeFragSize;
#endif

#ifdef __ENABLE_IKE_PPK_RFC8784__
    /**
    @brief      Controls if PPK is mandatory when PPK is configured in the peer config.
    @details    Controls if PPK is mandatory when PPK is configured in the peer
                config (default is \c TRUE).
    @note       This field is defined only if the
                \c \__ENABLE_IKE_PPK_RFC8784__ flag is defined.
    @since 7.0
    @version 7.0 and later
    */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This field is not applicable for NanoMCP, so omit from the API documentation.
     * @endcond
     */

    byteBoolean bPpkEnforce;

#endif

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
    /**
    @brief      Controls if IKEv2 Signature Authentication [RFC7427] is disabled.
    @details    Controls whether IKEv2 Signature Authentication [RFC7427] is
                disabled (default is \c FALSE).
    @note       This field is defined only if the
                \c \__ENABLE_IKE_SIG_AUTH_RFC7427__ flag is defined.
    @since 6.5
    @version 6.5 and later
    */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This field is not applicable for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    intBoolean bNoSigAuth;
#endif

#ifdef __ENABLE_IKE_OCSP_EXT__
    /**
    @brief      Controls if OCSP extensions for IKEv2 [RFC4086] is disabled.
    @details    Controls whether OCSP extensions for IKEv2 [RFC4086] is disabled
                (default is \c FALSE).
    @note       This field is defined only if the
                \c \__ENABLE_IKE_OCSP_EXT__ flag is defined.
    @remark     The \c \__ENABLE_DIGICERT_OCSP_CLIENT__ flag must also be defined.
    @since 6.5
    @version 6.5 and later
    */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This field (and all ocsp-related items) is not applicable
     * for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    intBoolean bNoIkeOcsp;

    /**
    @brief      User-provided pointer to the OCSP client settings object.
    @details    User-provided pointer to the OCSP client settings object
                (default is \c NULL).
    @note       This field is defined only if the
                \c \__ENABLE_IKE_OCSP_EXT__ flag is defined.
    @remark     The \c \__ENABLE_DIGICERT_OCSP_CLIENT__ flag must also be defined.
    @since 6.5
    @version 6.5 and later
    */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This field (and all ocsp-related items) is not applicable
     * for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    struct ocspSettings *pOcspSettings;
#endif

#ifdef __ENABLE_IKE_REDIRECT__
    /**
    @brief      IP address of gateway to redirect.
    @details    IP address of gateway to redirect.
    @note       This field is defined only if the
                \c \__ENABLE_IKE_REDIRECT__ flag is defined.
    */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This field is not applicable for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    MOC_IP_ADDRESS_S redirectGwAddr;
#endif

#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
    MOC_IP_ADDRESS_S heartbeatMcastIP;
    MOC_IP_ADDRESS_S heartbeatTxIP[MOC_MAX_HEARTBEAT_INTERFACES];
    ubyte2      heartbeatTxPort;
    ubyte2      heartbeatTxFreq;
#endif

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    /**
    @brief      IP address of GDOI key server.
    @details    IP address of GDOI key server.
    @note       This field is defined only if the
                \c \__ENABLE_DIGICERT_GDOI_CLIENT__ flag is defined.
    */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This callback is not applicable for NanoMCP, so omit from the API
     * documentation.
     * @endcond
     */
    MOC_IP_ADDRESS_S keyServerAddr;
#endif

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    /**
    @brief      Multicast IP address of GDOI PUSH client.
    @details    Multicast IP address of GDOI PUSH client.
    @note       This field is defined only if the
                \c \__ENABLE_DIGICERT_GDOI_SERVER__ flag is defined.
    */
    /**
     * @private
     * @internal
     *
     * Doc Note: Not implemented yet.
     */
    MOC_IP_ADDRESS_S keyClientMAddr;

    /**
    @brief      GDOI KEK crypto algorithm configuration.
    @details    GDOI KEK crypto algorithm configuration.
    @note       These fields are defined only if the
                \c \__ENABLE_DIGICERT_GDOI_SERVER__ flag is defined.
    * Doc Note: Not implemented yet.
    */
    /**
     * @private
     * @internal
     */
    ubyte2 ikeHashAlgo;     /* OAKLEY hash algorithm attribute [v1] */
    /**
     * @private
     * @internal
     */
    ubyte2 ikeEncrAlgo;     /* OAKLEY encryption algorithm attribute [v1] */
    /**
     * @private
     * @internal
     */
    ubyte2 ikeEncrKeyLen;   /* encryption algo key length (in bytes); 0 if fixed-length */
    /**
     * @private
     * @internal
     */
    ubyte2 ikeSigMtd;       /* OAKLEY authentication method [v1] */
    /**
     * @private
     * @internal
     */
    ubyte2 ikeSigKeyLen;    /* signature algorithm key length (in bytes); 0 for ECDSA? */

/**
@brief      Determine whether a connection instance is a GDOI server
            connection; that is, a Group Controller/Key Server (GCKS).

@details    This callback function determines whether a connection instance
            is a GDOI server connection; that is, a Group Controller/Key
            Server (GCKS).

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 6.0
@version 6.0 and later

@flags
To enable this callback function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_GDOI_SERVER__

@param result           On return, pointer to boolean value (\c TRUE or \c
                          FALSE).
@param serverInstance   Application-specific identifier.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    ike.h
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This callback is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIsKeyServer)(intBoolean *result, sbyte4 serverInstance);
#endif

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Handle a status change in the host IKE server.

@details    This callback function handles notification of status change
            within the local host IKE server.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@note       For detailed information about when this callback is invoked, and
            about the \p cat and \p type parameters, refer to the
            @moc_doc_NanoSec_xref.

@note       If your custom callback function uses excessive processing time,
            performance may be degraded. If many tasks must be performed by
            the callback, the tasks should be assigned to a different context
            (thread). Additionally, your callback should not invoke top-level
            functions (those defined in ike.h) directly. For an implementation
            example, refer to the sample code in @ref ike_example.c.

@ingroup    ike_callback_functions

@since 4.0
@version 4.0 and later

@flags
No flag definitions are required to enable this callback.

@param cat      Any of the \c IKE_STATUS_CATEGORY enumerated values (see
                  ike_status.h).
@param type     Any of the \c IKE_STATUS_TYPE enumerated values (see
                  ike_status.h).
@param id       Identification number.
@param data1    Pointer to primary structure of interest.
@param data2    Pointer to secondary structure of interest.

@remark     This callback function can be used for loggings or alarms;
            implementation is optional.

@callbackdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This callback is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
    void (*funcPtrIkeStatHdlr)(sbyte4 cat, sbyte4 type, ubyte4 id,
                               void *data1, void *data2);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Determine whether a given peer ip/port is a valid configuration.

@details    This callback function determines whether a given peer ip/port
            is a valid configuration.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 5.8
@version 5.8 and later

@flags
No flag definitions are required to enable this callback.

@param config           Peer configuration object to check.
@param peerAddr         Peer IP address.
@param wPeerPort        Peer IKE server's port number.
@param serverInstance   Server instance, identifying a unique socket to
                        use. This argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.

@return     \c TRUE if successful; otherwise \c FALSE.

@remark     You must implement this callback function if user-defined
            configurations are used.

@callbackdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This callback (and all peer-related callbacks) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */
    byteBoolean (*funcPtrIsConfigForPeer)(struct ikePeerConfig *config,
                                          MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                                          sbyte4 serverInstance);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Send an IKE exchange message to a peer IKE server.

@details    This callback function sends an IKE exchange message to a peer IKE
            server.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 1.41
@version 3.06 and later

@flags
No flag definitions are required to enable this callback.

@note       Your custom callback function should transmit the message (via
            UDP) without inspecting the message contents.

@note       For an implementation example, refer to the sample code in
            @ref ike_example.c.

@param peerAddr         Peer IP address.
@param wPeerPort        Peer IKE server's port number.
@param pBuffer          Pointer to outbound message.
@param dwBufferSize     Number of bytes in outbound message (\p pBuffer).
@param serverInstance   Server instance, identifying a unique socket to
                        use. This argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.
@param bUseNattPort     \c TRUE to send the message through the NAT-T
                        port (that is, 4500); otherwise \c FALSE. This
                        argument applies only if the \c
                        \__ENABLE_IPSEC_NAT_T__ flag is defined; otherwise it
                        should be ignored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     You must always implement this callback function.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkeXchgSend)(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                                 ubyte *pBuffer, ubyte4 dwBufferSize,
                                 sbyte4 serverInstance,
                                 intBoolean bUseNattPort);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Send a unidirectional IPsec/IKE event to its host IKE server.

@details    This callback function sends a unidirectional IPsec/IKE event to
            its host IKE server. It is invoked from the IPsec layer.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@note       Your custom callback function should transmit the event to a local
            socket associated with the host IKE server (instad of calling
            IKE_msgRecv()).

@note       For an implementation example, refer to the sample code in
            @ref ike_example.c.

@ingroup    ike_callback_functions

@since 1.41
@version 3.2 and later

@flags
No flag definitions are required to enable this callback.

@param pBuffer      Pointer to the IPsec/IKE event.
@param dwBufferSize Number of bytes in the IPsec/IKE event (\p pBuffer).
@param hostAddr     Host IP address (host byte order); may be ignored if
                    the \c \__IKE_MULTI_HOMING__ flag is not defined in
                    moptions.h.
@param cookie       Application-provided cookie; may be ignored if the
                    \c \__ENABLE_IPSEC_COOKIE__ flag is not defined in
                    moptions.h.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     You must always implement this callback function.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkeEvtSend)(ubyte *pBuffer, ubyte4 dwBufferSize,
                                MOC_IP_ADDRESS hostAddr, ubyte4 cookie);

#ifdef __ENABLE_IPSEC_NAT_T__
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Perform NAT-T UDP encapsulation and send of an IP packet payload.

@details    This callback function perforsm NAT-T UDP encapsulation of an IP
            packet payload, and sends the resulting packet.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 1.41
@version 3.06 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_IPSEC_NAT_T__

@param peerAddr         Peer IP address.
@param wPeerPort        Peer IKE server's NAT-T port number.
@param pBuffer          Pointer to outbound IP packet payload to encapsulate.
@param dwBufferSize     Number of bytes in payload (\p pBuffer).
@param hostAddr         Host IP address; may be ignored if the
                        \c \__IKE_MULTI_HOMING__ flag is not defined in
                        moptions.h.
@param cookie           Application-provided cookie; may be ignored if the
                        \c \__ENABLE_IPSEC_COOKIE__ flag is not defined in
                        moptions.h.

@return     Any of the following:
+ If message successfully encapsulated and sent, \c OK (0).
+ If an error resulted, a negative number error code definition from
    merrors.h. To retrieve a string containing an English text error identifier
    corresponding to the function's returned error status, use the \c DISPLAY_ERROR macro.
+ A positive number specifying the host IKE server's NAT-T port number.

@remark     This callback function is used only in rare cases; implementation
            is optional.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkeNattSend)(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                                 ubyte *pBuffer, ubyte4 dwBufferSize,
                                 MOC_IP_ADDRESS hostAddr, ubyte4 cookie);
#endif

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Get the host IKE server's IP address.
@details    This callback function gets the host IKE server's IP address.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@note       If the \c \__IKE_MULTI_HOMING__ flag is not defined but multiple
            interfaces exist, your callback function must correctly return the
            sole IP address that is involved in the IKE negotiation.

@ingroup    ike_callback_functions

@since 1.41
@version 3.06 and later

@flags
No flag definitions are required to enable this callback.

@param pHostAddr        On return, pointer to host IP address.
@param serverInstance   Application-specific identifier. This
                        argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     You must always implement this callback function.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkeGetHostAddr)(MOC_IP_ADDRESS_S *pHostAddr,
                                    sbyte4 serverInstance);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Get the host IKE server's port number.
@details    This callback function gets the host IKE server's port number.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@param pwPort           On return, pointer to host port number.
@param bUseNatt         Specifies if the NAT-Traversal port should be returned.
@param serverInstance   Application-specific identifier. This
                        argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     If this callback function is not implemented, standard ports are
            assumed, i.e. 500 and 4500.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkeGetHostPort)(ubyte2 *pwPort, intBoolean bUseNatt,
                                    sbyte4 serverInstance);

#ifdef __ENABLE_IPSEC_COOKIE__
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Get an application-provided cookie; for example, VLan id.

@details    This callback function retrieves an application-provided cookie;
            for example, VLan id.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@note       Support for application-provided cookies is an advanced NanoSec
            IPsec/IKE feature that is rarely used.

@todo_eng_review (clarify the "rarely used" note: why is it rare; why is that
                  relevant to the user?)

@ingroup    ike_callback_functions

@since 1.41
@version 3.2 and later

@flags
To enable this callback function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_IPSEC_COOKIE__

@param pCookie          On return, pointer to custom cookie value.
@param serverInstance   Application-specific identifier.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     If the \c \__ENABLE_IPSEC_COOKIE__ flag is defined, you must
            implement this callback function.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkeGetCookie)(ubyte4 *pCookie, sbyte4 serverInstance);


/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Get an application-provided tunnel endpoint address given cookie and ifid.

@details    This callback function retrieves tunnel endpoint addresses for a given
            cookie and ifid. This function is called by IPSEC, if the SPD entry
            points to tunnel mode , but tunnel endpoint address is not configured.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@note       Support for application-provided tunnel endpoint addresses is an advanced NanoSec
            IPsec/IKE feature that is rarely used.

@ingroup    ike_callback_functions

@version 6.5 and later

@flags
To enable this callback function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_IPSEC_COOKIE__

@param  pTunDestIP      On return, pointer to destionation IP of tunnel endpoint
@param  pTunSrcIP       On return, pointer to source IP of tunnel endpoint
@param  ifid            interface id on which the outbound packet has arrived
@param pCookie          application specific cookie value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.


@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */


    sbyte4 (*funcPtrIpsecGetTunnelIP)(MOC_IP_ADDRESS *pTunDestIP,
                              MOC_IP_ADDRESS *pTunSrcIP, sbyte4 ifid, ubyte4 cookie);
#endif


#ifdef __ENABLE_IPSEC_INTERFACE_ID__
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Get IKE server's target interface.
@details    This callback function gets an IKE server's target interface's ID.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_IPSEC_INTERFACE_ID__

@param pIfId            On return, pointer to IKE server's target interface ID.
@param peerAddr         Peer IP address.
@param serverInstance   Application-specific identifier. This
                        argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrGetInterfaceId)(sbyte4 *pIfId,
                                MOC_IP_ADDRESS peerAddr, sbyte4 serverInstance);
#endif

#ifdef __IKE_MULTI_THREADED__
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Get the thread ID associated with given IKE header information.
@details    This callback function gets the thread ID that is associated with
            the given IKE message header information.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 6.5.1
@version 6.5.1 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__IKE_MULTI_THREADED__

@param pTid             On return, pointer to the associated thread ID.
@param poCkyI           Pointer to IKE message header Initiator SPI value.
@param version          IKE message header version (either 1 or 2).
@param bInitiator       Specifies if IKEv2 message header Initiator bit is set
                        (not applicable in IKEv1).
@param serverInstance   Application-specific identifier. This
                        argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     If this callback function is not implemented, IKE applications will
            not be able to initiate phase 1 negotiations and IKEv2 applications
            cannot rekey existing IKE SA's.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkeGetThreadId)(RTOS_THREAD *pTid,
                                    const ubyte *poCkyI,/* IKE_COOKIE_SIZE(8) */
                                    sbyte4 version,      /* 1 or 2 */
                                    intBoolean bInitiator,/* Am I initiator? */
                                    /* Note: IKEv1 message does not use
                                       IKE_FLAG_INITIATOR bit in its flags! */
                                    sbyte4 serverInstance);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Send data to a given thread for processing.
@details    This callback function sends internal data to a thread (associated
            with the given ID) for further processing.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 6.5.1
@version 6.5.1 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__IKE_MULTI_THREADED__

@param tid              ID associated with the target thread.
@param data             Pointer to data that is to be processed in the context
                        of the given thread. Note that the scope of this data
                        will not be retained (i.e. implementation must not keep
                        a reference but rather make a copy if necessary).
@param size             Total size of the given data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     If the \c \__IKE_MULTI_THREADED__ flag is defined, you must
            implement this callback function.

@note       Your IKE application servers should call IKE_dpcRecv() in the target
            thread's context upon receiving the given data.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkeThreadSend)(RTOS_THREAD tid, ubyte *data, ubyte4 size);
#endif

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Get a RADIUS passthrough server's ID.

@details    This callback function gets a RADIUS passthrough server's ID,
            returning it through the pRadSvrId parameter. (For detailed usage
            information, refer to the @ref ike_example.c sample file.)

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 3.06
@version 3.06 and later

@flags
To enable this callback, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__
+ \c \__ENABLE_DIGICERT_EAP_RADIUS__
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@param pRadSvrId        On return, pointer to passthrough server's ID.
@param radInstId        RADIUS instance ID (created interally by IKE).
@param poUser           Pointer to buffer containing EAP identity.
@param dwUserLen        Number of bytes in EAP identity buffer (\p poUser).
@param peerAddr         Peer IP address.
@param serverInstance   Application-specific identifier. This
                        argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkeGetRadSvrId)(sbyte4 *pRadSvrId, sbyte4 radInstId,
                                    const ubyte *poUser, ubyte4 dwUserLen,
                                    MOC_IP_ADDRESS peerAddr,
                                    sbyte4 serverInstance);
#endif

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__) && \
    defined(__ENABLE_DIGICERT_EAP_TLS__)
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Get an EAP TLS certificate store.

@details    This callback function gets a certificate store for IKEv2 EAP
            TLS-based authentication, e.g. EAP-TTLS. (For detailed usage
            information, refer to the @ref ike_example.c sample file.)

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 6.5.2
@version 6.5.2 and later

@flags
To enable this callback, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

@param ppCertStore      On return, pointer to a TLS certificate store.
@param ppCertCommonName On return, pointer to the common name string of the
                        TLS server certificate.
@param poUser           Pointer to buffer containing EAP identity.
@param dwUserLen        Number of bytes in the EAP identity buffer (\p poUser).
@param peerAddr         Peer IP address.
@param serverInstance   Application-specific identifier. This
                        argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkeGetTlsCertStore)(struct certStore **ppCertStore,
                                        sbyte **ppCertCommonName,
                                        const ubyte *poUser, ubyte4 dwUserLen,
                                        MOC_IP_ADDRESS peerAddr,
                                        sbyte4 serverInstance);
#endif

#ifdef __ENABLE_IKE_MODE_CFG__
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Set attributes from an IKE Attribute SET payload (for Mode Config).

@details    This callback function sets attributes from an IKE Attribute SET
            payload. For detailed information about the set-acknowledge
            sequence and the configuration structure fields, refer
            to RFC&nbsp;4306
            (ftp://ftp.rfc-editor.org/in-notes/pdfrfc/rfc4306.txt.pdf),
            particularly section 3.15.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 3.2
@version 4.0 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_IKE_MODE_CFG__

@param ppoCfgAck        On return, pointer to configuration attributes to
                        be used in acknowledge body.
@param pwCfgAckLen      On return, pointer to number of bytes in the acknowledge
                        message (\p *ppoCfgAck).
@param poCfgSet         Pointer to set body containing configuration attributes.
@param wCfgSetLen       Number of bytes in set body (\p poCfgSet).
@param poId             Pointer to ID returned from peer's identification
                        payload.
@param wIdLen           Number of byes in ID (\p poId).
@param idType           Any of the \c IKE_ID_T enumerated values (see
                        ike_defs.h).
@param peerAddr         Peer IP address.
@param serverInstance   Application-specific identifier. This
                        argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.
@param data             Pointer to structure of interest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkePutCfg)(ubyte **ppoCfgAck, ubyte2 *pwCfgAckLen,
                               ubyte *poCfgSet, ubyte2 wCfgSetLen,          /* Config. Attrs. (i.e. ATTR SET body) */
                               ubyte *poId, ubyte2 wIdLen, sbyte4 idType,   /* peer ID; see IKE_ID_T in "ike_defs.h" */
                               MOC_IP_ADDRESS peerAddr,
                               sbyte4 serverInstance,
                               void *data);

#endif /*__ENABLE_IKE_MODE_CFG__ */

#if defined(__ENABLE_IKE_CP__) || defined(__ENABLE_IKE_MODE_CFG__)
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Extract response attributes from IKEv2 configuration payload.

@details    This callback function extracts response attributes from an IKEv2
            configuration payload. For detailed information about the
            request-response sequence and the configuration structure fields,
            refer to RFC&nbsp;4306
            (ftp://ftp.rfc-editor.org/in-notes/pdfrfc/rfc4306.txt.pdf),
            particularly section 3.15.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 3.06
@version 4.0 and later

@flags
To enable this callback, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_IKE_CP__
+ \c \__ENABLE_IKE_MODE_CFG__

@param ppoCfgResp       On return, pointer to configuration attributes to
                        be used in response body.
@param pwCfgRespLen     On return, pointer to number of bytes in the response
                        message (\p *ppoCfgResp).
@param poCfgReq         Pointer to request body containing configuration
                        attributes.
@param wCfgReqLen       Number of bytes in request body (\p poCfgReq).
@param poId             Pointer to ID returned from peer's identification
                        payload.
@param wIdLen           Number of byes in ID (\p poId).
@param idType           Any of the \c IKE_ID_T enumerated values (see
                        ike_defs.h).
@param identity         Pointer to EAP identity.
@param id_len           Number of bytes in EAP identity (\p identity).
@param peerAddr         Peer IP address.
@param wPeerPort        Peer IKE port. Zero (0) if peer is not behind NAT or
                        the \c \__ENABLE_IPSEC_NAT_T__ flag is not defined.
@param serverInstance   Application-specific identifier. This
                        argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.
@param data             Pointer to structure of interest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkeGetCfg)(ubyte **ppoCfgResp, ubyte2 *pwCfgRespLen,
                               ubyte *poCfgReq, ubyte2 wCfgReqLen,          /* Config. Attrs. (i.e. ATTR REQUEST body) */
                               ubyte *poId, ubyte2 wIdLen, sbyte4 idType,   /* peer ID (e.g. [v2] IDi); see IKE_ID_T in "ike_defs.h" */
                               ubyte *identity, ubyte4 id_len,              /* [v2] EAP identity or [v1] XAUTH client username (TBD) */
                               MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                               sbyte4 serverInstance,
                               void *data);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Free memory previously allocated for response or acknowledgement
            configuration attributes.

@details    This callback function frees memory peviously allocated by
            \p ikeSettings::funcPtrIkeGetCfg for response configuration
            attributes (the \p ppoCfgResp parameter) or by
            \p ikeSettings::funcPtrIkePutCfg for acknowledgement configuration
            attributes (the \p ppoCfgAck parameter).

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 3.06
@version 3.06 and later

@flags
To enable this callback, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_IKE_CP__
+ \c \__ENABLE_IKE_MODE_CFG__

@param pCfgAttrs    Pointer to memory to free.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    void (*funcPtrIkeReleaseCfg)(void *pCfgAttrs);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Retrieve attributes to initiate an IKE Configuration Transaction
            (Mode Config).

@details    This callback function retrieves attributes to construct an IKE
            \c Attribute \c REQUEST or \c SET payload, which is then used by
            IKE server to initiate a Configuration Transaction (Mode Config).
            For detailed information about the request-response
            (or set-acknowledge) sequence and the configuration structure
            fields, refer to RFC&nbsp;4306
            (ftp://ftp.rfc-editor.org/in-notes/pdfrfc/rfc4306.txt.pdf),
            particularly section 3.15.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 4.0
@version 4.0 and later

@flags
To enable this callback, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_IKE_CP__
+ \c \__ENABLE_IKE_MODE_CFG__

@param ppoCfg_I     On return, pointer to configuration attributes to
                    be used in transaction message (\p Attribute payload body).
@param pwCfgLen_I   On return, pointer to number of bytes in the transaction
                    message (\p *ppoCfg_I).
@param poCfgType    On return, pointer to transaction type (REQUEST or SET).
@param wCfgId       Configuration Transaction identifier.
@param dwIkeId      IKE_SA internal identification number.
@param data         Pointer to structure of interest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkeInitCfg)(ubyte **ppoCfg_I, ubyte2 *pwCfgLen_I,   /* [output] Config. Attrs. (ATTR body) */
                                ubyte *poCfgType,                       /* [output]             REQUEST or SET */
                                ubyte2 wCfgId,                          /* transaction identifier */
                                ubyte4 dwIkeId, void *data);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Process attributes returned from an IKE Configuration Transaction
            (Mode Config).

@details    This callback function processes attributes in an IKE \c Attribute
            \c RESPONSE or \c ACK payload, which is returned from a
            previously initiated Configuration Transaction (Mode Config). For
            detailed information about the request-response
            (or set-acknowledge) sequence and the configuration structure
            fields, refer to RFC&nbsp;4306
            (ftp://ftp.rfc-editor.org/in-notes/pdfrfc/rfc4306.txt.pdf),
            particularly section 3.15.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 4.0
@version 4.0 and later

@flags
To enable this callback, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_IKE_CP__
+ \c \__ENABLE_IKE_MODE_CFG__

@param poCfg_R      Pointer to \c Attribute payload body containing
                    configuration attributes.
@param wCfgLen_R    Number of bytes in \c Attribute payload body(\p poCfg_R).
@param wCfgId       Configuration Transaction identifier.
@param dwIkeId      IKE_SA internal identification number.
@param data         Pointer to structure of interest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrIkeRespCfg)(const ubyte *poCfg_R, ubyte2 wCfgLen_R, /* Config. Attrs. (ATTR RESPONSE or ACK body) */
                                ubyte2 wCfgId,                          /* transaction identifier */
                                ubyte4 dwIkeId, void *data);

#endif /* defined(__ENABLE_IKE_CP__) || defined(__ENABLE_IKE_MODE_CFG__) */

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Retrieve the trust anchor from certificate store that validates an
            incomplete certificate chain.

@details    This callback function retrieves the trust anchor from certificate
            store that validates an incomplete certificate chain.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 6.5.4
@version 6.5.4 and later

@flags
No flag definitions are required to enable this callback.

@param serverInstance       Pointer to the IKE server instance.
@param pCertificate         Pointer to the X.509 certificate (of trust anchor).
@param certificateLen       Number of bytes in X.509 certificate of interest
                            (\p pCertificate).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     If IKE is configured to use digital certificates for
            authentication, you should define and customize this hookup
            function for your application.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrCertificateAnchorTest) (sbyte4 serverInstance,
                                            const ubyte *pCertificate,
                                            ubyte4 certificateLen);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Verify an intermediate certificate in a chain.

@details    This callback function verifies an intermediate certificate (neither
            the leaf/first nor root/last) in a certificate chain.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 4.2
@version 4.2 and later

@flags
No flag definitions are required to enable this callback.

@param serverInstance       Pointer to the IKE server instance.
@param pCertificate         Pointer to the X.509 certificate in the
                            certificate chain of interest.
@param certificateLen       Number of bytes in X.509 certificate of interest
                            (\p pCertificate).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     If IKE is configured to use digital certificates for
            authentication, you should define and customize this hookup
            function for your application.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrCertificateChainTest)   (sbyte4 serverInstance, ubyte *pCertificate, ubyte4 certificateLen);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Verify that the leaf (first certificate in a chain) is an
            acceptable, known certificate.

@details    This callback function verifies that the leaf (first certificate
            in a chain) is an acceptable, known certificate.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions
@since 4.2
@version 4.2 and later

@flags
No flag definitions are required to enable this callback.

@param serverInstance       Pointer to the IKE server instance.
@param pxSa                 IKE_SA (internal use only).
@param pCertificate         Pointer to the first X.509 certificate in the
                            certificate chain of interest.
@param certificateLen       Number of bytes in X.509 certificate of interest
                            (\p pCertificate).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     If IKE is configured to use digital certificates for
            authentication, you should define and customize this hookup
            function for your application.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrCertificateLeafTest)    (sbyte4 serverInstance,
                                             struct ikesa *pxSa,
                                             ubyte *pCertificate,
                                             ubyte4 certificateLen);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Verify the root (last) certificate in a chain.

@details    This callback function verifies the root certificate in a
            certificate chain.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 6.5.4
@version 6.5.4 and later

@flags
No flag definitions are required to enable this callback.

@param serverInstance       Pointer to the IKE server instance.
@param pCertificate         Pointer to the X.509 certificate in the
                            certificate chain of interest.
@param certificateLen       Number of bytes in X.509 certificate of interest
                            (\p pCertificate).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     If IKE is configured to use digital certificates for
            authentication, you should define and customize this hookup
            function for your application.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrCertificateRootTest) (sbyte4 serverInstance,
                                          ubyte *pCertificate,
                                          ubyte4 certificateLen);

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Verify the given password for a specific user.

@details    This callback function verifies the validity of the password
            provided by peer EAP supplicant for a certain user (i.e. EAP
            identity). This function is best-suited for EAP methods that carry
            clear-text passwords, e.g. EAP-GTC.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 6.5.3
@version 6.5.3 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@note       For an implementation example, refer to the sample code in
            @ref ike_example.c.

@param poUsername       Pointer to buffer containing user name or EAP identity.
@param dwUsernameLen    Number of bytes in the user name buffer (\p poUsername).
@param poPassword       Pointer to buffer containing clear-text password.
@param dwPasswordLen    Number of bytes in the password buffer (\p poPassword).
@param serverInstance   Application-specific identifier. This argument applies
                        only if the \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrVerifyPassword) (const ubyte *poUsername, ubyte4 dwUsernameLen,
                                     const ubyte *poPassword, ubyte4 dwPasswordLen,
                                     sbyte4 serverInstance);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Obtain the stored secret of a given EAP identity.

@details    This callback function finds the stored secret associated with a
            certain idenity (specified by peer EAP supplicant). The returned
            secret is typically a clear-text password for most EAP methods.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 6.5.3
@version 6.5.3 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@note       For an implementation example, refer to the sample code in
            @ref ike_example.c.

@param poIdentity       Pointer to buffer containing peer EAP identity.
@param dwIdentityLen    Number of bytes in the EAP identity buffer (\p
                        poIdentity).
@param ppoSecret        On return, pointer to buffer of the secret.
@param pdwSecretLen     On return, pointer to number of bytes in the secret
                        buffer (\p *ppoSecret).
@param serverInstance   Application-specific identifier. This argument applies
                        only if the \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     For EAP-SIM, the returned secret must be a concatenation of
            sequences of octets representing GSM triplets (RAND, SRES, Kc).
            See [RFC4186].

@remark     For EAP-AKA, the returned secret must be a sequence of octets
            representing an authentication vector (RAND, AUTN, CK, IK, RES).
            See [RFC4187].

@remark     Be sure to implement the \p ikeSettings::funcPtrReleaseSecret
            callback function where appropriate (e.g. zeroization and/or
            de-allocation).

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 documentation.
 * @endcond
 */
    sbyte4 (*funcPtrLookupSecret) (const ubyte *poIdentity, ubyte4 dwIdentityLen,
                                   ubyte **ppoSecret, ubyte4 *pdwSecretLen,
                                   sbyte4 serverInstance);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Release secret previously obtained for a given EAP identity.

@details    This callback function zeroizes and/or frees memory peviously
            allocated by \p ikeSettings::funcPtrLookupSecret for the returned
            buffer (the \p ppoSecret parameter) containing the secret.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 6.5.3
@version 6.5.3 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@note       For an implementation example, refer to the sample code in
            @ref ike_example.c.

@param poSecret         Pointer to buffer of the secret to release.
@param dwSecretLen      Number of bytes in the secret buffer (\p poSecret).
@param serverInstance   Application-specific identifier. This argument applies
                        only if the \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 documentation.
 * @endcond
 */
    sbyte4 (*funcPtrReleaseSecret) (ubyte *poSecret, ubyte4 dwSecretLen,
                                    sbyte4 serverInstance);

#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Obtain the user credential.

@details    This callback function is called when information must be provided
            by the user as per request by peer EAP authenticator. The returned
            credential is typically in clear-text such as a password, pin, or
            RSA SecurId token.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 5.4
@version 5.4 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@note       For an implementation example, refer to the sample code in
            @ref ike_example.c.

@param poData           Pointer to buffer containing EAP method-specific data
                        provided by peer EAP authenticator, e.g. EAP-GTC message
                        to be displayed to the user such as "Enter SecurId Token
                        Code".
@param dwDataLen        Number of bytes in the data buffer (\p poData).
@param ppoCredential    On return, pointer to buffer of the credential. The
                        callback function implementation must allocate memory
                        for this buffer and copy the credential value into the
                        argument. The caller module frees the memory.
@param pdwCredLen       On return, pointer to number of bytes in the credential
                        buffer (\p *ppoCredential).
@param serverInstance   Application-specific identifier. This argument applies
                        only if the \c \__IKE_MULTI_HOMING__flag is defined;
                        otherwise it should be ignored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     For EAP-SIM, the given data is a concatenation of multiple RAND
            octets from (RAND, SRES, Kc) GSM triplets, while the returned
            credential must be a concatenation of matching (SRES, Kc) octets.
            See [RFC4186].

@remark     For EAP-AKA, the given data is a sequence of octets representing the
            (RAND, AUTN) portion of an authentication vector
            (RAND, AUTN, CK, IK, RES), while the returned credential must be a
            sequence of octets representing a matching (CK, IK, RES). See
            [RFC4187].

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
   documentation.
 * @endcond
 */
    sbyte4 (*funcPtrGetToken)   (ubyte *poData, ubyte4 dwDataLen,
                                 ubyte **ppoCredential, ubyte4 *pdwCredLen,
                                 sbyte4 serverInstance);
#endif

#ifdef __ENABLE_IKE_MULTI_AUTH__
    /**
     @brief     Controls if IKEv2 multiple authention exchange is enabled.
     @details   Controls whether IKEv2 multiple authention exchange is enabled
                (default is \c FALSE).
     @note      This field is defined only if the
                \c \__ENABLE_IKE_MULTI_AUTH__ flag is defined.
     */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This function (and IKEv2 functions) is not applicable
     * for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    intBoolean bDoMultiAuth;

    /**
     @brief     Required peer authentication methods.
     @details   Required peer authentication methods (0=unspecified) as
                either initiator or responder.
     @note      This field is defined only if the
                \c \__ENABLE_IKE_MULTI_AUTH__ flag is defined.
     */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This function (and IKEv2 functions) is not applicable
     * for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    sbyte4 reqInAuthMtds[2];  /* required peer auth method(s) [I, R] */
#endif

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    /**
     @brief     IKEv2 EAP identity.
     @details   IKEv2 EAP identity string (default is \c NULL) used during EAP
                exchanges.
     @note      This field is defined only if either the
                \c \__ENABLE_DIGICERT_EAP_AUTH__ flag or the
                \c \__ENABLE_DIGICERT_EAP_PEER__ flag is defined.
     */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This function (and IKEv2 functions) is not applicable
     * for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    sbyte *eapIdentity;

#ifdef __ENABLE_IKE_EAP_ONLY__
    /**
     @brief     Controls if IKEv2 EAP-only authentication is enabled.
     @details   Controls whether IKEv2 EAP-only authentication is enabled
                (default is \c FALSE).
     @note      This field is defined only if the
                \c \__ENABLE_IKE_EAP_ONLY__ flag is defined and either the
                \c \__ENABLE_DIGICERT_EAP_AUTH__ flag or the
                \c \__ENABLE_DIGICERT_EAP_PEER__ flag is also defined.
     */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This function (and IKEv2 functions) is not applicable
     * for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    intBoolean bDoEapOnly; /* applicable only if EAP protocol is set (see below) */
#endif
#endif

    /* [v2] EAP protocol(s); see IKE_EAP_PROTO_T in "ike_defs.h" */
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    /**
     @brief     IKEv2 EAP authenticator negotiation protocol.
     @details   IKEv2 EAP authenticator negotiation protocol: any of the
                \c IKE_EAP_PROTO_T enumerated values (see ike_defs.h).
     @note      This field is defined only if the
                \c \__ENABLE_DIGICERT_EAP_AUTH__ flag is defined.
    */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This function (and IKEv2 functions) is not applicable
     * for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    sbyte4 eapProtoAuth; /* we are the authenticator */

/*
(doc note: for Atlas; AAA/IKEv2)
*/
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__
@coming_soon
@ingroup    ike_callback_functions
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function (and IKEv2 functions) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */
    sbyte4 (*funcPtrInteractWithAAAEAP)(ubyte *eapTrans,
                                        sbyte **perp,
                                        EAPPERP_aaaCallbackFun aaaCallback);
#endif

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    /**
     @brief     IKEv2 EAP supplicant negotiation protocol.
     @details   IKEv2 EAP supplicant negotiation protocol: any of the
                \c IKE_EAP_PROTO_T enumerated values (see ike_defs.h).
     @note      This field is defined only if the
                \c \__ENABLE_DIGICERT_EAP_PEER__ flag is defined.
     */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This function (and IKEv2 functions) is not applicable
     * for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    sbyte4 eapProtoPeer; /* we are the supplicant */

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    /**
     @brief     IKEv2 EAP-TTLS supplicant Stage 2 method type.
     @details   IKEv2 EAP-TTLS supplicant Stage 2 authentication method type:
                any of the \c eapTTLSMethodType enumerated values (see
                eap/eap_ttls.h; default is \c EAP_METHOD_TYPE_EAP).
     @note      This field is defined only if the
                \c \__ENABLE_DIGICERT_EAP_PEER__ flag and the
                \c \__ENABLE_DIGICERT_EAP_TTLS__ flag are defined.
     */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This function (and IKEv2 functions) is not applicable
     * for NanoMCP, so omit from the API documentation.
     * @endcond
     */
    sbyte4 eapTtlsType; /* see 'eapTTLSMethodType' in "eap/eap_ttls.h" */
#endif

/*
(doc note: for MAP (Atlas client))
*/
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__
@coming_soon
@ingroup    ike_callback_functions
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function (and IKEv2 functions) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */
    sbyte4 (*funcPtrInteractWithUsereap)(void* eapperpTrans, ubyte *perp,
                                         ubyte **Outperp, ubyte **perplen,
                                         EAPPERP_userCallbackFun eapperpcb);
#endif

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Utilize OOB (out-of-band) protocols to obtain a peer certificate's
            revocation status.

@details    This callback function is invoked when certificate-based
            authentication is employed and the revocation status of a peer's
            certificate is unknown.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 5.8
@version 5.8 and later

@flags
No flag definitions are required to enable this callback.

@param pCertificates    Array (chain) of certifictes to check.
@param numCertificates  Number of certificates in the chain (\p pCertificates).
@param certCallback     Pointer to a function that can be called
                        to supply the result asynchronously. (See
                        CERT_statusCallbackFun().)
@param cbData           Pointer to data for \p certCallback.
@param serverInstance   Application-specific identifier. This
                        argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.
@param pxSa             (Internal use only) IKE_SA.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     If OOB peer certificate status checking is desired, you should
            define and customize this callback function for your
            application. If your function will immediately (synchronously)
            return the result, you can ignore the \p certCallback and
            \p cbData parameters. If the function returns a status of
            \c STATUS_IKE_PENDING, you \em SHOULD call the callback later to
            return the result. If you do not call the callback later, you
            must manually free the allocated memory for \p cbData.

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function (and IKEv2 functions) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */
    sbyte4 (*funcPtrCertStatusCheck)(struct certDescriptor *pCertificates,
                                     sbyte4 numCertificates,
                                     CERT_statusCallbackFun certCallback,
                                     void *cbData,
                                     sbyte4 serverInstance, struct ikesa *pxSa);

#ifdef __ENABLE_IKE_XAUTH__
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Interact with user to obtain some authentication information.

@details    This callback function is called when information must be shown to
            or provided by the user (typically user name, password or pin).

Any of the arguments can be NULL. Zero or more of userame, password,
passCode, nextPin or answer can be requested. For required parameters (which
must be provided by the user), the parameter must be non-NULL, and it must
point to a NON-NULL value. Otherwise the value can be omitted. If your
function will return the required parameters through the callback, you do
not need to copy the value of the string arguments; they remain valid until
you call the callback. If the function returns a status of \c
STATUS_IKE_PENDING, you \b MUST call the callback to release the allocated
memory.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 4.0
@version 4.0 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_IKE_XAUTH__

@param xauthTrans   Pointer to the XAUTH transaction.
@param userName     Pointer to NULL-terminated sbyte array that
                    contains the user name.
@param password     Pointer to NULL-terminated sbyte array that
                    contains the password.
@param passCode     Pointer to NULL-terminated sbyte array that
                    contains the passcode.
@param nextPin      Pointer to NULL-terminated sbyte array that
                    contains the next pin.
@param answer       Pointer to NULL-terminated sbyte array that
                    contains the answer.
@param message      NULL-terminated sbyte array that contains
                    a message for the user.
@param domain       NULL-terminated sbyte array that contains
                    the domain for the authentication.
@param userCallback Pointer to a function that can be called
                    to supply the information. (See XAUTH_userCallbackFun().)
@param serverInstance   Application-specific identifier. This
                        argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.

@return     + \c OK (0) if successful;
            + STATUS_IKE_PENDING to indicate that the information will be
              provided by a subsequent call to \p userCallback;
            + otherwise a negative number error code definition from
              merrors.h. To retrieve a string containing an English text
              error identifier corresponding to the function's returned error
              status, use the \c DISPLAY_ERROR macro.

@remark     If IKE is configured to use the XAUTH IKE extension, you should
            define and customize this hookup function for your application.

@todo_techpubs (maybe add text explaining known issue with the "#ifdef" in
                the function signature appearing in the Doxygen output)

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
    sbyte4 (*funcPtrInteractWithUser)(void *xauthTrans,
                    sbyte **userName, sbyte **password,
                    sbyte **passCode, sbyte **nextPin, sbyte **answer,
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                    sbyte **perp,
#endif
                    const sbyte *message, const sbyte *domain,
                    XAUTH_userCallbackFun userCallback,
                    sbyte4 serverInstance);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Interact with AAA subsystem to authenticate credentials.

@details    This callback function interacts with the AAA subsystem to
            authenticate credentials.

Any of the arguments can be NULL. Zero or more of userame, password,
passCode, nextPin or answer can be requested. If your function will return
the required parameters through the callback, you do not need to copy the
value of the string arguments; they remain valid until you call the
callback. If the function returns a status of \c STATUS_IKE_PENDING, you \b
MUST call the callback to release the allocated memory.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    ike_callback_functions

@since 5.8
@version 5.8 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_IKE_XAUTH__

@param xauthTrans   Pointer to the XAUTH transaction.
@param cfgId        Configuration Transaction identifier (per IKE_SA).
@param userName     Pointer to array of NULL-terminated sbytes that
                    contains the user name.
@param password     Pointer to array of sbytes that contains the password.
@param passwordLen  Length of the above array that contains the password, if
                    any.
@param passCode     Pointer to array of NULL-terminated sbytes that
                    contains the passcode.
@param nextPin      Pointer to array of NULL-terminated sbytes that
                    contains the next pin.
@param answer       Pointer to array of NULL-terminated sbytes that
                    contains the answer.
@param message      Array of NULL-terminated sbytes that contains
                    a message for the user.
@param domain       Array of NULL-terminated sbytes that contains
                    the domain for the authentication.
@param challenge    Pointer to array of sbytes that contains the challenge.
@param challengeLen Length of the above array that contains the challenge, if
                    any.
@param cfgType      On return, indicating further action; that is, \c SET or
                    \c REQUEST.
@param result       On return,
                      + For \c SET, in the event that the AAA request can be
                        validated without waiting (synchronously) on the
                        domain for the authentication: 1 (pass) or 0 (fail).
                      + For \c REQUEST, the authentication type for the next
                        transaction exchange.
@param aaaCallback  Pointer to a function that can be called
                    to supply the information. (See XAUTH_aaaCallbackFun().)
@param serverInstance   Application-specific identifier. This
                        argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.

@return     + \c OK (0) if successful;
            + STATUS_IKE_PENDING to indicate that the information will be
              provided by a subsequent call to \p aaaCallback;
            + otherwise a negative number error code definition from
              merrors.h. To retrieve a string containing an English text
              error identifier corresponding to the function's returned
              error status, use the \c DISPLAY_ERROR macro.

@remark     If IKE is configured to use the XAUTH IKE extension, you should
            define and customize this hookup function for your application

@todo_techpubs (maybe add text explaining known issue with the "#ifdef" in
                the function signature appearing in the Doxygen output)

@callbackdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
    sbyte4 (*funcPtrInteractWithAAA)(void *xauthTrans, ubyte2 cfgId,
                            sbyte **userName, sbyte **password, ubyte2 passwordLen,
                            sbyte **passCode, sbyte **nextPin, sbyte *answer,
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                            sbyte **perp,
#endif
                            sbyte **message, sbyte **domain,
                            sbyte **challenge, ubyte2 *challengeLen,
                            ubyte *cfgType, ubyte2 *result,
                            XAUTH_aaaCallbackFun aaaCallback,
                            sbyte4 serverInstance);

    /**
     @brief     XAUTH type.
     @details   XAUTH type:\n
                &bull; 1=client
                &bull; 2=server
                &bull; otherwise no XAUTH.
     @note      This field is defined only if the
                \c \__ENABLE_IKE_XAUTH__ flag is defined.
     */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This function is not applicable for NanoMCP, so omit from the API
     * documentation.
     * @endcond
     */
    ubyte xauthType;    /* 1=client, 2=server, o/w no XAUTH */

    /**
     @brief     XAUTH draft version.
     @details   XAUTH draft version:\n
                &bull; 1=draft-ietf-ipsec-isakmp-xauth-01\n
                &bull; ...\n
                &bull; 9=draft-beaulieu-ike-xauth-02
     @note      This field is defined only if the
                \c \__ENABLE_IKE_XAUTH__ flag is defined.
     */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This function is not applicable for NanoMCP, so omit from the API
     * documentation.
     * @endcond
     */
    ubyte xauthDraft;   /* 9=draft-beaulieu-ike-xauth-02 (default)
                           4=draft-ietf-ipsec-isakmp-xauth-04
                           2=draft-ietf-ipsec-isakmp-xauth-02
                         */

#ifdef __ENABLE_IKE_HYBRID_RSA__
    /**
     @brief     Controls if IKEv1 hybrid-RSA authentication is enabled.
     @details   Controls whether IKEv1 hybrid-RSA authentication is enabled
                (default is \c FALSE).
     @sa        draft-ietf-ipsec-isakmp-hybrid-auth-05
     @remark    XAUTH must also be used if this field is enabled.
     @note      This field is defined only if the
                \c \__ENABLE_IKE_HYBRID_RSA__ flag and the
                \c \__ENABLE_IKE_XAUTH__ flag are defined.
     */
    /**
     * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
     * @private
     * @internal
     *
     * Doc Note: This function is not applicable for NanoMCP, so omit from the API
     * documentation.
     * @endcond
     */
    intBoolean bDoHybrid;
#endif /* __ENABLE_IKE_HYBRID_RSA__ */
#endif /* __ENABLE_IKE_XAUTH__ */

    /**
     * @private
     * @internal
     */
    ubyte2 flags;

#ifdef __ENABLE_DIGICERT_IKE_REF_IDENTIFIER_MATCH__
     /**
     @brief     Peer Host to be used for verifcation of host certificate's common name
     */
     sbyte *ikePeerHost;
#endif
} ikeSettings;

struct IKE_hashSuiteInfo;
struct IKE_cipherSuiteInfo;
struct IKE_macSuiteInfo;
struct IKE_dhGroupInfo;
struct IKE_authMtdInfo;
struct ikeCertDescr;

/* ikePeerConfig -- per peer (tunnel) IKE Configuration
 *   This structure is used to allow a single IKE process to handle
 *   multiple IKE Peers, each peer requires a peer config object.
 *
 * (provides backward compatibility w/older IKE API functions)
 */
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__
@todo_64
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
typedef struct ikePeerConfig
{
#ifdef __IKE_MULTI_HOMING__
    /* serverInstance can be used to match the peer connfig in the callback
       funcPtrIsConfigForPeer */
    sbyte4 serverInstance;
#endif
    /* Number of seconds (> 0) to wait for negotiation.
    Number of seconds (> 0) to wait for negotiation.
    */
    ubyte4  ikeTimeoutNegotiation;  /* seconds > 0 */

    /* Number of seconds (> 0) to wait for a peer response before declaring the peer dead.
    (Default = 300 (5 minutes)) Number of seconds (> 0) to wait for a peer
    response before declaring the peer dead; specify 0 for no dead peer detection.
    */
    ubyte4  ikeTimeoutDpd;          /* seconds; 0=passive */

    /* phase 1 */
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
/* Phase 1 negotiation mode.
Phase 1 negotiation mode:\n
\n
&bull; 2 = main (\c ISAKMP_XCHG_IDPROT)\n
&bull; 4 = aggressive (\c ISAKMP_XCHG_AGGR)

@note This field is defined only if the \c \__ENABLE_IKE_AGGRESSIVE_MODE__ flag is defined.
*/
    ubyte   ikeP1Mode;
#endif

/* IKE: Phase 1 DH group; IKEv2: IKE_SA_INIT default DH group.
IKE: Phase 1 DH group; IKEv2: IKE_SA_INIT default DH group.\n
\n
&bull; 0 = use first supported\n
&bull; 1 = \c OAKLEY_GROUP_MODP768\n
&bull; 2 = \c OAKLEY_GROUP_MODP1024
*/
    ubyte2  ikeP1DHgroup;

/* Default IKE version.
Default IKE version. One (1) to specify IKE; two (2) to specify IKEv2.
*/
    ubyte   ikeVersion;             /* [v2] default IKE version to use */

/* Initiator-proposed Phase 1 SA expiration time.
Initiator-proposed Phase 1 SA expiration time. Zero (0) to specify an infinite
lifetime (that is, no expiration).
*/
    ubyte4  ikeP1LifeSecs;          /* 0=no expiration, unless ikeP1LifeSecsMax != 0 */

/* Responder's maximum Phase 1 SA lifetime.
Responder's maximum Phase 1 SA lifetime. If the initiator's proposed expiration
time is shorter than this maximum lifetime, the time is accepted. If not, Mocana
IKE proposes its maximum lifetime (which the initiator may accept or reject).
*/
    ubyte4  ikeP1LifeSecsMax;       /* 0=unspecified */
    ubyte4  ikeP1LifeSecsMin;

/* Initiator-proposed Phase 1 number of KB to encrypt before requiring rekeying.
Initiator-proposed Phase 1 number of KB to encrypt before requiring rekeying;
zero (0) to specify no limit.
*/
    ubyte4  ikeP1LifeKBytes;        /* 0=no limit, unless ikeP1LifeKBytesMax != 0 */

/* Responder's maximum Phase 1 KB to encrypt before requiring rekeying.
Responder's maximum Phase 1 KB to encrypt before requiring rekeying. If the
initiator's proposed number of KB is less than this maximum KB, the proposed KB
value is accepted. If not, Mocana IKE proposes its maximum KBs (which the
initiator may accept or reject).
*/
    ubyte4  ikeP1LifeKBytesMax;     /* 0=unspecified, o/w >= ikeP1LifeKBytes */

/* PFS (Perfect Forward Security) exchange mode.
PFS (Perfect Forward Security) exchange mode. Zero (0) to specify No Perfect
Forward Security, in which case keying material from the Phase1 DH exchange is
used. -1 to use the OAKLEY_GROUP_DEFAULT (for [v1], the P1 DH group; for [v2],
the parent IKE_SA DH group). Other valid settings are groups 1, 2, 5, and 14.
Note that PFS is required in IKEv2 SA rekeying [RFC7296][RFC5996] 1.3.2 (in
which case 0 will default to OAKLEY_GROUP_DEFAULT).
*/
    ubyte2  ikeP2PFS;               /* 0=no PFS, 1=OAKLEY_GROUP_MODP768, 2=OAKLEY_GROUP_MODP1024 */
                                    /* -1=OAKLEY_GROUP_DEFAULT
                                       i.e. use [v1] P1 DH group or [v2] parent IKE_SA's DH group */

    /* phase 2 quick mode */
/* Initiator-proposed Phase 2 SA expiration time.
Initiator-proposed Phase 2 SA expiration time. Zero (0) to specify an infinite
lifetime (that is, no expiration).
*/
    ubyte4  ikeP2LifeSecs;          /* 0=unspecified, check ikeP2LifeSecsMax instead */

/* Responder's maximum Phase 2 SA lifetime.
Responder's maximum Phase 2 SA lifetime. If the initiator's proposed expiration
time is shorter than this maximum lifetime, the time is accepted. If not, Mocana
IKE proposes its maximum lifetime (which the initiator may accept or reject).
*/
    ubyte4  ikeP2LifeSecsMax;       /* 0=unspecified */
                                    /* Note: if both are unspecified, 28800 secs is used (8 hrs, RFC2407 4.5) */
    ubyte4  ikeP2LifeSecsMin;

/* Initiator-proposed Phase 2 number of KB to encrypt before requiring rekeying.
Initiator-proposed Phase 2 number of KB to encrypt before requiring rekeying;
zero (0) to specify no limit.
*/
    ubyte4  ikeP2LifeKBytes;        /* 0=no limit, unless ikeP2LifeKBytesMax != 0 */

/* Responder's maximum Phase 2 KB to encrypt before requiring rekeying.
Responder's maximum Phase 2 KB to encrypt before requiring rekeying. If the
initiator's proposed number of KB is less than this maximum KB, the proposed KB
value is accepted. If not, Mocana IKE proposes its maximum KBs (which the
initiator may accept or reject).
*/
    ubyte4  ikeP2LifeKBytesMax;     /* 0=unspecified, o/w >= ikeP2LifeKBytes */

/* (IKEv2 only) Time (number of seconds before SA expiration) at which reauthentication (IKE_SA_INIT) is attempted.
(IKEv2 only) Time (number of seconds before SA expiration) at which reauthorization
(IKE_SA_INIT) is attempted; specify 0 for no automatic reauthentication.
*/
    ubyte4  ikeReauthSecs;          /* [v2] Lifetime (in secs) left before repeating IKE_SA_INIT (rfc4478);
                                       0=no repeated auth. (original responder) */

#ifdef __ENABLE_IKE_FRAGMENTATION__
/* Controls whether IKE fragmentation is disabled (default is \c FALSE).
@note This field is defined only if the \c \__ENABLE_IKE_FRAGMENTATION__ flag is defined.
*/
    byteBoolean bNoIkeFrag;

/* Maximum number of IKE message bytes allowed before fragmentation may occur.
Maximum number of IKE message bytes allowed before fragmentation may occur.
@note This field is defined only if the \c \__ENABLE_IKE_FRAGMENTATION__ flag is defined.
*/
    ubyte2  ikeFragSize;
#endif

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
/* Controls whether IKEv2 Signature Authentication [RFC7427] is disabled (default is \c FALSE).
@note This field is defined only if the \c \__ENABLE_IKE_SIG_AUTH_RFC7427__ flag is defined.
*/
    intBoolean bNoSigAuth;
#endif

#ifdef __ENABLE_IKE_OCSP_EXT__
/* Controls whether OCSP extensions for IKEv2 [RFC4086] is disabled (default is \c FALSE).
@note This field is defined only if the \c \__ENABLE_IKE_OCSP_EXT__ flag is defined.
*/
    intBoolean bNoIkeOcsp;

/* User-provided pointer to the OCSP client settings object (default is \c NULL).
@note This field is defined only if the \c \__ENABLE_IKE_OCSP_EXT__ flag is defined.
*/
    struct ocspSettings *pOcspSettings;
#endif

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
/* IP address of GDOI key server.
IP address of GDOI key server.
@note This field is defined only if the \c \__ENABLE_DIGICERT_GDOI_CLIENT__ flag is defined.
*/
    MOC_IP_ADDRESS_S keyServerAddr;
#endif
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
/* Multicast IP address of GDOI PUSH client.
Multicast IP address of GDOI PUSH client.
@note This field is defined only if the \c \__ENABLE_DIGICERT_GDOI_SERVER__ flag is defined.
*/
    MOC_IP_ADDRESS_S keyClientMAddr;

/* GDOI KEK crypto algorithm configuration.
 GDOI KEK crypto algorithm configuration.
 @note These fields are defined only if the \c \__ENABLE_DIGICERT_GDOI_SERVER__ flag is defined.
 */
    ubyte2 ikeHashAlgo;     /* OAKLEY hash algorithm attribute [v1] */
    ubyte2 ikeEncrAlgo;     /* OAKLEY encryption algorithm attribute [v1] */
    ubyte2 ikeEncrKeyLen;   /* encryption algo key length (in bytes); 0 if fixed-length */
    ubyte2 ikeSigMtd;       /* OAKLEY authentication method [v1] */
    ubyte2 ikeSigKeyLen;    /* signature algorithm key length (in bytes); 0 for ECDSA? */
#endif
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    struct ikesa *pxKEK;    /* GDOI KEK */
#endif

#ifdef __ENABLE_IKE_MULTI_AUTH__
    intBoolean bDoMultiAuth;
    sbyte4 reqInAuthMtds[2];  /* required peer auth method(s) [I, R] */
#endif

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    sbyte *eapIdentity; /* for supplicants and EAP-PSK authenticator */

#ifdef __ENABLE_IKE_EAP_ONLY__
    intBoolean bDoEapOnly; /* applicable only if EAP protocol is set (see below) */
#endif
#endif
    /* [v2] EAP protocol(s); see IKE_EAP_PROTO_T in "ike_defs.h" */
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
/* (IKEv2 only) Negotiation protocol.
(IKEv2 only) Negotiation protocol: any of the \c IKE_EAP_PROTO_T enumerated values (see ike_defs.h).
@note This field is defined only if the \c \__ENABLE_DIGICERT_EAP_AUTH__ flag is defined.
*/
    sbyte4 eapProtoAuth; /* we are the authenticator */
#endif
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
/* (IKEv2 only) Negotiation protocol.
(IKEv2 only) The EAP authentication protocol is set to GTC to enable authentication between two different IKEv2 peers. The value is set to EAP_PROTO_GTC.
@note This field is defined only if the \c \__ENABLE_DIGICERT_EAP_PEER__ flag is defined.
*/
    sbyte4 eapProtoPeer; /* we are the supplicant */

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    sbyte4 eapTtlsType; /* see 'eapTTLSMethodType' in "eap/eap_ttls.h" */
#endif
#endif

#ifdef __ENABLE_IKE_XAUTH__
/* XAUTH type.
XAUTH type: 1=client; 2=server (for future use only); otherwise no XAUTH.
@note This field is defined only if the \c \__ENABLE_IKE_XAUTH__ flag is defined.
*/
    ubyte xauthType;    /* 1=client, 2=server, o/w no XAUTH */

/* XAUTH draft version.
XAUTH draft version: 1=draft-ietf-ipsec-isakmp-xauth-01 ... 9=draft-beaulieu-ike-xauth-02
@note This field is defined only if the \c \__ENABLE_IKE_XAUTH__ flag is defined.
*/
    ubyte xauthDraft;   /* 9=draft-beaulieu-ike-xauth-02 (default)
                           4=draft-ietf-ipsec-isakmp-xauth-04
                           2=draft-ietf-ipsec-isakmp-xauth-02
                         */

#ifdef __ENABLE_IKE_HYBRID_RSA__
/* Hybrid RSA Authentication.
This boolean setting indicates whether to perform Hybrid RSA authentication.
Reference: draft-ietf-ipsec-isakmp-hybrid-auth-05
@remark XAUTH must also be used if this field is enabled.
@note This field is defined only if the \c \__ENABLE_IKE_HYBRID_RSA__ flag and the
\c \__ENABLE_IKE_XAUTH__ flag are defined.
*/
    intBoolean bDoHybrid;
#endif /* __ENABLE_IKE_HYBRID_RSA__ */
#endif /* __ENABLE_IKE_XAUTH__ */

/* External private key encryption (i.e. signature generation)..
This callout function generates digital signature via an external private key.
The key algorithm type can be either RSA or ECDSA

Callout registration happens at session creation and initialization by
assigning your custom callout function (which can have any name) to this
callout pointer.

@since 5.8
@version 5.8 and later

@flags
No flag definitions are required to enable this callout.

@param poDigest         Pointer to text digest to be signed.
@param digestLen        Number of bytes in digest (\p poDigest).
@param ppRetSignature   On return, pointer to the generated signature.
@param pRetSignatureLen On return, pointer to number of bytes in the signature
                        (\p *ppRetSignature).
@param serverInstance   Application-specific identifier. This
                        argument applies only if the
                        \c \__IKE_MULTI_HOMING__ flag is defined;
                        otherwise it should be ignored.
@param data             Pointer to structure of interest.

@return \c OK (0) if successful; otherwise a negative number
error code definition from merrors.h. To retrieve a string containing an
English text error identifier corresponding to the function's returned error
status, use the \c DISPLAY_ERROR macro.

*/
    sbyte4 (*funcPtrSignHash)(ubyte *poDigest, ubyte4 digestLen,
                             ubyte **ppRetSignature, ubyte4 *pRetSignatureLen,
                             sbyte4 serverInstance, void *data);

/* Free memory previously allocated for the digital signature.
This callout function frees memory peviously allocated by
ikePeerConfig::funcPtrSignHash for output signature (the ppRetSignature
parameter).

Callout registration happens at session creation and initialization by
assigning your custom callout function (which can have any name) to this
callout pointer.

@since 5.8
@version 5.8 and later

@flags
No flag definitions are required to enable this callout.

@param pRetSignature    Pointer to memory to free.

@remark You do not need to implement this callout function if the memory
is statically allocated or should be managed by the application.

*/
    void (*funcPtrReleaseSig)(ubyte *pRetSignature);

/* This callout function get the key type from the certificate. It returns
either akt_rsa, or akt_ecc.

Callout registration happens at session creation and initialization by
assigning your custom callout function (which can have any name) to this
callout pointer.

@since 5.8
@version 5.8 and later

@flags
No flag definitions are required to enable this callout.

@param certData         Pointer to certificcate.
@param certDataLen      Length, in bytes, of certificate.

@remark You do not need to implement this callout function if the memory
is statically allocated or should be managed by the application.

*/
    sbyte4 (*funcPtrGetKeyTypeFromCertificate)(ubyte *certData, ubyte4 certDataLen, ubyte4 *pKeyType);

    /*------------------------------------------------------------------------*/
    /* The following items were used by internal storage.  They should not
     * be used or modified by users directly.
     */
    ubyte*  ikePSKey;
    sbyte4  ikePSKeyLen;
#ifdef CUSTOM_IKE_GET_PSK
    ubyte   psk[IKE_PSK_MAX];  // from ike_utils.c, m_psk
#endif
#ifdef __ENABLE_IKE_PPK_RFC8784__
    byteBoolean  bUsePpk;
    ubyte       *ppk_id;
    sbyte4       ppkid_len;
    ubyte       *ppk_psk;
    sbyte4       ppk_psk_len;
#endif

    struct ikeCertDescr* ikeCertChain;
    sbyte4   ikeCertChainLen;

    struct certStore *ikeCertStore; // for Trust Anchor's

    /* hash, cipher, mac suites, dh groups, auth-mtds */
    struct IKE_hashSuiteInfo* hashSuites;
    struct IKE_cipherSuiteInfo* cipherSuites;
    struct IKE_macSuiteInfo* macSuites;
    struct IKE_dhGroupInfo* dhGroups;
    struct IKE_authMtdInfo* authMtds;

    /* Pointer back to the (global) ikeSettings object for easy access */
    struct ikeSettings* ikeSettings;

    /* Pointer to the next peer in the peer list */
    struct ikePeerConfig* next;

} ikePeerConfig;


#define IKE_SETTINGS_FLAG_ENCR_AGGR     0x0001
#define IKE_SETTINGS_FLAG_ECDH_XY       0x0002


/*------------------------------------------------------------------*/

struct sainfo;

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Initialize NanoSec IKE server internal structures and counters.

@details    This function initializes NanoSec IKE server internal structures
            and counters. This function must be called before starting your IKE application servers.

@ingroup    ike_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@inc_file ike.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
extern void IKE_EXAMPLE_main(sbyte4 dummy)
{
    sbyte4  tid;
    certDescriptor  ikeCert;
    sbyte4             ret;

    DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, "IKE_EXAMPLE_main: Starting up IKE Server");

    if (0 > CA_MGMT_EXAMPLE_computeHostKeys(&ikeCert))
        goto exit;

    // initialize the IKE tables and structures
    if (0 > IKE_init())
    goto exit;

    // customize and change default settings here
    CA_MGMT_EXAMPLE_initUpcalls();
    IKE_ikeSettings()->funcPtrIkeXchgSend = IKE_SAMPLE_ikeXchgSend;
    IKE_ikeSettings()->funcPtrIkeEvtSend = IKE_SAMPLE_ikeEvtSend;
    IKE_ikeSettings()->funcPtrGetHostAddr = IKE_SAMPLE_ikeGetHostAddr;

    // for testing
    IKE_ikeSettings()->ikeP1LifeSecs = 120; // 2 mins.
    IKE_ikeSettings()->ikeP2LifeSecs = 300; // 5 mins.

    if (0 > IKE_initServer(&ikeCert, PSK, PSKlen))
        goto exit;

    IKE_EXAMPLE_startServer();           // startup the IKE server
    ret = IKE_shutdown();
    if (0 > ret)
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, "IKE_EXAMPLE: IKE_shutdown return error: ", ret);

    if (INVALID_SOCKET != mSocket) {
        closesocket(mSocket);
        mSocket = INVALID_SOCKET;
    }

    RTOS_sleepMS(2000);     // you'll want to wait for upper layer to say it's dead

exit:
    ret = CA_MGMT_EXAMPLE_releaseHostKeys(&ikeCert);
    if (0 > ret)
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, "IKE_EXAMPLE: CA_MGMT_EXAMPLE_releaseHostKeys return error: ", ret);

    return;
} // IKE_EXAMPLE_main
@endcode

@funcdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_init(void);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Release (free) internal structures and allocated memory for
            NanoSec IKE.

@details    This function releases (frees) internal structures and allocated
            memory for NanoSec IKE. You might need to close the sockets opened
            by your IKE application servers.

@ingroup    ike_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@inc_file ike.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa         For information about the IPsec/IKE shutdown sequence, see @ref
            ipsec_ike_shutdown.

For an example of how to call this function, see IKE_init().

@funcdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_shutdown(void);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Initialize the NanoSec IKE server and verify the global
            configuration.

@details    This function sets up the NanoSec IKE server's internal state.  This
            function should be called before you call any other IKE function.
            After you call this function, call IKE_initPeerConfig() to
            initialize a configuration. If you do not call both functions, any
            attempts at authentication will fail.

@ingroup    ike_functions

@since 5.8
@version 5.8 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@inc_file ike.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_initServerEx(void);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Set up NanoSec IKE server's authentication materials.

@details    This function sets up NanoSec IKE server's authentication
            materials&mdash;either a preshared key or a host key-certificate
            pair. This function should be called before starting your IKE
            application servers. (If you do not call this function, any
            attempts at authentication will fail.)

@ingroup    ike_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@param pCertificateDescr    Pointer to a \c certDescriptor structure containing a
                            certificate and public/private key. Pass a
                            \c NULL value if you are not using this
                            authentication method.
@param pStringPSK           Preshared key character string. Pass a \c NULL value
                            if you are not using this authentication method.
@param stringLen            Length of preshared key character string This
                            argument is ignored if the \p pStringPSK
                            argument value is \c NULL.
@param bHex                 \c TRUE if the preshared key is passed in as a
                            hexadecimal character string; \c FALSE otherwise
                            (for example, if the preshared key is passed as
                            an ASCII string). Pass a \c NULL value if you
                            are not using this authentication method.

@inc_file ike.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

For an example of how to call this function, see IKE_init().

@funcdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_initServer(struct certDescriptor *pCertificateDescr,
                                 sbyte *pStringPSK, sbyte4 stringLen, intBoolean bHex);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Set up NanoSec IKE server's authentication materials.

@details    This function sets up NanoSec IKE server's authentication
            materials&mdash;either a preshared key or a host key-certificate
            pair. This function should be called before starting your IKE
            application servers. (If you do not call this function, any attempts at authentication will fail.)

For an example of how to call this function, see IKE_init().

@ingroup    ike_functions

@since 5.8
@version 5.8 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@inc_file ike.h

@param config               Pointer to a \c ikePeerConfig object containing
                            the IKE Peer Configuration to initialize.
@param pCertificateDescr    Pointer to a \c certDescriptor structure
                            containing a certificate and public/private
                            key. Pass a \c NULL value if you are not using
                            this authentication method.
@param pStringPSK           Preshared key character string. Pass a \c NULL value
                            if you are not using this authentication method.
@param stringLen            Length of preshared key character string This
                            argument is ignored if the \p pStringPSK
                            argument value is \c NULL.
@param bHex                 \c TRUE if the preshared key is passed in as a
                            hexadecimal character string; \c FALSE
                            otherwise (for example, if the preshared key is
                            passed as an ASCII string). Pass a \c NULL value
                            if you are not using this authentication method.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function (and all peer-related functions) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_initPeerConfig(ikePeerConfig* config,
                                     struct certDescriptor *pCertificateDescr,
                                     sbyte *pStringPSK, sbyte4 stringLen,
                                     intBoolean bHex);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Set up NanoSec IKE server's authentication materials.

@details    This function sets up NanoSec IKE server's authentication
            materials for quantum preshared key. This function should be called before starting your IKE
            application servers. (If you do not call this function, any attempts at authentication will fail.)

For an example of how to call this function, see IKE_EXAMPLE_main().

@ingroup    ike_functions

@since 5.8
@version 5.8 and later

@flags
To enable this function, the following flag must be defined in the build:
+ \c \__ENABLE_IKE_PPK_RFC8784__

@inc_file ike.h

@param config               Pointer to a \c ikePeerConfig object containing
                            the IKE Peer Configuration to initialize.
@param pPpk                 Pointer to Quantum Preshared key character string.
@param ppkLen               Length of preshared key character string.
@param pPpkId               Pointer to Quantum Preshared key identifier string.
@param ppkIdLen             Length of ppkId identifier string.
@param bHex                 \c TRUE if the preshared key is passed in as a
                            hexadecimal character string; \c FALSE
                            otherwise (for example, if the preshared key is
                            passed as an ASCII string).
@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function (and all peer-related functions) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_setPpkPeerConfig(ikePeerConfig* config, sbyte *pPpk,
    sbyte4 ppkLen, sbyte *pPpkId, sbyte4 ppkIdLen, intBoolean bHexPpk);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Free IKE server's ppk authentication materials.

@details    This function frees NanoSec IKE server's ppk authentication
            materials for quantum preshared key. This function should be called before exiting your IKE
            application servers.


@ingroup    ike_functions

@since 7.0
@version 7.0 and later

@flags
To enable this function, the following flag must be defined in the build:
+ \c \__ENABLE_IKE_PPK_RFC8784__

@inc_file ike.h

@param config               Pointer to a \c ikePeerConfig object containing
                            the IKE Peer Configuration.
@return     \c OK (0) on success;
@funcdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function (and all peer-related functions) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_freePpkPeerConfig(ikePeerConfig* config);


/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Set up NanoSec IKE server's host certificate chain.

@details    This function sets up NanoSec IKE server's host certificate
            chain, which is used for authentication by peer IKE servers. This
            function should be called before starting your IKE application
            server. (If you do not call this function, any attempts at
            certificate-based authentication may fail.)

@ingroup    ike_functions

@since 5.1
@version 5.1 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@param pCertChain       Host certificate chain (in an array of \c certDescriptor
                        structures, starting with the leaf certificate).
@param certChainLen     Length of certificate chain (that is, the size of the
                        array).

@note       The leaf certificate should provide its private key in
            \c certDescriptor.

@inc_file ike.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     Call of this function overrides previously configured host
            certificate (chain).

@funcdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_initCertChain(struct certDescriptor *pCertChain, sbyte4 certChainLen);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__
@coming_soon
@ingroup    ike_functions
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_initCertChainEx(ikePeerConfig* config, struct certDescriptor *pCertChain, sbyte4 certChainLen);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Set up NanoSec IKE server's Certificate Authority (CA)
            certificate store.

@details    This function sets up NanoSec IKE server's CA certificate store,
            which is used to verify peer certificates. This function should
            be called before starting your IKE application server. (If you do
            not call this function, any attempts at certificate-based
            authentication will fail.)

@ingroup    ike_functions

@since 6.4
@version 6.4

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@param pTrustAnchor     Array of CA certificates. (In the \c certDescriptor
                        structure, only the \c pCertificate and
                        \c certLength fields need to be specified).
@param trustAnchorNum   Number of CA certificates (that is, the size of the
                        array).

@inc_file ike.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function overrides any previously configured CA certificate
            store.

@funcdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_initTrustAnchor(struct certDescriptor *pTrustAnchor, sbyte4 trustAnchorNum);

/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation (regardless of product).
 */
MOC_EXTERN sbyte4 IKE_initTrustAnchorEx(ikePeerConfig* config, struct certDescriptor *pTrustAnchor, sbyte4 trustAnchorNum);

/* (doc note: for multi-VPN implementation)
*/
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__
@coming_soon
@ingroup    ike_functions
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function (and all peer-related functions) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */
MOC_EXTERN ikePeerConfig* IKE_newPeerConfig(void);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__
@brief      Allocates and add new peer entry

@details    This function allocates and initializes new peer entry with
            default peer config information
@ingroup    ike_functions
@inc_file   ike.h
@param  serverInstance server instance to copy to peer config.
@return     \c Pointer to peer config or NULL on error
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function (and all peer-related functions) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */

MOC_EXTERN ikePeerConfig* IKE_newPeerConfigEx(sbyte4 serverInstance);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__
@coming_soon
@ingroup    ike_functions
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function (and all peer-related functions) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */
MOC_EXTERN ikePeerConfig* IKE_globalPeerConfig(void);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__
@coming_soon
@ingroup    ike_functions
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function (and all peer-related functions) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */
MOC_EXTERN void IKE_freePeerConfig(ikePeerConfig* config);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__
@coming_soon
@ingroup    ike_functions
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function (and all peer-related functions) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */
MOC_EXTERN ikePeerConfig* IKE_findPeerConfig(MOC_IP_ADDRESS peerAddr,
                                             ubyte2 wPeerPort,
                                             sbyte4 serverInstance);


/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__
@brief      Remove all IKE SAs that belong to a peer entry

@details    This function removes all existing IKE SAs belonging to an
            ike peer from the system.
@ingroup    ike_functions
@inc_file   ike.h
@param config    Pointer to peer config to compare with the one in IKE SA.
@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function (and all peer-related functions) is not applicable
 * for NanoMCP, so omit from the API documentation.
 * @endcond
 */

extern MSTATUS IKEDelPeerEntrySadb(ikePeerConfig* config);

/**
@brief      Get a pointer to NanoSec IKE server's configuration settings.

@details    This function returns a pointer to NanoSec IKE server settings
            that can be dynamicaly adjusted during initialization or runtime;
            for example, to change the IKE negotiation parameters.

@ingroup    ike_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@inc_file ike.h

@return     Pointer to \c ikeSettings structure containing configuration
            settings and callback pointers.

@sa         For detailed information about the configuration settings, see
            ikeSettings.

@funcdoc    ike.h
*/
MOC_EXTERN ikeSettings* IKE_ikeSettings(void);
MOC_EXTERN ikeSettings* IKE_ikeSettings_ex(void);


/*------------------------------------------------------------------*/

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Flush (remove) all existing IKE SAs.

@details    This function flushes (removes) all existing IKE channels (IKE SAs)
            from the system.

@ingroup    ike_functions

@since 4.0
@version 4.0 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@inc_file ike.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@note       Previously negotiated child IPsec SAs will not be removed
            by this call. To delete IPsec SAs, refer to IPSEC_keyDelete()
            or IPSEC_keyFlush() (see ipseckey.h).

@funcdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_keyFlush(void);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Delete an IKE SA.

@details    This function deletes IKE channels (IKE_SAs) specified by the given
parameters.

@ingroup    ike_functions

@since 4.0
@version 4.0 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@inc_file ike.h

@param peerAddr         Peer IKE server IP address (host byte order).
@param serverInstance   (Ignored unless \c \__IKE_MULTI_HOMING__ is defined in
                        moptions.h) Application-specific identifier.
@param wPeerPort        Peer IKE server port number. Zero (0) to match any port.
@param bDelNattPeer     (Ignored unless \c \__ENABLE_IPSEC_NAT_T__ is defined in
                        moptions.h.) \c FALSE to bypass peers behind NAT;
                        \c TRUE otherwise.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@note       Previously negotiated child IPsec SAs will not be removed
            due to this call. To delete IPsec SA's, refer to IPSEC_keyDelete()
            or IPSEC_keyFlush() (see ipseckey.h).

@funcdoc    ike.h
@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_keyDelete(MOC_IP_ADDRESS peerAddr, sbyte4 serverInstance,
                                ubyte2 wPeerPort,intBoolean bDelNattPeer);

/**
@brief      Initiate Phase 1 negotiation with an IKE peer.

@details    This function initiates a Phase 1 negotiation with an IKE peer
            independent of lower IPsec layer traffic. It can be used by a VPN
            %client to connect to its gateway before the subnet configuration
            is propagated.

@ingroup    ike_functions

@since 4.0
@version 6.4 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@inc_file ike.h

@param peerAddr         Peer IKE server IP address (host byte order).
@param serverInstance   (Ignored unless \c \__IKE_MULTI_HOMING__ is defined in
                        moptions.h) Application-specific identifier.
@param wPeerPort        (Ignored unless \c \__ENABLE_IPSEC_NAT_T__ is defined in
                        moptions.h.) Peer IKE server port number.
@param bUseNattPort     (Ignored unless \c \__ENABLE_IPSEC_NAT_T__ is defined in
                        moptions.h.) \c TRUE to use local port 4500;
                        \c FALSE otherwise.
@param pdwIkeId         On return, pointer to the negotiating IKE_SA's
                        internal ID.
@param bForce           \c TRUE to initiate even if an applicable IKE_SA already
                        exists; \c FALSE otherwise.
@param bInitCont        \c TRUE to send \c INITIAL_CONTACT; \c FALSE otherwise.
@param bGdoiClient      (Ignored unless \c \__ENABLE_DIGICERT_GDOI_CLIENT__ is
                        defined in moptions.h) \c TRUE to initiate GDOI-IKE
                        Phase 1 connection; \c FALSE otherwise.
@param pSAInfo          (Optional; may be \c NULL) Set of IKEv2 CHILD_SA
                        proposal parameters.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ike.h
*/
MOC_EXTERN sbyte4 IKE_keyConnect(MOC_IP_ADDRESS peerAddr, sbyte4 serverInstance,
                                 ubyte2 wPeerPort, intBoolean bUseNattPort,
                                 ubyte4 *pdwIkeId,
                                 intBoolean bForce,
                                 intBoolean bInitCont,
                                 intBoolean bGdoiClient,
                                 struct sainfo *pSAInfo);

#if defined(__ENABLE_MOBIKE__) && defined(__IKE_MULTI_HOMING__)
/**
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 */
MOC_EXTERN sbyte4 IKE2_keyUpdate(sbyte4 serverInstanceOld, sbyte4 serverInstanceNew);
#endif


/*------------------------------------------------------------------*/

#ifndef __IKE_TRACK__
/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Receive data from an IKE peer or lower IPsec layer.

@details    This function receives data from an IKE peer or lower IPsec
            layer. This function should be called by your IKE application
            servers whenever data has been received on the sockets.

@ingroup    ike_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@inc_file ike.h

For an example of how to call this function, see IKE_msgIdle().

@param peerAddr         Peer IKE server IP address (host byte order).
@param wPeerPort        Peer IKE server port number.
@param pBuffer          Pointer to input data buffer.
@param dwBufferSize     Number of bytes in input data buffer (\p pBuffer).
@param serverInstance   (Ignored unless \c \__IKE_MULTI_HOMING__ is defined in
                        moptions.h) Application-specific identifier.
@param bUseNattPort     (Ignored unless \c \__ENABLE_IPSEC_NAT_T__ is defined in
                        moptions.h.) \c TRUE to receive at local port 4500;
                        \c FALSE otherwise.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_msgRecv(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                              ubyte *pBuffer, ubyte4 dwBufferSize,
                              sbyte4 serverInstance,
                              intBoolean bUseNattPort);
#else
struct ike_track;
/** @private @internal */
MOC_EXTERN sbyte4 IKE_msgRecv(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                              ubyte *pBuffer, ubyte4 dwBufferSize,
                              sbyte4 serverInstance,
                              intBoolean bUseNattPort,
                              struct ike_track *pxTrack);
#endif

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Handle pending Phase 2 key exchange and evaluate established
            Phase 1 channels.

@details    This function handles pending Phase 2 key exchange. Additionally,
            Phase 1 channels are evaluated for expiration (to be deleted) and
            timeout (to stop retransmission). This function should be called
            when \c select() times out.

@ingroup    ike_functions

@since 1.41
@version 3.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@note       In the Mocana SoT Platform example code, this routine is called
            when \c select() times out (five seconds).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
static sbyte4 IKE_EXAMPLE_startServer(void)
{
    while (FALSE == isBreakSignalRequest)
    {
        SOCKADDR_IN saPeer;
        int saddrlen;
        ubyte2 wPeerPort;
        ubyte4 dwPeerAddr;

        // set up timeout
        FD_ZERO(pSocketList);
        FD_SET(mSocket, pSocketList);

        timeout.tv_sec  = msTimeout / 1000;
        timeout.tv_usec = (msTimeout % 1000) * 1000; // ms to us

        ret = select(FD_SETSIZE, pSocketList, NULL, NULL, &timeout);

        if (ret == SOCKET_ERROR) {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, "IKE_EXAMPLE: select() error: ", WSAGetLastError());
            goto exit;
        }

        if (ret == 0) {
            // timeout, let IKE do some book keeping
            status = IKE_msgIdle();
            continue;
        }

        // receive message/event
        saddrlen = sizeof(struct sockaddr);

        if (SOCKET_ERROR == (ret = recvfrom(mSocket, mBuffer, mBufSize, 0, (LPSOCKADDR)&saPeer, &saddrlen))) {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, "IKE_EXAMPLE: recvfrom() error: ", WSAGetLastError());
            continue;
        }

        if (ret == 0) break;

        wPeerPort = NTOHS(saPeer.sin_port);
        dwPeerAddr = NTOHL(saPeer.sin_addr.s_addr);

        if (0 != (status = IKE_msgRecv(dwPeerAddr, wPeerPort, mBuffer, ret)))
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, "IKE_EXAMPLE: IKE_msgRecv() return error: ", status);

    }  while

    // ...
}
@endcode

@funcdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_msgIdle(void);

#ifndef __IKE_TRACK__
/**
@brief      Receive IKEv2 message data from an IKE peer or lower IPsec layer.

@details    This function receives IKEv2 message data from an IKE peer or
            lower IPsec layer. This function should be called by your IKEv2
            application servers whenever data has been received on the sockets.

An IKEv2 message's version can be identifed by inspecting the high 4 bits of its
18th byte. If the message is received at port 4500, there will be 4 extra
leading bytes of non-ESP marker.

@ingroup    ike_functions

@since 2.02
@version 5.3 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__

@inc_file ike.h

@param peerAddr         Peer IKE server IP address (host byte order).
@param wPeerPort        Peer IKE server port number.
@param pBuffer          Pointer to input data buffer.
@param dwBufferSize     Number of bytes in input data buffer (\p pBuffer).
@param serverInstance   (Ignored unless \c \__IKE_MULTI_HOMING__ is defined in
                        moptions.h) Application-specific identifier.
@param bUseNattPort     (Ignored unless \c \__ENABLE_IPSEC_NAT_T__ is defined
                        in moptions.h.) \c TRUE to receive at local port
                        4500; \c FALSE otherwise.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ike.h
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE2_msgRecv(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                               ubyte *pBuffer, ubyte4 dwBufferSize,
                               sbyte4 serverInstance,
                               intBoolean bUseNattPort);
#else
struct ike2_track;
/** @private @internal */
MOC_EXTERN sbyte4 IKE2_msgRecv(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                               ubyte *pBuffer, ubyte4 dwBufferSize,
                               sbyte4 serverInstance,
                               intBoolean bUseNattPort,
                               struct ike2_track *pxTrack);
#endif

struct ike_event;
/** @private @internal */
MOC_EXTERN sbyte4 IKE_evtRecv(struct ike_event *pxEvt,
                              sbyte4 serverInstance,
                              intBoolean bUseNattPort);

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
/** @private @internal */
MOC_EXTERN sbyte4 IKE_radRecv(MOC_IP_ADDRESS srcAddr, ubyte2 wSrcPort,
                              ubyte *pBuffer, ubyte4 dwBufferSize,
                              sbyte4 serverId);
#endif

#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation (regardless of product).
 */
MOC_EXTERN sbyte4 IKE_cfgSend(const ubyte *poCfg, ubyte2 wCfgLen, ubyte oCfgType,
                              ubyte4 dwIkeId, ubyte2 *pwCfgId);
#endif

/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation (regardless of product).
 */
MOC_EXTERN sbyte4 IKE_p2RawSend(const ubyte *poData, ubyte2 wDataLen,
                                ubyte oNextPayload, ubyte oExchange,
                                ubyte4 dwIkeId);

#ifdef __ENABLE_IKE_REDIRECT__
/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN void IKE_redirectTimerExpiry(void *cookie, ubyte *type);
#endif

#ifdef __IKE_MULTI_THREADED__
/** @private @internal */
typedef sbyte4 (*IKE_dpcFunc)(ubyte *buf, ubyte4 bufsize);

/** @private @internal */
typedef struct dpcHdr
{
    void *unused;
    IKE_dpcFunc dpc_func;
    ubyte2 dpc_len;

} *DPC_HDR;

/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4 IKE_dpcRegister(IKE_dpcFunc dpcFunc);

/**
@cond __INCLUDE_DOXYGEN_FOR_SOTP__

@brief      Receive data in the context of an IKE thread.

@details    This function receives internal data sent from another IKE thread.
            This function should be called by your IKE application servers in
            the current IKE thread's context whenever internal data has been
            received, which was peviously sent via the
            \p ikeSettings::funcPtrIkeThreadSend callback function.

@ingroup    ike_functions

@since 6.5.1
@version 6.5.1 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IKE_SERVER__
+ \c \__IKE_MULTI_THREADED__

@inc_file ike.h

@param buf          Pointer to input data buffer.
@param bufsize      Number of bytes in input data buffer (\p buf).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ike.h

@endcond
*/
/**
 * @cond __INCLUDE_DOXYGEN_FOR_NanoMCP__
 * @private
 * @internal
 *
 * Doc Note: This function is not applicable for NanoMCP, so omit from the API
 * documentation.
 * @endcond
 */
MOC_EXTERN sbyte4 IKE_dpcRecv(ubyte *buf, ubyte4 bufsize);

#endif /* __IKE_MULTI_THREADED__ */


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_GET_PSK
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_PSK(
                        /* [output] */
                        ubyte *poPsk,       /* may be NULL */
                        ubyte4 *pdwPskLen,  /* +[input] */

                        /* [input] */
                        const ubyte *poId,  /* peer ID; may be NULL */
                        ubyte2 wIdLen,      /* [v1] aggresive mode or [v2] responder or inbound */
                        sbyte4 idType,      /* see IKE_ID_T in "ike_defs.h" */

                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 dir,         /* [v1] 0=both or [v2] 1=in/peer, 2=out/host */
                        intBoolean bInitiator, /* Am I the initiator? */
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_USE_CERT
MOC_EXTERN sbyte4 CUSTOM_IKE_USE_CERT(
                        /* [output] */
                        struct certDescriptor *pCert, /* host certificate(s), leaf first; may be NULL */
                        sbyte4 *certNum,    /* +[input] */

                        /* [input] */
                        const ubyte *poId,  /* dir=HOST: host ID; [v2] responder? */
                        ubyte2 wIdLen,      /* dir=PEER: peer ID; [v1] aggr responder */
                        sbyte4 idType,      /* see IKE_ID_T in "ike_defs.h" */

                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 dir,         /* [v1] 0=both or [v2] 1=in/peer, 2=out/host */
                        intBoolean bInitiator,
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_GET_DPD_TIMEOUT
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_DPD_TIMEOUT(
                        /* [output] */
                        ubyte4 *pdwTimeoutSecs, /* seconds; 0=passive */

                        /* [input] */
                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 unused,
                        intBoolean bInitiator,
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_GET_P1_LIFEKBYTES
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_P1_LIFEKBYTES(
                        /* [output] */
                        ubyte4 *pdwExpKBytes,

                        /* [input] */
                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 unused,
                        intBoolean bInitiator,
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_GET_P1_LIFESECS
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_P1_LIFESECS(
                        /* [output] */
                        ubyte4 *pdwExpSecs,

                        /* [input] */
                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 unused,
                        intBoolean bInitiator,
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_GET_ENCR_ALGO
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_ENCR_ALGO(
                        /* [output] */
                        ubyte2 awAlgo[],    /* [v1] Phase 1 OAKLEY_ 'attribute value - encr algo'
                                               or [v2] ENCR_ 'Transform ID' in "ike_defs.h" */
                        ubyte2 awKeyLen[],  /* must specify on return, if initiator */
                        sbyte4 *num,        /* +[input] */

                        /* [input] */
                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 version,     /* 2=[v2], o/w=[v1] (default) */
                        intBoolean bInitiator,
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_GET_HASH_ALGO
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_HASH_ALGO(
                        /* [output] */
                        ubyte2 awAlgo[],    /* [v1] Phase 1 OAKLEY_ 'attribute value - hash algo'
                                               or [v2] PRF_ 'Transform ID' in "ike_defs.h" */
                        sbyte4 *num,        /* +[input] */

                        /* [input] */
                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 version,     /* 2=[v2], o/w=[v1] (default) */
                        intBoolean bInitiator,
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_GET_INTEG_ALGO
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_INTEG_ALGO(/* [v2] */
                        /* [output] */
                        ubyte2 awAlgo[],    /* AUTH_ 'Transform ID' in "ike_defs.h" */
                        sbyte4 *num,        /* +[input] */

                        /* [input] */
                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 unused,
                        intBoolean bInitiator,
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_GET_P1_DHGRP
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_P1_DHGRP(
                        /* [output] */
                        ubyte2 awDhGrp[],
                        sbyte4 *num,        /* +[input] must > 0 on success */

                        /* [input] */
                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 version,     /* 2 or 1 */
                        intBoolean bInitiator,
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_GET_P2_PFS
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_P2_PFS(
                        /* [output] */
                        ubyte2 awDhGrp[],
                        sbyte4 *num,        /* +[input] must > 0 on success */

                        /* [input] */
                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 version,     /* 2 or 1 */
                        intBoolean bInitiator,
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_GET_VERSION
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_VERSION(
                        /* [output] */
                        sbyte4  aVerion[],
                        sbyte4  *num,       /* +[input] */

                        /* [input] */
                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 unused,
                        intBoolean bInitiator,
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_GET_HOST_ID /* backward comp. */
#ifndef CUSTOM_IKE_GET_ID
#define CUSTOM_IKE_GET_ID CUSTOM_IKE_GET_HOST_ID
#endif
#endif

#ifdef CUSTOM_IKE_GET_ID
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_ID(
                        /* [output] */
                        const ubyte **ppoId,/* ID payload data; allocated by callee (static) */
                        ubyte2 *pwIdLen,
                        sbyte4 *pIdType,    /* see IKE_ID_T in "ike_defs.h" */

                        /* [input] */
                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 dir,         /* 1=in/remote [v2 initiator], 2=out/local */
                        intBoolean bInitiator, /* Am I the initiator (e.g. [v2] EAP supplicant)? */
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_CHECK_ID
MOC_EXTERN sbyte4 CUSTOM_IKE_CHECK_ID(
                        /* [input] */
                        const ubyte *poId,  /* ID payload data */
                        ubyte2 wIdLen,
                        sbyte4 idType,      /* see IKE_ID_T in "ike_defs.h" */

                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 dir,         /* 1=remote, 2=local */
                        intBoolean bInitiator,
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_GET_VENDOR_ID
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_VENDOR_ID(
                        /* [output] */
                        ubyte   *poVid,
                        ubyte2  *vidLen,    /* +[input] */

                        /* [input] */
                        sbyte4  iteration,  /* >= 0 */

                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 dir,         /* n/a */
                        intBoolean bInitiator,
                        sbyte4 serverInstance);
#endif


#ifdef CUSTOM_IKE_GET_TFM_ATTRS
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_TFM_ATTRS( /* [v1] */
                        /* [output] */
                        ubyte *poAttrsEx,
                        ubyte2 *attrsExLen, /* +[input] */

                        /* [input] */
                        const ubyte *poAttrs,
                        ubyte2 wAttrsLen,
                        ubyte oProtoId,     /* PROTO_ISAKMP, PROTO_IPSEC_AH, or PROTO_IPSEC_ESP */
                        ubyte oTfmId,       /* IKE_KEY, AH_MD5, ESP_3DES, etc. */

                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 dir,         /* n/a */
                        intBoolean bInitiator, /* TRUE */
                        sbyte4 serverInstance);
#endif


#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#ifdef CUSTOM_IKE_GET_EAP_PROTO
MOC_EXTERN sbyte4 CUSTOM_IKE_GET_EAP_PROTO( /* [v2] */
                        /* [output] */
                        sbyte4 *eapProto,   /* see IKE_EAP_PROTO_T in "ike_defs.h" */

                        /* [input] */
                        const ubyte *poId,  /* peer ID */
                        ubyte2 wIdLen,
                        sbyte4 idType,      /* see IKE_ID_T in "ike_defs.h" */

                        MOC_IP_ADDRESS peerAddr,
                        sbyte4 dir,         /* n/a */
                        intBoolean bInitiator, /* Am I the supplicant (i.e. initiator)? */
                        sbyte4 serverInstance);
#endif
#endif


#ifdef CUSTOM_IKE_CATCH_EXCEPTION
extern void CUSTOM_IKE_CATCH_EXCEPTION(MSTATUS status, MOC_IP_ADDRESS peerAddr,
                                       void *pxIkeHdr, ubyte oPayload, void *pxPayload,
                                       void *pxSa, void *pxXg, void *pxIPsecSa);
#endif


/*------------------------------------------------------------------*/

#ifdef __IKE_TRACK__

/**
 * @private
 * @internal
 */
enum ike_status_ex1
{
    UNSPECIFIED_STATUS = 0,
    IKMP_SA_NEGOTIATED,     // IKE rekey negotiation is completed
    IKMP_SA_NEGOTIATED_NOTIFY, // The initial (when receive INITIAL_CONTACT) IKE negotiation completed
    IKMP_CONTINUE,          // In the middle of IKE negotiation phase, more exchanges needed
    IKMP_NOTIFY,            // IKE NOTIFY payload is received, ex. R_U_THERE/R_U_THERE_ACK
    IKMP_DELETE,            // IKE DELETE payload is received, ex. Peer sends isakmp_delete payload to indicate he wants to terminate the tunnel.
    IKMP_ERROR,             // Any bad formatted IKE packets for IKE phase I negotiation
    PROTOCOL_SA_NEGOTIATED, // IKE Phase II (IPSEC SA) negotiation completed
    PROTOCOL_CONTINUE,      // In the middle of IPSec SA negotiation, more exchange needed
    PROTOCOL_NOTIFY,        // IPSEC Notify Message Type is received
    PROTOCOL_DELETE,        // IPSEC Protocol delete msg is received
    PROTOCOL_ERROR,         // Any bad formatted IKE packets for IKE phase II negotiation
    RETRANSMIT_IGNORE,      // Let us know peer re-sent the same packet
    CONFIG_MODE_CONTINUE,   // In the middle of mod_config phase, more exchanges needed
    CONFIG_MODE_DONE,       // mod_config phase completed
    CONFIG_MODE_ERROR,      // Any bad formatted IKE packets for mod-config negotiation
};


/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation (regardless of product).
 */
MOC_EXTERN sbyte4 IKE_msgRecvEx1(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                                 ubyte *pBuffer, ubyte4 dwBufferSize,
                                 sbyte4 serverInstance,
                                 intBoolean bUseNattPort,
                                 enum ike_status_ex1 *ret);

/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation (regardless of product).
 */
MOC_EXTERN sbyte4 IKE2_msgRecvEx1(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                                  ubyte *pBuffer, ubyte4 dwBufferSize,
                                  sbyte4 serverInstance,
                                  intBoolean bUseNattPort,
                                  ubyte2 *ret);

#endif /* __IKE_TRACK__ */


#ifdef __cplusplus
}
#endif

#endif /* __IKE_HEADER__ */

