/**
 * @file  sadb.h
 * @brief NanoSec IPsec Security Association Database (SADB) header.
 *
 * @details    This file contains SADB data structures and function declarations.
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

#ifndef __SADB_HEADER__
#define __SADB_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
#ifndef ATOMIC_T
#include <asm/atomic.h>
#ifdef __ENABLE_IPSEC_ESN__
#define ATOMIC_T            atomic64_t
#define ATOMIC_SET(v, i)    atomic64_set(&(v), (long long)(i))
#define ATOMIC_GET(v)       ((ubyte8) atomic64_read(&(v)))
#define ATOMIC_INC_GET(v)   ((ubyte8) atomic64_add_return(1, &(v)))
#else
#define ATOMIC_T            atomic_t
#define ATOMIC_SET(v, i)    atomic_set(&(v), (int)(i))
#define ATOMIC_GET(v)       ((ubyte4) atomic_read(&(v)))
#define ATOMIC_INC_GET(v)   ((ubyte4) atomic_add_return(1, &(v)))
#endif
#endif
#ifndef DECL_SA_LOCK
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#define DECL_SA_LOCK        spinlock_t lock;
#define INIT_SA_LOCK(sa)    spin_lock_init(&(sa)->lock);
#define DOWN_SA_LOCK(sa)    spin_lock_bh(&(sa)->lock);
#define UP_SA_LOCK(sa)      spin_unlock_bh(&(sa)->lock);
#endif

#elif defined(__QNX_RTOS__) && defined(_KERNEL)
#ifndef DECL_SA_LOCK
#include <pthread.h>
#define DECL_SA_LOCK        pthread_spinlock_t lock;
#define INIT_SA_LOCK(sa)    pthread_spin_init(&(sa)->lock, PTHREAD_PROCESS_SHARED);
#define DOWN_SA_LOCK(sa)    pthread_spin_lock(&(sa)->lock);
#define UP_SA_LOCK(sa)      pthread_spin_unlock(&(sa)->lock);
#endif

#elif defined(__VXWORKS_RTOS__)
#ifndef IPCOM_KERNEL
#define IPCOM_KERNEL
#endif
#include <ipcom_os.h>

#ifndef ATOMIC_T
#include <vxWorks.h>
#include <vxAtomicLib.h>
#ifdef __ENABLE_IPSEC_ESN__
#define ATOMIC_T            atomic64_t
#define ATOMIC_SET(v, i)    vxAtomic64Set(&(v), (long long)(i))
#define ATOMIC_GET(v)       ((ubyte8) vxAtomic64Get(&(v)))
#define ATOMIC_INC_GET(v)   ((ubyte8) vxAtomic64Inc(&(v)))
#else
#define ATOMIC_T            atomic_t
#define ATOMIC_SET(v, i)    vxAtomicSet(&(v), (int)(i))
#define ATOMIC_GET(v)       ((ubyte4) vxAtomicGet(&(v)))
#define ATOMIC_INC_GET(v)   ((ubyte4) vxAtomicInc(&(v)))
#endif
#endif
#ifndef DECL_SA_LOCK
#define DECL_SA_LOCK        Ipcom_mutex lock;
#define INIT_SA_LOCK(sa)    ipcom_mutex_create(&(sa)->lock);
#define DOWN_SA_LOCK(sa)    ipcom_mutex_lock((sa)->lock);
#define UP_SA_LOCK(sa)      ipcom_mutex_unlock((sa)->lock);
#endif

#endif

#ifndef ATOMIC_T
#ifdef __ENABLE_IPSEC_ESN__
#define ATOMIC_T            ubyte8
#else
#define ATOMIC_T            ubyte4
#endif
#endif
#ifndef ATOMIC_GET
#define ATOMIC_GET(v)       v
#endif

#ifndef DECL_SA_LOCK
#define DECL_SA_LOCK
#endif
#ifndef INIT_SA_LOCK
#define INIT_SA_LOCK(sa)
#endif
#ifndef DOWN_SA_LOCK
#define DOWN_SA_LOCK(sa)
#endif
#ifndef UP_SA_LOCK
#define UP_SA_LOCK(sa)
#endif


/*------------------------------------------------------------------*/

struct SADB_hmacSuiteInfo;
struct SADB_cipherSuiteInfo;
struct spd;

/* Security Association (SA) */
typedef struct sadb
{
    struct sadb *pNext;             /* for ''old', 'free' or 'deleted' list */

    ubyte4      saFlags;            /* direction, initiator, etc.; see "ipseckey.h" */

    ubyte       oSaProto;           /* IPPROTO_AH, IPPROTO_ESP, or 0 (both) */
    ubyte4      dwSaSpi;            /* SPI to use */

    MOC_IP_ADDRESS_S dwSaDestAddr;  /* destination IP address (in host byte order) */
    MOC_IP_ADDRESS_S dwSaSrcAddr;   /* source IP address (in host byte order); 0=unspecified */

#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    ubyte4      cookie;             /* developer customizable cookie, e.g. VLan id */
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2      wSaUdpEncPort;      /* peer's UDP-encapsulation port number; 0=no UDP-encap. */
#endif
    ubyte2      wSaDestPort;        /* destination port number; 0=any or N/A */
    ubyte2      wSaSrcPort;         /* source port number; 0=any or N/A */
    ubyte       oSaUlp;             /* upper layer protocol; 0=any o/w see "ipsec_protos.h" */

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    ubyte       oSaMode;            /* IPSEC_MODE_TRANSPORT, IPSEC_MODE_TUNNEL, or 0 (don't care) */
    MOC_IP_ADDRESS_S
                dwSaDestIP, dwSaDestIPEnd;  /* private destination IP range (in host byte order); tunnel mode only */
    MOC_IP_ADDRESS_S
                dwSaSrcIP, dwSaSrcIPEnd;    /* private source IP range (in host byte order); tunnel mode only */
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    MOC_IP_ADDRESS_S dwSaSrcIPList[MAX_IP_IN_FQDN];     /* source IP range lower limit */

    MOC_IP_ADDRESS_S dwSaDestIPList[MAX_IP_IN_FQDN];

    ubyte4  dwSaDestIPCount;
    ubyte4  dwSaSrcIPCount;

    ubyte fqdn[MOC_MAX_FQDN_LEN]; /* store fqdn here*/

    intBoolean inbound;

    ubyte4 fqdnUniqueKey;

#endif
    ubyte       poAuthKey[IPSEC_AUTHKEY_MAX];   /* authentication key */
    struct SADB_hmacSuiteInfo *pHmacSuite;

    ubyte2      wEncrKeyLen;                    /* encryption key length (in bytes); GCM salt included */
    ubyte       poEncrKey[IPSEC_ENCRKEY_MAX];   /* encryption key */
    struct SADB_cipherSuiteInfo *pCipherSuite;

    BulkCtx     pCipherCtx,
                pCipherCtxM;        /* for manual keying inbound SA */
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
    sbyte4      users;
#endif

#ifdef __IPSEC_SINGLE_PASS_SUPPORT__
    ubyte4      dwSinglePassCookie; /* HW offload single pass support */
#endif
    ubyte4      dwSaEstablished;    /* system uptime (in ms) when this SA was established */
    ubyte4      dwSaExpSecs;        /* expire after so many seconds have elapsed */

    ubyte2      wSaCurBytes;        /* current count of bytes < 1k */
    ubyte4      dwSaCurKBytes;      /* current count of kbytes */
    ubyte4      dwSaExpKBytes;      /* expire after so many kbytes processed */

    ubyte4      dwSaTotPackets;     /* number of packets gone through this SA */
    ubyte4      dwSaCurPackets;     /* number of packets processed */

    ubyte4      dwSaLastUsed;       /* system uptime (in ms) when this SA was last used */

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    ubyte4      dwSaFirstUsed;      /* system uptime (in ms) when
                                       [outbound] first used after its mirrored inbound SA was last used OR
                                       [inbound] IKE was last informed of this SA's connection or deletion
                                     */
    ubyte4      dwSaLastRekey;      /* system uptime (in ms) at
                                       [outbound] last rekeying attempt OR [inbound] deletion
                                     */
    struct sadb *pxSaM;             /* mirrored SA */
    ubyte4      dwIdM;              /* mirrored SA's internal ID */

    struct spd  *pxSp;              /* trigger SP */
    ubyte4      dwSpdId;            /* trigger SP's internal ID */
    sbyte4      iNest;              /* SA bundle index in the trigger SP */

    ubyte4      dwIkeSaId;          /* parent IKE_SA's internal ID */
    sbyte4      ikeSaLoc;           /* parent IKE_SA's locator */
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

    ubyte4      dwId;               /* internal ID; reset to 0 when deleted */

    union
    {
        struct /* inbound */
        {
#ifdef IPSEC_REPLAY_SIZE
            ubyte    poReplayWindow[IPSEC_REPLAY_SIZE / 8]; /* anti-replay window */
#endif
            ATOMIC_T seqB;          /* lower bound of anti-replay window */
#ifdef __ENABLE_IPSEC_ESN__
            ATOMIC_T seqT;          /* highest sequence number authenticated so far */
#endif
        } i;

        struct /* outbound */
        {
#ifdef IPSEC_REPLAY_SIZE
            ubyte    unused[IPSEC_REPLAY_SIZE / 8];
#endif
            ATOMIC_T seq;           /* sequence number */
        } o;

#if 1 /* defined(LOADCONFIG_DUMP_TO_STDOUT) */
        struct /* loadConfig -d */
        {
#ifdef IPSEC_REPLAY_SIZE
            ubyte    unused[IPSEC_REPLAY_SIZE / 8];
#endif
#ifdef __ENABLE_IPSEC_ESN__
            ubyte8   seq;
#else
            ubyte4   seq;
#endif
        } d;
#endif

    } u;

#ifdef CUSTOM_IPSEC_FILTER_DSCP
    void       *pDscpValues;
#endif


#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
    intBoolean   avoidExpire;   /* SA expiration will not be checked*/
#endif


    /* Note: The rest of this structure must not be affected by zeroization! */
    /* See ZEROIZE_SA in "sadb.c" */

#if 1 /*defined(__IPSEC_SADB_MALLOC__)*/
    sbyte4      loc;                /* locator */
#endif

/* Leave this lock at the end of the structure */
    DECL_SA_LOCK

} *SADB, **PSADB;


/* Security Association (SA) */
typedef struct sadbCompat
{
    ubyte4 pNext;             /* for ''old', 'free' or 'deleted' list */

    ubyte4      saFlags;            /* direction, initiator, etc.; see "ipseckey.h" */

    ubyte       oSaProto;           /* IPPROTO_AH, IPPROTO_ESP, or 0 (both) */
    ubyte4      dwSaSpi;            /* SPI to use */

    MOC_IP_ADDRESS_S dwSaDestAddr;  /* destination IP address (in host byte order) */
    MOC_IP_ADDRESS_S dwSaSrcAddr;   /* source IP address (in host byte order); 0=unspecified */


#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    ubyte4      cookie;             /* developer customizable cookie, e.g. VLan id */
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2      wSaUdpEncPort;      /* peer's UDP-encapsulation port number; 0=no UDP-encap. */
#endif
    ubyte2      wSaDestPort;        /* destination port number; 0=any or N/A */
    ubyte2      wSaSrcPort;         /* source port number; 0=any or N/A */
    ubyte       oSaUlp;             /* upper layer protocol; 0=any o/w see "ipsec_protos.h" */

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    ubyte       oSaMode;            /* IPSEC_MODE_TRANSPORT, IPSEC_MODE_TUNNEL, or 0 (don't care) */
    MOC_IP_ADDRESS_S
                dwSaDestIP, dwSaDestIPEnd;  /* private destination IP range (in host byte order); tunnel mode only */
    MOC_IP_ADDRESS_S
                dwSaSrcIP, dwSaSrcIPEnd;    /* private source IP range (in host byte order); tunnel mode only */
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    MOC_IP_ADDRESS_S dwSaSrcIPList[MAX_IP_IN_FQDN];     /* source IP range lower limit */

    MOC_IP_ADDRESS_S dwSaDestIPList[MAX_IP_IN_FQDN];

    ubyte4  dwSaDestIPCount;
    ubyte4  dwSaSrcIPCount;

    ubyte fqdn[MOC_MAX_FQDN_LEN]; /* store fqdn here*/

    intBoolean inbound;

    ubyte4 fqdnUniqueKey;

#endif
    ubyte       poAuthKey[IPSEC_AUTHKEY_MAX];   /* authentication key */
    ubyte4      pHmacSuite;

    ubyte2      wEncrKeyLen;                    /* encryption key length (in bytes); GCM salt included */
    ubyte       poEncrKey[IPSEC_ENCRKEY_MAX];   /* encryption key */
    ubyte4      pCipherSuite;

    ubyte4     pCipherCtx,
                pCipherCtxM;        /* for manual keying inbound SA */
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
    sbyte4      users;
#endif

#ifdef __IPSEC_SINGLE_PASS_SUPPORT__
    ubyte4      dwSinglePassCookie; /* HW offload single pass support */
#endif
    ubyte4      dwSaEstablished;    /* system uptime (in ms) when this SA was established */
    ubyte4      dwSaExpSecs;        /* expire after so many seconds have elapsed */

    ubyte2      wSaCurBytes;        /* current count of bytes < 1k */
    ubyte4      dwSaCurKBytes;      /* current count of kbytes */
    ubyte4      dwSaExpKBytes;      /* expire after so many kbytes processed */

    ubyte4      dwSaTotPackets;     /* number of packets gone through this SA */
    ubyte4      dwSaCurPackets;     /* number of packets processed */

    ubyte4      dwSaLastUsed;       /* system uptime (in ms) when this SA was last used */

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    ubyte4      dwSaFirstUsed;      /* system uptime (in ms) when
                                       [outbound] first used after its mirrored inbound SA was last used OR
                                       [inbound] IKE was last informed of this SA's connection or deletion
                                     */
    ubyte4      dwSaLastRekey;      /* system uptime (in ms) at
                                       [outbound] last rekeying attempt OR [inbound] deletion
                                     */
    ubyte4      pxSaM;             /* mirrored SA */
    ubyte4      dwIdM;              /* mirrored SA's internal ID */

    ubyte4      pxSp;              /* trigger SP */
    ubyte4      dwSpdId;            /* trigger SP's internal ID */
    sbyte4      iNest;              /* SA bundle index in the trigger SP */

    ubyte4      dwIkeSaId;          /* parent IKE_SA's internal ID */
    sbyte4      ikeSaLoc;           /* parent IKE_SA's locator */
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

    ubyte4      dwId;               /* internal ID; reset to 0 when deleted */

    union
    {
        struct /* inbound */
        {
#ifdef IPSEC_REPLAY_SIZE
            ubyte    poReplayWindow[IPSEC_REPLAY_SIZE / 8]; /* anti-replay window */
#endif
            ATOMIC_T seqB;          /* lower bound of anti-replay window */
#ifdef __ENABLE_IPSEC_ESN__
            ATOMIC_T seqT;          /* highest sequence number authenticated so far */
#endif
        } i;

        struct /* outbound */
        {
#ifdef IPSEC_REPLAY_SIZE
            ubyte    unused[IPSEC_REPLAY_SIZE / 8];
#endif
            ATOMIC_T seq;           /* sequence number */
        } o;

#if 1 /* defined(LOADCONFIG_DUMP_TO_STDOUT) */
        struct /* loadConfig -d */
        {
#ifdef IPSEC_REPLAY_SIZE
            ubyte    unused[IPSEC_REPLAY_SIZE / 8];
#endif
#ifdef __ENABLE_IPSEC_ESN__
            ubyte8   seq;
#else
            ubyte4   seq;
#endif
        } d;
#endif

    } u;

#ifdef CUSTOM_IPSEC_FILTER_DSCP
    ubyte4  pDscpValues;
#endif


#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
    intBoolean   avoidExpire;   /* SA expiration will not be checked*/
#endif


    /* Note: The rest of this structure must not be affected by zeroization! */
    /* See ZEROIZE_SA in "sadb.c" */

#if 1 /*defined(__IPSEC_SADB_MALLOC__)*/
    sbyte4      loc;                /* locator */
#endif

/* Leave this lock at the end of the structure */
    DECL_SA_LOCK

} *SADBCOMPAT;

/*------------------------------------------------------------------*/

MOC_EXTERN SADB IPSEC_enumSa(SADB pxSa);


/*------------------------------------------------------------------*/
/* internal use only */

struct ipsecKeyEx;

MOC_EXTERN MSTATUS  IPSEC_initSadb(void);
MOC_EXTERN MSTATUS  IPSEC_flushSadb(void);

MOC_EXTERN MSTATUS  IPSEC_newSa(struct ipsecKeyEx *pxKey, SADB *ppxSa
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
                          , struct spd *pxSp
#endif
                            );
MOC_EXTERN MSTATUS  IPSEC_delSa(SADB pxSa, intBoolean bInfo);

MOC_EXTERN intBoolean IPSEC_expireSa(ubyte4 timenow, SADB pxSa);

MOC_EXTERN MSTATUS  IPSEC_findSa(ubyte4 dwSpi,
                             MOC_IP_ADDRESS dwDestAddr, MOC_IP_ADDRESS dwSrcAddr,
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
                             ubyte* fqdn,
#endif
                             ubyte oSaProto,
                             intBoolean bInbound,
                             SADB *ppxSa);

MOC_EXTERN MSTATUS  IPSEC_getSa(MOC_IP_ADDRESS dwDestAddr, MOC_IP_ADDRESS dwSrcAddr,
                            ubyte oProto, ubyte2 wDestPort, ubyte2 wSrcPort,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                            MOC_IP_ADDRESS dwTunlDestIP, MOC_IP_ADDRESS dwTunlSrcIP,
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
                            ubyte2 wUdpEncPort,
#endif
#ifdef CUSTOM_IPSEC_FILTER_DSCP
                            ubyte oDscp,
#endif
                            struct spd *pxSp, SADB *axSa MOC_COOKIE(cookie));

#ifdef __ENABLE_RB_SADB__
MOC_EXTERN MSTATUS  IPSEC_addSaIndex(SADB pxSa);
MOC_EXTERN MSTATUS  IPSEC_delSaIndex(SADB pxSa);
MOC_EXTERN ubyte4 IPSEC_mapIpToKey(MOC_IP_ADDRESS_S destAddr);
#endif


#ifdef __cplusplus
}
#endif

#endif /* __SADB_HEADER__ */

