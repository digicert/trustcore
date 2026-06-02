/**
 * @file  ikesa.h
 * @brief IKE Security Association definitions.
 *
 * @details    IKE (ISAKMP) SA structures and state definitions.
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

#ifndef __IKESA_HEADER__
#define __IKESA_HEADER__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#ifdef __cplusplus
extern "C" {
#endif

#ifndef IPSEC_NEST_MAX
#define IPSEC_NEST_MAX 1 /* no SA bundle support by default */
#ifdef __WIN32_RTOS__
#pragma message ("IPSEC_NEST_MAX should be defined")
#else
#warning "IPSEC_NEST_MAX should be defined"
#endif
#endif


/*------------------------------------------------------------------*/

#define IKE_SA_FLAG_INUSE           0x00000001
#define IKE_SA_FLAG_DELETED         0x00000002
#define IKE_SA_FLAG_INITIATOR       0x00000004
#define IKE_SA_FLAG_MATURE          0x00000008

/* internal use only */

#define IKE_SA_FLAG_CR              0x00000010
#define IKE_SA_FLAG_DPD             0x00000020
#define IKE_SA_FLAG_INIT_C          0x00000040
#define IKE_SA_FLAG_NEW             0x00000080
#define IKE_SA_FLAG_REKEYED         0x00000100
#define IKE_SA_FLAG_PKICLIENT_CERT  0x00000200
#define IKE_SA_FLAG_PKICLIENT_CRL   0x00000400
#define IKE_SA_FLAG_FRAGMENTATION   0x00000800
#define IKE_SA_FLAG_TX_INIT_C       0x40000000
#define IKE_SA_FLAG_RESERVED        0x80000000

/* [v1] */
#define IKE_SA_FLAG_KE              0x00001000
#define IKE_SA_FLAG_XAUTH           0x00002000
#define IKE_SA_FLAG_COMMIT          0x00004000 /* responder, aggr */
#define IKE_SA_FLAG_LIFETIME        0x00008000 /* responder, main, notify */
#define IKE_SA_FLAG_LIFETIME_SECS   0x00010000
#define IKE_SA_FLAG_LIFETIME_KBYTES 0x00020000
#define IKE_SA_FLAG_GDOI            0x00040000
#define IKE_SA_FLAG_GDOI_PUSH       0x00080000

/* [v2] */
#define IKE_SA_FLAG_DELETING        0x00100000
#define IKE_SA_FLAG_EAP             0x00200000
#define IKE_SA_FLAG_EAP_DONE        0x00400000
#define IKE_SA_FLAG_MOBILE          0x00800000
#define IKE_SA_FLAG_ORIG_INITR      0x01000000
#define IKE_SA_FLAG_REAUTH          0x02000000
#define IKE_SA_FLAG_UPDATING        0x04000000
#define IKE_SA_FLAG_REDIRECTED      0x08000000
#define IKE_SA_FLAG_CR_OCSP         0x00010000 /* OCSP request CERTREQ payload */
#define IKE_SA_FLAG_CERT_OCSP       0x00020000 /* OCSP response CERT payload */
#define IKE_SA_FLAG_MULTI_AUTH      0x00040000
#define IKE_SA_FLAG_EAP_ONLY        0x00080000
#define IKE_SA_FLAG_USEPPK          0x00004000
#define IKE_SA_FLAG_PPK_ID          0x00008000


/*------------------------------------------------------------------*/

/* CHILD SA flags */
#define IKE_CHILD_FLAG_INUSE        0x0001
#define IKE_CHILD_FLAG_DELETED      0x0002
#define IKE_CHILD_FLAG_INITIATOR    0x0004
#define IKE_CHILD_FLAG_MATURE       0x0008
#define IKE_CHILD_FLAG_LIFETIME     0x0800  /* [v1] responder, notify */
#define IKE_CHILD_FLAG_V2           0x1000
#define IKE_CHILD_FLAG_ID2          0x2000  /* [v1] */
#define IKE_CHILD_FLAG_COMMIT       0x4000  /* [v1] responder */
#define IKE_CHILD_FLAG_CONNECT2     0x8000  /* [v2] initiator, SA_INIT */

/* PROPOSAL (child SA) flags */
#ifndef __ENABLE_DIGICERT_PFKEY__     /* initiator (wildcard) */
#define IKE_PROP_FLAG_TFM_ID        0x0001
#define IKE_PROP_FLAG_AUTH_ALGO     0x0002
#define IKE_PROP_FLAG_ENCR_ALGO     0x0004
#define IKE_PROP_FLAG_ENCR_KEYLEN   0x0008
#endif
#define IKE_PROP_FLAG_UDP_ENCP      0x0100
#define IKE_PROP_FLAG_ESN           0x0200

/* Exchange flags */
#define IKE_XCHG_FLAG_INUSE         0x0001
#define IKE_XCHG_FLAG_DELETED       0x0002
#define IKE_XCHG_FLAG_INITIATOR     0x0004
#define IKE_XCHG_FLAG_PENDING       0x0008
#define IKE_XCHG_FLAG_UPDATE_SA     0x0010  /* [v2] MOBIKE */
#define IKE_XCHG_FLAG_COOKIE2       0x0020  /* [v2] MOBIKE, initiator */

/* NAT-T flags */
#define IKE_NATT_FLAG_D             0x01
#define IKE_NATT_FLAG_US            0x02
#define IKE_NATT_FLAG_PEER          0x04
#define IKE_NATT_FLAG_USE_NPORT     0x08
#define IKE_NATT_FLAG_NPORT_USED    0x10
#define IKE_NATT_FLAG_NOT_ALLOWED   0x20    /* [v2] MOBIKE */


/*------------------------------------------------------------------*/
/* key sizes */

/* Warning: Must update as needed (e.g. when new algorithms are
   supported).  See "ike_crypto.c".
 */

#if !defined(__DISABLE_DIGICERT_SHA512__)
#define IKE_HASH_MAX        64          /* SHA512_RESULT_SIZE */
#elif !defined(__DISABLE_DIGICERT_SHA384__)
#define IKE_HASH_MAX        48          /* SHA384_RESULT_SIZE */
#elif !defined(__DISABLE_DIGICERT_SHA256__)
#define IKE_HASH_MAX        32          /* SHA256_RESULT_SIZE */
#else
#define IKE_HASH_MAX        20          /* SHA_HASH_RESULT_SIZE */
#endif

#define IKE_IV_MAX      IKE_HASH_MAX    /* > 16 (AES_BLOCK_SIZE) */
#define IKE_AUTHKEY_MAX IKE_HASH_MAX    /* [v2] */


#if   !defined(__DISABLE_DIGICERT_SHA384__) && defined(__ENABLE_BLOWFISH_CIPHERS__)
#define IKE_ENCRKEY_MAX     (96)        /* 2xSHA384_RESULT_SIZE > 56 (blowfish) */

#elif !defined(__DISABLE_DIGICERT_SHA256__) && defined(__ENABLE_BLOWFISH_CIPHERS__)
#define IKE_ENCRKEY_MAX     (64)        /* 2xSHA256_RESULT_SIZE > 56 (blowfish) */

#elif !defined(__DISABLE_DIGICERT_SHA512__)
#define IKE_ENCRKEY_MAX     (64)        /* SHA512_RESULT_SIZE */

#elif defined(__ENABLE_BLOWFISH_CIPHERS__)
#define IKE_ENCRKEY_MAX     (60)        /* 3xSHA_HASH_RESULT_SIZE > 56 (blowfish) */

#elif !defined(__DISABLE_DIGICERT_SHA384__)
#define IKE_ENCRKEY_MAX     (48)        /* SHA384_RESULT_SIZE */

#elif !(defined(__DISABLE_AES256_CIPHER__) || defined(__DISABLE_AES_CIPHERS__))
#define IKE_ENCRKEY_MAX     (40)        /* 2xSHA_HASH_RESULT_SIZE > 32 (aes-256) */

#elif !(defined(__DISABLE_AES192_CIPHER__) || defined(__DISABLE_AES_CIPHERS__))
#define IKE_ENCRKEY_MAX     (40)        /* 2xSHA_HASH_RESULT_SIZE > 24 (aes-192) */

#elif !defined(__DISABLE_3DES_CIPHERS__)
#define IKE_ENCRKEY_MAX     (40)        /* 2xSHA_HASH_RESULT_SIZE > 24 (3des) */

#elif !defined(__DISABLE_DIGICERT_SHA256__)
#define IKE_ENCRKEY_MAX     (32)        /* SHA256_RESULT_SIZE */

#elif !(defined(__DISABLE_AES128_CIPHER__) || defined(__DISABLE_AES_CIPHERS__))
#define IKE_ENCRKEY_MAX     (20)        /* SHA_HASH_RESULT_SIZE > 16 (aes-128) */

#elif defined(__ENABLE_DES_CIPHER__)
#define IKE_ENCRKEY_MAX     (20)        /* SHA_HASH_RESULT_SIZE > 8 (des) */

#endif


#include "../ike/ike_childsa.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"

#ifdef __ENABLE_DIGICERT_PQC__
#include "../crypto_interface/crypto_interface_qs.h"
#endif

/*------------------------------------------------------------------*/

#define IKE_COOKIE_SIZE         (8)
#define IKE_P1_SPI_SIZE         (IKE_COOKIE_SIZE * 2)

#define IKE_LIFE_SECS_MAX       ((ubyte4)4294967) /* = (256^4 / 1000) secs */


/*------------------------------------------------------------------*/

#ifdef __IKE_UPDATE_TIMER__
#define IKE_ADD_TIMER_EVT(_t, _c, _sa, _cf, _n, _e, _h) \
            TIMER_schedule(m_ikeTimer, (ubyte4)_t, (sbyte4)_c, \
                           (_sa ? (_sa)->dwId : 0), \
                           (void *)_sa, _cf, (sbyte *)_n, &(_h), &(_e))
#define IKE_DEL_TIMER_EVT(_e, _h)   { \
                 if (_h) { TIMER_unschedule(_h); _h = NULL; }  \
                 _e = 0; }
#endif


/*------------------------------------------------------------------*/
#define MOC_MAX_FQDN_LEN 20
struct diffieHellmanContext;
struct ECCKey;

struct ike_event;

typedef struct ipsecpps
{
    ubyte2  p_flags;        /* see IKE_PROP_FLAG_... */

    ubyte   oPpsNo;
    ubyte   oTfmNo;         /* [v1] */

    ubyte   oSecuProto;     /* IPSEC_PROTO_AH (0)
                               IPSEC_PROTO_ESP
                               IPSEC_PROTO_ESP_AUTH
                               IPSEC_PROTO_ESP_NULL
                               (initiator)
                               */
    ubyte   oProtocol;      /* PROTO_IPSEC_AH
                               PROTO_IPSEC_ESP
                               */
    ubyte   oTfmId;         /* AH_MD5
                               AH_SHA
                               ESP_NULL */
    ubyte   oEncrAlgo;      /* ESP_DES
                               ESP_3DES
                               ESP_BLOWFISH
                               ESP_AES
                               etc.
                               */
    /* AUTH_ALGORITHM */
    ubyte2  wAuthAlgo;      /* AUTH_ALGORITHM_HMAC_MD5
                               AUTH_ALGORITHM_HMAC_SHA
                               etc.
                               */
    /* ENCAPSULATION_MODE */
    ubyte2  wMode;          /* ENCAPSULATION_MODE_TUNNEL
                               ENCAPSULATION_MODE_TRANSPORT
                               */
    /* SA_LIFE_TYPE */
    /* SA_LIFE_DURATION */
    ubyte4  dwExpSecs;      /* SA_LIFE_TYPE_SECONDS */
    ubyte4  dwExpKBytes;    /* SA_LIFE_TYPE_KBYTES */

    ubyte4  dwAdjSecs,      /* [v1] adjusted lifetime (responder) */
            dwAdjKBytes;

    /* KEY_LENGTH */
    ubyte2  wEncrKeyLen;
    ubyte2  wAuthKeyLen;    /* [v2] */

#ifndef __ENABLE_DIGICERT_PFKEY__
    /* special case - AEAD algo w/ WILDCARD tag size (initiator) */
    ubyte   oAeadAlgo;
    ubyte   aeadTag;
#endif

    /* {I, R} */
    ubyte4  dwSpi[2];

#ifdef __ENABLE_DIGICERT_IPCOMP__
    ubyte   oCompTfmNo;     /* [v1] responder */
    ubyte   oCompAlgo;      /* IP compression algorithm, e.g. IPCOMP_DEFLATE */
    ubyte2  wCpi[2];        /* Compression Parameter Index {I, R} */
#endif

} *IPSECPPS;


typedef struct ipsecsa
{
    ubyte2  c_flags;

    ubyte4  dwTimeStart;    /* system uptime (in ms) at quick mode exchange start */
    ubyte   oState;         /* quick mode exchange state (see "ike_state.h") */

    /* nonce */
    ubyte   poNonce[IKE_NONCE_SIZE];

    ubyte   *poNi_b;
    ubyte2  wNi_bLen;

    ubyte   *poNr_b;
    ubyte2  wNr_bLen;

    /* DH group description */
    ubyte2  wPFS;
    struct diffieHellmanContext *p_dhContext;

#ifdef CUSTOM_IKE_GET_P2_PFS
    ubyte2  *pwDhGrps;
    sbyte4  numDhGrps;
#endif

#ifdef __ENABLE_DIGICERT_PQC__
    QS_CTX *pQsCtx;
    ubyte *pQsCipherText;
    ubyte4 qsCipherTextLen;
    ubyte *pQsSharedSecret;
    ubyte4 qsSharedSecretLen;
#endif

#ifdef __ENABLE_DIGICERT_ECC__
    struct ECCKey *p_eccKey;
    ubyte   *poEccSharedSecret;
    sbyte4  eccSharedSecretLen;
#endif

    /* client identities {I, R} */
    ubyte   oUlp;
    ubyte2  wPort[2],
            wPortEnd[2]; /* v2 */
    IKE_ID_T IDc_t[2]; /* [v1] */

    MOC_IP_ADDRESS_S dwIP[2], dwIPEnd[2]; /* IP address range */
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    sbyte   fqdn[MOC_MAX_FQDN_LEN];
#endif

    /* SA's and proposals */
    struct
    {
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
            ubyte4  cookie;     /* developer customizable cookie; e.g. PF_KEY reqid */
#endif
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
            sbyte4  ifid;       /* interface ID; 0=any */
#endif
            ubyte4  dwSeqNo;    /* sequence#, e.g. PF_KEY */
            ubyte4  dwSpdId;    /* ID of trigger IPsec SP */
            sbyte4  spdIndex;   /* index of trigger IPsec SP */

#ifdef __ENABLE_DIGICERT_PFKEY__
            ubyte   oReplay;
#endif
            struct
            {
                    struct ipsecpps ipsecPps;
#ifdef __ENABLE_DIGICERT_PFKEY__
                    /* SA combos; initiator only */
                    ubyte oIPsecPpsNum;
                    struct ipsecpps *pxIPsecPps;
#endif
                    /* IPsec keys {I, R} */
                    ubyte poKey[2][CHILDSA_ENCRKEY_MAX + CHILDSA_AUTHKEY_MAX];
            }
                    axChildSa[IPSEC_NEST_MAX]; /* outermost first */
            ubyte   oChildSaLen;
    }
            axP2Sa[IKE_P2_SA_MAX];
    ubyte   oP2SaNum;

    /* CHILD_SA trigger event; initiator only */
    struct ike_event_q *pxEvt;
    ubyte4  dwEvtId;

    MSTATUS merror;     /* status code */
    ubyte2  wMsgType;   /* [v2] Notify error code; IKE_AUTH only */

    ubyte *pDhPeerPubKey;
    ubyte4 dhPeerPubKeyLen;
    ubyte *pDhSharedSecret;
    ubyte4 dhSharedSecretLen;

} *IPSECSA;


/*------------------------------------------------------------------*/

#ifdef __IKE_SADB_MALLOC__
#define P2XG_IPSECSA(x) ((x)->pxIPsecSa)
#else
#define P2XG_IPSECSA(x) (&((x)->ipsecSa))
#endif

struct ikesa;

typedef struct p2xg
{
    ubyte2  x_flags;
    ubyte4  dwTimeStart;        /* system uptime (in ms) at phase 2 exchange start */
    ubyte4  dwTimeStamp;        /* system uptime (in ms) at last outbound exchange */

    ubyte4  dwMsgId;            /* in network byte order - do not convert! */
    ubyte   oState;             /* phase 2 exchange state (see "ike_state.h") */

    ubyte   poIv[IKE_IV_MAX];   /* encryption iv (initialization vector) */
    ubyte   poIvOld[IKE_IV_MAX];/* previous iv; for re-transmission */

#ifdef __IKE_UPDATE_TIMER__
    IKE_TIMER_EVT_T expTimerId;
    IKE_TIMER_HDL_T expTimerHdl;

    /* re-transmission */
    ubyte   *poRtxMsg;           /* include non-ESP marker */
    ubyte4  dwRtxMsgLen;
    sbyte4  rtxCount;
    IKE_TIMER_EVT_T rtxTimerId;
    IKE_TIMER_HDL_T rtxTimerHdl;
#endif
#ifdef __ENABLE_IKE_FRAGMENTATION__
    ubyte2  wRtxFragId;
#endif

#ifdef __IKE_SADB_MALLOC__
    struct ipsecsa *pxIPsecSa;
#else
    struct ipsecsa ipsecSa;
#endif
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
    /* IKECFG - last outbound attributes */
    ubyte   oCfgType;           /* CFG_{REQUEST | REPLY | SET | ACK } */
    ubyte2  wCfgId;
    ubyte   *poCfgAttrs;
    ubyte2  wCfgAttrsLen;

    MSTATUS merror;             /* status code */
#endif

} *P2XG;


/*------------------------------------------------------------------*/
/* [v2] */

struct IKE_stateInfo;
struct ike_info;

typedef struct ike2xg
{
    ubyte2  x_flags;
    ubyte4  dwTimeStart;            /* system uptime (in ms) at exchange start */
    ubyte4  dwTimeStamp;            /* system uptime (in ms) at last outbound exchange */

    ubyte   oExchange;
    ubyte4  dwMsgId;

    struct IKE_stateInfo *pState;

#ifdef __ENABLE_IKE_FRAGMENTATION__
    /* reassembly */
    ubyte   oEfNextPayload;
    ubyte   *poEfBody[IKE2_FRAG_MAX];
    ubyte2  wEfBodyLen[IKE2_FRAG_MAX];
#endif

    /* inbound re-transmission */
    sbyte4  numIcvs;
#ifdef __ENABLE_IKE_FRAGMENTATION__
    ubyte   *poIcv[IKE2_FRAG_MAX];
#else
    ubyte   *poIcv[1];
#endif

    /* outbound re-transmission */
    sbyte4  numMsgs;
#ifdef __ENABLE_IKE_FRAGMENTATION__
    ubyte   *poMsg[IKE2_FRAG_MAX];
    ubyte4  dwMsgLen[IKE2_FRAG_MAX];
#else
    ubyte   *poMsg[1];              /* include non-ESP marker */
    ubyte4  dwMsgLen[1];
#endif
#ifdef __IKE_UPDATE_TIMER__
    sbyte4  rtxCount;
    IKE_TIMER_EVT_T rtxTimerId;
    IKE_TIMER_HDL_T rtxTimerHdl;
    IKE_TIMER_HDL_T expTimerHdl;
    IKE_TIMER_EVT_T expTimerId;
#endif

    ubyte4 dwSaId; /* REKEY_SA only */
    struct ikesa *pxSa;
    struct ipsecsa *pxIPsecSa;
    struct ike_info *pxInfo;

#ifdef __ENABLE_IKE_CP__
    ubyte   oCfgType;   /* CFG_{REQUEST | REPLY } */
    ubyte   *poCfgAttrs;
    ubyte2  wCfgAttrsLen;
#endif
#ifdef __ENABLE_MOBIKE__
    MSTATUS merror;     /* status code */
    ubyte2  wMsgType;   /* Notify error code (initiator only)
                           valid if (status code == ERR_IKE_NOTIFY_PAYLOAD) */
#endif
} *IKE2XG;


#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

struct ikesa;
struct eapMsgHdr;
struct IKE_eapSuiteInfo;

typedef struct ike2eap
{
    struct ikesa *pxSa;
    struct ike2xg *pxXg;

    IKE_EAP_PROTO_T proto; /* match either pEapSuite or pEapSuiteEx */
    const struct IKE_eapSuiteInfo *pEapSuite;

#ifdef __ENABLE_DIGICERT_EAP_PEER__
    const struct IKE_eapSuiteInfo *pEapSuiteEx; /* EAP_PROTO_ANY supplicant */

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    const struct IKE_eapSuiteInfo *pInnerEapSuite;
    void    *pInnerCbData;
    ubyte   *ttls_connection;
#endif
    const ubyte *identity;
    ubyte4 identityLen;
#endif

    void    *pCbData;           /* callback data */
    ubyte   *pSession;          /* session handle */
    struct eapMsgHdr *pxMsg;    /* last outbound EAP message */

    ubyte   *poMsk;             /* created shared key */
    ubyte4  dwMskLen;

} *IKE2EAP;

#endif


/*------------------------------------------------------------------*/

#ifdef __IKE_UPDATE_TIMER__
enum
{
    IKESA_TIMER_EXPIRATION = 0,
#ifdef __ENABLE_IKE_FRAGMENTATION__
    IKESA_TIMER_REASSEMBLY,
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    IKESA_TIMER_KEEPALIVE,
#endif
    IKESA_TIMER_NEWSA,  /* auto-rekeying new SA */
    IKESA_TIMER_OLDSA,  /* delayed deletion of rekeyed old SA */
    IKESA_TIMER_DPD,
    IKESA_TIMER_RUT,
    IKESA_TIMER_MAX
};
#endif


/*------------------------------------------------------------------*/

struct ikeIdHdr;
struct IKE_macSuiteInfo;
struct IKE_hashSuiteInfo;
struct IKE_cipherSuiteInfo;
struct ikeCertDescr;
struct AsymmetricKey;

#if defined(__ENABLE_IKE_FRAGMENTATION__)
typedef struct IKE_reassembly_list_t
{
    ubyte2                           fragId;
    ubyte2                           fragNum;
    ubyte                            lastFrag;
    ubyte4                           fragSize;
    ubyte*                           pBuffer;
    struct IKE_reassembly_list_t*    pNext;
} IKE_reassembly_list;
#endif

struct ikePeerConfig;
typedef struct ikesa
{
    void    *pNext;         /* for 'free' list or 'deleted' list */

    ubyte4  flags;
    ubyte   natt_flags;
    ubyte   oState;         /* [v1] phase 1 exchange state (see "ike_state.h") */

    ubyte4  dwTimeStart;    /* system uptime (in ms) at initial exchange */
    ubyte4  dwTimeStamp;    /* system uptime (in ms) at most recent outbound (phase 1),
                               inbound (phase 2), or inbound CHILD [v2] exchange */
    ubyte4  dwTimeCreated;  /* system uptime (in ms) at IKE_SA establishment */
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte4  dwTimeStampOut; /* for NAT keepalive */
#endif
#ifdef __IKE_UPDATE_TIMER__
    ubyte2  wExpDPD;        /* for responder */
    IKE_TIMER_EVT_T timerIDs[IKESA_TIMER_MAX];
    IKE_TIMER_HDL_T timerHdls[IKESA_TIMER_MAX];
#endif
    ubyte4  dwId;           /* internal ID; intact when deleted */
    ubyte4  dwId0;          /* [v2] original ID inherited from old SA */
    sbyte4  loc;            /* locator */

    ubyte   poCky_I[IKE_COOKIE_SIZE];   /* initiator cookie */
    ubyte   poCky_R[IKE_COOKIE_SIZE];   /* responder cookie */

    MOC_IP_ADDRESS_S dwPeerAddr;    /* IP adddress of the other negotiaing entity*/
    ubyte2  wPeerPort;

#if 1 /*defined(__IKE_MULTI_HOMING__) */
    sbyte4  serverInstance;
#endif
    MOC_IP_ADDRESS_S dwHostAddr;
    ubyte2  wHostPort;

#if defined(__ENABLE_IPSEC_COOKIE__) && !defined(__ENABLE_DIGICERT_PFKEY__)
    ubyte4  cookie;         /* developer customizable cookie; e.g. VLan id */
#endif

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    sbyte4  ifid;           /* interface ID; 0=any */
#endif

#if defined(CUSTOM_IKE_GET_P1_DHGRP) || defined(CUSTOM_IKE_GET_P2_PFS)
    ubyte2  *pwDhGrps;
    sbyte4  numDhGrps;
#endif

    struct ikesa *pxSaRekey;
    ubyte4 dwSaRekeyId; /* [v1] */

    /* lifetime */
    ubyte4  dwExpSecs;
    ubyte4  dwExpKBytes;
    ubyte4  dwCurKBytes;
    ubyte4  dwCurBytes;     /* count of bytes < 1k in addition to dwCurKBytes */

    /* TRUE if DH group to use is set */
    byteBoolean dhGrpSet;
    /* crypto suites */
    ubyte2  wDhGrp;         /* [v2] */
    struct diffieHellmanContext *p_dhContext;

#ifdef __ENABLE_DIGICERT_PQC__
    QS_CTX *pQsCtx;
    ubyte *pQsCipherText;
    ubyte4 qsCipherTextLen;
    ubyte *pQsSharedSecret;
    ubyte4 qsSharedSecretLen;
#endif

#ifdef __ENABLE_DIGICERT_ECC__
    struct ECCKey *p_eccKey;
    ubyte   *poEccSharedSecret;
    sbyte4  eccSharedSecretLen;

    struct ECCKey *p_eccKeyPeer; /* [v1] peer DH public value */

    ubyte   *poEcdsaSig; /* [v1] signature (out) - for re-transmission */
    ubyte2  wEcdsaSigLen;
#endif

    struct IKE_hashSuiteInfo *pHashSuite;

#ifdef CUSTOM_IKE_GET_HASH_ALGO
    sbyte4  numHashAlgos;
    ubyte2  *pwHashAlgos;
#endif

    struct IKE_macSuiteInfo *pMacSuite;
    ubyte2  wAuthKeyLen;    /* [v2] */

#ifdef CUSTOM_IKE_GET_INTEG_ALGO /* [v2] */
    sbyte4  numMacAlgos;
    ubyte2  *pwMacAlgos;
#endif

    struct IKE_cipherSuiteInfo *pCipherSuite;
    ubyte2  wEncrKeyLen;

#ifdef CUSTOM_IKE_GET_ENCR_ALGO
    sbyte4  numEncrAlgos;
    ubyte2  *pwEncrAlgos;
    ubyte2  *pwEncrKeyLens;
#endif

    /* [v1] SAi_b: initiator SA payload body (no generic header)
       [v2] IKE_INIT exchange messages (with SAi1 or SAr1 payloads); for IKE_AUTH */
    ubyte   *poMsg[2]; /* [v2] exclude non-ESP marker */
    ubyte4  dwMsgLen[2];

    /* nonce [_I, _R] */
    ubyte   nonce[IKE_NONCE_SIZE];
    ubyte   *poNonce[2];
    ubyte2  wNonceLen[2];

    struct ikeIdHdr *pxID[2];   /* Identification payloads */

#ifdef __ENABLE_IKE_FRAGMENTATION__
    ubyte2  maxSkBodyLen[2]; /* [v2] { SK, SKF } payloads */

    struct ikeHdr           ikeHeader;
    ubyte2                  fragId;
    IKE_reassembly_list*    pFragHash[IKE_FRAG_BUCKETS_MAX];
#ifndef __IKE_UPDATE_TIMER__
    ubyte                   *reassemblyTimerId;
    ubyte                   fragReceived;
#endif
#endif

    ubyte   oTfmNo; /* [v1] */
    ubyte   oPpsNo;         /* [v2] */

    struct ikeCertDescr *pCertChain;   /* host certificate chain */
    sbyte4  certChainLen;

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    ubyte4  dwSeqNo;            /* [GDOI] KEK sequence number */
    struct AsymmetricKey *pKey; /* [GDOI] KEK SIG key */
#endif

#ifdef __IKE_MULTI_THREADED__
    RTOS_THREAD tid;
#endif

    union
    {
        struct
        {
#ifdef __ENABLE_IPSEC_NAT_T__
            sbyte4  iNatT;
#endif
            ubyte4  dwDpdSeqNo;
            ubyte4  dwDpdTimeStart;
            ubyte4  dwDpdTimeStamp;

            ubyte   poKeyId[IKE_HASH_MAX];
            ubyte   poKeyId_d[IKE_HASH_MAX];        /* keying material to derive IPsec SA's */
            ubyte   poKeyId_a[IKE_HASH_MAX];        /* keying material for ISAKMP SA authentication */
            ubyte   poKeyId_e[IKE_ENCRKEY_MAX];     /* keying material for ISAKMP SA confidentiality */

            ubyte   poIv[IKE_IV_MAX];               /* encryption iv (initialization vector) */
            ubyte   poIvOld[IKE_IV_MAX];            /* previous iv - for re-transmit */

            ubyte2  pwIsaAttr[NUM_OAKLEY_ATTRIBUTE_TYPE];

            struct p2xg p2Xg[IKE_P2_MAX];

#ifdef __IKE_UPDATE_TIMER__
            /* re-transmission */
            IKE_TIMER_EVT_T rtxTimerId;
            IKE_TIMER_HDL_T rtxTimerHdl;
            ubyte   *poRtxMsg;       /* include non-ESP marker */
            ubyte4  dwRtxMsgLen;
#endif
#ifdef __ENABLE_IKE_FRAGMENTATION__
            ubyte2  wRtxFragId;
#endif
#ifdef IKE_P2_REPLAY_SIZE
            ubyte4  pdwMsgId[IKE_P2_REPLAY_SIZE];
            sbyte4  msgRplyIdx;
#endif
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
            ubyte2  wCfgId;
#endif
        } v1;

        struct
        {
            ubyte4  dwTimeAuthed;   /* system uptime (in ms) at IKE_AUTH establishment */
            ubyte4  dwExpAuthSecs;  /* rfc4478 Repeated Auth. */

            /* SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr */
            ubyte   SK[IKE_HASH_MAX*3 + IKE_AUTHKEY_MAX*2 + IKE_ENCRKEY_MAX*2]; /* keying material */
            ubyte   *SK_d;          /* CREATE_CHILD_SA */
            ubyte   *SK_a[2];       /* integrity key */
            ubyte   *SK_e[2];       /* encryption key */
            ubyte   *SK_p[2];       /* IKE_AUTH */

            struct ike2xg pxXg[2][IKE_WINDOW_SIZE];
            ubyte4  dwMsgId[2], dwWndLen[2], dwWndIdx[2];

            /* EAP */
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
            struct ike2eap eapState;
#endif
#ifdef __ENABLE_IKE_MULTI_AUTH__
            ubyte   oAuthMtd;       /* current auth method (host) */
            sbyte4  authMtds[2];    /* used auth methods (bit mask) [I,R]; see [v2] Auth Methods in "ike_defs.h" */
#endif
#if defined(__ENABLE_IKE_MULTI_AUTH__) || \
    (defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))
            /* responder only */
            IPSECSA pxIPsecSa;      /* piggybacked CHILD_SA */
            ubyte   *poSAi2;
#ifdef __ENABLE_IKE_CP__
            ubyte   *poCp;
#endif
#endif
#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
            /* peer's supported Signature Authentication Hash algorithms */
            sbyte4  numSahAlgos;
            ubyte2  sahAlgos[NUM_SIGAUTH_HASH];
#endif
        } v2;

    } u;

    MSTATUS merror;     /* status code */
    ubyte2  wMsgType;   /* [v2] Notify error code (initiator only)
                           valid if (status code == ERR_IKE_NOTIFY_PAYLOAD) */

    /* application-specific private use */
    MSTATUS merror_aux;
    ubyte4  flags_aux;

#ifdef __ENABLE_IKE_REDIRECT__
    ubyte*              redirectTimerId;
#endif

    /* Peer configuration object for this SA */
    struct ikePeerConfig *ikePeerConfig;

    ubyte *pDhPeerPubKey;
    ubyte4 dhPeerPubKeyLen;
    ubyte *pDhSharedSecret;
    ubyte4 dhSharedSecretLen;

} *IKESA;


/*------------------------------------------------------------------*/

#define IS_IKE2_SA(_sa) ((0x80000000 & (_sa)->dwId) ? TRUE : FALSE)

MOC_EXTERN IKESA    IKE_enumSa(IKESA pxSa, sbyte4 serverInstance);
/* Example:
        extern IKE_MUTEX g_ikeMtx;

        IKESA pxSa = NULL;

        IKE_LOCK_W;

        while (NULL != (pxSa = IKE_enumSa(pxSa, 0)))
        {
            // do work here
        }
        IKE_UNLOCK_W;
*/


/*------------------------------------------------------------------*/
/* internal use only */

struct ipsecKeyEx;
struct ike_context;

MOC_EXTERN MSTATUS  IKE_initSadb(void);
MOC_EXTERN MSTATUS  IKE_flushSadb(void);
MOC_EXTERN MSTATUS  IKE_updateSadb(void);

MOC_EXTERN IKESA    IKE_newSa(struct ikePeerConfig* config,
                          MOC_IP_ADDRESS dwPeerAddr, ubyte2 wPeerPort,
                          ubyte *poCky
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
                        , ubyte oExchange
#endif
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
                        , intBoolean bGdoi
#endif
                          MOC_NATT(bUseNattPort)
                          MOC_MTHM(serverInstance));

MOC_EXTERN MSTATUS  IKE_getSa(ubyte *poCky_I, ubyte *poCky_R, sbyte4 flag,
                        MOC_IP_ADDRESS dwPeerAddr, IKESA *ppxSa,
                        void *pExtraData,
                        MSTATUS(*funcPtrExtraCheck)(const IKESA, void *)
                        MOC_MTHM(serverInstance));
MOC_EXTERN MSTATUS  IKE_getSaByAddr(MOC_IP_ADDRESS dwPeerAddr, IKESA *ppxSa,
                        void *pExtraData,
                        MSTATUS(*funcPtrExtraMatch)(IKESA, void *, intBoolean *)
                        MOC_MTHM(serverInstance));
MOC_EXTERN MSTATUS  IKE_getSaById(ubyte4 dwId, sbyte4 loc, IKESA *ppxSa);
MOC_EXTERN MSTATUS  IKE_getSaByLoc(sbyte4 loc, IKESA *ppxSa);

MOC_EXTERN MSTATUS  IKE_delSa(IKESA pxSa, intBoolean bInfo, MSTATUS merror);
MOC_EXTERN void     IKE_initContSa(IKESA pxSa);
MOC_EXTERN void     IKE_finalizeSa(IKESA pxSa, ubyte4 timenow);

MOC_EXTERN MSTATUS  IKE_newIPsecSa(IKESA pxSa, ubyte4 dwMsgId, P2XG *ppxP2Xg);
MOC_EXTERN MSTATUS  IKE_delIPsecSa(IPSECSA pxIPsecSa, IKESA pxSa);

MOC_EXTERN MSTATUS  IKE_newXchg(IKESA pxSa, ubyte4 dwMsgId, P2XG *ppxP2Xg);
MOC_EXTERN MSTATUS  IKE_getXchg(IKESA pxSa, ubyte4 dwMsgId, P2XG *ppxP2Xg);
MOC_EXTERN MSTATUS  IKE_delXchg(P2XG pxP2Xg, IKESA pxSa, MSTATUS merror);

MOC_EXTERN sbyte4   IKE_findPps(IPSECSA pxIPsecSa, ubyte oProtoId, ubyte4 dwSpi);
MOC_EXTERN IPSECSA  IKE_findIPsecSa(IKESA pxSa, ubyte oProtoId, ubyte4 dwSpi);

MOC_EXTERN void     IKE_initIPsecKey(struct ipsecKeyEx *pxKey,
                        IKESA pxSa, IPSECSA pxIPsecSa, IPSECPPS pxIPsecPps,
                        ubyte *poKey, ubyte oSaIndex, sbyte4 iNest, sbyte4 _r);
MOC_EXTERN MSTATUS  IKE_addIPsecKey(struct ike_context *ctx);

MOC_EXTERN intBoolean IKE_checkExpSa(ubyte4 timenow, IKESA pxSa);

MOC_EXTERN MSTATUS  IKE_allocSa(struct ikePeerConfig* config,
                            MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                            ubyte *poCky, IKESA *ppxSa,
                            IKESA pxSa0, sbyte4 version
                            MOC_NATT(bUseNattPort)
                            MOC_MTHM(serverInstance));

#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
extern void IKE_delSaCkyIndex(IKESA pxSa);
extern void IKE_addSaCkyIndex(IKESA pxSa);
#endif
#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
extern void IKE_delSaAddrIndex(IKESA pxSa);
extern void IKE_addSaAddrIndex(IKESA pxSa);
#endif
#ifdef IKE_SA_ID_HASH_TABLE_SIZE_MASK
extern void IKE_delSaIdIndex(IKESA pxSa);
extern void IKE_addSaIdIndex(IKESA pxSa);
#endif

/* [v2] */
MOC_EXTERN MSTATUS  IKE2_updateSadb(void);

MOC_EXTERN IKESA    IKE2_newSa(struct ikePeerConfig* config,
                           MOC_IP_ADDRESS dwPeerAddr, ubyte2 wPeerPort,
                           ubyte *poCky, IKESA pxSa0
                           MOC_NATT(bUseNattPort)
                           MOC_MTHM(serverInstance));

MOC_EXTERN MSTATUS  IKE2_delSa(IKESA pxSa, intBoolean bInfo, MSTATUS merror);
MOC_EXTERN void     IKE2_finalizeSa(IKESA pxSa, ubyte4 timenow, IKESA pxSa0);

MOC_EXTERN MSTATUS  IKE2_newXchg(IKESA pxSa, ubyte oExchange, ubyte4 dwMsgId,
                             intBoolean bRequest, IKE2XG *ppxXg);
MOC_EXTERN MSTATUS  IKE2_getXchg(IKESA pxSa, ubyte4 dwMsgId,
                             intBoolean bRequest, IKE2XG *ppxXg);
MOC_EXTERN MSTATUS  IKE2_delXchg(IKE2XG pxXg, IKESA pxSa, MSTATUS merror);

MOC_EXTERN MSTATUS  IKE2_newIPsecSa(IKESA pxSa, IKE2XG pxXg, IPSECSA *ppxIPsecSa);

MOC_EXTERN MSTATUS IKE2_getSaNum(ubyte4 *pCount);


/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_THREADED__

#ifdef __IKE_UPDATE_TIMER__
typedef struct dpcTimerEvent
{
    struct dpcHdr hdr;
    void (*func)(sbyte4 cookie, ubyte4 saId, void *sa, ubyte4 timerId);
    sbyte4 cookie;
    ubyte4 saId;
    void *sa;
    ubyte4 timerId;

} *IKE_DPC_TIMER_EVT;

extern sbyte4 IKE_dpcTimerEvent(IKE_DPC_TIMER_EVT evt, ubyte4 evtSize);
#endif

typedef struct dpcDelSa
{
    struct dpcHdr hdr;
    IKESA pxSa;
    ubyte4 dwSaId;
    intBoolean bInfo;
    MSTATUS merror;

} *IKE_DPC_DEL_SA;

extern sbyte4 IKE_dpcDelSa(IKE_DPC_DEL_SA ds, ubyte4 dsSize);

#ifndef __IKE_UPDATE_TIMER__
extern MSTATUS IKE_updateSa(IKESA pxSa);
extern MSTATUS IKE2_updateSa(IKESA pxSa);

struct dpcStateCB;
extern sbyte4 IKE_dpcUpdateSa(struct dpcStateCB *us, ubyte4 usSize);
#endif

#if defined(__ENABLE_MOBIKE__) && defined(__IKE_MULTI_HOMING__)
struct dpcKeyUpd;
extern sbyte4 IKE2_dpcKeyUpdate(struct dpcKeyUpd *ku, ubyte4 kuSize);
#endif

#endif /* __IKE_MULTI_THREADED__ */


#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

#endif /* __IKESA_HEADER__ */

