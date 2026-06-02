/**
 * @file  ike_state.h
 * @brief IKE state machine definitions.
 *
 * @details    IKEv1 and IKEv2 exchange state definitions and enumerations.
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

#ifndef __IKE_STATE_HEADER__
#define __IKE_STATE_HEADER__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

enum
{
    STATE_INFO      = 0,

    STATE_MAIN_I1   ,
    STATE_MAIN_I2   ,
    STATE_MAIN_I3   ,
    STATE_MAIN_I4   ,
    STATE_MAIN_I    ,

    STATE_MAIN_R1   ,
    STATE_MAIN_R2   ,
    STATE_MAIN_R3   ,
    STATE_MAIN_R    ,

    STATE_QUICK_I1  ,
    STATE_QUICK_I2  ,
    STATE_QUICK_I2c ,
    STATE_QUICK_I   ,

    STATE_QUICK_R1  ,
    STATE_QUICK_R2  ,
    STATE_QUICK_R   ,

    STATE_RAW       ,

#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    STATE_AGGR_I1   ,
    STATE_AGGR_I2   ,
    STATE_AGGR_I2c  ,
    STATE_AGGR_I    ,

    STATE_AGGR_R1   ,
    STATE_AGGR_R2   ,
    STATE_AGGR_R    ,
#endif

#if (defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__))
    STATE_CFG_R1    ,
    STATE_CFG_R     ,
    STATE_CFG_I1    ,
    STATE_CFG_I2    ,
    STATE_CFG_I     ,
#ifdef __ENABLE_IKE_XAUTH__
    /* draft-ietf-ipsec-isakmp-xauth-01...02 (CFG_AUTH_OK/FAILED) */
    STATE_CFG_R1x   ,
    STATE_CFG_Rx    ,

    STATE_CFG_I1x   ,
    STATE_CFG_I2xc  ,
    STATE_CFG_Ixc   ,

    STATE_CFG_I2x   ,
    STATE_CFG_I3x   ,
    STATE_CFG_Ix    ,
#endif
#endif

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    STATE_GPULL_I1  ,
    STATE_GPULL_I2  ,
    STATE_GPULL_I3  ,
    STATE_GPULL_I   ,
#endif
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    STATE_GPULL_R1  ,
    STATE_GPULL_R2  ,
    STATE_GPULL_R   ,
#endif

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    STATE_GPUSH_I1  ,
    STATE_GPUSH_I   ,
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    STATE_GPUSH_R1  ,
    STATE_GPUSH_R   ,
#endif

    STATE_IKE_MAX
};

#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
#define IS_P1_FINAL_STATE(_s) \
((STATE_MAIN_I == (_s)) || (STATE_MAIN_R == (_s)) ||\
 (STATE_AGGR_I == (_s)) || (STATE_AGGR_R == (_s)))
#else
#define IS_P1_FINAL_STATE(_s) \
((STATE_MAIN_I == (_s)) || (STATE_MAIN_R == (_s)))
#endif


#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) && defined(__ENABLE_DIGICERT_GDOI_SERVER__)
#define IS_P2_FINAL_STATE(_s) \
    ((STATE_QUICK_I == (_s)) || (STATE_QUICK_R == (_s)) || \
     (STATE_GPULL_I == (_s)) || (STATE_GPULL_R == (_s)) || \
     (STATE_GPUSH_I == (_s)) || (STATE_GPUSH_R == (_s)))
#define IS_GPULL_STATE(_s) \
    ((STATE_GPULL_I1 <= (_s)) && (STATE_GPULL_R >= (_s)))

#elif defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
#define IS_P2_FINAL_STATE(_s) \
    ((STATE_QUICK_I == (_s)) || (STATE_QUICK_R == (_s)) || \
     (STATE_GPULL_I == (_s)) || (STATE_GPUSH_R == (_s)))
#define IS_GPULL_STATE(_s) \
    ((STATE_GPULL_I1 <= (_s)) && (STATE_GPULL_I >= (_s)))

#elif defined(__ENABLE_DIGICERT_GDOI_SERVER__)
#define IS_P2_FINAL_STATE(_s) \
    ((STATE_QUICK_I == (_s)) || (STATE_QUICK_R == (_s)) || \
     (STATE_GPULL_R == (_s)) || (STATE_GPUSH_I == (_s)))
#define IS_GPULL_STATE(_s) \
    ((STATE_GPULL_R1 <= (_s)) && (STATE_GPULL_R >= (_s)))
#endif

#define IS_QUICK_MODE_STATE(_s) \
    (((STATE_QUICK_I1 <= (_s)) && (STATE_QUICK_R >= (_s))) || IS_GPULL_STATE(_s))

#else

#define IS_QUICK_MODE_STATE(_s) \
    ((STATE_QUICK_I1 <= (_s)) && (STATE_QUICK_R >= (_s)))

#define IS_P2_FINAL_STATE(_s) \
    ((STATE_QUICK_I == (_s)) || (STATE_QUICK_R == (_s)))
#endif


#if defined(__ENABLE_IKE_XAUTH__)
#define IS_IKECFG_STATE(_s) \
    ((STATE_CFG_R1 <= (_s)) && (STATE_CFG_Ix >= (_s)))
#elif defined(__ENABLE_IKE_MODE_CFG__)
#define IS_IKECFG_STATE(_s) \
    ((STATE_CFG_R1 <= (_s)) && (STATE_CFG_I >= (_s)))
#endif


/*------------------------------------------------------------------*/

/* IKE_SA */
#define IS_INITIATOR(_sa)       ((IKE_SA_FLAG_INITIATOR & (_sa)->flags) ? TRUE : FALSE)
#define IS_MATURE(_sa)          ((IKE_SA_FLAG_MATURE & (_sa)->flags) ? TRUE : FALSE)
#define IS_VALID(_sa)           ((IKE_SA_FLAG_INUSE & (_sa)->flags) && !(IKE_SA_FLAG_DELETED & (_sa)->flags))

#define ID_VALID(_sa,ID)           ((ID == (_sa)->dwId) ? TRUE : FALSE )
#define MSGID_VALID(_pxXg,MSGID)   ((MSGID == (_pxXg)->dwMsgId) ? TRUE : FALSE )


/* NAT-T */
#define USE_NATT_PORT(_sa)      ((IKE_NATT_FLAG_USE_NPORT & (_sa)->natt_flags) ? TRUE : FALSE)
#define IS_BEHIND_NAT(_sa)      (((IKE_NATT_FLAG_US | IKE_NATT_FLAG_PEER) & (_sa)->natt_flags) ? TRUE : FALSE)

#define IS_HOST_BEHIND_NAT(_sa) ((IKE_NATT_FLAG_US & (_sa)->natt_flags) ? TRUE : FALSE)
#define SET_HOST_BEHIND_NAT(_sa) (_sa)->natt_flags |= IKE_NATT_FLAG_US;
#define HOST_NOT_BEHIND_NAT(_sa) (_sa)->natt_flags &= ~(IKE_NATT_FLAG_US);

#define IS_PEER_BEHIND_NAT(_sa) ((IKE_NATT_FLAG_PEER & (_sa)->natt_flags) ? TRUE : FALSE)
#define SET_PEER_BEHIND_NAT(_sa) (_sa)->natt_flags |= IKE_NATT_FLAG_PEER;
#define PEER_NOT_BEHIND_NAT(_sa) (_sa)->natt_flags &= ~(IKE_NATT_FLAG_PEER);

/* CHILD SA */
#define IS_CHILD_INITIATOR(_c)  ((IKE_CHILD_FLAG_INITIATOR & (_c)->c_flags) ? TRUE : FALSE)
#define IS_MATURE_CHILD(_c)     ((IKE_CHILD_FLAG_MATURE & (_c)->c_flags) ? TRUE : FALSE)
#define IS_VALID_CHILD(_c)      ((IKE_CHILD_FLAG_INUSE & (_c)->c_flags) && !(IKE_CHILD_FLAG_DELETED & (_c)->c_flags))

/* Exchange */
#define IS_XCHG_INITIATOR(_x)   ((IKE_XCHG_FLAG_INITIATOR & (_x)->x_flags) ? TRUE : FALSE)
#define IS_VALID_XCHG(_x)       ((IKE_XCHG_FLAG_INUSE & (_x)->x_flags) && !(IKE_XCHG_FLAG_DELETED & (_x)->x_flags))


/*------------------------------------------------------------------*/

#ifndef __ENABLE_IKE_XAUTH__
#define IS_IKE_SA_AUTHED(_sa)   IS_P1_FINAL_STATE((_sa)->oState)
#else
#define IS_IKE_SA_AUTHED(_sa)   (IS_P1_FINAL_STATE((_sa)->oState) && \
                                 !(IKE_SA_FLAG_XAUTH & (_sa)->flags))
#endif

#define IS_IKE2_SA_INITED(_sa)  ((((IKE_SA_FLAG_INITIATOR & (_sa)->flags) && \
                                   (STATE_MAIN_I1 < (_sa)->oState)) || \
                                  (!(IKE_SA_FLAG_INITIATOR & (_sa)->flags) && \
                                   (STATE_MAIN_R1 < (_sa)->oState))) \
                                 ? TRUE : FALSE)

#define IS_IKE2_SA_AUTHED(_sa)  (((STATE_MAIN_I == (_sa)->oState) || \
                                  (STATE_MAIN_R == (_sa)->oState)) \
                                 ? TRUE : FALSE)


/*------------------------------------------------------------------*/

struct ikesa;

typedef struct ike_info_notify
{
    ubyte   oProtoId;       /* e.g. PROTO_ISAKMP, PROTO_IPSEC_AH, PROTO_IPSEC_ESP */
    ubyte2  wMsgType;
    ubyte4  dwSpi;
    ubyte   oSpiSize;
    ubyte  *poData;
    ubyte2  wDataLen;
    struct ike_info_notify *next; /* [v2] */
} *IKEINFO_notify;

typedef struct ike_info_delete
{
    ubyte   oProtoId;       /* e.g. PROTO_ISAKMP, PROTO_IPSEC_AH, PROTO_IPSEC_ESP */
    ubyte4  dwSpi;
    struct ikesa *pxSa;
    struct ike_info_delete *next; /* [v2] */
} *IKEINFO_delete;

typedef struct ike_info
{
    IKEINFO_notify pxNotify;
    IKEINFO_delete pxDelete;
} *IKEINFO;

typedef struct p2raw
{
    ubyte   oNextPayload;
    ubyte   oExchange;
    ubyte2  wDataLen;
    const ubyte *poData;
} *P2RAW;


/*------------------------------------------------------------------*/

#define IKE_CNTXT_FLAG_PFS          0x0001
#define IKE_CNTXT_FLAG_NONCE        0x0002
#define IKE_CNTXT_FLAG_KE           0x0004

/* [v1] */
#define IKE_CNTXT_FLAG_CONNECTED    0x0008
#define IKE_CNTXT_FLAG_ID           0x0010
#define IKE_CNTXT_FLAG_HASHED       0x0020
#define IKE_CNTXT_FLAG_NAT_OA       0x0040

/* [v2] */
#define IKE_CNTXT_FALG_NAT_D_SRC    0x8000
#define IKE_CNTXT_FALG_NAT_D_DST    0x4000
#define IKE_CNTXT_FLAG_TS           0x2000
#define IKE_CNTXT_FLAG_CP           0x1000
#define IKE_CNTXT_FLAG_ID_I         0x0800
#define IKE_CNTXT_FLAG_ID_R         0x0400
#define IKE_CNTXT_FLAG_AUTH         0x0200
#define IKE_CNTXT_FLAG_SA           0x0100
#define IKE_CNTXT_FLAG_COOKIE2      0x0080
#define IKE_CNTXT_FLAG_EAP          0x0040
#define IKE_CNTXT_FLAG_EAP_ONLY     0x0020 /* responder */
#define IKE_CNTXT_FLAG_ANOTHER_AUTH 0x0010

#ifndef IPSEC_SA_MARGIN_LIFETIME
#define IPSEC_SA_MARGIN_LIFETIME 0
#endif

/*------------------------------------------------------------------*/

struct ikeHdr;
struct p2xg;
struct ipsecpps;
struct ike2xg;

typedef struct ike_context
{
    ubyte           *pBuffer;
    ubyte4          dwBufferSize;
    ubyte4          dwLength;

    void            *pHdrParent;

#ifdef CUSTOM_IKE_CATCH_EXCEPTION   /* IN [v1] */
    struct ikeHdr   *pxIkeHdr;
    void            *pCurrPayload;
    ubyte           oCurrPayload;
#endif

    ubyte           oNextPayload;   /* IN */
    ubyte           *poNextPayload; /* OUT */

    struct ikesa    *pxSa;
    struct p2xg     *pxP2Xg;            /* phase 2 */

    ubyte           oP2SaIndex;             /* SA, quick mode */
    struct ipsecpps *pxIPsecPps;            /*   Proposal, quick mode */
    ubyte           oPpsIndex;              /*     Transform, quick mode, IN or OUT(PF_KEY_I) */

#ifdef __ENABLE_DIGICERT_IPCOMP__
    intBoolean      bNoComp;                /*     IPComp proposals */
#endif

    struct p2raw    *pxP2Raw;               /* OUT */
    struct ike_info *pxInfo;                /* Notify/Delete, informational, OUT */

    sbyte4          certNum;                /* Cert, main/aggr. mode, IN */
#ifndef __ENABLE_IKE_OCSP_EXT__
    certDescriptor  certificates[IKE_CERT_CHAIN_MAX];
#else
    certDescriptor  certificates[IKE_CERT_CHAIN_MAX + 1];

    ubyte           *pOcspResp;
    ubyte2          ocspRespLen;
    ubyte           *pOcspReq;
    ubyte2          ocspReqLen;
#endif

    ubyte2          wPeerPort;              /* Sig, main/aggr. mode, IN */

    ubyte2          flags;          /* IN */
    ubyte2          wMsgType;       /* IN */

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr    hwAccelCookie;  /* hardware accelerator cookie */
    intBoolean      isHwAccelCookieInit;
#endif

    /* [v2] */
    MOC_IP_ADDRESS  peerAddr;
/*  ubyte2          wPeerPort;*/

#ifdef __ENABLE_IPSEC_NAT_T__
    intBoolean      bUseNattPort;
#endif
#ifdef __IKE_MULTI_HOMING__
    sbyte4          serverInstance;
#endif

#ifdef __ENABLE_IKE_REDIRECT__
    MOC_IP_ADDRESS_S oldPeerAddr;
#endif

    struct ike2xg   *pxXg;

    union
    {
        struct
        {
            ubyte2      wAuthMtd;   /* phase 1 SA - deprecated! */
#if defined(__ENABLE_IKE_FRAGMENTATION__) && !defined(__IKE_UPDATE_TIMER__)
            intBoolean  bIsRtx;
#endif
        } v1;

        struct
        {
            ubyte       *poCookie/*[MD5_DIGESTSIZE]*/; /* IKE_SA_INIT */
            const ubyte *poIcv;
#ifdef __ENABLE_IKE_FRAGMENTATION__
            intBoolean  bSKF;
#endif
            ubyte       oAuthMtd;   /* IKE_AUTH */

#if defined(__ENABLE_IKE_MULTI_AUTH__) || \
    (defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))
            const ubyte *poSAi2;    /* IKE_AUTH, responder, IN */
#endif
#ifdef __ENABLE_IKE_CP__
            const ubyte *poCp;      /* IKE_AUTH, responder, IN */
#endif
        } v2;

    } u;

    /* Holds pBuffer pointer to be freed. Used when pBuffer is overwritten */
    ubyte *pRefragmentationBuffer;
} *IKE_context;


/*------------------------------------------------------------------*/

typedef MSTATUS (*funcPtrIkeCtx)(IKE_context);

typedef struct IKE_stateInfo
{
    funcPtrIkeCtx inFunc;
    funcPtrIkeCtx outFunc;

} IKE_stateInfo;

typedef struct IKE_certStatusCB
{
    ubyte4 dwSaId;
    sbyte4 saLoc;
    struct ikesa *pxSa;

    /* for certificate cache cleanup in case of error */
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2 wPeerPort;
#endif

} IKE_certStatusCB;

#ifdef __IKE_MULTI_THREADED__
typedef struct dpcStateCB
{
    struct dpcHdr hdr;
    void  *data;
    sbyte4 status;
    sbyte4 version;

} *IKE_DPC_STATE_CB;
#endif


/*------------------------------------------------------------------*/
/* internal use only */

#ifdef __ENABLE_DIGICERT_ECC__
struct PrimeEllipticCurve;
struct PFE;
extern MSTATUS IKEEC_byteStringToPoint(const struct PrimeEllipticCurve *pEC,
                                       const ubyte* s, sbyte4 len,
                                       struct PFE **ppX, struct PFE **ppY);
#endif

#ifdef __IKE_MULTI_THREADED__
extern sbyte4 IKE_dpcCertStatusCallback(IKE_DPC_STATE_CB cb, ubyte4 cbSize);
#endif

/* [v1] */
extern MSTATUS IKE_xchgOut(IKE_context ctx);
extern sbyte4  IKE_certStatusCallback(void *data, sbyte4 result);

/* [v2] */
extern MSTATUS IKE2_xchgOut(IKE_context ctx);
extern sbyte4  IKE2_certStatusCallback(void *data, sbyte4 result);

extern IKE_stateInfo* IKE2_getStateInfo(ubyte oExchange, sbyte4 _r);

extern MSTATUS IKE2_outSK(IKE_context ctx);
extern MSTATUS IKE2_checkSK(IKE_context ctx);
extern MSTATUS IKE2_checkCookie(IKE_context ctx);

#ifdef __ENABLE_MOBIKE__
extern MSTATUS IKE2_doUpdateSa(IKE_context ctx);
#endif

/* PF_KEY only */
#ifdef __ENABLE_DIGICERT_PFKEY__
extern sbyte4 IKE_stateCallback(sbyte4 st, void *cbData);
extern sbyte4 IKE2_stateCallback(sbyte4 st, void *cbData);
#ifdef __IKE_MULTI_THREADED__
extern sbyte4 IKE_dpcStateCallback(IKE_DPC_STATE_CB cb, ubyte4 cbSize);
#endif
#endif


#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

#endif /* __IKE_STATE_HEADER__ */

