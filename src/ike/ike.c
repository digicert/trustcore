/**
 * @file  ike.c
 * @brief IKE Developer API implementation.
 *
 * @details    IKEv1 protocol implementation - main API functions.
 * @since      1.41
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flag must be defined in
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

#include "../common/moptions.h"
#define __ENABLE_DIGICERT_OLD_IKE_SETTINGS__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../crypto/dh.h"
#include "../crypto/rsa.h"
#include "../crypto/crypto.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"
#include "../crypto/sha1.h"
#include "../harness/harness.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/tree.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#ifdef __ENABLE_DIGICERT_PFKEY__
#include "../pfkey/pfkey.h"
#endif
#if defined(__IKE_UPDATE_TIMER__) || defined(__ENABLE_IKE_FRAGMENTATION__) || defined(__ENABLE_IKE_REDIRECT__)
#include "../common/timer.h"
#endif
#if (defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_TTLS__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#include "../eap/eap.h"
#include "../eap/eap_ttls.h"
#endif
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsecconf.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_crypto.h"
#include "../ike/ikesa.h"
#include "../ike/ikekey.h"
#include "../ike/ike_state.h"
#include "../ike/ike_event.h"
#include "../ike/ike_cert.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_status.h"
#include "../ike/ike_xauth.h"
#ifdef __ENABLE_IKE_FRAGMENTATION__
#include "../ike/ike_frag.h"
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
#include "../gdoi/client/gdoi_client.h"
#endif

/* [v2] EAP */
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#include "../eap/eap.h"

extern ubyte4 g_ikeEapInstId;
#endif

/* [v2] RADIUS */
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#include "../common/mudp.h"
#include "../radius/radius.h"
#include "../ike2/ike2_eap.h"

extern sbyte4 g_ikeRadInstId;

static sbyte4 RAD_UDP_connect(MOC_IP_ADDRESS, sbyte *, ubyte2, void **);
static sbyte4 RAD_UDP_send(void *pUDPCookie, ubyte *pData, ubyte4 dataLength);
static sbyte4 RAD_UDP_recv(void *pUDPCookie, ubyte *pData, ubyte4 dataLength, ubyte4 *pRetDataLength);
static sbyte4 RAD_UDP_unbind(void **ppUDPCookie);
#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_GDOI_SERVER__) && defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
extern intBoolean       m_stopRespAttrProcessing;
#endif

MOC_EXTERN_DATA_DECL moctime_t gStartTime;

#ifdef __IKE_MULTI_THREADED__
extern RTOS_RWLOCK m_ikeSaRwLock;
#else
#ifdef __RTOS_WIN32__
sbyte4 tidGlobalLock = 0;
#else
/* Protection against race conditions between IKE threads and timer thread */
RTOS_THREAD tidGlobalLock = 0;
#endif
#endif


/*------------------------------------------------------------------*/

#ifdef __DYNAMIC_IKE_DEFAULT_UDP_PORT__
ubyte2 g_ikeDefaultUdpPort = 500;
#endif


/*------------------------------------------------------------------*/

ikeSettings m_ikeSettings = { 0 };

static ikePeerConfig m_ikePeerConfig = { 0 };
static ikePeerConfig *m_ikePeerConfigList = NULL;

#ifdef __IKE_UPDATE_TIMER__
ubyte *m_ikeTimer = NULL;
#endif

IKE_MUTEX g_ikeMtx = NULL;

/* [v2] COOKIE in IKE_SA_INIT exchange */
ubyte4 g_ikeScrtVerID = 1;
sbyte  g_ikeSecret[] = "Secret for Mocana IKEv2 IKE_SA_INIT responder";
sbyte4 g_ikeScrtLen = sizeof(g_ikeSecret) - 1;
extern ubyte4 m_gdoiGroupCount;
#ifdef __IKE_UPDATE_TIMER__
static IKE_TIMER_EVT_T m_ikeScrtTimerId = (IKE_TIMER_EVT_T)0;
static IKE_TIMER_HDL_T m_ikeScrtTimerHdl = (IKE_TIMER_HDL_T)0;
#endif


/*------------------------------------------------------------------*/

#define _I 0
#define _R 1

#define DBG_ERRCODE(_s) debug_print_status((sbyte *)__FILE__, __LINE__, (sbyte4)_s);
#define DBG_STATUS      DBG_ERRCODE(status)
#define DBG_EXIT    { DBG_STATUS goto exit; }
#define DBG_ABORT   { DBG_STATUS goto abort; }

#define CHECK_MALLOC(p, s) \
    if (NULL == ((p) = (ubyte *) MALLOC(s))) \
    { \
        status = ERR_MEM_ALLOC_FAIL; \
        DBG_EXIT \
    } \

#define CHECK_FREE(p) if (NULL != (p)) { FREE(p); (p) = NULL; }

#ifdef __ENABLE_DIGICERT_HARNESS__
#define __crypto__(_d, _s) * _d = NULL
#define _CRYPTO_FREE_(_h, _d) if (_d) CRYPTO_FREE(_h, TRUE, (void**) &(_d));
#else
#define __crypto__(_d, _s) _d[_s]
#define _CRYPTO_FREE_(_h, _d)
#endif


/*------------------------------------------------------------------*/

extern IKE_stateInfo *m_StateInfo[];

#define STATE_IN_FUNC(s)    (m_StateInfo[s]->inFunc)
#define STATE_OUT_FUNC(s)   (m_StateInfo[s]->outFunc)
#define NEXT_STATE(s)       (++(s))

static void UninitCertChain(ikePeerConfig* config);


/*------------------------------------------------------------------*/

/* Note: this must only be called once! */
static void
InitIkePeerConfig(ikePeerConfig* config)
{
    config->ikeSettings = IKE_ikeSettings();
    if (!config->ikeCertChain)
    {
        sbyte4 len = sizeof(struct ikeCertDescr)*IKE_CERT_CHAIN_MAX;
        config->ikeCertChain = MALLOC(len);
        if (config->ikeCertChain)
            DIGI_MEMSET((ubyte*)config->ikeCertChain, 0, len);
    }

    /* Copy default settings from m_ikeSettings */
    config->ikeTimeoutNegotiation = m_ikeSettings.ikeTimeoutNegotiation;
    config->ikeTimeoutDpd   = m_ikeSettings.ikeTimeoutDpd;
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    config->ikeP1Mode       = m_ikeSettings.ikeP1Mode;
#endif
    config->ikeP1DHgroup    = m_ikeSettings.ikeP1DHgroup;
    config->ikeVersion      = m_ikeSettings.ikeVersion;
    config->ikeP1LifeSecs   = m_ikeSettings.ikeP1LifeSecs;
    config->ikeP1LifeSecsMax= m_ikeSettings.ikeP1LifeSecsMax;
    config->ikeP1LifeSecsMin= m_ikeSettings.ikeP1LifeSecsMin;
    config->ikeP1LifeKBytes = m_ikeSettings.ikeP1LifeKBytes;
    config->ikeP1LifeKBytesMax = m_ikeSettings.ikeP1LifeKBytesMax;
    config->ikeP2PFS        = m_ikeSettings.ikeP2PFS;
    config->ikeP2LifeSecs   = m_ikeSettings.ikeP2LifeSecs;
    config->ikeP2LifeSecsMax= m_ikeSettings.ikeP2LifeSecsMax;
    config->ikeP2LifeSecsMin= m_ikeSettings.ikeP2LifeSecsMin;
    config->ikeP2LifeKBytes = m_ikeSettings.ikeP2LifeKBytes;
    config->ikeP2LifeKBytesMax = m_ikeSettings.ikeP2LifeKBytesMax;
    config->ikeReauthSecs   = m_ikeSettings.ikeReauthSecs;
#ifdef __ENABLE_IKE_FRAGMENTATION__
    config->bNoIkeFrag      = m_ikeSettings.bNoIkeFrag;
    config->ikeFragSize     = m_ikeSettings.ikeFragSize;
#endif

#ifdef __ENABLE_IKE_PPK_RFC8784__
    config->bUsePpk      = FALSE;
#endif

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
    config->bNoSigAuth      = m_ikeSettings.bNoSigAuth;
#endif
#ifdef __ENABLE_IKE_OCSP_EXT__
    config->bNoIkeOcsp      = m_ikeSettings.bNoIkeOcsp;
    config->pOcspSettings   = m_ikeSettings.pOcspSettings;
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    config->keyServerAddr   = m_ikeSettings.keyServerAddr;
#endif
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    config->keyClientMAddr  = m_ikeSettings.keyClientMAddr;
    config->ikeHashAlgo     = m_ikeSettings.ikeHashAlgo;
    config->ikeEncrAlgo     = m_ikeSettings.ikeEncrAlgo;
    config->ikeEncrKeyLen   = m_ikeSettings.ikeEncrKeyLen;
    config->ikeSigMtd       = m_ikeSettings.ikeSigMtd;
    config->ikeSigKeyLen    = m_ikeSettings.ikeSigKeyLen;
#endif
#ifdef __ENABLE_IKE_MULTI_AUTH__
    config->bDoMultiAuth    = m_ikeSettings.bDoMultiAuth;
    config->reqInAuthMtds[_I] = m_ikeSettings.reqInAuthMtds[_I];
    config->reqInAuthMtds[_R] = m_ikeSettings.reqInAuthMtds[_R];
#endif
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    config->eapIdentity     = m_ikeSettings.eapIdentity;
#ifdef __ENABLE_IKE_EAP_ONLY__
    config->bDoEapOnly      = m_ikeSettings.bDoEapOnly;
#endif
#ifdef __ENABLE_DIGICERT_EAP_AUTH__
    config->eapProtoAuth    = m_ikeSettings.eapProtoAuth;
#endif
#ifdef __ENABLE_DIGICERT_EAP_PEER__
    config->eapProtoPeer    = m_ikeSettings.eapProtoPeer;
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    config->eapTtlsType     = m_ikeSettings.eapTtlsType;
#endif
#endif
#endif
#ifdef __ENABLE_IKE_XAUTH__
    config->xauthType       = m_ikeSettings.xauthType;
    config->xauthDraft      = m_ikeSettings.xauthDraft;
#ifdef __ENABLE_IKE_HYBRID_RSA__
    config->bDoHybrid       = m_ikeSettings.bDoHybrid;
#endif /* __ENABLE_IKE_HYBRID_RSA__ */
#endif /* __ENABLE_IKE_XAUTH__ */

    IKE_initSuiteInfo(config);
}

extern ikePeerConfig*
IKE_newPeerConfig(void)
{
    ikePeerConfig* config = MALLOC(sizeof(ikePeerConfig));
    if (config)
    {
        DIGI_MEMSET((ubyte*)config, 0, sizeof(ikePeerConfig));
        InitIkePeerConfig(config);
    }
    return config;
}

extern ikePeerConfig*
IKE_newPeerConfigEx(sbyte4 serverInstance)
{
    ikePeerConfig* config = MALLOC(sizeof(ikePeerConfig));
    if (config)
    {
        DIGI_MEMSET((ubyte*)config, 0, sizeof(ikePeerConfig));
        InitIkePeerConfig(config);
#ifdef __IKE_MULTI_HOMING__
        config->serverInstance = serverInstance;
#endif
    }
    return config;
}

extern ikePeerConfig*
IKE_globalPeerConfig(void)
{
    if (! m_ikePeerConfig.ikeCertChain)
        InitIkePeerConfig(&m_ikePeerConfig);

    return &m_ikePeerConfig;
}


/*------------------------------------------------------------------*/

static void
ClearPeerConfig(ikePeerConfig* config)
{
    UninitCertChain(config);

    if (config->ikePSKey)
    {
        DIGI_MEMSET(config->ikePSKey, 0, config->ikePSKeyLen);
        FREE(config->ikePSKey);
    }

    if (config->ikeCertChain)
    {
        DIGI_MEMSET((ubyte *) config->ikeCertChain, 0,
                   sizeof(struct ikeCertDescr)*IKE_CERT_CHAIN_MAX);
        FREE(config->ikeCertChain);
    }

    CERT_STORE_releaseStore(&config->ikeCertStore);

    CHECK_FREE(config->hashSuites);
    CHECK_FREE(config->cipherSuites);
    CHECK_FREE(config->macSuites);
    CHECK_FREE(config->dhGroups);
    CHECK_FREE(config->authMtds);
#ifdef __ENABLE_IKE_PPK_RFC8784__
    CHECK_FREE(config->ppk_id)
    CHECK_FREE(config->ppk_psk)
#endif
    DIGI_MEMSET((ubyte*)config, 0, sizeof(*config));
}

static void
freePeerConfig(ikePeerConfig* config)
{
    if (config)
    {
        /* Find the pointer to config in the config list */
        ikePeerConfig** prev;
        for (prev = &m_ikePeerConfigList;
             *prev && *prev != config ;
             prev = &((*prev)->next)) ;

        /* Remove config from the list */
        if (*prev)
            *prev = config->next;

        IKEDelPeerEntrySadb(config);
        /* Clear the config object */
        ClearPeerConfig(config);

        /* Free the config object if it is not the global config */
        if (config != &m_ikePeerConfig)
            FREE(config);
    }
}

static void
freePeerConfigList(void)
{
    while (m_ikePeerConfigList)
        freePeerConfig(m_ikePeerConfigList);
}

extern void
IKE_freePeerConfig(ikePeerConfig* config)
{
    IKE_LOCK_W;
    freePeerConfig(config);
    IKE_UNLOCK_W;
}


/*------------------------------------------------------------------*/

extern ikePeerConfig*
IKE_findPeerConfig(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort, sbyte4 serverInstance)
{
    ikePeerConfig *config;

    for (config = m_ikePeerConfigList; config; config = config->next)
    {
        if (m_ikeSettings.funcPtrIsConfigForPeer &&
            m_ikeSettings.funcPtrIsConfigForPeer(config, peerAddr, wPeerPort, serverInstance))
            return config;

        if (&m_ikePeerConfig == config) return config; /* global */
    }

    return NULL;
}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)

static MSTATUS
DoCfgInit(ubyte oCfgType, ubyte2 wCfgId,
          const ubyte *poCfg, ubyte2 wCfgLen,
          IKESA pxSa, IKE_context ctx)
{
    MSTATUS status;

    ubyte *poCfgAttrs = NULL;
    P2XG pxXg;

    if (!wCfgLen || (NULL == poCfg) ||
        ((CFG_REQUEST != oCfgType) && (CFG_SET != oCfgType)))
    {
        status = ERR_IKE_CONFIG;
        goto exit;
    }

    CHECK_MALLOC(poCfgAttrs, wCfgLen)

    if (OK > (status = IKE_newXchg(pxSa, 0, &pxXg)))
        goto exit;

    pxXg->oState = STATE_CFG_I1;
    pxXg->oCfgType = oCfgType;
    pxXg->wCfgId = wCfgId;
    pxXg->poCfgAttrs = poCfgAttrs;
    pxXg->wCfgAttrsLen = wCfgLen;

    DIGI_MEMCPY(poCfgAttrs, poCfg, wCfgLen);
    poCfgAttrs = NULL;

    ctx->pxP2Xg = pxXg;
    ctx->pxSa = pxSa;

    status = IKE_xchgOut(ctx);

exit:
    if (NULL != poCfgAttrs)
    {
        FREE(poCfgAttrs);
    }
    return status;
} /* DoCfgInit */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_cfgSend(const ubyte *poCfg, ubyte2 wCfgLen, ubyte oCfgType,
            ubyte4 dwIkeId, ubyte2 *pwCfgId)
{
    MSTATUS status;

    IKESA pxSa;
    ubyte2 wCfgId;
    struct ike_context ctx = { NULL };

    IKE_LOCK_W; /* !!! */

    if (OK > (status = IKE_getSaById(dwIkeId, -1, &pxSa)))
        goto exit;

    if ((NULL == pxSa) || !IS_P1_FINAL_STATE(pxSa->oState))
    {
        status = ERR_IKE_GETSA_FAIL;
        goto exit;
    }

    if (IS_IKE2_SA(pxSa)) /* jic */
    {
        status = ERR_IKE_BAD_SA; /* for now */
        goto exit;
    }

    wCfgId = (pxSa->u.v1.wCfgId)++;
    if (OK > (status = DoCfgInit(oCfgType, wCfgId, poCfg, wCfgLen,
                                 pxSa, &ctx)))
        goto exit;

    if (NULL != pwCfgId)
        *pwCfgId = wCfgId;

exit:
    IKE_UNLOCK_W;
    return (sbyte4)status;
} /* IKE_cfgSend */

#endif /* defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__) */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IKE_MODE_CFG__

static MSTATUS
FetchMoreCfg(IKESA pxSa, IKE_context ctx, ubyte2 wCfgId)
{
    MSTATUS status;

    ubyte oCfgType = 0;
    ubyte2 wCfgLen = 0;
    ubyte *poCfg = NULL;
    /*ubyte2 wCfgId = (pxSa->u.v1.wCfgId)++;*/
    pxSa->u.v1.wCfgId = wCfgId;

    if (OK > (status = m_ikeSettings.funcPtrIkeInitCfg(
        &poCfg, &wCfgLen, &oCfgType, wCfgId,
        pxSa->dwId, pxSa)))
        goto exit;

    status = DoCfgInit(oCfgType, wCfgId, poCfg, wCfgLen, pxSa, ctx);

exit:
    if ((NULL != poCfg) &&
        m_ikeSettings.funcPtrIkeReleaseCfg)
    {
        m_ikeSettings.funcPtrIkeReleaseCfg(poCfg);
    }
    return status;
} /* SendModeCfg */

static MSTATUS
InitModeCfg(IKESA pxSa, IKE_context ctx)
{
    MSTATUS status;

    ubyte oCfgType = 0;
    ubyte2 wCfgLen = 0;
    ubyte *poCfg = NULL;
    ubyte2 wCfgId = (pxSa->u.v1.wCfgId)++;

    if (OK > (status = m_ikeSettings.funcPtrIkeInitCfg(
                                        &poCfg, &wCfgLen, &oCfgType, wCfgId,
                                        pxSa->dwId, pxSa)))
        goto exit;

    status = DoCfgInit(oCfgType, wCfgId, poCfg, wCfgLen, pxSa, ctx);

exit:
    if ((NULL != poCfg) &&
        m_ikeSettings.funcPtrIkeReleaseCfg)
    {
        m_ikeSettings.funcPtrIkeReleaseCfg(poCfg);
    }
    return status;
} /* InitModeCfg */

#endif


/*------------------------------------------------------------------*/

extern sbyte4
IKE_p2RawSend(const ubyte *poData, ubyte2 wDataLen,
              ubyte oNextPayload, ubyte oExchange,
              ubyte4 dwIkeId)
{
    MSTATUS status;

    IKESA pxSa;

    IKE_LOCK_W; /* !!! */

    /* get IKE_SA */
    if (OK > (status = IKE_getSaById(dwIkeId, -1, &pxSa)))
        goto exit;

    /* send it */
    if ((NULL == pxSa) || !IS_P1_FINAL_STATE(pxSa->oState))
    {
        status = ERR_IKE_GETSA_FAIL;
    }
    else if (IS_IKE2_SA(pxSa)) /* jic */
    {
        status = ERR_IKE_BAD_SA; /* for now */
    }
    else
    {
        struct p2raw raw;
        struct ike_context ctx = { NULL };

        raw.oNextPayload = oNextPayload;
        raw.oExchange = oExchange;
        raw.wDataLen = wDataLen;
        raw.poData = poData;

        ctx.pxP2Raw = &raw;
        ctx.pxSa = pxSa;

        status = IKE_xchgOut(&ctx);
    }

exit:
    IKE_UNLOCK_W;
    return (sbyte4)status;
} /* IKE_p2RawSend */


#ifdef __IKE_UPDATE_TIMER__

/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_THREADED__

extern sbyte4
IKE_dpcTimerEvent(IKE_DPC_TIMER_EVT pxEvt, ubyte4 dwEvtSize)
{
    if ((sizeof(struct dpcTimerEvent) <= dwEvtSize) &&
        (sizeof(struct dpcTimerEvent) == pxEvt->hdr.dpc_len) &&
        ((IKE_dpcFunc)IKE_dpcTimerEvent == pxEvt->hdr.dpc_func))
    {
        pxEvt->func(pxEvt->cookie, pxEvt->saId, pxEvt->sa, pxEvt->timerId);
    }
    return 0;
} /* IKE_dpcTimerEvent */


#define EXIT_SA goto exit_sa;
#else
#define EXIT_SA goto exit;
#endif


/*------------------------------------------------------------------*/

static intBoolean
CanRekey(IKESA pxSa)
{
    intBoolean bRet = FALSE;

    if (IS_IKE_SA_AUTHED(pxSa) &&
        IS_INITIATOR(pxSa) && IS_MATURE(pxSa) && /* initiator, mature */
        !(IKE_SA_FLAG_REKEYED & pxSa->flags)) /* not rekeyed */
    {
        IKESA pxSaRekey = pxSa->pxSaRekey;
        if (pxSaRekey)
        {
#ifdef __IKE_MULTI_THREADED__
            RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif
            if (IS_VALID(pxSaRekey) &&
                (pxSaRekey->dwId == pxSa->dwSaRekeyId))
            {
                /* old or being rekeyed */
#ifdef __IKE_MULTI_THREADED__
                RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
                goto exit;
            }
#ifdef __IKE_MULTI_THREADED__
            RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        }

        bRet = TRUE;
    }

exit:
    return bRet;
} /* CanRekey */


/*------------------------------------------------------------------*/

static void
DoRekey(IKESA pxSa)
{
    IKESA pxSaRekey;

    /* new IKE SA for phase 1 exchange */
    if (NULL != (pxSaRekey = IKE_newSa(pxSa->ikePeerConfig,
                                       REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                       pxSa->wPeerPort, NULL
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
                                     , ((STATE_AGGR_I == pxSa->oState)
                                        ? ISAKMP_XCHG_AGGR : ISAKMP_XCHG_IDPROT)
#endif
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
                                     , ((IKE_SA_FLAG_GDOI & pxSa->flags) ? TRUE : FALSE)
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
                                     , USE_NATT_PORT(pxSa)
#endif
                                       MOC_MTHM_VALUE(pxSa->serverInstance))))
    {
        struct ike_context ctx = { NULL };
        ctx.pxSa = pxSaRekey;

        if (OK <= IKE_xchgOut(&ctx))
        {
            pxSa->pxSaRekey = pxSaRekey;
            pxSa->dwSaRekeyId = pxSaRekey->dwId;
        }
    }

    return;
} /* DoRekey */


/*------------------------------------------------------------------*/

/* auto. rekeying - lifetime kbytes */
#define KB_REKEY(pxSa) \
if (pxSa->dwExpKBytes && CanRekey(pxSa))\
{\
    ubyte4 warning = 6; /* 6K - FOR NOW */\
    if ((pxSa->dwCurKBytes > (ubyte4)(pxSa->dwExpKBytes/2)) && /* old enough */\
        ((pxSa->dwExpKBytes < (pxSa->dwCurKBytes + warning)) || /* expiring soon */\
         (pxSa->dwCurKBytes > (pxSa->dwCurKBytes + warning)))) /* jic KBytes wraps back to 0 */\
    {\
        DoRekey(pxSa);\
    }\
}


/*------------------------------------------------------------------*/

static void
RekeyingTimerEvent(sbyte4 cookie, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;

    ubyte4 timeout;
    MSTATUS status;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_NEWSA]))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_NEWSA]))
    {
        EXIT_SA
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = RekeyingTimerEvent;
            evt.cookie = cookie;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->timerIDs[IKESA_TIMER_NEWSA] = (IKE_TIMER_EVT_T)0; /* !!! */
    pxSa->timerHdls[IKESA_TIMER_NEWSA] = (IKE_TIMER_HDL_T)NULL; /* !!! */

    if (IKE_SA_FLAG_REKEYED & pxSa->flags)
    {
        goto exit;
    }

    timeout = 1000 * pxSa->ikePeerConfig->ikeTimeoutNegotiation;

    if (CanRekey(pxSa))
    {

        /* new IKE SA for phase 1 exchange */
        DoRekey(pxSa);
    }

    if (OK > (status = IKE_ADD_TIMER_EVT((timeout/2), 0, pxSa,
                                         RekeyingTimerEvent, "NEW",
                                         pxSa->timerIDs[IKESA_TIMER_NEWSA],
                                         pxSa->timerHdls[IKESA_TIMER_NEWSA] )))
    {
        DBG_STATUS
    }

    MOC_UNUSED(cookie);

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* RekeyingTimerEvent */


/*------------------------------------------------------------------*/

static void
ExpTimerEvent(sbyte4 cookie, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_EXPIRATION]))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_EXPIRATION]))
    {
        EXIT_SA
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = ExpTimerEvent;
            evt.cookie = cookie;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->timerIDs[IKESA_TIMER_EXPIRATION] = (IKE_TIMER_EVT_T)0; /* !!! */
    pxSa->timerHdls[IKESA_TIMER_EXPIRATION] = (IKE_TIMER_HDL_T)NULL; /* !!! */

    IKE_delSa(pxSa, FALSE, STATUS_IKE_LIFETIME_SECONDS);

    MOC_UNUSED(cookie);

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* ExpTimerEvent */


/*------------------------------------------------------------------*/

static MSTATUS
SendDpd(IKESA pxSa, ubyte4 timenow)
{
    MSTATUS status;

    struct ike_info_notify notifyInfo = { PROTO_ISAKMP, R_U_THERE };
    struct ike_info info = { NULL };
    struct ike_context ctx = { NULL };

    ubyte4 dwSeqNo = pxSa->u.v1.dwDpdSeqNo;

    if (timenow) /* indicating new DPD exchange */
    {
        if (0 == ++dwSeqNo)
        {
            dwSeqNo = 1; /* jic */
        }
    }
    SET_HTONL_1(dwSeqNo);

    /* send DPD informational exchange message */
    notifyInfo.wDataLen = (ubyte2) sizeof(ubyte4);
    notifyInfo.poData = (ubyte *) &dwSeqNo;
    notifyInfo.oSpiSize = IKE_P1_SPI_SIZE;
    info.pxNotify = &notifyInfo;

    ctx.pxInfo = &info;
    ctx.pxSa = pxSa;

    if (OK > (status = IKE_xchgOut(&ctx)))
    {
        goto exit;
    }

    if (timenow) /* starting new DPD */
    {
        pxSa->u.v1.dwDpdSeqNo = dwSeqNo;
        pxSa->u.v1.dwDpdTimeStart = timenow;
    }

exit:
    return status;
} /* SendDpd */


/*------------------------------------------------------------------*/

static void
DpdTimerEvent(sbyte4 cookie, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;

    ubyte4 timenow, timestart, timeidled, timeoutDpd;
    MSTATUS status;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_DPD]))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_DPD]))
    {
        EXIT_SA
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = DpdTimerEvent;
            evt.cookie = cookie;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->timerIDs[IKESA_TIMER_DPD] = (IKE_TIMER_EVT_T)0; /* !!! */
    pxSa->timerHdls[IKESA_TIMER_DPD] = (IKE_TIMER_HDL_T)NULL; /* !!! */

    if (IKE_SA_FLAG_REKEYED & pxSa->flags)
    {
        goto exit;
    }

    timenow = RTOS_deltaMS(&gStartTime, NULL);

    timeidled = timenow - pxSa->dwTimeStamp;
    timestart = pxSa->u.v1.dwDpdTimeStart;

    timeoutDpd = 1000 * pxSa->ikePeerConfig->ikeTimeoutDpd;

#ifdef CUSTOM_IKE_GET_DPD_TIMEOUT
    if (OK <= CUSTOM_IKE_GET_DPD_TIMEOUT(&timeoutDpd,
                                    REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                    0, IS_INITIATOR(pxSa)
                                    MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
    {
        timeoutDpd = 1000 * timeoutDpd;
    }
#endif

    if (timestart) /* DPD already started */
    {
        ubyte4 timeout = 1000 * pxSa->ikePeerConfig->ikeTimeoutNegotiation;
        ubyte4 timediff = timenow - timestart;

        if (timediff > timeidled) /* response received */
        {
            pxSa->u.v1.dwDpdTimeStart = 0;

            if (!timeoutDpd) /* jic */
            {
                goto exit;
            }

            pxSa->flags &= ~IKE_SA_FLAG_DPD;

            if (timeidled < timeoutDpd)
            {
                timeoutDpd -= timeidled;
                goto sched;
            }
            timestart = 0; /* !!! */
        }
        else if (timediff >= timeout) /* timed out */
        {
            pxSa->u.v1.dwDpdTimeStart = 0;

            if (!timeoutDpd) /* jic */
            {
                goto exit;
            }

            /* dead peer detected */
            if (!(pxSa->flags & IKE_SA_FLAG_DPD))
            {
                pxSa->flags |= IKE_SA_FLAG_DPD;

                /* TODO - SHOULD assume its peer to be unreachable and
                   delete IPSec and IKE SAs to the peer (RFC3706 5.4)
                 */
                if (m_ikeSettings.funcPtrIkeStatHdlr)
                {
                    m_ikeSettings.funcPtrIkeStatHdlr(ISC_SA, IST_DPD,
                                                     pxSa->dwId, pxSa, NULL);
                    if (!IS_VALID(pxSa)) /* jic */
                    {
                        goto exit;
                    }
                }
            }
            goto sched;
        }
        else
        {
            timeoutDpd = (ubyte4)cookie;
            cookie *= 2; /* increment next re-transmission interval */
        }
    }
    else
    {
        if (!timeoutDpd) /* jic */
        {
            goto exit;
        }

        if (timeidled < timeoutDpd) /* not time yet to send DPD */
        {
            timeoutDpd -= timeidled;
            goto sched;
        }
    }

    if (!timestart) /* new DPD */
    {
        timeoutDpd = 1000; /* re-transmit Timer timeout */
        cookie = 2000; /* next re-transmission interval */
    }

    /* send DPD informational exchange message */
    if (OK > (status = SendDpd(pxSa, (timestart ? 0 : timenow))))
    {
        DBG_STATUS
    }

sched:
    if (OK > (status = IKE_ADD_TIMER_EVT(timeoutDpd, cookie, pxSa,
                                         DpdTimerEvent, "DPD",
                                         pxSa->timerIDs[IKESA_TIMER_DPD],
                                         pxSa->timerHdls[IKESA_TIMER_DPD])))
    {
        DBG_STATUS
    }

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* DpdTimerEvent */


/*------------------------------------------------------------------*/

static void
RutTimerEvent(sbyte4 cookie, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;

    MSTATUS status;
    ubyte4 timenow = 0, timeout;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_RUT]))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_RUT]))
    {
        EXIT_SA
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = RutTimerEvent;
            evt.cookie = cookie;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->timerIDs[IKESA_TIMER_RUT] = (IKE_TIMER_EVT_T)0; /* !!! */
    pxSa->timerHdls[IKESA_TIMER_RUT] = (IKE_TIMER_HDL_T)NULL; /* !!! */

    if (IKE_SA_FLAG_REKEYED & pxSa->flags)
    {
        goto exit;
    }

    if (pxSa->dwCurKBytes > 10)
    {
        goto exit;
    }

    if (IS_MATURE(pxSa))
    {
        if (pxSa->u.v1.dwDpdTimeStart) /* DPD already started */
        {
            goto sched;
        }

        IKE_DEL_TIMER_EVT(pxSa->timerIDs[IKESA_TIMER_DPD], pxSa->timerHdls[IKESA_TIMER_DPD])

        /* send DPD informational exchange message */
        timenow = RTOS_deltaMS(&gStartTime, NULL);
        if (OK > (status = SendDpd(pxSa, timenow)))
        {
            DBG_STATUS
            goto sched;
        }

        /* set re-transmission timer */
        if (OK > (status = IKE_ADD_TIMER_EVT(1000, 2000, pxSa,
                                             DpdTimerEvent, "DPD",
                                             pxSa->timerIDs[IKESA_TIMER_DPD],
                                             pxSa->timerHdls[IKESA_TIMER_DPD])))
        {
            DBG_STATUS
        }
    }

sched:
    if (3 > pxSa->wExpDPD++)
    {
        if (!timenow)
        {
            timenow = RTOS_deltaMS(&gStartTime, NULL);
        }

        timeout = (timenow - pxSa->dwTimeCreated);
        if ((1000 * pxSa->dwExpSecs) <= timeout) /* jic */
        {
            goto exit;
        }
        timeout = (1000 * pxSa->dwExpSecs) - timeout; /* remaining lifetime ms */

        if (OK > (status = IKE_ADD_TIMER_EVT((timeout/2), 0, pxSa,
                                             RutTimerEvent, "RUT",
                                             pxSa->timerIDs[IKESA_TIMER_RUT],
                                             pxSa->timerHdls[IKESA_TIMER_RUT])))
        {
            DBG_STATUS
        }
    }

    MOC_UNUSED(cookie);

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* RutTimerEvent */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IPSEC_NAT_T__
static void
KeepaliveTimerEvent(sbyte4 cookie, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;
    ubyte4 timeout = (ubyte4)cookie;

    ubyte4 timenow, timediff;
    MSTATUS status;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_KEEPALIVE]))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_KEEPALIVE]))
    {
        EXIT_SA
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = KeepaliveTimerEvent;
            evt.cookie = cookie;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->timerIDs[IKESA_TIMER_KEEPALIVE] = (IKE_TIMER_EVT_T)0; /* !!! */
    pxSa->timerHdls[IKESA_TIMER_KEEPALIVE] = (IKE_TIMER_HDL_T)NULL; /* !!! */

    if (IKE_SA_FLAG_REKEYED & pxSa->flags)
    {
        goto exit;
    }

    timenow = RTOS_deltaMS(&gStartTime, NULL);
    timediff = timenow - pxSa->dwTimeStampOut;

    if (timediff < timeout)
    {
        timeout -= timediff; /* not quite the time yet */
    }
    else
    if (NULL != m_ikeSettings.funcPtrIkeXchgSend) /* jic */
    {
        ubyte b = 0xFF;
        m_ikeSettings.
        funcPtrIkeXchgSend(REF_MOC_IPADDR(pxSa->dwPeerAddr), pxSa->wPeerPort,
                           (ubyte *)&b, sizeof(ubyte)
                           MOC_MTHM_REQ_VALUE(pxSa->serverInstance),
                           TRUE);
        debug_print("#SEND 1 byte to ");
        debug_print_ip(REF_MOC_IPADDR(pxSa->dwPeerAddr));
        debug_print("[");
        debug_int(pxSa->wPeerPort);
        debug_print("]");
#ifdef __IKE_MULTI_HOMING__
        debug_print(" at ");
        debug_print_ip(REF_MOC_IPADDR(pxSa->dwHostAddr));
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
        debug_print("@");
        debug_hexint(pxSa->serverInstance);
#endif
#endif
        debug_uptime();
        debug_printnl("");

        pxSa->dwTimeStampOut = timenow;
    }

    if (OK > (status = IKE_ADD_TIMER_EVT(timeout, cookie, pxSa,
                                         KeepaliveTimerEvent, "KAL",
                                         pxSa->timerIDs[IKESA_TIMER_KEEPALIVE],
                                         pxSa->timerHdls[IKESA_TIMER_KEEPALIVE])))
    {
        DBG_STATUS
    }

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* KeepaliveTimerEvent */
#endif

#endif /* __IKE_UPDATE_TIMER__ */


/*------------------------------------------------------------------*/

static MSTATUS
OnAuthenticated(IKESA pxSa, ubyte oState, IKE_context ctx)
{
    MSTATUS status = OK;

#ifdef __IKE_UPDATE_TIMER__
    MSTATUS st;
    ubyte4 timeout;
#endif

    /* INITIAL-CONTACT */
    if (IKE_SA_FLAG_INIT_C & pxSa->flags)
        IKE_initContSa(pxSa);

#ifdef __IKE_UPDATE_TIMER__
    IKE_DEL_TIMER_EVT(pxSa->timerIDs[IKESA_TIMER_EXPIRATION], pxSa->timerHdls[IKESA_TIMER_EXPIRATION])

    if (pxSa->dwExpSecs)
    {
        timeout = 1000 * pxSa->dwExpSecs;

        if (IS_INITIATOR(pxSa)) /* Initiator auto. rekeying */
        {
            ubyte4 warning = 2 * 1000 * pxSa->ikePeerConfig->ikeTimeoutNegotiation;
            if (warning > (timeout/2))
            {
                warning = (timeout/2); /* don't rekey too soon */
            }

            if (OK > (st = IKE_ADD_TIMER_EVT((timeout - warning), 0, pxSa,
                                             RekeyingTimerEvent, "NEW",
                                             pxSa->timerIDs[IKESA_TIMER_NEWSA],
                                             pxSa->timerHdls[IKESA_TIMER_NEWSA])))
            {
                DBG_ERRCODE(st)
            }
        }
        /* Responder rekey helper */
        else if (pxSa->u.v1.dwDpdSeqNo) /* DPD is supported by peer */
        {
            if (OK > (st = IKE_ADD_TIMER_EVT((timeout/2), 0, pxSa,
                                             RutTimerEvent, "RUT",
                                             pxSa->timerIDs[IKESA_TIMER_RUT],
                                             pxSa->timerHdls[IKESA_TIMER_RUT])))
            {
                DBG_ERRCODE(st)
            }
        }

        /* lifetime seconds */
        if (OK > (st = IKE_ADD_TIMER_EVT(timeout, 0, pxSa,
                                         ExpTimerEvent, "EXP",
                                         pxSa->timerIDs[IKESA_TIMER_EXPIRATION],
                                         pxSa->timerHdls[IKESA_TIMER_EXPIRATION])))
        {
            DBG_ERRCODE(st)
        }
    }

    if (pxSa->u.v1.dwDpdSeqNo) /* DPD is supported by peer */
    {
#ifdef CUSTOM_IKE_GET_DPD_TIMEOUT
        if (OK <= CUSTOM_IKE_GET_DPD_TIMEOUT(&timeout,
                                    REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                    0, IS_INITIATOR(pxSa)
                                    MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
        {
            timeout = 1000 * timeout;
        }
        else
#endif
        timeout = 1000 * pxSa->ikePeerConfig->ikeTimeoutDpd;

        if (timeout && /* NOT passive */
            (OK > (st = IKE_ADD_TIMER_EVT(timeout, 0, pxSa,
                                          DpdTimerEvent, "DPD",
                                          pxSa->timerIDs[IKESA_TIMER_DPD],
                                          pxSa->timerHdls[IKESA_TIMER_DPD]))))
        {
            DBG_ERRCODE(st)
        }
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    if (IS_HOST_BEHIND_NAT(pxSa))
    {
        timeout = 1000 * m_ikeSettings.ikeIntervalKeepalive;

        if (OK > (st = IKE_ADD_TIMER_EVT(timeout, timeout, pxSa,
                                         KeepaliveTimerEvent, "KAL",
                                         pxSa->timerIDs[IKESA_TIMER_KEEPALIVE],
                                         pxSa->timerHdls[IKESA_TIMER_KEEPALIVE])))
        {
            DBG_ERRCODE(st)
        }
    }
#endif
#endif /* __IKE_UPDATE_TIMER__ */

    IKE_finalizeSa(pxSa,
                   pxSa->dwTimeCreated = pxSa->dwTimeStamp
                   );

#ifdef __ENABLE_IKE_MODE_CFG__
    if (m_ikeSettings.funcPtrIkeInitCfg)
    {
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        if (pxSa->dwPeerAddr != m_ikeSettings.keyServerAddr)
        {
            DB_PRINT("Peer address mismatch, skip config negotiation");
            goto exit;
        }
#endif
        if (OK == InitModeCfg(pxSa, ctx))
            goto exit;
    }
#else
    MOC_UNUSED(ctx);
#endif

#ifndef __IKE_MULTI_THREADED__ /* for now */
    /* initiate phase 2 exchange, if any */
    if (IS_INITIATOR(pxSa) && IS_MATURE(pxSa)) /* initiator, mature */
    {
#ifdef __ENABLE_IKE_XAUTH__
        if ((oState == pxSa->oState) ||
            /* XAUTH 'mature' final state */
            (STATE_CFG_Ix == oState) || (STATE_CFG_Rx == oState))
#else
        MOC_UNUSED(oState);
#endif
        IKE_evtXchg(pxSa);
    }
#endif

#ifdef __ENABLE_IKE_MODE_CFG__
exit:
#endif
    return status;
} /* OnAuthenticated */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IKE_XAUTH__

static MSTATUS
OnP1FinalState(IKESA pxSa, ubyte oState, IKE_context ctx)
{
    MSTATUS status = OK;

    if (IKE_SA_FLAG_XAUTH & pxSa->flags) /* pending XAUTH */
    {
        /* XAUTH server */
        if (2 == pxSa->ikePeerConfig->xauthType)
        {
            ubyte2 wAuthMtd = pxSa->u.v1.pwIsaAttr[OAKLEY_AUTHENTICATION_METHOD];
            intBoolean bInitiator = IS_INITIATOR(pxSa);
            if ((bInitiator && !(wAuthMtd % 2)) ||
                (!bInitiator && (wAuthMtd % 2)))
            {
                if ((ubyte)6 > pxSa->ikePeerConfig->xauthDraft)
                {
                    /* draft-ietf-ipsec-isakmp-xauth-05 or lower */
                    status = ERR_IKE_XAUTH_DRAFT_VERSION;
                }
                else
                {
                    /* Initiate XAUTH transaction exchange */
                    status = IKE_xauthAAAInit(pxSa, ctx);
                }
            }
            else /* sanity-check - shouldn't get here */
            {
                DBUG_PRINT(DEBUG_IPSEC,
                           ("XUATH - NA - IN IF! %d", wAuthMtd));
                status = ERR_IKE_XAUTH_FAILED;
            }

            if (OK > status)
            {
                IKE_delSa(pxSa, TRUE, status);
                DBG_STATUS
            }
        }

        goto exit; /* !!! */
    }

    status = OnAuthenticated(pxSa, oState, ctx);

exit:
    return status;
} /* OnP1FinalState */

#else

#define OnP1FinalState OnAuthenticated
#endif /* __ENABLE_IKE_XAUTH__ */


/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_THREADED__

extern sbyte4
IKE_dpcCertStatusCallback(IKE_DPC_STATE_CB cb, ubyte4 cbSize)
{
    sbyte4 status = 0;

    if ((sizeof(struct dpcStateCB) <= cbSize) &&
        (sizeof(struct dpcStateCB) == cb->hdr.dpc_len) &&
        ((IKE_dpcFunc)IKE_dpcCertStatusCallback == cb->hdr.dpc_func))
    {
        if (1 == cb->version)
            status = IKE_certStatusCallback(cb->data, cb->status);
        else if (2 == cb->version)
            status = IKE2_certStatusCallback(cb->data, cb->status);
    }
    return status;
} /* IKE_dpcCertStatusCallback */

#endif /* __IKE_MULTI_THREADED__ */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_certStatusCallback(void *data, sbyte4 result)
{
#define cb ((IKE_certStatusCB *)data)
    MSTATUS status;

    IKESA pxSa = NULL;
    ubyte oState;
    struct ike_context ctx = { NULL };

    IKE_LOCK_R; /* !!! */

    if ((NULL == cb) || (NULL == cb->pxSa))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* get IKE_SA */
    if (OK > (status = IKE_getSaByLoc(cb->saLoc, &pxSa)))
    {
        goto exit;
    }

    if (cb->pxSa != pxSa)
    {
        status = ERR_IKE_GETSA_FAIL;
        goto exit;
    }

#ifdef __IKE_MULTI_THREADED__
    RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif
    if (!IS_VALID(pxSa) || (cb->dwSaId != pxSa->dwId))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        status = ERR_IKE_GETSA_FAIL;
        goto exit;
    }

    oState = pxSa->oState;

    /* sanity-check */
    if (IS_IKE2_SA(pxSa) ||
        (STATUS_IKE_PENDING != pxSa->merror) ||
        ((STATE_MAIN_I4 != oState) &&
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
         (STATE_AGGR_I2 != oState) &&
         (STATE_AGGR_R2 != oState) &&
#endif
         (STATE_MAIN_R3 != oState)))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        status = ERR_IKE_BAD_SA;
        goto exit;
    }

#ifdef __IKE_MULTI_THREADED__
    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            ubyte4 size = sizeof(struct dpcStateCB);
            struct dpcStateCB cs;
            cs.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcCertStatusCallback;
            cs.hdr.dpc_len = (ubyte2)size;
            cs.version = 1;
            cs.status = result;
            cs.data = data;
            status = (MSTATUS) m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                                            (ubyte *)&cs, size);
            if (OK <= status) data = NULL; /* !!! */
        }
        else
        {
            status = ERR_IKE_CONFIG;
        }
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
        goto exit;
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->merror = OK;

    /* certificate status-check returns error */
    if (OK > (status = (MSTATUS)result))
    {
        /* clear cache */
        ctx.pxSa = pxSa;
#ifdef __ENABLE_IPSEC_NAT_T__
        ctx.wPeerPort = cb->wPeerPort;
#endif
        IKE_certUnbind(&ctx);

        /* send notification (responder only) */
        if ((STATE_MAIN_R3 == oState)
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
         || (STATE_AGGR_R2 == oState)
#endif
            )
        {
            struct ike_info_notify notifyInfo = { 0 };
            struct ike_info info = { NULL };

            notifyInfo.wMsgType = AUTHENTICATION_FAILED;
            notifyInfo.oProtoId = PROTO_ISAKMP;
            info.pxNotify = &notifyInfo;

            ctx.pxInfo = &info;
            ctx.pxSa = pxSa;
            IKE_xchgOut(&ctx);
        }

        /* delete IKE_SA */
        status = IKE_delSa(pxSa, FALSE, status);
        goto exit;
    }

    /* resume IKE negotiation */
    ctx.pxSa = pxSa;
    if (OK > (status = IKE_xchgOut(&ctx)))
    {
        goto exit;
    }

    oState = pxSa->oState;
    if (IS_P1_FINAL_STATE(oState))
    {
        status = OnP1FinalState(pxSa, oState, &ctx);
    }

exit:
    if (data) FREE(data);
    IKE_UNLOCK_R;
    return (sbyte4)status;
#undef cb
} /* IKE_certStatusCallback */


/*------------------------------------------------------------------*/

static MSTATUS
SendMessage(IKESA pxSa, ubyte *pBuffer, ubyte4 dwLength
#ifdef __ENABLE_IKE_FRAGMENTATION__
          , ubyte2 *pFragId
#endif
            )
{
    MSTATUS status = OK;

#if defined(__ENABLE_IKE_FRAGMENTATION__) || \
    (defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__))
    struct ikeHdr *pxHdr = (struct ikeHdr *)pBuffer;
#endif
#ifdef __ENABLE_IKE_FRAGMENTATION__
    ubyte4  lastFragSize;
    ubyte4  lastFragDataSize;
    ubyte4  ikeTotalDataSize;
    ubyte4  maxFragDataSize;
    ubyte4  numFrags;
    ubyte4  i;
    ubyte  *pData;
    ubyte  *pPkt = NULL;
#endif
    INIT_MOC_IPADDR(peerAddr, pxSa->dwPeerAddr)

#ifdef __ENABLE_IPSEC_NAT_T__
    intBoolean bUseNattPort = USE_NATT_PORT(pxSa);

#if defined(__ENABLE_IKE_FRAGMENTATION__) || \
    (defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__))
    if (bUseNattPort)
    {
        pxHdr = (struct ikeHdr *)(pBuffer + 4);
        debug_print("#");
    }
#endif
#endif
    debug_print("SEND ");
    debug_uint(dwLength);
    debug_print(" bytes to ");
    debug_print_ip(peerAddr);
    debug_print("[");
    debug_int(pxSa->wPeerPort);
    debug_print("]");

#ifdef __IKE_MULTI_HOMING__
    debug_print(" at ");
    debug_print_ip(REF_MOC_IPADDR(pxSa->dwHostAddr));
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    debug_print("@");
    debug_hexint(pxSa->serverInstance);
#endif
#endif
    debug_uptime();
    debug_printnl("");

#ifdef __ENABLE_IKE_FRAGMENTATION__
    if ((IKE_SA_FLAG_FRAGMENTATION & pxSa->flags) &&
        (dwLength > pxSa->ikePeerConfig->ikeFragSize))
    {
        /* split into n fragments */
        ikeTotalDataSize = dwLength;
        maxFragDataSize  = pxSa->ikePeerConfig->ikeFragSize
                         - SIZEOF_ISAKMP_HDR - SIZEOF_IKE_FRAG_HDR;

#ifdef __ENABLE_IPSEC_NAT_T__
        if (bUseNattPort)
        {
            /* account for the non-ESP marker */
            ikeTotalDataSize -= 4;
            maxFragDataSize -= 4;
        }
#endif
        numFrags         = (ikeTotalDataSize / maxFragDataSize);

        lastFragDataSize = ikeTotalDataSize % maxFragDataSize;
        if (lastFragDataSize)
            numFrags++;
        else
            lastFragDataSize = maxFragDataSize;

        pData = (ubyte *)pxHdr;

        /* loop for constructing fragments */
        for (i = 1; i < numFrags; i++)
        {
            if (OK > (status = IKE_fragCreate(pxSa, i, pFragId, pxHdr, pData, FALSE,
                                              pxSa->ikePeerConfig->ikeFragSize,
                                              &pPkt)))
            {
                goto exit;
            }

#ifdef __ENABLE_IPSEC_NAT_T__
            debug_print_ikehdr(pPkt + (bUseNattPort ? 4 : 0));
#else
            debug_print_ikehdr(pPkt);
#endif
            m_ikeSettings.funcPtrIkeXchgSend(peerAddr, pxSa->wPeerPort,
                                             pPkt, pxSa->ikePeerConfig->ikeFragSize
                                             MOC_MTHM_REQ_VALUE(pxSa->serverInstance)
                                             MOC_NATT_REQ_VALUE(bUseNattPort));
            DIGI_FREE((void **)&pPkt);

            pData += maxFragDataSize;
        } /* for */

        /* special case for last fragment */
        lastFragSize = lastFragDataSize + SIZEOF_ISAKMP_HDR + SIZEOF_IKE_FRAG_HDR;
#ifdef __ENABLE_IPSEC_NAT_T__
        if (bUseNattPort)
        {
            lastFragSize += 4;
        }
#endif
        if (OK > (status = IKE_fragCreate(pxSa, i, pFragId, pxHdr, pData, TRUE,
                                          lastFragSize, &pPkt)))
        {
            goto exit;
        }

#ifdef __ENABLE_IPSEC_NAT_T__
        debug_print_ikehdr(pPkt + (bUseNattPort ? 4 : 0));
#else
        debug_print_ikehdr(pPkt);
#endif
        m_ikeSettings.funcPtrIkeXchgSend(peerAddr, pxSa->wPeerPort,
                                         pPkt, lastFragSize
                                         MOC_MTHM_REQ_VALUE(pxSa->serverInstance)
                                         MOC_NATT_REQ_VALUE(bUseNattPort));
        DIGI_FREE((void **)&pPkt);
    }
    else
#endif /* __ENABLE_IKE_FRAGMENTATION__ */
    {
        debug_print_ikehdr((ubyte *)pxHdr);

        m_ikeSettings.funcPtrIkeXchgSend(peerAddr, pxSa->wPeerPort,
                                         pBuffer, dwLength
                                         MOC_MTHM_REQ_VALUE(pxSa->serverInstance)
                                         MOC_NATT_REQ_VALUE(bUseNattPort));
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    pxSa->dwTimeStampOut = RTOS_deltaMS(&gStartTime, NULL);
#endif

#ifdef __ENABLE_IKE_FRAGMENTATION__
exit:
#endif
    return status;
} /* SendMessage */


#ifdef __IKE_UPDATE_TIMER__

/*------------------------------------------------------------------*/

static void
RtxTimerEvent1(sbyte4 cookie, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;
    ubyte4 timeout = (ubyte4)cookie, timenow = 0;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->u.v1.rtxTimerId))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->u.v1.rtxTimerId))
    {
        EXIT_SA
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = RtxTimerEvent1;
            evt.cookie = cookie;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->u.v1.rtxTimerId = (IKE_TIMER_EVT_T)0; /* !!! */
    pxSa->u.v1.rtxTimerHdl = (IKE_TIMER_HDL_T)NULL; /* !!! */

    if (NULL == pxSa->u.v1.poRtxMsg) /* jic */
    {
        pxSa->u.v1.dwRtxMsgLen = 0;
#ifdef __ENABLE_IKE_FRAGMENTATION__
        pxSa->u.v1.wRtxFragId = 0;
#endif
        goto exit;
    }

    if (IS_P1_FINAL_STATE(pxSa->oState))
    {
        if (IS_MATURE(pxSa))
        {
            goto cleanup;
        }

#ifdef __ENABLE_IKE_XAUTH__
        if (!(IKE_SA_FLAG_XAUTH & pxSa->flags))
#endif
        {
            timenow = RTOS_deltaMS(&gStartTime, NULL);

            if ((timenow - pxSa->dwTimeStart) >=
                (1000 * pxSa->ikePeerConfig->ikeTimeoutNegotiation))
            {
                IKE_finalizeSa(pxSa, timenow);
                goto cleanup;
            }
        }
    }
    else if (OK > pxSa->merror) /* jic - pending??? */
    {
        goto sched;
    }

    if (OK <= SendMessage(pxSa, pxSa->u.v1.poRtxMsg, pxSa->u.v1.dwRtxMsgLen
#ifdef __ENABLE_IKE_FRAGMENTATION__
                        , &(pxSa->u.v1.wRtxFragId)
#endif
                          ))
    {
        if (!timenow)
        {
            timenow = RTOS_deltaMS(&gStartTime, NULL);
        }
        pxSa->dwTimeStamp = timenow;
        cookie *= 2; /* next timeout */
    }

sched:
    if (OK > IKE_ADD_TIMER_EVT(timeout, cookie, pxSa,
                               RtxTimerEvent1, "RT1",
                               pxSa->u.v1.rtxTimerId,
                               pxSa->u.v1.rtxTimerHdl))
    {
        debug_printnl("Failed to schedule timer for retransmission [1].");
        goto cleanup;
    }

exit:
    IKE_UNLOCK_R;
    return;

cleanup:
    FREE(pxSa->u.v1.poRtxMsg);
    pxSa->u.v1.poRtxMsg = NULL;
    pxSa->u.v1.dwRtxMsgLen = 0;
#ifdef __ENABLE_IKE_FRAGMENTATION__
    pxSa->u.v1.wRtxFragId = 0;
#endif
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* RtxTimerEvent1 */


/*------------------------------------------------------------------*/

static void
RtxTimerEvent2(sbyte4 i, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;
    P2XG pxXg;

    sbyte4 count, timeout;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId))
    {
        EXIT_SA
    }
#endif

    pxXg = &(pxSa->u.v1.p2Xg[i]);
    if (!IS_VALID_XCHG(pxXg))
    {
        EXIT_SA
    }
    if (timerId != pxXg->rtxTimerId)
    {
        EXIT_SA
    }

#ifdef __IKE_MULTI_THREADED__

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = RtxTimerEvent2;
            evt.cookie = i;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxXg->rtxTimerId = (IKE_TIMER_EVT_T)0; /* !!! */
    pxXg->rtxTimerHdl = (IKE_TIMER_HDL_T)NULL; /* !!! */

    if (NULL == pxXg->poRtxMsg) /* jic */
    {
        pxXg->dwRtxMsgLen = 0;
#ifdef __ENABLE_IKE_FRAGMENTATION__
        pxXg->wRtxFragId = 0;
#endif
        goto exit;
    }

    if (!(IKE_XCHG_FLAG_PENDING & pxXg->x_flags)) /* !!! */
    {
        ++pxXg->rtxCount; /* for next timeout */

        if (IS_QUICK_MODE_STATE(pxXg->oState))
        {
            IPSECSA pxIPsecSa = P2XG_IPSECSA(pxXg);

            if (IKE_CHILD_FLAG_DELETED & pxIPsecSa->c_flags) /* jic */
            {
                /* quick mode exchange already deleted (e.g. "ike_event.c") */
                IKE_delXchg(pxXg, pxSa, OK);
                goto exit;
            }
        }
        else /* IKECFG */
        {
            if (!IS_XCHG_INITIATOR(pxXg)) /* responder */
            {
                /* re-transmit only if necessary */
                if (pxXg->dwTimeStamp)
                {
                    /* no re-transmission from initiator */
                    goto sched;
                }
            }
        }

        if (OK <= SendMessage(pxSa, pxXg->poRtxMsg, pxXg->dwRtxMsgLen
#ifdef __ENABLE_IKE_FRAGMENTATION__
                            , &(pxXg->wRtxFragId)
#endif
                              ))
        {
            pxXg->dwTimeStamp = RTOS_deltaMS(&gStartTime, NULL);
        }
    }

sched:
    for (count=0, timeout=1; count < pxXg->rtxCount; count++)
    {
        timeout *= 2;
    }
    if (OK > IKE_ADD_TIMER_EVT((1000 * timeout), i, pxSa,
                               RtxTimerEvent2, "RT2",
                               pxXg->rtxTimerId, pxXg->rtxTimerHdl))
    {
        debug_printnl("Failed to schedule timer for retransmission [2].");
        goto exit;
    }

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* RtxTimerEvent2 */

#endif /* __IKE_UPDATE_TIMER__ */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_xchgOut(IKE_context ctx)
{
    MSTATUS status = OK;

#ifdef __DIGICERT_DUMP_IKE_PLAINTEXT__
    ubyte *poMsgPlain = NULL;
#endif
    IKESA pxSa = ctx->pxSa;
    P2XG pxXg = ctx->pxP2Xg;
    P2RAW pxRaw = ctx->pxP2Raw;
    IKEINFO pxInfo = ctx->pxInfo;

    ubyte oState = (ubyte)((NULL != pxInfo) ? STATE_INFO :
                           ((NULL != pxRaw) ? STATE_RAW :
                            ((NULL != pxXg) ? pxXg->oState : pxSa->oState)));

    /* Note: Any error may result in deleting pxXg or pxSa; see the end */

    IPSECSA pxIPsecSa = (IS_QUICK_MODE_STATE(oState)
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
                      || (STATE_GPUSH_I1 == oState)
#endif
                         ) ? P2XG_IPSECSA(pxXg) : NULL;

    ubyte *pBuffer = NULL;
    ubyte4 dwBufferSize;

    struct ikeHdr *pxHdr;
    funcPtrIkeCtx pOutFunc;

    ubyte __crypto__(poIvInfo, IKE_IV_MAX);
    ubyte *poIv = NULL;

#ifdef __ENABLE_IKE_FRAGMENTATION__
    ubyte2 wFragId = 0;
    ubyte2 *pFragId = (pxInfo || pxRaw) ? &wFragId :
                      (pxXg ? &pxXg->wRtxFragId: &pxSa->u.v1.wRtxFragId);
#endif
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    intBoolean hasHwAccelCookie = FALSE;

    if (!ctx->isHwAccelCookieInit)
    {
        if (OK > (status = IKE_getHwAccelChannel(&ctx->hwAccelCookie)))
            DBG_ABORT

        ctx->isHwAccelCookieInit = hasHwAccelCookie = TRUE;
    }
#endif

    /* get output function */
    if (STATE_IKE_MAX <= oState) /* jic */
    {
        status = ERR_IKE;
        DBG_EXIT
    }

#ifndef __IKE_UPDATE_TIMER__
#ifdef __ENABLE_IKE_FRAGMENTATION__
    if (TRUE != ctx->u.v1.bIsRtx) /* not re-transmission */
        *pFragId = 0; /* reset fragmentation */
    else
        ctx->u.v1.bIsRtx = FALSE; /* jic */
#endif
#else
    /* reset re-transmission timer */
    if (!pxInfo && !pxRaw)
    {
        if (NULL == pxXg) /* phase 1 */
        {
            IKE_DEL_TIMER_EVT(pxSa->u.v1.rtxTimerId, pxSa->u.v1.rtxTimerHdl)

            if (pxSa->u.v1.poRtxMsg)
            {
                FREE(pxSa->u.v1.poRtxMsg);
                pxSa->u.v1.poRtxMsg = NULL;
            }
            pxSa->u.v1.dwRtxMsgLen = 0;
        }
        else /* phase 2 */
        {
            IKE_DEL_TIMER_EVT(pxXg->rtxTimerId, pxXg->rtxTimerHdl)

            if (pxXg->poRtxMsg)
            {
                FREE(pxXg->poRtxMsg);
                pxXg->poRtxMsg = NULL;
            }
            pxXg->dwRtxMsgLen = 0;
            pxXg->rtxCount = 0;
        }

#ifdef __ENABLE_IKE_FRAGMENTATION__
        *pFragId = 0;
#endif
    }
#endif /* __IKE_UPDATE_TIMER__ */

    if (NULL == (pOutFunc = STATE_OUT_FUNC(oState)))
    {
        goto done;  /* reaching final state */
    }

    /* output buffer */
    dwBufferSize = m_ikeSettings.ikeBufferSize;
#ifdef __ENABLE_IPSEC_NAT_T__
    dwBufferSize += 4;
#endif
    if ((NULL == ctx->pBuffer) || (dwBufferSize > ctx->dwBufferSize))
    {
        /* allocate new buffer */
        if (OK > (status = CRYPTO_ALLOC(ctx->hwAccelCookie, dwBufferSize,
                                        TRUE, (void**) &pBuffer)))
            DBG_EXIT

        ctx->pBuffer = pBuffer;
        ctx->dwBufferSize = dwBufferSize;
    }
    DIGI_MEMSET(ctx->pBuffer, 0x00, ctx->dwBufferSize);

#ifdef __ENABLE_IPSEC_NAT_T__
    ctx->pBuffer += 4;
    ctx->dwBufferSize -= 4;
#endif

    /* ISAKMP header */
    if (SIZEOF_ISAKMP_HDR > ctx->dwBufferSize)
    {
        status = ERR_IKE_BUFFER_OVERFLOW;
        DBG_EXIT
    }
    pxHdr = (struct ikeHdr *) ctx->pBuffer;

    DIGI_MEMCPY(pxHdr->poCky_I, pxSa->poCky_I, IKE_COOKIE_SIZE);
    DIGI_MEMCPY(pxHdr->poCky_R, pxSa->poCky_R, IKE_COOKIE_SIZE);
    pxHdr->oVersion = (1 << 4) | 0; /* 1.0 */

    switch (oState)
    {
    case STATE_INFO :
        pxHdr->oExchange = ISAKMP_XCHG_INFO;    /* informational */
    case STATE_RAW :
        if (IKE_SA_FLAG_KE & pxSa->flags)
        {
            pxHdr->oFlags |= ISAKMP_FLAG_ENCRYPTION;

#ifdef __ENABLE_DIGICERT_HARNESS__
            if (OK > (status = CRYPTO_ALLOC(ctx->hwAccelCookie, IKE_IV_MAX,
                                            TRUE, (void**) &poIvInfo)))
                DBG_EXIT
#endif
            poIv = poIvInfo;

            /* calculate iv - MUST do this *before* constructing message! */
            if (OK != (status = IKE_newSaIv(MOC_HASH(ctx->hwAccelCookie)
                                            pxSa, &(pxHdr->dwMsgId), poIv)))
                DBG_EXIT
        }
        else
        {
            if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,
                                        (ubyte *) &(pxHdr->dwMsgId), sizeof(ubyte4))))
                DBG_EXIT
        }
        break;

    default :
        if ((NULL == pxXg) &&
            (((STATE_MAIN_I1 <= oState) && (STATE_MAIN_I > oState)) ||
             ((STATE_MAIN_R1 <= oState) && (STATE_MAIN_R > oState))))
        {
            pxHdr->oExchange = ISAKMP_XCHG_IDPROT;  /* main mode */
        }
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
        else if ((NULL == pxXg) &&
                 (((STATE_AGGR_I1 <= oState) && (STATE_AGGR_I > oState)) ||
                  ((STATE_AGGR_R1 <= oState) && (STATE_AGGR_R > oState))))
        {
            pxHdr->oExchange = ISAKMP_XCHG_AGGR;    /* aggressive moe */
        }
#endif
        else if ((NULL != pxXg) &&
                 IS_QUICK_MODE_STATE(oState) &&
                 !IS_P2_FINAL_STATE(oState)) /* jic */
        {
            pxHdr->oExchange = ISAKMP_XCHG_QUICK;   /* quick mode */
                            /* ISAKMP_XCHG_GPULL has the same value! */
            pxHdr->oFlags |= ISAKMP_FLAG_ENCRYPTION;
            pxHdr->dwMsgId = pxXg->dwMsgId;
        }
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
        else if ((NULL != pxXg) && (STATE_GPUSH_I1 == oState))
        {
            pxHdr->oExchange = ISAKMP_XCHG_GPUSH;
            pxHdr->oFlags |= ISAKMP_FLAG_ENCRYPTION;
            pxHdr->dwMsgId = pxXg->dwMsgId;
        }
#endif
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
        else if ((NULL != pxXg) &&
                 ((STATE_CFG_R1  == oState) ||
#ifdef __ENABLE_IKE_XAUTH__
                  (STATE_CFG_I1x == oState) || (STATE_CFG_I2x == oState) ||
#endif
                  (STATE_CFG_I1  == oState)))
        {
            /*if (IKE_SA_FLAG_KE & pxSa->flags)*/
            pxHdr->oFlags |= ISAKMP_FLAG_ENCRYPTION;
            pxHdr->oExchange = ISAKMP_XCHG_CFG;
            pxHdr->dwMsgId = pxXg->dwMsgId;
        }
#endif
        else
        {
            status = ERR_IKE;
            DBG_EXIT
        }

        break;
    } /* switch */

    /* set up context */
    ctx->pBuffer       += SIZEOF_ISAKMP_HDR;
    ctx->dwBufferSize  -= SIZEOF_ISAKMP_HDR;

    ctx->dwLength       = SIZEOF_ISAKMP_HDR;

    ctx->poNextPayload  = &(pxHdr->oNextPayload);
    ctx->pHdrParent     = pxHdr;

    /* construct output message */
    if (OK > (status = pOutFunc(ctx)))
        goto exit;

    /* set ISAKMP message length */
    SET_HTONL(pxHdr->dwLength, ctx->dwLength);

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    switch (oState)
    {
    case STATE_MAIN_I1 :
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    case STATE_AGGR_I1 :
#endif
    case STATE_QUICK_I1 :
        debug_print_ikehdr((ubyte *)pxHdr);
        break;
    default :
        break;
    }
#endif

    /* encrypt message, if necessary */
    if (ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags)
    {
        ubyte2 wLength;

        ubyte4 dwLength = ctx->dwLength;
        ubyte4 dwBodyLen = dwLength - SIZEOF_ISAKMP_HDR;
        ubyte2 wBlockLen = (ubyte2) pxSa->pCipherSuite->pBEAlgo->blockSize;

        /* add padding */
        if (0 != (wLength = (ubyte2)(dwBodyLen % wBlockLen)))
        {
            wLength = (ubyte2)(wBlockLen - wLength);
            if (ctx->dwBufferSize < wLength)
            {
                status = ERR_IKE_BUFFER_OVERFLOW;
                DBG_EXIT
            }
            ctx->pBuffer += wLength;
            ctx->dwBufferSize -= (ubyte4)wLength;
            ctx->dwLength += (ubyte4)wLength;

            dwLength += (ubyte4)wLength;
            dwBodyLen += (ubyte4)wLength;

            /* adjust message length */
            SET_HTONL(pxHdr->dwLength, dwLength);
        }

#ifdef __DIGICERT_DUMP_IKE_PLAINTEXT__
        if (NULL != (poMsgPlain = MALLOC(dwLength + 4)))
        {
            struct ikeHdr *pxHdrPlain;
#ifdef __ENABLE_IPSEC_NAT_T__
            if (USE_NATT_PORT(pxSa))
            {
                DIGI_MEMSET(poMsgPlain, 0x00, 4);
                pxHdrPlain = (struct ikeHdr *)(poMsgPlain + 4);
            }
            else
#endif
            pxHdrPlain = (struct ikeHdr *)poMsgPlain;

            DIGI_MEMCPY((ubyte *)pxHdrPlain, ctx->pBuffer - dwLength, dwLength);
            pxHdrPlain->oFlags &= ~(ISAKMP_FLAG_ENCRYPTION);
        }
#endif

        /* iv */
        if ((STATE_INFO == oState) || (STATE_RAW == oState))
        {
/*          poIv = poIvInfo;*/
        }
        else
        {
            ubyte *poIvOld = (pxXg ? pxXg->poIvOld : pxSa->u.v1.poIvOld);
#ifdef __ENABLE_DIGICERT_HARNESS__
            if (OK > (status = CRYPTO_ALLOC(ctx->hwAccelCookie, IKE_IV_MAX,
                                            TRUE, (void**) &poIv)))
                DBG_EXIT
#else
            poIv = (pxXg ? pxXg->poIv : pxSa->u.v1.poIv);
#endif
            DIGI_MEMCPY(poIv, poIvOld, pxSa->pCipherSuite->wIvLen);
        }

        /* encrypt */
        if (OK > (status = CRYPTO_Process(MOC_SYM(ctx->hwAccelCookie)
                                    pxSa->pCipherSuite->pBEAlgo,
                                    pxSa->u.v1.poKeyId_e,
                                    pxSa->wEncrKeyLen,
                                    poIv, /* to be modified */
                                    (ubyte *)pxHdr + SIZEOF_ISAKMP_HDR,
                                    dwBodyLen,
                                    TRUE)))
            DBG_EXIT

        if ((STATE_INFO != oState) && (STATE_RAW != oState))
        {
#ifdef __ENABLE_DIGICERT_HARNESS__
            ubyte *poIvNew = (pxXg ? pxXg->poIv : pxSa->u.v1.poIv);
            DIGI_MEMCPY(poIvNew, poIv, pxSa->pCipherSuite->wIvLen);
#endif

#ifndef __ENABLE_KEYVPN_LOG_SUPPRESSION__
            if (NULL == pxXg) /* phase 1 */
                debug_printd((sbyte *)"   Initialization vector:", poIv, pxSa->pCipherSuite->wIvLen);
#endif
        }

        /* book-keeping */
        pxSa->dwCurBytes += dwLength;
        if (1024 <= pxSa->dwCurBytes)
        {
            ubyte4 dwNewKBytes = pxSa->dwCurKBytes + (pxSa->dwCurBytes / 1024);
            pxSa->dwCurBytes = (pxSa->dwCurBytes % 1024);

             /* jic KBytes wraps back to 0 */
            if (pxSa->dwExpKBytes && (pxSa->dwCurKBytes > dwNewKBytes))
            {
                pxSa->dwCurBytes += (ubyte4)((dwNewKBytes + 1) * 1024);
                dwNewKBytes = ~((ubyte4)0);
            }
            pxSa->dwCurKBytes = dwNewKBytes;
        }

#ifdef __IKE_UPDATE_TIMER__
        KB_REKEY(pxSa) /* auto. rekeying - lifetime kbytes */
#endif
    } /* if (ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags) */

    /* transmit message */
    if (NULL != m_ikeSettings.funcPtrIkeXchgSend)
    {
        ubyte4 dwLength = ctx->dwLength;
#ifdef __ENABLE_IPSEC_NAT_T__
        intBoolean bUseNattPort = USE_NATT_PORT(pxSa);
        if (bUseNattPort)
        {
            dwLength += 4;
        }
#endif
        if (OK > (status = SendMessage(pxSa, ctx->pBuffer - dwLength, dwLength
#ifdef __ENABLE_IKE_FRAGMENTATION__
                                     , pFragId
#endif
                                       )))
        {
            DBG_EXIT
        }

#ifdef __DIGICERT_DUMP_IKE_PLAINTEXT__
        if (poMsgPlain)
        m_ikeSettings.funcPtrIkeXchgSend(REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                         pxSa->wPeerPort,
                                         poMsgPlain, dwLength
                                         MOC_MTHM_REQ_VALUE(pxSa->serverInstance)
                                         MOC_NATT_REQ_VALUE(bUseNattPort));
#endif

#ifdef __IKE_UPDATE_TIMER__
        /* set up re-transmission */
        if ((STATE_INFO != oState) && (STATE_RAW != oState))
        {
            ubyte *poRtxMsg;
            if (NULL == (poRtxMsg = (ubyte *) MALLOC(dwLength)))
            {
                debug_printnl("Failed to allocate memory for re-transmission.");
                goto done;
            }
            DIGI_MEMCPY(poRtxMsg, ctx->pBuffer - dwLength, dwLength);

            if (NULL == pxXg) /* phase 1 */
            {
                if (OK > IKE_ADD_TIMER_EVT(1000, 2000, pxSa,
                                           RtxTimerEvent1, "RT1",
                                           pxSa->u.v1.rtxTimerId, pxSa->u.v1.rtxTimerHdl))
                {
                    debug_printnl("Failed to schedule timer for retransmission [1].");
                    FREE(poRtxMsg);
                }
                else
                {
                    pxSa->u.v1.poRtxMsg = poRtxMsg;
                    pxSa->u.v1.dwRtxMsgLen = dwLength;
                }
            }
            else /* phase 2 */
            {
                sbyte4 i;
                for (i=0; i < IKE_P2_MAX; i++)
                {
                    if (&(pxSa->u.v1.p2Xg[i]) == pxXg)
                    {
                        break;
                    }
                }

                if ((IKE_P2_MAX <= i) || /* jic */
                    OK > IKE_ADD_TIMER_EVT(1000, i, pxSa,
                                           RtxTimerEvent2, "RT2",
                                           pxXg->rtxTimerId, pxXg->rtxTimerHdl))
                {
                    debug_printnl("Failed to schedule timer for retransmission [2].");
                    FREE(poRtxMsg);
                }
                else
                {
                    pxXg->poRtxMsg = poRtxMsg;
                    pxXg->dwRtxMsgLen = dwLength;
                }
            }
        }
#endif /* __IKE_UPDATE_TIMER__ */
    }
    else
    {
        status = ERR_IKE_CONFIG;
        DBG_EXIT
    }

done:
    if ((STATE_INFO != oState) && (STATE_RAW != oState))
    {
        ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);

        if (NULL == pxXg) /* phase 1 */
        {
            pxSa->dwTimeStamp = timenow;
            NEXT_STATE(pxSa->oState);
        }
        else /* phase 2 */
        {
            pxXg->dwTimeStamp = timenow;
            NEXT_STATE(pxXg->oState);

            if (NULL != pxIPsecSa) /* quick mode */
                pxIPsecSa->oState = pxXg->oState;
        }
    }

exit:
#ifdef __DIGICERT_DUMP_IKE_PLAINTEXT__
    if (poMsgPlain) FREE(poMsgPlain);
#endif
    if (pBuffer)
    {
        ctx->pBuffer = NULL;
        ctx->dwBufferSize = 0;
        CRYPTO_FREE(ctx->hwAccelCookie, TRUE, (void**) &pBuffer);
    }
    _CRYPTO_FREE_(ctx->hwAccelCookie, poIv)

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if (hasHwAccelCookie)
    {
        IKE_releaseHwAccelChannel(&ctx->hwAccelCookie);
        ctx->isHwAccelCookieInit = FALSE;
    }

abort:
#endif
    if (OK > status)
    {
        if ((STATE_INFO != oState) && (STATE_RAW != oState))
        {
            if (NULL == pxXg) /* phase 1 */
                IKE_delSa(pxSa, FALSE, status);
            else
                IKE_delXchg(pxXg, pxSa, status);
        }
    }
    return status;
} /* IKE_xchgOut */


/*------------------------------------------------------------------*/

#ifdef __IKE_TRACK__

#ifndef __IKE_MULTI_THREADED__
#define TK_BUF_SIZE 65535
static ubyte m_tkBuffer[TK_BUF_SIZE];
#else
#define TK_BUF_SIZE 4096
#define m_tkBuffer pxTrack->pBuffer
#endif

typedef struct ike_track
{
#ifdef __IKE_MULTI_THREADED__
    ubyte *pBuffer;
#endif
    struct ikeHdr *pxHdr;
    struct ikesa *pxSa;
    struct p2xg *pxXg;

    intBoolean bMsgOK;

    void *userData;

} *IKE_TRACK;

#define TRACK_HDR \
    if (pxTrack) \
    { \
        DIGI_MEMCPY(m_tkBuffer, pxHdr, (ctx.dwBufferSize < TK_BUF_SIZE) \
                                 ? ctx.dwBufferSize \
                                 : TK_BUF_SIZE); \
        pxTrack->pxHdr = (struct ikeHdr *)m_tkBuffer; \
    }

#define TRACK_PLAINTEXT \
    if (pxTrack) \
    { \
        pxTrack->pxHdr->oFlags &= ~(ISAKMP_FLAG_ENCRYPTION); \
        DIGI_MEMCPY(&m_tkBuffer[SIZEOF_ISAKMP_HDR], ctx.pBuffer, dwBodyLen); \
    }

#define TRACK_SA if (pxTrack) pxTrack->pxSa = pxSa;
#define TRACK_XG if (pxTrack) pxTrack->pxXg = pxXg ;
#define TRACK_OK if (pxTrack) pxTrack->bMsgOK = TRUE;

#else
#define TRACK_HDR
#define TRACK_PLAINTEXT
#define TRACK_SA
#define TRACK_XG
#define TRACK_OK

#endif /* __IKE_TRACK__ */


/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_THREADED__

static sbyte4       m_dpcFuncNum = 0;
static IKE_dpcFunc  m_dpcFunc[IKE_DPC_FUNC_MAX] = { NULL };

extern sbyte4
IKE_dpcRegister(IKE_dpcFunc dpcFunc)
{
    MSTATUS status = OK;

    if (NULL == dpcFunc)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (IKE_DPC_FUNC_MAX <= m_dpcFuncNum)
    {
        status = ERR_IKE;
        goto exit;
    }

    m_dpcFunc[m_dpcFuncNum++] = dpcFunc;

exit:
    return (sbyte4)status;
} /* IKE_dpcRegister */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_dpcRecv(ubyte *buf, ubyte4 bufsize)
{
    sbyte4 status = 0;

    if (NULL == buf) /* jic */
    {
        status = (sbyte4)ERR_NULL_POINTER;
        goto exit;
    }

    if (sizeof(struct dpcHdr) <= bufsize)
    {
        IKE_dpcFunc dpcFunc = ((DPC_HDR)buf)->dpc_func;
        sbyte4 i;
        for (i=0; i < m_dpcFuncNum; i++)
        {
            if (dpcFunc == m_dpcFunc[i])
            {
                status = dpcFunc(buf, bufsize);
                break;
            }
        }
    }

exit:
    return status;
} /* IKE_dpcRecv */


/*------------------------------------------------------------------*/

static MSTATUS
CheckMsgRecv(const IKESA pxSa, void *pData)
{
    MSTATUS status = OK;

    MOC_UNUSED(pData);

    if (IKE_SA_FLAG_DELETED & pxSa->flags)
    {
        status = ERR_IKE_GETSA_FAIL;
        goto exit;
    }

    if (FALSE == RTOS_sameThreadId(pxSa->tid, RTOS_currentThreadId()))
    {
        status = ERR_IKE;//ERR_IKE_BAD_THREAD;
        goto exit; /* abort */
    }

exit:
    return status;
} /* CheckMsgRecv */

#endif /* __IKE_MULTI_THREADED__ */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_msgRecv(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
            ubyte *pBuffer, ubyte4 dwBufferSize,
            sbyte4 serverInstance,
            intBoolean bUseNattPort /* received at local port 4500? */
#ifdef __IKE_TRACK__
          , IKE_TRACK pxTrack
#endif
            )
{
    MSTATUS status = OK;
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
    ubyte2 wCfgId = 0;
#endif
#define DBG_EXIT_IN  { DBG_STATUS goto exit_in; }

    struct ikeHdr *pxHdr = NULL;
    ubyte4 dwLength, dwBodyLen, dwMsgId;

#if defined(__ENABLE_IKE_FRAGMENTATION__)
    ubyte isFragment    = 0;
    ubyte isReassembled = 0;
#endif

    IKESA pxSa = NULL;
    P2XG pxXg = NULL;
    IPSECSA pxIPsecSa = NULL;

    ikePeerConfig *config;

    ubyte oState = 0;
    funcPtrIkeCtx pInFunc;

    MSTATUS status_out;

#ifdef __ENABLE_IKE_XAUTH__
    intBoolean bXauth = FALSE;
#endif

    ubyte2 wIvLen = 0;
    ubyte __crypto__(poIv, IKE_IV_MAX);

    struct ike_context ctx = { NULL };

    struct ike_info_notify notifyInfo = { 0 };
    struct ike_info info = { NULL };
    info.pxNotify = &notifyInfo;

#ifndef __IKE_MULTI_HOMING__
    MOC_UNUSED(serverInstance);
#endif
#ifndef __ENABLE_IPSEC_NAT_T__
    MOC_UNUSED(bUseNattPort);
#endif

    /* sanity check */
    TEST_MOC_IPADDR6(peerAddr,
    {
        const ubyte *addr6 = GET_MOC_IPADDR6(peerAddr);
        if (0xFF == addr6[0]) /* multicast */
        {
            status = ERR_IKE;
            DBG_STATUS
            goto nocleanup;
        }
    })
    {
        ubyte4 dwPeerAddr = GET_MOC_IPADDR4(peerAddr);
        if ((0 == dwPeerAddr) || (0 == wPeerPort) || /* jic */
            ((dwPeerAddr & 0xe0000000) == 0xe0000000)) /* multicast/broadcast */
        {
            status = ERR_IKE;
            DBG_STATUS
            goto nocleanup;
        }
    }

    IKE_LOCK_R; /* !!! */

    if (NULL == (config = IKE_findPeerConfig(peerAddr, wPeerPort, serverInstance)))
    {
        status = ERR_IKE_NO_PEER_CONFIG;
        DBG_ABORT
    }

    /* message/event received */
    debug_printnl("");
#ifdef __ENABLE_IPSEC_NAT_T__
    if (bUseNattPort) debug_print("#");
#endif
    debug_print("RECV ");
    debug_uint(dwBufferSize);
    debug_print(" bytes from ");
    debug_print_ip(peerAddr);
    debug_print("[");
    debug_int(wPeerPort);
    debug_print("]");

#ifdef __IKE_MULTI_HOMING__
    debug_print(" at ");
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    if (NULL != m_ikeSettings.funcPtrIkeGetHostAddr) /* jic */
    {
        MOC_IP_ADDRESS_S hostAddr;
        if (OK > (m_ikeSettings.funcPtrIkeGetHostAddr(&hostAddr, serverInstance)))
        {
            debug_print("@");
            debug_hexint(serverInstance);
        }
        else
        {
            debug_print_ip(REF_MOC_IPADDR(hostAddr));
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
            debug_print("@");
            debug_hexint(serverInstance);
#endif
        }
    }
#endif
#endif
    debug_uptime();
    debug_printnl("");

#ifdef __ENABLE_IPSEC_NAT_T__
    if (bUseNattPort) /* received at port 4500 */
    {
        struct ikeNatEspMarker *pxEspMkr = (struct ikeNatEspMarker *)pBuffer;

        if (4 > dwBufferSize)
        {
            /* check NAT-Keepalive */
            if ((1 == dwBufferSize) && (0xFF == pBuffer[0]))
            {
                goto abort; /* ignore */
            }
            status = ERR_IKE_BAD_LEN;
            DBG_ABORT
        }
        if (0 != GET_NTOHL(pxEspMkr->dwSpi))
        {
            /* Note: This may be an UDP-encap. ESP packet, which is
               either not for us or yet to be processed by IPsec.
             */
            status = ERR_IPSEC_DROP_FINDSA_FAIL;
            DBG_ABORT
        }
        if (IKE_DEFAULT_UDP_PORT == wPeerPort) /* jic */
        {
            status = ERR_IKE_BAD_PORT;
            DBG_ABORT
        }
    }
    else /* received at port 500 */
    {
        if (IKE_NAT_UDP_PORT == wPeerPort) /* jic */
        {
           status = ERR_IKE_BAD_PORT;
           DBG_ABORT
        }
    }
#endif /* __ENABLE_IPSEC_NAT_T__ */

    /* set up context */
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if (OK > (status = IKE_getHwAccelChannel(&ctx.hwAccelCookie)))
        DBG_ABORT

    ctx.isHwAccelCookieInit = TRUE;
#endif
    ctx.pBuffer         = pBuffer;
    ctx.dwBufferSize    = dwBufferSize;

#ifdef __ENABLE_DIGICERT_HARNESS__
    dwBufferSize = m_ikeSettings.ikeBufferSize;
#ifdef __ENABLE_IPSEC_NAT_T__
    dwBufferSize += 4;
#endif
    if (dwBufferSize < ctx.dwBufferSize)
        dwBufferSize = ctx.dwBufferSize;

    pBuffer = NULL;
    if (OK > (status = CRYPTO_ALLOC(ctx.hwAccelCookie, dwBufferSize,
                                    TRUE, (void**) &pBuffer)))
        DBG_EXIT

    DIGI_MEMCPY(pBuffer, ctx.pBuffer, ctx.dwBufferSize);
    ctx.pBuffer         = pBuffer;
#endif /* __ENABLE_DIGICERT_HARNESS__ */

#ifdef __ENABLE_IPSEC_NAT_T__
    /* remove non-ESP marker */
    if (bUseNattPort) /* received at 4500 */
    {
        ctx.pBuffer += 4;
        ctx.dwBufferSize -= 4;
    }
#endif

    /* ISAKMP header */
    if (SIZEOF_ISAKMP_HDR > ctx.dwBufferSize)
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }
    pxHdr = (struct ikeHdr *) ctx.pBuffer;
    TRACK_HDR

    ctx.pBuffer         += SIZEOF_ISAKMP_HDR;
    ctx.dwBufferSize    -= SIZEOF_ISAKMP_HDR;
    ctx.dwLength        = SIZEOF_ISAKMP_HDR;

    /* message length */
    SET_NTOHL(dwLength, pxHdr->dwLength);
    dwBodyLen = dwLength - SIZEOF_ISAKMP_HDR;

    if ((SIZEOF_ISAKMP_HDR > dwLength) ||
        (dwBodyLen > ctx.dwBufferSize))
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }

    /* version */
    if ((1<<4) != pxHdr->oVersion)
    {
        status = ERR_IKE_BAD_VERSION;
        DBG_EXIT_IN
    }

    debug_print_ikehdr((ubyte *)pxHdr);

    dwMsgId = pxHdr->dwMsgId;

    /* exchange type */
    switch (pxHdr->oExchange)
    {
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    case ISAKMP_XCHG_AGGR :     /* aggressive mode */
#endif
    case ISAKMP_XCHG_IDPROT :   /* main mode */
        if (0 != dwMsgId)
        {
            status = ERR_IKE_BAD_MSGID;
            DBG_EXIT_IN
        }

        break;

#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
    case ISAKMP_XCHG_CFG :
#endif
    case ISAKMP_XCHG_QUICK :    /* quick mode */
        if ((pxHdr->oNextPayload != ISAKMP_NEXT_FRAGMENT) &&
            !(ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags))
        {
            status = ERR_IKE_BAD_FLAGS;
            DBG_EXIT_IN
        }
        /* fall through */
    case ISAKMP_XCHG_INFO :     /* informational exchange */
        if (0 == dwMsgId)
        {
            if (!(ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags))
                break;
            status = ERR_IKE_BAD_MSGID;
            DBG_EXIT_IN
        }
        break;

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    case ISAKMP_XCHG_GPUSH :    /* Note: same value as ISAKMP_XCHG_NGRP! */
        if (!(ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags))
        {
            status = ERR_IKE_BAD_FLAGS;
            DBG_EXIT_IN
        }
        if (0 == dwMsgId)
        {
            status = ERR_IKE_BAD_MSGID;
            DBG_EXIT_IN
        }
        break;
#else
    case ISAKMP_XCHG_NGRP :
#endif
    case ISAKMP_XCHG_BASE:
    case ISAKMP_XCHG_AO:
    case ISAKMP_XCHG_ACK_INFO :
#ifndef __ENABLE_IKE_AGGRESSIVE_MODE__
    case ISAKMP_XCHG_AGGR :
#endif
#if !(defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__))
    case ISAKMP_XCHG_CFG :
#endif
        status = ERR_IKE_BAD_XCHG;
        DBG_EXIT_IN
        /*break;*/
    default :
        status = ERR_IKE_BAD_MSG;
        DBG_EXIT_IN
        /*break;*/
    }

    /* check empty initiator cookie */
    if (IKE_isEmptyCky(pxHdr->poCky_I))
    {
        status = ERR_IKE_BAD_COOKIE;
        DBG_EXIT_IN
    }

    /* get IKE SA */
    if (OK > (status = IKE_getSa(pxHdr->poCky_I, pxHdr->poCky_R,
                                 0, peerAddr, &pxSa, NULL,
#ifdef __IKE_MULTI_THREADED__
                                 CheckMsgRecv
#else
                                 NULL
#endif
                                 MOC_MTHM_VALUE(serverInstance))))
    {
        TRACK_SA

        /* existing, but no longer valid */
        DBG_STATUS

#ifndef __IKE_MULTI_THREADED__
        if ((ERR_IKE_GETSA_FAIL == status) &&
            (NULL != pxSa) && /* jic */
            IS_IKE_SA_AUTHED(pxSa) &&
            (ISAKMP_XCHG_QUICK == pxHdr->oExchange) &&
            !IKE_isEmptyCky(pxHdr->poCky_R) &&
            (OK == IKE_getXchg(pxSa, dwMsgId, &pxXg)) &&
            (NULL == pxXg)) /* jic */
        {
            /* FOR NOW */
            IKE_delSa(pxSa, TRUE, OK); /* notify peer of deletion */
        }
#endif
        goto exit; /* !!! */
    }

    if (NULL == pxSa) /* not found */
    {
        if (IKE_isEmptyCky(pxHdr->poCky_R)) /* empty responder cookie */
        {
            /* 1st message received by the responder */
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
            intBoolean bGdoi = FALSE;

            if (m_ikeSettings.funcPtrIsKeyServer)
            {
                if (OK > (status = (MSTATUS)
                          m_ikeSettings.funcPtrIsKeyServer(&bGdoi
                                        MOC_MTHM_REQ_VALUE(serverInstance))))
                {
                    DBG_EXIT
                }
            }
#endif
            switch (pxHdr->oExchange)
            {
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
            case ISAKMP_XCHG_AGGR :     /* aggressive mode */
#endif
            case ISAKMP_XCHG_IDPROT :   /* main mode */
                break;
            default :
                status = ERR_IKE_BAD_XCHG;
                DBG_EXIT_IN
                /*break;*/
            }

             /* check encryption flag here to avoid calling IKE_newSa() prematurely */
            if (ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags)
            {
                status = ERR_IKE_BAD_FLAGS;
                DBG_EXIT_IN
            }

            /* new IKE SA for phase 1 exchange */
            if (NULL == (pxSa = IKE_newSa(config, peerAddr, wPeerPort, pxHdr->poCky_I
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
                                        , pxHdr->oExchange
#endif
#if defined(__ENABLE_DIGICERT_GDOI_SERVER__)
                                        , bGdoi
#elif defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
                                        , FALSE
#endif
                                          MOC_NATT_VALUE(bUseNattPort)
                                          MOC_MTHM_VALUE(serverInstance))))
            {
                status = ERR_IKE_NEWSA_FAIL;
                DBG_EXIT
            }
        }
        else
        {
            /* unknown cookies */
            status = ERR_IKE_BAD_COOKIE;
            DBG_EXIT_IN
        }
    }
    else
    {
        if (IKE_isEmptyCky(pxHdr->poCky_R))
        {
            if (IKE_isEmptyCky(pxSa->poCky_R))
            {
                /* reject empty responder cookie */
                if (ISAKMP_XCHG_INFO != pxHdr->oExchange)
                {
                    status = ERR_IKE_BAD_COOKIE;
                    DBG_EXIT
                }
            }
            else
            {
                TRACK_SA

                /* already received (1st message to us); probably re-transmit */
                status = ERR_IKE_BAD_XCHG;
                goto exit;
            }
        }

        /* check peer IP address */
        if (!SAME_MOC_IPADDR(peerAddr, pxSa->dwPeerAddr))
        {
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }

    } /* if (NULL == pxSa) */

    TRACK_SA

    /* check IKE SA */
    oState = pxSa->oState;
    switch (pxHdr->oExchange)
    {
    case ISAKMP_XCHG_IDPROT :   /* main mode */
        if (((STATE_MAIN_I1 >= oState) || (STATE_MAIN_I < oState)) &&
            ((STATE_MAIN_R1 > oState) || (STATE_MAIN_R < oState)))
        {
            status = ERR_IKE_BAD_XCHG;
            DBG_EXIT_IN
        }

        if ((STATUS_IKE_PENDING == pxSa->merror) &&
            ((STATE_MAIN_I4 == oState) || (STATE_MAIN_R3 == oState)))
        {
            /* certificate status check in progress */
            status = STATUS_IKE_PENDING;
            goto exit;
        }

#ifdef __ENABLE_IKE_FRAGMENTATION__
        if (pxSa && (IKE_SA_FLAG_FRAGMENTATION & pxSa->flags))
        {
#ifdef __ENABLE_IPSEC_NAT_T__
            /* remove non-ESP marker */
            if (bUseNattPort) /* received at 4500 */
            {
                status = IKE_fragCheckFragment(pBuffer+4, &isFragment);
            }
            else
#endif
            status = IKE_fragCheckFragment(pBuffer, &isFragment);
            if( OK > status)
            {
                goto exit;
            }

            if(isFragment)
            {
                ctx.pBuffer         -= SIZEOF_ISAKMP_HDR;
                ctx.dwBufferSize    += SIZEOF_ISAKMP_HDR;
                ctx.pxSa            = pxSa;
                status              = IKE_fragRecv(&ctx, &isReassembled);
                goto exit;
            }
        }
#endif /* __ENABLE_IKE_FRAGMENTATION__ */

        break;

#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    case ISAKMP_XCHG_AGGR :     /* aggressive mode */
        if (((STATE_AGGR_I1 >= oState) || (STATE_AGGR_I < oState)) &&
            ((STATE_AGGR_R1 > oState) || (STATE_AGGR_R < oState)))
        {
            status = ERR_IKE_BAD_XCHG;
            DBG_EXIT_IN
        }

        if ((STATUS_IKE_PENDING == pxSa->merror) &&
            ((STATE_AGGR_I2 == oState) || (STATE_AGGR_R2 == oState)))
        {
            /* certificate status check in progress */
            status = STATUS_IKE_PENDING;
            goto exit;
        }
#ifdef __ENABLE_IKE_FRAGMENTATION__
#ifdef __ENABLE_IPSEC_NAT_T__
        /* remove non-ESP marker */
        if (bUseNattPort) /* received at 4500 */
        {
            status = IKE_fragCheckFragment(pBuffer+4, &isFragment);
        }
        else
#endif
        status = IKE_fragCheckFragment(pBuffer, &isFragment);
        if (OK > status)
        {
            goto exit;
        }

        if (isFragment)
        {
            intBoolean fragNotSupported = (IKE_SA_FLAG_FRAGMENTATION & pxSa->flags)
                                        ? FALSE : TRUE;
            if (fragNotSupported)
            {
                /* VID not received yet but may be part of this message */
                pxSa->flags |= IKE_SA_FLAG_FRAGMENTATION; /* !!! */
            }
            ctx.pBuffer         -= SIZEOF_ISAKMP_HDR;
            ctx.dwBufferSize    += SIZEOF_ISAKMP_HDR;
            ctx.pxSa            = pxSa;
            status              = IKE_fragRecv(&ctx, &isReassembled);
            if (fragNotSupported)
            {
                pxSa->flags &= ~IKE_SA_FLAG_FRAGMENTATION;
            }
            goto exit;
        }
#endif /* __ENABLE_IKE_FRAGMENTATION__ */
        break;
#endif
    case ISAKMP_XCHG_QUICK :    /* quick mode */
        /* phase 1 exchange must be completed */
        if (!IS_IKE_SA_AUTHED(pxSa))
        {
            status = ERR_IKE_BAD_XCHG;
            DBG_EXIT_IN
        }

#ifdef __ENABLE_IKE_FRAGMENTATION__
        if (pxSa && (IKE_SA_FLAG_FRAGMENTATION & pxSa->flags))
        {
#ifdef __ENABLE_IPSEC_NAT_T__
            /* remove non-ESP marker */
            if (bUseNattPort) /* received at 4500 */
            {
                status = IKE_fragCheckFragment(pBuffer+4, &isFragment);
            }
            else
#endif
            status = IKE_fragCheckFragment(pBuffer, &isFragment);
            if( OK > status)
            {
                goto exit;
            }

            if(isFragment)
            {
                ctx.pBuffer         -= SIZEOF_ISAKMP_HDR;
                ctx.dwBufferSize    += SIZEOF_ISAKMP_HDR;
                ctx.pxSa            = pxSa;
                status              = IKE_fragRecv(&ctx, &isReassembled);
                goto exit;
            }
        }
#endif /* __ENABLE_IKE_FRAGMENTATION__ */

        /* get quick mode exchange */
        if (OK > (status = IKE_getXchg(pxSa, dwMsgId, &pxXg)))
        {
            TRACK_XG

            /* invalid exchange (deleted or expired) */
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
            if (NULL != pxXg)
            {
                if (!IS_P2_FINAL_STATE(pxXg->oState)) /* may be a re-transmission */
                    DBG_STATUS

                goto exit;
            }
            else
#endif
            DBG_EXIT
        }

        /* 1st message received by the quick mode responder? */
        if (NULL == pxXg) /* yes */
        {
            if (IKE_SA_FLAG_REKEYED & pxSa->flags)
            {
                /* IKE_SA already rekeyed */
                status = ERR_IKE_NEWSA_FAIL;
                DBG_EXIT
            }

            /* new IPSEC SA for quick mode exchange */
            if (OK > (status = IKE_newIPsecSa(pxSa, dwMsgId, &pxXg)))
                DBG_EXIT

            TRACK_XG
            oState = pxXg->oState;
        }
        else /* no */
        {
            TRACK_XG
            oState = pxXg->oState;

            if ((STATE_QUICK_R1 == oState) &&
                (IKE_XCHG_FLAG_PENDING & pxXg->x_flags))
            {
                status = STATUS_IKE_PENDING;
                goto exit;
            }

            /* sanity-check - jic */
            if (!IS_QUICK_MODE_STATE(oState) ||
                (STATE_QUICK_I1 == oState) ||
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
                (STATE_GPULL_I1 == oState) ||
#endif
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
                (STATE_GPULL_R1 == oState) ||
#endif
                (STATE_QUICK_R1 == oState))
            {
                status = ERR_IKE_BAD_XCHG;
                DBG_EXIT
            }
        }
        pxIPsecSa = P2XG_IPSECSA(pxXg);
        break;

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    case ISAKMP_XCHG_GPUSH :    /* GDOI PUSH client */
        if (!(IKE_SA_FLAG_GDOI_PUSH & pxSa->flags) || IS_INITIATOR(pxSa))
        {
            status = ERR_IKE_BAD_XCHG;
            DBG_EXIT_IN
        }

        /* get exchange */
        if (OK > (status = IKE_getXchg(pxSa, dwMsgId, &pxXg)))
        {
            TRACK_XG

            /* invalid exchange (deleted or expired) */
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
            if (NULL != pxXg)
            {
                if (STATE_GPUSH_R != pxXg->oState) /* may be a re-transmission */
                    DBG_STATUS

                goto exit;
            }
            else
#endif
            DBG_EXIT
        }

        /* 1st (and only) message received by responder? */
        if (NULL == pxXg) /* yes */
        {
            /* new IPSEC SA */
            if (OK > (status = IKE_newIPsecSa(pxSa, dwMsgId, &pxXg)))
                DBG_EXIT

            TRACK_XG
            oState = pxXg->oState;
        }
        else /* no */
        {
            TRACK_XG

            status = ERR_IKE_BAD_XCHG;
            DBG_EXIT
        }
        pxIPsecSa = P2XG_IPSECSA(pxXg);
        break;
#endif /* __ENABLE_DIGICERT_GDOI_CLIENT__ */

    case ISAKMP_XCHG_INFO :     /* informational */

        /* check existing message id */
        if (IS_P1_FINAL_STATE(oState))
        {
            /* Messgae ID must be unique for each informational exchange */
            if (0 == dwMsgId)
            {
                status = ERR_IKE_BAD_MSGID;
                DBG_EXIT
            }

            if (OK > (status = IKE_getXchg(pxSa, dwMsgId, &pxXg)))
            {
                TRACK_XG

                /* invalid phase 2 exchange (deleted or expired)
                   OR re-transmitted informational exchange!
                 */
                DBG_EXIT
            }

            if (NULL != pxXg) /* active phase 2 exchange */
            {
                oState = pxXg->oState;
                if (STATE_QUICK_I2c == oState) /* COMMIT state (quick mode) */
                {
                    TRACK_XG

                    if (!(ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags))
                    {
                        status = ERR_IKE_BAD_FLAGS;
                        DBG_EXIT_IN
                    }
                    pxIPsecSa = P2XG_IPSECSA(pxXg);
                    break;
                }
                status = ERR_IKE_BAD_MSGID;
                DBG_EXIT_IN
            }
        }
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
        else if (STATE_AGGR_I2c == oState) /* COMMIT state */
            break;
#endif
        oState = STATE_INFO;
        break;

#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
    case ISAKMP_XCHG_CFG :      /* IKECFG: MODE_CFG or XAUTH */
        /* phase 1 exchange must be completed */
        if (!IS_P1_FINAL_STATE(oState))
        {
            status = ERR_IKE_BAD_XCHG;
            DBG_EXIT
        }

#ifdef __ENABLE_IKE_FRAGMENTATION__
        if (pxSa && (IKE_SA_FLAG_FRAGMENTATION & pxSa->flags))
        {
#ifdef __ENABLE_IPSEC_NAT_T__
            /* remove non-ESP marker */
            if (bUseNattPort) /* received at 4500 */
            {
                status = IKE_fragCheckFragment(pBuffer+4, &isFragment);
            }
            else
#endif
            status = IKE_fragCheckFragment(pBuffer, &isFragment);
            if( OK > status)
            {
                goto exit;
            }

            if(isFragment)
            {
                ctx.pBuffer         -= SIZEOF_ISAKMP_HDR;
                ctx.dwBufferSize    += SIZEOF_ISAKMP_HDR;
                ctx.pxSa            = pxSa;
                status              = IKE_fragRecv(&ctx, &isReassembled);
                goto exit;
            }
        }
#endif /* __ENABLE_IKE_FRAGMENTATION__ */

        /* get IKECFG exchange */
        if (OK > (status = IKE_getXchg(pxSa, dwMsgId, &pxXg)))
        {
            TRACK_XG

            /* invalid exchange (expired or deleted) */
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
            if (NULL != pxXg) /* jic */
            {
                switch (pxXg->oState)
                {
                case STATE_CFG_I :
                case STATE_CFG_R :
#ifdef __ENABLE_IKE_XAUTH__
                case STATE_CFG_Ixc :
                case STATE_CFG_Ix :
                case STATE_CFG_Rx : /* draft-ietf-ipsec-isakmp-xauth-01...02 (CFG_AUTH_OK/FAILED) */
#endif
                    goto exit;
                    break;
                }
            }
#endif
            DBG_EXIT
        }

        if (NULL != pxXg) /* existing exchange */
        {
            TRACK_XG

            oState = pxXg->oState;
            switch (oState)
            {
            case STATE_CFG_R1 :
                /*if (IKE_XCHG_FLAG_PENDING & pxXg->x_flags)*/
                status = STATUS_IKE_PENDING;
                goto exit;
                break;

            case STATE_CFG_R :
#ifndef __ENABLE_IKE_XAUTH__
            {
                /* probably re-transmission */
#ifndef __IKE_UPDATE_TIMER__
                ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
                ubyte4 timewaitRetx = m_ikeSettings.ikeWaitRetransmit;

                if (timewaitRetx < (timenow - pxXg->dwTimeStamp))
#endif
                    pxXg->dwTimeStamp = 0; /* will re-transmit */
                goto exit;
            }
#endif
            case STATE_CFG_I2 :
                break;
#ifdef __ENABLE_IKE_XAUTH__
            /* XAUTH Server */
            case STATE_CFG_I2xc:
                if (IKE_XCHG_FLAG_PENDING & pxXg->x_flags)
                {
                    status = STATUS_IKE_PENDING;
                    goto exit;
                }
                break; /* waiting for REPLY */
            case STATE_CFG_I3x:
                break; /* waiting for ACK */
#endif
            default :
                status = ERR_IKE_BAD_XCHG;
                DBG_EXIT
                break;
            }
        }
        else /* new exchange */
        {
            if (IKE_SA_FLAG_REKEYED & pxSa->flags)
            {
                /* IKE_SA already rekeyed */
                status = ERR_IKE_NEWSA_FAIL;
                DBG_EXIT
            }

            if (OK > (status = IKE_newXchg(pxSa, dwMsgId, &pxXg)))
                DBG_EXIT

            oState =
            pxXg->oState = STATE_CFG_R1;

            TRACK_XG
        }

#ifdef __ENABLE_IKE_XAUTH__
        bXauth = (IKE_SA_FLAG_XAUTH & pxSa->flags);
#endif
        break;
#endif /* IKECFG */

    default : /* should not get here */
        goto exit; /* jic */
    }

    if (NULL == (pInFunc = STATE_IN_FUNC(oState)))
    {
        /* already reached final state - probably re-transmission */
        status = ERR_IKE_BAD_XCHG;
        goto exit;
    }

    /* check peer port */
    if (STATE_INFO != oState)
    {
#ifdef __ENABLE_IPSEC_NAT_T__
        if (!bUseNattPort && USE_NATT_PORT(pxSa)) /* expect port 4500 */
        {
            status = ERR_IKE_BAD_PORT;
            DBG_EXIT_IN
        }
#endif
        if (wPeerPort != pxSa->wPeerPort) /* peer port changed */
        {
#ifdef __ENABLE_IPSEC_NAT_T__
            if ((IKE_NATT_FLAG_NPORT_USED & pxSa->natt_flags) ||
                (/*(STATE_MAIN_I3 != oState)
                 && (STATE_MAIN_I4 != oState)
                 &&*/ (STATE_MAIN_R3 != oState)
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
/*               && (STATE_AGGR_I2 != oState)*/
                 && (STATE_AGGR_R2 != oState)
#endif
                 ))
#endif
            {
                status = ERR_IKE_BAD_MSG;
                DBG_EXIT_IN
            }
        }
    }

    /* decrypt message, if necessary */
    if (ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags)
    {
        /* encryption key established? */
        if (!(IKE_SA_FLAG_KE & pxSa->flags))
        {
            status = ERR_IKE_BAD_FLAGS;
            DBG_EXIT_IN
        }

        /* the length of encrypted data should be multiple of block length */
        if (!dwBodyLen || (dwBodyLen % pxSa->pCipherSuite->pBEAlgo->blockSize))
        {
            status = ERR_IKE_BAD_BLOCK;
            DBG_EXIT_IN
        }

        /* iv */
#ifdef __ENABLE_DIGICERT_HARNESS__
        if (OK > (status = CRYPTO_ALLOC(ctx.hwAccelCookie, IKE_IV_MAX,
                                        TRUE, (void**) &poIv)))
            DBG_EXIT_IN
#endif
        if (ISAKMP_XCHG_INFO == pxHdr->oExchange) /* informational - do not use 'oState' */
        {
            /* calculate iv */
            if (OK > (status = IKE_newSaIv(MOC_HASH(ctx.hwAccelCookie)
                                           pxSa, &dwMsgId, poIv)))
                DBG_EXIT
        }
        else
        {
            /* copy iv */
            wIvLen = pxSa->pCipherSuite->wIvLen;
            DIGI_MEMCPY(poIv, (pxXg ? pxXg->poIv : pxSa->u.v1.poIv), wIvLen);
/*          DIGI_MEMCPY(poIv, ctx.pBuffer + dwBodyLen - wIvLen, wIvLen);*/ /* store new iv */
        }

        /* decrypt */
        if (OK > (status = CRYPTO_Process(MOC_SYM(ctx.hwAccelCookie)
                                    pxSa->pCipherSuite->pBEAlgo,
                                    pxSa->u.v1.poKeyId_e,
                                    pxSa->wEncrKeyLen,
                                    poIv, /* to be midified */
                                    ctx.pBuffer,
                                    dwBodyLen,
                                    FALSE)))
            DBG_EXIT_IN

        TRACK_PLAINTEXT

    } /* if (ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags) */

    /* process message */
    ctx.dwBufferSize    = dwBodyLen;

    ctx.pxSa            = pxSa;
    ctx.pxP2Xg          = pxXg;

    ctx.oNextPayload    = pxHdr->oNextPayload;
    ctx.pHdrParent      = pxHdr;

#ifdef CUSTOM_IKE_CATCH_EXCEPTION
    ctx.pxIkeHdr        = pxHdr;
#endif

    if (STATE_INFO == oState) /* informational */
    {
        if (OK > (status = pInFunc(&ctx)))
            goto exit_in;
    }
    else
    {
        ubyte4 old_flags = ((NULL == pxXg) ? pxSa->flags /* phase 1 */
                         : ((NULL != pxIPsecSa) ? pxIPsecSa->c_flags /* quick mode */
                         : 0));

#ifdef __ENABLE_IPSEC_NAT_T__
        ubyte old_natt_flags = pxSa->natt_flags;
        ubyte2 wHostPortOld = pxSa->wHostPort;
        ubyte2 wPeerPortOld = pxSa->wPeerPort;

        /* changing port, if necessary */
        if (NULL == pxXg) /* phase 1 */
        {
            if (wPeerPort != wPeerPortOld) /* peer port changed */
            {
                ctx.wPeerPort = wPeerPortOld;
                pxSa->wPeerPort = wPeerPort;
            }

            if (bUseNattPort)
            {
                if (!USE_NATT_PORT(pxSa))
                {
                    if (m_ikeSettings.funcPtrIkeGetHostPort)
                    {
                        if (OK > (status = (MSTATUS)
                                  m_ikeSettings.funcPtrIkeGetHostPort(
                                    &pxSa->wHostPort
                                    MOC_NATT_REQ_VALUE(TRUE)
                                    MOC_MTHM_REQ_VALUE(pxSa->serverInstance))))
                        {
                            DBG_EXIT_IN
                        }
                    }
                    else
                    {
                        pxSa->wHostPort = IKE_NAT_UDP_PORT;
                    }
                    pxSa->natt_flags |= IKE_NATT_FLAG_USE_NPORT;
                }
                pxSa->natt_flags |= IKE_NATT_FLAG_NPORT_USED;
            }
        }
#endif

        /* check COMMIT flag */
        if (ISAKMP_FLAG_COMMIT & pxHdr->oFlags)
        {
            if (NULL == pxXg) /* phase 1 */
            {
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
                if (IS_INITIATOR(pxSa) && (ISAKMP_XCHG_AGGR == pxHdr->oExchange))
                    pxSa->flags |= IKE_SA_FLAG_COMMIT;
#endif
            }
            else if (NULL != pxIPsecSa) /* quick mode */
            {
                if (IS_CHILD_INITIATOR(pxIPsecSa))
                    pxIPsecSa->c_flags |= IKE_CHILD_FLAG_COMMIT;
            }
        }

        /* check error in received exchange message */
        if ((OK > (status = pInFunc(&ctx))) &&
            (STATUS_IKE_PENDING != status)) /* !!! */
        {
            /* reset flags */
            if (NULL == pxXg) /* phase 1 */
            {
                pxSa->flags = old_flags;
#ifdef __ENABLE_IPSEC_NAT_T__
                pxSa->natt_flags = old_natt_flags;

                pxSa->wHostPort = wHostPortOld;
                pxSa->wPeerPort = wPeerPortOld;
#endif
            }
            else if (NULL != pxIPsecSa) /* quick mode */
            {
                pxIPsecSa->c_flags = (ubyte2)old_flags;
            }

            /* notify peer, if applicable */
            if (0 != ctx.wMsgType)
            {
                notifyInfo.wMsgType = ctx.wMsgType;
                notifyInfo.oProtoId = PROTO_ISAKMP;
                if (NULL != pxIPsecSa)
                {
                    int i = (sbyte4)pxIPsecSa->oP2SaNum - 1;
                    if (0 <= i) /* jic */
                    {
                        IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[i].
                                                axChildSa[0].ipsecPps);
                        notifyInfo.oProtoId = pxIPsecPps->oProtocol;
                        notifyInfo.dwSpi = IS_CHILD_INITIATOR(pxIPsecSa)
                                         ? pxIPsecPps->dwSpi[_R]
                                         : pxIPsecPps->dwSpi[_I];
                    }
                }
                ctx.pxInfo = &info;
            }

            goto exit_in;
        }
    }

    /* message accepted */
    if (ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags)
    {
        /* replace iv */
        if (ISAKMP_XCHG_INFO != pxHdr->oExchange)
        {
            DIGI_MEMCPY((pxXg ? pxXg->poIv : pxSa->u.v1.poIv), poIv, wIvLen);
            DIGI_MEMCPY((pxXg ? pxXg->poIvOld : pxSa->u.v1.poIvOld), poIv, wIvLen);

#ifndef __ENABLE_KEYVPN_LOG_SUPPRESSION__
            if (NULL == pxXg)
                debug_printd((sbyte *)"   Initialization vector:", poIv, wIvLen);
#endif
        }

        /* book-keeping */
        pxSa->dwCurBytes += dwLength;
        if (1024 <= pxSa->dwCurBytes)
        {
            ubyte4 dwNewKBytes = pxSa->dwCurKBytes + (pxSa->dwCurBytes / 1024);
            pxSa->dwCurBytes = (pxSa->dwCurBytes % 1024);

             /* jic KBytes wraps back to 0 */
            if (pxSa->dwExpKBytes && (pxSa->dwCurKBytes > dwNewKBytes))
            {
                pxSa->dwCurBytes += (ubyte4)((dwNewKBytes + 1) * 1024);
                dwNewKBytes = ~((ubyte4)0);
            }
            pxSa->dwCurKBytes = dwNewKBytes;
        }

#ifdef __IKE_UPDATE_TIMER__
        KB_REKEY(pxSa) /* auto. rekeying - lifetime kbytes */
#endif
    }

exit_in:
#ifdef CUSTOM_IKE_CATCH_EXCEPTION
    if ((OK > status) && (STATUS_IKE_PENDING != status))
    {
        ubyte oNp = ctx.oCurrPayload;
        void *pPayload = ctx.pCurrPayload;

        CUSTOM_IKE_CATCH_EXCEPTION(status,
            peerAddr, pxHdr,
            oNp, pPayload,
            pxSa, pxXg, pxIPsecSa);
    }
#endif

    if (STATE_INFO == oState)
    {
        if ((OK <= status) && (NULL != pxSa) && (0 != ctx.wMsgType))
        {
            pxSa->wMsgType = ctx.wMsgType;
            pxSa->merror = ERR_IKE_NOTIFY_PAYLOAD;
        }
        TRACK_OK
        goto exit;
    }

    if (OK > status)
    {
        if (NULL != pxXg) /* phase 2 */
        {
            if (IKE_CNTXT_FLAG_HASHED & ctx.flags) /* integrity-check passed! */
            {
                if (STATUS_IKE_PENDING != status) /* !!! */
                {
                    IKE_delXchg(pxXg, pxSa, status); /* delete exchange */
#ifdef __ENABLE_IKE_XAUTH__
                    if ((STATE_CFG_I2xc == oState) || (STATE_CFG_I3x == oState))
                    {
                        /* XAUTH server */
                        IKE_delSa(pxSa, TRUE, status);
#ifdef __IKE_MULTI_THREADED__
                        goto exit;
#endif
                    }
#endif
                }
            }
            else if ((STATE_QUICK_R1 == oState)
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
                  || (STATE_CFG_R1 == oState)
#endif
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
                  || (STATE_GPULL_R1 == oState)
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
                  || (STATE_GPUSH_R1 == oState)
#endif
                     )
            {
                /* disregard 1st message, if integrity-check failed! */
                IKE_delXchg(pxXg, pxSa, status); /* delete exchange */
                DIGI_MEMSET((ubyte *)pxXg, 0x00, sizeof(struct p2xg)); /* clean up */
            }
            else if (NULL != pxIPsecSa)
            {
                pxIPsecSa->merror = status;
            }
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
            else
            {
#ifdef __ENABLE_IKE_XAUTH__
                /* draft-ietf-ipsec-isakmp-xauth-01...04 (Message ID) */
                if (STATE_CFG_R == oState)
                {
                    /* XAUTH client - probably re-transmission */
#ifndef __IKE_UPDATE_TIMER__
                    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
                    ubyte4 timewaitRetx = m_ikeSettings.ikeWaitRetransmit;

                    if (timewaitRetx < (timenow - pxXg->dwTimeStamp))
#endif
                        pxXg->dwTimeStamp = 0; /* will re-transmit */
                }
                else
#endif
                pxXg->merror = status;
            }
#endif
        }
        else /* !!! */
        if ((NULL != pxSa) && /* jic */
            !IS_IKE_SA_AUTHED(pxSa))
        {
            if ((STATE_MAIN_R1 == oState)
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
             || (STATE_AGGR_R1 == oState)
#endif
                )
            {
                /* delete SA - responder 1st msg. */
                IKE_delSa(pxSa, FALSE, status);
#ifdef __IKE_MULTI_THREADED__
                goto exit;
#endif
            }
            else
            {
                pxSa->merror = status;
            }
        }

        if (NULL == ctx.pxInfo)
        {
            goto exit;
        }
    }
    else
    {
        if (NULL != pxIPsecSa)
        {
            pxIPsecSa->merror = OK;
        }
        else if (NULL != pxXg)
        {
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
            pxXg->merror = OK;
#endif
        }
        else if ((NULL != pxSa) && /* jic */
                 !IS_IKE_SA_AUTHED(pxSa))
        {
            pxSa->merror = OK;
        }

        TRACK_OK
    }

    /* send exchange message */
    ctx.pBuffer         = pBuffer;
    ctx.dwBufferSize    = dwBufferSize;

    if (OK > (status_out = IKE_xchgOut(&ctx)))
    {
#ifdef __IKE_KEYADD_DONT_WAIT__
        if ((NULL != pxIPsecSa) &&
            (OK <= pxIPsecSa->merror) &&
            !IS_MATURE_CHILD(pxIPsecSa) &&
            IS_P2_FINAL_STATE(pxIPsecSa->oState))
        {
            /* TODO: delete keys */
        }
#endif
        if (NULL == ctx.pxInfo)
        {
            status = status_out;
        }
        goto exit;
    }

    if (NULL != ctx.pxInfo)
        goto exit;

    /* check completed exchange */

    if (NULL != pxIPsecSa) /* phase 2 quick mode */
    {
        oState = pxIPsecSa->oState;
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
        if (STATE_GPULL_R != oState) /* GDOI server does not 'add' any key! */
#endif
        if (IS_P2_FINAL_STATE(oState))
        {
            /* make Klocwork happy */
            if (NULL == pxXg)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
            if ((STATE_GPULL_I == oState) || (STATE_GPUSH_R == oState))
            {
                GDOI_addTek(&ctx);
                IKE_delXchg(pxXg, pxSa, OK);
            }
            else
#endif
            /* update IPsec SADB */
            /* WARNING: race condition between peers */
#ifndef __IKE_KEYADD_DONT_WAIT__
            if ((OK > IKE_addIPsecKey(&ctx)) || IS_MATURE_CHILD(pxIPsecSa))
                IKE_delXchg(pxXg, pxSa, OK);
#else
            if (IS_MATURE_CHILD(pxIPsecSa))
            {
                IKE_addIPsecKey(&ctx);
                IKE_delXchg(pxXg, pxSa, OK);
            }
#endif
        }
    }

    else if (NULL == pxXg) /* phase 1 */
    {
        oState = pxSa->oState;
        if (IS_P1_FINAL_STATE(oState))
        {
            ctx.pBuffer = pBuffer;
            ctx.dwBufferSize = dwBufferSize;
            status = OnP1FinalState(pxSa, oState, &ctx);
        }
    }
    else
    {
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
        /* delete exchange in 'mature' final state */
        switch (oState = pxXg->oState)
        {
#ifdef __ENABLE_IKE_XAUTH__
        /* XAUTH server */
        case STATE_CFG_Ixc : /* REPLY processed */
            bXauth = FALSE; /* do not act on Fail/Success yet (see below) */
        case STATE_CFG_Ix : /* ACK received */

        /* XAUTH client */
        case STATE_CFG_Rx : /* draft-ietf-ipsec-isakmp-xauth-01...02 (CFG_AUTH_OK/FAILED) */
#endif
        case STATE_CFG_I :
            wCfgId = pxXg->wCfgId;
            IKE_delXchg(pxXg, pxSa, OK);
#if defined(__ENABLE_DIGICERT_GDOI_SERVER__) && defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
            if (!m_stopRespAttrProcessing)
            {
                break;
            }
            if(( m_gdoiGroupCount == (ubyte4) (wCfgId +1)* MAX_SKDC_KEY_NEGOTIATION) && (m_gdoiGroupCount < MAX_GROUP_NEGOTIATION))   /* 2^n -1 keys are received for the cfg identifier*/
                FetchMoreCfg(pxSa,&ctx, wCfgId+1);
#endif
            break;
        }

#ifdef __ENABLE_IKE_XAUTH__
        if (bXauth)
        {
            if (IKE_SA_FLAG_XAUTH & pxSa->flags)
            {
                if (ERR_IKE_XAUTH_FAILED == pxSa->merror)
                {
                    IKE_delSa(pxSa, FALSE, OK); /* delete IKE_SA immediately */
                    status = ERR_IKE_XAUTH_FAILED;
                }
                goto exit;
            }

            /* XAUTH success */
            ctx.pBuffer = pBuffer;
            ctx.dwBufferSize = dwBufferSize;
            status = OnAuthenticated(pxSa, oState, &ctx);
        }
#endif /* __ENABLE_IKE_XAUTH__ */
#endif /* defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__) */
    }

exit:
    _CRYPTO_FREE_(ctx.hwAccelCookie, pBuffer)
    _CRYPTO_FREE_(ctx.hwAccelCookie, poIv)

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if (ctx.isHwAccelCookieInit)
    {
        IKE_releaseHwAccelChannel(&ctx.hwAccelCookie);
    }
#endif
abort:
    IKE_UNLOCK_R;

#ifdef __ENABLE_IKE_FRAGMENTATION__
    /* if it is a reassembled msg, recurse, else exit */
    if ((OK == status) && (isReassembled))
    {
#ifdef __ENABLE_IPSEC_NAT_T__
        if (bUseNattPort)
        {
            pxHdr = (struct ikeHdr *)(ctx.pBuffer + 4);
            SET_NTOHL(dwLength, pxHdr->dwLength);
            dwLength += 4;
        }
        else
#endif
        {
            pxHdr = (struct ikeHdr *)ctx.pBuffer;
            SET_NTOHL(dwLength, pxHdr->dwLength);
        }
        status = IKE_msgRecv(peerAddr, wPeerPort, ctx.pBuffer, dwLength,
                             serverInstance, bUseNattPort
#ifdef __IKE_TRACK__
                           , pxTrack
#endif
                             );
        CHECK_FREE(ctx.pRefragmentationBuffer);  /* free the reassembled buffer */
    }

#endif

nocleanup:
    return (sbyte4)status;
} /* IKE_msgRecv */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_msgIdle(void)
{
    MSTATUS status = OK;

#ifdef __IKE_UPDATE_TIMER__
    TIMER_progress(m_ikeTimer);
#else
    /* expire/rekey p1 SA's */
    IKE_updateSadb();
    IKE2_updateSadb(); /* [v2] */

    /* handle pending p2 exchange */
    status = IKE_handleEvents();
#endif

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (g_ikeRadInstId)
    {
        IKE_LOCK_W;
        status = RADIUS_periodic(g_ikeRadInstId);
        IKE_UNLOCK_W;
    }
#endif
    return (sbyte4)status;
} /* IKE_msgIdle */


/*------------------------------------------------------------------*/

#ifdef __IKE_UPDATE_TIMER__

static void
SecretTimerEvent(sbyte4 cookie, ubyte4 cookie1, void *data, ubyte4 timerId)
{
    /* [v2] regenerate Notify COOKIE secret; every 5 minutes */

#ifdef __IKE_MULTI_THREADED__
    if (timerId != m_ikeScrtTimerId) return;
#else
    MOC_UNUSED(timerId);
#endif

    m_ikeScrtTimerId = (IKE_TIMER_EVT_T)0; /* !!! */
    m_ikeScrtTimerHdl = (IKE_TIMER_HDL_T)NULL; /* !!! */

    RANDOM_numberGenerator(g_pRandomContext, (ubyte *)g_ikeSecret, g_ikeScrtLen);
    g_ikeScrtVerID++;

    if (OK > IKE_ADD_TIMER_EVT(300000, 0, ((IKESA)NULL),
                               SecretTimerEvent, "SRT",
                               m_ikeScrtTimerId, m_ikeScrtTimerHdl))
    {
        debug_printnl("Failed to schedule timer for Notify COOKIE.");
    }

    MOC_UNUSED(cookie);
    MOC_UNUSED(data);
    MOC_UNUSED(cookie1);

    return;
} /* SecretTimerEvent */

#endif


/*------------------------------------------------------------------*/

extern sbyte4
IKE_init(void)
{
    MSTATUS status = OK;

    if (NULL != g_ikeMtx)
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockFree(&g_ikeMtx);
#else
#ifdef __ENABLE_DIGICERT_IKE_RECURSIVE_MUTEX__
        RTOS_recursiveMutexFree(&g_ikeMtx);
#else
        RTOS_mutexFree(&g_ikeMtx);
#endif
#endif
        g_ikeMtx = NULL;
    }

#ifdef __IKE_MULTI_THREADED__
    if (OK > (status = RTOS_rwLockCreate(&g_ikeMtx)))
#else
#ifdef __ENABLE_DIGICERT_IKE_RECURSIVE_MUTEX__
    if (OK > (status = RTOS_recursiveMutexCreate(&g_ikeMtx, IKE_MT_MUTEX, 0)))
#else
    if (OK > (status = RTOS_mutexCreate(&g_ikeMtx, IKE_MT_MUTEX, 0)))
#endif
#endif
    {
        DIGICERT_log((sbyte4)MOCANA_IKE, (sbyte4)LS_MAJOR, (sbyte *)"RTOS_mutexCreate() failed.");
        goto exit;
    }

    /* default settings */
    DIGI_MEMSET((ubyte *)&m_ikeSettings, 0x00, sizeof(ikeSettings));

    m_ikeSettings.ikeTimeoutNegotiation = TIMEOUT_IKE_NEGOTIATION;
    m_ikeSettings.ikeTimeoutEvent       = TIMEOUT_IKE_EVENT;
    m_ikeSettings.ikeTimeoutDpd         = TIMEOUT_IKE_DPD;

#ifdef __ENABLE_IPSEC_NAT_T__
    m_ikeSettings.ikeIntervalKeepalive  = INTERVAL_IKE_KEEPALIVE;
#endif
    m_ikeSettings.ikeWaitRetransmit     = WAIT_IKE_RETRANSMIT;

    m_ikeSettings.ikeP1LifeSecs         = ISAKMP_SA_LIFE_SECS;      /* 1 hr. */
    m_ikeSettings.ikeP1LifeSecsMax      = ISAKMP_SA_LIFE_SECS_MAX;  /* 1 day */
/*
    m_ikeSettings.ikeReauthSecs         = 0;

    m_ikeSettings.ikeP1LifeKBytes       = 0;
    m_ikeSettings.ikeP1LifeKBytesMax    = 0;
*/
    m_ikeSettings.ikeP2LifeSecs         = IPSEC_SA_LIFE_SECS;       /* 8 hrs - RFC 2407 4.5, p.13 */
    m_ikeSettings.ikeP2LifeSecsMax      = IPSEC_SA_LIFE_SECS_MAX;   /* 1 day */
/*
    m_ikeSettings.ikeP2LifeKBytes       = 0;
    m_ikeSettings.ikeP2LifeKBytesMax    = 0;
*/
    m_ikeSettings.ikeVersion            = MOC_IKE_VERSION;

#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    m_ikeSettings.ikeP1Mode             = IKE_P1_MODE;
#endif
    m_ikeSettings.ikeP1DHgroup          = IKE_P1_DH_GROUP;

    m_ikeSettings.ikeP2PFS              = IKE_P2_PFS;

    m_ikeSettings.ikeBufferSize         = IKE_DEFAULT_BUFFER_SIZE
#if defined(__ENABLE_IKE_OCSP_EXT__)
                                        + 2048
#endif
                                        ;
#ifdef __ENABLE_IKE_FRAGMENTATION__
    m_ikeSettings.ikeFragSize           = IKE_FRAG_SIZE;
#endif

#ifdef __ENABLE_IKE_PPK_RFC8784__
    m_ikeSettings.bPpkEnforce      = TRUE;
#endif

#ifdef __IKE_ENCR_AGGR_MODE__ /* backward comp. */
    m_ikeSettings.flags                |= IKE_SETTINGS_FLAG_ENCR_AGGR;
#endif

#ifdef __ENABLE_IKE_XAUTH__
    m_ikeSettings.xauthDraft            = 9; /* draft-beaulieu-ike-xauth-02 */
#endif

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_TTLS__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    m_ikeSettings.eapTtlsType           = (sbyte4)EAP_METHOD_TYPE_EAP;
#endif

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    m_ikeSettings.ikeHashAlgo           = OAKLEY_SHA;
    m_ikeSettings.ikeEncrAlgo           = OAKLEY_3DES_CBC;
/*  m_ikeSettings.ikeEncrKeyLen         = 0; */
#endif

#if defined(__IKE_UPDATE_TIMER__) || defined( __ENABLE_IKE_FRAGMENTATION__) || defined(__ENABLE_IKE_REDIRECT__)
    if (OK > (status = TIMER_initTimer()))
        goto exit;
#endif
#ifdef __IKE_UPDATE_TIMER__
    if (OK > (status = TIMER_createTimer(NULL, &m_ikeTimer)))
        goto exit;

    DIGICERT_log(MOCANA_IKE, LS_INFO, (sbyte *)"Timer created.");
#endif

    if (OK > (status = IKE_cryptoInit()))
        goto exit;

    /* initialize internal tables/structures */
    if (OK > (status = IKE_initSadb()))
        goto exit;

    if(OK > (status = IKE_clearEvents(IKED_STATE_INIT)))
        goto exit;
    IKE_initCertCache();

    /* register dpc functions */
#ifdef __IKE_MULTI_THREADED__
    IKE_dpcRegister((IKE_dpcFunc)IKE_dpcDelSa);

#ifdef __IKE_UPDATE_TIMER__
    IKE_dpcRegister((IKE_dpcFunc)IKE_dpcTimerEvent);
#else
    IKE_dpcRegister((IKE_dpcFunc)IKE_dpcUpdateSa);
#endif
#ifdef __ENABLE_DIGICERT_PFKEY__
    IKE_dpcRegister((IKE_dpcFunc)IKE_dpcStateCallback);
#endif
#ifdef __ENABLE_IKE_XAUTH__
    IKE_dpcRegister((IKE_dpcFunc)IKE_dpcXauthCallback);
#endif
#if defined(__ENABLE_MOBIKE__) && defined(__IKE_MULTI_HOMING__)
    IKE_dpcRegister((IKE_dpcFunc)IKE2_dpcKeyUpdate);
#endif
    IKE_dpcRegister((IKE_dpcFunc)IKE_dpcCertStatusCallback);
#endif

#ifdef __IKE_UPDATE_TIMER__
    /* [v2] regenerate Notify COOKIE secret; every 5 minutes */
    if (OK > (status = IKE_ADD_TIMER_EVT(300000, 0, ((IKESA)NULL),
                                         SecretTimerEvent, "SRT",
                                         m_ikeScrtTimerId, m_ikeScrtTimerHdl)))
        goto exit;
#endif

    /* EAP [v2] */
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    {
        /*status = */EAP_initInstance(&g_ikeEapInstId);
            /* Note: make sure EAP_INSTANCE_ID_START in non-zero! */
    }
#endif

    /* RADIUS [v2] */
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    {
        MSTATUS st;
        RADIUS_Config config = { NULL };
        MOC_IP_ADDRESS addr = MOC_UDP_ANY_ADDR;

        config.funcPtrRadiusInd     = IKE_radIndCallback;
        config.funcPtrBindUDP       = RAD_UDP_connect;
        config.funcPtrSendUDP       = RAD_UDP_send;
        config.funcPtrPollUDP       = RAD_UDP_recv;
        config.funcPtrUnBindUDP     = RAD_UDP_unbind;
/*      config.radiusRetryIntervalMS= RADIUS_RETRY_INTERVAL_MS;
        config.radiusRetryCount     = RADIUS_RETRY_COUNT;
        config.radiusFailoverCount  = RADIUS_FAILOVER_COUNT; */
        config.numInterfaces        = 1; /* FOR NOW */
        config.interfaceArrayPtr    = &addr;

        if (OK > (st = RADIUS_addInstance(&g_ikeRadInstId, &config)))
        {
            DEBUG_ERROR(DEBUG_RADIUS, (sbyte *)"RADIUS_addInstance: Unable to add instance, status = ", st);
        }
        else
        {
            DIGICERT_log((sbyte4)MOCANA_RADIUS, (sbyte4)LS_INFO, (sbyte *)"Added RADIUS instance");
        }
    }
#endif /* RADIUS */

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__) && \
    defined(__ENABLE_DIGICERT_EAP_TLS__)
#endif

#ifndef __DISABLE_DIGICERT_INIT__
    gMocanaAppsRunning++;
#endif

exit:
    if (OK > status)
    {
        /* TODO: clean up */
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_init: failed, status = ");
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)status);
        DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)".");
    }
    else
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_init: completed after");
        DEBUG_UPTIME(DEBUG_IKE_MESSAGES);
        DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)" seconds.");
    }
    return (sbyte4)status;
} /* IKE_init */


/*------------------------------------------------------------------*/

static void
UninitCertChain(ikePeerConfig* config)
{
    if (0 < config->ikeCertChainLen)
        IKE_certUnsetChain(config->ikeCertChain, config->ikeCertChainLen);

    config->ikeCertChainLen = 0;

    /* disable SIG auth [v1] */
    IKE_initPropEx(config, OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG, 0, 0, FALSE);
#ifdef __ENABLE_DIGICERT_ECC__
    IKE_initPropEx(config, OAKLEY_AUTHENTICATION_METHOD, OAKLEY_ECDSA_SIG, 0, 0, FALSE);
    IKE_initPropEx(config, OAKLEY_AUTHENTICATION_METHOD, OAKLEY_ECDSA_256, 0, 0, FALSE);
    IKE_initPropEx(config, OAKLEY_AUTHENTICATION_METHOD, OAKLEY_ECDSA_384, 0, 0, FALSE);
    IKE_initPropEx(config, OAKLEY_AUTHENTICATION_METHOD, OAKLEY_ECDSA_521, 0, 0, FALSE);
#endif

    /* disable 'HOST' SIG auth [v2] */
    IKE2_initAuthMtdEx(config, AUTH_MTD_RSA_SIG, 2/*OUT*/, 0, FALSE);
#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
    IKE2_initAuthMtdEx(config, AUTH_MTD_SIG, 2, 0, FALSE);
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    IKE2_initAuthMtdEx(config, AUTH_MTD_ECDSA_256, 2, 0, FALSE);
    IKE2_initAuthMtdEx(config, AUTH_MTD_ECDSA_384, 2, 0, FALSE);
    IKE2_initAuthMtdEx(config, AUTH_MTD_ECDSA_521, 2, 0, FALSE);
#endif

    return;
} /* UninitCertChain */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_shutdown(void)
{
    MSTATUS status;

    DIGICERT_log((sbyte4)MOCANA_IKE, (sbyte4)LS_INFO, (sbyte *)"IKE server shutting down.");

    IKE_LOCK_W;

#ifdef __IKE_MULTI_THREADED__
    m_dpcFuncNum = 0;
#endif
    IKE_clearEvents(IKED_STATE_SHUTDOWN);
    IKE_flushCertCache();

    IKE_flushSadb();

    IKE_cryptoUninit();

    freePeerConfigList();

    IKE_UNLOCK_W;

    /* [v2] */
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (g_ikeRadInstId)
    {
        RADIUS_deleteInstance(g_ikeRadInstId);
        g_ikeRadInstId = 0;
    }
#endif
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (g_ikeEapInstId)
    {
        EAP_deleteInstance(g_ikeEapInstId);
        g_ikeEapInstId = 0;
    }
#endif

#ifdef __IKE_UPDATE_TIMER__
    if (NULL != m_ikeTimer)
    {
        IKE_DEL_TIMER_EVT(m_ikeScrtTimerId, m_ikeScrtTimerHdl)
        status = TIMER_destroyTimer(m_ikeTimer);
        m_ikeTimer = NULL;
    }
#endif
#if defined(__IKE_UPDATE_TIMER__) || defined( __ENABLE_IKE_FRAGMENTATION__) || defined(__ENABLE_IKE_REDIRECT__)
    status = TIMER_deInitTimer();
#endif

#ifndef __DISABLE_DIGICERT_INIT__
    gMocanaAppsRunning--;
#endif

#ifdef __IKE_MULTI_THREADED__
    status = RTOS_rwLockFree(&g_ikeMtx);
#else
#ifdef __ENABLE_DIGICERT_IKE_RECURSIVE_MUTEX__
    status = RTOS_recursiveMutexFree(&g_ikeMtx);
#else
    status = RTOS_mutexFree(&g_ikeMtx);
#endif
#endif
    g_ikeMtx = NULL;

    return (sbyte4)status;
} /* IKE_shutdown */


/*------------------------------------------------------------------*/

extern ikeSettings *
IKE_ikeSettings(void)
{
    return &m_ikeSettings;
} /* IKE_ikeSettings */


/*------------------------------------------------------------------*/

static MSTATUS
InitCertChain(ikePeerConfig* config, certDescriptor *pCertChain, sbyte4 certChainLen)
{
    MSTATUS status = OK;

    ubyte2 wAuthMtd; /* [v1] */
    ubyte oAuthMtd; /* [v2] */

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    sbyte4 i;
#endif
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx;

    if (OK > (status = IKE_getHwAccelChannel(&hwAccelCtx)))
        goto nocleanup;
#endif

    UninitCertChain(config); /* clean up */

    if (OK > (status = IKE_certSetChain(MOC_HASH(hwAccelCtx)
                                    pCertChain, certChainLen,
                                    config->ikeCertChain, &config->ikeCertChainLen,
                                    config,
                                    TRUE, TRUE)))
    {
        goto exit;
    }

    if (0 >= config->ikeCertChainLen)
        goto exit;

    wAuthMtd = config->ikeCertChain[0].wAuthMtd;
    oAuthMtd = config->ikeCertChain[0].oAuthMtd;

    /* enable SIG auth now */
    IKE_initPropEx(config, OAKLEY_AUTHENTICATION_METHOD, wAuthMtd, 0, 0, TRUE);
    IKE2_initAuthMtdEx(config, oAuthMtd, 2/*OUT*/, 0, TRUE);

#ifdef __ENABLE_DIGICERT_ECC__
    if (OAKLEY_ECDSA_SIG == wAuthMtd)
    {
        /* no standard ECDSA auth method chosen */
        DIGICERT_log((sbyte4)MOCANA_IKE, (sbyte4)LS_WARNING, (sbyte *)"Non-standard ECDSA certificate.");
    }
    else if (OAKLEY_RSA_SIG != wAuthMtd)
    {
        IKE_initPropEx(config, OAKLEY_AUTHENTICATION_METHOD, OAKLEY_ECDSA_SIG, 0, 1, TRUE); /* responder only!!! */
    }
#endif

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    for (i=0; i < config->ikeCertChainLen; i++)
    {
        ubyte *certSubject = config->ikeCertChain[i].poSubject;
        ubyte2 certSubjLen = config->ikeCertChain[i].wSubjLen;

        if (0 == i) /* leaf */
        {
#ifndef __ENABLE_DIGICERT_ECC__
            DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_initServer: Host Certificate is set");
#else
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_initServer: Host Certificate is set (");
            debug_print_ike_p1_attr_v(wAuthMtd, OAKLEY_AUTHENTICATION_METHOD);
            DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)")");
#endif
        }
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"  ");
        debug_print_ike_dn(certSubject, certSubjLen);
        DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)NULL);
    }
#endif

exit:
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    IKE_releaseHwAccelChannel(&hwAccelCtx);

nocleanup:
#endif
    return status;
} /* InitCertChain */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_initCertChain(certDescriptor *pCertChain, sbyte4 certChainLen)
{
    return IKE_initCertChainEx(IKE_globalPeerConfig(), pCertChain, certChainLen);
}


/*------------------------------------------------------------------*/

extern sbyte4
IKE_initCertChainEx(ikePeerConfig* config, certDescriptor *pCertChain, sbyte4 certChainLen)
{
    MSTATUS status;

    if (NULL == config)
        return ERR_IKE_NO_PEER_CONFIG;

    if (NULL == pCertChain) /* remove certificate chain */
         certChainLen = 0;
    else
    if (IKE_CERT_CHAIN_MAX < certChainLen) /* jic */
        certChainLen = IKE_CERT_CHAIN_MAX;

    IKE_LOCK_W;
    status = InitCertChain(config, pCertChain, certChainLen);
    IKE_UNLOCK_W;

    return (sbyte4)status;
} /* IKE_initCertChainEx */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_initTrustAnchor(certDescriptor *pTrustAnchor, sbyte4 trustAnchorNum)
{
    return IKE_initTrustAnchorEx(IKE_globalPeerConfig(), pTrustAnchor, trustAnchorNum);
} /* IKE_initTrustAnchor */

extern sbyte4
IKE_initTrustAnchorEx(ikePeerConfig* config, certDescriptor *pTA, sbyte4 num)
{
    MSTATUS status = OK;
    sbyte4 i;

    IKE_LOCK_W;

    if (NULL == config)
    {
        status = ERR_IKE_NO_PEER_CONFIG;
        goto exit;
    }

    CERT_STORE_releaseStore(&config->ikeCertStore); /* clean up */

    if ((NULL == pTA) || (0 >= num)) /* remove TA's */
    {
        goto exit;
    }

    if (OK > (status = CERT_STORE_createStore(&config->ikeCertStore)))
    {
        goto exit;
    }

    for (i=0; i < num; i++)
    {
        status = CERT_STORE_addTrustPoint(config->ikeCertStore,
                                          pTA[i].pCertificate,
                                          pTA[i].certLength);
        if (OK > status) break;
    }

exit:
    IKE_UNLOCK_W;
    return (sbyte4)status;
} /* IKE_initTrustAnchorEx */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_initServer(certDescriptor *pCertificateDescr,
               sbyte *pStringPSK, sbyte4 stringLen, intBoolean bHex)
{
    sbyte4 status = IKE_initServerEx();
    if (OK == status)
    {
        ikePeerConfig *config = IKE_globalPeerConfig();
        status = IKE_initPeerConfig(config, pCertificateDescr,
                                    pStringPSK, stringLen, bHex);
    }
    return status;
} /* IKE_initServer */

extern sbyte4
IKE_initServerEx(void)
{
    MSTATUS status = OK;

    IKE_LOCK_W;

    /* get host IP address */
    if (NULL == m_ikeSettings.funcPtrIkeGetHostAddr)
    {
        DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_initServerEx: funcPtrIkeGetHostAddr() not set!");
        status = ERR_IKE_CONFIG;
        goto exit;
    }

#ifdef USE_MOC_COOKIE
    /* get cutom cookie */
    if (NULL == m_ikeSettings.funcPtrIkeGetCookie)
    {
        DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_initServerEx: funcPtrIkeGetCookie() not set!");
        status = ERR_IKE_CONFIG;
        goto exit;
    }
#endif

#ifdef __IKE_MULTI_THREADED__
    if (NULL == m_ikeSettings.funcPtrIkeThreadSend)
    {
        DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_initServerEx: funcPtrIkeThreadSend() not set!");
        status = ERR_IKE_CONFIG;
        goto exit;
    }

    if (NULL == m_ikeSettings.funcPtrIkeGetThreadId)
    {
        DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_initServerEx: funcPtrIkeGetThreadId() not set!");
    }
#endif

exit:
    IKE_UNLOCK_W;
    return (sbyte4)status;
} /* IKE_initServerEx */

#ifdef __ENABLE_IKE_PPK_RFC8784__
extern sbyte4 IKE_freePpkPeerConfig(ikePeerConfig* config)
{
    if (!config)
        return ERR_IKE_NO_PEER_CONFIG;

    IKE_LOCK_W;
    CHECK_FREE(config->ppk_id)
    CHECK_FREE(config->ppk_psk)
    config->bUsePpk = FALSE;
    IKE_UNLOCK_W;
    return OK;
}


extern sbyte4 IKE_setPpkPeerConfig(ikePeerConfig* config, sbyte *pPpk,
    sbyte4 ppkLen, sbyte *pPpkId, sbyte4 ppkIdLen, intBoolean bHexPpk)
{
    MSTATUS status = OK;
    sbyte4 psk_len ;

    if (!config)
        return ERR_IKE_NO_PEER_CONFIG;

    if(!pPpk || !pPpkId || !ppkLen || !ppkIdLen)
    {
        return ERR_IKE_CONFIG;
    }

    if((ppkIdLen < IKE_PPK_ID_MIN_LEN) || (ppkIdLen > IKE_PPK_ID_MAX_LEN))
    {
        status = ERR_IKE_CONFIG;
        debug_print_status((sbyte *)__FILE__, __LINE__, status);
        return status;
    }
    psk_len = (bHexPpk ? ((ppkLen/2) + (ppkLen%2)) : ppkLen);
    if((psk_len < IKE_PPK_PSK_MIN_LEN) || (psk_len > IKE_PPK_PSK_MAX_LEN))
    {
        status = ERR_IKE_CONFIG;
        debug_print_status((sbyte *)__FILE__, __LINE__, status);
        return status;
    }
    IKE_LOCK_W;

    CHECK_MALLOC(config->ppk_id, ppkIdLen)
    CHECK_MALLOC(config->ppk_psk, psk_len)
    DIGI_MEMCPY(config->ppk_id, (ubyte*)pPpkId, ppkIdLen);
    if (bHexPpk)
        IKE_scanHexKey(ppkLen, pPpk, psk_len, config->ppk_psk);
    else
        DIGI_MEMCPY(config->ppk_psk, (ubyte*)pPpk, psk_len);
    config->ppkid_len   = ppkIdLen;
    config->ppk_psk_len = psk_len;
    config->bUsePpk = TRUE;

exit:
    IKE_UNLOCK_W;
    if(OK > status)
        IKE_freePpkPeerConfig(config);
    return (sbyte4)status;

}
#endif

extern sbyte4
IKE_initPeerConfig(ikePeerConfig* config, certDescriptor *pCertificateDescr,
                   sbyte *pStringPSK, sbyte4 stringLen, intBoolean bHex)
{
    MSTATUS status = OK;

    if (!config)
        return ERR_IKE_NO_PEER_CONFIG;

    IKE_LOCK_W;

    /* make sure funcPtrIsConfigForPeer is set */
    if ((&m_ikePeerConfig != config) && /* unless it's global */
        (NULL == m_ikeSettings.funcPtrIsConfigForPeer))
    {
        DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_initPeerConfig: funcPtrIsConfigForPeer() not set!");
        status = ERR_IKE_CONFIG;
        goto exit;
    }

    /* pre-shared key */
    if (pStringPSK)
    {
        /* disable PSK auth first */
        IKE_initPropEx(config, OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY, 0, 0, FALSE);
        IKE2_initAuthMtdEx(config, AUTH_MTD_SHARED_KEY, 0, 0, FALSE);

        /* clean up */
        CHECK_FREE(config->ikePSKey)
        config->ikePSKeyLen = 0;

        if (0 < stringLen)
        {
            config->ikePSKeyLen = (bHex ? ((stringLen/2) + (stringLen%2)) : stringLen);
            if (IKE_PSK_MAX < config->ikePSKeyLen)
            {
                DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_initPeerConfig: PSK truncated!");
                config->ikePSKeyLen = IKE_PSK_MAX;
            }
            CHECK_MALLOC(config->ikePSKey, config->ikePSKeyLen)
            if (bHex)
                IKE_scanHexKey(stringLen, pStringPSK, config->ikePSKeyLen, config->ikePSKey);
            else
                DIGI_MEMCPY(config->ikePSKey, (ubyte*)pStringPSK, stringLen);

            /* enable PSK auth now  */
            IKE_initPropEx(config, OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY, 0, 0, TRUE);
            IKE2_initAuthMtdEx(config, AUTH_MTD_SHARED_KEY, 0, 0, TRUE);
        }
    }

    /* certificate */
    if (pCertificateDescr)
    {
        if (OK > (status = InitCertChain(config, pCertificateDescr, 1)))
            goto exit;
    }

    /* Add this into the list of configured peer configurations */
    if (NULL == config->next)
    {
        ikePeerConfig *c;
        for (c = m_ikePeerConfigList;
             c && c != config ;
             c = c->next) ;

        if (NULL == c) /* this peer configuration is not in the list */
        {
            config->next = m_ikePeerConfigList;
            m_ikePeerConfigList = config;
        }
    }

exit:
    IKE_UNLOCK_W;
    return (sbyte4)status;
} /* IKE_initPeerConfig */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_keyConnect(MOC_IP_ADDRESS peerAddr, sbyte4 serverInstance,
               ubyte2 wPeerPort, intBoolean bUseNattPort,
               ubyte4 *pdwIkeId,
               intBoolean bForce,
               intBoolean bInitCont,
               intBoolean bGdoiClient,
               struct sainfo *pSAInfo)
{
    MSTATUS status;

    struct ike_event evt = { 0 };
#ifdef __ENABLE_DIGICERT_IPV6__
    ubyte4 dwIPEnd[4] = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff };
#endif
    evt.type = IKE_KEY_TYPE_SAINIT;
    if (NULL == m_ikeSettings.funcPtrIkeGetHostAddr) /* jic */
    {
        status = ERR_IKE_CONFIG;
        goto exit;
    }

    if (OK > (status = m_ikeSettings.funcPtrIkeGetHostAddr(&evt.dwSrcAddr,
                                                           serverInstance)))
        goto exit;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (evt.dwSrcAddr.family != peerAddr->family)
    {
        status = ERR_IKE;
        goto exit;
    }
#endif

    COPY_MOC_IPADDR(evt.dwDestAddr, peerAddr);

#ifdef __ENABLE_IPSEC_NAT_T__
    evt.wUdpEncPort = wPeerPort;
#else
    MOC_UNUSED(wPeerPort);
#endif

    /* [v2] set traffic selectors !!! */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    evt.oMode = IPSEC_MODE_TUNNEL;

    TEST_MOC_IPADDR6(peerAddr,
    {
        SET_MOC_IPADDR6(evt.dwSrcIPEnd, dwIPEnd);
        evt.dwSrcIP.family = AF_INET6;
    })
    {
        SET_MOC_IPADDR4(evt.dwSrcIP, 0);
        SET_MOC_IPADDR4(evt.dwSrcIPEnd, 0xffffffff);
    }

    evt.dwDestIP = evt.dwSrcIP;
    evt.dwDestIPEnd = evt.dwSrcIPEnd;
#endif

    /* [v2] set proposals - FOR NOW */
#ifndef __ENABLE_DIGICERT_PFKEY__
    evt.oSaLen = 1;
    if (pSAInfo)
    {
        evt.pxSa[0].oSecuProto = pSAInfo->oSecuProto;
        evt.pxSa[0].oAuthAlgo = pSAInfo->oAuthAlgo;
        evt.pxSa[0].oEncrAlgo = pSAInfo->oEncrAlgo;
        evt.pxSa[0].oEncrKeyLen = pSAInfo->oEncrKeyLen;
        evt.pxSa[0].aeadTag = pSAInfo->aeadTag;
    }
    else
        evt.pxSa[0].oSecuProto = IPSEC_PROTO_ESP_AUTH;
#else
    evt.oCombLen = 1;

    evt.pxSa[0].oAuthAlgo = IPSEC_AUTHALG_MD5;
    evt.pxSa[0].oEncrAlgo = IPSEC_ENCALG_3DES;
    evt.pxSa[0].oEncrKeyLen = 24;
#endif

    /* connect only if no IKE_SA is applicable */
    if (!bForce) evt.type |= IKE_KEY_MOD_SAINIT;

    if (bInitCont) /* will send INITIAL_CONTACT */
        evt.type |= IKE_KEY_MOD_INITC;

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    if (bGdoiClient)
        evt.type |= IKE_KEY_MOD_GDOI;
#else
    MOC_UNUSED(bGdoiClient);
#endif

    if (OK > (status = (MSTATUS)
                       IKE_evtRecv(&evt, serverInstance, bUseNattPort)))
        goto exit;

exit:
    if (NULL != pdwIkeId)
        *pdwIkeId = evt.dwSeqNo; /* !!! */

    return (sbyte4)status;
} /* IKE_keyConnect */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IKE_REDIRECT__

typedef struct redirect_event
{
    struct ike_event event;
    sbyte4 serverInstance;
    intBoolean bUseNattPort;

} *REDIRECT_EVENT;

static void
IKE_redirectThread(void *data)
{
    REDIRECT_EVENT cb = (REDIRECT_EVENT)data;
    IKEEVT pxEvt = &cb->event;
    sbyte4 serverInstance = cb->serverInstance;
    intBoolean bUseNattPort = cb->bUseNattPort;

    sbyte4 status;
    if (0 > (status = IKE_evtRecv(pxEvt, serverInstance, bUseNattPort)))
    {
        DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_redirect() failed; status = ", status);
    }

    FREE(data);
}


/*------------------------------------------------------------------*/

extern sbyte4
IKE_redirect(IKE_context ctx)
{
    MSTATUS status;

#ifdef __ENABLE_IPSEC_NAT_T__
    intBoolean bUseNattPort = ctx->bUseNattPort;
#else
    intBoolean bUseNattPort = 0;
#endif
#ifdef __IKE_MULTI_HOMING__
    sbyte4 serverInstance = ctx->serverInstance;
#else
    sbyte4 serverInstance = 0;
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
    ubyte4 dwIPEnd[4] = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff };
#endif
    REDIRECT_EVENT pxEvtRedirect = NULL;
    IKEEVT pxEvt;

    RTOS_THREAD tid;

    if (NULL == m_ikeSettings.funcPtrIkeGetHostAddr) /* jic */
    {
        status = ERR_IKE_CONFIG;
        goto exit;
    }

    if (NULL == (pxEvtRedirect = (REDIRECT_EVENT)
                                 MALLOC(sizeof(struct redirect_event))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)pxEvtRedirect, 0, sizeof(struct redirect_event));
    pxEvtRedirect->serverInstance = serverInstance;
    pxEvtRedirect->bUseNattPort = bUseNattPort;

    pxEvt = &pxEvtRedirect->event;
    pxEvt->type = IKE_KEY_TYPE_SAINIT;

    if (OK > (status = m_ikeSettings.funcPtrIkeGetHostAddr(&pxEvt->dwSrcAddr,
                                                           serverInstance)))
        goto exit;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (pxEvt->dwSrcAddr.family != ctx->peerAddr->family)
    {
        status = ERR_IKE;
        goto exit;
    }
#endif

    COPY_MOC_IPADDR(pxEvt->dwDestAddr, ctx->peerAddr);

#ifdef __ENABLE_IPSEC_NAT_T__
    pxEvt->wUdpEncPort = ctx->wPeerPort;
#endif

    /* [v2] set traffic selectors !!! */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    pxEvt->oMode = IPSEC_MODE_TUNNEL;

    TEST_MOC_IPADDR6(ctx->peerAddr,
    {
        SET_MOC_IPADDR6(pxEvt->dwSrcIPEnd, dwIPEnd);
        pxEvt->dwSrcIP.family = AF_INET6;
    })
    {
        SET_MOC_IPADDR4(pxEvt->dwSrcIP, 0);
        SET_MOC_IPADDR4(pxEvt->dwSrcIPEnd, 0xffffffff);
    }

    pxEvt->dwDestIP = pxEvt->dwSrcIP;
    pxEvt->dwDestIPEnd = pxEvt->dwSrcIPEnd;
#endif

    /* [v2] set proposals - FOR NOW */
#ifndef __ENABLE_DIGICERT_PFKEY__
    pxEvt->oSaLen = 1;
#else
    pxEvt->oCombLen = 1;

    pxEvt->pxSa[0].oAuthAlgo = IPSEC_AUTHALG_MD5;
    pxEvt->pxSa[0].oEncrAlgo = IPSEC_ENCALG_3DES;
    pxEvt->pxSa[0].oEncrKeyLen = 24;
#endif
    pxEvt->pxSa[0].oSecuProto = IPSEC_PROTO_ESP_AUTH;

    pxEvt->type |= IKE_KEY_MOD_REDIRECTED;
    pxEvt->dwOldPeerIP = ctx->oldPeerAddr;

    /* connect only if no IKE_SA is applicable */
    pxEvt->type |= IKE_KEY_MOD_SAINIT;

    if (OK > RTOS_createThread(IKE_redirectThread, (void *)pxEvtRedirect, IKE_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: IKE_redirectThread failed.");
        goto exit;
    }

    pxEvtRedirect = NULL;

exit:
    if (pxEvtRedirect) FREE(pxEvtRedirect);
    return (sbyte4)status;
} /* IKE_redirect */

#endif  /* __ENABLE_IKE_REDIRECT__ */


/*------------------------------------------------------------------*/

/* RADIUS */
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

static sbyte4
RAD_UDP_connect(MOC_IP_ADDRESS srcAddress,
                sbyte *serverIPAdress, ubyte2 serverPort,
                void **ppUDPCookie)
{
    MOC_IP_ADDRESS_S dstAddress;
    MSTATUS status;

    if (OK > (status = UDP_getAddrOfHost(serverIPAdress, &dstAddress)))
        goto exit;

    status = UDP_connect(ppUDPCookie, srcAddress, MOC_UDP_ANY_PORT,
                         REF_MOC_IPADDR(dstAddress), serverPort, 1);

exit:
    return (sbyte4)status;
} /* RAD_UDP_connect */

static sbyte4
RAD_UDP_send(void *pUDPCookie, ubyte *pData, ubyte4 dataLength)
{
    return (sbyte4) UDP_send(pUDPCookie, pData, dataLength);
} /* RAD_UDP_send */

static sbyte4
RAD_UDP_recv(void *pUDPCookie, ubyte *pData, ubyte4 dataLength, ubyte4 *pRetDataLength)
{
    return (sbyte4) UDP_recv(pUDPCookie, pData, dataLength, pRetDataLength);
} /* RAD_UDP_recv */

static sbyte4
RAD_UDP_unbind(void **ppUDPCookie)
{
    return (sbyte4) UDP_unbind(ppUDPCookie);
} /* RAD_UDP_unbind */

#endif /* RADIUS */


/*------------------------------------------------------------------*/

#ifdef __IKE_TRACK__

static MSTATUS
CheckInfoXchg(void *cb, ubyte oType, const ubyte *pPayload, intBoolean *stop)
{
    MSTATUS status = OK;

    IKE_TRACK pxTrack = (IKE_TRACK)cb;
    enum ike_status_ex1 *st = (enum ike_status_ex1 *) pxTrack->userData;

    struct ikeNotifyHdr *pxNotifyHdr;
    struct ikeDelHdr *pxDelHdr;

    *stop = FALSE;

    switch (oType)
    {
    case ISAKMP_NEXT_N :
        *stop = TRUE;
        pxNotifyHdr = (struct ikeNotifyHdr *)pPayload;
        switch (pxNotifyHdr->oProtoId)
        {
        case 0 :
        case PROTO_ISAKMP :
            *st = IKMP_NOTIFY;
            break;
        case PROTO_IPSEC_AH :
        case PROTO_IPSEC_ESP :
            *st = PROTOCOL_NOTIFY;
            break;
        default : /* jic */
            *stop = FALSE;
            break;
        }
        break;

    case ISAKMP_NEXT_D :
        *stop = TRUE;
        pxDelHdr = (struct ikeDelHdr *)pPayload;
        switch (pxDelHdr->oProtoId)
        {
        case PROTO_ISAKMP :
            *st = IKMP_DELETE;
            break;
        case PROTO_IPSEC_AH :
        case PROTO_IPSEC_ESP :
            *st = PROTOCOL_DELETE;
            break;
        default : /* jic */
            *stop = FALSE;
            break;
        }
        break;

    default :
        break;
    }

    return status;
} /* CheckInfoXchg */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_msgRecvEx1(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
               ubyte *pBuffer, ubyte4 dwBufferSize,
               sbyte4 serverInstance,
               intBoolean bUseNattPort,
               enum ike_status_ex1 *ret)
{
    sbyte4 status;
    enum ike_status_ex1 st = UNSPECIFIED_STATUS;

    struct ike_track track = { NULL };
    struct ikeHdr *pxHdr = NULL;
    struct ikesa *pxSa = NULL;
    struct p2xg *pxXg = NULL;
    byteBoolean  bReleaseLock = FALSE;

    ubyte oState;

#ifdef __IKE_MULTI_THREADED__
    if (NULL == (track.pBuffer = (ubyte *) MALLOC(TK_BUF_SIZE)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
#endif

    status = IKE_msgRecv(peerAddr, wPeerPort,
                         pBuffer, dwBufferSize,
                         serverInstance,
                         bUseNattPort,
                         &track);
    IKE_LOCK_R;
    bReleaseLock = TRUE;

    pxHdr = track.pxHdr;
    pxSa = track.pxSa;
    pxXg = track.pxXg;
    if (pxSa && !IS_VALID(pxSa))
    {
        if(track.bMsgOK && (OK == status) && (pxSa->flags & IKE_SA_FLAG_DELETED))
        {
            st = IKMP_DELETE;
        }
        else
        {
            status = ERR_IKE_BAD_SA;
        }
        goto exit;
    }

    if (track.bMsgOK)
    {
        if (0 > status)
        {
            // internal error during state-change
            goto exit;
        }

        if (pxXg) /* phase 2, non-informational */
        {
            oState = pxXg->oState;
            if (IS_P2_FINAL_STATE(oState))
            {
                st = PROTOCOL_SA_NEGOTIATED;
            }
            else if (IS_QUICK_MODE_STATE(oState))
            {
                st = PROTOCOL_CONTINUE;
            }
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
            else /* IKECFG */
            {
                if ((STATE_CFG_I == oState) ||
                    (STATE_CFG_R == oState)) // XXX server only - FOR NOW */
                {
                    st = CONFIG_MODE_DONE;
                }
                else
                {
                    st = CONFIG_MODE_CONTINUE;
                }
            }
#endif
        }
        else if (ISAKMP_XCHG_INFO == pxHdr->oExchange) /* informational */
        {
            track.userData = (void *) &st;
            IKE_travMsg((ubyte *)pxHdr, TK_BUF_SIZE, (void *)&track,
                        CheckInfoXchg);
        }
        else /* phase 1 */
        {
            oState = (pxSa)?pxSa->oState:0;
            if (IS_P1_FINAL_STATE(oState))
            {
                st = (IKE_SA_FLAG_INIT_C & pxSa->flags)
                   ? IKMP_SA_NEGOTIATED_NOTIFY
                   : IKMP_SA_NEGOTIATED;
            }
            else
            {
                st = IKMP_CONTINUE;
            }
        }

        goto exit; /* !!! */
    }

    /* check re-transmission */
    if (pxXg)
    {
        oState = pxXg->oState;

        if (IS_VALID_XCHG(pxXg) &&
            (STATUS_IKE_PENDING == status))
        {
            st = RETRANSMIT_IGNORE;
            goto exit;
        }

        switch (pxHdr->oExchange)
        {
        case ISAKMP_XCHG_QUICK :
            if (IS_P2_FINAL_STATE(oState))
            {
                st = RETRANSMIT_IGNORE;
                goto exit;
            }
            break;
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
        case ISAKMP_XCHG_CFG :
            if (NULL == STATE_IN_FUNC(oState))
            {
                st = RETRANSMIT_IGNORE;
                goto exit;
            }
            break;
#endif
        default :
            break;
        }
    }
    else if (pxSa)
    {
        oState = pxSa->oState;

        switch (pxHdr->oExchange)
        {
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
        case ISAKMP_XCHG_AGGR :
#endif
        case ISAKMP_XCHG_IDPROT :
            if (IS_VALID(pxSa) &&
                (IS_P1_FINAL_STATE(oState)      ||
                 IKE_isEmptyCky(pxHdr->poCky_R) ||
                 (STATUS_IKE_PENDING == status) ||
                 (ERR_IKE_BAD_FLAGS == status)
                 ))
            {
                st = RETRANSMIT_IGNORE;
                goto exit;
            }
            break;
#ifdef __ENABLE_IKE_FRAGMENTATION__
        case ISAKMP_XCHG_QUICK :
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
        case ISAKMP_XCHG_CFG :
#endif
            if (IS_VALID(pxSa) && (STATUS_IKE_PENDING == status))
            {
                st = RETRANSMIT_IGNORE;
                goto exit;
            }
#endif /* __ENABLE_IKE_FRAGMENTATION__ */
        default :
            break;
        }
    }

    /* message error */
    if (pxHdr)
    {
#ifdef __ENABLE_IKE_FRAGMENTATION__
        if ((sbyte4)ERR_IKE_REASSEMBLY_INCOMPLETE == status)
        {
            switch (pxHdr->oExchange)
            {
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
            case ISAKMP_XCHG_AGGR :
#endif
            case ISAKMP_XCHG_IDPROT :
                st = IKMP_CONTINUE;
                goto exit;
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
            case ISAKMP_XCHG_CFG :
                st = CONFIG_MODE_CONTINUE;
                goto exit;
#endif
            case ISAKMP_XCHG_QUICK :
                st = PROTOCOL_CONTINUE;
                goto exit;
            default :
                break;
            }
        }
#endif /* __ENABLE_IKE_FRAGMENTATION__ */

        switch (pxHdr->oExchange)
        {
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
        case ISAKMP_XCHG_AGGR :
#endif
        case ISAKMP_XCHG_IDPROT :
            st = IKMP_ERROR;
            break;
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
        case ISAKMP_XCHG_CFG :
            st = CONFIG_MODE_ERROR;
            break;
#endif
        case ISAKMP_XCHG_INFO :
            break;
        case ISAKMP_XCHG_QUICK :
            st = PROTOCOL_ERROR;
            break;
        default :
            break;
        }
    }

exit:
#ifdef __IKE_MULTI_THREADED__
    if (track.pBuffer) FREE(track.pBuffer);
#endif
    //DB_PRINT("%s: status_ex1 = %d\n", __FUNCTION__, st);
    if (ret) *ret = st;

    if(bReleaseLock == TRUE)
        IKE_UNLOCK_R;

    return status;
} /* IKE_msgRecvEx1 */

#endif /* #ifdef __IKE_TRACK__ */


#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

