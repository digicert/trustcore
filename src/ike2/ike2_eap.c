/**
 * @file  ike2_eap.c
 * @brief IKEv2 IKEv2 EAP Integration
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__ or \c \__ENABLE_DIGICERT_EAP_PEER__
 *     +   \c \__DISABLE_DIGICERT_IKE_EAP__ must not be defined.
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

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../crypto/md5.h"
#include "../crypto/dh.h"
#include "../crypto/rsa.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/crypto.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"

#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsecconf.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike/ike_state.h"
#include "../ike/ike_utils.h"
#include "../ike2/ike2_eap.h"


/*------------------------------------------------------------------*/

/* authenticator */
#ifdef __ENABLE_DIGICERT_EAP_AUTH__
#define EAP_NO_AUTH_SUITE NULL,

#ifdef __ENABLE_DIGICERT_EAP_MD5__
extern const IKE_eapSuiteInfo g_ikeEapMD5authSuite;
#define EAP_MD5_AUTH_SUITE &g_ikeEapMD5authSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_GTC__
extern const IKE_eapSuiteInfo g_ikeEapGTCauthSuite;
#define EAP_GTC_AUTH_SUITE &g_ikeEapGTCauthSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_MSCHAPv2__
extern const IKE_eapSuiteInfo g_ikeEapMSCHAPv2authSuite;
#define EAP_MSCHAPv2_AUTH_SUITE &g_ikeEapMSCHAPv2authSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_SIM__
extern const IKE_eapSuiteInfo g_ikeEapSIMauthSuite;
#define EAP_SIM_AUTH_SUITE &g_ikeEapSIMauthSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_SRP__
extern const IKE_eapSuiteInfo g_ikeEapSRPauthSuite;
#define EAP_SRP_AUTH_SUITE &g_ikeEapSRPauthSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_PSK__
extern const IKE_eapSuiteInfo g_ikeEapPSKauthSuite;
#define EAP_PSK_AUTH_SUITE &g_ikeEapPSKauthSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_TLS__
extern const IKE_eapSuiteInfo g_ikeEapTLSauthSuite;
#define EAP_TLS_AUTH_SUITE &g_ikeEapTLSauthSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_LEAP__
extern const IKE_eapSuiteInfo g_ikeEapLEAPauthSuite;
#define EAP_LEAP_AUTH_SUITE &g_ikeEapLEAPauthSuite,
#endif

#if defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
extern const IKE_eapSuiteInfo g_ikeEapRADIUSpassthruSuite;
#define EAP_RADIUS_PASSTHRU_SUITE &g_ikeEapRADIUSpassthruSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_PERP__
extern const IKE_eapSuiteInfo g_ikeEapPERPauthSuite;
#define EAP_PERP_AUTH_SUITE &g_ikeEapPERPauthSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
extern const IKE_eapSuiteInfo g_ikeEapTTLSauthSuite;
#define EAP_TTLS_AUTH_SUITE &g_ikeEapTTLSauthSuite,
#endif

#else
#define EAP_NO_AUTH_SUITE
#define EAP_MD5_AUTH_SUITE
#define EAP_MSCHAPv2_AUTH_SUITE
#define EAP_SIM_AUTH_SUITE
#define EAP_TLS_AUTH_SUITE
#define EAP_SRP_AUTH_SUITE
#define EAP_PSK_AUTH_SUITE
#define EAP_LEAP_AUTH_SUITE
#define EAP_GTC_AUTH_SUITE
#define EAP_RADIUS_PASSTHRU_SUITE
#define EAP_PERP_AUTH_SUITE
#define EAP_TTLS_AUTH_SUITE
#endif /* __ENABLE_DIGICERT_EAP_AUTH__ */


/*------------------------------------------------------------------*/

/* supplicant */
#ifdef __ENABLE_DIGICERT_EAP_PEER__
#define EAP_NO_PEER_SUITE NULL,

#ifdef __ENABLE_DIGICERT_EAP_MD5__
extern const IKE_eapSuiteInfo g_ikeEapMD5peerSuite;
#define EAP_MD5_PEER_SUITE &g_ikeEapMD5peerSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_MSCHAPv2__
extern const IKE_eapSuiteInfo g_ikeEapMSCHAPv2peerSuite;
#define EAP_MSCHAPv2_PEER_SUITE &g_ikeEapMSCHAPv2peerSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_SIM__
extern const IKE_eapSuiteInfo g_ikeEapSIMpeerSuite;
#define EAP_SIM_PEER_SUITE &g_ikeEapSIMpeerSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_TLS__
extern const IKE_eapSuiteInfo g_ikeEapTLSpeerSuite;
#define EAP_TLS_PEER_SUITE &g_ikeEapTLSpeerSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_SRP__
extern const IKE_eapSuiteInfo g_ikeEapSRPpeerSuite;
#define EAP_SRP_PEER_SUITE &g_ikeEapSRPpeerSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_PSK__
extern const IKE_eapSuiteInfo g_ikeEapPSKpeerSuite;
#define EAP_PSK_PEER_SUITE &g_ikeEapPSKpeerSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_LEAP__
extern const IKE_eapSuiteInfo g_ikeEapLEAPpeerSuite;
#define EAP_LEAP_PEER_SUITE &g_ikeEapLEAPpeerSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_GTC__
extern const IKE_eapSuiteInfo g_ikeEapGTCpeerSuite;
#define EAP_GTC_PEER_SUITE &g_ikeEapGTCpeerSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_PERP__
extern const IKE_eapSuiteInfo g_ikeEapPERPpeerSuite;
#define EAP_PERP_PEER_SUITE &g_ikeEapPERPpeerSuite,
#endif

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
extern const IKE_eapSuiteInfo g_ikeEapTTLSpeerSuite;
#define EAP_TTLS_PEER_SUITE &g_ikeEapTTLSpeerSuite,
#endif

extern const IKE_eapSuiteInfo g_ikeEapANYpeerSuite;
#define EAP_ANY_PEER_SUITE &g_ikeEapANYpeerSuite,

#else
#define EAP_NO_PEER_SUITE
#define EAP_MD5_PEER_SUITE
#define EAP_MSCHAPv2_PEER_SUITE
#define EAP_SIM_PEER_SUITE
#define EAP_TLS_PEER_SUITE
#define EAP_SRP_PEER_SUITE
#define EAP_PSK_PEER_SUITE
#define EAP_LEAP_PEER_SUITE
#define EAP_GTC_PEER_SUITE
#define EAP_PERP_PEER_SUITE
#define EAP_TTLS_PEER_SUITE
#define EAP_ANY_PEER_SUITE
#endif /* __ENABLE_DIGICERT_EAP_PEER__ */


/*------------------------------------------------------------------*/

static struct mEapSuite
{
#ifdef __ENABLE_DIGICERT_EAP_AUTH__
    const IKE_eapSuiteInfo *pAuthSuite;
#endif
#ifdef __ENABLE_DIGICERT_EAP_PEER__
    const IKE_eapSuiteInfo *pPeerSuite;
#endif
    IKE_EAP_PROTO_T proto_t;

} mEapSuites[] =
{
#ifdef __ENABLE_DIGICERT_EAP_MD5__
    { EAP_MD5_AUTH_SUITE        EAP_MD5_PEER_SUITE      EAP_PROTO_MD5 },
#endif
#ifdef __ENABLE_DIGICERT_EAP_MSCHAPv2__
    { EAP_MSCHAPv2_AUTH_SUITE   EAP_MSCHAPv2_PEER_SUITE EAP_PROTO_MSCHAPv2 },
#endif
#ifdef __ENABLE_DIGICERT_EAP_SIM__
    { EAP_SIM_AUTH_SUITE        EAP_SIM_PEER_SUITE      EAP_PROTO_SIM },

    { EAP_SIM_AUTH_SUITE        EAP_SIM_PEER_SUITE      EAP_PROTO_AKA },
#endif
#ifdef __ENABLE_DIGICERT_EAP_SRP__
    { EAP_SRP_AUTH_SUITE        EAP_SRP_PEER_SUITE      EAP_PROTO_SRP },
#endif
#ifdef __ENABLE_DIGICERT_EAP_TLS__
    { EAP_TLS_AUTH_SUITE        EAP_TLS_PEER_SUITE      EAP_PROTO_TLS },
#endif
#ifdef __ENABLE_DIGICERT_EAP_PSK__
    { EAP_PSK_AUTH_SUITE        EAP_PSK_PEER_SUITE      EAP_PROTO_PSK },
#endif
#ifdef __ENABLE_DIGICERT_EAP_LEAP__
    { EAP_LEAP_AUTH_SUITE       EAP_LEAP_PEER_SUITE     EAP_PROTO_LEAP },
#endif
#ifdef __ENABLE_DIGICERT_EAP_GTC__
    { EAP_GTC_AUTH_SUITE        EAP_GTC_PEER_SUITE      EAP_PROTO_GTC },
#endif
#ifdef __ENABLE_DIGICERT_EAP_PERP__
    { EAP_PERP_AUTH_SUITE       EAP_PERP_PEER_SUITE     EAP_PROTO_PERP },
#endif
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    { EAP_TTLS_AUTH_SUITE       EAP_TTLS_PEER_SUITE     EAP_PROTO_TTLS },
#endif
#if defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
    { EAP_RADIUS_PASSTHRU_SUITE EAP_NO_PEER_SUITE       EAP_PROTO_RADIUS },
#endif
    { EAP_NO_AUTH_SUITE         EAP_ANY_PEER_SUITE      EAP_PROTO_ANY },
    { EAP_NO_AUTH_SUITE         EAP_NO_PEER_SUITE       EAP_PROTO_NONE },
};

#define NUM_IKE_EAP_SUITES (sizeof(mEapSuites)/sizeof(struct mEapSuite))


/*------------------------------------------------------------------*/

ubyte4 g_ikeEapInstId = 0; /* EAP instance */


/*------------------------------------------------------------------*/

#define _I 0
#define _R 1

#define _IN  1
#define _OUT 2

#define DBG_ERRCODE(_s) debug_print_status((sbyte *)__FILE__, __LINE__, (sbyte4)_s);
#define DBG_STATUS      DBG_ERRCODE(status)
#define DBG_EXIT        { DBG_STATUS goto exit; }

#define CHECK_MALLOC(p, s) \
    if (NULL == ((p) = (ubyte *) MALLOC(s))) \
    { \
        status = ERR_MEM_ALLOC_FAIL; \
        DBG_EXIT \
    } \

#define CHECK_FREE(p) if (NULL != (p)) { FREE(p); (p) = NULL; }


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_eapSuite(IKE_EAP_PROTO_T proto_t, intBoolean bInitiator,
             const IKE_eapSuiteInfo **ppEapSuite)
{
    MSTATUS status = OK;

    ubyte4 i;
    for (i=0; i < NUM_IKE_EAP_SUITES; i++)
    {
        if (proto_t == mEapSuites[i].proto_t)
        {
            const IKE_eapSuiteInfo *s = NULL;
#ifdef __ENABLE_DIGICERT_EAP_AUTH__
            if (!bInitiator) /* authenticator */
                s = mEapSuites[i].pAuthSuite;
#endif
#ifdef __ENABLE_DIGICERT_EAP_PEER__
            if (bInitiator) /* supplicant */
                s = mEapSuites[i].pPeerSuite;
#endif
            *ppEapSuite = s;
            goto exit;
        }
    }

    status = ERR_EAP;

exit:
    return status;
} /* IKE_eapSuite */


/*------------------------------------------------------------------*/

extern const IKE_eapSuiteInfo *
IKE_getEapSuite(intBoolean bInitiator, sbyte4 i, IKE_EAP_PROTO_T *proto_t)
{
    const IKE_eapSuiteInfo *pEapSuite = NULL;

    if (proto_t) *proto_t = (IKE_EAP_PROTO_T)0;
    if ((0 > i) || (i >= (sbyte4) NUM_IKE_EAP_SUITES)) goto exit;

    if (proto_t) *proto_t = mEapSuites[i].proto_t;

#ifdef __ENABLE_DIGICERT_EAP_AUTH__
    if (!bInitiator) /* authenticator */
        pEapSuite = mEapSuites[i].pAuthSuite;
#endif
#ifdef __ENABLE_DIGICERT_EAP_PEER__
    if (bInitiator) /* supplicant */
        pEapSuite = mEapSuites[i].pPeerSuite;
#endif

exit:
    return pEapSuite;
} /* IKE_getEapSuite */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_eapProcess(struct eapMsgHdr *pxMsg,
               struct ikesa *pxSa, struct ike2xg *pxXg)
{
    MSTATUS status = OK;

    IKE2EAP pxEap = &pxSa->u.v2.eapState;
    intBoolean bInitiator = IS_INITIATOR(pxSa);

    if (!g_ikeEapInstId)
    {
        status = ERR_EAP;
        DBG_EXIT
    }

    pxEap->pxSa = pxSa;
    pxEap->pxXg = pxXg;

    if (pxEap->pSession)
    {
        CHECK_FREE(pxEap->pxMsg) /* !!! */
    }
    else
    {
        sbyte4 proto_t=0;
        const IKE_eapSuiteInfo *pEapSuite;
        const eapMethodDef_t *pEapMethodDef;
        eapSessionConfig_t sessionConfig;

        /* get configured EAP protocol */
#ifdef CUSTOM_IKE_GET_EAP_PROTO
        ubyte2 wIdLen=0;
        ubyte *poId = NULL;
        sbyte4 id_t=0;

        struct ikeIdHdr *pxIdHdr = pxSa->pxID[bInitiator ? _R : _I];
        if (pxIdHdr) /* jic */
        {
            wIdLen = GET_NTOHS(pxIdHdr->wLength) - SIZEOF_IKE_ID_HDR;
            poId = ((ubyte *)pxIdHdr) + SIZEOF_IKE_ID_HDR;
            id_t = pxIdHdr->oType;
        }

        status = CUSTOM_IKE_GET_EAP_PROTO(&proto_t,
                            poId, wIdLen, id_t,
                            REF_MOC_IPADDR(pxSa->dwPeerAddr),
                            (bInitiator ? _IN : _OUT), bInitiator
                            MOC_MTHM_REQ_VALUE(pxSa->serverInstance));

        if (STATUS_IKE_CUSTOM_CONTINUE != status)
        {
            if (OK > status) DBG_EXIT
        }
        else
#endif /* CUSTOM_IKE_GET_EAP_PROTO */
        {
#ifdef __ENABLE_DIGICERT_EAP_AUTH__
            if (!bInitiator) /* authenticator */
                proto_t = pxSa->ikePeerConfig->eapProtoAuth;
#endif
#ifdef __ENABLE_DIGICERT_EAP_PEER__
            if (bInitiator) /* supplicant */
                proto_t = pxSa->ikePeerConfig->eapProtoPeer;
#endif
        }

        /* get EAP suite */
        if (OK > (status = IKE_eapSuite((IKE_EAP_PROTO_T)proto_t, bInitiator,
                                        &pEapSuite)))
            DBG_EXIT

        if (NULL == pEapSuite) /* not found */
        {
            status = ERR_EAP_INVALID_METHOD_TYPE;
            DBG_EXIT
        }

#ifdef __ENABLE_IKE_EAP_ONLY__
        /* preliminary check if the EAP method is safe w/ EAP-Only */
        if ((IKE_SA_FLAG_EAP_ONLY & pxSa->flags) &&
            (FALSE == pEapSuite->bEapOnlyOk))
        {
            if (bInitiator) /* supplicant */
            {
#ifdef __ENABLE_DIGICERT_EAP_PEER__
                if (EAP_PROTO_ANY != (IKE_EAP_PROTO_T)proto_t)
                {
                    status = ERR_IKE_EAP_ONLY;
                    DBG_EXIT
                }
#endif
            }
#ifdef __ENABLE_DIGICERT_EAP_AUTH__
            else /* authenticator */
            {
                if (EAP_PROTO_RADIUS != (IKE_EAP_PROTO_T)proto_t)
                    pxSa->flags &= ~(IKE_SA_FLAG_EAP_ONLY);
            }
#endif
        }
#endif
        pEapMethodDef = pEapSuite->pMethodDef;
        if (!pEapMethodDef) /* jic */
        {
            status = ERR_EAP;
            DBG_EXIT
        }

        pxEap->proto = proto_t;

        if (pEapSuite->initFunc &&
            (OK > (status = pEapSuite->initFunc(pxEap))))
            DBG_EXIT

        pxEap->pEapSuite = pEapSuite;

#ifdef __ENABLE_DIGICERT_EAP_PEER__
        pxEap->identity = (ubyte *) pxSa->ikePeerConfig->eapIdentity;
        if (pxEap->identity)
            pxEap->identityLen = DIGI_STRLEN((const sbyte *)pxEap->identity);
#endif
        /* create a new EAP session */
        sessionConfig.eap_mtu = 1020;
        sessionConfig.eap_ul_timeout = 0;/*60*/
        sessionConfig.eap_retrans_timeout = 0;/*5*/
        sessionConfig.eap_max_retrans = 0;/*5*/
        sessionConfig.sessionType = pEapSuite->sessionType;

        if (OK > (status = EAP_sessionCreate((ubyte *)pxEap, g_ikeEapInstId,
                                             *pEapMethodDef,
                                             sessionConfig,
                                             &pxEap->pSession)))
            DBG_EXIT

        if (OK > (status = EAP_sessionEnable(pxEap->pSession, g_ikeEapInstId)))
            DBG_EXIT

#ifdef __ENABLE_DIGICERT_EAP_AUTH__
        if (!bInitiator) /* authenticator */
        {
            ubyte *eap_data = NULL;
            ubyte2 eap_data_len = 0;
            struct eapMsgHdr eapHdr;

            if (EAP_SESSION_TYPE_PASSTHROUGH == pEapSuite->sessionType)
            {
                eap_data = (ubyte *) &eapHdr;
                eap_data_len = SIZEOF_EAP_MSG_HDR + 1;

                eapHdr.oCode = EAP_CODE_REQUEST;
                eapHdr.oIdentifier = 0;
                SET_HTONS(eapHdr.wLength, eap_data_len);
                eapHdr.oType = EAP_TYPE_IDENTITY;
            }

            /* send Identity Request */
            if (OK > (status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                              EAP_TYPE_IDENTITY, EAP_CODE_REQUEST,
                                              EAP_METHOD_DECISION_NONE,
                                              EAP_METHOD_STATE_CONT,
                                              eap_data, eap_data_len)))
                DBG_STATUS
            goto exit;
        }
#endif
    }

    if(NULL == pxMsg)
    {
        DBG_EXIT
    }
    /* call llreceive fn */
    if (OK > (status = EAP_llReceivePacket(pxEap->pSession, g_ikeEapInstId,
                                           (ubyte *)pxMsg, GET_NTOHS(pxMsg->wLength),
                                           NULL)))
        DBG_EXIT

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__)
    if (!bInitiator && /* authenticator */
        (NULL == pxEap->pxMsg) &&
        ((EAP_PROTO_RADIUS == pxEap->proto) ||
         (EAP_PROTO_TTLS == pxEap->proto))) /* EAP-TTLS stage 2 radius request */
    {
        status = STATUS_IKE_PENDING; /* !!! */
    }
#endif

exit:
    if (STATUS_IKE_PENDING == status)
    {
        pxXg->x_flags |= IKE_XCHG_FLAG_PENDING;
    }
    return status;
} /* IKE_eapProcess */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_eapReceiveIndication(ubyte* app_session_handle,
                         eapIndication ind_type,
                         ubyte* data,
                         ubyte4 data_len)
{
    MOC_UNUSED(app_session_handle);
    MOC_UNUSED(ind_type);
    MOC_UNUSED(data);
    MOC_UNUSED(data_len);
    return OK;
} /* IKE_eapReceiveIndication */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_eapVerifyMIC(ubyte* app_session_handle,
                 ubyte* pkt,
                 ubyte4 pkt_len)
{
    MOC_UNUSED(app_session_handle);
    MOC_UNUSED(pkt);
    MOC_UNUSED(pkt_len);
    return OK;
} /* IKE_eapVerifyMIC */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_eapGetMethodState(ubyte*  app_session_handle,
                      ubyte4* methodState)
{
    MOC_UNUSED(app_session_handle);
    MOC_UNUSED(methodState);
    return OK;
} /* IKE_eapGetMethodState */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_eapGetDecision(ubyte*  app_session_handle,
                   ubyte4* decision)
{
    MOC_UNUSED(app_session_handle);
    MOC_UNUSED(decision);
    return OK;
} /* IKE_eapGetDecision */


/*------------------------------------------------------------------*/

extern  MSTATUS
IKE_eapTransmitPktCallback(ubyte*    appSessionHdl,
                           eapHdr_t* eap_hdr,
                           ubyte*    eap_data,
                           ubyte4    eap_data_len)
{
    MSTATUS status = OK;

    IKE2EAP pxEap = (IKE2EAP)appSessionHdl;

    void *pMsg;
    if (NULL == (pMsg = MALLOC(eap_data_len+sizeof(eapHdr_t))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pMsg, eap_hdr, sizeof(eapHdr_t));
    DIGI_MEMCPY((ubyte *)pMsg + sizeof(eapHdr_t), eap_data, eap_data_len);

    pxEap->pxMsg = (struct eapMsgHdr *)pMsg;

exit:
    return status;
} /* IKE_eapTransmitPktCallback */


#endif /* (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

