/**
 * @file  ike2_eap_sim_peer.c
 * @brief IKEv2 IKEv2 EAP-SIM Peer
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     +   \c \__ENABLE_DIGICERT_EAP_SIM__
 *     +   \c \__DISABLE_DIGICERT_IKE_EAP__ must not be defined
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

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_SIM__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_sim.h"
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
#include "../eap/eap_ttls.h"
#endif

#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike2/ike2_eap.h"


/*------------------------------------------------------------------*/

extern ubyte4 g_ikeEapInstId; /* EAP instance */
extern ikeSettings m_ikeSettings;


/*------------------------------------------------------------------*/

static ubyte2 versionList[] = {1, 2};
static ubyte2 versionListLen = 2;


/*------------------------------------------------------------------*/

typedef struct appCtrlBlk_t
{
    eapSimCb           *eapSim;

    /* Result Indication Supported Flag  */
    ubyte              eapSimResultInd;

} appCtrlBlk;


/*------------------------------------------------------------------*/

static MSTATUS
getSresKc(void *appCb, void *eapSim,
          ubyte *rand, ubyte numRand,
          ubyte *Sres, ubyte *Kc)
{
    MSTATUS status;

    struct ike2eap *pxEap = (struct ike2eap *)appCb;
    ubyte *sks; /* concatenation of [sRes, kC] pairs */
    ubyte4 sksLen;
    ubyte i;

    if (NULL == m_ikeSettings.funcPtrGetToken)
    {
        status = ERR_IKE_CONFIG;
        goto exit;
    }

    if (OK > (status = m_ikeSettings.funcPtrGetToken(rand,
                                                 (EAP_SIM_RAND_LEN * numRand),
                                                 &sks, &sksLen,
                                                 pxEap->pxSa->serverInstance)))
        goto exit;

    if (numRand != (ubyte)(sksLen / (EAP_SIM_SRES_LEN + EAP_SIM_KC_LEN)))
    {
        status = ERR_EAP_SIM;
    }
    else
    for (i=0; i < numRand; i++)
    {
        ubyte *cur = sks + (i * (EAP_SIM_SRES_LEN + EAP_SIM_KC_LEN));
        DIGI_MEMCPY(Sres + (i * EAP_SIM_SRES_LEN), cur,
                   EAP_SIM_SRES_LEN/*4*/);
        DIGI_MEMCPY(Kc + (i * EAP_SIM_KC_LEN), cur + EAP_SIM_SRES_LEN,
                   EAP_SIM_KC_LEN/*8*/);
     }

    if (sks)
    {
        DIGI_MEMSET(sks, 0x0, sksLen);
        FREE(sks);
    }

    MOC_UNUSED(eapSim);
 
exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Function that gets called once RAND from AUTN are received  */
static MSTATUS
getAKARes(void *appCb, void *eapSim,
          ubyte *rand, ubyte *autn,
          ubyte *ik, ubyte *ck,
          ubyte *Res, ubyte2 *resLen, ubyte *auts)
{
    /* If the AUTN is not within the seq range, generate status = ERR_EAP_AKA_SYNC_FAIL and
       fill in the Res Value , else pass ERR_EAP_AKA_AUTH_REJECT if we get some other error */
    MSTATUS status;

    struct ike2eap *pxEap = (struct ike2eap *)appCb;
    ubyte data[EAP_SIM_RAND_LEN + EAP_AKA_AUTN_LEN]; /* [RAND, AUTN] */
    ubyte *vector; /* [CK, IK, RES] */
    ubyte4 vectorLen;

    MOC_UNUSED(eapSim);
    MOC_UNUSED(auts);

    if (NULL == m_ikeSettings.funcPtrGetToken)
    {
        status = ERR_IKE_CONFIG;
        goto exit;
    }

    DIGI_MEMCPY(data, rand, EAP_SIM_RAND_LEN);
    DIGI_MEMCPY(data+EAP_SIM_RAND_LEN, autn, EAP_AKA_AUTN_LEN);

    if (OK > (status = m_ikeSettings.funcPtrGetToken(data, sizeof(data),
                                                 &vector, &vectorLen,
                                                 pxEap->pxSa->serverInstance)))
        goto exit;

    if (((EAP_AKA_CK_LEN+EAP_AKA_IK_LEN+4) > vectorLen) ||
        ((EAP_AKA_CK_LEN+EAP_AKA_IK_LEN+16) < vectorLen))
    {
        status = ERR_EAP_AKA;
    }
    else
    {
        DIGI_MEMCPY(ck, vector, EAP_AKA_CK_LEN);
        DIGI_MEMCPY(ik, vector+EAP_AKA_CK_LEN, EAP_AKA_IK_LEN);
        DIGI_MEMCPY(Res, vector+(EAP_AKA_CK_LEN+EAP_AKA_IK_LEN),
                   vectorLen-(EAP_AKA_CK_LEN+EAP_AKA_IK_LEN));
        *resLen = (ubyte2) /* It's in Bits 32 to 128  */
                  ((vectorLen-(EAP_AKA_CK_LEN+EAP_AKA_IK_LEN)) * 8);
    }

    if (vector)
    {
        DIGI_MEMSET(vector, 0x0, vectorLen);
        FREE(vector);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_SIM_PeerInitFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    eapSimConfig eapSimCfg = { 0 };
    ubyte *imsi;
    ubyte2 imsiLen;

    ubyte *poMsk = NULL;
    appCtrlBlk *cb = NULL;

    /* allocate */
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    if (NULL == pxEap->ttls_connection)
#endif
    if (NULL == (poMsk = (ubyte *) MALLOC(EAP_SIM_MSK_LEN))) /* MSK */
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL == (cb = (appCtrlBlk *) MALLOC(sizeof(appCtrlBlk))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

/*  DIGI_MEMSET((ubyte *)cb, 0x00, sizeof(appCtrlBlk));*/
    cb->eapSim = NULL;
    cb->eapSimResultInd = 1;  /* support Result Ind */

    /* initialize SIM/AKA session */
    eapSimCfg.send_result_ind = cb->eapSimResultInd;
    eapSimCfg.sessionType = EAP_SESSION_TYPE_PEER;
    if (EAP_PROTO_AKA == pxEap->proto)
    {
        eapSimCfg.aka       = 1;
        eapSimCfg.getAKARes = getAKARes;
    }
    else
    {
        eapSimCfg.getSresKc = getSresKc;
    }
    if (OK > (status = EAP_SIMInitSession(pxEap, (void **)&cb->eapSim, eapSimCfg)))
        goto exit;

    /* set Permanent Identity (IMSI) */
    imsi = (ubyte *) pxEap->pxSa->ikePeerConfig->eapIdentity;
    if (!imsi || (0 == (imsiLen = (ubyte2) DIGI_STRLEN((sbyte *)imsi))))
    {
        status = ERR_EAP_INVALID_PARAM;
        goto exit;
    }

    if ((OK > (status = EAP_SIMSetPermIdentity(cb->eapSim, imsi, imsiLen))) ||
        (OK > (status = EAP_SIMSetIdentity(cb->eapSim, imsi, imsiLen))))
        goto exit;

    if (OK > (status = EAP_SIMSetImplementedVersion(cb->eapSim,
                                        versionList, versionListLen)))
        goto exit;

    /* done */
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    if (pxEap->ttls_connection)
    {
        pxEap->pInnerCbData = cb;
        cb = NULL;
        goto exit;
    }
#endif
    pxEap->pCbData = cb;
    cb = NULL;

    pxEap->dwMskLen = EAP_SIM_MSK_LEN; /* 64 */
    pxEap->poMsk = poMsk;
    poMsk = NULL;

exit:
    if (poMsk) FREE(poMsk);
    if (cb)
    {
        if (cb->eapSim) EAP_SIMDeleteSession(cb->eapSim);
        FREE(cb);
    }
    return status;
} /* EAP_SIM_PeerInitFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_SIM_PeerDelFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    appCtrlBlk *cb;
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    if (pxEap->ttls_connection)
        cb = (appCtrlBlk *) pxEap->pInnerCbData;
    else
#endif
    cb = (appCtrlBlk *) pxEap->pCbData;

    if (NULL != cb)
    {
        if (cb->eapSim) EAP_SIMDeleteSession(cb->eapSim);

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
        if (pxEap->ttls_connection)
            pxEap->pInnerCbData = NULL;
        else
#endif
        pxEap->pCbData = NULL;
        FREE(cb);
    }

    return status;
} /* EAP_SIM_PeerDelFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_SIM_PeerReceivePktCallback(ubyte *appSessionHdl,
                               eapMethodType type,
                               eapCode code, ubyte id,
                               ubyte *data, ubyte4 len,
                               ubyte *opaque_data)
{
    MSTATUS status = OK;
    ubyte *eapResponse = NULL;
    ubyte4 eapRespLen = 0;
    ubyte sendResponse = 0;
    ubyte freebuffer = 0;
    eapMethodType methodType = 0;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = EAP_METHOD_DECISION_NONE;

    struct ike2eap *pxEap = (struct ike2eap *)appSessionHdl;
    appCtrlBlk *cb;
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    if (pxEap->ttls_connection)
        cb = (appCtrlBlk *) pxEap->pInnerCbData;
    else
#endif
    cb = (appCtrlBlk *) pxEap->pCbData;

    MOC_UNUSED(id);
    MOC_UNUSED(opaque_data);

    switch (code)
    {
        case EAP_CODE_REQUEST :
            break;
        case EAP_CODE_SUCCESS :
        case EAP_CODE_FAILURE :
            /* delete session */
/*          EAP_SIM_PeerDelFunc(pxEap);
            EAP_sessionDelete(pxEap->pSession, g_ikeEapInstId);
            pxEap->pSession = NULL;*/
            goto exit;
        case EAP_CODE_RESPONSE :
        default :
        {
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte *)"Invalid EAP Code", status);
            break;
        }
    }

    if (OK != status)
        goto exit;

    switch (type)
    {
        case EAP_TYPE_NONE :
        {
            /* set error code */
            status = ERR_EAP_INVALID_METHOD_TYPE;
            break;
        }

        case EAP_TYPE_IDENTITY :
        {
            /* Build IDENTITY response */
            const ubyte *identity = pxEap->identity;
            if (identity && (0 != (eapRespLen = pxEap->identityLen)))
            {
                if (NULL == (eapResponse = (ubyte *) MALLOC(eapRespLen)))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }
                DIGI_MEMCPY(eapResponse, identity, eapRespLen);
            }
            else
            {
                status = ERR_EAP_INVALID_PARAM;
                goto exit;
            }
            methodType =  EAP_TYPE_IDENTITY;
            methodState = EAP_METHOD_STATE_CONT;
            decision = EAP_METHOD_DECISION_FAIL;
            sendResponse = 1;
            freebuffer = 1;
            break;
        }

        case EAP_TYPE_NOTIFICATION :
        {
            /* Log msg */
            methodType = EAP_TYPE_NOTIFICATION;
            break;
        }

        case EAP_TYPE_SIM :
        case EAP_TYPE_AKA :
        {
            eapSimStatus sessionState;
            ubyte rInd;

            if (!pxEap->proto)
                pxEap->proto = (IKE_EAP_PROTO_T)type;
            else if ((IKE_EAP_PROTO_T)type != pxEap->proto)
            {
                status = ERR_EAP_INVALID_METHOD_TYPE;
                break;
            }

            /* process request */
            if (EAP_TYPE_AKA == type)
                status = EAP_AKAProcessPkt(cb->eapSim, data, (ubyte2)len,
                                           &eapResponse, &eapRespLen,
                                           &sessionState);
            else
                status = EAP_SIMProcessPkt(cb->eapSim, data, (ubyte2)len,
                                           &eapResponse, &eapRespLen,
                                           &sessionState);
            if (OK > status)
            {
                if (eapResponse && !eapRespLen) /* jic */
                {
                    methodType = type;
                    methodState = EAP_METHOD_STATE_CONT;
                    decision = EAP_METHOD_DECISION_FAIL;
                    sendResponse = 1;
                    freebuffer = 1;
                }
            }
            else
            {
                intBoolean bMsk = FALSE;

                methodType = type;
                methodState = EAP_METHOD_STATE_CONT;
                decision = EAP_METHOD_DECISION_FAIL;
                sendResponse = 1;
                freebuffer = 1;

                if (EAP_SIM_STATUS_RECV_CHALLENGE_REQ == sessionState)
                {
                    /* If the Negotiation included RESULT IND
                       then we have to wait for that before we accept SUCCESS */
                    EAP_SIMGetResultInd(cb->eapSim, &rInd);
                    if (!cb->eapSimResultInd || !rInd)
                    {
                        /* Looks like we are done unless the AUTH rejects us
                           Then it can send us Notification Error or FAILURE */
                        methodState = EAP_METHOD_STATE_DONE;
                        decision = EAP_METHOD_DECISION_UNCOND_SUCC;
                        bMsk = TRUE;
                    }
                }
                else if (EAP_SIM_STATUS_RECV_NOTIFICATION_REQ == sessionState)
                {
                    EAP_SIMGetSuccessNotifCode(cb->eapSim, &rInd);
                    if (rInd)
                    {
                        methodState = EAP_METHOD_STATE_DONE;
                        decision = EAP_METHOD_DECISION_UNCOND_SUCC;
                        bMsk = TRUE;
                    }
                }

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
                if (pxEap->ttls_connection) /* EAP-TTLS inner EAP tunnel */
                    bMsk = FALSE;
#endif
                /* get MSK */
                if (bMsk)
                {
                    ubyte *key; ubyte4 keyLen;
                    if (OK > (status = EAP_SIMgetKey(cb->eapSim, EAP_SIM_MSK_KEY, &key, &keyLen)))
                        break;

                    DIGI_MEMCPY(pxEap->poMsk, key, keyLen);
                }
            }
            break;
        }

        default :
        {
            /* send NAK response */
            status = EAP_buildNAK(pxEap->pSession, g_ikeEapInstId,
                                  (ubyte *)NULL, 0,
                                  &eapResponse, &eapRespLen);

            if (OK == status)
            {
                methodType = EAP_TYPE_NAK;
                decision = EAP_METHOD_DECISION_FAIL;
                sendResponse = 1;
                freebuffer = 1;
            }

            break;
        }
    }

    if (sendResponse)
    {
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
        if (pxEap->ttls_connection) /* EAP-TTLS inner EAP tunnel */
        status = EAP_TTLSulPeerTransmit(pxEap->ttls_connection, g_ikeEapInstId,
                                        methodType, EAP_CODE_RESPONSE,
                                        decision, methodState,
                                        eapResponse, eapRespLen);
        else
#endif
        status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                methodType, EAP_CODE_RESPONSE,
                                decision, methodState,
                                eapResponse, eapRespLen);

    }

    if (freebuffer && NULL != eapResponse)
    {
        FREE(eapResponse);
    }

exit:
    return status;
} /* EAP_SIM_PeerReceivePktCallback */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_SIM_PeerReceiveIndication(ubyte* app_session_handle,
                              eapIndication ind_type,
                              ubyte* data,
                              ubyte4 data_len)
{
    /* Note: this function is probably never used, as IKEv2's EAP
       instance does not re-transmit EAP messages.
     */
    MOC_UNUSED(data);
    MOC_UNUSED(data_len);

    /* If Indication is Timeout or Error , Delete the session */
    if ((EAP_INDICATION_ERROR        == ind_type) ||
        (EAP_INDICATION_PEER_TIMEOUT == ind_type))
    {
        struct ike2eap *pxEap = (struct ike2eap *)app_session_handle;
        if (pxEap) /* jic */
        {
            EAP_SIM_PeerDelFunc(pxEap);
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
            if (pxEap->ttls_connection) /* EAP-TTLS inner EAP tunnel */
            {
                pxEap->pInnerEapSuite = NULL;
            }
            else
#endif
            {
                EAP_sessionDelete(pxEap->pSession, g_ikeEapInstId);
                pxEap->pSession = NULL;
            }
        }
    }

    return OK;
} /* EAP_SIM_PeerReceiveIndication */


/*------------------------------------------------------------------*/

static eapMethodDef_t methodDef =
{/*
        eapMethodType,
        ubyte method_name[EAP_MAX_METHOD_NAME],
        funcPtr_ulReceiveCallback,
        funcPtr_ulReceivePassthruCallback,
        funcPtr_ulReceiveIndication,
        funcPtr_ulMICVerify,
        funcPtr_ulGetMethodstate,
        funcPtr_ulGetDecision,
        funcPtr_llTransmitPacket
  */
        EAP_TYPE_NONE,
        "IKE_EAP_SIM_PEER",
        EAP_SIM_PeerReceivePktCallback,
        NULL,
        EAP_SIM_PeerReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapSIMpeerSuite =
{
    EAP_SIM_PeerInitFunc,
    EAP_SIM_PeerDelFunc,
    &methodDef,
    EAP_SESSION_TYPE_PEER,
#ifdef __ENABLE_IKE_EAP_ONLY__
    TRUE
#endif
};


#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_SIM__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

