/**
 * @file  ike2_eap_psk_peer.c
 * @brief IKEv2 IKEv2 EAP-PSK Peer
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     +   \c \__ENABLE_DIGICERT_EAP_PSK__
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
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_PSK__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/random.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_psk.h"
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

typedef struct appCtrlBlk_t
{
    eapPSKEvt           pskState;
    ubyte*              eapPSKHdl;
    ubyte               rand_p[16];

} appCtrlBlk;


/*------------------------------------------------------------------*/

static MSTATUS
EAP_PSK_PeerInitFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    ubyte *poMsk = NULL;
    appCtrlBlk *cb = NULL;

    /* allocate */
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    if (NULL == pxEap->ttls_connection)
#endif
    if (NULL == (poMsk = (ubyte *) MALLOC(64))) /* MSK */
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL == (cb = (appCtrlBlk *) MALLOC(sizeof(appCtrlBlk))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)cb, 0x0, sizeof(appCtrlBlk));

    /* done */
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    if (pxEap->ttls_connection)
    {
        pxEap->pInnerCbData = cb;
        goto exit;
    }
#endif
    pxEap->pCbData = cb;

    pxEap->dwMskLen = 64;
    pxEap->poMsk = poMsk;
    poMsk = NULL;

exit:
    if (poMsk) FREE(poMsk);
    return status;
} /* EAP_PSK_PeerInitFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_PSK_PeerDelFunc(struct ike2eap *pxEap)
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
        if (cb->eapPSKHdl) EAP_PSKDeleteSession(cb->eapPSKHdl);

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
        if (pxEap->ttls_connection)
            pxEap->pInnerCbData = NULL;
        else
#endif
        pxEap->pCbData = NULL;
        FREE(cb);
    }

    return status;
} /* EAP_PSK_PeerDelFunc */


/*------------------------------------------------------------------*/

static MSTATUS
eap_peer_psk_evt_callback(ubyte *appCb, ubyte *eapPSKHdl, eapPSKEvt evt)
{
    MSTATUS status = OK;

    struct ike2eap *pxEap;
    appCtrlBlk *cb;

    MOC_UNUSED(eapPSKHdl);

    if ((NULL == (pxEap = (struct ike2eap *)appCb)) ||
        (NULL == (cb = (appCtrlBlk *) pxEap->pCbData)))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    cb->pskState = evt;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_PSK_PeerReceivePktCallback(ubyte *appSessionHdl,
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

    MOC_UNUSED(opaque_data);

    switch (code)
    {
        case EAP_CODE_REQUEST :
            break;
        case EAP_CODE_SUCCESS :
        case EAP_CODE_FAILURE :
            /* delete session */
/*          EAP_PSK_PeerDelFunc(pxEap);
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

        case EAP_TYPE_PSK :
        {
            ubyte *tek;
            ubyte *msk;
            ubyte *emsk;

            ubyte *ext = NULL;
            ubyte2 extLen = 0;
            eapPSKResultInd resInd = 0;

            /* PSK processing */
            if (!cb->pskState)
            {
                eapPSKConfig eapPSKCfg;
                eapPSKCfg.sessionType = EAP_SESSION_TYPE_PEER;
                eapPSKCfg.functionPtrEvtCallback = eap_peer_psk_evt_callback;

                if (OK > (status = EAP_PSKInitSession(appSessionHdl, &cb->eapPSKHdl,
                                                      eapPSKCfg)))
                    goto exit;
            }

            if (OK != (status = EAP_PSKProcessMsg(cb->eapPSKHdl, data, len, id)))
                goto exit;

            if (EAP_PSK_EVT_RECV_FIRST_PKT == cb->pskState)
            {
                /* Get the ID_s received from Auth */
                sbyte *id_p;
                ubyte2 id_p_len;
                ubyte *psk;
                ubyte4 psk_len;
                ubyte *id_s;
                ubyte2 id_s_len;
                EAP_PSKgetID_S(cb->eapPSKHdl, &id_s, &id_s_len);

                /* Base upon ID_s, select the correct ID_p and PSK */
                id_p = pxEap->pxSa->ikePeerConfig->eapIdentity;
                if (!id_p ||
                    (0 == (id_p_len = (ubyte2) DIGI_STRLEN(id_p))))
                {
                    status = ERR_EAP_INVALID_PARAM;
                    goto exit;
                }
 
                if (NULL == m_ikeSettings.funcPtrGetToken)
                {
                    status = ERR_IKE_CONFIG;
                    goto exit;
                }
                if (OK > (status = m_ikeSettings.funcPtrGetToken(
                                                 id_s, (ubyte4)id_s_len,
                                                 &psk, &psk_len,
                                                 pxEap->pxSa->serverInstance)))
                    goto exit;

                /* Call Key Setup */
                if (16 != psk_len) status = ERR_EAP_PSK_INVALID_LENGTH;
                else
                EAP_PSKKeySetup(cb->eapPSKHdl, psk);

                if (psk)
                {
                    DIGI_MEMSET(psk, 0x0, psk_len);
                    FREE(psk);
                }
                if (OK > status) break;

                /* Call Second Packet Reply */
                RANDOM_numberGenerator(g_pRandomContext, cb->rand_p, 16);

                status = EAP_PSKPeerReplySecond(cb->eapPSKHdl, cb->rand_p,
                                                (ubyte *)id_p, id_p_len,
                                                &eapResponse, &eapRespLen);
                if (OK == status)
                {
                    methodType = EAP_TYPE_PSK;
                    methodState = EAP_METHOD_STATE_CONT;
                    decision = EAP_METHOD_DECISION_FAIL;
                    sendResponse = 1;
                    freebuffer = 1;
                }
            }
            else if (EAP_PSK_EVT_RECV_THIRD_PKT == cb->pskState)
            {
                /*
                if (OK > status)
                    We can reply with Fourth but Error Result Ind
                */
                /* Check whether EXT Has been Sent Currently shoudl
                   be NULL as Nothing defined yet
                */
                EAP_PSKgetEXT(cb->eapPSKHdl, &ext, &extLen);

                /* Get Result Ind from the Auth */
                /* If we get Failure We send Failure . If CONT then we send
                   CONT or SuCCESS Depending upon whether we
                   got ext or not and whther we want to send EXT or not
                   , if SUCC we send SUCC */
                EAP_PSKgetResultInd(cb->eapPSKHdl, &resInd);
                if (EAP_PSK_RESULT_SUCCESS != resInd)
                {
                    /* DO What Ever if Required */
                }

                status = EAP_PSKPeerReplyFourth(cb->eapPSKHdl, resInd,
                                                NULL, 0,
                                                id,
                                                &eapResponse, &eapRespLen);
                if (OK == status)
                {
                    freebuffer = 1;

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
                    if (!pxEap->ttls_connection) /* EAP-TTLS inner EAP tunnel */
#endif
                    {
                        /* get MSK */
                        EAP_PSKgetKeys(cb->eapPSKHdl, &tek, &msk, &emsk);
                        DIGI_MEMCPY(pxEap->poMsk, msk, 64);
                    }
                    methodType = EAP_TYPE_PSK;
                    methodState = EAP_METHOD_STATE_DONE;
                    decision = EAP_METHOD_DECISION_UNCOND_SUCC;
                    sendResponse = 1;
                }
            }
            else if (EAP_PSK_EVT_RECV_EXT_PKT == cb->pskState)
            {
                /*
                if (OK > status)
                    We can reply with EXT but Error Result Ind
                */
                /* Check whether EXT Has been Sent Currently shoudl
                   be NULL as Nothing defined yet
                */
                EAP_PSKgetEXT(cb->eapPSKHdl, &ext, &extLen);

                /* Get Result Ind from the Auth */
                /* If we get Failure We send Failure . If CONT then we send
                   CONT or SuCCESS Depending upon whether we
                   got ext or not and whther we want to send EXT or not
                   , if SUCC we send SUCC */
                EAP_PSKgetResultInd(cb->eapPSKHdl, &resInd);
                /*
                status = EAP_PSKPeerReplyEXT(cb->eapPSKHdl, EAP_PSK_RESULT_SUCCESS,
                                             NULL, 0,
                                             id,
                                             &eapResponse, &eapRespLen);
                */
                if (OK == status)
                {
                    freebuffer = 1;

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
                    if (!pxEap->ttls_connection) /* EAP-TTLS inner EAP tunnel */
#endif
                    {
                        /* get MSK */
                        EAP_PSKgetKeys(cb->eapPSKHdl, &tek, &msk, &emsk);
                        DIGI_MEMCPY(pxEap->poMsk, msk, 64);
                    }
                    methodType = EAP_TYPE_PSK;
                    methodState = EAP_METHOD_STATE_DONE;
                    decision = EAP_METHOD_DECISION_UNCOND_SUCC;
                    sendResponse = 1;
                }
            }
            break;
        }

        default :
        {
            /* send NAK response */
            ubyte methodSup = EAP_TYPE_PSK;
            status = EAP_buildNAK(pxEap->pSession, g_ikeEapInstId,
                                  &methodSup, 1,
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
} /* EAP_PSK_PeerReceivePktCallback */


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
        "IKE_EAP_PSK_PEER",
        EAP_PSK_PeerReceivePktCallback,
        NULL,
        IKE_eapReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapPSKpeerSuite =
{
    EAP_PSK_PeerInitFunc,
    EAP_PSK_PeerDelFunc,
    &methodDef,
    EAP_SESSION_TYPE_PEER,
#ifdef __ENABLE_IKE_EAP_ONLY__
    FALSE
#endif
};


#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_PSK__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

