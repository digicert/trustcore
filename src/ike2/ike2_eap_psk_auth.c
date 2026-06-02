/**
 * @file  ike2_eap_psk_auth.c
 * @brief IKEv2 IKEv2 EAP-PSK Authenticator
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
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
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_PSK__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/random.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_psk.h"

#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike2/ike2_eap.h"


/*------------------------------------------------------------------*/

extern ubyte4 g_ikeEapInstId; /* EAP instance */
extern ikeSettings m_ikeSettings;

/* --eap_identity user -A pskuser:pskipskipskipski */ /* 16 bytes */


/*------------------------------------------------------------------*/

typedef struct appCtrlBlk_t
{
    eapPSKEvt           pskState;
    ubyte *             eapPSKHdl;
    ubyte               rand_s[16];

} appCtrlBlk;


/*------------------------------------------------------------------*/

static MSTATUS
EAP_PSK_AuthInitFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    ubyte *poMsk = NULL;
    appCtrlBlk *cb = NULL;

    /* allocate */
    if ((NULL == (poMsk = (ubyte *) MALLOC(64))) || /* MSK */
        (NULL == (cb = (appCtrlBlk *) MALLOC(sizeof(appCtrlBlk)))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    cb->pskState = 0;
    cb->eapPSKHdl = NULL;

    /* done */
    pxEap->dwMskLen = 64;
    pxEap->poMsk = poMsk;
    pxEap->pCbData = cb;

    poMsk = NULL;

exit:
    if (poMsk) FREE(poMsk);
    return status;
} /* EAP_PSK_AuthInitFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_PSK_AuthDelFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    appCtrlBlk *cb;
    if (NULL != (cb = (appCtrlBlk *) pxEap->pCbData))
    {
        if (cb->eapPSKHdl) EAP_PSKDeleteSession(cb->eapPSKHdl);
        pxEap->pCbData = NULL;
        FREE(cb);
    }

    return status;
} /* EAP_PSK_AuthDelFunc */


/*------------------------------------------------------------------*/

static MSTATUS
eap_auth_psk_evt_callback(ubyte *appCb, ubyte *eapPSKHdl, eapPSKEvt evt)
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

    if (EAP_PSK_EVT_RECV_SECOND_PKT == cb->pskState)
    {
        ubyte *psk = NULL;
        ubyte4 psk_len = 0;

        /* Get the ID_p received from Peer */
        ubyte *id_p = NULL;
        ubyte2 id_p_len = 0;
        EAP_PSKgetID_P(cb->eapPSKHdl, &id_p, &id_p_len);

        /* Base upon ID_s, ID_p select PSK */
        if (NULL == m_ikeSettings.funcPtrLookupSecret)
        {
            status = ERR_IKE_CONFIG;
            goto exit;
        }
        if (OK > (status = m_ikeSettings.funcPtrLookupSecret(
                                               id_p, (ubyte4)id_p_len,
                                               &psk, &psk_len,
                                               pxEap->pxSa->serverInstance)))
            goto exit;

        /* Call Key Setup */
        if (16 <= psk_len)
        EAP_PSKKeySetup(cb->eapPSKHdl, psk);

        else status = ERR_EAP_PSK_INVALID_LENGTH;

        if (NULL != m_ikeSettings.funcPtrReleaseSecret)
            m_ikeSettings.funcPtrReleaseSecret(psk, psk_len,
                                               pxEap->pxSa->serverInstance);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
authProcessIdentityResponse(struct ike2eap *pxEap,
                            ubyte *data, ubyte4 len,
                            ubyte **reqData, ubyte4 *reqLen)
{
    MSTATUS  status = OK;

    ubyte*   pos;
    ubyte4   id_len;
    ubyte*   identity;
    sbyte*   id_s;
    ubyte4   id_s_len;

    appCtrlBlk *cb = (appCtrlBlk *) pxEap->pCbData;

    /* set identity */
    pos = data + sizeof(eapHdr_t) + 1;
    id_len = len - sizeof(eapHdr_t) - 1;
    EAP_setIdentity(pxEap->pSession, g_ikeEapInstId, pos, id_len);
    EAP_getIdentity(pxEap->pSession, g_ikeEapInstId, &identity, &id_len);

    /* TBD : map identity to method */

    /* send method (psk) request */
    RANDOM_numberGenerator(g_pRandomContext, cb->rand_s, 16);

    if (!cb->pskState)
    {
        eapPSKConfig eapPSKCfg;
        eapPSKCfg.sessionType = EAP_SESSION_TYPE_AUTHENTICATOR;
        eapPSKCfg.functionPtrEvtCallback = eap_auth_psk_evt_callback;

        if (OK > (status = EAP_PSKInitSession((ubyte *)pxEap, &cb->eapPSKHdl,
                                              eapPSKCfg)))
            goto exit;
    }

    /* send method (PSK) request */
    id_s = pxEap->pxSa->ikePeerConfig->eapIdentity;
    if (!id_s || (0 == (id_s_len = DIGI_STRLEN(id_s))))
    {
        status = ERR_EAP_INVALID_PARAM;
        goto exit;
    }

    status = EAP_PSKAuthRequestFirst(cb->eapPSKHdl, cb->rand_s,
                                     (ubyte *)id_s, (ubyte2)id_s_len,
                                     reqData, reqLen);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_PSK_AuthReceivePktCallback(ubyte *appSessionHdl,
                               eapMethodType type,
                               eapCode code, ubyte id,
                               ubyte *data, ubyte4 len,
                               ubyte *opaque_data)
{
    MSTATUS status = OK;
    ubyte4 eapReqLen = 0;
    ubyte sendReq = 0;
    ubyte *reqData = NULL;
    eapMethodType methodType = 0;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = 0;
    eapCode sendCode = 0;
    ubyte freebuffer = 0;

    struct ike2eap *pxEap = (struct ike2eap *)appSessionHdl;
    appCtrlBlk *cb = (appCtrlBlk *) pxEap->pCbData;

    MOC_UNUSED(opaque_data);

    switch (code)
    {
        case EAP_CODE_RESPONSE :
            break;
        case EAP_CODE_REQUEST :
        case EAP_CODE_SUCCESS :
        case EAP_CODE_FAILURE :
        default:
        {
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"Invalid EAP Code", status);
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
            status = authProcessIdentityResponse(pxEap, data, len,
                                                 &reqData, &eapReqLen);
            if (OK == status && eapReqLen != 0)
            {
                methodType = EAP_TYPE_PSK;
                sendCode = EAP_CODE_REQUEST;
                methodState = EAP_METHOD_STATE_PROPOSED;
                decision = EAP_METHOD_DECISION_CONTINUE;
                sendReq = 1;
                freebuffer = 1;
            }
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
            ubyte *ext;
            ubyte2 extLen;
            eapPSKResultInd resInd;

            /* process psk response */
            if (OK > (status = EAP_PSKProcessMsg(cb->eapPSKHdl, data, len, id)))
                goto fail; /* Send FAILURE */

            if (EAP_PSK_EVT_RECV_SECOND_PKT == cb->pskState)
            {
                /* If we send EXT we can Send Result Ind CONT */
                /* Currently no EXT Defined */
                status = EAP_PSKAuthRequestThird(cb->eapPSKHdl,
                                                 EAP_PSK_RESULT_SUCCESS,
                                                 NULL, 0, /* ext */
                                                 id + 1, /* The Next Id */
                                                 &reqData, &eapReqLen);
                if (OK > status) goto fail; /* Send FAILURE */

                sendCode = EAP_CODE_REQUEST;
                freebuffer = 1;
            }
            else if (EAP_PSK_EVT_RECV_FOURTH_PKT == cb->pskState)
            {
                /* Check whether EXT Has been Sent Currently shoudld
                   be NULL as Nothing defined yet
                */
                EAP_PSKgetEXT(cb->eapPSKHdl, &ext, &extLen);

                /* Get Result Ind from the Peer */
                /* If we get Failure We send Failure .
                   we want to send EXT or not we can send CONT
                   , if SUCC we can send SUCC/ or CONT */
                EAP_PSKgetResultInd(cb->eapPSKHdl, &resInd);

                if (EAP_PSK_RESULT_SUCCESS == resInd)
                    sendCode = EAP_CODE_SUCCESS;
                else
                    sendCode = EAP_CODE_FAILURE;
            }
            else if (EAP_PSK_EVT_RECV_EXT_PKT == cb->pskState)
            {
                /* DO what ever */
                /* Currently No EXT Exists */
                EAP_PSKgetEXT(cb->eapPSKHdl, &ext, &extLen);
                EAP_PSKgetResultInd(cb->eapPSKHdl, &resInd);
                goto fail; /* ??? */
                break;
            }
            else
            {
                goto fail; /* ??? */
                break;
            }

            if (EAP_CODE_SUCCESS == sendCode)
            {
                ubyte *tek;
                ubyte *msk;
                ubyte *emsk;

                /* get MSK */
                EAP_PSKgetKeys(cb->eapPSKHdl, &tek, &msk, &emsk);
                DIGI_MEMCPY(pxEap->poMsk, msk, 64);

                /* send SUCCESS */
                decision = EAP_METHOD_DECISION_SUCCESS;
                methodState = EAP_METHOD_STATE_CONTINUE;
            }
            else if (EAP_CODE_FAILURE == sendCode)
            {
                /* send FAILURE */
                decision = EAP_METHOD_DECISION_FAILURE;
                methodState = EAP_METHOD_STATE_END;
            }
            else
            {
                methodType = EAP_TYPE_PSK;
                decision = EAP_METHOD_DECISION_CONTINUE;
                methodState = EAP_METHOD_STATE_CONTINUE;
            }
            sendReq = 1;
            break;
        }

        case EAP_TYPE_NAK :
        {
            /* check for additional methods */
            break;
        }

        default :
        {
            break;
        }
    }

    goto send;

fail:
    /* Send FAILURE */
    sendCode = EAP_CODE_FAILURE;
    decision = EAP_METHOD_DECISION_FAILURE;
    methodState = EAP_METHOD_STATE_END;
    sendReq = 1;

    status = OK;

send:
    if (sendReq)
    {
        status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                methodType, sendCode,
                                decision, methodState,
                                reqData, eapReqLen);
    }

    if (freebuffer && NULL != reqData)
    {
        FREE(reqData);
    }

exit:
    return status;
} /* EAP_PSK_AuthReceivePktCallback */


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
        "IKE_EAP_PSK_AUTH",
        EAP_PSK_AuthReceivePktCallback,
        NULL,
        IKE_eapReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapPSKauthSuite =
{
    EAP_PSK_AuthInitFunc,
    EAP_PSK_AuthDelFunc,
    &methodDef,
    EAP_SESSION_TYPE_AUTHENTICATOR,
#ifdef __ENABLE_IKE_EAP_ONLY__
    TRUE
#endif
};


#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_PSK__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

