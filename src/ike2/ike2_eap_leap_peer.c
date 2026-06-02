/**
 * @file  ike2_eap_leap_peer.c
 * @brief IKEv2 IKEv2 EAP-LEAP Peer
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     +   \c \__ENABLE_DIGICERT_EAP_LEAP__
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
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_LEAP__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_leap.h"

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
    void               *eapLeapCb;

    ubyte              *password;
    ubyte4              passwordLen;
    
} appCtrlBlk;


/*------------------------------------------------------------------*/

static MSTATUS
EAP_LEAP_PeerInitFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    ubyte *poMsk = NULL;
    appCtrlBlk *cb = NULL;

    /* allocate */
    if ((NULL == (poMsk = (ubyte *) MALLOC(LEAP_KEY_LEN))) || /* MSK */
        (NULL == (cb = (appCtrlBlk *) MALLOC(sizeof(appCtrlBlk)))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)cb, 0x0, sizeof(appCtrlBlk));

    /* initialize LEAP session */
    if (OK > (status =  EAP_LEAPinitSession(pxEap, &(cb->eapLeapCb),
                                            EAP_SESSION_TYPE_PEER)))
        goto exit;

    /* done */
    pxEap->pCbData = cb;
    cb = NULL;

    pxEap->dwMskLen = LEAP_KEY_LEN;/* 16 */
    pxEap->poMsk = poMsk;
    poMsk = NULL;

exit:
    if (poMsk) FREE(poMsk);
    if (cb) FREE(cb);
    return status;
} /* EAP_LEAP_PeerInitFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_LEAP_PeerDelFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    appCtrlBlk *cb = (appCtrlBlk *) pxEap->pCbData;
    if (NULL != cb)
    {
        if (cb->eapLeapCb) EAP_LEAPdeleteSession(cb->eapLeapCb);
        if (cb->password)
        {
            DIGI_MEMSET(cb->password, 0x0, cb->passwordLen);
            FREE(cb->password);
        }
        pxEap->pCbData = NULL;
        FREE(cb);
    }

    return status;
} /* EAP_LEAP_PeerDelFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_LEAP_PeerReceivePktCallback(ubyte *appSessionHdl,
                                eapMethodType type,
                                eapCode code, ubyte id,
                                ubyte *data, ubyte4 len,
                                ubyte *opaque_data)
{
    MSTATUS status = OK;
    ubyte* eapResponse = NULL;
    ubyte4 eapRespLen = 0;
    ubyte4 sendResponse = 0;
    ubyte freebuffer = 0;
    eapCode sendCode = 0;
    ubyte *pKey = NULL;
    eapMethodType methodType = 0;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = EAP_METHOD_DECISION_NONE;

    struct ike2eap *pxEap = (struct ike2eap *)appSessionHdl;
    appCtrlBlk *cb = (appCtrlBlk *) pxEap->pCbData;

    MOC_UNUSED(id);
    MOC_UNUSED(opaque_data);

    switch (code)
    {
        /* In case of LEAP, all these codes are valid because of mutual auth */
        case EAP_CODE_REQUEST :
        case EAP_CODE_RESPONSE :
        case EAP_CODE_SUCCESS :
            break;
        case EAP_CODE_FAILURE :
            /* delete session */
/*          EAP_LEAP_PeerDelFunc(pxEap);
            EAP_sessionDelete(pxEap->pSession, g_ikeEapInstId);
            pxEap->pSession = NULL;*/
            goto exit;
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
            if (EAP_CODE_SUCCESS == code)
            {
                sbyte *identityString = pxEap->pxSa->ikePeerConfig->eapIdentity;
                ubyte2 identityStringLen = (ubyte2)
                                (identityString ? DIGI_STRLEN(identityString) : 0);

                status = EAP_LEAP_processPeer(cb->eapLeapCb, code, data, len,
                                      cb->password, (ubyte2) cb->passwordLen,
                                      (ubyte *)identityString, identityStringLen,
                                      &sendCode, &pKey,
                                      &eapResponse, &eapRespLen);
                if (OK == status)
                {
                    if (sendCode)
                    {
                        methodType = EAP_TYPE_LEAP;
                        methodState = EAP_METHOD_STATE_MAY_CONT;
                        decision = EAP_METHOD_DECISION_COND_SUCC;
                        sendResponse = 1;
                        freebuffer = 1;
                    }
                }
            }
            else
            {
                /* set error code */
                status = ERR_EAP_INVALID_METHOD_TYPE;
            }
            break;
        }

        case EAP_TYPE_IDENTITY :
        {
            /* Build IDENTITY response */
            sbyte *identity = pxEap->pxSa->ikePeerConfig->eapIdentity;
            if (identity && (0 != (eapRespLen = DIGI_STRLEN(identity))))
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
            sendCode = EAP_CODE_RESPONSE;
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

        case EAP_TYPE_LEAP :
        {
            sbyte *identityString = pxEap->pxSa->ikePeerConfig->eapIdentity;
            ubyte2 identityStringLen = (ubyte2)
                                (identityString ? DIGI_STRLEN(identityString) : 0);

            if (NULL == cb->password)
            {
                if (NULL == m_ikeSettings.funcPtrGetToken)
                {
                    status = ERR_IKE_CONFIG;
                    goto exit;
                }
                if (OK > (status = m_ikeSettings.funcPtrGetToken(NULL, 0,
                                             &cb->password, &cb->passwordLen,
                                             pxEap->pxSa->serverInstance)))
                    goto exit;
            }

            /* LEAP processing */
            status = EAP_LEAP_processPeer(cb->eapLeapCb, code, data, len,
                                          cb->password, (ubyte2) cb->passwordLen,
                                          (ubyte *)identityString, identityStringLen,
                                          &sendCode, &pKey,
                                          &eapResponse, &eapRespLen);
            if (OK == status)
            {
                if (sendCode)
                {
                    methodType = EAP_TYPE_LEAP;
                    methodState = EAP_METHOD_STATE_MAY_CONT;
                    decision = EAP_METHOD_DECISION_COND_SUCC;
                    sendResponse = 1;
                    freebuffer = 1;
                }
                else
                {
                    methodType = EAP_TYPE_LEAP;
                    methodState = EAP_METHOD_STATE_DONE;
                    decision = EAP_METHOD_DECISION_UNCOND_SUCC;
                    if (OK > (status = EAP_setMethodStateDecision(
                                                pxEap->pSession, g_ikeEapInstId,
                                                methodState, decision)))
                        break;

                    /* get MSK */
                    status = EAP_LEAP_getKey(cb->eapLeapCb,
                                             pxEap->poMsk, LEAP_KEY_LEN);
                }
            }
            break;
        }

        default :
        {
            /* send NAK response */
            ubyte methodSup = EAP_TYPE_LEAP;
            status = EAP_buildNAK(pxEap->pSession, g_ikeEapInstId,
                                  &methodSup, 1,
                                  &eapResponse, &eapRespLen);
            if (OK == status)
            {
                sendCode = EAP_CODE_RESPONSE; /* ??? */
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
        status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                methodType, sendCode,
                                decision, methodState,
                                eapResponse, eapRespLen);

    }
    if (freebuffer && NULL != eapResponse)
    {
        FREE(eapResponse);
    }

exit:
    return status;
} /* EAP_LEAP_PeerReceivePktCallback */


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
        "IKE_EAP_LEAP_PEER",
        EAP_LEAP_PeerReceivePktCallback,
        NULL,
        IKE_eapReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapLEAPpeerSuite =
{
    EAP_LEAP_PeerInitFunc,
    EAP_LEAP_PeerDelFunc,
    &methodDef,
    EAP_SESSION_TYPE_PEER,
#ifdef __ENABLE_IKE_EAP_ONLY__
    FALSE
#endif
};


#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_LEAP__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

