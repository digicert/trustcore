/**
 * @file  ike2_eap_leap_auth.c
 * @brief IKEv2 IKEv2 EAP-LEAP Authenticator
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
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
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_LEAP__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../crypto/md5.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_auth.h"
#include "../eap/eap_session.h"
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

static MSTATUS
EAP_LEAP_AuthInitFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    /* allocate */
    ubyte *poMsk;
    if (NULL == (poMsk = (ubyte *) MALLOC(LEAP_KEY_LEN))) /* MSK */
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* initialize LEAP session */
    if (OK > (status =  EAP_LEAPinitSession(pxEap, &pxEap->pCbData,
                                    EAP_SESSION_TYPE_AUTHENTICATOR)))
        goto exit;

    /* done */
    pxEap->dwMskLen = LEAP_KEY_LEN;/* 16 */
    pxEap->poMsk = poMsk;

    poMsk = NULL;

exit:
    if (poMsk) FREE(poMsk);
    return status;
} /* EAP_LEAP_AuthInitFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_LEAP_AuthDelFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    if (pxEap->pCbData)
    {
        EAP_LEAPdeleteSession(pxEap->pCbData);
        pxEap->pCbData = NULL;
    }

    return status;
} /* EAP_LEAP_AuthDelFunc */


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

    /* set identity */
    pos = data + sizeof(eapHdr_t) + 1;
    id_len = len - sizeof(eapHdr_t) - 1;
    EAP_setIdentity(pxEap->pSession, g_ikeEapInstId, pos, id_len);
    EAP_getIdentity(pxEap->pSession, g_ikeEapInstId, &identity, &id_len);

    /* TBD : map identity to method */
/*  eapSession->eapSelectedMethod = EAP_TYPE_LEAP;*/

    /* send method (LEAP) request */
    status = EAP_LEAP_buildChallenge((eapLeapCb_t *) pxEap->pCbData,
                                     EAP_SESSION_TYPE_AUTHENTICATOR,
                                     identity, (ubyte2)id_len,
                                     reqData, reqLen);
/*
exit:*/
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_LEAP_AuthReceivePktCallback(ubyte *appSessionHdl,
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

    MOC_UNUSED(id);
    MOC_UNUSED(opaque_data);

    switch (code)
    {
        case EAP_CODE_REQUEST :
        case EAP_CODE_RESPONSE :
            break;
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
                methodType = EAP_TYPE_LEAP;
                sendCode = EAP_CODE_REQUEST;
                decision = EAP_METHOD_DECISION_CONTINUE;
                methodState = EAP_METHOD_STATE_PROPOSED;
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

        case EAP_TYPE_LEAP :
        {
            ubyte *identity = NULL;
            ubyte4 id_len = 0;
            ubyte *password = NULL;
            ubyte4 pwd_len = 0;

            if (OK > (status = EAP_getIdentity(pxEap->pSession, g_ikeEapInstId,
                                               &identity, &id_len)))
                goto exit;

            if (NULL == m_ikeSettings.funcPtrLookupSecret)
            {
                status = ERR_IKE_CONFIG;
                goto exit;
            }
            if (OK > (status = m_ikeSettings.funcPtrLookupSecret(
                                                 identity, id_len,
                                                 &password, &pwd_len,
                                                 pxEap->pxSa->serverInstance)))
                goto fail;

            /* process response */
            status = EAP_LEAP_processAuth(pxEap->pCbData, code, data, len,
                                          password, (ubyte2)pwd_len,
                                          &sendCode, &reqData, &eapReqLen);

            if (NULL != m_ikeSettings.funcPtrReleaseSecret)
                m_ikeSettings.funcPtrReleaseSecret(password, pwd_len,
                                                   pxEap->pxSa->serverInstance);

            if ((OK > status) || !sendCode)
                goto fail; /* Send FAILURE */

            if (EAP_CODE_SUCCESS == sendCode)
            {
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
                methodType = EAP_TYPE_LEAP;
                decision = EAP_METHOD_DECISION_CONTINUE;
                methodState = EAP_METHOD_STATE_CONTINUE;
                freebuffer = 1;
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

    if ((OK == status) &&
        (EAP_TYPE_LEAP == methodType && EAP_CODE_RESPONSE == sendCode))
    {
        if (OK > (status = EAP_setMethodStateDecision(
                                pxEap->pSession, g_ikeEapInstId,
                                EAP_METHOD_STATE_END,
                                EAP_METHOD_DECISION_SUCCESS)))
            goto exit;

        /* get MSK */
        status = EAP_LEAP_getKey((ubyte *) pxEap->pCbData,
                                 pxEap->poMsk, LEAP_KEY_LEN);
    }

exit:
    return status;
} /* EAP_LEAP_AuthReceivePktCallback */


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
        "IKE_EAP_LEAP_AUTH",
        EAP_LEAP_AuthReceivePktCallback,
        NULL,
        IKE_eapReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapLEAPauthSuite =
{
    EAP_LEAP_AuthInitFunc,
    EAP_LEAP_AuthDelFunc,
    &methodDef,
    EAP_SESSION_TYPE_AUTHENTICATOR,
#ifdef __ENABLE_IKE_EAP_ONLY__
    TRUE
#endif
};


#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_LEAP__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

