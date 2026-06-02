/**
 * @file  ike2_eap_gtc_auth.c
 * @brief IKEv2 IKEv2 EAP-GTC Authenticator
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flag must be defined in
 *     moptions.h:
 *    +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *   Additionally, the following flags must be defined:
 *    +   \c \__ENABLE_DIGICERT_EAP_AUTH__
 *    +   \c \__ENABLE_DIGICERT_EAP_GTC__
 *    +   \c \__DISABLE_DIGICERT_IKE_EAP__ must not be defined.
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
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_GTC__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_gtc.h"

#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike2/ike2_eap.h"


/*------------------------------------------------------------------*/

extern ubyte4 g_ikeEapInstId; /* EAP instance */
extern ikeSettings m_ikeSettings;

sbyte *m_pIkeEapGtcMsg = (sbyte *)"Please enter the PIN + token code";


/*------------------------------------------------------------------*/

static MSTATUS
authProcessIdentityResponse(struct ike2eap *pxEap,
                            ubyte *data, ubyte4 len,
                            eapMethodType *method_type,
                            ubyte **reqData, ubyte4 *reqLen)
{
    MSTATUS  status = OK;

    ubyte*   pos;
    ubyte4   id_len;
    ubyte*   identity;
    sbyte*   msg = m_pIkeEapGtcMsg ? m_pIkeEapGtcMsg : (sbyte*)"";
    ubyte4   msgLen = DIGI_STRLEN(msg);

    /* set identity */
    pos = data + sizeof(eapHdr_t) + 1;
    id_len = len - sizeof(eapHdr_t) - 1;
    EAP_setIdentity(pxEap->pSession, g_ikeEapInstId, pos, id_len);
    EAP_getIdentity(pxEap->pSession, g_ikeEapInstId, &identity, &id_len);

    /* TBD : map identity to method */

    /* send method (gtc) request */
#ifdef TEST_EXPANDED_FORMAT
    ubyte*   eapRequest;
    ubyte4   eapReqLen;

    /*allocate space for vendor id & type */
    eapReqLen = msgLen + 7;/*GTC_DIGESTSIZE + 8*/
    if (NULL == (eapRequest = (ubyte *) MALLOC(eapReqLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    pos = eapRequest;
    *pos++ = 0;
    *pos++ = 0;
    *pos++ = EAP_VENDOR_ID_IETF;
    DIGI_HTONL(pos, EAP_TYPE_GTC);
    pos += 4;
    /* *pos = msgLen;*/
    DIGI_MEMCPY(pos/* + 1*/, m_ikeEapGtcMsg, msgLen);

    *reqData = eapRequest;
    *reqLen = eapReqLen;
    *method_type = EAP_TYPE_EXPANDED;
#else
    if (OK > (status = EAP_GTCstartRequest((ubyte *)pxEap,
                                           (ubyte *)msg, msgLen,
                                           reqData, reqLen)))
        goto exit;

    *method_type = EAP_TYPE_GTC;
#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_GTC_AuthReceivePktCallback(ubyte *appSessionHdl,
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

    sbyte4 cmp;
    ubyte *identity = NULL;
    ubyte4 id_len = 0;
    ubyte *password = NULL;
    ubyte4 pwd_len = 0;

    struct ike2eap *pxEap = (struct ike2eap *)appSessionHdl;

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
                                                 &methodType,
                                                 &reqData, &eapReqLen);
            if (OK == status && eapReqLen != 0)
            {
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

        case EAP_TYPE_GTC :
        {
            if (OK > (status = EAP_getIdentity(pxEap->pSession, g_ikeEapInstId,
                                               &identity, &id_len)))
                goto exit;

            if (NULL != m_ikeSettings.funcPtrVerifyPassword)
            {
                if (OK > (status = m_ikeSettings.funcPtrVerifyPassword(
                                                  identity, id_len,
                                                  data + 1, len - 1,
                                                  pxEap->pxSa->serverInstance)))
                    goto fail;

                DIGI_MEMSET(data + 1, 0x0, len - 1);

                /* send SUCCESS */
                sendCode = EAP_CODE_SUCCESS;
                decision = EAP_METHOD_DECISION_SUCCESS;
                methodState = EAP_METHOD_STATE_END;
                sendReq = 1;
                break;
            }

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

            /* process gtc response */
            status = EAP_GTCProcessAuth(appSessionHdl,
                                        data, len,
                                        password, pwd_len,
                                        &cmp);

            if (NULL != m_ikeSettings.funcPtrReleaseSecret)
                m_ikeSettings.funcPtrReleaseSecret(password, pwd_len,
                                                   pxEap->pxSa->serverInstance);

            if ((OK > status) || cmp)
                goto fail; /* Send FAILURE */

            /* send SUCCESS */
            sendCode = EAP_CODE_SUCCESS;
            decision = EAP_METHOD_DECISION_SUCCESS;
            methodState = EAP_METHOD_STATE_END;
            sendReq = 1;

            break;
        }

        case EAP_TYPE_NAK :
        {
            /* check for additional methods */
            break;
        }

        case EAP_TYPE_EXPANDED :
        {
            ubyte4 expVendorId = DIGI_NTOHL(data) & 0x00ffffff;
            ubyte4 expMethodId = DIGI_NTOHL(data + 4);

            if ((EAP_VENDOR_ID_IETF == expVendorId) &&
                (EAP_TYPE_GTC == expMethodId))
            {
                if (OK > (status = EAP_getIdentity(pxEap->pSession,
                                                   g_ikeEapInstId,
                                                   &identity, &id_len)))
                    goto exit;

                if (NULL != m_ikeSettings.funcPtrVerifyPassword)
                {
                    if (OK > (status = m_ikeSettings.funcPtrVerifyPassword(
                                               identity, id_len,
                                               data + 8, len - 8,
                                               pxEap->pxSa->serverInstance)))
                        goto fail;

                    DIGI_MEMSET(data + 8, 0x0, len - 8);

                    /* send SUCCESS */
                    sendCode = EAP_CODE_SUCCESS;
                    decision = EAP_METHOD_DECISION_SUCCESS;
                    methodState = EAP_METHOD_STATE_END;
                    sendReq = 1;
                    break;
                }

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

                /* process gtc response */
                status = EAP_GTCProcessAuth(appSessionHdl,
                                            data + 7, len - 7,
                                            password, pwd_len,
                                            &cmp);

                if (NULL != m_ikeSettings.funcPtrReleaseSecret)
                    m_ikeSettings.funcPtrReleaseSecret(password, pwd_len,
                                                 pxEap->pxSa->serverInstance);

                if ((OK > status) || cmp)
                    goto fail; /* Send FAILURE */

                /* send SUCCESS */
                sendCode = EAP_CODE_SUCCESS;
                decision = EAP_METHOD_DECISION_SUCCESS;
                methodState = EAP_METHOD_STATE_END;
                sendReq = 1;
            }
            break;
        }

        default:
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
} /* EAP_GTC_AuthReceivePktCallback */


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
        "IKE_EAP_GTC_AUTH",
        EAP_GTC_AuthReceivePktCallback,
        NULL,
        IKE_eapReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapGTCauthSuite =
{
    NULL,
    NULL,
    &methodDef,
    EAP_SESSION_TYPE_AUTHENTICATOR,
#ifdef __ENABLE_IKE_EAP_ONLY__
    FALSE
#endif
};


#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_GTC__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

