/**
 * @file  ike2_eap_perp_auth.c
 * @brief IKEv2 IKEv2 EAP-PERP Authenticator
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
 *     +   \c \__ENABLE_DIGICERT_EAP_PERP__
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
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_PERP__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/md5.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_perp.h"

#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike2/ike2_eap.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_state.h"

#define _I 0
#define _R 1


/*------------------------------------------------------------------*/

extern ubyte4 g_ikeEapInstId; /* EAP instance */
extern ikeSettings m_ikeSettings;
extern IKE_MUTEX g_ikeMtx;


/*------------------------------------------------------------------*/

static MSTATUS
EAP_PERP_AuthInitFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;
    return status;
}


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

    /* set identity */
    pos = data + sizeof(eapHdr_t) + 1;
    id_len = len - sizeof(eapHdr_t) - 1;
    EAP_setIdentity(pxEap->pSession, g_ikeEapInstId, pos, id_len);

    return status;
}


/*------------------------------------------------------------------*/
/*
 *This function will be called to process EAP-PERP messages
 *
 */

static MSTATUS
EAP_PERP_AuthReceivePktCallback(ubyte *appSessionHdl,
                                eapMethodType type,
                                eapCode code, ubyte id,
                                ubyte *data, ubyte4 len,
                                ubyte *opaque_data)
{
    MSTATUS status = OK;
    ubyte4 eapReqLen = 0;
    intBoolean sendReq = FALSE;
    ubyte *reqData = NULL;
    eapMethodType methodType = 0;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = 0;
    eapCode sendCode = 0;
    intBoolean freebuffer = FALSE;
    IKE2EAP pxEap = (IKE2EAP)appSessionHdl;
    IKE_EAPPERP_requestData *pEapperpData = NULL;

    MOC_UNUSED(opaque_data);

    switch (code)
    {
        case EAP_CODE_RESPONSE :
        case EAP_CODE_REQUEST :
        case EAP_CODE_SUCCESS :
        case EAP_CODE_FAILURE :
             break;
        default:
        {
            /* We have received any invalid code as response */
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, "Invalid EAP Code", status);
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

            /* Send Initial Perp request to client */
            status = EAP_Perp_request_auth(appSessionHdl, &reqData, &eapReqLen);

            if (OK == status && eapReqLen != 0)
            {
                methodType = EAP_TYPE_PERP;
                sendCode = EAP_CODE_REQUEST;
                methodState = EAP_METHOD_STATE_PROPOSED;
                decision = EAP_METHOD_DECISION_CONTINUE;
                sendReq = TRUE;
                freebuffer = TRUE;
            }
            break;
        }

        case EAP_TYPE_NOTIFICATION :
        {
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, " received EAP_TYPE_NOTIFICATION ");
            methodType = EAP_TYPE_NOTIFICATION;
            break;
        }

        case EAP_TYPE_PERP :
        {
            data =data+1;

            if (NULL == (pEapperpData = MALLOC(sizeof(IKE_EAPPERP_requestData))))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            DIGI_MEMSET((ubyte *)pEapperpData, 0x00, sizeof(IKE_EAPPERP_requestData));

            if (pxEap && pxEap->pxSa && pxEap->pxXg)
            {
                /* Save the required information to retrive sa in callback */
                pEapperpData->ikeSaId = pxEap->pxSa->dwId;
                pEapperpData->ikeSaLoc = pxEap->pxSa->loc;
                pEapperpData->dwMsgId = pxEap->pxXg->dwMsgId;
                pEapperpData->pSession = pxEap->pxSa->u.v2.eapState.pSession;
            }
            else
            {
                status = ERR_NULL_POINTER;
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, "Null sa in eap perp session ");
                goto exit;
            }

            status = EAP_Perp_process_auth((ubyte *)pEapperpData, data);

            if (OK == status)
            {
                sendCode = EAP_CODE_SUCCESS;
                decision = EAP_METHOD_DECISION_SUCCESS;
                methodState = EAP_METHOD_STATE_END;
                sendReq = TRUE;
                freebuffer = TRUE;
            }
            else if (STATUS_IKE_PENDING == status)
            {
                pxEap->pxXg->x_flags |= IKE_XCHG_FLAG_PENDING;
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, "AAA Processing perp response ");
                goto exit;
            }
            else
            {
                DEBUG_ERROR(DEBUG_EAP_MESSAGE, "Processing perp response failed", status);
                goto fail;
            }

            break;
        }

        case EAP_TYPE_NAK :
        {
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, " received EAP_TYPE_NAK ");
            break;
        }

        case EAP_TYPE_EXPANDED :
        {
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, " received EAP_TYPE_EXPANDED ");
            break;
        }

        default:
        {
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, " received Invalid EAP response code ");
            break;
        }
    }

    goto send;

fail:
    /* Send FAILURE */
    sendCode = EAP_CODE_FAILURE;
    decision = EAP_METHOD_DECISION_FAILURE;
    methodState = EAP_METHOD_STATE_END;
    sendReq = TRUE;

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
}


/*------------------------------------------------------------------*/

extern sbyte4
IKEv2_Eapperp_auth_Callback(ubyte *appSessionHdl, const sbyte *perp, ubyte cfgType, ubyte2 Status)
{
    MSTATUS status = OK;
    struct ike_context ctx = { NULL };
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = 0;
    eapCode sendCode = 0;
    IKESA pxSa = NULL;
    ubyte4 len=0;
    struct ike2eap *pxEap = NULL;
    IKE2XG pxXg = NULL;
    IKE_EAPPERP_requestData *pEapperpData = NULL;

    IKE_LOCK_W;

    if (appSessionHdl)
    {
        pEapperpData = (IKE_EAPPERP_requestData *)appSessionHdl;
    }
    else
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "connection  handle from AAA is NULL = ",status);
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = IKE_getSaById(pEapperpData->ikeSaId,
                           pEapperpData->ikeSaLoc,
                           &pxSa);
    if (OK > status || NULL == pxSa)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "ikesa not found status = ",status);
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pxEap = &(pxSa->u.v2.eapState);

    if (!pxEap ||
        (NULL == (pxSa = (struct ikesa *) pxEap->pxSa))||
        (NULL == (pxXg = (IKE2XG) pxEap->pxXg)))
    {
        status = ERR_NULL_POINTER;
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "NUll pointers= ",status);
        goto exit;
    }

    if (pxEap->pSession != pEapperpData->pSession)
    {
        status = ERR_MISSING_STATE_CHANGE;
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "Eap session did not match ",status);
        goto exit;
    }

    /* sanity check */
    if (!(IS_VALID(pxSa) && IS_IKE2_SA(pxSa) &&
          MSGID_VALID(pxXg, pEapperpData->dwMsgId)))
    {
        status = ERR_EAP;
        goto exit;
    }

    switch (cfgType)
    {
    case CFG_SET :
        /* Need to build an CFG_SET, STATUS = OK or FAIL, based on AAA result */

        pxSa->flags |= IKE_SA_FLAG_EAP_DONE;
        /* overloading 'authType' for auth result! */
        if (XAUTH_STATUS_OK == Status)
        {
            pxSa->merror = OK; /* jic */
            sendCode = EAP_CODE_SUCCESS;
            decision = EAP_METHOD_DECISION_SUCCESS;
            methodState = EAP_METHOD_STATE_END;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, "Perp authentication passed", status);
        }
        else
        {
            pxSa->merror = ERR_IKE_XAUTH_FAILED;
            sendCode = EAP_CODE_FAILURE;
            decision = EAP_METHOD_DECISION_FAILURE;
            methodState = EAP_METHOD_STATE_END;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, "Perp authentication failed ", status);
        }
        break;

    case CFG_REQUEST :
        /* (Multiple) CFG_REQUEST/REPLY exchanges */
        sendCode = EAP_CODE_REQUEST;
        methodState = EAP_METHOD_STATE_PROPOSED;
        decision = EAP_METHOD_DECISION_CONTINUE;
        break;

    default :
        status = ERR_IKE_XAUTH_INVALID_CFG_TYPE;
        goto exit;
    }

    if (perp != NULL)
        len = DIGI_STRLEN((const sbyte *)perp);

    pxEap->pxXg->x_flags &= ~(IKE_XCHG_FLAG_PENDING);

    if (OK > (status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                      EAP_TYPE_PERP, sendCode,
                                      methodState,
                                      decision,
                                      (ubyte*)perp,len)))
    {
        //DB_STATUS
    }
    else if (!pxEap->pxMsg) /* jic */
    {
        status = ERR_EAP;
    }
    pxSa->merror = status;

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP transmit failed ", status);
        ctx.wMsgType = AUTHENTICATION_FAILED;
    }

    ctx.pxSa = pxSa;
    ctx.pxXg = pxEap->pxXg;
    status = IKE2_xchgOut(&ctx);

exit:
    if (pEapperpData)
    {
        FREE(pEapperpData);
    }
    IKE_UNLOCK_W;
    return (sbyte4)status;
} /* IKEv2_Eapperp_auth_Callback */


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
        EAP_TYPE_PERP,
        "IKE_EAP_PERP_AUTH",
        EAP_PERP_AuthReceivePktCallback,
        NULL,
        IKE_eapReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapPERPauthSuite =
{
    EAP_PERP_AuthInitFunc,
    NULL,
    &methodDef,
    EAP_SESSION_TYPE_AUTHENTICATOR
};


#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_PERP__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */
