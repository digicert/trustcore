/**
 * @file  ike2_eap_perp_peer.c
 * @brief IKEv2 IKEv2 EAP-PERP Peer
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
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
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_PERP__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../crypto/ca_mgmt.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_md5.h"

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

typedef struct appCtrlBlk_t
{
    ubyte               allowed_methods[EAP_MAX_METHODS];
    ubyte4              allowed_method_count;

    eapExpandedMethod_t expanded_methods[EAP_MAX_METHODS];
    ubyte4              expanded_method_count;

} appCtrlBlk;


/*------------------------------------------------------------------*/

static MSTATUS
EAP_PERP_PeerReceivePktCallback(ubyte *appSessionHdl,
                                eapMethodType type,
                                eapCode code, ubyte id,
                                ubyte *data, ubyte4 len,
                                ubyte *opaque_data)
{
    MSTATUS status = OK;
    ubyte *eapResponse = NULL;
    ubyte4 eapRespLen = 0;
    intBoolean sendResponse = FALSE;
    intBoolean freebuffer = FALSE;
    eapMethodType methodType = 0;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = EAP_METHOD_DECISION_NONE;
    IKE_EAPPERP_requestData *pEapperpData = NULL;
    struct ike2eap *pxEap = (struct ike2eap *)appSessionHdl;
    appCtrlBlk *cb = (appCtrlBlk *) pxEap->pCbData;

    MOC_UNUSED(opaque_data);

    switch (code)
    {
        case EAP_CODE_REQUEST :
            break;
        case EAP_CODE_SUCCESS :
        case EAP_CODE_FAILURE :
            /* delete session */
            goto exit;
        case EAP_CODE_RESPONSE :
        default :
        {
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
            /* Build IDENTITY response */
            methodType =  EAP_TYPE_IDENTITY;

            if ((pxEap->pxSa) && (pxEap->pxSa->ikePeerConfig) &&
                (pxEap->pxSa->ikePeerConfig->eapIdentity))
            {
                eapRespLen = DIGI_STRLEN(pxEap->pxSa->ikePeerConfig->eapIdentity);
            }
            else
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            eapResponse = (ubyte *) MALLOC(eapRespLen);
            if (NULL == eapResponse)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            DIGI_MEMCPY(eapResponse, pxEap->pxSa->ikePeerConfig->eapIdentity, eapRespLen);
            methodState = EAP_METHOD_STATE_CONT;
            decision = EAP_METHOD_DECISION_FAIL;
            sendResponse = TRUE;
            freebuffer = TRUE;
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
            data = data+1;
            if (NULL == (pEapperpData = MALLOC(sizeof(IKE_EAPPERP_requestData))))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            DIGI_MEMSET((ubyte *)pEapperpData,0x00,sizeof(IKE_EAPPERP_requestData));

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
            status = EAP_Perp_process_peer((ubyte *)pEapperpData, data,
                                           &eapResponse,&eapRespLen);
            methodType = EAP_TYPE_PERP;

            if (OK == status && eapRespLen != 0)
            {
                sendResponse = TRUE;
                methodState = EAP_METHOD_STATE_DONE;
                decision = EAP_METHOD_DECISION_UNCOND_SUCC;
                freebuffer = TRUE;
            }
            break;
        }

        case EAP_TYPE_EXPANDED :
        {
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, " received EAP_TYPE_EXPANDED ");
            break;
        }

        default :
        {
            /* send NAK response */
            status = EAP_buildNAK(pxEap->pSession, g_ikeEapInstId,
                                  cb->allowed_methods,
                                  cb->allowed_method_count,
                                  &eapResponse, &eapRespLen);
            if (OK == status)
            {
                methodType = EAP_TYPE_NAK;
                decision = EAP_METHOD_DECISION_FAIL;
                sendResponse = TRUE;
                freebuffer = TRUE;
            }

            if (status == STATUS_IKE_PENDING)
                goto exit;

            break;
        }
    }

    if (sendResponse)
    {
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
    if (status == STATUS_IKE_PENDING)
    {
        pxEap->pxXg->x_flags |= (IKE_XCHG_FLAG_PENDING);
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_PERP_PeerInitFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;
    appCtrlBlk *cb;

    if (NULL == (cb = (appCtrlBlk *)
                 (pxEap->pCbData = MALLOC(sizeof(appCtrlBlk)))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    cb->allowed_methods[0] = EAP_TYPE_PERP;
    cb->allowed_method_count = 1;
    cb->expanded_methods[0].method_type[3] = EAP_TYPE_PERP;
    cb->expanded_method_count = 1;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
IKEv2_EapperpCallback(ubyte *appSessionHdl, const sbyte *perp)
{
    MSTATUS status = OK;
    struct ike_context ctx = { NULL };
    struct ike2eap *pxEap = (struct ike2eap *)appSessionHdl;
    struct ikesa *pxSa = NULL;
    appCtrlBlk *cb = NULL;
    struct eapMsgHdr eapHdr;
    IKE2XG pxXg = NULL;
    IKE_EAPPERP_requestData *pEapperpData = NULL;
    sbyte4 i;

    IKE_LOCK_W;

    if (appSessionHdl)
    {
        pEapperpData = (IKE_EAPPERP_requestData *)appSessionHdl;
    }
    else
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "connection  handle from AAA is NULL = ", status);
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = IKE_getSaById(pEapperpData->ikeSaId,
                           pEapperpData->ikeSaLoc,
                           &pxSa);
    if (OK > status || NULL == pxSa)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "ikesa not found status = ", status);
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pxEap = &(pxSa->u.v2.eapState);

    if (!pxEap ||
        (NULL == (cb = (appCtrlBlk *) pxEap->pCbData)) ||
        (NULL == (pxSa = (struct ikesa *) pxEap->pxSa))||
        (NULL == (pxXg = (IKE2XG) pxEap->pxXg)))
    {
        status = ERR_NULL_POINTER;
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "NUll pointers= ", status);
        goto exit;
    }

    if (pxEap->pSession != pEapperpData->pSession)
    {
        status = ERR_MISSING_STATE_CHANGE;
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "Eap session did not match ", status);
        goto exit;
    }

    /* sanity check */
    if (!(IS_VALID(pxSa) && IS_IKE2_SA(pxSa) &&
          MSGID_VALID(pxXg,pEapperpData->dwMsgId)))
    {
        status = ERR_EAP;
        goto exit;
    }

    pxSa->merror = OK;
    pxEap->pxXg->x_flags &= ~(IKE_XCHG_FLAG_PENDING);

    if (OK > (status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                      EAP_TYPE_PERP, EAP_CODE_RESPONSE,
                                      EAP_METHOD_DECISION_CONTINUE,
                                      EAP_METHOD_STATE_DONE,
                                      perp, DIGI_STRLEN(perp)+1)))
    {
        //DBG_STATUS
    }
    else if (!pxEap->pxMsg) /* jic */
    {
        status = ERR_EAP;
    }

    /* output IKE2+EAP message to peer */
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP transmit failed ", status);
        ctx.wMsgType = AUTHENTICATION_FAILED;
        IKE2_delSa(pxSa, FALSE, status);
        goto exit;
    }

    pxXg = pxEap->pxXg;

    /* prepare for next exchange */
    for (i=0; i < pxXg->numMsgs; i++)
    {
        if (pxXg->poMsg[i])
        {
            FREE(pxXg->poMsg[i]);
            pxXg->dwMsgLen[i] = 0;
            pxXg->poMsg[i] = NULL;
        }
    }
    pxXg->numMsgs = 0;

    for (i=0; i < pxXg->numIcvs; i++)
    {
        if (pxXg->poIcv[i])
        {
            FREE(pxXg->poIcv[i]);
            pxXg->poIcv[i] = NULL;
        }
#ifdef __ENABLE_IKE_FRAGMENTATION__
        if (pxXg->poEfBody[i])
        {
            FREE(pxXg->poEfBody[i]);
            pxXg->poEfBody[i] = NULL;
            pxXg->wEfBodyLen[i] = 0;
        }
#endif
    }
    pxXg->numIcvs = 0;

    /* advance msg ID !!! */
    pxXg->dwMsgId = ++(pxSa->u.v2.dwMsgId[_I]);

    ctx.pxSa = pxSa;
    ctx.pxXg = pxXg;
    status = IKE2_xchgOut(&ctx);

exit:
    IKE_UNLOCK_W;
    return (sbyte4)status;
} /* IKEv2_EapperpCallback */


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
        "IKE_EAP_PERP_PEER",
        EAP_PERP_PeerReceivePktCallback,
        NULL,
        IKE_eapReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapPERPpeerSuite =
{
    EAP_PERP_PeerInitFunc,
    NULL,
    &methodDef,
    EAP_SESSION_TYPE_PEER
};

#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_PERP__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */
