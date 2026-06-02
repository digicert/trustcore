/**
 * @file  ike2_eap_radius_passthru.c
 * @brief IKEv2 IKEv2 EAP RADIUS Passthrough
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
 *     +   \c \__ENABLE_DIGICERT_EAP_RADIUS__
 *     +   \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
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
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../crypto/ca_mgmt.h"

#ifdef __IKE_MULTI_THREADED__
#ifdef __WIN32_RTOS__
#pragma message ("RADIUS code is not thread-safe!")
#else
#warning "RADIUS code is not thread-safe!"
#endif
#endif
#include "../radius/radius.h"
#include "../radius/radius_req.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_radius.h"
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
#include "../eap/eap_ttls.h"
#endif
#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_state.h"
#include "../ike/ikesa.h"
#include "../ike2/ike2_eap.h"


/*------------------------------------------------------------------*/

extern ikeSettings m_ikeSettings;
extern ubyte4 g_ikeEapInstId; /* EAP instance */
extern IKE_MUTEX g_ikeMtx;


/*------------------------------------------------------------------*/

sbyte4 g_ikeRadInstId = 0;  /* RADIUS Client instance */


#define IKE_EAP_NAS_PORT        5
#define IKE_EAP_NAS_PORT_TYPE   19 /* IEEE 802.11 */


/*------------------------------------------------------------------*/

#define DBG_ERRCODE(_s) debug_print_status((sbyte *)__FILE__, __LINE__, (sbyte4)(_s));
#define DBG_STATUS      DBG_ERRCODE(status)
#define DBG_EXIT        { DBG_STATUS goto exit; }
#define DBG_DONE        { DBG_STATUS goto done; }


/*------------------------------------------------------------------*/

typedef struct appCtrlBlk_t
{
    sbyte4 radiusSvrId;
    //MOC_IP_ADDRESS radiusSvrrAddr;

    RADIUS_RqstRecord *pRadiusReq;

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    /* see 'appTtlsCtrlBlk' in "ike2_eap_ttls_auth.c" */
    ubyte *ttls_connection;
#endif

} appCtrlBlk;


/*------------------------------------------------------------------*/

static MSTATUS
EAP_RADIUS_PassthruInitFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    appCtrlBlk *cb = NULL;

    if (NULL == pxEap) /* jic */
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* allocate */
    if (NULL == (cb = (appCtrlBlk *) MALLOC(sizeof(appCtrlBlk))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)cb, 0x00, sizeof(appCtrlBlk));

    /* done */
    pxEap->pCbData = cb;
    cb = NULL;

exit:
    if (cb) FREE(cb);
    return status;
} /* EAP_RADIUS_PassthruInitFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_RADIUS_PassthruDelFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    appCtrlBlk *cb;
    if (NULL != (cb = (appCtrlBlk *) pxEap->pCbData))
    {
        if (cb->pRadiusReq)
            RADIUS_requestRelease(&cb->pRadiusReq);
        pxEap->pCbData = NULL;
        FREE(cb);
    }

    return status;
} /* EAP_RADIUS_PassthruDelFunc */


/*------------------------------------------------------------------*/

static MSTATUS
passthruProcessIdentityResponse(struct ike2eap *pxEap,
                                ubyte *data, ubyte4 len)
{
    MSTATUS  status = OK;

    ubyte*   pos;
    ubyte4   id_len;
    ubyte*   identity;

    appCtrlBlk *cb = (appCtrlBlk *) pxEap->pCbData;
    struct ikesa *pxSa = pxEap->pxSa;

    /* set identity */
    pos = data + sizeof(eapHdr_t) + 1;
    id_len = len - sizeof(eapHdr_t) - 1;
    EAP_setIdentity(pxEap->pSession, g_ikeEapInstId, pos, id_len);
    EAP_getIdentity(pxEap->pSession, g_ikeEapInstId, &identity, &id_len);

    /* get RADIUS server */
    if (cb->radiusSvrId) goto exit; /* jic */

    if (NULL == m_ikeSettings.funcPtrIkeGetRadSvrId)
    {
        status = ERR_IKE_CONFIG;
        goto exit;
    }
    status = m_ikeSettings.funcPtrIkeGetRadSvrId(&cb->radiusSvrId, g_ikeRadInstId,
                                                 identity, id_len,
                                                 REF_MOC_IPADDR(pxSa->dwPeerAddr)
                                                 MOC_MTHM_REQ_VALUE(pxSa->serverInstance));

    if (OK <= status)
        status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_RADIUS_ReceivePktCallback(ubyte *appSessionHdl,
                              eapMethodType type,
                              eapCode code, ubyte id,
                              ubyte *data, ubyte4 len,
                              ubyte *opaque_data)
{
    MSTATUS status = OK;

    struct ike2eap *pxEap = (struct ike2eap *)appSessionHdl;
    appCtrlBlk *cb = (appCtrlBlk *) pxEap->pCbData;
    struct ikesa *pxSa = pxEap->pxSa;

    RADIUS_ServerRecord *pServer;

    MOC_UNUSED(id);
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
/*          DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte *)"Invalid EAP Code", status);*/
            break;
        }
    }

    if (OK != status)
        goto exit;

    switch (type)
    {
    case EAP_TYPE_NONE :
        /* set error code */
        status = ERR_EAP_INVALID_METHOD_TYPE;
        break;
    case EAP_TYPE_IDENTITY :
        status = passthruProcessIdentityResponse(pxEap, data, len);
        break;
    default :
        break;
    }

    if (OK != status)
        goto exit;

    if (OK > (status = RADIUS_getServerRecordFromID(cb->radiusSvrId, &pServer)))
        goto exit;

    status = EAP_radiusEncapsulate(pxEap->pSession, g_ikeEapInstId,
                                   cb->radiusSvrId,
                                   REF_MOC_IPADDR(pxSa->dwHostAddr),
                                   IKE_EAP_NAS_PORT, IKE_EAP_NAS_PORT_TYPE,
                                   pServer->sharedSecret,
                                   pServer->sharedSecretLength,
                                   data,
                                   &cb->pRadiusReq);
    if (OK > status) goto exit;

    RADIUS_setRequestUserCookie(cb->pRadiusReq, pxEap);
    status = RADIUS_requestSend(cb->pRadiusReq);

exit:
    return status;
} /* EAP_RADIUS_ReceivePktCallback */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_radRecv(MOC_IP_ADDRESS srcAddr, ubyte2 wSrcPort,
            ubyte *pBuffer, ubyte4 dwBufferSize,
            sbyte4 serverId)
{
    MSTATUS status;

    struct ike_context ctx = { NULL };

    RADIUS_RqstRecord *pRqst = NULL;
    RADIUS_RESULT      result;

    ubyte *newEapReq = NULL;
    ubyte4 newEapReqLen = 0;

    struct ike2eap *pxEap;
    struct ikesa *pxSa;
    appCtrlBlk *cb;

    struct eapMsgHdr *eapHdr;

    MOC_UNUSED(srcAddr);

    IKE_LOCK_W;

    if (OK > (status = (MSTATUS) RADIUS_responseCallback(serverId, wSrcPort,
                                                         pBuffer, dwBufferSize,
                                                         &pRqst, &result)))
        DBG_EXIT

    switch (result)
    {
        case RADIUS_FOUND:
        case RADIUS_RETRIES_EXCEEDED:
            break;
        case RADIUS_NOT_FOUND:
            status = ERR_RADIUS_REQUEST_NOT_FOUND;
            break;
        default:
            status = ERR_RADIUS_BAD_RESPONSE;
            break;
    }

    if (OK > status) DBG_EXIT

    if (NULL == pRqst) /* jic */
    {
        status = ERR_NULL_POINTER;
        DBG_EXIT
    }

    /* get our Cookie */
    /* is this safe? what if the IKE session was timed out and its data freed? */
    if ((NULL == (pxEap = (struct ike2eap *) RADIUS_getRequestUserCookie(pRqst))) ||
        (NULL == (pxSa = (struct ikesa *) pxEap->pxSa)) ||
        (NULL == (cb = (appCtrlBlk *) pxEap->pCbData)))
    {
        /*RADIUS_requestRelease(&pRqst);*/
        status = ERR_NULL_POINTER;
        DBG_EXIT
    }

    if (!IS_VALID(pxSa) ||
        !IS_IKE2_SA(pxSa) ||
        (pxEap != &pxSa->u.v2.eapState))
    {
        /*RADIUS_requestRelease(&pRqst);*/
        status = ERR_IKE_GETSA_FAIL;
        DBG_EXIT
    }

    /* sanity check */
    if ((pRqst != cb->pRadiusReq) ||
        (serverId != cb->radiusSvrId))
    {
        /*RADIUS_requestRelease(&pRqst);*/
        status = ERR_RADIUS;
        DBG_EXIT
    }

    /* extract EAP message (from RADIUS server) */
    if (RADIUS_FOUND == result)
    {
        RADIUS_ServerRecord *pServer;

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
        if (EAP_PROTO_TTLS == pxEap->proto)
        {
            status = EAP_TTLSProcessRadiusAuthResponse(cb->ttls_connection, pRqst);
            goto done;
        }
#endif
        if (OK > (status = RADIUS_getServerRecordFromID(serverId, &pServer)))
            DBG_DONE

        if (OK > (status = EAP_radiusDecapsulate(pxEap->pSession, g_ikeEapInstId,
                                                 pServer->sharedSecret,
                                                 pServer->sharedSecretLength,
                                                 pRqst,
                                                 &newEapReq, &newEapReqLen)))
            DBG_DONE

        if (NULL == newEapReq)
        {
            status = ERR_NULL_POINTER;
            DBG_DONE
        }

        /* get MSK */
        eapHdr = (struct eapMsgHdr *)newEapReq;
        if (EAP_CODE_SUCCESS == eapHdr->oCode)
        {
            ubyte *sendKey, *recvKey;
            ubyte4 sendKeyLen, recvKeyLen, mskLen = 0;

            if (OK > (status = EAP_radiusGetMPPEKeys(
                                        pxEap->pSession, g_ikeEapInstId,
                                        &sendKey, &sendKeyLen,
                                        &recvKey, &recvKeyLen)))
                DBG_DONE

            if (0 != (mskLen = sendKeyLen + recvKeyLen))
            {
                sbyte4 recvPad=0, sendPad=0;
                ubyte *poMsk;

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
                ubyte4 i;
                DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"MPPE_Send (");
                DEBUG_UINT(DEBUG_IKE_MESSAGES, sendKeyLen);
                DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)") = ");
                for (i=0; i < sendKeyLen; i++)
                    DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, sendKey[i]);
                DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");

                DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"MPPE_Recv (");
                DEBUG_UINT(DEBUG_IKE_MESSAGES, recvKeyLen);
                DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)") = ");
                for (i=0; i < recvKeyLen; i++)
                    DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, recvKey[i]);
                DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");
#endif
                /* Note: The following code for MSK is experimental!!! */
                if (64 > mskLen)
                {
                    recvPad = (64 - mskLen) / 2;
                    sendPad = 64 - (mskLen + recvPad);
                    mskLen = 64;
                }

                if (NULL == (pxEap->poMsk = (ubyte *) MALLOC(mskLen)))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    DBG_DONE
                }
                poMsk = pxEap->poMsk;
                /* Strongswan or Win2008 server: use the following MSK format */
                /* MSK = MasterReceiveKey + MasterSendKey + 32 bytes zeroes (padding) */
                DIGI_MEMCPY(poMsk, recvKey, recvKeyLen);
                poMsk += recvKeyLen;
                DIGI_MEMCPY(poMsk, sendKey, sendKeyLen);
                poMsk += sendPad;
                DIGI_MEMSET(poMsk, 0x00, (recvPad+sendPad));
                pxEap->dwMskLen = mskLen;

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
                DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"MSK (");
                DEBUG_UINT(DEBUG_IKE_MESSAGES, pxEap->dwMskLen);
                DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)") = ");
                for (i=0; i < pxEap->dwMskLen; i++)
                    DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, pxEap->poMsk[i]);
                DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");
#endif
            }
#ifdef __ENABLE_IKE_EAP_ONLY__
            else if (IKE_SA_FLAG_EAP_ONLY & pxSa->flags)
            {
                /* EAP-only auth must generate a PSK; see RFC5998 3. p.6 */
                status = ERR_IKE_BAD_AUTH;
                DBG_DONE
            }
#endif
        }

        if (OK > (status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                          EAP_TYPE_NONE, EAP_CODE_REQUEST,
                                          EAP_METHOD_DECISION_NONE,
                                          EAP_METHOD_STATE_INIT,
                                          newEapReq, newEapReqLen)))
            DBG_DONE
    }
    else /* if (RADIUS_RETRIES_EXCEEDED) */
    {
        /* send FAILURE */
        newEapReqLen = SIZEOF_EAP_MSG_HDR;
        if (NULL == (newEapReq = (ubyte*) MALLOC(newEapReqLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            DBG_DONE
        }
        eapHdr = (struct eapMsgHdr *)newEapReq;
        eapHdr->oCode = EAP_CODE_FAILURE;
        eapHdr->oIdentifier = 0;
        SET_HTONS(eapHdr->wLength, newEapReqLen);

        if (OK > (status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                          EAP_TYPE_NONE, EAP_CODE_FAILURE,
                                          EAP_METHOD_DECISION_FAILURE,
                                          EAP_METHOD_STATE_END,
                                          newEapReq, newEapReqLen)))
            DBG_DONE
    }

    switch (eapHdr->oCode)
    {
    case EAP_CODE_SUCCESS :
        pxSa->flags |= IKE_SA_FLAG_EAP_DONE;
        break;
    case EAP_CODE_FAILURE :
        DBG_ERRCODE(ERR_EAP)
        break;
    default :
        break;
    }

done:
    RADIUS_requestRelease(&pRqst);
    cb->pRadiusReq = NULL;

    if (OK <= status)
    if (!pxEap->pxMsg) /* jic */
    {
        status = ERR_EAP;
        DBG_STATUS
    }

    /* output IKE2+EAP message to peer */
    if (OK > status)
        ctx.wMsgType = AUTHENTICATION_FAILED;

    ctx.pxSa = pxSa;
    ctx.pxXg = pxEap->pxXg;
    pxEap->pxXg->x_flags &= ~(IKE_XCHG_FLAG_PENDING);
    pxSa->merror = status;

    status = IKE2_xchgOut(&ctx);

exit:
    if (newEapReq) FREE(newEapReq);
    IKE_UNLOCK_W;
    return (sbyte4)status;
} /* IKE_radRecv */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_radIndCallback(ubyte *appSessionHdl,
                   RADIUS_RESULT result,
                   RADIUS_RqstRecord *pRqst)
{
    MSTATUS status = OK;

    struct ike_context ctx = { NULL };
    struct ike2eap *pxEap = (struct ike2eap *)appSessionHdl;

    struct ikesa *pxSa;
    appCtrlBlk *cb;

    struct eapMsgHdr eapHdr;

    MOC_UNUSED(result);

    IKE_LOCK_W;

    if (!pxEap || !pRqst ||
        (NULL == (cb = (appCtrlBlk *) pxEap->pCbData)) ||
        (NULL == (pxSa = (struct ikesa *) pxEap->pxSa)))
    {
        status = ERR_NULL_POINTER;
        DBG_EXIT
    }

    if (!IS_VALID(pxSa))
    {
        /*RADIUS_requestRelease(&pRqst);*/
        status = ERR_IKE_GETSA_FAIL;
        DBG_EXIT
    }

    /* sanity check */
    if (!IS_IKE2_SA(pxSa) ||
        (pRqst != cb->pRadiusReq) ||
        (pxEap != &pxSa->u.v2.eapState))
    {
        /*RADIUS_requestRelease(&pRqst);*/
        status = ERR_RADIUS;
        DBG_EXIT
    }

    RADIUS_requestRelease(&pRqst);
    cb->pRadiusReq = NULL;

    /* send FAILURE */
    eapHdr.oCode = EAP_CODE_FAILURE;
    eapHdr.oIdentifier = 0;
    SET_HTONS(eapHdr.wLength, SIZEOF_EAP_MSG_HDR);

    if (OK > (status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                      EAP_TYPE_NONE, EAP_CODE_FAILURE,
                                      EAP_METHOD_DECISION_FAILURE,
                                      EAP_METHOD_STATE_END,
                                      (ubyte*)&eapHdr, SIZEOF_EAP_MSG_HDR)))
    {
        DBG_STATUS
    }
    else if (!pxEap->pxMsg) /* jic */
    {
        status = ERR_EAP;
        DBG_STATUS
    }
    else
    {
        DBG_ERRCODE(ERR_EAP)
    }

    /* output IKE2+EAP message to peer */
    if (OK > status)
        ctx.wMsgType = AUTHENTICATION_FAILED;

    ctx.pxSa = pxSa;
    ctx.pxXg = pxEap->pxXg;

    status = IKE2_xchgOut(&ctx);

exit:
    IKE_UNLOCK_W;
    return (sbyte4)status;
} /* IKE_radIndCallback */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_RADIUS_ReceiveIndication(ubyte* app_session_handle,
                             eapIndication ind_type,
                             ubyte* data,
                             ubyte4 data_len)
{
    MOC_UNUSED(data);
    MOC_UNUSED(data_len);

    /* If Indication is retransmission Timeout or Error, Delete the session */
    if ((EAP_INDICATION_ERROR              == ind_type) ||
        (EAP_INDICATION_RETRANSMIT_TIMEOUT == ind_type))
    {
        /* Note: this part is probably never reached, as IKEv2's EAP
           instance does not re-transmit EAP messages.
         */
        struct ike2eap *pxEap = (struct ike2eap *)app_session_handle;
        if (pxEap) /* jic */
        {
            EAP_RADIUS_PassthruDelFunc(pxEap);
            EAP_sessionDelete(pxEap->pSession, g_ikeEapInstId);
            pxEap->pSession = NULL;
        }
    }

    return OK;
} /* EAP_RADIUS_ReceiveIndication */


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
        "IKE_EAP_RADIUS_PASSTHRU",
        NULL,
        EAP_RADIUS_ReceivePktCallback,
        EAP_RADIUS_ReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapRADIUSpassthruSuite =
{
    EAP_RADIUS_PassthruInitFunc,
    EAP_RADIUS_PassthruDelFunc,
    &methodDef,
    EAP_SESSION_TYPE_PASSTHROUGH,
#ifdef __ENABLE_IKE_EAP_ONLY__
    FALSE
#endif
};


#endif /* defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) */
#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

