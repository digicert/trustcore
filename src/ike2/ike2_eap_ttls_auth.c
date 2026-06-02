/**
 * @file  ike2_eap_ttls_auth.c
 * @brief IKEv2 IKEv2 EAP-TTLS Authenticator
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
 *     +   \c \__ENABLE_DIGICERT_EAP_TTLS__
 *     +   \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
 *     +   \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
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

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_TTLS__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#if defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)

#ifndef __ENABLE_DIGICERT_EAP_TLS__
#ifdef __WIN32_RTOS__
#pragma message ("Must define __ENABLE_DIGICERT_EAP_TLS__")
#else
#warning "Must define __ENABLE_DIGICERT_EAP_TLS__"
#endif
#endif

#ifndef __ENABLE_DIGICERT_EAP_RADIUS__
#ifdef __WIN32_RTOS__
#pragma message ("Must define __ENABLE_DIGICERT_EAP_RADIUS__")
#else
#warning "Must define __ENABLE_DIGICERT_EAP_RADIUS__"
#endif
#endif

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../common/sizedbuffer.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"

#include "../radius/radius.h"
#include "../radius/radius_req.h"
#include "../radius/radius_resp.h"
#include "../ssl/ssl.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_tls.h"
#include "../eap/eap_ttls.h"

#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike2/ike2_eap.h"


/*------------------------------------------------------------------*/

extern ikeSettings  m_ikeSettings;
extern IKE_MUTEX    g_ikeMtx;

extern ubyte4       g_ikeEapInstId; /* EAP instance */
extern sbyte4       g_ikeRadInstId; /* RADIUS Client instance */


/*------------------------------------------------------------------*/

typedef struct appTtlsCtrlBlk_t
{
    sbyte4              radiusAuthServerId;
    /*MOC_IP_ADDRESS      radiusAuthServerAddr;*/

    RADIUS_RqstRecord  *radiusReq;

    ubyte              *ttls_connection;
    /* members above must match 'appCtrlBlk' in "ike2_eap_radius_passthru.c" */
    ubyte              *tls_connection;
    ubyte               tls_version; /* always 0 for now */
    ubyte               tlsOpen;

    ubyte4              sessionIdLen;
    ubyte               sessionId[SSL_MAXSESSIONIDSIZE];
    ubyte               masterSecret[SSL_MASTERSECRETSIZE];

#ifdef __ENABLE_DIGICERT_INNER_APP__
    ubyte               authStatus; /* for version 1 only */
#endif
} appTtlsCtrlBlk;

#define EAP_TTLS_KEY_LEN 128


/*------------------------------------------------------------------*/

static MSTATUS
authProcessIdentityResponse(IKE2EAP pxEap,
                            ubyte *data, ubyte4 len,
                            eapMethodType *method_type,
                            ubyte **reqData, ubyte4 *reqLen)
{
    MSTATUS status = OK;

    ubyte* pos;
    ubyte4 id_len;
    ubyte* identity;
    sbyte* certCommonName = NULL;
    certStorePtr tlsCertStore = NULL;

    appTtlsCtrlBlk *cb = (appTtlsCtrlBlk *) pxEap->pCbData;
    IKESA pxSa = pxEap->pxSa;

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    sbyte4 connectionInstance;
    ubyte4 sslFlags;
#endif

    /* set identity */
    pos = data + sizeof(eapHdr_t) + 1;
    id_len = len - sizeof(eapHdr_t) - 1;
    EAP_setIdentity(pxEap->pSession, g_ikeEapInstId, pos, id_len);
    EAP_getIdentity(pxEap->pSession, g_ikeEapInstId, &identity, &id_len);
    DB_PRINT("EAP identity (%d) = %s\n", id_len, identity);

    /* TBD : map identity to method */

    /* get RADIUS server */
    if (cb->radiusAuthServerId) goto exit; /* jic */

    if (NULL == m_ikeSettings.funcPtrIkeGetRadSvrId)
    {
        status = ERR_IKE_CONFIG;
        goto exit;
    }
    if (OK > (status = m_ikeSettings.funcPtrIkeGetRadSvrId(
                                    &cb->radiusAuthServerId,
                                    g_ikeRadInstId,
                                    identity, id_len,
                                    REF_MOC_IPADDR(pxSa->dwPeerAddr)
                                    MOC_MTHM_REQ_VALUE(pxSa->serverInstance))))
        goto exit;

    /* get TLS server certificate store */
    if (NULL == m_ikeSettings.funcPtrIkeGetTlsCertStore)
    {
        status = ERR_IKE_CONFIG;
        goto exit;
    }
    if (OK > (status = m_ikeSettings.funcPtrIkeGetTlsCertStore(
                                    &tlsCertStore, &certCommonName,
                                    identity, id_len,
                                    REF_MOC_IPADDR(pxSa->dwPeerAddr)
                                    MOC_MTHM_REQ_VALUE(pxSa->serverInstance))))
        goto exit;

    /* establish TLS Session for the outer EAP layer */
    if (OK > (status = EAP_TLSCreateSession((ubyte *)pxEap,
                                            &cb->tls_connection,
                                            EAP_TLS_CONNECTION_SERVER,
                                            &cb->sessionIdLen, cb->sessionId,
                                            cb->masterSecret,
                                            (ubyte *)certCommonName,
                                            EAP_TYPE_TTLS,
                                            cb->tls_version, cb->tls_version,
                                            tlsCertStore)))
        goto exit;

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    if (OK > (status = EAP_TLSgetSSLInstance((ubyte *)pxEap, cb->tls_connection,
                                             &connectionInstance)) ||
        OK > (status = SSL_getSessionFlags(connectionInstance, &sslFlags)) ||
        OK > (status = SSL_setSessionFlags(connectionInstance,
                                (sslFlags | SSL_FLAG_NO_MUTUAL_AUTH_REQUEST))))
        goto exit;
#endif

#ifdef __ENABLE_DIGICERT_INNER_APP__
    if (1 == cb->tls_version)
    {
        ubyte innerApp = 1;
        if (OK > (status = EAP_TLSsetParams((ubyte *)pxEap, cb->tls_connection,
                                        EAP_TYPE_TTLS, EAP_TLS_PARAM_INNER_APP,
                                        (ubyte *)&innerApp, sizeof(innerApp))))
            goto exit;
    }
#endif

    status = EAP_TLSstartRequest((ubyte *)pxEap, cb->tls_connection,
                                 NULL, EAP_TYPE_TTLS, reqData, reqLen);
    if (OK == status)
        *method_type = EAP_TYPE_TTLS;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TTLS_AuthInitFunc(IKE2EAP pxEap)
{
    MSTATUS status = OK;

    ubyte *poMsk = NULL;
    appTtlsCtrlBlk *cb = NULL;

    if (NULL == pxEap) /* jic */
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* allocate */
    if ((NULL == (poMsk = (ubyte *) MALLOC(EAP_TTLS_KEY_LEN))) || /* MSK+EMSK */
        (NULL == (cb = (appTtlsCtrlBlk *) MALLOC(sizeof(appTtlsCtrlBlk)))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)cb, 0, sizeof(appTtlsCtrlBlk));

    /* done */
    pxEap->dwMskLen = 0; /* !!! */
    pxEap->poMsk = poMsk;
    pxEap->pCbData = cb;

    poMsk = NULL;
    cb = NULL;

exit:
    if (poMsk) FREE(poMsk);
    if (cb) FREE(cb);
    return status;
} /* EAP_TTLS_AuthInitFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TTLS_AuthDelFunc(IKE2EAP pxEap)
{
    MSTATUS status = OK;

    appTtlsCtrlBlk *cb;
    if (NULL != (cb = (appTtlsCtrlBlk *) pxEap->pCbData))
    {
        if (cb->radiusReq)
            RADIUS_requestRelease(&cb->radiusReq);
        if (cb->ttls_connection)
            EAP_TTLSdeleteSession(cb->ttls_connection);
        if (cb->tls_connection)
            EAP_TLScloseConnection((ubyte *)pxEap, cb->tls_connection);
        pxEap->pCbData = NULL;
        FREE(cb);
    }

    return status;
} /* EAP_TTLS_AuthDelFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TTLS_AuthReceiveIndication(ubyte* app_session_handle,
                               eapIndication ind_type,
                               ubyte* data, ubyte4 data_len)
{
    MOC_UNUSED(ind_type);
    MOC_UNUSED(data);
    MOC_UNUSED(data_len);

    /* If Indication is Timeout or Error , Delete the session */
    IKE2EAP pxEap = (IKE2EAP)app_session_handle;
    if (pxEap) /* jic */
    {
        EAP_TTLS_AuthDelFunc(pxEap);
        EAP_sessionDelete(pxEap->pSession, g_ikeEapInstId);
        pxEap->pSession = NULL;
    }

    return OK;
} /* EAP_TTLS_AuthReceiveIndication */


/*------------------------------------------------------------------*/
/* 2nd-stage auth */

static MSTATUS
EAP_TTLSAuth_ULTransmitPktCallback(ubyte *appSessionHdl,
                                   ubyte *data, ubyte4 len,
                                   intBoolean encrypt);
static MSTATUS
EAP_TTLSAuth_ULAuthResultCallback(ubyte *appSessionHdl, eapAuthStatus status);

static MSTATUS
EAP_TTLSAuth_RadiusCallback(ubyte *appSessionHdl, ubyte *eapCb,
                            ubyte *pkt, ubyte4 pktLen);


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TTLS_AuthReceivePktCallback(ubyte *appSessionHdl,
                                eapMethodType type, eapCode code, ubyte id,
                                ubyte *data, ubyte4 len,
                                ubyte *opaque_data)
{
    MSTATUS status = OK;

    ubyte *eapReqData = NULL;
    ubyte4 eapReqLen = 0;
    eapMethodType methodType = 0;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = 0;
    eapCode sendCode = 0;
    ubyte sendReq = 0;

    IKE2EAP pxEap = (IKE2EAP)appSessionHdl;
    appTtlsCtrlBlk *cb = (appTtlsCtrlBlk *) pxEap->pCbData;

    switch (code)
    {
    case EAP_CODE_RESPONSE :
        break;
    case EAP_CODE_REQUEST :
    case EAP_CODE_SUCCESS :
    case EAP_CODE_FAILURE :
    default:
        status = ERR_EAP_INVALID_CODE;
        DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"Invalid EAP Code", status);
        goto exit;
    }

    switch (type)
    {
    case EAP_TYPE_NONE:
        /* set error code */
        status = ERR_EAP_INVALID_METHOD_TYPE;
        break;

    case EAP_TYPE_IDENTITY:
        status = authProcessIdentityResponse(pxEap, data, len, &methodType,
                                             &eapReqData, &eapReqLen);
        if (OK == status && eapReqLen != 0)
        {
            methodState = EAP_METHOD_STATE_PROPOSED;
            decision = EAP_METHOD_DECISION_CONTINUE;
            sendCode = EAP_CODE_REQUEST;
            sendReq = 1;
        }
        break;

    case EAP_TYPE_NOTIFICATION:
        /* log msg */
        methodType = EAP_TYPE_NOTIFICATION;
        break;

    case EAP_TYPE_TTLS :
        if (cb->tlsOpen)
        {
            /* send the packet up to 2nd stage */
            status = EAP_TTLSreceiveLLPacket(cb->ttls_connection, data, len);
            break;
        }

        status = EAP_TLSProcessMsg(appSessionHdl, cb->tls_connection,
                                   data, len, &eapReqData, &eapReqLen);
        if (OK == status)
        {
            ubyte4 sessionStatus;
            status = EAP_TLSgetSessionStatus(appSessionHdl,
                                             cb->tls_connection, &sessionStatus);
            if ((OK == status) && (SSL_CONNECTION_OPEN == sessionStatus))
                cb->tlsOpen = 1;

            if (cb->tlsOpen)
            {
                RADIUS_ServerRecord *radiusAuthServer;

                /* open the 2nd-stage TTLS session */
                EAP_TTLS_params eapTTLSparams = { NULL };
                eapTTLSparams.ulTransmit            = EAP_TTLSAuth_ULTransmitPktCallback;
                eapTTLSparams.ulAuthResultTransmit  = EAP_TTLSAuth_ULAuthResultCallback;
                eapTTLSparams.ulAuthTransmit        = EAP_TTLSAuth_RadiusCallback;
                eapTTLSparams.sessionType           = EAP_SESSION_TYPE_AUTHENTICATOR;
                eapTTLSparams.tls_con               = cb->tls_connection;
                eapTTLSparams.version               = cb->tls_version;
                eapTTLSparams.instanceId            = g_ikeEapInstId;
                /*eapTTLSparams.methodType            = EAP_METHOD_TYPE_EAP;*/

                if (OK > (status = RADIUS_getServerRecordFromID(
                                                        cb->radiusAuthServerId,
                                                        &radiusAuthServer)))
                    goto exit;

                if (sizeof(eapTTLSparams.radiusSecret) < radiusAuthServer->sharedSecretLength)
                {
                    /* see 'eap_ttls_params' in "eap_ttls.h" */
                    status = ERR_EAP_TTLS_BAD_LENGTH;
                    goto exit;
                }
                DIGI_MEMCPY(eapTTLSparams.radiusSecret,
                           radiusAuthServer->sharedSecret,
                           radiusAuthServer->sharedSecretLength);
                eapTTLSparams.radiusSecretLen = (ubyte2) radiusAuthServer->sharedSecretLength;
                eapTTLSparams.authServerId    = (ubyte4) cb->radiusAuthServerId;
                /*eapTTLSparams.myaddr          = cb->radiusAuthServerAddr;*/

                EAP_TLSgetSSLInstance(appSessionHdl, cb->tls_connection,
                                      &eapTTLSparams.connectionInstance);

                if (OK > (status = EAP_TTLSinitSession(appSessionHdl,
                                                       &cb->ttls_connection,
                                                       &eapTTLSparams)))
                {
                    /* send FAILURE */
                    sendCode = EAP_CODE_FAILURE;
                    decision = EAP_METHOD_DECISION_FAILURE;
                    methodState = EAP_METHOD_STATE_END;
                    sendReq = 1;
                    eapReqLen = 0;
                    break;
                }
            }

            methodType = EAP_TYPE_TTLS;
            sendCode = EAP_CODE_REQUEST;
            decision = EAP_METHOD_DECISION_CONTINUE;
            methodState = EAP_METHOD_STATE_CONTINUE;
            sendReq = 1;
        }
        else
        {
            /* send FAILURE */
            sendCode = EAP_CODE_FAILURE;
            decision = EAP_METHOD_DECISION_FAILURE;
            methodState = EAP_METHOD_STATE_END;
            sendReq = 1;
        }

        break;

    case EAP_TYPE_NAK:
        /* check for additional methods */
        break;

    default:
        break;
    }

    if (sendReq)
    {
        status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                methodType, sendCode, decision, methodState,
                                eapReqData, eapReqLen);
    }

exit:
    if (eapReqData)
        FREE(eapReqData);
    return status;
} /* EAP_TTLS_AuthReceivePktCallback */


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
        "IKE_EAP_TTLS_AUTH",
        EAP_TTLS_AuthReceivePktCallback,
        NULL,
        EAP_TTLS_AuthReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapTTLSauthSuite =
{
    EAP_TTLS_AuthInitFunc,
    EAP_TTLS_AuthDelFunc,
    &methodDef,
    EAP_SESSION_TYPE_AUTHENTICATOR,
#ifdef __ENABLE_IKE_EAP_ONLY__
    TRUE
#endif
};


/* ttls 2nd-stage auth */

/*------------------------------------------------------------------*/

static  MSTATUS
EAP_TTLSAuth_ULTransmitPktCallback(ubyte *appSessionHdl,
                                   ubyte *data, ubyte4 len,
                                   intBoolean encrypt)
{
    MSTATUS status;
    ubyte *eapReqData = NULL;
    ubyte4 eapReqLen;
    eapMethodState methodState = EAP_METHOD_STATE_CONTINUE;
    eapMethodDecision decision = EAP_METHOD_DECISION_CONTINUE;

    IKE2EAP pxEap = (IKE2EAP)appSessionHdl;
    appTtlsCtrlBlk *cb = (appTtlsCtrlBlk *) pxEap->pCbData;

    /* First we encrypt the Buffer using EAP_TLSSendPacket */
    /* EAP Data has 5 Bytes Offset already built in */
    /* If this is a fragment, it is already encrypted hence we just send it */
    if (!encrypt)
    {
        ubyte *request;
        ubyte4 requestLen;

#ifdef __ENABLE_DIGICERT_INNER_APP__
        if (1 == appCb->tls_version) /* version 1 */
        {
            status = EAP_TTLSSendData(cb->ttls_connection,
                                      data, len,
                                      SSL_INNER_APPLICATION_DATA,
                                      &request, &requestLen);
        }
        else /* version 0 */
#endif
        {
            status = EAP_TLSSendData(appSessionHdl,
                                     cb->tls_connection,
                                     data, len,
                                     &request, &requestLen);
        }

        if (OK > status)
            goto exit;

        /* feed the buffer into the FormSend packet for Fragmentation Support */
        status = EAP_TTLSFormSendPacket(cb->ttls_connection,
                                        request, requestLen,
                                        &eapReqData, &eapReqLen);
        FREE(request);
        if (OK > status)
            goto exit;
    }
    else
    {
        eapReqData = data;
        eapReqLen = len;
    }

    /* What we get here We just blindly Transmit */
    status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                            EAP_TYPE_TTLS, EAP_CODE_REQUEST,
                            decision, methodState,
                            eapReqData, eapReqLen);

exit:
    if (eapReqData && (eapReqData != data))
        FREE(eapReqData);

    return status;
} /* EAP_TTLSAuth_ULTransmitPktCallback */


/*------------------------------------------------------------------*/

static  MSTATUS
EAP_TTLSAuth_ULAuthResultCallback(ubyte *app_session_handle,
                                  eapAuthStatus eapStatus)
{
    MSTATUS status;
    eapMethodState methodState;
    eapMethodDecision decision;
    eapCode code;

#ifdef __ENABLE_DIGICERT_INNER_APP__
    ubyte          *innerBuf = NULL;
    ubyte4          innerBufLen;
#endif
    ubyte          *eapReqData = NULL;
    ubyte4          eapReqLen = 0;
    
    IKE2EAP pxEap = (IKE2EAP)app_session_handle;
    appTtlsCtrlBlk *appCb = (appTtlsCtrlBlk *) pxEap->pCbData;

    if (EAP_AUTH_FAILURE == eapStatus)
    {
        decision = EAP_METHOD_DECISION_FAILURE;
        methodState = EAP_METHOD_STATE_END;
        code = EAP_CODE_FAILURE;
    }
#ifdef __ENABLE_DIGICERT_INNER_APP__
    /* If its version 1 then we have to first send FINAL FINISHED
     before we send the success. On the FINAL FINISHED REPLY we
     send Success */
    else if ((0 == appCb->authStatus) && (1 == appCb->tls_version))
    {
        if (OK > (status = EAP_TTLSSendData(appCb->ttls_connection,
                                            NULL, 0,
                                            SSL_INNER_FINAL_FINISHED,
                                            &innerBuf, &innerBufLen)))
            goto exit;

        if (OK > (status = EAP_TTLSFormSendPacket(appCb->ttls_connection,
                                                  innerBuf, innerBufLen,
                                                  &eapReqData, &eapReqLen)))
            goto exit;

        methodState = EAP_METHOD_STATE_CONT;
        decision = EAP_METHOD_DECISION_FAIL;
        code = EAP_CODE_REQUEST;
        appCb->authStatus = 1;
    }
#endif
    else
    {
        /* get MSK */
        if (OK > (status = EAP_TTLSgetKey(appCb->ttls_connection,
                                          pxEap->poMsk, EAP_TTLS_KEY_LEN)))
            goto exit;

        pxEap->dwMskLen = (EAP_TTLS_KEY_LEN / 2); /* 64 */

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
        {
            ubyte4 i;
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"MSK (");
            DEBUG_UINT(DEBUG_IKE_MESSAGES, pxEap->dwMskLen);
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)") = ");
            for (i=0; i < pxEap->dwMskLen; i++)
                DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, pxEap->poMsk[i]);
            DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");
        }
#endif
        decision = EAP_METHOD_DECISION_SUCCESS;
        methodState = EAP_METHOD_STATE_END;
        code = EAP_CODE_SUCCESS;
    }

    if (OK > (status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                      EAP_TYPE_TTLS, code,
                                      decision, methodState,
                                      eapReqData, eapReqLen)))
        goto exit;

    if (EAP_CODE_SUCCESS == code)
    {
        pxEap->pxSa->flags |= IKE_SA_FLAG_EAP_DONE; /* !!! */
    }

exit:
#ifdef __ENABLE_DIGICERT_INNER_APP__
    if (innerBuf)
        FREE(innerBuf);
#endif
    if (eapReqData)
        FREE(eapReqData);

    return status;
} /* EAP_TTLSAuth_ULAuthResultCallback */


/*------------------------------------------------------------------*/
extern  MSTATUS
EAP_TTLSAuth_RadiusCallback(ubyte *app_session_handle, ubyte *eapCb,
                            ubyte *pkt, ubyte4 pktLen)
{
    IKE2EAP pxEap = (IKE2EAP)app_session_handle;
    RADIUS_RqstRecord *radiusReq = (RADIUS_RqstRecord *)pkt;

    ((appTtlsCtrlBlk *) pxEap->pCbData)->radiusReq = radiusReq;
    RADIUS_setRequestUserCookie(radiusReq, app_session_handle);

    /* send packet to Radius */
    return RADIUS_requestSend(radiusReq);
} /* EAP_TTLSAuth_RadiusCallback */


#endif /* defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) */
#endif /* defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) */
#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_TTLS__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#else
static void
dummy(void)
{
    return;
}
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

