/**
 * @file  ike2_eap_tls_auth.c
 * @brief IKEv2 IKEv2 EAP-TLS Authenticator
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
 *     +   \c \__ENABLE_DIGICERT_EAP_TLS__
 *     +   \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
 *     +   \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
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

/* Add to your makefile */
#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_TLS__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#if (defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && defined( __ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__ ))

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

#include "../ssl/ssl.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_tls.h"

#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike2/ike2_eap.h"

#ifndef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
#ifdef __WIN32_RTOS__
#pragma message ("Should define __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__")
#else
#warning "Should define __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__"
#endif
#endif


/*------------------------------------------------------------------*/

extern ikeSettings  m_ikeSettings;
extern ubyte4       g_ikeEapInstId; /* EAP instance */

typedef struct appTlsCtrlBlk_t
{
    ubyte4              sessionIdLen;
    ubyte               sessionId[SSL_MAXSESSIONIDSIZE];
    ubyte               masterSecret[SSL_MASTERSECRETSIZE];
    ubyte              *tls_connection;
    ubyte               tlsOpen;

} appTlsCtrlBlk;

#define EAP_TLS_KEY_LEN 64


/*------------------------------------------------------------------*/

static MSTATUS
authProcessIdentityResponse(struct ike2eap *pxEap,
                            ubyte *data, ubyte len,
                            eapMethodType *method_type,
                            ubyte **reqData, ubyte4 *reqLen)
{
    MSTATUS status = OK;

    ubyte* pos;
    ubyte4 id_len;
    ubyte* identity;
    sbyte* certCommonName = NULL;
    certStorePtr tlsCertStore = NULL;

    appTlsCtrlBlk *cb = (appTlsCtrlBlk *) pxEap->pCbData;
    IKESA pxSa = pxEap->pxSa;

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    sbyte4 connectionInstance;
    ubyte4 sslFlags;
#endif

    /* set identity */
    pos = data + sizeof(eapHdr_t) + 1;
    id_len = len - sizeof(eapHdr_t) - 1;
    EAP_setIdentity(pxEap->pSession,g_ikeEapInstId, pos, id_len);
    EAP_getIdentity(pxEap->pSession,g_ikeEapInstId, &identity, &id_len);
    DB_PRINT("EAP identity (%d) = %s\n", id_len, identity);

    /* TBD : map identity to method */

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

    /* set method callbacks */
    status = EAP_TLSCreateSession((ubyte *)pxEap,
                                  &cb->tls_connection,
                                  EAP_TLS_CONNECTION_SERVER,
                                  &cb->sessionIdLen, cb->sessionId,
                                  cb->masterSecret,
                                  (ubyte *)certCommonName,
                                  EAP_TYPE_TLS, 0, 0,
                                  tlsCertStore);
    if (OK > status)
        goto exit;

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    if (OK > (status = EAP_TLSgetSSLInstance((ubyte *)pxEap, cb->tls_connection,
                                             &connectionInstance)) ||
        OK > (status = SSL_getSessionFlags(connectionInstance, &sslFlags)) ||
        OK > (status = SSL_setSessionFlags(connectionInstance,
                                    (sslFlags | SSL_FLAG_REQUIRE_MUTUAL_AUTH))))
        goto exit;
#else
    status = ERR_SSL_MUTUAL_AUTHENTICATION_NOT_REQUESTED;
    goto exit;
#endif

    status = EAP_TLSstartRequest ((ubyte *)pxEap, cb->tls_connection,
                                  NULL, EAP_TYPE_TLS, reqData, reqLen);
    if (OK == status)
    {
        *method_type = EAP_TYPE_TLS;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TLS_AuthInitFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    ubyte *poMsk = NULL;
    appTlsCtrlBlk *cb = NULL;

    /* allocate */
    if ((NULL == (poMsk = (ubyte *) MALLOC(EAP_TLS_KEY_LEN))) || /* MSK */
        (NULL == (cb = (appTlsCtrlBlk *) MALLOC(sizeof(appTlsCtrlBlk)))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)cb, 0, sizeof(*cb));

    /* done */
    pxEap->dwMskLen = EAP_TLS_KEY_LEN; /* 64 */
    pxEap->poMsk = poMsk;
    pxEap->pCbData = cb;

    poMsk = NULL;
    cb = NULL;

exit:
    if (poMsk) FREE(poMsk);
    if (cb) FREE(cb);
    return status;
} /* EAP_TLS_AuthInitFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TLS_AuthDelFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    appTlsCtrlBlk *cb;
    if (NULL != (cb = (appTlsCtrlBlk *) pxEap->pCbData))
    {
        if (cb->tls_connection)
            EAP_TLScloseConnection((ubyte *)pxEap, cb->tls_connection);
        pxEap->pCbData = NULL;
        FREE(cb);
    }

    return status;
} /* EAP_TLS_AuthDelFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TLS_AuthReceiveIndication(ubyte* app_session_handle,
                              eapIndication ind_type,
                              ubyte* data,
                              ubyte4 data_len)
{
    MOC_UNUSED(data);
    MOC_UNUSED(data_len);

    /* If Indication is Timeout or Error , Delete the session */
    struct ike2eap *pxEap = (struct ike2eap *)app_session_handle;
    if (pxEap) /* jic */
    {
        EAP_TLS_AuthDelFunc(pxEap);
        EAP_sessionDelete(pxEap->pSession, g_ikeEapInstId);
        pxEap->pSession = NULL;
    }

    return OK;
} /* EAP_TLS_AuthReceiveIndication */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TLS_AuthReceivePktCallback(ubyte *appSessionHdl,
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

    struct ike2eap *pxEap = (struct ike2eap *)appSessionHdl;
    appTlsCtrlBlk *cb = (appTlsCtrlBlk *) pxEap->pCbData;

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

    switch(type)
    {
        case EAP_TYPE_NONE:
            /* set error code */
            status = ERR_EAP_INVALID_METHOD_TYPE;
            break;

        case EAP_TYPE_IDENTITY:
            status = authProcessIdentityResponse(pxEap, data, len, &methodType,
                                                 &reqData, &eapReqLen);
            if (OK == status && eapReqLen != 0)
            {
                methodState = EAP_METHOD_STATE_PROPOSED;
                decision = EAP_METHOD_DECISION_CONTINUE;
                sendCode = EAP_CODE_REQUEST;
                sendReq = 1;
            }
            break;

        case EAP_TYPE_NOTIFICATION:
            /* Log msg */
            methodType = EAP_TYPE_NOTIFICATION;
            break;

        case EAP_TYPE_TLS :
            if (cb->tlsOpen)
            {
                if ( 3 > len )
                {
                    /* send SUCCESS */
                    sendCode = EAP_CODE_SUCCESS;
                    decision = EAP_METHOD_DECISION_SUCCESS;
                    methodState = EAP_METHOD_STATE_END;
                    sendReq = 1;
                }
                else
                {
                    /* What Kind of TLS Packet is this one (SSL_ALERT ?)
                       Before replying with a SUCCESS, some times WINXP send a
                       TLS Alert Access Denied  after we send TLS Finished
                       If so then feed it to the TLS stack and Tear down the session
                     */
                    /*DEBUG_ERROR(DEBUG_IKE_MESSAGES,(sbyte *)"received  TLS Packet Mostly an Alert .. Need to Process this and tear down the conneciton and send Failure"); */

                    /* send SUCCESS */
                    sendCode = EAP_CODE_FAILURE;
                    decision = EAP_METHOD_DECISION_FAILURE;
                    methodState = EAP_METHOD_STATE_END;
                    sendReq = 1;
                }
            }
            else
            {
                status = EAP_TLSProcessMsg(appSessionHdl,cb->tls_connection,
                                           data,len,
                                           &reqData, &eapReqLen);
                if (OK == status)
                {
                    ubyte4 sessionStatus;
                    status = EAP_TLSgetSessionStatus(appSessionHdl,cb->tls_connection,&sessionStatus);
                    if ((OK == status) && (SSL_CONNECTION_OPEN == sessionStatus))
                        cb->tlsOpen = 1;

                    methodType = EAP_TYPE_TLS;
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
                                reqData, eapReqLen);
        if (reqData)
            FREE(reqData);
    }

    if (sendCode == EAP_CODE_SUCCESS)
    {
        ubyte *key = pxEap->poMsk;
        EAP_TLSgetKey(cb->tls_connection, key, EAP_TLS_KEY_LEN);

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
        {
            ubyte4 i;
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"MSK (");
            DEBUG_UINT(DEBUG_IKE_MESSAGES, EAP_TLS_KEY_LEN);
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)") = ");
            for (i=0; i < EAP_TLS_KEY_LEN; i++)
                DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, key[i]);
            DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");
        }
#endif
    }

exit:
    return status;
} /* EAP_TLS_AuthReceivePktCallback */


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
        "IKE_EAP_TLS_AUTH",
        EAP_TLS_AuthReceivePktCallback,
        NULL,
        EAP_TLS_AuthReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapTLSauthSuite =
{
    EAP_TLS_AuthInitFunc,
    EAP_TLS_AuthDelFunc,
    &methodDef,
    EAP_SESSION_TYPE_AUTHENTICATOR,
#ifdef __ENABLE_IKE_EAP_ONLY__
    TRUE
#endif
};

#endif /*(defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && defined( __ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__ )) */
#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_TLS__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#else
static void
dummy(void)
{
    return;
}
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

