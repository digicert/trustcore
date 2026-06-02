/**
 * @file  ike2_eap_ttls_peer.c
 * @brief IKEv2 IKEv2 EAP-TTLS Peer
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     +   \c \__ENABLE_DIGICERT_EAP_TTLS__
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

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_TTLS__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#if defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)

#ifndef __ENABLE_DIGICERT_EAP_TLS__
#ifdef __WIN32_RTOS__
#pragma message ("Must define __ENABLE_DIGICERT_EAP_TLS__!")
#else
#warning "Must define __ENABLE_DIGICERT_EAP_TLS__!"
#endif
#endif

#if !(defined(__ENABLE_DIGICERT_EAP_GTC__)        || \
      defined(__ENABLE_DIGICERT_EAP_MD5__)        || \
      defined(__ENABLE_DIGICERT_EAP_MSCHAPv2__)   || \
      defined(__ENABLE_DIGICERT_EAP_PSK__)        || \
      defined(__ENABLE_DIGICERT_EAP_SIM__)        || \
      defined(__ENABLE_DIGICERT_EAP_SRP__))
#error "Must define at least 1 other __ENABLE_DIGICERT_EAP_*__ other than __ENABLE_DIGICERT_EAP_TTLS__ or __ENABLE_DIGICERT_EAP_TLS__"
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

#include "../ssl/ssl.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_tls.h"
#include "../eap/eap_ttls.h"
#ifdef __ENABLE_DIGICERT_EAP_GTC__
#include "../eap/eap_gtc.h"
#endif
#ifdef __ENABLE_DIGICERT_EAP_MD5__
#include "../eap/eap_md5.h"
#endif
#ifdef __ENABLE_DIGICERT_EAP_MSCHAPv2__
#include "../eap/eap_mschapv2.h"
#endif

#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike2/ike2_eap.h"


/*------------------------------------------------------------------*/

extern ikeSettings m_ikeSettings;
extern ubyte4 g_ikeEapInstId; /* EAP instance */


/*------------------------------------------------------------------*/

typedef struct appTtlsCtrlBlk_t
{
    ubyte4  sessionIdLen;
    ubyte   sessionId[SSL_MAXSESSIONIDSIZE];
    ubyte   masterSecret[SSL_MASTERSECRETSIZE];

    ubyte   tls_version;
    ubyte   tlsState;
    ubyte  *tls_connection;

    eapMethodState methodState;
    eapMethodDecision decision;

} appTtlsCtrlBlk;

#define EAP_TTLS_KEY_LEN 128


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TTLS_PeerInitFunc(IKE2EAP pxEap)
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

    DIGI_MEMSET((ubyte *)cb, 0x0, sizeof(appTtlsCtrlBlk));

    /* done */
    pxEap->pCbData = cb;
    pxEap->dwMskLen = 0; /* !!! */
    pxEap->poMsk = poMsk;
    poMsk = NULL;

exit:
    if (poMsk) FREE(poMsk);
    return status;
} /* EAP_TTLS_PeerInitFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TTLS_PeerDelFunc(IKE2EAP pxEap)
{
    MSTATUS status = OK;

    appTtlsCtrlBlk *cb;
    const IKE_eapSuiteInfo *pInnerEapSuite;

    if (NULL != (pInnerEapSuite = pxEap->pInnerEapSuite))
    {
        if (pInnerEapSuite->delFunc)
            status = pInnerEapSuite->delFunc(pxEap);
        pxEap->pInnerEapSuite = NULL;
    }

    if (pxEap->pInnerCbData)
    {
        FREE(pxEap->pInnerCbData);
        pxEap->pInnerCbData = NULL;
    }

    if (pxEap->ttls_connection)
    {
        EAP_TTLSdeleteSession(pxEap->ttls_connection);
        pxEap->ttls_connection = NULL;
    }

    if (NULL != (cb = (appTtlsCtrlBlk *) pxEap->pCbData))
    {
        if (cb->tls_connection)
            EAP_TLScloseConnection((ubyte *)pxEap, cb->tls_connection);

        pxEap->pCbData = NULL;
        FREE(cb);
    }

    return status;
} /* EAP_TTLS_PeerDelFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TTLS_PeerReceiveIndication(ubyte* appSessionHdl,
                               eapIndication ind_type,
                               ubyte* data, ubyte4 len)
{
    MOC_UNUSED(data);
    MOC_UNUSED(len);

    /* If Indication is Timeout or Error, Delete the session */
    if ((EAP_INDICATION_ERROR        == ind_type) ||
        (EAP_INDICATION_PEER_TIMEOUT == ind_type))
    {
        IKE2EAP pxEap = (IKE2EAP)appSessionHdl;
        if (pxEap) /* jic */
        {
            EAP_TTLS_PeerDelFunc(pxEap);
            EAP_sessionDelete(pxEap->pSession, g_ikeEapInstId);
            pxEap->pSession = NULL;
        }
    }

    return OK;
} /* EAP_TTLS_PeerReceiveIndication */


/*------------------------------------------------------------------*/
/* 2nd-stage auth */

static  MSTATUS
EAP_TTLSPeer_ULTransmitPktCallback(ubyte *appSessionHdl,
                                   ubyte *data, ubyte4 len,
                                   intBoolean encrypt);
static  MSTATUS
EAP_TTLSPeer_ULAuthResultCallback(ubyte *appSessionHdl, eapAuthStatus status);

static MSTATUS
EAP_TTLSPeer_2ndStgULRcvPktCbk(ubyte *appSessionHdl,
                               eapMethodType type, eapCode code, ubyte id,
                               ubyte *data, ubyte4 len,
                               ubyte *opaque_data);


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TTLS_PeerReceivePktCallback(ubyte *appSessionHdl,
                                eapMethodType type, eapCode code, ubyte id,
                                ubyte *data, ubyte4 len,
                                ubyte *opaque_data)
{
    MSTATUS status = OK;

    ubyte *eapResponse = NULL;
    ubyte4 eapRespLen = 0;
    eapMethodType methodType = 0;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = EAP_METHOD_DECISION_NONE;
    ubyte sendResponse = 0;

    ubyte4 sessionStatus;
    EAP_TTLS_params eapTTLSparams = { NULL };

    IKE2EAP pxEap = (IKE2EAP)appSessionHdl;
    appTtlsCtrlBlk *cb = (appTtlsCtrlBlk *) pxEap->pCbData;

    switch (code)
    {
    case EAP_CODE_REQUEST :
        break;
    case EAP_CODE_SUCCESS :
    case EAP_CODE_FAILURE :
        /* will delete session */
        goto exit;
    case EAP_CODE_RESPONSE :
    default:
        status = ERR_EAP_INVALID_CODE;
        DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"Invalid EAP Code", status);
        goto exit;
    }

    switch (type)
    {
    case EAP_TYPE_NONE :
        /* set error code */
        status = ERR_EAP_INVALID_METHOD_TYPE;
        break;

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
        methodType = EAP_TYPE_IDENTITY;
        //cb->methodState =
        methodState = EAP_METHOD_STATE_CONT;
        //cb->decision =
        decision = EAP_METHOD_DECISION_FAIL;
        sendResponse = 1;
        break;
    }
    case EAP_TYPE_NOTIFICATION :
        /* Log msg */
        methodType = EAP_TYPE_NOTIFICATION;
        break;

    case EAP_TYPE_TTLS :
        if (!cb->tlsState) /* Initial State */
        {
            ubyte authVersion;
            sbyte *certCommonName = NULL;
            certStorePtr tlsCertStore = NULL;

            if (2 != len)
            {
                status = ERR_EAP_TLS_INVALID_LEN;
                DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"Error in the message: Invalid TLS Start Length", status);
                goto exit;
            }

            /* Check for the Start Flag */
            if (!(*(data+1) & EAP_TLS_START_FLAG))
            {
                status = ERR_EAP_TLS_INVALID_FLAG;
                DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"Error in the message: Expecting TLS Start Flag", status);
                goto exit;
            }

            /* Check for TTLS Version */
            if (OK > (status = EAP_TLSPeerGetAuthVersion(appSessionHdl,
                                                     &authVersion, data, len)))
                goto exit;

            cb->tls_version = authVersion;

            /* get TLS CA certificate store */
            if (NULL == m_ikeSettings.funcPtrIkeGetTlsCertStore)
            {
                status = ERR_IKE_CONFIG;
                goto exit;
            }
            if (OK > (status = m_ikeSettings.funcPtrIkeGetTlsCertStore(
                                   &tlsCertStore, &certCommonName,
                                   pxEap->identity, pxEap->identityLen,
                                   REF_MOC_IPADDR(pxEap->pxSa->dwPeerAddr)
                                   MOC_MTHM_REQ_VALUE(pxEap->pxSa->serverInstance))))
                goto exit;

            /* establish TLS session for the outer EAP layer */
            if (OK > (status = EAP_TLSCreateSession(appSessionHdl,
                                            &cb->tls_connection,
                                            EAP_TLS_CONNECTION_CLIENT,
                                            &cb->sessionIdLen, cb->sessionId,
                                            cb->masterSecret,
                                            (ubyte *)certCommonName,
                                            EAP_TYPE_TTLS,
                                            authVersion, authVersion,
                                            tlsCertStore)))
                goto exit;

#ifdef __ENABLE_DIGICERT_INNER_APP__
            if (1 == authVersion)
            {
                ubyte innerApp = 1;
                if (OK > (status = EAP_TLSsetParams(appSessionHdl,
                                        cb->tls_connection,
                                        EAP_TYPE_TTLS, EAP_TLS_PARAM_INNER_APP,
                                        (ubyte *)&innerApp, sizeof(innerApp))))
                    goto exit;
            }
#endif
            status = EAP_TLSPeerStart(appSessionHdl, cb->tls_connection,
                                      EAP_TYPE_TTLS, data, len,
                                      &eapResponse, &eapRespLen);
            if (OK == status)
            {
                methodType = EAP_TYPE_TTLS;
                cb->methodState =
                methodState = EAP_METHOD_STATE_CONT;
                cb->decision =
                decision = EAP_METHOD_DECISION_FAIL;
                sendResponse = 1;
                cb->tlsState = 1;
            }

            break;
        }

        if (1 < cb->tlsState) /* Open State */
        {
            /* The outer TLS channel is open. Tunnel the inner Payload
               to the 2nd stage */
            /* It's a continuation of the 2nd stage dialog */
            /* Pass it up for coalesing and decrypting */
            /* Call the TTLS LL receive function here */
            status = EAP_TTLSreceiveLLPacket(pxEap->ttls_connection, data, len);
            break;
        }

        /* Negotiation State (Stage 1: Handshake) */
        if (OK > (status = EAP_TLSProcessMsg(appSessionHdl, cb->tls_connection,
                                             data, len,
                                             &eapResponse, &eapRespLen)))
            goto exit;

        /* Check Whether the TLS Channel Got Established */
        if (OK > (status = EAP_TLSgetSessionStatus(appSessionHdl,
                                                   cb->tls_connection,
                                                   &sessionStatus)))
            goto exit;

        methodType = EAP_TYPE_TTLS;

        if (SSL_CONNECTION_OPEN != sessionStatus) /* still handshaking */
        {
            decision = EAP_METHOD_DECISION_FAIL;
            methodState = EAP_METHOD_STATE_CONT;
            sendResponse = 1;
            break;
        }

        if (OK > (status = EAP_TLSgetClientSessionInfo(appSessionHdl,
                                                       cb->tls_connection,
                                                       &cb->sessionIdLen,
                                                       cb->sessionId,
                                                       cb->masterSecret)))
            goto exit;

       /* We open the  TTLS COnnection here and Feed the LL Layer with the null
          packet to activate the TTLS Second stage */
        eapTTLSparams.ulTransmit            = EAP_TTLSPeer_ULTransmitPktCallback;
        eapTTLSparams.ulAuthResultTransmit  = EAP_TTLSPeer_ULAuthResultCallback;
        eapTTLSparams.ul2ndStageReceive     = EAP_TTLSPeer_2ndStgULRcvPktCbk;
        eapTTLSparams.sessionType           = EAP_SESSION_TYPE_PEER;
        eapTTLSparams.tls_con               = cb->tls_connection;
        eapTTLSparams.version               = cb->tls_version;
        eapTTLSparams.instanceId            = g_ikeEapInstId;
        eapTTLSparams.methodType            = (eapTTLSMethodType)
                                        pxEap->pxSa->ikePeerConfig->eapTtlsType;
                                            /* EAP_METHOD_TYPE_EAP
                                               EAP_METHOD_TYPE_PAP
                                               EAP_METHOD_TYPE_CHAP
                                               EAP_METHOD_TYPE_MSCHAP
                                               EAP_METHOD_TYPE_MSCHAPV2
                                             */
        if (sizeof(eapTTLSparams.UserName) < pxEap->identityLen)
        {
            /* see 'eap_ttls_params' in "eap_ttls.h" */
            status = ERR_EAP_TTLS_BAD_LENGTH;
            goto exit;
        }
        DIGI_MEMCPY(eapTTLSparams.UserName, pxEap->identity, pxEap->identityLen);
        eapTTLSparams.UserNameLen = (ubyte2) pxEap->identityLen;

        if (EAP_METHOD_TYPE_EAP != eapTTLSparams.methodType)
        {
            ubyte *password = NULL;
            ubyte4 passwordLen = 0;

            if (NULL == m_ikeSettings.funcPtrGetToken)
            {
                status = ERR_IKE_CONFIG;
                goto exit;
            }
            if (OK > (status = m_ikeSettings.funcPtrGetToken(NULL, 0,
                                                 &password, &passwordLen,
                                                 pxEap->pxSa->serverInstance)))
                goto exit;

            if (sizeof(eapTTLSparams.Password) < passwordLen)
            {
                /* see 'eap_ttls_params' in "eap_ttls.h" */
                status = ERR_EAP_TTLS_BAD_LENGTH;
            }
            else
            {
                DIGI_MEMCPY(eapTTLSparams.Password, password, passwordLen);
                eapTTLSparams.PasswordLen = (ubyte2)passwordLen;
            }

            if (password)
            {
                DIGI_MEMSET(password, 0x0, passwordLen);
                FREE(password);
            }
            if (OK > status) goto exit;
        }

        EAP_TLSgetSSLInstance(appSessionHdl, cb->tls_connection,
                              &eapTTLSparams.connectionInstance);

        if (OK > (status = EAP_TTLSinitSession(appSessionHdl,
                                               &pxEap->ttls_connection,
                                               &eapTTLSparams)))
            goto exit;

        /* PAP/CHAP/MSCHAP/MSCHAPv2: send the Auth AVPS to authenticator */
        /* EAP: send EAP-Identity response to authenticator */
        if (OK > (status = EAP_TTLSreceiveLLPacket(pxEap->ttls_connection,
                                                   NULL, 0)))
            goto exit;

        cb->tlsState = 2;
        break;

    default :
    {
        /* send NAK response */
        ubyte methodSup = EAP_TYPE_TTLS;
        status = EAP_buildNAK(pxEap->pSession, g_ikeEapInstId,
                              &methodSup, 1,
                              &eapResponse, &eapRespLen);
        if (OK == status)
        {
            methodType = EAP_TYPE_NAK;
            decision = EAP_METHOD_DECISION_FAIL;
            sendResponse = 1;
        }
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

exit:
    if (eapResponse)
        FREE(eapResponse);
    return status;
} /* EAP_TTLS_PeerReceivePktCallback */


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
        "IKE_EAP_TTLS_PEER",
        EAP_TTLS_PeerReceivePktCallback,
        NULL,
        EAP_TTLS_PeerReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapTTLSpeerSuite =
{
    EAP_TTLS_PeerInitFunc,
    EAP_TTLS_PeerDelFunc,
    &methodDef,
    EAP_SESSION_TYPE_PEER,
#ifdef __ENABLE_IKE_EAP_ONLY__
    TRUE
#endif
};


/* ttls 2nd-stage auth */

/*------------------------------------------------------------------*/
/* The callback that we registrerd for the ttls 2nd stage to call us
   back to encrypt the packet using the outer layer EAP TLS Channel
   and send to the authenticator */

static MSTATUS
EAP_TTLSPeer_ULTransmitPktCallback(ubyte *appSessionHdl,
                                   ubyte *data, ubyte4 len,
                                   intBoolean encrypt)
{
    /* First we encrypt the buffer using EAP_TLSSendPacket */
    /* If this is a fragment, it is already encrypted hence we just send it */
    MSTATUS status;
    ubyte *eapResponse = NULL;
    ubyte4 eapRespLen;

    IKE2EAP pxEap = (IKE2EAP)appSessionHdl;
    appTtlsCtrlBlk *cb = (appTtlsCtrlBlk *) pxEap->pCbData;

    /* If the the Packet is Not Encrypted we need to Encrypt the packet */
    /* In some cases like ACKs or Fragments, the packet is already encrypted
       and hence we dont need to encrypt the packet here */
    if (!encrypt)
    {
        ubyte *response;
        ubyte4 responseLen;

#ifdef __ENABLE_DIGICERT_INNER_APP__
        if (1 == cb->ttls_version ) /* version 1 */
        {
            status = EAP_TTLSSendData(pxEap->ttls_connection,
                                      data, len, SSL_INNER_APPLICATION_DATA,
                                      &response, &responseLen);
        }
        else /* version 0 */
#endif
        {
            status = EAP_TLSSendData(appSessionHdl, cb->tls_connection,
                                     data, len, &response, &responseLen);
        }

        if (OK > status)
            goto exit;

        /* feed the buffer into the FormSend packet for Fragmentation Support */
        status = EAP_TTLSFormSendPacket(pxEap->ttls_connection,
                                        response, responseLen,
                                        &eapResponse, &eapRespLen);
        FREE(response);
        if (OK > status)
            goto exit;
    }
    else
    {
        eapResponse = data;
        eapRespLen = len;
    }

    /* What we get here We just blindly Transmit */
    status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                            EAP_TYPE_TTLS, EAP_CODE_RESPONSE,
                            cb->decision, cb->methodState,
                            eapResponse, eapRespLen);

exit:
    if (eapResponse && (eapResponse != data))
        FREE(eapResponse);

    return status;
} /* EAP_TTLSPeer_ULTransmitPktCallback */


/*------------------------------------------------------------------*/
/* This is an Indication from the Inner Method as to the status of
   the Method Negotiation..Based on this we can set the Method State
   and Decision for the Outer EAP Session so that the Failure/Success
   which gets transmitted for the Outer EAP Session gets processed
   properly */

static  MSTATUS
EAP_TTLSPeer_ULAuthResultCallback(ubyte *appSessionHdl, eapAuthStatus eapStatus)
{
    MSTATUS status;

    IKE2EAP pxEap = (IKE2EAP)appSessionHdl;
    appTtlsCtrlBlk *cb = (appTtlsCtrlBlk *) pxEap->pCbData;

    if (EAP_AUTH_FAILURE == eapStatus)
    {
        cb->methodState = EAP_METHOD_STATE_CONT;
        cb->decision = EAP_METHOD_DECISION_FAIL;
    }
    else /* success */
    {
        /* get MSK */
        if (OK > (status = EAP_TTLSgetKey(pxEap->ttls_connection,
                                          pxEap->poMsk, EAP_TTLS_KEY_LEN)))
            goto exit;

        pxEap->dwMskLen = (EAP_TTLS_KEY_LEN / 2); /* 64 */

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
        {
            ubyte4 i;
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"MSK (");
            DEBUG_UINT(DEBUG_IKE_MESSAGES, pxEap->dwMskLen);
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)") = ");
            for (i =0; i < pxEap->dwMskLen; i++)
                DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, pxEap->poMsk[i]);
            DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");
        }
#endif
        /* Update the Decision and Method on the outer EAP stack */
        cb->decision = EAP_METHOD_DECISION_UNCOND_SUCC;
        cb->methodState = EAP_METHOD_STATE_DONE;
    }

    status = EAP_setMethodStateDecision(pxEap->pSession, g_ikeEapInstId,
                                        cb->methodState, cb->decision);

exit:
    return status;
} /* EAP_TTLSPeer_ULAuthResultCallback */


/*------------------------------------------------------------------*/
/* Second Stage  (Inner EAP) EAP Callback Function to process the
   method specific Information coming in from the Authenticator */

static MSTATUS
EAP_TTLSPeer_2ndStgULRcvPktCbk(ubyte *appSessionHdl,
                               eapMethodType type, eapCode code, ubyte id,
                               ubyte *data, ubyte4 len,
                               ubyte *opaque_data)
{
    MSTATUS status = OK;

    ubyte* eapResponse = NULL;
    ubyte4 eapRespLen = 0;
    eapMethodType methodType = 0;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = EAP_METHOD_DECISION_NONE;
    ubyte sendResponse = 0;

    IKE2EAP pxEap = (IKE2EAP)appSessionHdl;

    switch (code)
    {
    case EAP_CODE_REQUEST :
        break;
    case EAP_CODE_SUCCESS :
    case EAP_CODE_FAILURE :
        /* will delete session */
        goto exit;
    case EAP_CODE_RESPONSE :
    default :
        status = ERR_EAP_INVALID_CODE;
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte *)"Invalid EAP Code", status);
        goto exit;
    }

    switch (type)
    {
    case EAP_TYPE_NONE :
        /* set error code */
        status = ERR_EAP_INVALID_METHOD_TYPE;
        break;

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
        methodType =  EAP_TYPE_IDENTITY;
        methodState = EAP_METHOD_STATE_CONT;
        decision = EAP_METHOD_DECISION_FAIL;
        sendResponse = 1;
        break;
    }
    case EAP_TYPE_NOTIFICATION :
        /* Log msg */
        methodType = EAP_TYPE_NOTIFICATION;
        break;

#if defined(__ENABLE_DIGICERT_EAP_GTC__) || defined(__ENABLE_DIGICERT_EAP_MD5__)
    case EAP_TYPE_EXPANDED :
    {
        ubyte4 expVendorId = DIGI_NTOHL(data) & 0x00ffffff;
        ubyte4 expMethodId = DIGI_NTOHL(data + 4);
        eapExpandedMethod_t expanded_methods[EAP_MAX_METHODS];
        ubyte expanded_method_count = 0;

        const IKE_eapSuiteInfo *pInnerEapSuite = pxEap->pInnerEapSuite;
        if ((NULL == pInnerEapSuite) && (8 < len) &&
            (EAP_VENDOR_ID_IETF == expVendorId) &&
            (
#ifdef __ENABLE_DIGICERT_EAP_GTC__
             (EAP_TYPE_GTC == expMethodId) ||
#endif
#ifdef __ENABLE_DIGICERT_EAP_MD5__
             (EAP_TYPE_MD5 == expMethodId) ||
#endif
             FALSE))
        {
            if (OK == IKE_eapSuite((IKE_EAP_PROTO_T)expMethodId, TRUE, &pInnerEapSuite) &&
                NULL != pInnerEapSuite)
            {
                if ((NULL != pInnerEapSuite->initFunc) &&
                    (OK > (status = pInnerEapSuite->initFunc(pxEap))))
                    goto exit;

                pxEap->pInnerEapSuite = pInnerEapSuite;
            }
        }

        if (pInnerEapSuite)
        {
            status = pInnerEapSuite->pMethodDef->funcPtr_ulReceiveCallback(
                                                               appSessionHdl,
                                                               type, code,
                                                               id, data, len,
                                                               opaque_data);
            goto exit;
        }

        /* send Expanded NAK */
#ifdef __ENABLE_DIGICERT_EAP_GTC__
        DIGI_HTONL((ubyte *)&expanded_methods[expanded_method_count].vendor_id, EAP_VENDOR_ID_IETF);
        DIGI_HTONL((ubyte *)&expanded_methods[expanded_method_count++].method_type, EAP_TYPE_GTC);
#endif
#ifdef __ENABLE_DIGICERT_EAP_MD5__
        DIGI_HTONL((ubyte *)&expanded_methods[expanded_method_count].vendor_id, EAP_VENDOR_ID_IETF);
        DIGI_HTONL((ubyte *)&expanded_methods[expanded_method_count++].method_type, EAP_TYPE_MD5);
#endif
        status = EAP_buildExpandedNAK(pxEap->pSession, g_ikeEapInstId,
                                      expanded_methods, expanded_method_count,
                                      &eapResponse, &eapRespLen);
        if (OK == status)
        {
            methodType = EAP_TYPE_EXPANDED_NAK;
            decision = EAP_METHOD_DECISION_FAIL;
            sendResponse = 1;
        }
        break;
    }
#endif

    default :
    {
        ubyte nakMsg[EAP_MAX_METHODS];
        sbyte4 i, j;

        const IKE_eapSuiteInfo *pInnerEapSuite = pxEap->pInnerEapSuite;
        if ((NULL == pInnerEapSuite) &&
            (EAP_PROTO_TTLS != (IKE_EAP_PROTO_T)type) &&
            (EAP_PROTO_TLS != (IKE_EAP_PROTO_T)type) &&
#ifdef  __ENABLE_DIGICERT_EAP_LEAP__
            (EAP_PROTO_LEAP != (IKE_EAP_PROTO_T)type) &&
#endif
            (EAP_PROTO_ANY != (IKE_EAP_PROTO_T)type))
        {
            if (OK == IKE_eapSuite((IKE_EAP_PROTO_T)type, TRUE, &pInnerEapSuite) &&
                NULL != pInnerEapSuite)
            {
                if (NULL == pInnerEapSuite->pMethodDef)
                {
                    status = ERR_EAP;
                    goto exit;
                }

                if (NULL == pInnerEapSuite->pMethodDef->funcPtr_ulReceiveCallback)
                {
                    status = ERR_EAP_INVALID_CALLBACK_FN;
                    goto exit;
                }

                if ((NULL != pInnerEapSuite->initFunc) &&
                    (OK > (status = pInnerEapSuite->initFunc(pxEap))))
                    goto exit;

                pxEap->pInnerEapSuite = pInnerEapSuite;
            }
        }

        if (pInnerEapSuite)
        {
            status = pInnerEapSuite->pMethodDef->funcPtr_ulReceiveCallback(
                                                               appSessionHdl,
                                                               type, code,
                                                               id, data, len,
                                                               opaque_data);
            goto exit;
        }

        /* send NAK response */
        for (i=0, j=0; i < EAP_MAX_METHODS; i++)
        {
            IKE_EAP_PROTO_T proto_t;
            if (NULL == IKE_getEapSuite(TRUE, i, &proto_t))
                break;

            if ((EAP_PROTO_TTLS == proto_t) ||
                (EAP_PROTO_TLS == proto_t) ||
#ifdef  __ENABLE_DIGICERT_EAP_LEAP__
                (EAP_PROTO_LEAP == proto_t) ||
#endif
                (EAP_PROTO_ANY == proto_t))
                continue;

            nakMsg[j++] = (ubyte)proto_t;
        }

        status = EAP_buildNAK(pxEap->pSession, g_ikeEapInstId,
                              (ubyte *)nakMsg, j,
                              &eapResponse, &eapRespLen);
        if (OK == status)
        {
            methodType = EAP_TYPE_NAK;
            decision = EAP_METHOD_DECISION_FAIL;
            sendResponse = 1;
        }
        break;
    }
    }

    if (sendResponse)
    {
        status = EAP_TTLSulPeerTransmit(pxEap->ttls_connection, g_ikeEapInstId,
                                        methodType, EAP_CODE_RESPONSE,
                                        decision, methodState,
                                        eapResponse, eapRespLen);
    }

exit:
    if (eapResponse)
        FREE(eapResponse);
    return status;
} /* EAP_TTLSPeer_2ndStgULRcvPktCbk */


#endif /* defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) */
#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_TTLS__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#else
static void
dummy(void)
{
    return;
}
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

