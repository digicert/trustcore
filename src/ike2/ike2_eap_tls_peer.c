/**
 * @file  ike2_eap_tls_peer.c
 * @brief IKEv2 IKEv2 EAP-TLS Peer
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     +   \c \__ENABLE_DIGICERT_EAP_TLS__
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

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_TLS__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#if defined( __ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__ )

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


/*------------------------------------------------------------------*/

extern ikeSettings  m_ikeSettings;
extern ubyte4       g_ikeEapInstId; /* EAP instance */


/*------------------------------------------------------------------*/

typedef struct appTlsCtrlBlk_t
{
    ubyte*              eapSessionHdl;
    ubyte               tlsState;
    ubyte4              sessionIdLen;
    ubyte               sessionId[SSL_MAXSESSIONIDSIZE];
    ubyte               masterSecret[SSL_MASTERSECRETSIZE];
    ubyte              *tls_connection;
    ubyte               tlsOpen;
} appTlsCtrlBlk;

#define EAP_TLS_KEY_LEN 64

/*------------------------------------------------------------------*/

static MSTATUS
EAP_TLS_PeerInitFunc(struct ike2eap *pxEap)
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

    DIGI_MEMSET((ubyte *)cb, 0x0, sizeof(*cb));

    /* done */
    pxEap->dwMskLen = EAP_TLS_KEY_LEN; /* 64 */
    pxEap->poMsk = poMsk;
    pxEap->pCbData = cb;

    poMsk = NULL;

exit:
    if (poMsk) FREE(poMsk);
    return status;
} /* EAP_TLS_PeerInitFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TLS_PeerDelFunc(struct ike2eap *pxEap)
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

}

/*------------------------------------------------------------------*/

static MSTATUS
EAP_TLS_PeerReceiveIndication(ubyte* app_session_handle,
                  eapIndication ind_type,
                  ubyte* data,
                  ubyte4 data_len)
{
    MOC_UNUSED(data);
    MOC_UNUSED(data_len);

    /* If Indication is Timeout or Error , Delete the session */
    if ((EAP_INDICATION_ERROR        == ind_type) ||
    (EAP_INDICATION_PEER_TIMEOUT == ind_type))
    {
    struct ike2eap *pxEap = (struct ike2eap *)app_session_handle;
    if (pxEap) /* jic */
    {
        EAP_TLS_PeerDelFunc(pxEap);
        EAP_sessionDelete(pxEap->pSession, g_ikeEapInstId);
        pxEap->pSession = NULL;
    }
    }

    return OK;
} /* EAP_TLS_PeerReceiveIndication */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_TLS_PeerReceivePktCallback(ubyte *appSessionHdl,
                         eapMethodType type,
                         eapCode code, ubyte id,
                         ubyte *data, ubyte4 len,
                         ubyte *opaque_data)
{
    MSTATUS status = OK;
    ubyte *eapResponse = NULL;
    ubyte4 eapRespLen = 0, sendResponse =0;
    ubyte freebuffer = 0;
    ubyte authVersion;
    eapMethodType methodType;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = EAP_METHOD_DECISION_NONE;
    ubyte4 setMTU = 1300; /* new variable added to hold the user defined value of MTU */
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
    /* new variables to send the class(FATAL/WARNING) and Id of alert */
    sbyte4 alertClass;
    sbyte4 alertId;
#endif
    struct ike2eap *pxEap = (struct ike2eap *)appSessionHdl;
    appTlsCtrlBlk *cb = (appTlsCtrlBlk *) pxEap->pCbData;

    switch(code)
    {
        case EAP_CODE_REQUEST :
        {
            status = OK;
            break;
        }

        case EAP_CODE_SUCCESS :
        case EAP_CODE_FAILURE :
        {
            goto exit;
        }

        case EAP_CODE_RESPONSE :
        default:
        {
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE,(sbyte *)"Invalid EAP Code",status);
            break;
        }

    }

    if ((EAP_CODE_RESPONSE == code) || (status != OK))
        goto exit;

    switch(type)
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
        else
        {
            status = ERR_EAP_INVALID_PARAM;
            goto exit;
        }
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

        case EAP_TYPE_TLS :
        {
            if (!cb->tlsState )
            {
                sbyte *certCommonName = NULL;
                certStorePtr tlsCertStore = NULL;

                if (2 !=len)
                {
                    status = -1;
                    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte *)"Error in the message. Expecting Start Msg \n", status);
                    break;
                }

                if (*(data+1) != EAP_TLS_START_FLAG)
                {
                    status = -1;
                    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte *)"Error in the message. Expecting Start Msg \n", status);
                    break;
                }
                if (OK > (status = EAP_TLSPeerGetAuthVersion(appSessionHdl,
                                   &authVersion, data, len)))
                    goto exit;

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

                status = EAP_TLSCreateSession (appSessionHdl,
                               &cb->tls_connection,
                               EAP_TLS_CONNECTION_CLIENT,
                               &cb->sessionIdLen, cb->sessionId,
                               cb->masterSecret,
                               (ubyte *)certCommonName,
                               EAP_TYPE_TLS, 0, 0,
                               tlsCertStore);
                if (OK > status)
                    goto exit;

                /* Calling setParams to set the MTU value in eap_tls.c here */
                status = EAP_TLSsetParams(appSessionHdl,
                                          cb->tls_connection,
                                          EAP_TYPE_TLS,
                                          EAP_TLS_PARAM_MAX_MTU,
                                          (ubyte *)&setMTU,4);

                status = EAP_TLSPeerStart (appSessionHdl,cb->tls_connection,
                                EAP_TYPE_TLS,
                                data,len,
                                &eapResponse, &eapRespLen);

                if (OK == status)
                {
                    methodType = EAP_TYPE_TLS;
                    methodState = EAP_METHOD_STATE_CONT;
                    decision = EAP_METHOD_DECISION_FAIL;
                    sendResponse = 1;
                    freebuffer = 1;
                    cb->tlsState = 1;
                }
            }
            else
            {
                status = EAP_TLSProcessMsg (appSessionHdl,cb->tls_connection,
                                  data,len,
                                  &eapResponse, &eapRespLen);
                if (OK == status)
                {
                    ubyte4 sessionStatus;
                    methodType = EAP_TYPE_TLS;

                    status = EAP_TLSgetSessionStatus (appSessionHdl,
                                            cb->tls_connection,&sessionStatus);
                    if ((OK == status ) && (SSL_CONNECTION_OPEN == sessionStatus))
                    {
                       cb->tlsOpen = 1;
                       status = EAP_TLSgetClientSessionInfo (appSessionHdl,
                                              cb->tls_connection,
                                              &cb->sessionIdLen,
                                              cb->sessionId,
                                              cb->masterSecret );
                       if ( OK == status)
                       {
                           DEBUG_PRINT(DEBUG_EAP_MESSAGE,(sbyte *)"Session Id Len is :");
                           DEBUG_INT(DEBUG_EAP_MESSAGE,cb->sessionIdLen);
                           DEBUG_PRINTNL(DEBUG_EAP_MESSAGE,(sbyte *)" ");
                           if (0 == eapRespLen)
                           {
                               /* Send a Blank Flag Byte as the last ACK to the TLS Finished */
                               eapRespLen = 1;
                               eapResponse = (ubyte *) MALLOC(eapRespLen);
                               if (NULL == eapResponse)
                               {
                                   status = ERR_MEM_ALLOC_FAIL;
                                   goto exit;
                               }
                               /* TLS Flag Byte */
                               *eapResponse = 0;
                           }
                        }
                    }
                    if (!(cb->tlsOpen))
                    {
                        decision = EAP_METHOD_DECISION_FAIL;
                        methodState = EAP_METHOD_STATE_CONT;
                    }
                    else
                    {
                        ubyte key[EAP_TLS_KEY_LEN],i;
                        EAP_TLSgetKey(cb->tls_connection, key, EAP_TLS_KEY_LEN);
                        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *)"TLS SESSION KEY ");
                        for (i =0; i < EAP_TLS_KEY_LEN; i++)
                        {
                            DEBUG_HEXINT(DEBUG_EAP_MESSAGE, key[i]);
                            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)" ");
                        }
                        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *)" ");
                        DIGI_MEMCPY(pxEap->poMsk, key, EAP_TLS_KEY_LEN);
                        methodState = EAP_METHOD_STATE_DONE;
                        decision = EAP_METHOD_DECISION_UNCOND_SUCC;
                    }
                    sendResponse = 1;
                    freebuffer = 1;
                    cb->tlsState = 1;
                }
                /* Conditional Block handling TLS Alert*/
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                if (OK > status)
                {
                    alertClass = SSLALERTLEVEL_FATAL; /* the user can  set the appropriate alertClass and Id */
                    alertId = 42;
                    status = EAP_TLSformAlert(cb->tls_connection,
                                     alertClass,alertId,len,
                                     &eapResponse, &eapRespLen);

                    if(OK > status)
                    {
                        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE,(sbyte *)" Unable To Form Alert Packet:");
                        goto exit;
                    }

                    sendResponse = 1;
                    freebuffer = 1;
                    methodType = EAP_TYPE_TLS;
                    methodState = EAP_METHOD_STATE_DONE;
                    decision = EAP_METHOD_DECISION_FAIL;
                }/*Conditional Block*/
#endif
            }
            break;
        }

        default :
        {
            /* send NAK response */
            ubyte methodSup = EAP_TYPE_TLS;
            status = EAP_buildNAK(pxEap->pSession, g_ikeEapInstId,
                              &methodSup, 1,
                              &eapResponse,
                              &eapRespLen);
            if (OK == status)
            {
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
                                 methodType, EAP_CODE_RESPONSE,
                                 decision, methodState, eapResponse,
                                 eapRespLen);

    }
    if (freebuffer && NULL != eapResponse)
    {
        FREE(eapResponse);
    }
exit:
    return status;
}


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
        "IKE_EAP_TLS_PEER",
        EAP_TLS_PeerReceivePktCallback,
        NULL,
        EAP_TLS_PeerReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapTLSpeerSuite =
{
    EAP_TLS_PeerInitFunc,
    EAP_TLS_PeerDelFunc,
    &methodDef,
    EAP_SESSION_TYPE_PEER,
#ifdef __ENABLE_IKE_EAP_ONLY__
    TRUE
#endif
};

#endif /*(defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && defined( __ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__ )) */
#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_TLS__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#else
static void
dummy(void)
{
    return;
}
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

