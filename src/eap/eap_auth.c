/**
 * @file  eap_auth.c
 * @brief EAP authenticator implementation
 *
 * @details    EAP authenticator functions
 *
 * @flags      Compilation flags required:
 *     + \c \__ENABLE_DIGICERT_EAP_AUTH__
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

#if defined(__ENABLE_DIGICERT_EAP_AUTH__)

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mocana.h"
#include "../common/debug_console.h"
#include "../common/sizedbuffer.h"
#include "../crypto/crypto.h"
#include "../crypto/hw_accel.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/rsa.h"
#include "../crypto/des.h"
#include "../crypto/dh.h"
#include "../crypto/ca_mgmt.h"
#include "../common/redblack.h"
#include "../common/timer.h"
#include "../eap/eap.h"
#include "../eap/eap_auth.h"
#include "../eap/eap_session.h"


/*------------------------------------------------------------------*/

/* Local Methods */
static MSTATUS EAP_authStateDisabled (void *, void *);
static MSTATUS EAP_authStateInit (void *, void *);
static MSTATUS EAP_authStateIdle (void *, void *);
static MSTATUS EAP_authStateReceived (void *, void *);
static MSTATUS EAP_authStateDiscard (void *, void *);
static MSTATUS EAP_authStateSendRequest(void *, void *);
static MSTATUS EAP_authStateSuccess(void *, void *);
static MSTATUS EAP_authStateFailure(void *, void *);
static MSTATUS EAP_authStateRetransmit(void *, void *);
static MSTATUS EAP_authStateVerifyMIC(void *, void *);
static MSTATUS EAP_authStateNAK(void *, void *);
static MSTATUS EAP_authStateMethod(void *, void *);
static MSTATUS EAP_authStateTransition(eapAuthState_t newState,
                                       void *session,
                                       void * arg);

static MSTATUS
EAP_authValidatePacket(eapSessionCb_t* session,
                       ubyte* pktBuffer, ubyte4 pktLen);


/*------------------------------------------------------------------*/

const eapAuthStateBits_t eap_AuthStateBits[] =
{
    {0, (ubyte *)"NoState",NULL },
    {EAP_AUTH_STATE_DISABLED, (ubyte *)"AuthDisabled", EAP_authStateDisabled},
    {EAP_AUTH_STATE_INIT, (ubyte *)"AuthInit", EAP_authStateInit},
    {EAP_AUTH_STATE_IDLE, (ubyte *)"AuthIdle", EAP_authStateIdle},
    {EAP_AUTH_STATE_RECEIVED, (ubyte *)"AuthReceive", EAP_authStateReceived},
    {EAP_AUTH_STATE_DISCARD, (ubyte *)"AuthDiscard", EAP_authStateDiscard},
    {EAP_AUTH_STATE_SEND_REQUEST, (ubyte *)"AuthSendRequest", EAP_authStateSendRequest},
    {EAP_AUTH_STATE_SUCCESS, (ubyte *)"AuthSuccess", EAP_authStateSuccess},
    {EAP_AUTH_STATE_FAILURE, (ubyte *)"AuthFailure", EAP_authStateFailure},
    {EAP_AUTH_STATE_RETRANSMIT, (ubyte *)"AuthRetransmit", EAP_authStateRetransmit},
    {EAP_AUTH_STATE_VERIFY_MIC, (ubyte *)"AuthVerifyMIC", EAP_authStateVerifyMIC},
    {EAP_AUTH_STATE_NAK, (ubyte *)"AuthNAK", EAP_authStateNAK},
    {EAP_AUTH_STATE_METHOD, (ubyte *)"AuthMethod", EAP_authStateMethod}
};


/*------------------------------------------------------------------*/

/*Extern Definitions */
extern const ubyte *eapMethodStateString[];
extern const ubyte *eapMethodDecisionString[];
extern const ubyte nullIdentity [];


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authStateInit(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = (eapSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->eapSelectedMethod = EAP_TYPE_NONE;
    eapSession->eapMethodState = EAP_METHOD_STATE_INIT;
    eapSession->eapAllowNotification = FALSE;
    eapSession->eapRestart = FALSE;
    eapSession->eapSuccess = FALSE;
    eapSession->eapFail = FALSE;
    eapSession->eapKeyAvailable = FALSE;
    eapSession->eapLastId = 0;

    RANDOM_numberGenerator(g_pRandomContext, (ubyte *) &eapSession->eapLastId, 1);

    /* Change State to IDLE */
    status = EAP_authStateTransition(EAP_AUTH_STATE_IDLE, hdl, arg);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authStateIdle(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = (eapSessionCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->opaque_data = NULL;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authStateDisabled(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = (eapSessionCb_t *)hdl;
    MOC_UNUSED(arg);
    MOC_UNUSED(eapSession);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authStateReceived(void *hdl, void *arg)
{
    MSTATUS status = OK;
    ubyte2  expandedNak =0;
    eapSessionCb_t *eapSession = (eapSessionCb_t *)hdl;
    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    /* If AUTH State & Received Request Go To Discard */
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authStateReceived: Received Packet for Session Id = ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Code = ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvEapHdr.code);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Id = ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvEapHdr.id);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Length = ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvEapHdr.len);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, ", Type = ", eapSession->recvType);

    if (EAP_TYPE_IDENTITY == eapSession->recvType)
        eapSession->eapSessionStats.eap_pkts_rx_id_resp++;

    if (TRUE == eapSession->eapFail || FALSE == eapSession->eapPortEnabled)
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authStateReceived: Session ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Id = ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvEapHdr.id);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, ", eapLastId = ", eapSession->eapLastId);

        status = EAP_authStateTransition(EAP_AUTH_STATE_DISCARD, hdl, arg);
        goto exit;
    }

    if ((eapSession->recvEapHdr.id != eapSession->eapLastId) &&
       ((EAP_TYPE_LEAP != eapSession->recvType)              &&
       (EAP_CODE_REQUEST != eapSession->recvEapHdr.code)))
    {
        /* Go to DISCARD */
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authStateReceived: Session ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Discard Packet Received id ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvEapHdr.id);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, ", does not match sent id ", eapSession->eapLastId);

        status = EAP_authStateTransition(EAP_AUTH_STATE_DISCARD, hdl, arg);
        goto exit;
    }

    /* Check whether its a Expanded NAK Else extract out the vendor/method*/
    if (EAP_TYPE_EXPANDED == eapSession->recvType)
    {
        if ((EAP_VENDOR_ID_IETF == eapSession->recvVendorId) &&
            (EAP_TYPE_NAK == eapSession->recvMethodId))
        {
            expandedNak = 1;
        }
    }

    if (eapSession->recvEapHdr.id == eapSession->eapLastId)
    {
        /* Reset the previous request, cancel retransmission Should we do this
           here.. We may land up discarding the message then ??*/
        if (eapSession->eapSessionCfg.eap_max_retrans)
        {
            TIMER_unTimer(eapSession,eapSession->eapInstance->timerRetrans);

#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
            eapSession->radiusRetransTimeout = 0;
#endif
        }

        if (eapSession->eapReqData)
        {
            FREE(eapSession->eapReqData);
            eapSession->eapReqData = NULL;
            eapSession->eapReqDataLen = 0;
            eapSession->eapSendCode = 0;
        }
    }

    if ((EAP_TYPE_NAK == eapSession->recvType) ||
        (expandedNak))
    {
       if (EAP_METHOD_STATE_PROPOSED == eapSession->eapMethodState)
       {
            /* Go To NAK */
           status = EAP_authStateTransition(EAP_AUTH_STATE_NAK, hdl, arg);

           goto exit;
       }
       else
       {
           status = EAP_authStateTransition(EAP_AUTH_STATE_DISCARD, hdl, arg);
           goto exit;
       }
    }

    if (eapSession->sentType != eapSession->recvType)
    {
        /* Go to DISCARD */
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authStateReceived: Session ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Discard Packet Selected Method ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sentType);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, ", does not match received method ", eapSession->recvType);

        status = EAP_authStateTransition(EAP_AUTH_STATE_DISCARD, hdl, arg);
        goto exit;
    }

    /* Verify that the received Expanded Type is the same as that Sent */
    if (EAP_TYPE_EXPANDED == eapSession->recvType)
    {
        if ((eapSession->recvMethodId != eapSession->sentMethodId) ||
            (eapSession->recvVendorId != eapSession->sentVendorId))
        {
            /* Go to DISCARD */
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authStateReceived: Session ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Discard Packet Selected Expanded Type ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sentVendorId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sentMethodId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, " does not match received expanded type ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvVendorId);
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, ":", eapSession->eapMethodId);

            status = EAP_authStateTransition(EAP_AUTH_STATE_DISCARD, hdl, arg);
            goto exit;
        }
    }

    if (!eapSession->eapSelectedMethod)
    {
        if (EAP_TYPE_EXPANDED == eapSession->recvType)
        {
            eapSession->eapSelectedMethod = eapSession->sentType;
            eapSession->eapMethodId = eapSession->sentMethodId;
            eapSession->eapVendorId = eapSession->sentVendorId;

            DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authStateReceived: Session ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Selected Expanded Type ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sentVendorId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, ":", eapSession->sentMethodId);
        }
        else if ((EAP_TYPE_IDENTITY     != eapSession->recvType)&&
                 (EAP_TYPE_NOTIFICATION != eapSession->recvType)&&
                 (EAP_TYPE_NAK          != eapSession->recvType))
        {
            /* This method has been Selected now */
            eapSession->eapSelectedMethod = eapSession->sentType;
        }
    }

    eapSession->eapSessionStats.eap_pkts_ll_received++;
    status = EAP_authStateTransition(EAP_AUTH_STATE_VERIFY_MIC, hdl, arg);

exit:
    return status;
} /* EAP_authStateReceived */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authStateDiscard(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = (eapSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->recvEapHdr.code       = 0;
    eapSession->recvEapHdr.id         = 0;
    eapSession->recvEapHdr.len        = 0;
    eapSession->recvType              = 0;
    eapSession->recvMethodId          = 0;
    eapSession->recvVendorId          = 0;
    eapSession->opaque_data           = NULL;

    /* Ask the upper/lower Layer to Free the Pkt
       or somehow percolate the error to the layer
       so that it can handle it itself   */

    status = EAP_authStateTransition(EAP_AUTH_STATE_IDLE, eapSession, arg);

exit:
    if (OK == status)
        status = ERR_EAP_DISCARD_PKT;

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authStateSendRequest(void *hdl, void *arg)
{
    MSTATUS  status = OK;
    eapHdr_t eapHdr;
    eapSessionCb_t *eapSession = (eapSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (FALSE == eapSession->eapPortEnabled)
    {
        status = ERR_EAP_SESSION_DISABLED;
        goto exit;
    }

    if (EAP_SESSION_TYPE_AUTHENTICATOR == eapSession->session_type)
    {
/*******
        if (eapSession->eapLastId != eapSession->recvEapHdr.id)
        {
            DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO,
            (sbyte *)"Cannot send request when reply is pending.");
            status = ERR_EAP_REPLY_PENDING;
            goto exit;
        }
*******/

        if ((EAP_AUTH_STATE_RETRANSMIT != eapSession->eapAuthPrevState) &&
            (EAP_AUTH_STATE_SUCCESS    != eapSession->eapAuthPrevState) &&
            (EAP_CODE_RESPONSE         != eapSession->eapSendCode)      &&
            (EAP_AUTH_STATE_FAILURE    != eapSession->eapAuthPrevState))
        {
            if ((EAP_TYPE_SIM != eapSession->sentType) &&
                (EAP_TYPE_AKA != eapSession->sentType))
                eapSession->eapLastId++;
            else
                eapSession->eapLastId =
                          ((eapHdr_t *)eapSession->eapReqData)->id;
        }

        if ((EAP_TYPE_SIM == eapSession->sentType) ||
            (EAP_TYPE_AKA == eapSession->sentType))
        {
            status = eapSession->methodDef.funcPtr_llTransmitPacket (
                              eapSession->appSessionHandle,
                              (eapHdr_t *)eapSession->eapReqData,
                              (ubyte *)(eapSession->eapReqData + sizeof(eapHdr_t)),
                              eapSession->eapReqDataLen);
        }
        else
        {
        eapHdr.code                 = eapSession->eapSendCode;
        eapHdr.id                   = eapSession->eapLastId;
        eapHdr.len                  = eapSession->eapReqDataLen + sizeof(eapHdr_t);
        DIGI_HTONS((ubyte *)&eapHdr.len,eapHdr.len);

        status = eapSession->methodDef.funcPtr_llTransmitPacket (
                          eapSession->appSessionHandle,
                          &eapHdr ,
                          eapSession->eapReqData,
                          eapSession->eapReqDataLen);
        }
    }
    else if (EAP_SESSION_TYPE_PASSTHROUGH == eapSession->session_type)
    {
        status = eapSession->methodDef.funcPtr_llTransmitPacket (
                          eapSession->appSessionHandle,
                          (eapHdr_t *)eapSession->eapReqData,
                          (ubyte *)(eapSession->eapReqData + sizeof(eapHdr_t)),
                          eapSession->eapReqDataLen);
    }

    eapSession->eapSessionStats.eap_pkts_ll_sent++;
    if (EAP_TYPE_IDENTITY == eapSession->sentType)
        eapSession->eapSessionStats.eap_pkts_tx_id_req++;

    status = EAP_authStateTransition(EAP_AUTH_STATE_IDLE, eapSession, arg);

exit:
    return status;
} /* EAP_authStateSendRequest */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authStateNAK(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = (eapSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    status = EAP_authStateTransition(EAP_AUTH_STATE_METHOD, hdl, arg);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authStateSuccess(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = (eapSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->eapSuccess = TRUE;

    /* Remove Retransmit Timers && Free Req Buffer */
    if (eapSession->eapSessionCfg.eap_max_retrans)
    {
        TIMER_unTimer(eapSession,eapSession->eapInstance->timerRetrans);

#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
        eapSession->radiusRetransTimeout = 0;
#endif
    }
    if (eapSession->eapSessionCfg.eap_ul_timeout)
    {
        TIMER_unTimer(eapSession,eapSession->eapInstance->timerSession);
    }

    if (eapSession->eapReqData)
    {
       FREE(eapSession->eapReqData);
       eapSession->eapReqData = NULL;
       eapSession->eapReqDataLen = 0;
    }

    /* Send Success Packet */
    if (EAP_TYPE_LEAP != eapSession->eapSelectedMethod)
        eapSession->sentType = 0;
    eapSession->eapSendCode = EAP_CODE_SUCCESS;

    status = EAP_authStateTransition(EAP_AUTH_STATE_SEND_REQUEST, eapSession, arg);

exit:
    return status;
    /* Transition To IDLE To and Go To Restart automatically */
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authStateFailure(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession  = (eapSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->eapFail         = TRUE;
    eapSession->sentType        = 0;

    if (eapSession->eapSessionCfg.eap_max_retrans)
    {
        TIMER_unTimer(eapSession,eapSession->eapInstance->timerRetrans);

#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
        eapSession->radiusRetransTimeout = 0;
#endif
    }
    if (eapSession->eapSessionCfg.eap_ul_timeout)
    {
        TIMER_unTimer(eapSession,eapSession->eapInstance->timerSession);
    }

    if (eapSession->eapReqData)
    {
       FREE(eapSession->eapReqData);
       eapSession->eapReqData = NULL;
       eapSession->eapReqDataLen = 0;
    }

    /* Send Failure Packet */
    eapSession->sentType        = 0;
    eapSession->eapSendCode     = EAP_CODE_FAILURE;

    status = EAP_authStateTransition(EAP_AUTH_STATE_SEND_REQUEST, eapSession, arg);

    /* Transition To IDLE Should Drop All Packets Till Restart
        is called by the layer */
exit:
    return status;
} /* EAP_authStateFailure */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authStateVerifyMIC(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = (eapSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (eapSession->methodDef.funcPtr_ulMICVerify)
    {
        status = eapSession->methodDef.funcPtr_ulMICVerify(
                                            eapSession->appSessionHandle,
                                            arg,
                                            eapSession->recvEapHdr.len);
    }

    if (OK != status)
    {
        /* Possible bug: do you want to comment out 'status =' */
        status = EAP_authStateTransition(EAP_AUTH_STATE_DISCARD, hdl, arg);
    }
    else
    {
        status = EAP_authStateTransition(EAP_AUTH_STATE_METHOD, hdl, arg);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authStateMethod(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = (eapSessionCb_t *)hdl;
    ubyte4 len = 0;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (EAP_SESSION_TYPE_AUTHENTICATOR == eapSession->session_type)
    {
        if ((EAP_TYPE_IDENTITY != eapSession->recvType) &&
            (EAP_TYPE_NAK != eapSession->recvType) &&
            (EAP_TYPE_SIM != eapSession->recvType) &&
            (EAP_TYPE_AKA != eapSession->recvType) &&
            (EAP_TYPE_EXPANDED != eapSession->recvType))
        {
            len = eapSession->recvEapHdr.len - sizeof(eapHdr_t);
        }
        else
        {
            len = eapSession->recvEapHdr.len;
        }

        if (!eapSession->methodDef.funcPtr_ulReceiveCallback )
        {
            status = ERR_EAP_INVALID_CALLBACK_FN;
            goto exit;
        }
        status = eapSession->methodDef.funcPtr_ulReceiveCallback (
                                        eapSession->appSessionHandle,
                                        eapSession->recvType,
                                        eapSession->recvEapHdr.code,
                                        eapSession->recvEapHdr.id,
                                        arg,
                                        len,
                                        eapSession->opaque_data);
    }
    else if (EAP_SESSION_TYPE_PASSTHROUGH == eapSession->session_type)
    {
        /* Call passthrough callback */
        if (!eapSession->methodDef.funcPtr_ulReceivePassthruCallback )
        {
            status = ERR_EAP_INVALID_CALLBACK_FN;
            goto exit;
        }
        status = eapSession->methodDef.funcPtr_ulReceivePassthruCallback (
                                        eapSession->appSessionHandle,
                                        eapSession->recvType,
                                        eapSession->recvEapHdr.code,
                                        eapSession->recvEapHdr.id,
                                        arg,
                                        eapSession->recvEapHdr.len,
                                        eapSession->opaque_data);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authStateRetransmit(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = (eapSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (eapSession->eapReqData)
    {
       /* Go to Send Resp */
        status = EAP_authStateTransition(EAP_AUTH_STATE_SEND_REQUEST, hdl, arg);
    }

    /* Increment the count and restart the restransmit timer */

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authValidatePacket(eapSessionCb_t* session,
                       ubyte* pktBuffer,
                       ubyte4 pktLen)
{
    MSTATUS status = OK;
    eapHdr_t * eapHdr = (eapHdr_t *)pktBuffer;
    ubyte pktType;
    ubyte4 expVendorId= 0,expMethodId=0;

    if ((NULL == session) || (NULL == eapHdr))
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (pktLen < sizeof(eapHdr_t))
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authValidatePacket: Session Id ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, session->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(session->eapIdentity ? session->eapIdentity : nullIdentity));
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " received short packet < eapHdr Len: ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, pktLen);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

        status = ERR_EAP_INVALID_PKT_SIZE;
        goto exit;
    }

    session->recvEapHdr.code = eapHdr->code;
    session->recvEapHdr.id   = eapHdr->id;
    session->recvEapHdr.len  = DIGI_NTOHS(pktBuffer + 2);
    session->recvType = 0;
    session->recvMethodId = 0;
    session->recvVendorId = 0;

    switch (session->recvEapHdr.code)
    {
        case EAP_CODE_REQUEST:
        {
            if (EAP_TYPE_LEAP != session->eapSelectedMethod)
            {
                status = ERR_EAP_INVALID_PKT;
                break;
            }
        }

        case EAP_CODE_RESPONSE:
        {
            if (pktLen < sizeof(eapHdr_t) + 1)
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authValidatePacket: Session Id ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, session->sessionId);
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " received short packet < eapHdr+1 Len:");
                DEBUG_INT(DEBUG_EAP_MESSAGE, pktLen);
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

                status = ERR_EAP_INVALID_PKT_SIZE;
                goto exit;
            }

            if (session->recvEapHdr.len > pktLen)
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authValidatePacket: Session Id ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, session->sessionId);
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " received short Pkt Header Len ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, session->recvEapHdr.len);
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

                status = ERR_EAP_INVALID_PKT_SIZE;
                goto exit;
            }

            pktType = *(ubyte *) ((ubyte *)eapHdr
                                            + sizeof(eapHdr_t));
            session->recvType = pktType;

            if (EAP_TYPE_EXPANDED == pktType)
            {
                /* Verify that Vendor Id and Method Id Match */
                if (session->recvEapHdr.len < (sizeof(eapHdr_t) + 8))
                {
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authValidatePacket: Session Id ");
                    DEBUG_INT(DEBUG_EAP_MESSAGE, session->sessionId);
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(session->eapIdentity ? session->eapIdentity : nullIdentity));
                    DEBUG_ERROR(DEBUG_EAP_MESSAGE, " Invalid Expanded Len ", session->recvEapHdr.len);

                    status = ERR_EAP_INVALID_PKT_SIZE;
                    goto exit;
                }

                DIGI_MEMCPY((ubyte *)&expVendorId,(ubyte *)pktBuffer + sizeof(eapHdr_t)+1,3);
                DIGI_MEMCPY((ubyte *)&expMethodId,(ubyte *)pktBuffer + sizeof(eapHdr_t)+4,4);
                session->recvVendorId = EAP_NTOHL(expVendorId);
                session->recvMethodId = EAP_NTOHL(expMethodId);
            }

            break;
        }

        case EAP_CODE_SUCCESS:
        case EAP_CODE_FAILURE:
        {
            session->recvType = 0;
            status = ERR_EAP_INVALID_PKT;
            break;
        }

        default:
        {
            status = ERR_EAP_INVALID_PKT;
            break;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/****f* src/eap/EAP_authProcessRestart
*
*  NAME
*   EAP_authProcessRestart -- Restart the auth session
*  SYNOPSIS
*
*   #include "../eap/eap_auth.h"
*
*   extern  MSTATUS
*    EAP_authProcessRestart (eapSessionCb_t * eapSession)
*
*  FUNCTION
*  Called by the application to Restart the auth session or by EAP to create a
*  new session.
*
*  INPUTS
*    eapSession : EAP Session Handle
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_sessionCreate
******/

extern MSTATUS
EAP_authProcessRestart(eapSessionCb_t *eapSession)
{
    MSTATUS status = OK;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (TRUE == eapSession->eapPortEnabled)
    {
        status = EAP_authStateTransition(EAP_AUTH_STATE_INIT, eapSession, NULL);
    }
    else
    {
        status = EAP_authStateTransition(EAP_AUTH_STATE_DISABLED, eapSession, NULL);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
EAP_authSessionDisable(eapSessionCb_t *eapSession)
{
    MSTATUS status;

    status = EAP_authStateTransition(EAP_AUTH_STATE_DISABLED, eapSession, NULL);

    return status;
}


/*------------------------------------------------------------------*/

/****f* src/eap/EAP_passthruProcessULTransmit
*
*  NAME
*  EAP_passthruProcessULTransmit-- passthru specific transmit of EAP packet
*  SYNOPSIS
*
*   #include "../eap/eap_auth.h"
*   extern MSTATUS EAP_passthruProcessULTransmit (eapSessionCb_t * eapSession,
*                           eapMethodDecision  methodDecision,
*                           eapMethodState methodState,
*                           ubyte * eap_pkt)
*
*
*  FUNCTION
*  Called by the EAP to transmit a auth specific EAP packet
*
*  INPUTS
*    eapSessionHdl   : EAP Session Handle
*    methodDecision  : decision value
*    methodState     : Method State value
*    eap_pkt         : pointer to EAP pkt
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_ulTransmit
******/

extern MSTATUS
EAP_passthruProcessULTransmit(eapSessionCb_t *eapSession,
                              ubyte *eap_pkt)
{
    MSTATUS status = OK;
    eapHdr_t *eapHdr = (eapHdr_t *)eap_pkt;
    ubyte method_type = EAP_TYPE_NONE;
    ubyte2 len = 0;
    ubyte4 expMethodId = 0,expVendorId =0;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (NULL == eap_pkt)
    {
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "No data to be transmitted");
        goto exit;
    }

    len = DIGI_NTOHS(eap_pkt+2);

    /* Copy id from packet */
    eapSession->eapLastId = eapHdr->id;

    if (EAP_CODE_RESPONSE == eapHdr->code || eapHdr->code > EAP_CODE_FAILURE)
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_passthruProcessULTransmit: Session Id ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, ", Cannot Send an Invalid code ", eapHdr->code);

        status = ERR_EAP_INVALID_CODE;
        goto exit;
    }

    /* Check That we dont send an Out of Order Request
        If one is already pending return error*/

    if ((!eapSession->eapSelectedMethod) &&
        (EAP_CODE_REQUEST == eapHdr->code))
    {
        method_type = *(eap_pkt + sizeof(eapHdr_t));
        if ((EAP_TYPE_IDENTITY     == method_type) ||
            (EAP_TYPE_NOTIFICATION == method_type))
        {
            eapSession->eapMethodState = EAP_METHOD_STATE_CONTINUE;
        }
        else
        {
            eapSession->eapMethodState = EAP_METHOD_STATE_PROPOSED;
        }
    }
    if (EAP_TYPE_EXPANDED == method_type)
    {
       /* Verify length */
        if (len < sizeof(eapHdr_t)+8)
        {
            status = ERR_EAP_INVALID_PKT_SIZE;
            goto exit;
        }

        DIGI_MEMCPY((ubyte *)&expVendorId,(ubyte *)eap_pkt+sizeof(eapHdr_t)+1,3);
        DIGI_MEMCPY((ubyte *)&expMethodId,(ubyte *)eap_pkt+sizeof(eapHdr_t)+4,4);
    }

    if ((eapSession->eapSelectedMethod) &&
        (EAP_CODE_REQUEST == eapHdr->code))
    {
        method_type = *(eap_pkt + sizeof(eapHdr_t));
        if ((eapSession->eapSelectedMethod != method_type) &&
            (EAP_TYPE_TLV                  != method_type))
        {
            if (EAP_TYPE_NOTIFICATION != method_type)
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_passthruProcessULTransmit: Session Id ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Invalid Method Type ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, method_type);
                DEBUG_ERROR(DEBUG_EAP_MESSAGE, " Type has to Match Selected ", eapSession->eapSelectedMethod);

                status = ERR_EAP_INVALID_METHOD_TYPE;
                goto exit;
            }
        }
        if (EAP_TYPE_EXPANDED == method_type)
        {
            if ((eapSession->eapMethodId != expMethodId) ||
               (eapSession->eapVendorId != expVendorId))
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_passthruProcessULTransmit: Session Id ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Invalid Expanded Method Type ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, expVendorId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
                DEBUG_INT(DEBUG_EAP_MESSAGE, expMethodId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Type has to Match Selected ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->eapVendorId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->eapMethodId);
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "");

                status = ERR_EAP_INVALID_METHOD_TYPE;
                goto exit;
            }
        }
    }

    if (EAP_CODE_SUCCESS == eapHdr->code)
    {
        eapSession->eapMethodState = EAP_METHOD_STATE_END;
        eapSession->eapDecision = EAP_METHOD_DECISION_SUCCESS;
        eapSession->eapSuccess = TRUE;
    }
    else if (EAP_CODE_FAILURE == eapHdr->code)
    {
        eapSession->eapMethodState = EAP_METHOD_STATE_END;
        eapSession->eapDecision = EAP_METHOD_DECISION_FAILURE;
    }
    else if (eapSession->eapSelectedMethod)
    {
        eapSession->eapMethodState = EAP_METHOD_STATE_CONTINUE;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_passthruProcessULTransmit: Session ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Transmit Code ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapHdr->code);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Type ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, method_type);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Method State ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)eapMethodStateString[eapSession->eapMethodState]);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "");

    if (eapSession->eapReqData)
    {
        /* Free this buffer */
        FREE(eapSession->eapReqData);
        eapSession->eapReqData = NULL;
        eapSession->eapReqDataLen = 0;
    }

    /* Alloc a New Buffer and copy the pkt there */
    eapSession->eapReqData = (ubyte *)MALLOC(len);

    if (NULL == eapSession->eapReqData)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    eapSession->eapRetransCount = 0;

    DIGI_MEMCPY((ubyte *)eapSession->eapReqData, (ubyte *)eap_pkt, len);
    eapSession->eapReqDataLen = len;
    eapSession->eapSendCode = eapHdr->code;
    eapSession->sentType = method_type;

    /* Start Retransmission Timer if required */
    if ((EAP_METHOD_STATE_END != eapSession->eapMethodState) &&
        eapSession->eapSessionCfg.eap_max_retrans)
    {
#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
        if (eapSession->radiusRetransTimeout != 0)
        {
            TIMER_queueTimer(eapSession,eapSession->eapInstance->timerRetrans,
                             eapSession->radiusRetransTimeout,0);
        }
        else
#endif
        if (eapSession->eapSessionCfg.eap_retrans_timeout != 0)
        {
            TIMER_queueTimer(eapSession,eapSession->eapInstance->timerRetrans,
                             eapSession->eapSessionCfg.eap_retrans_timeout,0);
        }
    }

    status = EAP_authStateTransition(EAP_AUTH_STATE_SEND_REQUEST, eapSession, eap_pkt);

exit:
    return status;
} /* EAP_passthruProcessULTransmit */


/*------------------------------------------------------------------*/

/****f* src/eap/EAP_authProcessULTransmit
*
*  NAME
*  EAP_authProcessULTransmit  -- auth specific transmit of EAP packet
*  SYNOPSIS
*
*   #include "../eap/eap_auth.h"
*   extern MSTATUS EAP_authProcessULTransmit (eapSessionCb_t * eapSession,
*                           eapMethodType  method_type,
*                           eapCode  code,
*                           eapMethodDecision  methodDecision,
*                           eapMethodState methodState,
*                           ubyte * eap_data,
*                           ubyte4  eap_data_len)
*
*
*  FUNCTION
*  Called by the EAP to transmit a auth specific EAP packet
*
*  INPUTS
*    eapSessionHdl   : EAP Session Handle
*    method_type     : EAP Method Type
*    code            : EAP code field
*    methodDecision  : decision value
*    methodState     : Method State value
*    eap_data        : pointer to EAP payload
*    eap_data_len    : length of EAP payload
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_ulTransmit
******/

extern MSTATUS
EAP_authProcessULTransmit(eapSessionCb_t *eapSession,
                          eapMethodType method_type,
                          eapCode code,
                          eapMethodDecision methodDecision,
                          eapMethodState methodState,
                          ubyte *eap_data,
                          ubyte4 eap_data_len)
{
    ubyte4  expVendorId = 0;
    ubyte4  expMethodId = 0;
    MSTATUS status      = OK;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (((EAP_CODE_RESPONSE == code) && (method_type != EAP_TYPE_LEAP)) ||
        (code > EAP_CODE_FAILURE))
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authProcessULTransmit: Session Id ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Cannot Send an Invalid Code ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, code);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "");

        status = ERR_EAP_INVALID_CODE;
        goto exit;
    }

    if (EAP_TYPE_EXPANDED == method_type)
    {
        DIGI_MEMCPY((ubyte *) &expVendorId,eap_data,3);
        DIGI_MEMCPY((ubyte *) &expMethodId,eap_data+3,4);
        expVendorId = EAP_NTOHL(expVendorId);
        expMethodId = EAP_NTOHL(expMethodId);

        if ((EAP_VENDOR_ID_IETF == expVendorId) &&
            (EAP_TYPE_NAK == expMethodId))
        {
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authProcessULTransmit: Session Id ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Cannot Send a Expanded Nak");

            status = ERR_EAP_INVALID_METHOD_TYPE;
            goto exit;
        }
    }

    /* Check that we don't send an out of order request, if one is already pending return error */
    if ((!eapSession->eapSelectedMethod) &&
        (EAP_CODE_REQUEST == code))
    {
        if ((EAP_TYPE_IDENTITY     == method_type) ||
            (EAP_TYPE_NOTIFICATION == method_type))
        {
            eapSession->eapMethodState = EAP_METHOD_STATE_CONTINUE;
        }
        else
        {
            eapSession->eapMethodState = EAP_METHOD_STATE_PROPOSED;
        }
    }

    if ((eapSession->eapSelectedMethod) &&
        (EAP_CODE_REQUEST == code))
    {
        if (eapSession->eapSelectedMethod != method_type)
        {
            if ((EAP_TYPE_NOTIFICATION != method_type) &&
                (EAP_TYPE_TLV          != method_type))
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authProcessULTransmit: Session Id ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Invalid Method Type ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, method_type);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, "Type has to Match Selected ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->eapSelectedMethod);
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "");

                status = ERR_EAP_INVALID_METHOD_TYPE;
                goto exit;
            }
        }

        if (EAP_TYPE_EXPANDED == method_type)
        {
            if ((eapSession->eapVendorId != expVendorId) ||
                (eapSession->eapMethodId != expMethodId))
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authProcessULTransmit: Session Id ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Invalid Expanded Method Type ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, expVendorId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
                DEBUG_INT(DEBUG_EAP_MESSAGE, expMethodId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Type has to Match Selected ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->eapVendorId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->eapMethodId);
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "");

                status = ERR_EAP_INVALID_METHOD_TYPE;
                goto exit;

            }
        }
    }
    if (((EAP_CODE_SUCCESS == code) && (method_type != EAP_TYPE_LEAP)) ||
        (EAP_CODE_FAILURE == code))
    {
        /* If Code is SUCCESS || Failure , Method State has to End */
        if (EAP_METHOD_STATE_END != methodState)
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Code is SUCCESS/FAILURE, method State is Not END");
        }

        methodState = EAP_METHOD_STATE_END;
    }

    if (EAP_CODE_SUCCESS == code)
        methodDecision = EAP_METHOD_DECISION_SUCCESS;

    if (EAP_CODE_FAILURE == code)
        methodDecision = EAP_METHOD_DECISION_FAILURE;

    if ((EAP_METHOD_STATE_END == methodState) || (EAP_TYPE_LEAP == method_type))
    {
        if (EAP_METHOD_DECISION_SUCCESS == methodDecision)
        {
            status = EAP_authStateTransition(EAP_AUTH_STATE_SUCCESS, eapSession, NULL);

            goto exit;
        }
        else if (EAP_METHOD_DECISION_FAILURE == methodDecision)
        {
            status = EAP_authStateTransition(EAP_AUTH_STATE_FAILURE, eapSession, NULL);
            goto exit;
        }
    }

    if (eapSession->eapSelectedMethod)
    {
        eapSession->eapMethodState = EAP_METHOD_STATE_CONTINUE;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authProcessULTransmit: Session ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Transmit Code ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, code);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, ", Type ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, method_type);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Method State ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)eapMethodStateString[methodState]);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "");

    if (eapSession->eapReqData)
    {
        /* Free this buffer */
        FREE (eapSession->eapReqData);
        eapSession->eapReqData = NULL;
        eapSession->eapReqDataLen = 0;
    }

    /* Alloc a New Buffer and copy th epkt There */
    eapSession->eapReqData = (ubyte *) MALLOC(eap_data_len+1);
    if (NULL == eapSession->eapReqData)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eapSession->eapRetransCount = 0;

    /* EAP SIM Sends the Full Packet Down */
    if ((EAP_TYPE_SIM != method_type) &&
        (EAP_TYPE_AKA != method_type))
        *eapSession->eapReqData = method_type;

    if (eap_data_len)
    {
        if ((EAP_TYPE_SIM != method_type) &&
            (EAP_TYPE_AKA != method_type))
            DIGI_MEMCPY((ubyte *)eapSession->eapReqData+1,
                       (ubyte *)eap_data,
                       eap_data_len);
        else
            DIGI_MEMCPY((ubyte *)eapSession->eapReqData,
                       (ubyte *)eap_data,
                       eap_data_len);
    }

    eapSession->eapReqDataLen = eap_data_len+1;
    eapSession->eapSendCode = code;
    eapSession->sentType = method_type;
    eapSession->sentMethodId = expMethodId;
    eapSession->sentVendorId = expVendorId;

    /* Start Retransmission Timer if required */
    eapSession->eapRetransCount++;

    if (eapSession->eapSessionCfg.eap_max_retrans &&
        eapSession->eapSessionCfg.eap_retrans_timeout)
    {
        if (EAP_CODE_REQUEST == code)
        {
            TIMER_queueTimer(eapSession,eapSession->eapInstance->timerRetrans,
                             eapSession->eapSessionCfg.eap_retrans_timeout,0);
        }
    }

    status = EAP_authStateTransition(EAP_AUTH_STATE_SEND_REQUEST, eapSession, eap_data);

exit:
    return status;
} /* EAP_authProcessULTransmit */


/*------------------------------------------------------------------*/

/****f* src/eap/EAP_authProcessllReceivePacket
*
*  NAME
*   EAP_authProcessllReceivePacket  -- auth specific processing of EAP packet
*  SYNOPSIS
*
*   #include "../eap/eap_session.h"
*
*   extern MSTATUS
*   EAP_authProcessllReceivePacket (eapSessionCb_t *eapSession,
*                                ubyte * eap_pkt,
*                                ubyte4 eap_pkt_len,
*                                ubyte * opaque_data)
*
*  FUNCTION
*  Called by the EAP to trigger Authenticator state machine for processing of
*  packet received from the lower layer.
*
*  INPUTS
*    eapSessionHdl : EAP Session Handle
*    eap_pkt       : EAP Payload
*    eap_pkt_len   : EAP Payload Length
*    opaque_data   : Pointer to deliver to Method Layer
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_llReceivePacket
******/

extern MSTATUS
EAP_authProcessllReceivePacket(eapSessionCb_t *eapSession,
                               ubyte * eap_pkt,
                               ubyte4 eap_pkt_len,
                               ubyte * opaque_data)
{
    MSTATUS status = OK;
    ubyte *pkt_ptr = NULL;
    ubyte expandedNak = 0;

    eapSession->opaque_data = NULL;
    status = EAP_authValidatePacket(eapSession,
                                    eap_pkt,
                                    eap_pkt_len);

    if (OK > status)
    {
        /* Transition to DISCARD */
        status = EAP_authStateTransition(EAP_AUTH_STATE_DISCARD, eapSession, eap_pkt);
    }
    else
    {
        /* Transition to RECEIVE Packet */
        eapSession->opaque_data = opaque_data;
        pkt_ptr = eap_pkt;

        if (EAP_SESSION_TYPE_AUTHENTICATOR == eapSession->session_type)
        {
            /* Check whether its a Expanded NAK */
            if (EAP_TYPE_EXPANDED == eapSession->recvType)
            {
                if ((EAP_VENDOR_ID_IETF == eapSession->recvVendorId) &&
                    (EAP_TYPE_NAK == eapSession->recvMethodId))
                {
                    expandedNak = 1;
                }
            }

            if ((EAP_TYPE_IDENTITY != eapSession->recvType) &&
                (EAP_TYPE_NAK != eapSession->recvType) &&
                (EAP_TYPE_SIM != eapSession->recvType) &&
                (EAP_TYPE_AKA != eapSession->recvType) &&
                (!expandedNak))
            {
                pkt_ptr = eap_pkt + sizeof(eapHdr_t);
            }
        }

        status = EAP_authStateTransition(EAP_AUTH_STATE_RECEIVED, eapSession, pkt_ptr);
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_authStateTransition(eapAuthState_t newState,
                        void *session,
                        void * arg)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = (eapSessionCb_t *)session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_authStateTransition: Transition Session ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " from State ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)eap_AuthStateBits[eapSession->eapAuthCurrentState].stateDescription);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " to ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)eap_AuthStateBits[newState].stateDescription);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "");

    eapSession->eapAuthPrevState    = eapSession->eapAuthCurrentState;
    eapSession->eapAuthCurrentState = newState;
    status = eap_AuthStateBits[newState].stateFn (session,arg);

exit:
    return status;
}

/****f* src/eap/EAP_authRetransmitTimeout
*
*  NAME
*   EAP_authRetransmitTimeout -- Callback function on timeout expiry
*  SYNOPSIS
*
*   #include "../eap/eap_session.h"
*
*   extern void
*   EAP_authRetransmitTimeout (void *session)
*
*  FUNCTION
*  This function is called for handling handling retransmisions in case of
*  timeouts in case of auth sessions.
*
*
*  INPUTS
*    session : EAP Session Handle
*    type    : Type of timer
*
*
*  SEE ALSO
*   src/eap/EAP_timeoutCallback
******/

extern MSTATUS
EAP_authRetransmitTimeout(void *session)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = (eapSessionCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->eapRetransCount++;

    if (eapSession->eapSessionCfg.eap_max_retrans > eapSession->eapRetransCount)
    {
#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
        if (EAP_SESSION_TYPE_PASSTHROUGH == eapSession->session_type &&
            eapSession->radiusRetransTimeout != 0)
        {
            TIMER_queueTimer(eapSession,eapSession->eapInstance->timerRetrans,
                             eapSession->radiusRetransTimeout,0);
        }
        else
#endif
        if (eapSession->eapSessionCfg.eap_retrans_timeout != 0)
        {
            TIMER_queueTimer(eapSession,eapSession->eapInstance->timerRetrans,
                             eapSession->eapSessionCfg.eap_retrans_timeout,0);
        }

        status = EAP_authStateTransition(EAP_AUTH_STATE_RETRANSMIT, eapSession, NULL);
    }
    else
    {
        /* Send Indication Up  Clean up the Req Buffer ?*/
        if (eapSession->eapReqData)
        {
            /* Free this buffer */
            FREE (eapSession->eapReqData);
            eapSession->eapReqData = NULL;
            eapSession->eapReqDataLen = 0;
        }

        eapSession->eapFail  = TRUE;
        eapSession->sentType = 0;

        status = eapSession->methodDef.funcPtr_ulReceiveIndication(
                                        eapSession->appSessionHandle,
                                        EAP_INDICATION_RETRANSMIT_TIMEOUT,
                                        NULL,0);
    }

exit:
    return status;
} /* EAP_authRetransmitTimeout */

#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) */

