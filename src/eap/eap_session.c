/**
 * @file  eap_session.c
 * @brief EAP session management implementation
 *
 * @details    EAP session handling and state machine
 * @since      1.41
 * @version    1.41 and later
 *
 * @flags      Compilation flags required:
 *     + \c \__ENABLE_DIGICERT_EAP_PEER__
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

#if defined(__ENABLE_DIGICERT_EAP_PEER__)

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
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/rsa.h"
#include "../crypto/des.h"
#include "../crypto/dh.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/hw_accel.h"
#include "../common/redblack.h"
#include "../common/timer.h"
#include "../eap/eap.h"
#include "../eap/eap_auth.h"
#include "../eap/eap_session.h"


/*------------------------------------------------------------------*/

/* Local Methods */
static MSTATUS eap_peerStateTransition(eapState_t newState,
                                       void *session,
                                       void * arg);
static MSTATUS eap_peerInitReAuth (eapSessionCb_t * eapSession);

static MSTATUS eap_peerStateDisabled (void *, void *);
static MSTATUS eap_peerStateInit (void *, void *);
static MSTATUS eap_peerStateIdle (void *, void *);
static MSTATUS eap_peerStateReceived (void *, void *);
static MSTATUS eap_peerStateDiscard (void *, void *);
static MSTATUS eap_peerStateSendResponse(void *, void *);
static MSTATUS eap_peerStateSuccess(void *, void *);
static MSTATUS eap_peerStateFailure(void *, void *);
static MSTATUS eap_peerStateRetransmit(void *, void *);
static MSTATUS eap_peerStateGetMethod(void *, void *);
static MSTATUS eap_peerStateIdentity(void *, void *);
static MSTATUS eap_peerStateNotification(void *, void *);
static MSTATUS eap_peerStateMethod(void *, void *);


/*------------------------------------------------------------------*/

const eapStateBits_t eap_PeerStateBits[] =
{
    {0, (ubyte *)"NoState",NULL },
    {EAP_PEER_STATE_DISABLED, (ubyte *)"PeerDisabled",eap_peerStateDisabled},
    {EAP_PEER_STATE_INIT, (ubyte *)"PeerInit",eap_peerStateInit},
    {EAP_PEER_STATE_IDLE, (ubyte *)"PeerIdle",eap_peerStateIdle},
    {EAP_PEER_STATE_RECEIVED, (ubyte *)"PeerReceive",eap_peerStateReceived},
    {EAP_PEER_STATE_DISCARD, (ubyte *)"PeerDiscard",eap_peerStateDiscard},
    {EAP_PEER_STATE_SEND_RESPONSE, (ubyte *)"PeerSendResponse",eap_peerStateSendResponse},
    {EAP_PEER_STATE_SUCCESS, (ubyte *)"PeerSuccess",eap_peerStateSuccess},
    {EAP_PEER_STATE_FAILURE, (ubyte *)"PeerFailure",eap_peerStateFailure},
    {EAP_PEER_STATE_RETRANSMIT, (ubyte *)"PeerRetransmit",eap_peerStateRetransmit},
    {EAP_PEER_STATE_GET_METHOD, (ubyte *)"PeerGetMethod",eap_peerStateGetMethod},
    {EAP_PEER_STATE_IDENTITY, (ubyte *)"PeerIdentity",eap_peerStateIdentity},
    {EAP_PEER_STATE_NOTIFICATION, (ubyte *)"PeerNotification",eap_peerStateNotification},
    {EAP_PEER_STATE_METHOD, (ubyte *)"PeerMethod",eap_peerStateMethod}
};


/*------------------------------------------------------------------*/

/*Extern Definitions */
extern const ubyte * eapMethodStateString[];
extern const ubyte * eapMethodDecisionString[];
extern const ubyte nullIdentity [];


/*------------------------------------------------------------------*/

static  MSTATUS
eap_peerStateInit(void *hdl, void *arg)
{
    eapSessionCb_t *eapSession  = (eapSessionCb_t *)hdl;
    MSTATUS status = OK;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->eapSelectedMethod = EAP_TYPE_NONE;
    eapSession->eapMethodState = EAP_METHOD_STATE_INIT;
    eapSession->eapDecision = EAP_METHOD_DECISION_FAIL;
    eapSession->eapAllowNotification = FALSE;
    eapSession->eapRestart = FALSE;
    eapSession->eapSuccess = FALSE;
    eapSession->eapFail = FALSE;
    eapSession->eapKeyAvailable = FALSE;
    eapSession->sentType = 0;
    eapSession->eapRounds = 0;
    eapSession->eapLastId = 0;
    eapSession->eapRecvdStartRequest = FALSE;

    /* Make this Configuraiton Based */
    DIGI_MEMSET(eapSession->lastMD5,0,MD5_DIGESTSIZE);
    DIGI_MEMSET(eapSession->recvMD5,0,MD5_DIGESTSIZE);

    if (eapSession->eapRespData)
    {
        FREE (eapSession->eapRespData);
    }

    eapSession->eapRespData    = NULL;
    eapSession->eapRespDataLen = 0;

    if (eapSession->eapIdentity)
    {
        FREE (eapSession->eapIdentity);
    }

    eapSession->eapIdentity   = NULL;
    eapSession->eapIdentityLen = 0;

    if (eapSession->eapKeyData)
    {
        FREE (eapSession->eapKeyData);
    }

    eapSession->eapKeyData    = NULL;
    eapSession->eapKeyDataLen = 0;
    eapSession->eapKeyAvailable = FALSE;

    /* Change State to IDLE */
    status = eap_peerStateTransition(EAP_PEER_STATE_IDLE, hdl, arg);

exit:
    return status;

} /* eap_peerStateInit */


/*------------------------------------------------------------------*/

static MSTATUS
eap_peerStateIdle(void *hdl, void *arg)
{
    eapSessionCb_t *eapSession  = (eapSessionCb_t *)hdl;
    MSTATUS status = OK;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->opaque_data = NULL;
    if ((EAP_METHOD_STATE_DONE     == eapSession->eapMethodState) &&
        (EAP_METHOD_DECISION_FAIL  == eapSession->eapDecision  ))
    {
        /* Go To Failure */
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateIdle: Session ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Decision FAIL");
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

        status = eap_peerStateTransition(EAP_PEER_STATE_FAILURE, hdl, arg);
        goto exit;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static  MSTATUS
eap_peerStateDisabled(void* hdl, void *arg)
{
    MOC_UNUSED(hdl);
    MOC_UNUSED(arg);

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_peerStateReceived(void* hdl, void *arg)
{
    eapSessionCb_t *eapSession  = (eapSessionCb_t *)hdl;
    MSTATUS status = OK;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateReceived: Session ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Code ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvEapHdr.code);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Type ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvType);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Id ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvEapHdr.id);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Len ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvEapHdr.len);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    if (TRUE == eapSession->eapFail || FALSE == eapSession->eapPortEnabled)
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateReceived: Session ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Discarding Packet. State is FAIL");
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

        status = eap_peerStateTransition(EAP_PEER_STATE_DISCARD, hdl, arg);
        goto exit;
    }

    /* If its a canned SUCCESS Discard */
    if ((EAP_CODE_SUCCESS == eapSession->recvEapHdr.code) &&
        (!eapSession->eapSelectedMethod))
    {
        if ((EAP_CODE_SUCCESS == eapSession->recvEapHdr.code) &&
            (eapSession->eapSessionCfg.eap_options & EAP_OPTIONS_ENABLE_FORCED_AUTH))
        {
            status = eap_peerStateTransition(EAP_PEER_STATE_SUCCESS, hdl, arg);
            goto exit;
        }

        status = eap_peerStateTransition(EAP_PEER_STATE_DISCARD, hdl, arg);
        goto exit;
    }

    if ((eapSession->recvType) && (eapSession->eapSelectedMethod))
    {
        /* Verify that Vendor Id and Method Id Match */
        if (EAP_TYPE_EXPANDED == eapSession->eapSelectedMethod)
        {
            /* Verify that Vendor Id and Method Id Match */
            if ((eapSession->recvVendorId != eapSession->eapVendorId) ||
               (eapSession->recvMethodId != eapSession->eapMethodId))
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateReceived: Session ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Invalid Expanded Method Type ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvVendorId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvMethodId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Type has to Match Selected or received Type ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->eapVendorId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->eapMethodId);
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

                status = eap_peerStateTransition(EAP_PEER_STATE_DISCARD, hdl, arg);
                goto exit;
            }
        }

        if ((eapSession->eapSelectedMethod != eapSession->recvType) &&
            (EAP_TYPE_TLV != eapSession->recvType))
        {
            if (EAP_TYPE_IDENTITY == eapSession->recvType)
            {
                /* Should only happen if eapFAIL or eap SUCCESS is TRUE */
                if ((TRUE == eapSession->eapSuccess)  ||
                   (TRUE == eapSession->eapRestart)   ||
                   (TRUE == eapSession->eapFail))
                {
                    status = eapSession->methodDef.funcPtr_ulReceiveIndication(
                                        eapSession->appSessionHandle,
                                        EAP_INDICATION_RESTART_REQUEST,
                                        NULL,0);

                    if (OK == status)
                    {
                        /* Send a Restart Indication to UL */
                        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateReceived: Session ");
                        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
                        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
                        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Restarting the Peer");
                        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

                        EAP_peerProcessRestart(eapSession);

                        /* Untimer + Queue Timer  and feed the packet back in*/
                        if (eapSession->eapSessionCfg.eap_ul_timeout)
                        {
                            TIMER_unTimer(eapSession,eapSession->eapInstance->timerSession);
                            TIMER_queueTimer((void *) eapSession, eapSession->eapInstance->timerSession,
                                             eapSession->eapSessionCfg.eap_ul_timeout,0);
                        }

                        status = eap_peerStateTransition(EAP_PEER_STATE_RECEIVED, hdl, arg);
                        goto exit;
                    }
                }
            }

            /* Go to DISCARD */
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateReceived: Session ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Discard Packet Selected Method ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->eapSelectedMethod);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Does Not Match Received Method ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvType);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

            status = eap_peerStateTransition(EAP_PEER_STATE_DISCARD, hdl, arg);
            goto exit;
        }
    }

    if ((eapSession->recvType) && (TRUE == eapSession->eapSuccess))
    {
        if ((EAP_CODE_RESPONSE != eapSession->recvEapHdr.code) &&
            (EAP_TYPE_LEAP     != eapSession->recvType))
        {
            /* Its a Reauthentication */
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateReceived: Session ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Reauthenticating");
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

            status = eap_peerInitReAuth (eapSession);
        }
    }

    if ((eapSession->recvType) &&
       (TRUE == eapSession->eapFail))
    {
        /* Its a Reauthentication */
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateReceived: Session ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Reauthenticating");
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

        status = eap_peerInitReAuth (eapSession);
    }

    if (eapSession->recvEapHdr.id != eapSession->eapLastId)
    {
        if (eapSession->eapRespData )
        {
            FREE (eapSession->eapRespData);
        }

        eapSession->eapRespData       = NULL;
        eapSession->eapRespDataLen    = 0;
    }

    if (EAP_CODE_SUCCESS == eapSession->recvEapHdr.code)
    {
    /* Some AS send lastid+1 or 2 .. Need to take care of That */
        if (((eapSession->recvEapHdr.id == eapSession->eapLastId) || (eapSession->recvEapHdr.id == eapSession->eapLastId+1))  &&
            (eapSession->eapDecision != EAP_METHOD_DECISION_FAIL))
        {
            /* Go To SUCCESS */
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateReceived: Session ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Success Packet");
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

            status = eap_peerStateTransition(EAP_PEER_STATE_SUCCESS, hdl, arg);
            goto exit;
        }

        if ((eapSession->recvEapHdr.id == eapSession->eapLastId    ) &&
            (EAP_METHOD_STATE_CONT     != eapSession->eapMethodState) &&
            (EAP_METHOD_DECISION_FAIL  == eapSession->eapDecision  ))
        {
            /* Go To Failure */
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateReceived: Session ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Decision FAIL");
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

            status = eap_peerStateTransition(EAP_PEER_STATE_FAILURE, hdl, arg);
            goto exit;
        }
    }

    if (EAP_CODE_FAILURE == eapSession->recvEapHdr.code)
    {
        /* Confirm the  Statement about Decision as We will  be in UNCON SUCC
           and will ignore failure code if it comes */
        if ((eapSession->recvEapHdr.id       == eapSession->eapLastId    ) &&
            (EAP_METHOD_STATE_CONT           != eapSession->eapMethodState) &&
            (EAP_METHOD_DECISION_UNCOND_SUCC != eapSession->eapDecision  ))
        {
            /* Go To Failure */
            status = eap_peerStateTransition(EAP_PEER_STATE_FAILURE, hdl, arg);
            goto exit;
        }
        else
        { /* Currently Processing all Failure Requests */
            status = eap_peerStateTransition(EAP_PEER_STATE_FAILURE, hdl, arg);
            goto exit;
        }
    }

    /* Check that we send packets matching the right code and Type */
    /* Maybe Compare Current and Previous MD5 */
    if (eapSession->recvEapHdr.id == eapSession->eapLastId)
    {
        if (EAP_TYPE_LEAP == eapSession->recvType)
        {
            /* Dont Do Anything Its a Response from the Auth*/
        }
        else if ((eapSession->recvType) &&
                 (eapSession->recvType == eapSession->sentType))
        {
            /* Go to Retransmit */
            status = eap_peerStateTransition(EAP_PEER_STATE_RETRANSMIT, hdl, arg);
            goto exit;
        }
        else if (EAP_TYPE_NAK != eapSession->sentType)
        {
            /* If the Id received from the header in the Request matches our Id(eapLastId), we need to
               check whether this is the first Request.
               If this is the first Request, don't discard it. This is because the Random Number
               Generator in the Authenticator may have generated a number that leads to an Id matching
               our initalized Id(eapLastId) */
            if(eapSession->eapRecvdStartRequest==TRUE)
            {
                goto discard;
            }
            eapSession->eapRecvdStartRequest=TRUE; 
        }
    }

    if ((EAP_TYPE_NOTIFICATION == eapSession->recvType)  &&
        (eapSession->eapAllowNotification))

    {
        /* Go To Notifaction */
        eapSession->eapLastId = eapSession->recvEapHdr.id;
        status = eap_peerStateTransition(EAP_PEER_STATE_NOTIFICATION, hdl, arg);
        goto exit;

    }

    if ((EAP_TYPE_IDENTITY == eapSession->recvType)  &&
        (!eapSession->eapSelectedMethod))

    {
        /* Go To Identity */
        eapSession->eapLastId = eapSession->recvEapHdr.id;
        status = eap_peerStateTransition(EAP_PEER_STATE_IDENTITY, hdl, arg);
        goto exit;

    }

    if ( EAP_TYPE_PERP == eapSession->recvType)
    {
        /* Go To GetMethod */
        eapSession->eapLastId = eapSession->recvEapHdr.id;
        status = eap_peerStateTransition(EAP_PEER_STATE_GET_METHOD, hdl, arg);
        goto exit;
    }

    if (((EAP_TYPE_NOTIFICATION != eapSession->recvType)  &&
        (EAP_TYPE_IDENTITY      != eapSession->recvType)) &&
        (!eapSession->eapSelectedMethod))
    {
        /* Go To GetMethod */
        eapSession->eapLastId = eapSession->recvEapHdr.id;
        status = eap_peerStateTransition(EAP_PEER_STATE_GET_METHOD, hdl, arg);
        goto exit;
    }

    if (EAP_METHOD_STATE_DONE != eapSession->eapMethodState)
    {
        /* Go To Method */
        eapSession->eapLastId = eapSession->recvEapHdr.id;
        eapSession->eapRounds++;
        if (eapSession->eapRounds > EAP_MAX_ROUNDS)
        {
            status = eap_peerStateTransition(EAP_PEER_STATE_FAILURE, hdl, arg);
            goto exit;

        }

        status = eap_peerStateTransition(EAP_PEER_STATE_METHOD, hdl, arg);
        goto exit;

    }

discard:
    /* Default to DISCARD */
    status = eap_peerStateTransition(EAP_PEER_STATE_DISCARD, hdl, arg);

exit:
    return status;

} /* eap_peerStateReceived */


/*------------------------------------------------------------------*/

static MSTATUS
eap_peerStateDiscard(void *hdl, void *arg)
{
    eapSessionCb_t *eapSession = (eapSessionCb_t *)hdl;
    MSTATUS status = ERR_EAP_DISCARD_PKT;

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
    eapSession->eapSessionStats.eap_pkts_discard++;
    eapSession->eapInstance->gStats.eap_total_pkts_discard++;

    eap_peerStateTransition(EAP_PEER_STATE_IDLE, hdl, arg);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_peerStateIdentity(void *hdl, void *arg)
{
    eapSessionCb_t *eapSession = (eapSessionCb_t *)hdl;
    MSTATUS status = OK;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    status = eap_peerStateTransition(EAP_PEER_STATE_METHOD, hdl, arg);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_peerStateSendResponse(void* hdl, void *arg)
{
    eapHdr_t        eapHdr;
    eapSessionCb_t* eapSession  = (eapSessionCb_t *)hdl;
    ubyte4 intVal;
    MSTATUS         status = OK;

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

    eapHdr.code                 = eapSession->eapSendCode;
    eapHdr.id                   = eapSession->eapLastId;
    eapHdr.len                  = eapSession->eapRespDataLen + sizeof(eapHdr_t);
    intVal = eapHdr.len;
    DIGI_HTONS((ubyte *)&eapHdr.len, eapHdr.len);

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateSendResponse: Session ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Code ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapHdr.code);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Type ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sentType);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Id ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapHdr.id);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Len ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, intVal);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

#if defined(__ENABLE_ALL_DEBUGGING__)
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Sending EAP Payload <Upto 100 Bytes> ");
#ifndef __ENABLE_KEYVPN_LOG_SUPPRESSION__
        EAP_PrintBytes( eapSession->eapRespData, (eapSession->eapRespDataLen < 100) ? eapSession->eapRespDataLen : 100);
#endif
#endif
    /* Reset Received Variables */

    eapSession->recvType = 0;
    eapSession->recvEapHdr.code = 0;
    eapSession->recvEapHdr.id = 0;
    eapSession->recvEapHdr.len = 0;
    eapSession->recvVendorId = 0;
    eapSession->recvMethodId = 0;

    eapSession->eapSessionStats.eap_pkts_ll_sent++;
    if (EAP_TYPE_IDENTITY == eapSession->sentType)
        eapSession->eapSessionStats.eap_pkts_tx_id_resp++;
    eapSession->eapInstance->gStats.eap_total_pkts_sent++;

    if ((EAP_TYPE_SIM == eapSession->sentType) ||
        (EAP_TYPE_AKA == eapSession->sentType))
    {
        status = eapSession->methodDef.funcPtr_llTransmitPacket (
                              eapSession->appSessionHandle,
                              (eapHdr_t *)eapSession->eapRespData ,
                              (ubyte *) (eapSession->eapRespData+ sizeof(eapHdr_t)),
                              eapSession->eapRespDataLen);


    }
    else
    {
        status = eapSession->methodDef.funcPtr_llTransmitPacket (
                              eapSession->appSessionHandle,
                              &eapHdr ,
                              eapSession->eapRespData,
                              eapSession->eapRespDataLen);
    }

    if (OK > status)
    {
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateSendResponse: Error while Transmitting packet");
        goto exit;
    }

    /*P: Added the unqueuing and queuing of Timer after the response is send */
    if (eapSession->eapSessionCfg.eap_ul_timeout)
    {
        TIMER_unTimer(eapSession,eapSession->eapInstance->timerSession);
        TIMER_queueTimer((void *) eapSession, eapSession->eapInstance->timerSession,eapSession->eapSessionCfg.eap_ul_timeout,0);
    }
    status = eap_peerStateTransition(EAP_PEER_STATE_IDLE, eapSession, arg);

exit:
    return status;
} /* eap_peerStateSendResponse */


/*------------------------------------------------------------------*/

static MSTATUS
eap_peerStateNotification(void *hdl, void *arg)
{
    eapSessionCb_t* eapSession  = (eapSessionCb_t *)hdl;
    MSTATUS         status = OK;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (!eapSession->eapAllowNotification)
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateNotification: Session Id");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Notification Not Allowed");
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

        status = eap_peerStateTransition(EAP_PEER_STATE_DISCARD, hdl, arg);
        goto exit;
    }

    status = eap_peerStateTransition(EAP_PEER_STATE_METHOD, hdl, arg);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Peer Success */
static MSTATUS
eap_peerStateSuccess(void *hdl, void *arg)
{
    eapSessionCb_t* eapSession  = (eapSessionCb_t *)hdl;
    MSTATUS         status = OK;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->eapSuccess = TRUE;
    eapSession->eapInstance->gStats.eap_no_of_session_success++;

    if (eapSession->eapRespData)
    {
        FREE (eapSession->eapRespData);
    }

    eapSession->eapRespData       = NULL;
    eapSession->eapRespDataLen    = 0;

    /* Cancel the timer */
    TIMER_unTimer(eapSession, eapSession->eapInstance->timerSession);

    eapSession->eapSessionStats.eap_pkts_ul_callback++;
    DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"EAP SUCCESS");

    status = eapSession->methodDef.funcPtr_ulReceiveCallback (
                                        eapSession->appSessionHandle,
                                        0,
                                        EAP_CODE_SUCCESS,
                                        eapSession->recvEapHdr.id ,
                                        NULL,
                                        0,
                                        eapSession->opaque_data);
exit:
    return status;

} /* eap_peerStateSuccess */


/*------------------------------------------------------------------*/

static MSTATUS
eap_peerStateFailure(void *hdl, void *arg)
{
    eapSessionCb_t* eapSession  = (eapSessionCb_t *)hdl;
    MSTATUS         status = OK;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->eapFail         = TRUE;
    eapSession->eapInstance->gStats.eap_no_of_session_failure++;

    if (eapSession->eapRespData)
    {
        FREE (eapSession->eapRespData);
    }

    eapSession->eapRespData       = NULL;
    eapSession->eapRespDataLen    = 0;

    /* Cancel the timer */
    TIMER_unTimer (eapSession, eapSession->eapInstance->timerSession);

    /* Send Indication UP */
    eapSession->eapSessionStats.eap_pkts_ul_callback++;
    /* Transition To IDLE Should Drop All Packets Till Restart
        is called by the layer */
    eapSession->eapSelectedMethod = EAP_TYPE_NONE;

    DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"EAP FAILURE");

    status = eapSession->methodDef.funcPtr_ulReceiveCallback (
                                        eapSession->appSessionHandle,
                                        0,
                                        EAP_CODE_FAILURE,
                                        eapSession->recvEapHdr.id ,
                                        NULL,
                                        0,
                                        eapSession->opaque_data);



exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_buildExpandedNAK(eapSessionCb_t *eapSession,
                     eapExpandedMethod_t *expMethods, ubyte expMethodCount,
                     ubyte **eapResponse, ubyte4 *eapRespLen)
{
    ubyte*  pkt = NULL;
    ubyte4  i;
    ubyte4  count = expMethodCount;
    MSTATUS status = OK;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }
    if (0 == expMethodCount)
    {
        count = 1;
    }
    *eapRespLen = (count + 1) * 7 + count;
    pkt = MALLOC(*eapRespLen);
    if (NULL == pkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    *eapResponse = pkt;
    *pkt++ = 0;
    *pkt++ = 0;
    *pkt++ = EAP_VENDOR_ID_IETF;

    DIGI_MEMSET(pkt, 0, 3);
    pkt += 3;
    *pkt++ = EAP_TYPE_NAK;

    if (0 == expMethodCount)
    {
        *pkt++ = EAP_TYPE_EXPANDED;
        *pkt++ = 0;
        *pkt++ = 0;
        *pkt++ = EAP_VENDOR_ID_IETF;
        DIGI_MEMSET(pkt, 0, 4);

    }
    else
    {
        for(i = 0; i < expMethodCount; i++)
        {
            *pkt++ = EAP_TYPE_EXPANDED;
            DIGI_MEMCPY(pkt, (ubyte *)expMethods[i].vendor_id, 3);
            pkt += 3;
            DIGI_MEMCPY(pkt, (ubyte *)expMethods[i].method_type, 4);
            pkt += 4;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_buildExpandedResponse(eapSessionCb_t *eapSession,
                          ubyte4 expVendorId, ubyte4 expMethodId,
                          ubyte *eapPayload, ubyte4 eapPayloadLen,
                          ubyte **eapResponse, ubyte4 *eapRespLen)
{
    ubyte*  pkt = NULL;
    MSTATUS status = OK;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    *eapRespLen = eapPayloadLen + 7;
    pkt = MALLOC(*eapRespLen);

    if (NULL == pkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *eapResponse = pkt;
    DIGI_HTONL((ubyte *)&expVendorId,expVendorId);
    DIGI_HTONL((ubyte *)&expMethodId,expMethodId);
    DIGI_MEMCPY(pkt, (ubyte *)&expVendorId, 3);
    pkt += 3;
    DIGI_MEMCPY(pkt, (ubyte *)&expMethodId, 4);
    pkt += 4;
    DIGI_MEMCPY(pkt, eapPayload, eapPayloadLen);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_buildNAK(eapSessionCb_t *eapSession,
             ubyte* nakMethods, ubyte4 nakMethodCount,
             ubyte **eapResponse, ubyte4 *eapRespLen)
{
    ubyte*  pkt = NULL;
    ubyte4  count = nakMethodCount;
    MSTATUS status = OK;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (0 == nakMethodCount)
    {
        count = 1;
    }

    *eapRespLen = count;
    pkt = MALLOC(*eapRespLen);
    if (NULL == pkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *eapResponse = pkt;
    if (0 == nakMethodCount)
    {
        *pkt = 0;
    }
    else
    {
        DIGI_MEMCPY(pkt, (ubyte *)nakMethods, nakMethodCount);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_peerStateGetMethod(void *hdl, void *arg)
{
    eapSessionCb_t* eapSession  = (eapSessionCb_t *)hdl;
    MSTATUS         status = OK;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    status = eap_peerStateTransition(EAP_PEER_STATE_METHOD, hdl, arg);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_peerStateMethod(void *hdl, void *arg)
{
    eapSessionCb_t* eapSession  = (eapSessionCb_t *)hdl;
    MSTATUS         status = OK;
    ubyte          *pOpaque = NULL;
    ubyte4 len = 0;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }
    eapSession->eapSessionStats.eap_pkts_ul_callback++;

    if (!eapSession->methodDef.funcPtr_ulReceiveCallback)
    {
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"UL Receive Callback Fn Not defined");

        status = ERR_EAP_INVALID_CALLBACK_FN;
        eapSession->eapSessionStats.eap_pkts_drop_ul_nocallback++;

        goto exit;
    }

    if ((EAP_TYPE_SIM == eapSession->recvType) ||
        (EAP_TYPE_AKA == eapSession->recvType))
    {
        len = eapSession->recvEapHdr.len;
    }
    else
        len = eapSession->recvEapHdr.len - sizeof(eapHdr_t);

    pOpaque = eapSession->opaque_data;
    eapSession->opaque_data = NULL;

    if (eapSession->methodDef.funcPtr_ulReceiveCallback)
        status = eapSession->methodDef.funcPtr_ulReceiveCallback (
                                        eapSession->appSessionHandle,
                                        eapSession->recvType,
                                        eapSession->recvEapHdr.code,
                                        eapSession->recvEapHdr.id ,
                                        arg,
                                        len,
                                        pOpaque);

exit:

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_peerStateRetransmit(void *hdl, void *arg)
{
    eapSessionCb_t* eapSession  = (eapSessionCb_t *)hdl;
    MSTATUS         status = OK;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (eapSession->eapRespData)
    {
       /* Go to Send Resp */
        eapSession->eapSessionStats.eap_pkts_retransmitted++;
        eapSession->eapInstance->gStats.eap_no_of_retransmission++;
        status = eap_peerStateTransition(EAP_PEER_STATE_SEND_RESPONSE, hdl, arg);

    }
    else
    {
        /* Go to UL_Recv */
        eapSession->eapSessionStats.eap_pkts_ul_callback++;
        status = eap_peerStateTransition(EAP_PEER_STATE_METHOD, hdl, arg);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_peerValidatePacket(eapSessionCb_t * session,
                       ubyte * pktBuffer,
                       ubyte4 pktLen)
{
    eapHdr_t*   eapHdr = (eapHdr_t *)pktBuffer;
    ubyte       pktType;
    ubyte4      expVendorId= 0;
    ubyte4      expMethodId=0;
    MSTATUS     status = OK;

    if ((NULL == session) || (NULL == eapHdr))
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (pktLen < sizeof(eapHdr_t))
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerValidatePacket: Session ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, session->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(session->eapIdentity ? session->eapIdentity : nullIdentity));
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Received short packet");
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

        status = ERR_EAP_INVALID_PKT_SIZE;
        goto exit;
    }

    session->recvEapHdr.code = eapHdr->code;
    session->recvEapHdr.id   = eapHdr->id;
    session->recvEapHdr.len  = DIGI_NTOHS((const ubyte *)pktBuffer + 2);
    session->recvType = 0;
    session->recvMethodId = 0;
    session->recvVendorId = 0;

    switch (session->recvEapHdr.code)
    {
        case EAP_CODE_RESPONSE:
        {
            pktType = *(ubyte *) ((ubyte *)eapHdr + sizeof(eapHdr_t));
            if (EAP_TYPE_LEAP == pktType)
            {
                if (pktLen < sizeof(eapHdr_t) + 1)
                {
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerValidatePacket: Session ");
                    DEBUG_INT(DEBUG_EAP_MESSAGE, session->sessionId);
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(session->eapIdentity ? session->eapIdentity : nullIdentity));
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Received short LEAP packet");
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

                    status = ERR_EAP_INVALID_PKT_SIZE;
                    goto exit;
                }

                if (session->recvEapHdr.len > pktLen)
                {
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerValidatePacket: Session ");
                    DEBUG_INT(DEBUG_EAP_MESSAGE, session->sessionId);
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(session->eapIdentity ? session->eapIdentity : nullIdentity));
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Received short LEAP packet");
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

                    status = ERR_EAP_INVALID_PKT_SIZE;
                    goto exit;
                }
                session->recvType = pktType;
            }
            else
            {
                status = ERR_EAP_INVALID_PKT;
                goto exit;
            }
            break;
        }

        case EAP_CODE_REQUEST:
        {
            if (pktLen < sizeof(eapHdr_t) + 1)
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerValidatePacket: Session ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, session->sessionId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(session->eapIdentity ? session->eapIdentity : nullIdentity));
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Received short packet");
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

                status = ERR_EAP_INVALID_PKT_SIZE;
                goto exit;
            }

            if (session->recvEapHdr.len > pktLen)
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerValidatePacket: Session ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, session->sessionId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(session->eapIdentity ? session->eapIdentity : nullIdentity));
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Received short packet");
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

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
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerValidatePacket: Session ");
                    DEBUG_INT(DEBUG_EAP_MESSAGE, session->sessionId);
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(session->eapIdentity ? session->eapIdentity : nullIdentity));
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Invalid Expanded Len ");
                    DEBUG_INT(DEBUG_EAP_MESSAGE, session->recvEapHdr.len);
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

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
            break;
        }

        default:
        {
            status = ERR_EAP_INVALID_PKT;
            session->recvType = 0;
            break;
        }
    }

exit:
    return status;
} /* eap_peerValidatePacket */


/*------------------------------------------------------------------*/

static MSTATUS
eap_peerVerifyMethodStateDecision(eapSessionCb_t *eapSession,
                                  eapMethodDecision  methodDecision,
                                  eapMethodState methodState)
{
    MSTATUS status = OK;

    if ((EAP_METHOD_STATE_DONE     != methodState) &&
        (EAP_METHOD_STATE_CONT     != methodState) &&
        (EAP_METHOD_STATE_MAY_CONT != methodState))
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerVerifyMethodStateDecision: Session ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Invalid Method State ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, methodState);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

        status = ERR_EAP_INVALID_METHOD_STATE;
        goto exit;
    }

    if (EAP_METHOD_STATE_CONT == methodState)
    {
        if (EAP_METHOD_DECISION_FAIL != methodDecision)
        {
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerVerifyMethodStateDecision: Session ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Invalid Decision ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, methodDecision);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" for Method State ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, methodState);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

            status = ERR_EAP_INVALID_DECISION;
            goto exit;
        }
    }

    if (EAP_METHOD_STATE_MAY_CONT == methodState)
    {
        if ((EAP_METHOD_DECISION_FAIL      != methodDecision) &&
           (EAP_METHOD_DECISION_COND_SUCC != methodDecision))
        {
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerVerifyMethodStateDecision: Session ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Invalid Decision ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, methodDecision);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" for Method State ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, methodState);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

            status = ERR_EAP_INVALID_DECISION;
            goto exit;
        }
    }

exit:
    return status;
} /* eap_peerVerifyMethodStateDecision */


/*------------------------------------------------------------------*/

/****f* src/eap/EAP_peerProcessRestart
*
*  NAME
*   EAP_peerProcessRestart -- Restart the peer session
*  SYNOPSIS
*
*   #include "../eap/eap_session.h"
*
*   extern  MSTATUS
*    EAP_peerProcessRestart (eapSessionCb_t * eapSession)
*
*  FUNCTION
*  Called by the application to Restart the peer session or by EAP to create a
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
EAP_peerProcessRestart(eapSessionCb_t * eapSession)
{
    MSTATUS status = OK;

    eapSession->eapInstance->gStats.eap_no_of_restart_sessions++;

    if (TRUE == eapSession->eapPortEnabled)
    {
        status = eap_peerStateTransition(EAP_PEER_STATE_INIT, eapSession, NULL);
    }
    else
    {
        status = eap_peerStateTransition(EAP_PEER_STATE_DISABLED, eapSession, NULL);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
EAP_peerSessionDisable(eapSessionCb_t * eapSession)
{
    MSTATUS status;

    status = eap_peerStateTransition(EAP_PEER_STATE_DISABLED, eapSession, NULL);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_peerInitReAuth(eapSessionCb_t * eapSession)
{
    MSTATUS status = OK;

    eapSession->eapAllowNotification = TRUE;
    eapSession->eapRestart = FALSE;
    eapSession->eapSuccess = FALSE;
    eapSession->eapFail = FALSE;
    eapSession->eapKeyAvailable = FALSE;
    eapSession->eapDecision = EAP_METHOD_DECISION_FAIL;
    eapSession->eapMethodState = EAP_METHOD_STATE_INIT;
    eapSession->sentType = 0;
    eapSession->eapRounds = 0;
    eapSession->eapRecvdStartRequest = FALSE;
    DIGI_MEMSET(eapSession->lastMD5,0,MD5_DIGESTSIZE);
    DIGI_MEMSET(eapSession->recvMD5,0,MD5_DIGESTSIZE);

    /* Send Indication to UL About Reauth */
    if (eapSession->eapSessionCfg.eap_ul_timeout)
        TIMER_queueTimer((void *) eapSession, eapSession->eapInstance->timerSession,
                         eapSession->eapSessionCfg.eap_ul_timeout,0);

    return status;
}


/*------------------------------------------------------------------*/

/****f* src/eap/EAP_peerProcessULTransmit
*
*  NAME
*  EAP_peerProcessULTransmit  -- Peer specific transmit of EAP packet
*  SYNOPSIS
*
*   #include "../eap/eap_session.h"
*   extern MSTATUS EAP_peerProcessULTransmit (eapSessionCb_t * eapSession,
*                           eapMethodType  method_type,
*                           eapCode  code,
*                           eapMethodDecision  methodDecision,
*                           eapMethodState methodState,
*                           ubyte * eap_data,
*                           ubyte4  eap_data_len)
*
*
*  FUNCTION
*  Called by the EAP to transmit a peer specific EAP response packet
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
EAP_peerProcessULTransmit(eapSessionCb_t * eapSession,
                          eapMethodType  method_type,
                          eapCode  code,
                          eapMethodDecision  methodDecision,
                          eapMethodState methodState,
                          ubyte * eap_data,
                          ubyte4  eap_data_len)
{
    ubyte2  expandedNak = 0;
    ubyte4  expVendorId = 0;
    ubyte4  expMethodId = 0;
    MSTATUS status = OK;

    eapSession->eapSessionStats.eap_pkts_ul_received++;
    if (code != EAP_CODE_RESPONSE && method_type != EAP_TYPE_LEAP)
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_peerProcessULTransmit: Session ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Cannot Send Code ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, code);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

        status = ERR_EAP_INVALID_CODE;
        goto exit;
    }

    /* Check That its not an Out of turn Response */
    if (method_type != EAP_TYPE_LEAP && !eapSession->recvType)
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_peerProcessULTransmit: Session ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Out of Turn Packet being sent ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, code);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

        status = ERR_EAP_INVALID_CODE;
        goto exit;
    }

    /* Check whether its a Expanded NAK Else extract out the vendor/method*/
    if (EAP_TYPE_EXPANDED == method_type)
    {
       /* Verify length */
        if (7 > eap_data_len)
        {
            status = ERR_EAP_INVALID_PKT_SIZE;
            goto exit;
        }

        DIGI_MEMCPY((ubyte *)&expVendorId,eap_data,3);
        DIGI_MEMCPY((ubyte *)&expMethodId,(ubyte *)eap_data+3,4);
        expVendorId = EAP_NTOHL(expVendorId);
        expMethodId = EAP_NTOHL(expMethodId);

        if ((EAP_VENDOR_ID_IETF  == expVendorId) &&
            (EAP_TYPE_NAK == expMethodId))
        {
            expandedNak = 1;
        }
    }

    if (EAP_TYPE_EXPANDED == method_type)
    {
        /* Verify that the RecvExpanded Type Match the sent one */
        if ((!expandedNak) &&
            ((eapSession->recvVendorId != expVendorId) ||
            (eapSession->recvMethodId != expMethodId)))
        {
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_peerProcessULTransmit: Session ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Invalid Expanded Method Type ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, expVendorId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
            DEBUG_INT(DEBUG_EAP_MESSAGE, expMethodId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Type has to Match Selected or received Type ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvVendorId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvMethodId);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

            status = ERR_EAP_INVALID_METHOD_TYPE;
            goto exit;
        }
    }

    /* If Method Not Selected Extract Method */
    if (!eapSession->eapSelectedMethod)
    {
        if (eapSession->recvType == method_type)
        {
            if (EAP_TYPE_EXPANDED == method_type)
            {
                if (!expandedNak)
                {
                    /* Store Vendor Id/Method Id */
                    eapSession->eapSelectedMethod = (ubyte) method_type;
                    eapSession->eapVendorId = expVendorId;
                    eapSession->eapMethodId = expMethodId;

                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_peerProcessULTransmit: Session ");
                    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Selected Expanded Method Type ");
                    DEBUG_INT(DEBUG_EAP_MESSAGE, expVendorId);
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                    DEBUG_INT(DEBUG_EAP_MESSAGE, expMethodId);
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");
                }
            }
            else if ((EAP_TYPE_IDENTITY     != method_type) &&
                     (EAP_TYPE_NAK          != method_type) &&
                     (EAP_TYPE_NOTIFICATION != method_type))
            {
                eapSession->eapSelectedMethod = (ubyte) method_type;
            }
        }
        else
        {
            /* He can only Send a NAK */
            if (EAP_TYPE_NAK   != method_type)
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_peerProcessULTransmit: Session ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Invalid Method Type ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, method_type);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Type has to Match Selected or received Type ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvType);
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

                status = ERR_EAP_INVALID_METHOD_TYPE;
                goto exit;
            }
        }
    }

    /* If Method Selected verify  Method */
    if (eapSession->eapSelectedMethod)
    {
        if ((eapSession->eapSelectedMethod != method_type) &&
            (EAP_TYPE_TLV                  != method_type))
        {
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_peerProcessULTransmit: Session ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Invalid Method Type ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, method_type);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Type has to Match Selected or received Type ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvType);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

            status = ERR_EAP_INVALID_METHOD_TYPE;
            goto exit;
        }

        if (EAP_TYPE_EXPANDED == method_type)
        {
            /* Verify that the Vendor Id and Method Id Match */

            if ((expVendorId != eapSession->eapVendorId) ||
                (expMethodId != eapSession->eapMethodId))
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_peerProcessULTransmit: Session ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Invalid Expanded Method Type ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, expVendorId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                DEBUG_INT(DEBUG_EAP_MESSAGE, expMethodId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Type has to Match Selected or received Type ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->eapVendorId);
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
                DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->eapMethodId);
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

                status = ERR_EAP_INVALID_METHOD_TYPE;
                goto exit;
            }
        }
    }

    if ((EAP_TYPE_IDENTITY     == eapSession->recvType) ||
        (EAP_TYPE_NOTIFICATION == eapSession->recvType))
    {
        if (eapSession->recvType != method_type)
        {
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_peerProcessULTransmit: Session ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)", Invalid Method Type ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, method_type);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Type has to Match Selected or received Type ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->recvType);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

            status = ERR_EAP_INVALID_METHOD_TYPE;
            goto exit;
        }
    }

    /* Verify Method State and Decision */
    if ((EAP_TYPE_NAK != method_type) &&
        (!expandedNak))
    {
        if (OK > (status = eap_peerVerifyMethodStateDecision(eapSession,
                                                             methodDecision,
                                                             methodState)))
        {
            goto exit;
        }
    }

    if (EAP_TYPE_IDENTITY == method_type)
    {
        /* Set Identity */
        if (eapSession->eapIdentity)
        {
            FREE(eapSession->eapIdentity);
            eapSession->eapIdentity = NULL;
            eapSession->eapIdentityLen = 0;
        }

        eapSession->eapIdentity = MALLOC (eap_data_len+1);
        if (!eapSession->eapIdentity)
        {
           status = ERR_MEM_ALLOC_FAIL;
           goto exit;
        }

        DIGI_MEMCPY(eapSession->eapIdentity,eap_data,eap_data_len);
        eapSession->eapIdentity[eap_data_len] = 0;
        eapSession->eapIdentityLen = eap_data_len;
    }

    eapSession->eapMethodState = (ubyte) methodState;
    eapSession->eapDecision    = (ubyte) methodDecision;
    eapSession->sentType =   (ubyte) method_type;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_peerProcessULTransmit: Session ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Code ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, code);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Type ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, method_type);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Method State ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)eapMethodStateString[methodState]);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Decision ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)eapMethodDecisionString[methodDecision]);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    if (EAP_METHOD_STATE_DONE == eapSession->eapMethodState)
    {
        eapSession->eapAllowNotification = FALSE;
    }

    if (eapSession->eapRespData)
    {
        /* Free this buffer */
        FREE (eapSession->eapRespData);
        eapSession->eapRespData = NULL;
        eapSession->eapRespDataLen = 0;
    }

    /* Alloc a New Buffer and copy th epkt There */
    eapSession->eapRespData = (ubyte *) MALLOC(eap_data_len+1);
    if (NULL == eapSession->eapRespData)
    {

        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if ((EAP_TYPE_SIM != method_type)  &&
        (EAP_TYPE_AKA != method_type))
    {
        *eapSession->eapRespData = (ubyte) method_type;
    }

    if (eap_data_len)
    {
        if ((EAP_TYPE_SIM != method_type) &&
            (EAP_TYPE_AKA != method_type))
        {
            DIGI_MEMCPY((ubyte *)eapSession->eapRespData+1,
                       (ubyte *)eap_data,
                       eap_data_len);
        }
        else
            DIGI_MEMCPY((ubyte *)eapSession->eapRespData,
                       (ubyte *)eap_data,
                       eap_data_len);
    }

    eapSession->eapRespDataLen = eap_data_len + 1;
    eapSession->eapSendCode = (ubyte) code;

    status = eap_peerStateTransition(EAP_PEER_STATE_SEND_RESPONSE, eapSession, eap_data);

exit:
    return status;
} /* EAP_peerProcessULTransmit */


/*------------------------------------------------------------------*/

/****f* src/eap/EAP_peerProcessllReceivePacket
*
*  NAME
*   EAP_peerProcessllReceivePacket  -- Peer specific processing of EAP packet
*  SYNOPSIS
*
*   #include "../eap/eap_session.h"
*
*   extern MSTATUS
*   EAP_peerProcessllReceivePacket (eapSessionCb_t *eapSession,
*                                ubyte * eap_pkt,
*                                ubyte4 eap_pkt_len,
*                                ubyte * opaque_data)
*
*  FUNCTION
*  Called by the EAP to trigger Peer state machine for processing of
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
EAP_peerProcessllReceivePacket(eapSessionCb_t *eapSession,
                               ubyte * eap_pkt,
                               ubyte4 eap_pkt_len,
                               ubyte * opaque_data)
{
    MSTATUS status = OK;
    ubyte *recvPkt = eap_pkt;

    eapSession->eapSessionStats.eap_pkts_ll_received++;
    eapSession->eapInstance->gStats.eap_total_pkts_received++;
    eapSession->opaque_data = NULL;
    status = eap_peerValidatePacket (eapSession,
                                     eap_pkt,
                                     eap_pkt_len);

    if (status !=OK)
    {
        /* Transition to DISCARD */
        eapSession->eapSessionStats.eap_pkts_drop_invalid_pkt++;
        status = eap_peerStateTransition(EAP_PEER_STATE_DISCARD, eapSession, eap_pkt);
    }
    else
    {
        /* Transition to RECEIVE Packet */
        eapSession->opaque_data = opaque_data;
        /* Send Full EAP Packet Up for EAP_SIM */
        if ((EAP_TYPE_SIM != eapSession->recvType) &&
            (EAP_TYPE_AKA != eapSession->recvType))
        {
            recvPkt = eap_pkt+sizeof(eapHdr_t);
        }

        if (EAP_TYPE_IDENTITY == eapSession->recvType)
            eapSession->eapSessionStats.eap_pkts_rx_id_req++;
        status = eap_peerStateTransition(EAP_PEER_STATE_RECEIVED, eapSession, recvPkt);

    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
eap_peerStateTransition(eapState_t newState,
                        void *session,
                        void * arg)
{
    eapSessionCb_t*    eapSession = (eapSessionCb_t *) session;
    MSTATUS            status = OK;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_peerStateTransition: Session ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapSession->sessionId);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)(eapSession->eapIdentity ? eapSession->eapIdentity : nullIdentity));
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" from State ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)eap_PeerStateBits[eapSession->eapCurrentState].stateDescription);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" to ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)eap_PeerStateBits[newState].stateDescription);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    eapSession->eapPrevState    = eapSession->eapCurrentState;
    eapSession->eapCurrentState = newState;
    status = eap_PeerStateBits[newState].stateFn (session,arg);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
EAP_peerSessionTimeout(eapSessionCb_t * eapSession)
{
    MSTATUS status = OK;

    eapSession->eapInstance->gStats.eap_no_of_peer_timeouts++;

    if (EAP_METHOD_DECISION_UNCOND_SUCC != eapSession->eapDecision)
    {
        status = eap_peerStateTransition(EAP_PEER_STATE_FAILURE, eapSession, NULL);
    }
    else
    {
        status = eap_peerStateTransition(EAP_PEER_STATE_SUCCESS, eapSession, NULL);
    }

    return status;
}


/*------------------------------------------------------------------*/

/****f* src/eap/EAP_peerProcessAltEvent
*
*  NAME
*   EAP_peerProcessAltEvent -- Peer specific processing of Alternate Indication
*                              of Success/Failure
*  SYNOPSIS
*
*   #include "../eap/eap_session.h"
*
*   extern MSTATUS
*   EAP_peerProcessAltEvent (eapSessionCb_t *eapSession,
*                            eapCode code)
*
*  FUNCTION
*  Called by the EAP for processing Alternate Indication of Success or Failure
*
*  INPUTS
*    eapSessionHdl : EAP Session Handle
*    code          : SUCCESS or FAILURE
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_llReceiveIndication
******/
extern MSTATUS
EAP_peerProcessAltEvent(eapSessionCb_t *eapSession,
                        eapCode code)
{
    MSTATUS status = OK;

    if (EAP_CODE_FAILURE == code)
    {
        status = eap_peerStateTransition(EAP_PEER_STATE_FAILURE, eapSession, NULL);
    }
    else
    {
        status = eap_peerStateTransition(EAP_PEER_STATE_SUCCESS, eapSession, NULL);
    }

    return status;
}

#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) */
