/**
 * @file  eap1x_peer.c
 * @brief 802.1X peer implementation
 *
 * @details    802.1X client-side functions
 * @since      2.02
 * @version    3.1 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
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
#include "../common/mocana.h"
#include "../common/debug_console.h"
#include "../common/sizedbuffer.h"
#include "../crypto/hw_accel.h"
#include "../common/timer.h"
#include "../eap/eap1x.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap1x_peer.h"
#include "../eap/eap1x_peer_pvt.h"


/*------------------------------------------------------------------*/

/* Local Methods */
static MSTATUS EAP1X_peerStateLogoff (void *, void *);
static MSTATUS EAP1X_peerStateDisconnected (void *, void *);
static MSTATUS EAP1X_peerStateRestart (void *, void *);
static MSTATUS EAP1X_peerStateConnecting (void *, void *);
static MSTATUS EAP1X_peerStateAuthenticating(void *, void *);
static MSTATUS EAP1X_peerStateAuthenticated(void *, void *);
static MSTATUS EAP1X_peerStateHeld(void *, void *);
static MSTATUS EAP1X_peerStateForceAuth(void *, void *);
static MSTATUS EAP1X_peerStateForceUnAuth(void *, void *);
static MSTATUS EAP1X_peerStateTransition(eap1XPeerState_t newState,
                                       void *session,
                                       void * arg);
static void EAP1X_peerTimeoutCallback(void *session, ubyte *type);
static MSTATUS EAP1X_peerHeldTimeout(void *session);
static MSTATUS EAP1X_peerStartTimeout(void *session);
static MSTATUS EAP1X_peerCheckState(ubyte* session);

/*------------------------------------------------------------------*/

static eap1xPeerGlobal_t gEap1XGlobalState;

/*------------------------------------------------------------------*/

const eap1XPeerStateBits_t eap1X_PeerStateBits[] =
{
    {0, (ubyte *)"NoState",NULL },
    {EAP1X_PEER_STATE_LOGOFF, (ubyte *)"PeerLogoff", EAP1X_peerStateLogoff},
    {EAP1X_PEER_STATE_DISCONNECTED, (ubyte *)"PeerDisconnected", EAP1X_peerStateDisconnected},
    {EAP1X_PEER_STATE_RESTART, (ubyte *)"PeerRestart", EAP1X_peerStateRestart},
    {EAP1X_PEER_STATE_CONNECTING, (ubyte *)"PeerConnecting", EAP1X_peerStateConnecting},
    {EAP1X_PEER_STATE_AUTHENTICATING, (ubyte *)"PeerAuthenticating", EAP1X_peerStateAuthenticating},
    {EAP1X_PEER_STATE_AUTHENTICATED, (ubyte *)"PeerAuthenticated", EAP1X_peerStateAuthenticated},
    {EAP1X_PEER_STATE_HELD, (ubyte *)"PeerHeld", EAP1X_peerStateHeld},
    {EAP1X_PEER_STATE_FORCE_AUTH, (ubyte *)"PeerForceAuth", EAP1X_peerStateForceAuth},
    {EAP1X_PEER_STATE_FORCE_UNAUTH, (ubyte *)"PeerForceUnAuth", EAP1X_peerStateForceUnAuth}
};


/*------------------------------------------------------------------*/

/*Extern Definitions */

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_peerStateLogoff(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession  = (eap1xPeerCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->logoffSent        = TRUE;
    eapSession->suppPortStatus    = EAP1X_PORT_STATUS_UNAUTHORIZED;
    TIMER_unTimer(eapSession,gEap1XGlobalState.startTimer);
    TIMER_unTimer(eapSession,gEap1XGlobalState.heldTimer);
    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_UNAUTHORIZED);
    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_SEND_LOGOFF);


exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_peerStateForceAuth(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession  = (eap1xPeerCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    TIMER_unTimer(eapSession,gEap1XGlobalState.startTimer);
    TIMER_unTimer(eapSession,gEap1XGlobalState.heldTimer);
    eapSession->sPortMode = EAP1X_PORT_MODE_FORCED_AUTHORIZED;
    eapSession->suppPortStatus = EAP1X_PORT_STATUS_AUTHORIZED;
    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_AUTHORIZED);
exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_peerStateForceUnAuth(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession  = (eap1xPeerCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    TIMER_unTimer(eapSession,gEap1XGlobalState.startTimer);
    TIMER_unTimer(eapSession,gEap1XGlobalState.heldTimer);
    eapSession->sPortMode = EAP1X_PORT_MODE_FORCED_UNAUTHORIZED;
    eapSession->suppPortStatus = EAP1X_PORT_STATUS_UNAUTHORIZED;
    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_UNAUTHORIZED);
    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_SEND_LOGOFF);
exit:
    return status;

}

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_peerStateDisconnected(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession  = (eap1xPeerCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }


    eapSession->sPortMode      = EAP1X_PORT_MODE_AUTO;
    eapSession->startCount     = 0;
    eapSession->logoffSent     = FALSE;
    eapSession->suppAbort      = TRUE;
    eapSession->suppPortStatus = EAP1X_PORT_STATUS_UNAUTHORIZED;
    TIMER_unTimer(eapSession,gEap1XGlobalState.startTimer);
    TIMER_unTimer(eapSession,gEap1XGlobalState.heldTimer);

    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_UNAUTHORIZED);
    if (OK > status)
        goto exit;

    /* if the port is enabled and the session is not inititializing,
       exit out of this state */
    if ((TRUE == eapSession->portEnabled)     &&
        (!eapSession->initialize))
        status = EAP1X_peerCheckState((ubyte*) hdl);
exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_peerStateRestart(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession  = (eap1xPeerCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    TIMER_unTimer(eapSession,gEap1XGlobalState.startTimer);
    TIMER_unTimer(eapSession,gEap1XGlobalState.heldTimer);
    eapSession->eapRestart    = TRUE;

    /* Call the EAP Indication Layer That We are Restarting */
    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_RESTART);
    if (OK > status)
        goto exit;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_peerStateConnecting(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession  = (eap1xPeerCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    TIMER_queueTimer(eapSession,gEap1XGlobalState.startTimer,
                         eapSession->cfg.startTimeout,0);
    eapSession->stats.suppEntersConnecting++;
    eapSession->startCount++;
    eapSession->eapolEap    = FALSE;
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP1X_peerStateConnecting: Start Count ", (sbyte4)eapSession->startCount);

    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_SEND_START);

exit:

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_peerStateAuthenticating(void *hdl, void *arg)
{
    MSTATUS  status = OK;
    eap1xPeerCb_t *eapSession  = (eap1xPeerCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    TIMER_unTimer(eapSession,gEap1XGlobalState.startTimer);
    eapSession->stats.suppEntersAuthenticating++;
    eapSession->startCount  = 0;
    eapSession->suppSuccess = FALSE;
    eapSession->suppFail    = FALSE;
    eapSession->suppTimeout = FALSE;
    eapSession->keyRun      = FALSE;
    eapSession->keyDone     = FALSE;

exit:
    return status;

} /* EAP1X_peerStateAuthenticating */


/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_peerStateAuthenticated(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession  = (eap1xPeerCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->suppPortStatus = EAP1X_PORT_STATUS_AUTHORIZED;
    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_AUTHORIZED);


exit:
    return status;
}


/*------------------------------------------------------------------*/


static MSTATUS
EAP1X_peerStateHeld(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession  = (eap1xPeerCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->suppPortStatus = EAP1X_PORT_STATUS_UNAUTHORIZED;

    /* Restart the Timer  for quiet Period*/
    TIMER_queueTimer(eapSession,gEap1XGlobalState.heldTimer,eapSession->cfg.heldTimeout,0);
    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_UNAUTHORIZED);

exit:
    return status;

} /* EAP1X_peerStateHeld */

/*------------------------------------------------------------------*/


static MSTATUS
EAP1X_peerStateTransition(eap1XPeerState_t newState,
                        void *session,
                        void * arg)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession = (eap1xPeerCb_t *)session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP1X_peerStateTransition: Transition Session ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)((uintptr)eapSession->appHdl));
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)":");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" from State ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)eap1X_PeerStateBits[eapSession->eapPeerCurrentState].stateDescription);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" to ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)eap1X_PeerStateBits[newState].stateDescription);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    eapSession->eapPeerPrevState    = eapSession->eapPeerCurrentState;
    eapSession->eapPeerCurrentState = newState;
    status = eap1X_PeerStateBits[newState].stateFn (session,arg);

exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_peerHeldTimeout(void *session)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession = (eap1xPeerCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }



    status = EAP1X_peerStateTransition(EAP1X_PEER_STATE_CONNECTING, eapSession, NULL);

exit:
    return status;

} /* EAP1X_peerHeldTimeout */

/*------------------------------------------------------------------*/


static MSTATUS
EAP1X_peerStartTimeout(void *session)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession = (eap1xPeerCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }


    if (eapSession->startCount < eapSession->cfg.maxStart)
        status = EAP1X_peerStateTransition(EAP1X_PEER_STATE_CONNECTING, eapSession, NULL);
    else if (eapSession->portValid)
        status = EAP1X_peerStateTransition(EAP1X_PEER_STATE_AUTHENTICATED, eapSession, NULL);
    else
        status = EAP1X_peerStateTransition(EAP1X_PEER_STATE_HELD, eapSession, NULL);


exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_peerCheckState(ubyte* session)
{
    MSTATUS status = OK;
    eap1XPeerState_t newState;
    intBoolean  stateChangeRequired = FALSE ;

    eap1xPeerCb_t *eapSession = (eap1xPeerCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (((TRUE == eapSession->userLogoff) &&
        (FALSE == eapSession->logoffSent))     &&
        !((FALSE == eapSession->portEnabled)      ||
        (eapSession->initialize)))
    {
        newState = EAP1X_PEER_STATE_LOGOFF;
        stateChangeRequired = TRUE;
        goto stateChanged;
    }

    if (((EAP1X_PORT_MODE_AUTO == eapSession->portControl) &&
         (eapSession->sPortMode != eapSession->portControl))      ||
        (FALSE == eapSession->portEnabled)      ||
        (eapSession->initialize))
    {
        newState = EAP1X_PEER_STATE_DISCONNECTED;
        stateChangeRequired = TRUE;
        goto stateChanged;
    }

    if ((EAP1X_PORT_MODE_FORCED_AUTHORIZED == eapSession->portControl) &&
        (eapSession->sPortMode != eapSession->portControl)   &&
        !((FALSE == eapSession->portEnabled)      ||
          (eapSession->initialize)))
    {
        newState = EAP1X_PEER_STATE_FORCE_AUTH;
        stateChangeRequired = TRUE;
        goto stateChanged;
    }

    if ((EAP1X_PORT_MODE_FORCED_UNAUTHORIZED == eapSession->portControl) &&
        (eapSession->sPortMode != eapSession->portControl)   &&
        !((FALSE == eapSession->portEnabled)      ||
          (eapSession->initialize)))
    {
        newState = EAP1X_PEER_STATE_FORCE_UNAUTH;
        stateChangeRequired = TRUE;
        goto stateChanged;
    }

    switch (eapSession->eapPeerCurrentState)
    {

        case EAP1X_PEER_STATE_LOGOFF:
        {
            if (FALSE == eapSession->userLogoff)
            {
                newState = EAP1X_PEER_STATE_DISCONNECTED;
                stateChangeRequired = TRUE;
            }
            break;
        }

        case EAP1X_PEER_STATE_RESTART:
        {
            if (FALSE == eapSession->eapRestart)
            {
                newState = EAP1X_PEER_STATE_AUTHENTICATING;
                stateChangeRequired = TRUE;
            }
            break;
        }

        case EAP1X_PEER_STATE_HELD:
        {
            if (TRUE == eapSession->eapolEap)
            {
                newState = EAP1X_PEER_STATE_RESTART;
                stateChangeRequired = TRUE;
            }
            break;
        }

        case EAP1X_PEER_STATE_CONNECTING:
        {
            if (TRUE == eapSession->eapolEap)
            {
                newState = EAP1X_PEER_STATE_RESTART;
                stateChangeRequired = TRUE;
                break;
            }

            if((TRUE == eapSession->eapSuccess) ||
               (TRUE == eapSession->eapFail))
            {
                newState = EAP1X_PEER_STATE_AUTHENTICATING;
                stateChangeRequired = TRUE;
                break;
            }
            break;
        }

        case EAP1X_PEER_STATE_AUTHENTICATING:
        {
            if ((TRUE == eapSession->suppSuccess) &&
                (TRUE == eapSession->portValid))
            {
                eapSession->stats.suppSuccessesWhileAuthenticating++;
                newState = EAP1X_PEER_STATE_AUTHENTICATED;
                stateChangeRequired = TRUE;
                break;
            }

            if((TRUE == eapSession->suppTimeout))
            {
                eapSession->stats.suppTimeoutsWhileAuthenticating++;
                newState = EAP1X_PEER_STATE_CONNECTING;
                stateChangeRequired = TRUE;
                break;
            }

            if ((TRUE == eapSession->suppFail) ||
                ((TRUE == eapSession->keyDone) &&
                (FALSE == eapSession->portValid)))
            {
                if (TRUE == eapSession->suppFail)
                    eapSession->stats.suppFailWhileAuthenticating++;
                newState = EAP1X_PEER_STATE_HELD;
                stateChangeRequired = TRUE;
                break;
            }

            break;
        }

        case EAP1X_PEER_STATE_AUTHENTICATED:
        {
            if (FALSE == eapSession->portValid)
            {
                newState = EAP1X_PEER_STATE_DISCONNECTED;
                stateChangeRequired = TRUE;
                break;
            }

            if ((TRUE == eapSession->eapolEap) &&
                (TRUE == eapSession->portValid))
            {
                eapSession->stats.suppEapRecvWhileAuthenticated++;
                newState = EAP1X_PEER_STATE_RESTART;
                stateChangeRequired = TRUE;
                break;
            }

            break;
        }

        /* It can only transition out when initialize is deasserted
           and portEnabled is True */
        case EAP1X_PEER_STATE_DISCONNECTED:
        {

            if((FALSE == eapSession->initialize) &&
               (TRUE == eapSession->portEnabled))
            {
                stateChangeRequired = TRUE;
                newState = EAP1X_PEER_STATE_CONNECTING;
            }
            break;
        }

        default:
            break;

    }

stateChanged:
    if (stateChangeRequired)
        status = EAP1X_peerStateTransition(newState, eapSession, NULL);
exit:
    return status;

} /* EAP1X_peerCheckState */

/*------------------------------------------------------------------*/

/*! Set an EAP1X session's state parameters (which in turn control the EAP state machine).
This function sets an EAP1X session's state parameters (which in turn
control the EAP state machine).

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\note The state parameters are defined in IEEE Standard 802.1X-2004, Section
8.2.11 (Peer State machine).

\param session      EAP session handle returned from EAP1X_peerSessionCreate.
\param stateInfo    Bitmask combination (created by $OR$ing definitions
together) of desired state parameters to set. Valid state parameter
definitions are:\n
\n
&bull; $EAP1X_EAPOL_INITIALIZE$\n
&bull; $EAP1X_EAPOL_USERLOGOFF\n$
&bull; $EAP1X_EAPOL_LOGOFF$\n
&bull; $EAP1X_EAP_EAPOL$\n
&bull; $EAP1X_EAP_RESTART$\n
&bull; $EAP1X_EAP_PEER_SUCCESS$\n
&bull; $EAP1X_EAP_PEER_FAIL$\n
&bull; $EAP1X_EAP_EAP_SUCCESS$\n
&bull; $EAP1X_EAP_EAP_FAIL$\n
&bull; $EAP1X_EAP_PEER_TIMEOUT$\n
&bull; $EAP1X_EAP_PORT_VALID$\n
&bull; $EAP1X_EAP_PORT_ENABLED$

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_peerUpdateUnsetState

*/
extern MSTATUS
EAP1X_peerUpdateSetState (ubyte* session,ubyte4 stateInfo)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession = (eap1xPeerCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (stateInfo & EAP1X_EAPOL_INITIALIZE)
    {
        eapSession->initialize = TRUE;
    }

    if (stateInfo & EAP1X_EAPOL_USERLOGOFF)
    {
        eapSession->userLogoff = TRUE;
    }

    if (stateInfo & EAP1X_EAPOL_LOGOFF)
    {
        eapSession->logoffSent = TRUE;
    }

    if (stateInfo & EAP1X_EAP_EAPOL)
    {
        eapSession->eapolEap = TRUE;
    }

    if (stateInfo & EAP1X_EAP_RESTART)
    {
        eapSession->eapRestart = TRUE;
    }

    if (stateInfo & EAP1X_EAP_PEER_SUCCESS)
    {
        eapSession->suppSuccess = TRUE;
    }

    if (stateInfo & EAP1X_EAP_PEER_FAIL)
    {
        eapSession->suppFail = TRUE;
    }

    if (stateInfo & EAP1X_EAP_EAP_SUCCESS)
    {
        eapSession->eapSuccess = TRUE;
    }

    if (stateInfo & EAP1X_EAP_EAP_FAIL)
    {
        eapSession->eapFail = TRUE;
    }

    if (stateInfo & EAP1X_EAP_PEER_TIMEOUT)
    {
        eapSession->suppTimeout = TRUE;
    }


    if (stateInfo & EAP1X_EAP_PORT_VALID)
    {
        eapSession->portValid = TRUE;
    }

    if (stateInfo & EAP1X_EAP_PORT_ENABLED)
    {
        eapSession->portEnabled = TRUE;
    }

    EAP1X_peerCheckState(session);

exit:
    return status;
}

/*------------------------------------------------------------------*/

/*! Clear (unset) an EAP1X session's state parameters (which in turn control the EAP state machine).
This function clears (unsets) an EAP1X session's state parameters (which in turn
control the EAP state machine).

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\note The state parameters are defined in IEEE Standard 802.1X-2004, Section
8.2.11 (Peer State machine).

\param session      EAP session handle returned from EAP1X_peerSessionCreate.
\param stateInfo    Bitmask combination (created by $OR$ing definitions
together) of desired state parameters to clear (unset). Valid state parameter
definitions are:\n
\n
&bull; $EAP1X_EAPOL_INITIALIZE$\n
&bull; $EAP1X_EAPOL_USERLOGOFF\n$
&bull; $EAP1X_EAPOL_LOGOFF$\n
&bull; $EAP1X_EAP_EAPOL$\n
&bull; $EAP1X_EAP_RESTART$\n
&bull; $EAP1X_EAP_PEER_SUCCESS$\n
&bull; $EAP1X_EAP_PEER_FAIL$\n
&bull; $EAP1X_EAP_EAP_SUCCESS$\n
&bull; $EAP1X_EAP_EAP_FAIL$\n
&bull; $EAP1X_EAP_PEER_TIMEOUT$\n
&bull; $EAP1X_EAP_PORT_VALID$\n
&bull; $EAP1X_EAP_PORT_ENABLED$

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_peerUpdateSetState

*/
extern MSTATUS
EAP1X_peerUpdateUnsetState (ubyte* session,ubyte4 stateInfo)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession = (eap1xPeerCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (stateInfo & EAP1X_EAPOL_INITIALIZE)
    {
        eapSession->initialize = FALSE;
    }

    if (stateInfo & EAP1X_EAPOL_USERLOGOFF)
    {
        eapSession->userLogoff = FALSE;
    }

    if (stateInfo & EAP1X_EAPOL_LOGOFF)
    {
        eapSession->logoffSent = FALSE;
    }


    if (stateInfo & EAP1X_EAP_RESTART)
    {
        eapSession->eapRestart = FALSE;
    }

    if (stateInfo & EAP1X_EAP_PEER_SUCCESS)
    {
        eapSession->suppSuccess = FALSE;
    }

    if (stateInfo & EAP1X_EAP_PEER_FAIL)
    {
        eapSession->suppFail = FALSE;
    }

    if (stateInfo & EAP1X_EAP_EAP_SUCCESS)
    {
        eapSession->eapSuccess = FALSE;
    }

    if (stateInfo & EAP1X_EAP_EAP_FAIL)
    {
        eapSession->eapFail = FALSE;
    }

    if (stateInfo & EAP1X_EAP_PEER_TIMEOUT)
    {
        eapSession->suppTimeout = FALSE;
    }


    if (stateInfo & EAP1X_EAP_PORT_VALID)
    {
        eapSession->portValid = FALSE;
    }

    if (stateInfo & EAP1X_EAP_PORT_ENABLED)
    {
        eapSession->portEnabled = FALSE;
    }

    EAP1X_peerCheckState(session);

exit:
    return status;
}

/*------------------------------------------------------------------*/

/*! Build an EAPOL-Start message.
This function builds an EAPOL-Start message, returning it through the $ppPkt$
parameter. Your application can then send the message using the appropriate
transport layer functions

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\note To prevent a memory leak, be sure to free the resulting packet ($ppPkt$) after
your application is done with it.

\param session      EAP session handle returned from EAP1X_peerSessionCreate.
\param ppPkt        On return, pointer to resultant EAPOL-Start message packet.
\param pPktLen      On return, pointer to number of bytes (including the
$headRoom$) in resultant EAPOL-Start message packet ($ppPkt$).
\param headRoom     Number of bytes available to fill in the lower layer header.
(These bytes will be included in the returned $pPktLen$ value.)

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_sendEAPOLLogoff

*/
extern MSTATUS
EAP1X_sendEAPOLStart (ubyte* session,ubyte** ppPkt, ubyte4 *pPktLen,ubyte4 headRoom)
{
    MSTATUS status = OK;
    ubyte *pPkt = NULL;
    eap1xHdr_t *eap1xHdr;
    eap1xPeerCb_t *eapSession = (eap1xPeerCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->stats.suppEapolStartFramesTx++;
    pPkt = MALLOC(sizeof(eap1xHdr_t)+headRoom);

    if (NULL == pPkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }


    *ppPkt = pPkt;
    eap1xHdr = (eap1xHdr_t *)((ubyte *)pPkt + headRoom);

    /*Set EAP1X_ETH_TYPE);*/
    DIGI_HTONS(pPkt+headRoom, eapSession->cfg.etherProto);
    eap1xHdr->version = EAP1X_EAPOL_VERSION;
    eap1xHdr->pktType = EAP1X_EAPOL_START_TYPE;
    /*Set Length 0;*/
    DIGI_HTONS(pPkt + headRoom + EAP1X_HDR_LENGTH_OFFSET, 0);

    *pPktLen = sizeof(eap1xHdr_t) + headRoom;

exit:
    return status;
}

/*------------------------------------------------------------------*/

/*! Build an EAPOL-Logoff message.
This function builds an EAPOL-Logoff message, returning it through the $ppPkt$
parameter. Your application can then send the message using the appropriate
transport layer functions

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\note To prevent a memory leak, be sure to free the resulting packet ($ppPkt$) after
your application is done with it.

\param session      EAP session handle returned from EAP1X_peerSessionCreate.
\param ppPkt        On return, pointer to resultant EAPOL-Logoff message packet.
\param pPktLen      On return, pointer to number of bytes (including the
$headRoom$) in resultant EAPOL-Logoff message packet ($ppPkt$).
\param headRoom     Number of bytes available to fill in the lower layer header.
(These bytes will be included in the returned $pPktLen$ value.)

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_sendEAPOLStart

*/
extern MSTATUS
EAP1X_sendEAPOLLogoff (ubyte* session,ubyte** ppPkt, ubyte4 *pPktLen,ubyte4 headRoom)
{
    MSTATUS status = OK;
    ubyte *pPkt = NULL;
    eap1xHdr_t *eap1xHdr;
    eap1xPeerCb_t *eapSession = (eap1xPeerCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }


    pPkt = MALLOC(sizeof(eap1xHdr_t)+headRoom);

    if (NULL == pPkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }


    eapSession->stats.suppEapolLogoffFramesTx++;
    *ppPkt = pPkt;
    eap1xHdr = (eap1xHdr_t *)((ubyte *)pPkt + headRoom);

    /*Set EAP1X_ETH_TYPE);*/
    DIGI_HTONS(pPkt+headRoom, eapSession->cfg.etherProto);
    eap1xHdr->version = EAP1X_EAPOL_VERSION;
    eap1xHdr->pktType = EAP1X_EAPOL_LOGOFF_TYPE;
    /*Set Length  = 0;*/
    DIGI_HTONS(pPkt + headRoom + EAP1X_HDR_LENGTH_OFFSET, 0);

    *pPktLen = sizeof(eap1xHdr_t) + headRoom;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Create an EAP1X peer session.
This function creates an EAP1X peer session based on the specified
parameters, returning the resultant session handle through the $session$
parameter. Before calling this function, your application must first call
EAP1X_peerInit.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\param appHdl       Pointer to application cookie.
\param session      On return, pointer to EAP1X session handle.
\param cfg          Pointer to desired EAP1X session parameters.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_peerInit

*/
extern MSTATUS
EAP1X_peerSessionCreate (ubyte* appHdl, ubyte** session, eap1xPeerSessionCfg *cfg)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession = MALLOC(sizeof(eap1xPeerCb_t));

    if (NULL == eapSession)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if ((NULL == cfg->funcPtrEAPIndication) ||
        (NULL == cfg->funcPtrEAPOLCallback))
    {
        status = ERR_EAP_INVALID_PARAM;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)eapSession,0,sizeof(eap1xPeerCb_t));

    DIGI_MEMCPY((ubyte*)&eapSession->cfg, (ubyte*)cfg, sizeof(eap1xPeerSessionCfg));

    eapSession->appHdl = appHdl;
    eapSession->portControl = cfg->portControl;
    eapSession->initialize  = TRUE;

    *session = (ubyte *)eapSession;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"Session Create App Handle:");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)((uintptr)eapSession->appHdl));
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)": Port Number :");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)eapSession->cfg.portNumber);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" ");

exit:
    if (OK > status)
    {
        if (eapSession)
            FREE(eapSession);
    }
    return status;
}

/*------------------------------------------------------------------*/

/*! Delete an EAP1X peer session.
This function deletes an EAP1X peer session. After you delete the session, you
should call EAP1X_peerdeinit to destroy the session's timers.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\param appHdl       Pointer to application cookie.
\param session      Pointer to EAP1X session handle returned from EAP1X_peerSessionCreate.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_peerInit
\sa EAP1X_peerdeinit

*/
extern MSTATUS
EAP1X_peerSessionDelete (ubyte* appHdl, ubyte* session )
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession  = (eap1xPeerCb_t *)session;

    if (NULL == eapSession)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"Session Delete App Handle:");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)((uintptr)eapSession->appHdl));
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)": Port Number :");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)eapSession->cfg.portNumber);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" ");

    TIMER_unTimer(eapSession,gEap1XGlobalState.startTimer);
    TIMER_unTimer(eapSession,gEap1XGlobalState.heldTimer);
    FREE(eapSession);

exit:
    return status;
}

/*------------------------------------------------------------------*/

/*! Start the EAP1X state machine and initialize the EAP1X stack and timers.
This function starts the EAP1X state machine and initializes the EAP1X stack
and timers. This function needs to be called before calling EAP1X_peerSessionCreate.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_peerSessionCreate

*/
extern MSTATUS
EAP1X_peerInit()
{
    MSTATUS status;

    /* Initialize Timer Queue */
    status = TIMER_initTimer();
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP1X_init: TIMER_initTimer() failed, status = ", status);
        goto exit;
    }

    status = TIMER_createTimer(EAP1X_peerTimeoutCallback,&gEap1XGlobalState.startTimer);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP1X_init: TIMER_createTimer() failed, status = ", status);
        goto exit;
    }
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP1X_init: TIMER_createTimer() Start Timer ", status);


    status = TIMER_createTimer(EAP1X_peerTimeoutCallback,&gEap1XGlobalState.heldTimer);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP1X_init: TIMER_createTimer() failed, status = ", status);
        goto exit;
    }
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP1X_init: TIMER_createTimer() Held Timer ", status);

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"EAP1X_peerIinit: Initialized EAP Peer Instance");
    DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"Initialized EAP1X ");

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP1X_init: Failed Status ", (sbyte4)status);
    }

    return status;

} /* EAP1X_peerInit */


/*! Destroy EAP1X timers.
This function destroys EAP1X timers that were created by EAP1X_peerInit. You
should call this function after calling EAP1X_peerSessionDelete.

\since 3.1
\version 3.1 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_peerSessionDelete

*/
extern MSTATUS
EAP1X_peerdeinit()
{
    MSTATUS status;

    status = TIMER_destroyTimer(gEap1XGlobalState.startTimer);
    status = TIMER_destroyTimer(gEap1XGlobalState.heldTimer);
    return status;
}/* EAP1X_peerdeinit */
/*------------------------------------------------------------------*/

static void
EAP1X_peerTimeoutCallback(void *session, ubyte *type)
{

    if (gEap1XGlobalState.startTimer == type)
        EAP1X_peerStartTimeout(session);
    else if (gEap1XGlobalState.heldTimer == type)
        EAP1X_peerHeldTimeout(session);

    return;
}

/*------------------------------------------------------------------*/

/*! Get an EAP1X session's current statistics.
This function retrieves an EAP1X session's current statistics.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\param session  Pointer to EAP1X session handle returned from EAP1X_peerSessionCreate.
\param stats    On return, pointer to the session's current statistics values.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_peerSessionCreate

*/
extern MSTATUS
EAP1X_peerGetSesssionStats (ubyte* session,eap1xPeerStats* stats)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession = (eap1xPeerCb_t *) session;

    if ((NULL == eapSession) || (NULL == stats))
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    DIGI_MEMCPY((ubyte *)stats,(ubyte *)&eapSession->stats,sizeof(eap1xPeerStats));

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get an EAP1X session's current state.
This function retrieves an EAP1X session's current state.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\param session  Pointer to EAP1X session handle returned from EAP1X_peerSessionCreate.
\param state    On return, pointer to the session's current state values.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_peerSessionCreate

*/
extern MSTATUS
EAP1X_peerGetSesssionState (ubyte* session,eap1XPeerState_t* state)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession = (eap1xPeerCb_t *) session;

    if ((NULL == eapSession) || (NULL == state))
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    *state = eapSession->eapPeerCurrentState;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Set (update) an EAP1X session's port control mode.
This function sets (updates) an EAP1X session's port control mode.

For EAP-based authentication, the port control mode should be set to
$EAP1X_PORT_MODE_AUTO$. You can force the port into an authorized or
unauthorized state by setting the port control mode parameter to
$EAP1X_PORT_MODE_FORCED_AUTHORIZED$ or $EAP1X_PORT_MODE_FORCED_UNAUTHORIZED$,
respectively.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\param session      EAP session handle returned from EAP1X_peerSessionCreate.
\param portMode     Any of the $eap1xPortMode$ enumerated values (defined in eap1x.h).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_peerUpdateSetState

*/
extern MSTATUS
EAP1X_peerUpdatePortControl (ubyte* session,eap1xPortMode portMode)
{
    MSTATUS status = OK;
    eap1xPeerCb_t *eapSession = (eap1xPeerCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->portControl = portMode;

    EAP1X_peerCheckState(session);

exit:
    return status;

}

/*------------------------------------------------------------------*/

/*! Send the received EAP1X packets to the EAP1X layer.
This function sends the received EAP1X packets to the EAP1X layer. First the
packet header's type is evaluated. For EAP1X_EAP_EAPOL messages, this function
invokes the session's $funcPtrEAPOLCallback$ function.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\param session  Pointer to EAP1X session handle returned from EAP1X_peerSessionCreate.
\param pPkt     Pointer to received EAP1X packet.
\param pktLen   Number of bytes in the received packet ($pPkt$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_peerSendEAP
\sa EAP1X_sendEAPOLStart
\sa EAP1X_sendEAPOLLogoff

*/
extern MSTATUS
EAP1X_peerReceivePkt (ubyte* session,ubyte* pPkt,ubyte4 pktLen)
{

    MSTATUS status = OK;
    ubyte4  stateInfo = 0;
    ubyte *pktBody = pPkt + sizeof(eap1xHdr_t);
    eap1xPeerCb_t *eapSession = (eap1xPeerCb_t *) session;
    eap1xHdr_t *eap1xHdr = (eap1xHdr_t *)pPkt;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if ((!pPkt) || (pktLen < sizeof(eap1xHdr_t)))
    {
        status = ERR_EAP_INVALID_PKT;
        eapSession->stats.suppEapolInvalidLengthFramesRx++;
        goto exit;
    }

    /*Check length )*/
    if (DIGI_NTOHS(pPkt+EAP1X_HDR_LENGTH_OFFSET) >  pktLen)
    {
        status = ERR_EAP_INVALID_PKT;
        eapSession->stats.suppEapolInvalidLengthFramesRx++;
        goto exit;
    }

    eapSession->stats.suppEapolFramesRx++;
    eapSession->stats.suppEapolLastFrameVersion = eap1xHdr->version;

    switch (eap1xHdr->pktType)
    {
        case EAP1X_EAPOL_EAP_TYPE:
        {

            stateInfo  =  EAP1X_EAP_EAPOL;
            EAP1X_peerUpdateSetState(session,stateInfo);

            eapSession->cfg.funcPtrEAPOLCallback(eapSession->appHdl,pktBody,DIGI_NTOHS(pPkt+EAP1X_HDR_LENGTH_OFFSET), eap1xHdr->pktType);
            break;
        }
        default:
            eapSession->stats.suppEapolInvalidFramesRx++;
            status = ERR_EAP_INVALID_PKT;
            break;

    }
exit:
    return status;
}

/*------------------------------------------------------------------*/

/*! Encapsulate an EAP packet with an EAP1X header.
This function encapsulates an EAP packet with an EAP1X header. The calling
application must provide necessary data headroom for any required prepended
data, such as the source or destination MAC address in the EAP1X header.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\note To prevent a memory leak, be sure to free the resulting packet ($ppPkt$) after
your application is done with it.

\param session          Pointer to EAP1X session handle returned from EAP1X_peerSessionCreate.
\param eap_hdr          Pointer to EAP packet header.
\param eap_data         Pointer to EAP packet payload.
\param eap_data_len     Number of bytes in EAP packet payload ($eap_data$).
\param headRoom         Number of bytes available to fill in the lower layer
header. (These bytes will be included in the returned $pPktLen$ value.)
\param ppPkt            On return, pointer to resulting encapsulated packet.
\param pPktLen          On return, pointer to number of bytes (including the
$headRoom$) in the resulting encapsulated packet ($ppPkt$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_peerReceivePkt
\sa EAP1X_sendEAPOLStart
\sa EAP1X_sendEAPOLLogoff

*/
extern  MSTATUS
EAP1X_peerSendEAP(ubyte *session,
                          eapHdr_t *eap_hdr,
                          ubyte *eap_data,
                          ubyte4 eap_data_len,
                          ubyte4 headRoom,
                          ubyte **ppPkt,ubyte2 *pPktLen)
{

    MSTATUS status = OK;
    ubyte *pPkt = NULL;
    ubyte *pktBody;
    eap1xHdr_t *eap1xHdr;
    eap1xPeerCb_t *eapSession = (eap1xPeerCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }


    pPkt = MALLOC(sizeof(eap1xHdr_t)+headRoom+ sizeof(eapHdr_t)+eap_data_len);

    if (NULL == pPkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eapSession->stats.suppEapolFramesTx++;

    *ppPkt = pPkt;
    eap1xHdr = (eap1xHdr_t *)((ubyte *)pPkt + headRoom);

    /* Set EAP1X_ETH_TYPE);*/
    DIGI_HTONS(pPkt+headRoom, eapSession->cfg.etherProto);
    eap1xHdr->version = EAP1X_EAPOL_VERSION;
    eap1xHdr->pktType = EAP1X_EAPOL_EAP_TYPE;
    /* Set length */
    DIGI_HTONS(pPkt + headRoom + EAP1X_HDR_LENGTH_OFFSET, sizeof(eapHdr_t)+eap_data_len);
    pktBody = (ubyte *)eap1xHdr + sizeof(eap1xHdr_t);
    DIGI_MEMCPY(pktBody,(ubyte*)eap_hdr,sizeof(eapHdr_t));
    DIGI_MEMCPY(pktBody+sizeof(eapHdr_t),eap_data,eap_data_len);

    *pPktLen = sizeof(eap1xHdr_t) + headRoom +sizeof(eapHdr_t)+eap_data_len;

exit:
    return status;

}
/*------------------------------------------------------------------*/

/*! Call expired timers' callbacks.
This function determines whether any timers have expired, and if so then calls
each expired expired timer's callback function. Your application should call
this function on every clock tick (every 300 to 500 milliseconds) to provide
time to the EAP1X stack.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap1x_peer.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP1X_peerCheckTimers()
{
    /*DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, "EAP1X_peerCheckTimers: got here");*/

    if ( gEap1XGlobalState.startTimer)
        TIMER_checkTimer( gEap1XGlobalState.startTimer);
    if ( gEap1XGlobalState.heldTimer)
        TIMER_checkTimer( gEap1XGlobalState.heldTimer);

    return 0;
}


/*------------------------------------------------------------------*/
#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) */

