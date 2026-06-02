/**
 * @file  eap1x_auth.c
 * @brief 802.1X authenticator
 *
 * @details    802.1X server-side functions
 * @since      2.02
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
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
#include "../crypto/hw_accel.h"
#include "../common/timer.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap1x.h"
#include "../eap/eap1x_auth.h"
#include "../eap/eap1x_pvt.h"


/*------------------------------------------------------------------*/

/* Local Methods */
static MSTATUS EAP1X_authStateInit (void *, void *);
static MSTATUS EAP1X_authStateDisconnected (void *, void *);
static MSTATUS EAP1X_authStateRestart (void *, void *);
static MSTATUS EAP1X_authStateConnecting (void *, void *);
static MSTATUS EAP1X_authStateAuthenticating(void *, void *);
static MSTATUS EAP1X_authStateAuthenticated(void *, void *);
static MSTATUS EAP1X_authStateAborting(void *, void *);
static MSTATUS EAP1X_authStateHeld(void *, void *);
static MSTATUS EAP1X_authStateForceAuth(void *, void *);
static MSTATUS EAP1X_authStateForceUnAuth(void *, void *);
static MSTATUS EAP1X_authStateTransition(eap1XAuthState_t newState,
                                       void *session,
                                       void * arg);
static void EAP1X_authTimeoutCallback(void *session, ubyte *type);
static MSTATUS EAP1X_authPortTimeout(void *session);
static MSTATUS EAP1X_authReAuthTimeout(void *session);
static MSTATUS EAP1X_authHeldTimeout(void *session);
static MSTATUS EAP1X_authCheckState(ubyte* session);

/*------------------------------------------------------------------*/

static eap1xAuthGlobal_t gEap1XGlobalState;

/*------------------------------------------------------------------*/

const eap1XAuthStateBits_t eap1X_AuthStateBits[] =
{
    {0, (ubyte *)"NoState",NULL },
    {EAP1X_AUTH_STATE_INIT, (ubyte *)"AuthInit", EAP1X_authStateInit},
    {EAP1X_AUTH_STATE_DISCONNECTED, (ubyte *)"AuthDisconnected", EAP1X_authStateDisconnected},
    {EAP1X_AUTH_STATE_RESTART, (ubyte *)"AuthRestart", EAP1X_authStateRestart},
    {EAP1X_AUTH_STATE_CONNECTING, (ubyte *)"AuthConnecting", EAP1X_authStateConnecting},
    {EAP1X_AUTH_STATE_AUTHENTICATING, (ubyte *)"AuthAuthenticating", EAP1X_authStateAuthenticating},
    {EAP1X_AUTH_STATE_AUTHENTICATED, (ubyte *)"AuthAuthenticated", EAP1X_authStateAuthenticated},
    {EAP1X_AUTH_STATE_ABORTING, (ubyte *)"AuthAborting", EAP1X_authStateAborting},
    {EAP1X_AUTH_STATE_HELD, (ubyte *)"AuthHeld", EAP1X_authStateHeld},
    {EAP1X_AUTH_STATE_FORCE_AUTH, (ubyte *)"AuthForceAuth", EAP1X_authStateForceAuth},
    {EAP1X_AUTH_STATE_FORCE_UNAUTH, (ubyte *)"AuthForceUnAuth", EAP1X_authStateForceUnAuth}
};


/*------------------------------------------------------------------*/

/*Extern Definitions */

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_authStateInit(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession  = (eap1xSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->portMode = EAP1X_PORT_MODE_AUTO;
    eapSession->eapolStart    = FALSE;
    eapSession->eapReq        = FALSE;
    eapSession->eapRestart    = FALSE;
    eapSession->initialize    = FALSE;


    /* Change State to DISCONNECTED State */
    status = EAP1X_authStateTransition(EAP1X_AUTH_STATE_DISCONNECTED, hdl, arg);

exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_authStateForceAuth(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession  = (eap1xSessionCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->portMode = EAP1X_PORT_MODE_FORCED_AUTHORIZED;
    eapSession->authPortStatus = EAP1X_PORT_STATUS_AUTHORIZED;
    eapSession->eapolStart = FALSE;

    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_AUTHORIZED);
    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_SEND_SUCCESS);

exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_authStateForceUnAuth(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession  = (eap1xSessionCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->portMode = EAP1X_PORT_MODE_FORCED_UNAUTHORIZED;
    eapSession->authPortStatus = EAP1X_PORT_STATUS_UNAUTHORIZED;
    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_UNAUTHORIZED);
    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_SEND_FAILURE);
    eapSession->eapolStart = FALSE;

exit:
    return status;

}

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_authStateDisconnected(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession  = (eap1xSessionCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    /* Remove the Reauth Timer */
    if (TRUE == eapSession->cfg.reAuthEnabled)
        TIMER_unTimer(eapSession,gEap1XGlobalState.reAuthTimer);

    TIMER_unTimer(eapSession,gEap1XGlobalState.heldTimer);

    eapSession->authPortStatus = EAP1X_PORT_STATUS_UNAUTHORIZED;
    eapSession->reAuthCount    = 0;
    eapSession->eapolLogoff    = FALSE;

    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_UNAUTHORIZED);
    /* Change State to RESTART State */
    status = EAP1X_authStateTransition(EAP1X_AUTH_STATE_RESTART, hdl, arg);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_authStateRestart(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession  = (eap1xSessionCb_t *)hdl;
    MOC_UNUSED(arg);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    /* Remove the Reauth Timer */
    if (TRUE == eapSession->cfg.reAuthEnabled)
        TIMER_unTimer(eapSession,gEap1XGlobalState.reAuthTimer);

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
EAP1X_authStateConnecting(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession  = (eap1xSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->stats.authEntersConnecting++;
    eapSession->reAuthenticate = FALSE;
    eapSession->reAuthCount++;
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP1X_authStateConnecting: Reauth Count ", (sbyte4)eapSession->reAuthCount);

    if (eapSession->reAuthCount > eapSession->cfg.reAuthMax)
    {
        status = EAP1X_authStateTransition(EAP1X_AUTH_STATE_DISCONNECTED, eapSession, arg);
    }

exit:

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_authStateAuthenticating(void *hdl, void *arg)
{
    MSTATUS  status = OK;
    eap1xSessionCb_t *eapSession  = (eap1xSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->stats.authEntersAuthenticating++;
    eapSession->eapolStart  = FALSE;
    eapSession->authSuccess = FALSE;
    eapSession->authFail    = FALSE;
    eapSession->authTimeout = FALSE;
    eapSession->authStart   = TRUE;
    eapSession->keyRun      = FALSE;
    eapSession->keyDone     = FALSE;

exit:
    return status;

} /* EAP1X_authStateAuthenticating */


/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_authStateAuthenticated(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession  = (eap1xSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->authPortStatus = EAP1X_PORT_STATUS_AUTHORIZED;
    eapSession->reAuthCount    = 0;

    /* Set the Reauth Timer */
    if (TRUE == eapSession->cfg.reAuthEnabled)
        TIMER_queueTimer(eapSession,gEap1XGlobalState.reAuthTimer,
                         eapSession->cfg.reAuthTimeout,0);

    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_AUTHORIZED);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_authStateAborting(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession  = (eap1xSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->authAbort = TRUE;
    eapSession->keyRun    = FALSE;
    eapSession->keyDone   = TRUE;

    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_ABORT);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_authStateHeld(void *hdl, void *arg)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession  = (eap1xSessionCb_t *)hdl;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->authPortStatus = EAP1X_PORT_STATUS_UNAUTHORIZED;
    eapSession->eapolLogoff    = FALSE;

    /* Restart the Timer  for quiet Period*/
    TIMER_queueTimer(eapSession,gEap1XGlobalState.heldTimer,eapSession->cfg.quietTime,0);

    status = eapSession->cfg.funcPtrEAPIndication(eapSession->appHdl,(ubyte *)eapSession,EAP1X_INDICATION_UNAUTHORIZED);

exit:
    return status;

} /* EAP1X_authStateHeld */

/*------------------------------------------------------------------*/


static MSTATUS
EAP1X_authStateTransition(eap1XAuthState_t newState,
                        void *session,
                        void * arg)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession = (eap1xSessionCb_t *)session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP1X_authStateTransition: Transition Session ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)eapSession->appHdl);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, ":");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " from State ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)eap1X_AuthStateBits[eapSession->eapAuthCurrentState].stateDescription);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " to ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte *)eap1X_AuthStateBits[newState].stateDescription);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, "");

    eapSession->eapAuthPrevState    = eapSession->eapAuthCurrentState;
    eapSession->eapAuthCurrentState = newState;
    status = eap1X_AuthStateBits[newState].stateFn (session,arg);

exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_authHeldTimeout(void *session)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession = (eap1xSessionCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }



    status = EAP1X_authStateTransition(EAP1X_AUTH_STATE_RESTART, eapSession, NULL);

exit:
    return status;

} /* EAP1X_authHeldTimeout */

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_authReAuthTimeout(void *session)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession = (eap1xSessionCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->reAuthenticate = TRUE;
    eapSession->stats.authAuthReauthsWhileAuthenticated++;

    status = EAP1X_authStateTransition(EAP1X_AUTH_STATE_RESTART, eapSession, NULL);

exit:

    return status;

} /* EAP1X_authReAuthTimeout */

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_authPortTimeout(void *session)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession = (eap1xSessionCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }


    TIMER_queueTimer(eapSession,gEap1XGlobalState.portTimer,
                     eapSession->cfg.portTimeout,0);

    EAP1X_authCheckState(session);

exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
EAP1X_authCheckState(ubyte* session)
{
    MSTATUS status = OK;
    eap1XAuthState_t newState;
    intBoolean  stateChangeRequired = FALSE ;

    eap1xSessionCb_t *eapSession = (eap1xSessionCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }


    if ((EAP1X_PORT_MODE_AUTO == eapSession->portControl) &&
        ((eapSession->portMode != eapSession->portControl)      ||
        (FALSE == eapSession->portEnabled)      ||
        (eapSession->initialize)))
    {
        newState = EAP1X_AUTH_STATE_INIT;
        stateChangeRequired = TRUE;
        goto stateChanged;
    }

    if ((EAP1X_PORT_MODE_FORCED_AUTHORIZED == eapSession->portControl) &&
        ((eapSession->portMode != eapSession->portControl)   &&
        !((FALSE == eapSession->portEnabled)      ||
          (eapSession->initialize))))
    {
        newState = EAP1X_AUTH_STATE_FORCE_AUTH;
        stateChangeRequired = TRUE;
        goto stateChanged;
    }

    if ((EAP1X_PORT_MODE_FORCED_UNAUTHORIZED == eapSession->portControl) &&
        ((eapSession->portMode != eapSession->portControl)   &&
        !((FALSE == eapSession->portEnabled)      ||
          (eapSession->initialize))))
    {
        newState = EAP1X_AUTH_STATE_FORCE_AUTH;
        stateChangeRequired = TRUE;
        goto stateChanged;
    }

    switch (eapSession->eapAuthCurrentState)
    {

        case EAP1X_AUTH_STATE_RESTART:
        {
            if (FALSE == eapSession->eapRestart)
            {
                newState = EAP1X_AUTH_STATE_CONNECTING;
                stateChangeRequired = TRUE;
            }
            break;
        }

        case EAP1X_AUTH_STATE_CONNECTING:
        {
            if (TRUE == eapSession->eapolLogoff)
            {
                eapSession->stats.authEapLogoffsWhileConnecting++;
                newState = EAP1X_AUTH_STATE_DISCONNECTED;
                stateChangeRequired = TRUE;
                break;
            }

            if (((TRUE == eapSession->eapReq) &&
                (eapSession->reAuthCount <= eapSession->cfg.reAuthMax)) ||
                 (TRUE == eapSession->eapSuccess) ||
                 (TRUE == eapSession->eapFail))
            {
                newState = EAP1X_AUTH_STATE_AUTHENTICATING;
                stateChangeRequired = TRUE;
                break;
            }
            break;
        }

        case EAP1X_AUTH_STATE_AUTHENTICATING:
        {
            if ((TRUE == eapSession->authSuccess) &&
                (TRUE == eapSession->portValid))
            {
                eapSession->stats.authAuthSuccessesWhileAuthenticating++;
                newState = EAP1X_AUTH_STATE_AUTHENTICATED;
                stateChangeRequired = TRUE;
                break;
            }

            if ((TRUE == eapSession->eapolStart) ||
                (TRUE == eapSession->eapolLogoff) ||
                (TRUE == eapSession->authTimeout))
            {
                if (TRUE == eapSession->authTimeout)
                    eapSession->stats.authAuthTimeoutsWhileAuthenticating++;
                if (TRUE == eapSession->eapolStart)
                    eapSession->stats.authAuthEapStartsWhileAuthenticating++;
                if (TRUE == eapSession->eapolLogoff)
                    eapSession->stats.authAuthEapLogoffsWhileAuthenticating++;
                newState = EAP1X_AUTH_STATE_ABORTING;
                stateChangeRequired = TRUE;
                break;
            }

            if ((TRUE == eapSession->authFail) ||
                ((TRUE == eapSession->keyDone) &&
                (FALSE == eapSession->portValid)))
            {
                if (TRUE == eapSession->authFail)
                    eapSession->stats.authAuthFailWhileAuthenticating++;
                newState = EAP1X_AUTH_STATE_HELD;
                stateChangeRequired = TRUE;
                break;
            }

            break;
        }

        case EAP1X_AUTH_STATE_AUTHENTICATED:
        {
            if ((TRUE == eapSession->eapolStart) ||
                (TRUE == eapSession->reAuthenticate))
            {
                if (TRUE == eapSession->eapolStart)
                    eapSession->stats.authAuthEapStartsWhileAuthenticated++;
                newState = EAP1X_AUTH_STATE_RESTART;
                stateChangeRequired = TRUE;
                break;
            }

            if ((TRUE == eapSession->eapolLogoff) ||
                (FALSE == eapSession->portValid))
            {
                if (TRUE == eapSession->eapolLogoff)
                    eapSession->stats.authAuthEapLogoffsWhileAuthenticated++;
                newState = EAP1X_AUTH_STATE_DISCONNECTED;
                stateChangeRequired = TRUE;
                break;
            }

            break;
        }

        case EAP1X_AUTH_STATE_ABORTING:
        {
            if ((TRUE == eapSession->eapolLogoff) &&
                (FALSE == eapSession->authAbort))
            {
                newState = EAP1X_AUTH_STATE_DISCONNECTED;
                stateChangeRequired = TRUE;
                break;
            }

            if ((FALSE == eapSession->eapolLogoff) &&
                (FALSE == eapSession->authAbort))
            {
                newState = EAP1X_AUTH_STATE_RESTART;
                stateChangeRequired = TRUE;
                break;
            }

            break;
        }
        case EAP1X_AUTH_STATE_FORCE_AUTH:
        {
            if (TRUE == eapSession->eapolStart)
            {
                newState = EAP1X_AUTH_STATE_FORCE_AUTH;
                stateChangeRequired = TRUE;
            }
            break;
        }
        case EAP1X_AUTH_STATE_FORCE_UNAUTH:
        {
            if (TRUE == eapSession->eapolStart)
            {
                newState = EAP1X_AUTH_STATE_FORCE_UNAUTH;
                stateChangeRequired = TRUE;
            }
            break;
        }

        default:
            break;
    }

stateChanged:
    if (stateChangeRequired)
        status = EAP1X_authStateTransition(newState, eapSession, NULL);
exit:
    return status;

} /* EAP1X_authCheckState */

/*------------------------------------------------------------------*/

/*! Set an EAP1X session's state parameters (which in turn control the EAP state machine).
This function sets an EAP1X session's state parameters (which in turn
control the EAP state machine).

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap1x_auth.h

\note The state parameters are defined in IEEE Standard 802.1X-2004, Section
8.2.4 (Authenticator State machine).

\param session      EAP session handle returned from EAP1X_authSessionCreate.
\param stateInfo    Bitmask combination (created by $OR$ing definitions
together) of desired state parameters to set. Valid state parameter
definitions are:\n
\n
&bull; $EAP1X_EAPOL_INITIALIZE$\n
&bull; $EAP1X_EAPOL_START$\n
&bull; $EAP1X_EAPOL_LOGOFF$\n
&bull; $EAP1X_EAP_REQUEST$\n
&bull; $EAP1X_EAP_RESTART$\n
&bull; $EAP1X_EAP_AUTH_SUCCESS$\n
&bull; $EAP1X_EAP_AUTH_FAIL$\n
&bull; $EAP1X_EAP_EAP_SUCCESS$\n
&bull; $EAP1X_EAP_EAP_FAIL$\n
&bull; $EAP1X_EAP_AUTH_TIMEOUT$\n
&bull; $EAP1X_EAP_AUTH_ABORT$\n
&bull; $EAP1X_EAP_PORT_VALID$\n
&bull; $EAP1X_EAP_PORT_ENABLED$

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_authUpdateUnsetState

*/
extern MSTATUS
EAP1X_authUpdateSetState (ubyte* session,ubyte4 stateInfo)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession = (eap1xSessionCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (stateInfo & EAP1X_EAPOL_INITIALIZE)
    {
        eapSession->initialize = TRUE;
    }

    if (stateInfo & EAP1X_EAPOL_START)
    {
        eapSession->eapolStart = TRUE;
    }

    if (stateInfo & EAP1X_EAPOL_LOGOFF)
    {
        eapSession->eapolLogoff = TRUE;
    }

    if (stateInfo & EAP1X_EAP_REQUEST)
    {
        eapSession->eapReq = TRUE;
    }

    if (stateInfo & EAP1X_EAP_RESTART)
    {
        eapSession->eapRestart = TRUE;
    }

    if (stateInfo & EAP1X_EAP_AUTH_SUCCESS)
    {
        eapSession->authSuccess = TRUE;
    }

    if (stateInfo & EAP1X_EAP_AUTH_FAIL)
    {
        eapSession->authFail = TRUE;
    }

    if (stateInfo & EAP1X_EAP_EAP_SUCCESS)
    {
        eapSession->eapSuccess = TRUE;
    }

    if (stateInfo & EAP1X_EAP_EAP_FAIL)
    {
        eapSession->eapFail = TRUE;
    }

    if (stateInfo & EAP1X_EAP_AUTH_TIMEOUT)
    {
        eapSession->authTimeout = TRUE;
    }

    if (stateInfo & EAP1X_EAP_AUTH_ABORT)
    {
        eapSession->authAbort = TRUE;
    }

    if (stateInfo & EAP1X_EAP_PORT_VALID)
    {
        eapSession->portValid = TRUE;
    }

    if (stateInfo & EAP1X_EAP_PORT_ENABLED)
    {
        eapSession->portEnabled = TRUE;
    }

    EAP1X_authCheckState(session);

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
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap1x_auth.h

\note The state parameters are defined in IEEE Standard 802.1X-2004, Section
8.2.4 (Authenticator State machine).

\param session      EAP session handle returned from EAP1X_authSessionCreate.
\param stateInfo    Bitmask combination (created by $OR$ing definitions
together) of desired state parameters to clear (unset). Valid state parameter
definitions are:\n
\n
&bull; $EAP1X_EAPOL_INITIALIZE$\n
&bull; $EAP1X_EAPOL_START$\n
&bull; $EAP1X_EAPOL_LOGOFF$\n
&bull; $EAP1X_EAP_REQUEST$\n
&bull; $EAP1X_EAP_RESTART$\n
&bull; $EAP1X_EAP_AUTH_SUCCESS$\n
&bull; $EAP1X_EAP_AUTH_FAIL$\n
&bull; $EAP1X_EAP_EAP_SUCCESS$\n
&bull; $EAP1X_EAP_EAP_FAIL$\n
&bull; $EAP1X_EAP_AUTH_TIMEOUT$\n
&bull; $EAP1X_EAP_AUTH_ABORT$\n
&bull; $EAP1X_EAP_PORT_VALID$\n
&bull; $EAP1X_EAP_PORT_ENABLED$

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_authUpdateSetState

*/
extern MSTATUS
EAP1X_authUpdateUnsetState (ubyte* session,ubyte4 stateInfo)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession = (eap1xSessionCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (stateInfo & EAP1X_EAPOL_INITIALIZE)
    {
        eapSession->initialize = FALSE;
    }

    if (stateInfo & EAP1X_EAPOL_START)
    {
        eapSession->eapolStart = FALSE;
    }

    if (stateInfo & EAP1X_EAPOL_LOGOFF)
    {
        eapSession->eapolLogoff = FALSE;
    }

    if (stateInfo & EAP1X_EAP_REQUEST)
    {
        eapSession->eapReq = FALSE;
    }

    if (stateInfo & EAP1X_EAP_RESTART)
    {
        eapSession->eapRestart = FALSE;
    }

    if (stateInfo & EAP1X_EAP_AUTH_SUCCESS)
    {
        eapSession->authSuccess = FALSE;
    }

    if (stateInfo & EAP1X_EAP_AUTH_FAIL)
    {
        eapSession->authFail = FALSE;
    }

    if (stateInfo & EAP1X_EAP_EAP_SUCCESS)
    {
        eapSession->eapSuccess = FALSE;
    }

    if (stateInfo & EAP1X_EAP_EAP_FAIL)
    {
        eapSession->eapFail = FALSE;
    }

    if (stateInfo & EAP1X_EAP_AUTH_TIMEOUT)
    {
        eapSession->authTimeout = FALSE;
    }

    if (stateInfo & EAP1X_EAP_AUTH_ABORT)
    {
        eapSession->authAbort = FALSE;
    }

    if (stateInfo & EAP1X_EAP_PORT_VALID)
    {
        eapSession->portValid = FALSE;
    }

    if (stateInfo & EAP1X_EAP_PORT_ENABLED)
    {
        eapSession->portEnabled = FALSE;
    }

    EAP1X_authCheckState(session);

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
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap1x_auth.h

\param session      EAP session handle returned from EAP1X_authSessionCreate.
\param portMode     Any of the $eap1xPortMode$ enumerated values (defined in eap1x.h).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP1X_authUpdatePortControl (ubyte* session,eap1xPortMode portMode)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession = (eap1xSessionCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    eapSession->portControl = portMode;

    EAP1X_authCheckState(session);

exit:
    return status;

}

/*------------------------------------------------------------------*/

/*! Create an EAP1X authenticator session.
This function creates an EAP1X authenticator session based on the specified
parameters, returning the resultant session handle through the $session$
parameter. Before calling this function, your application must first call
EAP1X_authInit.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap1x_auth.h

\param appHdl       Pointer to application cookie.
\param session      On return, pointer to EAP1X session handle.
\param cfg          Pointer to desired EAP1X session parameters.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_authInit

*/
extern MSTATUS
EAP1X_authSessionCreate (ubyte* appHdl, ubyte** session, eap1xAuthSessionCfg *cfg)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession = MALLOC(sizeof(eap1xSessionCb_t));

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

    DIGI_MEMCPY((ubyte*)&eapSession->cfg, (ubyte*)cfg, sizeof(eap1xAuthSessionCfg));
    /* Start the Port Timer (1 sec) */
    TIMER_queueTimer(eapSession,gEap1XGlobalState.portTimer,
                     eapSession->cfg.portTimeout,0);

    eapSession->appHdl = appHdl;
    eapSession->portControl = cfg->portControl;
    eapSession->initialize  = TRUE;

    *session = (ubyte *)eapSession;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "Session Create App Handle:");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)eapSession->appHdl);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, ": Port Number :");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)eapSession->cfg.portNumber);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, " ");

exit:
    if (OK > status)
    {
        if (eapSession)
            FREE(eapSession);
    }
    return status;
}

/*------------------------------------------------------------------*/

/*! Delete an EAP1X authenticator session.
This function deletes an EAP1X authenticator session.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap1x_auth.h

\param appHdl       Pointer to application cookie.
\param session      Pointer to EAP1X session handle returned from EAP1X_authSessionCreate.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_authInit

*/
extern MSTATUS
EAP1X_authSessionDelete (ubyte* appHdl, ubyte* session )
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession  = (eap1xSessionCb_t*)session;

    if (NULL == eapSession)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "Session Delete App Handle:");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)eapSession->appHdl);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, ": Port Number :");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)eapSession->cfg.portNumber);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, " ");

    TIMER_unTimer(eapSession,gEap1XGlobalState.portTimer);
    TIMER_unTimer(eapSession,gEap1XGlobalState.heldTimer);
    TIMER_unTimer(eapSession,gEap1XGlobalState.reAuthTimer);
    FREE(eapSession);

exit:
    return status;
}

/*------------------------------------------------------------------*/

/*! Start the EAP1X state machine and initialize the EAP1X stack and timers.
This function starts the EAP1X state machine and initializes the EAP1X stack
and timers. This function needs to be called before calling EAP1X_authSessionCreate.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap1x_auth.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_authSessionCreate

*/
extern MSTATUS
EAP1X_authInit()
{
    MSTATUS status;

    /* Initialize Timer Queue */
    status = TIMER_initTimer();
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP1X_init: TIMER_initTimer() failed, status = ", status);
        goto exit;
    }

    status = TIMER_createTimer(EAP1X_authTimeoutCallback,&gEap1XGlobalState.portTimer);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP1X_init: TIMER_createTimer() failed, status = ", status);
        goto exit;
    }

    status = TIMER_createTimer(EAP1X_authTimeoutCallback,&gEap1XGlobalState.reAuthTimer);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP1X_init: TIMER_createTimer() failed, status = ", status);
        goto exit;
    }

    status = TIMER_createTimer(EAP1X_authTimeoutCallback,&gEap1XGlobalState.heldTimer);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP1X_init: TIMER_createTimer() failed, status = ", status);
        goto exit;
    }

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, "EAP1X_init: Initialized EAP Instance");
    DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"Initialized EAP1X ");

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP1X_init: Failed Status ", (sbyte4)status);
    }

    return status;

} /* EAP1X_init */


/*------------------------------------------------------------------*/
/*! Destroy EAP1X timers.
This function destroys EAP1X timers that were created by EAP1X_authInit. You
should call this function after calling EAP1X_authSessionDelete.

\since 6.0
\version 6.0 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap1x_auth.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_authSessionDelete

*/

extern MSTATUS
EAP1X_authDeInit(void)
{
    MSTATUS status;

    status = TIMER_destroyTimer(gEap1XGlobalState.portTimer);
    status = TIMER_destroyTimer(gEap1XGlobalState.reAuthTimer);
    status = TIMER_destroyTimer(gEap1XGlobalState.heldTimer);

    return status;
}

/*------------------------------------------------------------------*/

static void
EAP1X_authTimeoutCallback(void *session, ubyte *type)
{

    if (gEap1XGlobalState.portTimer == type)
        EAP1X_authPortTimeout(session);
    else if (gEap1XGlobalState.reAuthTimer == type)
        EAP1X_authReAuthTimeout(session);
    else if (gEap1XGlobalState.heldTimer == type)
        EAP1X_authHeldTimeout(session);

    return;
}

/*------------------------------------------------------------------*/

/*! Get an EAP1X session's current statistics.
This function retrieves an EAP1X session's current statistics.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap1x_auth.h

\param session  Pointer to EAP1X session handle returned from EAP1X_authSessionCreate.
\param stats    On return, pointer to the session's current statistics values.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_authSessionCreate

*/
extern MSTATUS
EAP1X_authGetSesssionStats (ubyte* session,eap1xSessionStats* stats)
{
    MSTATUS status = OK;
    eap1xSessionCb_t *eapSession = (eap1xSessionCb_t *) session;

    if ((NULL == eapSession) || (NULL == stats))
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    DIGI_MEMCPY((ubyte *)stats,(ubyte *)&eapSession->stats,sizeof(eap1xSessionStats));

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Send the received EAP1X packets to the EAP1X layer.
This function sends the received EAP1X packets to the EAP1X layer. First the
packet header's type is evaluated. Then based on the type, this function either
updates the EAP1X session's state parameters (which in turn control the EAP
state machine) or invokes the session's $funcPtrEAPOLCallback$ function.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap1x_auth.h

\param session  Pointer to EAP1X session handle returned from EAP1X_authSessionCreate.
\param pPkt     Pointer to received EAP1X packet.
\param pktLen   Number of bytes in the received packet ($pPkt$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP1X_authSendEAP

*/
extern MSTATUS
EAP1X_authReceivePkt (ubyte* session,ubyte* pPkt,ubyte4 pktLen)
{

    MSTATUS status = OK;
    ubyte4  stateInfo = 0;
    eap1xSessionCb_t *eapSession = (eap1xSessionCb_t *) session;
    eap1xHdr_t *eap1xHdr = (eap1xHdr_t *)pPkt;
    ubyte *pktBody = pPkt + sizeof (eap1xHdr_t);

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if ((!pPkt) || (pktLen < sizeof(eap1xHdr_t)))
    {
        status = ERR_EAP_INVALID_PKT;
        goto exit;
    }
    /* Check Length of Pkt */
    if (DIGI_NTOHS((const ubyte *)(pPkt+EAP1X_HDR_LENGTH_OFFSET)) >  pktLen)
    {
        status = ERR_EAP_INVALID_PKT;
        goto exit;
    }


    switch (eap1xHdr->pktType)
    {
        case EAP1X_EAPOL_START_TYPE:
        {
            stateInfo = EAP1X_EAPOL_START;
            status = EAP1X_authUpdateSetState(session,stateInfo);
            break;
        }
        case EAP1X_EAPOL_LOGOFF_TYPE:
        {
            stateInfo = EAP1X_EAPOL_LOGOFF;
            status = EAP1X_authUpdateSetState(session,stateInfo);
            break;
        }
        case EAP1X_EAPOL_EAP_TYPE:
        {

            eapSession->cfg.funcPtrEAPOLCallback(eapSession->appHdl, pktBody, DIGI_NTOHS(pPkt+EAP1X_HDR_LENGTH_OFFSET), eap1xHdr->pktType);
            break;
        }
        default:
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
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap1x_auth.h

\note To prevent a memory leak, be sure to free the resulting packet ($ppPkt$) after
your application is done with it.

\param session          Pointer to EAP1X session handle returned from EAP1X_authSessionCreate.
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

\sa EAP1X_authReceivePkt

*/
extern  MSTATUS
EAP1X_authSendEAP(ubyte *session,
                          eapHdr_t *eap_hdr,
                          ubyte *eap_data,
                          ubyte4 eap_data_len,
                          ubyte4 headRoom,
                          ubyte **ppPkt,ubyte2 *pPktLen)
{

    MSTATUS    status = OK;
    ubyte      *pPkt = NULL;
    eap1xHdr_t *eap1xHdr;
    ubyte4     stateInfo;
    ubyte      *pktBody;
    eap1xSessionCb_t *eapSession = (eap1xSessionCb_t *) session;

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


    *ppPkt = pPkt;
    eap1xHdr = (eap1xHdr_t *)((ubyte *)pPkt + headRoom);

    /*Set EAP1X_ETH_TYPE);*/
    DIGI_HTONS(pPkt+headRoom, EAP1X_ETHER_PROTO_EAPOL);
    eap1xHdr->version = EAP1X_EAPOL_VERSION;
    eap1xHdr->pktType = EAP1X_EAPOL_EAP_TYPE;
    /*Set Packet length;*/
    DIGI_HTONS(pPkt + headRoom + EAP1X_HDR_LENGTH_OFFSET, sizeof(eapHdr_t)+eap_data_len);
    pktBody = (ubyte *)eap1xHdr + sizeof (eap1xHdr_t);
    DIGI_MEMCPY(pktBody,(ubyte*)eap_hdr,sizeof(eapHdr_t));
    DIGI_MEMCPY(pktBody+sizeof(eapHdr_t),eap_data,eap_data_len);

    *pPktLen = sizeof(eap1xHdr_t) + headRoom +sizeof(eapHdr_t)+eap_data_len;

    stateInfo = EAP1X_EAP_REQUEST;
    EAP1X_authUpdateSetState(session,stateInfo);
    eapSession->eapReq = FALSE;

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
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap1x_auth.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP1X_authCheckTimers()
{
    /*DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, "EAP1X_authCheckTimers: got here");*/

    if ( gEap1XGlobalState.portTimer)
        TIMER_checkTimer( gEap1XGlobalState.portTimer);
    if ( gEap1XGlobalState.reAuthTimer)
        TIMER_checkTimer( gEap1XGlobalState.reAuthTimer);
    if ( gEap1XGlobalState.heldTimer)
        TIMER_checkTimer( gEap1XGlobalState.heldTimer);

    return 0;
}

#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) */

