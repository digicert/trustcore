/**
 * @file  eap1x_auth.h
 * @brief 802.1X authenticator API
 *
 * @details    802.1X server interface
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


/*------------------------------------------------------------------*/

#ifndef __EAP1X_AUTH_HEADER__
#define __EAP1X_AUTH_HEADER__

#ifdef __cplusplus
extern "C" {
#endif
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)


#define EAP1X_DEFAULT_PORT_TIME    (1)
#define EAP1X_DEFAULT_REAUTH_TIME  (3600)
#define EAP1X_DEFAULT_QUIET_TIME   (30)


/** @private @internal */
typedef struct eap1xAuthSessionCfg_s
{
    eap1xPortMode    portControl;
    ubyte4           portTimeout;
    ubyte4           reAuthMax;
    intBoolean       reAuthEnabled;
    ubyte4           reAuthTimeout;
    ubyte4           quietTime;
    ubyte4           portNumber;
    MSTATUS          (*funcPtrEAPIndication)(ubyte *appHdl,ubyte *eapSession,eap1XIndication indType);
    MSTATUS          (*funcPtrEAPOLCallback)(ubyte *appHdl,ubyte *pEapPkt,ubyte2 pktLen,ubyte4 pktType);

} eap1xAuthSessionCfg;


/** @private @internal */
typedef struct eap1xSessionStats_s
{
    ubyte4 authEntersConnecting;
    ubyte4 authEapLogoffsWhileConnecting;
    ubyte4 authEntersAuthenticating;
    ubyte4 authAuthSuccessesWhileAuthenticating;
    ubyte4 authAuthTimeoutsWhileAuthenticating;
    ubyte4 authAuthFailWhileAuthenticating;
    ubyte4 authAuthEapStartsWhileAuthenticating;
    ubyte4 authAuthEapLogoffsWhileAuthenticating;
    ubyte4 authAuthReauthsWhileAuthenticated;
    ubyte4 authAuthEapStartsWhileAuthenticated;
    ubyte4 authAuthEapLogoffsWhileAuthenticated;
} eap1xSessionStats;

/**
@brief      Set an EAP1X session's state parameters (which in turn control the
            EAP state machine).
@details    This function sets an EAP1X session's state parameters (which in
            turn control the EAP state machine).

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap1x_auth.h

@note       The state parameters are defined in IEEE Standard 802.1X-2004,
            Section 8.2.4 (Authenticator State machine).

@param session      EAP session handle returned from EAP1X_authSessionCreate.
@param stateInfo    Bitmask combination (created by \c OR&mdash;ing definitions
                    together) of desired state parameters to set. Valid state
                    parameter definitions are:\n
\n
+ \c EAP1X_EAPOL_INITIALIZE
+ \c EAP1X_EAPOL_START
+ \c EAP1X_EAPOL_LOGOFF
+ \c EAP1X_EAP_REQUEST
+ \c EAP1X_EAP_RESTART
+ \c EAP1X_EAP_AUTH_SUCCESS
+ \c EAP1X_EAP_AUTH_FAIL
+ \c EAP1X_EAP_EAP_SUCCESS
+ \c EAP1X_EAP_EAP_FAIL
+ \c EAP1X_EAP_AUTH_TIMEOUT
+ \c EAP1X_EAP_AUTH_ABORT
+ \c EAP1X_EAP_PORT_VALID
+ \c EAP1X_EAP_PORT_ENABLED

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_authUpdateUnsetState

@funcdoc    eap1x_auth.h
*/
MOC_EXTERN MSTATUS EAP1X_authUpdateSetState (ubyte* session,ubyte4 stateInfo);

/**
@brief      Clear (unset) an EAP1X session's state parameters (which in turn
            control the EAP state machine).
@details    This function clears (unsets) an EAP1X session's state parameters
            (which in turn control the EAP state machine).

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap1x_auth.h

@note       The state parameters are defined in IEEE Standard 802.1X-2004,
            Section 8.2.4 (Authenticator State machine).

@param session      EAP session handle returned from EAP1X_authSessionCreate.
@param stateInfo    Bitmask combination (created by \c OR&mdash;ing definitions
                    together) of desired state parameters to clear (unset).
                    Valid state parameter definitions are:\n
\n
+ \c EAP1X_EAPOL_INITIALIZE
+ \c EAP1X_EAPOL_START
+ \c EAP1X_EAPOL_LOGOFF
+ \c EAP1X_EAP_REQUEST
+ \c EAP1X_EAP_RESTART
+ \c EAP1X_EAP_AUTH_SUCCESS
+ \c EAP1X_EAP_AUTH_FAIL
+ \c EAP1X_EAP_EAP_SUCCESS
+ \c EAP1X_EAP_EAP_FAIL
+ \c EAP1X_EAP_AUTH_TIMEOUT
+ \c EAP1X_EAP_AUTH_ABORT
+ \c EAP1X_EAP_PORT_VALID
+ \c EAP1X_EAP_PORT_ENABLED

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_authUpdateSetState

@funcdoc    eap1x_auth.h
*/
MOC_EXTERN MSTATUS EAP1X_authUpdateUnsetState (ubyte* session,ubyte4 stateInfo);

/**
@brief      Create an EAP1X authenticator session.
@details    This function creates an EAP1X authenticator session based on the
            specified parameters, returning the resultant session handle through
            the \p session parameter. Before calling this function, your
            application must first call EAP1X_authInit.

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap1x_auth.h

@param appHdl       Pointer to application cookie.
@param session      On return, pointer to EAP1X session handle.
@param cfg          Pointer to desired EAP1X session parameters.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_authInit

@funcdoc    eap1x_auth.h
*/
MOC_EXTERN MSTATUS EAP1X_authSessionCreate (ubyte* appHdl, ubyte** session, eap1xAuthSessionCfg *cfg);

/**
@brief      Delete an EAP1X authenticator session.
@details    This function deletes an EAP1X authenticator session.

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap1x_auth.h

@param appHdl       Pointer to application cookie.
@param session      Pointer to EAP1X session handle returned from
                    EAP1X_authSessionCreate.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_authInit

@funcdoc    eap1x_auth.h
*/
MOC_EXTERN MSTATUS EAP1X_authSessionDelete (ubyte* appHdl, ubyte* session );

/**
@brief      Start the EAP1X state machine and initialize the EAP1X stack and
            timers.
@details    This function starts the EAP1X state machine and initializes the
            EAP1X stack and timers. This function needs to be called before
            calling EAP1X_authSessionCreate.

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap1x_auth.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_authSessionCreate

@funcdoc    eap1x_auth.h
*/
MOC_EXTERN MSTATUS EAP1X_authInit(void);

/**
@brief      Destroy EAP1X timers.
@details    This function destroys EAP1X timers that were created by
            EAP1X_authInit. You should call this function after calling
            EAP1X_authSessionDelete.

@ingroup    eap1x_functions

@since 6.0
@version 6.0 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap1x_auth.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_authSessionDelete

@funcdoc    eap1x_auth.h
*/
MOC_EXTERN MSTATUS EAP1X_authDeInit(void);

/**
@brief      Get an EAP1X session's current statistics.
@details    This function retrieves an EAP1X session's current statistics.

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap1x_auth.h

@param session  Pointer to EAP1X session handle returned from
                EAP1X_authSessionCreate.
@param stats    On return, pointer to the session's current statistics values.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_authSessionCreate

@funcdoc    eap1x_auth.h
*/
MOC_EXTERN MSTATUS EAP1X_authGetSesssionStats (ubyte* session,eap1xSessionStats* stats);

/**
@brief      Set (update) an EAP1X session's port control mode.
@details    This function sets (updates) an EAP1X session's port control mode.

For EAP-based authentication, the port control mode should be set to \c
EAP1X_PORT_MODE_AUTO. You can force the port into an authorized or unauthorized
state by setting the port control mode parameter to \c
EAP1X_PORT_MODE_FORCED_AUTHORIZED or \c EAP1X_PORT_MODE_FORCED_UNAUTHORIZED,
respectively.

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap1x_auth.h

@param session      EAP session handle returned from EAP1X_authSessionCreate.
@param portMode     Any of the \c eap1xPortMode enumerated values (defined in
                    @ref eap1x.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap1x_auth.h
*/
MOC_EXTERN MSTATUS EAP1X_authUpdatePortControl (ubyte* session,eap1xPortMode portMode);

/**
@brief      Send the received EAP1X packets to the EAP1X layer.
@details    This function sends the received EAP1X packets to the EAP1X layer.
            First the packet header's type is evaluated. Then based on the type,
            this function either updates the EAP1X session's state parameters
            (which in turn control the EAP state machine) or invokes the
            session's \c funcPtrEAPOLCallback function.

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap1x_auth.h

@param session  Pointer to EAP1X session handle returned from
                EAP1X_authSessionCreate.
@param pPkt     Pointer to received EAP1X packet.
@param pktLen   Number of bytes in the received packet (\p pPkt).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_authSendEAP

@funcdoc    eap1x_auth.h
*/
MOC_EXTERN MSTATUS EAP1X_authReceivePkt (ubyte* session,ubyte* pPkt,ubyte4 pktLen);

/**
@brief      Encapsulate an EAP packet with an EAP1X header.
@details    This function encapsulates an EAP packet with an EAP1X header. The
            calling application must provide necessary data headroom for any
            required prepended data, such as the source or destination MAC
            address in the EAP1X header.

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap1x_auth.h

@note       To prevent a memory leak, be sure to free the resulting packet (\p
            ppPkt) after your application is done with it.

@param session          Pointer to EAP1X session handle returned from
                        EAP1X_authSessionCreate.
@param eap_hdr          Pointer to EAP packet header.
@param eap_data         Pointer to EAP packet payload.
@param eap_data_len     Number of bytes in EAP packet payload (\p eap_data).
@param headRoom         Number of bytes available to fill in the lower layer
                        header. (These bytes will be included in the returned \p
                        pPktLen value.)
@param ppPkt            On return, pointer to resulting encapsulated packet.
@param pPktLen          On return, pointer to number of bytes (including the \p
                        headRoom) in the resulting encapsulated packet (\p
                        ppPkt).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_authReceivePkt

@funcdoc    eap1x_auth.h
*/
MOC_EXTERN MSTATUS
EAP1X_authSendEAP(ubyte *session, eapHdr_t *eap_hdr, ubyte *eap_data,
                          ubyte4 eap_data_len,
                          ubyte4 headRoom,
                          ubyte **ppPkt,ubyte2 *pPktLen);

/**
@brief      Call expired timers' callbacks.
@details    This function determines whether any timers have expired, and if so
            then calls each expired expired timer's callback function. Your
            application should call this function on every clock tick (every 300
            to 500 milliseconds) to provide time to the EAP1X stack.

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap1x_auth.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap1x_auth.h
*/
MOC_EXTERN MSTATUS EAP1X_authCheckTimers(void);

#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__)  */

#ifdef __cplusplus
}
#endif
#endif
