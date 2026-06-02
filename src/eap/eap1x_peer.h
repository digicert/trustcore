/**
 * @file  eap1x_peer.h
 * @brief 802.1X peer API
 *
 * @details    802.1X client interface
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *
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

#ifndef __EAP1X_PEER_HEADER__
#define __EAP1X_PEER_HEADER__
#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_EAP_PEER__)

#define EAP1X_DEFAULT_START_TIME    (30)
#define EAP1X_DEFAULT_HELD_TIME     (60)
#define EAP1X_DEFAULT_MAX_START     (3)

/** @private @internal */
typedef struct eap1xPeerSessionCfg_s
{
    eap1xPortMode    portControl;
    ubyte4           startTimeout;
    ubyte4           heldTimeout;
    ubyte4           maxStart;
    ubyte4           portNumber;
    ubyte2           etherProto;
    MSTATUS          (*funcPtrEAPIndication)(ubyte *appHdl,ubyte *eapSession,eap1XIndication indType);
    MSTATUS          (*funcPtrEAPOLCallback)(ubyte *appHdl,ubyte *pEapPkt,ubyte2 pktLen,ubyte4 pktType);

} eap1xPeerSessionCfg;


/** @private @internal */
typedef struct eap1xPeerStats_s
{
    ubyte4 suppEntersAuthenticating;
    ubyte4 suppEntersConnecting;
    ubyte4 suppSuccessesWhileAuthenticating;
    ubyte4 suppTimeoutsWhileAuthenticating;
    ubyte4 suppFailWhileAuthenticating;
    ubyte4 suppEapRecvWhileAuthenticated;
    ubyte4 suppEapolFramesRx;
    ubyte4 suppEapolFramesTx;
    ubyte4 suppEapolStartFramesTx;
    ubyte4 suppEapolLogoffFramesTx;
    ubyte4 suppEapolInvalidFramesRx;
    ubyte4 suppEapolInvalidLengthFramesRx;
    ubyte4 suppEapolLastFrameVersion;

} eap1xPeerStats;

/** @private @internal */
typedef enum eap1XPeerState_e
{
    EAP1X_PEER_STATE_NONE,
    EAP1X_PEER_STATE_LOGOFF,
    EAP1X_PEER_STATE_DISCONNECTED,
    EAP1X_PEER_STATE_RESTART,
    EAP1X_PEER_STATE_CONNECTING,
    EAP1X_PEER_STATE_AUTHENTICATING,
    EAP1X_PEER_STATE_AUTHENTICATED,
    EAP1X_PEER_STATE_HELD,
    EAP1X_PEER_STATE_FORCE_AUTH,
    EAP1X_PEER_STATE_FORCE_UNAUTH,
} eap1XPeerState_t;

/**
@brief      Get an EAP1X session's current statistics.
@details    This function retrieves an EAP1X session's current statistics.

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@param session  Pointer to EAP1X session handle returned from
                EAP1X_peerSessionCreate.
@param stats    On return, pointer to the session's current statistics values.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_peerSessionCreate

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS EAP1X_peerGetSesssionStats (ubyte* session,eap1xPeerStats* stats);

/**
@brief      Get an EAP1X session's current state.
@details    This function retrieves an EAP1X session's current state.

@ingroup    eap1x_functions

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@param session  Pointer to EAP1X session handle returned from
                EAP1X_peerSessionCreate.
@param state    On return, pointer to the session's current state values.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_peerSessionCreate

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS EAP1X_peerGetSesssionState (ubyte* session,eap1XPeerState_t* state);

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
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@note       The state parameters are defined in IEEE Standard 802.1X-2004,
            Section 8.2.11 (Peer State machine).

@param session      EAP session handle returned from EAP1X_peerSessionCreate.
@param stateInfo    Bitmask combination (created by \c OR&mdash;ing definitions
                    together) of desired state parameters to set. Valid state
                    parameter definitions are:\n
\n
+ \c EAP1X_EAPOL_INITIALIZE
+ \c EAP1X_EAPOL_USERLOGOFF
+ \c EAP1X_EAPOL_LOGOFF
+ \c EAP1X_EAP_EAPOL
+ \c EAP1X_EAP_RESTART
+ \c EAP1X_EAP_PEER_SUCCESS
+ \c EAP1X_EAP_PEER_FAIL
+ \c EAP1X_EAP_EAP_SUCCESS
+ \c EAP1X_EAP_EAP_FAIL
+ \c EAP1X_EAP_PEER_TIMEOUT
+ \c EAP1X_EAP_PORT_VALID
+ \c EAP1X_EAP_PORT_ENABLED

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_peerUpdateUnsetState

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS EAP1X_peerUpdateSetState (ubyte* session,ubyte4 stateInfo);

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
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@note       The state parameters are defined in IEEE Standard 802.1X-2004,
            Section 8.2.11 (Peer State machine).

@param session      EAP session handle returned from EAP1X_peerSessionCreate.
@param stateInfo    Bitmask combination (created by \c OR&mdash;ing definitions
                    together) of desired state parameters to clear (unset).
                    Valid state parameter definitions are:\n
\n
+ \c EAP1X_EAPOL_INITIALIZE
+ \c EAP1X_EAPOL_USERLOGOFF
+ \c EAP1X_EAPOL_LOGOFF
+ \c EAP1X_EAP_EAPOL
+ \c EAP1X_EAP_RESTART
+ \c EAP1X_EAP_PEER_SUCCESS
+ \c EAP1X_EAP_PEER_FAIL
+ \c EAP1X_EAP_EAP_SUCCESS
+ \c EAP1X_EAP_EAP_FAIL
+ \c EAP1X_EAP_PEER_TIMEOUT
+ \c EAP1X_EAP_PORT_VALID
+ \c EAP1X_EAP_PORT_ENABLED

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_peerUpdateSetState

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS EAP1X_peerUpdateUnsetState (ubyte* session,ubyte4 stateInfo);

/**
@brief      Create an EAP1X peer session.
@details    This function creates an EAP1X peer session based on the specified
            parameters, returning the resultant session handle through the \p
            session parameter. Before calling this function, your application
            must first call EAP1X_peerInit.

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@param appHdl       Pointer to application cookie.
@param session      On return, pointer to EAP1X session handle.
@param cfg          Pointer to desired EAP1X session parameters.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_peerInit

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS EAP1X_peerSessionCreate (ubyte* appHdl, ubyte** session, eap1xPeerSessionCfg *cfg);

/**
@brief      Delete an EAP1X peer session.
@details    This function deletes an EAP1X peer session. After you delete the
            session, you should call EAP1X_peerdeinit to destroy the session's
            timers.

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@param appHdl       Pointer to application cookie.
@param session      Pointer to EAP1X session handle returned from
                    EAP1X_peerSessionCreate.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_peerInit
@sa EAP1X_peerdeinit

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS EAP1X_peerSessionDelete (ubyte* appHdl, ubyte* session );

/**
@brief      Start the EAP1X state machine and initialize the EAP1X stack and
            timers.
@details    This function starts the EAP1X state machine and initializes the
            EAP1X stack and timers. This function needs to be called before
            calling EAP1X_peerSessionCreate.

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_peerSessionCreate

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS EAP1X_peerInit();

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
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@param session      EAP session handle returned from EAP1X_peerSessionCreate.
@param portMode     Any of the \c eap1xPortMode enumerated values (defined in
                    @ref eap1x.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_peerUpdateSetState

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS EAP1X_peerUpdatePortControl (ubyte* session,eap1xPortMode portMode);

/**
@brief      Build an EAPOL-Start message.
@details    This function builds an EAPOL-Start message, returning it through
            the \p ppPkt parameter. Your application can then send the message
            using the appropriate transport layer functions

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@note       To prevent a memory leak, be sure to free the resulting packet (\p
            ppPkt) after your application is done with it.

@param session      EAP session handle returned from EAP1X_peerSessionCreate.
@param ppPkt        On return, pointer to resultant EAPOL-Start message packet.
@param pPktLen      On return, pointer to number of bytes (including the \p
                    headRoom) in resultant EAPOL-Start message packet (\p ppPkt).
@param headRoom     Number of bytes available to fill in the lower layer header.
                    (These bytes will be included in the returned \p pPktLen
                    value.)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_sendEAPOLLogoff

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS EAP1X_sendEAPOLStart (ubyte* session,ubyte** ppPkt, ubyte4 *pPktLen,ubyte4 headRoom);

/**
@brief      Build an EAPOL-Logoff message.
@details    This function builds an EAPOL-Logoff message, returning it through
            the \p ppPkt parameter. Your application can then send the message
            using the appropriate transport layer functions

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@note       To prevent a memory leak, be sure to free the resulting packet (\p
            ppPkt) after your application is done with it.

@param session      EAP session handle returned from EAP1X_peerSessionCreate.
@param ppPkt        On return, pointer to resultant EAPOL-Logoff message packet.
@param pPktLen      On return, pointer to number of bytes (including the \p
                    headRoom) in resultant EAPOL-Logoff message packet (\p ppPkt).
@param headRoom     Number of bytes available to fill in the lower layer header.
                    (These bytes will be included in the returned \p pPktLen
                    value.)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_sendEAPOLStart

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS EAP1X_sendEAPOLLogoff (ubyte* session,ubyte** ppPkt, ubyte4 *pPktLen,ubyte4 headRoom);

/**
@brief      Send the received EAP1X packets to the EAP1X layer.
@details    This function sends the received EAP1X packets to the EAP1X layer.
            First the packet header's type is evaluated. For EAP1X_EAP_EAPOL
            messages, this function invokes the session's \c
            funcPtrEAPOLCallback function.

@ingroup    eap1x_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@param session  Pointer to EAP1X session handle returned from
                EAP1X_peerSessionCreate.
@param pPkt     Pointer to received EAP1X packet.
@param pktLen   Number of bytes in the received packet (\p pPkt).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_peerSendEAP
@sa EAP1X_sendEAPOLStart
@sa EAP1X_sendEAPOLLogoff

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS EAP1X_peerReceivePkt (ubyte* session,ubyte* pPkt,ubyte4 pktLen);

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
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@note       To prevent a memory leak, be sure to free the resulting packet (\p
            ppPkt) after your application is done with it.

@param session          Pointer to EAP1X session handle returned from
                        EAP1X_peerSessionCreate.
@param eap_hdr          Pointer to EAP packet header.
@param eap_data         Pointer to EAP packet payload.
@param eap_data_len     Number of bytes in EAP packet payload (\p eap_data).
@param headRoom         Number of bytes available to fill in the lower layer
                        header. (These bytes will be included in the returned \p
                        pPktLen value.)
@param ppPkt            On return, pointer to resulting encapsulated packet.
@param pPktLen          On return, pointer to number of bytes (including the \p
                        headRoom) in the resulting encapsulated packet (\p ppPkt).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_peerReceivePkt
@sa EAP1X_sendEAPOLStart
@sa EAP1X_sendEAPOLLogoff

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS
EAP1X_peerSendEAP(ubyte *session, eapHdr_t *eap_hdr, ubyte *eap_data,
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
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS EAP1X_peerCheckTimers();

/**
@brief      Destroy EAP1X timers.
@details    This function destroys EAP1X timers that were created by
            EAP1X_peerInit. You should call this function after calling
            EAP1X_peerSessionDelete.

@ingroup    eap1x_functions

@since 3.1
@version 3.1 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap1x_peer.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP1X_peerSessionDelete

@funcdoc    eap1x_peer.h
*/
MOC_EXTERN MSTATUS EAP1X_peerdeinit();

#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__)  */

#ifdef __cplusplus
}
#endif
#endif
