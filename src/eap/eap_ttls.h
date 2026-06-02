/**
 * @file  eap_ttls.h
 * @brief EAP-TTLS method API
 *
 * @details    EAP-TTLS interface
 * @since      1.41
 * @version    2.45 and later
 *
 * @flags      Compilation flags required:
 *     To build products using this header file's functions, the following flag must be
 *     defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_TTLS__
 *     Additionally, at least one of the following flags must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     Whether the following flag is defined determines which function declarations are
 *     enabled:
 *     +   \c \__ENABLE_DIGICERT_INNER_APP__
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

#ifndef __EAP_TTLS_H__
#define __EAP_TTLS_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
#if (defined(__ENABLE_DIGICERT_EAP_TTLS__))

/** @private @internal */
typedef enum eapTTLSMethodType_e
{
    EAP_METHOD_TYPE_PAP,
    EAP_METHOD_TYPE_CHAP,
    EAP_METHOD_TYPE_MSCHAP,
    EAP_METHOD_TYPE_MSCHAPV2,
    EAP_METHOD_TYPE_EAP

} eapTTLSMethodType;


/*------------------------------------------------------------------*/

/**
@brief      Configuration settings and callback function pointers for EAP-TTLS
            sessions.
@details    This structure is used for EAP-TTLS session configuration. Each
            included callback function should be customized for your application
            and then registered by assigning it to the appropriate structure
            function pointer(s).

@since 1.41
@version 2.45 and later

@flags
To use this structure, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TTLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__
+ \c \__ENABLE_DIGICERT_EAP_PEER__

*/
typedef struct eap_ttls_params
{
/**
@brief      Send a plain text inner method payload to the application (for
            further encryption and transmittal).
@details    This callback function sends a plain text inner method payload to
            the application (which will then further encrypt the message and
            send out the payload).

If the \p encrypted parameter value is \c TRUE, which occurs when the inner
method is sending an ACK or handling fragmented packets, the application does
not need to encrypt the payload.

However, if the \p encrypted parameter value is \c FALSE, indicating that the
payload is not yet encrypted, this callback should %encrypt the payload (TTLS
Attribute Value Pairs, such as EAP or UserName/Password) using the lower layer
TLS connection and then send the packet using the outer EAP \c %ulTransmit.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
There are no flag dependencies to enable this callback.

@param appSessionCB     Application-specific session identifier.
@param eapPkt           Pointer to plain text inner method payload to send.
@param eapPktLen        Number of bytes in payload to send (\p eapPkt).
@param encrypted        \c TRUE if the payload to send is encrypted; \c FALSE
                        otherwise.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap_ttls.h
*/
    MSTATUS (*ulTransmit)(ubyte * appSessionCB,ubyte * eapPkt,ubyte4 eapPktLen,
            intBoolean encrypted);

/**
@brief      Process received EAP messages.
@details    This callback function is provided to process received EAP messages.
            It is called by the inner EAP message processing if the inner TTLS
            method is EAP in order to provide application-specific data. Once
            the application is done processing the inner EAP method, the
            application should call EAP_TTLSulPeerTransmit to send the payload
            using the inner EAP session.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
There are no flag dependencies to enable this callback.

@param app_session_handle   Cookie given by the application to identify the
                            session.
@param type                 Any of the \c eapMethodType enumerated values (see
                            @ref eap_proto.h).
@param code                 Any of the \c eapCode enumerated values (see @ref
                            eap_proto.h).
@param id                   EAP packet id.
@param eap_data             Pointer to EAP payload.
@param eap_data_len         Length of EAP payload.
@param opaque_data          Pointer to any opaque data&mdash;extra data that's
                            passed from the lower layer to the upper (method)
                            layer through the EAP stack.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap_ttls.h
*/
    MSTATUS (*ul2ndStageReceive)(ubyte * app_session_handle, eapMethodType type,
                                 eapCode code, ubyte id, ubyte * eap_data,
                                 ubyte4 eap_data_len, ubyte * opaque_data);

/**
@brief      Send a fully formed RADIUS packet for authentication.
@details    This callback function is used by the EAP TTLS authenticator to send
            a fully formed RADIUS packet for authentication.

When the RADIUS server returns the response, your application should call
EAP_TTLSProcessRadiusAuthResponse to process the response.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
There are no flag dependencies to enable this callback.

@param appSessionCB     Application-specific session identifier.
@param eapTTLSCb        EAP-TTLS session handle returned from
                        EAP_TTLSinitSession.
@param pkt              Pointer to packet to send for authentication.
@param pktLen           Number of bytes in packet to send (\p pkt).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap_ttls.h
*/
    MSTATUS (*ulAuthTransmit)(ubyte *appSessionCB,
                                ubyte *eapTTLSCb, ubyte *pkt, ubyte4 pktLen);

/**
@brief      Send the inner method authentication status.
@details    This callback function is used to send the inner (second stage)
            method authenticatation status to the application, which in turn
            sets the outer (first stage) EAP session status.

For example, if the inner method receives an \c EAP_AUTH_SUCCESS or
\c EAP_AUTH_FAILURE (which are \c eapAuthStatus enumerations defined in @ref
eap_proto.h), the application must be informed of the authentication status.
Once informed, the application can set the state machine (\c methodState) and
decision (\c decision) values.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
There are no flag dependencies to enable this callback.

@param appSessionCB     Application-specific session identifier.
@param authStatus       Any of the eapAuthStatus enumerated values (defined in
                        @ref eap_proto.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap_ttls.h
*/
    MSTATUS (*ulAuthResultTransmit)(ubyte * appSessionCB, eapAuthStatus authStatus);

/**
@brief      Inner method user name passed by the peer for PAP, CHAP, MSCHAP, and
            MSCHAPv2.
@details    Inner method user name passed by the peer for PAP, CHAP, MSCHAP, and
            MSCHAPv2.
*/
    ubyte               UserName[EAP_MAX_USER_LEN];
/**
@brief      Number of bytes in the inner method user name (\p UserName).
@details    Number of bytes in the inner method user name (\p UserName).
*/
    ubyte2              UserNameLen;

/**
@brief      Inner method password passed by the peer for PAP, CHAP, MSCHAP, and
            MSCHAPv2.
@details    Inner method password passed by the peer for PAP, CHAP, MSCHAP, and
            MSCHAPv2.
*/
    ubyte               Password[EAP_MAX_PASS_LEN];
/**
@brief      Number of bytes in the inner method password (\p Password).
@details    Number of bytes in the inner method password (\p Password).
*/
    ubyte2              PasswordLen;

/**
@brief      Shared secret required for RADIUS %client-server authentication.
@details    Shared secret required for RADIUS %client-server authentication. It
            must be the same secret specified when the RADIUS server was added
            (see RADIUS_addServer).
*/
    ubyte               radiusSecret[EAP_MAX_PASS_LEN];
/**
@brief      Number of bytes in the RADIUS shared secret (\p radiusSecret).
@details    Number of bytes in the RADIUS shared secret (\p radiusSecret).

*/
    ubyte2              radiusSecretLen;

/**
@brief      Phase 1 instance ID.
@details    Phase 1 instance ID; for multiple instance (VLAN/VR) support.
*/
    ubyte4              instanceId;             /* Phase 1 Instance Id */

/**
@brief      Type of session: \c EAP_SESSION_TYPE_PEER or \c
            EAP_SESSION_TYPE_AUTHENTICATOR.
@details    Type of session. The following \c eapSessionType enumerated values
            (defined in @ref eap_proto.h) are supported:\n
- \c EAP_SESSION_TYPE_PEER
- \c EAP_SESSION_TYPE_AUTHENTICATOR

(No other \c eapSessionType enumerated values are valid.)
*/
    eapSessionType      sessionType;            /* (PEER/AUTH) */

/**
@brief      Method type used by a peer.
@details    Method type used by a peer: any of the \c eapTTLSMethodType
            enumerated values (defined in @ref eap_ttls.h).
*/
    eapTTLSMethodType   methodType;             /* (PAP/CHAP/MSCHAP/MSCHAPv2/EAP) */

/**
@brief      TLS connection's session ID.
@details    TLS connection's session ID: the 4-byte SSL connection ID returned
            from SSL session creation (not the session ID generated after TLS
            negotiation).
*/
    sbyte4              connectionInstance;     /* TLS COnnection INstance */

/**
@brief      EAP_TLS connection control block.
@details    EAP_TLS connection control block&mdash;the connection handle to an
            established outer (second stage) TLS connection. This handle is used
            in function calls to encrypt and decrpyt the payload and to generate
            session keys.
*/
    ubyte*              tls_con;                /* TLS Connection INstance */

/**
@brief      RADIUS server ID; used by the authenticator to send a RADIUS packet
            to the RADIUS server.
@details    RADIUS server ID; used by the authenticator to send a RADIUS packet
            to the RADIUS server.
*/
    ubyte4              authServerId;           /* Radius Server Id */

/**
@brief      NAS (network authentication server) IP address.
@details    NAS (network authentication server) IP address, in network byte
            order&mdash;bytes ordered from left to right.
*/
    MOC_IP_ADDRESS      myaddr;                 /* For Radius Request */

/**
@brief      TTLS %version: 0 or 1.
@details    TTLS %version: 0 or 1. Version 0 is more widely deployed. Version 1
            uses INNER_APP encapsulation.
*/
    ubyte               version;                /* ttls Version 0,1 */
/**
@brief      (Do not use) Padding to align structure to 4-byte boundary.
@details    (Do not use) Pads the strucutre for alignment with a 4-byte boundary.
*/
    ubyte               pad2[3];

} EAP_TTLS_params;


/*------------------------------------------------------------------*/

/**
@brief      Create and initialize a second stage TTLS session as a peer or
            passthrough authenticator.
@details    This function (typically called by your application) creates and
            initializes the second stage TTLS session as a peer or passthrough
            authenticator. On success, the function returns the TTLS session
            handle to the application.

@ingroup    eap_ttls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TTLS__

Additionally, for each of the following flag pairs at least one of the pair must
be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)

@inc_file   eap_ttls.h

@param appSessionCB     Application-specific session identifier.
@param eapTTLSSession   On return, pointer to EAP-TTLS session handle.
@param eapTTLSparams    Pointer to structure containing desired EAP-TTLS session
                        configuration settings and callback function pointers.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TTLSSendData
@sa EAP_TTLSreceiveLLPacket
@sa EAP_TTLSdeleteSession

@funcdoc    eap_ttls.h
*/
MOC_EXTERN MSTATUS EAP_TTLSinitSession(ubyte *appSessionCB,ubyte **eapTTLSSession, EAP_TTLS_params *eapTTLSparams);

/**
@brief      Delete a second (upper) stage EAP TTLS session.
@details    This function deletes a second (upper) stage TTLS session.

@ingroup    eap_ttls_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TTLS__

Additionally, for each of the following flag pairs at least one of the pair must
be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)

@inc_file   eap_ttls.h

@param eapTTLSSession   EAP-TTLS session handle returned from
                        EAP_TTLSinitSession.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TTLSSendData
@sa EAP_TTLSreceiveLLPacket
@sa EAP_TTLSinitSession

@funcdoc    eap_ttls.h
*/
MOC_EXTERN MSTATUS EAP_TTLSdeleteSession(void *eapTTLSSession);

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__))
/**
@brief      Process a received RADIUS packet and respond appropriately.
@details    This function (called from the TTLS passthrough server or
            authenticator) processes a RADIUS packet received from a RADIUS
            server. On receiving Access Accept or Reject, an EAP \c Success or
            \c Failure response is sent to the peer. On receiving other RADIUS
            attributes, the RADIUS packet is decapsulated and a corresponding
            EAP Request is sent to the peer.

@ingroup    eap_ttls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TTLS__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@inc_file   eap_ttls.h

@param eapCb        EAP-TTLS session handle returned from EAP_TTLSinitSession.
@param pRadiusResp  Pointer to the received RADIUS packet.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TTLSSendData
@sa EAP_TTLSreceiveLLPacket
@sa EAP_TTLSdeleteSession

@funcdoc    eap_ttls.h
*/
MOC_EXTERN MSTATUS EAP_TTLSProcessRadiusAuthResponse(void *eapCb,RADIUS_RqstRecord *pRadiusResp);
#endif

/**
@brief      Build the second stage payload.
@details    This function (typically called by the TTLS application) builds the
            second stage payload, including managing any required fragmentation,
            and then passes the result back to the calling function (which will
            then typically call EAP_ulTransmit to send the packet).

@ingroup    eap_ttls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TTLS__

Additionally, for each of the following flag pairs at least one of the pair must
be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)

@inc_file   eap_ttls.h

@param eapTTLSCb    EAP-TTLS session handle returned from EAP_TTLSinitSession.
@param pkt          Pointer to input data (payload).
@param pktLen       Number of bytes of input data (payload).
@param eapResponse  On return, pointer to resultant EAP output packet.
@param eapRespLen   On return, pointer to number of bytes in EAP output packet
                    (\p eapResponse).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TTLSSendData
@sa EAP_TTLSreceiveLLPacket

@funcdoc    eap_ttls.h
*/
MOC_EXTERN MSTATUS EAP_TTLSFormSendPacket(void *eapTTLSCb, ubyte *pkt, ubyte4 pktLen, ubyte **eapResponse, ubyte4 *eapRespLen);

/**
@brief      Process second stage packets.
@details    This function (typically called from the TTLS application) processes
            second stage packets received after the first stage TLS connection
            is established. Second stage packet processing includes any required
            reassembly.

@ingroup    eap_ttls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TTLS__

Additionally, for each of the following flag pairs at least one of the pair must
be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)

@inc_file   eap_ttls.h

@param eapTTLSCb    EAP-TTLS session handle returned from EAP_TTLSinitSession.
@param pkt          Pointer to input data (packet).
@param pktLen       Number of bytes of input data (\p pkt).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TTLSFormSendPacket
@sa EAP_TTLSSendData

@funcdoc    eap_ttls.h
*/
MOC_EXTERN MSTATUS EAP_TTLSreceiveLLPacket(void * eapTTLSCb,ubyte *pkt,ubyte4 pktLen);

/**
@brief      Get an EAP-TTLS session's session status.
@details    This function retrieves an EAP-TTLS session's session status.

@ingroup    eap_ttls_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TTLS__

Additionally, for each of the following flag pairs at least one of the pair must
be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)

@inc_file   eap_ttls.h

@param eapTTLSCb            EAP-TTLS session handle returned from
                            EAP_TTLSinitSession.
@param eapSessionStatus     On return, pointer to the session's current status:
                            one of the \c eap_ttls_eap_state enumerated values
                            (defined in @ref eap_ttls_pvt.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_ttls.h
*/
MOC_EXTERN MSTATUS EAP_TTLSgetSessionStatus(void * eapTTLSCb,ubyte *eapSessionStatus);

/**
@brief      Generate a session key.
@details    This function (typically called by your application) generates a
            session key for the specified TTLS session.

The first 64 bits of the returned key represent the MSK (master session key),
while the remaining bits represent the EMSK (extended master session key).

@ingroup    eap_ttls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TTLS__

Additionally, for each of the following flag pairs at least one of the pair must
be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)

@inc_file   eap_ttls.h

@param eapCb    EAP-TTLS session handle returned from EAP_TTLSinitSession.
@param key      On return, pointer to generated session key.
@param keyLen   Length (number of bytes) of key to generate.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TTLSSendData

@funcdoc    eap_ttls.h
*/
MOC_EXTERN MSTATUS EAP_TTLSgetKey(void *eapCb,ubyte *key,ubyte2 keyLen);

/**
@brief      Transmit (send) an EAP response to the authenticator.
@details    This function (called by the TTLS second stage peer processing)
            transmits (sends) responses from the peer to the authenticator
            through the second stage EAP stack.

@ingroup    eap_ttls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_TTLS__

@inc_file   eap_ttls.h

@param eapSessionHdl    EAP-PEAP session handle returned from
                        EAP_PEAPinitSession.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param methodType       \c eapMethodType enumerated value for the second phase
                        (refer to @ref eap_proto.h).
@param code             \c EAP_CODE_RESPONSE (an \c eapCode enumerated value,
                        defined in @ref eap_proto.h).
@param methodDecision   \c eapMethodDecision enumerated value (refer to @ref
                        eap_proto.h)
@param methodState      \c eapMethodState enumerated value (refer to @ref
                        eap_proto.h)
@param eap_data         Pointer to response to be transmitted.
@param eap_data_len     Number of bytes in response to be transmitted (\p
                        eap_data).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_ttls.h
*/
MOC_EXTERN MSTATUS EAP_TTLSulPeerTransmit(ubyte * eapSessionHdl, ubyte4 instanceId, eapMethodType  methodType, eapCode code, eapMethodDecision  methodDecision, eapMethodState methodState, ubyte * eap_data, ubyte4  eap_data_len);

#if (defined(__ENABLE_DIGICERT_INNER_APP__))
/**
@brief      Build a TLS \c Alert Message to be sent over EAP.
@details    This function builds a TLS \c Alert Message to be sent over EAP.

@ingroup    eap_ttls_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TTLS__
+ \c \__ENABLE_DIGICERT_INNER_APP__

Additionally, for each of the following flag pairs at least one of the pair must
be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)

@inc_file   eap_ttls.h

@note This funcitn is used during TTLS v1 negotiation.

@param eapSessionHdl    EAP-TTLS session handle returned from
                        EAP_TTLSinitSession.
@param alertClass       One of the following alert class definitions: \c
                        SSLALERTLEVEL_WARNING or \c SSLALERTLEVEL_FATAL.
@param alertId          SSL alert ID code (see @ref ssl_alert_codes).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_ttls.h
*/
MOC_EXTERN MSTATUS EAP_TTLSsendAlert(ubyte * eapSessionHdl,sbyte4 alertClass,sbyte4 alertId);

/**
@brief      Send data using the TLS inner application extension.
@details    This function encrypts and sends data using the TLS inner
            application extension.

@ingroup    eap_ttls_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TTLS__
+ \c \__ENABLE_DIGICERT_INNER_APP__

Additionally, for each of the following flag pairs at least one of the pair must
be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)

@inc_file   eap_ttls.h

@param ttls_connection  EAP-TTLS session handle returned from
                        EAP_TTLSinitSession.
@param data             Pointer to data to encrypt and send.
@param len              Number of bytes of data to encrypt and send (\p data).
@param innerApp         Inner application extension type; any of the \c
                        eap_ttls_inner_appState enumerated values (defined in
                        @ref eap_ttls_pvt.h).
@param eapRespData      On return, pointer to encrypted data.
@param eapRespLen       On return, pointer to number of bytes of encrypted data
                        (\p eapRespData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_ttls.h
*/
MOC_EXTERN MSTATUS EAP_TTLSSendData(ubyte *ttls_connection,
                ubyte *data, ubyte4 len,
                InnerAppType innerApp,ubyte **eapRespData, ubyte4 *eapRespLen);
#endif /*(defined(__ENABLE_DIGICERT_INNER_APP__)) */

#endif /* ((defined(__ENABLE_DIGICERT_EAP_TTLS__) */
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */

#ifdef __cplusplus
}
#endif

#endif /* __EAP_TTLS_H__  */
