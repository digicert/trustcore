/**
 * @file  eap_peap.h
 * @brief EAP-PEAP method API
 *
 * @details    EAP-PEAP interface
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     To build products using this header file's functions, the following flag must be
 *     defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEAP__
 *     Additionally, at least one of the following flags must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
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

#ifndef __EAP_PEAP_H__
#define __EAP_PEAP_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
#if (defined(__ENABLE_DIGICERT_EAP_PEAP__))

/**
@brief      Configuration settings and callback function pointers for EAP-PEAP
            sessions.
@details    This structure is used for EAP-PEAP session configuration. Each
            included callback function should be customized for your application
            and then registered by assigning it to the appropriate structure
            function pointer(s).

@since 1.41
@version 1.41 and later

@flags
To use this structure, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__
+ \c \__ENABLE_DIGICERT_EAP_PEER__

*/
typedef struct eap_peap_params
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

@callbackdoc    eap_peap.h
*/
    MSTATUS (*ulTransmit)(ubyte * appSessionCB,ubyte * eapPkt,ubyte4 eapPktLen,intBoolean encrypted);

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

@param appSessionCB     Cookie given by the application to identify the session.
@param type             Any of the \c eapMethodType enumerated values (see @ref
                        eap_proto.h).
@param code             Any of the \c eapCode enumerated values (see @ref
                        eap_proto.h).
@param id               EAP packet id.
@param eap_data         Pointer to EAP payload.
@param eap_data_len     Length of EAP payload.
@param opaque_data      Pointer to any opaque data&mdash;extra data that's
                        passed from the lower layer to the upper (method) layer
                        through the EAP stack.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap_peap.h
*/
    MSTATUS (*ul2ndStageReceive)(ubyte *appSessionCB, eapMethodType type,
                          eapCode code, ubyte id,
                          ubyte *eap_data, ubyte4 eap_data_len, ubyte *opaque_data);

/**
@brief      Send the inner method authentication status.
@details    This callback function is used to send the inner (second stage)
            method authenticatation status to the application, which in turn
            sets the outer (first stage) EAP session status.

For example, if the inner method receives an \c EAP_AUTH_SUCCESS or \c
EAP_AUTH_FAILURE (which are \c eapAuthStatus enumerations defined in @ref
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

@callbackdoc    eap_peap.h
*/
    MSTATUS (*ulAuthResultTransmit)(ubyte * appSessionCB,eapAuthStatus authStatus);

/**
@brief      Inner method user name passed by the peer.
@details    Inner method user name passed by the peer.
*/
    ubyte   UserName[EAP_MAX_USER_LEN];
/**
@brief      Number of bytes in the inner method user name (\p UserName).
@details    Number of bytes in the inner method user name (\p UserName).
*/
    ubyte2  UserNameLen;

/**
@brief      Phase 1 instance ID.
@details    Phase 1 instance ID; for multiple instance (VLAN/VR) support.
*/
    ubyte4  instanceId;             /* Phase 1 Instance Id */

/**
@brief      Type of session: \c EAP_SESSION_TYPE_PEER or \c
            EAP_SESSION_TYPE_AUTHENTICATOR.
@details    Type of session. The following \c eapSessionType enumerated values
            (defined in @ref eap_proto.h) are supported:\n
- \c EAP_SESSION_TYPE_PEER
- \c EAP_SESSION_TYPE_AUTHENTICATOR

(No other \c eapSessionType enumerated values are valid.)
*/
    eapSessionType sessionType;     /* (PEER/AUTH) */

/**
@brief      TLS connection's session ID.
@details    TLS connection's session ID: the 4-byte SSL connection ID returned
            from SSL session creation (not the session ID generated after TLS
            negotiation).
*/
    sbyte4  connectionInstance;     /* TLS COnnection INstance */

/**
@brief      EAP_TLS connection control block.
@details    EAP_TLS connection control block&mdash;the connection handle to an
            established outer (second stage) TLS connection. This handle is used
            in function calls to encrypt and decrpyt the payload and to generate
            session keys.
*/
    ubyte   *tls_con;               /* EAP TLS Connection INstance */

/**
@brief      PEAP version.
@details    PEAP version.
*/
    ubyte   version;               /*  PEAP Version */

} EAP_PEAP_params;

/**
@brief      Create and initialize an EAP-PEAP session.
@details    This function creates and initializes an EAP-PEAP session based on
            the specified parameters, returning the resultant session handle
            through the \p eapPEAPSession parameter.

@ingroup    eap_peap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_peap.h

@param appSessionCB     Application session handle (cookie given by the
                        application to identify the session).
@param eapPEAPSession   On return, pointer to EAP-PEAP session handle.
@param eapPEAPparams    Pointer to desired PEAP session parameters.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_peap.h
*/
MOC_EXTERN MSTATUS
EAP_PEAPinitSession(ubyte * appSessionCB,ubyte  **eapPEAPSession,
                    EAP_PEAP_params *eapPEAPparams);

/**
@brief      Build a PEAP packet.
@details    This function builds a PEAP packet from the specified encrypted
            second stage payload, prepending the header and performing any
            required fragmentation, and returns the resultant packet through the
            \p eapResponse parameter. Typically your application passes the
            resulting packet to EAP for transmission from authenticator to peer
            or from peer to authenticator.

@ingroup    eap_peap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_peap.h

@param eapPEAPCb    EAP-PEAP session handle returned from EAP_PEAPinitSession.
@param pkt          Pointer to payload to include in the PEAP packet.
@param pktLen       Number of bytes of payload data (\p pkt).
@param eapResponse  On return, pointer to resultant PEAP response packet.
@param eapRespLen   On return, number of bytes in EAP response payload (\p
                    eapResponse).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_peap.h
*/
MOC_EXTERN MSTATUS
EAP_PEAPFormSendPacket(void *eapPEAPCb,ubyte *pkt, ubyte4 pktLen,
                       ubyte **eapResponse, ubyte4 *eapRespLen);

/**
@brief      Get a session's current status.
@details    This function returns (through the \p eapSessionStatus parameter) a
            session's status.

@ingroup    eap_peap_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_peap.h

@param eapPEAPCb        EAP-PEAP session handle returned from
                        EAP_PEAPinitSession.
@param eapSessionStatus On return, pointer to session status structure.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_peap.h
*/
MOC_EXTERN MSTATUS
EAP_PEAPgetSessionStatus(void * eapPEAPCb,ubyte  *eapSessionStatus);

/**
@brief      Process an encrypted PEAP payload.
@details    This function processes an encrypted PEAP payload (in the form of
            TLVs&mdash;type-length-values), performs any required fragmentation,
            and passes the packet to the second phase of the PEAP stack.

@ingroup    eap_peap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_peap.h

@param eapPEAPCb    EAP-PEAP session handle returned from EAP_PEAPinitSession.
@param pkt          Pointer to encrypted PEAP packet.
@param pktLen       Number of bytes of encrypted PEAP data (\p pkt).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_peap.h
*/
MOC_EXTERN MSTATUS
EAP_PEAPreceiveLLPacket(void * eapPEAPCb,ubyte *pkt,ubyte4 pktLen);

/**
@brief      Transmit packets from the authenticator to the peer through the
            second stage EAP stack.
@details    This function (called by the second stage authenticator processing)
            transmits packets from the authenticator to the peer through the
            second stage EAP stack.

@ingroup    eap_peap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__
+ \c \__ENABLE_DIGICERT_EAP_PEAP__

@inc_file   eap_peap.h

@param eapSessionHdl    EAP-PEAP session handle returned from
                        EAP_PEAPinitSession.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param methodType       \c eapMethodType enumerated value for the second phase
                        (refer to @ref eap_proto.h).
@param code             Any of the following \c eapCode enumerated values (see
                        @ref eap_proto.h):\n
- \c EAP_CODE_REQUEST
- \c EAP_CODE_SUCCESS
- \c EAP_CODE_FAILURE

@param methodDecision   \c eapMethodDecision enumerated value (refer to @ref
                        eap_proto.h)
@param methodState      \c eapMethodState enumerated value (refer to @ref
                        eap_proto.h)
@param eap_data         Pointer to EAP packet to be transmitted.
@param eap_data_len     Number of bytes in EAP packet to be transmitted (\p
                        eap_data).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_peap.h
*/
MOC_EXTERN MSTATUS EAP_PEAPulAuthTransmit (ubyte * eapSessionHdl,
                 ubyte4 instanceId,
                 eapMethodType  methodType,
                 eapCode  code,
                 eapMethodDecision  methodDecision,
                 eapMethodState methodState,
                 ubyte * eap_data,
                 ubyte4  eap_data_len);

/**
@brief      Transmit packets from the peer to the authenticator through the
            second stage EAP stack.
@details    This function (called by the second stage peer processing) transmits
            packets from the peer to the authenticator through the second stage
            EAP stack.

@ingroup    eap_peap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_PEAP__

@inc_file   eap_peap.h

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
@param eap_data         Pointer to EAP packet to be transmitted.
@param eap_data_len     Number of bytes in EAP packet to be transmitted (\p
                        eap_data).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_peap.h
*/
MOC_EXTERN MSTATUS EAP_PEAPulPeerTransmit (ubyte * eapSessionHdl,
                 ubyte4 instanceId,
                 eapMethodType  methodType,
                 eapCode  code,
                 eapMethodDecision  methodDecision,
                 eapMethodState methodState,
                 ubyte * eap_data,
                 ubyte4  eap_data_len);

/**
@brief      Build and send a result TLV packet.
@details    This function builds a result TLV packet based on the specified \p
            intResult value and sends it to a peer.

@ingroup    eap_peap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__
+ \c \__ENABLE_DIGICERT_EAP_PEAP__

@inc_file   eap_peap.h

@param eapHdl       EAP-PEAP session handle returned from EAP_PEAPinitSession.
@param intResult    1 to specify a success TLV; any other value to specify a
                    failure TLV.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_peap.h
*/
MOC_EXTERN MSTATUS EAP_PEAPSendResultTlv(ubyte * eapHdl, ubyte2 intResult);

/**
@brief      Delete an EAP-PEAP session.
@details    This function deletes an EAP-PEAP session.

@ingroup    eap_peap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_peap.h

@param eapPEAPSession   EAP-PEAP session handle returned from
                        EAP_PEAPinitSession.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_peap.h
*/
MOC_EXTERN MSTATUS
EAP_PEAPdeleteSession(void *eapPEAPSession);

/**
@brief      Assign the code and ID values to an inner EAP header.
@details    This function assigns the specified code and ID values to an inner
            EAP header. Typically this is used in PEAP v0 when the authenticator
            or peer has not sent the inner header information, which is required
            by the inner (second stage) EAP state machine for packet processing.

@ingroup    eap_peap_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_peap.h

@param eapCB    EAP-PEAP session handle returned from EAP_PEAPinitSession.
@param code     Any of the \c eapCode enumerated values (defined in @ref
                eap_proto.h).
@param id       EAP request header ID (unique to this session).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_peap.h
*/
MOC_EXTERN MSTATUS
EAP_PEAPSetEapHdr(void  *eapCB, eapCode code, ubyte id);

/**
@brief      Generate and return a session's authentication keys.
@details    This function generates and returns a session's authentication keys.

@ingroup    eap_peap_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_peap.h

@param eapCb        EAP-PEAP session handle returned from EAP_PEAPinitSession.
@param key          On return, pointer to authentication keys.
@param keyLen       Number of bytes desired in the authentication key.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_peap.h
*/
MOC_EXTERN MSTATUS
EAP_PEAPgetKey(void *eapCb,ubyte *key,ubyte2 keyLen);

#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEAP__) */
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */

#ifdef __cplusplus
}
#endif

#endif /* __EAP_PEAP_H__  */
