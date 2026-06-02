/**
 * @file  eap_fast.h
 * @brief EAP-FAST method API
 *
 * @details    This header file contains definitions, enumerations, structures, and
 *            function declarations used by EAP FAST helper functions.
 *
 * @since 1.41
 * @version 2.02 and later
 *
 * @flags
 * To build products using this header file, at least one flag in each of the
 * following flag pairs must be defined in moptions.h:
 * Enable EAP peer/authenticator (
 * \c \__ENABLE_DIGICERT_EAP_PEER__,
 * \c \__ENABLE_DIGICERT_EAP_AUTH__)
 * Enable an EAP FAST method (
 * \c \__ENABLE_DIGICERT_EAP_FAST__,
 * \c \__ENABLE_DIGICERT_EAP_PEAPV2__)

 * Whether the following flags are defined determines which functions are enabled:
 * \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
 * \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
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

#ifndef __EAP_FAST_H__
#define __EAP_FAST_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
#if (defined(__ENABLE_DIGICERT_EAP_FAST__) || defined(__ENABLE_DIGICERT_EAP_PEAPV2__))

#define EAP_FAST_LENGTH_INCLUDED_FLAG   (0x80)
#define EAP_FAST_MORE_FRAGMENTS_FLAG    (0x40)
#define EAP_FAST_START_FLAG             (0x20)
#define EAP_FAST_AUTH_ID_TYPE           (0x04)


/* Result TLV values */
#define EAP_FAST_RESULT_TLV_SUCCESS     1
#define EAP_FAST_RESULT_TLV_FAILURE     2

#define EAP_MAX_USER_LEN                (64)
#define EAP_MAX_PASS_LEN                (64)
#define EAP_FAST_PAC_KEY_LENGTH          32

/** @private @internal */
typedef enum eap_fast_frag_flag
{
    EAP_FAST_FRAG_FLAG_RECV = 1,
    EAP_FAST_FRAG_FLAG_SEND

} eap_fast_frag_flag_e;

/** @private @internal */
typedef enum eap_fast_intermediate_result
{
    EAP_FAST_INTERMEDIATE_SUCCESS = 1,
    EAP_FAST_INTERMEDIATE_FAILURE

} eap_fast_intermediate_result_e;

/** @private @internal */
typedef enum eap_fast_eap_state_e
{
    EAP_FAST_EAP_INIT     = 0,
    EAP_FAST_EAP_IDENTITY = 1,
    EAP_FAST_EAP_METHOD   = 2,
    EAP_FAST_EAP_SUCCESS  = 3,
    EAP_FAST_EAP_FAILURE  = 4,

} eap_fast_eap_state;

/**
@brief      Configuration settings and callback function pointers for EAP-FAST
            sessions.
@details    This structure is used for EAP-FAST session configuration. Each
            included callback function should be customized for your application
            and then registered by assigning it to the appropriate structure
            function pointer(s).

@since 1.41
@version 1.41 and later

@flags
To use this structure, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_FAST__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__
+ \c \__ENABLE_DIGICERT_EAP_PEER__

*/
typedef struct eap_fast_params
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

@callbackdoc    eap_fast.h
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

@param appSessionCB         Cookie given by the application to identify the
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

@callbackdoc    eap_fast.h
*/
    MSTATUS (*ul2ndStageReceive)(ubyte *appSessionCB, eapMethodType type,
                          eapCode code, ubyte id,
                          ubyte *eap_data, ubyte4 eap_data_len, ubyte *opaque_data);

/**
@brief      Get compound session key (CMK).
@details    This callback is used by the EAP-FAST method implementation to get
            the compound session key(CMK)  from the application. The CMK is used
            to calculate the Compound MAC as part of the Crypto-Binding TLV,
            which helps provide assurance that the same entities are involved in
            all communications in EAP-FAST.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
There are no flag dependencies to enable this callback.

@param appSessionCB  Cookie given by the application to identify the session.
@param cmk           Pointer to compund session key.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap_fast.h
*/
    MSTATUS (*ulGetFastCompoundKey)(ubyte *appSessionCB, ubyte *cmk);

/**
@brief      Get compound session key.
@details    This callback is similar to ulGetFastCompoundKey, but it is needed
            if the method type is EAP-PEAP instead of EAP-FAST. This call back
            takes 2 additional parameters viz. s_nonce which is server nonce and
            c_nonce which is client nonce. these nonce values are used in
            calculation of CMK.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
There are no flag dependencies to enable this callback.

@param appSessionCB  Cookie given by the application to identify the session.
@param cmk           Pointer to compund session key.
@param s_nonce       Server nonce used to calculate CMK.
@param c_nonce       Client nonce used to calculate CMK.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap_fast.h
*/
    MSTATUS (*ulGetPeapV2CompoundKey)(ubyte *appSessionCB, ubyte *cmk, ubyte *s_nonce, ubyte *c_nonce);

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

@param appSessionCB             Application-specific session identifier.
@param cryptoBindingVerified    Status of %crypto binding attempt. \c TRUE ==
                                success. \c FALSE == failure.
@param authStatus               Any of the eapAuthStatus enumerated values
                                (defined in @ref eap_proto.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap_fast.h
*/
    MSTATUS (*ulAuthResultTransmit)(ubyte * appSessionCB,
                                     ubyte cryptoBindingVerified,
                                     eapAuthStatus authStatus);

/**
@brief      Close the TLS tunnel.
@details    This callback takes an application handle and closes the TLS tunnel.
            This is applicable if the session type is \c
            EAP_SESSION_TYPE_AUTHENTICATOR.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
There are no flag dependencies to enable this callback.

@param appSessionCB             Application-specific session identifier.


@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap_fast.h
*/
    MSTATUS (*ulTLSclose)(ubyte * appSessionCB);

/**
@brief      EAP-FAST %version.
@details    EAP-FAST %version.
*/
    ubyte          version;

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
@brief      Method type used by a peer.
@details    Method type used by a peer: any of the \c eapMethodType
            enumerated values (defined in @ref eap_proto.h).
*/
    eapMethodType  methodType;      /* (FAST/PEAPV2) */

/**
@brief      TLS connection's session ID.
@details    TLS connection's session ID: the 4-byte SSL connection ID returned
            from SSL session creation (not the session ID generated after TLS
            negotiation).
*/
    sbyte4  connectionInstance;     /* TLS COnnection Instance */

/**
@brief      EAP_TLS connection control block.
@details    EAP_TLS connection control block&mdash;the connection handle to an
            established outer (second stage) TLS connection. This handle is used
            in function calls to encrypt and decrpyt the payload and to generate
            session keys.
*/
    ubyte   *tls_con;               /* EAP TLS Connection Instance */

/**
@brief      Phase 1 instance ID.
@details    Phase 1 instance ID; for multiple instance (VLAN/VR) support.
*/
    ubyte4  instanceId;             /* Phase 1 Instance Id */

} EAP_FAST_params;

/** @private @internal */
typedef struct eap_fast_pac
{
   ubyte pacKey[EAP_FAST_PAC_KEY_LENGTH];
   ubyte *a_id;
   ubyte2 a_idLen;
   ubyte *i_id;
   ubyte2 i_idLen;
   ubyte4 pacLifetime;
   ubyte *pacOpaque;
   ubyte4 pacOpaqueLen;
   ubyte  *a_idInfo;
   ubyte4  a_idInfoLen;
   ubyte4  pacType;

}EAP_FAST_pac_t;

/**
@brief      Build an EAP-FAST packet from the specified encrypted second stage
            payload.
@details    This function builds an EAP-FAST packet from the specified encrypted
            second stage payload, prepending the header and performing any
            required fragmentation, and returning the resultant packet through
            the \p eapResponse parameter. Typically your application passes the
            resulting packet to EAP for transmission from authenticator to peer
            or from peer to authenticator.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one flag in each of the following flag pairs
must be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
- Enable an EAP FAST method (\c \__ENABLE_DIGICERT_EAP_FAST__, \c
  \__ENABLE_DIGICERT_EAP_PEAPV2__)

@inc_file   eap_fast.h

@param eapFASTCb    EAP-FAST session handle returned from EAP_FASTinitSession.
@param pkt          Pointer to payload to include in the EAP-FAST packet.
@param pktLen       Number of bytes in the payload data (\p pkt).
@param eapResponse  On return, pointer to resultant EAP-FAST response packet.
@param eapRespLen   On return, number of bytes in EAP-FAST response payload (\p
                    eapResponse).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTFormSendPacket(void *eapFASTCb,ubyte *pkt, ubyte4 pktLen,
                       ubyte **eapResponse, ubyte4 *eapRespLen);

/**
@brief      Transmits Result and crypto binding TLVs to the peer.
@details    This function (called by the authenticator) transmits the
            intermediate result and crypto binding TLVs (type-length-values) to
            the peer using the specified compound key and nonce.

This function enables the authenticator to negotiate additional methods. Once
the Result TLV is sent (by a call to EAP_FASTauthSendMethodResult), the
authenticator ceases negotiating additional methods.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one flag in each of the following flag pairs
must be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
- Enable an EAP FAST method (\c \__ENABLE_DIGICERT_EAP_FAST__, \c
  \__ENABLE_DIGICERT_EAP_PEAPV2__)

@inc_file   eap_fast.h

@param appSessionHdl    Application session handle (cookie given by the
                        application to identify the session).
@param cmk              Compound key (derived by using the FAST TLS algorithms
                        provided by the TLS layer).
@param nonce            32-byte random number to incorporate into the crypto
                        binding TLV and to use for calculating the %crypto MAC
                        (message authentication code).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTauthSendCryptoBindingTlv(ubyte *appSessionHdl, ubyte *cmk,ubyte *nonce);

/**
@brief      Buld a Method Result packet.
@details    This function builds a Method Result packet to pass the specified
            intermediate method %crypto binding, compound key (if any) and
            result TLVs to the peer's upper layer.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one flag in each of the following flag pairs
must be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
- Enable an EAP FAST method (\c \__ENABLE_DIGICERT_EAP_FAST__, \c
  \__ENABLE_DIGICERT_EAP_PEAPV2__)

@inc_file   eap_fast.h

@param appSessionHdl        Application session handle (cookie given by the
                            application to identify the session).
@param sendCryptoBinding    \c 1 to specify that the crypto-binding TLV be sent;
                            any other value to specify that it not be sent.
@param compoundKey          Pointer to compound intermediate method key (derived
                            by using the FAST TLS algorithms provided by the TLS
                            layer; may be \c NULL).
@param result               Result to transmit: \c EAP_FAST_RESULT_TLV_SUCCESS
                            or \c EAP_FAST_RESULT_TLV_FAILURE.
@param nonce                Pointer to 32-byte random number to incorporate into
                            the crypto binding TLV and to use for calculating
                            the crypto MAC (message authentication code).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTauthSendMethodResult(ubyte *appSessionHdl, ubyte sendCryptoBinding,
                             ubyte *compoundKey, ubyte2 result,ubyte *nonce);

/**
@brief      Process a packet's TLVs, managing fragmentation, and send the packet
            on for second stage negotiation.
@details    This function processes a packet's TLVs, performs any required
            reassembly, and passes the packet to the EAP-FAST lower layer for
            second stage (method) negotiation.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one flag in each of the following flag pairs
must be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
- Enable an EAP FAST method (\c \__ENABLE_DIGICERT_EAP_FAST__, \c
  \__ENABLE_DIGICERT_EAP_PEAPV2__)

@inc_file   eap_fast.h

@param eapFASTCb    EAP-FAST session handle returned from EAP_FASTinitSession.
@param pkt          Pointer to input packet (received from lower layer).
@param pktLen       Number of bytes in input packet (\p pkt).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTreceiveLLPacket(void * eapFASTCb, ubyte *pkt, ubyte4 pktLen);

/**
@brief      Delete a second stage EAP-FAST session.
@details    This function deletes a second stage EAP-FAST session.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one flag in each of the following flag pairs
must be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
- Enable an EAP FAST method (\c \__ENABLE_DIGICERT_EAP_FAST__, \c
  \__ENABLE_DIGICERT_EAP_PEAPV2__)

@inc_file   eap_fast.h

@param eapFASTSession   EAP-FAST session handle returned from
                        EAP_FASTinitSession.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTdeleteSession(ubyte *eapFASTSession);

/**
@brief      Create and initialize an EAP-FAST session.
@details    This function creates and initializes an EAP-FAST session based on
            the specified parameters, returning the resultant session handle
            through the \p eapFastSession parameter.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one flag in each of the following flag pairs
must be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
- Enable an EAP FAST method (\c \__ENABLE_DIGICERT_EAP_FAST__, \c
  \__ENABLE_DIGICERT_EAP_PEAPV2__)

@inc_file   eap_fast.h

@param appSessionCB     Application session handle (cookie given by the
                        application to identify the session).
@param eapFASTSession   On return, pointer to EAP-FAST session handle.
@param eapFASTparams    Pointer to desired EAP-FAST session parameters.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTinitSession(ubyte *appSessionCB, ubyte **eapFASTSession,
                    EAP_FAST_params *eapFASTparams);

/** @private @internal */
MOC_EXTERN MSTATUS
EAP_FASTAuthInit(ubyte *eapCb);

/**
@brief      Send an Identity request to the peer.
@details    This function (called by the authenticator) sends an identity
            request to the peer during the second phase of EAP-FAST.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

Additionally, at least one of the following flags (or set of flags) must be
defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_FAST__ and one of the asynchronous SSL flags (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__ or \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
+ \c \__ENABLE_DIGICERT_EAP_PEAPV2__

@inc_file   eap_fast.h

@param eapCb    EAP-FAST session handle returned from EAP_FASTinitSession.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTAuthInit2(ubyte *eapCb);

/**
@brief      Delete an EAP-FAST authenticator second stage stack.
@details    This function deletes an EAP-FAST authenticator second stage stack.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

Additionally, at least one of the following flags (or set of flags) must be
defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_FAST__ and one of the asynchronous SSL flags (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__ or \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
+ \c \__ENABLE_DIGICERT_EAP_PEAPV2__

@inc_file   eap_fast.h

@param eapFASTCb    EAP-FAST session handle returned from EAP_FASTinitSession.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTulAuthSessionDelete(ubyte *eapFASTCb);

/**
@brief      Get an EAP-FAST session's second stage EAP session handle.
@details    This function retrieves the EAP-FAST second stage handle. (In the first stage,
TLS is negotiated with EAP payload messaging. In the second stage, the method,
such as MS-CHAP-V2, is negotiated over the already secure TLS channel.)

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_FAST__
+ \c \__ENABLE_DIGICERT_EAP_PEAPV2__

@inc_file   eap_fast.h

@param eapCb            EAP-FAST session handle returned from EAP_FASTinitSession.
@param eapSessionHdl    On return, pointer to EAP-FAST second stage session handle.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTPeerGetSessionHdl(ubyte *eapCb, ubyte **eapSessionHdl);

/**
@brief      Get an EAP-FAST session's second stage EAP session handle.
@details    This function retrieves the specified EAP-FAST session's second stage EAP session
handle.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

Additionally, at least one of the following flags (or set of flags) must be
defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_FAST__ and one of the asynchronous SSL flags (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__ or \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
+ \c \__ENABLE_DIGICERT_EAP_PEAPV2__

@inc_file   eap_fast.h

@param eapCb                EAP-FAST session handle returned from EAP_FASTinitSession.
@param eapAuthSessionHdl    On return, pointer to EAP-FAST second stage session handle.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTAuthGetSessionHdl(ubyte *eapCb, ubyte **eapAuthSessionHdl);

/** @private @internal */
MOC_EXTERN MSTATUS
eap_FASTPeerInit(ubyte *eapCb);

/**
@brief      Build an EAP payload TLV from an input second stage EAP packet and then pass the packet to the first stage.
@details    This function builds an EAP payload TLV from the input second stage EAP packet
and then passes the packet to the first stage using the registered upper layer
callback. This packet can later be encrypted by the TLS session and passed to
the EAP lower layer.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one flag in each of the following flag pairs
must be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
- Enable an EAP FAST method (\c \__ENABLE_DIGICERT_EAP_FAST__, \c
  \__ENABLE_DIGICERT_EAP_PEAPV2__)

@inc_file   eap_fast.h

@param eapFastCb    EAP-FAST session handle returned from EAP_FASTinitSession.
@param eapPkt       Pointer to input EAP packet.
@param eapPktLen    Number of bytes in input EAP packet (\p eapPkt).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTEncapEAPPkt(ubyte *eapFastCb, ubyte *eapPkt, ubyte4 eapPktLen);

/**
@brief      Encapsulate an EAP packet into an EAP payload TLV packet.
@details    This function encapsulates an  EAP packet into an EAP payload TLV,
returning the resultant packet through the \p response parameter.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one flag in each of the following flag pairs
must be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
- Enable an EAP FAST method (\c \__ENABLE_DIGICERT_EAP_FAST__, \c
  \__ENABLE_DIGICERT_EAP_PEAPV2__)

@inc_file   eap_fast.h

@param eapPkt       Pointer to input EAP packet.
@param eapPktLen    Number of bytes in input EAP packet (\p eapPkt).
@param response     On return, pointer to response packet.
@param responseLen  On return, pointer to number of bytes in response packet (\p response).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTgetTLVEncapEAPPkt(ubyte *eapPkt, ubyte4 eapPktLen,ubyte **response,ubyte4 *responseLen);

/**
@brief      Process a decrypted EAP packet's TLVs.
@details    This function parses a decrypted EAP packet for TLVs and processes each
according to its type.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one flag in each of the following flag pairs
must be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
- Enable an EAP FAST method (\c \__ENABLE_DIGICERT_EAP_FAST__, \c
  \__ENABLE_DIGICERT_EAP_PEAPV2__)

@inc_file   eap_fast.h

@param fastHdl  EAP-FAST session handle returned from EAP_FASTinitSession.
@param pPkt     Pointer to input packet.
@param pktLen   Number of bytes in input packet (\p pPkt).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTProcessTLV(ubyte *fastHdl, ubyte *pPkt, ubyte4 pktLen);

/**
@brief      Delete an EAP-FAST peer second stage stack.
@details    This function deletes an EAP-FAST peer second stage stack.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_FAST__
+ \c \__ENABLE_DIGICERT_EAP_PEAPV2__

@inc_file   eap_fast.h

@param eapFASTCb    EAP-FAST session handle returned from EAP_FASTinitSession.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTulPeerSessionDelete(ubyte *eapFASTCb);

/** @private @internal */
MOC_EXTERN MSTATUS
EAP_FASTGetPAC(ubyte  *eapFASTCb, EAP_FAST_pac_t **pac);

/**
@brief      Transmits Result and PAC Provisioning TLVs to the peer.
@details    This function (called by the authenticator) transmits the result and
            PAC Provisioning TLVs (type-length-values) to the peer using the
            specified Key / A-ID and Other parameters specified by the User/.

This function enables the authenticator to provision PAC on the Peer

@ingroup    eap_fast_functions

@since 5.0
@version 5.0 and later

@flags
To enable this function, at least one flag in each of the following flag pairs
must be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
- Enable an EAP FAST method (\c \__ENABLE_DIGICERT_EAP_FAST__, \c
  \__ENABLE_DIGICERT_EAP_PEAPV2__)

@inc_file   eap_fast.h

@param eapFastSessionHdl    Application session handle (cookie given by the
                            application to identify the session).
@param pac                  PAC Structure with the Relevant information.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTauthSendPAC_ResultTlv(ubyte *eapFastSessionHdl, EAP_FAST_pac_t *pac);

/**
@brief      Transmit packets from peer to authenticator during second stage
            negotiation.
@details    This function transmits packets from the peer to the authenticator
            during second stage negotiation.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_FAST__
+ \c \__ENABLE_DIGICERT_EAP_PEAPV2__

@inc_file   eap_fast.h

@param eapSessionHdl    EAP-FAST session handle returned from
                        EAP_FASTinitSession.
@param instanceId       Instance ID.
@param methodType       \c eapMethodType enumerated value for the second phase
                        (see @ref eap_proto.h).
@param code             \c EAP_CODE_RESPONSE (an \c eapCode enumerated values
                        defined in @ref eap_proto.h).
@param methodDecision   \c eapMethodDecision enumerated value (see @ref
                        eap_proto.h).
@param methodState      \c eapMethodState enumerated value (see @ref
                        eap_proto.h).
@param eap_data         Pointer to EAP packet to be transmitted.
@param eap_data_len     Number of bytes in EAP packet to be transmitted (\p
                        eap_data).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTulPeerTransmit (ubyte *eapSessionHdl,
                 ubyte4 instanceId,
                 eapMethodType  methodType,
                 eapCode  code,
                 eapMethodDecision  methodDecision,
                 eapMethodState methodState,
                 ubyte * eap_data,
                 ubyte4  eap_data_len);

/**
@brief      Transmit packets from authenticator to peer during second stage
            negotiation.
@details    This function transmits packets from the authenticator to the peer
            during second stage negotiation.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

Additionally, at least one of the following flags (or set of flags) must be
defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_FAST__ and one of the asynchronous SSL flags (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__ or \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
+ \c \__ENABLE_DIGICERT_EAP_PEAPV2__

@inc_file   eap_fast.h

@param eapSessionHdl    EAP-FAST session handle returned from
                        EAP_FASTinitSession.
@param instanceId       Instance ID.
@param methodType       \c eapMethodType enumerated value for the second phase
                        (see @ref eap_proto.h).
@param code             Any of the following \c eapCode enumerated values
                        (defined in @ref eap_proto.h):\n
- \c EAP_CODE_REQUEST
- \c EAP_CODE_SUCCESS
- \c EAP_CODE_FAILURE

@param methodDecision   \c eapMethodDecision enumerated value (see @ref
                        eap_proto.h).
@param methodState      \c eapMethodState enumerated value (see @ref
                        eap_proto.h).
@param eap_data         Pointer to EAP packet to be transmitted.
@param eap_data_len     Number of bytes in EAP packet to be transmitted (\p
                        eap_data).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTulAuthTransmit (ubyte *eapSessionHdl,
                 ubyte4 instanceId,
                 eapMethodType  methodType,
                 eapCode  code,
                 eapMethodDecision  methodDecision,
                 eapMethodState methodState,
                 ubyte * eap_data,
                 ubyte4  eap_data_len);

/** @private @internal */
MOC_EXTERN MSTATUS
EAP_FASTauthGetCryptoBindingStatus(ubyte *eapFastSessionHdl,
                                    ubyte *bindingStatus);

/**
@brief      Extract the authority ID (if any) from an EAP-FAST packet.
@details    This function extracts the authority ID (if any) from an EAP-FAST
            packet, returning it through the \p authId parameter.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one flag in each of the following flag pairs
must be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
- Enable an EAP FAST method (\c \__ENABLE_DIGICERT_EAP_FAST__, \c
  \__ENABLE_DIGICERT_EAP_PEAPV2__)

@inc_file   eap_fast.h

@param pkt          Pointer to EAP-FAST packet.
@param pktLen       Number of bytes in EAP-FAST packet (\p pkt).
@param authId       On return, pointer to authority ID.
@param authIdLen    On return, pointer to number of bytes in authority ID (\p
                    authId).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTgetAuthId(ubyte *pkt, ubyte4 pktLen, ubyte **authId, ubyte2 *authIdLen);

/**
@brief      Build an Authority ID Requeest packet.
@details    This function (called by an EAP-TLS authenticator) builds an
            Authority ID Request packet that includes the specified \p flags
            values. The resultant data will ultimately be sent to the peer to
            provide hints about the authenticator's identity during a TLS Start
            message transmission.

@ingroup    eap_fast_functions

@since 1.41
@version 1.41

@deprecated For applications using version 2.02 and later, you should not use
this function. Instead, call the EAP_TLSSetAuthId function.

@flags
To enable this function, at least one flag in each of the following flag pairs
must be defined in moptions.h:
- Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c
  \__ENABLE_DIGICERT_EAP_AUTH__)
- Enable asynchronous SSL client/server (\c
  \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c
  \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
- Enable an EAP FAST method (\c \__ENABLE_DIGICERT_EAP_FAST__, \c
  \__ENABLE_DIGICERT_EAP_PEAPV2__)

@inc_file   eap_fast.h

@param flags        Sum of bitmasks indicating the TLS Start bit status and the
                    TLS version.
@param authId       Pointer to authority ID (often set by calling
                    EAP_TLSSetAuthId before calling EAP_TLSstartRequest).
@param authIdLen    Number of bytes in authority ID (\p authId).
@param eapReqData   On return, pointer to resultant EAP-FAST/TLS request payload.
@param eapReqLen    On return, pointer to number of bytes in EAP request payload
                    (\p eapReqData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_fast.h
*/
MOC_EXTERN MSTATUS
EAP_FASTbuildAuthId(ubyte flags, ubyte *authId, ubyte2 authIdLen,
                    ubyte **eapReqData, ubyte4 *eapReqLen);

#endif /* ((defined(__ENABLE_DIGICERT_EAP_FAST__) */
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */
#ifdef __cplusplus
}
#endif
#endif /* __EAP_FAST_H__  */
