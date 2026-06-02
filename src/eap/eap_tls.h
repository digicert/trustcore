/**
 * @file  eap_tls.h
 * @brief EAP-TLS method API
 *
 * @details    EAP-TLS interface
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     To build products using this header file's functions, the following flag must be
 *     defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_TLS__
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

#ifndef __EAP_TLS_H__
#define __EAP_TLS_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))

#define EAP_TLS_START_FLAG            (0x20)
#define EAP_TLS_MORE_FLAG             (0x40)
#define EAP_TLS_LENGTH_FLAG           (0x80)
#define EAP_TLS_VERSION_MASK          (0x07)
#define MAX_EAP_TLS_MTU               (1300)
#define MAX_EAP_SSL_CONNECTIONS_ALLOWED (1000)
#define EAP_TLS_LENGTH_BYTES          (4)

/** @private @internal */
typedef enum eap_tls_connection_e {
    EAP_TLS_CONNECTION_CLIENT = 1,
    EAP_TLS_CONNECTION_SERVER,

} eap_tls_connection;

/** @private @internal */
typedef enum eap_tls_param_e {
    EAP_TLS_PARAM_PAC_KEY = 1,
    EAP_TLS_PARAM_INNER_APP,
    EAP_TLS_PARAM_MAX_MTU,    /*P: PARAM for setting MAX MTU */
    EAP_TLS_SSL_CERT_STORE_PTR
} eap_tls_param;

#if (defined(__ENABLE_DIGICERT_EAP_TLS__))

/**
@brief      Set any parameter of any method to a specified value.
@details    This function sets the specified parameter's value for the specified
            method; for example, setting the \c pacKey value for EAP-FAST.

The two method-parameter combinations handled by this function are:

- \c EAP_TYPE_FAST-\c EAP_TLS_PARAM_PAC_KEY (Requires that the \c
  \c \__ENABLE_DIGICERT_EAP_FAST__ flag be defined)
- \c EAP_TYPE_TTLS-\c EAP_TLS_PARAM_INNER_APP (Requires that the \c
  \c \__ENABLE_DIGICERT_INNER_APP__ flag be defined)

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@note       A repeated call to this function overwrites the decrypted data.
            Therefore your application should immediately process the data or
            explicitly save it for later processing.

@inc_file   eap_tls.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.
@param methodType       \c eapMethodType enumerated value (see @ref eap_proto.h)
@param paramType        \c eap_tls_param enumerated value (see @ref eap_tls.h).\n
\n
There are four parameter settings you can use. Two of them are desribed here:\n

- \c EAP_TLS_PARAM_MAX_MTU : This is used to set the max MTU. The group of
  EAP-TLS messages sent in a single round may thus be larger than the MTU size
  or the  maximum Remote Authentication Dail-In User Service (RADIUS) packet
  size of 4096 octets.  As a result, an EAP-TLS implementation must provide its
  own support for fragmentation and reassembly. NanoEAP takes this value from
  use by providing API EAP_TLSsetParams, and uses for fragmentation and
  reassembly.\n

- \c EAP_TLS_SSL_CERT_STORE_PTR: This parameter is used to pass instance of
  certificate store to the EAP-TLS stack, so that it can find the client
  certificates and its private keys during mutual authentication.

@param param            Pointer to value to assign to specified \p methodType
                        parameter.
@param paramLen         Number of bytes in value to assign (\p param).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TLSstartRequest
@sa EAP_TLSPeerStart
@sa EAP_TLSRecvData
@sa EAP_TLSgetKey

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSsetParams(ubyte *appSessionHdl,ubyte *tls_connection,
                 ubyte methodType, eap_tls_param paramType,ubyte *param,ubyte4 paramLen);

/**
@brief      Get the authentication version of an EAP-TLS packet.
@details    This function extracts the authentication version from an
            EAP-TLS packet.

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_tls.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param authVersion      On return, authenticator method version.
@param pkt              EAP-TLS packet containing the authentication version.
@param pktLen           Number of bytes in the EAP-TLS packet (\p pkt).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSPeerGetAuthVersion(ubyte *appSessionHdl, ubyte *authVersion, ubyte *pkt,
                          ubyte pktLen);

/**
@brief      Create an EAP-TLS session.
@details    This function creates an EAP-TLS session using the specified
            parameters. The TLS connection handle is returned through the \p
            tls_connection parameter, and should be passed in all subsequent
            function calls for the TLS session. This function can be called by
            any method that runs over TLS, for example, TTLS, PEAP, and FAST.

Both clients and servers can call this function. If called by a server, the
function calls SSL_ASYNC_acceptConnection. If called by a %client, the function
calls SSL_ASYNC_connect.

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@note       The \p peerVersion and \p authVersion parameter values must match
            and must correspond to TLS v1.0 and later.

@inc_file   eap_tls.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param tls_connection   On return, EAP-TLS session handle.
@param connectionType   Any of the \c eap_tls_connection enumerated values (see
                        @ref eap_tls.h).
@param sessionIdLen     Pointer to number of bytes in EAP-TLS session ID (\p
                        sessionId).
@param sessionId        Pointer to EAP-TLS session ID.
@param masterSecret     Pointer to master secret for this session.
@param dnsName          Pointer to DNS common name in the certificate.
@param methodType       Any of the \c eapMethodType enumerated values (see @ref
                        eap_proto.h).
@param peerVersion      Peer method version.
@param authVersion      Authenticator method version.
@param pCertStore       Pointer to TLS certificate store.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSCreateSession(ubyte *appSessionHdl,ubyte **tls_connection,
                     eap_tls_connection connectionType,
                     ubyte4 *sessionIdLen,
                     ubyte *sessionId, ubyte *masterSecret,ubyte *dnsName,
                     ubyte methodType,ubyte peerVersion, ubyte authVersion,
                     struct certStore* pCertStore);

/**
@brief      Build a %client \c Hello message and add it to the send buffer.
@details    This function builds a client \c Hello response, returns the message
            through the \p eapRespData parameter, and adds the message to the
            asynchronous send buffer.

This function is used by the peer after it receives an EAP-TLS \c Start message
from the authenticator. Version negotiation is performed using the specified
authenticator and peer versions. This function can be called by any method that
runs over TLS, such as TTLS, PEAP, and FAST.

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap_tls.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.
@param methodType       Any of the \c eapMethodType enumerated values (see @ref
                        eap_proto.h).
@param pkt              \c Start message packet.
@param pktLen           Number of bytes in the \c Start message packet (\p pkt).
@param eapRespData      On return, pointer to generated \c Hello response.
@param eapRespLen       On return, pointer to length of generated \c Hello
                        response (\p eapRespData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@note       For EAP-FAST authentication, the authenticator ID can be extracted
            by calling EAP_FASTgetAuthId.

@note       Although any \c eapMethodType enumerated value can be specified for
            the \p methodType parameter, only the following values are
            specifically addressed by this function:
- \c EAP_TYPE_TLS
- \c EAP_TYPE_TTLS
- \c EAP_TYPE_PEAP
- \c EAP_TYPE_FAST

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSPeerStart(ubyte *appSessionHdl,ubyte *tls_connection,
                 ubyte methodType,
                 ubyte *pkt,ubyte4 pktLen,
                 ubyte **eapRespData, ubyte4 *eapRespLen);

/**
@brief      Send an EAP-TLS \c Start message.
@details    This function sends an EAP-TLS \c Start message, which is used by
            the authenticator to start an EAP conversation using TLS, TTLS,
            PEAP, or FAST methods. For EAP-FAST conversations, the authenticator
            can include its ID to send to the peer.

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_tls.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.
@param sslCert          SSL certificate for this server.
@param methodType       Any of the \c eapMethodType enumerated values (see @ref
                        eap_proto.h).
@param eapReqData       On return, pointer to returned data (the TLS encrypted
                        payload).
@param eapReqLen        On return, pointer to length of returned data (\p
                        eapReqData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSstartRequest(ubyte *appSessionHdl,ubyte *tls_connection,
                    certDescriptor* sslCert,
                    ubyte methodType,
                    ubyte **eapReqData, ubyte4 *eapReqLen);

/**
@brief      Process a received EAP-TLS message and build a response.
@details    This function processes an EAP-TLS message received by an
            authenticator or peer, performing any necessary fragmentation and
            reassembly of records, as well as wrapping the TLS response as an
            EAP payload.

If the \c ERR_EAP_TLS_DATA_ARRIVED error code is returned, the decrypted data is
returned through the \p eapRespData parameter, thereby managing cases where two
SSL frames are grouped within a single TLS packet. A typical example is the
Handshake Record for PEAP and FAST, where the Identity Request is frequently
piggybacked to the TLS \c Finished message.

If \c OK is returned, the data is decrypted for local processing; otherwise the
\p eapRespData parameter contains the decrypted data to be transmitted to the
peer or authenticator (according to whether this function was called by the
authenticator or peer, respectively).

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_tls.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.
@param data             EAP-TLS message payload.
@param len              Number of bytes in EAP-TLS message payload (\p data).
@param eapRespData      On return, pointer to decrypted data (regardless of the
                        functin's return stauts).
@param eapRespLen       On return, pointer to length of decrypted data (\p
                        eapRespData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TLSstartRequest
@sa EAP_TLSPeerStart
@sa EAP_TLSSendData
@sa EAP_TLSRecvData

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSProcessMsg (ubyte *appSessionHdl, ubyte *tls_connection,
                   ubyte *data, ubyte4 len,
                   ubyte **eapRespData, ubyte4 *eapRespLen);

/**
@brief      Get an EAP-TLS session's session status.
@details    This function retrieves TLS session's session status (\c
            SSL_CONNECTION_OPEN or \c SSL_CONNECTION_NEGOTIATE). This is usually
            used after a call to EAP_TLSProcessMsg to verify the TLS channel
            status.

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_tls.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.
@param sessionStatus    On return, pointer to the session's status.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TLSstartRequest
@sa EAP_TLSProcessMsg
@sa EAP_TLSgetClientSessionInfo
@sa EAP_TLSgetSSLInstance

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSgetSessionStatus(ubyte *appSessionHdl,ubyte * tls_connection,
                        ubyte4 *sessionStatus);

/**
@brief      Get an EAP-TLS connection's SSL connection instance.
@details    This function retrieves an EAP-TLS connection's SSL connection
            instance.

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_tls.h

@param appSessionHdl        Cookie given by the application to identify the
                            session.
@param tls_connection       EAP-TLS session handle returned from
                            EAP_TLSCreateSession.
@param connectionInstance   On return, pointer to the SSL connection instance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TLSstartRequest
@sa EAP_TLSProcessMsg
@sa EAP_TLSgetSessionStatus
@sa EAP_TLSgetClientSessionInfo

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSgetSSLInstance(ubyte *appSessionHdl,ubyte * tls_connection,
                      sbyte4 *connectionInstance);

/**
@brief      Close an EAP-TLS connection.
@details    This function closes an EAP-TLS connection.

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_tls.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TLSstartRequest
@sa EAP_TLSProcessMsg
@sa EAP_TLSgetClientSessionInfo

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLScloseConnection (ubyte *appSessionHdl,ubyte *tls_connection);

/**
@brief      Get EAP-TLS session's session ID and master secret.
@details    This function retrieves the specified TLS session's session ID and
            master secret.

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_tls.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.
@param sessionIdLen     On return, pointer to number of bytes in EAP-TLS session
                        ID (\p sessionId).
@param sessionId        On return, pointer to session's session ID.
@param masterSecret     On return, pointer to session's master secret.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TLSstartRequest
@sa EAP_TLSProcessMsg
@sa EAP_TLSgetSessionStatus
@sa EAP_TLSgetSSLInstance

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSgetClientSessionInfo(ubyte *appSessionHdl,ubyte * tls_connection,
                            ubyte4 *sessionIdLen,
                            ubyte *sessionId, ubyte *masterSecret);

/**
@brief      Decrypt EAP message payload.
@details    This function decrypts application data from an EAP payload. If the
            EAP payload contains multiple packets, this function decrypts the
            initial packet and returns the next packet through the \p eapRemData
            parameter, which must be used as input (via the \p data parameter)
            to a repeated call to this function. This function must be
            repeatedly called until \p eapRemData is \c NULL.

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@note A repeated call to this function overwrites the decrypted data. Therefore
your application should immediately process the data or explicitly save it for
later processing.

@inc_file   eap_tls.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.
@param data             EAP-TLS message payload.
@param len              Number of bytes in EAP-TLS message payload (\p data).
@param eapRespData      On return, pointer to decrypted data.
@param eapRespLen       On return, pointer to length of decrypted data (\p
                        eapRespData).
@param eapRemData       On return, pointer to remaining EAP payload (unprocessed
                        data).
@param eapRemLen        On return, pointer to number of bytes in remaining EAP
                        payload (\p eapRemData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TLSstartRequest
@sa EAP_TLSPeerStart
@sa EAP_TLSSendData
@sa EAP_TLSgetKey

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSRecvData(ubyte *appSessionHdl, ubyte *tls_connection,
                ubyte *data, ubyte4 len,
                ubyte **eapRespData, ubyte4 *eapRespLen,
                ubyte **eapRemData, ubyte4 *eapRemLen);

/**
@brief      Encrypt EAP (clear text) data.
@details    This function encrypts EAP payload (clear text) data for sending in
            either direction. You can use this function to }harvest} or process
            packets that have already been added to the send buffer.

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@note A repeated call to this function overwrites the decrypted data. Therefore
your application should immediately process the data or explicitly save it for
later processing.

@inc_file   eap_tls.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.
@param data             EAP payload (clear text %data) to encrypt.
@param len              Number of bytes in EAP payload (\p data).
@param eapRespData      On return, pointer to encrypted data.
@param eapRespLen       On return, pointer to number of types in encrypted data
                        (\p eapRespData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TLSstartRequest
@sa EAP_TLSPeerStart
@sa EAP_TLSRecvData
@sa EAP_TLSgetKey

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSSendData(ubyte *appSessionHdl, ubyte *tls_connection,
                ubyte *data, ubyte4 len,
                ubyte **eapRespData, ubyte4 *eapRespLen);

/**
@brief      Set EAP-FAST authenticator ID.
@details    This function sets an EAP-FAST authenticator's ID (which is sent to
            a peer in an EAP-TLS \c Start message) to the specified value.

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@note A repeated call to this function overwrites the decrypted data. Therefore
your application should immediately process the data or explicitly save it for
later processing.

@inc_file   eap_tls.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.
@param authId           Value to assign to the authenticator ID.
@param authIdLen        Number of bytes in authenticator ID value (\p authId).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TLSstartRequest
@sa EAP_TLSPeerStart
@sa EAP_TLSRecvData
@sa EAP_TLSgetKey

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSSetAuthId(ubyte *appSessionHdl, ubyte *tls_connection,
                 ubyte *authId, ubyte2 authIdLen);

/**
@brief      Get a new EAP-TLS session key.
@details    This function generates an EAP-TLS session key and returns it (or \c
            NULL if there's no key) through the \p key parameter.

@ingroup    eap_tls_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_tls.h

@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.
@param key              On return, pointer to the newly generated key.
@param keyLen           Length (number of bytes) of key to generate.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TLSstartRequest
@sa EAP_TLSPeerStart
@sa EAP_TLSRecvData

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSgetKey(ubyte *tls_connection,ubyte *key,ubyte2 keyLen);

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
/*P: Function declaration for formAlert */
/**
@brief      Build a TLS \c Alert Messsage to be sent over EAP.
@details    This function builds an EAP-TLS \c Alert Message for the peer to
            send whenever there is a TLS error.

@ingroup    eap_tls_functions

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__
+ \c \__ENABLE_DIGICERT_SSL_ALERTS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_tls.h

@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.
@param alertClass       Alert class (\c SSLALERTLEVEL_WARNING or \c
                        SSLALERTLEVEL_FATAL)
@param alertId          Alert ID.
@param len              Number of bytes in EAP-TLS message payload (\p data)
@param eapRespData      On return, pointer to EAP-TLS Alert Payload.
@param eapRespLen       On return, pointer to length of the Payload (\p
                        eapRespData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_TLSstartRequest
@sa EAP_TLSPeerStart
@sa EAP_TLSSendData
@sa EAP_TLSRecvData

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSformAlert(ubyte *tls_connection,sbyte4 alertClass,sbyte4 alertId,ubyte4 len, ubyte **eapRespData, ubyte4 *eapRespLen);
#endif

/*P: New API that fetches the negotiated version */
/**
@brief      Get the negotiated version of an EAP-TLS packet.
@details    This function returns the negotiated version to be used for second
            stage.

@ingroup    eap_tls_functions

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_tls.h

@note This function is applicable to EAP peers and authenticators.

@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.
@param version          Pointer to allocated \c ubyte that on return contains
                        the negotiated version.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSGetNegotiatedVersion(ubyte *tls_connection, ubyte *version);

/*P: Method that fetches the MTU */
/**
@brief      Get the MTU (maximum transmission unit) value from the TLS control
            block.
@details    This function retrieves the MTU (maximum transmission unit) value of
            an EAP-TLS session.

@ingroup    eap_tls_functions

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_TLS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_tls.h

@param tls_connection   EAP-TLS session handle returned from
                        EAP_TLSCreateSession.
@param setMTU           Pointer to allocated \c ubyte that on return contains
                        the MTU.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_tls.h
*/
MOC_EXTERN MSTATUS
EAP_TLSgetMTU(ubyte *tls_connection, ubyte *setMTU);

#endif /* ((defined(__ENABLE_DIGICERT_EAP_TLS__) */
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */

#ifdef __cplusplus
}
#endif

#endif /* __EAP_TLS_H__  */
