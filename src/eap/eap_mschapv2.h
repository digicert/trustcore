/**
 * @file  eap_mschapv2.h
 * @brief EAP-MSCHAPv2 method API
 *
 * @details    EAP-MSCHAPv2 interface
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__
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

#ifndef __EAP_MSCHAP_H__
#define __EAP_MSCHAP_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))

#define MSCHAPV2_CHALLENGE    (1)
#define MSCHAPV2_RESPONSE     (2)
#define MSCHAPV2_SUCCESS      (3)
#define MSCHAPV2_FAILURE      (4)

#define MSCHAPV2_RESP_LENGTH  (49)
#define MSCHAPV2_CHAL_LENGTH  (16)
#define MSCHAPV2_AUTHENTICATOR_LENGTH (42)

/**
@brief      Build a response to send to the authenticator.
@details    This function builds a response to send to the authenticator based
            on a challenge received by a peer.

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param appSessionHdl    Application session handle (cookie given by the
                        application to identify the session).
@param data             Pointer to received challenge packet, which must be in
                        the format \c <Type,&nbsp;MSCHAP&nbsp;packet>.
@param datalen          Number of bytes in received challenge packet (\p data).
@param UserName         Pointer to MS-CHAP-V2 session username to use for EAP
                        response.
@param UserNameLen      Number of bytes in session username (\p UserName).
@param passwordString   Pointer to MS-CHAP-V2 session password to use for
                        response.
@param passLen          Number of bytes in session password (\p passwordString).
@param peerChallenge    On return, pointer to peer challenge sent to
                        authenticator (piggybacked to the response to the
                        challenge originally sent by the authenticator).
@param authChallenge    On return, pointer to authenticator challenge value
                        extracted from the data packet; returned to the
                        application for subsequent inclusion in a call to
                        EAP_MSCHAPpeerResponse.
@param NtAuthenticator  On return, pointer to NT Authenticator (the \p
                        eapRespData plus the \p UserName); returned to the
                        application for subsequent inclusion in a call to
                        EAP_MSCHAPpeerResponse or
                        EAP_MSCHAPcheckAuthenticatorResponse.
@param eapRespData      On return, pointer to resultant authentication response.
@param eapRespLen       On return, pointer to number of bytes resultant
                        authentication response (\p eapRespData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_MSCHAPstartRequest
@sa EAP_MSCHAPProcessAuth

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS
EAP_MSCHAPProcessPeer (ubyte *appSessionHdl,
                    ubyte *data,ubyte4 datalen,
                    ubyte *UserName,ubyte4 UserNameLen,
                    ubyte *passwordString,ubyte4 passLen,
                    ubyte *peerChallenge,ubyte *authChallenge,
                    ubyte *NtAuthenticator,
                    ubyte **eapRespData, ubyte4 *eapRespLen);

/**
@brief      Build a challenge request.
@details    This function builds a challenge request based on the specified
            challenge data for the authenticator to transmit to the peer.

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param appSessionHdl    Application session handle (cookie given by the
                        application to identify the session).
@param identity         Pointer to user identity.
@param identityLen      Number of bytes in user identity (\p identity).
@param challenge        Pointer to challenge data to use in challenge request.
@param eapReqData       On return, pointer to resultant challenge request.
@param eapReqLen        On return, pointer to number of bytes of resultant
                        challenge request (\p eapReqData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS
EAP_MSCHAPstartRequest (ubyte *appSessionHdl,
                    ubyte * identity, ubyte2 identityLen,
                    ubyte * challenge,
                    ubyte **eapReqData, ubyte4 *eapReqLen);

/**
@brief      Determine whether a peer response is valid, build the resultant
            SUCCESS/FAIL response, and if SUCCESS, send the response.
@details    This function (called by the authenticator) validates an MSCHAP peer
            response and in turn builds an EAP response indicating success or
            failure. In the case of success, the authenticator also sends the
            response to the peer's challenge.

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param appSessionHdl    Application session handle (cookie given by the
                        application to identify the session).
@param data             Pointer to EAP payload containing MSCHAP peer response,
                        which must be in the format \c
                        <Type,&nbsp;MSCHAP&nbsp;packet>.
@param datalen          Number of bytes in EAP payload (\p data).
@param UserName         Pointer to MS-CHAP-V2 session username to use for EAP
                        response.
@param UserNameLen      Number of bytes in session username (\p UserName).
@param succMsg          Pointer to desired success message string to send to
                        peer.
@param succMsgLen       Number of bytes in desired success message (\p succMsg).
@param failMsg          Pointer to desired fail message string to send to peer.
@param failMsgLen       Number of bytes in desired fail message (\p failMsg).
@param passwordString   Pointer to MS-CHAP-V2 session password to use for
                        response.
@param passLen          Number of bytes in session password (\p passwordString).
@param authChallenge    Pointer to original authenticator challenge that was
                        sent to the peer by EAP_MSCHAPstartRequest.
@param NtResponse       On return, pointer to NT Authenticator for this session.
@param eapReqData       On return, pointer to EAP response message.
@param eapReqLen        On return, pointer to number of bytes in EAP response
                        message (\p eapReqData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_MSCHAPstartRequest
@sa EAP_MSCHAPProcessAuth

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS
EAP_MSCHAPProcessAuth (ubyte *appSessionHdl,
                    ubyte *data,ubyte4 datalen,
                    ubyte *UserName,ubyte4 UserNameLen,
                    ubyte *succMsg,ubyte4 succMsgLen,
                    ubyte *failMsg,ubyte4 failMsgLen,
                    ubyte *passwordString,ubyte4 passLen,
                    ubyte *authChallenge,ubyte *NtResponse,
                    ubyte **eapReqData, ubyte4 *eapReqLen);

/**
@brief      Determine whether an authenticator response to a peer challenge is
            valid and build the resultant SUCCESS/FAIL response.
@details    This function (used by the peer) determines whether the
            authenticator response to the peer's previous challenge is valid,
            returns the results (\c TRUE or \c FALSE) through the \p cmp
            parameter, and builds the resultant SUCCESS/FAIL response.

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param appSessionHdl    Application session handle (cookie given by the
                        application to identify the session).
@param data             Pointer to EAP payload containing MSCHAP authenticator
                        response, which must be in the format \c
                        <Type,&nbsp;MSCHAP&nbsp;packet>.
@param datalen          Number of bytes in EAP payload (\p data).
@param passwordString   Pointer to MS-CHAP-V2 session password to use for
                        response.
@param passLen          Number of bytes in session password (\p passwordString).
@param peerResponse     Calculated NT Authenticator value (returned from
                        EAP_MSCHAPProcessPeer) originally sent to the
                        authenticator.
@param peerChallenge    Pointer to original peer challenge that was sent to the
                        authenticator
@param authChallenge    Pointer to original challenge response received from the
                        authenticator by EAP_MSCHAPProcessPeer.
@param UserName         Pointer to MS-CHAP-V2 session username to use for EAP
                        response.
@param UserNameLen      Number of bytes in session username (\p UserName).
@param eapRespData      On return, pointer to EAP response message.
@param eapRespLen       On return, pointer to number of bytes in EAP response
                        message (\p eapRespData).
@param cmp              On return, pointer to result of authenticator-peer
                        mutual challenge result: \c TRUE or \c FALSE.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_MSCHAPstartRequest
@sa EAP_MSCHAPProcessAuth
@sa EAP_MSCHAPProcessPeer

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS
EAP_MSCHAPpeerResponse (ubyte *appSessionHdl,
                    ubyte *data,ubyte2 datalen,
                    ubyte *passwordString,ubyte2 passLen,
                    ubyte * peerResponse/*NT */,
                    ubyte * peerChallenge,
                    ubyte * authChallenge,
                    ubyte * UserName,ubyte2 UserNameLen,
                    ubyte **eapRespData, ubyte4 *eapRespLen,
                    byteBoolean *cmp);

/**
@brief      Generate an authenticator response.
@details    This function (used by Mocana internal code) generates an
            authenticator response.

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param Password         Pointer to MS-CHAP-V2 session password to use for
                        response.
@param PasswordLen      Number of bytes in MS-CHAP-V2 session password (\p
                        Password).
@param NtResponse       Calculated NT Authenticator value (returned from
                        EAP_MSCHAPProcessPeer).
@param PeerChallenge    Pointer to original peer challenge sent by
                        EAP_MSCHAPProcessPeer.
@param AuthenticatorChallenge   Pointer to original authenticator challenge
                        built by EAP_MSCHAPProcessPeer.
@param UserName         Pointer to MS-CHAP-V2 session username to use for EAP
                        response.
@param UserNameLen      Number of bytes in MS-CHAP-V2 session username (\p
                        Username).
@param AuthenticatorResponse    On return, pointer to response sent by the
                        authenticator to the peer in the challenge Success
                        message, in the format "S=" followed by 40 ASCII
                        hexadecimal digits.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_MSCHAPstartRequest
@sa EAP_MSCHAPProcessAuth

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS   EAP_MSCHAPgenerateAuthenticatorResponse(
                    ubyte * Password,
                    ubyte2  PasswordLen,
                    ubyte*  NtResponse,
                    ubyte*  PeerChallenge,
                    ubyte*  AuthenticatorChallenge,
                    ubyte*  UserName,
                    ubyte2  UserNameLen,
                    ubyte*  AuthenticatorResponse);

/**
@brief      Determine an MSCHAP authenticator response's status and include it
            in a new EAP response.
@details    This function (called by the peer) validates an MSCHAP authenticator
            response (by calling EAP_MSCHAPgenerateAuthenticatorResponse) and in
            turn builds an EAP response indicating the authenticator's response
            status.

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param Password         Pointer to MS-CHAP-V2 session password to use for
                        response.
@param PasswordLen      Number of bytes in session password (\p Password).
@param NtResponse       Calculated NT Authenticator value (returned from
                        EAP_MSCHAPProcessPeer).
@param PeerChallenge    Pointer to original peer challenge sent by
                        EAP_MSCHAPProcessPeer.
@param AuthenticatorChallenge   Pointer to original authenticator challenge
                        built by EAP_MSCHAPProcessPeer.
@param UserName         Pointer to MS-CHAP-V2 session username to use for
                        response.
@param UserNameLen      Number of bytes in session username (\p Username).
@param ReceivedResponse Pointer to response sent by the authenticator to the
                        peer in the challenge Success message. (If the challenge
                        fails, this value doesn't change.)
@param ResponseOK       On return, pointer to result to return to peer: \c TRUE
                        if the challenge succeeded, \c FALSE otherwise.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_MSCHAPstartRequest
@sa EAP_MSCHAPProcessAuth

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS   EAP_MSCHAPcheckAuthenticatorResponse(
                    ubyte * Password,
                    ubyte2  PasswordLen,
                    ubyte * NtResponse,
                    ubyte * PeerChallenge,
                    ubyte * AuthenticatorChallenge,
                    ubyte * UserName,
                    ubyte2  UserNameLen,
                    ubyte*  ReceivedResponse,
                    byteBoolean *         ResponseOK);

/**
@brief      Build an MS-CHAP-V2 NT response.
@details    This function builds an NT Response for MS-CHAP-V2 based on the
            specified authenticator and peer challenges, peer username, and peer
            password.

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param AuthenticatorChallenge   Pointer to original authenticator challenge
                                built by EAP_MSCHAPProcessPeer.
@param PeerChallenge            Pointer to original peer challenge sent by
                                EAP_MSCHAPProcessPeer.
@param UserName                 Pointer to peer username.
@param UserNameLen              Number of bytes in peer username (\p UserName).
@param Password                 Pointer to MS-CHAP-V2 session password to use
                                for response.
@param PasswordLen              Number of bytes in MS-CHAP-V2 session password
                                (\p Password).
@param Response                 On return, pointer to resultant response.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_MSCHAPstartRequest
@sa EAP_MSCHAPProcessAuth

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS   EAP_MSCHAPgenerateNTResponse(
                    ubyte * AuthenticatorChallenge,
                    ubyte * PeerChallenge,
                    ubyte * UserName,
                    ubyte2  UserNameLen,
                    ubyte * Password,
                    ubyte2  PasswordLen,
                    ubyte * Response);

/**
@brief      Build an MS-CHAP-V0 NT response.
@details    This function builds an NT Response for MS-CHAP-V0 based on the
            specified authenticator challenge and peer password.

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param AuthenticatorChallenge   Pointer to original authenticator challenge
                                built by EAP_MSCHAPProcessPeer.
@param Password                 Pointer to peer password to use for response.
@param PasswordLen              Number of bytes in peer password (\p Password).
@param Response                 On return, pointer to resultant response.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS
EAP_MSCHAPv0generateNTResponse(ubyte * AuthenticatorChallenge,
                               ubyte * Password,
                               ubyte2  PasswordLen,
                               ubyte * Response);

/**
@brief      Generate a send/receive client/server session key.
@details    This function generates a session key for send/receive and
            client/server, as specified, from the specified MSK (master session
            key). The combination of the send and server parameter values
            determine which keys are generated. The send-side key on the server
            (authenticator) must match the receive-side key on the client (peer).

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param masterKey        Pointer to MSK value.
@param sessionKey       On return, pointer to resultant session key.
@param sessionKeyLen    Length (number of bytes) of session key to generate.
@param send             \c 0 to specify a receive session key; non-zero for a
                        send session key.
@param server           \c 0 to specify a server-side (authenticator) key;
                        non-zero for a client-side (peer) key.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_MSCHAPstartRequest
@sa EAP_MSCHAPProcessAuth

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS
EAP_MSCHAPgenerateSessionKey(
                    ubyte*  masterKey ,
                    ubyte*  sessionKey ,
                    ubyte2  sessionKeyLen,
                    byteBoolean send,
                    byteBoolean server);

/**
@brief      Generate an MSK (master session key).
@details    This function generates an MSK (master session key).

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param Password         Pointer to MS-CHAP-V2 session password to use for
                        response.
@param PasswordLen      Number of bytes in MS-CHAP-V2 session password (\p
                        Password).
@param NtResponse       Calculated NT Authenticator value (returned from
                        EAP_MSCHAPProcessPeer).
@param MasterKey        On return, pointer to MSK value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_MSCHAPstartRequest
@sa EAP_MSCHAPProcessAuth

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS
EAP_MSCHAPgenerateMasterKey(
                    ubyte * Password,
                    ubyte2  PasswordLen,
                    ubyte*  NtResponse,
                    ubyte*  MasterKey);

/**
@brief      Get a hexadecimal representation of binary data.
@details    This function creates a hexadecimal representation of binary data.

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param szBin    Pointer to binary data to represent as hexadecimal.
@param szHex    On return, pointer to hexadecimal representation of the \p szBin
                data.
@param len      Number of bytes of binary data (\p szBin).

@return     None.

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN void
EAP_MSCHAPbin2hex (const ubyte *szBin, sbyte *szHex, ubyte4 len);

/**
@brief      Build an MSCHAP v0 response to the specified challenge and password
            hash.
@details    This function builds an MSCHAP v0 response to the specified
            challenge and password hash.

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param Challenge    Pointer to challenge value.
@param PasswordHash Pointer to password hash.
@param Response     On return, pointer to response.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS
EAP_MSCHAPChallengeResponse(
            ubyte*  Challenge,
            ubyte*  PasswordHash,
            ubyte*  Response);

/**
@brief      Get an irreversible hash of a password hash (using MD4).
@details    This function generates an irreversible hash of a password hash
            (using MD4).

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param PasswordHash         Pointer to password hash.
@param PasswordHashHash     On return, pointer to generated hash.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_MSCHAPstartRequest
@sa EAP_MSCHAPProcessAuth

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS
EAP_MSCHAPHashNtPasswordHash(
          ubyte * PasswordHash,
          ubyte * PasswordHashHash);

/**
@brief      Get a password hash (using MD4).
@details    This function generates a password hash (disregarding any
            terminating \c NULL) using MD4.

@ingroup    eap_mschap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param Password         Pointer to peer password.
@param PasswordLen      Number of bytes in peer password (\p Password).
@param PasswordHash     On return, pointer to generated password hash.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS   EAP_MSCHAPNtPasswordHash(
            ubyte * Password,
            ubyte2  PasswordLen,
            ubyte * PasswordHash);

/**
@brief      Get a 16-byte challenge value for an MSCHAPv2 exchange.
@details    This function returns (through the \p buf parameter) a 16-byte
            challenge value.

@ingroup    eap_mschap_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_mschapv2.h

@param buf  On return, pointer to 16-byte challenge value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_mschapv2.h
*/
MOC_EXTERN MSTATUS
EAP_MSCHAPV2_getChallenge(ubyte *buf);

#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */

#ifdef __cplusplus
}
#endif

#endif /* __EAP_MSCHAP_H__  */
