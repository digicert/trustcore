/**
 * @file  eap_md5.h
 * @brief EAP-MD5 method API
 *
 * @details    This header file contains function declarations for EAP MD5 helper
 *            functions.
 *
 * @since 1.41
 * @version 2.02 and later
 *
 * @flags
 * To enable any of this file's functions, the following flag must be defined in
 * moptions.h:
 * \c \__ENABLE_DIGICERT_EAP_MD5__
 *
 * Additionally, at least one of the following flags must be defined in moptions.h:
 * \c \__ENABLE_DIGICERT_EAP_AUTH__
 * \c \__ENABLE_DIGICERT_EAP_PEER__
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

#ifndef __EAP_MD5_H__
#define __EAP_MD5_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))

/**
@brief      Generate an MD5 challenge response.
@details    This function calculates an MD5 hash (the challenge response) and
            returns the resultant EAP payload. Your application should use this
            function for MD5 peer packet processing.

@ingroup    eap_md5_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MD5__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_md5.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param id               EAP packet ID
@param data             EAP request payload, in the following format \c
                        <Type,&nbsp;Chlg&nbsp;Len,&nbsp;Challenge>.
@param len              Number of bytes in EAP request payload.
@param passwordString   Session password for the response.
@param passLen          Number of bytes in \p passwordString.
@param eapRespData      On return, pointer to EAP response payload.
@param eapRespLen       On return, pointer to number of bytes in \p eapRespData.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_MD5_getChallenge
@sa EAP_MD5ProcessAuth

@funcdoc    eap_md5.h
*/
MOC_EXTERN MSTATUS
EAP_MD5ProcessPeer (ubyte *appSessionHdl, ubyte *eapSessionHdl,
                    ubyte4 instanceId, ubyte id,
                    ubyte *data, ubyte4 len,
                    ubyte *passwordString,ubyte4 passLen,
                    ubyte **eapRespData, ubyte4 *eapRespLen);

/** @private @internal */
MOC_EXTERN MSTATUS
EAP_MD5ChallengeResponse (ubyte id,
                           ubyte *challenge, ubyte4 challengeLen,
                           ubyte *passwordString,ubyte4 passLen,
                           ubyte *eapRespData, ubyte4 *eapRespLen);

/**
@brief      Generate a challenge for an MD5 request.
@details    This function generates a challenge for an MD5 request. The
            challenge is in the form of random data that's used as a
            nonce&mdash;a unique, random value inserted into a message to
            protect against replays&mdash;to hash a user's password using the
            MD5 algorithm. The challenge sequence is as follows:

- The server (authenticator) sends the nonce.
- The client (peer) hashes a clear text password using the nonce with MD5, and
  then sends the reply to the server.
- The server hashes the same clear text password using the same nonce and MD5
  algorithm, and then compares the result with the result sent by the peer.
  Matching client and server results indicate a successful challenge.

@ingroup    eap_md5_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MD5__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_md5.h

@param buf  On return, pointer to buffer containing the challenge.
@param len  Length of challenge to generate.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_MD5ProcessAuth
@sa EAP_MD5ProcessPeer

@funcdoc    eap_md5.h
*/
MOC_EXTERN MSTATUS
EAP_MD5_getChallenge(ubyte *buf, ubyte4 len);

/**
@brief      Validate an MD5 challenge response.
@details    This function validates an MD5 challenge response, indicating the
            result by its function return: \c OK, \c
            ERR_EAP_MD5_INVALID_CHALLENGE_LENGTH, or \c ERR_EAP_MD5_AUTH_FAILURE.
            Your application should use this function to process responses
            received from peers.

@ingroup    eap_md5_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_MD5__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_md5.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param code             Any of the \c eapCode enumerated values (see @ref
                        eap_proto.h).
@param id               EAP packet ID
@param data             EAP request payload, in the following format: \c
                        <Type,&nbsp;Chlg&nbsp;Len,&nbsp;Challenge>.
@param len              Number of bytes in EAP request payload.
@param passwordString   Session password for the response.
@param passLen          Number of bytes in \p passwordString.
@param challenge        Pointer to previously sent challenge.
@param challengeLen     Number of bytes in \p challenge.
@param cmp              On return, pointer to challenge comparison result (\c 0
                        indicates a match).

@return     One of the following:\n
\n
- \c OK (0) if successful.
- \c ERR_EAP_MD5_INVALID_CHALLENGE_LENGTH if the EAP request's \c Chlg&nbsp;Len
  doesn't match the length of the previously sent challenge (as specified by the
  \p challengeLen parameter value.
- \c ERR_EAP_MD5_AUTH_FAILURE if the challenge is invalid.

@sa EAP_MD5_getChallenge
@sa EAP_MD5ProcessPeer

@funcdoc    eap_md5.h
*/
MOC_EXTERN MSTATUS
EAP_MD5ProcessAuth (ubyte *appSessionHdl, ubyte *eapSessionHdl,
                    ubyte4 instanceId, eapCode code, ubyte id,
                    ubyte *data, ubyte4 len,ubyte *passwordString,
                    ubyte4 passLen, ubyte *challenge, ubyte4 challengeLen,
                    sbyte4 *cmp);

#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */

#ifdef __cplusplus
}
#endif

#endif /* __EAP_MD5_H__  */
