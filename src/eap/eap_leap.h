/**
 * @file  eap_leap.h
 * @brief EAP-LEAP method API
 *
 * @details    This header file contains definitions, enumerations, structures, and
 *            function declarations used by EAP LEAP helper functions.
 *
 * @since 1.41
 * @version 2.02 and later
 *
 * @flags
 * To enable any of this file's functions, the following flag must be defined in
 * moptions.h:
 * \c \__ENABLE_DIGICERT_EAP_LEAP__
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

#ifndef __EAP_LEAP_H__
#define __EAP_LEAP_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))

#define LEAP_CHALLENGE_LEN             (8)
#define LEAP_PW_HASH_HASH_LEN          (16)
#define LEAP_KEY_LEN                   (16)
#define LEAP_CHALLENGE_RESPONSE_LEN    (24)
#define LEAP_HDR_LEN                   (3)
#define LEAP_VERSION                   (0x01)


/*------------------------------------------------------------------*/

/** @private @internal */
typedef enum eapLeapState_e
{
    /* Peer States */
    LEAP_PEER_INIT,
    LEAP_PEER_WAIT_SUCCESS,
    LEAP_PEER_CHALLENGE_SENT,
    LEAP_PEER_DONE,

    /* Auth State */
    LEAP_AUTH_INIT,
    LEAP_AUTH_CHALLENGE_SENT,
    LEAP_AUTH_WAIT_CHALLENGE,
    LEAP_AUTH_DONE

} eapLeapState;

/** @private @internal */
typedef struct eapLeapCb_s
{
    void *appSessionHdl;
    ubyte pw_hash_hash[LEAP_PW_HASH_HASH_LEN];
    ubyte peerChallenge[LEAP_CHALLENGE_LEN];
    ubyte authChallenge[LEAP_CHALLENGE_LEN];
    ubyte peerResponse[LEAP_CHALLENGE_RESPONSE_LEN];
    ubyte authResponse[LEAP_CHALLENGE_RESPONSE_LEN];
    eapLeapState state;

} eapLeapCb_t;


/*------------------------------------------------------------------*/

/**
@brief      Create and initialize an EAP-LEAP session.
@details    This function creates and initializes an EAP-LEAP session using the
            specified parameters. The session handle is returned through the \p
            p_eapLeapCb parameter, and should be passed in all subsequent
            function calls for the EAP-LEAP session.

@ingroup    eap_leap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_LEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_leap.h

@param appCb        Application session handle (cookie given by the application
                    to identify the session).
@param p_eapLeapCb  On return, pointer to EAP-LEAP session handle.
@param sessionType  Either of the following \c eapSessionType enumerated values
                    (defined in @ref eap_proto.h):\n
\n
- \c EAP_SESSION_TYPE_PEER
- \c EAP_SESSION_TYPE_AUTHENTICATOR

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_leap.h
*/
MOC_EXTERN MSTATUS EAP_LEAPinitSession(void *appCb, void **p_eapLeapCb, ubyte sessionType);

/**
@brief      Generate a LEAP challenge packet.
@details    This function (which can be called by the authenticator or peer)
            builds the initial LEAP challenge, returning it through the \p
            eapRespData parameter. Additionally, this function updates the
            session handle's state (to \c LEAP_AUTH_CHALLENGE_SENT or \c
            LEAP_PEER_CHALLENGE_SENT), eliminating the need to call an
            additional function to manage the state flag.

@ingroup    eap_leap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_LEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_leap.h

@param leapCb       EAP-LEAP session handle returned from EAP_LEAPinitSession.
@param sessionType  One of the following \c eapSessionType enumerated values: \c
                    EAP_SESSION_TYPE_PEER or \c EAP_SESSION_TYPE_AUTHENTICATOR
                    (see @ref eap_proto.h).
@param identity     Pointer to peer identity (sent during identity
                    request/response).
@param identityLen  Number of bytes in peer identity string (\p identity).
@param eapRespData  On return, pointer to response packet.
@param eapRespLen   On return, pointer to number of bytes in response packet (\p
                    eapRespData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_leap.h
*/
MOC_EXTERN MSTATUS EAP_LEAP_buildChallenge(eapLeapCb_t *leapCb, ubyte sessionType, ubyte *identity, ubyte2 identityLen, ubyte **eapRespData, ubyte4 *eapRespLen);

/**
@brief      Process a LEAP packet received by a peer.
@details    This function processes a LEAP packet received by a peer, and
            returns the EAP code to be sent in reply through the \p p_sendCode
            parameter, the key (if any) through the \p pKey parameter, and the
            response packet through the \p eapRespData parameter. (The response
            packet can subsequently be transmitted by calling EAP_ulTransmit.)

@ingroup    eap_leap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_LEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_leap.h

@param eapLeapCb    EAP-LEAP session handle returned from EAP_LEAPinitSession.
@param code         Any of the \c eapCode enumerated values (see @ref
                    eap_proto.h).
@param data         Pointer to payload to process, in the format \c
                    <Type,&nbsp;LEAP&nbsp;packet>
@param len          Number of bytes in payload to process (\p data).
@param passwd       Pointer to password of the identity (EAP-LEAP session) being
                    authenticated.
@param passwdLen    Number of bytes in password (\p passwd).
@param identity     Pointer to peer identity (sent during identity
                    request/response).
@param identityLen  Number of bytes in peer identity string (\p identity).
@param p_sendCode   On return, pointer to EAP code to send in EAP response
                    packet.
@param pKey         On return, pointer to generated session key (if any) based
                    on MSCHAP encryption.
@param eapRespData  On return, pointer to LEAP response data packet.
@param eapRespLen   On return, pointer to number of bytes in LEAP response
                    packet (\p eapRespData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_leap.h
*/
MOC_EXTERN MSTATUS EAP_LEAP_processPeer(void *eapLeapCb, ubyte code, ubyte *data, ubyte4 len, ubyte *passwd, ubyte2 passwdLen, ubyte *identity, ubyte2 identityLen, eapCode *p_sendCode, ubyte **pKey, ubyte **eapRespData, ubyte4 *eapRespLen);

/**
@brief      Process a LEAP packet received by an authenticator.
@details    This function processes a LEAP packet received by an authenticator,
            and returns the EAP code to be sent in reply through the \p
            p_sendCode parameter, and the response packet through the \p
            eapRespData parameter. (The response packet can subsequently be
            transmitted by calling EAP_ulTransmit.)

@ingroup    eap_leap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_LEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_leap.h

@param eapLeapCb    EAP-LEAP session handle returned from EAP_LEAPinitSession.
@param code         Any of the \c eapCode enumerated values (see @ref
                    eap_proto.h).
@param data         Pointer to payload to process, in the format \c
                    <Type,&nbsp;LEAP&nbsp;packet>
@param len          Number of bytes in payload to process (\p data).
@param passwd       Pointer to password of the identity (EAP-LEAP session) being
                    authenticated.
@param passwdLen    Number of bytes in password (\p passwd).
@param p_sendCode   On return, pointer to EAP code to send in EAP response
                    packet.
@param eapRespData  On return, pointer to LEAP response data packet.
@param eapRespLen   On return, pointer to number of bytes in LEAP response
                    packet (\p eapRespData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_leap.h
*/
MOC_EXTERN MSTATUS EAP_LEAP_processAuth(void *eapLeapCb, ubyte code, ubyte *data, ubyte4 len, ubyte *passwd, ubyte2 passwdLen, eapCode *p_sendCode, ubyte **eapRespData, ubyte4 *eapRespLen);

/**
@brief      Get EAP-LEAP session's shared key.
@details    This function retrieves the EAP-LEAP session's shared key.

@warning    Before calling this function, be sure that the buffer pointed to by
            the \p key parameter is at least \c LEAP_KEY_LEN bytes (see @ref
            eap_leap.h); otherwise buffer overflow may occur.

@ingroup    eap_leap_functions

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_LEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_leap.h

@param eapLeapCb    EAP-LEAP session handle returned from EAP_LEAPinitSession.
@param key          Pointer to allocated buffer that on return contains the
                    shared key. (The allocated buffer must contain at least \c
                    LEAP_KEY_LEN bytes; otherwise buffer overflow may occur.)
@param keyLen       (Reserved for future use.)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_leap.h
*/
MOC_EXTERN MSTATUS EAP_LEAP_getKey (void *eapLeapCb,
                ubyte *key, ubyte4 keyLen /* 16 Bytes */);

/**
@brief      Delete an EAP-LEAP session.
@details    This function frees (releases) EAP LEAP resources and deletes an
            EAP-LEAP session.

@ingroup    eap_leap_functions

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_LEAP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_leap.h

@param p_eapLeapCb  EAP-LEAP session handle returned from EAP_LEAPinitSession.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_leap.h
*/
MOC_EXTERN MSTATUS EAP_LEAPdeleteSession(void *p_eapLeapCb);

#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */

#ifdef __cplusplus
}
#endif

#endif /* __EAP_LEAP_H__  */

