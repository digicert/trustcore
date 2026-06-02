/**
 * @file  eap_srp.h
 * @brief EAP-SRP method API
 *
 * @details    EAP-SRP interface
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_SRP__
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

#ifndef __EAP_SRP_H__
#define __EAP_SRP_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))

#define EAP_SRP_CHALLENGE                   1
#define EAP_SRP_CLIENT_KEY                  1
#define EAP_SRP_SERVER_KEY                  2
#define EAP_SRP_CLIENT_VALIDATOR            2
#define EAP_SRP_SERVER_VALIDATOR            3
#define EAP_SRP_SUBTYPE3_RESPONSE           3
#define EAP_SRP_LIGHTWEIGHT_RECHALLENGE     4

#define EAP_SRP_SALTLEN                     10
#define EAP_SRP_RECHALLENGE_LEN             10


/*------------------------------------------------------------------*/

/** @private @internal */
typedef enum eapSrpAuthState_e
{
    EAPSRP_AUTH_STATE_NONE,
    EAPSRP_AUTH_STATE_CHALLENGE,
    EAPSRP_AUTH_STATE_SERVER_KEY,
    EAPSRP_AUTH_STATE_SERVER_VALIDATOR,
    EAPSRP_AUTH_STATE_SUCCESS,
    EAPSRP_AUTH_STATE_FAILURE,
    EAPSRP_AUTH_STATE_RECHALLENGE

} eapSrpAuthState_t;

/** @private @internal */
typedef enum eapSrpPeerState_e
{
    EAPSRP_PEER_STATE_NONE,
    EAPSRP_PEER_STATE_CLIENT_KEY,
    EAPSRP_PEER_STATE_CLIENT_VALIDATOR,
    EAPSRP_PEER_STATE_SUBTYPE3_RESPONSE

} eapSrpPeerState_t;


/*------------------------------------------------------------------*/

/**
@brief      Get the EAP payload from an SRP-SHA1 message received by an SRP peer.
@details    This function processes a message received by an SRP peer and
            returns the resultant EAP payload through the \p eapRespData
            parameter.

@ingroup    eap_srp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SRP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_srp.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param id               EAP packet ID.
@param data             EAP payload to process.
@param len              Number of bytes in EAP payload (\p data).
@param username         User name.
@param usernameLen      Number of bytes in user name (\p username).
@param passwordString   Session password for the response.
@param passLen          Number of bytes in session password (\p passwordString).
@param eapRespData      On return, pointer to EAP response payload.
@param eapRespLen       On return, pointer to number of bytes in EAP response
                        payload (\p eapRespData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_srp.h
*/
MOC_EXTERN MSTATUS EAP_SRPprocessPeer(ubyte *appSessionHdl, ubyte *eapSessionHdl, ubyte4 instanceId, ubyte id, ubyte *data, ubyte4 len, ubyte *username, ubyte4 usernameLen, ubyte *passwordString, ubyte4 passLen, ubyte **eapRespData, ubyte4 *eapRespLen);

/**
@brief      Get the EAP payload from a message received by an SRP authenticator.
@details    This function processes a message received by an SRP authenticator
            and returns the resultant EAP payload through the \p eapRespData
            parameter. Additionally, the response status is returned (through
            the \p code parameter), which your application should use to update
            the EAP processing state machine variables, \c methodState and \c
            decision, according to application requirements.

@ingroup    eap_srp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SRP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_srp.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param id               EAP packet ID.
@param data             EAP payload to process.
@param len              Number of bytes in EAP payload (\p data).
@param passwordString   Session password for the response.
@param passLen          Number of bytes in session password (\p passwordString).
@param eapRespData      On return, pointer to EAP response payload.
@param eapRespLen       On return, pointer to number of bytes in EAP response
                        payload (\p eapRespData).
@param code             On return, pointer to response status to include in
                        response packet (one of the \c eapCode enumerated values
                        in @ref eap_proto.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_srp.h
*/
MOC_EXTERN MSTATUS EAP_SRPprocessAuth(ubyte *appSessionHdl, ubyte *eapSessionHdl, ubyte4 instanceId, ubyte id, ubyte *data, ubyte4 len, ubyte *passwordString,ubyte4 passLen, ubyte **eapRespData, ubyte4 *eapRespLen, ubyte *code);

/**
@brief      Generate an SRP challenge packet.
@details    This function generates an SRP challenge and builds an \c
            EAP_SRP_CHALLENGE packet (which is returned through the \p reqData
            parameter). The SRP authenticator uses this function after it
            receives an identity response from the peer.

@ingroup    eap_srp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SRP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_srp.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param username         User name.
@param usernameLen      Number of bytes in user name.
@param password         Session password for the response.
@param passwordLen      Number of bytes in \p password.
@param method_type      On return, pointer to method type to include in response
                        packet (see \c eapMethodType enumerated values in @ref
                        eap_proto.h).
@param reqData          On return, pointer to generated EAP packet.
@param reqLen           On return, pointer to number of bytes in generated EAP
                        packet (\p reqData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_srp.h
*/
MOC_EXTERN MSTATUS EAP_SRPbuildChallenge(ubyte *eapSessionHdl, ubyte4 instanceId, ubyte *username, ubyte4 usernameLen, ubyte *password, ubyte4 passwordLen, eapMethodType *method_type, ubyte **reqData, ubyte4 *reqLen);

/**
@brief      Build an EAP-SRP lightweight challenge packet for reauthentication.
@details    This function builds an EAP-SRP lightweight challenge packet at the
            authenticator for reauthentication. (For information about
            lightweight challenges, refer to the following RFC Draft:
http://www3.ietf.org/proceedings/01dec/I-D/draft-ietf-pppext-eap-srp-03.txt )

@ingroup    eap_srp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SRP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_srp.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param method_type      On return, pointer to method type to include in response
                        packet (see \c eapMethodType enumerated values in @ref
                        eap_proto.h).
@param reqData          On return, pointer to generated EAP packet.
@param reqLen           On return, pointer to number of bytes in generated EAP
                        packet (\p reqData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_srp.h
*/
MOC_EXTERN MSTATUS EAP_SRPbuildLightweightChallenge(ubyte *eapSessionHdl, ubyte4 instanceId, eapMethodType *method_type, ubyte **reqData, ubyte4 *reqLen);

#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */

#ifdef __cplusplus
}
#endif

#endif /* __EAP_SRP_H__  */

