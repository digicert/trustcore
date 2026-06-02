/**
 * @file  eap_gtc.h
 * @brief EAP-GTC method API
 *
 * @details    This header file contains function declarations for EAP GTC helper
            functions.
 *
 * @since 1.41
 * @version 2.02 and later
 *
 * @flags
 * To enable any of this file's functions, the following flag must be defined in
 * moptions.h:
 * \c \__ENABLE_DIGICERT_EAP_GTC__
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

#ifndef __EAP_GTC_H__
#define __EAP_GTC_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))

/**
@brief      Generate a token response.
@details    This function generates a token response and returns the resultant
            EAP payload. Your application should use this function for GTC peer
            packet processing.

@ingroup    eap_gtc_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_GTC__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_gtc.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param passwordString   Session password for the response.
@param passLen          Number of bytes in \p passwordString.
@param eapRespData      On return, pointer to EAP response payload.
@param eapRespLen       On return, pointer to number of bytes in \p eapRespData.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_GTCstartRequest
@sa EAP_GTCProcessAuth

@funcdoc    eap_gtc.h
*/
MOC_EXTERN MSTATUS
EAP_GTCProcessPeer (ubyte *appSessionHdl,
                    ubyte *passwordString,ubyte4 passLen,
                    ubyte **eapRespData, ubyte4 *eapRespLen);

/**
@brief      Builds an EAP request.
@details    This function builds an EAP request based on the specified data.

@ingroup    eap_gtc_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_GTC__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_gtc.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param msgString        Pointer to message data.
@param msgLen           Number of bytes in \p msgString.
@param eapReqData       On return, pointer to EAP request payload.
@param eapReqLen        On return, pointer to number of bytes in \p eapReqData.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_GTCProcessAuth
@sa EAP_GTCProcessPeer

@funcdoc    eap_gtc.h
*/
MOC_EXTERN MSTATUS
EAP_GTCstartRequest (ubyte *appSessionHdl,
                    ubyte *msgString,ubyte4 msgLen,
                    ubyte **eapReqData, ubyte4 *eapReqLen);

/**
@brief      Validate a token response.
@details    This function validates a token response, indicating the result by
            its function return: \c OK, \c ERR_EAP_GTC_INVALID_TOKEN_LENGTH, or
            \c ERR_EAP_GTC_AUTH_FAILURE. Your application should use this
            function to process responses received from peers.

@ingroup    eap_gtc_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_GTC__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_gtc.h

@param appSessionHdl    Cookie given by the application to identify the session.
@param data             EAP request payload, in the following format: \c
                        <Type,&nbsp;Chlg&nbsp;Len,&nbsp;Challenge>.
@param len              Number of bytes in EAP request payload.
@param passwordString   Session password for the response.
@param passLen          Number of bytes in \p passwordString.
@param cmp              On return, pointer to challenge comparison result (\c 0
                        indicates a match).

@return     One of the following:\n
\n
- \c OK (0) if successful.
- \c ERR_EAP_GTC_INVALID_TOKEN_LENGTH if the EAP request's \c Chlg&nbsp;Len
  doesn't match the length of the previously sent challenge (as specified by the
  \p passLen parameter value).
- \p ERR_EAP_GTC_AUTH_FAILURE if the token is invalid.

@sa EAP_GTCstartRequest
@sa EAP_GTCProcessAuth

@funcdoc    eap_gtc.h
*/
MOC_EXTERN MSTATUS
EAP_GTCProcessAuth (ubyte *appSessionHdl,
                    ubyte *data, ubyte4 len,ubyte *passwordString,
                    ubyte4 passLen,
                    sbyte4 *cmp);

#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */

#ifdef __cplusplus
}
#endif

#endif /* __EAP_GTC_H__  */
