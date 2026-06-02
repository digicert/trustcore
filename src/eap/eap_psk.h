/**
 * @file  eap_psk.h
 * @brief EAP-PSK method API
 *
 * @details    EAP-PSK interface
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PSK__
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

#ifndef __EAP_PSK_H__
#define __EAP_PSK_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))

/** @private @internal */
typedef enum eapPSKEvt_e
{
    EAP_PSK_EVT_RECV_FIRST_PKT = 1,
    EAP_PSK_EVT_RECV_SECOND_PKT,
    EAP_PSK_EVT_RECV_THIRD_PKT,
    EAP_PSK_EVT_RECV_FOURTH_PKT,
    EAP_PSK_EVT_RECV_EXT_PKT
} eapPSKEvt;

/** @private @internal */
typedef enum eapPSKResultInd_e
{
    EAP_PSK_RESULT_CONTINUE = 1,
    EAP_PSK_RESULT_SUCCESS,
    EAP_PSK_RESULT_FAILURE
} eapPSKResultInd;

/** @private @internal */
typedef struct eapPSKConfig_s
{
    MSTATUS(*functionPtrEvtCallback)(ubyte * appCb,ubyte *eapPSKHdl,eapPSKEvt evt);
    eapSessionType sessionType;                                     /* PEER- AUTH */

} eapPSKConfig;

/**
@brief      Generates the AK/KDK Based upon PSK.
@details    Generate AK and KDK based upon PSK for the session.

@ingroup    eap_psk_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PSK__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_psk.h

@param eapPSKHdl    EAP PSK Session Handle.
@param psk          Pointer to the 16 Byte PSK.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_PSKInitSession
@sa EAP_PSKDeleteSession
@sa EAP_PSKAuthRequestFirst
@sa EAP_PSKPeerReplySecond
@sa EAP_PSKAuthRequestThird
@sa EAP_PSKPeerReplyFourth

@funcdoc    eap_psk.h
*/
MOC_EXTERN MSTATUS
EAP_PSKKeySetup (ubyte *eapPSKHdl, ubyte *psk);

/** @private @internal */
MOC_EXTERN MSTATUS
EAP_PSKAes128(ubyte * key,ubyte2 keyLen,ubyte *encr_data,ubyte2 encrLen,ubyte *iv);

/**
@brief      Inits the EAP PSK Session.
@details    Inititializes the EAP PSK Session and Returns the EAP PSK Handle.

@ingroup    eap_psk_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PSK__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_psk.h

@param appSessionHdl    Application Session Handle.
@param eapPSKHdl        Pointer to EAP PSK Session Handle.
@param eapPSKCfg        EAP PSK Config params, such as session type, callback
                        function pointer.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_PSKDeleteSession
@sa EAP_PSKAuthRequestFirst
@sa EAP_PSKPeerReplySecond
@sa EAP_PSKAuthRequestThird
@sa EAP_PSKPeerReplyFourth

@funcdoc    eap_psk.h
*/
MOC_EXTERN MSTATUS
EAP_PSKInitSession(ubyte * appSessionHdl,ubyte **eapPSKHdl, eapPSKConfig eapPSKCfg);

/**
@brief      Deletes the EAP PSK Session.
@details    Deletes the EAP PSK Session.

@ingroup    eap_psk_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PSK__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_psk.h

@param eapPSKHdl    Pointer to EAP PSK Session Handle.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_PSKInitSession
@sa EAP_PSKAuthRequestFirst
@sa EAP_PSKPeerReplySecond
@sa EAP_PSKAuthRequestThird
@sa EAP_PSKPeerReplyFourth

@funcdoc    eap_psk.h
*/
MOC_EXTERN MSTATUS
EAP_PSKDeleteSession(ubyte *eapPSKHdl);

/**
@brief      Forms the First Packet to be sent by the Authenticator.
@details    Forms the First Packet to be sent by the Authenticator.

@ingroup    eap_psk_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PSK__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_psk.h

@param eapPSKHdl    EAP PSK Session Handle.
@param rand_s       16 Byte Rand Generated by the Authenticator.
@param id_s         ID of the Authenticator to be sent.
@param id_s_len     Number of bytes in \p id_s.
@param request      Pointer to the buffer where the request is stored.
                    Application needs to delete it after use.
@param requestLen   Request buffer length (\p request).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_PSKInitSession
@sa EAP_PSKDeleteSession
@sa EAP_PSKPeerReplySecond
@sa EAP_PSKAuthRequestThird
@sa EAP_PSKPeerReplyFourth

@funcdoc    eap_psk.h
*/
MOC_EXTERN MSTATUS
EAP_PSKAuthRequestFirst(ubyte * eapPSKHdl,ubyte * rand_s,
                               ubyte * id_s, ubyte2 id_s_len,
                               ubyte ** request,ubyte4 *requestLen);

/**
@brief      Forms the Second Packet to be sent by the Peer.
@details    Forms the Second Reply to be sent by the Peer after receving the
            first request from the Authenticator.

@ingroup    eap_psk_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PSK__
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap_psk.h

@param eapPSKHdl    EAP PSK Session Handle.
@param rand_p       16 Byte random number generated by the Peer.
@param id_p         ID of the Peer to be sent.
@param id_p_len     Number of bytes in \p id_p.
@param reply        Pointer to the buffer where the reply is stored.
                    Application needs to delete it after use.
@param replyLen     Reply buffer length (\p reply).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_PSKInitSession
@sa EAP_PSKDeleteSession
@sa EAP_PSKAuthRequestFirst
@sa EAP_PSKAuthRequestThird
@sa EAP_PSKPeerReplyFourth

@funcdoc    eap_psk.h
*/
MOC_EXTERN MSTATUS
EAP_PSKPeerReplySecond(ubyte * eapPSKHdl,ubyte * rand_p,
                             ubyte * id_p, ubyte2 id_p_len,
                             ubyte ** reply,ubyte4 *replyLen);

/**
@brief      Forms the third request packet to be sent by the Authenticator.
@details    Forms the Third request to be sent by the Authenticator after
            receving the second packet from the Peer.

@ingroup    eap_psk_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PSK__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_psk.h

@param eapPSKHdl    EAP PSK Session Handle.
@param resultInd    Result indication to be sent to the Peer.
@param ext          Any EXTENSION data to be sent to the Peer.
@param extLen       EXTENSION data Length (\p ext).
@param id           EAP ID from the received EAP header for calculation of
                    channel.
@param request      Pointer to the buffer where the request is stored.
                    Application needs to delete it after use.
@param requestLen   Request Buffer Length (\p request).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_PSKInitSession
@sa EAP_PSKDeleteSession
@sa EAP_PSKPeerReplySecond
@sa EAP_PSKAuthRequestThird
@sa EAP_PSKPeerReplyFourth

@funcdoc    eap_psk.h
*/
MOC_EXTERN MSTATUS
EAP_PSKAuthRequestThird(ubyte * eapPSKHdl,eapPSKResultInd resultInd,
                             ubyte * ext, ubyte2 extLen,ubyte id,
                             ubyte ** request,ubyte4 *requestLen);

/**
@brief      Forms the fourth reply packet to be sent by the Peer.
@details    Forms the fourth reply to be sent by the Peer after receving the
            third Packet from the Authenticator.

@ingroup    eap_psk_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PSK__
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap_psk.h

@param eapPSKHdl    EAP PSK Session Handle.
@param resultInd    Result Indication to be sent to the Authenticator.
@param ext          Any EXTENSION data to be sent to the Authenticator.
@param extLen       EXTENSION data Length (\p ext).
@param id           EAP ID from the received EAP header for calculation of
                    channel.
@param reply        Pointer to the buffer where the reply is stored.
                    Application needs to delete it after use.
@param replyLen     Reply buffer length (\p reply).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_PSKInitSession
@sa EAP_PSKDeleteSession
@sa EAP_PSKAuthRequestFirst
@sa EAP_PSKPeerReplySecond
@sa EAP_PSKAuthRequestThird
@sa EAP_PSKPeerReplyFourth

@funcdoc    eap_psk.h
*/
MOC_EXTERN MSTATUS
EAP_PSKPeerReplyFourth(ubyte * eapPSKHdl,eapPSKResultInd resultInd,
                             ubyte * ext, ubyte2 extLen,ubyte id,
                             ubyte ** reply,ubyte4 *replyLen);

/**
@brief      Processes the incoming EAP PSK data message.
@details    Processes the incoming EAP PSK message and verifies the responses
            and informs the application about the state change and status.

@ingroup    eap_psk_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PSK__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_psk.h

@param eapPSKHdl    EAP PSK Session Handle.
@param data         Incoming PSK data.
@param dataLen      Number of bytes in \p data.
@param id           EAP ID from the received EAP header for calculation of
                    channel.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_PSKInitSession
@sa EAP_PSKDeleteSession
@sa EAP_PSKPeerReplySecond
@sa EAP_PSKAuthRequestThird
@sa EAP_PSKPeerReplyFourth

@funcdoc    eap_psk.h
*/
MOC_EXTERN MSTATUS
EAP_PSKProcessMsg(ubyte * eapPSKHdl,ubyte * data,
                         ubyte4 dataLen,ubyte id);

/**
@brief      Returns the generated session keys.
@details    Returns the generated keys for the session.

@ingroup    eap_psk_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PSK__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_psk.h

@param eapPSKHdl    EAP PSK Session Handle.
@param tek          On return, pointer to the TEK (16 bytes).
@param msk          On return, pointer to the MSK (64 Bytes).
@param emsk         On return, pointer to the EMSK (64bytes).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_PSKInitSession
@sa EAP_PSKDeleteSession
@sa EAP_PSKAuthRequestFirst
@sa EAP_PSKPeerReplySecond
@sa EAP_PSKAuthRequestThird
@sa EAP_PSKPeerReplyFourth

@funcdoc    eap_psk.h
*/
MOC_EXTERN MSTATUS
EAP_PSKgetKeys(ubyte * eapPSKHdl,ubyte **tek,ubyte **msk,ubyte **emsk);

/**
@brief      Returns the ID_S received from the Authenticator.
@details    Returns the ID_S received from the Authenticator.

@ingroup    eap_psk_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PSK__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_psk.h

@param eapPSKHdl    EAP PSK Session Handle.
@param id_s         On return, pointer to the ID_S.
@param id_s_len     On return, pointer to the length of \p id_s.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_PSKInitSession
@sa EAP_PSKDeleteSession
@sa EAP_PSKAuthRequestFirst
@sa EAP_PSKPeerReplySecond
@sa EAP_PSKAuthRequestThird
@sa EAP_PSKPeerReplyFourth

@funcdoc    eap_psk.h
*/
MOC_EXTERN MSTATUS
EAP_PSKgetID_S(ubyte * eapPSKHdl,ubyte **id_s,ubyte2 *id_s_len);

/**
@brief      Returns the ID_P received from the Peer.
@details    Returns the ID_P received from the Peer.

@ingroup    eap_psk_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PSK__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_psk.h

@param eapPSKHdl     EAP PSK Session Handle.
@param id_p          On return, pointer to the ID_P.
@param id_p_len      On return, pointer to the length of \p id_p.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_PSKInitSession
@sa EAP_PSKDeleteSession
@sa EAP_PSKAuthRequestFirst
@sa EAP_PSKPeerReplySecond
@sa EAP_PSKAuthRequestThird
@sa EAP_PSKPeerReplyFourth

@funcdoc    eap_psk.h
*/
MOC_EXTERN MSTATUS
EAP_PSKgetID_P(ubyte * eapPSKHdl,ubyte **id_p,ubyte2 *id_p_len);

/**
@brief      Returns the EXTENSION data received.
@details    Returns the EXTENSION data received.

@ingroup    eap_psk_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PSK__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_psk.h

@param eapPSKHdl    EAP PSK Session Handle.
@param ext          On return, pointer to the EXTENSION data.
@param extLen       On return, pointer to the length of \p ext.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_PSKInitSession
@sa EAP_PSKDeleteSession
@sa EAP_PSKAuthRequestFirst
@sa EAP_PSKPeerReplySecond
@sa EAP_PSKAuthRequestThird
@sa EAP_PSKPeerReplyFourth

@funcdoc    eap_psk.h
*/
MOC_EXTERN MSTATUS
EAP_PSKgetEXT(ubyte * eapPSKHdl,ubyte **ext,ubyte2 *extLen);

/**
@brief      Returns the result indication received.
@details    Returns the result indication received.

@ingroup    eap_psk_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PSK__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_psk.h

@param eapPSKHdl    EAP PSK Session Handle.
@param resInd       On return, pointer to the result indication.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_PSKInitSession
@sa EAP_PSKDeleteSession
@sa EAP_PSKAuthRequestFirst
@sa EAP_PSKPeerReplySecond
@sa EAP_PSKAuthRequestThird
@sa EAP_PSKPeerReplyFourth

@funcdoc    eap_psk.h
*/
MOC_EXTERN MSTATUS
EAP_PSKgetResultInd(ubyte * eapPSKHdl,eapPSKResultInd *resInd);

#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */

#ifdef __cplusplus
}
#endif

#endif /* __EAP_PSK_H__  */
