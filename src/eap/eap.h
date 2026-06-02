/**
 * @file  eap.h
 * @brief EAP (Extensible Authentication Protocol) developer API
 *
 * @details    EAP API definitions, structures, and function declarations
 * @since      1.41
 * @version    1.41 and later
 *
 * @flags      Compilation flags required:
 *     To build products using this header file, at least one of the following flags
*      must be defined in moptions.h:
 *     + \c \__ENABLE_DIGICERT_EAP_PEER__
 *     + \c \__ENABLE_DIGICERT_EAP_AUTH__
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


/*------------------------------------------------------------------*/

#ifndef __EAP_HEADER__
#define __EAP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif
/* check for possible build configuration errors */

#if defined(MOC_LITTLE_ENDIAN)
#define EAP_NTOHS(A) SWAPWORD(A)
#define EAP_HTONS(A) SWAPWORD(A)
#define EAP_NTOHL(A) SWAPDWORD(A)
#define EAP_HTONL(A) SWAPDWORD(A)
#elif defined(MOC_BIG_ENDIAN)
#define EAP_NTOHS(A) (A)
#define EAP_HTONS(A) (A)
#define EAP_NTOHL(A) (A)
#define EAP_HTONL(A) (A)
#elif defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAPOL__)
#error Must define either MOC_LITTLE_ENDIAN or MOC_BIG_ENDIAN in moptions.h
#endif

#if defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)

/* timeouts in seconds */
#define TIMEOUT_EAP_CLIENT                (30)
#define TIMEOUT_EAP_RETRANSMIT            (10)

/* for reference */
#define EAP_DEFAULT_MTU                 (1020)
#define EAP_DEFAULT_RETRY_TIMER         (5)

/* sizes */
#define EAP_SHA_FINGER_PRINT_SIZE       (20)
#define EAP_MD5_FINGER_PRINT_SIZE       (16)
#define EAP_BUFFER_SIZE                 (1020)
#define EAP_HEADER_SIZE                 (8)
#define EAP_MAX_IDENTITY_SIZE           (128)
#define EAP_MAX_KEY_SIZE                (256)
#define EAP_MAX_METHOD_NAME             (64)
#define EAP_MAX_ROUNDS                  (50)
#define EAP_MAX_METHODS                 (25)
#define EAP_MAX_USER_LEN                (64)
#define EAP_MAX_PASS_LEN                (64)

/* EAP ioctl settings */
#define EAP_SET_VERSION                 (1)

/* Vendor Ids */
#define EAP_VENDOR_ID_IETF              (0)

#include "../eap/eap_proto.h"

/** @private @internal */
typedef enum logLevel_s
{
    EAP_LOG_LEVEL_NONE,
    EAP_LOG_LEVEL_WARN,
    EAP_LOG_LEVEL_NOTICE,
    EAP_LOG_LEVEL_VERBOSE,
    EAP_LOG_LEVEL_ALL

}logLevel;

/**
@brief      Configuration settings and callback function pointers for EAP
            methods.
@details    This structure is used to store configuration settings and to
            register callback function pointers for EAP methods.

@since 1.41
@version 1.41 and later

@flags
To enable the callbacks, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

*/
typedef struct eapMethodDef_s
{
/**
@brief      Method type, such as LEAP or PEAP, that these settings and callback
            pointers are for.
@details    Method type, such as LEAP or PEAP, that these settings and callback
            pointers are for.
*/
    eapMethodType method_type;

/**
@brief      User-defined text string identifier for this structure's EAP method.
@details    User-defined text string identifier for this structure's EAP method.
*/
    ubyte method_name[EAP_MAX_METHOD_NAME];

/**
@brief      Process received EAP messages.
@details    This callback function is provided to process received EAP messages.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to the
session's callback pointer in the eapMethodDef structure.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
To enable this callback, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

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

@callbackdoc    eap.h
*/
    MSTATUS (*funcPtr_ulReceiveCallback)   (ubyte * app_session_handle,
                                            eapMethodType type,
                                            eapCode code, ubyte id,
                                            ubyte * eap_data,
                                            ubyte4 eap_data_len, ubyte * opaque_data);

/**
@brief      Receive EAP packets in passthrough mode.
@details    This callback function is provided to receive EAP packets from the
            EAP layer in passthrough mode. The complete packet, including the
            EAP header, is passed to this function.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to the
session's callback pointer in the eapMethodDef structure.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
To enable this callback, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@param app_session_handle   Cookie given by the application to identify the
                            session.
@param type                 Any of the \c eapMethodType enumerated values (see
                            @ref eap_proto.h).
@param code                 Any of the \c eapCode enumerated values (see @ref
                            eap_proto.h).
@param id                   EAP packet ID.
@param eap_data             Pointer to EAP payload.
@param eap_data_len         Number of bytes in \p eap_data.
@param opaque_data          Pointer to any opaque data to be passed from lower
                            layer.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap.h
*/
    MSTATUS (*funcPtr_ulReceivePassthruCallback) (ubyte * app_session_handle,
                                            eapMethodType type,
                                            eapCode code, ubyte id,
                                            ubyte * eap_data, ubyte4 eap_data_len,
                                            ubyte * opaque_data);

/**
@brief      Notify the upper layer that an error has occurred or that
            reauthorization is needed.
@details    This callback function is provided to notify the upper layer that
            one of the following errors occurred:\n

- \c TIMEOUT &mdash; No data received by NanoEAP within the time configured at
  EAP session creation
- \c ERROR &mdash; Error number (as defined in merrors.h)
- \c REAUTH &mdash; Packet received for reauthorization

Your application must interpret the data returned through the \p data parameter
based on the indication type.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to the
session's callback pointer in the eapMethodDef structure.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
To enable this callback, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@param app_session_handle   Cookie given by the application to identify the
                            session.
@param ind_type             Any of the \c eapIndication enumerated values (see
                            @ref eap_proto.h).
@param data                 Data specific to the indication type.
@param data_len             Number of bytes in \p data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap.h
*/
    MSTATUS (*funcPtr_ulReceiveIndication) (ubyte * app_session_handle,
                                            eapIndication ind_type,
                                            ubyte * data, ubyte4 data_len);

/**
@brief      Verify a packet's MIC (message integrity code).
@details    This callback function is provided to verify a packet's MIC (message
            integrity code).

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to the
session's callback pointer in the eapMethodDef structure.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
To enable this callback, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@param app_session_handle   Cookie given by the application to identify the
                            session.
@param pkt                  Pointer to packet.
@param pkt_len              Number of bytes in \p pkt.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap.h
*/
    MSTATUS (*funcPtr_ulMICVerify)         (ubyte * app_session_handle,
                                            ubyte * pkt, ubyte4 pkt_len);

/**
@brief      Enable customized accounting.
@details    This callback function is provided to enable customized accounting.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to the
session's callback pointer in the eapMethodDef structure.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
To enable this callback, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@param app_session_handle   Cookie given by the application to identify the
                            session.
@param methodState          Pointer to current state machine value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap.h
*/
    MSTATUS (*funcPtr_ulGetMethodstate)    (ubyte * app_session_handle,
                                            ubyte4 * methodState);

/**
@brief      Enable customized accounting.
@details    This callback function is provided to enable customized accounting.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to the
session's callback pointer in the eapMethodDef structure.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
To enable this callback, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@param app_session_handle   Cookie given by the application to identify the
                            session.
@param decision             Pointer to current decision value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap.h
*/
    MSTATUS (*funcPtr_ulGetDecision)       (ubyte * app_session_handle,
                                            ubyte4 * decision);

/**
@brief      Transmit (send) an EAP packet out through the lower (physical) layer.
@details    This callback function is provided to transmit (send) an EAP packet
            out through the lower (physical) layer.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to the
session's callback pointer in the eapMethodDef structure.

@ingroup    eap_callback_functions

@since 1.41
@version 1.41 and later

@flags
To enable this callback, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@param app_session_handle   Cookie given by the application to identify the
                            session.
@param eap_hdr              Pointer to EAP header.
@param eap_data             Pointer to EAP payload.
@param eap_data_len         Number of bytes in \p eap_data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap.h
*/
    MSTATUS (*funcPtr_llTransmitPacket)    (ubyte * app_session_handle,
                                            eapHdr_t * eap_hdr,
                                            ubyte * eap_data, ubyte4 eap_data_len);
} eapMethodDef_t;

/* Structure for Expanded Method format */
/** @private @internal */
typedef struct eapExpandedMethod_t
{
    ubyte  vendor_id[3];
    ubyte  method_type[4];
} eapExpandedMethod_t;

/* Global Statistics */
/** @private @internal */
typedef struct eapGlobalStats_s
{
    ubyte4    eap_total_pkts_sent;
    ubyte4    eap_total_pkts_received;
    ubyte4    eap_total_pkts_discard;
    ubyte4    eap_no_of_create_sessions;
    ubyte4    eap_no_of_modify_sessions;
    ubyte4    eap_no_of_active_sessions;
    ubyte4    eap_no_of_failed_sessions;
    ubyte4    eap_no_of_restart_sessions;
    ubyte4    eap_no_of_session_success;
    ubyte4    eap_no_of_session_failure;
    ubyte4    eap_no_of_retransmission;
    ubyte4    eap_no_of_peer_timeouts;
    ubyte4    eap_pkts_drop_invalid_session;
    ubyte4    eap_pkts_drop_invalid_pkt;

} eapGlobalStats_t;

/* Session Statistics */
/** @private @internal */
typedef struct eapSessionStats_s
{
    ubyte4    eap_pkts_ll_sent;
    ubyte4    eap_pkts_ll_received;
    ubyte4    eap_pkts_ul_callback;
    ubyte4    eap_pkts_ul_received;
    ubyte4    eap_pkts_retransmitted;
    ubyte4    eap_pkts_discard;
    ubyte4    eap_pkts_drop_ul_nocallback;
    ubyte4    eap_pkts_drop_invalid_pkt;
    ubyte4    eap_pkts_tx_id_resp;
    ubyte4    eap_pkts_rx_id_resp;
    ubyte4    eap_pkts_rx_id_req;
    ubyte4    eap_pkts_tx_id_req;
} eapSessionStats_t;

/* Session Configuration */
/** @private @internal */
typedef struct eapSessionConfig_s
{
    eapSessionType sessionType;
    ubyte4         eap_mtu;
    ubyte4         eap_ul_timeout;
    ubyte4         eap_retrans_timeout;
    ubyte4         eap_max_retrans;
    ubyte4         eap_options;
} eapSessionConfig_t;

#define EAP_OPTIONS_ENABLE_FORCED_AUTH       (0x1)

#define EAP_MOD_METHOD_DEF                   (0x1)
#define EAP_MOD_SESSION_TYPE                 (0x2)
#define EAP_MOD_SESSION_MTU                  (0x4)
#define EAP_MOD_SESSION_UL_TIMEOUT           (0x8)
#define EAP_MOD_SESSION_RETRANS_TIMEOUT      (0x10)
#define EAP_MOD_SESSION_MAX_RETRANS          (0x20)

/**
@brief      Pass a packet from the upper (method) layer to the EAP stack.
@details    This function is called by the authenticator or peer to pass a
            packet from the upper (method) layer to the EAP stack. The EAP layer
            copies the packet sent by the application, builds the EAP header
            using the \p method_type parameter's information, and then passes
            the packet to the lower (physical) layer to be transmitted to the
            peer or authenticator, respectively.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param method_type      Any of the \c eapMethodType enumerated values (see @ref
                        eap_proto.h).
@param code             Any of the \c eapCode enumerated values (see @ref
                        eap_proto.h).
@param methodDecision   Any of the \c eapMethodState enumerated values (refer
                        to @ref eap_proto.h).
@param methodState      Any of the \c eapMethodDecision enumerated values
                        (refer to @ref eap_proto.h).
@param eap_data         Pointer to EAP payload.
@param eap_data_len     Number of bytes in \p eap_data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_ulTransmit (ubyte * eapSessionHdl,
                                ubyte4 instanceId,
                                eapMethodType  method_type,
                                eapCode  code,
                                eapMethodDecision  methodDecision,
                                eapMethodState methodState,
                                ubyte * eap_data,
                                ubyte4  eap_data_len);

/**
@brief      Pass a received packet from the lower layer to the upper for
            processing.
@details    This function is called by the lower layer to pass a received packet
            to the upper EAP layer for processing. This function also looks up
            the session context and passes it to the upper layer.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param eap_pkt          Pointer to EAP packet
@param eap_pkt_len      Number of bytes in \p eap_pkt.
@param opaque_data      Pointer to opaque data&mdash;extra data that's passed
                        from the lower layer to the upper (method) layer through
                        the EAP stack.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_ulTransmit
@sa EAP_llReceiveIndication

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_llReceivePacket (ubyte *eapSessionHdl,
                                    ubyte4 instanceId,
                                    ubyte * eap_pkt,
                                    ubyte4 eap_pkt_len,
                                    ubyte * opaque_data);

/* Receive Alternate Indication from lower layer */
/**
@brief      Change EAP state machine's \c EAP_SUCCESS or \c EAP_FAILURE state.
@details    This function changes the standard EAP state machine progression by
            applying custom logic, which can be useful in cases such as when an
            EAP status response is dropped, but the information is available
            through deductive reasoning (for example, the authenticator
            progresses through the PPP state machine). In this example, the peer
            lower layer can inform the EAP stack, enabling continued EAP
            processing.

This function is called by the application to give alternate indications of
accept or reject. EAP will proceed to the \c EAP_SUCCESS or \c EAP_FAILURE state
according to the current state of the \p decision variable.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID previously returned by EAP_initInstance.
@param altIndication    Alternate indication of success or failure&mdash;any of
                        the \c eapAltIndication enumerated values:\n
\n
+ \c EAP_ALT_ACCEPT
+ \c EAP_ALT_REJECT

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_ulTransmit
@sa EAP_llReceivePacket

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_llReceiveIndication (ubyte *eapSessionHdl,
                                    ubyte4 instanceId,
                                    eapAltIndication altIndication);

/* Session management API */

/**
@brief      Create an EAP Session.
@details    This function creates an EAP session based on the specified
            parameters, returning the resultant session handle through the \p
            eapSessionHdl parameter.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param appSessionHandle Cookie given by the application to identify the session.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param methodDef        Structure containing method information such as method
                        type and callback functions.
@param cfgParam         Structure containing desired configuration parameters
                        for this EAP session.
@param eapSessionHdl    On return, pointer to EAP session handle.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_sessionModify
@sa EAP_sessionDelete
@sa EAP_sessionEnable
@sa EAP_sessionDisable

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_sessionCreate (ubyte * appSessionHandle,
                                  ubyte4 instanceId,
                                  eapMethodDef_t methodDef,
                                  eapSessionConfig_t cfgParam ,
                      ubyte ** eapSessionHdl);

/**
@brief      Modify an EAP Session.
@details    This function modifies an existing EAP session, based on the
            specified parameters.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param methodDef        Structure containing method information such as method
                        type and callback functions.
@param cfgParam         Structure containing desired configuration parameters
                        for this EAP session.
@param modifiedFlag     Bitmask sum of all variables to modify:\n
\n
+ \c EAP_MOD_METHOD_DEF
+ \c EAP_MOD_SESSION_TYPE
+ \c EAP_MOD_SESSION_MTU
+ \c EAP_MOD_SESSION_UL_TIMEOUT
+ \c EAP_MOD_SESSION_RETRANS_TIMEOUT
+ \c EAP_MOD_SESSION_MAX_RETRANS

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_sessionCreate
@sa EAP_sessionDelete
@sa EAP_sessionEnable
@sa EAP_sessionDisable

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_sessionModify (ubyte * eapSessionHdl,
                                  ubyte4 instanceId,
                                  eapMethodDef_t methodDef,
                                  eapSessionConfig_t cfgParam,
                                  ubyte4 modifiedFlag);

/**
@brief      Delete an EAP session.
@details    This function deletes an existing EAP session.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_sessionCreate
@sa EAP_sessionModify
@sa EAP_sessionEnable
@sa EAP_sessionDisable

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_sessionDelete  (ubyte * eapSessionHdl,
                                  ubyte4 instanceId);

/**
@brief      Restart an EAP session.
@details    This function restarts an existing EAP session, setting its current
            state to \c EAP_INITIALIZE and resetting all remaining parameters.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_sessionCreate
@sa EAP_sessionModify
@sa EAP_sessionDelete
@sa EAP_sessionEnable
@sa EAP_sessionDisable

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_sessionRestart (ubyte * eapSessionHdl,
                                   ubyte4 instanceId);

/**
@brief      Enable an EAP session.
@details    This function enables an existing EAP session, sets its current
            state to \c EAP_INITIALIZE, and resets all remaining parameters. It
            cannot be called before the corresponding port is enabled, and it
            must be called in order for the EAP stack to process any packets.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_sessionCreate
@sa EAP_sessionModify
@sa EAP_sessionDisable

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_sessionEnable  (ubyte * eapSessionHdl, ubyte4 instanceId);

/**
@brief      Disable an EAP session.
@details    This function disables an existing EAP session. When a port is
            disabled (for any reason), the application should call this function
            for every active session on the disabled port.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_sessionCreate
@sa EAP_sessionModify
@sa EAP_sessionEnable

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_sessionDisable  (ubyte * eapSessionHdl, ubyte4 instanceId);

/**
@brief      Get EAP session's identity string.
@details    This function retrieves the EAP session's identity string.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID previously returned by EAP_initInstance.
@param identity         On return, pointer to the identity string.
@param len              On return, number of bytes in \p identity.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_getIdentity(ubyte * eapSessionHdl, ubyte4 instanceId,
                               ubyte **identity, ubyte4 *len);

/**
@brief      Set an EAP session's identity string.
@details    This function sets an EAP session's identity string.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param identity         Pointer to desired identity string value.
@param len              Pointer to number of bytes in \p identity.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_setIdentity(ubyte * eapSessionHdl, ubyte4 instanceId,
                               ubyte  *identity,ubyte4 len);

/**
@brief      Get an EAP session's authentication key.
@details    This function retrieves the EAP session's authentication key (or \c
            NULL if there's no key).

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID previously returned by EAP_initInstance.
@param key              On return, pointer to the authentication key.
@param keylen           On return, pointer to number of bytes in \p key.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_setKey

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_getKey(ubyte * eapSessionHdl,
                          ubyte4 instanceId,
                          ubyte **key, ubyte *keylen);

/**
@brief      Set an EAP session's authentication key.
@details    This function sets the EAP session's authentication key to the
            specified value.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID previously returned by EAP_initInstance.
@param key              Pointer to desired key value.
@param keylen           Number of bytes in \p key.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_getKey

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_setKey(ubyte * eapSessionHdl,
                          ubyte4 instanceId,
                          ubyte *key, ubyte4 keylen);

/**
@brief      Get an EAP session's current authentication status.
@details    This function retrieves the current EAP authentication status. The
            lower layer uses this function if it requires an authenticated EAP
            session before transmitting data but hasn't received the
            authentication status from the upper layer.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID previously returned by EAP_initInstance.
@param authStatus       On return, pointer to authentication status (an
                        \c eapAuthStatus enumerated value, defined in @ref
                        eap_proto.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_getAuthenticationStatus(ubyte * eapSessionHdl ,
                                           ubyte4 instanceId,
                                           eapAuthStatus *authStatus);

struct eapSessionStatus_s;
/**
@brief      Get an EAP session's status.
@details    This function retrieves the EAP session's status.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID previously returned by EAP_initInstance.
@param eapStatus        On return, pointer to EAP session status (see \c
                        eapSessionStatus_t in @ref eap_session.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_getSessionStatus(ubyte * eapSessionHdl,
                                    ubyte4 instanceId,
                                    struct eapSessionStatus_s *eapStatus);

/* Configuration/Management  API */

/**
@brief      Get an EAP session's statistics.
@details    This function retrieves statistics for the specified EAP session.
            The statistics are accumulated values since they were last reset via
            a call to EAP_resetSessionStats.

The following statistics are returned through the \p eapstats parameter:
- Number of lower layer packets sent and received
- Number of packets the lower layer passed to the upper layer
- Number of packets the upper layer received from the lower layer
- Number of packets retransmitted and discarded
- Number of packets dropped because no callback was registered to process them
- Number of packets dropped because of an invalid packet

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID previously returned by EAP_initInstance.
@param eapStats         On return, pointer to session statistics (see \c
                        eapSessionStats_t in @ref eap.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_getSessionStatus
@sa EAP_resetSessionStats
@sa EAP_getInstanceStats
@sa EAP_resetInstanceStats

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_getSessionStats  (ubyte * eapSessionHdl,
                                     ubyte4 instanceId,
                                     eapSessionStats_t *eapStats);

/**
@brief      Get an EAP instance's statistics.
@details    This function retrieves statistics for the specified EAP instance.
            The statistics are accumulated values since they were last reset via
            a call to EAP_resetInstanceStats.

The following statistics are returned through the \p stats parameter:
- Total packets sent, received, and discarded
- Number of sessions created, modified, active, failed, and restarted
- (Authenticators only) Number of successful and number of failed peer
  authentications
- Number of times the authenticator/peer performed a retransmission
- Number of times the peer timed out
- Number of packets dropped due to invalid session, invalid packet

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param instanceId   EAP instance ID previously returned by EAP_initInstance.
@param stats        On return, pointer to global statistics (see \c
                    eapGlobalStats_t in @ref eap.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_getSessionStatus
@sa EAP_getSessionStats
@sa EAP_resetSessionStats
@sa EAP_resetInstanceStats

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_getInstanceStats  (ubyte4 instanceId,
                                     eapGlobalStats_t *stats);

/**
@brief      Reset an EAP instance's global statistics.
@details    This function resets the specified EAP instance's global statistics
            to zero (\c 0).

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param instanceId   EAP instance ID previously returned by EAP_initInstance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_getSessionStats
@sa EAP_resetSessionStats
@sa EAP_getInstanceStats

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_resetInstanceStats  (ubyte4 instanceId);

/**
@brief      Reset an EAP session's statistics.
@details    This function resets the specified EAP session's statistics to zero
            (\c 0).

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID previously returned by EAP_initInstance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_getSessionStatus
@sa EAP_resetSessionStats
@sa EAP_getInstanceStats
@sa EAP_resetInstanceStats

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_resetSessionStats(ubyte *eapSessionHdl,
                                     ubyte4 instanceId);

/*
MOC_EXTERN MSTATUS EAP_setGlobalTimeout(ubyte4 timeout);

MOC_EXTERN MSTATUS EAP_loggingEnable (void);

MOC_EXTERN MSTATUS eap_setLogLevel (logLevel level);

MOC_EXTERN MSTATUS eap_loggingDisable (void);
*/

/* EAP Initialization APIs */

/**
@brief      Create and initialize an EAP instance and get its ID.
@details    This function creates an EAP instance, initializes it, and returns
            its ID through the \p instanceId parameter. All subsequent function
            calls made for this EAP instance use this returned ID.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param instanceId   On return, pointer to instance ID.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_initInstance  (ubyte4 *instanceId);

/**
@brief      Delete an EAP instance.
@details    This function deletes an EAP instance.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param instanceId   EAP instance ID previously returned by EAP_initInstance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_deleteInstance  (ubyte4 instanceId);

/**
@brief      Call expired timers' callbacks.
@details    This function determines whether any timers have expired, and if so
            then calls each expired expired timer's callback function. Your
            application should call this function every 300 to 500 milliseconds.

@ingroup    eap_functions

@since 1.41
@version 2.45 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param instanceId       EAP instance ID returned from EAP_initInstance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_checkTimers (ubyte4 instanceId);

/**
@brief      Initialize EAP structures, data, and stack.
@details    This function initializes NanoEAP structures, data, and stack.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_init(void);

/**
@brief      Clean up memory and mutexes and shut down the EAP stack.
@details    This function performs memory and mutex cleanup, shuts down the EAP
            stack, and deletes all core EAP sessions and EAP instances.

@ingroup    eap_functions

@since 2.45
@version 2.45 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_shutdown(void);

/**
@brief      Builds a NAK response to send to the authenticator.
@details    This function builds a NAK response for your application to send
            from the peer to the authenticator if the peer doesn't support the
            expanded method selected by the authenticator. NAK responses return
            a list of supported expanded methods through the \p eapMethods
            parameter.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param expMethods       Array of Expanded methods supported.
@param expMethodCount   Number of Expanded methods supported.
@param eapResponse      On return, pointer to EAP response payload.
@param eapRespLen       On return, pointer to number of bytes in \p eapResponse.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS
EAP_buildExpandedNAK(ubyte *eapSessionHdl, ubyte4 instanceId,
                     eapExpandedMethod_t *expMethods, ubyte expMethodCount,
                     ubyte **eapResponse, ubyte4 *eapRespLen);

/**
@brief      Builds an expanded payload response.
@details    This function builds the expanded payload response for the peer,
            which is sent in response to an expanded request received from the
            authenticator.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param expVendorId      Vendor ID (user-defined value).
@param expMethodId      ID of method being negotiated (user-defined value).
@param eapPayload       EAP response payload.
@param eapPayloadLen    EAP response payload length of \p eapPayload.
@param eapResponse      On return, pointer to expanded EAP response payload.
@param eapRespLen       On return, pointer to number of bytes in \p eapResponse.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS
EAP_buildExpandedResponse(ubyte *eapSessionHdl, ubyte4 instanceId,
                          ubyte4 expVendorId, ubyte4 expMethodId,
                          ubyte *eapPayload, ubyte4 eapPayloadLen,
                          ubyte **eapResponse, ubyte4 *eapRespLen);


/**
@brief      Builds a NAK response to send to the authenticator.
@details    This function builds a NAK response for your application to send
            from the peer to the authenticator if the peer doesn't support the
            method selected by the authenticator. NAK responses return a list of
            supported methods through the \p nakMethods parameter.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param nakMethods       Array of methods supported.
@param nakMethodCount   Number of methods supported.
@param eapResponse      On return, pointer to EAP response payload.
@param eapRespLen       On return, pointer to number of bytes in \p eapResponse.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS
EAP_buildNAK(ubyte *eapSessionHdl, ubyte4 instanceId,
             ubyte* nakMethods, ubyte4 nakMethodCount,
             ubyte **eapResponse, ubyte4 *eapRespLen);

/**
@brief      Assign (place on the EAP stack) the EAP processing state machine (\p
            methodState) and decision (\p methodDecision) values.
@details    This function assigns the specified EAP processing state machine (\p
            methodState) and decision (\p methodDecision) values, placing them
            on the EAP stack. It is particularly useful for two-phase methods:
            when the second stage method informs the application of the result,
            the application calls this function to update the EAP stack with the
            appropriate state machine values.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param methodState      Value to assign to \p methodState.
@param methodDecision   Value to assign to \p decision.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS
EAP_setMethodStateDecision(ubyte *eapSessionHdl, ubyte4 instanceId,
                           ubyte methodState, ubyte methodDecision);

/**
@brief      Set identifier and type to the last sent identifier and the EAP
            packet type.
@details    This function sets the values of the identifier to the last sent
            identifier and the type to the type of EAP packet on the stack. This
            function is used for EAP-FAST when the application piggybacks the
            second stage packet to the previous TLS packet (which in this case
            is the TLS Finished message).

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param id               Identifier in EAP packet.
@param type             Any of the \c eapMethodType enumerated values (see @ref
                        eap_proto.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS
EAP_setId_Type(ubyte * eapSessionHdl, ubyte4 instanceId,
               ubyte id, ubyte type);

/**
@brief      Builds an EAP request.
@details    This function builds an EAP request using the provided identifier
            value. It is used by EAP-FAST authenticators to piggyback an
            identity request to a TLS Finished message received from a peer.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param id       Value of identifier to be sent in EAP packet.
@param req      On return, pointer to generated EAP request packet.
@param reqLen   On return, pointer to number of bytes in \p req.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS
EAP_generateIdReq(ubyte id,ubyte ** req, ubyte4 *reqLen);

/** @private @internal */
MOC_EXTERN MSTATUS
EAP_getAppHdl(ubyte4  eapSessionHdl,
              ubyte4 instanceId,ubyte **appHdl);

#if defined(__ENABLE_ALL_DEBUGGING__)
/** @private @internal */
MOC_EXTERN void EAP_PrintBytes( ubyte* buffer, sbyte4 len);
#endif

#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
/**
@brief      Start reauthorization and timer rescheduling.
@details    This function checks the EAP session status, and if the status is \c
            SUCCESS, calls EAP_sessionRestart to begin the reauthorization and
            timer rescheduling.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID previously returned by EAP_initInstance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_ulStartReauth(ubyte * eapSessionHdl, ubyte4 instanceId);
#endif

/**
@brief      Get the MTU (maximum transmission unit) value.
@details    This function retrieves the MTU (maximum transmission unit) value
            that was set at EAP session creation.

@ingroup    eap_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param mtu              On return, pointer to MTU.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap.h
*/
MOC_EXTERN MSTATUS EAP_getMtu(ubyte *eapSessionHdl, ubyte4 instanceId, ubyte4 *mtu);

#endif  /* __ENABLE_DIGICERT_EAP_PEER__ || __ENABLE_DIGICERT_EAP_AUTH__ */

#ifdef __cplusplus
}
#endif

#endif  /* __EAP_HEADER__ */


