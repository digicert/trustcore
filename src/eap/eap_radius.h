/**
 * @file  eap_radius.h
 * @brief EAP RADIUS API
 *
 * @details    RADIUS interface
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     To build products using this header file's functions, the following flags must be
 *     defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_RADIUS__
 *     +   \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
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

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)
#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)

/*------------------------------------------------------------------*/

/**
@brief      Encapsulate an EAP packet into a RADIUS packet.
@details    This function encapsulates a given EAP packet into a RADIUS packet,
            appending the required attributes and returning the encapsulated
            packet through the \p radiusReq parameter. Typically the upper layer
            calls this function to provide passthrough authentication (sending
            packets to a backend RADIUS authentication %server).

@ingroup    eap_radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_DIGICERT_EAP_RADIUS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_radius.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param authServerID     Backend RADIUS authentication server ID (index specified
                        by Mocana internal code).
@param addr             Interface address of NAS (network authentication server).
@param nas_port         NAS port number.
@param nas_port_type    NAS port type (see @ref nas_port_types).
@param secret           Shared secret between RADIUS %client and backend RADIUS
                        authentication %server.
@param secretlen        Number of bytes in \p secret.
@param eap_pkt          Pointer to EAP packet to be encapsulated.
@param radiusReq        On return, pointer to encapsulated RADIUS EAP packet.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_radius.h
*/
MOC_EXTERN MSTATUS
EAP_radiusEncapsulate(ubyte * eapSessionHdl,
                      ubyte4 instanceId,
                      ubyte4 authServerID,
                      MOC_IP_ADDRESS addr,
                      ubyte4 nas_port,
                      ubyte4 nas_port_type,
                      ubyte *secret,
                      sbyte4 secretlen,
                      ubyte *eap_pkt, RADIUS_RqstRecord **radiusReq);

/**
@brief      Decapsulate (extract) an EAP packet from a RADIUS packet.
@details    This function  decapsulates (extracts) an EAP packet from a RADIUS
            packet. Typically the upper layer calls this function and then
            subsequently passes the decapsulated packet to the lower layer for
            transmission to a peer, thereby providing passthrough authentication
            service (sending packets to a backend RADIUS authentication server).

@ingroup    eap_radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_DIGICERT_EAP_RADIUS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_radius.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param secret           Shared secret between RADIUS %client and backend RADIUS
                        authentication %server.
@param secretlen        Number of bytes in \p secret.
@param pRadiusReq       Pointer to RADIUS packet (received from backend RADIUS
                        authentication %server) containing encapsulated EAP
                        packet.
@param eap_pkt          On return, pointer to decapsulated EAP packet.
@param eapLen           On return, pointer to number of bytes in \p eap_pkt.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_MD5_getChallenge
@sa EAP_MD5ProcessAuth

@funcdoc    eap_radius.h
*/
MOC_EXTERN MSTATUS
EAP_radiusDecapsulate(ubyte * eapSessionHdl,
                      ubyte4 instanceId,
                      ubyte *secret,
                      sbyte4 secretlen,
                      RADIUS_RqstRecord *pRadiusReq,
                      ubyte **eap_pkt,
                      ubyte4 *eapLen);

/**
@brief      Get a session's MPPE keys.
@details    This function retrieves a session's MPPE (Microsoft Point-to-Point
            Encryption) keys that the RADIUS server sent to the passthrough
            authenticator in the Access Accept Message.

@ingroup    eap_radius_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_DIGICERT_EAP_RADIUS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_radius.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param mppeSendKey      On return, pointer to sent MPPE key.
@param mppeSendKeyLen   On return, pointer to length of sent MPPE key (\p
                        mppeSendKey).
@param mppeRecvKey      On return, pointer to received MPPE key.
@param mppeRecvKeyLen   On return, pointer to length of received MPPE key (\p
                        mppeRecvKey).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_radius.h
*/
MOC_EXTERN MSTATUS
EAP_radiusGetMPPEKeys(ubyte * eapSessionHdl,
                      ubyte4 instanceId,
                      ubyte **mppeSendKey,ubyte4 *mppeSendKeyLen,
                      ubyte **mppeRecvKey,ubyte4 *mppeRecvKeyLen);

#ifdef __ENABLE_RADIUS_SERVER__

/**
@brief      Encapsulate an EAP packet into a RADIUS packet.
@details    This function encapsulates a given EAP packet into a RADIUS packet,
            appending the required attributes and returning the encapsulated
            packet through the \p radiusReq parameter. Typically the upper layer
            calls this function to provide passthrough authentication (sending
            packets to a backend RADIUS authentication %server).

@ingroup    eap_radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__
+ \c \__ENABLE_DIGICERT_EAP_RADIUS__
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RADIUS_SERVER__

@inc_file   eap_radius.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param authServerID     Backend RADIUS authentication server ID (index specified
                        by Mocana internal code).
@param secret           Shared secret between RADIUS %client and backend RADIUS
                        authentication %server.
@param secretlen        Number of bytes in \p secret.
@param eap_pkt          Pointer to EAP packet to be encapsulated.
@param eap_pkt_len      Number of bytes in \p eap_pkt.
@param pRadiusReq       On return, pointer to encapsulated RADIUS EAP packet.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_radius.h
*/
MOC_EXTERN MSTATUS
EAP_radiusServerEncapsulate(ubyte * eapSessionHdl,
                      ubyte4 instanceId,
                      ubyte4 authServerID,
                      ubyte *secret,
                      sbyte4 secretlen,
                      ubyte *eap_pkt,
                      ubyte4 eap_pkt_len,
                      RADIUS_RqstRecord *pRadiusReq);

/**
@brief      Decapsulate (extract) an EAP packet from a RADIUS packet.
@details    This function  decapsulates (extracts) an EAP packet from a RADIUS
            packet. Typically the upper layer calls this function and then
            subsequently passes the decapsulated packet to the lower layer for
            transmission to a peer, thereby providing passthrough authentication
            service (sending packets to a backend RADIUS authentication server).

@ingroup    eap_radius_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_AUTH__
+ \c \__ENABLE_DIGICERT_EAP_RADIUS__
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RADIUS_SERVER__

@inc_file   eap_radius.h

@param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
@param instanceId       EAP instance ID returned from EAP_initInstance.
@param secret           Shared secret between RADIUS %client and backend RADIUS
                        authentication %server.
@param secretlen        Number of bytes in \p secret.
@param stateAttr        State Attributes from backend RADIUS authentication
                        %server.
@param stateAttrLen     Number of bytes in \p stateAttr.
@param pRadiusReq       Pointer to RADIUS packet (received from backend RADIUS
                        authentication %server) containing encapsulated EAP
                        packet.
@param eap_pkt          On return, pointer to decapsulated EAP packet.
@param eapLen           On return, pointer to number of bytes in \p eap_pkt.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_MD5_getChallenge
@sa EAP_MD5ProcessAuth

@funcdoc    eap_radius.h
*/
MOC_EXTERN MSTATUS
EAP_radiusServerDecapsulate(ubyte * eapSessionHdl,
                      ubyte4 instanceId,
                      ubyte *secret,
                      sbyte4 secretlen,
                      ubyte* stateAttr,
                      ubyte4 stateAttrLen,
                      RADIUS_RqstRecord *pRadiusReq,
                      ubyte **eap_pkt,
                      ubyte4 *eapLen);

#endif /* RADIUS_SERVER*/

#endif /* defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) */
#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__) */

#ifdef __cplusplus
}
#endif
