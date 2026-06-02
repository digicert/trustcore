/**
 * @file  eap_proto.h
 * @brief EAP protocol definitions
 *
 * @details    EAP protocol constants and structures
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

#ifndef __EAP_PROTO_H__
#define __EAP_PROTO_H__
#ifdef __cplusplus
extern "C" {
#endif

typedef enum eapMethodDecision_e
{
    EAP_METHOD_DECISION_NONE,
    EAP_METHOD_DECISION_FAIL,
    EAP_METHOD_DECISION_COND_SUCC,
    EAP_METHOD_DECISION_UNCOND_SUCC,
    EAP_METHOD_DECISION_CONTINUE,
    EAP_METHOD_DECISION_SUCCESS,
    EAP_METHOD_DECISION_FAILURE

}eapMethodDecision;

typedef enum eapMethodState_e
{

    /* Used by Peer */
    EAP_METHOD_STATE_INIT,
    EAP_METHOD_STATE_CONT,
    EAP_METHOD_STATE_MAY_CONT,
    EAP_METHOD_STATE_DONE,
    /* Used by Authenticator */
    EAP_METHOD_STATE_PROPOSED,
    EAP_METHOD_STATE_CONTINUE,
    EAP_METHOD_STATE_END

}eapMethodState;

typedef enum eapCode_e
{
    EAP_CODE_REQUEST = 1,
    EAP_CODE_RESPONSE= 2,
    EAP_CODE_SUCCESS = 3,
    EAP_CODE_FAILURE = 4

} eapCode;

typedef enum eapMethodType_e
{
    EAP_TYPE_NONE = 0,
    EAP_TYPE_IDENTITY = 1,
    EAP_TYPE_NOTIFICATION = 2,
    EAP_TYPE_NAK = 3,
    EAP_TYPE_MD5 = 4,/* RFC 3748 */
    EAP_TYPE_OTP = 5 /* RFC 3748 */,
    EAP_TYPE_GTC = 6, /* RFC 3748 */
    EAP_TYPE_TLS = 13 /* RFC 2716 */,
    EAP_TYPE_LEAP = 17   /* Cisco  */,
    EAP_TYPE_SIM = 18    /* RFC 4186 */,
    EAP_TYPE_SRP_SHA1 = 19 /* draft-pppext-eap-srp-03.txt, RFC 2945 */,
    EAP_TYPE_TTLS = 21 /* draft-ietf-pppext-eap-ttls-02.txt */,
    EAP_TYPE_AKA = 23    /* RFC 4187 */,
    EAP_TYPE_PEAP = 25           /* draft-josefsson-pppext-eap-tls-eap-10.txt */,
    EAP_TYPE_MSCHAPV2 = 26 /* draft-kamath-pppext-eap-mschapv2-00.txt, RFC 2759 */,
    EAP_TYPE_TLV = 33 /* draft-josefsson-pppext-eap-tls-eap-07.txt */,
    EAP_TYPE_FAST = 43           /* draft-cam-winget-eap-fast-03.txt */,
    EAP_TYPE_PSK = 47           /* draft-bersani-eap_psk-11.txt */,
    EAP_TYPE_PERP = 253 /* EAP PERP for IKev2 */,
    EAP_TYPE_EXPANDED = 254 /* RFC 3748 */,

} eapMethodType;

#define    EAP_TYPE_EXPANDED_NAK  254

typedef enum eapAuthStatus_e
{
    EAP_AUTH_SUCCESS,
    EAP_AUTH_FAILURE,
    EAP_AUTH_TIMEOUT,
    EAP_AUTH_IN_PROGRESS

} eapAuthStatus;

typedef enum eapSessionType_e
{
    EAP_SESSION_TYPE_PEER,
    EAP_SESSION_TYPE_AUTHENTICATOR,
    EAP_SESSION_TYPE_PASSTHROUGH,
    EAP_SESSION_TYPE_BOTH

} eapSessionType;


typedef enum eapIndication_e
{
    EAP_INDICATION_PEER_TIMEOUT = 1,
    EAP_INDICATION_AUTH_TIMEOUT,
    EAP_INDICATION_RETRANSMIT_TIMEOUT,
    EAP_INDICATION_RESTART_REQUEST,
    EAP_INDICATION_ERROR,

} eapIndication;

typedef enum eapAltIndication_e
{
    EAP_ALT_ACCEPT,
    EAP_ALT_REJECT

} eapAltIndication;


/*------------------------------------------------------------------*/

typedef EAP_PACKED struct eapHdr_s
{
    ubyte code;
    ubyte id;
    ubyte2 len;

} EAP_PACKED_POST eapHdr_t;

#define EAP_FAST_VERSION                 1
#ifdef __cplusplus
}
#endif

#endif /* __EAP_PROTO_H__ */

