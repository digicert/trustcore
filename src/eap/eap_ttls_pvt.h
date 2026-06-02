/**
 * @file  eap_ttls_pvt.h
 * @brief EAP-TTLS private definitions
 *
 * @details    Internal TTLS structures
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

#ifndef EAP_TTLS_PVT_H
#define EAP_TTLS_PVT_H
#ifdef __cplusplus
extern "C" {
#endif
/*------------------------------------------------------------------*/

#define EAP_TTLS_MSCHAPV2_CHALLENGE_LEN      (16)
#define EAP_TTLS_MSCHAPV2_RESPONSE_LEN       (50)
#define EAP_TTLS_MSCHAP_CHALLENGE_LEN        (8)
#define EAP_TTLS_MSCHAP_RESPONSE_LEN         (50)
#define EAP_TTLS_CHAP_CHALLENGE_LEN          (16)
#define EAP_TTLS_CHAP_PASSWORD_LEN           (16)
#define MAX_EAP_PACKET                       (2048)

/*------------------------------------------------------------------*/
/* Attributes Bit Mask */

#define EAP_TTLS_USERNAME_AVP                (0x1)
#define EAP_TTLS_PASSWORD_AVP                (0x2)
#define EAP_TTLS_CHAP_PASSWORD_AVP           (0x4)
#define EAP_TTLS_MSCHAP_RESPONSE_AVP         (0x8)
#define EAP_TTLS_MSCHAPV2_RESPONSE_AVP       (0x10)
#define EAP_TTLS_MSCHAP_CHALLENGE_AVP        (0x20)
#define EAP_TTLS_CHAP_CHALLENGE_AVP          (0x40)
#define EAP_TTLS_MSCHAPV2_SUCCESS_AVP        (0x80)
#define EAP_TTLS_MSCHAPV2_ERROR_AVP          (0x100)
#define EAP_TTLS_EAP_AVP                     (0x200)

/*------------------------------------------------------------------*/

typedef enum eap_ttls_frag_flag
{
    EAP_TTLS_FRAG_FLAG_RECV = 1,
    EAP_TTLS_FRAG_FLAG_SEND

} eap_ttls_frag_flag_e;

typedef enum eap_ttls_mschapv2_state_e
{
    EAP_TTLS_MSCHAPV2_INIT      = 0,
    EAP_TTLS_MSCHAPV2_SUCCESS   = 1,
    EAP_TTLS_MSCHAPV2_FAILURE   = 2,
    EAP_TTLS_MSCHAPV2_CHALLENGE = 3

} eap_ttls_mschapv2_state;

typedef enum eap_ttls_eap_state_e
{
    EAP_TTLS_EAP_INIT     = 0,
    EAP_TTLS_EAP_IDENTITY = 1,
    EAP_TTLS_EAP_METHOD   = 2,
    EAP_TTLS_EAP_SUCCESS  = 3,
    EAP_TTLS_EAP_FAILURE  = 4,

} eap_ttls_eap_state;


typedef enum eap_ttls_inner_appState_e
{
    EAP_TTLS_INNER_INIT   = 0,
    EAP_TTLS_INNER_APP    = 1,
    EAP_TTLS_INNER_INTER  = 2,
    EAP_TTLS_INNER_FINAL  = 3,

} eap_ttls_inner_appState;
/*------------------------------------------------------------------*/


typedef struct
{
    void                    *appSessionCB;
    ubyte*                  eapAuthSessionHdl;
    EAP_TTLS_params         eapTTLSparam;
    eap_ttls_mschapv2_state msChapV2Status;
    eap_ttls_eap_state      eapStatus;
    ubyte                   AuthenticatorResponse[42];
    ubyte                   sessionStatus;
    ubyte                   msChapV2Id;
    ubyte                   * ttls_data_recv;
    ubyte                   * ttls_data_send;
    ubyte                   * ttls_data_send_cur;
    ubyte4                  ttls_data_recv_total_len;
    ubyte4                  ttls_data_recv_len;
    ubyte4                  ttls_data_send_total_len;
    ubyte4                  ttls_data_send_remaining;
    eap_ttls_frag_flag_e    ttls_frag_flag;
    eap_ttls_eap_state      eapStageStatus;
    ubyte*                  eapSessionHdl;
    eap_ttls_inner_appState eapInnerAppState;

} eapTTLSCB;


/*------------------------------------------------------------------*/

#define TTLS_CHALLENGE_PHRASE         "ttls challenge"
#define TTLS_CHALLENGE_PHRASE_LEN     (14)
#define TTLS_INNER_APP_CHALLENGE_PHRASE         "inner application challenge"
#define TTLS_INNER_APP_CHALLENGE_PHRASE_LEN     (27)
#define TTLS_KEYING_PHRASE            "ttls keying material"
#define TTLS_KEYING_PHRASE_LEN        (20)

/*------------------------------------------------------------------*/
/* These Values are defined in radius.h. These were also included here
   to make the TTLS Peer independent of the Radius Module */

#define EAP_RADIUS_ATTR_USER_NAME                   1
#define EAP_RADIUS_ATTR_USER_PASSWORD               2
#define EAP_RADIUS_ATTR_CHAP_PASSWORD               3
/* RFC 2548 */
#define EAP_RADIUS_VENDOR_ID_MS                     311
#define EAP_RADIUS_ATTR_MSCHAP_RESPONSE             1
#define EAP_RADIUS_ATTR_MSCHAP_ERROR                2
#define EAP_RADIUS_ATTR_MSCHAP_NT_ENC_PW            6
#define EAP_RADIUS_ATTR_MSCHAP_CHALLENGE            11
#define EAP_RADIUS_ATTR_MSCHAPV2_RESPONSE           25
#define EAP_RADIUS_ATTR_MSCHAPV2_SUCCESS            26
#define EAP_RADIUS_ATTR_MSCHAPV2_MPPE_SEND_KEY      16
#define EAP_RADIUS_ATTR_MSCHAPV2_MPPE_RECV_KEY      17
#define EAP_RADIUS_ATTR_EAP_MESSAGE                 79
#define EAP_RADIUS_ATTR_CHAP_CHALLENGE              60

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS EAP_TTLSProcessAVP(eapTTLSCB *eapCb, ubyte *pPkt, ubyte4 pktLen);
MOC_EXTERN MSTATUS EAP_TTLSProcessPAPAuthRequest(eapTTLSCB *eapCb,ubyte *papUsername,ubyte4 userLen,ubyte *papPassword, ubyte4 passLen);
MOC_EXTERN MSTATUS EAP_TTLSProcessChapAuthRequest(eapTTLSCB *eapCb,ubyte *Username,ubyte4 userLen,ubyte *password, ubyte4 passLen,ubyte *challenge);
MOC_EXTERN MSTATUS EAP_TTLSProcessMSChapAuthRequest(eapTTLSCB *eapCb,ubyte *Username,ubyte4 userLen,ubyte *password, ubyte4 passLen,ubyte *challenge);
MOC_EXTERN MSTATUS EAP_TTLSProcessMSChapV2AuthRequest(eapTTLSCB *eapCb,ubyte *Username,ubyte4 userLen,ubyte *password, ubyte4 passLen,ubyte *challenge);
MOC_EXTERN MSTATUS EAP_TTLSSendMSChapV2AuthSuccess(eapTTLSCB *eapCb,ubyte *success,ubyte4 successLen);
MOC_EXTERN MSTATUS EAP_TTLSProcessMSChapV2AuthResponse(eapTTLSCB *eapCb,ubyte *success, ubyte4 successLen);
MOC_EXTERN MSTATUS EAP_TTLSProcessPAPPeerRequest(eapTTLSCB *eapCb);
MOC_EXTERN MSTATUS EAP_TTLSProcessChapPeerRequest(eapTTLSCB *eapCb);
MOC_EXTERN MSTATUS EAP_TTLSProcessMSChapPeerRequest(eapTTLSCB *eapCb);
MOC_EXTERN MSTATUS EAP_TTLSProcessMSChapV2PeerRequest(eapTTLSCB *eapCb);
MOC_EXTERN MSTATUS EAP_TTLSInitEAPPeerRequest(eapTTLSCB *eapCb);
MOC_EXTERN MSTATUS EAP_TTLSEncapEAPPkt(eapTTLSCB *eapCb,ubyte *eapPkt, ubyte4 eapPktLen);
MOC_EXTERN MSTATUS EAP_TTLSProcessEAPAuthRequest(eapTTLSCB *eapCb,ubyte* eapPkt, ubyte4 eapPktLen);

MOC_EXTERN MSTATUS EAP_TTLSProcessEAPPeerRequest(eapTTLSCB *eapCb, ubyte *pkt, ubyte4 pktLen);
MOC_EXTERN MSTATUS EAP_TTLSInitEAPPeerRequest(eapTTLSCB *eapCb);
MOC_EXTERN MSTATUS eap_TTLSPeerInit(eapTTLSCB *eapCb);
#ifdef __cplusplus
}
#endif

#endif
