/**
 * @file  eap1x.h
 * @brief IEEE 802.1X definitions
 *
 * @details    802.1X port-based authentication
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

#ifndef __EAP1X_HEADER__
#define __EAP1X_HEADER__

#ifdef __cplusplus
extern "C" {
#endif
#define EAP1X_ETH_TYPE              (0x888e)
#define EAP1X_ETHER_PROTO_EAPOL     (0x888e)
#define EAP1X_ETHER_PROTO_PREAUTH   (0x88c7)

typedef enum eap1xPortMode_e
{
    EAP1X_PORT_MODE_FORCED_UNAUTHORIZED =1,
    EAP1X_PORT_MODE_FORCED_AUTHORIZED   =2,
    EAP1X_PORT_MODE_AUTO                =3

} eap1xPortMode;

typedef enum eap1xPortStatus_e
{
    EAP1X_PORT_STATUS_AUTHORIZED   =1,
    EAP1X_PORT_STATUS_UNAUTHORIZED =2

} eap1xPortStatus;


#define EAP1X_EAPOL_START          (0x01)
#define EAP1X_EAPOL_LOGOFF         (0x02)
#define EAP1X_EAP_RESTART          (0x04)
#define EAP1X_EAP_REQUEST          (0x08)
#define EAP1X_EAP_AUTH_SUCCESS     (0x10)
#define EAP1X_EAP_EAP_SUCCESS      (0x20)
#define EAP1X_EAP_AUTH_FAIL        (0x40)
#define EAP1X_EAP_EAP_FAIL         (0x80)
#define EAP1X_EAP_AUTH_TIMEOUT     (0x0100)
#define EAP1X_EAP_AUTH_START       (0x0200)
#define EAP1X_EAP_AUTH_ABORT       (0x0400)
#define EAP1X_EAP_PORT_VALID       (0x0800)
#define EAP1X_EAP_PORT_ENABLED     (0x1000)
#define EAP1X_EAPOL_INITIALIZE     (0x2000)
#define EAP1X_EAPOL_USERLOGOFF     (0x4000)
#define EAP1X_EAP_EAPOL            (0x8000)
#define EAP1X_EAP_PEER_SUCCESS     (0x10000)
#define EAP1X_EAP_PEER_FAIL        (0x20000)
#define EAP1X_EAP_PEER_TIMEOUT     (0x40000)

typedef enum eap1XIndication_e
{
    EAP1X_INDICATION_RESTART       = 1,
    EAP1X_INDICATION_ABORT         = 2,
    EAP1X_INDICATION_REAUTH        = 3,
    EAP1X_INDICATION_UNAUTHORIZED  = 4,
    EAP1X_INDICATION_AUTHORIZED    = 5,
    EAP1X_INDICATION_SEND_START    = 6,
    EAP1X_INDICATION_SEND_LOGOFF   = 7,
    EAP1X_INDICATION_SEND_SUCCESS  = 8,
    EAP1X_INDICATION_SEND_FAILURE  = 9,

} eap1XIndication ;

#define EAP1X_EAPOL_VERSION       00000002
#define EAP1X_EAPOL_EAP_TYPE      00000000
#define EAP1X_EAPOL_START_TYPE    00000001
#define EAP1X_EAPOL_LOGOFF_TYPE   00000002
#define EAP1X_EAPOL_KEY_TYPE      00000003

typedef EAP_PACKED struct eap1xHdr_s
{
    ubyte2     ethType;
    ubyte      version;
    ubyte      pktType;
    ubyte2     pktLen;

} EAP_PACKED_POST eap1xHdr_t;

#define EAP1X_HDR_LENGTH_OFFSET      (4)
#ifdef __cplusplus
}
#endif

#endif /* __EAP1X_HEADER__*/
