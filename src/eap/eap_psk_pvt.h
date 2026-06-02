/**
 * @file  eap_psk_pvt.h
 * @brief EAP-PSK private definitions
 *
 * @details    Internal PSK structures
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

#ifndef __EAP_PSK_PVT_H__
#define __EAP_PSK_PVT_H__

#ifdef __cplusplus
extern "C" {
#endif


#define EAP_PSK_FLAG_MASK       (0xC0)
#define EAP_PSK_FLAG_LEN        (1)
#define EAP_PSK_RAND_LEN        (16)
#define EAP_PSK_AK_LEN          (16)
#define EAP_PSK_KDK_LEN         (16)
#define EAP_PSK_NONCE_LEN       (4)
#define EAP_PSK_HEADER_LEN      (22)
#define EAP_PSK_MAC_LEN         (16)
#define EAP_PSK_TAG_LEN         (16)

#define EAP_PSK_RESULT_IND_MASK (0xC0)
#define EAP_PSK_EXT_MASK        (0x20)
#define EAP_PSK_FLAG_SHIFT      (6)
#define EAP_PSK_RESULT_IND_SHIFT (6)
#define EAP_PSK_EBIT_SHIFT      (5)

typedef enum eapPSKState_e {

    EAP_PSK_STATE_INIT  =0,
    EAP_PSK_STATE_FIRST =1,
    EAP_PSK_STATE_SECOND=2,
    EAP_PSK_STATE_THIRD =3,
    EAP_PSK_STATE_EXT   =4

} eapPSKState;


typedef EAP_PACKED struct eapPSKChan_s {
    ubyte    resultInd;
    ubyte    extensionBit;
    ubyte2   extLen;
    ubyte    *ext;

} EAP_PACKED_POST eapPSKChan;

typedef EAP_PACKED struct eapPSKHdr_s {
    eapHdr_t eapHdr;
    ubyte    eapType;
    ubyte    flag;
    ubyte    rand_s[EAP_PSK_RAND_LEN];

} EAP_PACKED_POST eapPSKHdr;


typedef struct eapPSKCb_s {
    ubyte          *appCbHdl;
    ubyte          ak[16];
    ubyte          kdk[16];
    ubyte          rand_s[16];
    ubyte          rand_p[16];
    ubyte          *id_s;
    ubyte2         id_s_len;
    ubyte2         id_p_len;
    ubyte          *id_p;
    ubyte4         nonce;
    eapPSKChan     pChan;
    eapPSKConfig   eapPSKCfg;
    eapPSKState    state;
    ubyte          tek[16];
    ubyte          msk[64];
    ubyte          emsk[64];
    ubyte4         inDataLen;
    ubyte          inFlag;

} eapPSKCb;



typedef EAP_PACKED struct eapPSKEAX_s {
    eapHdr_t eapHdr;
    ubyte    eapType;
    ubyte    flag;
    ubyte    rand_s[16];

} EAP_PACKED_POST eapPSKEAX;
#ifdef __cplusplus
}
#endif

#endif /*__EAP_PSK_PVT_H__*/

