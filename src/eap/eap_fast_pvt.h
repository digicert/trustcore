/**
 * @file  eap_fast_pvt.h
 * @brief EAP-FAST private definitions
 *
 * @details    Internal EAP-FAST structures
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__ or \c \__ENABLE_DIGICERT_EAP_AUTH__
 *     Additionally, the following flag must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_FAST__ or \c \__ENABLE_DIGICERT_EAP_PEAPV2__
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

#ifndef __EAP_FAST_PVT_H__
#define __EAP_FAST_PVT_H__

#ifdef __cplusplus
extern "C" {
#endif
#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
#if (defined(__ENABLE_DIGICERT_EAP_FAST__) || defined(__ENABLE_DIGICERT_EAP_PEAPV2__))

/* Crypto binding TLV types */
#define EAP_FAST_BINDING_REQUEST         0
#define EAP_FAST_BINDING_RESPONSE        1

/* TLV types flag values */
#define EAP_FAST_RESULT_TLV_FLAG              0x01
#define EAP_FAST_NAK_TLV_FLAG                 0x02
#define EAP_FAST_ERROR_TLV_FLAG               0x04
#define EAP_FAST_VENDOR_TLV_FLAG              0x08
#define EAP_FAST_EAP_PAYLOAD_TLV_FLAG         0x10
#define EAP_FAST_INTERMEDIATE_RESULT_TLV_FLAG 0x20
#define EAP_FAST_PAC_TLV_FLAG                 0x40
#define EAP_FAST_CRYPTO_BINDING_TLV_FLAG      0x80

/* TLV types */
#define EAP_FAST_RESULT_TLV              3
#define EAP_FAST_NAK_TLV                 4
#define EAP_FAST_ERROR_TLV               5
#define EAP_FAST_VENDOR_TLV              7
#define EAP_FAST_EAP_PAYLOAD_TLV         9
#define EAP_FAST_INTERMEDIATE_RESULT_TLV 10
#define EAP_FAST_PAC_TLV                 11
#define EAP_FAST_CRYPTO_BINDING_TLV      12
#define EAP_FAST_SERVER_TRUSTED_ROOT_TLV 18
#define EAP_FAST_REQUEST_ACTION_TLV      19
#define EAP_FAST_PKCS_7_TLV              20

/* PAC TLV Subtypes */
#define EAP_FAST_PAC_KEY                 1
#define EAP_FAST_PAC_OPAQUE              2
#define EAP_FAST_PAC_LIFETIME            3
#define EAP_FAST_PAC_A_ID                4
#define EAP_FAST_PAC_I_ID                5
#define EAP_FAST_PAC_RESERVED            6
#define EAP_FAST_PAC_A_ID_INFO           7
#define EAP_FAST_PAC_ACK                 8
#define EAP_FAST_PAC_INFO                9
#define EAP_FAST_PAC_TYPE                10

#define EAP_FAST_PAC_LIFETIME_LENGTH     4
#define EAP_FAST_PAC_A_ID_LENGTH         16
#define EAP_FAST_PAC_ACK_LENGTH          2
#define EAP_FAST_PAC_ACK_RESULT_SUCCESS  1
#define EAP_FAST_PAC_ACK_RESULT_FAILURE  2
#define EAP_FAST_PAC_TYPE_LENGTH         2
#define EAP_FAST_PAC_TYPE_TUNNEL         1
#define EAP_FAST_PAC_TYPE_MACHINE        2
#define EAP_FAST_PAC_TYPE_USER           3



/* Error TLV values */
#define EAP_FAST_TUNNEL_COMPROMISE_ERROR            2001
#define EAP_FAST_UNEXPECTED_TLVS_EXCHANGED_ERROR    2002

#define EAP_FAST_CRYPTO_BINDING_TLV_LEN     56
#define EAP_PEAPV2_CRYPTO_BINDING_TLV_LEN   52
#define EAP_FAST_CRYPTO_BINDING_NONCE_LEN   32
#define EAP_FAST_CRYPTO_BINDING_CMAC_LEN    20
#define EAP_PEAPV2_CRYPTO_BINDING_CMAC_LEN  16
#define EAP_FAST_ERROR_TLV_LEN              4
#define EAP_FAST_RESULT_TLV_LEN             2

typedef struct
{
    void                    *appSessionCB;
    EAP_FAST_params         eapFASTparam;
    ubyte                   *authId;
    ubyte                   intermediate_result;
    ubyte                   crypto_binding_verified;
    ubyte                   nonce[EAP_FAST_CRYPTO_BINDING_NONCE_LEN];
    ubyte                   c_nonce[EAP_FAST_CRYPTO_BINDING_NONCE_LEN];
    ubyte                   tlv_flag;
    ubyte                   pac_sent;
    ubyte2                  pac_ack_result;
    ubyte2                  pac_type_request;
    ubyte                   method_count;
    ubyte                   sessionStatus;
    ubyte                   *data_recv;
    ubyte4                  data_recv_total_len;
    ubyte4                  data_recv_len;
    ubyte                   *data_send;
    ubyte                   *data_send_cur;
    ubyte4                  data_send_total_len;
    ubyte4                  data_send_remaining;
    eap_fast_frag_flag_e    frag_flag;
    eap_fast_eap_state      eapStatus;
    ubyte                   *eapSessionHdl;
    ubyte                   *eapAuthSessionHdl;
    ubyte                   md5_challenge[MD5_DIGESTSIZE];
    EAP_FAST_pac_t          *pac;

} eapFASTCB;
MOC_EXTERN MSTATUS EAP_FASTPeerInit(ubyte *eapFastCb);
#endif /* ((defined(__ENABLE_DIGICERT_EAP_FAST__) */
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */
#ifdef __cplusplus
}
#endif
#endif /* __EAP_FAST_PVT_H__  */
